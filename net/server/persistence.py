"""
Server persistence: periodic JSON snapshot of state for debugging + crash recovery.

Snapshot files are human-readable (pretty JSON). Rotation keeps last N.

Format history:
  v1 (deprecated): keyed world_actors by form_id. UNSAFE across process
      restarts because 0xFF______ runtime refs alias to different objects.
      load_into() drops all v1 entries with a loud warning.
  v2 (prior): identity-keyed by (base_id, cell_id) for world_actors.
  v3 (current): v2 + `containers` section with per-container inventory
      state (base_id, cell_id, items dict). load_into() can read v2 snapshots
      (treating them as v3 with no containers) for zero-friction upgrade.
"""
from __future__ import annotations

import json
import logging
import os
import tempfile
import time
from pathlib import Path
from typing import Any

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from server.state import (  # noqa: E402
    ServerState, SessionState, ActorWorldState, ContainerWorldState,
    LockWorldState,
)


log = logging.getLogger("persistence")

SNAPSHOT_FORMAT_VERSION: int = 4
# v4 (B6.3 v0.5.3, 2026-05-08): adds `locks` section keyed by
#     (base_id, cell_id), with form_id hint + locked bool + timestamp.
#     v3 snapshots load fine (no locks key → empty lock_state).


def snapshot(state: ServerState, path: Path, *, pretty: bool = True) -> None:
    """Atomically write a snapshot of ServerState to JSON file.

    Writes to a temp file then renames (crash-safe against partial writes).
    """
    data: dict[str, Any] = {
        "version": SNAPSHOT_FORMAT_VERSION,
        "timestamp_ms": int(time.time() * 1000),
        "server": {
            "tick_rate_hz": state.tick_rate_hz,
            "server_version": list(state.server_version),
            "peer_timeout_ms": state.peer_timeout_ms,
        },
        "sessions": [
            {
                "session_id": s.session_id,
                "peer_id": s.peer_id,
                "addr": [s.addr[0], s.addr[1]],
                "client_version": list(s.client_version),
                "state": s.state.name,
                "joined_at_ms": s.joined_at_ms,
                "last_seen_ms": s.last_seen_ms,
                "total_pos_updates": s.total_pos_updates,
                "total_events": s.total_events,
                "last_pos": _pos_to_dict(s.last_pos) if s.last_pos else None,
                "channel_in_flight": len(s.channel.send.in_flight),
                "channel_rtt_ms": s.channel.send.rtt.srtt_ms,
            }
            for s in state.all_sessions()
        ],
        "world_actors": [
            {
                "base_id": f"0x{a.base_id:X}",
                "cell_id": f"0x{a.cell_id:X}",
                "alive": a.alive,
                "last_known_form_id": f"0x{a.last_known_form_id:X}",
                "last_owner": a.last_owner_peer_id,
                "last_update_ms": a.last_update_ms,
            }
            for a in state.all_actors()
        ],
        "containers": [
            {
                "base_id": f"0x{c.base_id:X}",
                "cell_id": f"0x{c.cell_id:X}",
                # items: hex-stringified keys for JSON (JSON keys must be str)
                "items": {f"0x{iid:X}": cnt for iid, cnt in c.items.items()},
                "last_known_form_id": f"0x{c.last_known_form_id:X}",
                "last_owner": c.last_owner_peer_id,
                "last_update_ms": c.last_update_ms,
            }
            for c in state.all_containers()
        ],
        "locks": [
            {
                "base_id": f"0x{lk.base_id:X}",
                "cell_id": f"0x{lk.cell_id:X}",
                "form_id": f"0x{lk.form_id:X}",
                "locked": lk.locked,
                "timestamp_ms": lk.timestamp_ms,
            }
            for lk in state.all_locks()
        ],
    }

    path.parent.mkdir(parents=True, exist_ok=True)
    # Atomic write: temp file + rename
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", dir=str(path.parent),
        prefix=f".{path.name}.", suffix=".tmp", delete=False,
    ) as tmp:
        if pretty:
            json.dump(data, tmp, indent=2)
        else:
            json.dump(data, tmp, separators=(",", ":"))
        tmp_path = tmp.name
    os.replace(tmp_path, path)


def _pos_to_dict(p) -> dict[str, Any]:
    return {
        "x": p.x, "y": p.y, "z": p.z,
        "rx": p.rx, "ry": p.ry, "rz": p.rz,
        "timestamp_ms": p.timestamp_ms,
    }


def load_into(state: ServerState, path: Path) -> int:
    """Restore ServerState from a snapshot JSON file.

    Only rebuilds world_actors and tick_rate/server_version (configuration).
    Sessions are NOT restored (peers must reconnect — their RTT, positions, etc.
    are ephemeral).

    Returns: number of actors restored. Raises FileNotFoundError if path missing,
    ValueError if format unknown/corrupt.
    """
    if not path.is_file():
        raise FileNotFoundError(f"snapshot not found: {path}")

    raw = path.read_text(encoding="utf-8")
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        raise ValueError(f"snapshot json malformed: {e}") from e

    version = data.get("version")

    # Restore server-level config (non-destructive: only if present in snapshot).
    # Done early so we get the config even when the world_actors section is
    # unusable (v1 legacy drop).
    server_cfg = data.get("server") or {}
    if "tick_rate_hz" in server_cfg:
        state.tick_rate_hz = int(server_cfg["tick_rate_hz"])
    if "peer_timeout_ms" in server_cfg:
        state.peer_timeout_ms = float(server_cfg["peer_timeout_ms"])

    if version == 1:
        # Legacy v1 snapshots keyed entries by form_id alone. Those form_ids
        # are unsafe to apply in v2 because runtime refs (0xFF______) alias
        # across processes — see step 1 of Option B. Drop everything with a
        # loud warning so the operator knows what happened.
        legacy_count = len(data.get("world_actors", []))
        log.warning(
            "snapshot %s is format v1 (pre-identity-keyed): dropping %d legacy "
            "world_actor entries. They lacked (base_id, cell_id) identity so "
            "applying them could disable the wrong objects at bootstrap.",
            path, legacy_count,
        )
        return 0

    # v2 snapshots have no containers section; v3 adds containers; v4 adds
    # locks. All three are readable — older missing sections become empty.
    # Unknown versions (> 4 or other) are rejected.
    if version not in (2, 3, SNAPSHOT_FORMAT_VERSION):
        raise ValueError(
            f"snapshot format version {version!r} unsupported "
            f"(expected {SNAPSHOT_FORMAT_VERSION}, 3, 2, or 1)"
        )

    # Restore world actors (the authoritative game state)
    n = 0
    skipped = 0
    for a in data.get("world_actors", []):
        base_raw = a.get("base_id")
        cell_raw = a.get("cell_id")
        if base_raw is None or cell_raw is None:
            skipped += 1
            continue
        base_id = int(base_raw, 16) if isinstance(base_raw, str) else int(base_raw)
        cell_id = int(cell_raw, 16) if isinstance(cell_raw, str) else int(cell_raw)
        if base_id == 0 or cell_id == 0:
            skipped += 1
            continue
        ref_raw = a.get("last_known_form_id", 0)
        last_form = (
            int(ref_raw, 16) if isinstance(ref_raw, str) else int(ref_raw)
        )
        actor = ActorWorldState(
            base_id=base_id,
            cell_id=cell_id,
            alive=bool(a.get("alive", True)),
            last_known_form_id=last_form,
            last_owner_peer_id=a.get("last_owner"),
            last_update_ms=float(a.get("last_update_ms", 0.0)),
        )
        state._world_actors[(actor.base_id, actor.cell_id)] = actor
        n += 1
    if skipped:
        log.warning(
            "snapshot %s: skipped %d world_actor entries with missing/zero identity",
            path, skipped,
        )

    # Restore container state (v3+). v2 snapshots won't have this key at all.
    container_skipped = 0
    for c in data.get("containers", []):
        base_raw = c.get("base_id")
        cell_raw = c.get("cell_id")
        if base_raw is None or cell_raw is None:
            container_skipped += 1
            continue
        base_id = int(base_raw, 16) if isinstance(base_raw, str) else int(base_raw)
        cell_id = int(cell_raw, 16) if isinstance(cell_raw, str) else int(cell_raw)
        if base_id == 0 or cell_id == 0:
            container_skipped += 1
            continue
        items_raw = c.get("items", {}) or {}
        items: dict[int, int] = {}
        for k, v in items_raw.items():
            try:
                iid = int(k, 16) if isinstance(k, str) else int(k)
            except (TypeError, ValueError):
                continue
            if iid == 0:
                continue
            count = int(v)
            if count > 0:
                items[iid] = count
        ref_raw = c.get("last_known_form_id", 0)
        last_form = (
            int(ref_raw, 16) if isinstance(ref_raw, str) else int(ref_raw)
        )
        container = ContainerWorldState(
            base_id=base_id,
            cell_id=cell_id,
            items=items,
            last_known_form_id=last_form,
            last_owner_peer_id=c.get("last_owner"),
            last_update_ms=float(c.get("last_update_ms", 0.0)),
        )
        state._containers[(container.base_id, container.cell_id)] = container
    if container_skipped:
        log.warning(
            "snapshot %s: skipped %d container entries with missing/zero identity",
            path, container_skipped,
        )

    # Restore lock states (v4+). Older snapshots won't have this key.
    lock_skipped = 0
    for lk in data.get("locks", []):
        base_raw = lk.get("base_id")
        cell_raw = lk.get("cell_id")
        if base_raw is None or cell_raw is None:
            lock_skipped += 1
            continue
        base_id = int(base_raw, 16) if isinstance(base_raw, str) else int(base_raw)
        cell_id = int(cell_raw, 16) if isinstance(cell_raw, str) else int(cell_raw)
        if base_id == 0 or cell_id == 0:
            lock_skipped += 1
            continue
        form_raw = lk.get("form_id", 0)
        form_id = int(form_raw, 16) if isinstance(form_raw, str) else int(form_raw)
        state.lock_state[(base_id, cell_id)] = LockWorldState(
            base_id=base_id,
            cell_id=cell_id,
            form_id=form_id,
            locked=bool(lk.get("locked", True)),
            timestamp_ms=int(lk.get("timestamp_ms", 0)),
        )
    if lock_skipped:
        log.warning(
            "snapshot %s: skipped %d lock entries with missing/zero identity",
            path, lock_skipped,
        )

    return n


def rotate_snapshots(base_path: Path, keep: int = 5) -> None:
    """Keep last `keep` snapshots in base_path.N suffix, oldest deleted.

    Convention:  snapshot.json, snapshot.json.1, .2, .3, ...
    """
    if not base_path.exists():
        return
    # Shift .N -> .N+1 from highest down
    for n in range(keep - 1, 0, -1):
        old = base_path.with_name(f"{base_path.name}.{n}")
        new = base_path.with_name(f"{base_path.name}.{n + 1}")
        if old.exists():
            if new.exists():
                new.unlink()
            old.rename(new)
    # Move current to .1
    rotated = base_path.with_name(f"{base_path.name}.1")
    if rotated.exists():
        rotated.unlink()
    base_path.rename(rotated)

    # Drop anything beyond `keep`
    for n in range(keep + 1, keep + 20):
        extra = base_path.with_name(f"{base_path.name}.{n}")
        if extra.exists():
            extra.unlink()
