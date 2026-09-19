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
    WorldSpawnState,
    ServerState, SessionState, ActorWorldState, ContainerWorldState,
    LockWorldState, OutfitEntry, ResumeTicket,
)
from protocol import PosStatePayload, EquipModRecord  # noqa: E402


log = logging.getLogger("persistence")

SNAPSHOT_FORMAT_VERSION: int = 5
# v4 (B6.3 v0.5.3, 2026-05-08): adds `locks` section keyed by
#     (base_id, cell_id), with form_id hint + locked bool + timestamp.
#     v3 snapshots load fine (no locks key → empty lock_state).
# v5 (session lifecycle phase 0, 2026-09-18): adds `presence` (per peer: the
#     name, the last accepted position, the worn outfit, the power-armour
#     frame being worn) and `resume_tokens`. Both must survive a restart:
#     presence is what a late joiner is shown, and a token that died with the
#     server would lock every client out of rejoining an authenticated one.
#     v2/v3/v4 snapshots load fine — the missing sections simply come up
#     empty, which is the same shape as a first run.


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
                "steam_id": s.steam_id,            # B6.6w5
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
        # B6.14 — spawned world objects. These MUST persist: the local copies
        # on every client are TEMPORARY refs that die with the session, so the
        # join bootstrap is the only thing that brings a spawned object back.
        "world_spawns": [
            {
                "wid": w.wid,
                # v26 — who is wearing it. Without this a restart puts an
                # empty suit of power armour in the world next to the player
                # standing inside it.
                "worn_by_peer_id": w.worn_by_peer_id,
                "worn_since_ms": w.worn_since_ms,
                "spawner_peer": w.spawner_peer,
                "base_form_id": w.base_form_id,
                "spawner_local_fid": w.spawner_local_fid,
                "px": w.px, "py": w.py, "pz": w.pz,
                "rx": w.rx, "ry": w.ry, "rz": w.rz,
                "cell_id": w.cell_id,
                "flags": w.flags,
                "timestamp_ms": w.timestamp_ms,
                # v23 — the frame's content survives a server restart with
                # the object itself.
                "pieces": [
                    [int(e[0]), int(e[1]),
                     [int(m) for m in (e[2] if len(e) > 2 else ())],
                     float(e[3]) if len(e) > 3 else -1.0]
                    for e in w.pieces
                ],
            }
            for w in state.all_world_spawns()
        ],
        # v20 — appearances, keyed by peer id. These MUST persist: a character
        # is made once and then never again, so losing this map on a server
        # restart would silently demote every player to the default model with
        # no way for them to notice or fix it short of re-running the creator.
        # Stored as the recipe line verbatim, which is also what the wire
        # carries — a snapshot is therefore directly comparable with a capture.
        "appearances": dict(state.all_appearances()),
        # v26 — presence. Same argument as the appearances above: the whole
        # point is that somebody joining hours later sees the others where
        # they are and dressed as they are, and a restart must not undo that.
        "presence": [
            {
                "peer_id": p.peer_id,
                "display_name": p.display_name,
                "last_pos": _pos_to_dict(p.last_pos) if p.last_pos else None,
                "last_pos_cell_id": (
                    getattr(p.last_pos, "cell_id", 0) if p.last_pos else 0),
                "worn_frame_wid": p.worn_frame_wid,
                "outfit": [
                    {
                        "item_form_id": e.item_form_id,
                        "slot_form_id": e.slot_form_id,
                        "count": e.count,
                        "effective_priority": e.effective_priority,
                        "timestamp_ms": e.timestamp_ms,
                        "mods": [
                            [m.form_id, m.attach_index, m.rank, m.flag]
                            for m in e.mods
                        ],
                    }
                    for e in p.outfit.values()
                ],
            }
            for p in state.all_presence()
        ],
        # v26 — resume tokens, hex-encoded. These are BEARER CREDENTIALS in
        # clear text: whoever reads this file can rejoin as any identity in
        # it until the token expires. Acceptable while the server runs on the
        # developer's own machine next to the repo, and the first thing to
        # revisit when it moves anywhere else.
        "resume_tokens": [
            {
                "token": tok.hex(),
                "peer_id": t.peer_id,
                "identity_hex": t.identity_hex,
                "issued_at_ms": t.issued_at_ms,
                "expires_at_ms": t.expires_at_ms,
            }
            for tok, t in state._resume_tokens.items()
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
        # Say it out loud when the snapshot disagrees with the code. This
        # field silently pinned 5 s over a 15 s default for a whole phase:
        # the value was raised in ServerState, deployed, and never applied,
        # because every boot restored the old one from the world file. A
        # tuning knob that cannot be turned is worse than a wrong value.
        snapshot_timeout = float(server_cfg["peer_timeout_ms"])
        if snapshot_timeout != state.peer_timeout_ms:
            log.info(
                "snapshot %s: peer_timeout_ms %.0f ms from the snapshot "
                "overrides the %.0f ms built into this build",
                path, snapshot_timeout, state.peer_timeout_ms,
            )
        state.peer_timeout_ms = snapshot_timeout

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
    if version not in (2, 3, 4, SNAPSHOT_FORMAT_VERSION):
        raise ValueError(
            f"snapshot format version {version!r} unsupported "
            f"(expected {SNAPSHOT_FORMAT_VERSION}, 4, 3, 2, or 1)"
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
    # Restore appearances (v20+). Absent in older snapshots, which simply
    # means nobody had a character yet. Skipped rather than repaired if the
    # shape is wrong: a malformed recipe would render as a silently wrong
    # character, which is worse than the default model.
    appearance_skipped = 0
    for peer_id, recipe in (data.get("appearances") or {}).items():
        if not isinstance(peer_id, str) or not isinstance(recipe, str)                 or not peer_id or not recipe:
            appearance_skipped += 1
            continue
        state.record_appearance(peer_id, recipe)
    if appearance_skipped:
        log.warning("snapshot %s: skipped %d malformed appearance entries",
                    path, appearance_skipped)

    # v26 — presence and resume tokens. Both sections are absent from v2..v4
    # snapshots, which simply means "nothing known yet".
    presence_restored = 0
    for p in (data.get("presence") or []):
        try:
            peer_id = str(p["peer_id"])
            if not peer_id:
                continue
            rec = state._presence_for(peer_id)
            rec.display_name = str(p.get("display_name", "") or "")
            rec.worn_frame_wid = int(p.get("worn_frame_wid", 0) or 0)
            pos = p.get("last_pos")
            if pos:
                rec.last_pos = PosStatePayload(
                    x=float(pos["x"]), y=float(pos["y"]), z=float(pos["z"]),
                    rx=float(pos["rx"]), ry=float(pos["ry"]),
                    rz=float(pos["rz"]),
                    timestamp_ms=int(pos.get("timestamp_ms", 0)),
                    cell_id=int(p.get("last_pos_cell_id", 0) or 0),
                )
            for item in (p.get("outfit") or []):
                mods = tuple(
                    EquipModRecord(
                        form_id=int(m[0]), attach_index=int(m[1]),
                        rank=int(m[2]), flag=int(m[3]),
                    )
                    for m in (item.get("mods") or [])
                )
                entry = OutfitEntry(
                    item_form_id=int(item["item_form_id"]),
                    slot_form_id=int(item.get("slot_form_id", 0)),
                    count=int(item.get("count", 1)),
                    effective_priority=int(item.get("effective_priority", 0)),
                    mods=mods,
                    timestamp_ms=int(item.get("timestamp_ms", 0)),
                )
                rec.outfit[entry.item_form_id] = entry
            presence_restored += 1
        except (KeyError, TypeError, ValueError) as e:
            log.warning("snapshot %s: skipping malformed presence entry: %s",
                        path, e)

    tokens_restored = 0
    for t in (data.get("resume_tokens") or []):
        try:
            raw = bytes.fromhex(str(t["token"]))
            state._resume_tokens[raw] = ResumeTicket(
                peer_id=str(t["peer_id"]),
                identity_hex=str(t.get("identity_hex", "") or ""),
                issued_at_ms=float(t.get("issued_at_ms", 0.0)),
                expires_at_ms=float(t.get("expires_at_ms", 0.0)),
            )
            tokens_restored += 1
        except (KeyError, TypeError, ValueError) as e:
            log.warning("snapshot %s: skipping malformed resume token: %s",
                        path, e)
    if presence_restored or tokens_restored:
        log.info("snapshot %s: restored presence for %d peer(s), %d resume "
                 "token(s)", path, presence_restored, tokens_restored)

    # B6.14 — restore spawned world objects and keep the wid counter ahead of
    # everything ever issued, so a restart can never mint a duplicate wid.
    for w in data.get("world_spawns", []):
        try:
            st = WorldSpawnState(
                wid=int(w["wid"]),
                spawner_peer=str(w.get("spawner_peer", "server")),
                base_form_id=int(w["base_form_id"]),
                spawner_local_fid=int(w.get("spawner_local_fid", 0)),
                px=float(w["px"]), py=float(w["py"]), pz=float(w["pz"]),
                rx=float(w.get("rx", 0.0)), ry=float(w.get("ry", 0.0)),
                rz=float(w.get("rz", 0.0)),
                cell_id=int(w.get("cell_id", 0)),
                flags=int(w.get("flags", 0)),
                timestamp_ms=int(w.get("timestamp_ms", 0)),
                pieces=tuple(
                    (int(e[0]), int(e[1]),
                     tuple(int(m) for m in (e[2] if len(e) > 2 else ())),
                     float(e[3]) if len(e) > 3 else -1.0)
                    for e in w.get("pieces", []) if len(e) >= 2),
                worn_by_peer_id=str(w.get("worn_by_peer_id", "") or ""),
                worn_since_ms=float(w.get("worn_since_ms", 0.0) or 0.0),
            )
        except (KeyError, TypeError, ValueError):
            continue
        state.world_spawns[st.wid] = st
        if st.wid >= state.next_world_spawn_wid:
            state.next_world_spawn_wid = st.wid + 1

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
