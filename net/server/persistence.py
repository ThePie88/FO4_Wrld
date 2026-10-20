"""
Server persistence: periodic JSON snapshot of state for debugging + crash recovery.

Snapshot files are human-readable (pretty JSON). Rotation keeps last N.

Format history:
  v1 (deprecated): keyed world_actors by form_id. UNSAFE across process
      restarts because 0xFF______ runtime refs alias to different objects.
      load_into() drops all v1 entries with a loud warning.
  v2 (prior): identity-keyed by (base_id, cell_id) for world_actors.
  v3: v2 + `containers` section with per-container inventory state
      (base_id, cell_id, items dict). load_into() can read v2 snapshots
      (treating them as v3 with no containers) for zero-friction upgrade.
  v4, v5: see SNAPSHOT_FORMAT_VERSION below.
  v6 (current): containers keyed by the placed REFR's form_id (loot rework
      L1). The container section of a v3..v5 snapshot is dropped on load.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
import tempfile
import time
from pathlib import Path
from typing import Any, Optional

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from server.state import (  # noqa: E402
    WorldSpawnState,
    ServerState, SessionState, ActorWorldState, ContainerWorldState,
    LockWorldState, OutfitEntry, ResumeTicket, PRE_SEED_OPS_MAX,
)
from protocol import (  # noqa: E402
    PosStatePayload, EquipModRecord, is_runtime_form_id, COUNT_MAX,
    wid_container_key, PA_FRAME_WEARABLES,
    FP_UNKNOWN, InstanceDescriptor,
)


log = logging.getLogger("persistence")

SNAPSHOT_FORMAT_VERSION: int = 15   # v15: the ops a partial container record saw, the world a checkpoint carries, the save each peer's world runs on (2026-10-20)
# v13 (L5 realtime R4, 2026-10-03): `player_stats`, each player's numbers
#     (PlayerStatsRecord: XP, level, perk points, SPECIAL, health, action
#     points, rads, perks). A v12 file loads with none.
# v12 (L5 realtime R1, 2026-10-03): `players`, each player's inventory
#     record (PlayerInvRecord: the lines [item, fp, count], the equipped
#     lines, the capture it stands on and the accepted ops pending on top);
#     `instances` also lists the descriptors a player's line or pending op
#     names. A v11 file loads with no records.
# v11 (L5 stage 4b, 2026-10-03): a container's `items` is a list of
#     [item, fp, count] (the line's instance fingerprint, protocol.instance_fp)
#     instead of {item: count}, and `instances` lists the descriptor of every
#     instance a line names. The items of a v6..v10 file load as FP_UNKNOWN
#     lines: their counts are kept, the instance they held is not known.
# v10 (L5 stage 3b, 2026-09-28): `custody` on each checkpoint, true when the
#     server holds its bytes (server/custody.py). Everything else as v9.
# v9 (L5 stage 3a, 2026-09-28): `checkpoints`, the last three checkpoints
#     each peer reported written (name, sha256, size, digest, watermark
#     LSN, status, boot failures). Everything else as v8.
# v8 (L5 stage 2, 2026-09-27): `inv_digests`, the last inventory digest each
#     peer reported (INV_DIGEST), advisory. Everything else as v7.
# v7 (L5 stage 1, 2026-09-27): the snapshot is a compaction of the journal.
#     `journal` = {lsn, epoch} says which journal records it covers, so a
#     boot replays only what came after; `quests` and `globals` are written
#     at last (they never were: every quest stage and global set died with
#     the process); `resume_tokens` entries carry `token_hash` (SHA-256 of
#     the token) instead of the token. v5/v6 files load as before, their
#     clear-text tokens hashed on the way in, their journal lsn taken as 0.
# v6 (loot rework L1, 2026-09-23): `containers` entries carry `form_id`, the
#     placed REFR's own id, and are keyed by it. The (base_id, cell_id) key
#     of v3..v5 merged every ref of one base in one cell into one record,
#     and such a record cannot be mapped back to one REFR: the container
#     section of an older snapshot is DROPPED on load, with a warning that
#     says how many records went. Everything else in a v2..v5 snapshot
#     loads as before.
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
    journal = getattr(state, "journal", None)
    data: dict[str, Any] = {
        "version": SNAPSHOT_FORMAT_VERSION,
        "timestamp_ms": int(time.time() * 1000),
        # v7 — what this file covers. A boot loads it and replays the
        # journal from lsn + 1; without a journal the lsn is 0 and the
        # snapshot is the whole story, as before.
        "journal": {
            "lsn": int(getattr(state, "applied_lsn", 0)),
            "epoch": int(getattr(journal, "epoch", 0)) if journal is not None else 0,
        },
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
                "form_id": f"0x{c.form_id:X}",
                "base_id": f"0x{c.base_id:X}",
                "cell_id": f"0x{c.cell_id:X}",
                # v11: [item, instance fingerprint, count], hex for reading
                "items": [[f"0x{iid:X}", f"0x{fp:X}", cnt]
                          for (iid, fp), cnt in sorted(c.items.items())],
                "seeded": c.seeded,
                "last_owner": c.last_owner_peer_id,
                "last_update_ms": c.last_update_ms,
                # D1 (v13): the world spawn of a container of the server's.
                "wid": c.wid,
                # D2 (v14): whose death made it, the ordinal and when ("" / 0 otherwise).
                "death_owner": c.death_owner,
                "death_ordinal": c.death_ordinal,
                "death_ms": c.death_ms,
                # 2026-10-20 (v15): the ops a partial record saw before its first
                # scan: [peer, ms, kind, item, fp, count]; empty once seeded.
                "pre_seed_ops": [[who, ms, kind, f"0x{item:X}", f"0x{fp:X}", cnt]
                                 for who, ms, kind, item, fp, cnt in c.pre_seed_ops],
                "pre_seed_overflow": bool(c.pre_seed_overflow),
            }
            for c in state.all_containers()
        ],
        # D2 (v14): how many death crates each peer's deaths made (the next ordinal).
        "death_counts": {peer: n for peer, n in sorted(state.all_death_counts().items())},
        # 2026-10-20 (v15): per peer [save_ms, load_ms] of its last load (ServerState.note_world_base).
        "world_base_ms": {peer: [wb[0], wb[1]] for peer, wb in sorted(state.all_world_bases().items())},
        # v11 — the descriptors of the instances a line still names.
        "instances": [
            {
                "fp": f"0x{fp:X}",
                "item": f"0x{item:X}",
                "template": d.template,
                "flags": d.flags,
                "health": d.health,
                "mods": [[f"0x{form:X}", attach, rank] for form, attach, rank in d.mods],
            }
            for fp, item, d in state.instance_defs_named()
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
        # v7 — quest stages and global variables. Both were relayed live and
        # forgotten at shutdown, so a quest advanced on Monday was back at
        # its old stage for whoever joined on Tuesday.
        "quests": [
            {
                "quest_form_id": f"0x{q.quest_form_id:X}",
                "stage": q.stage,
                "last_owner": q.last_owner_peer_id,
                "last_update_ms": q.last_update_ms,
            }
            for q in state.all_quest_stages()
        ],
        "globals": [
            {
                "global_form_id": f"0x{g.global_form_id:X}",
                "value": g.value,
                "last_owner": g.last_owner_peer_id,
                "last_update_ms": g.last_update_ms,
            }
            for g in state.all_globals()
        ],
        # v8 — the last inventory digest each peer reported. Advisory: the
        # record stage 3 holds a checkpoint against; nothing reads it yet.
        "inv_digests": [
            {
                "peer_id": d.peer_id,
                "seq": d.seq,
                "wall_ms": d.wall_ms,
                "digest": f"0x{d.digest:016X}",
                "entries": d.entries,
                "stacks": d.stacks,
                "items": d.items,
                "reasons": d.reasons,
                "flags": d.flags,
                "why": d.why,
                "received_ms": d.received_ms,
                "count": d.count,
            }
            for d in state.all_inv_digests()
        ],
        # v13 - the players' numbers (L5 realtime R4).
        "player_stats": [
            {
                "peer_id": r.peer_id, "session": r.session, "seq": r.seq,
                "level": r.level, "xp": r.xp, "perk_points": r.perk_points,
                "special": list(r.special), "health": r.health,
                "action_points": r.action_points, "rads": r.rads,
                "perks": [[f"0x{form:X}", rank] for form, rank in sorted(r.perks.items())],
                "captures": r.captures, "updated_ms": r.updated_ms,
            }
            for r in state.all_player_stats()
        ],
        # v12 - the players' inventory records (L5 realtime R1).
        "players": [
            {
                "peer_id": r.peer_id,
                "lines": [[f"0x{item:X}", f"0x{fp:X}", count]
                          for (item, fp), count in sorted(r.lines.items())],
                "equipped": [[f"0x{item:X}", f"0x{fp:X}"]
                             for (item, fp) in sorted(r.equipped)],
                "session": r.session,
                "seq": r.seq,
                "watermark": r.watermark,
                "op_epoch": r.op_epoch,
                "flags": r.flags,
                "digest": f"0x{r.digest:016X}",
                "pending": [[op_id, kind, f"0x{item:X}", f"0x{fp:X}", count]
                            for (op_id, kind, item, fp, count) in r.pending],
                "captures": r.captures,
                "updated_ms": r.updated_ms,
                "open_session": r.open_session,
            }
            for r in state.all_player_inventories()
        ],
        # v9 — the checkpoints, newest first per peer.
        "checkpoints": [
            {
                "peer_id": c.peer_id,
                "identity_hex": c.identity_hex,
                "seq": c.seq,
                "name": c.name,
                "sha256": c.sha256_hex,
                "size": c.size,
                "digest": f"0x{c.digest:016X}",
                "digest_seq": c.digest_seq,
                "wall_ms": c.wall_ms,
                "received_ms": c.received_ms,
                "watermark_lsn": c.watermark_lsn,
                "reason": c.reason,
                "status": c.status,
                "boot_failures": c.boot_failures,
                "custody": bool(c.custody),
                "in_pa": c.in_pa,            # D1: None when its digest never came
                "in_pa_wid": c.in_pa_wid,    # 2026-10-15: the frame they wore then
                "world_ms": c.world_ms,      # 2026-10-20 (v15): the world it carries
            }
            for c in state.all_checkpoints()
        ],
        # L5 realtime D1 (2026-10-03) — the wid counter itself. Derived from
        # the objects left, it went back under a wid already issued whenever
        # the newest object was gone (an emptied crate, as a rule), and the
        # next object got that wid and that container key again.
        "next_world_spawn_wid": int(state.next_world_spawn_wid),
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
        # v26 — resume tokens. Until v7 they were written in clear text, and
        # whoever read this file could rejoin as any identity in it. Since
        # L5 stage 1 the server never holds a token, only its SHA-256 (the
        # key of state._resume_tokens), and that is what is written.
        "resume_tokens": [
            {
                "token_hash": key.hex(),
                "peer_id": t.peer_id,
                "identity_hex": t.identity_hex,
                "issued_at_ms": t.issued_at_ms,
                "expires_at_ms": t.expires_at_ms,
            }
            for key, t in state._resume_tokens.items()
        ],
    }

    path.parent.mkdir(parents=True, exist_ok=True)
    # Atomic write: temp file, flushed and fsynced, then renamed over the
    # target. The fsync is what makes the rename mean anything: until stage 0
    # of L5 (2026-09-27) a power cut could leave the renamed file with no
    # data blocks behind it, and the loader answered such a file with an
    # empty world. A failed write removes its temp file and leaves the
    # previous snapshot as it was.
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=str(path.parent),
            prefix=f".{path.name}.", suffix=".tmp", delete=False,
        ) as tmp:
            tmp_path = tmp.name
            if pretty:
                json.dump(data, tmp, indent=2)
            else:
                json.dump(data, tmp, separators=(",", ":"))
            tmp.flush()
            os.fsync(tmp.fileno())
        os.replace(tmp_path, path)
        tmp_path = None
    finally:
        if tmp_path is not None:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
    _fsync_directory(path.parent)


def _fsync_directory(directory: Path) -> None:
    """Make the rename itself durable where the platform allows it. Windows
    cannot open a directory for fsync; the rename is journaled by NTFS."""
    if os.name == "nt":
        return
    try:
        fd = os.open(str(directory), os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


class SnapshotUnreadable(RuntimeError):
    """No snapshot copy could be loaded and the operator did not allow an
    empty world. Raised instead of starting a world that would overwrite
    every good copy within a few rotations."""


def restore_state(state: ServerState, path: Path, *, allow_empty_world: bool = False,
                  keep: int = 5) -> Optional[Path]:
    """Load the world at boot, fail-closed.

    Tries `path`, then the rotated copies `path.1` .. `path.keep` in order.
    A copy that fails to load is moved aside as `path.corrupt.N` so the next
    write cannot rotate it over a good copy. The copy that loaded is also
    saved as `path.lastgood`, a file the rotation never touches. Returns the
    path that loaded, or None when no snapshot exists at all (a new world)
    or when every copy failed and `allow_empty_world` is set.

    Stage 0 of L5 (2026-09-27): before this the loader logged "starting with
    empty world" on any failure, the first periodic write overwrote the
    unreadable file without rotating, and the next five rotations pushed
    every good copy out within about 180 s.
    """
    candidates = [path] + [path.with_name(f"{path.name}.{n}") for n in range(1, keep + 1)]
    present = [c for c in candidates if c.is_file()]
    if not present:
        return None
    failures: list[str] = []
    for candidate in present:
        try:
            n = load_into(state, candidate)
        except Exception as e:  # noqa: BLE001 - any loader failure moves the copy aside
            failures.append(f"{candidate.name}: {e}")
            _quarantine(candidate)
            state.reset_world()
            continue
        log.info("restored %d world actors from snapshot %s", n, candidate)
        if failures:
            log.warning("snapshot %s: loaded a rotated copy after %d unreadable file(s): %s",
                        path, len(failures), "; ".join(failures))
        _keep_last_good(candidate, path.with_name(f"{path.name}.lastgood"))
        return candidate
    if allow_empty_world:
        log.warning("no readable snapshot (%s): starting with an EMPTY world because "
                    "--allow-empty-world was given", "; ".join(failures))
        return None
    raise SnapshotUnreadable(
        "no readable snapshot: " + "; ".join(failures)
        + " (pass --allow-empty-world to start a new world on purpose)")


def _quarantine(bad: Path) -> None:
    for n in range(1, 1000):
        target = bad.with_name(f"{bad.name.split('.json')[0]}.json.corrupt.{n}")
        if not target.exists():
            try:
                bad.rename(target)
                log.warning("snapshot %s is unreadable, moved aside as %s", bad, target)
            except OSError as e:
                log.warning("snapshot %s is unreadable and could not be moved aside: %s", bad, e)
            return


def _keep_last_good(source: Path, target: Path) -> None:
    try:
        shutil.copyfile(str(source), str(target))
    except OSError as e:
        log.warning("could not keep a copy of the loaded snapshot at %s: %s", target, e)


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

    # The "server" section is informational. Configuration (tick rate, peer
    # timeout) comes from the command line and the code, never from the world
    # file: this block used to restore both, and a tuning knob that a boot
    # silently reverts is worse than a wrong value (a 5 s peer timeout pinned
    # over a 15 s default for a whole phase). Stage 0 of L5, 2026-09-27.
    server_cfg = data.get("server") or {}
    for key in ("tick_rate_hz", "peer_timeout_ms"):
        if key in server_cfg and server_cfg[key] != getattr(state, key):
            log.info("snapshot %s: %s=%s in the file, %s in this build (the build wins)",
                     path, key, server_cfg[key], getattr(state, key))

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
    # locks; v5 presence and resume tokens; v6 rekeys the containers; v7
    # adds the journal mark, quests, globals and hashed tokens; v8 the
    # inventory digests; v9 the checkpoints; v10 their custody; v11 the
    # instance of every container line. All readable — older missing
    # sections become empty. Unknown versions (> 11 or other) are rejected.
    if version not in (2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, SNAPSHOT_FORMAT_VERSION):
        raise ValueError(
            f"snapshot format version {version!r} unsupported "
            f"(expected {SNAPSHOT_FORMAT_VERSION}, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, or 1)"
        )

    # v7 — the journal mark. Older files carry none: lsn 0 means "replay
    # everything the journal holds", which is right for a journal that
    # started after the file was written and is said out loud by the boot
    # when it is not.
    journal_mark = data.get("journal") or {}
    try:
        state.applied_lsn = max(0, int(journal_mark.get("lsn", 0)))
    except (TypeError, ValueError):
        state.applied_lsn = 0

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

    # Restore container state. v3..v5 keyed containers by (base_id, cell_id)
    # and such a record cannot be mapped to one REFR (the old key merged every
    # twin of one base in one cell): those sections are dropped, loudly.
    container_skipped = 0
    frame_wear_stripped = 0   # 2026-10-05, see PA_FRAME_WEARABLES
    container_records = data.get("containers", []) or []
    if version < 6 and container_records:
        log.warning(
            "snapshot %s is format v%d: dropping %d container record(s) keyed "
            "by (base_id, cell_id). v6 keys containers by REFR form_id and the "
            "old records cannot be mapped to one REFR; the clients seed them "
            "again on the first open",
            path, version, len(container_records),
        )
        container_records = []
    for c in container_records:
        fid_raw = c.get("form_id")
        base_raw = c.get("base_id")
        cell_raw = c.get("cell_id")
        if fid_raw is None or base_raw is None or cell_raw is None:
            container_skipped += 1
            continue
        form_id = int(fid_raw, 16) if isinstance(fid_raw, str) else int(fid_raw)
        base_id = int(base_raw, 16) if isinstance(base_raw, str) else int(base_raw)
        cell_id = int(cell_raw, 16) if isinstance(cell_raw, str) else int(cell_raw)
        wid = int(c.get("wid", 0) or 0)
        if (form_id == 0 or base_id == 0 or cell_id == 0
                or (is_runtime_form_id(form_id)
                    and not (wid and form_id == wid_container_key(wid)))):
            container_skipped += 1
            continue
        # v11: [item, fp, count] lines. v6..v10: {item: count}, whose
        # instance nobody knows: FP_UNKNOWN lines (stage 4b).
        items_raw = c.get("items", {}) or {}
        triples: list[tuple[Any, Any, Any]] = []
        if isinstance(items_raw, dict):
            triples = [(k, FP_UNKNOWN, v) for k, v in items_raw.items()]
        else:
            triples = [tuple(t) for t in items_raw if isinstance(t, (list, tuple)) and len(t) == 3]
        items: dict[tuple[int, int], int] = {}
        for k, f, v in triples:
            try:
                iid = int(k, 16) if isinstance(k, str) else int(k)
                fp = int(f, 16) if isinstance(f, str) else int(f)
            except (TypeError, ValueError):
                continue
            if iid == 0:
                continue
            count = int(v)
            if count > COUNT_MAX:
                log.warning("snapshot %s: container 0x%X item 0x%X count %d clamped to %d",
                            path, form_id, iid, count, COUNT_MAX)
                count = COUNT_MAX
            if iid in PA_FRAME_WEARABLES:
                # 2026-10-05: the frame's body armour, loot in a crate made
                # before the rule; it is nobody's inventory.
                frame_wear_stripped += 1
                continue
            if count > 0:
                items[(iid, fp)] = count
        # 2026-10-20 (v15): the ops a partial record saw; a bad entry is dropped.
        pre_ops: list = []
        for e in (c.get("pre_seed_ops") or []):
            try:
                who, ms, kind, item, fp, cnt = e
                pre_ops.append((str(who), float(ms), int(kind),
                                int(item, 16) if isinstance(item, str) else int(item),
                                int(fp, 16) if isinstance(fp, str) else int(fp), int(cnt)))
            except (TypeError, ValueError):
                continue
        container = ContainerWorldState(
            form_id=form_id,
            base_id=base_id,
            cell_id=cell_id,
            items=items,
            last_owner_peer_id=c.get("last_owner"),
            last_update_ms=float(c.get("last_update_ms", 0.0)),
            seeded=bool(c.get("seeded", True)),
            wid=wid,
            # D2 (v14); a v13 file has neither: not a death crate as far as the map knows.
            death_owner=str(c.get("death_owner") or ""),
            death_ordinal=int(c.get("death_ordinal", 0) or 0),
            death_ms=int(c.get("death_ms", 0) or 0),
            pre_seed_ops=pre_ops[:PRE_SEED_OPS_MAX],
            pre_seed_overflow=bool(c.get("pre_seed_overflow", False)) or len(pre_ops) > PRE_SEED_OPS_MAX,
        )
        state._containers[form_id] = container
    # D2 (v14): the death crates made per peer.
    n_counts_bad = 0
    for peer, n in (data.get("death_counts", {}) or {}).items():
        try:
            state._restore_death_count(str(peer), int(n))
        except (TypeError, ValueError):
            n_counts_bad += 1
    if n_counts_bad:
        log.warning("snapshot %s: skipped %d bad death count entries", path, n_counts_bad)
    # 2026-10-20 (v15): the save each peer's world runs on and when it was
    # loaded; a bare number is both (nothing between them: no reconciliation).
    n_bases_bad = 0
    for peer, wb in (data.get("world_base_ms", {}) or {}).items():
        try:
            if isinstance(wb, (list, tuple)):
                state.note_world_base(str(peer), float(wb[0]), float(wb[1]))
            else:
                state.note_world_base(str(peer), float(wb), float(wb))
        except (TypeError, ValueError, IndexError):
            n_bases_bad += 1
    if n_bases_bad:
        log.warning("snapshot %s: skipped %d bad world base entries", path, n_bases_bad)
    if container_skipped:
        log.warning(
            "snapshot %s: skipped %d container entries with missing/zero identity",
            path, container_skipped,
        )

    # v11 — instance descriptors, back through the state's own validation
    # (a descriptor that does not make its fingerprint is not restored).
    n_inst_bad = 0
    for d in data.get("instances", []) or []:
        try:
            fp = int(d["fp"], 16) if isinstance(d["fp"], str) else int(d["fp"])
            item = int(d["item"], 16) if isinstance(d["item"], str) else int(d["item"])
            mods = tuple((int(m[0], 16) if isinstance(m[0], str) else int(m[0]),
                          int(m[1]), int(m[2])) for m in d.get("mods", []))
            desc = InstanceDescriptor(template=int(d.get("template", 0xFFFF)),
                                      flags=int(d.get("flags", 0)),
                                      health=float(d.get("health", -1.0)), mods=mods)
        except (KeyError, TypeError, ValueError, IndexError):
            n_inst_bad += 1
            continue
        was = state._replaying
        state.begin_replay()
        try:
            if not state.record_instance_def(item, fp, desc):
                n_inst_bad += 1
        finally:
            if not was:
                state.end_replay()
    if n_inst_bad:
        log.warning("snapshot %s: %d instance descriptor(s) not restored", path, n_inst_bad)

    # v12 - the players' inventory records, as they were written.
    def _hex(v) -> int:
        return int(v, 16) if isinstance(v, str) else int(v)
    n_players_bad = 0
    for r in data.get("players", []) or []:
        try:
            lines = {(_hex(l[0]), _hex(l[1])): int(l[2]) for l in r.get("lines", [])}
            equipped = {(_hex(e[0]), _hex(e[1])) for e in r.get("equipped", [])}
            # 2026-10-05: the frame's body armour out of a record written
            # before the rule.
            stale = [k for k in lines if k[0] in PA_FRAME_WEARABLES]
            for k in stale:
                del lines[k]
                equipped.discard(k)
            frame_wear_stripped += len(stale)
            pending = [(int(q[0]), int(q[1]), _hex(q[2]), _hex(q[3]), int(q[4]))
                       for q in r.get("pending", [])]
            if any(c <= 0 for c in lines.values()):
                raise ValueError("a line with no count")
            state._restore_player_inventory(
                str(r["peer_id"]), lines, equipped, int(r.get("session", 0)),
                int(r.get("seq", 0)), int(r.get("watermark", 0)),
                int(r.get("op_epoch", 0)), int(r.get("flags", 0)),
                _hex(r.get("digest", 0)), pending, int(r.get("captures", 0)),
                float(r.get("updated_ms", 0.0)), int(r.get("open_session", 0)))
        except (KeyError, TypeError, ValueError, IndexError):
            n_players_bad += 1
    if n_players_bad:
        log.warning("snapshot %s: %d player inventory record(s) not restored",
                    path, n_players_bad)
    if frame_wear_stripped:
        log.warning("snapshot %s: %d line(s) of a power armour frame's body armour "
                    "(ArmorPoweredFrame*) dropped from records and crates: never inventory",
                    path, frame_wear_stripped)

    # v13 - the players' numbers.
    n_stats_bad = 0
    for r in data.get("player_stats", []) or []:
        try:
            special = tuple(float(x) for x in r.get("special", []))
            if len(special) != 7:
                raise ValueError("SPECIAL")
            state._restore_player_stats(
                str(r["peer_id"]), session=int(r.get("session", 0)), seq=int(r.get("seq", 0)),
                level=int(r.get("level", 0)), xp=float(r.get("xp", 0.0)),
                perk_points=int(r.get("perk_points", 0)), special=special,
                health=float(r.get("health", 0.0)),
                action_points=float(r.get("action_points", 0.0)),
                rads=float(r.get("rads", 0.0)),
                perks={_hex(p[0]): int(p[1]) for p in r.get("perks", [])},
                captures=int(r.get("captures", 0)), updated_ms=float(r.get("updated_ms", 0.0)))
        except (KeyError, TypeError, ValueError, IndexError):
            n_stats_bad += 1
    if n_stats_bad:
        log.warning("snapshot %s: %d player stats record(s) not restored", path, n_stats_bad)

    # v7 — quests and globals. Restored through the state's own recorders
    # with the journal off (this is a load, not a new fact), so the same
    # validation applies as on the wire.
    was_replaying = state._replaying
    state.begin_replay()
    try:
        for q in data.get("quests", []) or []:
            try:
                raw_id = q["quest_form_id"]
                qid = int(raw_id, 16) if isinstance(raw_id, str) else int(raw_id)
                state.record_quest_stage(qid, int(q.get("stage", 0)),
                                         q.get("last_owner") or "",
                                         float(q.get("last_update_ms", 0.0)))
            except (KeyError, TypeError, ValueError):
                log.warning("snapshot %s: skipping malformed quest entry: %s", path, q)
        for g in data.get("globals", []) or []:
            try:
                raw_id = g["global_form_id"]
                gid = int(raw_id, 16) if isinstance(raw_id, str) else int(raw_id)
                state.record_global_var(gid, float(g.get("value", 0.0)),
                                        g.get("last_owner") or "",
                                        float(g.get("last_update_ms", 0.0)))
            except (KeyError, TypeError, ValueError):
                log.warning("snapshot %s: skipping malformed global entry: %s", path, g)
        # v8 — inventory digests, with their running count.
        for d in data.get("inv_digests", []) or []:
            try:
                raw = d["digest"]
                dig = int(raw, 16) if isinstance(raw, str) else int(raw)
                state.record_inv_digest(
                    str(d["peer_id"]), int(d.get("seq", 0)), int(d.get("wall_ms", 0)),
                    dig, int(d.get("entries", 0)), int(d.get("stacks", 0)),
                    int(d.get("items", 0)), int(d.get("reasons", 0)),
                    int(d.get("flags", 0)), int(d.get("why", 0)),
                    float(d.get("received_ms", 0.0)), count=int(d.get("count", 1)))
            except (KeyError, TypeError, ValueError):
                log.warning("snapshot %s: skipping malformed inv digest entry: %s", path, d)
        # v9 — checkpoints. The file lists them newest first; recording them
        # oldest first rebuilds the same order.
        for c in reversed(data.get("checkpoints", []) or []):
            try:
                raw = c.get("digest", 0)
                dig = int(raw, 16) if isinstance(raw, str) else int(raw)
                state.record_checkpoint(
                    str(c["peer_id"]), str(c.get("identity_hex", "")), int(c.get("seq", 0)),
                    str(c["name"]), str(c.get("sha256", "")), int(c.get("size", 0)), dig,
                    int(c.get("digest_seq", 0)), int(c.get("wall_ms", 0)),
                    float(c.get("received_ms", 0.0)), int(c.get("watermark_lsn", 0)),
                    int(c.get("reason", 0)), status=str(c.get("status", "provisional")),
                    boot_failures=int(c.get("boot_failures", 0)),
                    custody=bool(c.get("custody", False)),
                    in_pa=None if c.get("in_pa") is None else bool(c.get("in_pa")),
                    in_pa_wid=int(c.get("in_pa_wid", 0) or 0),
                    # v15; a v14 file has none: its own report's time, as before.
                    world_ms=None if c.get("world_ms") is None else float(c["world_ms"]))
            except (KeyError, TypeError, ValueError):
                log.warning("snapshot %s: skipping malformed checkpoint entry: %s", path, c)
    finally:
        if not was_replaying:
            state.end_replay()

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
            if "token_hash" in t:
                key = bytes.fromhex(str(t["token_hash"]))
            else:
                # v5/v6: the token itself. Hashed on the way in, so the
                # file that still holds it in clear can be rotated away.
                key = hashlib.sha256(bytes.fromhex(str(t["token"]))).digest()
            state._resume_tokens[key] = ResumeTicket(
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
    # L5 realtime D1: the counter as it was (absent before 2026-10-03).
    try:
        state.next_world_spawn_wid = max(state.next_world_spawn_wid,
                                         int(data.get("next_world_spawn_wid", 0) or 0))
    except (TypeError, ValueError):
        pass

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
