"""L5 stage 3d (2026-09-29) — the server moves a player by writing a checkpoint.

The owner's design: the respawn point is the server founder's choice, and a
dead player comes back there through the reload of a checkpoint the server
has already moved onto the point. The engine loads it like any other save:
one loading screen, the destination loaded by the load itself, no fast
travel afterwards (the fast travel after a reload kept the engine's loading
screen up for 116 and 339 s on the live tests of 2026-09-28/29).

make_respawn_checkpoint takes the checkpoint the player's next boot would
load, rewrites the player's position inside a copy of it (savepos), and
books the copy as the player's newest checkpoint: same character state, so
the same inventory digest and the same journal watermark; its bytes in
custody, where the client fetches them; the world manifest of the source
copied with it, because the objects of ours saved inside are the same ones.

Nothing is changed unless every step succeeds: the copy is written and
booked only after it read back the new position, and a failure leaves the
player's books exactly as they were (the caller falls back to what it did
before this stage existed).
"""
from __future__ import annotations

import hashlib
import logging
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from server.custody import CustodyStore, name_is_sane
from server.savepos import COMMONWEALTH, SaveFormatError, WornFrame, move_player, read_worn_frame
from server.state import CheckpointRecord, ServerState
from protocol import INV_DIGEST_FLAG_IN_POWER_ARMOR

log = logging.getLogger("server.respawn")

# The reason byte of a checkpoint the server wrote itself. The client-side
# reasons are 0-3 (protocol.CKPT_REASON); these never travel on the wire.
CKPT_REASON_RESPAWN = 4
CKPT_REASON_FIRST_ENTRY = 5


@dataclass(frozen=True)
class RespawnPoint:
    x: float
    y: float
    z: float
    yaw: float
    worldspace: int = COMMONWEALTH


class RespawnError(RuntimeError):
    """The moved checkpoint could not be made. The books are unchanged."""


def _name_for(peer_id: str, now_ms: float, taken: set[str]) -> str:
    """The client's own naming scheme, fwck_<peer>_<date>_<time>, so its
    rotation of the last three treats the copy like any checkpoint. A second
    is added while the name is already taken."""
    t = now_ms / 1000.0
    for _ in range(120):
        name = "fwck_%s_%s" % (peer_id, time.strftime("%Y%m%d_%H%M%S", time.localtime(t)))
        if name not in taken:
            return name
        t += 1.0
    raise RespawnError("no free checkpoint name in two minutes of seconds")


def checkpoint_in_power_armour(state: ServerState, peer_id: str) -> Optional[bool]:
    """Whether the player's boot checkpoint has them inside a power armour
    frame: the inventory digest sent with that checkpoint carries the bit.
    None when the last digest is not that checkpoint's."""
    src = state.checkpoint_to_boot(peer_id)
    inv = state.inv_digest(peer_id)
    if src is None or inv is None or inv.seq != src.digest_seq:
        return None
    return bool(inv.flags & INV_DIGEST_FLAG_IN_POWER_ARMOR)


def checkpoint_worn_frame(store: Optional[CustodyStore], peer_id: str,
                          rec: Optional[CheckpointRecord]) -> tuple[bool, Optional[WornFrame]]:
    """(known, frame): the power armour frame the player saved in `rec`
    wears, read from the bytes in custody (savepos: the player's
    ExtraPowerArmor link), or None when on foot. known is False when that
    cannot be read: no store or record, not in custody, the bytes missing
    or not the record's, or a save savepos cannot read."""
    if store is None or rec is None or not rec.custody:
        return False, None
    got = store.read(peer_id, rec.name)
    if got is None:
        return False, None
    data = got[0]
    if hashlib.sha256(data).hexdigest() != rec.sha256_hex:
        return False, None
    try:
        return True, read_worn_frame(data)
    except SaveFormatError:
        return False, None


def checkpoint_wears_frame(store: Optional[CustodyStore], peer_id: str,
                           rec: Optional[CheckpointRecord]) -> Optional[bool]:
    """Whether the player saved in `rec` wears a power armour frame; None
    when it cannot be known (checkpoint_worn_frame)."""
    known, frame = checkpoint_worn_frame(store, peer_id, rec)
    return (frame is not None) if known else None


def worn_frame_fid(frame: WornFrame) -> int:
    """The form id the client knows the saved worn frame by: a runtime
    reference (savepos only reports those), 0xFF000000 plus the refid's
    22-bit value (the frame 0xFF00139F is saved as refid 0x80139F)."""
    return 0xFF000000 | (frame.refid & 0x3FFFFF)


def make_first_checkpoint(state: ServerState, store: CustodyStore, peer_id: str,
                          identity_hex: str, genesis: bytes, point: RespawnPoint,
                          now_ms: float) -> CheckpointRecord:
    """L5 stage 3d (2026-09-30) — the first checkpoint of a new character:
    the genesis save (the one a client boots without a checkpoint) moved
    onto the founder's point, booked as the player's only checkpoint, in
    custody. The client boots it like any checkpoint, so a new character
    starts on the point instead of where the genesis save was written. The
    genesis has no objects of ours (an empty world manifest), no inventory
    digest the server knows (0) and the journal head as its watermark.
    RespawnError when the genesis cannot be moved or booked; nothing is
    written or booked then."""
    try:
        moved = move_player(genesis, point.x, point.y, point.z, point.yaw, point.worldspace,
                            expect_worn_frame=False)
    except SaveFormatError as e:
        raise RespawnError(f"the genesis save cannot be moved: {e}") from e
    taken = {r.name for r in state.checkpoints(peer_id)} | set(store.names(peer_id))
    name = _name_for(peer_id, now_ms, taken)
    if not name_is_sane(name):
        raise RespawnError(f"'{name}' is not a name custody accepts")
    sha = hashlib.sha256(moved).hexdigest()
    store.store(peer_id, name, moved, b"# fwworld 1 " + name.encode("ascii") + b"\n", sha)
    rec = state.record_checkpoint(
        peer_id, identity_hex, 0, name, sha, len(moved), 0, 0, int(now_ms), now_ms,
        int(state.applied_lsn), CKPT_REASON_FIRST_ENTRY,
        world_ms=0.0)   # 2026-10-20: the genesis world, no op of anyone in it
    if rec is None:
        store.delete(peer_id, name)
        raise RespawnError(f"the record for '{name}' was refused")
    state.set_checkpoint_custody(peer_id, name, sha, now_ms)
    log.info("first entry: the genesis save moved to (%.1f, %.1f, %.1f) yaw %.2f -> '%s' "
             "(%d bytes, sha %s...), booked as the first checkpoint of %s, in custody",
             point.x, point.y, point.z, point.yaw, name, len(moved), sha[:12], peer_id)
    return rec


def make_respawn_checkpoint(state: ServerState, store: CustodyStore, peer_id: str,
                            point: RespawnPoint, now_ms: float,
                            exterior_globals: Optional[dict[int, bytes]] = None,
                            genesis_path: Optional[Path] = None,
                            identity_hex: str = "") -> CheckpointRecord:
    """Book a copy of a checkpoint of the player moved onto `point` as the
    player's newest checkpoint, its bytes in custody.

    L5 realtime D1 (2026-10-04, the owner's rule): a death leaves a worn
    frame where the player fell, complete, and the player comes back ON
    FOOT, so the source is the newest checkpoint that has them on foot: the
    record's flag (in_pa, from the inventory digest sent with it) says,
    the save's bytes when the flag is unknown; one in a frame, not in
    custody, not on disk, not matching its record or unreadable is passed
    over. With none on foot the genesis save (`genesis_path`, the server's)
    moved onto the point stands in: the record brings the inventory and the
    numbers back (R1-R4), what that save held besides them starts over. A
    checkpoint written in an interior gets the sky of `exterior_globals`
    (savepos.exterior_sky of the genesis save) and is refused without it.
    RespawnError when nothing can be moved; nothing is written or booked
    then."""
    cands = [r for r in state.checkpoints(peer_id) if r.boot_failures < 2]
    src: Optional[CheckpointRecord] = None
    data = manifest = b""
    passed: list[str] = []
    for r in cands:
        if r.in_pa is True:
            passed.append(f"'{r.name}' has them in power armour")
            continue
        if not r.custody:
            passed.append(f"'{r.name}' is not in custody")
            continue
        got = store.read(peer_id, r.name)
        if got is None:
            passed.append(f"'{r.name}' is booked in custody but not on disk")
            continue
        if hashlib.sha256(got[0]).hexdigest() != r.sha256_hex:
            passed.append(f"'{r.name}' on disk does not match its record")
            continue
        if r.in_pa is None:
            try:
                worn = read_worn_frame(got[0])
            except SaveFormatError as e:
                passed.append(f"'{r.name}' cannot be read: {e}")
                continue
            if worn is not None:
                passed.append(f"'{r.name}' has them in power armour (the save says)")
                continue
        src, (data, manifest) = r, got
        break
    why = "; ".join(passed) if passed else "no checkpoint at all"
    if src is None:
        if genesis_path is None:
            raise RespawnError(f"no checkpoint of {peer_id} has them on foot ({why}) and this "
                               "server has no genesis save")
        try:
            genesis = genesis_path.read_bytes()
            moved = move_player(genesis, point.x, point.y, point.z, point.yaw, point.worldspace,
                                expect_worn_frame=False)
        except (OSError, SaveFormatError) as e:
            raise RespawnError(f"no checkpoint of {peer_id} has them on foot ({why}) and the "
                               f"genesis save cannot stand in: {e}") from e
        newest = cands[0] if cands else None
        ident = identity_hex or (newest.identity_hex if newest is not None else "")
        seq, digest, digest_seq, wall_ms = 0, 0, 0, int(now_ms)
        watermark = int(state.applied_lsn)
        manifest = b"# fwworld 1 genesis\n"
        source = "the genesis save"
    else:
        try:
            moved = move_player(data, point.x, point.y, point.z, point.yaw, point.worldspace,
                                expect_worn_frame=False, exterior_globals=exterior_globals)
        except SaveFormatError as e:
            raise RespawnError(f"'{src.name}' of {peer_id} cannot be moved: {e}") from e
        ident = src.identity_hex
        seq, digest, digest_seq, wall_ms = src.seq, src.digest, src.digest_seq, src.wall_ms
        watermark = src.watermark_lsn
        source = f"'{src.name}'"

    taken = {r.name for r in state.checkpoints(peer_id)} | set(store.names(peer_id))
    name = _name_for(peer_id, now_ms, taken)
    if not name_is_sane(name):
        raise RespawnError(f"'{name}' is not a name custody accepts")
    sha = hashlib.sha256(moved).hexdigest()
    store.store(peer_id, name, moved, manifest, sha)
    rec = state.record_checkpoint(
        peer_id, ident, seq, name, sha, len(moved), digest, digest_seq, wall_ms, now_ms,
        watermark, CKPT_REASON_RESPAWN, in_pa=False,
        # 2026-10-20: the copy carries the source's world (the genesis: none).
        world_ms=src.world_ms if src is not None else 0.0)
    if rec is None:
        store.delete(peer_id, name)
        raise RespawnError(f"the record for '{name}' was refused")
    state.set_checkpoint_custody(peer_id, name, sha, now_ms)
    gone = store.keep_only(peer_id, {r.name for r in state.checkpoints(peer_id)})
    if src is None:
        log.warning("respawn: no checkpoint of %s has them on foot (%s): the genesis save moved "
                    "onto the point stands in as '%s' (%d bytes, sha %s...); the record brings "
                    "the inventory and the numbers back, the rest of that save starts over; %d "
                    "old file(s) pruned", peer_id, why, name, len(moved), sha[:12], gone)
    else:
        log.info("respawn: %s of %s%s moved to (%.1f, %.1f, %.1f) yaw %.2f -> '%s' (%d bytes, "
                 "sha %s...), booked as the newest checkpoint, in custody; %d old file(s) pruned",
                 source, peer_id, f" (passed over: {why})" if passed else "",
                 point.x, point.y, point.z, point.yaw, name, len(moved), sha[:12], gone)
    return rec
