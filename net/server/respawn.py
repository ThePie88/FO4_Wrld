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
        int(state.applied_lsn), CKPT_REASON_FIRST_ENTRY)
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
                            exterior_globals: Optional[dict[int, bytes]] = None
                            ) -> CheckpointRecord:
    """Book a copy of the player's boot checkpoint moved onto `point` as the
    player's newest checkpoint, its bytes in custody. A power armour frame
    the player wears in it moves with them (savepos); a checkpoint written in
    an interior gets the sky of `exterior_globals` (savepos.exterior_sky of the
    genesis save) and is refused without it. RespawnError when the
    source is not in custody, does not match its record, is not a save
    savepos can move, or its frame disagrees with the inventory digest;
    nothing is written or booked then."""
    src: Optional[CheckpointRecord] = state.checkpoint_to_boot(peer_id)
    if src is None:
        raise RespawnError(f"{peer_id} has no checkpoint to move")
    if not src.custody:
        raise RespawnError(f"'{src.name}' of {peer_id} is not in custody")
    got = store.read(peer_id, src.name)
    if got is None:
        raise RespawnError(f"'{src.name}' of {peer_id} is booked in custody but not on disk")
    data, manifest = got
    if hashlib.sha256(data).hexdigest() != src.sha256_hex:
        raise RespawnError(f"'{src.name}' of {peer_id} on disk does not match its record")
    try:
        moved = move_player(data, point.x, point.y, point.z, point.yaw, point.worldspace,
                            expect_worn_frame=checkpoint_in_power_armour(state, peer_id),
                            exterior_globals=exterior_globals)
    except SaveFormatError as e:
        raise RespawnError(f"'{src.name}' of {peer_id} cannot be moved: {e}") from e

    taken = {r.name for r in state.checkpoints(peer_id)} | set(store.names(peer_id))
    name = _name_for(peer_id, now_ms, taken)
    if not name_is_sane(name):
        raise RespawnError(f"'{name}' is not a name custody accepts")
    sha = hashlib.sha256(moved).hexdigest()
    store.store(peer_id, name, moved, manifest, sha)
    rec = state.record_checkpoint(
        peer_id, src.identity_hex, src.seq, name, sha, len(moved), src.digest,
        src.digest_seq, src.wall_ms, now_ms, src.watermark_lsn, CKPT_REASON_RESPAWN)
    if rec is None:
        store.delete(peer_id, name)
        raise RespawnError(f"the record for '{name}' was refused")
    state.set_checkpoint_custody(peer_id, name, sha, now_ms)
    gone = store.keep_only(peer_id, {r.name for r in state.checkpoints(peer_id)})
    log.info("respawn: '%s' of %s moved to (%.1f, %.1f, %.1f) yaw %.2f -> '%s' (%d bytes, "
             "sha %s...), booked as the newest checkpoint, in custody; %d old file(s) pruned",
             src.name, peer_id, point.x, point.y, point.z, point.yaw, name, len(moved),
             sha[:12], gone)
    return rec
