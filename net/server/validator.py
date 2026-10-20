"""
Validation rules for incoming client messages.

Pure functions: given (session, payload, now_ms) return ValidationResult.
Used both for anti-cheat and to prevent client-desync from poisoning server state.

Thresholds configurable at module level — tune based on game physics.
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from enum import IntEnum
from typing import Optional

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from protocol import (  # noqa: E402
    WorldItemOpPayload, WORLD_ITEM_DROP, WORLD_ITEM_PICKUP, WORLD_SPAWN_FLAG_CONTAINER,
    PosStatePayload, ActorEventPayload, ContainerOpPayload, ContainerOpKind,
    is_runtime_form_id,
    identities_conflict,
    COUNT_MAX,
    FP_UNKNOWN, INSTANCE_MAX_MODS, instance_fp,
    InvStatePayload, INV_STATE_FLAG_COMPLETE,
    PlayerStatsPayload, STATS_FLAG_COMPLETE, SPECIAL_COUNT, STATS_MAX_PERKS,
)
from server.state import PeerSession, ContainerWorldState  # noqa: E402


# ------------------------------------------------------------------ thresholds

# FO4 world units: 1 unit ≈ 1.428cm. Sprinting player ≈ 500 units/s.
# Cap at 5x sprint to allow for teleport-like moveto/setpos without rejecting.
MAX_SPEED_UNITS_PER_SEC: float = 2500.0

# Z delta per second (falling/jumping). FO4 gravity ≈ 800 units/s^2.
MAX_VERTICAL_DELTA_PER_SEC: float = 5000.0

# Minimum time between updates — protection against flood even if rate bucket fails
MIN_UPDATE_INTERVAL_MS: float = 20.0  # 50Hz hard cap


class RejectReason(IntEnum):
    OK                       = 0
    RATE_LIMITED             = 1
    SPEED_EXCEEDED           = 2
    TIMESTAMP_INVERTED       = 3
    VERTICAL_EXCEEDED        = 4
    TOO_FAST_REPEAT          = 5
    UNKNOWN_ACTOR            = 6
    STATE_TRANSITION_INVALID = 7
    EVENT_FROM_WRONG_OWNER   = 8
    GHOST_TARGET             = 9   # kill/disable on a protected ghost-avatar actor
    NON_FINITE_COORD         = 10  # NaN/Inf/huge in position — peer reading uninit memory
    MISSING_IDENTITY         = 11  # container op with base_id=0 or cell_id=0
    INVALID_COUNT            = 12  # container op with count <= 0
    INVALID_KIND             = 13  # unknown op kind / actor event kind
    INSUFFICIENT_ITEMS       = 14  # TAKE more than the container has (upstream check)
    RUNTIME_REF              = 15  # container op on a 0xFF______ ref: its id aliases across processes
    IDENTITY_MISMATCH        = 16  # known REFR with another (base, cell): load-order drift
    COUNT_OVERFLOW           = 17  # PUT would push a line past the i32 the wire packs
    INSTANCE_MISMATCH        = 18  # container op whose descriptor does not make its fingerprint
    INV_STATE_INVALID        = 19  # player inventory capture: incomplete, bad line or bad chunking
    STATS_STATE_INVALID      = 20  # player stats capture: incomplete, a number or a perk the wire cannot mean


@dataclass(frozen=True, slots=True)
class ValidationResult:
    ok: bool
    reason: RejectReason
    detail: str = ""

    @classmethod
    def accept(cls) -> "ValidationResult":
        return cls(True, RejectReason.OK, "")

    @classmethod
    def reject(cls, reason: RejectReason, detail: str = "") -> "ValidationResult":
        return cls(False, reason, detail)


# ------------------------------------------------------------------ validators


def validate_pos_state(
    session: PeerSession, incoming: PosStatePayload, now_ms: float
) -> ValidationResult:
    """Check a POS_STATE update against session history + physics bounds."""

    # Rate limit via token bucket
    if not session.rate.consume(now_ms):
        return ValidationResult.reject(RejectReason.RATE_LIMITED,
                                       f"peer {session.peer_id}")

    # Finite + bounded sanity check on every scalar. A peer whose Frida read
    # the player singleton mid-save-load can ship NaN/Inf or garbage floats.
    # We must not relay those — writing them to the far peer's ghost actor
    # disables its rendering (observed in live Option B validation).
    coords = (incoming.x, incoming.y, incoming.z,
              incoming.rx, incoming.ry, incoming.rz)
    if not all(math.isfinite(v) for v in coords) or \
       any(abs(v) > 1e7 for v in (incoming.x, incoming.y, incoming.z)):
        return ValidationResult.reject(
            RejectReason.NON_FINITE_COORD,
            f"coords={coords!r}",
        )

    # First update: accept unconditionally (bootstrap baseline)
    if session.last_pos is None:
        return ValidationResult.accept()

    # Time since last update
    dt_ms = now_ms - session.last_pos_at_ms
    if dt_ms < MIN_UPDATE_INTERVAL_MS:
        return ValidationResult.reject(
            RejectReason.TOO_FAST_REPEAT,
            f"dt={dt_ms:.1f}ms < min={MIN_UPDATE_INTERVAL_MS}",
        )
    dt_s = dt_ms / 1000.0

    # Timestamp sanity: incoming.timestamp_ms should be non-decreasing
    if incoming.timestamp_ms < session.last_pos.timestamp_ms:
        return ValidationResult.reject(
            RejectReason.TIMESTAMP_INVERTED,
            f"incoming {incoming.timestamp_ms} < last {session.last_pos.timestamp_ms}",
        )

    # B6 prologue (v11, 2026-05-08) — cell-change teleport bypass.
    # When the player crosses a cell boundary the engine moves them via
    # MoveTo, often hundreds of thousands of units in a single frame
    # (interior cells use a coordinate frame near origin while exterior
    # is e.g. Sanctuary at ~(-76000, 93000, 7700) — delta ~120k units).
    # That registers as ~2.4M u/s through the speed gate below and gets
    # rejected as a cheat, dropping every POS_STATE forever after (since
    # session.last_pos stays at the pre-teleport value, every fresh
    # interior pos still computes a huge delta vs that stale baseline).
    # When the wire cell_id changes between two consecutive POS_STATE
    # frames, treat the new pos as a legitimate transition and accept it
    # as the new baseline. Both fields must be non-zero (pre-v11 senders
    # leave them at 0 and we keep the standard speed gate for them).
    cell_changed = (
        incoming.cell_id != 0
        and session.last_pos.cell_id != 0
        and incoming.cell_id != session.last_pos.cell_id
    )
    if cell_changed:
        return ValidationResult.accept()

    # 3D displacement
    dx = incoming.x - session.last_pos.x
    dy = incoming.y - session.last_pos.y
    dz = incoming.z - session.last_pos.z
    dist = math.sqrt(dx * dx + dy * dy + dz * dz)
    speed = dist / dt_s

    if speed > MAX_SPEED_UNITS_PER_SEC:
        return ValidationResult.reject(
            RejectReason.SPEED_EXCEEDED,
            f"speed={speed:.0f} u/s, dt={dt_ms:.0f}ms, d={dist:.0f}",
        )

    # Vertical-only check (e.g., teleport straight up)
    vspeed = abs(dz) / dt_s
    if vspeed > MAX_VERTICAL_DELTA_PER_SEC:
        return ValidationResult.reject(
            RejectReason.VERTICAL_EXCEEDED,
            f"v_speed={vspeed:.0f}",
        )

    return ValidationResult.accept()


def validate_container_op(
    session: PeerSession,
    op: ContainerOpPayload,
    container_state: Optional[ContainerWorldState],
    now_ms: float,
) -> ValidationResult:
    """Check a CONTAINER_OP for validity.

    container_state: the authoritative state for this container's REFR
        (op.container_form_id), or None if the server has never seen this
        container before. None is fine — TAKE on an unknown container is
        valid at v1 because clients may discover inventories independently
        (a loot run on a previously-unseen container). The server
        lazy-creates the entry via record_container_op.

    Rules:
      - Rate limit (shared token bucket)
      - Identity required: form_id != 0 and not a runtime ref (0xFF prefix,
        loot rework L1), base_id != 0 AND cell_id != 0
      - A known REFR must come with the (base, cell) it was recorded with:
        anything else is a load-order drift between two clients
      - count > 0 (negative or zero never makes sense; TAKE uses OP direction)
      - kind must be TAKE or PUT
      - TAKE: if we know the container, reject if count > available (keeps
              clients honest; race between two takers is still possible
              but the loser gets rejected cleanly instead of clamping)

    PUT is always permissive (beyond basic checks) — adding items to a
    container shared with others is legitimate.
    """
    # Stage 0 of L5 (2026-09-27): item ops meter their own bucket, not the
    # one the 20 Hz position stream drains (see PeerSession.item_rate).
    if not session.item_rate.consume(now_ms, amount=1.0):
        return ValidationResult.reject(RejectReason.RATE_LIMITED)

    if (op.container_form_id == 0 or op.container_base_id == 0
            or op.container_cell_id == 0):
        return ValidationResult.reject(
            RejectReason.MISSING_IDENTITY,
            f"container_form=0x{op.container_form_id:X} "
            f"base=0x{op.container_base_id:X} cell=0x{op.container_cell_id:X}",
        )
    if is_runtime_form_id(op.container_form_id):
        # L5 realtime D1: an 0xFF key names a container of the server's (the
        # death crate, keyed by its world spawn) or nothing. Its identity is
        # the wid: the base must match, the cell is wherever each client's
        # copy landed.
        if container_state is None or not container_state.wid:
            return ValidationResult.reject(
                RejectReason.RUNTIME_REF,
                f"container_form=0x{op.container_form_id:X} is a runtime ref",
            )
        if container_state.base_id != op.container_base_id:
            return ValidationResult.reject(
                RejectReason.IDENTITY_MISMATCH,
                f"container 0x{op.container_form_id:X} (wid {container_state.wid}) is base "
                f"0x{container_state.base_id:X}, op says 0x{op.container_base_id:X}",
            )
    elif container_state is not None and identities_conflict(
            container_state.base_id, container_state.cell_id,
            op.container_base_id, op.container_cell_id):
        return ValidationResult.reject(
            RejectReason.IDENTITY_MISMATCH,
            f"container_form=0x{op.container_form_id:X} recorded as "
            f"(base=0x{container_state.base_id:X} cell=0x{container_state.cell_id:X}), "
            f"op says (base=0x{op.container_base_id:X} cell=0x{op.container_cell_id:X})",
        )
    if op.count <= 0:
        return ValidationResult.reject(
            RejectReason.INVALID_COUNT,
            f"count={op.count}",
        )
    if op.kind not in (int(ContainerOpKind.TAKE), int(ContainerOpKind.PUT)):
        return ValidationResult.reject(
            RejectReason.INVALID_KIND,
            f"kind={op.kind}",
        )

    # L5 stage 4b (2026-10-03): the fingerprint names the instance, the
    # descriptor is how the others will build it, and the two must agree: a
    # plain fingerprint with a modded descriptor, or a descriptor of another
    # instance, would make the other clients build something nobody moved.
    # An unknown fingerprint carries no descriptor worth checking.
    if op.item_fp != FP_UNKNOWN:
        if (len(op.instance.mods) > INSTANCE_MAX_MODS
                or instance_fp(op.item_base_id, op.instance) != op.item_fp):
            return ValidationResult.reject(
                RejectReason.INSTANCE_MISMATCH,
                f"item 0x{op.item_base_id:X} fp=0x{op.item_fp:016X} does not match "
                f"its descriptor",
            )

    # B1.h.4 (2026-04-21): INSUFFICIENT_ITEMS REJECT RE-ENABLED.
    #
    # History:
    #   - B1.h.3 (2026-04-20) disabled this check because the DLL's
    #     scan_container_inventory was walking only the runtime
    #     BGSInventoryList at REFR+0xF8 and missing base CONT entries,
    #     producing incomplete SEEDs, under-counted server state, and
    #     spurious REJ_INSUFFICIENT on legitimate TAKEs. Trust-client
    #     (B0-style) was the correct emergency regression at that time.
    #   - B1.j.1 landed the force_materialize_inventory call pre-scan,
    #     so the runtime list is guaranteed populated before SEED emission.
    #   - The formType-LVLI filter bug that dropped legitimate items from
    #     the scan was removed in B1.j.1 as well.
    #   - B1.g + B1.k.3.3 (2026-04-21) closed the apply-on-receiver and
    #     PUT-capture loops end-to-end (live validated with 10+ items,
    #     both menu paths, persistent+normal forms).
    #
    # With SEEDs now complete and BCAST apply reliable, the preconditions
    # that motivated the B1.h.3 rollback no longer hold. Re-enabling
    # enforcement closes the dup race: two peers TAKEing the same item
    # concurrently produce one ACCEPTED (first to be validated) and one
    # REJ_INSUFFICIENT (race loser). No duplication.
    #
    # If a future regression reintroduces bogus INSUFFICIENT rejections,
    # set ENFORCE_INSUFFICIENT = False here and investigate the SEED
    # correctness before re-enabling.
    #
    # Loot rework L3 (2026-09-23): a record the server only INFERRED from a
    # first op (not seeded, see ContainerWorldState.seeded) does not know
    # the container's other items; a take of one of those is trusted, as
    # the very first op was. A seeded record knows them all: absent means
    # gone.
    #
    # L5 stage 4b: the count is the one of the lines this take may draw from
    # (its own instance and the base's unknown line), not the base's: a take
    # of an instance the record does not hold is a phantom on the client,
    # even when another instance of the same base is there. That was the
    # swap measured in 4a.
    ENFORCE_INSUFFICIENT = True
    if (ENFORCE_INSUFFICIENT
            and op.kind == int(ContainerOpKind.TAKE)
            and container_state is not None
            and (container_state.seeded
                 or any(k in container_state.items
                        for k in container_state.take_order(op.item_base_id, op.item_fp)))):
        have = container_state.available_for(op.item_base_id, op.item_fp)
        if op.count > have:
            return ValidationResult.reject(
                RejectReason.INSUFFICIENT_ITEMS,
                f"take {op.count}, container has {have} of item 0x{op.item_base_id:X} "
                f"instance 0x{op.item_fp:016X}",
            )

    # Stage 0 of L5 (2026-09-27): a line can never grow past what the wire
    # packs. Two console deposits of 2e9 caps made a 4e9 record whose ACK and
    # CONTAINER_STATE raised inside the join bootstrap for every joiner.
    if op.kind == int(ContainerOpKind.PUT):
        have = (container_state.count_of(op.item_base_id, op.item_fp)
                if container_state is not None else 0)
        if have + op.count > COUNT_MAX:
            return ValidationResult.reject(
                RejectReason.COUNT_OVERFLOW,
                f"put {op.count} on {have} of item 0x{op.item_base_id:X} "
                f"exceeds {COUNT_MAX}",
            )

    return ValidationResult.accept()


def validate_world_item_op(op: WorldItemOpPayload, spawn, persistent_objects: int
                           ) -> ValidationResult:
    """L5 realtime R1b (2026-10-05): a WORLD_ITEM_OP, a Pip-Boy drop that has
    come to rest or a pickup from the world. `spawn` is the server's object
    for op.wid (None when it names none), `persistent_objects` how many the
    world holds.

    No rate bucket, by decision: a refusal is undone on the client, and a
    pickup undone is an item destroyed, so a refusal must mean something
    about the world, never about the pace; the reliable channel has its own
    ceiling.

    Rules:
      - kind DROP or PICKUP; item != 0; 1 <= count <= COUNT_MAX
      - a named instance must make its fingerprint (as a container op)
      - DROP: the new REFR and its cell named; room for one more persistent
        object (1024)
      - PICKUP of a wid: the server must still hold it (otherwise someone
        else took it first: INSUFFICIENT_ITEMS, the client destroys its
        copy), it must not be a crate or a worn frame, and its base must be
        the op's
      - PICKUP of a REFR of the save: its cell named; a runtime REFR nobody
        knows is trusted
    """
    if op.kind not in (WORLD_ITEM_DROP, WORLD_ITEM_PICKUP):
        return ValidationResult.reject(RejectReason.INVALID_KIND, f"kind={op.kind}")
    if op.item_base_id == 0:
        return ValidationResult.reject(RejectReason.MISSING_IDENTITY, "item 0")
    if not (1 <= op.count <= COUNT_MAX):
        return ValidationResult.reject(RejectReason.INVALID_COUNT, f"count={op.count}")
    if op.item_fp != FP_UNKNOWN:
        if (len(op.instance.mods) > INSTANCE_MAX_MODS
                or instance_fp(op.item_base_id, op.instance) != op.item_fp):
            return ValidationResult.reject(
                RejectReason.INSTANCE_MISMATCH,
                f"item 0x{op.item_base_id:X} fp=0x{op.item_fp:016X} does not match its descriptor")
    if op.kind == WORLD_ITEM_DROP:
        if op.ref_form_id == 0 or op.cell_id == 0:
            return ValidationResult.reject(
                RejectReason.MISSING_IDENTITY,
                f"drop of 0x{op.item_base_id:X}: ref=0x{op.ref_form_id:X} cell=0x{op.cell_id:X}")
        if persistent_objects >= 1024:
            return ValidationResult.reject(
                RejectReason.COUNT_OVERFLOW, "1024 persistent objects already stored")
        return ValidationResult.accept()
    if op.wid:
        if spawn is None:
            return ValidationResult.reject(
                RejectReason.INSUFFICIENT_ITEMS,
                f"wid {op.wid} is nobody's: already taken, or never recorded")
        if spawn.flags & WORLD_SPAWN_FLAG_CONTAINER:
            return ValidationResult.reject(
                RejectReason.IDENTITY_MISMATCH, f"wid {op.wid} is a crate of the server's")
        if spawn.worn_by_peer_id:
            return ValidationResult.reject(
                RejectReason.IDENTITY_MISMATCH,
                f"wid {op.wid} is a frame worn by {spawn.worn_by_peer_id}")
        if spawn.base_form_id != op.item_base_id:
            return ValidationResult.reject(
                RejectReason.IDENTITY_MISMATCH,
                f"wid {op.wid} is base 0x{spawn.base_form_id:X}, op says 0x{op.item_base_id:X}")
        return ValidationResult.accept()
    if op.ref_form_id == 0:
        return ValidationResult.reject(RejectReason.MISSING_IDENTITY, "pickup of no REFR")
    if not is_runtime_form_id(op.ref_form_id) and op.cell_id == 0:
        return ValidationResult.reject(
            RejectReason.MISSING_IDENTITY,
            f"pickup of REFR 0x{op.ref_form_id:X} of the save without its cell")
    return ValidationResult.accept()


def validate_actor_event(
    session: PeerSession,
    event: ActorEventPayload,
    actor_state,
    now_ms: float,
    *,
    ghost_target_base_ids: "Optional[frozenset[int]]" = None,
) -> ValidationResult:
    """Check an ACTOR_EVENT. Rejects impossible transitions.

    actor_state: Optional[ActorWorldState] — current server-authoritative state
                 for event's identity, or None if unknown.

    ghost_target_base_ids: set of TESNPC base formIDs used as ghost avatars
        (default: none). Kill/disable events targeting these bases are
        silently rejected — they'd break the ghost rendering pipeline and
        cause exactly the bug Option B was built to prevent. SPAWN and ENABLE
        are allowed (no harm; may even be useful to resurrect a stuck avatar).
    """
    if not session.rate.consume(now_ms, amount=1.0):
        return ValidationResult.reject(RejectReason.RATE_LIMITED)

    # Protect ghost-target bases from destructive events. We check BEFORE the
    # SPAWN early-return because SPAWN on a ghost target is fine; only KILL
    # (kind=2) and DISABLE (kind=3) need to be stopped.
    if ghost_target_base_ids and event.actor_base_id in ghost_target_base_ids:
        if event.kind in (2, 3):  # KILL or DISABLE
            return ValidationResult.reject(
                RejectReason.GHOST_TARGET,
                f"base 0x{event.actor_base_id:X} is a ghost-avatar target "
                f"(kind={event.kind})",
            )

    # SPAWN events can always proceed (server may reject duplicates downstream)
    if event.kind == 1:  # SPAWN
        return ValidationResult.accept()

    # KILL/DISABLE on unknown actor -> accept (lazy-register as known, side effect
    # of record_actor_event). This handles client-side kills on runtime-spawned
    # refids (0xFF_______ range) that the server hasn't seen before.
    # ENABLE on unknown -> also accept (no-op essentially).
    if actor_state is None:
        return ValidationResult.accept()

    # KILL a dead actor -> redundant, reject
    if event.kind == 2 and not actor_state.alive:
        return ValidationResult.reject(
            RejectReason.STATE_TRANSITION_INVALID,
            "kill on already-dead actor",
        )
    # ENABLE an already alive actor -> redundant, reject
    if event.kind == 4 and actor_state.alive:
        return ValidationResult.reject(
            RejectReason.STATE_TRANSITION_INVALID,
            "enable on already-alive actor",
        )

    return ValidationResult.accept()


# L5 realtime R1 (2026-10-03): one capture spans at most this many frames
# (64 x 80 = 5120 lines, far beyond any inventory the capture can read).
INV_STATE_MAX_CHUNKS: int = 64


def validate_inv_state(payload: InvStatePayload) -> ValidationResult:
    """One chunk of a player's inventory capture. An incomplete capture is
    never a record (the client never sends one; a forged one must not become
    a fact), and neither is a line the wire cannot mean: a count outside 1..
    COUNT_MAX, item 0, or a chunk outside its declared capture."""
    def bad(detail: str) -> ValidationResult:
        return ValidationResult.reject(RejectReason.INV_STATE_INVALID, detail)
    if not (payload.flags & INV_STATE_FLAG_COMPLETE):
        return bad("capture not complete")
    if payload.session == 0:
        return bad("session 0")
    if not (1 <= payload.total_chunks <= INV_STATE_MAX_CHUNKS):
        return bad(f"total_chunks {payload.total_chunks}")
    if payload.chunk_index >= payload.total_chunks:
        return bad(f"chunk {payload.chunk_index} of {payload.total_chunks}")
    for e in payload.entries:
        if e.item_base_id == 0:
            return bad("item 0")
        if not (1 <= e.count <= COUNT_MAX):
            return bad(f"count {e.count} of 0x{e.item_base_id:X}")
    return ValidationResult.accept()


def validate_stats_state(payload: PlayerStatsPayload) -> ValidationResult:
    """One chunk of a player's stats capture (L5 realtime R4). Refused: an
    incomplete capture, session 0, a number that is not finite, a SPECIAL
    list that is not seven values, a perk 0 or of rank 0, a chunk outside
    its declared capture."""
    def bad(detail: str) -> ValidationResult:
        return ValidationResult.reject(RejectReason.STATS_STATE_INVALID, detail)
    if not (payload.flags & STATS_FLAG_COMPLETE):
        return bad("capture not complete")
    if payload.session == 0:
        return bad("session 0")
    if not (1 <= payload.total_chunks <= INV_STATE_MAX_CHUNKS):
        return bad(f"total_chunks {payload.total_chunks}")
    if payload.chunk_index >= payload.total_chunks:
        return bad(f"chunk {payload.chunk_index} of {payload.total_chunks}")
    numbers = (payload.xp, payload.health, payload.action_points, payload.rads) + tuple(payload.special)
    if len(payload.special) != SPECIAL_COUNT or not all(math.isfinite(x) for x in numbers):
        return bad("a number that is not finite, or not seven SPECIAL values")
    if len(payload.perks) > STATS_MAX_PERKS:
        return bad(f"{len(payload.perks)} perks")
    for pe in payload.perks:
        if pe.perk_form_id == 0 or pe.rank == 0:
            return bad(f"perk 0x{pe.perk_form_id:X} rank {pe.rank}")
    return ValidationResult.accept()
