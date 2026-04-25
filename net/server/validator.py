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

from protocol import PosStatePayload, ActorEventPayload, ContainerOpPayload, ContainerOpKind  # noqa: E402
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

    container_state: the authoritative state for this container's identity
        (base_id, cell_id), or None if the server has never seen this
        container before. None is fine — TAKE on an unknown container is
        valid at v1 because clients may discover inventories independently
        (a loot run on a previously-unseen container). The server
        lazy-creates the entry via record_container_op.

    Rules:
      - Rate limit (shared token bucket)
      - Identity required (base_id != 0 AND cell_id != 0)
      - count > 0 (negative or zero never makes sense; TAKE uses OP direction)
      - kind must be TAKE or PUT
      - TAKE: if we know the container, reject if count > available (keeps
              clients honest; race between two takers is still possible
              but the loser gets rejected cleanly instead of clamping)

    PUT is always permissive (beyond basic checks) — adding items to a
    container shared with others is legitimate.
    """
    if not session.rate.consume(now_ms, amount=1.0):
        return ValidationResult.reject(RejectReason.RATE_LIMITED)

    if op.container_base_id == 0 or op.container_cell_id == 0:
        return ValidationResult.reject(
            RejectReason.MISSING_IDENTITY,
            f"container_base=0x{op.container_base_id:X} cell=0x{op.container_cell_id:X}",
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
    ENFORCE_INSUFFICIENT = True
    if (ENFORCE_INSUFFICIENT
            and op.kind == int(ContainerOpKind.TAKE)
            and container_state is not None):
        have = container_state.items.get(op.item_base_id, 0)
        if op.count > have:
            return ValidationResult.reject(
                RejectReason.INSUFFICIENT_ITEMS,
                f"take {op.count}, container has {have} of item 0x{op.item_base_id:X}",
            )

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
