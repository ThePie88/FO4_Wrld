"""
Server state: tracks all peer sessions and authoritative world state.

Pure data + mutation methods. No I/O, no asyncio here — main.py drives this.
"""
from __future__ import annotations

import itertools
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Optional

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from channel import ReliableChannel  # noqa: E402
from protocol import (  # noqa: E402
    MessageType, MAX_CLIENT_ID_LEN,
    WelcomePayload, PeerJoinPayload, PeerLeavePayload,
    PosStatePayload, ActorEventPayload,
    ContainerOpPayload, ContainerOpKind,
)


class SessionState(IntEnum):
    PENDING = 1   # received HELLO, WELCOME not yet acked
    ACTIVE = 2    # normal operation
    DEAD = 3      # timeout or disconnect, pending removal


# Token-bucket rate limiter: accept up to BURST packets, refill at RATE/sec
@dataclass(slots=True)
class RateTracker:
    capacity: int = 40            # burst allowance (2s at 20Hz pos + some events)
    refill_per_sec: float = 25.0  # steady-state tokens/sec
    _tokens: float = field(init=False, default=0.0)
    _last_refill_ms: Optional[float] = field(init=False, default=None)

    def __post_init__(self) -> None:
        # Bucket starts full so the first burst is allowed.
        self._tokens = float(self.capacity)

    def consume(self, now_ms: float, amount: float = 1.0) -> bool:
        """Try to consume `amount` tokens. Returns True if allowed, False if over rate."""
        self._refill(now_ms)
        if self._tokens < amount:
            return False
        self._tokens -= amount
        return True

    def _refill(self, now_ms: float) -> None:
        if self._last_refill_ms is None:
            self._last_refill_ms = now_ms
            return
        delta_s = max(0.0, (now_ms - self._last_refill_ms) / 1000.0)
        self._tokens = min(float(self.capacity),
                            self._tokens + delta_s * self.refill_per_sec)
        self._last_refill_ms = now_ms


@dataclass(slots=True)
class PeerSession:
    """One connected peer from the server's perspective."""

    session_id: int
    peer_id: str
    addr: tuple[str, int]
    client_version: tuple[int, int]
    state: SessionState
    joined_at_ms: float
    last_seen_ms: float

    channel: ReliableChannel = field(default_factory=ReliableChannel)
    rate: RateTracker = field(default_factory=RateTracker)

    # Tracking for validation + debug
    last_pos: Optional[PosStatePayload] = None
    last_pos_at_ms: float = 0.0
    total_pos_updates: int = 0
    total_events: int = 0

    def touch(self, now_ms: float) -> None:
        self.last_seen_ms = now_ms


@dataclass(slots=True)
class ContainerWorldState:
    """Authoritative inventory state for one container REFR.

    Identity key is (base_id, cell_id) — same stability rationale as
    ActorWorldState. The `items` dict maps item TESForm.formID -> count.
    Entries with count == 0 are eagerly removed (no stale zero keys).

    `last_known_form_id` is the latest observed REFR formid of the
    container; useful hint for client-side lookup but not an identity.
    """
    base_id: int
    cell_id: int
    items: dict[int, int] = field(default_factory=dict)   # item_base_id -> count
    last_known_form_id: int = 0
    last_owner_peer_id: Optional[str] = None
    last_update_ms: float = 0.0


@dataclass(slots=True)
class ActorWorldState:
    """Authoritative state for a game-world actor tracked by server.

    Identity key is (base_id, cell_id) — stable across processes.
    `last_known_form_id` is a hint: for placed refs (0x00______) it is stable
    and usable as a LookupByFormID fast-path on the client; for runtime refs
    (0xFF______) it's session-scoped and must be validated against
    (base_id, cell_id) before applying any state.
    """
    base_id: int                               # identity key part 1
    cell_id: int                               # identity key part 2
    alive: bool = True
    last_known_form_id: int = 0                # hint, not key
    last_owner_peer_id: Optional[str] = None   # who last modified it
    last_update_ms: float = 0.0


# B4: world-state replication (quest progress + global variables).
@dataclass(slots=True)
class QuestStageState:
    """Authoritative stage for one quest.

    Keyed by quest_form_id (stable plugin-loaded TESForm.formID). The engine
    enforces stage monotonicity at the Papyrus level (SetStage refuses to
    go backwards unless ResetQuest is called), so the validator treats
    last-write-wins as a valid best-effort. If a reset happens, it just
    broadcasts the lower number and all peers catch up.
    """
    quest_form_id: int
    stage: int = 0
    last_owner_peer_id: Optional[str] = None
    last_update_ms: float = 0.0


@dataclass(slots=True)
class LockWorldState:
    """B6.3 v0.5.3 — authoritative lock state for one REFR.

    Identity key is (base_id, cell_id) — same stability rationale as
    actor / container state. `form_id` is a hint for receiver-side
    LookupByFormID; not a key. `locked` is the boolean state. `level`
    and `key_form` are static world data and not tracked here (server
    only cares about state transitions).
    """
    base_id: int
    cell_id: int
    form_id: int = 0
    locked: bool = True
    timestamp_ms: int = 0


@dataclass(slots=True)
class GlobalVarState:
    """Authoritative value of one GlobalVariable (TESGlobal).

    Value stored as float — matches the engine's own internal representation
    (int-typed globals are floats rounded to int at Papyrus boundaries).
    """
    global_form_id: int
    value: float = 0.0
    last_owner_peer_id: Optional[str] = None
    last_update_ms: float = 0.0


@dataclass(slots=True)
class ServerState:
    """Total server-side state. Thread-unsafe — only one asyncio task may mutate."""

    tick_rate_hz: int = 20
    server_version: tuple[int, int] = (1, 0)
    peer_timeout_ms: float = 5_000.0

    # TESNPC base formIDs used as ghost avatars in the rendering layer.
    # Kill/disable events targeting these bases are rejected at the validator
    # to preserve the ghost pipeline. Resurrecting the avatar still works
    # (ENABLE/SPAWN pass through). Configurable at server construction.
    #
    # IMPORTANT: use the BASE (TESNPC) formID, NOT the REF (placed REFR).
    # For Codsworth on FO4 1.11.191 the pair is:
    #   ref  = 0x1CA7D (the placed reference in Sanctuary) — used client-side
    #                   for LookupByFormID to drive the ghost actor
    #   base = 0x179FF (the TESNPC "Codsworth" record in Fallout4.esm) —
    #                   used here for persistence exemption
    # Verified live via the Frida kill hook: kill on ref 0x1CA7D reports
    # base 0x179FF in its readRefIdentity() output.
    ghost_target_base_ids: frozenset[int] = frozenset({0x179FF})

    _sessions_by_addr: dict[tuple[str, int], PeerSession] = field(default_factory=dict)
    _sessions_by_peer_id: dict[str, PeerSession] = field(default_factory=dict)
    _session_id_counter: "itertools.count[int]" = field(
        default_factory=lambda: itertools.count(1)
    )
    # Primary index: identity tuple (base_id, cell_id) -> world state.
    # Never index by form_id directly — ref IDs alias across processes for
    # runtime (0xFF______) refs. See step 1 of Option B for rationale.
    _world_actors: dict[tuple[int, int], ActorWorldState] = field(default_factory=dict)
    # Parallel index for container inventories, same keying scheme.
    _containers: dict[tuple[int, int], ContainerWorldState] = field(default_factory=dict)
    # B4: quest stages, keyed by quest_form_id.
    _quests: dict[int, QuestStageState] = field(default_factory=dict)
    # B4: global variables, keyed by global_form_id.
    _globals: dict[int, GlobalVarState] = field(default_factory=dict)
    # B6.3 v0.5.3: lock states keyed by (base_id, cell_id).
    lock_state: dict[tuple[int, int], LockWorldState] = field(default_factory=dict)

    # ---------------------------------------------------------- session mgmt

    def accept_peer(
        self,
        addr: tuple[str, int],
        peer_id: str,
        client_version: tuple[int, int],
        now_ms: float,
    ) -> tuple[Optional[PeerSession], str]:
        """Register a new peer. Returns (session, reason). session=None if rejected.

        Reasons for rejection:
        - "peer_id_taken": ID already used by an active peer
        - "peer_id_invalid": bad format
        - "version_mismatch": major version different from server
        """
        if not peer_id or len(peer_id) > MAX_CLIENT_ID_LEN:
            return (None, "peer_id_invalid")
        if not peer_id.isascii() or not all(c.isalnum() or c in "_-" for c in peer_id):
            return (None, "peer_id_invalid")

        # If same addr already has session (reconnection with same IP:port), replace it
        existing = self._sessions_by_addr.get(addr)
        if existing is not None:
            self._remove_session(existing)

        # Check peer_id uniqueness
        if peer_id in self._sessions_by_peer_id:
            return (None, "peer_id_taken")

        # Version check: same major required
        if client_version[0] != self.server_version[0]:
            return (None, "version_mismatch")

        session = PeerSession(
            session_id=next(self._session_id_counter),
            peer_id=peer_id,
            addr=addr,
            client_version=client_version,
            state=SessionState.ACTIVE,
            joined_at_ms=now_ms,
            last_seen_ms=now_ms,
        )
        self._sessions_by_addr[addr] = session
        self._sessions_by_peer_id[peer_id] = session
        return (session, "ok")

    def get_by_addr(self, addr: tuple[str, int]) -> Optional[PeerSession]:
        return self._sessions_by_addr.get(addr)

    def get_by_peer_id(self, peer_id: str) -> Optional[PeerSession]:
        return self._sessions_by_peer_id.get(peer_id)

    def all_sessions(self) -> list[PeerSession]:
        return list(self._sessions_by_addr.values())

    def other_sessions(self, exclude_addr: tuple[str, int]) -> list[PeerSession]:
        return [s for s in self._sessions_by_addr.values() if s.addr != exclude_addr]

    def expire_stale(self, now_ms: float) -> list[PeerSession]:
        """Remove peers not heard from in peer_timeout_ms. Returns removed sessions."""
        stale: list[PeerSession] = []
        for s in list(self._sessions_by_addr.values()):
            if now_ms - s.last_seen_ms > self.peer_timeout_ms:
                stale.append(s)
                self._remove_session(s)
        return stale

    def remove(self, peer_id: str) -> Optional[PeerSession]:
        """Force-remove a peer by id. Returns the removed session or None."""
        s = self._sessions_by_peer_id.get(peer_id)
        if s is not None:
            self._remove_session(s)
        return s

    def _remove_session(self, s: PeerSession) -> None:
        self._sessions_by_addr.pop(s.addr, None)
        self._sessions_by_peer_id.pop(s.peer_id, None)
        s.state = SessionState.DEAD

    # ---------------------------------------------------------- game state

    def record_actor_event(
        self, event: ActorEventPayload, by_peer_id: str, now_ms: float
    ) -> Optional[ActorWorldState]:
        """Apply an ActorEvent to the authoritative world state.

        Returns the updated ActorWorldState, or None if the event lacked
        a stable identity (base_id=0 or cell_id=0). Events without identity
        are not persisted — they may still be broadcast by the caller, but
        they won't survive a server restart.
        """
        if event.actor_base_id == 0 or event.cell_id == 0:
            return None
        # ActorEventKind: SPAWN=1, KILL=2, DISABLE=3, ENABLE=4
        key = (event.actor_base_id, event.cell_id)
        actor = self._world_actors.get(key)
        if actor is None:
            actor = ActorWorldState(
                base_id=event.actor_base_id,
                cell_id=event.cell_id,
                alive=True,
            )
            self._world_actors[key] = actor
        if event.kind == 1:       # SPAWN
            actor.alive = True
        elif event.kind == 2:     # KILL
            actor.alive = False
        elif event.kind == 3:     # DISABLE
            actor.alive = False
        elif event.kind == 4:     # ENABLE
            actor.alive = True
        actor.last_known_form_id = event.form_id
        actor.last_owner_peer_id = by_peer_id
        actor.last_update_ms = now_ms
        return actor

    def actor_state(self, base_id: int, cell_id: int) -> Optional[ActorWorldState]:
        """Identity-keyed lookup."""
        if base_id == 0 or cell_id == 0:
            return None
        return self._world_actors.get((base_id, cell_id))

    def actor_state_for_event(
        self, event: ActorEventPayload
    ) -> Optional[ActorWorldState]:
        """Resolve the stored state matching this event's identity. Returns
        None if the event lacks identity (base/cell = 0) OR if the identity
        has never been seen before."""
        return self.actor_state(event.actor_base_id, event.cell_id)

    def all_actors(self) -> list[ActorWorldState]:
        return list(self._world_actors.values())

    # ---------------------------------------------------------- container state

    def record_container_op(
        self, op: ContainerOpPayload, by_peer_id: str, now_ms: float
    ) -> Optional[ContainerWorldState]:
        """Apply a TAKE/PUT op to authoritative container state.

        Returns the updated ContainerWorldState, or None if:
        - op lacks stable identity (base=0 or cell=0)
        - op.count <= 0 (invalid — must be positive even for TAKE)
        - kind unknown

        Semantics:
          TAKE: decrement items[item_base_id] by count. If result <= 0,
                remove the key entirely (no stale zeros). If the container
                doesn't have that item or insufficient count, the op is
                still RECORDED (last-write-wins) but clamped to 0 — the
                validator upstream should have rejected truly invalid ones.
          PUT:  increment items[item_base_id] by count.
        """
        if op.container_base_id == 0 or op.container_cell_id == 0:
            return None
        if op.count <= 0:
            return None
        if op.kind not in (int(ContainerOpKind.TAKE), int(ContainerOpKind.PUT)):
            return None

        key = (op.container_base_id, op.container_cell_id)
        container = self._containers.get(key)
        if container is None:
            container = ContainerWorldState(
                base_id=op.container_base_id,
                cell_id=op.container_cell_id,
            )
            self._containers[key] = container

        # Trust-the-client policy for MVP: the server has no way to seed
        # container contents from the save file, so a TAKE against an
        # unknown-to-server item is interpreted as "the client observed
        # at least `count` of this item before the take; after the take,
        # 0 remain". No reject. PUT is straightforward additive.
        item_is_new = op.item_base_id not in container.items
        current = container.items.get(op.item_base_id, 0)
        if op.kind == int(ContainerOpKind.TAKE):
            if item_is_new:
                # First time we observe this item. Assume had exactly `count`,
                # now has 0.
                new_count = 0
            else:
                new_count = max(0, current - op.count)
        else:  # PUT
            new_count = current + op.count

        if new_count == 0:
            container.items.pop(op.item_base_id, None)
        else:
            container.items[op.item_base_id] = new_count

        container.last_owner_peer_id = by_peer_id
        container.last_update_ms = now_ms
        return container

    def container_state(
        self, base_id: int, cell_id: int
    ) -> Optional[ContainerWorldState]:
        """Identity-keyed container lookup."""
        if base_id == 0 or cell_id == 0:
            return None
        return self._containers.get((base_id, cell_id))

    def container_state_for_op(
        self, op: ContainerOpPayload
    ) -> Optional[ContainerWorldState]:
        return self.container_state(op.container_base_id, op.container_cell_id)

    def all_containers(self) -> list[ContainerWorldState]:
        return list(self._containers.values())

    # ---------------------------------------------------------- quests (B4)

    def record_quest_stage(
        self, quest_form_id: int, stage: int, by_peer_id: str, now_ms: float
    ) -> Optional[QuestStageState]:
        """Apply a quest SetStage to authoritative state.

        Returns the updated QuestStageState, or None if quest_form_id is 0.

        Semantics: last-write-wins. We do NOT enforce monotonicity at the
        server because ResetQuest legitimately drops the stage. The engine
        on each peer enforces sane transitions at the Papyrus layer; our
        job is to replicate what actually happened.
        """
        if quest_form_id == 0:
            return None
        if not (0 <= stage <= 0xFFFF):
            return None
        q = self._quests.get(quest_form_id)
        if q is None:
            q = QuestStageState(quest_form_id=quest_form_id)
            self._quests[quest_form_id] = q
        q.stage = stage
        q.last_owner_peer_id = by_peer_id
        q.last_update_ms = now_ms
        return q

    def quest_stage(self, quest_form_id: int) -> Optional[QuestStageState]:
        return self._quests.get(quest_form_id) if quest_form_id else None

    def all_quest_stages(self) -> list[QuestStageState]:
        return list(self._quests.values())

    # ---------------------------------------------------------- globals (B4)

    def record_global_var(
        self, global_form_id: int, value: float, by_peer_id: str, now_ms: float
    ) -> Optional[GlobalVarState]:
        """Apply a GlobalVariable.SetValue to authoritative state.

        Returns the updated GlobalVarState, or None if global_form_id is 0
        or value is not finite (NaN/Inf). Last-write-wins.
        """
        if global_form_id == 0:
            return None
        import math
        if not math.isfinite(value):
            return None
        g = self._globals.get(global_form_id)
        if g is None:
            g = GlobalVarState(global_form_id=global_form_id)
            self._globals[global_form_id] = g
        g.value = value
        g.last_owner_peer_id = by_peer_id
        g.last_update_ms = now_ms
        return g

    def global_var(self, global_form_id: int) -> Optional[GlobalVarState]:
        return self._globals.get(global_form_id) if global_form_id else None

    def all_globals(self) -> list[GlobalVarState]:
        return list(self._globals.values())

    # ---------------------------------------------------------- locks (B6.3)

    def all_locks(self) -> list[LockWorldState]:
        return list(self.lock_state.values())

    # ---------------------------------------------------------- convenience

    def welcome_for(self, session: PeerSession) -> WelcomePayload:
        return WelcomePayload(
            session_id=session.session_id,
            accepted=True,
            server_version_major=self.server_version[0],
            server_version_minor=self.server_version[1],
            tick_rate_hz=self.tick_rate_hz,
        )

    def peer_join_for(self, session: PeerSession) -> PeerJoinPayload:
        return PeerJoinPayload(peer_id=session.peer_id, session_id=session.session_id)

    def peer_leave_for(self, session: PeerSession, reason: int = 0) -> PeerLeavePayload:
        return PeerLeavePayload(peer_id=session.peer_id, reason=reason)
