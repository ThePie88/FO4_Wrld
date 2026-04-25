"""Tests for server/validator.py"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from server.state import ServerState, PeerSession, SessionState, RateTracker  # noqa: E402
from server.validator import (  # noqa: E402
    validate_pos_state, validate_actor_event, RejectReason,
    MAX_SPEED_UNITS_PER_SEC, MIN_UPDATE_INTERVAL_MS,
)
from protocol import PosStatePayload, ActorEventPayload, ActorEventKind  # noqa: E402
from channel import ReliableChannel  # noqa: E402


def _make_session(peer_id: str = "alice") -> PeerSession:
    return PeerSession(
        session_id=1, peer_id=peer_id,
        addr=("1.2.3.4", 5000),
        client_version=(1, 0),
        state=SessionState.ACTIVE,
        joined_at_ms=0.0, last_seen_ms=0.0,
    )


class TestPosValidation:
    def test_first_update_accepted(self):
        s = _make_session()
        p = PosStatePayload(0, 0, 0, 0, 0, 0, 100)
        r = validate_pos_state(s, p, 0.0)
        assert r.ok

    def test_normal_walk_accepted(self):
        s = _make_session()
        s.last_pos = PosStatePayload(0, 0, 0, 0, 0, 0, 0)
        s.last_pos_at_ms = 0.0
        # 50 units in 50ms = 1000 u/s, within limits
        p = PosStatePayload(50, 0, 0, 0, 0, 0, 50)
        r = validate_pos_state(s, p, 50.0)
        assert r.ok

    def test_teleport_rejected(self):
        s = _make_session()
        s.last_pos = PosStatePayload(0, 0, 0, 0, 0, 0, 0)
        s.last_pos_at_ms = 0.0
        # 1_000_000 units in 50ms = 20M u/s, way over cap
        p = PosStatePayload(1_000_000, 0, 0, 0, 0, 0, 50)
        r = validate_pos_state(s, p, 50.0)
        assert not r.ok
        assert r.reason == RejectReason.SPEED_EXCEEDED

    def test_rate_limit_rejects_flood(self):
        s = _make_session()
        s.rate = RateTracker(capacity=3, refill_per_sec=1)
        # First 3 OK, 4th over rate
        for i in range(3):
            p = PosStatePayload(i * 10, 0, 0, 0, 0, 0, i * 30)
            r = validate_pos_state(s, p, i * 30.0)
            assert r.ok
            s.last_pos = p
            s.last_pos_at_ms = i * 30.0
        p = PosStatePayload(40, 0, 0, 0, 0, 0, 120)
        r = validate_pos_state(s, p, 120.0)
        assert not r.ok
        assert r.reason == RejectReason.RATE_LIMITED

    def test_timestamp_inversion_rejected(self):
        s = _make_session()
        s.last_pos = PosStatePayload(0, 0, 0, 0, 0, 0, 1000)
        s.last_pos_at_ms = 0.0
        # Incoming ts is older than last
        p = PosStatePayload(10, 0, 0, 0, 0, 0, 500)
        r = validate_pos_state(s, p, 50.0)
        assert not r.ok
        assert r.reason == RejectReason.TIMESTAMP_INVERTED

    def test_too_fast_repeat_rejected(self):
        s = _make_session()
        s.last_pos = PosStatePayload(0, 0, 0, 0, 0, 0, 0)
        s.last_pos_at_ms = 100.0
        # Sub-10ms interval
        p = PosStatePayload(1, 0, 0, 0, 0, 0, 105)
        r = validate_pos_state(s, p, 105.0)
        assert not r.ok
        assert r.reason == RejectReason.TOO_FAST_REPEAT


class TestActorEventValidation:
    def test_spawn_always_accepted(self):
        s = _make_session()
        evt = ActorEventPayload(
            kind=int(ActorEventKind.SPAWN), form_id=0x1000,
            actor_base_id=0x20593, x=0, y=0, z=0, extra=0,
        )
        r = validate_actor_event(s, evt, None, 0.0)
        assert r.ok

    def test_kill_on_unknown_actor_accepted_lazy(self):
        """Unknown actors are lazy-registered. Runtime-spawned refs (0xFF____)
        commonly aren't known to the server yet when they get killed."""
        s = _make_session()
        evt = ActorEventPayload(
            kind=int(ActorEventKind.KILL), form_id=0xFF001000,
            actor_base_id=0, x=0, y=0, z=0, extra=0,
        )
        r = validate_actor_event(s, evt, None, 0.0)
        assert r.ok

    def test_kill_on_dead_actor_rejected(self):
        from server.state import ActorWorldState
        s = _make_session()
        actor = ActorWorldState(base_id=0x20593, cell_id=0x1696A, alive=False)
        evt = ActorEventPayload(
            kind=int(ActorEventKind.KILL), form_id=0x1000,
            actor_base_id=0x20593, x=0, y=0, z=0, extra=0,
            cell_id=0x1696A,
        )
        r = validate_actor_event(s, evt, actor, 0.0)
        assert not r.ok
        assert r.reason == RejectReason.STATE_TRANSITION_INVALID

    def test_enable_on_alive_actor_rejected(self):
        from server.state import ActorWorldState
        s = _make_session()
        actor = ActorWorldState(base_id=0x20593, cell_id=0x1696A, alive=True)
        evt = ActorEventPayload(
            kind=int(ActorEventKind.ENABLE), form_id=0x1000,
            actor_base_id=0x20593, x=0, y=0, z=0, extra=0,
            cell_id=0x1696A,
        )
        r = validate_actor_event(s, evt, actor, 0.0)
        assert not r.ok


class TestNonFiniteCoordRejection:
    """POS_STATE containing NaN/Inf or huge coords must be rejected.

    Regression for the bug where a peer's Frida read the player singleton
    mid-save-load, got garbage floats, and shipped them to the server,
    which then broadcast them to the other peer — whose ghost actor got
    written with invalid coordinates and stopped rendering entirely.
    """

    def test_nan_x_rejected(self):
        s = _make_session()
        p = PosStatePayload(float("nan"), 0, 0, 0, 0, 0, 100)
        r = validate_pos_state(s, p, 0.0)
        assert not r.ok
        assert r.reason == RejectReason.NON_FINITE_COORD

    def test_inf_y_rejected(self):
        s = _make_session()
        p = PosStatePayload(0, float("inf"), 0, 0, 0, 0, 100)
        r = validate_pos_state(s, p, 0.0)
        assert not r.ok
        assert r.reason == RejectReason.NON_FINITE_COORD

    def test_huge_coord_rejected(self):
        s = _make_session()
        p = PosStatePayload(0, 0, 1e12, 0, 0, 0, 100)
        r = validate_pos_state(s, p, 0.0)
        assert not r.ok
        assert r.reason == RejectReason.NON_FINITE_COORD

    def test_nan_rotation_rejected(self):
        s = _make_session()
        p = PosStatePayload(0, 0, 0, float("nan"), 0, 0, 100)
        r = validate_pos_state(s, p, 0.0)
        assert not r.ok
        assert r.reason == RejectReason.NON_FINITE_COORD

    def test_normal_large_coord_accepted(self):
        """Diamond City is ~1e5 from origin — accept."""
        s = _make_session()
        p = PosStatePayload(150000, -50000, 1000, 0, 0, 0, 100)
        r = validate_pos_state(s, p, 0.0)
        assert r.ok


class TestGhostTargetExemption:
    """Ghost targets — actors used as multiplayer avatars in the rendering
    pipeline — must be immune from kill/disable events. Otherwise we reproduce
    exactly the bug that triggered Option B: a kill gets persisted, future
    sessions apply it at bootstrap, the ghost avatar vanishes, multiplayer
    rendering breaks."""

    # Base TESNPC of Codsworth (verified live via Frida kill hook,
    # 2026-04-19). The placed REFR is 0x1CA7D but the TESNPC record it
    # instantiates is 0x179FF — that's what the server exemption matches on.
    GHOST_BASE = 0x179FF
    GHOST_CELL = 0x1696A

    def test_kill_on_ghost_target_rejected(self):
        s = _make_session()
        evt = ActorEventPayload(
            kind=int(ActorEventKind.KILL),
            form_id=0xFF00136F,
            actor_base_id=self.GHOST_BASE,
            x=0, y=0, z=0, extra=0,
            cell_id=self.GHOST_CELL,
        )
        r = validate_actor_event(
            s, evt, None, 0.0,
            ghost_target_base_ids=frozenset({self.GHOST_BASE}),
        )
        assert not r.ok
        assert r.reason == RejectReason.GHOST_TARGET

    def test_disable_on_ghost_target_rejected(self):
        s = _make_session()
        evt = ActorEventPayload(
            kind=int(ActorEventKind.DISABLE),
            form_id=0xFF00136F,
            actor_base_id=self.GHOST_BASE,
            x=0, y=0, z=0, extra=0,
            cell_id=self.GHOST_CELL,
        )
        r = validate_actor_event(
            s, evt, None, 0.0,
            ghost_target_base_ids=frozenset({self.GHOST_BASE}),
        )
        assert not r.ok
        assert r.reason == RejectReason.GHOST_TARGET

    def test_enable_on_ghost_target_allowed(self):
        """ENABLE passes — useful for resurrecting a stuck avatar."""
        s = _make_session()
        evt = ActorEventPayload(
            kind=int(ActorEventKind.ENABLE),
            form_id=0xFF00136F,
            actor_base_id=self.GHOST_BASE,
            x=0, y=0, z=0, extra=0,
            cell_id=self.GHOST_CELL,
        )
        r = validate_actor_event(
            s, evt, None, 0.0,
            ghost_target_base_ids=frozenset({self.GHOST_BASE}),
        )
        assert r.ok

    def test_spawn_on_ghost_target_allowed(self):
        """SPAWN passes — first introduction of an avatar is fine."""
        s = _make_session()
        evt = ActorEventPayload(
            kind=int(ActorEventKind.SPAWN),
            form_id=0xFF00136F,
            actor_base_id=self.GHOST_BASE,
            x=0, y=0, z=0, extra=0,
            cell_id=self.GHOST_CELL,
        )
        r = validate_actor_event(
            s, evt, None, 0.0,
            ghost_target_base_ids=frozenset({self.GHOST_BASE}),
        )
        assert r.ok

    def test_non_ghost_base_not_affected(self):
        """A non-ghost base receiving a kill proceeds normally (subject to the
        rest of the validator rules)."""
        s = _make_session()
        evt = ActorEventPayload(
            kind=int(ActorEventKind.KILL),
            form_id=0xFF00136F,
            actor_base_id=0x20594,       # not in ghost set
            x=0, y=0, z=0, extra=0,
            cell_id=self.GHOST_CELL,
        )
        r = validate_actor_event(
            s, evt, None, 0.0,
            ghost_target_base_ids=frozenset({self.GHOST_BASE}),
        )
        assert r.ok

    def test_empty_ghost_set_is_pass_through(self):
        """Default behavior (no ghost set) must not change validator semantics."""
        s = _make_session()
        evt = ActorEventPayload(
            kind=int(ActorEventKind.KILL),
            form_id=0xFF00136F,
            actor_base_id=self.GHOST_BASE,
            x=0, y=0, z=0, extra=0,
            cell_id=self.GHOST_CELL,
        )
        r = validate_actor_event(s, evt, None, 0.0)
        assert r.ok  # no ghost set -> no exemption -> accept
