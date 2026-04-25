"""Tests for server/state.py: session lifecycle, rate tracker, world actor state."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from server.state import (  # noqa: E402
    ServerState, PeerSession, SessionState, RateTracker, ActorWorldState,
)
from protocol import ActorEventPayload, ActorEventKind  # noqa: E402


# ------------------------------------------------------------------ RateTracker

class TestRateTracker:
    def test_burst_allowed(self):
        r = RateTracker(capacity=5, refill_per_sec=1)
        for _ in range(5):
            assert r.consume(0.0) is True
        # Exhausted
        assert r.consume(0.0) is False

    def test_refill_over_time(self):
        r = RateTracker(capacity=10, refill_per_sec=10)
        for _ in range(10):
            assert r.consume(0.0)
        assert r.consume(0.0) is False
        # 500ms later, should have ~5 tokens
        for _ in range(4):
            assert r.consume(500.0) is True
        # Not quite 6
        # (Exact count depends on float math but should be within 1)

    def test_cannot_exceed_capacity(self):
        r = RateTracker(capacity=5, refill_per_sec=100)
        # Long time passed: should be capped at capacity, not 100s worth
        assert r.consume(1_000_000.0) is True  # 1 consumed
        assert r.consume(1_000_000.0) is True
        assert r.consume(1_000_000.0) is True
        assert r.consume(1_000_000.0) is True
        assert r.consume(1_000_000.0) is True
        assert r.consume(1_000_000.0) is False


# ------------------------------------------------------------------ ServerState

class TestSessionLifecycle:
    def test_accept_first_peer(self):
        s = ServerState()
        session, reason = s.accept_peer(("1.2.3.4", 5000), "alice", (1, 0), 100.0)
        assert session is not None
        assert reason == "ok"
        assert session.peer_id == "alice"
        assert session.state == SessionState.ACTIVE
        assert session.session_id == 1

    def test_session_ids_monotonic(self):
        s = ServerState()
        a, _ = s.accept_peer(("1.2.3.4", 5000), "alice", (1, 0), 100.0)
        b, _ = s.accept_peer(("1.2.3.4", 5001), "bob", (1, 0), 200.0)
        assert b.session_id == a.session_id + 1

    def test_peer_id_taken_rejects(self):
        s = ServerState()
        s.accept_peer(("1.2.3.4", 5000), "alice", (1, 0), 100.0)
        dup, reason = s.accept_peer(("1.2.3.4", 5001), "alice", (1, 0), 200.0)
        assert dup is None
        assert reason == "peer_id_taken"

    def test_peer_id_invalid(self):
        s = ServerState()
        for bad in ["", " spaced ", "bad!char", "x" * 20]:
            session, reason = s.accept_peer(("1.2.3.4", 5000), bad, (1, 0), 0.0)
            assert session is None
            assert reason == "peer_id_invalid"

    def test_version_major_mismatch_rejected(self):
        s = ServerState()
        session, reason = s.accept_peer(("1.2.3.4", 5000), "alice", (2, 0), 0.0)
        assert session is None
        assert reason == "version_mismatch"

    def test_same_addr_reconnect_replaces(self):
        s = ServerState()
        s.accept_peer(("1.2.3.4", 5000), "alice", (1, 0), 0.0)
        # Same addr (packet from same UDP endpoint) reclaims
        new, reason = s.accept_peer(("1.2.3.4", 5000), "alice2", (1, 0), 100.0)
        assert new is not None
        assert s.get_by_peer_id("alice") is None
        assert s.get_by_peer_id("alice2") is new

    def test_expire_stale(self):
        s = ServerState(peer_timeout_ms=1000.0)
        a, _ = s.accept_peer(("1.2.3.4", 5000), "alice", (1, 0), 0.0)
        b, _ = s.accept_peer(("1.2.3.4", 5001), "bob", (1, 0), 0.0)
        b.touch(1800.0)  # bob fresh at check time (delta=200 < 1000)
        stale = s.expire_stale(2000.0)
        assert len(stale) == 1
        assert stale[0].peer_id == "alice"
        assert s.get_by_peer_id("alice") is None
        assert s.get_by_peer_id("bob") is not None

    def test_other_sessions_excludes_self(self):
        s = ServerState()
        a, _ = s.accept_peer(("1.2.3.4", 5000), "alice", (1, 0), 0.0)
        b, _ = s.accept_peer(("1.2.3.4", 5001), "bob", (1, 0), 0.0)
        c, _ = s.accept_peer(("1.2.3.4", 5002), "carol", (1, 0), 0.0)
        others = s.other_sessions(a.addr)
        ids = {o.peer_id for o in others}
        assert ids == {"bob", "carol"}


# ------------------------------------------------------------------ World actors

class TestWorldActors:
    def test_spawn_then_kill(self):
        # World state is now keyed by (base_id, cell_id). The form_id is a
        # hint only — stable for placed refs, session-scoped for 0xFF______.
        s = ServerState()
        BASE = 0x20593        # NPC_ (stable)
        CELL = 0x1696A        # Sanctuary cell (stable)
        REF  = 0xFF001000     # runtime ref id (hint)
        evt_spawn = ActorEventPayload(
            kind=int(ActorEventKind.SPAWN),
            form_id=REF, actor_base_id=BASE,
            x=100.0, y=200.0, z=50.0, extra=0,
            cell_id=CELL,
        )
        s.record_actor_event(evt_spawn, "alice", 100.0)
        state = s.actor_state(BASE, CELL)
        assert state is not None
        assert state.alive is True
        assert state.last_known_form_id == REF

        evt_kill = ActorEventPayload(
            kind=int(ActorEventKind.KILL),
            form_id=REF, actor_base_id=BASE,
            x=0, y=0, z=0, extra=0, cell_id=CELL,
        )
        s.record_actor_event(evt_kill, "bob", 200.0)
        assert s.actor_state(BASE, CELL).alive is False
        assert s.actor_state(BASE, CELL).last_owner_peer_id == "bob"

    def test_enable_disable_toggle(self):
        s = ServerState()
        BASE = 0x1CA7D
        CELL = 0x1696A
        evt = ActorEventPayload(
            kind=int(ActorEventKind.DISABLE),
            form_id=0x1CA7D, actor_base_id=BASE,
            x=0, y=0, z=0, extra=0, cell_id=CELL,
        )
        s.record_actor_event(evt, "alice", 0.0)
        assert s.actor_state(BASE, CELL).alive is False

        evt = ActorEventPayload(
            kind=int(ActorEventKind.ENABLE),
            form_id=0x1CA7D, actor_base_id=BASE,
            x=0, y=0, z=0, extra=0, cell_id=CELL,
        )
        s.record_actor_event(evt, "alice", 100.0)
        assert s.actor_state(BASE, CELL).alive is True

    def test_event_without_identity_not_persisted(self):
        """Events lacking stable (base, cell) identity are NOT persisted.

        This is the exact bug we fixed with Option B: 0xFF______ runtime refs
        aliased across processes, so the server now refuses to record anything
        without a stable identity pair."""
        s = ServerState()
        evt = ActorEventPayload(
            kind=int(ActorEventKind.KILL),
            form_id=0xFF00136F,
            actor_base_id=0,   # <-- missing identity
            x=0, y=0, z=0, extra=0, cell_id=0,
        )
        result = s.record_actor_event(evt, "alice", 0.0)
        assert result is None
        assert s.all_actors() == []
