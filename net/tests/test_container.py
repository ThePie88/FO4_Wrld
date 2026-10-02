"""Container sync tests: protocol + server state + validator + persistence + e2e."""
from __future__ import annotations

import asyncio
import json
import socket
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from protocol import (  # noqa: E402
    MessageType,
    ContainerOpPayload, ContainerBroadcastPayload,
    ContainerStatePayload, ContainerStateEntry,
    ContainerSeedPayload,
    ContainerOpKind, HelloPayload,
    identities_conflict, NPC_DEATH_FLAG_REPLAY,
    ContainerOpAckPayload, ContainerOpAckStatus,
    AckPayload,
    encode_frame, decode_frame,
)
from server.state import ServerState, ContainerWorldState, PeerSession, SessionState, RateTracker  # noqa: E402
from server.validator import (  # noqa: E402
    validate_container_op, RejectReason,
)
from server.persistence import (  # noqa: E402
    snapshot, load_into, SNAPSHOT_FORMAT_VERSION,
)
from server.main import ServerProtocol  # noqa: E402
from client.main import FalloutWorldClient, ClientConfig  # noqa: E402
from client.frida_bridge import ContainerCapture  # noqa: E402


# ------------------------------------------------------------------ helpers

def _session(peer_id: str = "alice") -> PeerSession:
    return PeerSession(
        session_id=1, peer_id=peer_id,
        addr=("1.2.3.4", 5000), client_version=(1, 0),
        state=SessionState.ACTIVE,
        joined_at_ms=0.0, last_seen_ms=0.0,
    )


# Canonical identity tuple used throughout the tests: Steamer Trunk in
# Sanctuary house. Base + cell are pure fixtures (not the actual FO4 IDs).
TRUNK_BASE = 0xDEAD01
TRUNK_CELL = 0x1696A
STIMPAK = 0x23736
AMMO_10MM = 0x4585E
# The placed REFR ids of the trunk and of a twin container that shares its
# base and cell (two identical toolboxes in one house). Placed ids are stable
# across processes with the same load order; the twin is exactly what the
# (base_id, cell_id) key of the first loot system merged into one record.
TRUNK_FID = 0x1F3A2
TWIN_FID = 0x1F3A3


def _put(fid: int, item: int, count: int) -> ContainerOpPayload:
    return ContainerOpPayload(
        kind=int(ContainerOpKind.PUT), container_form_id=fid,
        container_base_id=TRUNK_BASE, container_cell_id=TRUNK_CELL, item_base_id=item,
        count=count, timestamp_ms=0,
    )


def _take(fid: int, item: int, count: int, op_id: int = 0) -> ContainerOpPayload:
    return ContainerOpPayload(
        kind=int(ContainerOpKind.TAKE), container_form_id=fid,
        container_base_id=TRUNK_BASE, container_cell_id=TRUNK_CELL, item_base_id=item,
        count=count, timestamp_ms=0, client_op_id=op_id,
    )


def _seeded(state: ServerState, fid: int, items: dict[int, int],
            by: str = "seeder", now_ms: float = 0.0) -> ContainerWorldState:
    """A record the server KNOWS, as a client's full scan makes it. Ops on
    a container nobody scanned only make a partial record (loot rework L3),
    which is trusted item by item and never pushed to clients."""
    c = state.create_container(fid, TRUNK_BASE, TRUNK_CELL, items, by, now_ms)
    assert c is not None
    return c


# ------------------------------------------------------------------ protocol roundtrip

class TestProtocol:
    def test_op_roundtrip(self):
        p = ContainerOpPayload(
            kind=int(ContainerOpKind.TAKE),
            container_base_id=TRUNK_BASE, container_cell_id=TRUNK_CELL,
            container_form_id=TRUNK_FID,
            item_base_id=STIMPAK, count=3, timestamp_ms=123456789,
        )
        raw = encode_frame(MessageType.CONTAINER_OP, 7, p, reliable=True)
        f = decode_frame(raw)
        assert f.payload == p

    def test_bcast_roundtrip(self):
        b = ContainerBroadcastPayload(
            peer_id="player_X", kind=int(ContainerOpKind.PUT),
            container_base_id=TRUNK_BASE, container_cell_id=TRUNK_CELL,
            container_form_id=TRUNK_FID,
            item_base_id=AMMO_10MM, count=50, timestamp_ms=111,
        )
        raw = encode_frame(MessageType.CONTAINER_BCAST, 12, b, reliable=True)
        f = decode_frame(raw)
        assert f.payload == b

    def test_state_chunk_roundtrip(self):
        entries = tuple(
            ContainerStateEntry(TRUNK_FID, TRUNK_BASE, TRUNK_CELL, STIMPAK + i, 1 + i)
            for i in range(10)
        )
        s = ContainerStatePayload(entries=entries, chunk_index=1, total_chunks=3)
        raw = encode_frame(MessageType.CONTAINER_STATE, 99, s, reliable=True)
        f = decode_frame(raw)
        assert f.payload == s


# ------------------------------------------------------------------ server state

class TestServerState:
    def test_put_accumulates(self):
        s = ServerState()
        p = ContainerOpPayload(
            kind=int(ContainerOpKind.PUT),
            container_base_id=TRUNK_BASE, container_cell_id=TRUNK_CELL,
            container_form_id=TRUNK_FID,
            item_base_id=STIMPAK, count=5, timestamp_ms=0,
        )
        s.record_container_op(p, "alice", 100.0)
        s.record_container_op(p, "alice", 200.0)
        st = s.container_state(TRUNK_FID)
        assert st.items == {STIMPAK: 10}
        assert st.last_owner_peer_id == "alice"

    def test_take_decrements_then_removes_at_zero(self):
        s = ServerState()
        s.record_container_op(ContainerOpPayload(
            kind=int(ContainerOpKind.PUT),
            container_base_id=TRUNK_BASE, container_cell_id=TRUNK_CELL,
            container_form_id=TRUNK_FID,
            item_base_id=STIMPAK, count=7, timestamp_ms=0,
        ), "alice", 0.0)
        # take 3 leaves 4
        s.record_container_op(ContainerOpPayload(
            kind=int(ContainerOpKind.TAKE),
            container_base_id=TRUNK_BASE, container_cell_id=TRUNK_CELL,
            container_form_id=TRUNK_FID,
            item_base_id=STIMPAK, count=3, timestamp_ms=0,
        ), "bob", 0.0)
        assert s.container_state(TRUNK_FID).items == {STIMPAK: 4}
        # take remaining 4 -> zero -> key gone
        s.record_container_op(ContainerOpPayload(
            kind=int(ContainerOpKind.TAKE),
            container_base_id=TRUNK_BASE, container_cell_id=TRUNK_CELL,
            container_form_id=TRUNK_FID,
            item_base_id=STIMPAK, count=4, timestamp_ms=0,
        ), "bob", 0.0)
        assert s.container_state(TRUNK_FID).items == {}

    def test_record_rejects_missing_identity(self):
        s = ServerState()
        p = ContainerOpPayload(
            kind=int(ContainerOpKind.PUT),
            container_base_id=0, container_cell_id=TRUNK_CELL,
            container_form_id=TRUNK_FID,
            item_base_id=STIMPAK, count=1, timestamp_ms=0,
        )
        assert s.record_container_op(p, "alice", 0.0) is None

    def test_record_rejects_nonpositive_count(self):
        s = ServerState()
        p = ContainerOpPayload(
            kind=int(ContainerOpKind.PUT),
            container_base_id=TRUNK_BASE, container_cell_id=TRUNK_CELL,
            container_form_id=TRUNK_FID,
            item_base_id=STIMPAK, count=0, timestamp_ms=0,
        )
        assert s.record_container_op(p, "alice", 0.0) is None

    def test_first_take_unknown_container_trusts_client(self):
        """Regression for the live A.9 bug: the first TAKE of an item the
        server has never seen (because save-seeding isn't wired) must
        succeed — the server assumes the client's view (had >= count,
        now 0). Without this, all in-game take events after the first in
        a session get rejected."""
        s = ServerState()
        # First TAKE of item X on brand-new container
        op1 = ContainerOpPayload(
            kind=int(ContainerOpKind.TAKE),
            container_base_id=TRUNK_BASE, container_cell_id=TRUNK_CELL,
            container_form_id=TRUNK_FID,
            item_base_id=STIMPAK, count=1, timestamp_ms=0,
        )
        result = s.record_container_op(op1, "A", 100.0)
        assert result is not None  # accepted (lazy-created)
        st = s.container_state(TRUNK_FID)
        assert st.items == {}  # trust-the-client: had >=1, now 0 (popped)

        # Second TAKE of DIFFERENT item X' on the SAME (now known) container.
        # Without the fix this would have been rejected since items.get(X')=0.
        op2 = ContainerOpPayload(
            kind=int(ContainerOpKind.TAKE),
            container_base_id=TRUNK_BASE, container_cell_id=TRUNK_CELL,
            container_form_id=TRUNK_FID,
            item_base_id=AMMO_10MM, count=2, timestamp_ms=0,
        )
        result = s.record_container_op(op2, "A", 200.0)
        assert result is not None  # still accepted
        st = s.container_state(TRUNK_FID)
        assert st.items == {}  # AMMO_10MM also first-seen, trust-the-client

        # Third TAKE of the SAME item X (already at 0 after first take).
        # This is a true over-take. Gets clamped; server state stays 0.
        op3 = ContainerOpPayload(
            kind=int(ContainerOpKind.TAKE),
            container_base_id=TRUNK_BASE, container_cell_id=TRUNK_CELL,
            container_form_id=TRUNK_FID,
            item_base_id=STIMPAK, count=1, timestamp_ms=0,
        )
        result = s.record_container_op(op3, "A", 300.0)
        assert result is not None
        assert s.container_state(TRUNK_FID).items == {}

    def test_multiple_items_coexist(self):
        s = ServerState()
        for item, cnt in [(STIMPAK, 5), (AMMO_10MM, 200)]:
            s.record_container_op(ContainerOpPayload(
                kind=int(ContainerOpKind.PUT),
                container_base_id=TRUNK_BASE, container_cell_id=TRUNK_CELL,
                container_form_id=TRUNK_FID,
                item_base_id=item, count=cnt, timestamp_ms=0,
            ), "alice", 0.0)
        st = s.container_state(TRUNK_FID)
        assert st.items == {STIMPAK: 5, AMMO_10MM: 200}


# ------------------------------------------------------------------ validator

class TestValidator:
    def test_rejects_missing_identity(self):
        sess = _session()
        p = ContainerOpPayload(
            kind=int(ContainerOpKind.PUT),
            container_base_id=0, container_cell_id=TRUNK_CELL,
            container_form_id=TRUNK_FID,
            item_base_id=STIMPAK, count=1, timestamp_ms=0,
        )
        r = validate_container_op(sess, p, None, 0.0)
        assert not r.ok
        assert r.reason == RejectReason.MISSING_IDENTITY

    def test_rejects_nonpositive_count(self):
        sess = _session()
        p = ContainerOpPayload(
            kind=int(ContainerOpKind.PUT),
            container_base_id=TRUNK_BASE, container_cell_id=TRUNK_CELL,
            container_form_id=TRUNK_FID,
            item_base_id=STIMPAK, count=0, timestamp_ms=0,
        )
        r = validate_container_op(sess, p, None, 0.0)
        assert not r.ok
        assert r.reason == RejectReason.INVALID_COUNT

    def test_rejects_unknown_kind(self):
        sess = _session()
        p = ContainerOpPayload(
            kind=99,
            container_base_id=TRUNK_BASE, container_cell_id=TRUNK_CELL,
            container_form_id=TRUNK_FID,
            item_base_id=STIMPAK, count=1, timestamp_ms=0,
        )
        r = validate_container_op(sess, p, None, 0.0)
        assert not r.ok
        assert r.reason == RejectReason.INVALID_KIND

    def test_take_unknown_container_accepted(self):
        """Lazy registration: TAKE on a container the server has never seen
        is fine (accept, lazy-create on record)."""
        sess = _session()
        p = ContainerOpPayload(
            kind=int(ContainerOpKind.TAKE),
            container_base_id=TRUNK_BASE, container_cell_id=TRUNK_CELL,
            container_form_id=TRUNK_FID,
            item_base_id=STIMPAK, count=1, timestamp_ms=0,
        )
        r = validate_container_op(sess, p, None, 0.0)
        assert r.ok

    def test_take_over_available_rejected_b1h4_enforce(self):
        """B1.h.4 (2026-04-21): INSUFFICIENT_ITEMS enforcement RE-ENABLED.

        B1.j.1 (pre-scan force_materialize_inventory) + the LVLI filter
        removal fix the SEED completeness problem that motivated the
        B1.h.3 rollback. B1.g + B1.k.3.3 landed the apply-on-receiver
        and PUT-capture loops end-to-end (live validated). With server
        state now trustworthy, taking more than the container holds is
        a race loss or a desync — the correct answer is REJECT.

        See validator.py ENFORCE_INSUFFICIENT flag."""
        sess = _session()
        known = ContainerWorldState(
            form_id=TRUNK_FID, base_id=TRUNK_BASE, cell_id=TRUNK_CELL,
            items={STIMPAK: 2},
        )
        p = ContainerOpPayload(
            kind=int(ContainerOpKind.TAKE),
            container_base_id=TRUNK_BASE, container_cell_id=TRUNK_CELL,
            container_form_id=TRUNK_FID,
            item_base_id=STIMPAK, count=5, timestamp_ms=0,
        )
        r = validate_container_op(sess, p, known, 0.0)
        # Rejected: only 2 available, asked for 5.
        assert not r.ok
        assert r.reason == RejectReason.INSUFFICIENT_ITEMS

    def test_take_unknown_container_accepted_backward_compat(self):
        """If the server has no state for this container, it accepts (B0
        fallback for clients that haven't sent CONTAINER_SEED yet)."""
        sess = _session()
        p = ContainerOpPayload(
            kind=int(ContainerOpKind.TAKE),
            container_base_id=TRUNK_BASE, container_cell_id=TRUNK_CELL,
            container_form_id=TRUNK_FID,
            item_base_id=STIMPAK, count=999, timestamp_ms=0,
        )
        r = validate_container_op(sess, p, None, 0.0)
        assert r.ok

    def test_put_always_accepted(self):
        sess = _session()
        p = ContainerOpPayload(
            kind=int(ContainerOpKind.PUT),
            container_base_id=TRUNK_BASE, container_cell_id=TRUNK_CELL,
            container_form_id=TRUNK_FID,
            item_base_id=STIMPAK, count=9999, timestamp_ms=0,
        )
        r = validate_container_op(sess, p, None, 0.0)
        assert r.ok


# ------------------------------------------------------------------ persistence

class TestPersistence:
    def test_v6_snapshot_roundtrip(self, tmp_path: Path):
        src = ServerState()
        _seeded(src, TRUNK_FID, {STIMPAK: 10}, by="alice", now_ms=100.0)
        src.record_container_op(_put(TRUNK_FID, AMMO_10MM, 50), "bob", 200.0)
        # The twin shares base and cell: v6 keeps it apart. Made by an op
        # alone, it is a partial record (L3) and must load back as one.
        src.record_container_op(_put(TWIN_FID, STIMPAK, 1), "carol", 300.0)

        path = tmp_path / "snap.json"
        snapshot(src, path)
        data = json.loads(path.read_text())
        # v7 (L5 stage 1) keeps the v6 container layout; the version bump
        # added the journal mark, quests, globals and hashed tokens; v8 (L5
        # stage 2) adds the inventory digests; v9 (L5 stage 3a) the checkpoints;
        # v10 (L5 stage 3b) their custody.
        assert data["version"] == SNAPSHOT_FORMAT_VERSION == 10
        assert len(data["containers"]) == 2
        c = next(x for x in data["containers"] if x["form_id"] == f"0x{TRUNK_FID:X}")
        assert c["base_id"] == f"0x{TRUNK_BASE:X}"
        assert c["items"] == {f"0x{STIMPAK:X}": 10, f"0x{AMMO_10MM:X}": 50}

        dst = ServerState()
        load_into(dst, path)
        st = dst.container_state(TRUNK_FID)
        assert st is not None
        assert st.items == {STIMPAK: 10, AMMO_10MM: 50}
        assert st.last_owner_peer_id == "bob"  # last writer
        assert (st.base_id, st.cell_id) == (TRUNK_BASE, TRUNK_CELL)
        assert st.seeded is True
        assert dst.container_state(TWIN_FID).items == {STIMPAK: 1}
        assert dst.container_state(TWIN_FID).seeded is False

    def test_pre_v6_containers_are_dropped(self, tmp_path: Path):
        """A v5 snapshot keyed containers by (base, cell). Those records
        cannot be mapped to one REFR (the key merged every twin), so they
        are dropped with a warning while the rest of the snapshot loads."""
        path = tmp_path / "v5.json"
        path.write_text(json.dumps({
            "version": 5,
            "timestamp_ms": 0,
            "server": {"tick_rate_hz": 20, "server_version": [1, 0], "peer_timeout_ms": 15000.0},
            "sessions": [],
            "world_actors": [
                {
                    "base_id": "0x1234", "cell_id": "0x1696A", "alive": False,
                    "last_known_form_id": "0x1F3A9",
                    "last_owner": "alice", "last_update_ms": 0.0,
                },
            ],
            "containers": [
                {
                    "base_id": f"0x{TRUNK_BASE:X}", "cell_id": f"0x{TRUNK_CELL:X}",
                    "items": {f"0x{STIMPAK:X}": 3},
                    "last_known_form_id": f"0x{TRUNK_FID:X}",
                    "last_owner": "alice", "last_update_ms": 0.0,
                },
            ],
        }))
        dst = ServerState()
        n = load_into(dst, path)
        assert n == 1
        assert dst.all_containers() == []

    def test_v2_snapshot_loads_without_containers(self, tmp_path: Path):
        """A v2 snapshot (from before containers existed) must load cleanly
        with zero containers, not an error."""
        path = tmp_path / "v2.json"
        path.write_text(json.dumps({
            "version": 2,
            "timestamp_ms": 0,
            "server": {"tick_rate_hz": 20, "server_version": [1, 0], "peer_timeout_ms": 5000.0},
            "sessions": [],
            "world_actors": [
                {
                    "base_id": "0x1234", "cell_id": "0x1696A", "alive": False,
                    "last_known_form_id": "0xFF00136F",
                    "last_owner": "alice", "last_update_ms": 0.0,
                },
            ],
            # NOTE: no "containers" key — v2 didn't have it
        }))
        dst = ServerState()
        n = load_into(dst, path)
        assert n == 1  # one world actor restored
        assert dst.all_containers() == []


# ------------------------------------------------------------------ end-to-end

async def _start_server_with_state(state: ServerState, port: int):
    loop = asyncio.get_running_loop()
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: ServerProtocol(state),
        local_addr=("127.0.0.1", port),
    )
    from net.tests.test_server_integration import _periodic_tick_driver
    loop.create_task(_periodic_tick_driver(protocol, 20))
    return transport, protocol


@pytest.mark.asyncio
async def test_bootstrap_delivers_container_state():
    """Server seeded with a container; new client receives full state via
    CONTAINER_STATE chunks on bootstrap."""
    port = 31500
    state = ServerState()
    _seeded(state, TRUNK_FID, {STIMPAK: 5, AMMO_10MM: 200}, now_ms=100.0)
    _seeded(state, TWIN_FID, {STIMPAK: 1}, now_ms=100.0)

    transport, protocol = await _start_server_with_state(state, port)
    try:
        cfg = ClientConfig(pid=1, client_id="alice",
                           server_host="127.0.0.1", server_port=port,
                           use_fake_bridge=True)
        client = FalloutWorldClient(cfg)
        task = asyncio.create_task(client.run())

        for _ in range(100):
            if client.container_bootstrap_complete:
                break
            await asyncio.sleep(0.05)
        assert client.container_bootstrap_complete, \
            f"container bootstrap never completed (got chunks: {client._container_bootstrap_chunks_received})"

        key = TRUNK_FID
        assert key in client.container_state
        assert client.container_state[key] == {STIMPAK: 5, AMMO_10MM: 200}
        assert client.container_state[TWIN_FID] == {STIMPAK: 1}

        client.stop()
        await asyncio.wait_for(task, timeout=2.0)
    finally:
        transport.close()


@pytest.mark.asyncio
async def test_live_container_op_propagation():
    """A sends TAKE -> server validates + persists + broadcasts -> B receives
    CONTAINER_BCAST and updates local mirror. Both clients see the same
    authoritative state afterwards."""
    port = 31501
    state = ServerState()
    _seeded(state, TRUNK_FID, {STIMPAK: 10})

    transport, protocol = await _start_server_with_state(state, port)
    try:
        client_a = FalloutWorldClient(ClientConfig(
            pid=1, client_id="A",
            server_host="127.0.0.1", server_port=port,
            use_fake_bridge=True,
        ))
        client_b = FalloutWorldClient(ClientConfig(
            pid=2, client_id="B",
            server_host="127.0.0.1", server_port=port,
            use_fake_bridge=True,
        ))
        task_a = asyncio.create_task(client_a.run())
        task_b = asyncio.create_task(client_b.run())

        for _ in range(100):
            if (client_a.connected and client_b.connected
                and client_a.container_bootstrap_complete
                and client_b.container_bootstrap_complete):
                break
            await asyncio.sleep(0.05)
        assert client_a.connected and client_b.connected
        assert client_a.container_bootstrap_complete
        assert client_b.container_bootstrap_complete

        # A takes 3 stimpaks
        client_a.send_container_op(
            kind=ContainerOpKind.TAKE,
            container_base_id=TRUNK_BASE, container_cell_id=TRUNK_CELL,
            container_form_id=TRUNK_FID,
            item_base_id=STIMPAK, count=3,
        )

        # Wait for B to receive the broadcast
        for _ in range(100):
            key = TRUNK_FID
            if key in client_b.container_state \
                    and client_b.container_state[key].get(STIMPAK) == 7:
                break
            await asyncio.sleep(0.05)

        # Both sides agree: 7 stimpaks left
        key = TRUNK_FID
        # Server authoritative
        srv_view = protocol.state.container_state(key)
        assert srv_view.items.get(STIMPAK) == 7
        assert srv_view.last_owner_peer_id == "A"
        # B's mirror (via CONTAINER_BCAST)
        assert client_b.container_state[key].get(STIMPAK) == 7
        # A's mirror (via optimistic local apply on send — sender does NOT
        # receive an echo from the server, so without optimistic we'd drift)
        assert client_a.container_state[key].get(STIMPAK) == 7, (
            f"sender's mirror drifted — expected 7 but got "
            f"{client_a.container_state.get(key)}"
        )
        # A's stats reflect send
        assert client_a.stats["container_ops_sent"] >= 1
        assert client_b.stats["container_ops_received"] >= 1

        client_a.stop(); client_b.stop()
        await asyncio.wait_for(task_a, timeout=2.0)
        await asyncio.wait_for(task_b, timeout=2.0)
    finally:
        transport.close()


@pytest.mark.asyncio
async def test_frida_capture_flows_through_to_peer():
    """Simulates the engine hook firing on side A: ContainerCapture enters
    bridge.container_queue -> _send_container_loop drains -> send_container_op
    -> server -> CONTAINER_BCAST -> side B's mirror updated.

    This is the end-to-end flow that will happen in the live game when the
    player takes an item from a container. No Frida required in the test
    because FakeFridaBridge exposes feed_container_op()."""
    port = 31503
    state = ServerState()
    _seeded(state, TRUNK_FID, {STIMPAK: 5})

    transport, protocol = await _start_server_with_state(state, port)
    try:
        client_a = FalloutWorldClient(ClientConfig(
            pid=1, client_id="A", server_host="127.0.0.1", server_port=port,
            use_fake_bridge=True,
        ))
        client_b = FalloutWorldClient(ClientConfig(
            pid=2, client_id="B", server_host="127.0.0.1", server_port=port,
            use_fake_bridge=True,
        ))
        task_a = asyncio.create_task(client_a.run())
        task_b = asyncio.create_task(client_b.run())

        for _ in range(100):
            if (client_a.connected and client_b.connected
                and client_a.container_bootstrap_complete
                and client_b.container_bootstrap_complete):
                break
            await asyncio.sleep(0.05)
        assert client_a.connected and client_b.connected

        # Simulate the Frida hook: player on side A takes 2 stimpaks
        client_a.bridge.feed_container_op(ContainerCapture(
            op_kind="TAKE",
            container_base_id=TRUNK_BASE, container_cell_id=TRUNK_CELL,
            container_form_id=TRUNK_FID, item_base_id=STIMPAK, count=2,
        ))

        # Wait for the full chain: queue -> send -> server -> bcast -> B's mirror
        for _ in range(100):
            key = TRUNK_FID
            if client_b.container_state.get(key, {}).get(STIMPAK) == 3:
                break
            await asyncio.sleep(0.05)

        # Everybody agrees: 3 left after A took 2
        key = TRUNK_FID
        assert protocol.state.container_state(key).items.get(STIMPAK) == 3
        assert client_a.container_state[key].get(STIMPAK) == 3   # optimistic on sender
        assert client_b.container_state[key].get(STIMPAK) == 3   # via bcast
        assert client_a.stats["container_ops_captured"] >= 1
        assert client_a.stats["container_ops_sent"] >= 1
        assert client_b.stats["container_ops_received"] >= 1

        client_a.stop(); client_b.stop()
        await asyncio.wait_for(task_a, timeout=2.0)
        await asyncio.wait_for(task_b, timeout=2.0)
    finally:
        transport.close()


@pytest.mark.asyncio
async def test_take_over_available_rejected_not_broadcast_b1h4():
    """B1.h.4 (2026-04-21): TAKE over-available is REJECTED by the server
    (INSUFFICIENT_ITEMS), state is UNCHANGED, and NO broadcast is emitted
    to other peers. Replaces the B1.h.3 rollback contract now that SEED
    correctness is guaranteed by B1.j.1 + B1.g apply loop."""
    port = 31502
    state = ServerState()
    _seeded(state, TRUNK_FID, {STIMPAK: 2})

    transport, protocol = await _start_server_with_state(state, port)
    try:
        client_a = FalloutWorldClient(ClientConfig(
            pid=1, client_id="A",
            server_host="127.0.0.1", server_port=port,
            use_fake_bridge=True,
        ))
        client_b = FalloutWorldClient(ClientConfig(
            pid=2, client_id="B",
            server_host="127.0.0.1", server_port=port,
            use_fake_bridge=True,
        ))
        task_a = asyncio.create_task(client_a.run())
        task_b = asyncio.create_task(client_b.run())

        for _ in range(100):
            if (client_a.connected and client_b.connected
                and client_b.container_bootstrap_complete):
                break
            await asyncio.sleep(0.05)

        before_bcast = client_b.stats["container_ops_received"]
        rejections_before = protocol.stats()["rejections"]

        # A tries to take 10 (only 2 available) — B1.h.4 rejects and
        # does NOT mutate state or broadcast.
        client_a.send_container_op(
            kind=ContainerOpKind.TAKE,
            container_base_id=TRUNK_BASE, container_cell_id=TRUNK_CELL,
            container_form_id=TRUNK_FID,
            item_base_id=STIMPAK, count=10,
        )

        # Give the server a moment to process and B a chance to receive
        # (anything, including a phantom bcast we DON'T want).
        await asyncio.sleep(0.5)

        # Server state: unchanged (still 2 stimpaks from the seed).
        srv = protocol.state.container_state(TRUNK_FID)
        assert srv is not None
        assert srv.items == {STIMPAK: 2}, \
            f"state changed despite reject, got {srv.items}"
        # Rejection counter bumped by exactly 1.
        assert protocol.stats()["rejections"] == rejections_before + 1
        # B did NOT receive a broadcast for the rejected op.
        assert client_b.stats["container_ops_received"] == before_bcast

        client_a.stop(); client_b.stop()
        await asyncio.wait_for(task_a, timeout=2.0)
        await asyncio.wait_for(task_b, timeout=2.0)
    finally:
        transport.close()


# ---------------------------------------------------------------- B1.h: first-seed-wins

@pytest.mark.asyncio
async def test_first_seed_creates_state_second_is_rejected():
    """B1.h policy: a container's first SEED establishes canonical state.
    Subsequent SEEDs for the same container REFR are IGNORED (do not wholesale-
    replace) to protect against a drifted client erasing legitimate contents."""
    port = 31530
    state = ServerState()
    transport, protocol_obj = await _start_server_with_state(state, port)
    try:
        server_addr = ("127.0.0.1", port)
        sock_a = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock_b = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock_a.bind(("127.0.0.1", 0)); sock_b.bind(("127.0.0.1", 0))
        try:
            await asyncio.gather(
                _raw_peer_hello(sock_a, server_addr, "peer_sA"),
                _raw_peer_hello(sock_b, server_addr, "peer_sB"),
            )
            await _collect_frames(sock_b, 0.2)
            await _collect_frames(sock_a, 0.0)

            # Peer A sends initial SEED: container has {STIMPAK: 5, AMMO_10MM: 100}
            seed_a = ContainerSeedPayload(entries=(
                ContainerStateEntry(TRUNK_FID, TRUNK_BASE, TRUNK_CELL, STIMPAK, 5),
                ContainerStateEntry(TRUNK_FID, TRUNK_BASE, TRUNK_CELL, AMMO_10MM, 100),
            ))
            sock_a.sendto(encode_frame(MessageType.CONTAINER_SEED, 1, seed_a, reliable=True),
                          server_addr)
            await asyncio.sleep(0.3)

            srv = protocol_obj.state.container_state(TRUNK_FID)
            assert srv is not None
            assert srv.items == {STIMPAK: 5, AMMO_10MM: 100}
            assert srv.last_owner_peer_id == "peer_sA"

            # Peer B sends a SEED with LESS info (only STIMPAK, and lower count).
            # B1.h must REJECT this. Server state unchanged.
            seed_b = ContainerSeedPayload(entries=(
                ContainerStateEntry(TRUNK_FID, TRUNK_BASE, TRUNK_CELL, STIMPAK, 1),
            ))
            sock_b.sendto(encode_frame(MessageType.CONTAINER_SEED, 1, seed_b, reliable=True),
                          server_addr)
            await asyncio.sleep(0.3)

            srv_after = protocol_obj.state.container_state(TRUNK_FID)
            assert srv_after is not None
            assert srv_after.items == {STIMPAK: 5, AMMO_10MM: 100}, \
                f"second SEED wholesale-replaced state: {srv_after.items}"
            assert srv_after.last_owner_peer_id == "peer_sA"   # UNCHANGED
        finally:
            sock_a.close(); sock_b.close()
    finally:
        transport.close()


@pytest.mark.asyncio
async def test_seed_refills_empty_tracked_container():
    """B1.h refill policy: if a container is tracked server-side but has
    items={} (legitimately emptied OR leftover corruption from a pre-B1.h
    wipeout), a fresh SEED from a peer refills it. This unblocks the
    "stale snapshot shows empty but the engine has items" case which
    otherwise results in INSUFFICIENT_ITEMS on every TAKE."""
    from server.state import ContainerWorldState
    port = 31532
    state = ServerState()
    # Pre-existing empty tracked container (e.g., leftover from previous
    # session that got wiped, or respawned container that was emptied).
    state._containers[TRUNK_FID] = ContainerWorldState(
        form_id=TRUNK_FID, base_id=TRUNK_BASE, cell_id=TRUNK_CELL, items={},
        last_owner_peer_id="past_peer",
    )
    transport, protocol_obj = await _start_server_with_state(state, port)
    try:
        server_addr = ("127.0.0.1", port)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 0))
        try:
            await _raw_peer_hello(sock, server_addr, "peer_refill")
            await _collect_frames(sock, 0.2)

            seed = ContainerSeedPayload(entries=(
                ContainerStateEntry(TRUNK_FID, TRUNK_BASE, TRUNK_CELL, STIMPAK, 4),
                ContainerStateEntry(TRUNK_FID, TRUNK_BASE, TRUNK_CELL, AMMO_10MM, 50),
            ))
            sock.sendto(encode_frame(MessageType.CONTAINER_SEED, 1, seed, reliable=True),
                        server_addr)
            await asyncio.sleep(0.3)

            srv = protocol_obj.state.container_state(TRUNK_FID)
            assert srv is not None
            assert srv.items == {STIMPAK: 4, AMMO_10MM: 50}, \
                f"empty container wasn't refilled: {srv.items}"
            assert srv.last_owner_peer_id == "peer_refill"   # refresh owner
        finally:
            sock.close()
    finally:
        transport.close()


@pytest.mark.asyncio
async def test_empty_seed_does_not_erase_state():
    """An empty-content SEED from a drifted client MUST NOT create/replace
    server state. Pre-B1.h this was the 'PUT-then-TAKE sparisce' bug trigger:
    peer B (no sync) scans its stale-empty view → sends empty SEED →
    server wipes → peer A's TAKE then rejects with INSUFFICIENT_ITEMS →
    items 'disappear'."""
    port = 31531
    state = ServerState()
    state.record_container_op(ContainerOpPayload(
        kind=int(ContainerOpKind.PUT),
        container_base_id=TRUNK_BASE, container_cell_id=TRUNK_CELL,
        container_form_id=TRUNK_FID,
        item_base_id=STIMPAK, count=3, timestamp_ms=0,
    ), "peer_sA", 0.0)

    transport, protocol_obj = await _start_server_with_state(state, port)
    try:
        server_addr = ("127.0.0.1", port)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 0))
        try:
            await _raw_peer_hello(sock, server_addr, "peer_drift")
            await _collect_frames(sock, 0.2)

            # Send SEED payload with entries BUT count=0 (drifted client's
            # view of an "empty" container).
            seed = ContainerSeedPayload(entries=(
                ContainerStateEntry(TRUNK_FID, TRUNK_BASE, TRUNK_CELL, STIMPAK, 0),
            ))
            sock.sendto(encode_frame(MessageType.CONTAINER_SEED, 1, seed, reliable=True),
                        server_addr)
            await asyncio.sleep(0.3)

            # Server state is intact — the empty SEED must not wipe the stimpaks.
            srv = protocol_obj.state.container_state(TRUNK_FID)
            assert srv is not None
            assert srv.items.get(STIMPAK) == 3, \
                f"drifted client's empty SEED wiped state: {srv.items}"
        finally:
            sock.close()
    finally:
        transport.close()


# ---------------------------------------------------------------- B1.f: raw UDP 2-peer race

async def _raw_peer_hello(sock: socket.socket, server_addr, client_id: str) -> int:
    """Send HELLO via raw UDP and parse WELCOME. Returns session_id."""
    hello = HelloPayload(client_id=client_id, client_version_major=1, client_version_minor=0)
    raw = encode_frame(MessageType.HELLO, 0, hello, reliable=True)
    sock.sendto(raw, server_addr)

    sock.setblocking(False)
    deadline = asyncio.get_running_loop().time() + 2.0
    while asyncio.get_running_loop().time() < deadline:
        try:
            data, _ = sock.recvfrom(4096)
        except BlockingIOError:
            await asyncio.sleep(0.02)
            continue
        frame = decode_frame(data)
        if frame.header.msg_type == int(MessageType.WELCOME):
            # ACK WELCOME so server stops retransmitting.
            ack_payload = AckPayload(
                highest_contiguous_seq=frame.header.seq, sack_bitmap=0,
            )
            ack_raw = encode_frame(MessageType.ACK, 0, ack_payload, reliable=False)
            sock.sendto(ack_raw, server_addr)
            from protocol import WelcomePayload as _WP
            assert isinstance(frame.payload, _WP)
            assert frame.payload.accepted
            return frame.payload.session_id
    raise AssertionError("HELLO -> WELCOME timed out")


async def _collect_frames(sock: socket.socket, duration_s: float) -> list:
    """Drain UDP frames arriving within duration_s. ACKs reliable frames."""
    out = []
    loop = asyncio.get_running_loop()
    deadline = loop.time() + duration_s
    sock.setblocking(False)
    while loop.time() < deadline:
        try:
            data, addr = sock.recvfrom(4096)
        except BlockingIOError:
            await asyncio.sleep(0.01)
            continue
        try:
            frame = decode_frame(data)
        except Exception:
            continue
        out.append((frame, addr))
        if frame.header.flags & 0x01:  # FLAG_RELIABLE
            ack_payload = AckPayload(
                highest_contiguous_seq=frame.header.seq, sack_bitmap=0,
            )
            ack_raw = encode_frame(MessageType.ACK, 0, ack_payload, reliable=False)
            sock.sendto(ack_raw, addr)
    return out


@pytest.mark.asyncio
async def test_concurrent_take_dup_race_b1h4_one_wins_one_loses():
    """B1.h.4 (2026-04-21): dup race is CLOSED. Two peers TAKEing the
    same count=3 from a container with only 3 stimpaks: the first op
    to be validated is ACCEPTED, the second sees 0 remaining and gets
    REJ_INSUFFICIENT. Exactly one BCAST is emitted (to the non-winning
    peer). Server state goes to {} (winner took all 3).

    Asyncio event loop processes CONTAINER_OP frames sequentially (they
    arrive in independent datagrams but the server has a single-threaded
    dispatch loop), so there's no kernel-level race to worry about —
    the validator's container_state lookup+reject is atomic from the
    server's perspective."""
    port = 31510
    state = ServerState()
    _seeded(state, TRUNK_FID, {STIMPAK: 3})

    transport, protocol_obj = await _start_server_with_state(state, port)
    try:
        rejections_before = protocol_obj.stats()["rejections"]

        server_addr = ("127.0.0.1", port)
        sock_a = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock_b = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock_a.bind(("127.0.0.1", 0))
        sock_b.bind(("127.0.0.1", 0))
        try:
            sid_a, sid_b = await asyncio.gather(
                _raw_peer_hello(sock_a, server_addr, "peerA_race"),
                _raw_peer_hello(sock_b, server_addr, "peerB_race"),
            )
            assert sid_a != sid_b

            op_a = ContainerOpPayload(
                kind=int(ContainerOpKind.TAKE),
                container_base_id=TRUNK_BASE, container_cell_id=TRUNK_CELL,
                container_form_id=TRUNK_FID,
                item_base_id=STIMPAK, count=3, timestamp_ms=0,
                client_op_id=1001,
            )
            op_b = ContainerOpPayload(
                kind=int(ContainerOpKind.TAKE),
                container_base_id=TRUNK_BASE, container_cell_id=TRUNK_CELL,
                container_form_id=TRUNK_FID,
                item_base_id=STIMPAK, count=3, timestamp_ms=0,
                client_op_id=2002,
            )
            # seq=1 for first real reliable op after HELLO (seq=0 was HELLO).
            raw_a = encode_frame(MessageType.CONTAINER_OP, 1, op_a, reliable=True)
            raw_b = encode_frame(MessageType.CONTAINER_OP, 1, op_b, reliable=True)
            sock_a.sendto(raw_a, server_addr)
            sock_b.sendto(raw_b, server_addr)

            frames_a, frames_b = await asyncio.gather(
                _collect_frames(sock_a, 1.0),
                _collect_frames(sock_b, 1.0),
            )

            def _acks(frames):
                return [f.payload for f, _ in frames
                        if f.header.msg_type == int(MessageType.CONTAINER_OP_ACK)
                        and isinstance(f.payload, ContainerOpAckPayload)]
            def _bcasts(frames):
                return [f.payload for f, _ in frames
                        if f.header.msg_type == int(MessageType.CONTAINER_BCAST)]

            acks_a = _acks(frames_a)
            acks_b = _acks(frames_b)
            bcasts_a = _bcasts(frames_a)
            bcasts_b = _bcasts(frames_b)

            assert len(acks_a) == 1, f"expected 1 ACK for A, got {acks_a}"
            assert len(acks_b) == 1, f"expected 1 ACK for B, got {acks_b}"
            assert acks_a[0].client_op_id == 1001
            assert acks_b[0].client_op_id == 2002

            # B1.h.4: exactly ONE op is ACCEPTED, the other is REJECTED
            # with INSUFFICIENT_ITEMS. Which of A/B wins depends on the
            # datagram arrival order; both orderings are valid.
            statuses = {acks_a[0].status, acks_b[0].status}
            assert statuses == {
                int(ContainerOpAckStatus.ACCEPTED),
                int(ContainerOpAckStatus.REJ_INSUFFICIENT),
            }, f"expected one ACCEPTED + one REJ_INSUFFICIENT, got {statuses}"

            # Server state: winner took all 3, key removed (or value=0).
            final = protocol_obj.state.container_state(TRUNK_FID)
            assert final is not None
            assert final.items.get(STIMPAK, 0) == 0, \
                f"winner didn't clear the stock: {final.items}"

            # Exactly 1 REJ_INSUFFICIENT on the validator stats.
            assert protocol_obj.stats()["rejections"] == rejections_before + 1

            # B1.h.4: only the ACCEPTED op broadcasts. The loser's REJECT
            # is sent only as an ACK to the submitting peer, NOT as a
            # BCAST to the other peer. So total bcasts = 1 (winner's op
            # to the loser only; the winner doesn't see their own op).
            total_bcasts = len(bcasts_a) + len(bcasts_b)
            assert total_bcasts == 1, \
                f"expected 1 bcast (winner's op to loser only), got {total_bcasts}"
            # The bcast goes to whoever was the loser (status=REJ_INSUFFICIENT).
            if acks_a[0].status == int(ContainerOpAckStatus.REJ_INSUFFICIENT):
                # A lost → A receives B's (winning) bcast.
                assert len(bcasts_a) == 1 and len(bcasts_b) == 0
            else:
                # B lost → B receives A's (winning) bcast.
                assert len(bcasts_b) == 1 and len(bcasts_a) == 0
        finally:
            sock_a.close()
            sock_b.close()
    finally:
        transport.close()


# ---------------------------------------------------------------- L1: the key is the placed REFR

RUNTIME_FID = 0xFF000123   # a runtime ref: aliases across processes


class TestPlacedRefIdentity:
    """Loot rework L1 (2026-09-23): a container IS its placed REFR form_id.

    The (base_id, cell_id) key merged every ref of one base in one cell: two
    identical toolboxes in a house, two corpses of the same NPC base, two
    stimpaks on one floor were a single record. Emptying the first made the
    server refuse the second, and with the half-transaction block of B1 a
    refused take destroyed the item (six X-01 pieces, 2026-08-16). Placed ids
    (prefix 0x00..0xFE) are stable across processes with the same load
    order; runtime ids (prefix 0xFF) alias and are refused until they carry
    an identity of their own. (base, cell) stays as the verification.
    """

    def test_state_entry_carries_form_id(self):
        e = ContainerStateEntry(TRUNK_FID, TRUNK_BASE, TRUNK_CELL, STIMPAK, 4)
        s = ContainerStatePayload(entries=(e,))
        f = decode_frame(encode_frame(MessageType.CONTAINER_STATE, 1, s, reliable=True))
        assert f.payload.entries[0].container_form_id == TRUNK_FID
        # 20 bytes per entry under the 1400-byte payload, 6 of chunk header.
        assert ContainerStatePayload.MAX_ENTRIES_PER_FRAME == 69
        assert ContainerSeedPayload.MAX_ENTRIES_PER_FRAME == 69

    def test_twins_are_two_records(self):
        s = ServerState()
        for fid in (TRUNK_FID, TWIN_FID):
            s.record_container_op(_put(fid, STIMPAK, 5), "alice", 0.0)
        s.record_container_op(_take(TRUNK_FID, STIMPAK, 5), "bob", 1.0)
        assert s.container_state(TRUNK_FID).items == {}
        assert s.container_state(TWIN_FID).items == {STIMPAK: 5}
        assert len(s.all_containers()) == 2

    def test_take_on_emptied_twin_is_insufficient(self):
        """The merged key answered this take out of the twin's stock."""
        s = ServerState()
        _seeded(s, TWIN_FID, {STIMPAK: 5})
        _seeded(s, TRUNK_FID, {STIMPAK: 1})
        s.record_container_op(_take(TRUNK_FID, STIMPAK, 1), "alice", 0.0)
        op = _take(TRUNK_FID, STIMPAK, 1)
        r = validate_container_op(_session(), op, s.container_state_for_op(op), 0.0)
        assert not r.ok
        assert r.reason == RejectReason.INSUFFICIENT_ITEMS

    def test_validator_refuses_zero_form_id(self):
        r = validate_container_op(_session(), _take(0, STIMPAK, 1), None, 0.0)
        assert not r.ok
        assert r.reason == RejectReason.MISSING_IDENTITY

    def test_validator_refuses_runtime_ref(self):
        r = validate_container_op(_session(), _take(RUNTIME_FID, STIMPAK, 1), None, 0.0)
        assert not r.ok
        assert r.reason == RejectReason.RUNTIME_REF

    def test_validator_refuses_identity_drift(self):
        """Same form_id, another (base, cell): a load-order drift between
        two clients. The op must not touch the record."""
        known = ContainerWorldState(
            form_id=TRUNK_FID, base_id=TRUNK_BASE, cell_id=TRUNK_CELL,
            items={STIMPAK: 2},
        )
        drifted = ContainerOpPayload(
            kind=int(ContainerOpKind.TAKE),
            container_base_id=TRUNK_BASE + 1, container_cell_id=TRUNK_CELL,
            container_form_id=TRUNK_FID, item_base_id=STIMPAK, count=1,
            timestamp_ms=0,
        )
        r = validate_container_op(_session(), drifted, known, 0.0)
        assert not r.ok
        assert r.reason == RejectReason.IDENTITY_MISMATCH

    def test_record_refuses_identity_drift(self):
        s = ServerState()
        s.record_container_op(_put(TRUNK_FID, STIMPAK, 2), "alice", 0.0)
        drifted = ContainerOpPayload(
            kind=int(ContainerOpKind.TAKE),
            container_base_id=TRUNK_BASE + 1, container_cell_id=TRUNK_CELL,
            container_form_id=TRUNK_FID, item_base_id=STIMPAK, count=1,
            timestamp_ms=0,
        )
        assert s.record_container_op(drifted, "bob", 1.0) is None
        assert s.container_state(TRUNK_FID).items == {STIMPAK: 2}
        assert s.container_state(TRUNK_FID).last_owner_peer_id == "alice"


@pytest.mark.asyncio
async def test_seed_twins_create_two_records_and_runtime_refs_are_skipped():
    """One SEED can carry several containers. Two twins (same base and cell)
    become two records; an entry for a runtime ref (0xFF prefix) is skipped
    because its id means another object on every other client."""
    port = 31533
    state = ServerState()
    transport, protocol_obj = await _start_server_with_state(state, port)
    try:
        server_addr = ("127.0.0.1", port)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 0))
        try:
            await _raw_peer_hello(sock, server_addr, "peer_twins")
            await _collect_frames(sock, 0.2)
            seed = ContainerSeedPayload(entries=(
                ContainerStateEntry(TRUNK_FID, TRUNK_BASE, TRUNK_CELL, STIMPAK, 5),
                ContainerStateEntry(TWIN_FID, TRUNK_BASE, TRUNK_CELL, AMMO_10MM, 100),
                ContainerStateEntry(RUNTIME_FID, TRUNK_BASE, TRUNK_CELL, STIMPAK, 3),
            ))
            sock.sendto(encode_frame(MessageType.CONTAINER_SEED, 1, seed, reliable=True),
                        server_addr)
            await asyncio.sleep(0.3)

            assert protocol_obj.state.container_state(TRUNK_FID).items == {STIMPAK: 5}
            assert protocol_obj.state.container_state(TWIN_FID).items == {AMMO_10MM: 100}
            assert protocol_obj.state.container_state(RUNTIME_FID) is None
            assert len(protocol_obj.state.all_containers()) == 2
        finally:
            sock.close()
    finally:
        transport.close()


# ---------------------------------------------------------------- L2: one verdict per op id

class TestContainerVerdictMemory:
    """Loot rework L2 (2026-09-23): the client applies a take at once and
    sends the op afterwards, so an op whose ACK was lost in a session drop
    is sent again on the rejoin. The server keeps the verdict of the last
    ops of every peer, keyed by peer id (a rejoin is a new session), and
    answers a repeat with the stored ACK without applying it twice."""

    def test_remembers_per_peer_and_evicts_oldest(self):
        s = ServerState()
        ack = ContainerOpAckPayload(
            client_op_id=7, status=int(ContainerOpAckStatus.ACCEPTED),
            container_base_id=TRUNK_BASE, container_cell_id=TRUNK_CELL,
            item_base_id=STIMPAK, final_count=3,
        )
        s.remember_container_verdict("alice", 7, ack)
        assert s.recall_container_verdict("alice", 7) == ack
        assert s.recall_container_verdict("bob", 7) is None
        kept = ServerState.CONTAINER_VERDICTS_KEPT
        for i in range(kept):
            s.remember_container_verdict("alice", 1000 + i, ack)
        assert s.recall_container_verdict("alice", 7) is None
        assert s.recall_container_verdict("alice", 1000) is not None
        assert s.recall_container_verdict("alice", 1000 + kept - 1) is not None


@pytest.mark.asyncio
async def test_duplicate_op_applies_once_and_is_acked_twice():
    """The same CONTAINER_OP (same client_op_id) arrives twice with different
    channel sequence numbers, as it does when a client re-sends after a drop.
    The stock moves once, the sender gets two identical ACKs, the other peer
    gets one BCAST."""
    port = 31511
    state = ServerState()
    state.record_container_op(_put(TRUNK_FID, STIMPAK, 5), "seeder", 0.0)
    transport, protocol_obj = await _start_server_with_state(state, port)
    try:
        server_addr = ("127.0.0.1", port)
        sock_a = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock_b = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock_a.bind(("127.0.0.1", 0)); sock_b.bind(("127.0.0.1", 0))
        try:
            await asyncio.gather(
                _raw_peer_hello(sock_a, server_addr, "peer_dupA"),
                _raw_peer_hello(sock_b, server_addr, "peer_dupB"),
            )
            await asyncio.gather(_collect_frames(sock_a, 0.2), _collect_frames(sock_b, 0.2))

            op = _take(TRUNK_FID, STIMPAK, 2, op_id=4242)
            sock_a.sendto(encode_frame(MessageType.CONTAINER_OP, 1, op, reliable=True), server_addr)
            sock_a.sendto(encode_frame(MessageType.CONTAINER_OP, 2, op, reliable=True), server_addr)
            frames_a, frames_b = await asyncio.gather(
                _collect_frames(sock_a, 0.8), _collect_frames(sock_b, 0.8))

            acks = [f.payload for f, _ in frames_a
                    if f.header.msg_type == int(MessageType.CONTAINER_OP_ACK)]
            bcasts = [f.payload for f, _ in frames_b
                      if f.header.msg_type == int(MessageType.CONTAINER_BCAST)]
            assert len(acks) == 2, acks
            assert all(a.client_op_id == 4242 for a in acks)
            assert all(a.status == int(ContainerOpAckStatus.ACCEPTED) for a in acks)
            assert all(a.final_count == 3 for a in acks)
            assert len(bcasts) == 1, bcasts
            assert protocol_obj.state.container_state(TRUNK_FID).items == {STIMPAK: 3}
            assert protocol_obj.stats()["container_op_repeats"] == 1
        finally:
            sock_a.close(); sock_b.close()
    finally:
        transport.close()


@pytest.mark.asyncio
async def test_same_op_id_from_two_peers_both_apply():
    """Op ids are per peer: two peers reusing the same number are two ops."""
    port = 31512
    state = ServerState()
    state.record_container_op(_put(TRUNK_FID, STIMPAK, 5), "seeder", 0.0)
    transport, protocol_obj = await _start_server_with_state(state, port)
    try:
        server_addr = ("127.0.0.1", port)
        sock_a = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock_b = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock_a.bind(("127.0.0.1", 0)); sock_b.bind(("127.0.0.1", 0))
        try:
            await asyncio.gather(
                _raw_peer_hello(sock_a, server_addr, "peer_idA"),
                _raw_peer_hello(sock_b, server_addr, "peer_idB"),
            )
            await asyncio.gather(_collect_frames(sock_a, 0.2), _collect_frames(sock_b, 0.2))

            op = _take(TRUNK_FID, STIMPAK, 1, op_id=99)
            sock_a.sendto(encode_frame(MessageType.CONTAINER_OP, 1, op, reliable=True), server_addr)
            sock_b.sendto(encode_frame(MessageType.CONTAINER_OP, 1, op, reliable=True), server_addr)
            frames_a, frames_b = await asyncio.gather(
                _collect_frames(sock_a, 0.8), _collect_frames(sock_b, 0.8))

            def _acks(frames):
                return [f.payload for f, _ in frames
                        if f.header.msg_type == int(MessageType.CONTAINER_OP_ACK)]
            assert len(_acks(frames_a)) == 1 and len(_acks(frames_b)) == 1
            assert protocol_obj.state.container_state(TRUNK_FID).items == {STIMPAK: 3}
            assert protocol_obj.stats()["container_op_repeats"] == 0
        finally:
            sock_a.close(); sock_b.close()
    finally:
        transport.close()


CORPSE_FID = 0x246CD5          # a placed raider of the test area (ACHR)
BASE_ON_A = 0xFF0011EC         # its runtime TESNPC base on client A
BASE_ON_B = 0xFF001218         # the same raider's base on client B
CELL_ON_A = 0xDD5B
CELL_ON_B = 0xDD3A             # where B's ragdoll came to rest


def _corpse_take(base: int, cell: int, item: int, count: int) -> ContainerOpPayload:
    return ContainerOpPayload(
        kind=int(ContainerOpKind.TAKE), container_form_id=CORPSE_FID,
        container_base_id=base, container_cell_id=cell, item_base_id=item,
        count=count, timestamp_ms=0,
    )


class TestCorpseIdentity:
    """Loot rework L4 (2026-09-25): a placed actor's base is a runtime TESNPC
    that every client generates on its own (own face, gear and loot roll),
    and its corpse can lie in another cell on another client. Measured on
    four raiders: every op of the second client was refused with
    IDENTITY_MISMATCH and every alignment skipped, so the corpse loot never
    converged. For a runtime base the identity is the placed form_id alone;
    a static base (a container) keeps the (base, cell) verification."""

    def test_runtime_base_never_conflicts(self):
        assert not identities_conflict(BASE_ON_A, CELL_ON_A, BASE_ON_B, CELL_ON_A)
        assert not identities_conflict(BASE_ON_A, CELL_ON_A, BASE_ON_B, CELL_ON_B)
        assert not identities_conflict(BASE_ON_A, CELL_ON_A, TRUNK_BASE, TRUNK_CELL)
        assert identities_conflict(TRUNK_BASE, TRUNK_CELL, TRUNK_BASE, CELL_ON_B)
        assert identities_conflict(TRUNK_BASE, TRUNK_CELL, 0x913FB, TRUNK_CELL)

    def test_take_with_another_runtime_base_and_cell_is_accepted(self):
        s = ServerState()
        s.create_container(CORPSE_FID, BASE_ON_B, CELL_ON_A,
                           {AMMO_10MM: 9, STIMPAK: 1}, "bob", 0.0)
        op = _corpse_take(BASE_ON_A, CELL_ON_B, AMMO_10MM, 3)
        r = validate_container_op(_session(), op, s.container_state_for_op(op), 0.0)
        assert r.ok
        assert s.record_container_op(op, "alice", 1.0) is not None
        assert s.container_state(CORPSE_FID).items == {AMMO_10MM: 6, STIMPAK: 1}

    def test_static_base_still_catches_drift(self):
        s = ServerState()
        _seeded(s, TRUNK_FID, {STIMPAK: 1})
        op = ContainerOpPayload(
            kind=int(ContainerOpKind.TAKE), container_form_id=TRUNK_FID,
            container_base_id=0x913FB, container_cell_id=TRUNK_CELL,
            item_base_id=STIMPAK, count=1, timestamp_ms=0,
        )
        r = validate_container_op(_session(), op, s.container_state_for_op(op), 0.0)
        assert not r.ok and r.reason == RejectReason.IDENTITY_MISMATCH
        assert s.record_container_op(op, "alice", 1.0) is None

    def test_a_new_death_drops_the_corpse_record(self):
        """Loot rework L4.1: a death makes a new corpse with a new roll. The
        previous corpse's record (looted out yesterday) must not empty it:
        measured 2026-09-25, four raiders killed again lost their fresh loot
        at the activation. A replay of a known death keeps the record."""
        s = ServerState()
        s.create_container(CORPSE_FID, BASE_ON_B, CELL_ON_A, {}, "bob", 0.0)
        assert s.container_state(CORPSE_FID) is not None
        assert s.forget_container(CORPSE_FID) is True
        assert s.container_state(CORPSE_FID) is None
        assert s.forget_container(CORPSE_FID) is False
        assert NPC_DEATH_FLAG_REPLAY == 0x01
