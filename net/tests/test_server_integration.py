"""End-to-end integration tests: real asyncio server + fake UDP clients.

Verifies HELLO/WELCOME handshake, POS broadcast, PEER_JOIN/LEAVE notifications,
reliable ACK roundtrip. Does NOT touch Frida or FO4.
"""
from __future__ import annotations

import asyncio
import sys
import time
from pathlib import Path
from typing import Optional

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from protocol import (  # noqa: E402
    MessageType, HelloPayload, WelcomePayload, PeerJoinPayload, PeerLeavePayload,
    PosStatePayload, PosBroadcastPayload, ChatPayload, AckPayload,
    ActorEventPayload, ActorEventKind,
    encode_frame, decode_frame,
)
from server.main import ServerProtocol, Config, _now_ms  # noqa: E402
from server.state import ServerState  # noqa: E402


async def _periodic_tick_driver(protocol: ServerProtocol, rate_hz: int) -> None:
    """Mirror the real server's _periodic_tick so ACK timers fire."""
    interval = 1.0 / rate_hz
    while True:
        await asyncio.sleep(interval)
        protocol.tick(_now_ms())


async def _start_server(port: int, tick_hz: int = 20) -> tuple[asyncio.DatagramTransport, ServerProtocol]:
    """Start a server on 127.0.0.1:port. Returns (transport, protocol) for teardown."""
    state = ServerState(tick_rate_hz=tick_hz)
    loop = asyncio.get_running_loop()
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: ServerProtocol(state),
        local_addr=("127.0.0.1", port),
    )
    # Run periodic tick so reliability timers fire (matches run_server in main)
    loop.create_task(_periodic_tick_driver(protocol, tick_hz))
    return transport, protocol


class FakeClient(asyncio.DatagramProtocol):
    """Minimal UDP client for tests: collects frames, sends raw bytes."""

    def __init__(self) -> None:
        self.transport: Optional[asyncio.DatagramTransport] = None
        self.received: list[bytes] = []
        self.server_addr: Optional[tuple[str, int]] = None

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:  # type: ignore[override]
        self.transport = transport

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        self.received.append(data)

    def send(self, data: bytes) -> None:
        assert self.transport is not None and self.server_addr is not None
        self.transport.sendto(data, self.server_addr)


async def _make_client(server_port: int) -> FakeClient:
    loop = asyncio.get_running_loop()
    fake = FakeClient()
    transport, _ = await loop.create_datagram_endpoint(
        lambda: fake,
        local_addr=("127.0.0.1", 0),  # ephemeral
    )
    fake.transport = transport
    fake.server_addr = ("127.0.0.1", server_port)
    return fake


async def _wait_for(client: FakeClient, msg_type: int, timeout: float = 2.0) -> bytes:
    """Wait until client.received contains a frame of the given type."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for raw in client.received:
            try:
                frame = decode_frame(raw)
            except Exception:
                continue
            if frame.header.msg_type == msg_type:
                client.received.remove(raw)
                return raw
        await asyncio.sleep(0.01)
    raise TimeoutError(f"no msg_type=0x{msg_type:04X} within {timeout}s")


# ------------------------------------------------------------------ fixtures

@pytest.fixture
def server_port() -> int:
    # Try a few ports in the ephemeral range to avoid collision on parallel test runs
    return 31340


# ------------------------------------------------------------------ tests

@pytest.mark.asyncio
async def test_hello_welcome_handshake(server_port):
    transport, protocol = await _start_server(server_port)
    try:
        alice = await _make_client(server_port)
        # Send HELLO
        hello = HelloPayload(client_id="alice", client_version_major=1, client_version_minor=0)
        alice.send(encode_frame(MessageType.HELLO, 1, hello))

        # Expect WELCOME
        raw = await _wait_for(alice, MessageType.WELCOME)
        frame = decode_frame(raw)
        assert isinstance(frame.payload, WelcomePayload)
        assert frame.payload.accepted
        assert frame.payload.session_id > 0

        # Server now has alice registered
        sessions = protocol.state.all_sessions()
        assert len(sessions) == 1
        assert sessions[0].peer_id == "alice"
    finally:
        transport.close()
        alice.transport.close()


@pytest.mark.asyncio
async def test_duplicate_peer_id_rejected(server_port):
    transport, protocol = await _start_server(server_port + 1)
    try:
        alice1 = await _make_client(server_port + 1)
        alice1.send(encode_frame(MessageType.HELLO, 1,
                    HelloPayload("alice", 1, 0)))
        await _wait_for(alice1, MessageType.WELCOME)

        # Second client tries same id
        alice2 = await _make_client(server_port + 1)
        alice2.send(encode_frame(MessageType.HELLO, 1,
                    HelloPayload("alice", 1, 0)))
        raw = await _wait_for(alice2, MessageType.WELCOME)
        frame = decode_frame(raw)
        assert isinstance(frame.payload, WelcomePayload)
        assert frame.payload.accepted is False
    finally:
        transport.close()


@pytest.mark.asyncio
async def test_pos_broadcast_to_others(server_port):
    port = server_port + 2
    transport, protocol = await _start_server(port)
    try:
        alice = await _make_client(port)
        bob = await _make_client(port)
        alice.send(encode_frame(MessageType.HELLO, 1, HelloPayload("alice", 1, 0)))
        bob.send(encode_frame(MessageType.HELLO, 1, HelloPayload("bob", 1, 0)))

        await _wait_for(alice, MessageType.WELCOME)
        await _wait_for(bob, MessageType.WELCOME)
        # Both also get PEER_JOIN for the other
        await _wait_for(alice, MessageType.PEER_JOIN)
        await _wait_for(bob, MessageType.PEER_JOIN)

        # Alice sends pos state
        pos = PosStatePayload(100.0, 200.0, 50.0, 0.0, 0.0, 1.57, 1000)
        alice.send(encode_frame(MessageType.POS_STATE, 2, pos))

        # Bob should receive POS_BROADCAST
        raw = await _wait_for(bob, MessageType.POS_BROADCAST)
        frame = decode_frame(raw)
        assert isinstance(frame.payload, PosBroadcastPayload)
        assert frame.payload.peer_id == "alice"
        assert abs(frame.payload.x - 100.0) < 1e-3

        # Alice should NOT receive her own broadcast
        await asyncio.sleep(0.1)
        for raw in alice.received:
            frame = decode_frame(raw)
            assert frame.header.msg_type != MessageType.POS_BROADCAST, \
                "alice received her own pos broadcast"
    finally:
        transport.close()


@pytest.mark.asyncio
async def test_reliable_actor_event_acked(server_port):
    port = server_port + 3
    transport, protocol = await _start_server(port)
    try:
        alice = await _make_client(port)
        # HELLO sent reliable (seq 1) — handshake must be acknowledged
        alice.send(encode_frame(MessageType.HELLO, 1, HelloPayload("alice", 1, 0), reliable=True))
        await _wait_for(alice, MessageType.WELCOME)

        # Send a reliable ACTOR_EVENT (SPAWN) at seq 2 with full identity
        # so the server can actually persist it.
        evt = ActorEventPayload(
            kind=int(ActorEventKind.SPAWN), form_id=0xFF001000,
            actor_base_id=0x20593, x=1.0, y=2.0, z=3.0, extra=0,
            cell_id=0x1696A,
        )
        alice.send(encode_frame(MessageType.ACTOR_EVENT, 2, evt, reliable=True))

        # Poll incoming ACKs until we find one that covers seq 2 (server may emit
        # separate ACKs for HELLO and ACTOR_EVENT depending on tick timing).
        import time as _time
        deadline = _time.monotonic() + 2.0
        seq2_acked = False
        while _time.monotonic() < deadline and not seq2_acked:
            try:
                raw = await _wait_for(alice, MessageType.ACK, timeout=0.3)
            except TimeoutError:
                continue   # keep polling until outer deadline
            frame = decode_frame(raw)
            assert isinstance(frame.payload, AckPayload)
            h = frame.payload.highest_contiguous_seq
            b = frame.payload.sack_bitmap
            if h >= 2:
                seq2_acked = True
            elif h < 2 and (b & (1 << ((2 - h - 1) & 31))):
                seq2_acked = True
        assert seq2_acked, "seq 2 was never acknowledged by server"

        # Server state updated — lookup by identity (base, cell), not ref.
        actor = protocol.state.actor_state(0x20593, 0x1696A)
        assert actor is not None
        assert actor.alive is True
        assert actor.last_known_form_id == 0xFF001000
    finally:
        transport.close()


@pytest.mark.asyncio
async def test_peer_leave_on_disconnect(server_port):
    port = server_port + 4
    transport, protocol = await _start_server(port)
    try:
        alice = await _make_client(port)
        bob = await _make_client(port)
        alice.send(encode_frame(MessageType.HELLO, 1, HelloPayload("alice", 1, 0)))
        bob.send(encode_frame(MessageType.HELLO, 1, HelloPayload("bob", 1, 0)))
        await _wait_for(alice, MessageType.WELCOME)
        await _wait_for(bob, MessageType.WELCOME)
        await _wait_for(bob, MessageType.PEER_JOIN)  # bob sees alice

        # Alice sends DISCONNECT
        from protocol import DisconnectPayload
        alice.send(encode_frame(MessageType.DISCONNECT, 2,
                                 DisconnectPayload(reason=0),
                                 reliable=True))
        # Bob gets PEER_LEAVE
        raw = await _wait_for(bob, MessageType.PEER_LEAVE, timeout=2.0)
        frame = decode_frame(raw)
        assert isinstance(frame.payload, PeerLeavePayload)
        assert frame.payload.peer_id == "alice"
    finally:
        transport.close()


@pytest.mark.asyncio
async def test_chat_broadcast(server_port):
    port = server_port + 5
    transport, protocol = await _start_server(port)
    try:
        alice = await _make_client(port)
        bob = await _make_client(port)
        alice.send(encode_frame(MessageType.HELLO, 1, HelloPayload("alice", 1, 0)))
        bob.send(encode_frame(MessageType.HELLO, 1, HelloPayload("bob", 1, 0)))
        await _wait_for(alice, MessageType.WELCOME)
        await _wait_for(bob, MessageType.WELCOME)
        await _wait_for(bob, MessageType.PEER_JOIN)

        # Alice chats
        msg = ChatPayload(sender_id="alice", text="ciao bob")
        alice.send(encode_frame(MessageType.CHAT, 2, msg, reliable=True))

        # Bob receives
        raw = await _wait_for(bob, MessageType.CHAT, timeout=2.0)
        frame = decode_frame(raw)
        assert isinstance(frame.payload, ChatPayload)
        assert frame.payload.text == "ciao bob"
    finally:
        transport.close()


@pytest.mark.asyncio
async def test_invalid_speed_rejected(server_port):
    port = server_port + 6
    transport, protocol = await _start_server(port)
    try:
        alice = await _make_client(port)
        alice.send(encode_frame(MessageType.HELLO, 1, HelloPayload("alice", 1, 0)))
        await _wait_for(alice, MessageType.WELCOME)

        # Baseline pos
        pos1 = PosStatePayload(0.0, 0.0, 0.0, 0, 0, 0, 100)
        alice.send(encode_frame(MessageType.POS_STATE, 2, pos1))
        await asyncio.sleep(0.1)

        session = protocol.state.get_by_peer_id("alice")
        assert session is not None
        updates_before = session.total_pos_updates

        # Teleport way too fast
        pos2 = PosStatePayload(10_000_000.0, 0.0, 0.0, 0, 0, 0, 150)
        alice.send(encode_frame(MessageType.POS_STATE, 3, pos2))
        await asyncio.sleep(0.1)

        # Server should have rejected; total_pos_updates unchanged
        session = protocol.state.get_by_peer_id("alice")
        assert session.total_pos_updates == updates_before
        # And counter-reject incremented
        assert protocol.stats()["rejections"] >= 1
    finally:
        transport.close()
