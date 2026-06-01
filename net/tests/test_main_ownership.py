"""Integration tests for Build 65 owner-driven NPC sync wire-up in main.py.

Covers the seams that test_ownership.py (pure-registry) cannot reach:
- NPC_OBSERVED → PHASE_2 broadcast fan-out
- NPC_OWNERSHIP_BCAST bootstrap on join
- Peer disconnect → release-all + PHASE_2 fan-out
- Periodic tick → health-gate release
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
    MessageType,
    HelloPayload, WelcomePayload,
    NPCObservedPayload,
    NPCOwnershipBcastPayload,
    NPCOwnershipHandoffPhase2Payload,
    encode_frame, decode_frame,
)
from server.main import ServerProtocol, _now_ms  # noqa: E402
from server.ownership import HEARTBEAT_TIMEOUT_MS  # noqa: E402
from server.state import ServerState  # noqa: E402


# ----------------------------------------------------------------- harness

async def _periodic_tick_driver(protocol: ServerProtocol, rate_hz: int) -> None:
    interval = 1.0 / rate_hz
    while True:
        await asyncio.sleep(interval)
        protocol.tick(_now_ms())


async def _start_server(port: int, tick_hz: int = 50) -> tuple:
    state = ServerState(tick_rate_hz=tick_hz)
    loop = asyncio.get_running_loop()
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: ServerProtocol(state),
        local_addr=("127.0.0.1", port),
    )
    loop.create_task(_periodic_tick_driver(protocol, tick_hz))
    return transport, protocol


class FakeClient(asyncio.DatagramProtocol):
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
        lambda: fake, local_addr=("127.0.0.1", 0),
    )
    fake.transport = transport
    fake.server_addr = ("127.0.0.1", server_port)
    return fake


async def _wait_for(client: FakeClient, msg_type: int, timeout: float = 2.0) -> bytes:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for raw in list(client.received):
            try:
                frame = decode_frame(raw)
            except Exception:
                continue
            if frame.header.msg_type == msg_type:
                client.received.remove(raw)
                return raw
        await asyncio.sleep(0.01)
    raise TimeoutError(f"no msg_type=0x{msg_type:04X} within {timeout}s")


async def _drain_for(client: FakeClient, msg_type: int,
                     duration: float = 0.3) -> list[bytes]:
    """Collect every frame of msg_type seen in `duration` seconds."""
    deadline = time.monotonic() + duration
    out: list[bytes] = []
    while time.monotonic() < deadline:
        for raw in list(client.received):
            try:
                frame = decode_frame(raw)
            except Exception:
                continue
            if frame.header.msg_type == msg_type:
                client.received.remove(raw)
                out.append(raw)
        await asyncio.sleep(0.01)
    return out


async def _handshake(client: FakeClient, client_id: str, seq: int = 1) -> None:
    hello = HelloPayload(
        client_id=client_id, client_version_major=1, client_version_minor=0,
    )
    client.send(encode_frame(MessageType.HELLO, seq, hello))
    await _wait_for(client, MessageType.WELCOME)


# ----------------------------------------------------------------- ports

@pytest.fixture
def server_port() -> int:
    return 31420


@pytest.fixture
def server_port2() -> int:
    return 31421


@pytest.fixture
def server_port3() -> int:
    return 31422


@pytest.fixture
def server_port4() -> int:
    return 31423


# ----------------------------------------------------------------- tests


@pytest.mark.asyncio
async def test_npc_observed_emits_phase2_to_all(server_port):
    """First NPC_OBSERVED claims ownership and broadcasts PHASE_2."""
    transport, protocol = await _start_server(server_port)
    try:
        alice = await _make_client(server_port)
        bob = await _make_client(server_port)
        await _handshake(alice, "alice", seq=1)
        await _handshake(bob, "bob", seq=2)

        # Alice observes NPC 0x100.
        obs = NPCObservedPayload(
            form_id=0x100, base_id=0xCAFE, cell_id=0xBABE,
            pos_x=10.0, pos_y=20.0, pos_z=5.0,
            observer_distance_sq=1000.0,
        )
        alice.send(encode_frame(MessageType.NPC_OBSERVED, 100, obs))

        # Both clients should receive PHASE_2.
        raw_a = await _wait_for(alice, MessageType.NPC_OWNERSHIP_HANDOFF_PHASE_2)
        raw_b = await _wait_for(bob, MessageType.NPC_OWNERSHIP_HANDOFF_PHASE_2)
        for raw in (raw_a, raw_b):
            frame = decode_frame(raw)
            payload = frame.payload
            assert isinstance(payload, NPCOwnershipHandoffPhase2Payload)
            assert payload.form_id == 0x100
            assert payload.new_owner_peer_id.rstrip(b"\x00") == b"alice"
            assert payload.new_epoch == 1

        assert protocol.ownership.is_owner("alice", 0x100)
        assert protocol._counters["ownership_observed"] >= 1
        assert protocol._counters["ownership_changes"] >= 1
    finally:
        transport.close()
        alice.transport.close()
        bob.transport.close()


@pytest.mark.asyncio
async def test_ownership_bootstrap_on_join(server_port2):
    """New peer joins; receives current ownership table via NPC_OWNERSHIP_BCAST."""
    transport, protocol = await _start_server(server_port2)
    try:
        alice = await _make_client(server_port2)
        await _handshake(alice, "alice", seq=1)

        # Alice claims two NPCs.
        for fid in (0x100, 0x101):
            obs = NPCObservedPayload(
                form_id=fid, base_id=0xCAFE, cell_id=0xBABE,
                pos_x=0.0, pos_y=0.0, pos_z=0.0,
                observer_distance_sq=500.0,
            )
            alice.send(encode_frame(MessageType.NPC_OBSERVED, 100 + fid, obs))
            await _wait_for(alice, MessageType.NPC_OWNERSHIP_HANDOFF_PHASE_2)

        # Bob joins late.
        bob = await _make_client(server_port2)
        await _handshake(bob, "bob", seq=2)

        raw = await _wait_for(bob, MessageType.NPC_OWNERSHIP_BCAST)
        frame = decode_frame(raw)
        payload = frame.payload
        assert isinstance(payload, NPCOwnershipBcastPayload)
        fids = sorted(e.form_id for e in payload.entries)
        assert fids == [0x100, 0x101]
        # Epoch is registry-global and monotonic, so the two claims got
        # 1 and 2 respectively. Don't assert exact values, just that
        # they're set and distinct (Solver 2 §1.3 epoch invariant).
        epochs = {e.epoch for e in payload.entries}
        assert len(epochs) == 2
        for e in payload.entries:
            assert e.owner_peer_id.rstrip(b"\x00") == b"alice"
            assert e.epoch >= 1
    finally:
        transport.close()
        alice.transport.close()
        bob.transport.close()


@pytest.mark.asyncio
async def test_bootstrap_skipped_when_empty(server_port3):
    """No NPC_OWNERSHIP_BCAST sent when registry is empty (saves bytes)."""
    transport, protocol = await _start_server(server_port3)
    try:
        alice = await _make_client(server_port3)
        await _handshake(alice, "alice", seq=1)
        # Nothing observed → no bootstrap frame for the second peer.
        bob = await _make_client(server_port3)
        await _handshake(bob, "bob", seq=2)
        with pytest.raises(TimeoutError):
            await _wait_for(bob, MessageType.NPC_OWNERSHIP_BCAST, timeout=0.4)
    finally:
        transport.close()
        alice.transport.close()
        bob.transport.close()


@pytest.mark.asyncio
async def test_peer_disconnect_releases_owned(server_port4):
    """When the owner disconnects, all its NPCs are released; PHASE_2 with
    all-zero new_owner is broadcast to surviving peers."""
    transport, protocol = await _start_server(server_port4)
    try:
        alice = await _make_client(server_port4)
        bob = await _make_client(server_port4)
        await _handshake(alice, "alice", seq=1)
        await _handshake(bob, "bob", seq=2)

        # Alice claims two NPCs.
        owned_fids = (0x100, 0x101)
        for fid in owned_fids:
            obs = NPCObservedPayload(
                form_id=fid, base_id=0xCAFE, cell_id=0xBABE,
                pos_x=0.0, pos_y=0.0, pos_z=0.0,
                observer_distance_sq=500.0,
            )
            alice.send(encode_frame(MessageType.NPC_OBSERVED, 100 + fid, obs))
            await _wait_for(alice, MessageType.NPC_OWNERSHIP_HANDOFF_PHASE_2)
            await _wait_for(bob, MessageType.NPC_OWNERSHIP_HANDOFF_PHASE_2)

        # Yank alice. The cleanest scriptable disconnect = close her UDP
        # socket and wait for the stale-timeout sweep. But that takes ≥
        # state.peer_timeout_ms. Faster path: invoke the protocol's
        # internal kick directly.
        alice_session = next(
            s for s in protocol.state.all_sessions() if s.peer_id == "alice"
        )
        protocol._remove_and_notify(
            alice_session, reason=1, now_ms=_now_ms(),
        )

        # Bob should now receive two PHASE_2 release frames (all-zero
        # peer_id). The reliability channel can retransmit prior claim
        # frames too (since bob never ACK'd them), so filter on the
        # release marker.
        release_fids: set[int] = set()
        deadline = time.monotonic() + 1.0
        while time.monotonic() < deadline:
            for raw in list(bob.received):
                try:
                    frame = decode_frame(raw)
                except Exception:
                    continue
                if frame.header.msg_type != MessageType.NPC_OWNERSHIP_HANDOFF_PHASE_2:
                    continue
                bob.received.remove(raw)
                payload = frame.payload
                if isinstance(payload, NPCOwnershipHandoffPhase2Payload) and \
                        payload.new_owner_peer_id == b"\x00" * 16:
                    release_fids.add(payload.form_id)
            if release_fids == set(owned_fids):
                break
            await asyncio.sleep(0.02)
        assert release_fids == set(owned_fids), (
            f"expected releases for {owned_fids}, got {release_fids}")

        # Registry now reports both fids unowned.
        assert protocol.ownership.get(0x100) is None
        assert protocol.ownership.get(0x101) is None
    finally:
        transport.close()
        alice.transport.close()
        bob.transport.close()


def test_health_gate_via_protocol_tick():
    """Synthetic: drive periodic_tick directly. Owner with no heartbeat
    past HEARTBEAT_TIMEOUT_MS gets released by `protocol.tick`."""
    state = ServerState(tick_rate_hz=10)
    protocol = ServerProtocol(state)

    # Inject a fake session so the registry has somewhere to claim from.
    obs = NPCObservedPayload(
        form_id=0x100, base_id=0, cell_id=0,
        pos_x=0.0, pos_y=0.0, pos_z=0.0,
        observer_distance_sq=1.0,
    )
    # Claim at t=0.
    protocol.ownership.on_observed(obs, "peerX", now_ms=0.0)
    assert protocol.ownership.is_owner("peerX", 0x100)

    # Tick well past the timeout. transport is None so emits are no-ops
    # but the registry still mutates.
    protocol.tick(now_ms=HEARTBEAT_TIMEOUT_MS + 1000.0)

    assert protocol.ownership.get(0x100) is None
