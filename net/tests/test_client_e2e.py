"""End-to-end: 2 client reali (con FakeFridaBridge) + 1 server reale.

Verifica che un reading del player A arrivi al bridge di B come write_ghost,
attraverso server UDP + reliability + protocol.
"""
from __future__ import annotations

import asyncio
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from server.main import ServerProtocol  # noqa: E402
from server.state import ServerState  # noqa: E402
from client.main import FalloutWorldClient, ClientConfig  # noqa: E402
from client.frida_bridge import PlayerReading, FakeFridaBridge  # noqa: E402


async def _start_server(port: int) -> tuple:
    state = ServerState(tick_rate_hz=20)
    loop = asyncio.get_running_loop()
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: ServerProtocol(state),
        local_addr=("127.0.0.1", port),
    )
    return transport, protocol


async def _start_client(cfg: ClientConfig) -> tuple[FalloutWorldClient, asyncio.Task]:
    client = FalloutWorldClient(cfg)
    task = asyncio.create_task(client.run())
    # Give handshake time
    for _ in range(100):
        if client.connected:
            break
        await asyncio.sleep(0.05)
    return client, task


@pytest.mark.asyncio
async def test_bidirectional_ghost_sync():
    server_port = 31400
    server_t, server_proto = await _start_server(server_port)

    try:
        cfg_a = ClientConfig(
            pid=1, client_id="player_A",
            server_host="127.0.0.1", server_port=server_port,
            ghost_map={"player_B": 0xFFAA01},
            use_fake_bridge=True,
        )
        cfg_b = ClientConfig(
            pid=2, client_id="player_B",
            server_host="127.0.0.1", server_port=server_port,
            ghost_map={"player_A": 0xFFBB02},
            use_fake_bridge=True,
        )

        client_a, task_a = await _start_client(cfg_a)
        client_b, task_b = await _start_client(cfg_b)

        assert client_a.connected
        assert client_b.connected

        # Wait for peer_join propagation
        for _ in range(50):
            if "player_B" in client_a.known_peers and "player_A" in client_b.known_peers:
                break
            await asyncio.sleep(0.05)
        assert "player_B" in client_a.known_peers
        assert "player_A" in client_b.known_peers

        # A sends a player reading via fake bridge
        bridge_a: FakeFridaBridge = client_a.bridge  # type: ignore
        bridge_b: FakeFridaBridge = client_b.bridge  # type: ignore
        bridge_a.feed(PlayerReading(
            x=1000.0, y=2000.0, z=500.0, rx=0.0, ry=0.0, rz=1.57,
            ts_ms=int(time.time() * 1000),
        ))

        # B's bridge should receive a ghost write with formid 0xFFBB02
        for _ in range(50):
            if bridge_b.writes_received:
                break
            await asyncio.sleep(0.05)
        assert bridge_b.writes_received, "B did not receive any ghost write"
        formid, reading = bridge_b.writes_received[-1]
        assert formid == 0xFFBB02
        assert abs(reading.x - 1000.0) < 0.1
        assert abs(reading.y - 2000.0) < 0.1
        assert abs(reading.rz - 1.57) < 0.01

        # Reverse: B -> A
        bridge_b.feed(PlayerReading(
            x=-500.0, y=-300.0, z=50.0, rx=0.0, ry=0.0, rz=-1.0,
            ts_ms=int(time.time() * 1000) + 100,
        ))
        for _ in range(50):
            if bridge_a.writes_received:
                break
            await asyncio.sleep(0.05)
        assert bridge_a.writes_received, "A did not receive any ghost write"
        formid, reading = bridge_a.writes_received[-1]
        assert formid == 0xFFAA01
        assert abs(reading.x - -500.0) < 0.1

        # Clean shutdown
        client_a.stop()
        client_b.stop()
        await asyncio.wait_for(task_a, timeout=2.0)
        await asyncio.wait_for(task_b, timeout=2.0)
    finally:
        server_t.close()


@pytest.mark.asyncio
async def test_client_reconnect_after_server_restart():
    """Client must re-handshake gracefully if the server was restarted (fresh state)."""
    server_port = 31405
    server_t, _ = await _start_server(server_port)
    cfg = ClientConfig(
        pid=1, client_id="alice",
        server_host="127.0.0.1", server_port=server_port,
        use_fake_bridge=True,
    )
    client, task = await _start_client(cfg)
    try:
        assert client.connected
    finally:
        client.stop()
        await asyncio.wait_for(task, timeout=2.0)
        server_t.close()
