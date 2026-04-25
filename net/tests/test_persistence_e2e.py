"""End-to-end persistence: server restarts, client reconnecting sees prior world state."""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from protocol import (  # noqa: E402
    MessageType, HelloPayload, WorldStatePayload,
    encode_frame, decode_frame,
)
from server.main import ServerProtocol, Config, run_server  # noqa: E402
from server.state import ServerState  # noqa: E402
from server.persistence import snapshot  # noqa: E402
from client.main import FalloutWorldClient, ClientConfig  # noqa: E402
from client.frida_bridge import PlayerReading, KillEvent  # noqa: E402


async def _start_server_with_state(state: ServerState, port: int):
    loop = asyncio.get_running_loop()
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: ServerProtocol(state),
        local_addr=("127.0.0.1", port),
    )
    # Start tick driver (required for ACK emission)
    from net.tests.test_server_integration import _periodic_tick_driver
    loop.create_task(_periodic_tick_driver(protocol, 20))
    return transport, protocol


@pytest.mark.asyncio
async def test_new_client_receives_world_state_bootstrap():
    """A fresh client joining a server with pre-existing dead actors receives WORLD_STATE."""
    port = 31450
    # Seed server with some world state. Every entry must carry stable identity
    # (base_id, cell_id) — the server refuses to persist events without it.
    state = ServerState()
    from protocol import ActorEventPayload, ActorEventKind
    # Three distinct identities (same base repeated in different cells).
    fixtures = [
        # (base, cell, alive, ref_hint)
        (0x20593, 0x1696A, False, 0xFF001000),   # dead
        (0x20593, 0x2F1C3, True,  0xFF001001),   # alive
        (0x20594, 0x1696A, False, 0xFF001002),   # dead
    ]
    for base, cell, alive, ref in fixtures:
        spawn = ActorEventPayload(
            kind=int(ActorEventKind.SPAWN), form_id=ref, actor_base_id=base,
            x=0, y=0, z=0, extra=0, cell_id=cell,
        )
        state.record_actor_event(spawn, "seed", 1.0)
        if not alive:
            kill = ActorEventPayload(
                kind=int(ActorEventKind.KILL), form_id=ref, actor_base_id=base,
                x=0, y=0, z=0, extra=0, cell_id=cell,
            )
            state.record_actor_event(kill, "seed", 2.0)

    transport, protocol = await _start_server_with_state(state, port)

    try:
        cfg = ClientConfig(
            pid=1, client_id="alice",
            server_host="127.0.0.1", server_port=port,
            use_fake_bridge=True,
        )
        client = FalloutWorldClient(cfg)
        task = asyncio.create_task(client.run())

        # Wait for bootstrap to complete
        for _ in range(100):
            if client.bootstrap_complete:
                break
            await asyncio.sleep(0.05)
        assert client.bootstrap_complete, "client never completed bootstrap"
        # Client view is now keyed by (base_id, cell_id).
        alive_view = {
            key: entry.alive for key, entry in client.world_state.items()
        }
        assert alive_view == {
            (0x20593, 0x1696A): False,
            (0x20593, 0x2F1C3): True,
            (0x20594, 0x1696A): False,
        }

        client.stop()
        await asyncio.wait_for(task, timeout=2.0)
    finally:
        transport.close()


@pytest.mark.asyncio
async def test_bootstrap_triggers_disable_enable_on_bridge():
    """After WORLD_STATE bootstrap, client must call set_disabled_validated on
    the bridge for each actor according to alive/dead state — with the full
    identity tuple (base_id, cell_id) so the JS side can reject mismatches."""
    port = 31470
    state = ServerState()
    from protocol import ActorEventPayload, ActorEventKind
    # 3 distinct identities. Two will be killed.
    fixtures = [
        # (base, cell, ref_hint)
        (0xB0A001, 0x1696A, 0xCAFE01),
        (0xB0A002, 0x1696A, 0xCAFE02),
        (0xB0A003, 0x2F1C3, 0xCAFE03),
    ]
    for base, cell, ref in fixtures:
        e = ActorEventPayload(kind=int(ActorEventKind.SPAWN), form_id=ref,
                               actor_base_id=base, x=0, y=0, z=0, extra=0,
                               cell_id=cell)
        state.record_actor_event(e, "seeder", 100.0)
    # Kill 1st and 3rd
    for base, cell, ref in (fixtures[0], fixtures[2]):
        k = ActorEventPayload(kind=int(ActorEventKind.KILL), form_id=ref,
                               actor_base_id=base, x=0, y=0, z=0, extra=0,
                               cell_id=cell)
        state.record_actor_event(k, "seeder", 200.0)

    transport, _ = await _start_server_with_state(state, port)
    try:
        cfg = ClientConfig(
            pid=1, client_id="fresh",
            server_host="127.0.0.1", server_port=port,
            use_fake_bridge=True,
        )
        client = FalloutWorldClient(cfg)
        task = asyncio.create_task(client.run())

        for _ in range(100):
            if client.bootstrap_complete:
                break
            await asyncio.sleep(0.05)
        assert client.bootstrap_complete

        # Give one more tick for _apply_world_state_to_local to run
        await asyncio.sleep(0.1)

        # All 3 actors must have been processed via the validated path,
        # carrying full identity for the JS-side safety check.
        calls = client.bridge.validated_disabled_calls
        called_bases = {entry[1] for entry in calls}
        assert called_bases == {0xB0A001, 0xB0A002, 0xB0A003}

        disabled_set = {entry[1] for entry in calls if entry[3] is True}
        enabled_set  = {entry[1] for entry in calls if entry[3] is False}
        assert disabled_set == {0xB0A001, 0xB0A003}
        assert enabled_set == {0xB0A002}

        # The unvalidated path must NOT have been used — that's the bug fix.
        assert client.bridge.disabled_calls == []

        client.stop()
        await asyncio.wait_for(task, timeout=2.0)
    finally:
        transport.close()


@pytest.mark.asyncio
async def test_live_kill_propagation():
    """Client A captures a kill via Frida bridge (with full identity read from
    the REFR's baseForm + parentCell), sends ACTOR_EVENT, server broadcasts to
    B, B's bridge receives set_disabled_validated call — identity flows all
    the way through.

    Also verifies the server persisted the kill in world_actors keyed by
    (base_id, cell_id).
    """
    port = 31480
    state = ServerState()
    # Seed: one shared identity that's alive in server state.
    # Use a base that is NOT in ghost_target_base_ids (Codsworth TESNPC 0x179FF
    # is protected — see test_ghost_target_kill_is_not_persisted_or_broadcast
    # for the explicit ghost-target regression coverage).
    from protocol import ActorEventPayload, ActorEventKind
    VICTIM_BASE = 0x20593          # generic NPC TESNPC (non-ghost)
    VICTIM_CELL = 0x1696A          # Sanctuary
    VICTIM_REF  = 0xDEAD01         # runtime ref hint
    spawn = ActorEventPayload(
        kind=int(ActorEventKind.SPAWN), form_id=VICTIM_REF,
        actor_base_id=VICTIM_BASE, x=0, y=0, z=0, extra=0,
        cell_id=VICTIM_CELL,
    )
    state.record_actor_event(spawn, "seed", 0.0)

    transport, protocol = await _start_server_with_state(state, port)
    try:
        cfg_a = ClientConfig(pid=1, client_id="A",
                             server_host="127.0.0.1", server_port=port,
                             use_fake_bridge=True)
        cfg_b = ClientConfig(pid=2, client_id="B",
                             server_host="127.0.0.1", server_port=port,
                             use_fake_bridge=True)
        client_a = FalloutWorldClient(cfg_a)
        client_b = FalloutWorldClient(cfg_b)
        task_a = asyncio.create_task(client_a.run())
        task_b = asyncio.create_task(client_b.run())

        # Wait for both to connect + bootstrap
        for _ in range(100):
            if (client_a.connected and client_b.connected
                and client_a.bootstrap_complete and client_b.bootstrap_complete):
                break
            await asyncio.sleep(0.05)
        assert client_a.connected and client_b.connected

        # A captures a kill on the shared actor, carrying full identity
        # (as the Frida hook in v2 always does via readRefIdentity).
        bridge_a = client_a.bridge
        bridge_a.feed_kill(KillEvent(
            victim_form_id=VICTIM_REF,
            killer_form_id=0x14,
            victim_base_id=VICTIM_BASE,
            victim_cell_id=VICTIM_CELL,
        ))

        # Wait for the reliable event to roundtrip A -> server -> B and
        # appear as a validated disable on B's bridge.
        key = (VICTIM_REF, VICTIM_BASE, VICTIM_CELL, True)
        for _ in range(100):
            if any(entry == key for entry in client_b.bridge.validated_disabled_calls):
                break
            await asyncio.sleep(0.05)

        assert any(entry == key for entry in client_b.bridge.validated_disabled_calls), (
            f"B did not apply validated disable for VICTIM. "
            f"Got: {client_b.bridge.validated_disabled_calls}"
        )

        # Server must have updated its authoritative state, identity-keyed.
        server_view = protocol.state.actor_state(VICTIM_BASE, VICTIM_CELL)
        assert server_view is not None
        assert server_view.alive is False, "server didn't mark actor dead"
        assert server_view.last_owner_peer_id == "A"
        assert server_view.last_known_form_id == VICTIM_REF

        # Client stats
        assert client_a.stats["kills_captured"] >= 1
        assert client_b.stats["kills_broadcast_received"] >= 1

        client_a.stop(); client_b.stop()
        await asyncio.wait_for(task_a, timeout=2.0)
        await asyncio.wait_for(task_b, timeout=2.0)
    finally:
        transport.close()


@pytest.mark.asyncio
async def test_ghost_target_kill_is_not_persisted_or_broadcast():
    """Regression for the original Option B bug: a kill on a ghost-avatar
    actor must be silently dropped at the server. Future sessions will not
    re-apply a 'Codsworth is dead' state at bootstrap, and the other peer
    will not disable its own Codsworth copy."""
    port = 31490
    GHOST_BASE = 0x179FF      # Codsworth TESNPC (base form in Fallout4.esm)
    GHOST_CELL = 0x1696A      # Sanctuary

    # Server is seeded with the default ghost_target_base_ids={0x179FF}.
    state = ServerState()
    assert GHOST_BASE in state.ghost_target_base_ids

    transport, protocol = await _start_server_with_state(state, port)
    try:
        cfg_a = ClientConfig(pid=1, client_id="A",
                             server_host="127.0.0.1", server_port=port,
                             use_fake_bridge=True)
        cfg_b = ClientConfig(pid=2, client_id="B",
                             server_host="127.0.0.1", server_port=port,
                             use_fake_bridge=True)
        client_a = FalloutWorldClient(cfg_a)
        client_b = FalloutWorldClient(cfg_b)
        task_a = asyncio.create_task(client_a.run())
        task_b = asyncio.create_task(client_b.run())

        for _ in range(100):
            if (client_a.connected and client_b.connected
                and client_a.bootstrap_complete and client_b.bootstrap_complete):
                break
            await asyncio.sleep(0.05)
        assert client_a.connected and client_b.connected

        # A captures a kill on Codsworth (ghost target) with full identity.
        client_a.bridge.feed_kill(KillEvent(
            victim_form_id=0xFF00136F,
            killer_form_id=0x14,
            victim_base_id=GHOST_BASE,
            victim_cell_id=GHOST_CELL,
        ))

        # Give plenty of time for the roundtrip (reliable retransmit cadence).
        await asyncio.sleep(1.0)

        # Server must NOT have persisted the kill — Codsworth's identity has
        # no entry in world_actors.
        assert protocol.state.actor_state(GHOST_BASE, GHOST_CELL) is None

        # B must NOT have received any validated disable for this identity.
        bad = [
            entry for entry in client_b.bridge.validated_disabled_calls
            if entry[1] == GHOST_BASE and entry[2] == GHOST_CELL
        ]
        assert bad == [], (
            f"B applied validated disable on ghost target: {bad}"
        )

        # And the unvalidated path better not be used either.
        assert client_b.bridge.disabled_calls == []

        client_a.stop(); client_b.stop()
        await asyncio.wait_for(task_a, timeout=2.0)
        await asyncio.wait_for(task_b, timeout=2.0)
    finally:
        transport.close()


@pytest.mark.asyncio
async def test_server_restore_then_replay_to_new_client(tmp_path: Path):
    """Full lifecycle: server A persists -> server A dies -> server B restarts from snapshot
    -> new client joins server B -> receives same world state."""
    port_a = 31460
    port_b = 31461

    # --- Phase 1: server A accumulates state and snapshots ---
    state_a = ServerState()
    from protocol import ActorEventPayload, ActorEventKind
    # 3 distinct identities spawned (same base, different cells), 1 killed.
    fixtures = [
        (0x20593, 0x1696A, 0xFFAA01),
        (0x20593, 0x2F1C3, 0xFFAA02),
        (0x20594, 0x1696A, 0xFFAA03),
    ]
    for base, cell, ref in fixtures:
        e = ActorEventPayload(kind=int(ActorEventKind.SPAWN), form_id=ref,
                               actor_base_id=base, x=0, y=0, z=0, extra=0,
                               cell_id=cell)
        state_a.record_actor_event(e, "survivor", 100.0)
    # Kill the middle one
    base, cell, ref = fixtures[1]
    kill = ActorEventPayload(kind=int(ActorEventKind.KILL), form_id=ref,
                              actor_base_id=base, x=0, y=0, z=0, extra=0,
                              cell_id=cell)
    state_a.record_actor_event(kill, "survivor", 200.0)

    snap_path = tmp_path / "snap.json"
    snapshot(state_a, snap_path)

    # --- Phase 2: "restart" — new state loaded from snapshot ---
    from server.persistence import load_into
    state_b = ServerState()
    n = load_into(state_b, snap_path)
    assert n == 3
    assert state_b.actor_state(0x20593, 0x2F1C3).alive is False   # killed
    assert state_b.actor_state(0x20593, 0x1696A).alive is True    # alive
    assert state_b.actor_state(0x20594, 0x1696A).alive is True    # alive

    transport, protocol = await _start_server_with_state(state_b, port_b)

    try:
        # --- Phase 3: new client connects, expects bootstrap reflecting snapshot ---
        cfg = ClientConfig(
            pid=1, client_id="newcomer",
            server_host="127.0.0.1", server_port=port_b,
            use_fake_bridge=True,
        )
        client = FalloutWorldClient(cfg)
        task = asyncio.create_task(client.run())

        for _ in range(100):
            if client.bootstrap_complete:
                break
            await asyncio.sleep(0.05)
        assert client.bootstrap_complete

        # World state from snapshot faithfully delivered — identity-keyed.
        assert client.world_state[(0x20593, 0x1696A)].alive is True
        assert client.world_state[(0x20593, 0x2F1C3)].alive is False
        assert client.world_state[(0x20594, 0x1696A)].alive is True

        client.stop()
        await asyncio.wait_for(task, timeout=2.0)
    finally:
        transport.close()
