"""Loot rework L3 (2026-09-23): the server's container contents reach every
client, so the engine can be aligned to them (the client-side reconvergence
lives in the DLL; this file covers the server's half).

Until L3 the CONTAINER_STATE bootstrap skipped empty containers and was
sent once, at the join. A client therefore never learned that a container
it still saw full had been emptied by others, nor that a container another
peer had seeded existed on the server: its own later seed was rejected and
its mirror stayed wrong. Now:
  - a known but EMPTY container travels as a sentinel entry (item 0, count
    0), so the receiver knows to empty it;
  - whenever a container record is CREATED (seed, or the first op on an
    unknown container) or REFILLED, its state is pushed to every peer as a
    live CONTAINER_STATE;
  - a REJECTED seed (the server already knew the container) is answered
    with the server's state, so the seeder's mirror learns it.
"""
from __future__ import annotations

import asyncio
import socket
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from protocol import (  # noqa: E402
    MessageType, ContainerSeedPayload, ContainerStateEntry, ContainerStatePayload,
    ContainerOpPayload, ContainerOpKind,
    encode_frame,
)
from server.state import ServerState, ContainerWorldState  # noqa: E402
from client.main import FalloutWorldClient, ClientConfig  # noqa: E402
from server.validator import validate_container_op, RejectReason  # noqa: E402
from net.tests.test_container import (  # noqa: E402
    TRUNK_BASE, TRUNK_CELL, TRUNK_FID, TWIN_FID, STIMPAK, AMMO_10MM,
    _put, _take, _seeded, _session,
    _start_server_with_state, _raw_peer_hello, _collect_frames,
)


class TestPartialRecords:
    """A record made by an op on a container nobody scanned is partial: it
    knows only what the ops told it. The validator trusts the client on
    items it has never seen (as the first op was trusted), and the first
    scan replaces it whole."""

    def test_partial_record_trusts_unseen_items(self):
        s = ServerState()
        s.record_container_op(_put(TRUNK_FID, STIMPAK, 2), "alice", 0.0)
        rec = s.container_state(TRUNK_FID)
        assert rec.seeded is False
        r = validate_container_op(_session(), _take(TRUNK_FID, AMMO_10MM, 3), rec, 0.0)
        assert r.ok
        # What it HAS seen is enforced: two stimpaks, not three.
        r = validate_container_op(_session(), _take(TRUNK_FID, STIMPAK, 3), rec, 0.0)
        assert not r.ok and r.reason == RejectReason.INSUFFICIENT_ITEMS

    def test_seeded_record_enforces_absence(self):
        s = ServerState()
        _seeded(s, TRUNK_FID, {STIMPAK: 2})
        rec = s.container_state(TRUNK_FID)
        r = validate_container_op(_session(), _take(TRUNK_FID, AMMO_10MM, 1), rec, 0.0)
        assert not r.ok and r.reason == RejectReason.INSUFFICIENT_ITEMS


def _plain(items) -> dict[int, int]:
    """Server lines as {item: count}, every one of them asserted plain: the
    fixtures here deal in ammo and stimpaks (L5 stage 4b keys a line by
    (item, instance fingerprint))."""
    assert all(fp == 0 for _, fp in items), items
    return {iid: n for (iid, _), n in items.items()}


def _state_entries(frames) -> list[ContainerStateEntry]:
    out: list[ContainerStateEntry] = []
    for f, _ in frames:
        if f.header.msg_type == int(MessageType.CONTAINER_STATE) \
                and isinstance(f.payload, ContainerStatePayload):
            out.extend(f.payload.entries)
    return out


def _by_container(entries) -> dict[int, dict[int, int]]:
    """Fold entries the way a receiver does: the sentinel makes the container
    known and empty, a real entry sets one item's count."""
    view: dict[int, dict[int, int]] = {}
    for e in entries:
        bucket = view.setdefault(e.container_form_id, {})
        if e.item_base_id != 0 and e.count > 0:
            bucket[e.item_base_id] = e.count
    return view


@pytest.mark.asyncio
async def test_bootstrap_carries_known_empty_container_as_sentinel():
    port = 31540
    state = ServerState()
    _seeded(state, TRUNK_FID, {STIMPAK: 5})
    state.record_container_op(_take(TRUNK_FID, STIMPAK, 5), "looter", 1.0)   # now empty
    _seeded(state, TWIN_FID, {AMMO_10MM: 100}, now_ms=2.0)
    # A partial record (op only, never scanned) must not travel.
    state.record_container_op(_put(0x1F3A4, STIMPAK, 9), "someone", 3.0)
    transport, _ = await _start_server_with_state(state, port)
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 0))
        try:
            await _raw_peer_hello(sock, ("127.0.0.1", port), "peer_boot")
            entries = _state_entries(await _collect_frames(sock, 0.4))
            sentinel = [e for e in entries if e.container_form_id == TRUNK_FID]
            assert sentinel == [ContainerStateEntry(TRUNK_FID, TRUNK_BASE, TRUNK_CELL, 0, 0)]
            assert _by_container(entries) == {TRUNK_FID: {}, TWIN_FID: {AMMO_10MM: 100}}
        finally:
            sock.close()
    finally:
        transport.close()


@pytest.mark.asyncio
async def test_legacy_client_marks_sentinel_container_known_and_empty():
    port = 31541
    state = ServerState()
    _seeded(state, TRUNK_FID, {STIMPAK: 5})
    state.record_container_op(_take(TRUNK_FID, STIMPAK, 5), "looter", 1.0)
    transport, _ = await _start_server_with_state(state, port)
    try:
        client = FalloutWorldClient(ClientConfig(
            pid=1, client_id="alice", server_host="127.0.0.1", server_port=port,
            use_fake_bridge=True))
        task = asyncio.create_task(client.run())
        for _ in range(100):
            if client.container_bootstrap_complete:
                break
            await asyncio.sleep(0.05)
        assert client.container_bootstrap_complete
        assert client.container_state.get(TRUNK_FID) == {}
        client.stop()
        await asyncio.wait_for(task, timeout=2.0)
    finally:
        transport.close()


async def _two_raw_peers(port: int):
    server_addr = ("127.0.0.1", port)
    sock_a = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock_b = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock_a.bind(("127.0.0.1", 0)); sock_b.bind(("127.0.0.1", 0))
    await asyncio.gather(
        _raw_peer_hello(sock_a, server_addr, f"pA_{port}"),
        _raw_peer_hello(sock_b, server_addr, f"pB_{port}"),
    )
    # Drain the bootstraps so what follows is only the live traffic.
    await asyncio.gather(_collect_frames(sock_a, 0.3), _collect_frames(sock_b, 0.3))
    return server_addr, sock_a, sock_b


@pytest.mark.asyncio
async def test_seed_that_creates_a_record_is_pushed_to_every_peer():
    port = 31542
    transport, protocol_obj = await _start_server_with_state(ServerState(), port)
    try:
        server_addr, sock_a, sock_b = await _two_raw_peers(port)
        try:
            seed = ContainerSeedPayload(entries=(
                ContainerStateEntry(TRUNK_FID, TRUNK_BASE, TRUNK_CELL, STIMPAK, 5),
                ContainerStateEntry(TRUNK_FID, TRUNK_BASE, TRUNK_CELL, AMMO_10MM, 20),
            ))
            sock_a.sendto(encode_frame(MessageType.CONTAINER_SEED, 1, seed, reliable=True),
                          server_addr)
            frames_a, frames_b = await asyncio.gather(
                _collect_frames(sock_a, 0.6), _collect_frames(sock_b, 0.6))
            expected = {TRUNK_FID: {STIMPAK: 5, AMMO_10MM: 20}}
            assert _by_container(_state_entries(frames_b)) == expected
            assert _by_container(_state_entries(frames_a)) == expected
            assert _plain(protocol_obj.state.container_state(TRUNK_FID).items) == expected[TRUNK_FID]
        finally:
            sock_a.close(); sock_b.close()
    finally:
        transport.close()


@pytest.mark.asyncio
async def test_refill_of_an_empty_record_is_pushed():
    port = 31543
    state = ServerState()
    state._containers[TRUNK_FID] = ContainerWorldState(
        form_id=TRUNK_FID, base_id=TRUNK_BASE, cell_id=TRUNK_CELL, items={},
        last_owner_peer_id="past_peer")
    transport, _ = await _start_server_with_state(state, port)
    try:
        server_addr, sock_a, sock_b = await _two_raw_peers(port)
        try:
            seed = ContainerSeedPayload(entries=(
                ContainerStateEntry(TRUNK_FID, TRUNK_BASE, TRUNK_CELL, STIMPAK, 2),
            ))
            sock_a.sendto(encode_frame(MessageType.CONTAINER_SEED, 1, seed, reliable=True),
                          server_addr)
            frames_a, frames_b = await asyncio.gather(
                _collect_frames(sock_a, 0.6), _collect_frames(sock_b, 0.6))
            assert _by_container(_state_entries(frames_b)) == {TRUNK_FID: {STIMPAK: 2}}
            assert _by_container(_state_entries(frames_a)) == {TRUNK_FID: {STIMPAK: 2}}
        finally:
            sock_a.close(); sock_b.close()
    finally:
        transport.close()


@pytest.mark.asyncio
async def test_rejected_seed_is_answered_with_the_server_state():
    """The seeder saw its own engine's roll of the container; the server
    already holds another peer's. The seeder alone gets the server's view,
    the other peer hears nothing (it already has it)."""
    port = 31544
    state = ServerState()
    _seeded(state, TRUNK_FID, {STIMPAK: 5}, by="first")
    transport, protocol_obj = await _start_server_with_state(state, port)
    try:
        server_addr, sock_a, sock_b = await _two_raw_peers(port)
        try:
            seed = ContainerSeedPayload(entries=(
                ContainerStateEntry(TRUNK_FID, TRUNK_BASE, TRUNK_CELL, AMMO_10MM, 30),
            ))
            sock_a.sendto(encode_frame(MessageType.CONTAINER_SEED, 1, seed, reliable=True),
                          server_addr)
            frames_a, frames_b = await asyncio.gather(
                _collect_frames(sock_a, 0.6), _collect_frames(sock_b, 0.6))
            assert _by_container(_state_entries(frames_a)) == {TRUNK_FID: {STIMPAK: 5}}
            assert _state_entries(frames_b) == []
            assert protocol_obj.state.container_state(TRUNK_FID).items == {(STIMPAK, 0): 5}
        finally:
            sock_a.close(); sock_b.close()
    finally:
        transport.close()


@pytest.mark.asyncio
async def test_first_op_on_unknown_container_makes_a_partial_record_not_pushed():
    """A PUT into a container the server has never seen creates a PARTIAL
    record (the op is trusted, the container's other items are unknown).
    Nobody is aligned to it: pushing it would empty the container of
    everything the server never heard of. The BCAST still travels. The
    first scan then replaces it and IS pushed to everyone."""
    port = 31545
    transport, protocol_obj = await _start_server_with_state(ServerState(), port)
    try:
        server_addr, sock_a, sock_b = await _two_raw_peers(port)
        try:
            op = _put(TWIN_FID, AMMO_10MM, 3)
            sock_a.sendto(encode_frame(MessageType.CONTAINER_OP, 1, op, reliable=True),
                          server_addr)
            frames_a, frames_b = await asyncio.gather(
                _collect_frames(sock_a, 0.6), _collect_frames(sock_b, 0.6))
            assert _state_entries(frames_a) == [] and _state_entries(frames_b) == []
            assert any(f.header.msg_type == int(MessageType.CONTAINER_BCAST)
                       for f, _ in frames_b)
            rec = protocol_obj.state.container_state(TWIN_FID)
            assert rec.items == {(AMMO_10MM, 0): 3} and rec.seeded is False

            seed = ContainerSeedPayload(entries=(
                ContainerStateEntry(TWIN_FID, TRUNK_BASE, TRUNK_CELL, AMMO_10MM, 3),
                ContainerStateEntry(TWIN_FID, TRUNK_BASE, TRUNK_CELL, STIMPAK, 4),
            ))
            sock_a.sendto(encode_frame(MessageType.CONTAINER_SEED, 2, seed, reliable=True),
                          server_addr)
            frames_a, frames_b = await asyncio.gather(
                _collect_frames(sock_a, 0.6), _collect_frames(sock_b, 0.6))
            expected = {TWIN_FID: {AMMO_10MM: 3, STIMPAK: 4}}
            assert _by_container(_state_entries(frames_a)) == expected
            assert _by_container(_state_entries(frames_b)) == expected
            rec = protocol_obj.state.container_state(TWIN_FID)
            assert _plain(rec.items) == expected[TWIN_FID] and rec.seeded is True
        finally:
            sock_a.close(); sock_b.close()
    finally:
        transport.close()


@pytest.mark.asyncio
async def test_op_on_known_container_is_not_pushed():
    """Ordinary ops travel as CONTAINER_BCAST only: no CONTAINER_STATE noise."""
    port = 31546
    state = ServerState()
    _seeded(state, TRUNK_FID, {STIMPAK: 5})
    transport, _ = await _start_server_with_state(state, port)
    try:
        server_addr, sock_a, sock_b = await _two_raw_peers(port)
        try:
            op = _take(TRUNK_FID, STIMPAK, 1, op_id=7)
            sock_a.sendto(encode_frame(MessageType.CONTAINER_OP, 1, op, reliable=True),
                          server_addr)
            frames_a, frames_b = await asyncio.gather(
                _collect_frames(sock_a, 0.6), _collect_frames(sock_b, 0.6))
            assert _state_entries(frames_a) == [] and _state_entries(frames_b) == []
            assert sum(1 for f, _ in frames_b
                       if f.header.msg_type == int(MessageType.CONTAINER_BCAST)) == 1
        finally:
            sock_a.close(); sock_b.close()
    finally:
        transport.close()


# ---------------------------------------------------------------------------
# Loot rework L3.4 (2026-09-24): the deposit hook seeds too, and a scan of a
# container the client KNOWS is empty travels as the sentinel entry (item 0,
# count 0). Until then only a take seeded, so a deposit into a container the
# server had never seen left a PARTIAL record: never bootstrapped, replaced
# whole by the first scan of any client, including one whose engine never
# received the deposits.
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_empty_scan_sentinel_seeds_a_known_empty_record():
    """The pre-deposit scan of an empty container makes a seeded, empty
    record, pushed to everyone as the sentinel; the deposit that follows
    lands on a seeded record, not on a partial one."""
    port = 31547
    transport, protocol_obj = await _start_server_with_state(ServerState(), port)
    try:
        server_addr, sock_a, sock_b = await _two_raw_peers(port)
        try:
            seed = ContainerSeedPayload(entries=(
                ContainerStateEntry(TWIN_FID, TRUNK_BASE, TRUNK_CELL, 0, 0),
            ))
            sock_a.sendto(encode_frame(MessageType.CONTAINER_SEED, 1, seed, reliable=True),
                          server_addr)
            frames_a, frames_b = await asyncio.gather(
                _collect_frames(sock_a, 0.6), _collect_frames(sock_b, 0.6))
            assert _by_container(_state_entries(frames_a)) == {TWIN_FID: {}}
            assert _by_container(_state_entries(frames_b)) == {TWIN_FID: {}}
            rec = protocol_obj.state.container_state(TWIN_FID)
            assert rec is not None and rec.seeded is True and rec.items == {}

            op = _put(TWIN_FID, AMMO_10MM, 3)
            sock_a.sendto(encode_frame(MessageType.CONTAINER_OP, 2, op, reliable=True),
                          server_addr)
            await asyncio.gather(_collect_frames(sock_a, 0.4), _collect_frames(sock_b, 0.4))
            rec = protocol_obj.state.container_state(TWIN_FID)
            assert rec.seeded is True and rec.items == {(AMMO_10MM, 0): 3}
        finally:
            sock_a.close(); sock_b.close()
    finally:
        transport.close()


@pytest.mark.asyncio
async def test_empty_scan_sentinel_never_erases_a_seeded_record():
    """A client whose engine shows the container empty while the server
    holds items is stale: its sentinel is rejected and answered with the
    server's view, the record is untouched, the other peer hears nothing."""
    port = 31548
    state = ServerState()
    _seeded(state, TRUNK_FID, {STIMPAK: 5}, by="first")
    transport, protocol_obj = await _start_server_with_state(state, port)
    try:
        server_addr, sock_a, sock_b = await _two_raw_peers(port)
        try:
            seed = ContainerSeedPayload(entries=(
                ContainerStateEntry(TRUNK_FID, TRUNK_BASE, TRUNK_CELL, 0, 0),
            ))
            sock_a.sendto(encode_frame(MessageType.CONTAINER_SEED, 1, seed, reliable=True),
                          server_addr)
            frames_a, frames_b = await asyncio.gather(
                _collect_frames(sock_a, 0.6), _collect_frames(sock_b, 0.6))
            assert _by_container(_state_entries(frames_a)) == {TRUNK_FID: {STIMPAK: 5}}
            assert _state_entries(frames_b) == []
            rec = protocol_obj.state.container_state(TRUNK_FID)
            assert rec.seeded is True and rec.items == {(STIMPAK, 0): 5}
        finally:
            sock_a.close(); sock_b.close()
    finally:
        transport.close()


@pytest.mark.asyncio
async def test_empty_scan_sentinel_leaves_a_partial_record_alone():
    """A partial record holds deposits the scanner's engine may never have
    received: an empty scan does not replace it, does not seed it, and is
    not pushed (partial records never travel)."""
    port = 31549
    state = ServerState()
    state.record_container_op(_put(TWIN_FID, AMMO_10MM, 3), "alice", 0.0)
    transport, protocol_obj = await _start_server_with_state(state, port)
    try:
        server_addr, sock_a, sock_b = await _two_raw_peers(port)
        try:
            seed = ContainerSeedPayload(entries=(
                ContainerStateEntry(TWIN_FID, TRUNK_BASE, TRUNK_CELL, 0, 0),
            ))
            sock_a.sendto(encode_frame(MessageType.CONTAINER_SEED, 1, seed, reliable=True),
                          server_addr)
            frames_a, frames_b = await asyncio.gather(
                _collect_frames(sock_a, 0.6), _collect_frames(sock_b, 0.6))
            assert _state_entries(frames_a) == [] and _state_entries(frames_b) == []
            rec = protocol_obj.state.container_state(TWIN_FID)
            assert rec.seeded is False and rec.items == {(AMMO_10MM, 0): 3}
        finally:
            sock_a.close(); sock_b.close()
    finally:
        transport.close()


@pytest.mark.asyncio
async def test_corpse_seed_with_another_runtime_base_replaces_the_partial_record():
    """Loot rework L4 (2026-09-25): the record of a corpse holds the runtime
    base of whoever scanned it first; a scan from another client carries
    another runtime base and must not be refused as load-order drift."""
    port = 31550
    corpse = 0x246CD2
    state = ServerState()
    op = ContainerOpPayload(
        kind=int(ContainerOpKind.PUT), container_form_id=corpse,
        container_base_id=0xFF0012CC, container_cell_id=0xDD5B,
        item_base_id=AMMO_10MM, count=3, timestamp_ms=0)
    state.record_container_op(op, "alice", 0.0)
    assert state.container_state(corpse).seeded is False
    transport, protocol_obj = await _start_server_with_state(state, port)
    try:
        server_addr, sock_a, sock_b = await _two_raw_peers(port)
        try:
            seed = ContainerSeedPayload(entries=(
                ContainerStateEntry(corpse, 0xFF001204, 0xDD5B, AMMO_10MM, 3),
                ContainerStateEntry(corpse, 0xFF001204, 0xDD5B, STIMPAK, 1),
            ))
            sock_b.sendto(encode_frame(MessageType.CONTAINER_SEED, 1, seed, reliable=True),
                          server_addr)
            frames_a, frames_b = await asyncio.gather(
                _collect_frames(sock_a, 0.6), _collect_frames(sock_b, 0.6))
            expected = {corpse: {AMMO_10MM: 3, STIMPAK: 1}}
            assert _by_container(_state_entries(frames_a)) == expected
            assert _by_container(_state_entries(frames_b)) == expected
            rec = protocol_obj.state.container_state(corpse)
            assert rec.seeded is True and rec.items == {(AMMO_10MM, 0): 3, (STIMPAK, 0): 1}
        finally:
            sock_a.close(); sock_b.close()
    finally:
        transport.close()


@pytest.mark.asyncio
async def test_server_drops_the_corpse_record_on_a_real_death_only():
    """Loot rework L4.1 (2026-09-25): the server's two real death paths (pool
    kill, owner report) call _forget_corpse_record; the replay of a known
    death does not. The record of an actor's previous corpse must not empty
    the corpse of its next death."""
    port = 31551
    corpse = 0x246CD4
    state = ServerState()
    state.create_container(corpse, 0xFF00138F, 0xDD5B, {AMMO_10MM: 9}, "alice", 0.0)
    transport, protocol_obj = await _start_server_with_state(state, port)
    try:
        protocol_obj._forget_corpse_record(corpse, "test")
        assert protocol_obj.state.container_state(corpse) is None
        # Idempotent on an unknown actor.
        protocol_obj._forget_corpse_record(corpse, "test again")
        assert protocol_obj.state.container_state(corpse) is None
    finally:
        transport.close()
