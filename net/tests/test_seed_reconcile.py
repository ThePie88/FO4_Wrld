"""2026-10-20 - after the live death in an interior (RESEARCH_L5.md, the two
defects found with the D2 tests):

  1. the death release is ONE NPC_UNLOAD with form_id NPC_UNLOAD_ALL_OWNED
     (wire v43) and the server releases every NPC the sender owns;
  2. a scan that seeds a PARTIAL record is reconciled with the scanner's own
     ops that its engine no longer holds: newer than the save its world runs
     on, older than the load of that save (reconcile_scan); the server hears
     the loads from RESTORE_REQUEST, BOOT_RESULT and the death answer
     (ServerState.note_world_base);
  3. snapshot v15 and the journal carry the ops a partial record saw, the
     world a checkpoint carries and the world base per peer.
"""
from __future__ import annotations

import asyncio
import json
import socket
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from protocol import (  # noqa: E402
    MessageType, ContainerOpKind, ContainerSeedPayload, ContainerStateEntry,
    NPCUnloadPayload, NPC_UNLOAD_ALL_OWNED, NPCObservedPayload,
    RestoreRequestPayload, RESTORE_REASON_BOOT, BootResultPayload,
    encode_frame, FP_PLAIN,
)
from server.state import ServerState, reconcile_scan, PRE_SEED_OPS_MAX  # noqa: E402
from server.persistence import snapshot, load_into, SNAPSHOT_FORMAT_VERSION  # noqa: E402
from server.main import ServerProtocol  # noqa: E402
from server.journal import Journal  # noqa: E402
from net.tests.test_container import (  # noqa: E402
    _take, _put, _session, _start_server_with_state, _raw_peer_hello, _collect_frames,
    TRUNK_FID, TRUNK_BASE, TRUNK_CELL, STIMPAK, AMMO_10MM,
)

PEER = "peer_rc"
OTHER = "peer_ot"
TAKE = int(ContainerOpKind.TAKE)
PUT = int(ContainerOpKind.PUT)


def _seed_frame(items: dict[int, int]) -> bytes:
    entries = tuple(ContainerStateEntry(TRUNK_FID, TRUNK_BASE, TRUNK_CELL, item, n)
                    for item, n in items.items())
    return encode_frame(MessageType.CONTAINER_SEED, 1, ContainerSeedPayload(entries=entries),
                        reliable=True)


def _plain(items) -> dict[int, int]:
    return {k[0]: v for k, v in items.items()}


def _ckpt(state: ServerState, peer: str, seq: int, received_ms: float, **kw):
    return state.record_checkpoint(peer, "ab" * 16, seq, f"fwck_{peer}_{seq}", "cd" * 32, 9,
                                   0, 0, 1, received_ms, 1, 0, **kw)


# ------------------------------------------------------------ 1. the death release

class TestDeathRelease:
    def test_the_wildcard_releases_every_npc_of_the_sender_and_nobody_elses(self):
        protocol = ServerProtocol(ServerState())
        reg = protocol.ownership
        for fid in (0x100, 0x101, 0x102):
            reg.on_observed(NPCObservedPayload(fid, 0xCAFE, 0xBABE, 0.0, 0.0, 0.0, 1.0),
                            PEER, now_ms=0.0)
        reg.on_observed(NPCObservedPayload(0x200, 0xCAFE, 0xBABE, 0.0, 0.0, 0.0, 1.0),
                        OTHER, now_ms=0.0)
        assert all(reg.is_owner(PEER, f) for f in (0x100, 0x101, 0x102))
        session = _session(PEER)
        protocol._handle_npc_unload(
            session, NPCUnloadPayload(NPC_UNLOAD_ALL_OWNED, 3, 0.0, 0.0, 0.0, 0.0, 0, 0),
            now_ms=1000.0)
        assert all(reg.get(f) is None for f in (0x100, 0x101, 0x102))
        assert reg.is_owner(OTHER, 0x200)
        assert session.combat_dead_until_ms == 1000.0 + 25000.0

    def test_a_plain_unload_still_releases_one(self):
        protocol = ServerProtocol(ServerState())
        reg = protocol.ownership
        change = reg.on_observed(NPCObservedPayload(0x100, 0xCAFE, 0xBABE, 0.0, 0.0, 0.0, 1.0),
                                 PEER, now_ms=0.0)
        reg.on_observed(NPCObservedPayload(0x101, 0xCAFE, 0xBABE, 0.0, 0.0, 0.0, 1.0),
                        PEER, now_ms=0.0)
        protocol._handle_npc_unload(
            _session(PEER), NPCUnloadPayload(0x100, change.new_epoch, 0.0, 0.0, 0.0, 0.0, 0, 0),
            now_ms=1000.0)
        assert reg.get(0x100) is None and reg.is_owner(PEER, 0x101)

    def test_wire_roundtrip_of_the_wildcard(self):
        p = NPCUnloadPayload(NPC_UNLOAD_ALL_OWNED, 637, 0.0, 0.0, 0.0, 0.0, 0, 0)
        assert NPCUnloadPayload.decode(p.encode()) == p and len(p.encode()) == 26


# ------------------------------------------------------------ 2. the partial record and the scan

class TestPartialRecordOps:
    def test_ops_before_the_first_scan_are_remembered_and_the_scan_forgets_them(self):
        s = ServerState()
        s.record_container_op(_take(TRUNK_FID, STIMPAK, 3), PEER, 200.0)
        s.record_container_op(_put(TRUNK_FID, AMMO_10MM, 10), PEER, 210.0)
        rec = s.container_state(TRUNK_FID)
        assert rec.seeded is False
        assert rec.pre_seed_ops == [
            (PEER, 200.0, TAKE, STIMPAK, FP_PLAIN, 3),
            (PEER, 210.0, PUT, AMMO_10MM, FP_PLAIN, 10),
        ]
        assert s.reseed_container(TRUNK_FID, {STIMPAK: 5}, PEER, 300.0)
        assert rec.seeded is True and rec.pre_seed_ops == [] and rec.pre_seed_overflow is False

    def test_a_seeded_record_remembers_nothing(self):
        s = ServerState()
        s.create_container(TRUNK_FID, TRUNK_BASE, TRUNK_CELL, {STIMPAK: 5}, PEER, 0.0)
        s.record_container_op(_take(TRUNK_FID, STIMPAK, 2), PEER, 100.0)
        rec = s.container_state(TRUNK_FID)
        assert rec.pre_seed_ops == [] and _plain(rec.items) == {STIMPAK: 3}

    def test_past_the_cap_the_list_is_not_trusted(self):
        s = ServerState()
        rec = None
        for i in range(PRE_SEED_OPS_MAX + 5):
            rec = s.record_container_op(_put(TRUNK_FID, AMMO_10MM, 1), PEER, float(i))
        assert len(rec.pre_seed_ops) == PRE_SEED_OPS_MAX and rec.pre_seed_overflow is True
        lines, n = reconcile_scan(rec, {AMMO_10MM: 50}, PEER, (0.0, 1e9))
        assert _plain(lines) == {AMMO_10MM: 50} and n == 0


class TestReconcileScan:
    def _partial(self):
        # The live case: a toolbox taken whole with every scan refused (the
        # engine held the list's lock inside the take), 224 units; then the
        # reload of a checkpoint written BEFORE the takes.
        s = ServerState()
        s.record_container_op(_take(TRUNK_FID, STIMPAK, 4), PEER, 200.0)
        s.record_container_op(_take(TRUNK_FID, AMMO_10MM, 220), PEER, 201.0)
        return s, s.container_state(TRUNK_FID)

    def test_the_scanner_reloaded_an_older_save_so_its_takes_come_off_the_scan(self):
        s, rec = self._partial()
        lines, n = reconcile_scan(rec, {STIMPAK: 4, AMMO_10MM: 220}, PEER, (100.0, 300.0))
        assert lines == {} and n == 2

    def test_a_partial_take_leaves_the_rest(self):
        s, rec = self._partial()
        lines, n = reconcile_scan(rec, {STIMPAK: 10, AMMO_10MM: 220}, PEER, (100.0, 300.0))
        assert _plain(lines) == {STIMPAK: 6} and n == 2

    def test_a_save_newer_than_the_takes_already_lacks_them(self):
        s, rec = self._partial()
        lines, n = reconcile_scan(rec, {STIMPAK: 6}, PEER, (250.0, 300.0))
        assert _plain(lines) == {STIMPAK: 6} and n == 0

    def test_ops_made_after_the_load_are_live_in_the_engine(self):
        # Booted at 150 from a save of 100, then took: the engine holds the
        # takes, the scan lacks them already, nothing is applied twice.
        s, rec = self._partial()
        lines, n = reconcile_scan(rec, {STIMPAK: 6}, PEER, (100.0, 150.0))
        assert _plain(lines) == {STIMPAK: 6} and n == 0

    def test_no_load_known_keeps_the_scan(self):
        s, rec = self._partial()
        lines, n = reconcile_scan(rec, {STIMPAK: 4, AMMO_10MM: 220}, PEER, None)
        assert _plain(lines) == {STIMPAK: 4, AMMO_10MM: 220} and n == 0

    def test_another_peers_ops_are_left_alone(self):
        s, rec = self._partial()
        lines, n = reconcile_scan(rec, {STIMPAK: 4, AMMO_10MM: 220}, OTHER, (0.0, 1e9))
        assert _plain(lines) == {STIMPAK: 4, AMMO_10MM: 220} and n == 0

    def test_a_deposit_after_the_save_comes_back_onto_the_scan(self):
        s = ServerState()
        s.record_container_op(_put(TRUNK_FID, AMMO_10MM, 30), PEER, 200.0)
        rec = s.container_state(TRUNK_FID)
        lines, n = reconcile_scan(rec, {STIMPAK: 2}, PEER, (100.0, 300.0))
        assert _plain(lines) == {STIMPAK: 2, AMMO_10MM: 30} and n == 1

    def test_the_record_itself_is_untouched(self):
        s, rec = self._partial()
        before = (dict(rec.items), list(rec.pre_seed_ops))
        reconcile_scan(rec, {STIMPAK: 4}, PEER, (0.0, 1e9))
        assert (dict(rec.items), list(rec.pre_seed_ops)) == before


class TestWorldBase:
    def test_a_load_is_the_pair_and_a_second_load_moves_it(self):
        s = ServerState()
        assert s.world_base(PEER) is None
        s.note_world_base(PEER, 100.0, 150.0)
        assert s.world_base(PEER) == (100.0, 150.0)
        # Died again before any new checkpoint: the same save, a later load.
        s.note_world_base(PEER, 100.0, 900.0)
        assert s.world_base(PEER) == (100.0, 900.0)

    def test_the_genesis_is_zero_and_a_forgotten_peer_has_none(self):
        s = ServerState()
        s.note_world_base(PEER, -5.0, 10.0)
        assert s.world_base(PEER) == (0.0, 10.0)
        s.forget_peer(PEER)
        assert s.world_base(PEER) is None

    def test_a_respawn_copy_carries_the_source_world(self):
        s = ServerState()
        own = _ckpt(s, PEER, 1, 500.0)
        assert own.world_ms == 500.0
        copy = _ckpt(s, PEER, 2, 900.0, world_ms=own.world_ms)
        genesis = _ckpt(s, PEER, 3, 950.0, world_ms=0.0)
        assert copy.world_ms == 500.0 and genesis.world_ms == 0.0
        assert s.checkpoint_to_boot(PEER) is genesis


@pytest.mark.asyncio
async def test_seed_of_a_partial_record_after_a_reload_is_reconciled():
    port = 31585
    state = ServerState()
    transport, protocol_obj = await _start_server_with_state(state, port)
    try:
        server_addr = ("127.0.0.1", port)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 0))
        try:
            await _raw_peer_hello(sock, server_addr, PEER)
            await _collect_frames(sock, 0.2)
            # The takes on a container nobody scanned, then the reload of a
            # save written before them (the times are the server's clock).
            state.record_container_op(_take(TRUNK_FID, STIMPAK, 4), PEER, 200.0)
            state.record_container_op(_take(TRUNK_FID, AMMO_10MM, 220), PEER, 201.0)
            state.note_world_base(PEER, 100.0, 300.0)
            sock.sendto(_seed_frame({STIMPAK: 4, AMMO_10MM: 220}), server_addr)
            await asyncio.sleep(0.3)
            rec = state.container_state(TRUNK_FID)
            assert rec.seeded is True and rec.items == {} and rec.pre_seed_ops == []
        finally:
            sock.close()
    finally:
        transport.close()


@pytest.mark.asyncio
async def test_seed_of_a_partial_record_without_a_reload_stands_as_before():
    port = 31586
    state = ServerState()
    transport, protocol_obj = await _start_server_with_state(state, port)
    try:
        server_addr = ("127.0.0.1", port)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 0))
        try:
            await _raw_peer_hello(sock, server_addr, PEER)
            await _collect_frames(sock, 0.2)
            # Booted at 150 from a save of 100, took at 200 with the scan
            # refused, scanned at the next touch: the engine lacks the takes.
            state.note_world_base(PEER, 100.0, 150.0)
            state.record_container_op(_take(TRUNK_FID, STIMPAK, 4), PEER, 200.0)
            sock.sendto(_seed_frame({STIMPAK: 6, AMMO_10MM: 220}), server_addr)
            await asyncio.sleep(0.3)
            rec = state.container_state(TRUNK_FID)
            assert rec.seeded is True and _plain(rec.items) == {STIMPAK: 6, AMMO_10MM: 220}
        finally:
            sock.close()
    finally:
        transport.close()


@pytest.mark.asyncio
async def test_the_server_hears_the_loads():
    port = 31587
    state = ServerState()
    transport, protocol_obj = await _start_server_with_state(state, port)
    try:
        server_addr = ("127.0.0.1", port)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 0))
        try:
            await _raw_peer_hello(sock, server_addr, PEER)
            await _collect_frames(sock, 0.2)
            # A boot with no checkpoint: the genesis world.
            req = RestoreRequestPayload(session=7, last_seq=0, reason=RESTORE_REASON_BOOT)
            sock.sendto(encode_frame(MessageType.RESTORE_REQUEST, 1, req, reliable=True),
                        server_addr)
            await asyncio.sleep(0.2)
            wb = state.world_base(PEER)
            assert wb is not None and wb[0] == 0.0 and wb[1] > 1e12
            # A boot from a checkpoint: its world (a new sequence number: the
            # channel drops a repeat of the same one).
            _ckpt(state, PEER, 1, 500.0)
            sock.sendto(encode_frame(MessageType.RESTORE_REQUEST, 2, req, reliable=True),
                        server_addr)
            await asyncio.sleep(0.2)
            wb2 = state.world_base(PEER)
            assert wb2[0] == 500.0 and wb2[1] >= wb[1]
            # The boot result says the checkpoint could not be loaded: genesis.
            br = BootResultPayload(seq=1, outcome=4, name=f"fwck_{PEER}_1", wall_ms=0)
            sock.sendto(encode_frame(MessageType.BOOT_RESULT, 3, br, reliable=True),
                        server_addr)
            await asyncio.sleep(0.2)
            assert state.world_base(PEER)[0] == 0.0
        finally:
            sock.close()
    finally:
        transport.close()


# ------------------------------------------------------------ 3. durability

class TestDurability:
    def test_snapshot_v15_roundtrip(self, tmp_path: Path):
        a = ServerState()
        a.record_container_op(_take(TRUNK_FID, STIMPAK, 4), PEER, 200.0)
        a.record_container_op(_put(TRUNK_FID, AMMO_10MM, 7), OTHER, 201.0)
        a.note_world_base(PEER, 100.0, 300.0)
        _ckpt(a, PEER, 1, 500.0, world_ms=123.0)
        path = tmp_path / "snap.json"
        snapshot(a, path)
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data["version"] == SNAPSHOT_FORMAT_VERSION == 15
        assert data["world_base_ms"] == {PEER: [100.0, 300.0]}
        b = ServerState()
        load_into(b, path)
        rec = b.container_state(TRUNK_FID)
        assert rec.seeded is False and rec.pre_seed_overflow is False
        assert rec.pre_seed_ops == [(PEER, 200.0, TAKE, STIMPAK, FP_PLAIN, 4),
                                    (OTHER, 201.0, PUT, AMMO_10MM, FP_PLAIN, 7)]
        assert b.world_base(PEER) == (100.0, 300.0)
        assert b.checkpoints(PEER)[0].world_ms == 123.0

    def test_a_v14_file_loads_with_the_defaults(self, tmp_path: Path):
        a = ServerState()
        a.record_container_op(_take(TRUNK_FID, STIMPAK, 4), PEER, 200.0)
        _ckpt(a, PEER, 1, 500.0)
        path = tmp_path / "snap.json"
        snapshot(a, path)
        data = json.loads(path.read_text(encoding="utf-8"))
        data["version"] = 14
        del data["world_base_ms"]
        for c in data["containers"]:
            del c["pre_seed_ops"]
            del c["pre_seed_overflow"]
        for c in data["checkpoints"]:
            del c["world_ms"]
        path.write_text(json.dumps(data), encoding="utf-8")
        b = ServerState()
        load_into(b, path)
        rec = b.container_state(TRUNK_FID)
        assert rec.seeded is False and rec.pre_seed_ops == []
        assert b.world_base(PEER) is None
        assert b.checkpoints(PEER)[0].world_ms == 500.0   # its own report's time

    def test_the_journal_replays_the_ops_the_base_and_the_world(self, tmp_path: Path):
        j = Journal.open(tmp_path / "journal")
        a = ServerState()
        a.journal = j
        a.record_container_op(_take(TRUNK_FID, STIMPAK, 4), PEER, 200.0)
        a.note_world_base(PEER, 100.0, 300.0)
        _ckpt(a, PEER, 1, 500.0, world_ms=77.0)
        j.flush()
        j.close()
        b = ServerState()
        j2 = Journal.open(tmp_path / "journal")
        j2.replay(b, after_lsn=0)
        j2.close()
        assert b.container_state(TRUNK_FID).pre_seed_ops == [
            (PEER, 200.0, TAKE, STIMPAK, FP_PLAIN, 4)]
        assert b.world_base(PEER) == (100.0, 300.0)
        assert b.checkpoints(PEER)[0].world_ms == 77.0
