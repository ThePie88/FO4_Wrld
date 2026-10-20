"""L5 realtime persistence, slice R1b (2026-10-05): a Pip-Boy drop and a
pickup from the world are ops of the record, like a container take or put.

Until R1b the record learned a drop and a pickup from the next capture only
(250 ms after the tap): a crash in that window lost the item twice over (the
world had already moved it, the record had not), and two clients picking up
the same object of ours both kept it. Now the client numbers them in the
same op sequence as the container ops, the server applies the world side
and the record side inside ONE journal record and answers with a verdict,
and the client holds its captures until the verdict is in, so no capture
ever carries an op the server has not applied, and the server never
applies one twice.
"""
from __future__ import annotations

import asyncio
import dataclasses
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from protocol import (  # noqa: E402
    MessageType, PROTOCOL_VERSION, _TYPE_TO_PAYLOAD_CLS as PAYLOAD_TYPES,
    WorldItemOpPayload, WorldItemAckPayload, WORLD_ITEM_DROP, WORLD_ITEM_PICKUP,
    ContainerOpAckStatus, ActorEventPayload,
    InstanceDescriptor, INSTANCE_FLAG_OIE, INSTANCE_FLAG_HEALTH, FP_PLAIN, FP_UNKNOWN,
    instance_fp,
    INV_STATE_FLAG_COMPLETE, INV_ENTRY_EQUIPPED,
    WORLD_SPAWN_FLAG_CONTAINER, WORLD_SPAWN_FLAG_SELF_DESCRIBED,
    encode_frame,
)
from server.journal import Journal  # noqa: E402
from server.persistence import load_into, snapshot  # noqa: E402
from server.state import ServerState  # noqa: E402
from server.validator import RejectReason, validate_world_item_op  # noqa: E402
from net.tests.test_container import _collect_frames, _start_server_with_state  # noqa: E402
from net.tests.test_container_reconverge import _two_raw_peers  # noqa: E402

PIPBOY = 0x00021B3B
PISTOL = 0x4822
STIMPAK = 0x23736
CAPS = 0xF
CELL = 0xDD60
SESSION = 0x51510001
EPOCH = 0x5151
PEER = "alice"
AUTO_PISTOL = InstanceDescriptor(
    template=4, flags=INSTANCE_FLAG_OIE,
    mods=((0x100E2E, 0, 1), (0x231AB, 0, 1), (0x100E27, 0, 1)))
AUTO_FP = instance_fp(PISTOL, AUTO_PISTOL)
LINES = [(PIPBOY, FP_PLAIN, 1, INV_ENTRY_EQUIPPED), (PISTOL, AUTO_FP, 1, INV_ENTRY_EQUIPPED),
         (STIMPAK, FP_PLAIN, 4, 0), (CAPS, FP_PLAIN, 300, 0)]


def _op_id(seq: int, epoch: int = EPOCH) -> int:
    return (epoch << 16) | (seq & 0xFFFF)


def _record(state: ServerState, peer: str = PEER, lines=LINES, watermark: int = 0, seq: int = 1):
    return state.record_player_inventory(peer, SESSION, seq, watermark, EPOCH,
                                         INV_STATE_FLAG_COMPLETE, 0, tuple(lines), 0.0)


def _drop(item: int = STIMPAK, count: int = 2, desc: InstanceDescriptor | None = None,
          op_id: int = _op_id(1), ref: int = 0xFF001234, cell: int = CELL,
          fp: int | None = None, flags: int = 0) -> WorldItemOpPayload:
    d = desc if desc is not None else InstanceDescriptor()
    return WorldItemOpPayload(
        kind=WORLD_ITEM_DROP, client_op_id=op_id, item_base_id=item, count=count,
        item_fp=instance_fp(item, d) if fp is None else fp, ref_form_id=ref, wid=0,
        cell_id=cell, px=10.0, py=20.0, pz=30.0, rx=0.0, ry=0.0, rz=1.5, flags=flags,
        timestamp_ms=7, instance=d)


def _pickup(item: int = STIMPAK, count: int = 2, wid: int = 0, ref: int = 0x000A1234,
            desc: InstanceDescriptor | None = None, op_id: int = _op_id(2), cell: int = CELL,
            fp: int | None = None) -> WorldItemOpPayload:
    d = desc if desc is not None else InstanceDescriptor()
    return WorldItemOpPayload(
        kind=WORLD_ITEM_PICKUP, client_op_id=op_id, item_base_id=item, count=count,
        item_fp=instance_fp(item, d) if fp is None else fp, ref_form_id=ref, wid=wid,
        cell_id=cell, px=1.0, py=2.0, pz=3.0, rx=0.0, ry=0.0, rz=0.0, flags=0,
        timestamp_ms=8, instance=d)


def _spawn_item(state: ServerState, peer: str = "bob", item: int = STIMPAK, count: int = 2):
    return state.record_world_spawn(peer, item, 0xFF009999, 1.0, 2.0, 3.0, 0.0, 0.0, 0.0, CELL,
                                    WORLD_SPAWN_FLAG_SELF_DESCRIBED, 5, ((item, count, (), -1.0),))


class TestWire:
    def test_the_op_and_the_ack_round_trip(self):
        op = _drop(desc=AUTO_PISTOL, item=PISTOL, count=1)
        raw = op.encode()
        assert len(raw) == 170
        assert WorldItemOpPayload.decode(raw) == op
        ack = WorldItemAckPayload(client_op_id=_op_id(9), status=int(ContainerOpAckStatus.ACCEPTED),
                                  kind=WORLD_ITEM_DROP, wid=42, item_base_id=PISTOL,
                                  item_fp=AUTO_FP, record_count=3)
        raw = ack.encode()
        assert len(raw) == 26
        assert WorldItemAckPayload.decode(raw) == ack

    def test_the_messages_decode_and_the_wire_moved(self):
        assert PAYLOAD_TYPES[MessageType.WORLD_ITEM_OP] is WorldItemOpPayload
        assert PAYLOAD_TYPES[MessageType.WORLD_ITEM_ACK] is WorldItemAckPayload
        assert int(MessageType.WORLD_ITEM_OP) == 0x02B7
        assert int(MessageType.WORLD_ITEM_ACK) == 0x02B8
        assert PROTOCOL_VERSION == 43   # v43: NPC_UNLOAD form_id 0 = the death release in one message


class TestDrop:
    def test_a_drop_takes_the_line_out_of_the_record_and_makes_the_object(self):
        s = ServerState()
        _record(s)
        wid = s.next_world_spawn_wid
        st = s.record_world_drop(PEER, _drop(), 100.0)
        assert st is not None and st.wid == wid and s.next_world_spawn_wid == wid + 1
        assert st.spawner_peer == PEER and st.base_form_id == STIMPAK
        assert st.spawner_local_fid == 0xFF001234 and st.cell_id == CELL
        assert (st.px, st.py, st.pz, st.rz) == (10.0, 20.0, 30.0, 1.5)
        assert st.flags & WORLD_SPAWN_FLAG_SELF_DESCRIBED
        assert not (st.flags & WORLD_SPAWN_FLAG_CONTAINER)
        assert st.pieces == ((STIMPAK, 2, (), -1.0),)
        assert s.world_spawns[wid] is st
        rec = s.player_inventory(PEER)
        assert rec.lines[(STIMPAK, FP_PLAIN)] == 2
        assert rec.pending == [(_op_id(1), 2, STIMPAK, FP_PLAIN, 2)]

    def test_a_modded_drop_carries_its_descriptor_and_names_the_instance(self):
        s = ServerState()
        _record(s)
        st = s.record_world_drop(PEER, _drop(item=PISTOL, count=1, desc=AUTO_PISTOL), 100.0)
        assert st.pieces == ((PISTOL, 1, (0x100E2E, 0x231AB, 0x100E27), -1.0),)
        assert s.instance_def(AUTO_FP) == (PISTOL, AUTO_PISTOL)
        rec = s.player_inventory(PEER)
        assert (PISTOL, AUTO_FP) not in rec.lines
        assert (PISTOL, AUTO_FP) not in rec.equipped

    def test_a_drop_with_a_condition_puts_it_in_the_piece(self):
        s = ServerState()
        _record(s)
        worn = InstanceDescriptor(flags=INSTANCE_FLAG_HEALTH, health=0.5)
        st = s.record_world_drop(PEER, _drop(item=PISTOL, count=1, desc=worn), 100.0)
        assert st.pieces == ((PISTOL, 1, (), 0.5),)

    def test_the_record_behind_the_client_is_not_refused(self):
        s = ServerState()
        _record(s, lines=[(PIPBOY, FP_PLAIN, 1, INV_ENTRY_EQUIPPED)])
        st = s.record_world_drop(PEER, _drop(count=1), 100.0)
        assert st is not None
        rec = s.player_inventory(PEER)
        assert (STIMPAK, FP_PLAIN) not in rec.lines
        assert rec.pending == [(_op_id(1), 2, STIMPAK, FP_PLAIN, 1)]

    def test_a_drop_of_nothing_is_refused_before_the_journal(self):
        s = ServerState()
        _record(s)
        assert s.record_world_drop(PEER, _drop(item=0), 100.0) is None
        assert s.record_world_drop(PEER, _drop(count=0), 100.0) is None
        assert s.record_world_drop(PEER, _drop(ref=0), 100.0) is None
        assert s.world_spawns == {} and s.player_inventory(PEER).pending == []

    def test_one_journal_record_replays_the_drop_whole(self, tmp_path: Path):
        j = Journal.open(tmp_path / "journal")
        a = ServerState()
        a.journal = j
        _record(a)
        before = a.applied_lsn
        st = a.record_world_drop(PEER, _drop(item=PISTOL, count=1, desc=AUTO_PISTOL), 100.0)
        assert a.applied_lsn == before + 1
        j.flush()
        j.close()
        b = ServerState()
        Journal.open(tmp_path / "journal").replay(b, after_lsn=0)
        assert b.world_spawns[st.wid].pieces == st.pieces
        assert b.world_spawns[st.wid].spawner_local_fid == 0xFF001234
        assert b.next_world_spawn_wid == a.next_world_spawn_wid
        assert b.player_inventory(PEER).lines == a.player_inventory(PEER).lines
        assert b.player_inventory(PEER).pending == a.player_inventory(PEER).pending
        assert b.instance_def(AUTO_FP) == (PISTOL, AUTO_PISTOL)

    def test_the_snapshot_keeps_the_drop(self, tmp_path: Path):
        a = ServerState()
        _record(a)
        st = a.record_world_drop(PEER, _drop(), 100.0)
        path = tmp_path / "snap.json"
        snapshot(a, path)
        b = ServerState()
        load_into(b, path)
        assert b.world_spawns[st.wid].pieces == ((STIMPAK, 2, (), -1.0),)
        assert b.player_inventory(PEER).lines[(STIMPAK, FP_PLAIN)] == 2
        assert b.player_inventory(PEER).pending == [(_op_id(1), 2, STIMPAK, FP_PLAIN, 2)]


class TestPickup:
    def test_picking_up_our_object_removes_it_and_adds_the_line(self):
        s = ServerState()
        _record(s)
        st = _spawn_item(s)
        res = s.record_world_pickup(PEER, _pickup(wid=st.wid, ref=0xFF00AAAA), 100.0)
        assert res == (st.wid, False)
        assert st.wid not in s.world_spawns
        rec = s.player_inventory(PEER)
        assert rec.lines[(STIMPAK, FP_PLAIN)] == 6
        assert rec.pending == [(_op_id(2), 1, STIMPAK, FP_PLAIN, 2)]
        assert s.actor_state(STIMPAK, CELL) is None

    def test_a_modded_pickup_names_its_instance(self):
        s = ServerState()
        _record(s, lines=[(PIPBOY, FP_PLAIN, 1, INV_ENTRY_EQUIPPED)])
        st = s.record_world_spawn("bob", PISTOL, 0xFF009999, 1.0, 2.0, 3.0, 0.0, 0.0, 0.0, CELL,
                                  WORLD_SPAWN_FLAG_SELF_DESCRIBED, 5,
                                  ((PISTOL, 1, (0x100E2E, 0x231AB, 0x100E27), -1.0),))
        s.record_world_pickup(PEER, _pickup(item=PISTOL, count=1, wid=st.wid, ref=0xFF00AAAA,
                                            desc=AUTO_PISTOL), 100.0)
        assert s.player_inventory(PEER).lines[(PISTOL, AUTO_FP)] == 1
        assert s.instance_def(AUTO_FP) == (PISTOL, AUTO_PISTOL)

    def test_a_vanilla_pickup_disables_the_ref_and_adds_the_line(self):
        s = ServerState()
        _record(s)
        res = s.record_world_pickup(PEER, _pickup(ref=0x000A1234), 100.0)
        assert res == (0, True)
        actor = s.actor_state(STIMPAK, CELL)
        assert actor is not None and not actor.alive
        assert actor.last_known_form_id == 0x000A1234 and actor.last_owner_peer_id == PEER
        assert s.player_inventory(PEER).lines[(STIMPAK, FP_PLAIN)] == 6
        assert s.player_inventory(PEER).pending == [(_op_id(2), 1, STIMPAK, FP_PLAIN, 2)]

    def test_an_unknown_runtime_ref_is_trusted_without_a_world_mark(self):
        s = ServerState()
        _record(s)
        res = s.record_world_pickup(PEER, _pickup(ref=0xFF00BBBB), 100.0)
        assert res == (0, False)
        assert s.actor_state(STIMPAK, CELL) is None
        assert s.player_inventory(PEER).lines[(STIMPAK, FP_PLAIN)] == 6

    def test_a_pickup_without_a_record_opens_one(self):
        s = ServerState()
        res = s.record_world_pickup(PEER, _pickup(ref=0xFF00BBBB), 100.0)
        assert res == (0, False)
        rec = s.player_inventory(PEER)
        assert rec.lines == {(STIMPAK, FP_PLAIN): 2} and rec.captures == 0

    def test_a_pickup_of_nothing_is_refused_before_the_journal(self):
        s = ServerState()
        _record(s)
        assert s.record_world_pickup(PEER, _pickup(item=0), 100.0) is None
        assert s.record_world_pickup(PEER, _pickup(count=0), 100.0) is None
        assert s.record_world_pickup(PEER, _pickup(wid=77), 100.0) is None
        assert s.player_inventory(PEER).pending == []

    def test_one_journal_record_replays_the_pickup_whole(self, tmp_path: Path):
        j = Journal.open(tmp_path / "journal")
        a = ServerState()
        a.journal = j
        _record(a)
        st = _spawn_item(a)
        before = a.applied_lsn
        a.record_world_pickup(PEER, _pickup(wid=st.wid, ref=0xFF00AAAA), 100.0)
        a.record_world_pickup(PEER, _pickup(ref=0x000A1234, op_id=_op_id(3)), 101.0)
        assert a.applied_lsn == before + 2
        j.flush()
        j.close()
        b = ServerState()
        Journal.open(tmp_path / "journal").replay(b, after_lsn=0)
        assert st.wid not in b.world_spawns
        assert not b.actor_state(STIMPAK, CELL).alive
        assert b.player_inventory(PEER).lines == a.player_inventory(PEER).lines
        assert b.player_inventory(PEER).pending == a.player_inventory(PEER).pending


class TestValidator:
    def _check(self, s: ServerState, op: WorldItemOpPayload):
        return validate_world_item_op(op, s.world_spawns.get(op.wid) if op.wid else None,
                                      len(s.world_spawns))

    def test_a_good_drop_and_a_good_pickup_pass(self):
        s = ServerState()
        st = _spawn_item(s)
        assert self._check(s, _drop()).ok
        assert self._check(s, _pickup(wid=st.wid, ref=0xFF00AAAA)).ok
        assert self._check(s, _pickup(ref=0x000A1234)).ok
        assert self._check(s, _pickup(ref=0xFF00BBBB)).ok
        assert self._check(s, _drop(fp=FP_UNKNOWN)).ok

    def test_the_line_itself(self):
        s = ServerState()
        assert self._check(s, _drop(item=0)).reason == RejectReason.MISSING_IDENTITY
        assert self._check(s, _drop(count=0)).reason == RejectReason.INVALID_COUNT
        assert self._check(s, _drop(count=-3)).reason == RejectReason.INVALID_COUNT
        bad = dataclasses.replace(_drop(), kind=9)
        assert self._check(s, bad).reason == RejectReason.INVALID_KIND
        wrong = _drop(item=PISTOL, count=1, desc=AUTO_PISTOL, fp=0x1234)
        assert self._check(s, wrong).reason == RejectReason.INSTANCE_MISMATCH

    def test_a_drop_needs_its_ref_and_its_cell_and_room_in_the_world(self):
        s = ServerState()
        assert self._check(s, _drop(ref=0)).reason == RejectReason.MISSING_IDENTITY
        assert self._check(s, _drop(cell=0)).reason == RejectReason.MISSING_IDENTITY
        full = validate_world_item_op(_drop(), None, 1024)
        assert full.reason == RejectReason.COUNT_OVERFLOW

    def test_a_pickup_of_a_wid_nobody_has_is_someone_elses(self):
        s = ServerState()
        assert self._check(s, _pickup(wid=77, ref=0xFF00AAAA)).reason == RejectReason.INSUFFICIENT_ITEMS

    def test_a_pickup_of_a_crate_or_a_worn_frame_or_another_base_is_refused(self):
        s = ServerState()
        _record(s)
        crate_wid = s.next_world_spawn_wid
        s.record_death_crate(PEER, crate_wid, 0x1D0FB, CELL, 1.0, 2.0, 3.0, 0.0, (PIPBOY,), 0.0)
        r = self._check(s, _pickup(item=0x1D0FB, count=1, wid=crate_wid, ref=0xFF00AAAA))
        assert r.reason == RejectReason.IDENTITY_MISMATCH
        frame = s.record_world_spawn("bob", 0x2079E, 0xFF009998, 1.0, 2.0, 3.0, 0.0, 0.0, 0.0,
                                     CELL, 0, 5, ())
        s.mark_world_spawn_worn(frame.wid, "bob", 0.0)
        r = self._check(s, _pickup(item=0x2079E, count=1, wid=frame.wid, ref=0xFF00AAAA))
        assert r.reason == RejectReason.IDENTITY_MISMATCH
        st = _spawn_item(s)
        r = self._check(s, _pickup(item=CAPS, count=1, wid=st.wid, ref=0xFF00AAAA))
        assert r.reason == RejectReason.IDENTITY_MISMATCH

    def test_a_vanilla_pickup_needs_a_cell(self):
        s = ServerState()
        assert self._check(s, _pickup(ref=0x000A1234, cell=0)).reason == RejectReason.MISSING_IDENTITY
        assert self._check(s, _pickup(ref=0)).reason == RejectReason.MISSING_IDENTITY


class TestCaptureAfterTheOps:
    def test_a_capture_that_covers_the_ops_drops_them(self):
        s = ServerState()
        _record(s)
        s.record_world_drop(PEER, _drop(op_id=_op_id(5)), 100.0)
        st = _spawn_item(s)
        s.record_world_pickup(PEER, _pickup(item=CAPS, count=10, wid=st.wid, ref=0xFF00AAAA,
                                            op_id=_op_id(6)), 101.0)
        assert len(s.player_inventory(PEER).pending) == 2
        _record(s, lines=[(PIPBOY, FP_PLAIN, 1, INV_ENTRY_EQUIPPED), (STIMPAK, FP_PLAIN, 2, 0),
                          (CAPS, FP_PLAIN, 310, 0)], watermark=_op_id(6), seq=2)
        rec = s.player_inventory(PEER)
        assert rec.pending == []
        assert rec.lines == {(PIPBOY, FP_PLAIN): 1, (STIMPAK, FP_PLAIN): 2, (CAPS, FP_PLAIN): 310}

    def test_a_capture_from_before_the_ops_gets_them_again_on_top(self):
        s = ServerState()
        _record(s)
        s.record_world_drop(PEER, _drop(op_id=_op_id(5)), 100.0)
        st = _spawn_item(s)
        s.record_world_pickup(PEER, _pickup(item=CAPS, count=10, wid=st.wid, ref=0xFF00AAAA,
                                            op_id=_op_id(6)), 101.0)
        _record(s, lines=LINES, watermark=_op_id(4), seq=2)
        rec = s.player_inventory(PEER)
        assert len(rec.pending) == 2
        assert rec.lines[(STIMPAK, FP_PLAIN)] == 2 and rec.lines[(CAPS, FP_PLAIN)] == 310


class TestVerdicts:
    def test_a_verdict_is_remembered_per_op_id_and_replayed(self, tmp_path: Path):
        j = Journal.open(tmp_path / "journal")
        a = ServerState()
        a.journal = j
        ack = WorldItemAckPayload(client_op_id=_op_id(1), status=int(ContainerOpAckStatus.ACCEPTED),
                                  kind=WORLD_ITEM_DROP, wid=3, item_base_id=STIMPAK,
                                  item_fp=FP_PLAIN, record_count=2)
        a.remember_world_item_verdict(PEER, _op_id(1), ack)
        assert a.recall_world_item_verdict(PEER, _op_id(1)) == ack
        assert a.recall_world_item_verdict(PEER, _op_id(2)) is None
        assert a.recall_world_item_verdict("nobody", _op_id(1)) is None
        j.flush()
        j.close()
        b = ServerState()
        Journal.open(tmp_path / "journal").replay(b, after_lsn=0)
        assert b.recall_world_item_verdict(PEER, _op_id(1)) == ack
        b.forget_peer(PEER)
        assert b.recall_world_item_verdict(PEER, _op_id(1)) is None


def _frames_of(frames, mtype):
    return [f.payload for f, _ in frames if f.header.msg_type == int(mtype)]


class TestServerHandlers:
    @staticmethod
    async def _setup(port: int):
        state = ServerState()
        transport, protocol_obj = await _start_server_with_state(state, port)
        server_addr, sock_a, sock_b = await _two_raw_peers(port)
        peer_a, peer_b = f"pA_{port}", f"pB_{port}"
        _record(protocol_obj.state, peer_a)
        _record(protocol_obj.state, peer_b, lines=[(PIPBOY, FP_PLAIN, 1, INV_ENTRY_EQUIPPED)])
        return transport, protocol_obj, server_addr, sock_a, sock_b, peer_a, peer_b

    @pytest.mark.asyncio
    async def test_a_drop_is_acknowledged_with_its_wid_and_placed_for_everyone(self):
        transport, p, addr, sock_a, sock_b, peer_a, peer_b = await self._setup(31680)
        try:
            sock_a.sendto(encode_frame(MessageType.WORLD_ITEM_OP, 1, _drop(), reliable=True), addr)
            fa, fb = await asyncio.gather(_collect_frames(sock_a, 0.5), _collect_frames(sock_b, 0.5))
            [ack] = _frames_of(fa, MessageType.WORLD_ITEM_ACK)
            assert ack.status == int(ContainerOpAckStatus.ACCEPTED) and ack.kind == WORLD_ITEM_DROP
            assert ack.client_op_id == _op_id(1) and ack.wid != 0
            assert (ack.item_base_id, ack.item_fp, ack.record_count) == (STIMPAK, FP_PLAIN, 2)
            for frames in (fa, fb):
                [sp] = _frames_of(frames, MessageType.WORLD_SPAWN_BCAST)
                assert sp.wid == ack.wid and sp.peer_id == peer_a
                assert sp.base_form_id == STIMPAK and sp.spawner_local_fid == 0xFF001234
                assert sp.flags & WORLD_SPAWN_FLAG_SELF_DESCRIBED
                assert sp.pieces == ((STIMPAK, 2, (), -1.0),)
            assert _frames_of(fb, MessageType.WORLD_ITEM_ACK) == []
            assert p.state.player_inventory(peer_a).lines[(STIMPAK, FP_PLAIN)] == 2
            assert p.state.world_spawns[ack.wid].spawner_peer == peer_a
        finally:
            sock_a.close(); sock_b.close(); transport.close()

    @pytest.mark.asyncio
    async def test_the_first_pickup_wins_and_the_second_is_refused(self):
        transport, p, addr, sock_a, sock_b, peer_a, peer_b = await self._setup(31681)
        try:
            st = _spawn_item(p.state, peer_a)
            op_b = _pickup(wid=st.wid, ref=0xFF00AAAA, op_id=_op_id(1))
            sock_b.sendto(encode_frame(MessageType.WORLD_ITEM_OP, 1, op_b, reliable=True), addr)
            fa, fb = await asyncio.gather(_collect_frames(sock_a, 0.5), _collect_frames(sock_b, 0.5))
            [ack] = _frames_of(fb, MessageType.WORLD_ITEM_ACK)
            assert ack.status == int(ContainerOpAckStatus.ACCEPTED) and ack.wid == st.wid
            assert ack.kind == WORLD_ITEM_PICKUP and ack.record_count == 2
            for frames in (fa, fb):
                [ds] = _frames_of(frames, MessageType.WORLD_DESPAWN_BCAST)
                assert ds.wid == st.wid and ds.reason == 5
            assert st.wid not in p.state.world_spawns
            assert p.state.player_inventory(peer_b).lines[(STIMPAK, FP_PLAIN)] == 2
            op_a = _pickup(wid=st.wid, ref=0xFF00AAAB, op_id=_op_id(1))
            sock_a.sendto(encode_frame(MessageType.WORLD_ITEM_OP, 2, op_a, reliable=True), addr)
            fa, fb = await asyncio.gather(_collect_frames(sock_a, 0.5), _collect_frames(sock_b, 0.5))
            [ack] = _frames_of(fa, MessageType.WORLD_ITEM_ACK)
            assert ack.status == int(ContainerOpAckStatus.REJ_INSUFFICIENT)
            assert ack.kind == WORLD_ITEM_PICKUP and ack.wid == 0
            assert _frames_of(fa, MessageType.WORLD_DESPAWN_BCAST) == []
            assert _frames_of(fb, MessageType.WORLD_DESPAWN_BCAST) == []
            assert p.state.player_inventory(peer_a).lines[(STIMPAK, FP_PLAIN)] == 4
            assert p.state.player_inventory(peer_a).pending == []
        finally:
            sock_a.close(); sock_b.close(); transport.close()

    @pytest.mark.asyncio
    async def test_a_vanilla_pickup_is_relayed_as_a_disable_to_the_others(self):
        transport, p, addr, sock_a, sock_b, peer_a, peer_b = await self._setup(31682)
        try:
            op = _pickup(ref=0x000A1234, op_id=_op_id(1))
            sock_a.sendto(encode_frame(MessageType.WORLD_ITEM_OP, 1, op, reliable=True), addr)
            fa, fb = await asyncio.gather(_collect_frames(sock_a, 0.5), _collect_frames(sock_b, 0.5))
            [ack] = _frames_of(fa, MessageType.WORLD_ITEM_ACK)
            assert ack.status == int(ContainerOpAckStatus.ACCEPTED) and ack.wid == 0
            [ev] = _frames_of(fb, MessageType.ACTOR_EVENT)
            assert isinstance(ev, ActorEventPayload)
            assert ev.kind == 3 and ev.form_id == 0x000A1234
            assert ev.actor_base_id == STIMPAK and ev.cell_id == CELL
            assert (ev.x, ev.y, ev.z) == (1.0, 2.0, 3.0)
            assert _frames_of(fa, MessageType.ACTOR_EVENT) == []
            assert not p.state.actor_state(STIMPAK, CELL).alive
            assert p.state.player_inventory(peer_a).lines[(STIMPAK, FP_PLAIN)] == 6
        finally:
            sock_a.close(); sock_b.close(); transport.close()

    @pytest.mark.asyncio
    async def test_a_repeated_op_gets_its_verdict_again_and_is_applied_once(self):
        transport, p, addr, sock_a, sock_b, peer_a, peer_b = await self._setup(31683)
        try:
            op = _drop(op_id=_op_id(1))
            sock_a.sendto(encode_frame(MessageType.WORLD_ITEM_OP, 1, op, reliable=True), addr)
            fa, _ = await asyncio.gather(_collect_frames(sock_a, 0.5), _collect_frames(sock_b, 0.5))
            [first] = _frames_of(fa, MessageType.WORLD_ITEM_ACK)
            sock_a.sendto(encode_frame(MessageType.WORLD_ITEM_OP, 2, op, reliable=True), addr)
            fa, fb = await asyncio.gather(_collect_frames(sock_a, 0.5), _collect_frames(sock_b, 0.5))
            [again] = _frames_of(fa, MessageType.WORLD_ITEM_ACK)
            assert again == first
            assert _frames_of(fa, MessageType.WORLD_SPAWN_BCAST) == []
            assert _frames_of(fb, MessageType.WORLD_SPAWN_BCAST) == []
            assert len(p.state.world_spawns) == 1
            assert p.state.player_inventory(peer_a).lines[(STIMPAK, FP_PLAIN)] == 2
        finally:
            sock_a.close(); sock_b.close(); transport.close()

    @pytest.mark.asyncio
    async def test_a_refused_op_changes_nothing_and_says_why(self):
        transport, p, addr, sock_a, sock_b, peer_a, peer_b = await self._setup(31684)
        try:
            wrong = _drop(item=PISTOL, count=1, desc=AUTO_PISTOL, fp=0x1234, op_id=_op_id(1))
            sock_a.sendto(encode_frame(MessageType.WORLD_ITEM_OP, 1, wrong, reliable=True), addr)
            fa, fb = await asyncio.gather(_collect_frames(sock_a, 0.5), _collect_frames(sock_b, 0.5))
            [ack] = _frames_of(fa, MessageType.WORLD_ITEM_ACK)
            assert ack.status == int(ContainerOpAckStatus.REJ_INSTANCE) and ack.wid == 0
            assert _frames_of(fa, MessageType.WORLD_SPAWN_BCAST) == []
            assert _frames_of(fb, MessageType.WORLD_SPAWN_BCAST) == []
            assert p.state.world_spawns == {}
            assert p.state.player_inventory(peer_a).lines[(PISTOL, AUTO_FP)] == 1
            assert p.state.player_inventory(peer_a).pending == []
        finally:
            sock_a.close(); sock_b.close(); transport.close()

    @pytest.mark.asyncio
    async def test_with_the_journal_down_nothing_is_accepted(self, tmp_path: Path):
        transport, p, addr, sock_a, sock_b, peer_a, peer_b = await self._setup(31685)
        try:
            p.state.journal = Journal.open(tmp_path / "journal")
            p._journal_healthy = False
            sock_a.sendto(encode_frame(MessageType.WORLD_ITEM_OP, 1, _drop(), reliable=True), addr)
            fa, fb = await asyncio.gather(_collect_frames(sock_a, 0.5), _collect_frames(sock_b, 0.5))
            [ack] = _frames_of(fa, MessageType.WORLD_ITEM_ACK)
            assert ack.status == int(ContainerOpAckStatus.REJ_UNAVAILABLE)
            assert p.state.world_spawns == {}
            assert p.state.player_inventory(peer_a).lines[(STIMPAK, FP_PLAIN)] == 4
            assert p.state.recall_world_item_verdict(peer_a, _op_id(1)) is None
        finally:
            p.state.journal.close()
            sock_a.close(); sock_b.close(); transport.close()
