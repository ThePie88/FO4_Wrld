"""L5 realtime persistence, slice R1 (2026-10-03): the player's inventory
on the server, kept current.

The owner's decision of 2026-10-03: the checkpoint must be realtime, Alt+F4,
a crash and a death lose nothing. A .fos blocks the main thread ~127 ms, so
the coverage is a character record on the server: the player's inventory by
instance, made of the client's captures (sent at every change, only complete,
only with no container op in flight) and of the container ops the server
accepts, which change the record inside the same journal record as the
container. A capture names the last op it includes (the watermark); the ops
after it stay pending on top of it.
"""
from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from protocol import (  # noqa: E402
    MessageType, ProtocolError,
    ContainerOpPayload, ContainerOpKind,
    InstanceDescriptor, InstanceDefEntry, InstanceDefsPayload,
    INSTANCE_FLAG_OIE, FP_PLAIN, FP_UNKNOWN, instance_fp,
    InvStateEntry, InvStatePayload,
    INV_STATE_FLAG_COMPLETE, INV_ENTRY_EQUIPPED,
    encode_frame, decode_frame,
)
from server.journal import Journal  # noqa: E402
from server.state import ServerState  # noqa: E402
from server.validator import validate_inv_state, RejectReason  # noqa: E402
from server.persistence import snapshot, load_into, SNAPSHOT_FORMAT_VERSION  # noqa: E402
from net.tests.test_container import _start_server_with_state, _collect_frames  # noqa: E402
from net.tests.test_container_reconverge import _two_raw_peers  # noqa: E402

TRUNK_FID = 0x1F3A2
TRUNK_BASE = 0xDEAD01
TRUNK_CELL = 0x1696A
PISTOL = 0x4822
STIMPAK = 0x23736
CAPS = 0xF
EPOCH = 0xBEFE
SESSION = 0x5A5A0001

AUTO_PISTOL = InstanceDescriptor(
    template=4, flags=INSTANCE_FLAG_OIE,
    mods=((0x100E2E, 0, 1), (0x231AB, 0, 1), (0x100E27, 0, 1),
          (0x91FC2, 0, 1), (0x148409, 0, 1), (0x4F21D, 0, 1)))
AUTO_FP = instance_fp(PISTOL, AUTO_PISTOL)


def _op_id(seq: int, epoch: int = EPOCH) -> int:
    return (epoch << 16) | (seq & 0xFFFF)


def _op(kind: ContainerOpKind, item: int, count: int, op_id: int,
        desc: InstanceDescriptor | None = None) -> ContainerOpPayload:
    d = desc if desc is not None else InstanceDescriptor()
    return ContainerOpPayload(
        kind=int(kind), container_form_id=TRUNK_FID,
        container_base_id=TRUNK_BASE, container_cell_id=TRUNK_CELL,
        item_base_id=item, count=count, timestamp_ms=0, client_op_id=op_id,
        item_fp=instance_fp(item, d), instance=d,
    )


def _capture(state: ServerState, peer: str, seq: int, lines, watermark: int = 0,
             session: int = SESSION, epoch: int = EPOCH, now: float = 0.0):
    """lines: (item, fp, count[, flags])."""
    entries = tuple((l[0], l[1], l[2], l[3] if len(l) > 3 else 0) for l in lines)
    return state.record_player_inventory(
        peer, session, seq, watermark, epoch, INV_STATE_FLAG_COMPLETE, 0x1234, entries, now)


def _seeded_trunk(state: ServerState, items: dict) -> None:
    state.create_container(TRUNK_FID, TRUNK_BASE, TRUNK_CELL, items, "seed", 0.0)


# ------------------------------------------------------------------- wire

class TestWire:
    def test_roundtrip(self):
        p = InvStatePayload(
            session=SESSION, seq=7, watermark=_op_id(3), op_epoch=EPOCH,
            flags=INV_STATE_FLAG_COMPLETE, digest=0x0123456789ABCDEF,
            entries=(InvStateEntry(PISTOL, AUTO_FP, 1, INV_ENTRY_EQUIPPED),
                     InvStateEntry(STIMPAK, FP_PLAIN, 12)),
            chunk_index=1, total_chunks=3)
        raw = encode_frame(MessageType.INV_STATE, 5, p, reliable=True)
        frame = decode_frame(raw)
        assert frame.header.msg_type == int(MessageType.INV_STATE)
        assert frame.payload == p

    def test_one_frame_carries_80_lines(self):
        assert InvStatePayload.MAX_ENTRIES_PER_FRAME == 80
        full = InvStatePayload(session=1, seq=1, watermark=0, op_epoch=1, flags=1, digest=0,
                               entries=tuple(InvStateEntry(i + 1, FP_PLAIN, 1) for i in range(80)))
        assert len(full.encode()) <= 1400
        with pytest.raises(ProtocolError):
            InvStatePayload(session=1, seq=1, watermark=0, op_epoch=1, flags=1, digest=0,
                            entries=tuple(InvStateEntry(i + 1, FP_PLAIN, 1)
                                          for i in range(81))).encode()

    def test_truncated_is_refused(self):
        p = InvStatePayload(session=1, seq=1, watermark=0, op_epoch=1, flags=1, digest=0,
                            entries=(InvStateEntry(STIMPAK, FP_PLAIN, 2),))
        with pytest.raises(ProtocolError):
            InvStatePayload.decode(p.encode()[:-1])


# ---------------------------------------------------------------- record

class TestRecordFromCaptures:
    def test_a_capture_is_the_record(self):
        s = ServerState()
        rec = _capture(s, "alice", 1, [(PISTOL, AUTO_FP, 1, INV_ENTRY_EQUIPPED),
                                       (STIMPAK, FP_PLAIN, 12), (CAPS, FP_PLAIN, 300)])
        assert rec is not None
        assert rec.lines == {(PISTOL, AUTO_FP): 1, (STIMPAK, FP_PLAIN): 12,
                             (CAPS, FP_PLAIN): 300}
        assert rec.equipped == {(PISTOL, AUTO_FP)}
        assert rec.captures == 1

    def test_the_next_capture_replaces_the_lines(self):
        s = ServerState()
        _capture(s, "alice", 1, [(STIMPAK, FP_PLAIN, 12), (CAPS, FP_PLAIN, 300)])
        rec = _capture(s, "alice", 2, [(STIMPAK, FP_PLAIN, 11)])
        assert rec.lines == {(STIMPAK, FP_PLAIN): 11}

    def test_two_stacks_of_one_instance_are_one_line(self):
        s = ServerState()
        rec = _capture(s, "alice", 1, [(STIMPAK, FP_PLAIN, 5), (STIMPAK, FP_PLAIN, 7)])
        assert rec.lines == {(STIMPAK, FP_PLAIN): 12}

    def test_a_stale_capture_of_the_same_process_is_ignored(self):
        s = ServerState()
        _capture(s, "alice", 5, [(STIMPAK, FP_PLAIN, 3)])
        assert _capture(s, "alice", 4, [(STIMPAK, FP_PLAIN, 9)]) is None
        assert _capture(s, "alice", 5, [(STIMPAK, FP_PLAIN, 9)]) is None
        assert s.player_inventory("alice").lines == {(STIMPAK, FP_PLAIN): 3}

    def test_a_new_process_starts_its_numbers_again(self):
        s = ServerState()
        _capture(s, "alice", 50, [(STIMPAK, FP_PLAIN, 3)])
        s.record_player_restored("alice", 0x77770002, 0.0)   # R2: its record came back
        rec = _capture(s, "alice", 1, [(STIMPAK, FP_PLAIN, 9)], session=0x77770002)
        assert rec is not None and rec.lines == {(STIMPAK, FP_PLAIN): 9}

    def test_invalid_captures_are_refused(self):
        s = ServerState()
        assert _capture(s, "alice", 1, [(STIMPAK, FP_PLAIN, 0)]) is None
        assert _capture(s, "alice", 1, [(0, FP_PLAIN, 1)]) is None
        assert _capture(s, "alice", 1, [(STIMPAK, FP_PLAIN, 1)], session=0) is None
        assert _capture(s, "", 1, [(STIMPAK, FP_PLAIN, 1)]) is None
        assert s.player_inventory("alice") is None


class TestRecordFromContainerOps:
    def test_an_accepted_take_lands_in_the_takers_record(self):
        s = ServerState()
        _seeded_trunk(s, {STIMPAK: 5})
        _capture(s, "alice", 1, [(CAPS, FP_PLAIN, 300)])
        s.record_container_op(_op(ContainerOpKind.TAKE, STIMPAK, 2, _op_id(1)), "alice", 0.0)
        assert s.player_inventory("alice").lines == {(CAPS, FP_PLAIN): 300, (STIMPAK, FP_PLAIN): 2}
        assert s.container_state(TRUNK_FID).items == {(STIMPAK, FP_PLAIN): 3}

    def test_a_put_leaves_the_record_with_its_instance(self):
        s = ServerState()
        _capture(s, "alice", 1, [(PISTOL, AUTO_FP, 1), (STIMPAK, FP_PLAIN, 4)])
        s.record_container_op(_op(ContainerOpKind.PUT, PISTOL, 1, _op_id(1), AUTO_PISTOL),
                              "alice", 0.0)
        assert s.player_inventory("alice").lines == {(STIMPAK, FP_PLAIN): 4}

    def test_a_put_of_what_the_record_lacks_never_goes_negative(self):
        s = ServerState()
        _capture(s, "alice", 1, [(STIMPAK, FP_PLAIN, 1)])
        s.record_container_op(_op(ContainerOpKind.PUT, STIMPAK, 3, _op_id(1)), "alice", 0.0)
        assert s.player_inventory("alice").lines == {}

    def test_someone_elses_ops_do_not_touch_the_record(self):
        s = ServerState()
        _seeded_trunk(s, {STIMPAK: 5})
        _capture(s, "alice", 1, [(CAPS, FP_PLAIN, 300)])
        s.record_container_op(_op(ContainerOpKind.TAKE, STIMPAK, 2, _op_id(1, 0x1111)),
                              "bob", 0.0)
        assert s.player_inventory("alice").lines == {(CAPS, FP_PLAIN): 300}
        assert s.player_inventory("bob").lines == {(STIMPAK, FP_PLAIN): 2}
        # An op without a capture under it makes a record that is not a base.
        assert s.player_inventory("bob").captures == 0


class TestWatermark:
    """The capture names the last op it includes; the ops after it stay."""

    def _take_two(self, s: ServerState) -> None:
        _seeded_trunk(s, {STIMPAK: 10})
        _capture(s, "alice", 1, [(CAPS, FP_PLAIN, 300)])
        s.record_container_op(_op(ContainerOpKind.TAKE, STIMPAK, 2, _op_id(1)), "alice", 0.0)
        s.record_container_op(_op(ContainerOpKind.TAKE, STIMPAK, 3, _op_id(2)), "alice", 0.0)

    def test_a_capture_that_includes_every_op_absorbs_them(self):
        s = ServerState()
        self._take_two(s)
        rec = _capture(s, "alice", 2, [(CAPS, FP_PLAIN, 300), (STIMPAK, FP_PLAIN, 5)],
                       watermark=_op_id(2))
        assert rec.lines == {(CAPS, FP_PLAIN): 300, (STIMPAK, FP_PLAIN): 5}
        assert rec.pending == []

    def test_a_capture_older_than_an_op_keeps_that_op_on_top(self):
        s = ServerState()
        self._take_two(s)
        # Taken after op 1 and before op 2 (op 2 overtook it on the wire).
        rec = _capture(s, "alice", 2, [(CAPS, FP_PLAIN, 300), (STIMPAK, FP_PLAIN, 2)],
                       watermark=_op_id(1))
        assert rec.lines == {(CAPS, FP_PLAIN): 300, (STIMPAK, FP_PLAIN): 5}
        assert [p[0] for p in rec.pending] == [_op_id(2)]

    def test_a_capture_with_no_op_yet_keeps_every_op_of_its_process(self):
        s = ServerState()
        self._take_two(s)
        rec = _capture(s, "alice", 2, [(CAPS, FP_PLAIN, 290)], watermark=0)
        assert rec.lines == {(CAPS, FP_PLAIN): 290, (STIMPAK, FP_PLAIN): 5}

    def test_the_first_capture_of_a_new_process_drops_the_old_processs_ops(self):
        s = ServerState()
        self._take_two(s)
        # The old process died; the new one restored the record, then captured.
        s.record_player_restored("alice", 0x12340001, 0.0)
        rec = _capture(s, "alice", 1, [(CAPS, FP_PLAIN, 300), (STIMPAK, FP_PLAIN, 5)],
                       watermark=0, session=0x12340001, epoch=0x4321)
        assert rec.lines == {(CAPS, FP_PLAIN): 300, (STIMPAK, FP_PLAIN): 5}
        assert rec.pending == []

    def test_an_op_of_the_new_process_that_overtook_its_first_capture_stays(self):
        s = ServerState()
        self._take_two(s)
        s.record_container_op(_op(ContainerOpKind.TAKE, STIMPAK, 1, _op_id(1, 0x4321)),
                              "alice", 0.0)
        s.record_player_restored("alice", 0x12340001, 0.0)
        rec = _capture(s, "alice", 1, [(CAPS, FP_PLAIN, 300), (STIMPAK, FP_PLAIN, 5)],
                       watermark=0, session=0x12340001, epoch=0x4321)
        assert rec.lines == {(CAPS, FP_PLAIN): 300, (STIMPAK, FP_PLAIN): 6}
        assert [p[0] for p in rec.pending] == [_op_id(1, 0x4321)]

    def test_the_op_numbers_wrap(self):
        s = ServerState()
        _seeded_trunk(s, {STIMPAK: 10})
        _capture(s, "alice", 1, [])
        s.record_container_op(_op(ContainerOpKind.TAKE, STIMPAK, 2, _op_id(0xFFFF)), "alice", 0.0)
        s.record_container_op(_op(ContainerOpKind.TAKE, STIMPAK, 3, _op_id(0x0001)), "alice", 0.0)
        rec = _capture(s, "alice", 2, [(STIMPAK, FP_PLAIN, 2)], watermark=_op_id(0xFFFF))
        assert rec.lines == {(STIMPAK, FP_PLAIN): 5}
        assert [p[0] for p in rec.pending] == [_op_id(0x0001)]


# --------------------------------------------------------------- validator

class TestValidator:
    def _p(self, **kw) -> InvStatePayload:
        base = dict(session=SESSION, seq=1, watermark=0, op_epoch=EPOCH,
                    flags=INV_STATE_FLAG_COMPLETE, digest=0,
                    entries=(InvStateEntry(STIMPAK, FP_PLAIN, 2),))
        base.update(kw)
        return InvStatePayload(**base)

    def test_a_good_chunk_passes(self):
        assert validate_inv_state(self._p()).ok

    def test_an_incomplete_capture_is_refused(self):
        r = validate_inv_state(self._p(flags=0))
        assert not r.ok and r.reason == RejectReason.INV_STATE_INVALID

    def test_bad_counts_items_and_chunking_are_refused(self):
        for p in (self._p(entries=(InvStateEntry(STIMPAK, FP_PLAIN, 0),)),
                  self._p(entries=(InvStateEntry(0, FP_PLAIN, 1),)),
                  self._p(session=0),
                  self._p(chunk_index=2, total_chunks=2),
                  self._p(total_chunks=0),
                  self._p(total_chunks=65)):
            r = validate_inv_state(p)
            assert not r.ok and r.reason == RejectReason.INV_STATE_INVALID


# ------------------------------------------------------- journal, snapshot

class TestDurability:
    def test_the_journal_replays_the_record(self, tmp_path: Path):
        j = Journal.open(tmp_path / "journal")
        a = ServerState()
        a.journal = j
        _seeded_trunk(a, {STIMPAK: 10})
        _capture(a, "alice", 1, [(PISTOL, AUTO_FP, 1, INV_ENTRY_EQUIPPED)])
        a.record_container_op(_op(ContainerOpKind.TAKE, STIMPAK, 2, _op_id(1)), "alice", 0.0)
        a.record_container_op(_op(ContainerOpKind.TAKE, STIMPAK, 1, _op_id(2)), "alice", 0.0)
        _capture(a, "alice", 2, [(PISTOL, AUTO_FP, 1, INV_ENTRY_EQUIPPED),
                                 (STIMPAK, FP_PLAIN, 2)], watermark=_op_id(1))
        want = a.player_inventory("alice")
        j.flush()
        j.close()
        b = ServerState()
        Journal.open(tmp_path / "journal").replay(b, after_lsn=0)
        got = b.player_inventory("alice")
        assert got.lines == want.lines == {(PISTOL, AUTO_FP): 1, (STIMPAK, FP_PLAIN): 3}
        assert got.equipped == want.equipped
        assert got.pending == want.pending
        assert (got.session, got.seq, got.watermark) == (want.session, want.seq, want.watermark)

    def test_snapshot_roundtrip_keeps_the_record_and_its_descriptors(self, tmp_path: Path):
        s = ServerState()
        _seeded_trunk(s, {STIMPAK: 10})
        s.record_instance_def(PISTOL, AUTO_FP, AUTO_PISTOL)
        _capture(s, "alice", 3, [(PISTOL, AUTO_FP, 1, INV_ENTRY_EQUIPPED), (CAPS, FP_PLAIN, 300)])
        s.record_container_op(_op(ContainerOpKind.TAKE, STIMPAK, 2, _op_id(9)), "alice", 0.0)
        path = tmp_path / "snap.json"
        snapshot(s, path)
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data["version"] == SNAPSHOT_FORMAT_VERSION == 15   # v15: partial-record ops, checkpoint world, world base per peer (2026-10-20)
        # The pistol is in no container: its descriptor is written for the record.
        assert [d["fp"] for d in data["instances"]] == [f"0x{AUTO_FP:X}"]
        t = ServerState()
        load_into(t, path)
        rec = t.player_inventory("alice")
        assert rec.lines == {(PISTOL, AUTO_FP): 1, (CAPS, FP_PLAIN): 300, (STIMPAK, FP_PLAIN): 2}
        assert rec.equipped == {(PISTOL, AUTO_FP)}
        assert [p[0] for p in rec.pending] == [_op_id(9)]
        assert (rec.session, rec.seq, rec.captures) == (SESSION, 3, 1)
        assert t.instance_def(AUTO_FP) == (PISTOL, AUTO_PISTOL)

    def test_a_v11_snapshot_loads_with_no_records(self, tmp_path: Path):
        s = ServerState()
        _seeded_trunk(s, {STIMPAK: 10})
        path = tmp_path / "snap.json"
        snapshot(s, path)
        data = json.loads(path.read_text(encoding="utf-8"))
        data["version"] = 11
        data.pop("players", None)
        path.write_text(json.dumps(data), encoding="utf-8")
        t = ServerState()
        load_into(t, path)
        assert t.all_player_inventories() == []
        assert t.container_state(TRUNK_FID).items == {(STIMPAK, FP_PLAIN): 10}


# ------------------------------------------------------------- the server

class TestServerHandler:
    @staticmethod
    def _chunks(entries, seq=1, flags=INV_STATE_FLAG_COMPLETE, per=80):
        parts = [entries[i:i + per] for i in range(0, len(entries), per)] or [()]
        return [InvStatePayload(session=SESSION, seq=seq, watermark=0, op_epoch=EPOCH,
                                flags=flags, digest=0xD1, entries=tuple(p),
                                chunk_index=i, total_chunks=len(parts))
                for i, p in enumerate(parts)]

    @pytest.mark.asyncio
    async def test_a_capture_in_two_chunks_becomes_the_record(self):
        port = 31590
        transport, protocol_obj = await _start_server_with_state(ServerState(), port)
        try:
            server_addr, sock_a, sock_b = await _two_raw_peers(port)
            try:
                defs = InstanceDefsPayload(entries=(InstanceDefEntry(PISTOL, AUTO_FP, AUTO_PISTOL),))
                sock_a.sendto(encode_frame(MessageType.INSTANCE_DEFS, 1, defs, reliable=True),
                              server_addr)
                entries = [InvStateEntry(0x1000 + i, FP_PLAIN, 1) for i in range(100)]
                entries.append(InvStateEntry(PISTOL, AUTO_FP, 1, INV_ENTRY_EQUIPPED))
                chunks = self._chunks(entries)
                assert len(chunks) == 2
                # The second chunk first: the record waits for the whole capture.
                sock_a.sendto(encode_frame(MessageType.INV_STATE, 3, chunks[1], reliable=True),
                              server_addr)
                await _collect_frames(sock_a, 0.2)
                assert protocol_obj.state.player_inventory(f"pA_{port}") is None
                sock_a.sendto(encode_frame(MessageType.INV_STATE, 2, chunks[0], reliable=True),
                              server_addr)
                await _collect_frames(sock_a, 0.3)
                rec = protocol_obj.state.player_inventory(f"pA_{port}")
                assert rec is not None and len(rec.lines) == 101
                assert rec.equipped == {(PISTOL, AUTO_FP)}
                assert protocol_obj.state.instance_def(AUTO_FP) == (PISTOL, AUTO_PISTOL)
            finally:
                sock_a.close(); sock_b.close()
        finally:
            transport.close()

    @pytest.mark.asyncio
    async def test_an_incomplete_capture_never_becomes_the_record(self):
        port = 31591
        transport, protocol_obj = await _start_server_with_state(ServerState(), port)
        try:
            server_addr, sock_a, sock_b = await _two_raw_peers(port)
            try:
                [chunk] = self._chunks([InvStateEntry(STIMPAK, FP_PLAIN, 2)], flags=0)
                sock_a.sendto(encode_frame(MessageType.INV_STATE, 1, chunk, reliable=True),
                              server_addr)
                await _collect_frames(sock_a, 0.3)
                assert protocol_obj.state.player_inventory(f"pA_{port}") is None
            finally:
                sock_a.close(); sock_b.close()
        finally:
            transport.close()

    @pytest.mark.asyncio
    async def test_a_newer_capture_replaces_an_unfinished_one(self):
        port = 31592
        transport, protocol_obj = await _start_server_with_state(ServerState(), port)
        try:
            server_addr, sock_a, sock_b = await _two_raw_peers(port)
            try:
                old = self._chunks([InvStateEntry(0x1000 + i, FP_PLAIN, 1) for i in range(100)],
                                   seq=1)
                [new] = self._chunks([InvStateEntry(STIMPAK, FP_PLAIN, 7)], seq=2)
                sock_a.sendto(encode_frame(MessageType.INV_STATE, 1, old[0], reliable=True),
                              server_addr)
                sock_a.sendto(encode_frame(MessageType.INV_STATE, 2, new, reliable=True),
                              server_addr)
                # The rest of the old one arrives late: it is stale, never applied.
                sock_a.sendto(encode_frame(MessageType.INV_STATE, 3, old[1], reliable=True),
                              server_addr)
                await _collect_frames(sock_a, 0.3)
                rec = protocol_obj.state.player_inventory(f"pA_{port}")
                assert rec.lines == {(STIMPAK, FP_PLAIN): 7}
                assert rec.seq == 2
            finally:
                sock_a.close(); sock_b.close()
        finally:
            transport.close()

    @pytest.mark.asyncio
    async def test_a_take_from_the_menu_reaches_the_record_at_once(self):
        port = 31593
        state = ServerState()
        _seeded_trunk(state, {STIMPAK: 5})
        transport, protocol_obj = await _start_server_with_state(state, port)
        try:
            server_addr, sock_a, sock_b = await _two_raw_peers(port)
            try:
                [chunk] = self._chunks([InvStateEntry(CAPS, FP_PLAIN, 300)])
                sock_a.sendto(encode_frame(MessageType.INV_STATE, 1, chunk, reliable=True),
                              server_addr)
                op = _op(ContainerOpKind.TAKE, STIMPAK, 2, _op_id(1))
                sock_a.sendto(encode_frame(MessageType.CONTAINER_OP, 2, op, reliable=True),
                              server_addr)
                await _collect_frames(sock_a, 0.3)
                rec = protocol_obj.state.player_inventory(f"pA_{port}")
                assert rec.lines == {(CAPS, FP_PLAIN): 300, (STIMPAK, FP_PLAIN): 2}
            finally:
                sock_a.close(); sock_b.close()
        finally:
            transport.close()
