"""L5 realtime persistence, slice R2 (2026-10-03): the record goes back into
the game after every load.

After a boot, a crash or a death the engine loads a checkpoint older than the
player's record (slice R1). The client asks for the record (RESTORE_REQUEST,
as soon as it knows a load is coming), the server answers with the lines
(PLAYER_INV, after the descriptors of its named instances), the client aligns
the player once the load is over and says so (RESTORE_DONE). Until then the
new process's captures are refused: a capture taken over the old checkpoint
would write the past over the record.
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
    InstanceDescriptor, InstanceDefEntry, INSTANCE_FLAG_OIE, FP_PLAIN, instance_fp,
    InvStateEntry, InvStatePayload, INV_STATE_FLAG_COMPLETE, INV_ENTRY_EQUIPPED,
    RestoreRequestPayload, PlayerInvPayload, RestoreDonePayload,
    RESTORE_REASON_BOOT, RESTORE_REASON_DEATH,
    PLAYER_INV_RECORD, PLAYER_INV_NONE, PLAYER_INV_BEHIND,
    RESTORE_ALIGNED, RESTORE_FAILED,
    encode_frame, decode_frame,
)
from server.journal import Journal  # noqa: E402
from server.state import ServerState  # noqa: E402
from server.persistence import snapshot, load_into  # noqa: E402
from net.tests.test_container import _start_server_with_state, _collect_frames  # noqa: E402
from net.tests.test_container_reconverge import _two_raw_peers  # noqa: E402

PISTOL = 0x4822
STIMPAK = 0x23736
CAPS = 0xF
OLD = 0x11110001       # the process that crashed
NEW = 0x22220001       # the one that booted after it
EPOCH_OLD = 0x1111
EPOCH_NEW = 0x2222

AUTO_PISTOL = InstanceDescriptor(
    template=4, flags=INSTANCE_FLAG_OIE,
    mods=((0x100E2E, 0, 1), (0x231AB, 0, 1), (0x100E27, 0, 1),
          (0x91FC2, 0, 1), (0x148409, 0, 1), (0x4F21D, 0, 1)))
AUTO_FP = instance_fp(PISTOL, AUTO_PISTOL)


def _cap(state: ServerState, peer: str, session: int, seq: int, lines, epoch: int):
    entries = tuple((l[0], l[1], l[2], l[3] if len(l) > 3 else 0) for l in lines)
    return state.record_player_inventory(peer, session, seq, 0, epoch,
                                         INV_STATE_FLAG_COMPLETE, 0, entries, 0.0)


# ------------------------------------------------------------------- wire

class TestWire:
    def test_request_roundtrip(self):
        p = RestoreRequestPayload(session=NEW, last_seq=7, reason=RESTORE_REASON_DEATH)
        f = decode_frame(encode_frame(MessageType.RESTORE_REQUEST, 1, p, reliable=True))
        assert f.payload == p and len(p.encode()) == 16

    def test_player_inv_roundtrip(self):
        p = PlayerInvPayload(session=NEW, record_seq=9, captures=4, status=PLAYER_INV_RECORD,
                             entries=(InvStateEntry(PISTOL, AUTO_FP, 1, INV_ENTRY_EQUIPPED),
                                      InvStateEntry(CAPS, FP_PLAIN, 300)),
                             chunk_index=0, total_chunks=1)
        f = decode_frame(encode_frame(MessageType.PLAYER_INV, 1, p, reliable=True))
        assert f.payload == p
        assert PlayerInvPayload.MAX_ENTRIES_PER_FRAME == 81
        with pytest.raises(ProtocolError):
            PlayerInvPayload(session=1, record_seq=1, captures=1, status=0,
                             entries=tuple(InvStateEntry(i + 1, FP_PLAIN, 1)
                                           for i in range(82))).encode()

    def test_done_roundtrip(self):
        p = RestoreDonePayload(session=NEW, record_seq=9, outcome=RESTORE_ALIGNED,
                               removed=2, added=3, unresolved=0, digest=0xABCDEF)
        f = decode_frame(encode_frame(MessageType.RESTORE_DONE, 1, p, reliable=True))
        assert f.payload == p and len(p.encode()) == 24


# ------------------------------------------------------------------- state

class TestTheRecordIsClosedUntilTheRestore:
    def test_a_new_process_cannot_overwrite_the_record_before_restoring(self):
        s = ServerState()
        _cap(s, "alice", OLD, 5, [(PISTOL, AUTO_FP, 1)], EPOCH_OLD)
        # The new process captured the old checkpoint's inventory: refused.
        assert _cap(s, "alice", NEW, 1, [(STIMPAK, FP_PLAIN, 1)], EPOCH_NEW) is None
        assert s.player_inventory("alice").lines == {(PISTOL, AUTO_FP): 1}
        assert s.record_player_restored("alice", NEW, 0.0)
        rec = _cap(s, "alice", NEW, 1, [(PISTOL, AUTO_FP, 1), (STIMPAK, FP_PLAIN, 1)], EPOCH_NEW)
        assert rec is not None and rec.session == NEW

    def test_a_new_character_opens_its_record_with_its_first_capture(self):
        s = ServerState()
        assert _cap(s, "bob", NEW, 1, [(CAPS, FP_PLAIN, 10)], EPOCH_NEW) is not None
        assert _cap(s, "bob", NEW, 2, [(CAPS, FP_PLAIN, 11)], EPOCH_NEW) is not None
        assert s.player_inventory("bob").open_session == NEW

    def test_a_record_made_of_ops_alone_is_open_to_any_process(self):
        s = ServerState()
        s.create_container(0x1F3A2, 0xDEAD01, 0x1696A, {STIMPAK: 5}, "seed", 0.0)
        from net.tests.test_realtime_record import _op, _op_id
        from protocol import ContainerOpKind
        s.record_container_op(_op(ContainerOpKind.TAKE, STIMPAK, 2, _op_id(1, EPOCH_OLD)),
                              "carol", 0.0)
        assert _cap(s, "carol", NEW, 1, [(STIMPAK, FP_PLAIN, 2)], EPOCH_NEW) is not None

    def test_the_same_process_keeps_writing_across_a_death(self):
        s = ServerState()
        _cap(s, "alice", NEW, 1, [(CAPS, FP_PLAIN, 10)], EPOCH_NEW)
        assert _cap(s, "alice", NEW, 2, [(CAPS, FP_PLAIN, 9)], EPOCH_NEW) is not None

    def test_restored_needs_a_session(self):
        s = ServerState()
        assert not s.record_player_restored("alice", 0, 0.0)
        assert not s.record_player_restored("", NEW, 0.0)


class TestDurability:
    def test_the_journal_replays_the_opening(self, tmp_path: Path):
        j = Journal.open(tmp_path / "journal")
        a = ServerState()
        a.journal = j
        _cap(a, "alice", OLD, 5, [(PISTOL, AUTO_FP, 1)], EPOCH_OLD)
        a.record_player_restored("alice", NEW, 0.0)
        _cap(a, "alice", NEW, 1, [(PISTOL, AUTO_FP, 1), (CAPS, FP_PLAIN, 3)], EPOCH_NEW)
        j.flush()
        j.close()
        b = ServerState()
        Journal.open(tmp_path / "journal").replay(b, after_lsn=0)
        rec = b.player_inventory("alice")
        assert rec.open_session == NEW
        assert rec.lines == {(PISTOL, AUTO_FP): 1, (CAPS, FP_PLAIN): 3}

    def test_snapshot_keeps_the_open_process(self, tmp_path: Path):
        s = ServerState()
        _cap(s, "alice", OLD, 5, [(PISTOL, AUTO_FP, 1)], EPOCH_OLD)
        s.record_player_restored("alice", NEW, 0.0)
        path = tmp_path / "snap.json"
        snapshot(s, path)
        t = ServerState()
        load_into(t, path)
        assert t.player_inventory("alice").open_session == NEW
        data = json.loads(path.read_text(encoding="utf-8"))
        for r in data["players"]:
            r.pop("open_session")
        path.write_text(json.dumps(data), encoding="utf-8")
        u = ServerState()
        load_into(u, path)
        assert u.player_inventory("alice").open_session == 0


# ------------------------------------------------------------- the server

def _frames_of(frames, mtype):
    return [f.payload for f, _ in frames if f.header.msg_type == int(mtype)]


class TestServerHandlers:
    @pytest.mark.asyncio
    async def test_no_record_answers_none(self):
        port = 31600
        transport, protocol_obj = await _start_server_with_state(ServerState(), port)
        try:
            server_addr, sock_a, sock_b = await _two_raw_peers(port)
            try:
                req = RestoreRequestPayload(session=NEW, last_seq=0, reason=RESTORE_REASON_BOOT)
                sock_a.sendto(encode_frame(MessageType.RESTORE_REQUEST, 1, req, reliable=True),
                              server_addr)
                frames = await _collect_frames(sock_a, 0.4)
                [inv] = _frames_of(frames, MessageType.PLAYER_INV)
                assert inv.status == PLAYER_INV_NONE and inv.session == NEW
                assert inv.entries == ()
            finally:
                sock_a.close(); sock_b.close()
        finally:
            transport.close()

    @pytest.mark.asyncio
    async def test_a_boot_gets_the_record_with_its_descriptors(self):
        port = 31601
        state = ServerState()
        state.record_instance_def(PISTOL, AUTO_FP, AUTO_PISTOL)
        transport, protocol_obj = await _start_server_with_state(state, port)
        try:
            server_addr, sock_a, sock_b = await _two_raw_peers(port)
            try:
                peer = f"pA_{port}"
                _cap(protocol_obj.state, peer, OLD, 5,
                     [(PISTOL, AUTO_FP, 1, INV_ENTRY_EQUIPPED), (CAPS, FP_PLAIN, 300)], EPOCH_OLD)
                req = RestoreRequestPayload(session=NEW, last_seq=0, reason=RESTORE_REASON_BOOT)
                sock_a.sendto(encode_frame(MessageType.RESTORE_REQUEST, 1, req, reliable=True),
                              server_addr)
                frames = await _collect_frames(sock_a, 0.4)
                defs = [e for p in _frames_of(frames, MessageType.INSTANCE_DEFS) for e in p.entries]
                assert defs == [InstanceDefEntry(PISTOL, AUTO_FP, AUTO_PISTOL)]
                [inv] = _frames_of(frames, MessageType.PLAYER_INV)
                assert inv.status == PLAYER_INV_RECORD and inv.record_seq == 5
                assert {(e.item_base_id, e.item_fp): (e.count, e.flags) for e in inv.entries} == {
                    (PISTOL, AUTO_FP): (1, INV_ENTRY_EQUIPPED), (CAPS, FP_PLAIN): (300, 0)}
                # The descriptors are sent before the lines.
                types = [f.header.msg_type for f, _ in frames
                         if f.header.msg_type in (int(MessageType.INSTANCE_DEFS),
                                                  int(MessageType.PLAYER_INV))]
                assert types == [int(MessageType.INSTANCE_DEFS), int(MessageType.PLAYER_INV)]
            finally:
                sock_a.close(); sock_b.close()
        finally:
            transport.close()

    @pytest.mark.asyncio
    async def test_a_death_waits_for_the_last_capture(self):
        port = 31602
        transport, protocol_obj = await _start_server_with_state(ServerState(), port)
        try:
            server_addr, sock_a, sock_b = await _two_raw_peers(port)
            try:
                peer = f"pA_{port}"
                _cap(protocol_obj.state, peer, NEW, 3, [(CAPS, FP_PLAIN, 300)], EPOCH_NEW)
                # Died after sending capture 4, which has not arrived yet.
                req = RestoreRequestPayload(session=NEW, last_seq=4, reason=RESTORE_REASON_DEATH)
                sock_a.sendto(encode_frame(MessageType.RESTORE_REQUEST, 1, req, reliable=True),
                              server_addr)
                frames = await _collect_frames(sock_a, 0.3)
                assert _frames_of(frames, MessageType.PLAYER_INV) == []
                cap = InvStatePayload(session=NEW, seq=4, watermark=0, op_epoch=EPOCH_NEW,
                                      flags=INV_STATE_FLAG_COMPLETE, digest=1,
                                      entries=(InvStateEntry(CAPS, FP_PLAIN, 250),))
                sock_a.sendto(encode_frame(MessageType.INV_STATE, 2, cap, reliable=True),
                              server_addr)
                frames = await _collect_frames(sock_a, 0.4)
                [inv] = _frames_of(frames, MessageType.PLAYER_INV)
                assert inv.status == PLAYER_INV_RECORD and inv.record_seq == 4
                assert [(e.item_base_id, e.count) for e in inv.entries] == [(CAPS, 250)]
            finally:
                sock_a.close(); sock_b.close()
        finally:
            transport.close()

    @pytest.mark.asyncio
    async def test_a_capture_that_never_comes_is_answered_behind(self):
        port = 31603
        transport, protocol_obj = await _start_server_with_state(ServerState(), port)
        protocol_obj.RESTORE_WAIT_MS = 200.0
        try:
            server_addr, sock_a, sock_b = await _two_raw_peers(port)
            try:
                peer = f"pA_{port}"
                _cap(protocol_obj.state, peer, NEW, 3, [(CAPS, FP_PLAIN, 300)], EPOCH_NEW)
                req = RestoreRequestPayload(session=NEW, last_seq=9, reason=RESTORE_REASON_DEATH)
                sock_a.sendto(encode_frame(MessageType.RESTORE_REQUEST, 1, req, reliable=True),
                              server_addr)
                frames = await _collect_frames(sock_a, 0.8)
                [inv] = _frames_of(frames, MessageType.PLAYER_INV)
                assert inv.status == PLAYER_INV_BEHIND and inv.record_seq == 3
            finally:
                sock_a.close(); sock_b.close()
        finally:
            transport.close()

    @pytest.mark.asyncio
    async def test_restore_done_opens_the_record_to_the_new_process(self):
        port = 31604
        transport, protocol_obj = await _start_server_with_state(ServerState(), port)
        try:
            server_addr, sock_a, sock_b = await _two_raw_peers(port)
            try:
                peer = f"pA_{port}"
                _cap(protocol_obj.state, peer, OLD, 5, [(CAPS, FP_PLAIN, 300)], EPOCH_OLD)
                cap = InvStatePayload(session=NEW, seq=1, watermark=0, op_epoch=EPOCH_NEW,
                                      flags=INV_STATE_FLAG_COMPLETE, digest=1,
                                      entries=(InvStateEntry(CAPS, FP_PLAIN, 7),))
                sock_a.sendto(encode_frame(MessageType.INV_STATE, 1, cap, reliable=True),
                              server_addr)
                await _collect_frames(sock_a, 0.3)
                assert protocol_obj.state.player_inventory(peer).lines == {(CAPS, FP_PLAIN): 300}
                done = RestoreDonePayload(session=NEW, record_seq=5, outcome=RESTORE_ALIGNED,
                                          removed=0, added=0, unresolved=0, digest=2)
                sock_a.sendto(encode_frame(MessageType.RESTORE_DONE, 2, done, reliable=True),
                              server_addr)
                cap2 = InvStatePayload(session=NEW, seq=2, watermark=0, op_epoch=EPOCH_NEW,
                                       flags=INV_STATE_FLAG_COMPLETE, digest=3,
                                       entries=(InvStateEntry(CAPS, FP_PLAIN, 299),))
                sock_a.sendto(encode_frame(MessageType.INV_STATE, 3, cap2, reliable=True),
                              server_addr)
                await _collect_frames(sock_a, 0.3)
                rec = protocol_obj.state.player_inventory(peer)
                assert rec.open_session == NEW
                assert rec.lines == {(CAPS, FP_PLAIN): 299}
            finally:
                sock_a.close(); sock_b.close()
        finally:
            transport.close()

    @pytest.mark.asyncio
    async def test_a_failed_restore_keeps_the_record_closed(self):
        port = 31605
        transport, protocol_obj = await _start_server_with_state(ServerState(), port)
        try:
            server_addr, sock_a, sock_b = await _two_raw_peers(port)
            try:
                peer = f"pA_{port}"
                _cap(protocol_obj.state, peer, OLD, 5, [(CAPS, FP_PLAIN, 300)], EPOCH_OLD)
                done = RestoreDonePayload(session=NEW, record_seq=5, outcome=RESTORE_FAILED,
                                          removed=0, added=0, unresolved=1, digest=2)
                sock_a.sendto(encode_frame(MessageType.RESTORE_DONE, 1, done, reliable=True),
                              server_addr)
                await _collect_frames(sock_a, 0.3)
                assert protocol_obj.state.player_inventory(peer).open_session != NEW
            finally:
                sock_a.close(); sock_b.close()
        finally:
            transport.close()
