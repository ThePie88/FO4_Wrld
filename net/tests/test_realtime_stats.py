"""L5 realtime persistence, slice R4 (2026-10-03): the character's numbers
on the server.

Every death reloads the last checkpoint, so before R4 the XP, the levels and
the perks earned since it were lost at every death (and at a crash). The
client now captures XP, level, perk points, the SPECIAL base values, health,
action points, rads and the perks it holds (STATS_STATE, at every change);
the server keeps them next to the inventory record, behind the same gate of
process, and the restore answer carries them back (PLAYER_STATS).
"""
from __future__ import annotations

import json
import math
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from protocol import (  # noqa: E402
    MessageType, ProtocolError,
    PerkEntry, PlayerStatsPayload, STATS_FLAG_COMPLETE,
    RestoreRequestPayload, RESTORE_REASON_BOOT, RESTORE_REASON_DEATH,
    PLAYER_INV_RECORD, PLAYER_INV_NONE, INV_STATE_FLAG_COMPLETE,
    InvStateEntry, InvStatePayload, FP_PLAIN,
    encode_frame, decode_frame,
)
from server.journal import Journal  # noqa: E402
from server.state import ServerState  # noqa: E402
from server.validator import validate_stats_state, RejectReason  # noqa: E402
from server.persistence import snapshot, load_into, SNAPSHOT_FORMAT_VERSION  # noqa: E402
from net.tests.test_container import _start_server_with_state, _collect_frames  # noqa: E402
from net.tests.test_container_reconverge import _two_raw_peers  # noqa: E402

OLD = 0x11110001
NEW = 0x22220001
SPECIAL = (5.0, 4.0, 3.0, 6.0, 7.0, 2.0, 1.0)
GUNSLINGER1 = 0x0004A0E3
GUNSLINGER2 = 0x0004A0E4
BOBBLE_STR = 0x001AB2E1


def _stats(state: ServerState, peer: str, session: int, seq: int, *, xp: float = 1200.0,
           level: int = 7, points: int = 1, special=SPECIAL, perks=None, health: float = 180.0):
    perks = perks if perks is not None else ((GUNSLINGER1, 1), (GUNSLINGER2, 1))
    return state.record_player_stats(peer, session, seq, level, xp, points, tuple(special),
                                     health, 90.0, 12.0, tuple(perks), 0.0)


def _cap(state: ServerState, peer: str, session: int, seq: int, epoch: int = 0x2222):
    return state.record_player_inventory(peer, session, seq, 0, epoch, INV_STATE_FLAG_COMPLETE,
                                         0, ((0xF, FP_PLAIN, 10, 0),), 0.0)


# ------------------------------------------------------------------- wire

class TestWire:
    def _p(self, **kw):
        base = dict(session=NEW, seq=3, status=0, flags=STATS_FLAG_COMPLETE, level=7, xp=1234.5,
                    perk_points=2, special=SPECIAL, health=180.0, action_points=90.0, rads=12.0,
                    perks=(PerkEntry(GUNSLINGER1, 1), PerkEntry(BOBBLE_STR, 1)))
        base.update(kw)
        return PlayerStatsPayload(**base)

    def test_stats_state_roundtrip(self):
        p = self._p()
        f = decode_frame(encode_frame(MessageType.STATS_STATE, 1, p, reliable=True))
        assert f.payload == p

    def test_player_stats_roundtrip(self):
        p = self._p(status=PLAYER_INV_RECORD, flags=0)
        f = decode_frame(encode_frame(MessageType.PLAYER_STATS, 1, p, reliable=True))
        assert f.payload == p

    def test_one_frame_carries_267_perks(self):
        assert PlayerStatsPayload.MAX_PERKS_PER_FRAME == 267
        full = self._p(perks=tuple(PerkEntry(i + 1, 1) for i in range(267)))
        assert len(full.encode()) <= 1400
        with pytest.raises(ProtocolError):
            self._p(perks=tuple(PerkEntry(i + 1, 1) for i in range(268))).encode()

    def test_special_has_seven_values(self):
        with pytest.raises(ProtocolError):
            self._p(special=(1.0, 2.0)).encode()

    def test_restore_request_names_the_last_stats_capture(self):
        p = RestoreRequestPayload(session=NEW, last_seq=7, reason=RESTORE_REASON_DEATH,
                                  last_stats_seq=4)
        assert len(p.encode()) == 16
        f = decode_frame(encode_frame(MessageType.RESTORE_REQUEST, 1, p, reliable=True))
        assert f.payload == p


# ------------------------------------------------------------------- state

class TestRecord:
    def test_a_capture_is_the_record(self):
        s = ServerState()
        rec = _stats(s, "alice", NEW, 1)
        assert rec is not None
        assert (rec.level, rec.xp, rec.perk_points) == (7, 1200.0, 1)
        assert rec.special == SPECIAL
        assert rec.perks == {GUNSLINGER1: 1, GUNSLINGER2: 1}

    def test_a_stale_capture_is_ignored(self):
        s = ServerState()
        _stats(s, "alice", NEW, 5, xp=2000.0)
        assert _stats(s, "alice", NEW, 4, xp=1.0) is None
        assert s.player_stats("alice").xp == 2000.0

    def test_invalid_captures_are_refused(self):
        s = ServerState()
        assert _stats(s, "alice", 0, 1) is None
        assert _stats(s, "alice", NEW, 1, xp=math.nan) is None
        assert _stats(s, "alice", NEW, 1, special=(1.0,) * 6) is None
        assert _stats(s, "alice", NEW, 1, perks=((0, 1),)) is None
        assert _stats(s, "alice", NEW, 1, perks=((GUNSLINGER1, 0),)) is None
        assert s.player_stats("alice") is None

    def test_a_new_process_waits_for_its_restore(self):
        s = ServerState()
        _cap(s, "alice", OLD, 3)
        _stats(s, "alice", OLD, 3, xp=5000.0)
        assert _stats(s, "alice", NEW, 1, xp=100.0) is None
        s.record_player_restored("alice", NEW, 0.0)
        assert _stats(s, "alice", NEW, 1, xp=5100.0).xp == 5100.0


class TestDurability:
    def test_the_journal_replays_the_stats(self, tmp_path: Path):
        j = Journal.open(tmp_path / "journal")
        a = ServerState()
        a.journal = j
        _stats(a, "alice", NEW, 1)
        _stats(a, "alice", NEW, 2, xp=1500.0, level=8, perks=((GUNSLINGER1, 1),))
        j.flush()
        j.close()
        b = ServerState()
        Journal.open(tmp_path / "journal").replay(b, after_lsn=0)
        rec = b.player_stats("alice")
        assert (rec.seq, rec.xp, rec.level) == (2, 1500.0, 8)
        assert rec.perks == {GUNSLINGER1: 1}

    def test_snapshot_roundtrip(self, tmp_path: Path):
        s = ServerState()
        _stats(s, "alice", NEW, 4)
        path = tmp_path / "snap.json"
        snapshot(s, path)
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data["version"] == SNAPSHOT_FORMAT_VERSION == 15   # v15: partial-record ops, checkpoint world, world base per peer (2026-10-20)
        t = ServerState()
        load_into(t, path)
        rec = t.player_stats("alice")
        assert (rec.session, rec.seq, rec.level, rec.xp) == (NEW, 4, 7, 1200.0)
        assert rec.special == SPECIAL and rec.perks == {GUNSLINGER1: 1, GUNSLINGER2: 1}

    def test_a_v12_snapshot_loads_with_no_stats(self, tmp_path: Path):
        s = ServerState()
        _stats(s, "alice", NEW, 4)
        path = tmp_path / "snap.json"
        snapshot(s, path)
        data = json.loads(path.read_text(encoding="utf-8"))
        data["version"] = 12
        data.pop("player_stats", None)
        path.write_text(json.dumps(data), encoding="utf-8")
        t = ServerState()
        load_into(t, path)
        assert t.player_stats("alice") is None


class TestValidator:
    def test_good_and_bad_chunks(self):
        good = PlayerStatsPayload(session=NEW, seq=1, status=0, flags=STATS_FLAG_COMPLETE,
                                  level=1, xp=0.0, perk_points=0, special=SPECIAL, health=100.0,
                                  action_points=80.0, rads=0.0, perks=())
        assert validate_stats_state(good).ok
        import dataclasses
        for change in ({"flags": 0}, {"session": 0}, {"xp": math.inf},
                       {"perks": (PerkEntry(0, 1),)}, {"perks": (PerkEntry(5, 0),)},
                       {"chunk_index": 1, "total_chunks": 1}):
            r = validate_stats_state(dataclasses.replace(good, **change))
            assert not r.ok and r.reason == RejectReason.STATS_STATE_INVALID


# ------------------------------------------------------------- the server

def _frames_of(frames, mtype):
    return [f.payload for f, _ in frames if f.header.msg_type == int(mtype)]


class TestServerHandlers:
    @pytest.mark.asyncio
    async def test_stats_in_two_chunks_become_the_record(self):
        port = 31610
        transport, protocol_obj = await _start_server_with_state(ServerState(), port)
        try:
            server_addr, sock_a, sock_b = await _two_raw_peers(port)
            try:
                perks = tuple(PerkEntry(0x1000 + i, 1) for i in range(300))
                per = PlayerStatsPayload.MAX_PERKS_PER_FRAME
                chunks = [PlayerStatsPayload(
                    session=NEW, seq=1, status=0, flags=STATS_FLAG_COMPLETE, level=9, xp=3000.0,
                    perk_points=2, special=SPECIAL, health=200.0, action_points=95.0, rads=0.0,
                    perks=perks[i * per:(i + 1) * per], chunk_index=i, total_chunks=2)
                    for i in range(2)]
                for n, c in enumerate(reversed(chunks)):
                    sock_a.sendto(encode_frame(MessageType.STATS_STATE, n + 1, c, reliable=True),
                                  server_addr)
                await _collect_frames(sock_a, 0.3)
                rec = protocol_obj.state.player_stats(f"pA_{port}")
                assert rec is not None and len(rec.perks) == 300 and rec.level == 9
            finally:
                sock_a.close(); sock_b.close()
        finally:
            transport.close()

    @pytest.mark.asyncio
    async def test_the_restore_answer_carries_the_stats(self):
        port = 31611
        transport, protocol_obj = await _start_server_with_state(ServerState(), port)
        try:
            server_addr, sock_a, sock_b = await _two_raw_peers(port)
            try:
                peer = f"pA_{port}"
                _cap(protocol_obj.state, peer, OLD, 3, epoch=0x1111)
                _stats(protocol_obj.state, peer, OLD, 2, xp=4321.0, level=12, points=3)
                req = RestoreRequestPayload(session=NEW, last_seq=0, reason=RESTORE_REASON_BOOT)
                sock_a.sendto(encode_frame(MessageType.RESTORE_REQUEST, 1, req, reliable=True),
                              server_addr)
                frames = await _collect_frames(sock_a, 0.4)
                [stats] = _frames_of(frames, MessageType.PLAYER_STATS)
                assert stats.status == PLAYER_INV_RECORD and stats.session == NEW
                assert (stats.xp, stats.level, stats.perk_points) == (4321.0, 12, 3)
                assert {(p.perk_form_id, p.rank) for p in stats.perks} == {
                    (GUNSLINGER1, 1), (GUNSLINGER2, 1)}
                types = [f.header.msg_type for f, _ in frames
                         if f.header.msg_type in (int(MessageType.PLAYER_INV),
                                                  int(MessageType.PLAYER_STATS))]
                assert types == [int(MessageType.PLAYER_STATS), int(MessageType.PLAYER_INV)]
            finally:
                sock_a.close(); sock_b.close()
        finally:
            transport.close()

    @pytest.mark.asyncio
    async def test_no_stats_answers_none(self):
        port = 31612
        transport, protocol_obj = await _start_server_with_state(ServerState(), port)
        try:
            server_addr, sock_a, sock_b = await _two_raw_peers(port)
            try:
                _cap(protocol_obj.state, f"pA_{port}", OLD, 3, epoch=0x1111)
                req = RestoreRequestPayload(session=NEW, last_seq=0, reason=RESTORE_REASON_BOOT)
                sock_a.sendto(encode_frame(MessageType.RESTORE_REQUEST, 1, req, reliable=True),
                              server_addr)
                frames = await _collect_frames(sock_a, 0.4)
                [stats] = _frames_of(frames, MessageType.PLAYER_STATS)
                assert stats.status == PLAYER_INV_NONE and stats.perks == ()
            finally:
                sock_a.close(); sock_b.close()
        finally:
            transport.close()

    @pytest.mark.asyncio
    async def test_a_death_waits_for_the_last_stats_capture(self):
        port = 31613
        transport, protocol_obj = await _start_server_with_state(ServerState(), port)
        try:
            server_addr, sock_a, sock_b = await _two_raw_peers(port)
            try:
                peer = f"pA_{port}"
                _cap(protocol_obj.state, peer, NEW, 3)
                _stats(protocol_obj.state, peer, NEW, 6, xp=100.0)
                req = RestoreRequestPayload(session=NEW, last_seq=3, reason=RESTORE_REASON_DEATH,
                                            last_stats_seq=7)
                sock_a.sendto(encode_frame(MessageType.RESTORE_REQUEST, 1, req, reliable=True),
                              server_addr)
                frames = await _collect_frames(sock_a, 0.3)
                assert _frames_of(frames, MessageType.PLAYER_STATS) == []
                st = PlayerStatsPayload(session=NEW, seq=7, status=0, flags=STATS_FLAG_COMPLETE,
                                        level=8, xp=900.0, perk_points=1, special=SPECIAL,
                                        health=100.0, action_points=80.0, rads=0.0, perks=())
                sock_a.sendto(encode_frame(MessageType.STATS_STATE, 2, st, reliable=True),
                              server_addr)
                frames = await _collect_frames(sock_a, 0.4)
                [stats] = _frames_of(frames, MessageType.PLAYER_STATS)
                assert stats.xp == 900.0 and stats.seq == 7
            finally:
                sock_a.close(); sock_b.close()
        finally:
            transport.close()
