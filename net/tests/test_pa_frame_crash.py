"""2026-10-15: a crash or a quit inside power armour must not double the frame.

Live test of 2026-10-15 (A, kill inside wid 124): the periodic checkpoint
had them inside; the timeout gave the frame back to the world and took its
pieces out of the record; at the boot the reclaim looked for the frame by
the form id the save knows it by, but the server's record of wid 124 carried
the fid of an older announce (the copy had been ADOPTED since), so nothing
was taken back: the bootstrap placed the frame with its pieces next to the
player inside the save's copy, the restore stripped the pieces off the
copy, and the exit announced the copy as a second frame.

Now the CKPT_DONE records the frame they wear (in_pa_wid), the enter asks
for a checkpoint as the exit does, a departure keeps the frame the newest
checkpoint has them inside (they come back inside it, its pieces stay in
their record), and the boot takes a standing frame back by that wid first,
by the save's form id only when the record names none.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))   # server.auth imports net.protocol
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from protocol import (  # noqa: E402
    MessageType, decode_frame, FP_PLAIN, FP_UNKNOWN,
    INV_STATE_FLAG_COMPLETE, INV_ENTRY_EQUIPPED,
    CkptDonePayload, WorldDespawnOpPayload,
)
from server.journal import Journal  # noqa: E402
from server.persistence import load_into, snapshot  # noqa: E402
from server.state import ServerState  # noqa: E402
from test_stage3d_respawn import NOW, PEER, _server, _spawns, _wearing  # noqa: E402

FRAME = 0x2079E
OTHER_WEARER = "fw0000000000c0c"
SAVE_FRAME_FID = 0xFF00139F   # the worn frame of test_stage3d_savepos.build_save(frame=True)


def _record_with_pieces(state: ServerState) -> None:
    state.record_player_inventory(PEER, 0x1234, 1, 0, 0x12, INV_STATE_FLAG_COMPLETE, 0, (
        (0x21B3B, FP_PLAIN, 1, INV_ENTRY_EQUIPPED), (0x154AC5, 0x77, 1, INV_ENTRY_EQUIPPED),
        (0x154AC8, 0x79, 1, INV_ENTRY_EQUIPPED)), 0.0)


def _despawns(proto):
    out = []
    for addr, raw in proto.transport.sent:
        f = decode_frame(raw)
        if f.header.msg_type == MessageType.WORLD_DESPAWN_BCAST:
            out.append((addr, f.payload.wid))
    return out


def _requests(proto, session):
    out = []
    for addr, raw in proto.transport.sent:
        f = decode_frame(raw)
        if addr == session.addr and f.header.msg_type == MessageType.CKPT_REQUEST:
            out.append(f.payload)
    return out


class TestTheDeparture:
    def test_keeps_the_frame_the_newest_checkpoint_has_them_inside(self, tmp_path):
        # The booked checkpoint has them in a frame (the save says; no digest
        # flag, no wid named): the one frame they wear is that one.
        state, proto, session, store = _server(tmp_path, frame=True)
        wid, other = _wearing(state)
        state.record_presence_worn_frame(PEER, wid, NOW)
        _record_with_pieces(state)
        proto._reannounce_worn_frames(PEER, NOW + 61_000)
        assert state.world_spawns[wid].worn_by_peer_id == PEER
        assert _spawns(proto) == []
        assert state.player_inventory(PEER).lines[(0x154AC5, 0x77)] == 1
        assert state.presence(PEER).worn_frame_wid == wid

    def test_gives_the_frame_back_when_the_checkpoint_has_them_on_foot(self, tmp_path):
        state, proto, session, store = _server(tmp_path, frame=False)
        wid, other = _wearing(state)
        state.record_presence_worn_frame(PEER, wid, NOW)
        _record_with_pieces(state)
        proto._reannounce_worn_frames(PEER, NOW + 61_000)
        assert state.world_spawns[wid].worn_by_peer_id == ""
        assert [addr for addr, _ in _spawns(proto)] == [other.addr]
        assert (0x154AC5, 0x77) not in state.player_inventory(PEER).lines
        assert state.presence(PEER).worn_frame_wid == 0

    def test_gives_back_a_frame_the_checkpoint_does_not_name(self, tmp_path):
        state, proto, session, store = _server(tmp_path, frame=True)
        wid, other = _wearing(state)
        rec = state.checkpoint_to_boot(PEER)
        rec.in_pa, rec.in_pa_wid = True, wid + 100
        proto._reannounce_worn_frames(PEER, NOW + 61_000)
        assert state.world_spawns[wid].worn_by_peer_id == ""

    def test_keeps_only_the_frame_the_checkpoint_names_among_two(self, tmp_path):
        state, proto, session, store = _server(tmp_path, frame=True)
        wid, other = _wearing(state)
        st2 = state.record_world_spawn(PEER, FRAME, 0xFF001DEF, 5.0, 6.0, 7.0, 0.0, 0.0, 0.0,
                                       0xDD60, 0, 2, pieces=())
        assert state.mark_world_spawn_worn(st2.wid, PEER, NOW + 1)
        rec = state.checkpoint_to_boot(PEER)
        rec.in_pa, rec.in_pa_wid = True, wid
        proto._reannounce_worn_frames(PEER, NOW + 61_000)
        assert state.world_spawns[wid].worn_by_peer_id == PEER
        assert state.world_spawns[st2.wid].worn_by_peer_id == ""
        assert [w.wid for _, w in _spawns(proto)] == [st2.wid]

    def test_two_worn_and_none_named_gives_both_back(self, tmp_path):
        state, proto, session, store = _server(tmp_path, frame=True)
        wid, other = _wearing(state)
        st2 = state.record_world_spawn(PEER, FRAME, 0xFF001DEF, 5.0, 6.0, 7.0, 0.0, 0.0, 0.0,
                                       0xDD60, 0, 2, pieces=())
        assert state.mark_world_spawn_worn(st2.wid, PEER, NOW + 1)
        proto._reannounce_worn_frames(PEER, NOW + 61_000)
        assert state.world_spawns[wid].worn_by_peer_id == ""
        assert state.world_spawns[st2.wid].worn_by_peer_id == ""

    def test_a_death_still_leaves_the_frame_where_they_fell(self, tmp_path):
        from protocol import PlayerLifePayload
        state, proto, session, store = _server(tmp_path, frame=True)
        wid, other = _wearing(state)
        proto._handle_player_life(session, PlayerLifePayload(0, (7.0, 8.0, 9.0), 10), NOW + 60_000)
        proto._handle_player_life(session, PlayerLifePayload(1, (4.0, 5.0, 6.0), 10), NOW + 70_000)
        st = state.world_spawns[wid]
        assert st.worn_by_peer_id == "" and (st.px, st.py, st.pz) == (7.0, 8.0, 9.0)


class TestTheBoot:
    def test_takes_back_the_frame_the_checkpoint_names_whatever_its_form_id(self, tmp_path):
        state, proto, session, store = _server(tmp_path, frame=True)
        wid, other = _wearing(state)
        _record_with_pieces(state)
        rec = state.checkpoint_to_boot(PEER)
        rec.in_pa, rec.in_pa_wid = True, wid
        # Given back before this server knew better: standing, nobody's, and
        # the record without its pieces; its fid is not the save's.
        assert state.return_worn_frame(wid, 1.0, 2.0, 3.0, 0xDD60)
        state.record_pieces_to_frame(PEER, [(0x154AC5, 1), (0x154AC8, 1)], NOW)
        assert (0x154AC5, 0x77) not in state.player_inventory(PEER).lines
        proto._reclaim_frame_at_boot(PEER, rec, NOW + 70_000)
        st = state.world_spawns[wid]
        assert st.worn_by_peer_id == PEER
        assert state.presence(PEER).worn_frame_wid == wid
        assert sorted({w for _, w in _despawns(proto)}) == [wid]   # every session, this wid only
        lines = state.player_inventory(PEER).lines
        for base in {p[0] for p in st.pieces}:
            assert (base, FP_UNKNOWN) in lines

    def test_finds_the_frame_by_the_saves_form_id_when_the_record_names_none(self, tmp_path):
        state, proto, session, store = _server(tmp_path, frame=True)
        st = state.record_world_spawn(PEER, FRAME, SAVE_FRAME_FID, 1.0, 2.0, 3.0, 0.0, 0.0, 0.0,
                                      0xDD60, 0, 1, pieces=())
        rec = state.checkpoint_to_boot(PEER)
        assert rec.in_pa_wid == 0
        proto._reclaim_frame_at_boot(PEER, rec, NOW + 70_000)
        assert state.world_spawns[st.wid].worn_by_peer_id == PEER

    def test_falls_back_to_the_form_id_when_the_named_frame_is_gone(self, tmp_path):
        state, proto, session, store = _server(tmp_path, frame=True)
        st = state.record_world_spawn(PEER, FRAME, SAVE_FRAME_FID, 1.0, 2.0, 3.0, 0.0, 0.0, 0.0,
                                      0xDD60, 0, 1, pieces=())
        rec = state.checkpoint_to_boot(PEER)
        rec.in_pa, rec.in_pa_wid = True, st.wid + 500
        proto._reclaim_frame_at_boot(PEER, rec, NOW + 70_000)
        assert state.world_spawns[st.wid].worn_by_peer_id == PEER

    def test_does_nothing_when_the_named_frame_is_still_theirs(self, tmp_path):
        state, proto, session, store = _server(tmp_path, frame=True)
        wid, other = _wearing(state)
        rec = state.checkpoint_to_boot(PEER)
        rec.in_pa, rec.in_pa_wid = True, wid
        proto._reclaim_frame_at_boot(PEER, rec, NOW + 70_000)
        assert state.world_spawns[wid].worn_by_peer_id == PEER
        assert _despawns(proto) == []

    def test_leaves_a_frame_another_peer_wears(self, tmp_path):
        state, proto, session, store = _server(tmp_path, frame=True)
        wid, other = _wearing(state)
        assert state.return_worn_frame(wid, 1.0, 2.0, 3.0, 0xDD60)
        assert state.mark_world_spawn_worn(wid, OTHER_WEARER, NOW + 5)
        rec = state.checkpoint_to_boot(PEER)
        rec.in_pa, rec.in_pa_wid = True, wid
        proto._reclaim_frame_at_boot(PEER, rec, NOW + 70_000)
        assert state.world_spawns[wid].worn_by_peer_id == OTHER_WEARER
        assert _despawns(proto) == []


class TestTheEnter:
    def test_entering_a_frame_asks_for_a_checkpoint(self, tmp_path):
        state, proto, session, store = _server(tmp_path, frame=False)
        st = state.record_world_spawn(PEER, FRAME, 0xFF001DEE, 1.0, 2.0, 3.0, 0.0, 0.0, 0.0,
                                      0xDD60, 0, 1, pieces=())
        before = session.ckpt_seq
        proto._handle_world_despawn_op(
            session, WorldDespawnOpPayload(wid=st.wid, reason=2, timestamp_ms=0), NOW + 1000)
        assert state.world_spawns[st.wid].worn_by_peer_id == PEER
        assert state.presence(PEER).worn_frame_wid == st.wid
        assert session.ckpt_seq == before + 1
        reqs = _requests(proto, session)
        assert reqs and reqs[-1].reason == 1 and reqs[-1].seq == session.ckpt_seq

    def test_the_checkpoint_records_the_frame_they_wear(self, tmp_path):
        state, proto, session, store = _server(tmp_path, frame=False, pa=True)   # digest #9 in PA
        wid, other = _wearing(state)
        done = CkptDonePayload(seq=1, status=0, name=f"fwck_{PEER}_20261015_150000",
                               sha256=b"\x11" * 32, size=100, digest=0xABC, digest_seq=9,
                               wall_ms=5)
        proto._handle_ckpt_done(session, done, NOW + 2000)
        rec = state.checkpoint_to_boot(PEER)
        assert rec.name == done.name and rec.in_pa is True and rec.in_pa_wid == wid

    def test_a_checkpoint_on_foot_names_no_frame(self, tmp_path):
        state, proto, session, store = _server(tmp_path, frame=False, pa=False)
        wid, other = _wearing(state)
        done = CkptDonePayload(seq=1, status=0, name=f"fwck_{PEER}_20261015_150001",
                               sha256=b"\x12" * 32, size=100, digest=0xABC, digest_seq=9,
                               wall_ms=5)
        proto._handle_ckpt_done(session, done, NOW + 2000)
        rec = state.checkpoint_to_boot(PEER)
        assert rec.name == done.name and rec.in_pa is False and rec.in_pa_wid == 0


class TestDurability:
    def test_in_pa_wid_survives_the_snapshot_and_the_journal(self, tmp_path):
        j = Journal.open(tmp_path / "journal")
        a = ServerState()
        a.journal = j
        a.record_checkpoint(PEER, "ab" * 16, 1, "fwck_%s_1" % PEER, "cd" * 32, 9, 0, 0, 1, 1.0, 1, 0,
                            in_pa=True, in_pa_wid=7)
        j.flush()
        j.close()
        b = ServerState()
        Journal.open(tmp_path / "journal").replay(b, after_lsn=0)
        assert b.checkpoint_to_boot(PEER).in_pa_wid == 7
        path = tmp_path / "snap.json"
        snapshot(a, path)
        c = ServerState()
        load_into(c, path)
        assert c.checkpoint_to_boot(PEER).in_pa_wid == 7 and c.checkpoint_to_boot(PEER).in_pa is True
