"""L5 realtime D2 (2026-10-15) - the owner's death crates on the map.

The server counts a peer's deaths (1, 2, 3..., durable in the journal and
the snapshot, never below the ordinal of a crate of theirs still in the
world), gives the crate of the n-th death ordinal n, lists the crates still
in the world and sends them to the owner as DEATH_CRATES: after the record
(boot and death) and after one of the crates goes. The client names them
from the ordinal: the crate whose ordinal equals the count is "LATEST
DEATH", every other "CORPSE #ordinal", so a crate changes name once at most
and a death that leaves no crate still turns the last one into a corpse.
A crate of the server's with nothing in it is swept away.
"""
from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from protocol import (  # noqa: E402
    MessageType, ProtocolError, DeathCratesPayload, DeathCrateEntry, DEATH_CRATES_MAX,
    RestoreRequestPayload, RESTORE_REASON_BOOT, RESTORE_REASON_DEATH,
    ContainerOpKind, FP_PLAIN, INV_STATE_FLAG_COMPLETE, INV_ENTRY_EQUIPPED, wid_container_key,
    encode_frame, _TYPE_TO_PAYLOAD_CLS,
)
from server.journal import Journal  # noqa: E402
from server.state import ServerState  # noqa: E402
from server.persistence import snapshot, load_into  # noqa: E402
from net.tests.test_container import _collect_frames  # noqa: E402
from net.tests.test_death_crate import (  # noqa: E402
    _record, _crate, _op, _frames_of, TestServerHandlers,
    LINES, CAPS, CELL, SESSION, EPOCH, PIPBOY,
)


def _server_now(protocol_obj) -> float:
    from server.main import _now_ms
    return _now_ms()


def _record_again(state: ServerState, peer: str, seq: int):
    """A capture after a crate emptied the record: the lines are back (the
    player found them again), with a newer seq."""
    return state.record_player_inventory(peer, SESSION, seq, 0, EPOCH, INV_STATE_FLAG_COMPLETE, 0,
                                         tuple(LINES), 0.0)


def _two_crates(state: ServerState, peer: str = "alice"):
    _record(state, peer)
    first = _crate(state, peer)
    _record_again(state, peer, 2)
    second = _crate(state, peer)
    assert first is not None and second is not None
    return first, second


class TestOrdinals:
    def test_the_crates_carry_the_number_of_the_death(self):
        s = ServerState()
        (sp1, c1), (sp2, c2) = _two_crates(s)
        assert (c1.death_owner, c1.death_ordinal) == ("alice", 1)
        assert (c2.death_owner, c2.death_ordinal) == ("alice", 2)
        assert s.death_count("alice") == 2
        assert s.death_crates_of("alice") == [
            (sp1.wid, 1, 0, 10.0, 20.0, 30.0, CELL),
            (sp2.wid, 2, 0, 10.0, 20.0, 30.0, CELL),
        ]

    def test_a_death_counted_first_gives_its_crate_its_number(self):
        s = ServerState()
        _record(s)
        n = s.record_death("alice", 0.0)
        assert n == 1
        _, c = s.record_death_crate("alice", s.next_world_spawn_wid, 0x1D0FB, CELL, 10.0, 20.0, 30.0,
                                    1.5, (PIPBOY,), 0.0, death_ordinal=n)
        assert c.death_ordinal == 1 and s.death_count("alice") == 1   # not counted twice
        # a number no death had, or one a crate already carries: counted afresh
        _record_again(s, "alice", 2)
        _, c2 = s.record_death_crate("alice", s.next_world_spawn_wid, 0x1D0FB, CELL, 10.0, 20.0, 30.0,
                                     1.5, (PIPBOY,), 0.0, death_ordinal=1)
        assert c2.death_ordinal == 2 and s.death_count("alice") == 2
        _record_again(s, "alice", 3)
        _, c3 = s.record_death_crate("alice", s.next_world_spawn_wid, 0x1D0FB, CELL, 10.0, 20.0, 30.0,
                                     1.5, (PIPBOY,), 0.0, death_ordinal=9)
        assert c3.death_ordinal == 3 and s.death_count("alice") == 3

    def test_a_death_without_a_crate_still_counts(self):
        s = ServerState()
        (sp1, _), (sp2, _) = _two_crates(s)
        assert s.record_death("alice", 5.0) == 3
        assert s.death_count("alice") == 3
        assert [t[0] for t in s.death_crates_of("alice")] == [sp1.wid, sp2.wid]
        # nobody is the latest death any more: the client names both corpses
        assert all(t[1] != s.death_count("alice") for t in s.death_crates_of("alice"))
        _record_again(s, "alice", 3)
        _, c4 = _crate(s)
        assert c4.death_ordinal == 4

    def test_another_peer_counts_on_its_own(self):
        s = ServerState()
        _two_crates(s, "alice")
        _record(s, "bob")
        sp, c = _crate(s, "bob")
        assert (c.death_owner, c.death_ordinal) == ("bob", 1)
        assert s.death_count("bob") == 1
        assert [t[0] for t in s.death_crates_of("bob")] == [sp.wid]
        assert sp.wid not in [t[0] for t in s.death_crates_of("alice")]

    def test_a_crate_gone_leaves_the_list_but_not_the_count(self):
        s = ServerState()
        (sp1, _), (sp2, _) = _two_crates(s)
        assert s.remove_wid_container(sp1.wid)
        assert [t[0] for t in s.death_crates_of("alice")] == [sp2.wid]
        assert s.death_count("alice") == 2
        assert s.remove_wid_container(sp2.wid)
        assert s.death_crates_of("alice") == []
        assert s.death_count("alice") == 2   # the next death is #3, never #2 again

    def test_a_forgotten_peer_continues_above_the_crates_still_there(self):
        """The first live test: the reset of A emptied its count while two
        old crates (#4, #5) stayed in the world; the next deaths got 4 and 5
        again and two crates were the latest death at once."""
        s = ServerState()
        (sp1, c1), (sp2, c2) = _two_crates(s)
        s.forget_peer("alice")
        assert s.death_count("alice") == 2          # never below a crate still there
        _record(s, "alice")
        _, c3 = _crate(s, "alice")
        assert c3.death_ordinal == 3
        assert s.death_count("alice") == 3
        s.remove_wid_container(sp1.wid)
        s.remove_wid_container(sp2.wid)
        s.remove_wid_container(c3.wid)
        s.forget_peer("alice")
        assert s.death_count("alice") == 0          # nothing left: a fresh start
        _record(s, "alice")
        _, c = _crate(s, "alice")
        assert c.death_ordinal == 1

    def test_nothing_for_a_peer_without_crates(self):
        s = ServerState()
        assert s.death_count("nobody") == 0
        assert s.death_crates_of("nobody") == []
        assert s.record_death("", 0.0) == 0


class TestDurability:
    def test_the_journal_replays_the_deaths_and_the_ordinals(self, tmp_path: Path):
        j = Journal.open(tmp_path / "journal")
        a = ServerState()
        a.journal = j
        (sp1, _), (sp2, _) = _two_crates(a)
        a.record_death("alice", 9.0)                 # a death without a crate
        assert a.remove_wid_container(sp1.wid)
        j.flush()
        j.close()
        b = ServerState()
        Journal.open(tmp_path / "journal").replay(b, after_lsn=0)
        assert b.death_count("alice") == 3
        assert b.death_crates_of("alice") == a.death_crates_of("alice")
        c2 = b.container_state(wid_container_key(sp2.wid))
        assert (c2.death_owner, c2.death_ordinal) == ("alice", 2)

    def test_a_journal_from_before_the_count_numbers_the_crates_in_order(self, tmp_path: Path):
        """record_death_crate records alone (no record_death before them)
        still give 1, 2, 3 on replay: the crate counts the death itself."""
        j = Journal.open(tmp_path / "journal")
        a = ServerState()
        a.journal = j
        _two_crates(a)
        j.flush()
        j.close()
        b = ServerState()
        Journal.open(tmp_path / "journal").replay(b, after_lsn=0)
        assert [t[1] for t in b.death_crates_of("alice")] == [1, 2]
        assert b.death_count("alice") == 2

    def test_the_snapshot_keeps_the_count_and_the_fields(self, tmp_path: Path):
        s = ServerState()
        (sp1, _), (sp2, _) = _two_crates(s)
        s.record_death("alice", 9.0)
        path = tmp_path / "snap.json"
        snapshot(s, path)
        t = ServerState()
        load_into(t, path)
        assert t.death_count("alice") == 3
        assert t.death_crates_of("alice") == s.death_crates_of("alice")
        c1 = t.container_state(wid_container_key(sp1.wid))
        assert (c1.death_owner, c1.death_ordinal, c1.death_ms) == ("alice", 1, 0)

    def test_an_old_snapshot_without_the_fields_loads(self, tmp_path: Path):
        s = ServerState()
        _record(s)
        _crate(s)
        path = tmp_path / "snap.json"
        snapshot(s, path)
        text = path.read_text(encoding="utf-8")
        for key in ('"death_owner"', '"death_ordinal"', '"death_ms"', '"death_counts"'):
            assert key in text
        data = json.loads(text)
        data.pop("death_counts")
        for c in data["containers"]:
            for key in ("death_owner", "death_ordinal", "death_ms"):
                c.pop(key, None)
        path.write_text(json.dumps(data), encoding="utf-8")
        t = ServerState()
        load_into(t, path)
        assert t.death_count("alice") == 0
        assert t.death_crates_of("alice") == []   # not a death crate as far as the map knows


class TestPayload:
    def test_round_trip(self):
        p = DeathCratesPayload(death_count=7, crates=(
            DeathCrateEntry(wid=5, ordinal=6, age_ms=123_456, px=1.5, py=-2.5, pz=300.25,
                            cell_id=0xDD60),
            DeathCrateEntry(wid=0, ordinal=7, age_ms=0, px=0.0, py=0.0, pz=0.0,
                            cell_id=0),
        ))
        raw = p.encode()
        assert len(raw) == 8 + 2 * 32
        back = _TYPE_TO_PAYLOAD_CLS[MessageType.DEATH_CRATES].decode(raw)
        assert back == p

    def test_empty_list(self):
        p = DeathCratesPayload(death_count=3)
        back = DeathCratesPayload.decode(p.encode())
        assert back.death_count == 3 and back.crates == ()

    def test_refuses_too_many_and_truncation(self):
        many = tuple(DeathCrateEntry(i + 1, i + 1, 0, 0.0, 0.0, 0.0, 0) for i in range(DEATH_CRATES_MAX + 1))
        with pytest.raises(ProtocolError):
            DeathCratesPayload(death_count=1, crates=many).encode()
        raw = DeathCratesPayload(death_count=1, crates=many[:2]).encode()
        with pytest.raises(ProtocolError):
            DeathCratesPayload.decode(raw[:-1])
        with pytest.raises(ProtocolError):
            DeathCratesPayload.decode(raw[:4])


class TestServer:
    @pytest.mark.asyncio
    async def test_a_death_sends_the_dead_their_crate(self):
        transport, p, addr, sock_a, sock_b, peer = await TestServerHandlers._setup(31710)
        try:
            req = RestoreRequestPayload(session=SESSION, last_seq=1, reason=RESTORE_REASON_DEATH)
            sock_a.sendto(encode_frame(MessageType.RESTORE_REQUEST, 1, req, reliable=True), addr)
            fa, fb = await asyncio.gather(_collect_frames(sock_a, 0.5), _collect_frames(sock_b, 0.5))
            [dc] = _frames_of(fa, MessageType.DEATH_CRATES)
            assert dc.death_count == 1 and len(dc.crates) == 1
            [c] = dc.crates
            assert c.ordinal == 1 and (c.px, c.py, c.pz) == (10.0, 20.0, 30.0) and c.cell_id == CELL
            assert c.wid == p.state.death_crates_of(peer)[0][0]
            assert _frames_of(fb, MessageType.DEATH_CRATES) == []
        finally:
            sock_a.close(); sock_b.close(); transport.close()

    @pytest.mark.asyncio
    async def test_a_death_with_nothing_to_drop_counts_and_leaves_a_spot(self):
        only_pipboy = [(PIPBOY, FP_PLAIN, 1, INV_ENTRY_EQUIPPED)]
        transport, p, addr, sock_a, sock_b, peer = await TestServerHandlers._setup(31713, lines=only_pipboy)
        try:
            req = RestoreRequestPayload(session=SESSION, last_seq=1, reason=RESTORE_REASON_DEATH)
            sock_a.sendto(encode_frame(MessageType.RESTORE_REQUEST, 1, req, reliable=True), addr)
            fa, fb = await asyncio.gather(_collect_frames(sock_a, 0.5), _collect_frames(sock_b, 0.5))
            [dc] = _frames_of(fa, MessageType.DEATH_CRATES)
            assert dc.death_count == 1 and len(dc.crates) == 1
            [s] = dc.crates
            assert s.wid == 0 and s.ordinal == 1 and s.age_ms < 5000
            assert (s.px, s.py, s.pz, s.cell_id) == (10.0, 20.0, 30.0, CELL)
            assert p.state.death_crates_of(peer) == []
            assert _frames_of(fb, MessageType.WORLD_SPAWN_BCAST) == []
            # the spot expires with the sweep, and the owner hears
            assert p.sweep_empty_crates(_server_now(p) + p.DEATH_SPOT_TTL_MS + 1) == 0
            fa2 = await _collect_frames(sock_a, 0.5)
            [dc2] = _frames_of(fa2, MessageType.DEATH_CRATES)
            assert dc2.crates == () and dc2.death_count == 1
        finally:
            sock_a.close(); sock_b.close(); transport.close()

    @pytest.mark.asyncio
    async def test_crates_and_spots_come_oldest_first(self):
        transport, p, addr, sock_a, sock_b, peer = await TestServerHandlers._setup(31715)
        try:
            spawn, crate = _crate(p.state, peer)       # death #1, a crate
            req = RestoreRequestPayload(session=SESSION, last_seq=1, reason=RESTORE_REASON_DEATH)
            sock_a.sendto(encode_frame(MessageType.RESTORE_REQUEST, 1, req, reliable=True), addr)
            fa, fb = await asyncio.gather(_collect_frames(sock_a, 0.5), _collect_frames(sock_b, 0.5))
            [dc] = _frames_of(fa, MessageType.DEATH_CRATES)   # death #2: the record kept only the Pip-Boy
            assert dc.death_count == 2
            assert [(e.wid, e.ordinal) for e in dc.crates] == [(spawn.wid, 1), (0, 2)]
        finally:
            sock_a.close(); sock_b.close(); transport.close()

    @pytest.mark.asyncio
    async def test_a_boot_sends_the_crates_still_there(self):
        transport, p, addr, sock_a, sock_b, peer = await TestServerHandlers._setup(31711)
        try:
            spawn, crate = _crate(p.state, peer)
            req = RestoreRequestPayload(session=SESSION, last_seq=1, reason=RESTORE_REASON_BOOT)
            sock_a.sendto(encode_frame(MessageType.RESTORE_REQUEST, 1, req, reliable=True), addr)
            fa, fb = await asyncio.gather(_collect_frames(sock_a, 0.5), _collect_frames(sock_b, 0.5))
            [dc] = _frames_of(fa, MessageType.DEATH_CRATES)
            assert dc.death_count == 1 and [c.wid for c in dc.crates] == [spawn.wid]
            assert _frames_of(fb, MessageType.DEATH_CRATES) == []
        finally:
            sock_a.close(); sock_b.close(); transport.close()

    @pytest.mark.asyncio
    async def test_the_emptied_crate_leaves_the_owners_list(self):
        transport, p, addr, sock_a, sock_b, peer = await TestServerHandlers._setup(31712)
        try:
            spawn, crate = _crate(p.state, peer)
            p.state.container_state(crate.form_id).items = {(CAPS, FP_PLAIN): 300}
            op = _op(ContainerOpKind.TAKE, crate.form_id, CAPS, 300)
            sock_b.sendto(encode_frame(MessageType.CONTAINER_OP, 1, op, reliable=True), addr)
            fa, fb = await asyncio.gather(_collect_frames(sock_a, 0.5), _collect_frames(sock_b, 0.5))
            [dc] = _frames_of(fa, MessageType.DEATH_CRATES)
            assert dc.death_count == 1 and dc.crates == ()
            assert _frames_of(fb, MessageType.DEATH_CRATES) == []
            assert p.state.death_crates_of(peer) == []
        finally:
            sock_a.close(); sock_b.close(); transport.close()

    @pytest.mark.asyncio
    async def test_the_sweep_removes_an_empty_crate_for_everyone(self):
        """The first live test: crates of weeks ago, emptied before the
        answer to the last take existed, stayed on the map."""
        transport, p, addr, sock_a, sock_b, peer = await TestServerHandlers._setup(31714)
        try:
            spawn, crate = _crate(p.state, peer)
            p.state.container_state(crate.form_id).items = {}
            assert p.sweep_empty_crates(1000.0) == 1
            assert p.sweep_empty_crates(1000.0) == 0
            fa, fb = await asyncio.gather(_collect_frames(sock_a, 0.5), _collect_frames(sock_b, 0.5))
            for frames in (fa, fb):
                assert [d.wid for d in _frames_of(frames, MessageType.WORLD_DESPAWN_BCAST)] == [spawn.wid]
            [dc] = _frames_of(fa, MessageType.DEATH_CRATES)
            assert dc.death_count == 1 and dc.crates == ()
            assert p.state.death_crates_of(peer) == [] and spawn.wid not in p.state.world_spawns
        finally:
            sock_a.close(); sock_b.close(); transport.close()
