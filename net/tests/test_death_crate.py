"""L5 realtime persistence, slice D1 (2026-10-03): the death crate.

The owner's decision of 2026-10-03: at a death the WHOLE inventory (junk,
clothes, weapons, what is worn) goes into a crate at the death point and the
character respawns naked. The Pip-Boy stays: it is an inventory item, and
without it the game cannot open its menu.

The crate is an object of the server's (a world spawn with a wid, placed by
every client) whose content travels by the ordinary container protocol under
the key 0xFF000000 | wid: the server never accepted a 0xFF id as a container
before (runtime refs alias across processes), so on the wire such a key can
only name a container of the server's. The move from the player's record to
the crate is one journal record: a crash of the server never leaves it half
done. The crate disappears when it is emptied.
"""
from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from protocol import (  # noqa: E402
    MessageType, PosStatePayload,
    ContainerOpPayload, ContainerOpKind, ContainerOpAckStatus,
    InstanceDescriptor, INSTANCE_FLAG_OIE, FP_PLAIN, FP_UNKNOWN, instance_fp,
    INV_STATE_FLAG_COMPLETE, INV_ENTRY_EQUIPPED,
    RestoreRequestPayload, RESTORE_REASON_DEATH, PLAYER_INV_RECORD,
    WORLD_SPAWN_FLAG_CONTAINER, wid_container_key, is_wid_container_key,
    WorldDespawnOpPayload, WorldSpawnOpPayload, PlayerLifePayload,
    encode_frame,
)
from server.journal import Journal  # noqa: E402
from server.state import ServerState, PeerSession, SessionState  # noqa: E402
from server.validator import validate_container_op, RejectReason  # noqa: E402
from server.persistence import snapshot, load_into  # noqa: E402
from net.tests.test_container import _start_server_with_state, _collect_frames  # noqa: E402
from net.tests.test_container_reconverge import _two_raw_peers  # noqa: E402

PIPBOY = 0x00021B3B
VAULT_SUIT = 0x0001EED7
PISTOL = 0x4822
STIMPAK = 0x23736
CAPS = 0xF
CRATE_BASE = 0x1D0FB   # the default: an empty footlocker (server/main.py)
CELL = 0xDD60
SESSION = 0x33330001
EPOCH = 0x3333

AUTO_PISTOL = InstanceDescriptor(
    template=4, flags=INSTANCE_FLAG_OIE,
    mods=((0x100E2E, 0, 1), (0x231AB, 0, 1), (0x100E27, 0, 1),
          (0x91FC2, 0, 1), (0x148409, 0, 1), (0x4F21D, 0, 1)))
AUTO_FP = instance_fp(PISTOL, AUTO_PISTOL)

LINES = [(PIPBOY, FP_PLAIN, 1, INV_ENTRY_EQUIPPED), (VAULT_SUIT, FP_PLAIN, 1, INV_ENTRY_EQUIPPED),
         (PISTOL, AUTO_FP, 1, INV_ENTRY_EQUIPPED), (STIMPAK, FP_PLAIN, 4, 0), (CAPS, FP_PLAIN, 300, 0)]


def _record(state: ServerState, peer: str = "alice", lines=LINES):
    return state.record_player_inventory(peer, SESSION, 1, 0, EPOCH, INV_STATE_FLAG_COMPLETE, 0,
                                         tuple(lines), 0.0)


def _crate(state: ServerState, peer: str = "alice"):
    wid = state.next_world_spawn_wid
    return state.record_death_crate(peer, wid, CRATE_BASE, CELL, 10.0, 20.0, 30.0, 1.5,
                                    (PIPBOY,), 0.0)


def _session(peer_id: str = "bob") -> PeerSession:
    return PeerSession(session_id=2, peer_id=peer_id, addr=("1.2.3.4", 5001),
                       client_version=(1, 0), state=SessionState.ACTIVE,
                       joined_at_ms=0.0, last_seen_ms=0.0)


def _op(kind, key: int, item: int, count: int, desc=None, op_id: int = 0x44440001,
        base: int = CRATE_BASE, cell: int = 0x1234) -> ContainerOpPayload:
    d = desc if desc is not None else InstanceDescriptor()
    return ContainerOpPayload(kind=int(kind), container_base_id=base, container_cell_id=cell,
                              item_base_id=item, count=count, timestamp_ms=0, client_op_id=op_id,
                              container_form_id=key, item_fp=instance_fp(item, d), instance=d)


class TestKey:
    def test_the_key_of_a_wid(self):
        assert wid_container_key(42) == 0xFF00002A
        assert is_wid_container_key(0xFF00002A)
        assert not is_wid_container_key(0x000AE137)


class TestTheMove:
    def test_everything_but_the_pipboy_goes_into_the_crate(self):
        s = ServerState()
        _record(s)
        spawn, crate = _crate(s)
        assert spawn.flags & WORLD_SPAWN_FLAG_CONTAINER and spawn.spawner_peer == ""
        assert (spawn.base_form_id, spawn.cell_id) == (CRATE_BASE, CELL)
        assert crate.form_id == wid_container_key(spawn.wid) and crate.wid == spawn.wid
        assert crate.seeded and crate.base_id == CRATE_BASE
        assert crate.items == {(VAULT_SUIT, FP_PLAIN): 1, (PISTOL, AUTO_FP): 1,
                               (STIMPAK, FP_PLAIN): 4, (CAPS, FP_PLAIN): 300}
        rec = s.player_inventory("alice")
        assert rec.lines == {(PIPBOY, FP_PLAIN): 1}
        assert rec.equipped == {(PIPBOY, FP_PLAIN)}
        assert rec.pending == []
        assert s.next_world_spawn_wid == spawn.wid + 1

    def test_nothing_to_move_makes_no_crate(self):
        s = ServerState()
        _record(s, lines=[(PIPBOY, FP_PLAIN, 1, INV_ENTRY_EQUIPPED)])
        assert _crate(s) is None
        assert s.world_spawns == {}
        assert s.player_inventory("alice").lines == {(PIPBOY, FP_PLAIN): 1}

    def test_no_record_makes_no_crate(self):
        s = ServerState()
        assert _crate(s) is None

    def test_the_journal_replays_the_move_whole(self, tmp_path: Path):
        j = Journal.open(tmp_path / "journal")
        a = ServerState()
        a.journal = j
        _record(a)
        spawn, _ = _crate(a)
        j.flush()
        j.close()
        b = ServerState()
        Journal.open(tmp_path / "journal").replay(b, after_lsn=0)
        assert b.world_spawns[spawn.wid].flags & WORLD_SPAWN_FLAG_CONTAINER
        assert b.container_state(wid_container_key(spawn.wid)).items[(CAPS, FP_PLAIN)] == 300
        assert b.player_inventory("alice").lines == {(PIPBOY, FP_PLAIN): 1}
        assert b.next_world_spawn_wid == spawn.wid + 1

    def test_a_restart_never_mints_the_wid_of_a_crate_that_is_gone(self, tmp_path: Path):
        # An emptied crate is usually the newest world object. The snapshot
        # kept no counter and a restart derived it from the objects left, so
        # the next object got the wid (and the container key) of the crate.
        s = ServerState()
        _record(s)
        spawn, _ = _crate(s)
        assert s.remove_wid_container(spawn.wid)
        path = tmp_path / "snap.json"
        snapshot(s, path)
        t = ServerState()
        load_into(t, path)
        assert t.next_world_spawn_wid == spawn.wid + 1

    def test_snapshot_keeps_the_crate(self, tmp_path: Path):
        s = ServerState()
        _record(s)
        spawn, _ = _crate(s)
        path = tmp_path / "snap.json"
        snapshot(s, path)
        t = ServerState()
        load_into(t, path)
        crate = t.container_state(wid_container_key(spawn.wid))
        assert crate is not None and crate.wid == spawn.wid and crate.seeded
        assert crate.items[(PISTOL, AUTO_FP)] == 1
        assert spawn.wid in t.world_spawns


class TestOpsOnTheCrate:
    def test_anyone_takes_from_it_and_the_item_reaches_their_record(self):
        s = ServerState()
        _record(s)
        spawn, crate = _crate(s)
        op = _op(ContainerOpKind.TAKE, crate.form_id, PISTOL, 1, AUTO_PISTOL)
        r = validate_container_op(_session(), op, crate, 0.0)
        assert r.ok, r
        assert s.record_container_op(op, "bob", 0.0) is not None
        assert (PISTOL, AUTO_FP) not in s.container_state(crate.form_id).items
        assert s.player_inventory("bob").lines == {(PISTOL, AUTO_FP): 1}

    def test_a_ff_key_without_a_crate_is_still_a_runtime_ref(self):
        s = ServerState()
        op = _op(ContainerOpKind.TAKE, 0xFF000077, STIMPAK, 1)
        r = validate_container_op(_session(), op, None, 0.0)
        assert not r.ok and r.reason == RejectReason.RUNTIME_REF
        assert s.record_container_op(op, "bob", 0.0) is None

    def test_the_base_must_match_the_cell_need_not(self):
        s = ServerState()
        _record(s)
        _, crate = _crate(s)
        wrong_base = _op(ContainerOpKind.TAKE, crate.form_id, STIMPAK, 1, base=0x777)
        r = validate_container_op(_session(), wrong_base, crate, 0.0)
        assert not r.ok and r.reason == RejectReason.IDENTITY_MISMATCH
        other_cell = _op(ContainerOpKind.TAKE, crate.form_id, STIMPAK, 1, cell=0x9999)
        assert validate_container_op(_session(), other_cell, crate, 0.0).ok

    def test_removing_the_crate_takes_its_object_and_its_record_together(self, tmp_path: Path):
        j = Journal.open(tmp_path / "journal")
        a = ServerState()
        a.journal = j
        _record(a)
        spawn, crate = _crate(a)
        assert a.remove_wid_container(spawn.wid)
        assert spawn.wid not in a.world_spawns and a.container_state(crate.form_id) is None
        j.flush()
        j.close()
        b = ServerState()
        Journal.open(tmp_path / "journal").replay(b, after_lsn=0)
        assert spawn.wid not in b.world_spawns and b.container_state(crate.form_id) is None


def _frames_of(frames, mtype):
    return [f.payload for f, _ in frames if f.header.msg_type == int(mtype)]


class TestServerHandlers:
    @staticmethod
    async def _setup(port: int, base: int = CRATE_BASE, pos: bool = True, lines=LINES):
        state = ServerState()
        transport, protocol_obj = await _start_server_with_state(state, port)
        protocol_obj.death_crate_base = base
        server_addr, sock_a, sock_b = await _two_raw_peers(port)
        peer = f"pA_{port}"
        _record(protocol_obj.state, peer, lines=lines)
        if pos:
            protocol_obj.state.record_presence_pos(
                peer, PosStatePayload(x=10.0, y=20.0, z=30.0, rx=0.0, ry=0.0, rz=1.5,
                                      timestamp_ms=0, cell_id=CELL), 0.0)
        return transport, protocol_obj, server_addr, sock_a, sock_b, peer

    @pytest.mark.asyncio
    async def test_a_death_makes_the_crate_for_everyone_and_leaves_the_pipboy(self):
        transport, p, addr, sock_a, sock_b, peer = await self._setup(31620)
        try:
            req = RestoreRequestPayload(session=SESSION, last_seq=1, reason=RESTORE_REASON_DEATH)
            sock_a.sendto(encode_frame(MessageType.RESTORE_REQUEST, 1, req, reliable=True), addr)
            fa, fb = await asyncio.gather(_collect_frames(sock_a, 0.5), _collect_frames(sock_b, 0.5))
            for frames in (fa, fb):
                [sp] = [s for s in _frames_of(frames, MessageType.WORLD_SPAWN_BCAST)
                        if s.flags & WORLD_SPAWN_FLAG_CONTAINER]
                assert sp.base_form_id == CRATE_BASE and (sp.px, sp.py, sp.pz) == (10.0, 20.0, 30.0)
                key = wid_container_key(sp.wid)
                lines = {(e.item_base_id, e.item_fp): e.count
                         for c in _frames_of(frames, MessageType.CONTAINER_STATE)
                         for e in c.entries if e.container_form_id == key}
                assert lines[(CAPS, FP_PLAIN)] == 300 and lines[(PISTOL, AUTO_FP)] == 1
                assert (PIPBOY, FP_PLAIN) not in lines
            [inv] = _frames_of(fa, MessageType.PLAYER_INV)
            assert inv.status == PLAYER_INV_RECORD
            assert [(e.item_base_id, e.count) for e in inv.entries] == [(PIPBOY, 1)]
        finally:
            sock_a.close(); sock_b.close(); transport.close()

    @pytest.mark.asyncio
    async def test_the_last_take_empties_the_crate_and_it_disappears(self):
        transport, p, addr, sock_a, sock_b, peer = await self._setup(31621)
        try:
            spawn, crate = _crate(p.state, peer)
            p.state.container_state(crate.form_id).items = {(CAPS, FP_PLAIN): 300}
            op = _op(ContainerOpKind.TAKE, crate.form_id, CAPS, 300)
            sock_b.sendto(encode_frame(MessageType.CONTAINER_OP, 1, op, reliable=True), addr)
            fa, fb = await asyncio.gather(_collect_frames(sock_a, 0.5), _collect_frames(sock_b, 0.5))
            [ack] = _frames_of(fb, MessageType.CONTAINER_OP_ACK)
            assert ack.status == int(ContainerOpAckStatus.ACCEPTED)
            for frames in (fa, fb):
                assert [d.wid for d in _frames_of(frames, MessageType.WORLD_DESPAWN_BCAST)] == [spawn.wid]
            assert spawn.wid not in p.state.world_spawns
            assert p.state.container_state(crate.form_id) is None
        finally:
            sock_a.close(); sock_b.close(); transport.close()

    @pytest.mark.asyncio
    async def test_no_crate_base_keeps_the_inventory(self):
        transport, p, addr, sock_a, sock_b, peer = await self._setup(31622, base=0)
        try:
            req = RestoreRequestPayload(session=SESSION, last_seq=1, reason=RESTORE_REASON_DEATH)
            sock_a.sendto(encode_frame(MessageType.RESTORE_REQUEST, 1, req, reliable=True), addr)
            fa = await _collect_frames(sock_a, 0.4)
            assert not any(s.flags & WORLD_SPAWN_FLAG_CONTAINER
                           for s in _frames_of(fa, MessageType.WORLD_SPAWN_BCAST))
            [inv] = _frames_of(fa, MessageType.PLAYER_INV)
            assert len(inv.entries) == len(LINES)
        finally:
            sock_a.close(); sock_b.close(); transport.close()

    @pytest.mark.asyncio
    async def test_no_known_position_keeps_the_inventory(self):
        transport, p, addr, sock_a, sock_b, peer = await self._setup(31623, pos=False)
        try:
            req = RestoreRequestPayload(session=SESSION, last_seq=1, reason=RESTORE_REASON_DEATH)
            sock_a.sendto(encode_frame(MessageType.RESTORE_REQUEST, 1, req, reliable=True), addr)
            fa = await _collect_frames(sock_a, 0.4)
            [inv] = _frames_of(fa, MessageType.PLAYER_INV)
            assert len(inv.entries) == len(LINES)
            assert p.state.world_spawns == {}
        finally:
            sock_a.close(); sock_b.close(); transport.close()

    @pytest.mark.asyncio
    async def test_a_client_cannot_end_a_crate(self):
        transport, p, addr, sock_a, sock_b, peer = await self._setup(31624)
        try:
            spawn, crate = _crate(p.state, peer)
            op = WorldDespawnOpPayload(wid=spawn.wid, reason=3, timestamp_ms=0)
            sock_b.sendto(encode_frame(MessageType.WORLD_DESPAWN_OP, 1, op, reliable=True), addr)
            fa, fb = await asyncio.gather(_collect_frames(sock_a, 0.4), _collect_frames(sock_b, 0.4))
            assert _frames_of(fa, MessageType.WORLD_DESPAWN_BCAST) == []
            assert spawn.wid in p.state.world_spawns
            assert p.state.container_state(crate.form_id) is not None
        finally:
            sock_a.close(); sock_b.close(); transport.close()

    @pytest.mark.asyncio
    async def test_a_client_cannot_claim_the_crate_flag(self):
        # Only the server makes a crate: a client's spawn that says it is one
        # would be an object no client may ever end.
        transport, p, addr, sock_a, sock_b, peer = await self._setup(31625)
        try:
            op = WorldSpawnOpPayload(base_form_id=CRATE_BASE, local_form_id=0xFF000123,
                                     px=1.0, py=2.0, pz=3.0, rx=0.0, ry=0.0, rz=0.0,
                                     cell_id=CELL, flags=WORLD_SPAWN_FLAG_CONTAINER | 2,
                                     timestamp_ms=0)
            sock_b.sendto(encode_frame(MessageType.WORLD_SPAWN_OP, 1, op, reliable=True), addr)
            fa = await _collect_frames(sock_a, 0.4)
            [sp] = _frames_of(fa, MessageType.WORLD_SPAWN_BCAST)
            assert sp.flags == 2
            assert p.state.world_spawns[sp.wid].flags == 2
        finally:
            sock_a.close(); sock_b.close(); transport.close()


    @pytest.mark.asyncio
    async def test_the_crate_stands_where_the_death_was_not_where_the_reload_put_them(self):
        # A death request that waits for its last capture is answered up to
        # RESTORE_WAIT_MS later, and by then the reload of the death may have
        # put the player on the respawn point: the crate takes the position
        # the server had when the request arrived, the death's.
        transport, p, addr, sock_a, sock_b, peer = await self._setup(31626)
        p.RESTORE_WAIT_MS = 300
        try:
            req = RestoreRequestPayload(session=SESSION, last_seq=2, reason=RESTORE_REASON_DEATH)
            sock_a.sendto(encode_frame(MessageType.RESTORE_REQUEST, 1, req, reliable=True), addr)
            await asyncio.sleep(0.1)
            p.state.record_presence_pos(
                peer, PosStatePayload(x=999.0, y=999.0, z=999.0, rx=0.0, ry=0.0, rz=0.0,
                                      timestamp_ms=0, cell_id=0x4444), 0.0)
            fa = await _collect_frames(sock_a, 1.0)
            [sp] = [s for s in _frames_of(fa, MessageType.WORLD_SPAWN_BCAST)
                    if s.flags & WORLD_SPAWN_FLAG_CONTAINER]
            assert (sp.px, sp.py, sp.pz, sp.cell_id) == (10.0, 20.0, 30.0, CELL)
        finally:
            sock_a.close(); sock_b.close(); transport.close()


# L5 realtime D1 (2026-10-04, the owner's rule): a death in power armour
# leaves the frame where they fell, COMPLETE, next to the crate; the player
# comes back on foot. What is mounted on the frame (its piece ledger) and the
# wearable the engine equips on entering are the frame's: not in the crate,
# not kept on the player. A spare of the same base in the backpack is loot.
PA_FRAME_WEARABLE = 0x3E577
LEFT_ARM, RIGHT_ARM = 0x154AC5, 0x154AC8
LEDGER = ((LEFT_ARM, 1, (0x1681EA, 0x1834D8), 0.926), (RIGHT_ARM, 1, (0x1681E9,), 0.917))
FRAME_ITEMS = ((LEFT_ARM, 1), (RIGHT_ARM, 1), (PA_FRAME_WEARABLE, 1))
LINES_IN_PA = [(PIPBOY, FP_PLAIN, 1, INV_ENTRY_EQUIPPED), (CAPS, FP_PLAIN, 300, 0),
               (LEFT_ARM, 0x77, 1, INV_ENTRY_EQUIPPED), (LEFT_ARM, 0x78, 1, 0),   # mounted, a spare
               (RIGHT_ARM, 0x79, 1, INV_ENTRY_EQUIPPED), (PA_FRAME_WEARABLE, FP_PLAIN, 1, INV_ENTRY_EQUIPPED)]


class TestDeathInPowerArmour:
    def test_what_is_mounted_on_the_frame_is_not_in_the_crate(self):
        s = ServerState()
        _record(s, lines=LINES_IN_PA)
        spawn, crate = s.record_death_crate("alice", s.next_world_spawn_wid, CRATE_BASE, CELL,
                                            10.0, 20.0, 30.0, 1.5, (PIPBOY,), 0.0,
                                            frame_pieces=FRAME_ITEMS)
        assert crate.items == {(CAPS, FP_PLAIN): 300, (LEFT_ARM, 0x78): 1}
        rec = s.player_inventory("alice")
        assert rec.lines == {(PIPBOY, FP_PLAIN): 1} and rec.equipped == {(PIPBOY, FP_PLAIN)}

    def test_only_the_frame_and_the_pipboy_makes_no_crate_but_the_record_still_empties(self):
        s = ServerState()
        _record(s, lines=[(PIPBOY, FP_PLAIN, 1, INV_ENTRY_EQUIPPED),
                          (LEFT_ARM, 0x77, 1, INV_ENTRY_EQUIPPED),
                          (PA_FRAME_WEARABLE, FP_PLAIN, 1, INV_ENTRY_EQUIPPED)])
        assert s.record_death_crate("alice", s.next_world_spawn_wid, CRATE_BASE, CELL, 10.0, 20.0,
                                    30.0, 1.5, (PIPBOY,), 0.0, frame_pieces=FRAME_ITEMS) is None
        assert len(s.player_inventory("alice").lines) == 2     # untouched: the give-back takes them
        assert s.record_pieces_to_frame("alice", FRAME_ITEMS, 1.0) == 1
        assert s.player_inventory("alice").lines == {(PIPBOY, FP_PLAIN): 1}

    def test_the_journal_replays_the_move(self, tmp_path: Path):
        j = Journal.open(tmp_path / "journal")
        a = ServerState()
        a.journal = j
        _record(a, lines=LINES_IN_PA)
        spawn, _ = a.record_death_crate("alice", a.next_world_spawn_wid, CRATE_BASE, CELL, 10.0,
                                        20.0, 30.0, 1.5, (PIPBOY,), 0.0, frame_pieces=FRAME_ITEMS)
        assert a.record_pieces_from_frame("alice", FRAME_ITEMS, 2.0) == 2
        j.flush()
        j.close()
        b = ServerState()
        Journal.open(tmp_path / "journal").replay(b, after_lsn=0)
        assert b.container_state(wid_container_key(spawn.wid)).items == {
            (CAPS, FP_PLAIN): 300, (LEFT_ARM, 0x78): 1}
        assert b.player_inventory("alice").lines == {
            (PIPBOY, FP_PLAIN): 1, (LEFT_ARM, FP_UNKNOWN): 1, (RIGHT_ARM, FP_UNKNOWN): 1}

    def test_pieces_come_back_as_lines_nobody_read(self):
        # A base the record holds by instance (a spare) and the mounted one
        # are two lines; the frame's body armour never comes back (2026-10-05:
        # never inventory).
        s = ServerState()
        _record(s, lines=[(PIPBOY, FP_PLAIN, 1, INV_ENTRY_EQUIPPED), (LEFT_ARM, 0x78, 1, 0)])
        assert s.record_pieces_from_frame("alice", FRAME_ITEMS, 1.0) == 2
        assert s.record_pieces_from_frame("alice", ((PA_FRAME_WEARABLE, 1),), 2.0) == 0
        rec = s.player_inventory("alice")
        assert rec.lines == {(PIPBOY, FP_PLAIN): 1, (LEFT_ARM, 0x78): 1, (LEFT_ARM, FP_UNKNOWN): 1,
                             (RIGHT_ARM, FP_UNKNOWN): 1}
        assert s.record_pieces_from_frame("nobody", FRAME_ITEMS, 3.0) == 0

    @pytest.mark.asyncio
    async def test_the_frame_stands_complete_next_to_the_crate(self):
        transport, p, addr, sock_a, sock_b, peer = await TestServerHandlers._setup(
            31627, lines=LINES_IN_PA)
        try:
            st = p.state.record_world_spawn(peer, 0x2079E, 0xFF001DEE, 10.0, 20.0, 30.0, 0.0, 0.0,
                                            1.5, CELL, 0, 1, pieces=LEDGER)
            assert p.state.mark_world_spawn_worn(st.wid, peer, 0.0)
            req = RestoreRequestPayload(session=SESSION, last_seq=1, reason=RESTORE_REASON_DEATH)
            sock_a.sendto(encode_frame(MessageType.RESTORE_REQUEST, 1, req, reliable=True), addr)
            died = PlayerLifePayload(0, (10.0, 20.0, 30.0), 10)
            sock_a.sendto(encode_frame(MessageType.PLAYER_LIFE, 2, died, reliable=True), addr)
            fa, fb = await asyncio.gather(_collect_frames(sock_a, 0.5), _collect_frames(sock_b, 0.5))
            [sp] = [s for s in _frames_of(fb, MessageType.WORLD_SPAWN_BCAST)
                    if s.flags & WORLD_SPAWN_FLAG_CONTAINER]
            key = wid_container_key(sp.wid)
            lines = {(e.item_base_id, e.item_fp): e.count
                     for c in _frames_of(fb, MessageType.CONTAINER_STATE)
                     for e in c.entries if e.container_form_id == key}
            assert lines == {(CAPS, FP_PLAIN): 300, (LEFT_ARM, 0x78): 1}
            [inv] = _frames_of(fa, MessageType.PLAYER_INV)
            assert [(e.item_base_id, e.count) for e in inv.entries] == [(PIPBOY, 1)]
            # The corpse is still in the frame until the respawn.
            assert p.state.world_spawns[st.wid].worn_by_peer_id == peer
            back = PlayerLifePayload(1, (-79857.5, 89852.6, 7821.7), 10)
            sock_a.sendto(encode_frame(MessageType.PLAYER_LIFE, 3, back, reliable=True), addr)
            fa, fb = await asyncio.gather(_collect_frames(sock_a, 0.5), _collect_frames(sock_b, 0.5))
            for frames in (fa, fb):
                [fr] = [s for s in _frames_of(frames, MessageType.WORLD_SPAWN_BCAST)
                        if s.wid == st.wid]
                assert fr.base_form_id == 0x2079E and (fr.px, fr.py, fr.pz) == (10.0, 20.0, 30.0)
                assert [q[0] for q in fr.pieces] == [LEFT_ARM, RIGHT_ARM]
            assert p.state.world_spawns[st.wid].worn_by_peer_id == ""
            assert p.state.player_inventory(peer).lines == {(PIPBOY, FP_PLAIN): 1}
        finally:
            sock_a.close(); sock_b.close(); transport.close()


# 2026-10-05: the "body" armours of a frame (protocol.PA_FRAME_WEARABLES,
# every ArmorPoweredFrame* of the base game, all on biped slot 30, the
# Pip-Boy's) are never inventory. Live: the raider one (0x1909D6) went into
# the death crate as loot, came back on the player with the loot, and every
# exit from a frame since left it equipped over the Pip-Boy.
RAIDER_FRAME = 0x1909D6


class TestFrameWearables:
    def test_a_capture_is_recorded_without_them(self):
        s = ServerState()
        _record(s, lines=[(PIPBOY, FP_PLAIN, 1, INV_ENTRY_EQUIPPED),
                          (RAIDER_FRAME, 0x77, 1, INV_ENTRY_EQUIPPED), (CAPS, FP_PLAIN, 5, 0)])
        rec = s.player_inventory("alice")
        assert rec.lines == {(PIPBOY, FP_PLAIN): 1, (CAPS, FP_PLAIN): 5}
        assert rec.equipped == {(PIPBOY, FP_PLAIN)}

    def test_a_record_written_before_the_rule_never_feeds_a_crate(self):
        s = ServerState()
        s._restore_player_inventory("alice", {(PIPBOY, FP_PLAIN): 1, (RAIDER_FRAME, 0x77): 1,
                                              (CAPS, FP_PLAIN): 5},
                                    {(PIPBOY, FP_PLAIN), (RAIDER_FRAME, 0x77)}, SESSION, 1, 0,
                                    EPOCH, INV_STATE_FLAG_COMPLETE, 0, [], 1, 0.0, SESSION)
        spawn, crate = s.record_death_crate("alice", s.next_world_spawn_wid, CRATE_BASE, CELL,
                                            10.0, 20.0, 30.0, 1.5, (PIPBOY,), 0.0)
        assert crate.items == {(CAPS, FP_PLAIN): 5}
        assert s.player_inventory("alice").lines == {(PIPBOY, FP_PLAIN): 1}

    def test_an_old_snapshot_is_stripped_when_loaded(self, tmp_path: Path):
        s = ServerState()
        s._restore_player_inventory("alice", {(PIPBOY, FP_PLAIN): 1, (RAIDER_FRAME, 0x77): 1},
                                    {(PIPBOY, FP_PLAIN), (RAIDER_FRAME, 0x77)}, SESSION, 1, 0,
                                    EPOCH, INV_STATE_FLAG_COMPLETE, 0, [], 1, 0.0, SESSION)
        _record(s, peer="bob")
        spawn, crate = _crate(s, "bob")
        s.container_state(crate.form_id).items[(RAIDER_FRAME, 0x78)] = 1
        path = tmp_path / "snap.json"
        snapshot(s, path)
        t = ServerState()
        load_into(t, path)
        assert t.player_inventory("alice").lines == {(PIPBOY, FP_PLAIN): 1}
        assert t.player_inventory("alice").equipped == {(PIPBOY, FP_PLAIN)}
        assert (RAIDER_FRAME, 0x78) not in t.container_state(crate.form_id).items
        assert t.container_state(crate.form_id).items[(CAPS, FP_PLAIN)] == 300


class TestConfig:
    def test_the_default_crate_is_an_empty_footlocker(self, tmp_path: Path):
        # Loot_Prewar_Suitcase_Clothes (0x64A3C), the first choice, rolls
        # three leveled lists of clothes into a new copy, runs
        # lockExtraLootSCRIPT and respawns its content; the footlocker of
        # DN156 has no content, no script and no keyword.
        from server.main import read_death_crate, DEFAULT_DEATH_CRATE_BASE
        assert DEFAULT_DEATH_CRATE_BASE == 0x1D0FB
        assert read_death_crate(tmp_path / "missing.ini") == DEFAULT_DEATH_CRATE_BASE
        ini = tmp_path / "server.ini"
        ini.write_text("[death]\ncrate = off\n", encoding="utf-8")
        assert read_death_crate(ini) == 0
        ini.write_text("[death]\ncrate = 0x2381BA\n", encoding="utf-8")
        assert read_death_crate(ini) == 0x2381BA

    def test_the_shipped_server_ini_names_the_default(self):
        from server.main import read_death_crate, DEFAULT_DEATH_CRATE_BASE
        ini = Path(__file__).resolve().parents[2] / "server.ini"
        assert read_death_crate(ini) == DEFAULT_DEATH_CRATE_BASE
