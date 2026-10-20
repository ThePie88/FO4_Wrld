"""L5 stage 3d (2026-09-29) — the server books a moved checkpoint.

The source is the checkpoint the player's next boot would load, in custody;
the copy is booked newest, in custody, with the same digest and watermark,
and a failure books and writes nothing.
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))   # server.auth imports net.protocol
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from server.custody import CustodyStore  # noqa: E402
from server.respawn import (  # noqa: E402
    CKPT_REASON_FIRST_ENTRY, CKPT_REASON_RESPAWN, RespawnError, RespawnPoint,
    checkpoint_wears_frame, make_first_checkpoint, make_respawn_checkpoint,
)
from server.savepos import exterior_sky, read_position, read_worn_frame  # noqa: E402
from server.state import CHECKPOINTS_KEPT, ServerState  # noqa: E402
from test_stage3d_savepos import build_save  # noqa: E402

PEER = "fw697d1c84d3e62"
NOW = 1_790_600_000_000.0   # 2026-09-28, the server's wall-anchored clock
POINT = RespawnPoint(-55911.7, 101867.7, 8542.9, 0.25)


def _book(state: ServerState, store: CustodyStore, name: str, data: bytes, *,
          custody: bool = True, now: float = NOW, digest: int = 0xABC, lsn: int = 77,
          in_pa=None) -> None:
    sha = hashlib.sha256(data).hexdigest()
    store.store(PEER, name, data, b"# fwworld 1 " + name.encode() + b"\n", sha)
    state.record_checkpoint(PEER, "id" * 16, 3, name, sha, len(data), digest, 9, 123, now, lsn, 0,
                            in_pa=in_pa)
    if custody:
        assert state.set_checkpoint_custody(PEER, name, sha, now) is not None


def test_books_a_moved_copy(tmp_path):
    state, store = ServerState(), CustodyStore(tmp_path)
    _book(state, store, "fwck_%s_20260929_010000" % PEER, build_save())
    rec = make_respawn_checkpoint(state, store, PEER, POINT, NOW + 60_000)
    assert state.checkpoint_to_boot(PEER) is rec
    assert rec.custody and rec.reason == CKPT_REASON_RESPAWN
    assert (rec.digest, rec.watermark_lsn, rec.seq) == (0xABC, 77, 3)
    data, manifest = store.read(PEER, rec.name)
    assert hashlib.sha256(data).hexdigest() == rec.sha256_hex and len(data) == rec.size
    assert manifest.startswith(b"# fwworld 1 fwck_")
    _, mv = read_position(data)
    assert mv.pos[1] == pytest.approx(101867.7, abs=0.01) and mv.rot[2] == pytest.approx(0.25)


def test_keeps_the_last_three(tmp_path):
    state, store = ServerState(), CustodyStore(tmp_path)
    for i in range(CHECKPOINTS_KEPT):
        _book(state, store, "fwck_%s_20260929_01000%d" % (PEER, i), build_save(), now=NOW + i)
    rec = make_respawn_checkpoint(state, store, PEER, POINT, NOW + 60_000)
    names = [r.name for r in state.checkpoints(PEER)]
    assert names[0] == rec.name and len(names) == CHECKPOINTS_KEPT
    assert sorted(store.names(PEER)) == sorted(names)


def test_the_newest_checkpoint_on_foot_outlives_the_last_three_in_power_armour(tmp_path):
    # L5 realtime D1 (2026-10-04): a death puts the player back on foot, so
    # the respawn needs a checkpoint on foot; the newest one is kept past
    # the last CHECKPOINTS_KEPT while every newer one has them in a frame.
    state, store = ServerState(), CustodyStore(tmp_path)
    foot = "fwck_%s_20260929_010000" % PEER
    _book(state, store, foot, build_save(), in_pa=False)
    for i in range(1, CHECKPOINTS_KEPT + 1):
        _book(state, store, "fwck_%s_20260929_01000%d" % (PEER, i), build_save(frame=True),
              now=NOW + i, in_pa=True)
    names = [r.name for r in state.checkpoints(PEER)]
    assert len(names) == CHECKPOINTS_KEPT + 1 and names[-1] == foot
    rec = make_respawn_checkpoint(state, store, PEER, POINT, NOW + 60_000)
    assert rec.in_pa is False and read_worn_frame(store.read(PEER, rec.name)[0]) is None
    names = [r.name for r in state.checkpoints(PEER)]
    assert names[0] == rec.name and len(names) == CHECKPOINTS_KEPT   # the copy on foot lets the old one go
    assert sorted(store.names(PEER)) == sorted(names)


def test_the_flag_survives_the_snapshot_and_the_journal(tmp_path):
    from server.journal import Journal
    from server.persistence import load_into, snapshot
    j = Journal.open(tmp_path / "journal")
    a = ServerState()
    a.journal = j
    a.record_checkpoint(PEER, "id" * 16, 1, "fwck_%s_1" % PEER, "ab" * 32, 9, 0, 0, 1, 1.0, 1, 0,
                        in_pa=True)
    a.record_checkpoint(PEER, "id" * 16, 2, "fwck_%s_2" % PEER, "cd" * 32, 9, 0, 0, 2, 2.0, 2, 0,
                        in_pa=False)
    a.record_checkpoint(PEER, "id" * 16, 3, "fwck_%s_3" % PEER, "ef" * 32, 9, 0, 0, 3, 3.0, 3, 0)
    j.flush()
    j.close()
    snap = tmp_path / "snap.json"
    snapshot(a, snap)
    for b in (ServerState(), ServerState()):
        if b is not a:
            pass
    b = ServerState()
    load_into(b, snap)
    c = ServerState()
    Journal.open(tmp_path / "journal").replay(c, after_lsn=0)
    for s in (b, c):
        flags = {r.name[-1]: r.in_pa for r in s.checkpoints(PEER)}
        assert flags == {"1": True, "2": False, "3": None}


def _unchanged(state, store, before_names, before_files):
    assert [r.name for r in state.checkpoints(PEER)] == before_names
    assert store.names(PEER) == before_files


def test_refuses_what_is_not_in_custody(tmp_path):
    state, store = ServerState(), CustodyStore(tmp_path)
    _book(state, store, "fwck_%s_20260929_010000" % PEER, build_save(), custody=False)
    names, files = [r.name for r in state.checkpoints(PEER)], store.names(PEER)
    with pytest.raises(RespawnError):
        make_respawn_checkpoint(state, store, PEER, POINT, NOW + 60_000)
    _unchanged(state, store, names, files)


def test_refuses_bytes_that_are_not_the_record(tmp_path):
    state, store = ServerState(), CustodyStore(tmp_path)
    name = "fwck_%s_20260929_010000" % PEER
    _book(state, store, name, build_save())
    store.fos_path(PEER, name).write_bytes(build_save(pos=(1.0, 2.0, 3.0)))
    names, files = [r.name for r in state.checkpoints(PEER)], store.names(PEER)
    with pytest.raises(RespawnError):
        make_respawn_checkpoint(state, store, PEER, POINT, NOW + 60_000)
    _unchanged(state, store, names, files)


def test_refuses_a_plugin_worldspace_and_books_nothing(tmp_path):
    state, store = ServerState(), CustodyStore(tmp_path)
    _book(state, store, "fwck_%s_20260929_010000" % PEER, build_save(space=5))
    names, files = [r.name for r in state.checkpoints(PEER)], store.names(PEER)
    with pytest.raises(RespawnError):
        make_respawn_checkpoint(state, store, PEER, POINT, NOW + 60_000)
    _unchanged(state, store, names, files)


GENESIS_SKY = exterior_sky(build_save())


def test_a_checkpoint_written_in_an_interior_is_moved_out(tmp_path):
    state, store = ServerState(), CustodyStore(tmp_path)
    _book(state, store, "fwck_%s_20260929_010000" % PEER,
          build_save(cell=(1 << 22) | 0x0A36EA, pos=(-72.1, -104.1, -8.7)))
    rec = make_respawn_checkpoint(state, store, PEER, POINT, NOW + 60_000,
                                  exterior_globals=GENESIS_SKY)
    data = store.read(PEER, rec.name)[0]
    loc, mv = read_position(data)
    assert loc.worldspace2 == mv.space == (1 << 22) | 0x3C
    assert mv.pos[0] == pytest.approx(POINT.x, abs=0.01)
    assert exterior_sky(data) == GENESIS_SKY


def test_an_interior_without_the_genesis_sky_is_refused_and_books_nothing(tmp_path):
    state, store = ServerState(), CustodyStore(tmp_path)
    _book(state, store, "fwck_%s_20260929_010000" % PEER,
          build_save(cell=(1 << 22) | 0x0A36EA, pos=(-72.1, -104.1, -8.7)))
    names, files = [r.name for r in state.checkpoints(PEER)], store.names(PEER)
    with pytest.raises(RespawnError):
        make_respawn_checkpoint(state, store, PEER, POINT, NOW + 60_000)
    _unchanged(state, store, names, files)


def test_no_checkpoint_at_all(tmp_path):
    with pytest.raises(RespawnError):
        make_respawn_checkpoint(ServerState(), CustodyStore(tmp_path), PEER, POINT, NOW)


# ---------------------------------------------------------------------------
# The server's answer to a death (wire v33, CKPT_RESPAWN) and server.ini.
# ---------------------------------------------------------------------------
from protocol import (  # noqa: E402
    CkptRespawnPayload, INV_DIGEST_FLAG_COMPLETE, INV_DIGEST_FLAG_IN_POWER_ARMOR, MessageType,
    PlayerLifePayload, decode_frame,
    FP_PLAIN, FP_UNKNOWN, INV_ENTRY_EQUIPPED, INV_STATE_FLAG_COMPLETE,
)
from server.main import RESPAWN_POINTS, ServerProtocol, read_server_ini  # noqa: E402


class FakeTransport:
    def __init__(self):
        self.sent = []

    def sendto(self, data, addr):
        self.sent.append((addr, data))


def _server(tmp_path, *, point=True, custody=True, pa=False, digest_matches=True, frame=False,
            cell=None, genesis=False):
    state = ServerState()
    proto = ServerProtocol(state)
    proto.transport = FakeTransport()
    store = CustodyStore(tmp_path)
    if custody:
        proto.custody = store
    if point:
        proto.respawn_point = RESPAWN_POINTS["sanctuary"]
    session, reason = state.accept_peer(("127.0.0.1", 5), PEER, (1, 0), 0.0)
    assert session is not None, reason
    session.identity_hex = "ab" * 16
    _book(state, store, "fwck_%s_20260929_010000" % PEER, build_save(frame=frame, cell=cell))
    if genesis:
        proto.exterior_globals = GENESIS_SKY
    flags = INV_DIGEST_FLAG_COMPLETE | (INV_DIGEST_FLAG_IN_POWER_ARMOR if pa else 0)
    state.record_inv_digest(PEER, 9 if digest_matches else 10, 123, 0xABC, 5, 6, 7, 0, flags, 1, NOW)
    return state, proto, session, store


def _answers(proto, session):
    out = []
    for addr, raw in proto.transport.sent:
        f = decode_frame(raw)
        if addr == session.addr and f.header.msg_type == MessageType.CKPT_RESPAWN:
            out.append(f.payload)
    return out


def test_the_answer_payload_round_trips():
    p = CkptRespawnPayload(True, "fwck_%s_20260929_014816" % PEER, bytes(range(32)), 5040357)
    raw = p.encode()
    assert len(raw) == 85
    q = CkptRespawnPayload.decode(raw)
    assert (q.has, q.name, q.sha256, q.size) == (True, p.name, p.sha256, 5040357)
    none = CkptRespawnPayload.decode(CkptRespawnPayload(False, "", b"", 0).encode())
    assert none.has is False and none.name == "" and none.sha256 == b""


def test_a_death_is_answered_with_the_moved_checkpoint(tmp_path):
    state, proto, session, store = _server(tmp_path)
    proto._handle_player_life(session, PlayerLifePayload(0, (1.0, 2.0, 3.0), 10), NOW + 60_000)
    (ans,) = _answers(proto, session)
    rec = state.checkpoint_to_boot(PEER)
    assert ans.has and ans.name == rec.name and ans.size == rec.size
    assert ans.sha256.hex() == rec.sha256_hex
    assert read_position(store.read(PEER, rec.name)[0])[1].pos[0] == pytest.approx(
        RESPAWN_POINTS["sanctuary"][0], abs=0.01)
    assert proto._counters["respawn_checkpoints"] == 1


@pytest.mark.parametrize("kwargs", [
    dict(point=False), dict(custody=False),
    dict(frame=True),                    # the only checkpoint has them in a frame, no genesis
])
def test_no_moved_checkpoint_says_so_and_books_nothing(tmp_path, kwargs):
    state, proto, session, store = _server(tmp_path, **kwargs)
    before = [r.name for r in state.checkpoints(PEER)]
    proto._handle_player_life(session, PlayerLifePayload(0, (1.0, 2.0, 3.0), 10), NOW + 60_000)
    (ans,) = _answers(proto, session)
    assert ans.has is False
    assert [r.name for r in state.checkpoints(PEER)] == before


def test_only_a_death_is_answered(tmp_path):
    state, proto, session, store = _server(tmp_path)
    proto._handle_player_life(session, PlayerLifePayload(1, (1.0, 2.0, 3.0), 10), NOW + 60_000)
    proto._handle_player_life(session, PlayerLifePayload(2, (1.0, 2.0, 3.0), 10), NOW + 61_000)
    assert _answers(proto, session) == []


def test_server_ini(tmp_path):
    assert read_server_ini(tmp_path / "missing.ini") == (None, {})
    ini = tmp_path / "server.ini"
    ini.write_text("[spawn]\npoint = redrocket   ; the founder's pick\n\n"
                   "[points]\nRedRocket = -46000.5, 102000.25, 8200, 1.5\n", encoding="utf-8")
    point, points = read_server_ini(ini)
    assert point == "redrocket"
    assert points["redrocket"] == (-46000.5, 102000.25, 8200.0, 1.5)
    ini.write_text("[points]\nbad = 1, 2\n", encoding="utf-8")
    with pytest.raises(ValueError):
        read_server_ini(ini)
    ini.write_text("[spawn]\npoint = off\n", encoding="utf-8")
    assert read_server_ini(ini) == ("off", {})


# L5 realtime D1 (2026-10-04, the owner's rule): a death in power armour
# leaves the frame where they fell, complete, next to the crate, and the
# player comes back ON FOOT: the respawn checkpoint is the newest one that
# has them on foot, the genesis save moved onto the point when none does.
def test_a_death_in_power_armour_is_answered_with_the_newest_checkpoint_on_foot(tmp_path):
    state, proto, session, store = _server(tmp_path)                     # on foot, the older
    _book(state, store, "fwck_%s_20260929_010100" % PEER, build_save(frame=True), now=NOW + 1,
          in_pa=True)
    assert read_worn_frame(store.read(PEER, state.checkpoint_to_boot(PEER).name)[0]) is not None
    proto._handle_player_life(session, PlayerLifePayload(0, (1.0, 2.0, 3.0), 10), NOW + 60_000)
    (ans,) = _answers(proto, session)
    assert ans.has
    data = store.read(PEER, ans.name)[0]
    assert read_worn_frame(data) is None
    assert read_position(data)[1].pos[0] == pytest.approx(RESPAWN_POINTS["sanctuary"][0], abs=0.01)
    assert state.checkpoint_to_boot(PEER).in_pa is False


def test_the_save_decides_when_the_flag_is_unknown(tmp_path):
    state, proto, session, store = _server(tmp_path)
    _book(state, store, "fwck_%s_20260929_010100" % PEER, build_save(frame=True), now=NOW + 1)
    proto._handle_player_life(session, PlayerLifePayload(0, (1.0, 2.0, 3.0), 10), NOW + 60_000)
    (ans,) = _answers(proto, session)
    assert ans.has and read_worn_frame(store.read(PEER, ans.name)[0]) is None


def test_with_every_checkpoint_in_power_armour_the_genesis_stands_in(tmp_path):
    state, proto, session, store = _server(tmp_path, pa=True, frame=True)
    g = tmp_path / "world_base.fos"
    g.write_bytes(build_save(pos=(1.0, 2.0, 3.0)))
    proto.genesis_path = g
    proto._handle_player_life(session, PlayerLifePayload(0, (1.0, 2.0, 3.0), 10), NOW + 60_000)
    (ans,) = _answers(proto, session)
    assert ans.has
    rec = state.checkpoint_to_boot(PEER)
    assert rec.name == ans.name and rec.reason == CKPT_REASON_RESPAWN and rec.in_pa is False
    assert rec.custody and rec.identity_hex == session.identity_hex
    data = store.read(PEER, ans.name)[0]
    assert read_worn_frame(data) is None
    assert read_position(data)[1].pos[0] == pytest.approx(RESPAWN_POINTS["sanctuary"][0], abs=0.01)


def test_a_death_in_an_interior_is_moved_out_with_the_genesis_sky(tmp_path):
    state, proto, session, store = _server(tmp_path, cell=(1 << 22) | 0x0A36EA, genesis=True)
    proto._handle_player_life(session, PlayerLifePayload(0, (1.0, 2.0, 3.0), 10), NOW + 60_000)
    (ans,) = _answers(proto, session)
    assert ans.has
    data = store.read(PEER, ans.name)[0]
    assert read_position(data)[1].space == (1 << 22) | 0x3C
    assert exterior_sky(data) == GENESIS_SKY


def test_a_death_in_an_interior_without_a_genesis_falls_back(tmp_path):
    state, proto, session, store = _server(tmp_path, cell=(1 << 22) | 0x0A36EA)
    before = [r.name for r in state.checkpoints(PEER)]
    proto._handle_player_life(session, PlayerLifePayload(0, (1.0, 2.0, 3.0), 10), NOW + 60_000)
    (ans,) = _answers(proto, session)
    assert ans.has is False
    assert [r.name for r in state.checkpoints(PEER)] == before


# ---------------------------------------------------------------------------
# The first entry of a new character (2026-09-30): the genesis save moved
# onto the founder's point is its first checkpoint.
# ---------------------------------------------------------------------------
NEWBIE = "fw0000000000c0c"


def test_make_first_checkpoint(tmp_path):
    state, store = ServerState(), CustodyStore(tmp_path)
    rec = make_first_checkpoint(state, store, NEWBIE, "cd" * 16, build_save(), POINT, NOW)
    assert state.checkpoint_to_boot(NEWBIE) == rec
    assert rec.reason == CKPT_REASON_FIRST_ENTRY and rec.custody and rec.seq == 0
    data, manifest = store.read(NEWBIE, rec.name)
    assert hashlib.sha256(data).hexdigest() == rec.sha256_hex
    assert manifest.startswith(b"# fwworld 1 ") and manifest.count(b"\n") == 1   # no objects
    mv = read_position(data)[1]
    assert (mv.pos[0], mv.pos[1]) == pytest.approx((POINT.x, POINT.y), abs=0.01)
    with pytest.raises(RespawnError):
        make_first_checkpoint(state, store, NEWBIE, "cd" * 16, b"not a save", POINT, NOW)


def _boots(proto, session):
    out = []
    for addr, raw in proto.transport.sent:
        f = decode_frame(raw)
        if addr == session.addr and f.header.msg_type == MessageType.CKPT_BOOT:
            out.append(f.payload)
    return out


def _newcomer(tmp_path, *, genesis=True, point=True, known=False):
    state = ServerState()
    proto = ServerProtocol(state)
    proto.transport = FakeTransport()
    proto.custody = CustodyStore(tmp_path / "custody")
    if point:
        proto.respawn_point = RESPAWN_POINTS["sanctuary"]
    if genesis:
        g = tmp_path / "world_base.fos"
        g.write_bytes(build_save())
        proto.genesis_path = g
    session, reason = state.accept_peer(("127.0.0.1", 7), NEWBIE, (1, 0), 0.0)
    assert session is not None, reason
    session.identity_hex = "cd" * 16
    return state, proto, session


def test_a_new_character_boots_its_first_checkpoint_on_the_point(tmp_path):
    state, proto, session = _newcomer(tmp_path)
    proto._send_checkpoint_boot(session, NOW)
    (boot,) = _boots(proto, session)
    rec = state.checkpoint_to_boot(NEWBIE)
    assert boot.has and boot.name == rec.name and rec.reason == CKPT_REASON_FIRST_ENTRY
    data = proto.custody.read(NEWBIE, rec.name)[0]
    assert read_position(data)[1].pos[0] == pytest.approx(RESPAWN_POINTS["sanctuary"][0], abs=0.01)
    assert proto._counters["first_entries"] == 1
    # The next boot is an ordinary one: the same checkpoint, nothing new made.
    proto._send_checkpoint_boot(session, NOW + 1000)
    assert [b.name for b in _boots(proto, session)] == [rec.name, rec.name]
    assert proto._counters["first_entries"] == 1


@pytest.mark.parametrize("kwargs", [dict(genesis=False), dict(point=False)])
def test_without_a_genesis_or_a_point_the_genesis_boots_as_before(tmp_path, kwargs):
    state, proto, session = _newcomer(tmp_path, **kwargs)
    proto._send_checkpoint_boot(session, NOW)
    (boot,) = _boots(proto, session)
    assert boot.has is False and state.checkpoints(NEWBIE) == []


def test_a_player_seen_before_is_not_a_new_character(tmp_path):
    from types import SimpleNamespace
    state, proto, session = _newcomer(tmp_path)
    pos = SimpleNamespace(x=10.0, y=20.0, z=30.0, rx=0.0, ry=0.0, rz=0.0, timestamp_ms=1,
                          cell_id=0x3C)
    state.record_presence_pos(NEWBIE, pos, NOW - 5000)
    proto._send_checkpoint_boot(session, NOW)
    (boot,) = _boots(proto, session)
    assert boot.has is False and state.checkpoints(NEWBIE) == []


# ---------------------------------------------------------------------------
# The duplicate frame (2026-09-30): a checkpoint in power armour, the player
# leaves the frame, then dies on foot or boots again: the frame they left is
# taken back from the world, since they come back inside the save's copy.
# ---------------------------------------------------------------------------
SAVED_FRAME_FID = 0xFF00139F       # the frame build_save(frame=True) links


def _standing_frame(state, *, spawner=PEER, local_fid=SAVED_FRAME_FID):
    st = state.record_world_spawn(spawner, 0x2079E, local_fid, 5.0, 6.0, 7.0, 0.0, 0.0, 0.0,
                                  0xDD60, 0, 1, pieces=PIECES)
    return st.wid


def _despawns(proto):
    out = []
    for addr, raw in proto.transport.sent:
        f = decode_frame(raw)
        if f.header.msg_type == MessageType.WORLD_DESPAWN_BCAST:
            out.append((addr, f.payload))
    return out


def test_worn_frame_fid():
    from server.respawn import worn_frame_fid
    from server.savepos import read_worn_frame as rwf
    assert worn_frame_fid(rwf(build_save(frame=True))) == SAVED_FRAME_FID


def test_a_death_on_foot_leaves_the_standing_frame_alone(tmp_path):
    # D1 (2026-10-04): the player comes back on foot whatever the newest
    # checkpoint says, so the frame they left keeps standing.
    state, proto, session, store = _server(tmp_path)
    _book(state, store, "fwck_%s_20260929_010100" % PEER, build_save(frame=True), now=NOW + 1,
          in_pa=True)
    other, _ = state.accept_peer(("127.0.0.1", 6), OTHER, (1, 0), 0.0)
    wid = _standing_frame(state)
    proto._handle_player_life(session, PlayerLifePayload(0, (1.0, 2.0, 3.0), 10), NOW + 60_000)
    (ans,) = _answers(proto, session)
    assert ans.has and read_worn_frame(store.read(PEER, ans.name)[0]) is None
    proto._handle_player_life(session, PlayerLifePayload(1, (4.0, 5.0, 6.0), 10), NOW + 70_000)
    assert state.world_spawns[wid].worn_by_peer_id == "" and _despawns(proto) == []


def test_a_frame_someone_else_wears_is_left_alone(tmp_path):
    state, proto, session, store = _server(tmp_path, pa=True, frame=True)
    state.accept_peer(("127.0.0.1", 6), OTHER, (1, 0), 0.0)
    wid = _standing_frame(state)
    assert state.mark_world_spawn_worn(wid, OTHER, NOW)
    proto._handle_player_life(session, PlayerLifePayload(0, (1.0, 2.0, 3.0), 10), NOW + 60_000)
    proto._handle_player_life(session, PlayerLifePayload(1, (4.0, 5.0, 6.0), 10), NOW + 70_000)
    assert state.world_spawns[wid].worn_by_peer_id == OTHER and _despawns(proto) == []


def test_a_boot_inside_the_checkpoints_frame_takes_it_back(tmp_path):
    state, proto, session, store = _server(tmp_path, pa=True, frame=True)
    wid = _standing_frame(state)
    proto._send_checkpoint_boot(session, NOW)
    assert state.world_spawns[wid].worn_by_peer_id == PEER
    assert [p.wid for _, p in _despawns(proto)] == [wid]


def test_a_boot_inside_the_frame_puts_its_pieces_back_into_the_record(tmp_path):
    # D1 (2026-10-04): the record lost the pieces when the frame was given
    # back; the boot puts the player inside the save's copy, which has them,
    # so the record gets them back as lines nobody read (the restore keeps
    # what the save has of each base, builds and removes nothing of them).
    state, proto, session, store = _server(tmp_path, pa=True, frame=True)
    wid = _standing_frame(state)
    state.record_player_inventory(PEER, 0x1234, 1, 0, 0x12, INV_STATE_FLAG_COMPLETE, 0,
                                  ((0x21B3B, FP_PLAIN, 1, INV_ENTRY_EQUIPPED),), 0.0)
    proto._send_checkpoint_boot(session, NOW)
    assert state.world_spawns[wid].worn_by_peer_id == PEER
    rec = state.player_inventory(PEER)
    assert rec.lines == {(0x21B3B, FP_PLAIN): 1, (0x154AC5, FP_UNKNOWN): 1,
                         (0x154AC8, FP_UNKNOWN): 1}
    assert (0x154AC5, FP_UNKNOWN) in rec.equipped


def test_a_boot_on_foot_takes_nothing(tmp_path):
    state, proto, session, store = _server(tmp_path)
    wid = _standing_frame(state)
    proto._send_checkpoint_boot(session, NOW)
    assert state.world_spawns[wid].worn_by_peer_id == "" and _despawns(proto) == []


def test_leaving_power_armour_asks_for_a_checkpoint(tmp_path):
    from protocol import WorldSpawnOpPayload
    state, proto, session, store = _server(tmp_path)
    wid = _standing_frame(state)
    assert state.mark_world_spawn_worn(wid, PEER, NOW)
    exit_op = WorldSpawnOpPayload(0x2079E, 0xFF00139F, 5.0, 6.0, 7.0, 0.0, 0.0, 0.0, 0xDD60, 0,
                                  1, pieces=PIECES)
    proto._handle_world_spawn_op(session, exit_op, NOW + 1000)
    reqs = [decode_frame(raw).payload for addr, raw in proto.transport.sent
            if addr == session.addr
            and decode_frame(raw).header.msg_type == MessageType.CKPT_REQUEST]
    assert [(r.reason, r.seq) for r in reqs] == [(1, 1)]
    # A frame spawned without leaving one (a console spawn) asks for nothing.
    proto._handle_world_spawn_op(session, exit_op, NOW + 2000)
    reqs = [raw for addr, raw in proto.transport.sent
            if decode_frame(raw).header.msg_type == MessageType.CKPT_REQUEST]
    assert len(reqs) == 1


def test_read_genesis_path(tmp_path):
    from server.main import read_genesis_path
    assert read_genesis_path(tmp_path / "missing.ini") is None
    ini = tmp_path / "server.ini"
    ini.write_text("[genesis]\nsave = net/genesis/world_base.fos   ; the founder's copy\n",
                   encoding="utf-8")
    assert read_genesis_path(ini) == "net/genesis/world_base.fos"
    ini.write_text("[spawn]\npoint = sanctuary\n", encoding="utf-8")
    assert read_genesis_path(ini) is None


# ---------------------------------------------------------------------------
# A death in power armour with a checkpoint on foot (live test #18): the
# frame stays where the player fell and is given back at the respawn.
# ---------------------------------------------------------------------------
OTHER = "fw0000000000b0b"
PIECES = ((0x154AC5, 1, (0x1681EA, 0x1834D8), 0.926), (0x154AC8, 1, (0x1681E9,), 0.917))


def _wearing(state, *, where=(100.0, 200.0, 300.0)):
    st = state.record_world_spawn(PEER, 0x2079E, 0xFF001DEE, where[0], where[1], where[2],
                                  0.0, 0.0, 1.5, 0xDD60, 0, 1, pieces=PIECES)
    assert state.mark_world_spawn_worn(st.wid, PEER, NOW)
    other, reason = state.accept_peer(("127.0.0.1", 6), OTHER, (1, 0), 0.0)
    assert other is not None, reason
    return st.wid, other


def _spawns(proto):
    out = []
    for addr, raw in proto.transport.sent:
        f = decode_frame(raw)
        if f.header.msg_type == MessageType.WORLD_SPAWN_BCAST:
            out.append((addr, f.payload))
    return out


def test_checkpoint_wears_frame(tmp_path):
    state, proto, session, store = _server(tmp_path, frame=True)
    rec = state.checkpoint_to_boot(PEER)
    assert checkpoint_wears_frame(store, PEER, rec) is True
    assert checkpoint_wears_frame(None, PEER, rec) is None
    assert checkpoint_wears_frame(store, PEER, None) is None
    state2, proto2, session2, store2 = _server(tmp_path / "foot", frame=False)
    assert checkpoint_wears_frame(store2, PEER, state2.checkpoint_to_boot(PEER)) is False
    store.store(PEER, rec.name, b"not the record", b"", rec.sha256_hex)
    assert checkpoint_wears_frame(store, PEER, rec) is None


def test_a_death_in_power_armour_on_foot_leaves_the_frame_where_they_fell(tmp_path):
    state, proto, session, store = _server(tmp_path, frame=False)
    wid, other = _wearing(state)
    proto._handle_player_life(session, PlayerLifePayload(0, (-79708.4, 90519.0, 7839.9), 10),
                              NOW + 60_000)
    (ans,) = _answers(proto, session)
    assert ans.has
    # Until the respawn the corpse is still in it: nothing moves yet.
    assert state.world_spawns[wid].worn_by_peer_id == PEER
    assert _spawns(proto) == []
    proto._handle_player_life(session, PlayerLifePayload(1, (-79857.5, 89852.6, 7821.7), 10),
                              NOW + 70_000)
    st = state.world_spawns[wid]
    assert st.worn_by_peer_id == ""
    assert (st.px, st.py, st.pz) == pytest.approx((-79708.4, 90519.0, 7839.9), abs=0.01)
    sent = _spawns(proto)
    assert {addr for addr, _ in sent} == {session.addr, other.addr}   # theirs included
    for _, p in sent:
        assert p.wid == wid and p.base_form_id == 0x2079E
        assert [q[0] for q in p.pieces] == [0x154AC5, 0x154AC8]
    # A second respawn report gives nothing back twice.
    proto._handle_player_life(session, PlayerLifePayload(1, (-79857.5, 89852.6, 7821.7), 10),
                              NOW + 71_000)
    assert len(_spawns(proto)) == 2


@pytest.mark.parametrize("kwargs", [
    dict(pa=True, frame=True),           # the only checkpoint has them inside: the reload runs
    dict(custody=False),                 # nothing can be read
])
def test_a_death_in_power_armour_gives_the_frame_back_whatever_the_checkpoint_says(tmp_path,
                                                                                   kwargs):
    # D1 (2026-10-04): the frame stays where they fell, complete, even when
    # no checkpoint on foot can be moved and the engine's reload runs.
    state, proto, session, store = _server(tmp_path, **kwargs)
    wid, other = _wearing(state)
    proto._handle_player_life(session, PlayerLifePayload(0, (1.0, 2.0, 3.0), 10), NOW + 60_000)
    (ans,) = _answers(proto, session)
    assert ans.has is False
    assert state.world_spawns[wid].worn_by_peer_id == PEER and _spawns(proto) == []
    proto._handle_player_life(session, PlayerLifePayload(1, (4.0, 5.0, 6.0), 10), NOW + 70_000)
    st = state.world_spawns[wid]
    assert st.worn_by_peer_id == "" and (st.px, st.py, st.pz) == (1.0, 2.0, 3.0)
    sent = _spawns(proto)
    assert {addr for addr, _ in sent} == {session.addr, other.addr}
    assert all([q[0] for q in p.pieces] == [0x154AC5, 0x154AC8] for _, p in sent)


def test_the_pieces_leave_the_record_when_the_frame_is_given_back(tmp_path):
    # D1 (2026-10-04): what is mounted on the frame is the frame's. The
    # record (what the restore puts back on the player) loses the mounted
    # pieces and the wearable the engine equips on entering; a spare of the
    # same base in the backpack stays.
    state, proto, session, store = _server(tmp_path)
    wid, other = _wearing(state)
    state.record_player_inventory(PEER, 0x1234, 1, 0, 0x12, INV_STATE_FLAG_COMPLETE, 0, (
        (0x21B3B, FP_PLAIN, 1, INV_ENTRY_EQUIPPED), (0x154AC5, 0x77, 1, INV_ENTRY_EQUIPPED),
        (0x154AC5, 0x78, 1, 0), (0x154AC8, 0x79, 1, INV_ENTRY_EQUIPPED),
        (0x3E577, FP_PLAIN, 1, INV_ENTRY_EQUIPPED)), 0.0)
    proto._handle_player_life(session, PlayerLifePayload(0, (7.0, 8.0, 9.0), 10), NOW + 60_000)
    proto._handle_player_life(session, PlayerLifePayload(1, (4.0, 5.0, 6.0), 10), NOW + 70_000)
    rec = state.player_inventory(PEER)
    assert rec.lines == {(0x21B3B, FP_PLAIN): 1, (0x154AC5, 0x78): 1}
    assert rec.equipped == {(0x21B3B, FP_PLAIN)}


def test_leaving_power_armour_takes_its_pieces_out_of_the_record(tmp_path):
    # The exit puts the pieces back on the frame natively; the capture that
    # follows says so within a quarter of a second, and the server says it
    # at once from the re-announce, for the crash in between.
    state, proto, session, store = _server(tmp_path)
    wid, other = _wearing(state)
    state.record_player_inventory(PEER, 0x1234, 1, 0, 0x12, INV_STATE_FLAG_COMPLETE, 0, (
        (0x21B3B, FP_PLAIN, 1, INV_ENTRY_EQUIPPED), (0x154AC5, 0x77, 1, INV_ENTRY_EQUIPPED),
        (0x3E577, FP_PLAIN, 1, INV_ENTRY_EQUIPPED)), 0.0)
    from protocol import WorldSpawnOpPayload
    op = WorldSpawnOpPayload(base_form_id=0x2079E, local_form_id=0xFF001DEE, px=1.0, py=2.0,
                             pz=3.0, rx=0.0, ry=0.0, rz=0.0, cell_id=0xDD60, flags=0,
                             timestamp_ms=0, pieces=((0x154AC5, 1, (0x1681EA,), 0.9),))
    proto._handle_world_spawn_op(session, op, NOW + 60_000)
    assert wid not in state.world_spawns
    assert state.player_inventory(PEER).lines == {(0x21B3B, FP_PLAIN): 1}


def test_leaving_before_the_respawn_gives_it_back_once(tmp_path):
    state, proto, session, store = _server(tmp_path, frame=False)
    wid, other = _wearing(state)
    proto._handle_player_life(session, PlayerLifePayload(0, (7.0, 8.0, 9.0), 10), NOW + 60_000)
    proto._reannounce_worn_frames(PEER, NOW + 61_000)
    assert state.world_spawns[wid].worn_by_peer_id == ""
    assert [addr for addr, _ in _spawns(proto)] == [other.addr]      # not to the one leaving
    proto._handle_player_life(session, PlayerLifePayload(1, (4.0, 5.0, 6.0), 10), NOW + 70_000)
    assert len(_spawns(proto)) == 1
