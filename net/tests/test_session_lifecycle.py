"""Session lifecycle, phase 0 (wire v26) — server side.

What these cover, and why each one exists:

  * a client that dropped can come back with its resume token, without the
    launcher, because the launcher's login proof is single use;
  * a HELLO landing on an address the server still thinks is busy is a
    relaunch, not a retransmit — before v26 that case deadlocked forever;
  * displacing a session tells everyone, instead of leaving the departed
    peer owning NPCs and standing in everybody's world;
  * a peer joining long after the others is shown where they are and what
    they wear;
  * power armour a peer is wearing survives that peer disappearing.
"""
import sys
from pathlib import Path

_HERE = Path(__file__).resolve()
sys.path.insert(0, str(_HERE.parents[2]))
sys.path.insert(0, str(_HERE.parents[1]))

from net.protocol import (  # noqa: E402
    MessageType, RejectCode, encode_frame, decode_frame,
    HelloPayload, HelloResumePayload, WelcomePayload,
    PeerJoinPayload, PeerLeavePayload,
    PosStatePayload, PosBroadcastPayload,
    EquipOpPayload, EquipBroadcastPayload, EquipOpKind, EquipModRecord,
    WorldSpawnOpPayload, WorldSpawnBroadcastPayload,
    WorldDespawnOpPayload,
)
from server.main import ServerProtocol  # noqa: E402
from server.state import ServerState, OutfitEntry  # noqa: E402

PA_FRAME_BASE = 0x0002079E


class _Xport:
    def __init__(self):
        self.sent = []

    def sendto(self, data, addr):
        self.sent.append((data, addr))


def _mkproto(**state_kw):
    proto = ServerProtocol(ServerState(**state_kw))
    proto.transport = _Xport()
    return proto


def _frames(proto, addr, msg_type):
    out = []
    for data, a in proto.transport.sent:
        if a != addr:
            continue
        f = decode_frame(data)
        if f.header.msg_type == msg_type:
            out.append(f.payload)
    return out


_SEQ: dict = {}


def _hello(proto, addr, peer, seq=1):
    _SEQ[addr] = seq
    proto.datagram_received(
        encode_frame(MessageType.HELLO, seq,
                     HelloPayload(peer, 1, 0, 0), reliable=True),
        addr)


def _op(proto, addr, msg_type, payload):
    """Everything a client says must go in as BYTES.

    `net.protocol` and `protocol` are two different module objects under the
    test path, so their payload classes are different types: handing a
    payload object straight to a handler makes its isinstance check fail in
    silence. Going through the wire is also what a client actually does.
    """
    _SEQ[addr] = _SEQ.get(addr, 1) + 1
    proto.datagram_received(
        encode_frame(msg_type, _SEQ[addr], payload, reliable=True), addr)


def _welcome(proto, addr) -> WelcomePayload:
    return _frames(proto, addr, MessageType.WELCOME)[-1]


def _drain(proto, now_ms=0.0):
    """Hand the queued bootstrap frames to the socket.

    The bootstrap is paced across ticks on purpose (a burst wider than the
    32-frame receive window used to be silently truncated and could kill the
    channel of the peer that had just joined), so a test that wants to see
    those frames has to tick the server.
    """
    for _ in range(40):
        for session in proto.state.all_sessions():
            proto._drain_bootstrap(session, now_ms)


# ------------------------------------------------------------ resume token

def test_welcome_carries_a_resume_token():
    proto = _mkproto()
    addr = ("127.0.0.1", 41001)
    _hello(proto, addr, "player_A")
    w = _welcome(proto, addr)
    assert w.accepted
    assert len(w.resume_token) == 32
    assert w.reject_code == RejectCode.NONE


def test_resume_rejoins_from_a_different_port():
    """The crash-and-relaunch case: same identity, new UDP socket, and no
    fresh proof from the launcher because that proof was single use."""
    proto = _mkproto()
    a1 = ("127.0.0.1", 41002)
    _hello(proto, a1, "player_A")
    token = _welcome(proto, a1).resume_token

    a2 = ("127.0.0.1", 41003)
    proto.datagram_received(
        encode_frame(MessageType.HELLO_RESUME, 1,
                     HelloResumePayload("player_A", token, 1, 0),
                     reliable=True),
        a2)
    w2 = _welcome(proto, a2)
    assert w2.accepted
    sess = proto.state.get_by_addr(a2)
    assert sess is not None and sess.peer_id == "player_A"
    # the old session is gone, not duplicated
    assert proto.state.get_by_addr(a1) is None
    assert len(proto.state.all_sessions()) == 1


def test_resume_token_is_single_use():
    proto = _mkproto()
    a1 = ("127.0.0.1", 41004)
    _hello(proto, a1, "player_A")
    token = _welcome(proto, a1).resume_token

    a2 = ("127.0.0.1", 41005)
    proto.datagram_received(
        encode_frame(MessageType.HELLO_RESUME, 1,
                     HelloResumePayload("player_A", token, 1, 0), reliable=True),
        a2)
    assert _welcome(proto, a2).accepted
    # the same token again, from somewhere else: refused
    a3 = ("127.0.0.1", 41006)
    proto.datagram_received(
        encode_frame(MessageType.HELLO_RESUME, 1,
                     HelloResumePayload("player_A", token, 1, 0), reliable=True),
        a3)
    w3 = _welcome(proto, a3)
    assert not w3.accepted
    assert w3.reject_code == RejectCode.RESUME_UNKNOWN


def test_resume_with_an_unknown_token_is_refused_with_a_reason():
    proto = _mkproto()
    addr = ("127.0.0.1", 41007)
    proto.datagram_received(
        encode_frame(MessageType.HELLO_RESUME, 1,
                     HelloResumePayload("player_A", b"\x09" * 32, 1, 0),
                     reliable=True),
        addr)
    w = _welcome(proto, addr)
    assert not w.accepted and w.reject_code == RejectCode.RESUME_UNKNOWN
    assert proto.state.get_by_addr(addr) is None


def test_expired_resume_token_is_refused():
    st = ServerState()
    proto = ServerProtocol(st)
    proto.transport = _Xport()
    addr = ("127.0.0.1", 41008)
    _hello(proto, addr, "player_A")
    sess = st.get_by_addr(addr)
    token = st.issue_resume_token(sess, now_ms=0.0, ttl_s=1.0)
    ticket, reason = st.consume_resume_token(token, now_ms=5_000.0)
    assert ticket is None and reason == "resume_expired"


# ------------------------------------------------- relaunch on the same port

def test_hello_on_a_live_address_is_treated_as_a_relaunch():
    """The deadlock v26 fixes: the relaunched client's own HELLO kept its
    zombie session alive, and the HELLO was then discarded as already
    handled, so the join could never succeed."""
    proto = _mkproto()
    addr = ("127.0.0.1", 41009)
    _hello(proto, addr, "player_A")
    first = proto.state.get_by_addr(addr)
    assert first is not None

    # same address, well past the handshake retransmit window
    later = proto._HELLO_RELAUNCH_GRACE_MS + 1_000.0
    proto._handle_incoming(
        encode_frame(MessageType.HELLO, 1, HelloPayload("player_A", 1, 0, 0),
                     reliable=True),
        addr, first.joined_at_ms + later)
    second = proto.state.get_by_addr(addr)
    assert second is not None
    assert second.session_id != first.session_id, "the old session survived"


def test_hello_retransmit_inside_the_grace_does_not_evict():
    proto = _mkproto()
    addr = ("127.0.0.1", 41010)
    _hello(proto, addr, "player_A")
    first = proto.state.get_by_addr(addr)
    _hello(proto, addr, "player_A", seq=1)   # the client's own retransmit
    assert proto.state.get_by_addr(addr).session_id == first.session_id


def test_displacing_a_session_tells_the_other_peers():
    """Both eviction branches used to drop a session in silence: its NPCs
    stayed owned by a peer that no longer existed and its ghost stood in
    everybody's world forever."""
    proto = _mkproto()
    watcher = ("127.0.0.1", 41011)
    _hello(proto, watcher, "watcher")
    victim = ("127.0.0.1", 41012)
    _hello(proto, victim, "player_A")

    before = len(_frames(proto, watcher, MessageType.PEER_LEAVE))
    sess = proto.state.get_by_addr(victim)
    proto._handle_incoming(
        encode_frame(MessageType.HELLO, 1, HelloPayload("player_A", 1, 0, 0),
                     reliable=True),
        victim, sess.joined_at_ms + proto._HELLO_RELAUNCH_GRACE_MS + 1_000.0)
    leaves = _frames(proto, watcher, MessageType.PEER_LEAVE)
    assert len(leaves) == before + 1
    assert leaves[-1].peer_id == "player_A"


# -------------------------------------------------------------- presence

def test_peer_join_carries_the_display_name():
    proto = _mkproto()
    a1 = ("127.0.0.1", 41013)
    _hello(proto, a1, "player_A")
    proto.state.get_by_addr(a1).display_name = "Filippo"
    proto.state.record_presence_name("player_A", "Filippo", 0.0)
    a2 = ("127.0.0.1", 41014)
    _hello(proto, a2, "player_B")
    joins = [p for p in _frames(proto, a2, MessageType.PEER_JOIN)
             if p.peer_id == "player_A"]
    assert joins and joins[-1].display_name == "Filippo"


def test_late_joiner_is_shown_where_the_others_are_and_what_they_wear():
    """The whole point of presence: before v26 a peer joining hours later
    saw everyone naked at the origin until they happened to move or change
    clothes."""
    proto = _mkproto()
    a1 = ("127.0.0.1", 41015)
    _hello(proto, a1, "player_A")
    st = proto.state
    st.record_presence_pos(
        "player_A",
        PosStatePayload(x=100.0, y=200.0, z=300.0, rx=0.0, ry=0.0, rz=1.5,
                        timestamp_ms=1234, cell_id=0x1E5B),
        now_ms=10.0)
    st.record_presence_equip(
        "player_A",
        OutfitEntry(item_form_id=0x1F, slot_form_id=0, count=1,
                    effective_priority=7, mods=(), timestamp_ms=99),
        equipped=True, now_ms=11.0)

    a2 = ("127.0.0.1", 41016)
    _hello(proto, a2, "player_B")
    _drain(proto)

    poses = _frames(proto, a2, MessageType.POS_BROADCAST)
    assert poses and poses[-1].peer_id == "player_A"
    assert (poses[-1].x, poses[-1].y, poses[-1].z) == (100.0, 200.0, 300.0)
    assert poses[-1].cell_id == 0x1E5B

    equips = _frames(proto, a2, MessageType.EQUIP_BCAST)
    assert equips and equips[-1].peer_id == "player_A"
    assert equips[-1].item_form_id == 0x1F
    assert equips[-1].kind == EquipOpKind.EQUIP
    assert equips[-1].effective_priority == 7


def test_a_rejoining_peer_is_announced_to_those_already_here():
    """The mirror, and the reason the ghost was dressed once and naked after.

    The presence bootstrap answers "what do the others look like" for a
    joiner. Nothing answered "what does the joiner look like" for the
    others, so the peer already in the world kept a ghost it had dressed
    from its OWN join bootstrap and never heard about that outfit again.
    The OMOD list has to ride along: attaching an armour without its mods
    is what made the rebuilt ghost come back wrong.
    """
    proto = _mkproto()
    a1 = ("127.0.0.1", 41031)
    _hello(proto, a1, "player_A")

    st = proto.state
    st.record_presence_equip(
        "player_B",
        OutfitEntry(item_form_id=0x1EED7, slot_form_id=0, count=1,
                    effective_priority=3, mods=(EquipModRecord(0x18E59C, 0, 1, 0),), timestamp_ms=42),
        equipped=True, now_ms=5.0)

    before = len(_frames(proto, a1, MessageType.EQUIP_BCAST))
    a2 = ("127.0.0.1", 41032)
    _hello(proto, a2, "player_B")
    _drain(proto)

    to_a = _frames(proto, a1, MessageType.EQUIP_BCAST)[before:]
    assert to_a, "the peer already here was told nothing about the joiner"
    assert to_a[-1].peer_id == "player_B"
    assert to_a[-1].item_form_id == 0x1EED7
    assert to_a[-1].kind == EquipOpKind.EQUIP
    assert len(to_a[-1].mods) == 1, "the OMOD list must ride along"
    assert to_a[-1].mods[0].form_id == 0x18E59C


def test_leaving_gives_the_power_armour_back_to_the_world_and_takes_it_off_you():
    """La regola: indosso a qualcuno OPPURE oggetto del mondo, mai le due.

    Il telaio torna gia' nel mondo all'ultima posizione di chi se n'e'
    andato. Quello che mancava e' il rovescio: le stesse piastre devono
    USCIRE dal vestito memorizzato, o il server le rigioca a ogni ingresso e
    veste il ghost con una power armor che quel giocatore non ha addosso da
    un'ora — e ogni pezzo fasullo retargeta lo scheletro condiviso al bind
    della PA, che e' cio' che stirava il corpo.
    """
    proto = _mkproto()
    a1 = ("127.0.0.1", 41041)
    _hello(proto, a1, "player_A")
    a2 = ("127.0.0.1", 41042)
    _hello(proto, a2, "player_B")

    st = proto.state
    # player_B indossa il telaio, e il suo vestito porta le piastre + la tuta.
    for fid in (0x154AC7, 0x154AC8, 0x3E577, 0x1EED7):
        st.record_presence_equip(
            "player_B",
            OutfitEntry(item_form_id=fid, slot_form_id=0, count=1,
                        effective_priority=0, mods=(), timestamp_ms=7),
            equipped=True, now_ms=5.0)

    wid = _spawn_frame(proto, a2, "player_B")
    ws = st.world_spawns[wid]
    ws.pieces = ((0x154AC7, 1, (), 1.0), (0x154AC8, 1, (), 1.0))
    ws.worn_by_peer_id = "player_B"
    ws.worn_since_ms = 6.0

    proto._remove_and_notify(st.get_by_addr(a2), reason=1, now_ms=99.0)

    outfit = st.presence("player_B").outfit
    assert 0x154AC7 not in outfit, "una piastra e' rimasta addosso al peer"
    assert 0x154AC8 not in outfit, "una piastra e' rimasta addosso al peer"
    assert 0x3E577 not in outfit, "l'esoscheletro e' rimasto addosso al peer"
    assert 0x1EED7 in outfit, "la tuta non c'entra col telaio e deve restare"
    assert st.world_spawns[wid].worn_by_peer_id == ""


def test_a_joiner_with_no_stored_outfit_announces_nothing():
    """A peer the server has never seen wear anything must not produce an
    empty EQUIP_BCAST: the receiver would queue an attach for form 0."""
    proto = _mkproto()
    a1 = ("127.0.0.1", 41033)
    _hello(proto, a1, "player_A")
    before = len(_frames(proto, a1, MessageType.EQUIP_BCAST))
    a2 = ("127.0.0.1", 41034)
    _hello(proto, a2, "player_B")
    _drain(proto)
    assert len(_frames(proto, a1, MessageType.EQUIP_BCAST)) == before


def test_unequip_removes_the_item_from_the_stored_outfit():
    st = ServerState()
    entry = OutfitEntry(0x1F, 0, 1, 0)
    st.record_presence_equip("p", entry, equipped=True, now_ms=1.0)
    assert 0x1F in st.presence("p").outfit
    st.record_presence_equip("p", entry, equipped=False, now_ms=2.0)
    assert 0x1F not in st.presence("p").outfit


# ------------------------------------------------------- worn power armour

def _spawn_frame(proto, addr, peer, now_ms=0.0) -> int:
    _op(proto, addr, MessageType.WORLD_SPAWN_OP, WorldSpawnOpPayload(
        local_form_id=0xFF001234, base_form_id=PA_FRAME_BASE,
        px=10.0, py=20.0, pz=30.0, rx=0.0, ry=0.0, rz=0.0,
        cell_id=0x1E5B, flags=0, timestamp_ms=int(now_ms),
        pieces=((0xAA, 1, (), 1.0),),
    ))
    assert proto.state.world_spawns, "the spawn never reached the server"
    return max(proto.state.world_spawns)


def _despawn(proto, addr, wid, reason):
    _op(proto, addr, MessageType.WORLD_DESPAWN_OP,
        WorldDespawnOpPayload(wid=wid, reason=reason, timestamp_ms=0))


def test_entering_power_armour_marks_the_frame_instead_of_deleting_it():
    proto = _mkproto()
    addr = ("127.0.0.1", 41017)
    _hello(proto, addr, "player_A")
    wid = _spawn_frame(proto, addr, "player_A")
    _despawn(proto, addr, wid, reason=2)
    st = proto.state.world_spawns.get(wid)
    assert st is not None, "the frame was deleted, so the wearer's armour is lost"
    assert st.worn_by_peer_id == "player_A"
    assert st.pieces, "the piece ledger went with it"


def test_a_real_despawn_still_deletes():
    proto = _mkproto()
    addr = ("127.0.0.1", 41018)
    _hello(proto, addr, "player_A")
    wid = _spawn_frame(proto, addr, "player_A")
    _despawn(proto, addr, wid, reason=1)
    assert wid not in proto.state.world_spawns


def test_a_worn_frame_comes_back_when_its_wearer_disappears():
    proto = _mkproto()
    wearer = ("127.0.0.1", 41019)
    _hello(proto, wearer, "player_A")
    watcher = ("127.0.0.1", 41020)
    _hello(proto, watcher, "watcher")

    wid = _spawn_frame(proto, wearer, "player_A")
    proto.state.record_presence_pos(
        "player_A",
        PosStatePayload(x=777.0, y=888.0, z=999.0, rx=0.0, ry=0.0, rz=0.0,
                        timestamp_ms=1, cell_id=0x1E5B),
        now_ms=50.0)
    _despawn(proto, wearer, wid, reason=2)

    proto._remove_and_notify(proto.state.get_by_addr(wearer),
                             reason=1, now_ms=200.0)

    spawns = [p for p in _frames(proto, watcher, MessageType.WORLD_SPAWN_BCAST)
              if p.wid == wid]
    assert spawns, "the frame was never handed back"
    assert (spawns[-1].px, spawns[-1].py, spawns[-1].pz) == (777.0, 888.0, 999.0)
    assert proto.state.world_spawns[wid].worn_by_peer_id == ""


def test_a_worn_frame_is_not_placed_for_a_joining_peer():
    proto = _mkproto()
    wearer = ("127.0.0.1", 41021)
    _hello(proto, wearer, "player_A")
    wid = _spawn_frame(proto, wearer, "player_A")
    _despawn(proto, wearer, wid, reason=2)

    joiner = ("127.0.0.1", 41022)
    _hello(proto, joiner, "player_B")
    _drain(proto)
    placed = [p for p in _frames(proto, joiner, MessageType.WORLD_SPAWN_BCAST)
              if p.wid == wid]
    assert not placed, "an empty suit was placed next to the player inside it"


# ---------------------------------------------------------------- heartbeat

def test_heartbeat_is_answered():
    """The client had no way to notice the SERVER had died: it kept talking
    into a void with a frozen ghost and no signal."""
    from net.protocol import HeartbeatPayload
    proto = _mkproto()
    addr = ("127.0.0.1", 41023)
    _hello(proto, addr, "player_A")
    before = len(_frames(proto, addr, MessageType.HEARTBEAT))
    proto.datagram_received(
        encode_frame(MessageType.HEARTBEAT, 2, HeartbeatPayload(timestamp_ms=7),
                     reliable=False),
        addr)
    assert len(_frames(proto, addr, MessageType.HEARTBEAT)) == before + 1


# ---- the three holes the live test of 2026-09-18 exposed --------------
#
# The happy path worked, which is exactly why these went unnoticed: all
# three only show up when a wearer CRASHES, which is the one case the
# feature exists for.

def test_a_timeout_also_gives_the_power_armour_back():
    """A player who crashes or closes the game sends no DISCONNECT: they
    stop talking and are evicted by the timeout sweep. The first version of
    this only ran on the graceful paths, so it missed its own use case."""
    proto = _mkproto()
    wearer = ("127.0.0.1", 41030)
    _hello(proto, wearer, "player_A")
    watcher = ("127.0.0.1", 41031)
    _hello(proto, watcher, "watcher")

    wid = _spawn_frame(proto, wearer, "player_A")
    proto.state.record_presence_pos(
        "player_A",
        PosStatePayload(x=5.0, y=6.0, z=7.0, rx=0.0, ry=0.0, rz=0.0,
                        timestamp_ms=1, cell_id=0x1E5B),
        now_ms=10.0)
    _despawn(proto, wearer, wid, reason=2)
    assert proto.state.world_spawns[wid].worn_by_peer_id == "player_A"

    sess = proto.state.get_by_addr(wearer)
    proto.tick(now_ms=sess.last_seen_ms + proto.state.peer_timeout_ms + 1_000.0)

    assert proto.state.get_by_addr(wearer) is None, "the peer was not evicted"
    assert proto.state.world_spawns[wid].worn_by_peer_id == "", \
        "the frame is still marked worn, so nobody was told it is back"


def test_leaving_power_armour_supersedes_the_worn_record():
    """The exit is announced as a NEW spawn. Without this the old record
    stayed marked for the life of the server and would have been handed back
    as a SECOND frame on the next disconnect."""
    proto = _mkproto()
    addr = ("127.0.0.1", 41032)
    _hello(proto, addr, "player_A")
    worn = _spawn_frame(proto, addr, "player_A")
    _despawn(proto, addr, worn, reason=2)
    fresh = _spawn_frame(proto, addr, "player_A")

    assert fresh != worn
    assert worn not in proto.state.world_spawns, "two records for one frame"
    assert proto.state.world_spawns[fresh].worn_by_peer_id == ""


def test_worn_state_survives_a_server_restart():
    """Otherwise the bootstrap places an empty suit of power armour in the
    world, next to the player standing inside it."""
    import tempfile
    from pathlib import Path
    from server.persistence import snapshot, load_into

    proto = _mkproto()
    addr = ("127.0.0.1", 41033)
    _hello(proto, addr, "player_A")
    wid = _spawn_frame(proto, addr, "player_A")
    _despawn(proto, addr, wid, reason=2)

    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "snap.json"
        snapshot(proto.state, path)
        fresh = ServerState()
        load_into(fresh, path)

    assert fresh.world_spawns[wid].worn_by_peer_id == "player_A"
