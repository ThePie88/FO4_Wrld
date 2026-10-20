"""2026-10-04: a join replays only the peers who are online.

Live test of 2026-10-04: three peers long gone (an old test id and two
superseded identities) kept their presence and their appearance in the
snapshot; every join replayed them, so every client built three ghosts that
never move and scanned their three faces every frame, 1,700 log lines a
second on one client, 500 on the other. A joiner now gets the positions,
outfits and recipes of the sessions that exist (and its own recipe); the
others get the joiner's stored recipe with its PEER_JOIN, which the
replay-everything bootstrap used to be the only source of.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from protocol import MessageType, PosStatePayload, decode_frame  # noqa: E402
from server.main import ServerProtocol  # noqa: E402
from server.state import ServerState  # noqa: E402


class FakeTransport:
    def __init__(self):
        self.sent = []

    def sendto(self, data, addr):
        self.sent.append((addr, data))


def _pos():
    return PosStatePayload(x=1.0, y=2.0, z=3.0, rx=0.0, ry=0.0, rz=0.0, timestamp_ms=0,
                           cell_id=0xDD60)


def _known(state, peer_id):
    state.record_appearance(peer_id, "v2\trecipe of %s" % peer_id)
    state.record_presence_pos(peer_id, _pos(), 0.0)


def _online(state, port, peer_id):
    session, reason = state.accept_peer(("127.0.0.1", port), peer_id, (1, 0), 0.0)
    assert session is not None, reason
    session.identity_hex = "ab" * 16
    _known(state, peer_id)
    return session


def _setup():
    state = ServerState()
    proto = ServerProtocol(state)
    proto.transport = FakeTransport()
    for gone in ("player_B", "fw697d1c84d3e62"):
        _known(state, gone)
    here = _online(state, 5, "fw0000000000aaa")
    joiner = _online(state, 6, "fw0000000000bbb")
    return state, proto, here, joiner


def test_the_bootstrap_replays_the_peers_online_and_the_joiners_own_recipe():
    state, proto, here, joiner = _setup()
    proto._send_appearance_bootstrap(joiner, 1.0)
    proto._send_presence_bootstrap(joiner, 1.0)
    recipes = sorted(p.peer_id for t, p in joiner.pending_bootstrap
                     if t == MessageType.APPEARANCE_BCAST)
    positions = sorted(p.peer_id for t, p in joiner.pending_bootstrap
                       if t == MessageType.POS_BROADCAST)
    assert recipes == ["fw0000000000aaa", "fw0000000000bbb"]
    assert positions == ["fw0000000000aaa"]


def test_the_join_carries_the_joiners_recipe_to_the_others():
    state, proto, here, joiner = _setup()
    proto._send_peer_joins(joiner, 1.0)
    got = []
    for addr, raw in proto.transport.sent:
        f = decode_frame(raw)
        if f.header.msg_type == MessageType.APPEARANCE_BCAST:
            got.append((addr, f.payload.peer_id, f.payload.recipe))
    assert got == [(here.addr, "fw0000000000bbb", "v2\trecipe of fw0000000000bbb")]


def test_a_joiner_without_a_recipe_sends_none():
    state = ServerState()
    proto = ServerProtocol(state)
    proto.transport = FakeTransport()
    here = _online(state, 5, "fw0000000000aaa")
    joiner, reason = state.accept_peer(("127.0.0.1", 6), "fw0000000000ccc", (1, 0), 0.0)
    assert joiner is not None, reason
    proto._send_peer_joins(joiner, 1.0)
    kinds = [decode_frame(raw).header.msg_type for _, raw in proto.transport.sent]
    assert MessageType.APPEARANCE_BCAST not in kinds
