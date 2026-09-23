"""Global chat — server side (session lifecycle, phase 4).

The server has relayed CHAT since the first protocol, but no client ever sent
one, so the relay was never exercised. These pin what it has to guarantee
now that the native client speaks it:

  * the name on a message is the server's word, not the sender's: the
    payload carries a sender field and the relay used to forward it as is,
    so any client could speak as anyone else;
  * the sender gets its own message back, so every client shows the same
    order and a line only appears once the server has actually taken it;
  * the text is hostile input on its way to other players' screens and to
    the server log, like the display name already is;
  * one client cannot turn the relay into a flood amplifier: every message
    it sends is a reliable frame to every other peer.
"""
import sys
from pathlib import Path

_HERE = Path(__file__).resolve()
sys.path.insert(0, str(_HERE.parents[2]))
sys.path.insert(0, str(_HERE.parents[1]))

from net.protocol import (  # noqa: E402
    MessageType, encode_frame, decode_frame, HelloPayload, ChatPayload,
)
import server.main as server_main  # noqa: E402
from server.main import ServerProtocol  # noqa: E402
from server.state import ServerState  # noqa: E402


class _Xport:
    def __init__(self):
        self.sent = []

    def sendto(self, data, addr):
        self.sent.append((data, addr))


def _mkproto():
    proto = ServerProtocol(ServerState())
    proto.transport = _Xport()
    return proto


def _chats(proto, addr):
    out = []
    for data, a in proto.transport.sent:
        if a != addr:
            continue
        f = decode_frame(data)
        if f.header.msg_type == MessageType.CHAT:
            out.append(f.payload)
    return out


_SEQ: dict = {}


def _hello(proto, addr, peer):
    _SEQ[addr] = 1
    proto.datagram_received(
        encode_frame(MessageType.HELLO, 1,
                     HelloPayload(peer, 1, 0, 0), reliable=True),
        addr)


def _say(proto, addr, sender_field, text):
    """What a client puts on the wire. Bytes, never a payload object: the
    test path imports the protocol twice, and a payload object from the
    other copy fails the handler's isinstance check in silence."""
    _SEQ[addr] = _SEQ.get(addr, 1) + 1
    proto.datagram_received(
        encode_frame(MessageType.CHAT, _SEQ[addr],
                     ChatPayload(sender_field, text), reliable=True),
        addr)


A = ("127.0.0.1", 42001)
B = ("127.0.0.1", 42002)


def _two_peers():
    proto = _mkproto()
    _hello(proto, A, "player_A")
    _hello(proto, B, "player_B")
    return proto


def test_the_name_on_a_message_is_the_servers_not_the_senders():
    proto = _two_peers()
    _say(proto, A, "player_B", "ciao")       # A pretends to be B
    got = _chats(proto, B)
    assert [(c.sender_id, c.text) for c in got] == [("player_A", "ciao")], (
        "the relay forwarded the sender field the client wrote")


def test_the_sender_gets_its_own_message_back():
    proto = _two_peers()
    _say(proto, A, "player_A", "ciao")
    assert [(c.sender_id, c.text) for c in _chats(proto, A)] == [
        ("player_A", "ciao")], "the sender was left out of its own message"


def test_control_characters_never_reach_a_screen_or_the_log():
    proto = _two_peers()
    _say(proto, A, "player_A", "\x1b[2Jciao\r\nmondo\x07")
    got = _chats(proto, B)
    assert len(got) == 1
    assert got[0].text == "[2Jciao  mondo", repr(got[0].text)


def test_a_message_with_nothing_printable_is_dropped():
    proto = _two_peers()
    _say(proto, A, "player_A", " \r\n\x07\t ")
    assert _chats(proto, A) == [] and _chats(proto, B) == []


def test_a_long_message_is_cut_not_dropped():
    proto = _two_peers()
    _say(proto, A, "player_A", "x" * 500)
    got = _chats(proto, B)
    assert len(got) == 1
    assert got[0].text == "x" * server_main.CHAT_MAX_CHARS


def test_one_client_cannot_flood_everyone(monkeypatch):
    clock = [1_000_000.0]
    monkeypatch.setattr(server_main, "_now_ms", lambda: clock[0])
    proto = _two_peers()
    for i in range(server_main.CHAT_BURST + 3):
        _say(proto, A, "player_A", f"m{i}")
    assert len(_chats(proto, B)) == server_main.CHAT_BURST

    clock[0] += server_main.CHAT_WINDOW_MS + 1
    _say(proto, A, "player_A", "after the window")
    assert _chats(proto, B)[-1].text == "after the window"
