"""Stage 3c of L5 (2026-09-28): death without a reload.

The client resurrects its dead player and teleports it to the point the
server names, instead of letting the engine reload the last checkpoint.
The server's part is small and pinned here:

- the boot word (CKPT_BOOT, wire v32) carries the respawn point when the
  server has one, and says so when it has none; PLAYER_LIFE round-trips;
- `--respawn` takes a named point, "x,y,z[,yaw]" or off, and refuses the
  rest at startup;
- a PLAYER_LIFE report is counted by its kind and never changes the world.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from protocol import (  # noqa: E402
    MessageType, CkptBootPayload, PlayerLifePayload, PLAYER_LIFE_EVENTS, decode_frame,
)
from server.state import ServerState  # noqa: E402
from server.main import ServerProtocol, parse_respawn, RESPAWN_POINTS  # noqa: E402


def _accept(state: ServerState, peer: str, port: int, identity: str = "abc123"):
    session, reason = state.accept_peer(("127.0.0.1", port), peer, (1, 0), 0.0)
    assert session is not None, reason
    session.identity_hex = identity
    return session


class FakeTransport:
    def __init__(self):
        self.sent = []

    def sendto(self, data, addr):
        self.sent.append((addr, data))


def _boots_to(transport, addr):
    out = []
    for a, raw in transport.sent:
        if a != addr:
            continue
        frame = decode_frame(raw)
        if frame.header.msg_type == MessageType.CKPT_BOOT:
            out.append(frame.payload)
    return out


class TestWire:
    def test_the_boot_word_and_player_life_round_trip(self):
        p = CkptBootPayload(has=False, seq=0, name="", sha256=b"", size=0, digest=0,
                            has_respawn=True, respawn_pos=(-79857.5, 89852.6, 7821.7), respawn_yaw=1.25)
        raw = p.encode()
        assert len(raw) == CkptBootPayload.SIZE == 441
        q = CkptBootPayload.decode(raw)
        assert q.has_respawn is True and abs(q.respawn_yaw - 1.25) < 1e-6
        assert all(abs(a - b) < 0.01 for a, b in zip(q.respawn_pos, (-79857.5, 89852.6, 7821.7)))
        bare = CkptBootPayload.decode(CkptBootPayload(has=False, seq=0, name="", sha256=b"",
                                                      size=0, digest=0).encode())
        assert bare.has_respawn is False and bare.respawn_pos == (0.0, 0.0, 0.0)
        life = PlayerLifePayload(event=1, pos=(1.0, -2.0, 3.5), wall_ms=1_700_000_000_123)
        assert len(life.encode()) == 21
        back = PlayerLifePayload.decode(life.encode())
        assert back.event == 1 and back.pos == (1.0, -2.0, 3.5) and back.wall_ms == life.wall_ms
        assert PLAYER_LIFE_EVENTS[0] == "died" and PLAYER_LIFE_EVENTS[2] == "reload fallback"

    def test_the_boot_word_carries_the_point_or_says_none(self):
        state = ServerState()
        proto = ServerProtocol(state)
        proto.transport = FakeTransport()
        alice = _accept(state, "alice", 1)
        proto._send_checkpoint_boot(alice, 1_000.0)
        word = _boots_to(proto.transport, alice.addr)[-1]
        assert word.has_respawn is False
        proto.respawn_point = RESPAWN_POINTS["sanctuary"]
        proto._send_checkpoint_boot(alice, 2_000.0)
        word = _boots_to(proto.transport, alice.addr)[-1]
        assert word.has_respawn is True
        assert abs(word.respawn_pos[0] - RESPAWN_POINTS["sanctuary"][0]) < 0.01
        anon = _accept(state, "carol", 2, identity="")
        proto._send_checkpoint_boot(anon, 3_000.0)
        assert _boots_to(proto.transport, anon.addr)[-1].has_respawn is True   # the point is the world's, not the identity's


class TestOption:
    def test_a_name_coordinates_or_off(self):
        assert parse_respawn("sanctuary") == RESPAWN_POINTS["sanctuary"]
        assert parse_respawn("Sanctuary ") == RESPAWN_POINTS["sanctuary"]
        assert parse_respawn("1,2,3") == (1.0, 2.0, 3.0, 0.0)
        assert parse_respawn("-79857.5, 89852.6, 7821.7, 1.5") == (-79857.5, 89852.6, 7821.7, 1.5)
        assert parse_respawn("off") is None and parse_respawn("none") is None and parse_respawn("") is None
        with pytest.raises(ValueError):
            parse_respawn("vault111")
        with pytest.raises(ValueError):
            parse_respawn("1,2")
        with pytest.raises(ValueError):
            parse_respawn("1,2,nan")


class TestReports:
    def test_a_player_life_report_is_counted_and_changes_nothing(self):
        state = ServerState()
        proto = ServerProtocol(state)
        alice = _accept(state, "alice", 1)
        lsn = state.applied_lsn
        proto._handle_player_life(alice, PlayerLifePayload(0, (1.0, 2.0, 3.0), 10), 1_000.0)
        proto._handle_player_life(alice, PlayerLifePayload(1, (4.0, 5.0, 6.0), 20), 6_000.0)
        proto._handle_player_life(alice, PlayerLifePayload(0, (1.0, 2.0, 3.0), 30), 9_000.0)
        proto._handle_player_life(alice, PlayerLifePayload(2, (1.0, 2.0, 3.0), 40), 14_000.0)
        assert proto._counters["player_deaths"] == 2
        assert proto._counters["player_respawns"] == 1
        assert proto._counters["player_reload_fallbacks"] == 1
        assert state.applied_lsn == lsn
        proto._handle_player_life(alice, "not a payload", 15_000.0)   # ignored
        assert proto._counters["player_deaths"] == 2
