"""2026-10-05: the server forgets a character (tools/peer_forget.py).

The owner's decision for a spoilt save lineage: start the character over,
stock, with the creation and the genesis inventory. One journal record drops
everything the server keeps about the peer; the world keeps what the peer
put in it.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from protocol import FP_PLAIN, INV_ENTRY_EQUIPPED, INV_STATE_FLAG_COMPLETE, PosStatePayload  # noqa: E402
from server.journal import Journal  # noqa: E402
from server.persistence import load_into, snapshot  # noqa: E402
from server.state import ServerState  # noqa: E402

PEER = "fw0000000000aaa"
OTHER = "fw0000000000bbb"


def _fill(s: ServerState, peer: str, seq: int) -> None:
    s.record_player_inventory(peer, 0x1234, seq, 0, 0x12, INV_STATE_FLAG_COMPLETE, 0,
                              ((0x21B3B, FP_PLAIN, 1, INV_ENTRY_EQUIPPED),), 0.0)
    s.record_player_stats(peer, 0x1234, seq, 20, 16626.0, 3,
                          (5, 5, 5, 5, 5, 5, 5), 100.0, 80.0, 0.0, ((0x4B254, 1),), 0.0)
    s.record_appearance(peer, "v2\trecipe of %s" % peer)
    s.record_checkpoint(peer, "ab" * 16, 1, "fwck_%s_1" % peer, "cd" * 32, 9, 0, 0, 1, 1.0, 1, 0)
    s.record_presence_pos(peer, PosStatePayload(x=1.0, y=2.0, z=3.0, rx=0.0, ry=0.0, rz=0.0,
                                                timestamp_ms=0, cell_id=0xDD60), 0.0)
    s.record_inv_digest(peer, seq, 1, 0xABC, 1, 1, 1, 0, INV_STATE_FLAG_COMPLETE, 1, 0.0)


def _empty(s: ServerState, peer: str) -> bool:
    return (s.player_inventory(peer) is None and s.player_stats(peer) is None
            and s.appearance(peer) is None and s.checkpoints(peer) == []
            and s.presence(peer) is None and s.inv_digest(peer) is None)


def test_forget_drops_the_character_and_leaves_the_others_and_the_world():
    s = ServerState()
    _fill(s, PEER, 1)
    _fill(s, OTHER, 1)
    st = s.record_world_spawn(PEER, 0x2079E, 0xFF001DEE, 1.0, 2.0, 3.0, 0.0, 0.0, 0.0, 0xDD60, 0, 1)
    gone = s.forget_peer(PEER)
    assert gone["inventory record"] == 1 and gone["appearance"] == 1 and gone["checkpoints"] == 1
    assert _empty(s, PEER)
    assert not _empty(s, OTHER)
    assert st.wid in s.world_spawns and s.world_spawns[st.wid].spawner_peer == PEER
    assert s.forget_peer(PEER) == {}


def test_the_journal_and_the_snapshot_agree(tmp_path: Path):
    j = Journal.open(tmp_path / "journal")
    a = ServerState()
    a.journal = j
    _fill(a, PEER, 1)
    _fill(a, OTHER, 1)
    a.forget_peer(PEER)
    j.flush()
    j.close()
    b = ServerState()
    Journal.open(tmp_path / "journal").replay(b, after_lsn=0)
    assert _empty(b, PEER) and not _empty(b, OTHER)
    path = tmp_path / "snap.json"
    snapshot(a, path)
    c = ServerState()
    load_into(c, path)
    assert _empty(c, PEER) and not _empty(c, OTHER)


def test_the_next_hello_is_a_first_entry_with_the_creation():
    s = ServerState()
    s.require_chargen = True
    _fill(s, PEER, 1)
    s.forget_peer(PEER)
    session, reason = s.accept_peer(("127.0.0.1", 5), PEER, (1, 0), 0.0)
    assert session is not None, reason
    assert s.welcome_for(session).chargen_required
    assert s.checkpoint_to_boot(PEER) is None and s.presence(PEER) is None
