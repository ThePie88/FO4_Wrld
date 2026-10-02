"""Stage 2 of L5 (2026-09-27): INV_DIGEST, the advisory digest of a player's
inventory.

The client reads its inventory once a second and reports the digest of a
COMPLETE capture when it changes, before a test checkpoint and on the way
out. The server records the last one per peer and acts on nothing: stage 3
compares a checkpoint against the record, stage 4's ledger is what will
judge an inventory. Each test here failed on the code before the message
existed, and pins one property:

- the payload is 38 bytes, round-trips through the frame codec, and a full
  64-bit digest survives;
- the handler keeps the last digest per peer with a running count, ignores
  an incomplete one, and takes at most one per second per peer;
- the record is journaled and comes back from a replay;
- the record survives the snapshot (v8) with its count, and a v7 snapshot
  without the section loads with none.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from protocol import (  # noqa: E402
    MessageType, InvDigestPayload, INV_DIGEST_FLAG_COMPLETE,
    INV_DIGEST_FLAG_IN_POWER_ARMOR, encode_frame, decode_frame,
)
from server.journal import Journal  # noqa: E402
from server.state import ServerState  # noqa: E402
from server.persistence import (  # noqa: E402
    snapshot, load_into, SNAPSHOT_FORMAT_VERSION,
)
from server.main import ServerProtocol  # noqa: E402

FULL = 0xFFFFFFFFFFFFFFFF


def _digest(seq: int = 1, digest: int = 0x1234ABCD5678EF90, flags: int = INV_DIGEST_FLAG_COMPLETE,
            why: int = 3, items: int = 62) -> InvDigestPayload:
    return InvDigestPayload(seq=seq, wall_ms=1_700_000_000_000, digest=digest, entries=6,
                            stacks=7, items=items, reasons=0, flags=flags, why=why)


def _accept(state: ServerState, peer: str, port: int):
    session, reason = state.accept_peer(("127.0.0.1", port), peer, (1, 0), 0.0)
    assert session is not None, reason
    return session


class TestCodec:
    def test_payload_is_38_bytes_and_round_trips(self):
        p = _digest(flags=INV_DIGEST_FLAG_COMPLETE | INV_DIGEST_FLAG_IN_POWER_ARMOR)
        raw = p.encode()
        assert len(raw) == 38
        assert InvDigestPayload.decode(raw) == p

    def test_a_full_64_bit_digest_survives(self):
        p = _digest(digest=FULL)
        assert InvDigestPayload.decode(p.encode()).digest == FULL

    def test_the_frame_codec_knows_the_message(self):
        p = _digest()
        raw = encode_frame(MessageType.INV_DIGEST, 7, p, reliable=True)
        frame = decode_frame(raw)
        assert frame.header.msg_type == MessageType.INV_DIGEST
        assert frame.payload == p

    def test_a_wrong_length_is_refused(self):
        try:
            InvDigestPayload.decode(b"\x00" * 37)
        except ValueError:
            return
        raise AssertionError("37 bytes decoded as a digest")


class TestHandler:
    def test_the_last_digest_per_peer_is_kept_with_a_count(self):
        state = ServerState()
        proto = ServerProtocol(state)
        alice = _accept(state, "alice", 1)
        proto._handle_inv_digest(alice, _digest(seq=1, digest=0x11), 1_000.0)
        proto._handle_inv_digest(alice, _digest(seq=2, digest=0x22, why=0), 12_000.0)
        rec = state.inv_digest("alice")
        assert rec is not None
        assert rec.seq == 2 and rec.digest == 0x22 and rec.why == 0
        assert rec.items == 62 and rec.stacks == 7 and rec.entries == 6
        assert rec.count == 2
        assert rec.received_ms == 12_000.0
        assert state.inv_digest("bob") is None

    def test_an_incomplete_digest_is_ignored(self):
        state = ServerState()
        proto = ServerProtocol(state)
        alice = _accept(state, "alice", 1)
        proto._handle_inv_digest(alice, _digest(flags=0), 1_000.0)
        assert state.inv_digest("alice") is None

    def test_at_most_one_per_second_per_peer(self):
        state = ServerState()
        proto = ServerProtocol(state)
        alice = _accept(state, "alice", 1)
        bob = _accept(state, "bob", 2)
        proto._handle_inv_digest(alice, _digest(seq=1, digest=0x11), 1_000.0)
        proto._handle_inv_digest(alice, _digest(seq=2, digest=0x22), 1_500.0)   # noise
        proto._handle_inv_digest(bob, _digest(seq=1, digest=0x33), 1_500.0)     # another peer
        proto._handle_inv_digest(alice, _digest(seq=3, digest=0x44), 2_100.0)
        assert state.inv_digest("alice").digest == 0x44
        assert state.inv_digest("alice").count == 2
        assert state.inv_digest("bob").digest == 0x33

    def test_the_dispatcher_routes_the_message(self):
        state = ServerState()
        proto = ServerProtocol(state)
        alice = _accept(state, "alice", 1)
        proto._dispatch(alice, MessageType.INV_DIGEST, _digest(digest=0x55), 1_000.0)
        assert state.inv_digest("alice").digest == 0x55


class TestJournal:
    def test_the_record_comes_back_from_a_replay(self, tmp_path: Path):
        a = ServerState()
        j = Journal.open(tmp_path / "journal")
        a.journal = j
        a.record_inv_digest("alice", 1, 5, 0x11, 6, 7, 62, 0, 1, 3, 1_000.0)
        a.record_inv_digest("alice", 2, 6, FULL, 6, 8, 63, 0, 3, 0, 2_000.0)
        j.flush()
        j.close()
        b = ServerState()
        j2 = Journal.open(tmp_path / "journal")
        n = j2.replay(b, after_lsn=0)
        j2.close()
        assert n == 2
        rec = b.inv_digest("alice")
        assert rec.digest == FULL and rec.seq == 2 and rec.flags == 3
        assert rec.count == 2
        assert rec.received_ms == 2_000.0


class TestSnapshot:
    def test_the_record_survives_the_snapshot_with_its_count(self, tmp_path: Path):
        a = ServerState()
        a.record_inv_digest("alice", 1, 5, 0x11, 6, 7, 62, 0, 1, 3, 1_000.0)
        a.record_inv_digest("alice", 2, 6, FULL, 6, 8, 63, 0, 1, 0, 2_000.0)
        snap = tmp_path / "snap.json"
        snapshot(a, snap)
        data = json.loads(snap.read_text())
        assert data["version"] == SNAPSHOT_FORMAT_VERSION >= 8   # v8 added this section, v9 (stage 3a) the checkpoints
        assert data["inv_digests"][0]["digest"] == f"0x{FULL:016X}"
        b = ServerState()
        load_into(b, snap)
        rec = b.inv_digest("alice")
        assert rec.digest == FULL and rec.seq == 2 and rec.items == 63
        assert rec.count == 2
        assert rec.received_ms == 2_000.0

    def test_a_v7_snapshot_without_the_section_loads_with_none(self, tmp_path: Path):
        snap = tmp_path / "snap.json"
        snap.write_text(json.dumps({"version": 7, "world_actors": [], "containers": []}))
        b = ServerState()
        load_into(b, snap)
        assert b.all_inv_digests() == []
