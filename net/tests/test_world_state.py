"""Tests for WorldStatePayload roundtrip + chunk semantics + persistence load."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from protocol import (  # noqa: E402
    MessageType, WorldStatePayload, WorldActorEntry,
    encode_frame, decode_frame, ProtocolError,
)
from server.state import ServerState, ActorWorldState  # noqa: E402
from server.persistence import snapshot, load_into  # noqa: E402
from protocol import ActorEventPayload, ActorEventKind  # noqa: E402


# ------------------------------------------------------------------ Payload roundtrip

class TestWorldStatePayloadRoundtrip:
    def test_empty(self):
        p = WorldStatePayload(entries=(), chunk_index=0, total_chunks=1)
        assert WorldStatePayload.decode(p.encode()) == p

    def test_single_entry(self):
        p = WorldStatePayload(
            entries=(WorldActorEntry(form_id=0xFF001234, alive=True),),
        )
        d = WorldStatePayload.decode(p.encode())
        assert d.entries[0].form_id == 0xFF001234
        assert d.entries[0].alive is True

    def test_mixed_alive_dead(self):
        entries = tuple(
            WorldActorEntry(form_id=0xFF000000 + i, alive=(i % 2 == 0))
            for i in range(10)
        )
        p = WorldStatePayload(entries=entries, chunk_index=2, total_chunks=5)
        d = WorldStatePayload.decode(p.encode())
        assert d.chunk_index == 2
        assert d.total_chunks == 5
        assert len(d.entries) == 10
        for orig, dec in zip(entries, d.entries):
            assert orig == dec

    def test_max_entries_encodable(self):
        """The documented maximum should fit within MAX_PAYLOAD_SIZE."""
        n = WorldStatePayload.MAX_ENTRIES_PER_FRAME
        entries = tuple(
            WorldActorEntry(form_id=i, alive=True) for i in range(n)
        )
        p = WorldStatePayload(entries=entries)
        raw = p.encode()
        # Must fit within protocol payload bound
        from protocol import MAX_PAYLOAD_SIZE
        assert len(raw) <= MAX_PAYLOAD_SIZE

    def test_over_max_rejected(self):
        n = WorldStatePayload.MAX_ENTRIES_PER_FRAME + 1
        entries = tuple(
            WorldActorEntry(form_id=i, alive=True) for i in range(n)
        )
        p = WorldStatePayload(entries=entries)
        with pytest.raises(ProtocolError, match="too many entries"):
            p.encode()

    def test_truncated_decode_rejected(self):
        with pytest.raises(ProtocolError):
            WorldStatePayload.decode(b"\x00")  # < 6-byte header

    def test_frame_wire(self):
        """Full frame encoding/decoding with WORLD_STATE msg type."""
        p = WorldStatePayload(
            entries=(
                WorldActorEntry(form_id=0x1CA7D, alive=False),
                WorldActorEntry(form_id=0xFF001345, alive=True),
            ),
            chunk_index=0, total_chunks=1,
        )
        raw = encode_frame(MessageType.WORLD_STATE, seq=42, payload=p, reliable=True)
        frame = decode_frame(raw)
        assert frame.header.msg_type == MessageType.WORLD_STATE
        assert frame.header.is_reliable
        assert isinstance(frame.payload, WorldStatePayload)
        assert frame.payload.entries[0].form_id == 0x1CA7D
        assert frame.payload.entries[0].alive is False


# ------------------------------------------------------------------ Persistence load

class TestPersistenceLoad:
    def test_roundtrip_empty_state(self, tmp_path: Path):
        """Snapshot then load empty ServerState."""
        src = ServerState()
        path = tmp_path / "snap.json"
        snapshot(src, path)
        dst = ServerState()
        n = load_into(dst, path)
        assert n == 0
        assert dst.all_actors() == []

    def test_restores_world_actors(self, tmp_path: Path):
        src = ServerState()
        # Two DIFFERENT identities (same base can repeat in different cells).
        e1 = ActorEventPayload(
            kind=int(ActorEventKind.SPAWN), form_id=0xFF001000,
            actor_base_id=0x20593, x=0, y=0, z=0, extra=0,
            cell_id=0x1696A,   # Sanctuary
        )
        src.record_actor_event(e1, "alice", 100.0)
        e2 = ActorEventPayload(
            kind=int(ActorEventKind.KILL), form_id=0xFF001001,
            actor_base_id=0x20593, x=0, y=0, z=0, extra=0,
            cell_id=0x2F1C3,   # Diamond City (different cell -> different entry)
        )
        src.record_actor_event(e2, "bob", 200.0)

        path = tmp_path / "snap.json"
        snapshot(src, path)

        dst = ServerState()
        n = load_into(dst, path)
        assert n == 2
        a1 = dst.actor_state(0x20593, 0x1696A)
        a2 = dst.actor_state(0x20593, 0x2F1C3)
        assert a1 is not None and a1.alive is True
        assert a2 is not None and a2.alive is False

    def test_restores_server_config(self, tmp_path: Path):
        src = ServerState(tick_rate_hz=42, peer_timeout_ms=7_777.0)
        path = tmp_path / "snap.json"
        snapshot(src, path)

        dst = ServerState()  # defaults differ
        load_into(dst, path)
        assert dst.tick_rate_hz == 42
        assert dst.peer_timeout_ms == 7_777.0

    def test_missing_file_raises(self, tmp_path: Path):
        with pytest.raises(FileNotFoundError):
            load_into(ServerState(), tmp_path / "nonexistent.json")

    def test_bad_version_rejected(self, tmp_path: Path):
        path = tmp_path / "bad.json"
        path.write_text(json.dumps({"version": 99, "world_actors": []}))
        with pytest.raises(ValueError, match="version"):
            load_into(ServerState(), path)

    def test_malformed_json_rejected(self, tmp_path: Path):
        path = tmp_path / "broken.json"
        path.write_text("not json at all {{{{")
        with pytest.raises(ValueError, match="malformed"):
            load_into(ServerState(), path)

    def test_does_not_restore_sessions(self, tmp_path: Path):
        """Sessions are ephemeral — must NOT be resurrected from snapshot."""
        src = ServerState()
        src.accept_peer(("1.2.3.4", 5000), "alice", (1, 0), 100.0)
        path = tmp_path / "snap.json"
        snapshot(src, path)

        dst = ServerState()
        load_into(dst, path)
        assert dst.get_by_peer_id("alice") is None
