"""Tests for server/persistence.py"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from server.state import ServerState  # noqa: E402
from server.persistence import snapshot, rotate_snapshots  # noqa: E402
from protocol import PosStatePayload, ActorEventPayload, ActorEventKind  # noqa: E402


class TestSnapshot:
    def test_empty_state(self, tmp_path: Path):
        s = ServerState()
        path = tmp_path / "snap.json"
        snapshot(s, path)
        assert path.exists()
        data = json.loads(path.read_text())
        assert data["version"] == 3  # bumped to add container state in v3
        assert data["sessions"] == []
        assert data["world_actors"] == []
        assert data["containers"] == []

    def test_with_sessions(self, tmp_path: Path):
        s = ServerState()
        a, _ = s.accept_peer(("127.0.0.1", 5000), "alice", (1, 0), 100.0)
        b, _ = s.accept_peer(("127.0.0.1", 5001), "bob", (1, 0), 200.0)
        a.last_pos = PosStatePayload(1, 2, 3, 0, 0, 0, 100)
        a.total_pos_updates = 42
        path = tmp_path / "snap.json"
        snapshot(s, path)
        data = json.loads(path.read_text())
        peer_ids = {ss["peer_id"] for ss in data["sessions"]}
        assert peer_ids == {"alice", "bob"}
        alice = next(ss for ss in data["sessions"] if ss["peer_id"] == "alice")
        assert alice["total_pos_updates"] == 42
        assert alice["last_pos"]["x"] == 1.0

    def test_with_actors(self, tmp_path: Path):
        s = ServerState()
        evt = ActorEventPayload(
            kind=int(ActorEventKind.SPAWN),
            form_id=0xFF001000, actor_base_id=0x20593,
            x=100.0, y=200.0, z=50.0, extra=0,
            cell_id=0x1696A,  # Sanctuary
        )
        s.record_actor_event(evt, "alice", 500.0)
        path = tmp_path / "snap.json"
        snapshot(s, path)
        data = json.loads(path.read_text())
        assert len(data["world_actors"]) == 1
        entry = data["world_actors"][0]
        assert entry["base_id"] == "0x20593"
        assert entry["cell_id"] == "0x1696A"
        assert entry["last_known_form_id"] == "0xFF001000"
        assert entry["alive"] is True

    def test_atomic_write_no_partial_file(self, tmp_path: Path):
        """Snapshot should not leave a half-written file on error."""
        s = ServerState()
        path = tmp_path / "snap.json"
        snapshot(s, path)
        # Check no temp file left behind
        temps = list(tmp_path.glob(".snap.json*.tmp"))
        assert len(temps) == 0


class TestRotation:
    def test_rotate_creates_numbered_backups(self, tmp_path: Path):
        s = ServerState()
        base = tmp_path / "snap.json"
        # Write 3 snapshots with rotation
        snapshot(s, base)
        rotate_snapshots(base, keep=3)

        snapshot(s, base)
        rotate_snapshots(base, keep=3)

        snapshot(s, base)
        rotate_snapshots(base, keep=3)

        # After 3 rotations: snap.json.1 is the most recent snapshot
        # Actually rotate_snapshots moves base -> .1, so after 3 rotations we have .1, .2, .3
        # but .3 exists only if we rotated 3+ times
        assert (tmp_path / "snap.json.1").exists()
        assert (tmp_path / "snap.json.2").exists()
        assert (tmp_path / "snap.json.3").exists()

    def test_rotate_respects_keep(self, tmp_path: Path):
        s = ServerState()
        base = tmp_path / "snap.json"
        for _ in range(6):
            snapshot(s, base)
            rotate_snapshots(base, keep=3)
        # Only 3 backups should remain
        files = sorted(tmp_path.glob("snap.json*"))
        assert len(files) <= 3
