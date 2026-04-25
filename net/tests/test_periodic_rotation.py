"""Tests for the fix: _periodic_snapshot now calls rotate_snapshots before each write.

Prior bug: snapshot.json was silently overwritten every interval, no history kept.
Now: existing snapshot is rotated to .1 (previous .1 to .2, etc.) before each write.
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from server.main import ServerProtocol, _periodic_snapshot  # noqa: E402
from server.state import ServerState  # noqa: E402


@pytest.mark.asyncio
async def test_periodic_snapshot_creates_rotations(tmp_path: Path):
    """After N ticks of _periodic_snapshot, expect snapshot.json + snapshot.json.1..N-1."""
    state = ServerState()
    # We don't need a real transport; use a dummy ServerProtocol
    protocol = ServerProtocol(state)

    snap_path = tmp_path / "snap.json"

    async def _run():
        # Very short interval so we complete quickly
        await _periodic_snapshot(protocol, snap_path, interval_s=0.05, rotate_keep=3)

    task = asyncio.create_task(_run())
    # Let 4 cycles run (0.2s total at 0.05s interval)
    await asyncio.sleep(0.35)
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass

    # Expect: current snap.json + up to 3 rotated (.1, .2, .3)
    assert snap_path.exists(), "current snapshot.json missing"
    assert (tmp_path / "snap.json.1").exists(), "no .1 rotation"
    # At least one rotation occurred — that alone is the fix validation


@pytest.mark.asyncio
async def test_rotate_keep_respected(tmp_path: Path):
    """Never more than keep rotated backups, regardless of how many ticks run."""
    state = ServerState()
    protocol = ServerProtocol(state)

    snap_path = tmp_path / "snap.json"

    async def _run():
        await _periodic_snapshot(protocol, snap_path, interval_s=0.02, rotate_keep=2)

    task = asyncio.create_task(_run())
    await asyncio.sleep(0.5)   # many cycles
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass

    # keep=2 means at most snap.json + .1 + .2 = 3 files
    matching = list(tmp_path.glob("snap.json*"))
    assert len(matching) <= 3, f"expected <=3 files, got {[p.name for p in matching]}"
    # Always at least the current one
    assert snap_path.exists()


@pytest.mark.asyncio
async def test_first_tick_does_not_rotate_nonexistent(tmp_path: Path):
    """No .1 created if there's never been a prior snapshot (first tick only)."""
    state = ServerState()
    protocol = ServerProtocol(state)

    snap_path = tmp_path / "fresh.json"
    # Ensure no pre-existing file
    assert not snap_path.exists()

    async def _run():
        await _periodic_snapshot(protocol, snap_path, interval_s=0.05, rotate_keep=3)

    task = asyncio.create_task(_run())
    # Only enough time for ~1 tick
    await asyncio.sleep(0.08)
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass

    assert snap_path.exists(), "first snapshot was not written"
    # No .1 should exist because we only rotated zero or one time but .1 only
    # appears after the 2nd write. Verify no spurious .1.
    assert not (tmp_path / "fresh.json.1").exists(), \
        "first tick should not create a rotation"
