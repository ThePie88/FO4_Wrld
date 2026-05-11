"""Tests for ``server/npc_brain.py``: load + tick state machine.

B6.5w1 scope: idle waypoint patrol only. Combat / damage / death are
exercised in their own test files when those wedges land (B6.6+).
"""
from __future__ import annotations

import json
import logging
import math
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from server.npc_brain import (  # noqa: E402
    NPCBrain, NPCSpec, NPCRuntime, Waypoint, AnimState,
)


# ---------------------------------------------------------------- fixtures

def _two_npc_json(tmp_path: Path) -> Path:
    """One NPC with explicit spawn (alpha), one defaulting to first wp (beta)."""
    data = {
        "cell_name": "TestCell",
        "cell_id": "0x00001234",
        "npcs": [
            {
                "name": "alpha",
                "form_id": "0xDEAD0001",
                "base_id": "0xBEEF0001",
                "spawn": {"x": 0.0, "y": 0.0, "z": 0.0, "yaw": 0.0},
                "walk_speed_ftps": 100.0,
                "arrive_radius_ft": 1.0,
                "waypoints": [
                    {"x": 100.0, "y":   0.0, "z": 0.0, "yaw":  0.0, "dwell_s": 0.5},
                    {"x": 100.0, "y": 100.0, "z": 0.0, "yaw": 90.0, "dwell_s": 0.0},
                ],
            },
            {
                "name": "beta",
                "form_id": "0xDEAD0002",
                "base_id": "0xBEEF0001",
                "walk_speed_ftps": 50.0,
                "waypoints": [
                    {"x": 50.0, "y": 50.0, "z": 0.0},
                ],
            },
        ],
    }
    p = tmp_path / "test_cell.json"
    p.write_text(json.dumps(data), encoding="utf-8")
    return p


def _loop_npc_json(tmp_path: Path) -> Path:
    """One NPC with 3 waypoints, no dwell — for cycle-through tests."""
    data = {
        "cell_name": "LoopCell",
        "cell_id": "0x00005678",
        "npcs": [
            {
                "name": "loopr",
                "form_id": "0xDEAD0010",
                "base_id": "0xBEEF0010",
                "spawn": {"x": 0.0, "y": 0.0, "z": 0.0},
                "walk_speed_ftps": 100.0,
                "arrive_radius_ft": 1.0,
                "waypoints": [
                    {"x": 100.0, "y":   0.0, "z": 0.0, "dwell_s": 0.0},
                    {"x": 100.0, "y": 100.0, "z": 0.0, "dwell_s": 0.0},
                    {"x":   0.0, "y": 100.0, "z": 0.0, "dwell_s": 0.0},
                ],
            },
        ],
    }
    p = tmp_path / "loop.json"
    p.write_text(json.dumps(data), encoding="utf-8")
    return p


# ---------------------------------------------------------------- load

class TestLoadCell:
    def test_loads_two_npcs(self, tmp_path: Path):
        brain = NPCBrain()
        n = brain.load_cell(_two_npc_json(tmp_path))
        assert n == 2
        assert brain.count() == 2
        assert "TestCell" in brain.cells_loaded

    def test_parses_hex_ids(self, tmp_path: Path):
        brain = NPCBrain()
        brain.load_cell(_two_npc_json(tmp_path))
        a = brain.npc_for(0xDEAD0001)
        assert a is not None
        assert a.spec.form_id == 0xDEAD0001
        assert a.spec.base_id == 0xBEEF0001
        assert a.spec.cell_id == 0x1234

    def test_waypoints_parsed(self, tmp_path: Path):
        brain = NPCBrain()
        brain.load_cell(_two_npc_json(tmp_path))
        a = brain.npc_for(0xDEAD0001)
        assert a is not None
        assert len(a.spec.waypoints) == 2
        assert a.spec.waypoints[0].x == 100.0
        assert a.spec.waypoints[0].dwell_s == 0.5
        assert a.spec.waypoints[1].yaw == 90.0

    def test_explicit_spawn_used(self, tmp_path: Path):
        brain = NPCBrain()
        brain.load_cell(_two_npc_json(tmp_path))
        a = brain.npc_for(0xDEAD0001)
        assert a.pos_x == 0.0 and a.pos_y == 0.0 and a.pos_z == 0.0

    def test_default_spawn_uses_first_waypoint(self, tmp_path: Path):
        brain = NPCBrain()
        brain.load_cell(_two_npc_json(tmp_path))
        b = brain.npc_for(0xDEAD0002)
        assert b is not None
        assert b.pos_x == 50.0 and b.pos_y == 50.0 and b.pos_z == 0.0

    def test_duplicate_form_id_overwrites_with_warning(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture,
    ):
        brain = NPCBrain()
        brain.load_cell(_two_npc_json(tmp_path))
        caplog.set_level(logging.WARNING)
        brain.load_cell(_two_npc_json(tmp_path))
        assert brain.count() == 2  # not doubled
        assert any("duplicate form_id" in r.getMessage() for r in caplog.records)

    def test_initial_anim_state_is_idle(self, tmp_path: Path):
        brain = NPCBrain()
        brain.load_cell(_two_npc_json(tmp_path))
        for npc in brain.all_npcs():
            assert npc.anim_state == int(AnimState.IDLE)

    def test_real_sanctuary_mvp_json_loads(self):
        """Smoke test: the shipped MVP JSON parses cleanly.

        Real form_ids (Dogmeat, Codsworth) confirmed alive in any FO4 save
        (placed in Sanctuary/Red Rocket world cells). Coords cross-referenced
        with the local player_pos_hook log to confirm Actor+0xD0 is real
        world pos for any Actor, not just PlayerCharacter.
        """
        brain = NPCBrain()
        repo_root = Path(__file__).resolve().parents[2]
        jp = repo_root / "net" / "server" / "waypoints" / "sanctuary_mvp.json"
        if not jp.is_file():
            pytest.skip(f"waypoint JSON not present at {jp}")
        n = brain.load_cell(jp)
        assert n == 2
        assert brain.npc_for(0x0001D162) is not None  # Dogmeat
        assert brain.npc_for(0x0001CA7D) is not None  # Codsworth
        # Spawn coord sanity-check: Dogmeat at Red Rocket ish (-69k, 80k).
        dm = brain.npc_for(0x0001D162)
        assert -70000 < dm.pos_x < -68000
        assert 80000 < dm.pos_y < 82000


# ---------------------------------------------------------------- tick

class TestTickSingle:
    def test_walks_toward_waypoint(self, tmp_path: Path):
        brain = NPCBrain()
        brain.load_cell(_two_npc_json(tmp_path))
        a = brain.npc_for(0xDEAD0001)
        assert a is not None
        # speed 100 ftps × 0.1s = 10 ft toward (100, 0, 0)
        brain.tick(now_ms=100.0, dt_s=0.1)
        assert math.isclose(a.pos_x, 10.0, abs_tol=0.01)
        assert math.isclose(a.pos_y, 0.0, abs_tol=0.01)
        assert a.anim_state == int(AnimState.WALKING)
        assert a.last_change_ms == 100.0

    def test_yaw_points_at_waypoint(self, tmp_path: Path):
        brain = NPCBrain()
        brain.load_cell(_two_npc_json(tmp_path))
        a = brain.npc_for(0xDEAD0001)
        brain.tick(now_ms=100.0, dt_s=0.1)
        # atan2(0, 100) = 0
        assert math.isclose(a.yaw, 0.0, abs_tol=0.01)

    def test_arrive_snaps_and_advances_index(self, tmp_path: Path):
        brain = NPCBrain()
        brain.load_cell(_two_npc_json(tmp_path))
        a = brain.npc_for(0xDEAD0001)
        # Walk 100 ft @ 100 ftps in one tick → ends up exactly at wp0.
        brain.tick(now_ms=1000.0, dt_s=1.0)
        # Next tick: dist≈0 → arrive branch fires.
        brain.tick(now_ms=1100.0, dt_s=0.1)
        assert math.isclose(a.pos_x, 100.0, abs_tol=0.01)
        assert math.isclose(a.pos_y, 0.0, abs_tol=0.01)
        assert a.waypoint_idx == 1
        # alpha's wp0 has dwell 0.5s
        assert a.dwell_until_ms == pytest.approx(1100.0 + 500.0)
        assert a.anim_state == int(AnimState.IDLE)

    def test_dwell_holds_position(self, tmp_path: Path):
        brain = NPCBrain()
        brain.load_cell(_two_npc_json(tmp_path))
        a = brain.npc_for(0xDEAD0001)
        # Force arrival at wp0 (with dwell)
        brain.tick(now_ms=1000.0, dt_s=1.0)
        brain.tick(now_ms=1100.0, dt_s=0.1)
        assert a.dwell_until_ms > 0
        snap_x, snap_y = a.pos_x, a.pos_y
        # During dwell: tick is a no-op for movement
        brain.tick(now_ms=1200.0, dt_s=0.1)
        assert a.pos_x == snap_x and a.pos_y == snap_y
        assert a.anim_state == int(AnimState.IDLE)

    def test_dwell_expires_then_walks(self, tmp_path: Path):
        brain = NPCBrain()
        brain.load_cell(_two_npc_json(tmp_path))
        a = brain.npc_for(0xDEAD0001)
        brain.tick(now_ms=1000.0, dt_s=1.0)
        brain.tick(now_ms=1100.0, dt_s=0.1)
        assert a.dwell_until_ms == pytest.approx(1600.0)
        # Skip past dwell expiry: tick at t=2000 with dt=0.4 → walks 40 ft toward wp1 (100,100)
        brain.tick(now_ms=2000.0, dt_s=0.4)
        assert a.dwell_until_ms == 0.0
        assert a.anim_state == int(AnimState.WALKING)
        assert a.pos_y > 0.0  # moved +Y toward wp1

    def test_no_waypoints_stays_idle(self):
        """An NPC built with empty waypoints tuple should never leave IDLE."""
        brain = NPCBrain()
        spec = NPCSpec(
            form_id=0x1, base_id=0x2, cell_id=0x3,
            name="empty", waypoints=(),
        )
        npc = NPCRuntime(spec=spec, pos_x=10.0, pos_y=20.0, pos_z=30.0)
        npc.anim_state = int(AnimState.WALKING)  # provoke a transition
        brain.npcs[spec.form_id] = npc
        brain.tick(now_ms=100.0, dt_s=0.1)
        assert npc.pos_x == 10.0  # didn't move
        assert npc.anim_state == int(AnimState.IDLE)


class TestTickLoop:
    def test_visits_all_waypoints_and_loops(self, tmp_path: Path):
        brain = NPCBrain()
        brain.load_cell(_loop_npc_json(tmp_path))
        a = brain.npc_for(0xDEAD0010)
        assert a is not None
        visited: set[int] = set()
        last_idx = a.waypoint_idx
        # 30 seconds simulated at 10 Hz: 300 ticks. Plenty for many full loops.
        for i in range(300):
            brain.tick(now_ms=1000.0 + i * 100, dt_s=0.1)
            if a.waypoint_idx != last_idx:
                visited.add(last_idx)
                last_idx = a.waypoint_idx
        assert visited == {0, 1, 2}

    def test_returns_count_ticked(self, tmp_path: Path):
        brain = NPCBrain()
        brain.load_cell(_two_npc_json(tmp_path))
        n = brain.tick(now_ms=100.0, dt_s=0.1)
        assert n == 2

    def test_negative_dt_clamped_to_zero(self, tmp_path: Path):
        brain = NPCBrain()
        brain.load_cell(_two_npc_json(tmp_path))
        a = brain.npc_for(0xDEAD0001)
        assert a is not None
        # Negative dt shouldn't move the NPC backwards.
        brain.tick(now_ms=100.0, dt_s=-1.0)
        assert a.pos_x == 0.0

    def test_arrive_no_dwell_keeps_walking_state(self, tmp_path: Path):
        """Passthrough at a no-dwell waypoint must NOT flicker anim to IDLE.

        Visual-only concern for w3 (client), but cheap to lock in here so
        the receiver's anim-graph variable churn is minimized.
        """
        brain = NPCBrain()
        brain.load_cell(_loop_npc_json(tmp_path))
        a = brain.npc_for(0xDEAD0010)
        assert a is not None
        # Tick 1: walk 100 ft to land exactly on wp0.
        brain.tick(now_ms=100.0, dt_s=1.0)
        assert a.anim_state == int(AnimState.WALKING)
        # Tick 2: arrive at wp0 (no dwell), advance to wp1.
        brain.tick(now_ms=200.0, dt_s=0.1)
        assert a.waypoint_idx == 1
        # Anim still WALKING (no flicker), no dwell timer set.
        assert a.anim_state == int(AnimState.WALKING)
        assert a.dwell_until_ms == 0.0
