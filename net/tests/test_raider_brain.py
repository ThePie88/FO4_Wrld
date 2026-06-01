"""Tests for ``server/raider_brain.py``: combat state machine.

B6.6w0 scope: pure compute brain. Target selection, hysteresis, fire
cooldown, aim point, damage application, per-peer payload projection.

These tests do NOT touch the wire (proto v15 is a separate wedge); they
just verify the brain produces the right ``NPCRuntime`` mutations + the
right per-peer override dicts.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from server.npc_brain import (  # noqa: E402
    AggroState, AnimState, NPCRuntime, NPCSpec, Waypoint,
)
from server.raider_brain import (  # noqa: E402
    AIM_VERTICAL_OFFSET_FT,
    LOCAL_PLAYER_FORM_ID,
    RaiderBrain,
    RaiderCombatSpec,
)


# ---------------------------------------------------------------- fixtures

def _make_runtime(
    form_id: int = 0xDEAD0001,
    x: float = 0.0, y: float = 0.0, z: float = 0.0,
) -> NPCRuntime:
    """Bare-bones NPCRuntime suitable for brain registration. We don't
    need waypoints — combat brain ignores them (movement is server's
    business once we layer pathing on top in a later wedge).
    """
    spec = NPCSpec(
        form_id=form_id,
        base_id=0xBEEF0001,
        cell_id=0x12345,
        name=f"raider_{form_id:X}",
        waypoints=(),
    )
    return NPCRuntime(spec=spec, pos_x=x, pos_y=y, pos_z=z)


def _make_spec(**kw) -> RaiderCombatSpec:
    """Build a spec overriding any default. Tight cooldown by default so
    tests don't have to advance time by full vanilla 800 ms.
    """
    base = dict(
        detection_range_ft=1000.0,
        weapon_range_ft=500.0,
        fire_cooldown_ms=100.0,
        swap_hysteresis_ft=50.0,
        target_loss_ms=300.0,
        alert_window_ms=500.0,
    )
    base.update(kw)
    return RaiderCombatSpec(**base)


# ---------------------------------------------------------------- registration

class TestLoad:
    def test_load_one(self):
        brain = RaiderBrain()
        rt = _make_runtime()
        brain.load_runtime(rt, _make_spec())
        assert brain.count() == 1
        assert brain.raider_for(rt.spec.form_id) is not None

    def test_duplicate_overwrites(self, caplog):
        brain = RaiderBrain()
        rt1 = _make_runtime()
        rt2 = _make_runtime()
        brain.load_runtime(rt1, _make_spec())
        brain.load_runtime(rt2, _make_spec())
        assert brain.count() == 1

    def test_load_from_json_dict(self):
        brain = RaiderBrain()
        rt = _make_runtime()
        brain.load_from_json_dict(
            {
                "name": "x",
                "form_id": "0xDEAD0001",
                "combat": {
                    "weapon_range_ft": 1234.0,
                    "fire_cooldown_ms": 250.0,
                },
            },
            rt,
        )
        r = brain.raider_for(rt.spec.form_id)
        assert r.spec.weapon_range_ft == 1234.0
        assert r.spec.fire_cooldown_ms == 250.0

    def test_load_from_json_uses_defaults(self):
        brain = RaiderBrain()
        rt = _make_runtime()
        brain.load_from_json_dict({"name": "x"}, rt)
        r = brain.raider_for(rt.spec.form_id)
        assert r.spec.fire_cooldown_ms == 800.0    # DEFAULT_FIRE_COOLDOWN_MS


# ---------------------------------------------------------------- target sel

class TestTargetSelection:
    def test_idle_no_peers(self):
        brain = RaiderBrain()
        rt = _make_runtime()
        brain.load_runtime(rt, _make_spec())
        brain.tick(0.0, 0.1, {})
        assert rt.aggro_state == int(AggroState.IDLE)
        assert rt.combat_target_form_id == 0

    def test_picks_only_peer_in_range(self):
        brain = RaiderBrain()
        rt = _make_runtime(x=0, y=0, z=0)
        brain.load_runtime(rt, _make_spec())          # detect=1000
        peers = {"peerA": (300.0, 0.0, 0.0, True)}
        brain.tick(0.0, 0.1, peers)
        r = brain.raider_for(rt.spec.form_id)
        assert r.aggro_peer_id == "peerA"
        assert rt.aggro_state == int(AggroState.COMBAT)
        # combat_target_form_id is PER-PEER (resolved at broadcast
        # time via project_for_peer), not stored on the NPCRuntime.
        # The runtime field stays 0 to avoid leaking into the
        # non-projected (Dogmeat/Codsworth) broadcast path.
        assert rt.combat_target_form_id == 0
        proj = brain.project_for_peer(rt.spec.form_id, "peerA")
        assert proj["combat_target_form_id"] == LOCAL_PLAYER_FORM_ID

    def test_picks_closest_of_two(self):
        brain = RaiderBrain()
        rt = _make_runtime()
        brain.load_runtime(rt, _make_spec())
        peers = {
            "near":  (200.0, 0.0, 0.0, True),
            "far":   (800.0, 0.0, 0.0, True),
        }
        brain.tick(0.0, 0.1, peers)
        assert brain.raider_for(rt.spec.form_id).aggro_peer_id == "near"

    def test_ignores_dead_peers(self):
        brain = RaiderBrain()
        rt = _make_runtime()
        brain.load_runtime(rt, _make_spec())
        peers = {
            "ghostA": (100.0, 0.0, 0.0, False),
            "aliveB": (500.0, 0.0, 0.0, True),
        }
        brain.tick(0.0, 0.1, peers)
        assert brain.raider_for(rt.spec.form_id).aggro_peer_id == "aliveB"

    def test_ignores_peer_out_of_detection_range(self):
        brain = RaiderBrain()
        rt = _make_runtime()
        brain.load_runtime(rt, _make_spec())          # detection=1000
        peers = {"far": (2000.0, 0.0, 0.0, True)}
        brain.tick(0.0, 0.1, peers)
        assert rt.aggro_state == int(AggroState.IDLE)


# ---------------------------------------------------------------- hysteresis

class TestHysteresis:
    def test_no_swap_when_close(self):
        """Swap only if new candidate is closer by hysteresis margin."""
        brain = RaiderBrain()
        rt = _make_runtime()
        brain.load_runtime(rt, _make_spec(swap_hysteresis_ft=100.0))

        # Tick 1: only A.
        brain.tick(0.0, 0.1, {"A": (200.0, 0.0, 0.0, True)})
        assert brain.raider_for(rt.spec.form_id).aggro_peer_id == "A"

        # Tick 2: B appears at 180 (closer by only 20 < hysteresis=100).
        # Should keep A.
        brain.tick(100.0, 0.1, {
            "A": (200.0, 0.0, 0.0, True),
            "B": (180.0, 0.0, 0.0, True),
        })
        assert brain.raider_for(rt.spec.form_id).aggro_peer_id == "A"

    def test_swap_when_far_enough(self):
        brain = RaiderBrain()
        rt = _make_runtime()
        brain.load_runtime(rt, _make_spec(swap_hysteresis_ft=50.0))

        brain.tick(0.0, 0.1, {"A": (400.0, 0.0, 0.0, True)})
        # B is 250 closer — swap.
        brain.tick(100.0, 0.1, {
            "A": (400.0, 0.0, 0.0, True),
            "B": (150.0, 0.0, 0.0, True),
        })
        assert brain.raider_for(rt.spec.form_id).aggro_peer_id == "B"

    def test_lost_target_drops_aggro(self):
        """Target leaves range; brain keeps it for ``target_loss_ms``,
        then drops to ALERT.
        """
        brain = RaiderBrain()
        rt = _make_runtime()
        brain.load_runtime(
            rt,
            _make_spec(detection_range_ft=500.0, target_loss_ms=200.0,
                       alert_window_ms=500.0),
        )
        peers = {"A": (300.0, 0.0, 0.0, True)}
        brain.tick(0.0, 0.1, peers)
        assert rt.aggro_state == int(AggroState.COMBAT)

        # A moves out of range. Within loss window we keep aggro.
        brain.tick(100.0, 0.1, {"A": (800.0, 0.0, 0.0, True)})
        assert brain.raider_for(rt.spec.form_id).aggro_peer_id == "A"

        # Past loss window: drop to ALERT.
        brain.tick(400.0, 0.1, {"A": (800.0, 0.0, 0.0, True)})
        assert rt.aggro_state == int(AggroState.ALERT)

        # Past alert window: IDLE.
        brain.tick(1000.0, 0.1, {"A": (800.0, 0.0, 0.0, True)})
        assert rt.aggro_state == int(AggroState.IDLE)
        assert brain.raider_for(rt.spec.form_id).aggro_peer_id is None

    def test_peer_disconnect_drops_aggro(self):
        brain = RaiderBrain()
        rt = _make_runtime()
        brain.load_runtime(rt, _make_spec())
        brain.tick(0.0, 0.1, {"A": (200.0, 0.0, 0.0, True)})
        # A disappears.
        brain.tick(100.0, 0.1, {})
        # No replacement candidate → ALERT.
        assert rt.aggro_state == int(AggroState.ALERT)


# ---------------------------------------------------------------- fire timing

class TestFire:
    def test_fires_when_in_range_and_cooldown_ok(self):
        brain = RaiderBrain()
        rt = _make_runtime()
        brain.load_runtime(rt, _make_spec(
            weapon_range_ft=500.0, fire_cooldown_ms=100.0,
        ))
        brain.tick(0.0, 0.1, {"A": (200.0, 0.0, 0.0, True)})
        r = brain.raider_for(rt.spec.form_id)
        assert r.fire_this_tick is True
        assert r.last_fire_ms == 0.0
        assert rt.anim_state == int(AnimState.FIRING)

    def test_cooldown_prevents_double_fire(self):
        brain = RaiderBrain()
        rt = _make_runtime()
        brain.load_runtime(rt, _make_spec(fire_cooldown_ms=200.0))

        brain.tick(0.0, 0.1, {"A": (100.0, 0.0, 0.0, True)})
        assert brain.raider_for(rt.spec.form_id).fire_this_tick is True

        # 100 ms later → still in cooldown.
        brain.tick(100.0, 0.1, {"A": (100.0, 0.0, 0.0, True)})
        assert brain.raider_for(rt.spec.form_id).fire_this_tick is False
        assert rt.anim_state == int(AnimState.AIMING)

        # 300 ms total → can fire again.
        brain.tick(300.0, 0.1, {"A": (100.0, 0.0, 0.0, True)})
        assert brain.raider_for(rt.spec.form_id).fire_this_tick is True

    def test_out_of_weapon_range_no_fire(self):
        brain = RaiderBrain()
        rt = _make_runtime()
        brain.load_runtime(rt, _make_spec(
            detection_range_ft=1000.0, weapon_range_ft=300.0,
        ))
        # Inside detection (300 < 1000) but outside weapon (300 not < 300).
        # Use 400 to ensure outside weapon.
        brain.tick(0.0, 0.1, {"A": (400.0, 0.0, 0.0, True)})
        r = brain.raider_for(rt.spec.form_id)
        assert r.fire_this_tick is False
        assert rt.aggro_state == int(AggroState.COMBAT)
        assert rt.anim_state == int(AnimState.AIMING)


# ---------------------------------------------------------------- aim point

class TestAimPoint:
    def test_aim_offsets_vertical(self):
        brain = RaiderBrain()
        rt = _make_runtime()
        brain.load_runtime(rt, _make_spec())
        brain.tick(0.0, 0.1, {"A": (300.0, 50.0, 60.0, True)})
        r = brain.raider_for(rt.spec.form_id)
        assert r.aim_target_x == 300.0
        assert r.aim_target_y == 50.0
        assert r.aim_target_z == pytest.approx(60.0 + AIM_VERTICAL_OFFSET_FT)


# ---------------------------------------------------------------- damage

class TestDamage:
    def test_damage_reduces_hp(self):
        brain = RaiderBrain()
        rt = _make_runtime()
        brain.load_runtime(rt, _make_spec())
        killed, new_hp = brain.apply_damage(rt.spec.form_id, 30, "shooterA", 0.0)
        assert killed is False
        assert new_hp == 70
        assert rt.hp_pct == 70

    def test_lethal_damage_sets_dead(self):
        brain = RaiderBrain()
        rt = _make_runtime()
        brain.load_runtime(rt, _make_spec())
        killed, hp = brain.apply_damage(rt.spec.form_id, 200, "shooterA", 0.0)
        assert killed is True
        assert hp == 0
        assert rt.anim_state == int(AnimState.DEAD)
        assert rt.aggro_state == int(AggroState.IDLE)

    def test_shoot_to_aggro(self):
        """Damage from a peer immediately makes that peer the aggro
        target, even if they weren't selected by distance.
        """
        brain = RaiderBrain()
        rt = _make_runtime()
        brain.load_runtime(rt, _make_spec())
        # No tick yet, no aggro.
        brain.apply_damage(rt.spec.form_id, 10, "shooterA", 50.0)
        r = brain.raider_for(rt.spec.form_id)
        assert r.aggro_peer_id == "shooterA"
        assert r.last_seen_target_ms == 50.0

    def test_dead_raider_skips_tick(self):
        brain = RaiderBrain()
        rt = _make_runtime()
        brain.load_runtime(rt, _make_spec())
        brain.apply_damage(rt.spec.form_id, 200, None, 0.0)
        # Tick should NOT change state from DEAD.
        brain.tick(100.0, 0.1, {"A": (100.0, 0.0, 0.0, True)})
        assert rt.anim_state == int(AnimState.DEAD)
        assert brain.raider_for(rt.spec.form_id).fire_this_tick is False


# ---------------------------------------------------------------- projection

class TestProjectForPeer:
    def test_chosen_target_gets_local_player_form_id(self):
        brain = RaiderBrain()
        rt = _make_runtime()
        brain.load_runtime(rt, _make_spec())
        brain.tick(0.0, 0.1, {
            "A": (100.0, 0.0, 0.0, True),
            "B": (900.0, 0.0, 0.0, True),
        })
        proj_a = brain.project_for_peer(rt.spec.form_id, "A")
        proj_b = brain.project_for_peer(rt.spec.form_id, "B")
        # A is the chosen target → 0x14 on A's client.
        assert proj_a["combat_target_form_id"] == LOCAL_PLAYER_FORM_ID
        # B is not → no override (vanilla AI on B's client).
        assert proj_b["combat_target_form_id"] == 0

    def test_world_aim_is_shared(self):
        """Aim point is world-frame, identical for all peers."""
        brain = RaiderBrain()
        rt = _make_runtime()
        brain.load_runtime(rt, _make_spec())
        brain.tick(0.0, 0.1, {"A": (100.0, 50.0, 60.0, True)})
        pa = brain.project_for_peer(rt.spec.form_id, "A")
        pb = brain.project_for_peer(rt.spec.form_id, "B")
        for k in ("aim_target_x", "aim_target_y", "aim_target_z"):
            assert pa[k] == pb[k]

    def test_fire_this_tick_shared(self):
        brain = RaiderBrain()
        rt = _make_runtime()
        brain.load_runtime(rt, _make_spec(fire_cooldown_ms=50.0))
        brain.tick(0.0, 0.1, {"A": (100.0, 0.0, 0.0, True)})
        pa = brain.project_for_peer(rt.spec.form_id, "A")
        pb = brain.project_for_peer(rt.spec.form_id, "B")
        # Same fire timing regardless of who is the target.
        assert pa["fire_this_tick"] == pb["fire_this_tick"] is True

    def test_unknown_raider_returns_zeros(self):
        brain = RaiderBrain()
        proj = brain.project_for_peer(0xDEADBEEF, "A")
        assert proj["combat_target_form_id"] == 0
        assert proj["fire_this_tick"] is False
        assert proj["aim_target_x"] == 0.0
