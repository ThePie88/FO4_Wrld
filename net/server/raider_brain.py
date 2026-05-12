"""
B6.6w0 — Combat-aware brain for tracked raiders.

Replaces ``npc_brain.py``'s idle waypoint patroller for NPCs that should
exhibit combat behavior (target selection, aim, fire timing, hit response).
Built on the same ``NPCRuntime`` / ``NPCSpec`` primitives so the wire
payload extension stays minimal — wire proto v15 just adds 3 floats
(``aim_target_xyz``) + 1 byte (``fire_this_tick``) to the existing
``NPCStateEntry`` from v14.

This brain assumes the client has the **v5 freeze + no-crash-on-damage**
infrastructure active (closed 2026-05-12):

- ``npc_ai_suppress`` bails ``Update_PerFrame`` for tracked actors.
- ``ghost_ai_havok_step`` + ``ghost_ai_actor_setpos`` + ``ghost_ai_pos_belt``
  bail motion writers (NIF + Havok body integration).
- ``set_actor_motion_keyframed`` applied at AUTO-TRACK insert → Havok
  treats body as keyframed → no ragdoll-on-damage crash.

The new B6.6 hooks (to be implemented post RE arena B6.6w0) will read
the brain's outputs:

- ``combat_target_form_id`` → real combat target writer hook
- ``aim_target_xyz``        → aim vector hook (CombatAim::ComputeAimVector)
- ``fire_this_tick``        → fire decision hook
- ``anim_*`` flags          → engine-internal SetGraphVariable* callers

Server-authoritative: no client-side rolls, no LOS divergence, no aggro
divergence. Both clients see the SAME raider attack the SAME peer at the
SAME tick.

Cross-references
----------------
- ``net/server/npc_brain.py`` — shared ``AnimState`` / ``AggroState``
  enums + ``NPCRuntime`` dataclass we mutate.
- ``net/server/state.py`` — ``ServerState`` (peers + their last positions).
  Brain reads peer pos snapshot per tick to compute distance / aggro.
- ``net/server/waypoints/concord_museum_mvp.json`` — raider catalog with
  spawn coords + (optional) raider_combat_spec overrides.
- ``re/B6.6w0_pair_AGENT_*.md`` — RE dossiers for the engine functions
  this brain feeds.

State machine (per raider)
--------------------------
  IDLE      no peer in detection_range
  ALERT     was COMBAT, lost LOS within alert_window_ms (kept aggro)
  COMBAT    live aggro_peer, fires when cooldown + range + LOS clear
  FLEEING   hp_pct < flee_hp_threshold (post-MVP; not used B6.6w0)
  DEAD      hp_pct == 0 (terminal)

Aggro selection
---------------
- Closest peer in detection_range wins.
- Hysteresis: don't swap target unless new is closer by
  ``swap_hysteresis_ft`` (prevents oscillation between equidistant peers).
- Lost-target timeout: if aggro_peer > detection_range for
  ``target_loss_ms``, drop aggro → ALERT then IDLE.

Fire timing
-----------
- Per-raider cooldown (weapon-dependent; default 800 ms).
- Range check: distance <= weapon_range_ft.
- LOS check (MVP): distance only. Real raycast/navmesh is deferred per
  NPCs.md "NavMesh sync" risk section.
- Output: ``fire_this_tick = True`` exactly ONE tick per shot. Client
  hook reads this flag and triggers projectile spawn.

Concurrency: same as ``npc_brain.py`` — single-task mutation, pure
compute, no I/O.
"""
from __future__ import annotations

import logging
import math
from dataclasses import dataclass, field
from typing import Optional

from .npc_brain import (
    AggroState,
    AnimState,
    NPCRuntime,
    NPCSpec,
    Waypoint,
    _parse_hex,
)


log = logging.getLogger("raider_brain")


# ----------------------------------------------------------------------------
# Tunables
# ----------------------------------------------------------------------------
#
# Default values for raiders. Per-NPC overrides can be supplied in the
# waypoint JSON under a ``combat`` sub-object.

DEFAULT_DETECTION_RANGE_FT = 4000.0        # ≈ 60 m (1 unit ≈ 1.5 cm)
DEFAULT_WEAPON_RANGE_FT    = 2500.0        # ≈ 37 m
DEFAULT_FIRE_COOLDOWN_MS   = 800.0         # 1.25 shots / sec
DEFAULT_SWAP_HYSTERESIS_FT = 200.0         # ~3 m new-target advantage required
DEFAULT_TARGET_LOSS_MS     = 1500.0        # lose aggro after 1.5s out-of-range
DEFAULT_ALERT_WINDOW_MS    = 3000.0        # ALERT decays to IDLE after 3s
DEFAULT_FLEE_HP_THRESHOLD  = 15            # hp_pct below this → FLEE (B6.6w-extra)

# Vertical bias for aim. Real Bethesda actors aim at the torso/head, not
# at the foot pos that pos_send broadcasts. 70 units ≈ chest height.
AIM_VERTICAL_OFFSET_FT = 70.0

# Sentinel: client engine uses 0x14 = PlayerCharacter form_id. When the
# server picks a peer as aggro target, the CLIENT-LOCAL form_id substituted
# into the combat target field is always 0x14 (each client's own player).
# This is per-client substitution — the network payload encodes "who is
# being attacked" via the wire's peer_id, and ``project_for_peer()`` below
# turns that into the local form_id.
LOCAL_PLAYER_FORM_ID = 0x00000014


# ----------------------------------------------------------------------------
# Specs / per-raider config
# ----------------------------------------------------------------------------

@dataclass(slots=True)
class RaiderCombatSpec:
    """Per-raider combat tuning. Loaded from waypoint JSON's ``combat``
    sub-object; defaults applied for missing fields.

    Stable across runtime — these are weapon + AI presets, not state.
    """
    detection_range_ft: float = DEFAULT_DETECTION_RANGE_FT
    weapon_range_ft:    float = DEFAULT_WEAPON_RANGE_FT
    fire_cooldown_ms:   float = DEFAULT_FIRE_COOLDOWN_MS
    swap_hysteresis_ft: float = DEFAULT_SWAP_HYSTERESIS_FT
    target_loss_ms:     float = DEFAULT_TARGET_LOSS_MS
    alert_window_ms:    float = DEFAULT_ALERT_WINDOW_MS
    flee_hp_threshold:  int   = DEFAULT_FLEE_HP_THRESHOLD


@dataclass(slots=True)
class RaiderRuntime:
    """Combat brain state. Wraps an ``NPCRuntime`` (which stays the
    canonical wire-payload surface) + per-raider combat bookkeeping.

    Mutation rules
    --------------
    - ``ai`` (NPCRuntime) is the EXTERNAL surface. ``main.py`` reads it
      for BCAST emit. Brain writes here every tick.
    - All other fields are INTERNAL bookkeeping. Not serialized.
    """
    ai: NPCRuntime
    spec: RaiderCombatSpec

    # Combat target memory (server-side; not on wire).
    aggro_peer_id: Optional[str] = None       # 16-byte FixedClientId truncated
    aim_target_x: float = 0.0
    aim_target_y: float = 0.0
    aim_target_z: float = 0.0

    # Fire timing. Default sentinel ensures the first fire is allowed
    # regardless of ``now_ms`` (otherwise `now_ms - 0` < cooldown at t=0
    # would lock the first shot).
    last_fire_ms: float = -1e12
    fire_this_tick: bool = False              # mutated each tick (reset->set)

    # Aggro hysteresis / alert decay.
    last_seen_target_ms: float = 0.0
    alert_started_ms: float = 0.0


# ----------------------------------------------------------------------------
# Brain
# ----------------------------------------------------------------------------

class RaiderBrain:
    """Combat brain for tracked raiders.

    Public API (kept narrow so ``main.py`` integration is trivial):

    - ``load_runtime(form_id, NPCRuntime, RaiderCombatSpec)`` — register
      a raider already loaded by ``NPCBrain.load_cell``. The brain
      doesn't own the NPCRuntime — it borrows the reference and mutates
      it. NPCBrain still owns the dict.
    - ``tick(now_ms, dt_s, peers)`` — advance every raider. ``peers`` is
      a snapshot ``{peer_id: (x, y, z, alive_bool)}``. Returns count
      ticked. Pure compute.
    - ``project_for_peer(form_id, peer_id)`` — generate the per-peer
      override fields for the wire payload (combat_target_form_id +
      aim_target_xyz + fire_this_tick). Called from main.py per
      (peer, raider) when composing NPC_STATE_BCAST.
    """

    def __init__(self) -> None:
        self.raiders: dict[int, RaiderRuntime] = {}     # form_id -> RaiderRuntime

    # ------------------------------------------------------------------- load

    def load_runtime(self, runtime: NPCRuntime, spec: RaiderCombatSpec) -> None:
        """Register an NPCRuntime as a combat raider. ``runtime`` is
        expected to be the same instance held by ``NPCBrain.npcs``;
        we mutate it in place so the wire BCAST sees brain decisions.
        """
        form_id = runtime.spec.form_id
        if form_id in self.raiders:
            log.warning(
                "raider_brain: duplicate form_id 0x%X — overwriting",
                form_id,
            )
        self.raiders[form_id] = RaiderRuntime(ai=runtime, spec=spec)

    def load_from_json_dict(
        self,
        npc_json: dict,
        runtime: NPCRuntime,
    ) -> None:
        """Convenience: pull a ``combat`` sub-object from the waypoint
        JSON entry (if present) and register the runtime.
        """
        combat = npc_json.get("combat") or {}
        spec = RaiderCombatSpec(
            detection_range_ft=float(combat.get(
                "detection_range_ft", DEFAULT_DETECTION_RANGE_FT)),
            weapon_range_ft=float(combat.get(
                "weapon_range_ft", DEFAULT_WEAPON_RANGE_FT)),
            fire_cooldown_ms=float(combat.get(
                "fire_cooldown_ms", DEFAULT_FIRE_COOLDOWN_MS)),
            swap_hysteresis_ft=float(combat.get(
                "swap_hysteresis_ft", DEFAULT_SWAP_HYSTERESIS_FT)),
            target_loss_ms=float(combat.get(
                "target_loss_ms", DEFAULT_TARGET_LOSS_MS)),
            alert_window_ms=float(combat.get(
                "alert_window_ms", DEFAULT_ALERT_WINDOW_MS)),
            flee_hp_threshold=int(combat.get(
                "flee_hp_threshold", DEFAULT_FLEE_HP_THRESHOLD)),
        )
        self.load_runtime(runtime, spec)

    # ------------------------------------------------------------------- tick

    def tick(
        self,
        now_ms: float,
        dt_s: float,
        peers: dict[str, tuple[float, float, float, bool]],
    ) -> int:
        """Advance every registered raider. ``peers`` is a snapshot of
        live peer positions: ``{peer_id: (pos_x, pos_y, pos_z, alive)}``.

        Returns count ticked. Pure compute, no I/O.

        ``main.py`` is expected to build ``peers`` from ``ServerState``
        once per tick and pass it in. Decoupling brain from state
        plumbing keeps it independently testable.
        """
        if dt_s < 0.0:
            dt_s = 0.0
        n = 0
        for raider in self.raiders.values():
            if raider.ai.hp_pct <= 0:
                # Dead. Brain leaves the runtime in DEAD state; client's
                # kill_hook + ragdoll handle the visual.
                if raider.ai.anim_state != int(AnimState.DEAD):
                    raider.ai.anim_state = int(AnimState.DEAD)
                    raider.ai.aggro_state = int(AggroState.IDLE)
                    raider.ai.last_change_ms = now_ms
                    raider.fire_this_tick = False
                n += 1
                continue
            self._tick_one(raider, now_ms, dt_s, peers)
            n += 1
        return n

    def _tick_one(
        self,
        raider: RaiderRuntime,
        now_ms: float,
        dt_s: float,
        peers: dict[str, tuple[float, float, float, bool]],
    ) -> None:
        # Reset per-tick output flag. Re-set below if firing this tick.
        raider.fire_this_tick = False
        raider.ai.last_tick_ms = now_ms

        # 1) Target selection.
        new_aggro_id, new_aggro_pos, new_aggro_dist = self._select_target(
            raider, peers
        )

        # 2) Apply hysteresis & loss-timeout.
        chosen_aggro_id = self._apply_hysteresis(
            raider, new_aggro_id, new_aggro_pos, new_aggro_dist, peers, now_ms
        )

        # 3) State machine transition.
        prev_aggro = raider.ai.aggro_state
        if chosen_aggro_id is None:
            # No target in range.
            if (raider.aggro_peer_id is not None
                    and raider.alert_started_ms == 0.0):
                # Was in COMBAT, just lost target → ALERT.
                raider.alert_started_ms = now_ms
                raider.ai.aggro_state = int(AggroState.ALERT)
            elif (raider.alert_started_ms > 0.0
                  and (now_ms - raider.alert_started_ms)
                  >= raider.spec.alert_window_ms):
                # Alert window expired → IDLE.
                raider.alert_started_ms = 0.0
                raider.aggro_peer_id = None
                raider.ai.aggro_state = int(AggroState.IDLE)
        else:
            # Target acquired / kept.
            raider.aggro_peer_id = chosen_aggro_id
            raider.last_seen_target_ms = now_ms
            raider.alert_started_ms = 0.0
            raider.ai.aggro_state = int(AggroState.COMBAT)

            # Set aim point (chest height bias).
            apx, apy, apz, _alive = peers[chosen_aggro_id]
            raider.aim_target_x = apx
            raider.aim_target_y = apy
            raider.aim_target_z = apz + AIM_VERTICAL_OFFSET_FT

            # 4) Fire decision.
            self._maybe_fire(raider, now_ms, new_aggro_dist)

        # 5) Anim state (visible posture).
        self._update_anim_state(raider, prev_aggro, now_ms)

        # 6) Mirror brain decisions to NPCRuntime fields (= wire payload).
        # combat_target_form_id is per-peer (each peer's local 0x14),
        # so we set a SENTINEL value here (= LOCAL_PLAYER_FORM_ID if any
        # target acquired, else 0). main.py's ``project_for_peer`` will
        # turn it into 0x14 only for the chosen peer, 0 for others.
        if chosen_aggro_id is not None:
            raider.ai.combat_target_form_id = LOCAL_PLAYER_FORM_ID
        else:
            raider.ai.combat_target_form_id = 0

    # ----------------------------------------------------- target selection

    def _select_target(
        self,
        raider: RaiderRuntime,
        peers: dict[str, tuple[float, float, float, bool]],
    ) -> tuple[Optional[str], Optional[tuple[float, float, float]], float]:
        """Return (closest_alive_peer_id_in_detection_range, pos, distance)
        or (None, None, inf).
        """
        best_id: Optional[str] = None
        best_pos: Optional[tuple[float, float, float]] = None
        best_d2 = float("inf")
        rx, ry, rz = raider.ai.pos_x, raider.ai.pos_y, raider.ai.pos_z
        det_d2 = raider.spec.detection_range_ft ** 2

        for peer_id, (px, py, pz, alive) in peers.items():
            if not alive:
                continue
            dx, dy, dz = px - rx, py - ry, pz - rz
            d2 = dx * dx + dy * dy + dz * dz
            if d2 > det_d2:
                continue
            if d2 < best_d2:
                best_d2 = d2
                best_id = peer_id
                best_pos = (px, py, pz)

        return best_id, best_pos, math.sqrt(best_d2) if best_id else float("inf")

    def _apply_hysteresis(
        self,
        raider: RaiderRuntime,
        candidate_id: Optional[str],
        candidate_pos: Optional[tuple[float, float, float]],
        candidate_dist: float,
        peers: dict[str, tuple[float, float, float, bool]],
        now_ms: float,
    ) -> Optional[str]:
        """Decide whether to swap from the current aggro target.

        Rules:
        - No current aggro → take ``candidate_id`` (may be None).
        - Have aggro + candidate is same peer → keep.
        - Have aggro + candidate is different peer:
            - keep current unless current is now >detection_range
              ``target_loss_ms`` ago (lost) OR new is closer by
              ``swap_hysteresis_ft``.
        - Have aggro + current peer disappeared from ``peers`` (logout) →
          drop aggro → return candidate.
        """
        cur = raider.aggro_peer_id
        if cur is None:
            return candidate_id

        cur_entry = peers.get(cur)
        if cur_entry is None or not cur_entry[3]:
            # Current peer disconnected or died. Take candidate.
            return candidate_id

        # Distance to current peer.
        cx, cy, cz, _ = cur_entry
        rx, ry, rz = raider.ai.pos_x, raider.ai.pos_y, raider.ai.pos_z
        cur_dist = math.sqrt(
            (cx - rx) ** 2 + (cy - ry) ** 2 + (cz - rz) ** 2
        )

        if cur_dist > raider.spec.detection_range_ft:
            # Out of range. If still within loss window keep it (so we
            # don't oscillate when peer ducks behind cover briefly);
            # else drop.
            since_seen = now_ms - raider.last_seen_target_ms
            if since_seen < raider.spec.target_loss_ms:
                return cur          # keep for now
            return candidate_id     # drop, accept candidate

        # Current is in range. Swap only if candidate is closer by
        # hysteresis margin.
        if candidate_id is not None and candidate_id != cur:
            if candidate_dist + raider.spec.swap_hysteresis_ft < cur_dist:
                return candidate_id

        return cur

    # ----------------------------------------------------- fire decision

    def _maybe_fire(
        self,
        raider: RaiderRuntime,
        now_ms: float,
        dist: float,
    ) -> None:
        """Set ``fire_this_tick`` if cooldown + range cleared."""
        if dist > raider.spec.weapon_range_ft:
            return
        if (now_ms - raider.last_fire_ms) < raider.spec.fire_cooldown_ms:
            return
        # LOS check (MVP: distance-only — already covered above).
        raider.fire_this_tick = True
        raider.last_fire_ms = now_ms

    # ----------------------------------------------------- anim state

    def _update_anim_state(
        self,
        raider: RaiderRuntime,
        prev_aggro: int,
        now_ms: float,
    ) -> None:
        """Map (aggro_state, fire_this_tick) → anim_state enum.

        Client's anim-graph-feeds hook (B6.6) reads anim_state and sets
        the engine's bool flags (bIsAttacking, bIsAimingGun, bIsFiring).
        """
        if raider.ai.aggro_state == int(AggroState.COMBAT):
            new_anim = (int(AnimState.FIRING) if raider.fire_this_tick
                        else int(AnimState.AIMING))
        elif raider.ai.aggro_state == int(AggroState.ALERT):
            new_anim = int(AnimState.IDLE)        # weapon drawn but idle
        else:
            new_anim = int(AnimState.IDLE)

        if new_anim != raider.ai.anim_state:
            raider.ai.anim_state = new_anim
            raider.ai.last_change_ms = now_ms

    # ----------------------------------------------------- per-peer projection

    def project_for_peer(
        self,
        form_id: int,
        peer_id: str,
    ) -> dict:
        """Return per-peer override fields for the wire payload.

        Each peer sees the brain's authoritative aim+fire identically
        (both pos vectors and fire timing are world-frame), but the
        ``combat_target_form_id`` substitution is per-peer:

        - If this raider's brain aggro_peer == ``peer_id``: this peer is
          THE TARGET → combat_target_form_id = 0x14 (their local player).
        - Else: combat_target_form_id = 0 (no override; vanilla AI on
          this client decides — likely no aggro since v5 freeze suppresses
          local AI tick anyway, but kept clean for symmetry).

        ``aim_target_xyz`` is the same world position for every peer —
        each client renders the raider aiming/firing at that world coord,
        which is where peer A actually is (broadcast via pos_bcast).

        Returns ``{"combat_target_form_id": int, "aim_target_x/y/z": float,
        "fire_this_tick": bool}``.
        """
        raider = self.raiders.get(form_id)
        if raider is None:
            return {
                "combat_target_form_id": 0,
                "aim_target_x": 0.0,
                "aim_target_y": 0.0,
                "aim_target_z": 0.0,
                "fire_this_tick": False,
            }
        is_target = (raider.aggro_peer_id == peer_id)
        return {
            "combat_target_form_id":
                LOCAL_PLAYER_FORM_ID if is_target else 0,
            "aim_target_x": raider.aim_target_x,
            "aim_target_y": raider.aim_target_y,
            "aim_target_z": raider.aim_target_z,
            "fire_this_tick": raider.fire_this_tick,
        }

    # ----------------------------------------------------- accessors

    def count(self) -> int:
        return len(self.raiders)

    def all_raiders(self) -> list[RaiderRuntime]:
        return list(self.raiders.values())

    def raider_for(self, form_id: int) -> Optional[RaiderRuntime]:
        return self.raiders.get(form_id)

    # ----------------------------------------------------- damage flow (B6.6w2+)

    def apply_damage(
        self,
        form_id: int,
        amount: int,
        source_peer_id: Optional[str],
        now_ms: float,
    ) -> tuple[bool, int]:
        """Apply server-validated damage. Called from PEER_HIT_REPORT
        handler in main.py after validation.

        Returns ``(killed, new_hp_pct)``. If killed, brain transitions
        the raider to DEAD anim state; the client's existing ``kill_hook``
        applies the ragdoll.

        Bookkeeping:
        - source_peer_id added/refreshed in aggro memory (if alive),
          even if it wasn't currently the chosen target — this makes
          "shoot to aggro" responsive without waiting for distance
          recheck.
        """
        raider = self.raiders.get(form_id)
        if raider is None:
            return False, 0

        new_hp = max(0, raider.ai.hp_pct - max(0, amount))
        raider.ai.hp_pct = new_hp

        # Shoot-to-aggro: even if source peer wasn't selected target,
        # mark them as the most-recent threat so target_selection picks
        # them up immediately on next tick.
        if source_peer_id is not None:
            raider.aggro_peer_id = source_peer_id
            raider.last_seen_target_ms = now_ms
            raider.alert_started_ms = 0.0

        if new_hp == 0:
            raider.ai.anim_state = int(AnimState.DEAD)
            raider.ai.aggro_state = int(AggroState.IDLE)
            raider.ai.last_change_ms = now_ms
            raider.fire_this_tick = False
            return True, 0
        return False, new_hp
