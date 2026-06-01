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

import json
import logging
import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import ClassVar, Optional

from .npc_brain import (
    AggroState,
    AnimState,
    NPCBrain,
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

DEFAULT_DETECTION_RANGE_FT = 30000.0       # ≈ 430 m (1 unit ≈ 1.42 cm) — bumped
                                            # 2026-05-12 for MVP testing: player
                                            # spawning at Concord exterior is
                                            # typically 300-400 m from the
                                            # raider cluster (~-76000, 88800).
                                            # Original 4000 (~57 m) was too tight
                                            # — required the player to be in the
                                            # raider's face to aggro.
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

    # Build 62 (2026-05-24) — proximity sphere perception trigger config.
    #
    # Per re/arena_synthesis/SUPERVISOR_SYNTHESIS.md: when a peer's pos
    # enters an NPC's effective perception sphere, the server emits one
    # NPC_PERCEPTION_TRIGGER per (npc, peer) pair (server-side debounced).
    # Receiving clients invoke trigger_npc_perception(npc, peer_ghost),
    # which calls engine sub_140CCF810 to naturally allocate combat tier.
    #
    # Tunables:
    #   PERCEPTION_BASE_RADIUS = base sphere radius in game units.
    #     1024 ≈ vanilla "alerted at gunshot" range. 1600 ≈ vanilla combat
    #     range for ranged weapons. Start conservative at 1024 to avoid
    #     spam; live-test and tune.
    #   PERCEPTION_DEBOUNCE_MS = re-emit cooldown per (npc_fid, peer_id).
    #     Once engine allocates HighProcess via CCF810, subsequent calls
    #     hit the existing controller (idempotent merge). 5s avoids spam
    #     during ongoing combat without missing post-decay re-engagement.
    #   POSTURE_RADIUS_MULT = per-peer-posture scaler. Sneak shrinks the
    #     sphere (stealth), sprint expands it (loud footsteps).
    PERCEPTION_BASE_RADIUS: ClassVar[float] = 1024.0
    PERCEPTION_DEBOUNCE_MS: ClassVar[float] = 5000.0

    # Build 62.4 (2026-05-24) — server-authoritative range/acquisition gates.
    #
    # Hard range ceiling: ABOVE this distance, no perception trigger
    # is ever emitted, regardless of sphere-multiplier math. This
    # prevents the Build 62.3 freeze where Concord raiders entered
    # combat tier with Sanctuary peers (~30000 units away) — engine
    # combat pathfinder hangs trying to navigate to an unreachable
    # cross-cell target during cell load.
    #
    # 4000 units ≈ 57m, generous for raider weapon engagement.
    # Concord MQ102 cell is ≤ 3000 units across; Sanctuary core
    # is ~25000 units from Concord. A 4000 cap cleanly separates them.
    PERCEPTION_HARD_RANGE: ClassVar[float] = 4000.0

    # Acquired-hold debounce: once a (npc, peer) pair has fired a trigger
    # (CCF810 allocated HighProcess + CombatController + added target),
    # the engine sustains combat tier naturally. Re-emitting the trigger
    # only causes install_fixed_selector_on_raider re-runs which inflate
    # known_targets[] entries and corrupt CombatController state.
    #
    # 60 seconds is long enough to cover a typical engagement; if the
    # peer escapes and combat decays naturally, the engine clears
    # +0x328 and the next trigger will re-acquire fresh.
    #
    # Note: this is COMPLEMENTARY to PERCEPTION_DEBOUNCE_MS (5s). The
    # 5s value is still used as the "still in sphere, keep heartbeat"
    # cadence; the 60s value is the AFTER-FIRST-ACQUISITION cooldown.
    # Acquisition is cleared when peer leaves hysteresis radius (2x base)
    # so re-engagement triggers fresh.
    PERCEPTION_ACQUIRED_HOLD_MS: ClassVar[float] = 60_000.0

    POSTURE_RADIUS_MULT: ClassVar[dict[int, float]] = {
        0: 1.00,   # Stand
        1: 0.40,   # Sneak
        2: 0.70,   # Walk
        3: 1.00,   # Run
        4: 1.30,   # Sprint
    }

    def __init__(self) -> None:
        self.raiders: dict[int, RaiderRuntime] = {}     # form_id -> RaiderRuntime
        # Build 62 — debounce tracker: (npc_fid, peer_id) -> last emit ms.
        # Cleared lazily when (npc, peer) distance exceeds sphere
        # (with hysteresis margin) so re-engagement post-decay re-fires.
        self._perception_emit_ms: dict[tuple[int, str], float] = {}

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

    def load_cell(self, json_path: Path, npc_brain: NPCBrain) -> int:
        """Walk one waypoint JSON; register every NPC whose entry has
        a `combat` sub-object OR `combat_target_form_id` set.

        Mirrors the eligibility hint already present in the Concord
        catalog (`concord_museum_mvp.json`). Sanctuary/Drumlin JSONs
        without these fields are skipped — Codsworth and Dogmeat
        remain pure waypoint patrollers driven by `NPCBrain` only.

        ``npc_brain`` must already have ``load_cell``'d the same path
        (the brain owns the NPCRuntime instances; we just borrow
        references for combat mutation).

        Returns count registered.
        """
        try:
            data = json.loads(json_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            log.warning(
                "raider_brain: failed to parse %s (%s); skipping",
                json_path.name, e,
            )
            return 0

        added = 0
        for entry in data.get("npcs", []):
            has_combat_sub = isinstance(entry.get("combat"), dict)
            combat_target = entry.get("combat_target_form_id")
            has_combat_target = (
                combat_target is not None
                and _parse_hex(combat_target) != 0
            )
            if not (has_combat_sub or has_combat_target):
                continue

            fid = _parse_hex(entry["form_id"])
            runtime = npc_brain.npc_for(fid)
            if runtime is None:
                log.warning(
                    "raider_brain: NPCRuntime for fid=0x%X missing "
                    "(npc_brain.load_cell not run yet?) — skipping",
                    fid,
                )
                continue

            self.load_from_json_dict(entry, runtime)
            added += 1

        log.info(
            "raider_brain: loaded %d combat-eligible NPC(s) from %s",
            added, json_path.name,
        )
        return added

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

    def register_dynamic(
        self,
        *,
        npc_brain: NPCBrain,
        form_id: int,
        base_id: int,
        cell_id: int,
        pos_x: float,
        pos_y: float,
        pos_z: float,
        reporter_peer_id: str = "",
    ) -> None:
        """B6.6w2 — register a raider discovered at runtime via NPC_DISCOVER.

        Adds the actor to BOTH brains:
          - ``npc_brain.npcs[form_id]`` so it appears in NPC_STATE_BCAST.
          - ``self.raiders[form_id]`` so the combat tick processes it.

        All combat parameters use defaults (detection range, fire
        cooldown, etc). No waypoint patrol (raider stays at discovery
        pos unless combat AI overrides).

        Idempotent: caller should pre-check ``raider_for(form_id) is None``;
        this method warns + skips on duplicate.
        """
        if form_id in self.raiders:
            log.warning(
                "raider_brain: register_dynamic form=0x%X already "
                "tracked — skipping (reporter=%s)",
                form_id, reporter_peer_id,
            )
            return

        # Build NPCSpec + NPCRuntime + add to npc_brain.
        spec = NPCSpec(
            form_id=form_id,
            base_id=base_id,
            cell_id=cell_id,
            name=f"dyn_raider_0x{form_id:X}",
            waypoints=tuple(),     # no patrol path; raider stays put
            walk_speed_ftps=4.0,
            arrive_radius_ft=32.0,
        )
        runtime = NPCRuntime(
            spec=spec,
            pos_x=float(pos_x),
            pos_y=float(pos_y),
            pos_z=float(pos_z),
        )
        npc_brain.npcs[form_id] = runtime

        # Default combat spec — same as a JSON entry without `combat`
        # sub-object.
        combat_spec = RaiderCombatSpec(
            detection_range_ft=DEFAULT_DETECTION_RANGE_FT,
            weapon_range_ft=DEFAULT_WEAPON_RANGE_FT,
            fire_cooldown_ms=DEFAULT_FIRE_COOLDOWN_MS,
            swap_hysteresis_ft=DEFAULT_SWAP_HYSTERESIS_FT,
            target_loss_ms=DEFAULT_TARGET_LOSS_MS,
            alert_window_ms=DEFAULT_ALERT_WINDOW_MS,
            flee_hp_threshold=DEFAULT_FLEE_HP_THRESHOLD,
        )
        self.load_runtime(runtime, combat_spec)

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

    # ============================================================================
    # Build 62 (2026-05-24) — Proximity sphere perception trigger.
    #
    # Architectural pivot. Replaces synth/Tier1/Tier2/walker fragile code with
    # engine-native CCF810 EnterCombat. Server detects when a peer enters an
    # NPC's perception sphere; client invokes sub_140CCF810(observer, target)
    # which makes engine allocate HighProcess+CombatController+AddTarget
    # naturally in 1 frame.
    #
    # Per arena synthesis §5.1: this runs AFTER tick() each cycle. Returns the
    # list of (npc_fid, peer_id) pairs that crossed sphere boundary THIS tick.
    # Caller (main.py) packages each into MSG_NPC_PERCEPTION_TRIGGER and
    # broadcasts to all peers (each peer's client decides if it has the NPC
    # locally loaded, otherwise drops silently).
    #
    # Posture handling: peer_postures is optional dict {peer_id: posture_byte}.
    # 0=Stand, 1=Sneak, 2=Walk, 3=Run, 4=Sprint. Unknown peer defaults to Stand.
    # Wire integration (POS_BROADCAST posture byte) lands in a follow-up build;
    # Build 62 ships with posture wiring stubbed (everyone == Stand → 1.0 mult).
    # ============================================================================

    def compute_perception_triggers(
        self,
        now_ms: float,
        peers: dict[str, tuple[float, float, float, bool]],
        peer_postures: dict[str, int] | None = None,
    ) -> list[tuple[int, str]]:
        """Per-tick proximity sphere check. Returns list of (npc_fid, peer_id)
        pairs that crossed into perception range and are NOT debounced.

        Cost: O(N_raiders × N_peers). For 17 raiders × 2 peers = 34 dist
        computations / tick (10 Hz) = 340 ops/sec. Negligible.
        """
        if peer_postures is None:
            peer_postures = {}

        triggers: list[tuple[int, str]] = []

        # Build 62.4 — pre-compute hard-range² once (used in inner loop).
        hard_r_sq = (
            self.PERCEPTION_HARD_RANGE * self.PERCEPTION_HARD_RANGE
        )

        for raider in self.raiders.values():
            if raider.ai.hp_pct <= 0:
                continue  # dead raider: never perceives anything
            rx, ry, rz = raider.ai.pos_x, raider.ai.pos_y, raider.ai.pos_z
            fid = raider.ai.spec.form_id

            for peer_id, (px, py, pz, alive) in peers.items():
                if not alive:
                    continue

                dx = px - rx
                dy = py - ry
                dz = pz - rz
                dist_sq = dx * dx + dy * dy + dz * dz
                key = (fid, peer_id)

                # ---- Build 62.4 — HARD range ceiling (cross-cell gate). ----
                # Above this distance NEVER emit, regardless of sphere/posture.
                # Drop any prior acquisition so when peer re-enters range
                # we re-emit fresh (engine combat tier may have decayed in
                # the meantime).
                if dist_sq > hard_r_sq:
                    if key in self._perception_emit_ms:
                        del self._perception_emit_ms[key]
                    continue

                posture = peer_postures.get(peer_id, 0)  # default Stand
                mult = self.POSTURE_RADIUS_MULT.get(posture, 1.0)
                eff_radius = self.PERCEPTION_BASE_RADIUS * mult
                eff_r_sq = eff_radius * eff_radius
                last_emit = self._perception_emit_ms.get(key, 0.0)

                if dist_sq < eff_r_sq:
                    # In sphere. Emit trigger if ACQUIRED-HOLD window expired.
                    # Build 62.4 — switched from 5s debounce to 60s
                    # acquired-hold. Engine combat tier persists naturally
                    # once allocated; spamming re-triggers inflates
                    # known_targets[] and starves the AI tick (verified
                    # Build 62.3 freeze: 13 re-triggers × install_fixed_selector
                    # = client hang during cell load).
                    if (now_ms - last_emit) > self.PERCEPTION_ACQUIRED_HOLD_MS:
                        triggers.append(key)
                        self._perception_emit_ms[key] = now_ms
                else:
                    # Outside posture sphere but still within hard range.
                    # Hysteresis: if peer is past 1.2× sphere edge, forget
                    # the acquisition so re-entry re-fires the trigger.
                    hyst_r_sq = (eff_radius * 1.2) ** 2
                    if (dist_sq > hyst_r_sq
                            and key in self._perception_emit_ms):
                        del self._perception_emit_ms[key]

        return triggers

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

        # 6) NPCRuntime.combat_target_form_id stays at 0 here. The wire
        # payload's combat_target is PER-PEER and resolved at broadcast
        # time via `project_for_peer` (= LOCAL_PLAYER_FORM_ID only for
        # the chosen target peer, 0 for the others). Writing a stale
        # placeholder onto NPCRuntime would leak into the non-projected
        # path used for Dogmeat / Codsworth.
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
        *,
        viewer_ghost_form_id: int = 0,
    ) -> dict:
        """Return per-peer override fields for the wire payload.

        Each peer sees the brain's authoritative aim+fire identically
        (both pos vectors and fire timing are world-frame), but the
        ``combat_target_form_id`` substitution is per-peer:

        - If this raider's brain aggro_peer == ``peer_id``: this viewer
          IS the target → combat_target_form_id = 0x14 (their local player).
        - Else if the aggro_peer is a DIFFERENT live peer AND the viewer
          has registered a local ghost-actor (B6.6w5 PEER_GHOST_REGISTER):
          → combat_target_form_id = viewer's local ghost fid. On the
          viewer's screen this is the actor that represents the remote
          aggro target visually, so the raider's hook substitutes the
          combat target to the right local Actor → both clients see the
          raider attacking the SAME conceptual peer.
        - Else: combat_target_form_id = 0 (no override; vanilla AI on
          this client keeps its own target — likely the local player
          since it's the closest hostile).

        ``aim_target_xyz`` is the same world position for every peer —
        each client renders the raider aiming/firing at that world coord,
        which is where the aggro peer actually is (broadcast via pos_bcast).

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
        # Decide combat target form_id for THIS viewer.
        combat_target = 0
        if raider.aggro_peer_id is not None:
            if raider.aggro_peer_id == peer_id:
                # Viewer IS the aggro target.
                combat_target = LOCAL_PLAYER_FORM_ID
            elif viewer_ghost_form_id != 0:
                # Viewer is OTHER peer; use their local ghost fid for
                # the remote aggro target representation.
                combat_target = viewer_ghost_form_id
            # else: ghost not registered yet → leave at 0 (no override).
        return {
            "combat_target_form_id": combat_target,
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
