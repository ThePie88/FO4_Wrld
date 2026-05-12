"""
Server-side NPC brain (B6.5+).

Cross-references in this codebase
---------------------------------
- Pattern parallels: ``server/state.py::LockWorldState`` (B6.3 v0.5.3) —
  identity-keyed authoritative state, last-write-wins, persisted via
  ``server/persistence.py``.
- Tick loop: ``server/main.py::_periodic_tick`` runs the channel
  maintenance task at ``tick_rate_hz`` (default 20). NPCs run on a
  separate task at ``npc_tick_hz`` (default 10) so the two cadences
  don't fight each other.
- Engine bridge (downstream wedges, not landed yet):

    * **B6.5w2** — ``NPC_STATE_BCAST`` opcode 0x0270 will broadcast
      ``NPCRuntime`` snapshots over wire proto v13.
    * **B6.5w3** — client receiver writes pos/rot using the existing
      ``pos_update_seh`` pattern (``fw_native/src/native/skin_rebind.cpp``
      style SEH-safe deref + ``UpdateDownward``) and drives the
      animation graph via
      ``IAnimationGraphManagerHolder::SetGraphVariable*``
      (RVA 0x818D60/D80/DA0 — see
      ``re/B6.5_npc_pipeline_AGENT_B.md`` for holder offset and
      pre-interned name pool).
    * **B6.5w4** — client suppresses local AI tick via MinHook detour
      on ``Actor::Update_PerFrame@0x140C636A0`` (single funnel for all
      three ``ProcessLists`` tier walkers — see
      ``re/B6.5_npc_pipeline_AGENT_A.md``); detour bails when the
      Actor's ``form_id`` is in ``brain.npcs``.

Scope (B6.5w1)
--------------
Idle waypoint patrol only. ``AnimState`` enum values exposed but only
``IDLE`` and ``WALKING`` exercised by the tick state machine. Combat
(``FIRING`` / target / aggro / damage / death) is layered in by B6.6.

No wire protocol (w2). No client apply (w3). No AI suppression (w4).
This wedge is pure server-side compute + structured state, log-verifiable
("npc tick: processed N npcs" once a second).

Concurrency
-----------
Pure compute on ``tick()``. No I/O, no asyncio. Single-task mutation —
identical model to ``ServerState``. The brain is held by the
``ServerProtocol`` (composition); the asyncio task in ``main.py`` is the
sole writer.
"""
from __future__ import annotations

import json
import logging
import math
from dataclasses import dataclass
from enum import IntEnum
from pathlib import Path
from typing import Any, Optional


log = logging.getLogger("npc_brain")


class AnimState(IntEnum):
    """High-level animation enum the server publishes per NPC.

    Maps 1:1 to the wire ``anim_state`` byte (B6.5w2). On the client,
    each enum value translates to one or more
    ``BSAnimationGraphManager`` variable writes — e.g. ``WALKING`` →
    ``Direction`` + ``SpeedSampled``; ``AIMING`` → ``bAimActive=1``;
    ``FIRING`` → drive the engine's WeaponFire action via the action
    data path. See ``re/B6.5_npc_pipeline_AGENT_B.md`` § "Suggested
    call sequence" for the per-state mapping table.
    """
    IDLE = 0
    WALKING = 1
    RUNNING = 2
    AIMING = 3
    FIRING = 4
    RELOADING = 5
    DEAD = 6


class AggroState(IntEnum):
    """High-level combat posture. Drives target selection in B6.6."""
    IDLE = 0
    ALERT = 1
    COMBAT = 2
    FLEEING = 3


@dataclass(slots=True)
class Waypoint:
    """One node in a hand-authored patrol path.

    Coords are Bethesda game units (1 unit ≈ 1.428 cm; 70 units ≈
    1 yard). ``yaw`` is degrees in atan2 convention (0 = +X axis,
    counter-clockwise positive). The client receiver translates to
    Bethesda's heading convention (0 = +Y, clockwise) at apply time.
    """
    x: float
    y: float
    z: float
    yaw: float = 0.0           # facing on arrival, degrees
    dwell_s: float = 0.0       # idle time at waypoint (0 = pass through)


@dataclass(slots=True)
class NPCSpec:
    """Static per-NPC config: identity + path. Loaded from JSON, immutable at runtime.

    Identity uses placed-REFR ``form_id`` for the MVP — stable across
    clients because it's authored in the .esm. Runtime-spawned (``0xFF___``)
    refs aren't tracked yet; leveled-list determinism is B6.5w-extra2.
    """
    form_id: int                          # placed REFR formID (stable across processes)
    base_id: int                          # TESNPC base — validation hint, not key
    cell_id: int                          # parent cell formID
    name: str                             # debug-friendly label (logs)
    waypoints: tuple[Waypoint, ...]       # patrol path; tick loops indefinitely
    walk_speed_ftps: float = 4.0          # vanilla slow-walk ≈ 3-4 ft/s — calibrate in w3
    arrive_radius_ft: float = 32.0        # within this distance, snap + advance


@dataclass(slots=True)
class NPCRuntime:
    """Live state mutated each tick. Mirror of B6.5w2 NPC_STATE_BCAST surface.

    Field order is loose for now; w2 will pin it down to a packed struct
    in ``protocol.py``. Extra runtime-only bookkeeping (``last_tick_ms``,
    ``last_change_ms``) won't ship over the wire.
    """
    spec: NPCSpec
    pos_x: float
    pos_y: float
    pos_z: float
    yaw: float = 0.0
    pitch: float = 0.0
    anim_state: int = int(AnimState.IDLE)
    aggro_state: int = int(AggroState.IDLE)
    waypoint_idx: int = 0
    dwell_until_ms: float = 0.0           # 0 = not dwelling
    hp_pct: int = 100
    target_kind: int = 0                  # 0=NONE, 1=PEER, 2=NPC (B6.6)
    target_id: int = 0                    # peer_id-derived or form_id (B6.6)
    last_tick_ms: float = 0.0
    last_change_ms: float = 0.0           # last anim_state transition

    # B6.5w12 v14 — Ghost AI server-authoritative decisions.
    # Default 0 = "no override, pass through to vanilla AI logic" (the
    # client's MinHook detour checks for non-zero before substituting).
    # Phase 3 step A: field exists, brain still emits 0 (plumbing only).
    # Phase 3 step B+: brain decides actual values per NPC.
    package_form_id: int = 0              # hook: TESPackage::EvaluateConditions
    combat_target_form_id: int = 0        # hook: SyncCombatTargetFromAIProcess


class NPCBrain:
    """Authoritative NPC state machine + waypoint patroller.

    Single-task mutation (called from ``main.py::_periodic_npc_brain_tick``).
    Pure compute — no I/O. Public read accessors (``npc_for``, ``all_npcs``)
    are how B6.5w2 will compose ``NPC_STATE_BCAST`` payloads.
    """

    def __init__(self) -> None:
        self.npcs: dict[int, NPCRuntime] = {}     # form_id -> runtime
        self.cells_loaded: list[str] = []         # cell_name labels for log/diag

    # ------------------------------------------------------------ load

    def load_cell(self, json_path: Path) -> int:
        """Load all NPCs from one waypoint JSON. Returns count added.

        JSON format reference: ``net/server/waypoints/drumlin_diner.json``.

        Hex-string IDs (``"0x000FF812"``) match ``persistence.py``'s
        snapshot convention. Plain ints are also accepted. Duplicate
        ``form_id`` overwrites with a warning (last-load-wins).
        """
        data = json.loads(json_path.read_text(encoding="utf-8"))
        cell_label = str(data.get("cell_name", json_path.stem))
        cell_id = _parse_hex(data.get("cell_id", 0))

        added = 0
        for n in data.get("npcs", []):
            spec = NPCSpec(
                form_id=_parse_hex(n["form_id"]),
                base_id=_parse_hex(n["base_id"]),
                cell_id=cell_id,
                name=str(n.get("name", "")),
                waypoints=tuple(
                    Waypoint(
                        x=float(w["x"]),
                        y=float(w["y"]),
                        z=float(w["z"]),
                        yaw=float(w.get("yaw", 0.0)),
                        dwell_s=float(w.get("dwell_s", 0.0)),
                    )
                    for w in n.get("waypoints", [])
                ),
                walk_speed_ftps=float(n.get("walk_speed_ftps", 4.0)),
                arrive_radius_ft=float(n.get("arrive_radius_ft", 32.0)),
            )

            # Spawn position resolution: explicit > first waypoint > origin.
            spawn = n.get("spawn")
            if spawn is None:
                if not spec.waypoints:
                    log.warning(
                        "npc_brain: %s has no waypoints and no spawn; "
                        "anchoring at origin",
                        spec.name or hex(spec.form_id))
                    px = py = pz = 0.0
                    yaw = 0.0
                else:
                    wp0 = spec.waypoints[0]
                    px, py, pz, yaw = wp0.x, wp0.y, wp0.z, wp0.yaw
            else:
                px = float(spawn["x"])
                py = float(spawn["y"])
                pz = float(spawn["z"])
                yaw = float(spawn.get("yaw", 0.0))

            # B6.5w12 v14 Ghost AI per-NPC overrides (optional in JSON).
            # Each field if present forces the engine's corresponding
            # decision-point hook to substitute the server's value for
            # this NPC. Default 0 = "no override; vanilla AI decides".
            package_fid = _parse_hex(n.get("package_form_id", 0))
            combat_tgt_fid = _parse_hex(n.get("combat_target_form_id", 0))

            runtime = NPCRuntime(
                spec=spec,
                pos_x=px, pos_y=py, pos_z=pz,
                yaw=yaw,
                package_form_id=package_fid,
                combat_target_form_id=combat_tgt_fid,
            )
            if spec.form_id in self.npcs:
                log.warning(
                    "npc_brain: duplicate form_id 0x%X — overwriting "
                    "(prev cell=0x%X, new cell=0x%X)",
                    spec.form_id,
                    self.npcs[spec.form_id].spec.cell_id,
                    spec.cell_id,
                )
            self.npcs[spec.form_id] = runtime
            added += 1

        self.cells_loaded.append(cell_label)
        log.info(
            "npc_brain: loaded %d npc(s) from %s (cell=%s, cell_id=0x%X)",
            added, json_path.name, cell_label, cell_id,
        )
        return added

    # ------------------------------------------------------------ tick

    def tick(self, now_ms: float, dt_s: float) -> int:
        """Advance every NPC by ``dt_s`` seconds. Returns count ticked.

        Pure compute. Caller decides cadence (default 10 Hz from
        ``main.py::_periodic_npc_brain_tick``).

        Negative ``dt_s`` is clamped to 0 (defensive — should never
        happen with monotonic clocks, but a paused/rewound system clock
        shouldn't roll NPCs backwards).
        """
        if dt_s < 0.0:
            dt_s = 0.0
        n = 0
        for runtime in self.npcs.values():
            self._tick_one(runtime, now_ms, dt_s)
            n += 1
        return n

    def _tick_one(self, npc: NPCRuntime, now_ms: float, dt_s: float) -> None:
        npc.last_tick_ms = now_ms
        if not npc.spec.waypoints:
            # No path → permanent IDLE. Defensive — load_cell warns on this.
            if npc.anim_state != int(AnimState.IDLE):
                npc.anim_state = int(AnimState.IDLE)
                npc.last_change_ms = now_ms
            return

        # Are we dwelling at a waypoint?
        if npc.dwell_until_ms > 0.0:
            if now_ms < npc.dwell_until_ms:
                if npc.anim_state != int(AnimState.IDLE):
                    npc.anim_state = int(AnimState.IDLE)
                    npc.last_change_ms = now_ms
                return
            # Dwell expired — fall through to walk logic.
            npc.dwell_until_ms = 0.0

        wp = npc.spec.waypoints[npc.waypoint_idx]
        dx = wp.x - npc.pos_x
        dy = wp.y - npc.pos_y
        dz = wp.z - npc.pos_z
        dist = math.sqrt(dx * dx + dy * dy + dz * dz)

        if dist < npc.spec.arrive_radius_ft:
            # Arrive: snap, set facing, advance index, optionally enter dwell.
            npc.pos_x = wp.x
            npc.pos_y = wp.y
            npc.pos_z = wp.z
            npc.yaw = wp.yaw
            if wp.dwell_s > 0.0:
                npc.dwell_until_ms = now_ms + wp.dwell_s * 1000.0
                if npc.anim_state != int(AnimState.IDLE):
                    npc.anim_state = int(AnimState.IDLE)
                    npc.last_change_ms = now_ms
            # else: anim_state untouched — leave WALKING so passthrough
            # at a no-dwell waypoint doesn't visually flicker on the
            # client when w3 lands.
            npc.waypoint_idx = (npc.waypoint_idx + 1) % len(npc.spec.waypoints)
            return

        # Walk one step toward the waypoint.
        step = npc.spec.walk_speed_ftps * dt_s
        if step > dist:
            step = dist
        if dist > 0.0:
            inv = step / dist
            npc.pos_x += dx * inv
            npc.pos_y += dy * inv
            npc.pos_z += dz * inv
            # atan2(dy, dx) yields radians; convert to degrees. yaw=0
            # faces +X, increases counter-clockwise. Bethesda's
            # convention is yaw=0 faces +Y (north), clockwise. We store
            # the math convention; the w3 client receiver will translate
            # at apply time. (Documented here so the future reader of
            # ``apply_npc_state_to_engine`` knows where to negate.)
            npc.yaw = math.degrees(math.atan2(dy, dx))
        if npc.anim_state != int(AnimState.WALKING):
            npc.anim_state = int(AnimState.WALKING)
            npc.last_change_ms = now_ms

    # ------------------------------------------------------------ accessors

    def all_npcs(self) -> list[NPCRuntime]:
        """Snapshot list — caller may not mutate. Used by w2 broadcast."""
        return list(self.npcs.values())

    def npc_for(self, form_id: int) -> Optional[NPCRuntime]:
        return self.npcs.get(form_id)

    def count(self) -> int:
        return len(self.npcs)


# ------------------------------------------------------------------ helpers

def _parse_hex(s: Any) -> int:
    """Accept ``'0x...'`` (or plain) hex string OR raw int. Caller owns errors."""
    if isinstance(s, int):
        return s
    return int(str(s), 16)
