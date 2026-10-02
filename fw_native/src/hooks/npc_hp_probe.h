// ============================================================================
// N3 (shared HP) — STEP 1: READ-ONLY diagnostic probe on the HP-write funnel
// sub_140CC9650 (RVA 0xCC9650).
//
// Purpose: confirm 3 RUNTIME facts in-engine BEFORE building the real
// capture+clamp, so we don't guess. From the 3-agent decomp RE (2026-06-04):
//   (1) Is the funnel's `delta` arg (a4) == the FINAL applied Health damage
//       (old_hp - new_hp), i.e. already post-resist / post-perk for our raiders,
//       or does the funnel re-derive it (the vtable+2440 "special mode")?
//   (2) Does reading the Health cell at Actor+0x444 (sum of its 3 float columns)
//       actually track current HP across the write?
//   (3) Does the `source` arg (a5 = aggressor Actor*) decode to the firer, and
//       is the by_player check correct?
//
// GUARANTEES: ZERO writes, ZERO clamp, ZERO network, ZERO arg mutation. The
// detour ALWAYS calls the original with the original arguments. Gated to
// server-tracked raiders + avIdx==2 only. Every memory read is SEH-caged in a
// helper (the detour itself has no __try → no C2712 with C++ unwind objects).
// Kill-switch: set_hp_probe_enabled(false).
// ============================================================================
#pragma once

#include <cstdint>

namespace fw::hooks {

// Install the read-only detour on sub_140CC9650. Idempotent-safe via the
// hook manager. Returns true on success.
bool install_npc_hp_probe(std::uintptr_t module_base);

// Runtime kill-switches. Default ON. `set_hp_probe_enabled(false)` silences the
// diagnostic log; `set_hp_capture_enabled(false)` stops the server damage claim.
void set_hp_probe_enabled(bool on) noexcept;
void set_hp_capture_enabled(bool on) noexcept;   // N3 — toggle the shared-pool damage report
void set_hp_clamp_enabled(bool on) noexcept;     // N3 round 2 — toggle the floor-1 clamp

// vita-locale-dal-pool (HP bar) — set the actor's LOCAL Health so the vanilla
// enemy-health bar renders the SHARED pool fraction. target = AVO.GetMax *
// (pool_cur/pool_max), floored ≥1, applied as a delta through the original funnel
// (no detour re-entry). Called from the main-thread pool-health drain after
// lookup_by_form_id. SEH-caged; no-op on null actor / unresolvable Health AVInfo.
// MAIN THREAD ONLY.
void apply_pool_health_to_actor(void* actor, float pool_cur, float pool_max) noexcept;

// L5 stage 3d (2026-09-29) — the respawn heals. The checkpoint the player
// comes back from keeps the health and the radiation it was written with
// (the resurrect of stage 3c restored them, a reload does not). Rads first
// (registry index 58: clearing them raises the maximum health, see
// sub_1406C9C90), then the damage column of the Health cell back to zero.
// Both through the ORIGINAL HP funnel, the one radiation and every health
// change pass through, never through our detour. MAIN THREAD. False when
// a read or the registry failed; `out` says what was seen either way.
struct HealReport {
    float health_damage_before = 0.0f;   // Health cell column 2, <= 0 when hurt
    float rads_before = 0.0f;
    float health_damage_after = 0.0f;
    float rads_after = 0.0f;
};
bool heal_local_player(void* player, HealReport* out) noexcept;

// Diagnostics.
std::uint64_t get_hp_probe_fires()    noexcept;  // # of diagnostic log fires
std::uint64_t get_hp_probe_captures() noexcept;  // # of damage claims sent to the pool
std::uint64_t get_hp_probe_clamps()   noexcept;  // # of clamp-to-floor events
std::uint64_t get_hp_probe_seh()      noexcept;  // # of SEH faults swallowed in the read helpers

} // namespace fw::hooks
