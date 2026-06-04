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

// Diagnostics.
std::uint64_t get_hp_probe_fires()    noexcept;  // # of diagnostic log fires
std::uint64_t get_hp_probe_captures() noexcept;  // # of damage claims sent to the pool
std::uint64_t get_hp_probe_clamps()   noexcept;  // # of clamp-to-floor events
std::uint64_t get_hp_probe_seh()      noexcept;  // # of SEH faults swallowed in the read helpers

} // namespace fw::hooks
