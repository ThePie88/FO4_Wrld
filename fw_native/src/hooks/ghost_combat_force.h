// Build 40 (2026-05-17) — ghost_combat_force: 4-hook surgical decision
// override making engine's vanilla AI treat our ghost proxy as a valid
// hostile target.
//
// Reference: re/AI_pipeline/MASTER.md cross-section synthesis identifies
// 4 independent root causes blocking raider→ghost combat:
//
//   A. HostilityCore returns 0 (neutral) — ghost.baseForm.factions[] has
//      no hostile relation to RaidersFaction. Section 10 §1.
//   C. Aim solver returns 0 — CombatAimController.target_pos stays at
//      sentinel because we don't trigger orchestrator's aim-update.
//      Section 08 (passive — fixed automatically by A+D).
//   D. Alive count stays 0 — sub_140E9E650 skips ghost-entry because
//      ghost+0x328 (HighProcess) is NULL. Section 03 §3.
//
//   (B = weapon-state class transition. Engine handles automatically
//    when A+D pass and EnterCombat triggers naturally.)
//
// Plus the post-pick gate (Section 06 §8) which threads "stay engaged"
// vs "re-pick" into the orchestrator. We force "stay engaged" for ghost.
//
// And cell-loaded (Section 06 §1) which gates many AI subsystems on
// target.parent_cell being loaded. Our ghost has parent_cell == NULL.
//
// Each detour:
//   - Reads ghost duplicate ptr via fw::engine::get_ghost_duplicate()
//   - Checks if any arg involves the ghost (actor pointer match or
//     ghost in controller's known_targets[] for the alive-counter)
//   - If yes: returns favorable value (hostile, alive, loaded, engaged)
//   - If no: passthrough to orig
//
// Side effects:
//   - Engine's vanilla AI runs unmodified for non-ghost actors.
//   - Vanilla AI on raiders sees ghost as hostile → enters combat →
//     handles locomotion / aim / fire / cover / state machine
//     organically.
//   - No puppet rendering, no manual state injection — engine drives
//     visuals from its own pipeline.
//
// Each hook is SEH-caged and logs first 8 fires + every 200th heartbeat.
#pragma once

#include <cstdint>

namespace fw::hooks {

bool install_ghost_combat_force(std::uintptr_t module_base);

// Diagnostic counters
std::uint64_t get_combat_force_hostility_fires();
std::uint64_t get_combat_force_hostility_overrides();
std::uint64_t get_combat_force_alive_fires();
std::uint64_t get_combat_force_alive_boosts();
std::uint64_t get_combat_force_cell_fires();
std::uint64_t get_combat_force_cell_overrides();
std::uint64_t get_combat_force_pick_fires();
std::uint64_t get_combat_force_pick_overrides();
std::uint64_t get_combat_force_seh_failures();

} // namespace fw::hooks
