// B6.5w12 Ghost AI hook #4 — Actor::TickMovementController detour.
//
// MinHook on sub_140C65E20 @ RVA 0x00C65E20. Per agent 2 dossier
// (re/B6.5w12_round1_AGENT_2.md): 291-byte per-actor per-frame wrapper.
// Called from THREE paths and they all funnel through this single
// function:
//   - High-tier movement walker (sub_140DA9B30)
//   - CombatManager::Update (sub_140ED1BB0)
//   - Actor::Update_PerFrame inline copy
// Detouring here covers movement across all AI contexts including combat.
//
// Substitution strategy (Phase 4 step B, in this file):
//   If cache.movement_override != 0 for the actor → BAIL the function
//   (don't call original). The engine's MovementControllerNPC::Tick
//   doesn't fire, so no nav/path/havok movement integration happens for
//   the actor this frame. Pos stays where it was. Result: visible
//   "raider freezes in place" while combat-target (hook #2) is still
//   driven, so the raider is "in combat but motionless" — easy to verify
//   by eye.
//
// SKELETON path (when movement_override == 0): pass through to original.
// Engine's vanilla movement integration runs unchanged.

#pragma once

#include <cstdint>

namespace fw::hooks {

bool install_ghost_ai_movement(std::uintptr_t module_base);

std::uint64_t get_ghost_ai_movement_fires();
std::uint64_t get_ghost_ai_movement_bails();
std::uint64_t get_ghost_ai_movement_seh_failures();

} // namespace fw::hooks
