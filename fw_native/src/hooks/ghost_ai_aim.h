// B6.5w12 Ghost AI hook #3 — CombatAimController::SetAimTarget detour.
//
// MinHook on sub_140E65820 @ RVA 0x00E65820. Per agent 1 dossier
// (re/B6.5w12_round1_AGENT_1.md): tiny (0x2A bytes) — writes target
// xyz into self+24/28/32 plus flag bit at +52 plus time at +56.
//
// SKELETON for this step: install + first-10-fire diagnostic dump of
// candidate offsets to locate the owner Actor from CombatAimController.
// Once owner located, step B will add the tracked-set lookup + aim
// coord substitution from cache.aim_x/y/z.

#pragma once

#include <cstdint>

namespace fw::hooks {

bool install_ghost_ai_aim(std::uintptr_t module_base);

std::uint64_t get_ghost_ai_aim_fires();
std::uint64_t get_ghost_ai_aim_seh_failures();

} // namespace fw::hooks
