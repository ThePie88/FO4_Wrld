// B6.6w0 NUKE hook — `sub_140CCFDF0` = Actor::vt[255] combat orchestrator.
//
// Per A1 dossier this is the per-actor per-frame combat brain entry.
// Bailing it for tracked NPCs short-circuits the ENTIRE combat
// pipeline (target promotion, fire decide chain, dispatch attack,
// aim update, ...) for that actor in one shot.
//
// This is the top-level "shut up" switch. Combined with existing
// freeze hooks (Update_PerFrame, motion writers) and hit_applier BAIL,
// tracked NPCs become completely neutral.
#pragma once

#include <cstdint>

namespace fw::hooks {

bool install_ghost_ai_combat_orchestrator(std::uintptr_t module_base);

std::uint64_t get_ghost_ai_combat_orchestrator_fires();
std::uint64_t get_ghost_ai_combat_orchestrator_bails();
std::uint64_t get_ghost_ai_combat_orchestrator_seh_failures();

} // namespace fw::hooks
