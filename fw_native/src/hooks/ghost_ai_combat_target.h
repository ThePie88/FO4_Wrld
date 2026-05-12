// B6.5w12 Ghost AI hook #2 — Actor::SyncCombatTargetFromAIProcess detour.
//
// MinHook on sub_140C5CCE0 @ RVA 0x00C5CCE0. Per agent 1 dossier
// (re/B6.5w12_round1_AGENT_1.md), this 0x74-byte function is called
// per-actor per-frame from inside Actor::Update_PerFrame and mirrors the
// combat-target form_id from AIProcess+0x6C to Actor+0x380 plus toggles
// the InCombat flag (bit 0x4000 in Actor+0x2D0). This is THE write path
// the engine uses to keep an actor's "I'm fighting X" state up to date.
//
// Ghost AI substitution strategy (Phase 4 step B, not in this skeleton):
//   For tracked actors with a non-zero server.combat_target_form_id:
//     - Write the server's form_id directly into Actor+0x380
//     - Force the InCombat flag bit 0x4000 in Actor+0x2D0
//     - Skip the original (which would otherwise overwrite with
//       AIProcess+0x6C, undoing our work the next frame)
//   For all other actors:
//     - Pass through to original
//
// THIS STEP (Phase 4 step A — SKELETON ONLY):
//   Install + log first-10 fires + passthrough. Confirms RVA correct,
//   signature compatible, no crashes. Phase 4 step B adds the actual
//   tracked-set lookup + substitution + InCombat-flag mutation.

#pragma once

#include <cstdint>

namespace fw::hooks {

bool install_ghost_ai_combat_target(std::uintptr_t module_base);

std::uint64_t get_ghost_ai_combat_target_fires();
std::uint64_t get_ghost_ai_combat_target_seh_failures();

} // namespace fw::hooks
