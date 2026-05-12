// B6.6w0 hook #5 — `sub_140CD2780` central hit applier orchestrator.
//
// CRITICAL for crash prevention. Per D2 dossier this function is the
// single funnel for ALL damage paths (projectile, melee, explosion,
// magic DOT, fire, fall): each impacted Actor's hit processing
// converges here, then fans out to stagger / hit-reaction / HP / ragdoll
// sub-handlers.
//
// Live test 2026-05-12 evening: Client B crashed when player shot a
// frozen "friendly" raider. Root cause hypothesis: this function tries
// to apply stagger anim + hit reaction onto a FROZEN anim graph
// (Update_PerFrame bailed). Anim graph state machine stuck → next
// frame an inconsistent transition AVs → crash.
//
// Fix: BAIL the entire orchestrator when target Actor is in the
// freeze set. Skips ALL inner calls (stagger, hit-anim, HP, ragdoll).
//
// Side effects of bailing:
//   - Damage dealt by player to frozen NPC is NEVER applied locally
//     (no HP decrement). Server-side HP authority (B6.6w-extra) is the
//     intended path; for MVP we accept "frozen NPCs are effectively
//     invulnerable client-side."
//   - No hit-reaction visible. Frozen NPCs already don't visibly react
//     to anything (they're statues), so this is consistent.
//   - No ragdoll on death. Same reasoning.
//
// Args (signature from funcs_0307.md:6911):
//   __int64 __fastcall sub_140CD2780(__m128 *a1, __m128 *a2);
//   a1 = hit-data struct (rcx). `a1[48].m128_u64[0]` = a1+0x300 = target Actor*.
//   a2 = secondary vector data (rdx). Not used by us.
//
// Returns __int64 (per IDA). We return 0 on bail.
#pragma once

#include <cstdint>

namespace fw::hooks {

bool install_ghost_ai_hit_applier(std::uintptr_t module_base);

std::uint64_t get_ghost_ai_hit_applier_fires();
std::uint64_t get_ghost_ai_hit_applier_bails();
std::uint64_t get_ghost_ai_hit_applier_seh_failures();

} // namespace fw::hooks
