// B6.5w4 — Per-Actor AI tick suppression.
//
// MinHook detour on Actor::Update_PerFrame@RVA 0xC636A0 (single funnel
// for all per-Actor AI work, RE'd in re/B6.5_npc_pipeline_AGENT_A.md).
// For Actors whose form_id is in fw::dispatch::g_tracked_npc_set
// (registered by the net thread on each NPC_STATE_BCAST), the detour
// returns without calling the original — vanilla AI is silenced and our
// server-authoritative pos/yaw/anim writes from B6.5w3 become the only
// authority over the NPC's state.
//
// Without this hook, vanilla AI runs at 60 Hz vs our 10 Hz pos write →
// engine wins 5 of 6 frames → NPC jitters + drifts to vanilla goal +
// each client diverges (independent AI processes on each side).
//
// Side effects of suppression for tracked NPCs:
//   - No pathfinding
//   - No anim graph update by AI (good — SetGraphVariable from w3.b wins)
//   - No gravity/collision check (NPC may float on Z mismatches)
//   - No combat/dialogue
// All intentional — server brain is authoritative.

#pragma once

#include <cstdint>

namespace fw::hooks {

// Install the MinHook detour on Actor::Update_PerFrame@0xC636A0.
// Returns true on success. Idempotent: subsequent calls return true if
// already installed.
bool install_npc_ai_suppress(std::uintptr_t module_base);

// Diagnostic counters (atomic, lock-free reads).
//   suppress: count of detour fires where form_id matched tracked set
//             and original was skipped.
//   passthrough: count of detour fires where form_id was NOT tracked
//                and original was invoked (normal AI tick).
//   seh_failures: count of detour fires where form_id read SEH-faulted.
std::uint64_t get_npc_ai_suppress_fires();
std::uint64_t get_npc_ai_passthrough_fires();
std::uint64_t get_npc_ai_seh_failures();

} // namespace fw::hooks
