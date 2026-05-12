// B6.5w13 belt-and-braces hook — TESObjectREFR::SetPosition_NiPoint3.
//
// Per re/B6.5w13_root_AGENT_2.md: this is the single funnel for all
// Actor+0xD0 writes (82 callers across the engine). Of note, AIPackage
// executor sub_140CEEC30 has 8 direct calls for warp/idle packages that
// bypass MovementController entirely. Hook #4 (movement wrapper) alone
// can't catch those.
//
// Hooking SetPosition is a fail-safe: any path that tries to write pos
// for a tracked NPC with movement_override gets bailed.

#pragma once

#include <cstdint>

namespace fw::hooks {

bool install_ghost_ai_pos_belt(std::uintptr_t module_base);

std::uint64_t get_ghost_ai_pos_belt_fires();
std::uint64_t get_ghost_ai_pos_belt_bails();
std::uint64_t get_ghost_ai_pos_belt_seh_failures();

} // namespace fw::hooks
