// B6.5w15 DIAGNOSTIC ONLY hook — bhkCharRigidBodyController::FinishPhysicsStep
//
// Per re/B6.5w14_pair_AGENT_5A.md: candidate path for the per-frame pos
// mover that bypasses hooks #5 + #6. This hook logs only — no bail.
// Verifies whether the function actually fires for our tracked combat
// raiders at per-frame rate.

#pragma once

#include <cstdint>

namespace fw::hooks {

bool install_ghost_ai_havok_step(std::uintptr_t module_base);

std::uint64_t get_ghost_ai_havok_step_fires();
std::uint64_t get_ghost_ai_havok_step_tracked_fires();
std::uint64_t get_ghost_ai_havok_step_seh_failures();

} // namespace fw::hooks
