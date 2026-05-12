// B6.6w0 hook #3 (fire decision) — CombatBehaviorGunFire::DecideAndFire.
//
// MinHook detour on RVA 0x86FCA0 (per re/B6.6w0_pair_AGENT_C1.md, cross-
// checked by C2). This is the single funnel point where the gun-fire
// behavior-tree leaf decides "fire this tick OR fail-branch retry".
//
// Why it matters: live test (v5 freeze deployed 2026-05-12) showed
// frozen raiders STILL FIRE weapons at the player. Diagnosis (C1 §3):
// the gun-fire path runs on CombatManager::Update (RVA 0xED1BB0), a
// SIBLING tick to Actor::Update_PerFrame (RVA 0xC636A0) which we already
// bail. Suppressing one does not suppress the other.
//
// Plan (3 phases):
//   Phase A — DIAGNOSTIC ONLY. Hook fires every shot decision; we just
//     walk the TLS chain to derive owner Actor* and log fid. Verifies
//     the chain offsets (medium confidence per C1) without behavior
//     change. Goal: counter > 0 during live combat; logged fids match
//     known raiders.
//   Phase B — BAIL TRACKED. Once Phase A confirms the chain works,
//     enable `return 0` for actors in the shared dynamic bail set.
//     Goal: tracked raiders stop firing entirely.
//   Phase C — GRANULAR FIRE. Wire raider_brain's `fire_this_tick` flag
//     through the cache; bail when flag=0, pass-through when flag=1.
//     Server decides every shot.
//
// This header exposes install + diagnostic counters in the same shape
// as the v5 freeze hooks.
#pragma once

#include <cstdint>

namespace fw::hooks {

bool install_ghost_ai_fire(std::uintptr_t module_base);

// Diagnostic counters (atomic, lock-free reads).
std::uint64_t get_ghost_ai_fire_fires();
std::uint64_t get_ghost_ai_fire_bails();
std::uint64_t get_ghost_ai_fire_seh_failures();

} // namespace fw::hooks
