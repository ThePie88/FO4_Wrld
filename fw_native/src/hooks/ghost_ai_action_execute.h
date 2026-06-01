// B6.6w5 Build 18 — Hook on `sub_140E6F830` (BGSActionData::Execute entry).
//
// Per re/B6.6w5_build16_forensic.md, the engine path that crashes when
// raider's combat_target is our duplicate is:
//
//   sub_14086DC80 (CombatBehaviorGunFire dispatch, funcs_0239.md:5315)
//     → sub_140E6F830(target, action_id, slot) (funcs_0334.md:7286) ← HOOK HERE
//        → sub_140321F80 (ActionInput ctor, refcount inc on duplicate)
//        → TESActionData::vt[5] = sub_140DBFD20 → sub_140CE9280
//          → sub_140CEC490 → sub_140D0CF70(real_player.AIProcess, ...)
//            → funcs_0311.md:1621/1625: InterlockedInc/Dec on
//              real_player's owned AIProcess sub-object refcount byte
//              → cross-thread race / vtable destructor on live state
//              → CRASH
//
// The fix that didn't work: zero `duplicate+0x300` (AIProcess ptr).
// Build 17 live test (2026-05-13 17:26): cascade-fault on null deref
// in engine paths that DON'T null-check the AIProcess. Forensic
// agent's 5% reservation predicted this exact failure mode.
//
// Build 18 approach: hook `sub_140E6F830` and bail when the first arg
// (target) matches `fw::engine::get_ghost_duplicate()`. Engine's
// upstream code (aim resolution, animation rotation) runs normally
// — those don't touch the dangerous AIProcess walk. Downstream
// action execute is skipped — preempts the SEH chain.
//
// Side effect: raider doesn't "execute" the fire action on the
// duplicate, so engine-side combat group bookkeeping doesn't update.
// This is fine for the MVP — the visual aim is what matters; the
// projectile is fired via our separate `engine::fire_actor_weapon`
// NPC_FIRE trigger which (as Build 17 showed) we also need to gate.
//
// Signature (verified from decomp funcs_0334.md:7289):
//   __int64 __fastcall sub_140E6F830(__int64 target, int action_id, int slot);
//
// Returns: unsigned uint8 (cast to __int64). Bail returns 0
// (= "action did not execute").
#pragma once

#include <cstdint>

namespace fw::hooks {

bool install_ghost_ai_action_execute(std::uintptr_t module_base);

std::uint64_t get_ghost_ai_action_execute_fires();
std::uint64_t get_ghost_ai_action_execute_bails();
std::uint64_t get_ghost_ai_action_execute_seh_failures();

} // namespace fw::hooks
