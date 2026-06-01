// ============================================================================
// LIVE (preventive) — 2026-05-17. Installed at install_all.cpp:174. Detour
// fires on every BGSActionData::Execute call (universal attack funnel),
// passthrough for most actors, BAIL when target == ghost.
//
// LOG PROOF (Client A `fw_native.log` 17:29-17:39):
//   No `[ghost_ai_action_execute] BAIL` lines.
//   Counter g_bails likely 0 (raiders never fire ON the duplicate in
//   current architecture — they fire on player_A naturally).
//
// WHY KEEP RUNNING:
//   The Builds 18-19 forensic established this hook's BAIL-when-target-
//   equals-duplicate path is critical to prevent the funcs_0311.md:1621/1625
//   SEH chain inside sub_140CEC490→sub_140D0CF70 when raider's combat AI
//   tries to InterlockedInc/Dec the duplicate's PlayerNPC-inherited
//   refcount byte. Even though that scenario doesn't trigger in current
//   tests, ANY future scenario where engine combat brain dispatches an
//   attack at our duplicate would crash without this guard.
//
// Build 19 fix critical: returns 1 (not 0) on BAIL — engine thinks action
// executed → post-action update runs → raider stays in combat state.
// Returning 0 caused raiders to go idle in <1s after entering attack pose
// (Build 18 regression).
//
// KEEP-AS-IS RATIONALE:
//   Preventive guard; zero-cost when ghost is never targeted; critical
//   when it eventually is (puppet fire pivot might end up with engine
//   doing some ambient queries on duplicate when it's nominally aim
//   target).
// ============================================================================

#include "ghost_ai_action_execute.h"

#include <windows.h>
#include <atomic>
#include <cstdint>

#include "../hook_manager.h"
#include "../log.h"
#include "../engine/engine_calls.h"   // get_ghost_duplicate

namespace fw::hooks {

namespace {

// `BGSActionData::Execute` entry — `sub_140E6F830`.
// Verified at D:\falloutworld_decomp\out\10_decomp\funcs_0334.md:7289
//   __int64 __fastcall sub_140E6F830(__int64 a1, int a2, int a3);
// a1 = target actor*, a2 = action_id (14/15/17/19 per fire flags),
// a3 = slot index from CombatBehaviorGunFire dispatcher.
using ActionExecuteFn = std::uint64_t (*)(std::uint64_t target,
                                          int action_id,
                                          int slot);

constexpr std::uintptr_t ACTION_EXECUTE_RVA = 0x00E6F830;

ActionExecuteFn g_orig_action_execute = nullptr;

std::atomic<std::uint64_t> g_fires{0};
std::atomic<std::uint64_t> g_bails{0};
std::atomic<std::uint64_t> g_seh_failures{0};
std::atomic<bool>          g_installed{false};

// Detour. Bail (return 0) when the target arg is our duplicate.
// This preempts the BGSActionData::Execute → sub_140CEC490 → sub_140D0CF70
// chain at funcs_0311.md:1621/1625 where engine InterlockedInc/Dec
// on real_player's owned AIProcess sub-object refcount byte —
// the smoking gun identified by re/B6.6w5_build16_forensic.md.
//
// Normal flow (target != duplicate) passes through to orig.
std::uint64_t __fastcall detour_action_execute(std::uint64_t target,
                                               int action_id,
                                               int slot) {
    __try {
        const auto n = g_fires.fetch_add(1, std::memory_order_relaxed);

        void* duplicate = fw::engine::get_ghost_duplicate();
        const bool is_duplicate = duplicate
            && target == reinterpret_cast<std::uint64_t>(duplicate);

        if (is_duplicate) {
            const auto bn = g_bails.fetch_add(1, std::memory_order_relaxed);
            if (bn < 20 || (bn % 100) == 0) {
                FW_LOG("[ghost_ai_action_execute] BAIL #%llu target=%p "
                       "(= duplicate) action_id=%d slot=%d — return 1 "
                       "(action executed successfully) so engine keeps "
                       "raider in combat state instead of going idle",
                       static_cast<unsigned long long>(bn),
                       reinterpret_cast<void*>(target), action_id, slot);
            }
            // Build 19 fix: return 1 instead of 0.
            //
            // Build 18 live test (2026-05-13): no crash but raiders went
            // idle in <1s after entering attack pose. Per sub_14086DC80
            // (funcs_0239.md:5408-5413):
            //   v20 = sub_140E6F830(v5, v18);
            //   if (v20 && a1[4]) { sub_140ED71A0; sub_140E69FC0; }
            // Returning 0 (Build 18) made the engine think "action did
            // not execute" → skip post-action update → raider abandons
            // combat behavior → idle.
            //
            // Returning 1 makes engine think action succeeded → post-
            // action runs → raider stays engaged. sub_140ED71A0 and
            // sub_140E69FC0 take a1[4] (some weapon ptr / combat data
            // struct), not the target directly — should be safe even
            // though we didn't actually execute the action.
            return 1;
        }

        if (n < 10) {
            FW_LOG("[ghost_ai_action_execute] fire #%llu target=%p "
                   "action_id=%d slot=%d — passthrough",
                   static_cast<unsigned long long>(n),
                   reinterpret_cast<void*>(target), action_id, slot);
        } else if ((n % 1000) == 0) {
            FW_DBG("[ghost_ai_action_execute] fire #%llu (heartbeat, "
                   "bails=%llu)",
                   static_cast<unsigned long long>(n),
                   g_bails.load(std::memory_order_relaxed));
        }

        if (g_orig_action_execute) {
            return g_orig_action_execute(target, action_id, slot);
        }
        return 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        g_seh_failures.fetch_add(1, std::memory_order_relaxed);
        FW_ERR("[ghost_ai_action_execute] SEH in detour (target=%p)",
               reinterpret_cast<void*>(target));
        return 0;
    }
}

} // namespace

bool install_ghost_ai_action_execute(std::uintptr_t module_base) {
    if (g_installed.load(std::memory_order_acquire)) {
        FW_LOG("[ghost_ai_action_execute] already installed; skipping");
        return true;
    }
    const auto target_ea = module_base + ACTION_EXECUTE_RVA;
    const bool ok = install(
        reinterpret_cast<void*>(target_ea),
        reinterpret_cast<void*>(&detour_action_execute),
        reinterpret_cast<void**>(&g_orig_action_execute));
    if (ok) {
        g_installed.store(true, std::memory_order_release);
        FW_LOG("[ghost_ai_action_execute] BGSActionData::Execute hook "
               "installed at 0x%llX (RVA 0x%lX) — Build 18 bail-on-duplicate "
               "to preempt funcs_0311.md:1621/1625 SEH chain",
               static_cast<unsigned long long>(target_ea),
               static_cast<unsigned long>(ACTION_EXECUTE_RVA));
    } else {
        FW_ERR("[ghost_ai_action_execute] hook FAILED at 0x%llX",
               static_cast<unsigned long long>(target_ea));
    }
    return ok;
}

std::uint64_t get_ghost_ai_action_execute_fires() {
    return g_fires.load(std::memory_order_relaxed);
}
std::uint64_t get_ghost_ai_action_execute_bails() {
    return g_bails.load(std::memory_order_relaxed);
}
std::uint64_t get_ghost_ai_action_execute_seh_failures() {
    return g_seh_failures.load(std::memory_order_relaxed);
}

} // namespace fw::hooks
