#include "ghost_ai_package.h"

#include <windows.h>
#include <atomic>
#include <cstdint>

#include "../hook_manager.h"
#include "../log.h"
#include "../offsets.h"

namespace fw::hooks {

namespace {

// Engine signature (per agent 3 dossier — re/B6.5w12_round1_AGENT_3.md):
//   bool __fastcall sub_140768CC0(
//       __int64*** condition_list_head,   // = pkg + 0x60
//       void*      eval_ctx);             // 112-B struct from sub_140768260
using PkgEvalConditionsFn = bool (*)(void* condition_list_head, void* eval_ctx);

PkgEvalConditionsFn g_orig_pkg_eval_conditions = nullptr;

// Counters. Hot path is ~1-100 calls/sec per loaded actor (AI ticks
// every ~3 s for full package re-eval, more for forced re-evals); not
// performance-critical to use relaxed.
std::atomic<std::uint64_t> g_fires{0};
std::atomic<std::uint64_t> g_seh_failures{0};
std::atomic<bool>          g_installed{false};

// Phase 2 step B SKELETON: the detour just calls original and bumps
// counters. No tracked-set lookup, no package_form_id substitution.
//
// What the production detour will do (Phase 4):
//   1. SEH-guarded read of pkg form_id via the offset trick
//        pkg_fid = *(u32*)((char*)arg1 - 0x4C)
//      (since arg1 = pkg + 0x60 and TESForm.formID = pkg + 0x14).
//   2. SEH-guarded read of Actor* via eval_ctx + 8 → Actor.formID at +0x14.
//   3. Cache lookup: if Actor.formID ∈ tracked_set AND server's
//      cache[actor_fid].package_form_id ≠ 0, return
//      (pkg_fid == server.package_form_id).
//   4. Else passthrough to original.
//
// For the skeleton we just want PROOF the detour fires under AI activity.
// First 10 fires + every 1000th get logged. SEH cage wraps the whole body
// so a malformed arg never propagates to the original (defensive).
bool __fastcall detour_pkg_eval_conditions(void* condition_list_head,
                                          void* eval_ctx)
{
    bool result = false;
    __try {
        const auto n = g_fires.fetch_add(1, std::memory_order_relaxed);
        if (n < 10) {
            FW_LOG("[ghost_ai_pkg] fire #%llu — cond_list=%p eval_ctx=%p "
                   "(SKELETON: passthrough, no decision yet)",
                   static_cast<unsigned long long>(n),
                   condition_list_head, eval_ctx);
        } else if ((n % 1000) == 0) {
            FW_DBG("[ghost_ai_pkg] fire #%llu (heartbeat)",
                   static_cast<unsigned long long>(n));
        }
        if (g_orig_pkg_eval_conditions) {
            result = g_orig_pkg_eval_conditions(condition_list_head, eval_ctx);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        g_seh_failures.fetch_add(1, std::memory_order_relaxed);
        FW_ERR("[ghost_ai_pkg] SEH in detour (cond_list=%p eval_ctx=%p) — "
               "returning false to be safe",
               condition_list_head, eval_ctx);
        result = false;
    }
    return result;
}

} // namespace

bool install_ghost_ai_package(std::uintptr_t module_base) {
    if (g_installed.load(std::memory_order_acquire)) {
        FW_LOG("[ghost_ai_pkg] already installed; skipping");
        return true;
    }
    const auto target_ea =
        module_base + fw::offsets::PKG_EVAL_CONDITIONS_RVA;
    const bool ok = install(
        reinterpret_cast<void*>(target_ea),
        reinterpret_cast<void*>(&detour_pkg_eval_conditions),
        reinterpret_cast<void**>(&g_orig_pkg_eval_conditions));
    if (ok) {
        g_installed.store(true, std::memory_order_release);
        FW_LOG("[ghost_ai_pkg] TESPackage::EvaluateConditions hook installed "
               "at 0x%llX (RVA 0x%lX) — SKELETON, passthrough only",
               static_cast<unsigned long long>(target_ea),
               static_cast<unsigned long>(fw::offsets::PKG_EVAL_CONDITIONS_RVA));
    } else {
        FW_ERR("[ghost_ai_pkg] hook FAILED at 0x%llX — Ghost AI hook #1 "
               "will be inactive (server's package selection won't apply)",
               static_cast<unsigned long long>(target_ea));
    }
    return ok;
}

std::uint64_t get_ghost_ai_package_fires() {
    return g_fires.load(std::memory_order_relaxed);
}
std::uint64_t get_ghost_ai_package_seh_failures() {
    return g_seh_failures.load(std::memory_order_relaxed);
}

} // namespace fw::hooks
