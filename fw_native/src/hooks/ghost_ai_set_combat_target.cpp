#include "ghost_ai_set_combat_target.h"

#include <windows.h>
#include <atomic>
#include <cstdint>

#include "../hook_manager.h"
#include "../log.h"
#include "../offsets.h"
#include "npc_ai_suppress.h"   // get_fid_for_aiproc

namespace fw::hooks {

namespace {

// `AIProcess::SetCombatTarget(AIProcess* rcx, Actor* rdx)`.
using SetCombatTargetFn = void (*)(void* aiproc, void* new_target);

SetCombatTargetFn g_orig_set_combat_target = nullptr;

std::atomic<std::uint64_t> g_fires{0};
std::atomic<std::uint64_t> g_substitutions{0};
std::atomic<std::uint64_t> g_seh_failures{0};
std::atomic<bool>          g_installed{false};

static std::uint32_t safe_read_form_id(const void* form_or_ref) noexcept {
    if (!form_or_ref) return 0xFFFFFFFFu;
    __try {
        return *reinterpret_cast<const std::uint32_t*>(
            reinterpret_cast<const std::uint8_t*>(form_or_ref) +
            fw::offsets::FORMID_OFF);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0xFFFFFFFFu;
    }
}

// PHASE 1 = diagnostic only. No substitution this iteration.
void __fastcall detour_set_combat_target(void* aiproc, void* new_target) {
    __try {
        const auto n = g_fires.fetch_add(1, std::memory_order_relaxed);

        // Identify owner via the aiproc→fid map (populated by
        // npc_ai_suppress at Actor+0x328).
        std::uint32_t owner_fid = 0xFFFFFFFFu;
        const bool owner_known =
            aiproc && fw::hooks::get_fid_for_aiproc(aiproc, &owner_fid);

        const std::uint32_t target_fid = safe_read_form_id(new_target);

        if (n < 10) {
            FW_LOG("[ghost_ai_set_target] fire #%llu aiproc=%p owner_fid=0x%08X "
                   "owner_known=%d new_target=%p target_fid=0x%08X "
                   "(DIAGNOSTIC, no substitution yet)",
                   static_cast<unsigned long long>(n), aiproc, owner_fid,
                   owner_known ? 1 : 0, new_target, target_fid);
        } else if ((n % 1000) == 0) {
            FW_DBG("[ghost_ai_set_target] fire #%llu (heartbeat, subs=%llu)",
                   static_cast<unsigned long long>(n),
                   static_cast<unsigned long long>(
                       g_substitutions.load(std::memory_order_relaxed)));
        }

        // TODO Phase 2: if owner_known && owner is tracked &&
        // cache.combat_target_form_id != 0:
        //   lookup_by_form_id(server.target_fid) → new_target_ptr
        //   replace `new_target` in arg2
        //   g_substitutions++
        // For now pass through unchanged.

        if (g_orig_set_combat_target) {
            g_orig_set_combat_target(aiproc, new_target);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        g_seh_failures.fetch_add(1, std::memory_order_relaxed);
        FW_ERR("[ghost_ai_set_target] SEH in detour (aiproc=%p)", aiproc);
    }
}

} // namespace

bool install_ghost_ai_set_combat_target(std::uintptr_t module_base) {
    if (g_installed.load(std::memory_order_acquire)) {
        FW_LOG("[ghost_ai_set_target] already installed; skipping");
        return true;
    }
    const auto target_ea =
        module_base + fw::offsets::AIPROCESS_SET_COMBAT_TARGET_RVA;
    const bool ok = install(
        reinterpret_cast<void*>(target_ea),
        reinterpret_cast<void*>(&detour_set_combat_target),
        reinterpret_cast<void**>(&g_orig_set_combat_target));
    if (ok) {
        g_installed.store(true, std::memory_order_release);
        FW_LOG("[ghost_ai_set_target] AIProcess::SetCombatTarget hook "
               "installed at 0x%llX (RVA 0x%lX) — DIAGNOSTIC phase",
               static_cast<unsigned long long>(target_ea),
               static_cast<unsigned long>(
                   fw::offsets::AIPROCESS_SET_COMBAT_TARGET_RVA));
    } else {
        FW_ERR("[ghost_ai_set_target] hook FAILED at 0x%llX",
               static_cast<unsigned long long>(target_ea));
    }
    return ok;
}

std::uint64_t get_ghost_ai_set_combat_target_fires() {
    return g_fires.load(std::memory_order_relaxed);
}
std::uint64_t get_ghost_ai_set_combat_target_substitutions() {
    return g_substitutions.load(std::memory_order_relaxed);
}
std::uint64_t get_ghost_ai_set_combat_target_seh_failures() {
    return g_seh_failures.load(std::memory_order_relaxed);
}

} // namespace fw::hooks
