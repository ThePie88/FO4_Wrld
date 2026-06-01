// ============================================================================
// NOT INSTALLED — 2026-05-17. install_all.cpp:248 has only `(void)install_ghost_ai_process_movement;`
// for ODR; actual install call is OUT (see install_all.cpp:235 "pending review").
//
// LOG PROOF: `[ghost_ai_procmov]` strings absent from both client logs.
//
// WHY DISABLED:
//   Hook detours `AIProcess::ProcessPackages_Movement` (sub_140CEEC30).
//   Bailing it for tracked NPCs would prevent the AI's package iteration
//   from generating movement intent. Same effect as ghost_ai_movement
//   (which bails the downstream wrapper `Actor::TickMovementController`),
//   but at an earlier point in the chain.
//
//   B6.6w4 chose the wrapper bail over this package-iteration bail because:
//     - The wrapper bail is simpler (single Actor* arg, no bridge needed).
//     - Bailing the package iterator might starve OTHER AI subsystems
//       (perception updates, faction list refresh, dialogue triggers)
//       that share the same iteration loop.
//
//   "Pending review" means: empirically wrapper bail is sufficient; this
//   hook adds no value over what ghost_ai_movement does. But the detour
//   body is correct; could replace ghost_ai_movement if a cleaner design
//   ever wants a single-point intercept.
//
// KEEP-AS-IS RATIONALE:
//   Alternative-architecture artifact. Don't delete; revisit if the
//   wrapper-level bail (ghost_ai_movement) develops issues that the
//   package-level bail would solve.
// ============================================================================

#include "ghost_ai_process_movement.h"

#include <windows.h>
#include <atomic>
#include <cstdint>

#include "../hook_manager.h"
#include "../log.h"
#include "../offsets.h"
#include "npc_ai_suppress.h"   // is_actor_bail_tracked
#include "ownership_manager.h" // Build 65: owner-driven predicate

namespace fw::hooks {

namespace {

// `AIProcess::ProcessPackages_Movement(AIProcess* rcx, Actor* rdx, char a3)`.
// Returns __int64 (per IDA), we treat as opaque passthrough.
using ProcessMovementFn =
    std::int64_t (*)(void* aiproc, void* actor, char flag);

ProcessMovementFn g_orig_process_movement = nullptr;

std::atomic<std::uint64_t> g_fires{0};
std::atomic<std::uint64_t> g_bails{0};
std::atomic<std::uint64_t> g_seh_failures{0};
std::atomic<bool>          g_installed{false};

constexpr std::uint32_t PLAYER_FORM_ID = 0x00000014;

static std::uint32_t safe_read_actor_fid(const void* actor) noexcept {
    if (!actor) return 0xFFFFFFFFu;
    __try {
        return *reinterpret_cast<const std::uint32_t*>(
            reinterpret_cast<const std::uint8_t*>(actor) +
            fw::offsets::FORMID_OFF);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0xFFFFFFFFu;
    }
}

static bool fid_looks_real(std::uint32_t fid) noexcept {
    if (fid == 0 || fid == 0xFFFFFFFFu) return false;
    const std::uint32_t hi = fid & 0xFF000000u;
    return hi == 0x00000000u || hi == 0xFF000000u;
}

std::int64_t __fastcall detour_process_movement(void* aiproc, void* actor,
                                                char flag) {
    __try {
        const auto n = g_fires.fetch_add(1, std::memory_order_relaxed);
        const std::uint32_t fid = safe_read_actor_fid(actor);
        const bool plausible = fid_looks_real(fid);

        if (n < 10) {
            FW_LOG("[ghost_ai_procmov] fire #%llu aiproc=%p actor=%p "
                   "fid=0x%08X flag=%d plausible=%d",
                   static_cast<unsigned long long>(n), aiproc, actor, fid,
                   static_cast<int>(flag), plausible ? 1 : 0);
        } else if ((n % 5000) == 0) {
            FW_DBG("[ghost_ai_procmov] fire #%llu (heartbeat, bails=%llu)",
                   static_cast<unsigned long long>(n),
                   static_cast<unsigned long long>(
                       g_bails.load(std::memory_order_relaxed)));
        }

        if (plausible && fid != PLAYER_FORM_ID) {
            bool should_bail = fw::hooks::should_freeze_actor(fid);

            // Build 65 — owner-driven override (with fallback).
            if (fw::ownership::is_owner_of(fid)) {
                should_bail = false;
            } else if (fw::ownership::is_non_owner_tracked(fid)) {
                should_bail = true;
            }

            if (should_bail) {
                const auto bn = g_bails.fetch_add(
                    1, std::memory_order_relaxed);
                if (bn < 10) {
                    FW_LOG("[ghost_ai_procmov] BAIL #%llu fid=0x%08X "
                           "(skipping ProcessPackages_Movement)",
                           static_cast<unsigned long long>(bn), fid);
                }
                return 0;
            }
        }

        if (g_orig_process_movement) {
            return g_orig_process_movement(aiproc, actor, flag);
        }
        return 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        g_seh_failures.fetch_add(1, std::memory_order_relaxed);
        FW_ERR("[ghost_ai_procmov] SEH in detour (actor=%p)", actor);
        return 0;
    }
}

} // namespace

bool install_ghost_ai_process_movement(std::uintptr_t module_base) {
    if (g_installed.load(std::memory_order_acquire)) {
        FW_LOG("[ghost_ai_procmov] already installed; skipping");
        return true;
    }
    const auto target_ea =
        module_base + fw::offsets::AIPROCESS_PROCESS_MOVEMENT_RVA;
    const bool ok = install(
        reinterpret_cast<void*>(target_ea),
        reinterpret_cast<void*>(&detour_process_movement),
        reinterpret_cast<void**>(&g_orig_process_movement));
    if (ok) {
        g_installed.store(true, std::memory_order_release);
        FW_LOG("[ghost_ai_procmov] AIProcess::ProcessPackages_Movement "
               "hook installed at 0x%llX (RVA 0x%lX) — movement decision "
               "funnel; tracked NPCs skip package iteration",
               static_cast<unsigned long long>(target_ea),
               static_cast<unsigned long>(
                   fw::offsets::AIPROCESS_PROCESS_MOVEMENT_RVA));
    } else {
        FW_ERR("[ghost_ai_procmov] hook FAILED at 0x%llX",
               static_cast<unsigned long long>(target_ea));
    }
    return ok;
}

std::uint64_t get_ghost_ai_process_movement_fires() {
    return g_fires.load(std::memory_order_relaxed);
}
std::uint64_t get_ghost_ai_process_movement_bails() {
    return g_bails.load(std::memory_order_relaxed);
}
std::uint64_t get_ghost_ai_process_movement_seh_failures() {
    return g_seh_failures.load(std::memory_order_relaxed);
}

} // namespace fw::hooks
