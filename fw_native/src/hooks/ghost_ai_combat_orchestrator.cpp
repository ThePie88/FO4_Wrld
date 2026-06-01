// ============================================================================
// PASSTHROUGH ONLY — 2026-05-17. Hook installed but DEMOTED to diagnostic per
// inline comment at line ~64 ("Previously this BAILed for tracked actors...
// Replacement strategy: orchestrator runs unconditionally").
//
// LOG PROOF: install_all.cpp:247 has `(void)install_ghost_ai_combat_orchestrator;`
// — that's a function-pointer reference for ODR, NOT an install call. So this
// hook is NOT installed in current build (B6.6w5 Phase A v5).
//
// Check: search Client A `fw_native.log` for `[ghost_ai_orchestrator]`:
//   0 lines. Hook is dormant by install_all gate.
//
// WHY DISABLED IN install_all:
//   Per the demotion comment at line ~67, bailing this orchestrator caused
//   raiders to lose red compass marker and decay to neutral ("Talk" prompt).
//   The hostility re-eval AND the player-detection logic ALSO live inside
//   this orchestrator. Bailing it = friendly raiders.
//
// KEEP-AS-IS RATIONALE:
//   Detour body has a complete (counters, SEH cage, plausibility check)
//   skeleton. If a future redesign needs to intercept the orchestrator
//   (e.g., to inject a server-driven aim vector BEFORE the engine's aim
//   solver runs), this file is the install point. Cost of keeping
//   compiled-but-not-installed: ~5 KB binary.
// ============================================================================

#include "ghost_ai_combat_orchestrator.h"

#include <windows.h>
#include <atomic>
#include <cstdint>

#include "../hook_manager.h"
#include "../log.h"
#include "../offsets.h"
#include "npc_ai_suppress.h"   // should_freeze_actor

namespace fw::hooks {

namespace {

// `sub_140CCFDF0` = Actor::vt[255] = per-actor combat orchestrator.
// Signature per pseudo-C: `char __fastcall(Actor* a1, __int64 a2)`.
using CombatOrchestratorFn = char (*)(void* actor, std::int64_t a2);

CombatOrchestratorFn g_orig_orchestrator = nullptr;

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

char __fastcall detour_combat_orchestrator(void* actor, std::int64_t a2) {
    __try {
        const auto n = g_fires.fetch_add(1, std::memory_order_relaxed);
        const std::uint32_t fid = safe_read_actor_fid(actor);
        const bool plausible = fid_looks_real(fid);

        if (n < 10) {
            FW_LOG("[ghost_ai_orchestrator] fire #%llu actor=%p fid=0x%08X "
                   "a2=%lld plausible=%d",
                   static_cast<unsigned long long>(n), actor, fid,
                   static_cast<long long>(a2), plausible ? 1 : 0);
        } else if ((n % 1000) == 0) {
            FW_DBG("[ghost_ai_orchestrator] fire #%llu (heartbeat, bails=%llu)",
                   static_cast<unsigned long long>(n),
                   static_cast<unsigned long long>(
                       g_bails.load(std::memory_order_relaxed)));
        }

        // B6.6w0 (2026-05-12, post-live-test): DEMOTED to diagnostic.
        //
        // Previously this BAILed for tracked actors with no server
        // aggro. Live test result: the engine's faction-hostility
        // and player-detection logic ALSO lives inside the
        // orchestrator. Bailing it for the entire session caused
        // raiders to lose their red compass marker and acquire a
        // "Talk" activation prompt — they decayed from hostile to
        // neutral because the orchestrator never re-evaluated
        // hostility.
        //
        // Replacement strategy: orchestrator runs unconditionally.
        // The downstream attack hooks (dispatch_attack, fire_decide)
        // remain gated on should_silence_combat — they BAIL when
        // server has no aggro, so the raider stays hostile (red
        // marker) but cannot fire / swing. Pos hooks stay always
        // bailed for tracked → standing still while hostile.
        (void)fid;

        if (g_orig_orchestrator) {
            return g_orig_orchestrator(actor, a2);
        }
        return 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        g_seh_failures.fetch_add(1, std::memory_order_relaxed);
        FW_ERR("[ghost_ai_orchestrator] SEH in detour (actor=%p)", actor);
        return 0;
    }
}

} // namespace

bool install_ghost_ai_combat_orchestrator(std::uintptr_t module_base) {
    if (g_installed.load(std::memory_order_acquire)) {
        FW_LOG("[ghost_ai_orchestrator] already installed; skipping");
        return true;
    }
    const auto target_ea =
        module_base + fw::offsets::ACTOR_COMBAT_ORCHESTRATOR_RVA;
    const bool ok = install(
        reinterpret_cast<void*>(target_ea),
        reinterpret_cast<void*>(&detour_combat_orchestrator),
        reinterpret_cast<void**>(&g_orig_orchestrator));
    if (ok) {
        g_installed.store(true, std::memory_order_release);
        FW_LOG("[ghost_ai_orchestrator] Actor::vt[255] combat orchestrator "
               "hook installed at 0x%llX (RVA 0x%lX) — TOP-LEVEL NUKE; "
               "tracked NPCs skip entire combat brain per frame",
               static_cast<unsigned long long>(target_ea),
               static_cast<unsigned long>(
                   fw::offsets::ACTOR_COMBAT_ORCHESTRATOR_RVA));
    } else {
        FW_ERR("[ghost_ai_orchestrator] hook FAILED at 0x%llX",
               static_cast<unsigned long long>(target_ea));
    }
    return ok;
}

std::uint64_t get_ghost_ai_combat_orchestrator_fires() {
    return g_fires.load(std::memory_order_relaxed);
}
std::uint64_t get_ghost_ai_combat_orchestrator_bails() {
    return g_bails.load(std::memory_order_relaxed);
}
std::uint64_t get_ghost_ai_combat_orchestrator_seh_failures() {
    return g_seh_failures.load(std::memory_order_relaxed);
}

} // namespace fw::hooks
