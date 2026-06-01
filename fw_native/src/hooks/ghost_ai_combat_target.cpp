// ============================================================================
// DIAGNOSTIC ONLY — 2026-05-17. Hook installed (install_all.cpp:238) but
// substitution PERMANENTLY DISABLED (B6.5w13 root analysis, inline comment
// at lines 95-114): "sub_140C5CCE0 is a PURE MIRROR — copies AIProcess+0x6C
// → Actor+0x380. Writing the mirror is a functional no-op for combat
// behavior. This hook stays installed as scaffolding + diag counter but
// doesn't substitute (no point)."
//
// LOG PROOF: Client A `fw_native.log` 17:29-17:39 has the install line at
// boot but no `[ghost_ai_combat] fire #N` lines after that — counter is
// effectively 0 in production (sub_140C5CCE0 only fires when raider's
// combat tier transitions, which doesn't happen for cross-peer ghost aggro).
//
// KEEP-AS-IS RATIONALE:
//   Scaffolding is correct. If a redesign ever needs the mirror update
//   (e.g. for Papyrus GetCombatTarget queries on the raider to return
//   ghost.form_id), substitution branch is one CAS away from being live.
//   Zero overhead at fires=0.
// ============================================================================

#include "ghost_ai_combat_target.h"

#include <windows.h>
#include <atomic>
#include <cstdint>

#include "../hook_manager.h"
#include "../log.h"
#include "../offsets.h"
#include "../main_thread_dispatch.h"

namespace fw::hooks {

namespace {

// Engine signature (per agent 1 dossier):
//   char __fastcall sub_140C5CCE0(__int64 actor);
// Single arg = Actor*. Returns char (1 = on-mount/in-combat tracking active,
// 0 = cleared). We declare void* for arg type to keep ABI compatible.
using CombatTargetSetterFn = char (*)(void* actor);

CombatTargetSetterFn g_orig_combat_target_setter = nullptr;

std::atomic<std::uint64_t> g_fires{0};
std::atomic<std::uint64_t> g_seh_failures{0};
std::atomic<std::uint64_t> g_substitutions{0};
std::atomic<bool>          g_installed{false};

// Local-player form_id. NEVER substitute on the player — that would let
// the server force the player into combat with arbitrary targets, which
// breaks gameplay and risks input/camera glitches.
constexpr std::uint32_t PLAYER_FORM_ID = 0x00000014;

static std::uint32_t safe_read_actor_fid(const void* actor) noexcept {
    if (!actor) return 0xFFFFFFFFu;
    __try {
        return *reinterpret_cast<const std::uint32_t*>(
            reinterpret_cast<const std::uint8_t*>(actor) + 0x14);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0xFFFFFFFFu;
    }
}

static bool seh_write_combat_target(void* actor,
                                   std::uint32_t target_fid) noexcept {
    if (!actor) return false;
    __try {
        // Write Actor + 0x380 = server's chosen combat target form_id.
        *reinterpret_cast<std::uint32_t*>(
            reinterpret_cast<std::uint8_t*>(actor) +
            fw::offsets::ACTOR_COMBAT_TARGET_FORMID_OFF) = target_fid;
        // Force the InCombat flag bit 0x4000 in Actor + 0x2D0 so AI
        // systems treat the actor as in active combat with the target.
        std::uint32_t* flags = reinterpret_cast<std::uint32_t*>(
            reinterpret_cast<std::uint8_t*>(actor) +
            fw::offsets::ACTOR_FLAGS_720_OFF);
        *flags |= 0x4000u;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// Phase 4 step B: decision logic + substitution.
//
// Decision tree per call:
//   1. Read actor.form_id (SEH-safe).
//   2. If actor IS the local player (form_id 0x14): NEVER substitute.
//      Pass through original — letting the server override the player's
//      combat target would break input/camera/gameplay.
//   3. If actor IS a tracked NPC AND cache.combat_target_form_id != 0:
//      Write the server's chosen target into Actor+0x380, force the
//      InCombat flag bit 0x4000 in Actor+0x2D0, return 1. Original is
//      SKIPPED — calling it would overwrite our write with AIProcess+0x6C.
//   4. Otherwise (untracked actor OR server has no opinion): pass through
//      to original so vanilla AI keeps deciding for that actor.
char __fastcall detour_combat_target_setter(void* actor) {
    char result = 0;
    __try {
        const auto n = g_fires.fetch_add(1, std::memory_order_relaxed);
        const std::uint32_t fid = safe_read_actor_fid(actor);

        // First-N + heartbeat logging.
        if (n < 10) {
            FW_LOG("[ghost_ai_combat] fire #%llu actor=%p actor_fid=0x%08X",
                   static_cast<unsigned long long>(n), actor, fid);
        } else if ((n % 1000) == 0) {
            FW_DBG("[ghost_ai_combat] fire #%llu (heartbeat, "
                   "substitutions=%llu)",
                   static_cast<unsigned long long>(n),
                   static_cast<unsigned long long>(
                       g_substitutions.load(std::memory_order_relaxed)));
        }

        // === SUBSTITUTION DISABLED (B6.5w13 root analysis) ===
        //
        // sub_140C5CCE0 is a PURE MIRROR — copies AIProcess+0x6C → Actor+0x380.
        // Disasm raw:
        //   mov eax, [rcx+6Ch]    ; READ AIProcess+0x6C (source)
        //   mov [rbx+380h], eax   ; WRITE Actor+0x380 (mirror destination)
        //
        // Actor+0x380 is read ONLY by Papyrus GetCombatTarget and inter-actor
        // "share-target" tallies. The AI's actual aim/movement/fire logic
        // reads from AIProcess+0x6C and CombatController.known_targets[]
        // (controller+8), NEVER from Actor+0x380. So writing the mirror is a
        // functional no-op for combat behavior.
        //
        // Per re/B6.5w13_root_AGENT_1.md, the TRUE choke point is
        // CombatController::AddTarget @ 0x00E91D70 (writes known_targets[]
        // array) or CombatController::Update @ 0x00E918C0 (full combat tick).
        // The next-iteration 4-agent RE will identify the
        // CombatController -> Actor back-pointer needed to filter at that
        // level. This hook stays installed as scaffolding + diag counter
        // but doesn't substitute (no point).

        // Passthrough: untracked actor / no server opinion / write failed.
        if (g_orig_combat_target_setter) {
            result = g_orig_combat_target_setter(actor);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        g_seh_failures.fetch_add(1, std::memory_order_relaxed);
        FW_ERR("[ghost_ai_combat] SEH in detour (actor=%p) — returning 0",
               actor);
        result = 0;
    }
    return result;
}

} // namespace

bool install_ghost_ai_combat_target(std::uintptr_t module_base) {
    if (g_installed.load(std::memory_order_acquire)) {
        FW_LOG("[ghost_ai_combat] already installed; skipping");
        return true;
    }
    const auto target_ea =
        module_base + fw::offsets::COMBAT_TARGET_SETTER_RVA;
    const bool ok = install(
        reinterpret_cast<void*>(target_ea),
        reinterpret_cast<void*>(&detour_combat_target_setter),
        reinterpret_cast<void**>(&g_orig_combat_target_setter));
    if (ok) {
        g_installed.store(true, std::memory_order_release);
        FW_LOG("[ghost_ai_combat] Actor::SyncCombatTargetFromAIProcess hook "
               "installed at 0x%llX (RVA 0x%lX) — SKELETON, passthrough only",
               static_cast<unsigned long long>(target_ea),
               static_cast<unsigned long>(fw::offsets::COMBAT_TARGET_SETTER_RVA));
    } else {
        FW_ERR("[ghost_ai_combat] hook FAILED at 0x%llX",
               static_cast<unsigned long long>(target_ea));
    }
    return ok;
}

std::uint64_t get_ghost_ai_combat_target_fires() {
    return g_fires.load(std::memory_order_relaxed);
}
std::uint64_t get_ghost_ai_combat_target_seh_failures() {
    return g_seh_failures.load(std::memory_order_relaxed);
}

} // namespace fw::hooks
