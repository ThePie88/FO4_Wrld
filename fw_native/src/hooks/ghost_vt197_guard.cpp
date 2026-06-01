// ============================================================================
// Build 55e — Actor::IsHostileTo (vt[197]) guard for ghost.
// 2026-05-23.
//
// Hooks sub_140CA85C0 (RVA 0xCA85C0, funcs_0304.md:7823, size 0x92).
// Vtable slot 197 of TESObjectREFR (= byte offset 0x628 in vtable @
// RVA 0x2564838). Confirmed via 08_data_section.hex:77035.
//
// Signature: __int64 __fastcall sub_140CA85C0(Actor* a1, Actor* a2,
//                                             __int64 a3)
//
// Body (per AGENT_ca8624_analysis.md §1 + §2):
//   - Primary predicate: sub_140519F10(a1, a2, a3) — AI-faction hostility
//   - If primary returns true OR a2==NULL → return primary result
//   - Otherwise: secondary override path via a1+0x418 (MovementType*)
//     1. rcx = *(a1+0x418)  — our s_buf_418 (non-NULL by Build 35.1 design)
//     2. rcx = rcx + 0x80   — &MovementType[+0x80] = inline interface object
//     3. r9 = *(rcx)        — vtable ptr; ON OUR ZERO BUFFER = 0
//     4. call [r9+8]        — vtable[1]; AV addr=0x8 when r9 == 0
//
// Build 35.1's s_buf_418 was installed to bypass sub_1408800C0's null-deref
// at +0x1C8 (= field within the MovementType struct). Worked for that
// caller but `sub_140CA85C0` reads ANOTHER field (+0x80) and walks it as
// a vtable pointer — our zero buffer doesn't survive this access pattern.
//
// Trigger: cell-sync put ghost in local PC's parent_cell → engine made
// ghost enumerable → death-event fan-out (player_B died) → vt[197]
// dispatch on ghost → crash.
//
// Fix: return 0 (= not hostile) when either operand is ghost. The engine
// then takes a benign path (no hostility-based actions on ghost). Our
// cross-peer aggro doesn't depend on engine calling IsHostileTo — we
// drive target selection via apply_npc_combat_target's direct aiproc+0x6C
// write and the puppet-fire pipeline. So forcing "not hostile" from vt[197]
// is architecturally safe.
//
// Polarity NOTE: this DIFFERS from ghost_hostility_guard.cpp + Strada A
// hooks, which FORCE-HOSTILE (= return 1) when ghost is the subject. The
// difference is that those layers are used by perception/target-validate
// paths where we WANT engine to engage ghost; vt[197] specifically is a
// general IsHostileTo dispatcher invoked by death-event fan-out and other
// non-combat-engagement paths where we want NO engagement effect on ghost.
// ============================================================================

#include "ghost_vt197_guard.h"

#include <windows.h>
#include <atomic>
#include <cstdint>

#include "../hook_manager.h"
#include "../log.h"
#include "../engine/engine_calls.h"  // get_ghost_duplicate

namespace fw::hooks {

namespace {

// Actor vt[197] = IsHostileTo dispatcher. RVA 0xCA85C0 verified.
using IsHostileToVt197Fn = std::int64_t (__fastcall *)(void* a1, void* a2,
                                                       std::int64_t a3);
constexpr std::uintptr_t VT197_IS_HOSTILE_TO_RVA = 0x00CA85C0;
IsHostileToVt197Fn g_orig_vt197 = nullptr;

std::atomic<std::uint64_t> g_force_count{0};
std::atomic<std::uint64_t> g_passthrough_count{0};
std::atomic<std::uint64_t> g_seh_count{0};
std::atomic<bool>          g_installed{false};

std::int64_t __fastcall detour_vt197(void* a1, void* a2, std::int64_t a3) {
    __try {
        // Force "not hostile" (= 0) when either operand is the ghost.
        // Prevents the +0x418→+0x80 vtable chain from being walked on
        // our zero-filled s_buf_418 (= NULL+8 deref AV).
        void* ghost = fw::engine::get_ghost_duplicate();
        if (ghost && (a1 == ghost || a2 == ghost)) {
            const auto fn = g_force_count.fetch_add(
                1, std::memory_order_relaxed);
            if (fn < 16 || (fn % 256) == 0) {
                FW_LOG("[vt197-guard] FORCE-0 #%llu → 0 "
                       "(a1=%p a2=%p ghost=%p a3=%lld) — avoiding "
                       "+0x418→+0x80 NULL+8 vtable AV",
                       static_cast<unsigned long long>(fn),
                       a1, a2, ghost, static_cast<long long>(a3));
            }
            return 0;
        }

        // Passthrough: not ghost-involving. Let engine compute normally.
        g_passthrough_count.fetch_add(1, std::memory_order_relaxed);
        if (g_orig_vt197) {
            return g_orig_vt197(a1, a2, a3);
        }
        return 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        g_seh_count.fetch_add(1, std::memory_order_relaxed);
        FW_ERR("[vt197-guard] SEH in detour (a1=%p a2=%p a3=%lld)",
               a1, a2, static_cast<long long>(a3));
        return 0;
    }
}

} // namespace

bool install_ghost_vt197_guard(std::uintptr_t module_base) {
    if (g_installed.load(std::memory_order_acquire)) {
        FW_LOG("[vt197-guard] already installed; skipping");
        return true;
    }

    const auto target_ea = module_base + VT197_IS_HOSTILE_TO_RVA;
    const bool ok = install(
        reinterpret_cast<void*>(target_ea),
        reinterpret_cast<void*>(&detour_vt197),
        reinterpret_cast<void**>(&g_orig_vt197));
    if (ok) {
        g_installed.store(true, std::memory_order_release);
        FW_LOG("[vt197-guard] sub_140CA85C0 hook installed at 0x%llX "
               "(RVA 0x%lX) — Build 55e: bail-on-ghost vt[197] IsHostileTo "
               "to avoid +0x418→+0x80 vtable AV on our s_buf_418",
               static_cast<unsigned long long>(target_ea),
               static_cast<unsigned long>(VT197_IS_HOSTILE_TO_RVA));
    } else {
        FW_ERR("[vt197-guard] hook FAILED at 0x%llX",
               static_cast<unsigned long long>(target_ea));
    }
    return ok;
}

std::uint64_t get_vt197_guard_force_count() {
    return g_force_count.load(std::memory_order_relaxed);
}
std::uint64_t get_vt197_guard_passthrough_count() {
    return g_passthrough_count.load(std::memory_order_relaxed);
}
std::uint64_t get_vt197_guard_seh_count() {
    return g_seh_count.load(std::memory_order_relaxed);
}

} // namespace fw::hooks
