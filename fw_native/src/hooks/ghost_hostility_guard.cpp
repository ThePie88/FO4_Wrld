// ============================================================================
// LIVE (preventive) — 2026-05-17 log evidence: BYPASS path catches stale
// baseForms 0..2 times per session (rare; only when AddTarget validator
// hits a corrupted known_targets[] entry). FORCE-HOSTILE override branch
// (Build 40 addition) NEVER fires because the engine NEVER calls
// HostilityCore with ghost as a1/a2 in the current architecture (raiders
// in Concord don't perceive ghost in Sanctuary, cross-cell ~26000 units).
//
// LOG PROOF (Client A `fw_native.log` 17:29-17:39):
//   0× `[hostility-guard] FORCE-HOSTILE` lines  ← Build 40 branch
//   0× `[hostility-guard] BYPASS` lines         ← Build 30 Fix 2 branch
//
//   Counter `g_force_hostile_count` stays 0. Counter `g_bypass_count`
//   also 0 in this session (no stale handles triggered the validator).
//
// WHY FORCE-HOSTILE NEVER FIRES:
//   The engine calls HostilityCore(observer, subject) inside
//   `IsHostile_master` (sub_140C7AD40) and `AddTarget` validator
//   (sub_140E924A0). For HostilityCore to be called with subject==ghost,
//   one of:
//     (a) Engine added ghost to controller.known_targets[] (validator
//         loop iterates the array). Requires AddTarget to have succeeded
//         — which requires install_fixed_selector_on_raider, which is
//         dormant (see engine_calls.cpp banner).
//     (b) IsHostile_master called from perception ray (raider sees
//         ghost). Requires same-cell perception, ghost is in Sanctuary
//         while server-aggro'd raiders are in Concord.
//
//   Neither (a) nor (b) happens in current scenario.
//
// WHY BYPASS BRANCH STAYS RUNNING:
//   The is_actor_baseform_valid() guard is still valuable for safety:
//   any time AddTarget IS called (even on player_A's natural raider
//   targets) with a stale handle in known_targets[], this guard prevents
//   the AV at RVA 0x308AE7 that Build 29.2 documented. Cheap (2 SEH-
//   caged reads), defense-in-depth.
//
// KEEP-AS-IS RATIONALE:
//   BYPASS branch: preventive, low cost, kept ON.
//   FORCE-HOSTILE branch: kept ON in case a future redesign causes the
//   engine to query HostilityCore(raider, ghost). When that happens
//   (e.g. if we ever shoehorn ghost into raider's known_targets[]
//   manually via AddTarget+0x08 write), this branch will force
//   rank=1 and the engine will accept the ghost as a valid target.
//   No-op overhead today, but architecturally important.
// ============================================================================

#include "ghost_hostility_guard.h"

#include <windows.h>
#include <intrin.h>   // _ReturnAddress (Build 65.c.30 caller-disambiguation log)
#include <atomic>
#include <cstdint>

#pragma intrinsic(_ReturnAddress)

#include "../hook_manager.h"
#include "../log.h"
#include "../engine/engine_calls.h"  // get_ghost_duplicate (Build 40)

namespace fw::hooks {

namespace {

// `sub_140C8DFF0` RelationshipRank/HostilityCore — RVA 0xC8DFF0 verified
// funcs_0303.md:2895. Size 0x3C6 = 966 bytes.
// Signature: __int64 __fastcall(__int64 a1_actor, __int64 a2_actor, char a3_mode)
// Returns: relationship rank int (0=neutral, 1=hostile, 2=friend, 3=ally)
// Both a1 and a2 get `*(actor+0xE0)+0xB8` walked → factions BSTArray.
using HostilityRankFn = std::uint64_t (*)(std::uint64_t a1,
                                          std::uint64_t a2,
                                          char a3);
constexpr std::uintptr_t HOSTILITY_RANK_RVA = 0x00C8DFF0;
HostilityRankFn g_orig_hostility_rank = nullptr;

std::atomic<std::uint64_t> g_bypass_count{0};
std::atomic<std::uint64_t> g_passthrough_count{0};
std::atomic<std::uint64_t> g_seh_count{0};
std::atomic<bool>          g_installed{false};

// Returns true if `actor` looks like a valid Actor with a readable baseForm
// suitable for the engine's factions BSTArray walk at sub_140C8DFF0.
//
// Validation steps:
//   1. actor non-null
//   2. *(actor+0xE0) is readable + non-null (baseForm ptr)
//   3. baseForm+0x1A is a known TESActorBase formType (0x2D=TESNPC, 0x2E=LCHAR)
//   4. baseForm+0xB8 (factions BSTArray header) is readable (we touch +0x10
//      = count field which is what sub_140308AA0 reads first at line 9985)
//
// All reads wrapped in SEH so a totally bogus `actor` pointer (e.g.,
// freed memory) returns false instead of crashing the caller.
bool is_actor_baseform_valid(std::uint64_t actor) noexcept {
    if (!actor) return false;
    __try {
        const auto baseform = *reinterpret_cast<std::uint64_t*>(
            actor + 0xE0);
        if (!baseform) return false;

        // formType byte. TESActorBase derives from TESForm which has the
        // type byte at offset +0x1A. Real NPCs = 0x2D; leveled character
        // lists = 0x2E (these reach this path via stale handles in
        // controller+32, less common but defensive).
        const std::uint8_t formType =
            *reinterpret_cast<std::uint8_t*>(baseform + 0x1A);
        if (formType != 0x2D && formType != 0x2E) return false;

        // Touch the factions BSTArray header's count field (offset +0x10
        // per sub_140308AA0 line 9985: `*((unsigned int *)a2 + 4)`). If
        // baseform+0xB8 itself faults or the count is wildly insane → reject.
        const std::uint32_t count =
            *reinterpret_cast<std::uint32_t*>(baseform + 0xB8 + 0x10);
        // Sanity bound: vanilla TESNPCs rarely have >32 factions. A count
        // of >4096 almost certainly means we're reading garbage that
        // happens to be a non-faulting page.
        if (count > 4096) return false;

        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// Build 40 (2026-05-17) — additional counters for force-hostile override.
std::atomic<std::uint64_t> g_force_hostile_count{0};

std::uint64_t __fastcall detour_hostility_rank(std::uint64_t a1,
                                               std::uint64_t a2,
                                               char a3) {
    __try {
        // Build 40: force-hostile override when ghost is involved.
        // Per re/AI_pipeline/section_10 §1: HostilityCore returns
        // 0=neutral / 1=hostile / 2=friend / 3=ally. Our ghost.baseForm
        // (whichever cached vanilla TESNPC swap chose) typically has NO
        // hostile relations vs RaidersFaction → returns 0 → IsHostile
        // false → raiders never engage.
        //
        // We override: if either operand is our ghost proxy, return 1
        // (hostile). Vanilla AI then naturally engages combat against
        // the ghost, handling locomotion + aim + fire organically.
        void* ghost = fw::engine::get_ghost_duplicate();
        if (ghost) {
            auto ghost_u = reinterpret_cast<std::uint64_t>(ghost);
            if (a1 == ghost_u || a2 == ghost_u) {
                const auto fn = g_force_hostile_count.fetch_add(
                    1, std::memory_order_relaxed);
                if (fn < 8 || (fn % 200) == 0) {
                    FW_LOG("[hostility-guard] FORCE-HOSTILE #%llu → 1 "
                           "(a1=0x%llX a2=0x%llX ghost=%p a3=%d)",
                           static_cast<unsigned long long>(fn),
                           static_cast<unsigned long long>(a1),
                           static_cast<unsigned long long>(a2),
                           ghost,
                           static_cast<int>(a3));
                }
                return 1;
            }
        }

        // a1 is the "subject" actor whose baseForm gets walked first
        // (sub_140C8DFF0 line 2957: `v8 = *(a1+0xE0)`). Empirically (Agent 1
        // dossier) this is the parameter that comes from controller+32
        // known_targets[] in the AddTarget validator loop — i.e., the
        // most likely-stale handle.
        if (!is_actor_baseform_valid(a1)) {
            const auto n = g_bypass_count.fetch_add(
                1, std::memory_order_relaxed);
            if (n < 10 || (n % 500) == 0) {
                FW_LOG("[hostility-guard] BYPASS #%llu — a1 stale "
                       "(a1=0x%llX a2=0x%llX a3=%d) returning 0",
                       static_cast<unsigned long long>(n),
                       static_cast<unsigned long long>(a1),
                       static_cast<unsigned long long>(a2),
                       static_cast<int>(a3));
            }
            return 0;
        }
        // a2 is the "candidate" actor whose factions get walked second
        // (line 3004-3010). Less likely to be stale (typically the local
        // player or our ghost which we control) but defensive.
        if (a2 && !is_actor_baseform_valid(a2)) {
            const auto n = g_bypass_count.fetch_add(
                1, std::memory_order_relaxed);
            if (n < 10 || (n % 500) == 0) {
                FW_LOG("[hostility-guard] BYPASS #%llu — a2 stale "
                       "(a1=0x%llX a2=0x%llX a3=%d) returning 0",
                       static_cast<unsigned long long>(n),
                       static_cast<unsigned long long>(a1),
                       static_cast<unsigned long long>(a2),
                       static_cast<int>(a3));
            }
            return 0;
        }
        g_passthrough_count.fetch_add(1, std::memory_order_relaxed);
        if (g_orig_hostility_rank) {
            return g_orig_hostility_rank(a1, a2, a3);
        }
        return 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        g_seh_count.fetch_add(1, std::memory_order_relaxed);
        FW_ERR("[hostility-guard] SEH in detour (a1=0x%llX a2=0x%llX)",
               static_cast<unsigned long long>(a1),
               static_cast<unsigned long long>(a2));
        return 0;
    }
}

// ============================================================================
// Build 65.c.29 — DIRECT guard on the faction-list collector sub_140308AA0.
//
// sub_140C8DFF0 (hooked above) is only ONE of 15 hostility/relation callers
// that reach the collector. The crash at RVA 0x308AE7 (the loop that walks
// the source faction array) can be reached from any of them. Hooking the
// COLLECTOR ITSELF guards all 15 entry points at a single choke point.
//
// This re-instates the anti-crash protection that Build 64's "STRATEGIC
// ROLLBACK — all AI hooks disabled" removed as collateral damage (the
// sub_140C8DFF0 guard is BUILD64_DISABLED in install_all.cpp). The crash
// was live-confirmed at 0x308AE7 in Build 29.2 and again in Build 65.c.28.1
// (use-after-free on a freed faction array during a coc cell teardown:
// count read as 0x1C87A4 = 1.8M garbage → walk into unmapped memory → AV).
//
// Decomp funcs_0139.md:9975 — __int64 __fastcall(_DWORD* a1, __int64* a2):
//   a1 = destination BSTArray (collector appends into it)
//   a2 = source faction-array descriptor: a2[0]=base ptr, a2[4]=count (=+0x10)
//   loop: walk 16B entries base..base+16*count, copy each whose rank!=0xFF.
// The AV is the `cmp byte ptr [rbx+8], 0FFh` read when base+16*count runs
// off the end of a freed/garbage array.
//
// Guard: read the source count (a2+0x10) under SEH. If unreadable or
// implausibly large (> FACTION_COUNT_SANE_MAX), skip the collect entirely
// and return 0 — the destination array is simply left as-is (empty / prior
// contents), which the hostility resolver treats as "no factions" = neutral.
// A briefly-neutral hostility verdict during a cell teardown is invisible;
// a hard AV is not.
using FactionCollectFn = std::uint64_t (*)(void* a1, void* a2);
constexpr std::uintptr_t FACTION_COLLECT_RVA   = 0x00308AA0;
constexpr std::uint32_t  FACTION_COUNT_SANE_MAX = 4096;
FactionCollectFn           g_orig_faction_collect = nullptr;
std::atomic<std::uint64_t> g_collect_bail_count{0};
std::atomic<std::uint64_t> g_collect_pass_count{0};
std::atomic<bool>          g_collect_installed{false};

// SEH-safe read of the source array count at a2+0x10. Separate function so
// the detour body stays __try-free (it calls through the trampoline).
static bool safe_read_faction_count(void* a2, std::uint32_t* out) noexcept {
    if (!a2 || !out) return false;
    __try {
        *out = *reinterpret_cast<std::uint32_t*>(
            reinterpret_cast<std::uint8_t*>(a2) + 0x10);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

std::uint64_t __fastcall detour_faction_collect(void* a1, void* a2) {
    std::uint32_t count = 0;
    const bool readable = safe_read_faction_count(a2, &count);
    if (!readable || count > FACTION_COUNT_SANE_MAX) {
        const auto n = g_collect_bail_count.fetch_add(
            1, std::memory_order_relaxed);
        if (n < 20 || (n % 200) == 0) {
            FW_LOG("[faction-guard] BAIL #%llu — source count=%u "
                   "readable=%d (>%u sane max) a1=%p a2=%p — skip collect "
                   "(would AV @ RVA 0x308AE7 on freed faction array)",
                   static_cast<unsigned long long>(n), count,
                   readable ? 1 : 0, FACTION_COUNT_SANE_MAX, a1, a2);
        }
        return 0;
    }
    g_collect_pass_count.fetch_add(1, std::memory_order_relaxed);
    if (g_orig_faction_collect) {
        return g_orig_faction_collect(a1, a2);
    }
    return 0;
}

// ============================================================================
// Build 65.c.30 — player-death cell-teardown crash guard on sub_1404CAE90.
//
// AV @ RVA 0x4CAF43 (sub_1404CAE90+0xB3), ~8s after the LOCAL PLAYER dies.
// Disasm-proven (re/crash_0x4CAF43_death_AGENT.md):
//   0x1404CAF3C  mov rax, cs:qword_1430DBF78+4298h   ; rax = global[2131]
//   0x1404CAF43  mov rdi, [rax+50h]                  ; AV: rax==0 → read [+0x50]
// 0x4298/8 = 2131, so the null base is the global-table slot [2131]
// (RVA 0x30E0210) — a player target/crosshair singleton the engine NULLs on
// teardown (dtor sub_140DA6380 writes [2131]=0). sub_1404CAE90 is a refcounted
// "resolve canonical target for a1(cell)" accessor; during death→reload the
// CELL destructor (sub_1404C1F90 → sub_140D4CE10 music-changer ref-clear, H1)
// calls it, every cell-local lookup fails mid-teardown, and it falls through to
// the *([2131]+0x50) fallback while [2131] is null → AV. The ~8s gap = FO4
// death-cam → "load last save" cell-unload window. The OTHER caller is the
// music-changer death-event ProcessEvent (sub_140D4CAE0, H2) — same crasher.
//
// Guard: detour sub_1404CAE90. If global[2131] is null → return 0. Returning 0
// is the function's own "no target resolved" path (loc_1404CAF60 returns rdi=0);
// both callers act benignly on 0 (cell-dtor: 0 != tracked cell → no-op;
// music-changer: 0 == "clear", valid). Semantically "player has no current
// target right now" — true mid-death/reload. We return BEFORE the function takes
// its a1+0xC0 lock/AddRef, so there is no refcount leak. A belt SEH around
// orig() catches any other AV as a last resort (returns 0). On the first bails
// we log _ReturnAddress() RVA to disambiguate caller (H1 cell-dtor ≈ 0xD4CE2D
// vs H2 music-changer in sub_140D4CAE0) — same fix covers both. NOT a hot path
// (callers fire only on cell unload / player cell-change / death events).
using TargetResolveFn = std::uint64_t (*)(std::uint64_t a1);
constexpr std::uintptr_t TARGET_RESOLVE_RVA          = 0x004CAE90; // sub_1404CAE90
constexpr std::uintptr_t PLAYER_TARGET_SINGLETON_RVA = 0x030E0210; // qword_1430DBF78[2131]
TargetResolveFn            g_orig_target_resolve = nullptr;
std::uintptr_t             g_module_base_for_resolve = 0;
std::uintptr_t             g_player_target_singleton_addr = 0;
std::atomic<std::uint64_t> g_resolve_bail_count{0};
std::atomic<std::uint64_t> g_resolve_pass_count{0};
std::atomic<std::uint64_t> g_resolve_seh_count{0};
std::atomic<bool>          g_resolve_installed{false};

// SEH-safe read of the player-target singleton pointer at module+0x30E0210.
// Separate fn so the detour stays clean; defends against the (improbable) case
// where the table slot page itself is unmapped during teardown.
static bool safe_read_singleton(std::uintptr_t addr,
                                std::uint64_t* out) noexcept {
    if (!addr || !out) return false;
    __try {
        *out = *reinterpret_cast<std::uint64_t*>(addr);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

std::uint64_t __fastcall detour_target_resolve(std::uint64_t a1) {
    const void* const ret_addr = _ReturnAddress();
    __try {
        // Guard A — the proven crash condition: player-target singleton [2131]
        // is null (teardown). Original would fall through to *([2131]+0x50) and
        // AV. Return 0 == function's own "no target" sentinel.
        std::uint64_t singleton = 0;
        const bool read_ok =
            safe_read_singleton(g_player_target_singleton_addr, &singleton);
        if (!read_ok || singleton == 0) {
            const auto n =
                g_resolve_bail_count.fetch_add(1, std::memory_order_relaxed);
            if (n < 20 || (n % 200) == 0) {
                const auto ret_rva =
                    g_module_base_for_resolve
                        ? (reinterpret_cast<std::uintptr_t>(ret_addr)
                           - g_module_base_for_resolve)
                        : reinterpret_cast<std::uintptr_t>(ret_addr);
                FW_LOG("[death-guard] BAIL #%llu — player-target singleton "
                       "[2131] null (read_ok=%d) a1=0x%llX caller_rva=0x%llX "
                       "— return 0 (skip AV @ RVA 0x4CAF43 on death/reload)",
                       static_cast<unsigned long long>(n), read_ok ? 1 : 0,
                       static_cast<unsigned long long>(a1),
                       static_cast<unsigned long long>(ret_rva));
            }
            return 0;
        }

        // Guard B (defensive) — a1 (cell) structurally invalid.
        if (!a1 || a1 < 0x10000) {
            g_resolve_bail_count.fetch_add(1, std::memory_order_relaxed);
            return 0;
        }

        g_resolve_pass_count.fetch_add(1, std::memory_order_relaxed);
        if (g_orig_target_resolve) {
            return g_orig_target_resolve(a1);
        }
        return 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        g_resolve_seh_count.fetch_add(1, std::memory_order_relaxed);
        FW_ERR("[death-guard] SEH in detour (a1=0x%llX) — returning 0",
               static_cast<unsigned long long>(a1));
        return 0;
    }
}

} // namespace

bool install_ghost_hostility_guard(std::uintptr_t module_base) {
    if (g_installed.load(std::memory_order_acquire)) {
        FW_LOG("[hostility-guard] already installed; skipping");
        return true;
    }

    const auto target_ea = module_base + HOSTILITY_RANK_RVA;
    const bool ok = install(
        reinterpret_cast<void*>(target_ea),
        reinterpret_cast<void*>(&detour_hostility_rank),
        reinterpret_cast<void**>(&g_orig_hostility_rank));
    if (ok) {
        g_installed.store(true, std::memory_order_release);
        FW_LOG("[hostility-guard] sub_140C8DFF0 hook installed at "
               "0x%llX (RVA 0x%lX) — Build 30 Fix 2: validates baseForm "
               "before factions walk to prevent AV on stale known_targets",
               static_cast<unsigned long long>(target_ea),
               static_cast<unsigned long>(HOSTILITY_RANK_RVA));
    } else {
        FW_ERR("[hostility-guard] hook FAILED at 0x%llX",
               static_cast<unsigned long long>(target_ea));
    }
    return ok;
}

// Build 65.c.29 — install the direct collector guard. Call UNCONDITIONALLY
// (NOT gated by BUILD64_DISABLED) — this is the anti-crash safety net Agent 1
// flagged: Build 64 disabled it as collateral damage and the AV at 0x308AE7
// returned. Covers all 15 hostility callers at the single choke point.
bool install_ghost_faction_collect_guard(std::uintptr_t module_base) {
    if (g_collect_installed.load(std::memory_order_acquire)) {
        FW_LOG("[faction-guard] already installed; skipping");
        return true;
    }
    const auto target_ea = module_base + FACTION_COLLECT_RVA;
    const bool ok = install(
        reinterpret_cast<void*>(target_ea),
        reinterpret_cast<void*>(&detour_faction_collect),
        reinterpret_cast<void**>(&g_orig_faction_collect));
    if (ok) {
        g_collect_installed.store(true, std::memory_order_release);
        FW_LOG("[faction-guard] sub_140308AA0 collector hook installed at "
               "0x%llX (RVA 0x%lX) — count-sanity guard covers all 15 "
               "hostility callers; re-instates Build 29.2 anti-crash that "
               "Build 64 disabled (AV @ 0x308AE7 on freed faction array)",
               static_cast<unsigned long long>(target_ea),
               static_cast<unsigned long>(FACTION_COLLECT_RVA));
    } else {
        FW_ERR("[faction-guard] hook FAILED at 0x%llX",
               static_cast<unsigned long long>(target_ea));
    }
    return ok;
}

// Build 65.c.30 — install the player-death cell-teardown crash guard on
// sub_1404CAE90. Call UNCONDITIONALLY — pure defensive null-check + SEH, no
// AI-control behaviour (Build 64 "AI hooks disabled" rationale does not apply).
bool install_ghost_target_resolve_guard(std::uintptr_t module_base) {
    if (g_resolve_installed.load(std::memory_order_acquire)) {
        FW_LOG("[death-guard] already installed; skipping");
        return true;
    }
    g_module_base_for_resolve = module_base;
    g_player_target_singleton_addr = module_base + PLAYER_TARGET_SINGLETON_RVA;
    const auto target_ea = module_base + TARGET_RESOLVE_RVA;
    const bool ok = install(
        reinterpret_cast<void*>(target_ea),
        reinterpret_cast<void*>(&detour_target_resolve),
        reinterpret_cast<void**>(&g_orig_target_resolve));
    if (ok) {
        g_resolve_installed.store(true, std::memory_order_release);
        FW_LOG("[death-guard] sub_1404CAE90 hook installed at 0x%llX "
               "(RVA 0x%lX) — null-[2131] early-out prevents AV @ RVA 0x4CAF43 "
               "on player-death cell teardown; singleton@0x%llX",
               static_cast<unsigned long long>(target_ea),
               static_cast<unsigned long>(TARGET_RESOLVE_RVA),
               static_cast<unsigned long long>(g_player_target_singleton_addr));
    } else {
        FW_ERR("[death-guard] hook FAILED at 0x%llX",
               static_cast<unsigned long long>(target_ea));
    }
    return ok;
}

std::uint64_t get_death_guard_bail_count() {
    return g_resolve_bail_count.load(std::memory_order_relaxed);
}
std::uint64_t get_death_guard_pass_count() {
    return g_resolve_pass_count.load(std::memory_order_relaxed);
}
std::uint64_t get_death_guard_seh_count() {
    return g_resolve_seh_count.load(std::memory_order_relaxed);
}

std::uint64_t get_faction_collect_bail_count() {
    return g_collect_bail_count.load(std::memory_order_relaxed);
}
std::uint64_t get_faction_collect_pass_count() {
    return g_collect_pass_count.load(std::memory_order_relaxed);
}

std::uint64_t get_hostility_guard_bypass_count() {
    return g_bypass_count.load(std::memory_order_relaxed);
}
std::uint64_t get_hostility_guard_passthrough_count() {
    return g_passthrough_count.load(std::memory_order_relaxed);
}
std::uint64_t get_hostility_guard_seh_count() {
    return g_seh_count.load(std::memory_order_relaxed);
}

} // namespace fw::hooks
