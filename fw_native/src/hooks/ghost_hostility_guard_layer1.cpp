// ============================================================================
// Build 50 Strada A — Layer-1 IsHostile gateway hook.
// 2026-05-22.
//
// Hooks sub_140C7AD40 (RVA 0xC7AD40, funcs_0302.md:11363, size 0x47E).
// Signature: bool __fastcall(__int64 a1_observer, __int64 a2_subject,
//                            unsigned __int8 a3_mode).
//
// Target: catch every layer-1 hostility query that touches the ghost,
// at the level above sub_140C8DFF0 (the existing hostility_guard target,
// which sits at layer 3 and is unreachable via the engine's short-circuits
// in the ghost case).
//
// Strategy: SEH-cage + self-check replication + force-return-1 if ghost
// is either operand. Pattern mirrors ghost_hostility_guard.cpp (see RVA
// 0xC8DFF0 sibling hook). Counters: force, passthrough, SEH, self-check.
//
// Verified by 4-agent RE arena (re/strada_A_ishostile_master/):
//   - A_AGENT_body_decomp.md (92% conf, GREEN)
//   - B_AGENT_caller_xref.md (85% conf, GREEN)
//   - C_AGENT_side_effects.md (60% conf, YELLOW-GREEN; downstream gates
//     B+C may still block visible fire — see NPCs.md "puppet fire" plan)
//   - SUPERVISOR_SYNTHESIS.md (60% aggregate, GREEN to ship; SAFE)
//
// Coverage estimate: ~95% of acquire/enter-combat flows for raider->ghost
// (Agent B §6). The 5% gap is mid-combat re-evaluation via sub_140C9FBA0
// (Combat::Controller) which calls C8DFF0 directly — irrelevant because
// next perception tick re-acquires via layer 1.
//
// Expected log signatures (post-deploy, Concord raid with ghost in cell):
//   "[hostility-l1] hook installed at 0x..."          (1x at boot)
//   "[hostility-l1] FORCE-1 #N a1=... a2=... mode=..."  (>0 — critical signal)
//   "[hostility-l1] SEH ..."                           (=0 — safety check)
// Cascading expected:
//   "[combat-force] OVERRIDE -> 1"                     (was 0 pre-Build 50)
//   "[hostility-guard] FORCE-HOSTILE"                  (may now fire via LABEL_55)
// ============================================================================

#include "ghost_hostility_guard_layer1.h"

#include <windows.h>
#include <atomic>
#include <cstdint>

#include "../hook_manager.h"
#include "../log.h"
#include "../offsets.h"
#include "../engine/engine_calls.h"  // get_ghost_duplicate

namespace fw::hooks {

namespace {

// sub_140C7AD40 IsHostile_master / layer-1 gateway.
// Verified RVA + signature from D:\falloutworld_decomp\out\10_decomp\
//   funcs_0302.md:11363 (header) and :11366 (body).
using IsHostileMasterFn = bool (__fastcall *)(std::uint64_t a1,
                                              std::uint64_t a2,
                                              std::uint8_t  a3);
constexpr std::uintptr_t IS_HOSTILE_MASTER_RVA = 0x00C7AD40;
IsHostileMasterFn g_orig_is_hostile_master = nullptr;

std::atomic<std::uint64_t> g_force_count{0};
std::atomic<std::uint64_t> g_passthrough_count{0};
std::atomic<std::uint64_t> g_seh_count{0};
std::atomic<std::uint64_t> g_self_check_count{0};
std::atomic<bool>          g_installed{false};

// MinHook detour. Order matters:
//   1. SEH cage (defensive — any internal AV unwinds to "return 0" = safe).
//   2. Replicate engine self-check (a2 == a1 -> 0) BEFORE ghost equality.
//      Per A_AGENT §7 R4: avoids ghost-vs-ghost returning 1.
//   3. Ghost-equality check on both operands. If matched, force 1.
//   4. Passthrough to original.
bool __fastcall detour_is_hostile_master(std::uint64_t a1,
                                         std::uint64_t a2,
                                         std::uint8_t  a3) {
    __try {
        // Step 2: Replicate self-check — the engine's first non-AI-category
        // check at funcs_0302.md:11411 is `if (a2 == a1) return 0`. If we
        // skipped this and a1==a2==ghost, our hook would force-return 1
        // (= "ghost is hostile to itself"). Vanishingly rare in practice
        // (no caller passes ghost twice), but cheap defense.
        if (a1 == a2) {
            g_self_check_count.fetch_add(1, std::memory_order_relaxed);
            return false;
        }

        // Step 3: Ghost-equality check. acquire-load on g_ghost_duplicate_ptr
        // ensures we see a coherent ghost pointer published by the spawn
        // path on the main thread (matches existing ghost_hostility_guard
        // pattern at line 138).
        void* ghost = fw::engine::get_ghost_duplicate();
        if (ghost) {
            const auto ghost_u = reinterpret_cast<std::uint64_t>(ghost);
            if (a1 == ghost_u || a2 == ghost_u) {
                const auto n = g_force_count.fetch_add(
                    1, std::memory_order_relaxed);
                if (n < 16 || (n % 256) == 0) {
                    FW_LOG("[hostility-l1] FORCE-1 #%llu  "
                           "a1=0x%llX a2=0x%llX mode=%u ghost=%p",
                           static_cast<unsigned long long>(n),
                           static_cast<unsigned long long>(a1),
                           static_cast<unsigned long long>(a2),
                           static_cast<unsigned>(a3),
                           ghost);
                }
                return true;
            }
        }

        // Step 4: Passthrough to vanilla.
        g_passthrough_count.fetch_add(1, std::memory_order_relaxed);
        if (g_orig_is_hostile_master) {
            return g_orig_is_hostile_master(a1, a2, a3);
        }
        return false;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        g_seh_count.fetch_add(1, std::memory_order_relaxed);
        FW_ERR("[hostility-l1] SEH in detour (a1=0x%llX a2=0x%llX mode=%u)",
               static_cast<unsigned long long>(a1),
               static_cast<unsigned long long>(a2),
               static_cast<unsigned>(a3));
        return false;
    }
}

} // namespace

bool install_ghost_hostility_guard_layer1(std::uintptr_t module_base) {
    if (g_installed.load(std::memory_order_acquire)) {
        FW_LOG("[hostility-l1] already installed; skipping");
        return true;
    }

    const auto target_ea = module_base + IS_HOSTILE_MASTER_RVA;
    const bool ok = install(
        reinterpret_cast<void*>(target_ea),
        reinterpret_cast<void*>(&detour_is_hostile_master),
        reinterpret_cast<void**>(&g_orig_is_hostile_master));
    if (ok) {
        g_installed.store(true, std::memory_order_release);
        FW_LOG("[hostility-l1] sub_140C7AD40 hook installed at 0x%llX "
               "(RVA 0x%lX) - Build 50 Strada A: layer-1 force-hostile "
               "override for ghost-involving queries (above existing "
               "sub_140C8DFF0 layer-3 hook)",
               static_cast<unsigned long long>(target_ea),
               static_cast<unsigned long>(IS_HOSTILE_MASTER_RVA));
    } else {
        FW_ERR("[hostility-l1] hook FAILED at 0x%llX",
               static_cast<unsigned long long>(target_ea));
    }
    return ok;
}

std::uint64_t get_hostility_guard_l1_force_count() {
    return g_force_count.load(std::memory_order_relaxed);
}
std::uint64_t get_hostility_guard_l1_passthrough_count() {
    return g_passthrough_count.load(std::memory_order_relaxed);
}
std::uint64_t get_hostility_guard_l1_seh_count() {
    return g_seh_count.load(std::memory_order_relaxed);
}
std::uint64_t get_hostility_guard_l1_self_check_count() {
    return g_self_check_count.load(std::memory_order_relaxed);
}

} // namespace fw::hooks
