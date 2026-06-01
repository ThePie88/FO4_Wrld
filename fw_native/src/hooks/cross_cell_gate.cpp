// ============================================================================
// DORMANT — 2026-05-17. Hook fires (8 hits in 5 minutes of live test) but
// only on engine-internal events; never on a path where a2==ghost, so the
// cell swap branch never engages.
//
// LOG PROOF (Client A, Client B 17:29-17:39 session):
//   No `[cross-cell-gate] SWAP ghost=...` line ever appears.
//   Counter `g_swaps` stays at 0 across both clients.
//
// WHY:
//   This hook detours `sub_140CF6100` (target-engagement / cell-gated commit).
//   The function is called from inside the combat orchestrator's late stage
//   AFTER a raider has already (a) entered combat tier, (b) promoted a
//   target via selectors, and (c) called sub_140CF1130 to commit. Per
//   re/AI_pipeline/section_06 §8 + section_02, the call chain is:
//     Actor::vt[255] orchestrator
//       → sub_14087B080 promoter (selector pick)
//         → sub_14087A900 post-pick gate
//           → sub_140CF6100 commit (THIS HOOK)
//
//   For the call to land here with a2==ghost, the raider must have ghost
//   in known_targets[] AND have promoted it via a selector. That requires
//   `install_fixed_selector_on_raider` to have succeeded, which requires
//   raider+0x328 != NULL, which requires raider already in combat tier
//   vs ghost, which never happens (see ghost_combat_force.cpp banner for
//   the full circular-dependency proof).
//
//   Net effect: hook fires when raider commits target = real_player (a2
//   pointer != ghost), passthrough triggers immediately at the
//   `a2_void != ghost` check, swap branch is unreachable.
//
// KEEP-AS-IS RATIONALE:
//   Cost is one ptr-compare per fire. Hook would become live IF the
//   puppet-fire pivot ever drives a raider into "real combat tier" with
//   ghost via a different route. Code is correct (verified with manual
//   walk through funcs_0309.md:9651-9926). Just inert in current design.
//
//   The transient-cell-swap mechanic itself is the right architectural
//   primitive for satisfying `PC.parent_cell == target.parent_cell`
//   gates the engine has scattered through combat code. Don't rewrite,
//   don't delete.
// ============================================================================

#include "cross_cell_gate.h"

#include <windows.h>
#include <atomic>
#include <cstdint>

#include "../hook_manager.h"
#include "../log.h"
#include "../offsets.h"
#include "../engine/engine_calls.h"  // get_ghost_duplicate, get_pc_parent_cell

namespace fw::hooks {

namespace {

// sub_140CF6100 = target engagement / cell-gated commit
// Signature per pseudo-C (funcs_0309.md:9651):
//     bool __fastcall(__int64 a1_controller, __int64 a2_target, char a3)
using TargetEngageFn =
    bool (__fastcall *)(std::int64_t a1, std::int64_t a2, char a3);

TargetEngageFn g_orig_engage = nullptr;

std::atomic<std::uint64_t> g_fires{0};         // total detour entries
std::atomic<std::uint64_t> g_swaps{0};         // transient swap successes
std::atomic<std::uint64_t> g_passthroughs{0};  // target != ghost
std::atomic<std::uint64_t> g_seh_failures{0};
std::atomic<bool>          g_installed{false};

} // namespace

extern "C" bool __fastcall detour_cross_cell_gate(
    std::int64_t a1, std::int64_t a2, char a3) noexcept
{
    const auto n = g_fires.fetch_add(1, std::memory_order_relaxed);

    // Fast-path probe: is the target our registered ghost duplicate?
    // get_ghost_duplicate returns nullptr until spawn completes;
    // that's fine — we just passthrough.
    void* ghost = fw::engine::get_ghost_duplicate();
    void* a2_void = reinterpret_cast<void*>(a2);

    if (!ghost || a2_void != ghost) {
        g_passthroughs.fetch_add(1, std::memory_order_relaxed);
        if (g_orig_engage) {
            return g_orig_engage(a1, a2, a3);
        }
        return false;
    }

    // Target IS our ghost. Perform TRANSIENT cell swap.
    //
    // Steps:
    //   1. Read PC's current parent_cell.
    //   2. Save ghost's current parent_cell to a local.
    //   3. Write PC.parent_cell to ghost+0xB8.
    //   4. Call original sub_140CF6100. Inside the original, the
    //      gate at funcs_0309.md:9926 sees PC.cell == ghost.cell
    //      → goes to commit branch, calls sub_140CF1130 →
    //      activates target.AIProcess → raider commits to engage.
    //   5. Restore ghost+0xB8 to the saved value IMMEDIATELY on
    //      return. Per-tick walkers running between calls see the
    //      stale cell → don't iterate ghost as in-cell → no crash.
    //
    // Atomicity / safety:
    //   - The write + read of ghost+0xB8 is an 8-byte qword aligned
    //     access; atomic on x64.
    //   - The save/restore happens within a SINGLE thread (main game
    //     thread; this is part of the combat AI tick).
    //   - sub_140CF6100 is NOT recursive (verified by visual inspect
    //     of its 1958-byte body — no self-call) so nested swaps
    //     cannot happen.
    //   - Other game threads cannot observe the ghost cell pointer
    //     during the brief swap window because they don't process
    //     this actor on this thread's tick.
    //   - If sub_140CF6100 faults internally (e.g. our F-series
    //     patches still trigger something), we MUST still restore
    //     ghost+0xB8 before returning. The SEH cage covers this.

    void* pc_cell = fw::engine::get_pc_parent_cell();
    if (!pc_cell) {
        // PC not yet bound / faulted → passthrough without swap.
        g_passthroughs.fetch_add(1, std::memory_order_relaxed);
        if (g_orig_engage) return g_orig_engage(a1, a2, a3);
        return false;
    }

    void* saved_ghost_cell = nullptr;
    bool swapped = false;

    __try {
        saved_ghost_cell = *reinterpret_cast<void**>(
            reinterpret_cast<std::uint8_t*>(ghost) +
            fw::offsets::PARENT_CELL_OFF);
        *reinterpret_cast<void**>(
            reinterpret_cast<std::uint8_t*>(ghost) +
            fw::offsets::PARENT_CELL_OFF) = pc_cell;
        swapped = true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        // SEH writing ghost+0xB8 — extremely unlikely but possible if
        // the ghost was just despawned in another thread. Fall back to
        // passthrough.
        g_seh_failures.fetch_add(1, std::memory_order_relaxed);
        if (g_orig_engage) return g_orig_engage(a1, a2, a3);
        return false;
    }

    if (n < 8 || (n % 200) == 0) {
        FW_LOG("[cross-cell-gate] #%llu SWAP ghost=%p +0xB8 %p → %p "
               "(PC.parent_cell). a1=0x%llX a3=%d. About to call orig.",
               static_cast<unsigned long long>(n), ghost,
               saved_ghost_cell, pc_cell,
               static_cast<unsigned long long>(a1),
               static_cast<int>(a3));
    }

    bool result = false;
    bool orig_seh = false;
    __try {
        result = g_orig_engage(a1, a2, a3);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        // Original faulted. Still restore the cell pointer below.
        g_seh_failures.fetch_add(1, std::memory_order_relaxed);
        orig_seh = true;
    }

    // ALWAYS restore — even on SEH from orig. The saved_ghost_cell is
    // by-value on our stack, guaranteed valid.
    if (swapped) {
        __try {
            *reinterpret_cast<void**>(
                reinterpret_cast<std::uint8_t*>(ghost) +
                fw::offsets::PARENT_CELL_OFF) = saved_ghost_cell;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            // SEH restoring — ghost likely despawned mid-call. Counter
            // bumps but state is lost; not much we can do.
            g_seh_failures.fetch_add(1, std::memory_order_relaxed);
        }
        g_swaps.fetch_add(1, std::memory_order_relaxed);
    }

    if (orig_seh) {
        FW_WRN("[cross-cell-gate] #%llu SEH inside orig sub_140CF6100 "
               "(restored ghost+0xB8 anyway)",
               static_cast<unsigned long long>(n));
        return false;
    }

    if (n < 8 || (n % 200) == 0) {
        FW_LOG("[cross-cell-gate] #%llu DONE orig returned %d "
               "(0=engaged, 1=bailed); ghost+0xB8 restored to %p",
               static_cast<unsigned long long>(n),
               result ? 1 : 0, saved_ghost_cell);
    }

    return result;
}

bool install_cross_cell_gate(std::uintptr_t module_base) {
    if (g_installed.load(std::memory_order_acquire)) {
        FW_LOG("[cross-cell-gate] already installed; skipping");
        return true;
    }
    const auto target_ea =
        module_base + fw::offsets::COMBAT_ENGAGE_GATE_RVA;
    const bool ok = install(
        reinterpret_cast<void*>(target_ea),
        reinterpret_cast<void*>(&detour_cross_cell_gate),
        reinterpret_cast<void**>(&g_orig_engage));
    if (ok) {
        g_installed.store(true, std::memory_order_release);
        FW_LOG("[cross-cell-gate] sub_140CF6100 hook installed at "
               "0x%llX (RVA 0x%lX). Transient ghost+0xB8 cell swap "
               "active — engine sees ghost in PC's cell for the "
               "duration of each engage check, restored on return.",
               static_cast<unsigned long long>(target_ea),
               static_cast<unsigned long>(
                   fw::offsets::COMBAT_ENGAGE_GATE_RVA));
    } else {
        FW_ERR("[cross-cell-gate] hook FAILED at 0x%llX",
               static_cast<unsigned long long>(target_ea));
    }
    return ok;
}

std::uint64_t get_cross_cell_gate_fires() {
    return g_fires.load(std::memory_order_relaxed);
}
std::uint64_t get_cross_cell_gate_swaps() {
    return g_swaps.load(std::memory_order_relaxed);
}
std::uint64_t get_cross_cell_gate_passthroughs() {
    return g_passthroughs.load(std::memory_order_relaxed);
}
std::uint64_t get_cross_cell_gate_seh_failures() {
    return g_seh_failures.load(std::memory_order_relaxed);
}

} // namespace fw::hooks
