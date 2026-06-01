// ============================================================================
// DORMANT-PREVENTIVE — 2026-05-17. Hook fires (8x in 5 min) but bypass branch
// never triggers because the upstream crash signature it guards against
// (Build 43b vt[3] UAF EXEC fault) requires the engine to have already
// committed combat with the ghost, which doesn't happen in the current
// architecture (see ghost_combat_force.cpp banner for the full root cause).
//
// LOG PROOF (Client A, Client B 17:29-17:39):
//   [event-disp] fire #0..#7  (bypasses=0 so far)
//   No `BYPASS` line. Counter g_bypasses stays 0 across both clients.
//
// WHY KEEP ENABLED:
//   The cost is one ptr-range compare per dispatch (cheap). Hook stays
//   active as INSURANCE: if the puppet-fire pivot succeeds in driving
//   raider→ghost combat in a future build, the engine WILL hit the
//   sub_140DEF780 → vt[3] dispatch path that Build 43b's stack proved
//   AVs on stale event sinks. This guard remains correct and would
//   trigger then. Removing it would re-introduce the exact crash class
//   that motivated Build 44.
//
//   In current "raiders ignore ghost" state, the dispatch sink targets
//   are always normal combat-event subscribers (vt[3] in module range),
//   so the bypass branch is never needed. That's why bypasses=0.
//
// REVISIT: if `aiproc+0x6C = ghost_handle` ever sticks (i.e. if
// install_fixed_selector_on_raider starts succeeding under a new design),
// expect this hook's `BYPASS` counter to start incrementing.
// ============================================================================

#include "event_dispatch_guard.h"

#include <windows.h>
#include <psapi.h>
#include <atomic>
#include <cstdint>

#include "../hook_manager.h"
#include "../log.h"
#include "../offsets.h"

namespace fw::hooks {

namespace {

// sub_140DEF780 signature per funcs_0324.md:11402.
using EventDispatchFn =
    std::int64_t (__fastcall *)(std::int64_t a1,
                                void* a2,
                                int a3);

EventDispatchFn g_orig_dispatch = nullptr;

std::atomic<std::uint64_t> g_fires{0};
std::atomic<std::uint64_t> g_bypasses{0};
std::atomic<std::uint64_t> g_seh_failures{0};
std::atomic<bool>          g_installed{false};

// Module text section bounds — initialized at install time so we can
// validate function pointers cheaply (single range compare).
std::uintptr_t g_module_text_lo = 0;
std::uintptr_t g_module_text_hi = 0;

// Inline check: is `fn_ptr` plausibly a valid function in the loaded
// game module's .text segment? We use the OS-reported image extent
// (HMODULE base + SizeOfImage) — overestimates slightly (includes
// .rdata/.data) but never under-estimates, so we never reject a real
// function pointer. Heap addresses (0x000001xx_xxxxxxxx range on
// Windows) are unambiguously outside.
inline bool fn_ptr_in_module(const void* fn_ptr) noexcept {
    const auto u = reinterpret_cast<std::uintptr_t>(fn_ptr);
    return u >= g_module_text_lo && u < g_module_text_hi;
}

// Read `*(*a2 + 0x18)` (= vt[3] = the function pointer the orig is
// about to call) and check it's in module range. SEH-caged: a corrupt
// `a2` (zero, freed, or otherwise unmappable) → returns false (invalid).
static bool dispatch_vtable_slot3_valid(void* a2) noexcept {
    if (!a2) return false;
    __try {
        // a2 → vtable pointer (first field of any C++ polymorphic object).
        const std::uint64_t* vt =
            *reinterpret_cast<std::uint64_t* const*>(a2);
        if (!vt) return false;
        // vt[3] = byte offset 0x18 = 24.
        const std::uint64_t fn = vt[3];
        return fn_ptr_in_module(reinterpret_cast<void*>(fn));
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

std::int64_t __fastcall detour_event_dispatch(
    std::int64_t a1,
    void* a2,
    int a3) noexcept
{
    const auto n = g_fires.fetch_add(1, std::memory_order_relaxed);

    if (!dispatch_vtable_slot3_valid(a2)) {
        const auto bn = g_bypasses.fetch_add(1, std::memory_order_relaxed);
        if (bn < 8 || (bn % 200) == 0) {
            // Log the bad vt slot value if we can read it (defensive).
            std::uint64_t bad_fn = 0;
            __try {
                const std::uint64_t* vt =
                    *reinterpret_cast<std::uint64_t* const*>(a2);
                if (vt) bad_fn = vt[3];
            } __except (EXCEPTION_EXECUTE_HANDLER) {}
            FW_WRN("[event-disp] BYPASS #%llu a1=0x%llX a2=%p a3=%d "
                   "vt[3]=0x%llX (out of module range %llX-%llX) — "
                   "dropping dispatch to prevent EXEC fault on stale "
                   "event sink",
                   static_cast<unsigned long long>(bn),
                   static_cast<unsigned long long>(a1),
                   static_cast<const void*>(a2),
                   a3,
                   static_cast<unsigned long long>(bad_fn),
                   static_cast<unsigned long long>(g_module_text_lo),
                   static_cast<unsigned long long>(g_module_text_hi));
        }
        // Safe bail. Original return value: __int64. 0 = "no events
        // dispatched, no state change". Engine continues without
        // executing the dead sink.
        return 0;
    }

    // Per-fire diagnostic (rate-limited).
    if (n < 8 || (n % 5000) == 0) {
        FW_LOG("[event-disp] fire #%llu a1=0x%llX a2=%p a3=%d "
               "(bypasses=%llu so far)",
               static_cast<unsigned long long>(n),
               static_cast<unsigned long long>(a1),
               static_cast<const void*>(a2),
               a3,
               static_cast<unsigned long long>(
                   g_bypasses.load(std::memory_order_relaxed)));
    }

    std::int64_t rc = 0;
    __try {
        rc = g_orig_dispatch ? g_orig_dispatch(a1, a2, a3) : 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        g_seh_failures.fetch_add(1, std::memory_order_relaxed);
        FW_ERR("[event-disp] SEH in orig sub_140DEF780 — a1=0x%llX a2=%p",
               static_cast<unsigned long long>(a1),
               static_cast<const void*>(a2));
        rc = 0;
    }
    return rc;
}

} // namespace

bool install_event_dispatch_guard(std::uintptr_t module_base) {
    if (g_installed.load(std::memory_order_acquire)) {
        FW_LOG("[event-disp] already installed; skipping");
        return true;
    }

    // Compute module .text range from the OS view of the EXE.
    // GetModuleHandle(NULL) returns the EXE's base address (which
    // equals our `module_base` arg). SizeOfImage gives the full
    // mapped image size — slightly overestimates .text (includes
    // .rdata/.data) but that's fine: we want NO false negatives.
    HMODULE hmod = ::GetModuleHandleW(nullptr);
    MODULEINFO mi{};
    if (hmod && ::GetModuleInformation(::GetCurrentProcess(), hmod,
                                       &mi, sizeof(mi)))
    {
        g_module_text_lo = reinterpret_cast<std::uintptr_t>(mi.lpBaseOfDll);
        g_module_text_hi = g_module_text_lo + mi.SizeOfImage;
    } else {
        // Fallback: use caller's module_base + generous 256MB.
        g_module_text_lo = module_base;
        g_module_text_hi = module_base + 0x10000000ull;
        FW_WRN("[event-disp] GetModuleInformation failed; using "
               "fallback range %llX-%llX",
               static_cast<unsigned long long>(g_module_text_lo),
               static_cast<unsigned long long>(g_module_text_hi));
    }

    const auto target_ea =
        module_base + fw::offsets::EVENT_DISPATCH_RVA;
    const bool ok = install(
        reinterpret_cast<void*>(target_ea),
        reinterpret_cast<void*>(&detour_event_dispatch),
        reinterpret_cast<void**>(&g_orig_dispatch));
    if (ok) {
        g_installed.store(true, std::memory_order_release);
        FW_LOG("[event-disp] sub_140DEF780 vtable-validity guard "
               "installed at 0x%llX (RVA 0x%lX). Module text range "
               "%llX-%llX. Dispatches whose a2.vt[3] points outside "
               "this range will be bypassed (return 0).",
               static_cast<unsigned long long>(target_ea),
               static_cast<unsigned long>(fw::offsets::EVENT_DISPATCH_RVA),
               static_cast<unsigned long long>(g_module_text_lo),
               static_cast<unsigned long long>(g_module_text_hi));
    } else {
        FW_ERR("[event-disp] hook FAILED at 0x%llX",
               static_cast<unsigned long long>(target_ea));
    }
    return ok;
}

std::uint64_t get_event_dispatch_fires() {
    return g_fires.load(std::memory_order_relaxed);
}
std::uint64_t get_event_dispatch_bypasses() {
    return g_bypasses.load(std::memory_order_relaxed);
}
std::uint64_t get_event_dispatch_seh_failures() {
    return g_seh_failures.load(std::memory_order_relaxed);
}

} // namespace fw::hooks
