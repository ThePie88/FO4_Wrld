#include "lock_hook.h"

#include <windows.h>
#include <atomic>
#include <chrono>
#include <cstdint>

#include "container_hook.h"      // tls_applying_remote (feedback-loop guard)
#include "../hook_manager.h"
#include "../log.h"
#include "../offsets.h"
#include "../ref_identity.h"
#include "../net/client.h"

namespace fw::hooks {

namespace {

// Engine ForceUnlock / ForceLock — both signatures void(REFR*).
using LockFlipFn = void (*)(void* refr);

// LockData getter — sub_140563170(REFR*) → LockData* (or null if no lock).
using LockDataGetFn = void* (*)(void* refr);

LockFlipFn    g_orig_force_unlock = nullptr;
LockFlipFn    g_orig_force_lock   = nullptr;
LockDataGetFn g_lock_data_get     = nullptr;

// Monotonic fire counters per direction for diagnostics + matching
// tx ↔ rx in the log.
std::atomic<std::uint64_t> g_unlock_fires{0};
std::atomic<std::uint64_t> g_lock_fires{0};

struct LockObserveResult {
    std::uint32_t form_id;
    std::uint32_t base_id;
    std::uint32_t cell_id;
    bool          identity_ok;
};

static void observe_target(void* refr, LockObserveResult* out) {
    out->form_id = 0;
    out->base_id = 0;
    out->cell_id = 0;
    out->identity_ok = false;
    __try {
        if (!refr) return;
        const auto cid = read_ref_identity(refr);
        out->form_id = cid.form_id;
        out->base_id = cid.base_id;
        out->cell_id = cid.cell_id;
        out->identity_ok = (cid.base_id != 0 && cid.cell_id != 0);
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
}

// Read the LOCKED flag from the REFR's ExtraLock data, post-flip. Used
// for diagnostic logging — the broadcast itself carries the new state
// directly from which detour fired (unlock detour → locked=0, lock
// detour → locked=1), which is more reliable than re-reading after the
// engine call (engine could free LockData in some edge cases).
static bool read_post_locked_flag_seh(void* refr) {
    if (!refr || !g_lock_data_get) return false;
    __try {
        void* ld = g_lock_data_get(refr);
        if (!ld) return false;
        const auto* p = reinterpret_cast<const std::uint8_t*>(ld);
        return (p[fw::offsets::LOCK_DATA_FLAGS_OFF]
                & fw::offsets::LOCK_FLAG_LOCKED) != 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// Common detour body. `new_locked_state` is the state we KNOW the engine
// is transitioning to (false for unlock detour, true for lock detour).
// The original engine function is called first so the engine's state
// reflects the new value before we broadcast.
static void on_lock_flip(void* refr, bool new_locked_state, LockFlipFn orig,
                         std::atomic<std::uint64_t>& counter,
                         const char* tag) {
    const auto fire = counter.fetch_add(1, std::memory_order_relaxed) + 1;

    // Feedback-loop guard: when the local main thread is mid-apply of a
    // remote LOCK_BCAST (drain_lock_apply_queue → engine apply), the
    // engine's own ForceLock/ForceUnlock cascade fires and lands here.
    // tls_applying_remote is true in that path; we MUST skip broadcast
    // so the apply doesn't echo back as a fresh LOCK_OP.
    if (tls_applying_remote) {
        FW_DBG("[lock-act] %s FIRE #%llu — applying_remote, passthrough",
               tag, static_cast<unsigned long long>(fire));
        if (orig) orig(refr);
        return;
    }

    // Run the engine's flip first so post-state read sees the new value
    // (also so any side effects within the engine — partial-pick clear,
    // visual refresh, leveled-list re-eval — happen before our work).
    if (orig) {
        orig(refr);
    } else {
        FW_ERR("[lock-act] %s g_orig NULL — engine call dropped", tag);
        return;
    }

    LockObserveResult r{};
    observe_target(refr, &r);
    if (!r.identity_ok) {
        FW_DBG("[lock-act] %s FIRE #%llu skip (id_ok=0 fid=0x%X base=0x%X cell=0x%X)",
               tag, static_cast<unsigned long long>(fire),
               r.form_id, r.base_id, r.cell_id);
        return;
    }

    // Sanity: confirm the engine actually flipped to the state we
    // expect. If a future engine path calls these for some other reason
    // (e.g. partial-state-reset), we don't want to broadcast a wrong
    // state. Mismatch logs and skips.
    const bool actual_locked = read_post_locked_flag_seh(refr);
    if (actual_locked != new_locked_state) {
        FW_LOG("[lock-act] %s FIRE #%llu state mismatch — expected locked=%d "
               "got locked=%d for fid=0x%X — skipping broadcast",
               tag, static_cast<unsigned long long>(fire),
               new_locked_state ? 1 : 0, actual_locked ? 1 : 0,
               r.form_id);
        return;
    }

    using namespace std::chrono;
    const std::uint64_t ts_ms = duration_cast<milliseconds>(
        system_clock::now().time_since_epoch()).count();

    fw::net::client().enqueue_lock_op(r.form_id, r.base_id, r.cell_id,
                                      new_locked_state, ts_ms);

    FW_LOG("[lock-act] %s FIRE #%llu BROADCAST form=0x%X base=0x%X cell=0x%X "
           "locked=%d ts=%llu",
           tag, static_cast<unsigned long long>(fire),
           r.form_id, r.base_id, r.cell_id,
           new_locked_state ? 1 : 0,
           static_cast<unsigned long long>(ts_ms));
}

void __fastcall detour_force_unlock(void* refr) {
    on_lock_flip(refr, /*new_locked_state=*/false,
                 g_orig_force_unlock, g_unlock_fires, "UNLOCK");
}

void __fastcall detour_force_lock(void* refr) {
    on_lock_flip(refr, /*new_locked_state=*/true,
                 g_orig_force_lock, g_lock_fires, "LOCK");
}

} // namespace

bool install_lock_hook(std::uintptr_t module_base) {
    g_lock_data_get = reinterpret_cast<LockDataGetFn>(
        module_base + fw::offsets::ENGINE_LOCK_DATA_GET_RVA);

    const auto unlock_ea = module_base + fw::offsets::ENGINE_FORCE_UNLOCK_RVA;
    const bool unlock_ok = install(
        reinterpret_cast<void*>(unlock_ea),
        reinterpret_cast<void*>(&detour_force_unlock),
        reinterpret_cast<void**>(&g_orig_force_unlock));
    if (unlock_ok) {
        FW_LOG("[lock-act] ForceUnlock hook installed at 0x%llX (RVA 0x%lX)",
               static_cast<unsigned long long>(unlock_ea),
               static_cast<unsigned long>(fw::offsets::ENGINE_FORCE_UNLOCK_RVA));
    } else {
        FW_ERR("[lock-act] ForceUnlock hook FAILED at 0x%llX",
               static_cast<unsigned long long>(unlock_ea));
    }

    const auto lock_ea = module_base + fw::offsets::ENGINE_FORCE_LOCK_RVA;
    const bool lock_ok = install(
        reinterpret_cast<void*>(lock_ea),
        reinterpret_cast<void*>(&detour_force_lock),
        reinterpret_cast<void**>(&g_orig_force_lock));
    if (lock_ok) {
        FW_LOG("[lock-act] ForceLock hook installed at 0x%llX (RVA 0x%lX)",
               static_cast<unsigned long long>(lock_ea),
               static_cast<unsigned long>(fw::offsets::ENGINE_FORCE_LOCK_RVA));
    } else {
        FW_ERR("[lock-act] ForceLock hook FAILED at 0x%llX",
               static_cast<unsigned long long>(lock_ea));
    }

    return unlock_ok && lock_ok;
}

} // namespace fw::hooks
