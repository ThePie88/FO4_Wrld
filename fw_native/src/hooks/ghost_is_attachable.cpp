#include "ghost_is_attachable.h"

#include <windows.h>
#include <atomic>
#include <cstdint>

#include "../hook_manager.h"
#include "../log.h"

namespace fw::hooks {

namespace {

// `sub_1403095C0` Cell::IsAttachable — RVA 0x3095C0 verified
// funcs_0139.md:10555. Size 0x63 = 99 bytes.
//   bool __fastcall(__int64 a1, int a2)
using IsAttachableFn = char (*)(std::uint64_t a1, int a2);

// `sub_1403097E0` Cell::AttachREFR — RVA 0x3097E0 verified
// funcs_0139.md:10669. Size 0x7AD = 1965 bytes.
//   char __fastcall(__int64 cell_ctx, _QWORD* refr, char flag)
using AttachRefrFn   = char (*)(std::uint64_t cell_ctx, void* refr, char flag);

// `sub_1404C4DF0` actor-lock-walker — RVA 0x4C4DF0 verified
// funcs_0171.md:6045. Size 70 bytes.
//   bool __fastcall(__int64 actor)
//   reads `v1 = *(actor+0x48)`, passes `v1+32` to sub_141658FE0 (lock).
//   If actor+0x48 is NULL → crash at NULL+0x20 (Build 28h/o crash).
//
// Hook: when called with actor.fid == 0xFF000001 (our ghost proxy),
// bail immediately (return 0). Same root-level pattern as
// npc_ai_suppress Update_PerFrame bail (Build 28k).
using ActorLockWalkerFn = char (*)(std::uint64_t actor);
constexpr std::uintptr_t ACTOR_LOCK_WALKER_RVA = 0x004C4DF0;
ActorLockWalkerFn g_orig_actor_lock_walker = nullptr;

// `sub_140312690` IsTransientFid — RVA 0x312690 verified
// funcs_0140.md:7387. Size 8 bytes.
//   bool __fastcall(__int64 actor) — returns actor.fid >= 0xFF000000
// Called inside NEW_REFR_DATA dispatcher (sub_1402E4DF0 line 6849).
// All PlaceAtMe-spawned actors get transient fids (0xFF...) so this
// returns TRUE → dispatcher short-circuits to non-attached path which
// never calls vt[191](actor, cell) — the very function that populates
// actor+0x48 with a real lock-object pointer. Result (Build 28g log):
// proxy+0x48 stays as Actor::vftable_4 from ctor → sub_1404C4DF0 reads
// vftable+32 thinking it's a lock → bad read → crash.
//
// Hook this with TLS flag during our spawn → return FALSE → dispatcher
// evaluates the second condition (IsAttachable) which is also hooked to
// TRUE → final condition FALSE → ATTACHED path runs → vt[191](actor,
// cell) populates +0x48 with proper lock pointer.
using IsTransientFidFn = char (*)(std::uint64_t actor);

constexpr std::uintptr_t IS_ATTACHABLE_RVA = 0x003095C0;
constexpr std::uintptr_t ATTACH_REFR_RVA   = 0x003097E0;
constexpr std::uintptr_t IS_TRANSIENT_FID_RVA = 0x00312690;

IsAttachableFn   g_orig_is_attachable  = nullptr;
AttachRefrFn     g_orig_attach_refr    = nullptr;
IsTransientFidFn g_orig_is_transient_fid = nullptr;

// Thread-local "spawn in progress" flag. Both hooks read it.
thread_local bool t_force_not_attachable = false;

std::atomic<std::uint64_t> g_isatt_bypass_count{0};
std::atomic<std::uint64_t> g_isatt_passthrough_count{0};
std::atomic<std::uint64_t> g_attref_bypass_count{0};
std::atomic<std::uint64_t> g_attref_passthrough_count{0};
std::atomic<std::uint64_t> g_xfid_bypass_count{0};
std::atomic<std::uint64_t> g_xfid_passthrough_count{0};
std::atomic<std::uint64_t> g_lockwalker_bypass_count{0};
std::atomic<std::uint64_t> g_lockwalker_passthrough_count{0};
std::atomic<std::uint64_t> g_seh_failures{0};
std::atomic<bool>          g_installed{false};

// Build 28g: return **1** (TRUE) during our spawn so the engine takes
// the ATTACHED path, which calls vt[191](actor, cell) to populate
// actor+0x48 and friends. The actual AttachREFR call is no-op'd by
// the sibling hook below.
char __fastcall detour_is_attachable(std::uint64_t a1, int a2) {
    __try {
        if (t_force_not_attachable) {
            const auto n = g_isatt_bypass_count.fetch_add(
                1, std::memory_order_relaxed);
            if (n < 10) {
                FW_LOG("[is-attachable] BYPASS #%llu (a1=0x%llX a2=%d) "
                       "returning 1 — force ATTACHED path so vt[191] "
                       "populates actor+0x48 etc.",
                       static_cast<unsigned long long>(n),
                       static_cast<unsigned long long>(a1), a2);
            }
            return 1;
        }
        g_isatt_passthrough_count.fetch_add(1, std::memory_order_relaxed);
        if (g_orig_is_attachable) {
            return g_orig_is_attachable(a1, a2);
        }
        return 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        g_seh_failures.fetch_add(1, std::memory_order_relaxed);
        FW_ERR("[is-attachable] SEH in detour (a1=0x%llX)",
               static_cast<unsigned long long>(a1));
        return 0;
    }
}

// Build 28g: no-op AttachREFR during our spawn. Engine code that
// called AttachREFR believes it succeeded (return value 1) without
// any actual cell-attach side effects (physics bind, audio bind,
// render-list add). Our proxy doesn't need any of that — body ghost
// renders separately.
// Build 28q: bail sub_1404C4DF0 (actor-lock-walker) UNIVERSALLY when
// actor+0x48 is NULL (regardless of fid). Function dereferences
// `*(actor+0x48)` then passes `result+32` to a lock acquire — if NULL,
// crash at NULL+0x20.
//
// Build 28p version only bailed for our ghost proxy fid. But the visitor
// pattern `sub_14018BA40` iterates many actors; some other partially-
// initialized actor (potentially freed but still listed) ALSO has
// +0x48 NULL → crash unrelated to our proxy.
//
// Universal safety: bail for ANY actor with +0x48 NULL. Function
// returns 0 (= "lock not acquired" / "no work") which is the same as
// "actor has no lock object" — semantically equivalent to skip.
char __fastcall detour_actor_lock_walker(std::uint64_t actor) {
    __try {
        if (!actor) {
            g_lockwalker_passthrough_count.fetch_add(
                1, std::memory_order_relaxed);
            if (g_orig_actor_lock_walker) {
                return g_orig_actor_lock_walker(actor);
            }
            return 0;
        }

        // Check +0x48 first (universal NULL safety).
        void* lock_obj = *reinterpret_cast<void**>(actor + 0x48);
        std::uint32_t fid = *reinterpret_cast<std::uint32_t*>(
            actor + 0x14);
        const bool is_ghost = (fid == 0xFF000001);
        const bool null_lock = (lock_obj == nullptr);

        if (is_ghost || null_lock) {
            const auto n = g_lockwalker_bypass_count.fetch_add(
                1, std::memory_order_relaxed);
            if (n < 5 || (n % 1000) == 0) {
                FW_LOG("[lock-walker] BYPASS #%llu actor=0x%llX "
                       "fid=0x%08X reason=%s",
                       static_cast<unsigned long long>(n),
                       static_cast<unsigned long long>(actor), fid,
                       is_ghost ? (null_lock ? "GHOST+NULL_LOCK" : "GHOST")
                                : "NULL_LOCK");
            }
            return 0;
        }

        g_lockwalker_passthrough_count.fetch_add(
            1, std::memory_order_relaxed);
        if (g_orig_actor_lock_walker) {
            return g_orig_actor_lock_walker(actor);
        }
        return 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        g_seh_failures.fetch_add(1, std::memory_order_relaxed);
        FW_ERR("[lock-walker] SEH (actor=0x%llX) — bailing",
               static_cast<unsigned long long>(actor));
        return 0;
    }
}

// Build 28h: force IsTransientFid → FALSE during spawn so dispatcher
// takes ATTACHED path (which calls vt[191](actor, cell), populating
// +0x48 with a real lock object).
char __fastcall detour_is_transient_fid(std::uint64_t actor) {
    __try {
        if (t_force_not_attachable) {
            const auto n = g_xfid_bypass_count.fetch_add(
                1, std::memory_order_relaxed);
            if (n < 10) {
                FW_LOG("[is-xfid] BYPASS #%llu (actor=0x%llX) "
                       "returning 0 — force dispatcher attached path",
                       static_cast<unsigned long long>(n),
                       static_cast<unsigned long long>(actor));
            }
            return 0;
        }
        g_xfid_passthrough_count.fetch_add(1, std::memory_order_relaxed);
        if (g_orig_is_transient_fid) {
            return g_orig_is_transient_fid(actor);
        }
        return 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        g_seh_failures.fetch_add(1, std::memory_order_relaxed);
        FW_ERR("[is-xfid] SEH in detour (actor=0x%llX)",
               static_cast<unsigned long long>(actor));
        return 0;
    }
}

char __fastcall detour_attach_refr(std::uint64_t cell_ctx, void* refr, char flag) {
    __try {
        if (t_force_not_attachable) {
            const auto n = g_attref_bypass_count.fetch_add(
                1, std::memory_order_relaxed);
            if (n < 10) {
                FW_LOG("[attach-refr] BYPASS #%llu (cell=0x%llX refr=%p "
                       "flag=%d) returning 1 (no-op) — engine thinks "
                       "attach succeeded",
                       static_cast<unsigned long long>(n),
                       static_cast<unsigned long long>(cell_ctx),
                       refr, static_cast<int>(flag));
            }
            return 1;
        }
        g_attref_passthrough_count.fetch_add(1, std::memory_order_relaxed);
        if (g_orig_attach_refr) {
            return g_orig_attach_refr(cell_ctx, refr, flag);
        }
        return 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        g_seh_failures.fetch_add(1, std::memory_order_relaxed);
        FW_ERR("[attach-refr] SEH in detour (cell=0x%llX refr=%p)",
               static_cast<unsigned long long>(cell_ctx), refr);
        return 0;
    }
}

} // namespace

void set_force_not_attachable(bool v) {
    t_force_not_attachable = v;
}

bool install_ghost_is_attachable(std::uintptr_t module_base) {
    if (g_installed.load(std::memory_order_acquire)) {
        FW_LOG("[is-attachable] already installed; skipping");
        return true;
    }

    // Hook IsAttachable.
    const auto isatt_ea = module_base + IS_ATTACHABLE_RVA;
    const bool ok1 = install(
        reinterpret_cast<void*>(isatt_ea),
        reinterpret_cast<void*>(&detour_is_attachable),
        reinterpret_cast<void**>(&g_orig_is_attachable));
    if (ok1) {
        FW_LOG("[is-attachable] IsAttachable hook installed at "
               "0x%llX (RVA 0x%lX) — TLS-gated; returns 1 during spawn",
               static_cast<unsigned long long>(isatt_ea),
               static_cast<unsigned long>(IS_ATTACHABLE_RVA));
    } else {
        FW_ERR("[is-attachable] IsAttachable hook FAILED at 0x%llX",
               static_cast<unsigned long long>(isatt_ea));
    }

    // Hook AttachREFR.
    const auto attref_ea = module_base + ATTACH_REFR_RVA;
    const bool ok2 = install(
        reinterpret_cast<void*>(attref_ea),
        reinterpret_cast<void*>(&detour_attach_refr),
        reinterpret_cast<void**>(&g_orig_attach_refr));
    if (ok2) {
        FW_LOG("[attach-refr] AttachREFR hook installed at "
               "0x%llX (RVA 0x%lX) — TLS-gated; no-op during spawn",
               static_cast<unsigned long long>(attref_ea),
               static_cast<unsigned long>(ATTACH_REFR_RVA));
    } else {
        FW_ERR("[attach-refr] AttachREFR hook FAILED at 0x%llX",
               static_cast<unsigned long long>(attref_ea));
    }

    // Hook IsTransientFid (Build 28h).
    const auto xfid_ea = module_base + IS_TRANSIENT_FID_RVA;
    const bool ok3 = install(
        reinterpret_cast<void*>(xfid_ea),
        reinterpret_cast<void*>(&detour_is_transient_fid),
        reinterpret_cast<void**>(&g_orig_is_transient_fid));
    if (ok3) {
        FW_LOG("[is-xfid] IsTransientFid hook installed at "
               "0x%llX (RVA 0x%lX) — TLS-gated; returns 0 during spawn",
               static_cast<unsigned long long>(xfid_ea),
               static_cast<unsigned long>(IS_TRANSIENT_FID_RVA));
    } else {
        FW_ERR("[is-xfid] IsTransientFid hook FAILED at 0x%llX",
               static_cast<unsigned long long>(xfid_ea));
    }

    // Hook actor-lock-walker (Build 28p).
    const auto lockwalker_ea = module_base + ACTOR_LOCK_WALKER_RVA;
    const bool ok4 = install(
        reinterpret_cast<void*>(lockwalker_ea),
        reinterpret_cast<void*>(&detour_actor_lock_walker),
        reinterpret_cast<void**>(&g_orig_actor_lock_walker));
    if (ok4) {
        FW_LOG("[lock-walker] sub_1404C4DF0 hook installed at "
               "0x%llX (RVA 0x%lX) — Build 28q: universal bail when "
               "actor+0x48==NULL OR fid==0xFF000001",
               static_cast<unsigned long long>(lockwalker_ea),
               static_cast<unsigned long>(ACTOR_LOCK_WALKER_RVA));
    } else {
        FW_ERR("[lock-walker] sub_1404C4DF0 hook FAILED at 0x%llX",
               static_cast<unsigned long long>(lockwalker_ea));
    }

    const bool ok = ok1 && ok2 && ok3 && ok4;
    if (ok) {
        g_installed.store(true, std::memory_order_release);
    }
    return ok;
}

std::uint64_t get_is_attachable_bypass_count() {
    return g_isatt_bypass_count.load(std::memory_order_relaxed);
}
std::uint64_t get_is_attachable_passthrough_count() {
    return g_isatt_passthrough_count.load(std::memory_order_relaxed);
}
std::uint64_t get_attach_refr_bypass_count() {
    return g_attref_bypass_count.load(std::memory_order_relaxed);
}
std::uint64_t get_attach_refr_passthrough_count() {
    return g_attref_passthrough_count.load(std::memory_order_relaxed);
}

} // namespace fw::hooks
