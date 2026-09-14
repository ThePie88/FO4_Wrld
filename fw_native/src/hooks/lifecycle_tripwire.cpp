#include "lifecycle_tripwire.h"

#include <windows.h>
#include <intrin.h>

#include <atomic>

#include "../hook_manager.h"
#include "../engine/engine_calls.h"
#include "../native/world_spawn.h"
#include "../offsets.h"
#include "../ref_identity.h"
#include "../log.h"

#pragma intrinsic(_ReturnAddress)

namespace fw::hooks {

namespace {

// DestroyByHandle: `__int64 __fastcall sub_140C23EC0(int* handle_ptr)`.
using DestroyByHandleFn = std::int64_t(__fastcall*)(std::uint32_t* handle_ptr);
// Unpersist: `char __fastcall sub_1403380C0(mgr, REFR*, tag, char)`.
using UnpersistFn = char(__fastcall*)(void* mgr, void* refr,
                                      std::uint64_t tag, char a4);

DestroyByHandleFn g_orig_destroy   = nullptr;
UnpersistFn       g_orig_unpersist = nullptr;

std::atomic<std::uintptr_t> g_base{0};

// Nesting markers so a destroy that fires INSIDE an unpersist call names its
// real driver even when return-address attribution would be ambiguous.
thread_local std::uint32_t t_unpersist_depth   = 0;
thread_local std::uint32_t t_nested_destroys   = 0;

// Vanilla-ref destroys (fid < 0xFF000000) flood during any cell detach —
// the purge destroys every non-persistent ref of the cell. Those are counted
// and summarized, never logged one by one.
std::atomic<std::uint64_t> g_skipped_vanilla{0};
std::atomic<std::uint64_t> g_skipped_dynamic{0};
std::atomic<std::uintptr_t> g_last_vanilla_caller{0};

std::uint32_t seh_u32_at(const void* p, std::size_t off) noexcept {
    if (!p) return 0;
    __try {
        return *reinterpret_cast<const std::uint32_t*>(
            reinterpret_cast<const std::uint8_t*>(p) + off);
    } __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
}

std::uint8_t seh_u8_at(const void* p, std::size_t off) noexcept {
    if (!p) return 0;
    __try {
        return *reinterpret_cast<const std::uint8_t*>(
            reinterpret_cast<const std::uint8_t*>(p) + off);
    } __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
}

void* seh_ptr_at(const void* p, std::size_t off) noexcept {
    if (!p) return nullptr;
    __try {
        return *reinterpret_cast<void* const*>(
            reinterpret_cast<const std::uint8_t*>(p) + off);
    } __except (EXCEPTION_EXECUTE_HANDLER) { return nullptr; }
}

bool seh_and_u32(void* p, std::size_t off, std::uint32_t mask) noexcept {
    if (!p) return false;
    __try {
        *reinterpret_cast<std::uint32_t*>(
            reinterpret_cast<std::uint8_t*>(p) + off) &= mask;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

// Identity + flags under SEH. read_ref_identity guards null pointers but
// relies on the CALLER for structurally-bad ones ("we catch SEH at the hook
// boundary", ref_identity.h) — and during the reload teardown this detour
// sees freed objects with garbage base pointers. RefIdentity is POD, so the
// call is legal inside __try.
bool seh_identity(void* refr, std::uint32_t* fid, std::uint32_t* base_id,
                  std::uint32_t* cell_id, std::uint32_t* flags) noexcept {
    if (!refr) return false;
    __try {
        const fw::RefIdentity id = fw::read_ref_identity(refr);
        *fid     = id.form_id;
        *base_id = id.base_id;
        *cell_id = id.cell_id;
        *flags   = *reinterpret_cast<const std::uint32_t*>(
            reinterpret_cast<const std::uint8_t*>(refr)
            + fw::offsets::FLAGS_OFF);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

std::int64_t __fastcall detour_destroy_by_handle(std::uint32_t* handle_ptr) {
    const std::uintptr_t base = g_base.load(std::memory_order_relaxed);
    const std::uintptr_t caller =
        reinterpret_cast<std::uintptr_t>(_ReturnAddress()) - base;

    // Any destroy inside an Unpersist call counts for its prediction check,
    // whatever the fid space — vanilla NPC frames die there too.
    if (t_unpersist_depth > 0) ++t_nested_destroys;

    // Identity BEFORE the original runs — afterwards the handle is released
    // and the object queued for the deferred free. resolve_refhandle is
    // borrow-semantics since Build 70, so this pins nothing. All reads are
    // SEH-caged: during the reload teardown this path sees freed objects.
    if (handle_ptr && *handle_ptr != 0) {
        void* refr = fw::engine::resolve_refhandle(handle_ptr);
        std::uint32_t fid = 0, base_id = 0, cell_id = 0, flags = 0;
        if (seh_identity(refr, &fid, &base_id, &cell_id, &flags)) {
            const bool ours = fid >= 0xFF000000u
                              && fw::native::world_spawn::is_our_fid(fid);
            if (ours) {
                // Build 70c — THE POST-DEATH CRASH FIX. A ref that dies with
                // no-save 0x4000 set SKIPS all global-manager unregistration
                // in its dtor chain (flag census site 11, slot 74 early-out).
                // The stale registry entry then detonates the next reload:
                // BGSSaveLoadGame::ClearForm (sub_140BED5F0) walks the
                // dynamic-form table and calls vt[+0x208] on the freed
                // object — measured AV at RVA 0xBED687, garbage vtable.
                // Clearing the bit BEFORE the destruction runs routes the
                // dtor down the vanilla unregistration path.
                const bool cleared = (flags & fw::offsets::REFR_FLAG_TEMPORARY)
                    ? seh_and_u32(refr, fw::offsets::FLAGS_OFF,
                                  ~fw::offsets::REFR_FLAG_TEMPORARY)
                    : false;
                FW_LOG("[tripwire] DESTROY of OUR replica fid=0x%08X "
                       "base=0x%08X cell=0x%08X flags=0x%X caller=+0x%llX%s%s",
                       fid, base_id, cell_id, flags,
                       static_cast<unsigned long long>(caller),
                       t_unpersist_depth > 0 ? " via=UNPERSIST" : "",
                       cleared ? " [no-save CLEARED for full unregister]"
                               : "");
            } else if (fid >= 0xFF000000u) {
                // Dynamic but not ours (ghost bones, engine spawns, reload
                // teardown corpses): counted, DBG detail, INF summary. The
                // per-line INF flood during teardown was itself a hazard.
                const std::uint64_t n = 1 +
                    g_skipped_dynamic.fetch_add(1, std::memory_order_relaxed);
                FW_DBG("[tripwire] DESTROY fid=0x%08X base=0x%08X flags=0x%X "
                       "caller=+0x%llX", fid, base_id, flags,
                       static_cast<unsigned long long>(caller));
                if ((n & 0x1FF) == 0) {
                    FW_LOG("[tripwire] DESTROY x%llu dynamic (not-ours) refs "
                           "so far (last caller=+0x%llX)",
                           static_cast<unsigned long long>(n),
                           static_cast<unsigned long long>(caller));
                }
            } else {
                const std::uint64_t n = 1 +
                    g_skipped_vanilla.fetch_add(1, std::memory_order_relaxed);
                g_last_vanilla_caller.store(caller, std::memory_order_relaxed);
                if ((n & 0x1FF) == 0) {   // one line every 512
                    FW_DBG("[tripwire] DESTROY x%llu vanilla refs so far "
                           "(last caller=+0x%llX)",
                           static_cast<unsigned long long>(n),
                           static_cast<unsigned long long>(caller));
                }
            }
        }
    }
    return g_orig_destroy(handle_ptr);
}

char __fastcall detour_unpersist(void* mgr, void* refr,
                                 std::uint64_t tag, char a4) {
    const std::uintptr_t base = g_base.load(std::memory_order_relaxed);
    const std::uintptr_t caller =
        reinterpret_cast<std::uintptr_t>(_ReturnAddress()) - base;

    // The destruction branch, read off the function body itself
    // (funcs_0143.md:11236): destroy when `!parentCell || cell+0x44 == 0`;
    // secondary path when wants-delete (+0x18 bit 1) is set and the 3D is
    // gone. Predict it here so the log tells us BEFORE the engine acts.
    // Every read SEH-caged (Build 70c).
    std::uint32_t fid = 0, base_id = 0, cell_id = 0, flags = 0;
    (void)seh_identity(refr, &fid, &base_id, &cell_id, &flags);
    void* cell = seh_ptr_at(refr, fw::offsets::PARENT_CELL_OFF);
    const std::uint8_t cell_state = cell ? seh_u8_at(cell, 0x44) : 0;
    const bool wants_delete = (seh_u32_at(refr, 0x18) & 0x1) != 0;
    const bool predicted_destroy = (!cell || cell_state == 0);
    // Only log at INF when the ref is one of OURS or the kill branch is
    // predicted — the janitor calls this on vanilla NPC frames all day.
    const bool ours = fid >= 0xFF000000u
                      && fw::native::world_spawn::is_our_fid(fid);
    const bool loud = ours || predicted_destroy;

    if (loud) {
        FW_LOG("[tripwire] UNPERSIST fid=0x%08X base=0x%08X tag=0x%llX a4=%d "
               "cell=0x%08X state=%u wantsdel=%d caller=+0x%llX%s -> "
               "predicted %s",
               fid, base_id,
               static_cast<unsigned long long>(tag), int(a4),
               cell_id, unsigned(cell_state), int(wants_delete),
               static_cast<unsigned long long>(caller),
               ours ? " [OURS]" : "",
               predicted_destroy ? "DESTROY" : "keep");
    }

    ++t_unpersist_depth;
    const std::uint32_t destroys_before = t_nested_destroys;
    const char ret = g_orig_unpersist(mgr, refr, tag, a4);
    --t_unpersist_depth;

    const std::uint32_t nested = t_nested_destroys - destroys_before;
    if (loud || nested > 0) {
        FW_LOG("[tripwire] UNPERSIST fid=0x%08X done ret=%d "
               "nested_destroys=%u%s", fid, int(ret), nested,
               (ret != 0) && ((nested > 0) != predicted_destroy)
                   ? " (PREDICTION WRONG — read the branch again)" : "");
    }
    return ret;
}

}  // namespace

bool install_lifecycle_tripwire(std::uintptr_t module_base) {
    if (!module_base) return false;
    g_base.store(module_base, std::memory_order_relaxed);

    void* dtarget = reinterpret_cast<void*>(
        module_base + fw::offsets::DESTROY_BY_HANDLE_RVA);
    const bool d_ok = fw::hooks::install(
        dtarget, reinterpret_cast<void*>(&detour_destroy_by_handle),
        reinterpret_cast<void**>(&g_orig_destroy));

    void* utarget = reinterpret_cast<void*>(
        module_base + fw::offsets::UNPERSIST_PROMOTED_REF_RVA);
    const bool u_ok = fw::hooks::install(
        utarget, reinterpret_cast<void*>(&detour_unpersist),
        reinterpret_cast<void**>(&g_orig_unpersist));

    if (d_ok && u_ok) {
        FW_LOG("[tripwire] lifecycle tripwires installed "
               "(DestroyByHandle=%p Unpersist=%p) — observe-only",
               dtarget, utarget);
    } else {
        FW_ERR("[tripwire] install FAILED (destroy=%d unpersist=%d)",
               int(d_ok), int(u_ok));
    }
    return d_ok && u_ok;
}

}  // namespace fw::hooks
