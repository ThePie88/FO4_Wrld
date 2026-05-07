// M9 wedge 4 (witness pattern, step 1) — NIF path cache.
// See nif_path_cache.h for design.
//
// HOOK TARGET — 2026-04-30 22:50 update: moved from public API
// (sub_1417B3E90) to the WORKER (sub_1417B3480, NIF_LOAD_WORKER_RVA).
//
// Why: 4 NIF-load wrappers exist in FO4 1.11.191 (TESModel, batch,
// REFR::Load3D, Actor::Load3D — see ni_offsets.h §12), all of which
// funnel into sub_1417B3480. The public API sub_1417B3E90 is just one
// of those wrappers. M9.w4 iter 9-10 logs showed the cache catching
// markers, morphs, water, fire effects — but ZERO weapon NIFs, because
// weapons get loaded via Actor::Load3D / REFR::Load3D bypassing the
// public wrapper.
//
// Hooking the worker is the choke point — every NIF parse on the
// machine flows through it. After this change we expect to see
// "Weapons\..." entries in the cache log.
//
// IMPORTANT: engine_tracer.cpp also has a detour skeleton on
// sub_1417B3E90 (the public API) but is currently NOT installed
// (install_all.cpp commented out). Targets are now disjoint, so
// re-enabling engine_tracer would not conflict. But we still recommend
// keeping engine_tracer disabled in production to avoid double work.

#include "nif_path_cache.h"

#include <windows.h>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <unordered_map>

#include "../hook_manager.h"
#include "../log.h"
#include "ni_offsets.h"
#include "weapon_capture.h"  // M9.w4 PROPER (v0.4.2+, Path NIF-CAPTURE)

namespace fw::native::nif_path_cache {

namespace {

// Worker NIF parse-and-build (sub_1417B3480, NIF_LOAD_WORKER_RVA).
// 5-argument signature from re/stradaB_nif_loader_api.txt §1:
//
//   _DWORD* __fastcall sub_1417B3480(
//       __int64       streamCtx,    // rcx — stream ctx (often null; wrapper builds)
//       const char*   pathCstr,     // rdx — ANSI path; null falls back to global
//       void*         opts,         // r8  — 16-byte NifLoadOpts struct
//       NiAVObject**  outNode,      // r9  — BYREF, receives BSFadeNode*
//       __int64       userCtx);     // stack — passed to BSModelProcessor cb
//
// Return: TLS scratch DWORD* (caller ignores). Real output is *outNode
// (refcount already incremented).
//
// We treat the return as opaque (just `void*`).
using NifLoadWorkerFn =
    void* (__fastcall*)(std::int64_t, const char*, void*, void**, std::int64_t);

NifLoadWorkerFn g_orig = nullptr;

// Cache resolver (sub_1416A6D00). 5-arg fastcall:
//   rcx = modelDB
//   rdx = pathCstr (ANSI)
//   r8  = entry (Entry* / state)
//   r9  = handlePtrPtr (BYREF — written by resolver, read by worker on miss
//                        OR contains the cached NiAVObject* on hit)
//   stack = flag (char)
// Returns int: 1=hit, 2=miss, 0=ambiguous.
using NifCacheResolverFn =
    int (__fastcall*)(void*, const char*, void*, void**, char);

NifCacheResolverFn g_orig_resolver = nullptr;

// Global cache. shared_mutex pattern — many concurrent readers (lookup),
// rare writers (every successful nif_load completion).
std::shared_mutex                                g_mtx;
std::unordered_map<void*, std::string>           g_cache;
std::atomic<std::uint64_t>                       g_invocations{0};
std::atomic<std::uint64_t>                       g_evictions{0};
std::atomic<std::uint64_t>                       g_resolver_invocations{0};
std::atomic<std::uint64_t>                       g_resolver_weapon_hits{0};

// Cap. Typical equip-cycle adds <50 entries; cell transitions add
// ~100-300 (full body+armor+weapon reload). 8192 gives plenty of headroom
// before we hit the eviction path.
constexpr std::size_t MAX_ENTRIES = 8192;

// SEH-safe ANSI string copy. Truncates at `bufsz - 1` chars or at first
// null. Returns true if at least the null was placed (i.e. buf is a valid
// C-string after return). Returns false on AV — buf untouched in that case.
bool seh_strcpy(const char* src, char* dst, std::size_t bufsz) {
    if (!src || bufsz < 2) return false;
    __try {
        std::size_t i = 0;
        for (; i < bufsz - 1 && src[i]; ++i) {
            const char c = src[i];
            // Filter out non-printable garbage that would suggest the
            // pointer drifted into binary data.
            if (c == 0) break;
            dst[i] = c;
        }
        dst[i] = 0;
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// Detour for sub_1417B3480 (worker). 5-arg form. Chain through then
// capture on success.
//
// NOTE: the worker's return value is a TLS scratch pointer (not a status
// code). The "success" criterion is: *out_node != null after the call.
// We don't try to interpret the return.
void* __fastcall detour_nif_load(
    std::int64_t streamCtx, const char* path, void* opts,
    void** out_node, std::int64_t userCtx)
{
    // Chain to original immediately. We must not introduce side effects
    // BEFORE the engine call — vanilla loaders carry main-thread expectations
    // that are easy to violate.
    void* rc = g_orig(streamCtx, path, opts, out_node, userCtx);
    g_invocations.fetch_add(1, std::memory_order_relaxed);

    // Capture only when we have a non-null output node. The worker can
    // succeed-without-output if the path was null and the global fallback
    // also unset, in which case *out_node stays null.
    if (!out_node) return rc;
    void* node = *out_node;
    if (!node) return rc;

    // Safe path copy (paths in BSResource come from cached BSFixedString
    // backing storage, but they are sometimes interned via aux allocators
    // whose lifetime overlaps the load — a defensive copy costs nothing
    // and removes a class of dangling-pointer bugs).
    char buf[MAX_PATH];
    if (!seh_strcpy(path, buf, sizeof(buf))) {
        // AV reading the input path — drop silently, the cache entry would
        // be garbage anyway. Log at DBG so we see frequency in dev.
        FW_DBG("[nif-cache] AV reading path; node=%p skipped", node);
        return rc;
    }

    // Filter empty paths (shouldn't happen for a successful load but
    // defensive).
    if (buf[0] == 0) return rc;

    // M9.w4 PROPER (v0.4.2+, Path NIF-CAPTURE) — notify weapon_capture if
    // an equip window is currently armed. Filters internally to weapon
    // paths; cheap fast-out otherwise.
    fw::native::weapon_capture::record_loaded_path(buf);

    // Insert under exclusive lock. Cap-and-clear on overflow.
    {
        std::unique_lock<std::shared_mutex> lk(g_mtx);
        if (g_cache.size() >= MAX_ENTRIES) {
            // Drop the cache entirely. Subsequent loads repopulate it. We
            // log because hitting this in normal play would indicate a
            // bigger-than-expected churn that warrants investigation.
            const std::size_t before = g_cache.size();
            g_cache.clear();
            g_evictions.fetch_add(before, std::memory_order_relaxed);
            FW_WRN("[nif-cache] reached cap %zu — cleared (total evictions=%llu)",
                   before,
                   static_cast<unsigned long long>(
                       g_evictions.load(std::memory_order_relaxed)));
        }
        g_cache.emplace(node, std::string{buf});
    }

    // Verbose-but-bounded log: only the first ~100 invocations are logged
    // verbatim so we can validate the cache populates correctly during
    // boot without spamming the file across 30 minutes of play.
    const std::uint64_t n =
        g_invocations.load(std::memory_order_relaxed);
    if (n <= 100) {
        FW_LOG("[nif-cache] #%llu node=%p path='%s'",
               static_cast<unsigned long long>(n), node, buf);
    } else if ((n % 256) == 0) {
        FW_DBG("[nif-cache] #%llu node=%p path='%s' (heartbeat)",
               static_cast<unsigned long long>(n), node, buf);
    }
    return rc;
}

// Detour for sub_1416A6D00 (cache resolver). 5-arg form. Diagnostic-only:
// log every path that flows through, with special highlighting for
// "Weapons\..." paths to confirm whether weapon lookups are visible at
// this layer at all.
//
// On HIT (rc=1) we ALSO try to write the resolved NiAVObject* into the
// cache map. The handle layout is observed empirically — if weapons hit
// at this level we'll log handle hex bytes for offset discovery.
int __fastcall detour_cache_resolver(
    void* modelDB, const char* path, void* entry, void** handlePtrPtr,
    char flag)
{
    const int rc = g_orig_resolver(modelDB, path, entry, handlePtrPtr, flag);
    const std::uint64_t n =
        g_resolver_invocations.fetch_add(1, std::memory_order_relaxed) + 1;

    char buf[MAX_PATH];
    if (!seh_strcpy(path, buf, sizeof(buf))) return rc;
    if (buf[0] == 0) return rc;

    // M9.w4 PROPER (v0.4.2+, Path NIF-CAPTURE) — notify weapon_capture.
    // Resolver fires on EVERY lookup including cache hits, so this is
    // where we catch repeat-equips of the same modded weapon (worker
    // hook only fires on cache miss).
    fw::native::weapon_capture::record_loaded_path(buf);

    // Detect weapon-ish paths for quick visual scanning of the log.
    // FO4 uses "Weapons\\..." rooted under "Meshes\\". Because we observe
    // path strings with and without the "Meshes\\" prefix depending on the
    // call site, match on case-insensitive substring "Weapons\\".
    auto contains_ci = [](const char* hay, const char* needle) -> bool {
        for (; *hay; ++hay) {
            const char* h = hay; const char* n = needle;
            while (*h && *n) {
                char ch = *h; char cn = *n;
                if (ch >= 'A' && ch <= 'Z') ch = (char)(ch - 'A' + 'a');
                if (cn >= 'A' && cn <= 'Z') cn = (char)(cn - 'A' + 'a');
                if (ch != cn) break;
                ++h; ++n;
            }
            if (!*n) return true;
        }
        return false;
    };
    const bool is_weaponish = contains_ci(buf, "weapon")
                            || contains_ci(buf, "10mm")
                            || contains_ci(buf, "pistol")
                            || contains_ci(buf, "baton")
                            || contains_ci(buf, "rifle");

    if (is_weaponish) {
        const std::uint64_t w = g_resolver_weapon_hits.fetch_add(
            1, std::memory_order_relaxed) + 1;
        // Always log weapon paths verbatim, plus dump first 16 bytes of
        // the handle output for layout discovery on HIT.
        std::uint64_t handle_qw[2] = {0, 0};
        if (rc == 1 && handlePtrPtr) {
            __try {
                handle_qw[0] = *reinterpret_cast<std::uint64_t*>(
                    handlePtrPtr);
                handle_qw[1] = *reinterpret_cast<std::uint64_t*>(
                    reinterpret_cast<char*>(handlePtrPtr) + 8);
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                handle_qw[0] = 0xDEADBEEF;
            }
        }
        FW_LOG("[nif-resolver] WEAPON-ISH #%llu rc=%d path='%s' "
               "handlePtrPtr=%p handle[0]=0x%llX handle[1]=0x%llX",
               static_cast<unsigned long long>(w), rc, buf,
               handlePtrPtr,
               static_cast<unsigned long long>(handle_qw[0]),
               static_cast<unsigned long long>(handle_qw[1]));
    } else if (n <= 200) {
        // Log first 200 non-weapon invocations to see what categories of
        // paths flow through (markers, body, armor, etc).
        FW_DBG("[nif-resolver] #%llu rc=%d path='%s'",
               static_cast<unsigned long long>(n), rc, buf);
    } else if ((n % 1024) == 0) {
        FW_DBG("[nif-resolver] #%llu rc=%d path='%s' (heartbeat)",
               static_cast<unsigned long long>(n), rc, buf);
    }
    return rc;
}

std::atomic<bool> g_installed{false};
std::atomic<bool> g_resolver_installed{false};

} // namespace

bool install(std::uintptr_t module_base) {
    if (g_installed.load(std::memory_order_acquire)) {
        FW_DBG("[nif-cache] install: already installed — no-op");
        return true;
    }
    if (!module_base) {
        FW_ERR("[nif-cache] install: module_base=0");
        return false;
    }

    // Hook the WORKER (sub_1417B3480), not the public API (sub_1417B3E90).
    // Every NIF parse-and-build flows through the worker; hooking it gives
    // us a true choke point. See the file header comment for rationale.
    void* target = reinterpret_cast<void*>(
        module_base + NIF_LOAD_WORKER_RVA);
    const bool ok = fw::hooks::install(
        target,
        reinterpret_cast<void*>(&detour_nif_load),
        reinterpret_cast<void**>(&g_orig));
    if (!ok) {
        FW_ERR("[nif-cache] install: MH_CreateHook/EnableHook failed "
               "(target=%p RVA=0x%llX worker). Confirm no other module is "
               "hooking sub_1417B3480.",
               target,
               static_cast<unsigned long long>(NIF_LOAD_WORKER_RVA));
        return false;
    }

    g_installed.store(true, std::memory_order_release);
    FW_LOG("[nif-cache] installed: detour on NIF worker "
           "(target=%p RVA=0x%llX sub_1417B3480) cap=%zu",
           target,
           static_cast<unsigned long long>(NIF_LOAD_WORKER_RVA),
           MAX_ENTRIES);

    // CACHE RESOLVER HOOK — DISABLED 2026-04-30 23:10.
    // We tried hooking sub_1416A6D00 to catch weapon NIFs that bypass the
    // worker. Result: 437 "WEAPON-ISH" hits in 3 minutes of play but ALL
    // were .hkx Havok animation files — zero .nif weapon mesh paths.
    // Weapons are loaded via a streaming/async route that bypasses BOTH
    // the worker AND the resolver. Conclusion: form_id → path lookup is
    // not feasible at any hook point we've tried; raw mesh capture
    // (Path B) is the only remaining route.
    //
    // Detour function `detour_cache_resolver` is kept compiled-but-unused
    // for diagnostic re-enablement if we want to verify with a different
    // path-filter pattern later. Suppress the unused-static warning:
    (void)&detour_cache_resolver;
    return true;
}

std::string lookup(void* node) {
    if (!node) return {};
    std::shared_lock<std::shared_mutex> lk(g_mtx);
    auto it = g_cache.find(node);
    if (it == g_cache.end()) return {};
    return it->second; // copy out under shared lock
}

std::size_t entry_count() {
    std::shared_lock<std::shared_mutex> lk(g_mtx);
    return g_cache.size();
}

std::uint64_t total_invocations() {
    return g_invocations.load(std::memory_order_relaxed);
}

std::uint64_t total_evictions() {
    return g_evictions.load(std::memory_order_relaxed);
}

} // namespace fw::native::nif_path_cache
