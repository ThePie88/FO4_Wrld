// M9 wedge 4 — Path B-alt-2 — NiObject pool allocator tracker.
// See ni_alloc_tracker.h for design.

#include "ni_alloc_tracker.h"

#include <windows.h>
#include <atomic>
#include <chrono>
#include <intrin.h>      // _ReturnAddress()
#include <mutex>
#include <shared_mutex>
#include <unordered_map>

#include "../hook_manager.h"
#include "../log.h"
#include "ni_offsets.h"

namespace fw::native::ni_alloc_tracker {

namespace {

// Engine signature from ni_offsets.h §1 (canonical NiObject allocator).
//   void* __fastcall sub_1416579C0(
//       void*         pool,            // rcx
//       std::size_t   size,            // rdx
//       std::uint32_t align,           // r8
//       bool          aligned_fb);     // r9
using AllocateFn = void* (__fastcall*)(void*, std::size_t,
                                        std::uint32_t, bool);

AllocateFn g_orig = nullptr;

std::shared_mutex                                 g_mtx;
std::unordered_map<const void*, AllocTrace>       g_cache;
std::atomic<std::uint64_t>                        g_invocations{0};
std::atomic<std::uint64_t>                        g_evictions{0};
std::uintptr_t                                    g_module_base = 0;

// Sizes we care about. NiNode (0x140) skipped: too frequent (every
// transient bone, every NIF subnode, etc.) and not the bullseye.
constexpr std::size_t SIZE_BSTRISHAPE        = 0x170;
constexpr std::size_t SIZE_BSDYNAMICTRISHAPE = 0x190;

constexpr std::size_t MAX_ENTRIES = 16384;

bool size_is_relevant(std::size_t s) {
    return s == SIZE_BSTRISHAPE || s == SIZE_BSDYNAMICTRISHAPE;
}

std::uint64_t now_ms() {
    using namespace std::chrono;
    return duration_cast<milliseconds>(
        steady_clock::now().time_since_epoch()).count();
}

void* __fastcall detour_alloc(void* pool, std::size_t size,
                               std::uint32_t align, bool aligned_fb)
{
    // _ReturnAddress() returns the RIP of the instruction immediately
    // AFTER the `call` that invoked this detour. That's the caller's
    // function PC — exactly what we need to identify who's allocating.
    void* caller_rip = _ReturnAddress();

    void* result = g_orig(pool, size, align, aligned_fb);

    // Filter for BSTriShape/BSDynamicTriShape allocations only. Skip
    // everything else immediately to keep overhead low — the allocator
    // is one of the hottest functions in the binary (8763 callsites).
    if (!size_is_relevant(size) || !result) return result;

    const std::uint64_t n =
        g_invocations.fetch_add(1, std::memory_order_relaxed) + 1;

    {
        std::unique_lock<std::shared_mutex> lk(g_mtx);
        if (g_cache.size() >= MAX_ENTRIES) {
            const std::size_t before = g_cache.size();
            g_cache.clear();
            g_evictions.fetch_add(before, std::memory_order_relaxed);
            FW_WRN("[alloc-trk] cap %zu reached, cleared", before);
        }
        g_cache[result] = AllocTrace{ size, caller_rip, now_ms() };
    }

    // Log first 100 calls verbatim; then heartbeat at ~256/1024.
    // Caller RVA helps map back to function in IDA quickly.
    const std::uintptr_t rva = (g_module_base && caller_rip)
        ? (reinterpret_cast<std::uintptr_t>(caller_rip) - g_module_base)
        : 0;
    if (n <= 100) {
        FW_LOG("[alloc-trk] #%llu size=0x%zX result=%p caller_rip=%p "
               "caller_rva=0x%llX tid=%lu",
               static_cast<unsigned long long>(n), size, result,
               caller_rip,
               static_cast<unsigned long long>(rva),
               GetCurrentThreadId());
    } else if ((n % 256) == 0) {
        FW_DBG("[alloc-trk] #%llu size=0x%zX result=%p rva=0x%llX (heartbeat)",
               static_cast<unsigned long long>(n), size, result,
               static_cast<unsigned long long>(rva));
    }

    return result;
}

std::atomic<bool> g_installed{false};

} // namespace

bool install(std::uintptr_t module_base) {
    if (g_installed.load(std::memory_order_acquire)) return true;
    if (!module_base) {
        FW_ERR("[alloc-trk] install: module_base=0");
        return false;
    }
    g_module_base = module_base;

    void* target = reinterpret_cast<void*>(module_base + ALLOCATE_FN_RVA);
    const bool ok = fw::hooks::install(
        target,
        reinterpret_cast<void*>(&detour_alloc),
        reinterpret_cast<void**>(&g_orig));
    if (!ok) {
        FW_ERR("[alloc-trk] hook install FAILED on target=%p RVA=0x%llX",
               target,
               static_cast<unsigned long long>(ALLOCATE_FN_RVA));
        return false;
    }
    g_installed.store(true, std::memory_order_release);
    FW_LOG("[alloc-trk] installed: detour on NiObject allocator "
           "(target=%p RVA=0x%llX sub_1416579C0) filter={0x170,0x190} "
           "cap=%zu",
           target,
           static_cast<unsigned long long>(ALLOCATE_FN_RVA),
           MAX_ENTRIES);
    return true;
}

const AllocTrace* lookup(const void* ptr) {
    if (!ptr) return nullptr;
    std::shared_lock<std::shared_mutex> lk(g_mtx);
    auto it = g_cache.find(ptr);
    if (it == g_cache.end()) return nullptr;
    return &it->second;
}

std::uint64_t total_invocations() {
    return g_invocations.load(std::memory_order_relaxed);
}
std::size_t entry_count() {
    std::shared_lock<std::shared_mutex> lk(g_mtx);
    return g_cache.size();
}
std::uint64_t total_evictions() {
    return g_evictions.load(std::memory_order_relaxed);
}

std::uintptr_t caller_rva(const AllocTrace* tr) {
    if (!tr || !tr->caller_rip || !g_module_base) return 0;
    return reinterpret_cast<std::uintptr_t>(tr->caller_rip) - g_module_base;
}

} // namespace fw::native::ni_alloc_tracker
