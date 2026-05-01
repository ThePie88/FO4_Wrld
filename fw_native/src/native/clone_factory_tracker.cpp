// M9 wedge 4 — clone factory tracker. See header for design.

#include "clone_factory_tracker.h"

#include <windows.h>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <shared_mutex>
#include <unordered_map>

#include "../hook_manager.h"
#include "../log.h"

namespace fw::native::clone_factory_tracker {

namespace {

// sub_1416D99E0 — _BYTE* __fastcall sub_1416D99E0(__int64 a1, __int64 a2)
constexpr std::uintptr_t CLONE_FACTORY_RVA = 0x0016D99E0;

using CloneFactoryFn = void* (__fastcall*)(void*, void*);
CloneFactoryFn g_orig = nullptr;

std::shared_mutex                                    g_mtx;
std::unordered_map<const void*, CloneTrace>          g_cache;
std::atomic<std::uint64_t>                           g_invocations{0};
std::atomic<bool>                                    g_installed{false};

constexpr std::size_t MAX_ENTRIES = 16384;

std::uint64_t now_ms() {
    using namespace std::chrono;
    return duration_cast<milliseconds>(
        steady_clock::now().time_since_epoch()).count();
}

// SEH-safe qword read.
std::uint64_t seh_read_qw(const void* p) {
    if (!p) return 0;
    __try {
        return *reinterpret_cast<const std::uint64_t*>(p);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0xDEADBEEFDEADBEEFULL;
    }
}

// SEH-safe pointer-at-offset read. Returns nullptr on AV. POD-only
// signature so callers with C++ unwind in scope can use it safely
// (avoids C2712 on detour functions that hold std::unique_lock).
const void* seh_read_ptr_at(const void* base, std::size_t off) {
    if (!base) return nullptr;
    __try {
        return *reinterpret_cast<const void* const*>(
            reinterpret_cast<const char*>(base) + off);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return nullptr;
    }
}

// Dump up to N bytes (rounded to qword) at addr to a single FW_LOG line.
// SEH-cages each qword so a partial corruption produces logged 0xDEAD...
// markers instead of crashing.
void dump_hex_qwords(const char* tag, const void* addr,
                     std::size_t qword_count) {
    if (!addr) {
        FW_LOG("%s addr=NULL", tag);
        return;
    }
    char buf[1024];
    int w = std::snprintf(buf, sizeof(buf), "%s addr=%p", tag, addr);
    for (std::size_t i = 0; i < qword_count && w < (int)sizeof(buf) - 24; ++i) {
        const std::uint8_t* off_addr =
            reinterpret_cast<const std::uint8_t*>(addr) + i * 8;
        std::uint64_t qw = seh_read_qw(off_addr);
        w += std::snprintf(buf + w, sizeof(buf) - w,
                            " +0x%02zX=0x%016llX",
                            i * 8, static_cast<unsigned long long>(qw));
    }
    FW_LOG("%s", buf);
}

void* __fastcall detour_clone_factory(void* a1, void* a2) {
    const std::uint64_t n =
        g_invocations.fetch_add(1, std::memory_order_relaxed) + 1;

    // Diagnostic: dump source `a1` header (0x40 bytes) AND the
    // mysterious struct at *(a1 + 0x148). Only for first 30 invocations
    // to avoid spam. This data tells us the actual layout of the
    // weapon-template's vertex/index data store.
    if (n <= 30) {
        dump_hex_qwords("[clone-trk] a1.head[0..0x40]", a1, 8);

        const void* sub = seh_read_ptr_at(a1, 0x148);
        if (sub) {
            dump_hex_qwords("[clone-trk] a1+0x148.deref[0..0x60]",
                             sub, 12);
        } else {
            FW_LOG("[clone-trk] #%llu a1+0x148 NULL or AV",
                   static_cast<unsigned long long>(n));
        }
        FW_LOG("[clone-trk] #%llu pre-chain a1=%p a2=%p",
               static_cast<unsigned long long>(n), a1, a2);
    }

    void* clone = g_orig(a1, a2);

    // Cache the clone→source mapping for later walker queries.
    if (clone && a1) {
        std::unique_lock<std::shared_mutex> lk(g_mtx);
        if (g_cache.size() >= MAX_ENTRIES) {
            g_cache.clear();
            FW_WRN("[clone-trk] cap reached, cleared");
        }
        g_cache[clone] = CloneTrace{ a1, now_ms() };
    }

    if (n <= 30) {
        FW_LOG("[clone-trk] #%llu post-chain clone=%p (source a1=%p)",
               static_cast<unsigned long long>(n), clone, a1);
    } else if ((n % 256) == 0) {
        FW_DBG("[clone-trk] #%llu clone=%p source=%p (heartbeat)",
               static_cast<unsigned long long>(n), clone, a1);
    }
    return clone;
}

} // namespace

bool install(std::uintptr_t module_base) {
    if (g_installed.load(std::memory_order_acquire)) return true;
    if (!module_base) {
        FW_ERR("[clone-trk] install: module_base=0");
        return false;
    }
    void* target = reinterpret_cast<void*>(module_base + CLONE_FACTORY_RVA);
    const bool ok = fw::hooks::install(
        target,
        reinterpret_cast<void*>(&detour_clone_factory),
        reinterpret_cast<void**>(&g_orig));
    if (!ok) {
        FW_ERR("[clone-trk] hook install FAILED on target=%p RVA=0x%llX",
               target,
               static_cast<unsigned long long>(CLONE_FACTORY_RVA));
        return false;
    }
    g_installed.store(true, std::memory_order_release);
    FW_LOG("[clone-trk] installed: detour on BSTriShape clone factory "
           "(target=%p RVA=0x%llX sub_1416D99E0)",
           target,
           static_cast<unsigned long long>(CLONE_FACTORY_RVA));
    return true;
}

const CloneTrace* lookup(const void* clone) {
    if (!clone) return nullptr;
    std::shared_lock<std::shared_mutex> lk(g_mtx);
    auto it = g_cache.find(clone);
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

} // namespace fw::native::clone_factory_tracker
