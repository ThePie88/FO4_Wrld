// L5 detour (2026-10-18): leaving an interior took 90-112 s in VANILLA on a
// 7900X / NVMe / 7900 XT while entering took 5 s, with the whole machine
// idle (RESEARCH_interior_loads.md sections 8-12, tools/fo4_thread_sampler.py).
//
// WHAT THE SAMPLER SAW. The teleport job runs on a job-system worker. Its
// exterior load (TES::LoadExterior sub_1402D0AE0) ends in sub_1417AF2F0, the
// loader flush: "wait until every queued load up to this priority is done",
// a loop of kick + Sleep(1) + post-process (sub_1417AF000, slices of
// iPostProcessMillisecondsLoadingQueuedPriority = 20 ms under the global
// try-lock unk_14355EB40). The queue held the same ~24 requests,
// BGSCombinedCellGeometryDB::LoadTask (the precombined geometry of the
// exterior cells; interiors have none, hence their 5 s), going round nine
// million times a second. The steps that complete them (the stream
// completion sub_140484120 and the task run step sub_140483760, which
// hands the NIFs to the unpacker thread) run only on the loader's OWNER
// thread (loader+5280, the main thread); off it they defer. The main
// thread, in the load's message pump, still runs frames and calls the
// post-process once per frame, but wins the try-lock against the worker's
// 20 ms slices by luck alone: one task every 1-4 s on the slow runs
// (90-112 s), many more on a lucky one (5 s). Precombined geometry off
// (bUseCombinedObjects=0): 8 s, always. The 1 ms slice (INI): 8-23 s.
//
// WHAT DID NOT WORK (20:10, flush #8: 139 s). Making the flushing worker
// the owner for the flush's duration: the owner-only steps are not reached
// from the worker at all; they ran 25 times on the main thread, which had
// just lost its ownership, and deferred every one of them. Kept behind
// loader_flush_owner_spoof, default OFF.
//
// THE FIX (loader_owner_priority, default ON): the owner thread gets the
// post-process lock when it asks for it. Our detour of sub_1417AF000 on
// the owner thread, during a flush, raises a "wanted" flag, waits for the
// lock to free (at most 25 ms: the worker's slice ends by then), runs the
// post-process, lowers the flag; the same detour on any other thread
// returns 1 ("busy") without touching the loader while the flag is up.
// Nothing else changes: the same engine code runs on the same threads, the
// owner just stops losing the lottery.
//
// WHAT IS LOGGED. One `[loader] flush` line per outer flush that took 50 ms
// or more (or the first 10): priority, thread, owner, the pending count
// before and after, the ring traffic, how many post-process calls each side
// made and how many the worker yielded, and the time. One `[loader]
// precombined task run` line per run step (one per exterior cell): thread,
// owner, the task's state, counts and the outcome. That is the proof the
// fix works or the trail if it does not.
#include "loader_flush_hook.h"

#include <windows.h>
#include <atomic>
#include <cstdint>

#include "../config.h"
#include "../hook_manager.h"
#include "../log.h"
#include "../offsets.h"

namespace fw::hooks {

namespace {

using FlushFn   = void (__fastcall*)(void* loader, unsigned int priority);
using PostFn    = std::int64_t (__fastcall*)(void* loader);
using TaskRunFn = char (__fastcall*)(void* task);

FlushFn        g_orig_flush    = nullptr;
PostFn         g_orig_post     = nullptr;
TaskRunFn      g_orig_task_run = nullptr;
std::uintptr_t g_base          = 0;
bool           g_spoof         = false;
bool           g_priority      = true;

std::atomic<bool>          g_owner_wants{false};   // the owner thread is waiting for the post-process lock
std::atomic<std::uint32_t> g_run_owner{0};         // precombined task run steps on the owner thread
std::atomic<std::uint32_t> g_run_other{0};         // ... on any other thread (they defer)
std::atomic<std::uint32_t> g_post_owner{0};        // post-process calls on the owner thread during a flush
std::atomic<std::uint32_t> g_post_owner_free{0};   // ... that found the lock free
std::atomic<std::uint32_t> g_post_other{0};        // post-process calls off the owner thread during a flush
std::atomic<std::uint32_t> g_post_yield{0};        // ... that yielded to the owner
std::atomic<std::uint32_t> g_flushes{0};
std::atomic<std::uint32_t> g_flush_depth{0};       // flushes in progress, any thread

thread_local int t_depth = 0;   // nested flushes on one thread: the outer one logs

std::uint32_t seh_read_u32(std::uintptr_t addr) noexcept {
    __try {
        return *reinterpret_cast<volatile std::uint32_t*>(addr);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
}

bool seh_write_u32(std::uintptr_t addr, std::uint32_t v) noexcept {
    __try {
        *reinterpret_cast<volatile std::uint32_t*>(addr) = v;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

std::uintptr_t seh_loader() noexcept {
    __try {
        return *reinterpret_cast<std::uintptr_t*>(g_base + offsets::LOADER_SINGLETON_RVA);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
}

std::uint32_t lock_word() noexcept {
    return seh_read_u32(g_base + offsets::LOADER_POST_PROCESS_LOCK_RVA);
}

// POD on purpose: run_flush keeps the restoration in a __finally, and a
// function with __try may hold no object that needs unwinding.
struct FlushFrame {
    std::uintptr_t loader;
    std::uint32_t  owner;
    std::uint32_t  tid;
    bool           spoofed;
};

void run_flush(const FlushFrame* f, void* loader, unsigned int prio) noexcept {
    __try {
        g_orig_flush(loader, prio);
    } __finally {
        if (f->spoofed) seh_write_u32(f->loader + offsets::LOADER_OWNER_TID_OFF, f->owner);
        --t_depth;
        g_flush_depth.fetch_sub(1, std::memory_order_relaxed);
    }
}

void __fastcall detour_flush(void* loader, unsigned int prio) {
    if (!g_orig_flush) return;
    FlushFrame f{};
    f.loader = reinterpret_cast<std::uintptr_t>(loader);
    f.tid    = GetCurrentThreadId();
    f.owner  = loader ? seh_read_u32(f.loader + offsets::LOADER_OWNER_TID_OFF) : 0;
    const bool outer = (t_depth == 0);
    ++t_depth;
    g_flush_depth.fetch_add(1, std::memory_order_relaxed);
    f.spoofed = g_spoof && outer && loader && f.owner != 0 && f.owner != f.tid &&
                seh_write_u32(f.loader + offsets::LOADER_OWNER_TID_OFF, f.tid);
    const std::uint32_t pend0 = loader ? seh_read_u32(f.loader + offsets::LOADER_PENDING_OFF) : 0;
    const std::uint32_t ring0 = loader ? seh_read_u32(f.loader + offsets::LOADER_RING_OFF +
                                                      offsets::LOADER_RING_CONSUME_OFF) : 0;
    if (outer) {
        g_run_owner.store(0, std::memory_order_relaxed);
        g_run_other.store(0, std::memory_order_relaxed);
        g_post_owner.store(0, std::memory_order_relaxed);
        g_post_owner_free.store(0, std::memory_order_relaxed);
        g_post_other.store(0, std::memory_order_relaxed);
        g_post_yield.store(0, std::memory_order_relaxed);
    }
    const std::uint64_t t0 = GetTickCount64();
    run_flush(&f, loader, prio);   // restores the owner id and the depths itself
    if (!outer) return;
    const std::uint64_t ms    = GetTickCount64() - t0;
    const std::uint32_t pend1 = loader ? seh_read_u32(f.loader + offsets::LOADER_PENDING_OFF) : 0;
    const std::uint32_t ring1 = loader ? seh_read_u32(f.loader + offsets::LOADER_RING_OFF +
                                                      offsets::LOADER_RING_CONSUME_OFF) : 0;
    const std::uint32_t n = g_flushes.fetch_add(1, std::memory_order_relaxed) + 1;
    if (f.spoofed || ms >= 50 || n <= 10) {
        FW_LOG("[loader] flush #%u prio %u on tid %lu (owner %lu%s): pending %u -> %u, ring +%u, "
               "precombined task runs on owner %u / elsewhere %u, post-process calls owner %u (lock free %u) / "
               "others %u (yielded %u), %llu ms",
               n, prio, static_cast<unsigned long>(f.tid), static_cast<unsigned long>(f.owner),
               f.spoofed ? ", spoofed to this thread" : "", pend0, pend1, ring1 - ring0,
               g_run_owner.load(std::memory_order_relaxed), g_run_other.load(std::memory_order_relaxed),
               g_post_owner.load(std::memory_order_relaxed), g_post_owner_free.load(std::memory_order_relaxed),
               g_post_other.load(std::memory_order_relaxed), g_post_yield.load(std::memory_order_relaxed),
               static_cast<unsigned long long>(ms));
    }
}

std::int64_t __fastcall detour_post(void* loader) {
    if (!g_orig_post) return 1;
    const std::uintptr_t L = reinterpret_cast<std::uintptr_t>(loader);
    const std::uint32_t tid = GetCurrentThreadId();
    const std::uint32_t owner = loader ? seh_read_u32(L + offsets::LOADER_OWNER_TID_OFF) : 0;
    const bool flushing = g_flush_depth.load(std::memory_order_relaxed) > 0;
    if (!flushing) return g_orig_post(loader);
    if (owner != 0 && tid == owner) {
        g_post_owner.fetch_add(1, std::memory_order_relaxed);
        if (g_priority) {
            g_owner_wants.store(true, std::memory_order_release);
            const std::uint64_t t0 = GetTickCount64();
            while (lock_word() != 0 && GetTickCount64() - t0 < 25) Sleep(0);
        }
        if (lock_word() == 0) g_post_owner_free.fetch_add(1, std::memory_order_relaxed);
        const std::int64_t r = g_orig_post(loader);
        if (g_priority) g_owner_wants.store(false, std::memory_order_release);
        return r;
    }
    g_post_other.fetch_add(1, std::memory_order_relaxed);
    if (g_priority && g_owner_wants.load(std::memory_order_acquire)) {
        g_post_yield.fetch_add(1, std::memory_order_relaxed);
        Sleep(0);
        return 1;   // "busy", the engine's own answer when the lock is taken
    }
    return g_orig_post(loader);
}

char __fastcall detour_task_run(void* task) {
    const std::uintptr_t loader = seh_loader();
    const std::uint32_t owner = loader ? seh_read_u32(loader + offsets::LOADER_OWNER_TID_OFF) : 0;
    const std::uint32_t tid = GetCurrentThreadId();
    const bool on_owner = (owner != 0 && owner == tid);
    if (on_owner) g_run_owner.fetch_add(1, std::memory_order_relaxed);
    else          g_run_other.fetch_add(1, std::memory_order_relaxed);
    const std::uintptr_t T = reinterpret_cast<std::uintptr_t>(task);
    const std::uint32_t state0 = seh_read_u32(T + 52), left0 = seh_read_u32(T + 120),
                        count = seh_read_u32(T + 192), unpack0 = seh_read_u32(T + 300);
    const char r = g_orig_task_run ? g_orig_task_run(task) : 0;
    FW_LOG("[loader] precombined task run on tid %lu (%s): state %u -> %u, NIFs left %u -> %u of %u, "
           "unpacking %u -> %u, returned %d",
           static_cast<unsigned long>(tid), on_owner ? "the owner" : "NOT the owner", state0,
           seh_read_u32(T + 52), left0, seh_read_u32(T + 120), count, unpack0, seh_read_u32(T + 300), int(r));
    return r;
}

} // namespace

bool loader_flush_active() noexcept {
    return g_flush_depth.load(std::memory_order_relaxed) > 0;
}

bool install_loader_flush_hook(std::uintptr_t module_base, const fw::config::Settings& cfg) {
    g_base     = module_base;
    g_spoof    = cfg.loader_flush_owner_spoof;
    g_priority = cfg.loader_owner_priority;
    void* flush = reinterpret_cast<void*>(module_base + offsets::LOADER_FLUSH_RVA);
    void* post  = reinterpret_cast<void*>(module_base + offsets::LOADER_POST_PROCESS_RVA);
    void* run   = reinterpret_cast<void*>(module_base + offsets::COMBINED_GEOMETRY_TASK_RUN_RVA);
    const bool ok_flush = fw::hooks::install(flush, reinterpret_cast<void*>(&detour_flush),
                                             reinterpret_cast<void**>(&g_orig_flush));
    const bool ok_post = fw::hooks::install(post, reinterpret_cast<void*>(&detour_post),
                                            reinterpret_cast<void**>(&g_orig_post));
    const bool ok_run = fw::hooks::install(run, reinterpret_cast<void*>(&detour_task_run),
                                           reinterpret_cast<void**>(&g_orig_task_run));
    if (!ok_flush) g_orig_flush = nullptr;
    if (!ok_post) g_orig_post = nullptr;
    if (!ok_run) g_orig_task_run = nullptr;
    FW_LOG("[loader] flush hook %s (sub_1417AF2F0), post-process hook %s (sub_1417AF000), precombined "
           "task-run trace %s (sub_140483760); owner priority on the post-process lock: %s; owner spoof: %s",
           ok_flush ? "installed" : "FAILED", ok_post ? "installed" : "FAILED", ok_run ? "installed" : "FAILED",
           (ok_post && g_priority) ? "ON" : "off", g_spoof ? "ON" : "off");
    return ok_flush && ok_post;
}

} // namespace fw::hooks
