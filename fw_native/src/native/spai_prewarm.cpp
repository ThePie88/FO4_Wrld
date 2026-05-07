// SPAI Tier 1 — see spai_prewarm.h for design.

#include "spai_prewarm.h"

#include <windows.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <fstream>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "../log.h"
#include "../main_thread_dispatch.h"  // FW_MSG_SPAI_PREWARM, get_target_hwnd
#include "scene_inject.h"             // spai_force_load_path

namespace fw::native::spai {

namespace {

// The catalog. Populated by load_catalog, drained by on_prewarm_message
// via a monotonically-advancing cursor. We keep it as a simple vector
// of std::string — the worker only reads, the main thread only reads
// (the cursor is the synchronization point), so no mutex needed once
// load_catalog returns and the catalog is published. We do guard
// load_catalog itself so that a (theoretical) re-load doesn't tear up
// readers — it shouldn't normally race because load_catalog is called
// once at DLL init before arm_prewarm.
std::mutex                g_catalog_mtx;
std::vector<std::string>  g_paths;            // guarded by g_catalog_mtx
std::atomic<std::size_t>  g_cursor{0};         // monotonic — main thread

// Counters for the final summary log.
std::atomic<std::uint32_t> g_loads_attempted{0};
std::atomic<std::uint32_t> g_loads_succeeded{0};

// One-shot guard: arm_prewarm must run at most once per DLL load.
std::atomic<bool>          g_armed{false};
std::atomic<bool>          g_summary_logged{false};

// Stamps for the summary-log timing.
std::chrono::steady_clock::time_point g_prewarm_started_at{};

// Per-thread guard: set true around spai_force_load_path so the path
// cache hook's record_loaded_path can ignore prewarm-driven loads. See
// in_prewarm_load() in the header for full rationale.
thread_local bool g_tls_in_prewarm = false;

void prewarm_worker(unsigned int delay_ms, unsigned int throttle_ms) {
    Sleep(delay_ms);

    const std::size_t total = catalog_size();
    if (total == 0) {
        FW_WRN("[spai] worker: catalog empty — nothing to prewarm");
        return;
    }

    g_prewarm_started_at = std::chrono::steady_clock::now();
    FW_LOG("[spai] worker: starting prewarm of %zu paths "
           "(throttle %u ms ≈ %u s total)",
           total, throttle_ms,
           static_cast<unsigned>((total * throttle_ms) / 1000));

    // One PostMessage per path. Each one wakes the main thread to call
    // on_prewarm_message which pops one entry. We stop sending once
    // the cursor reaches `total` even if PostMessage failures lost
    // some — the cursor advance is what's authoritative.
    for (std::size_t i = 0; i < total; ++i) {
        const HWND h = fw::dispatch::get_target_hwnd();
        if (h) {
            // Best-effort post — failures are logged but not retried.
            // The drain handler is idempotent past the cursor end.
            if (!PostMessageW(h, fw::dispatch::FW_MSG_SPAI_PREWARM,
                              0, 0)) {
                FW_DBG("[spai] PostMessage(SPAI_PREWARM) #%zu err=%lu",
                       i, GetLastError());
            }
        } else {
            // HWND not yet set: WndProc subclass not installed. Try
            // again after a short backoff. Don't burn the CPU.
            FW_DBG("[spai] worker: HWND not ready @ %zu — backing off",
                   i);
            Sleep(500);
            // Don't increment i — re-attempt this slot.
            --i;
            continue;
        }
        if (throttle_ms) Sleep(throttle_ms);
    }

    FW_LOG("[spai] worker: finished posting %zu prewarm messages "
           "(handler will log final summary)",
           total);
}

}  // namespace

bool load_catalog(const std::filesystem::path& manifest_path) {
    std::ifstream in(manifest_path);
    if (!in) {
        FW_WRN("[spai] catalog: open FAILED '%s'",
               manifest_path.string().c_str());
        return false;
    }

    std::vector<std::string> tmp;
    tmp.reserve(2048);

    std::string line;
    while (std::getline(in, line)) {
        // Trim trailing '\r' (manifest is LF but if someone hand-edits on
        // Windows we tolerate CRLF).
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty()) continue;
        if (line.front() == '#') continue;
        tmp.emplace_back(std::move(line));
        line.clear();
    }

    const std::size_t n = tmp.size();
    if (n == 0) {
        FW_WRN("[spai] catalog: '%s' parsed but empty",
               manifest_path.string().c_str());
        return false;
    }

    {
        std::lock_guard lk(g_catalog_mtx);
        g_paths = std::move(tmp);
        g_cursor.store(0, std::memory_order_release);
        g_loads_attempted.store(0, std::memory_order_relaxed);
        g_loads_succeeded.store(0, std::memory_order_relaxed);
        g_summary_logged.store(false, std::memory_order_relaxed);
    }

    FW_LOG("[spai] catalog: loaded %zu paths from '%s'",
           n, manifest_path.string().c_str());
    return true;
}

std::size_t catalog_size() {
    std::lock_guard lk(g_catalog_mtx);
    return g_paths.size();
}

void arm_prewarm(unsigned int delay_ms, unsigned int throttle_ms) {
    bool expected = false;
    if (!g_armed.compare_exchange_strong(expected, true)) {
        FW_DBG("[spai] arm_prewarm: already armed — ignoring");
        return;
    }

    if (catalog_size() == 0) {
        FW_WRN("[spai] arm_prewarm: catalog empty — call load_catalog first");
        // Leave g_armed=true so a no-catalog state stays clearly broken
        // rather than half-firing later.
        return;
    }

    std::thread(&prewarm_worker, delay_ms, throttle_ms).detach();
    FW_LOG("[spai] arm_prewarm: armed (delay=%u ms, throttle=%u ms, "
           "total=%zu paths)",
           delay_ms, throttle_ms, catalog_size());
}

void on_prewarm_message() {
    // Snapshot total under the catalog lock so a hot-reload (unlikely
    // but possible) can't trip us. Reading g_paths[idx] outside the
    // lock is safe as long as load_catalog isn't running concurrently
    // — which it shouldn't be after init.
    std::size_t total = 0;
    const char* path = nullptr;
    {
        std::lock_guard lk(g_catalog_mtx);
        total = g_paths.size();
        const std::size_t idx =
            g_cursor.fetch_add(1, std::memory_order_acq_rel);
        if (idx >= total) {
            // Past end. If we haven't logged the summary yet, do it now.
            if (!g_summary_logged.exchange(true,
                                            std::memory_order_acq_rel)) {
                const auto elapsed_ms =
                    std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::steady_clock::now() -
                        g_prewarm_started_at)
                        .count();
                const auto attempted =
                    g_loads_attempted.load(std::memory_order_acquire);
                const auto succeeded =
                    g_loads_succeeded.load(std::memory_order_acquire);
                FW_LOG("[spai] prewarm DONE: total=%zu attempted=%u "
                       "succeeded=%u (%.1f%%) elapsed=%lld ms",
                       total, attempted, succeeded,
                       attempted ? (100.0 * succeeded / attempted) : 0.0,
                       static_cast<long long>(elapsed_ms));
            }
            return;
        }
        path = g_paths[idx].c_str();
    }

    g_loads_attempted.fetch_add(1, std::memory_order_relaxed);
    // Guard: tell record_loaded_path (the path-cache hook callback) to
    // ignore the engine's nif_load_by_path invocation we're about to
    // trigger. Without this, prewarm loads land in the per-equip path
    // capture window and pollute the wire blob with random weapon NIFs.
    g_tls_in_prewarm = true;
    const bool ok = fw::native::spai_force_load_path(path);
    g_tls_in_prewarm = false;
    if (ok) {
        const auto succ =
            g_loads_succeeded.fetch_add(1, std::memory_order_relaxed) + 1;
        // Periodic progress beacon every 100 loads — keeps the log
        // useful without spamming on every single path.
        if (succ % 100 == 0) {
            const auto attempted =
                g_loads_attempted.load(std::memory_order_relaxed);
            FW_LOG("[spai] prewarm progress: %u attempted, %u succeeded "
                   "of %zu (cursor=%zu)",
                   attempted, succ, total,
                   g_cursor.load(std::memory_order_relaxed));
        }
    }
}

bool in_prewarm_load() {
    return g_tls_in_prewarm;
}

}  // namespace fw::native::spai
