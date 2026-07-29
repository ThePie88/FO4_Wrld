#include "log.h"

#include <windows.h>
#include <atomic>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <mutex>

namespace fw::log {

namespace {
HANDLE g_file = INVALID_HANDLE_VALUE;
std::mutex g_mutex;
std::atomic<Level> g_level{Level::Info};
// Build 68.3 — sampled once at init(): with no debugger attached the
// OutputDebugString mirror is a pure kernel round-trip nobody reads.
bool g_debugger_present = false;

const char* level_tag(Level lvl) {
    switch (lvl) {
    case Level::Error: return "ERR";
    case Level::Warn:  return "WRN";
    case Level::Info:  return "INF";
    case Level::Debug: return "DBG";
    }
    return "???";
}

// Build 68.3 — THE LOG PATH WAS A FRAME-KILLER.
//
// Measured on client B (2026-07-29 session): 26,054 lines in 168 s = 155
// lines/sec, sustained, emitted from the GAME MAIN THREAD. The old body did,
// per line: 3x WriteFile + FlushFileBuffers + OutputDebugStringA, all under a
// global mutex. FlushFileBuffers is a SYNCHRONOUS disk sync (0.1-1 ms+ each,
// worse on a spinning disk / under AV) and OutputDebugStringA is a kernel
// round-trip that also stalls if any debugger/DebugView is listening. At 155
// lines/sec that is ~15-150 ms of blocking I/O per SECOND of gameplay, and a
// burst (e.g. one drain logging 17 entries) lands entirely inside a single
// 16.6 ms frame → visible stutter. That is the "Codsworth lags on B" report.
//
// Now: format once into a stack buffer, ONE WriteFile, and:
//   - flush ONLY on Warn/Error, so a crash still has its context on disk
//     (the crash-veh / watchdog lines are ERR, so forensics is unaffected);
//   - mirror to OutputDebugString ONLY when a debugger is actually attached
//     (checked once at init — no debugger, no kernel round-trip).
// The OS write-behind cache handles the rest; a hard process kill can lose at
// most the last unflushed INF/DBG lines, which is an acceptable trade for a
// stable frame time (and ERR/WRN, the ones that matter, are always flushed).
void write_locked(Level lvl, std::string_view line) {
    // Timestamp prefix: [HH:MM:SS.mmm][TAG]
    SYSTEMTIME st;
    GetLocalTime(&st);
    char buf[1152];
    const int n = std::snprintf(
        buf, sizeof(buf), "[%02u:%02u:%02u.%03u][%s] ",
        st.wHour, st.wMinute, st.wSecond, st.wMilliseconds, level_tag(lvl));
    const size_t plen = (n > 0 && static_cast<size_t>(n) < sizeof(buf))
        ? static_cast<size_t>(n) : 0;
    size_t total = plen;
    const size_t copy = (line.size() < sizeof(buf) - total - 2)
        ? line.size() : (sizeof(buf) - total - 2);
    std::memcpy(buf + total, line.data(), copy);
    total += copy;
    buf[total++] = '\n';

    if (g_file != INVALID_HANDLE_VALUE) {
        DWORD written = 0;
        WriteFile(g_file, buf, static_cast<DWORD>(total), &written, nullptr);
        // Durability only where it matters: a crash must not lose its own
        // ERR/WRN context. INF/DBG ride the OS write-behind cache.
        if (static_cast<int>(lvl) <= static_cast<int>(Level::Warn)) {
            FlushFileBuffers(g_file);
        }
    }

    // Debugger mirror — only worth its kernel round-trip when someone listens.
    if (g_debugger_present) {
        buf[total] = '\0';
        OutputDebugStringA(buf);
    }
}
} // namespace

void init(const std::wstring& path, Level level) {
    std::lock_guard lk(g_mutex);
    g_level.store(level, std::memory_order_relaxed);
    g_debugger_present = (IsDebuggerPresent() != FALSE);   // Build 68.3

    if (g_file != INVALID_HANDLE_VALUE) {
        CloseHandle(g_file);
        g_file = INVALID_HANDLE_VALUE;
    }
    g_file = CreateFileW(path.c_str(),
        FILE_APPEND_DATA,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
    if (g_file == INVALID_HANDLE_VALUE) return;

    // Session marker so `tail -f` reveals when a new process started.
    const char banner[] = "\n--- session start ---\n";
    DWORD written = 0;
    WriteFile(g_file, banner, sizeof(banner) - 1, &written, nullptr);
    FlushFileBuffers(g_file);
}

void close() {
    std::lock_guard lk(g_mutex);
    if (g_file != INVALID_HANDLE_VALUE) {
        CloseHandle(g_file);
        g_file = INVALID_HANDLE_VALUE;
    }
}

void set_level(Level level) {
    g_level.store(level, std::memory_order_relaxed);
}

Level get_level() {
    return g_level.load(std::memory_order_relaxed);
}

void writef(Level level, const char* fmt, ...) {
    if (static_cast<int>(level) > static_cast<int>(g_level.load(std::memory_order_relaxed))) {
        return;  // filtered out
    }

    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    const int n = std::vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (n <= 0) return;

    const size_t len = (static_cast<size_t>(n) < sizeof(buf))
        ? static_cast<size_t>(n)
        : sizeof(buf) - 1;

    std::lock_guard lk(g_mutex);
    write_locked(level, std::string_view(buf, len));
}

} // namespace fw::log
