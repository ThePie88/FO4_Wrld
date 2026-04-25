#include "log.h"

#include <windows.h>
#include <atomic>
#include <cstdarg>
#include <cstdio>
#include <mutex>

namespace fw::log {

namespace {
HANDLE g_file = INVALID_HANDLE_VALUE;
std::mutex g_mutex;
std::atomic<Level> g_level{Level::Info};

const char* level_tag(Level lvl) {
    switch (lvl) {
    case Level::Error: return "ERR";
    case Level::Warn:  return "WRN";
    case Level::Info:  return "INF";
    case Level::Debug: return "DBG";
    }
    return "???";
}

void write_locked(Level lvl, std::string_view line) {
    // Timestamp prefix: [HH:MM:SS.mmm][TAG]
    SYSTEMTIME st;
    GetLocalTime(&st);
    char prefix[48];
    const int n = std::snprintf(
        prefix, sizeof(prefix), "[%02u:%02u:%02u.%03u][%s] ",
        st.wHour, st.wMinute, st.wSecond, st.wMilliseconds, level_tag(lvl));

    // File path
    if (g_file != INVALID_HANDLE_VALUE) {
        DWORD written = 0;
        if (n > 0) {
            WriteFile(g_file, prefix, static_cast<DWORD>(n), &written, nullptr);
        }
        WriteFile(g_file, line.data(), static_cast<DWORD>(line.size()), &written, nullptr);
        const char nl = '\n';
        WriteFile(g_file, &nl, 1, &written, nullptr);
        FlushFileBuffers(g_file);
    }

    // Debugger mirror — shows in Visual Studio Output window and DebugView.
    // Building one wide string; fine since log path is not hot.
    std::string dbg;
    dbg.reserve(static_cast<size_t>(n) + line.size() + 10);
    dbg.append("[fw_native] ");
    dbg.append(prefix, prefix + (n > 0 ? n : 0));
    dbg.append(line);
    dbg.push_back('\n');
    OutputDebugStringA(dbg.c_str());
}
} // namespace

void init(const std::wstring& path, Level level) {
    std::lock_guard lk(g_mutex);
    g_level.store(level, std::memory_order_relaxed);

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
