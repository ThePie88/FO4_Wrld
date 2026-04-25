// Thread-safe append-only log with severity filtering. Not a hot path — we
// log bootstrapping events, not per-frame telemetry. Flushes on every write
// so nothing is lost if the game crashes with us inside.
#pragma once

#include <string_view>
#include <string>

namespace fw::log {

enum class Level : int {
    Error = 0,
    Warn  = 1,
    Info  = 2,
    Debug = 3,
};

// Opens the log file at `path` (append) and sets the minimum level that
// will be written. Messages below `level` are dropped silently.
// Also mirrors every line to OutputDebugString so an attached debugger
// sees them, with or without the file.
void init(const std::wstring& path, Level level = Level::Info);

void close();
void set_level(Level level);
Level get_level();

// printf-style front-door. Truncates to 1024 bytes per line.
void writef(Level level, const char* fmt, ...);

} // namespace fw::log

// Convenience macros — the level-gated version avoids format cost when the
// message would be dropped anyway (useful for FW_DBG in hot code).
#define FW_ERR(fmt, ...) ::fw::log::writef(::fw::log::Level::Error, (fmt), ##__VA_ARGS__)
#define FW_WRN(fmt, ...) ::fw::log::writef(::fw::log::Level::Warn,  (fmt), ##__VA_ARGS__)
#define FW_LOG(fmt, ...) ::fw::log::writef(::fw::log::Level::Info,  (fmt), ##__VA_ARGS__)
#define FW_DBG(fmt, ...) \
    do { if (::fw::log::get_level() >= ::fw::log::Level::Debug) \
         ::fw::log::writef(::fw::log::Level::Debug, (fmt), ##__VA_ARGS__); } while(0)
