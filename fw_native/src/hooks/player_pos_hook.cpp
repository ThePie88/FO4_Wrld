#include "player_pos_hook.h"

#include <windows.h>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <system_error>
#include <thread>

#include "../log.h"
#include "../offsets.h"
#include "../net/client.h"
#include "../net/protocol.h"

namespace fw::hooks {

namespace {

constexpr DWORD POLL_INTERVAL_MS = 50;      // match Frida JS 20 Hz
constexpr DWORD LOG_THROTTLE_MS  = 2000;    // emit at most one INFO per 2s
constexpr float MIN_MOVE_UNITS   = 4.0f;    // ignore sub-unit jitter

std::atomic<bool> g_stop{false};
std::thread g_thread;

struct Vec3 { float x, y, z; };

bool float_finite_bounded(float v) {
    return std::isfinite(v) && std::fabs(v) < 1.0e7f;
}

// SEH-safe deref: returns fallback on access violation.
template <typename T>
T safe_read(const void* addr, T fallback) noexcept {
    if (!addr) return fallback;
    __try { return *reinterpret_cast<const T*>(addr); }
    __except (EXCEPTION_EXECUTE_HANDLER) { return fallback; }
}

void poll_loop(std::uintptr_t module_base) {
    auto* singleton_slot = reinterpret_cast<void**>(
        module_base + offsets::PLAYER_SINGLETON_RVA);

    Vec3 last{0, 0, 0};
    bool has_last = false;
    DWORD last_log_ms = 0;
    std::uint64_t reads_total = 0;
    std::uint64_t reads_valid = 0;

    while (!g_stop.load(std::memory_order_relaxed)) {
        Sleep(POLL_INTERVAL_MS);

        __try {
            void* player = safe_read<void*>(singleton_slot, nullptr);
            if (!player) continue;

            const auto* base = reinterpret_cast<const std::uint8_t*>(player);

            // formID must be 0x14 for PlayerCharacter — during main menu /
            // intro the struct can be pre-populated with garbage.
            const auto formid = safe_read<std::uint32_t>(
                base + offsets::FORMID_OFF, 0u);
            if (formid != offsets::PLAYER_FORMID) continue;

            // parentCell must be non-null — gate same as Frida era.
            const auto* cell = safe_read<void*>(
                base + offsets::PARENT_CELL_OFF, nullptr);
            if (!cell) continue;

            // v11 (B6 prologue): read parentCell.formID so receiver can
            // CULL the ghost when peers are in different cells. Cell is a
            // TESObjectCELL → inherits TESForm → formID at +0x14.
            const auto cell_form_id = safe_read<std::uint32_t>(
                reinterpret_cast<const std::uint8_t*>(cell) + offsets::FORMID_OFF,
                0u);

            const Vec3 pos{
                safe_read<float>(base + offsets::POS_OFF,     0.0f),
                safe_read<float>(base + offsets::POS_OFF + 4, 0.0f),
                safe_read<float>(base + offsets::POS_OFF + 8, 0.0f),
            };
            const Vec3 rot{
                safe_read<float>(base + offsets::ROT_OFF,     0.0f),
                safe_read<float>(base + offsets::ROT_OFF + 4, 0.0f),
                safe_read<float>(base + offsets::ROT_OFF + 8, 0.0f),
            };
            if (!float_finite_bounded(pos.x) ||
                !float_finite_bounded(pos.y) ||
                !float_finite_bounded(pos.z) ||
                !float_finite_bounded(rot.x) ||
                !float_finite_bounded(rot.y) ||
                !float_finite_bounded(rot.z)) {
                continue;
            }

            ++reads_total;
            ++reads_valid;

            // Push POS_STATE to the server every tick (no throttle). The
            // Python server already handles rate limiting; we stream at
            // 20 Hz just like the old Frida-era did. Logging stays throttled.
            {
                using namespace std::chrono;
                fw::net::PosStatePayload p{};
                p.x = pos.x; p.y = pos.y; p.z = pos.z;
                p.rx = rot.x; p.ry = rot.y; p.rz = rot.z;
                p.timestamp_ms = duration_cast<milliseconds>(
                    system_clock::now().time_since_epoch()).count();
                p.cell_id = cell_form_id;   // v11 — B6 prologue
                fw::net::client().enqueue_pos_state(p);
            }

            const DWORD now = GetTickCount();
            float dx = 0, dy = 0, dz = 0, dist = 0;
            if (has_last) {
                dx = pos.x - last.x;
                dy = pos.y - last.y;
                dz = pos.z - last.z;
                dist = std::sqrt(dx * dx + dy * dy + dz * dz);
            }

            const bool moved = (!has_last) || (dist >= MIN_MOVE_UNITS);
            const bool throttled_ok =
                (now - last_log_ms) >= LOG_THROTTLE_MS;

            if (moved && throttled_ok) {
                FW_LOG("[pos] pos=(%.1f, %.1f, %.1f) d=%.1f  reads=%llu",
                       pos.x, pos.y, pos.z, dist,
                       static_cast<unsigned long long>(reads_valid));
                last = pos;
                has_last = true;
                last_log_ms = now;
            } else if (!has_last) {
                last = pos;
                has_last = true;
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            // Rare — only happens if memory is unmapped between the
            // singleton slot check and the actual reads. Next iteration.
        }
    }

    FW_LOG("[pos] poll thread stopping (total_valid_reads=%llu)",
           static_cast<unsigned long long>(reads_valid));
}

} // namespace

bool start_player_pos_poll(std::uintptr_t module_base) {
    if (g_thread.joinable()) {
        FW_WRN("[pos] start called twice — ignoring");
        return true;
    }
    g_stop.store(false);
    try {
        g_thread = std::thread(poll_loop, module_base);
    } catch (const std::system_error& e) {
        FW_ERR("[pos] failed to spawn poll thread: %s", e.what());
        return false;
    }
    FW_LOG("[pos] poll thread started at %u ms interval (throttled INFO @ %u ms, min move %.1f u)",
           POLL_INTERVAL_MS, LOG_THROTTLE_MS, MIN_MOVE_UNITS);
    return true;
}

void stop_player_pos_poll() {
    g_stop.store(true);
    if (g_thread.joinable()) {
        g_thread.join();
    }
}

} // namespace fw::hooks
