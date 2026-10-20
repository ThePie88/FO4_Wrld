#include "../game_build.h"
#include "death.h"

#include <windows.h>

#include <array>
#include <atomic>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <string>
#include <thread>

#include "../config.h"
#include "../engine/engine_calls.h"       // get_local_player, player_fast_travel_to, actor_teleport_handoff, set_actor_ghost
#include "../hooks/npc_ai_suppress.h"     // local_player_hp_sum, note_local_player_respawned
#include "../hooks/equip_announce.h"      // the outfit across the respawn (stage 3d)
#include "../hooks/npc_hp_probe.h"        // heal_local_player (stage 3d)
#include "../hooks/pa_pipeline_trace.h"   // forget_player_process
#include "../log.h"
#include "../native/scene_inject.h"       // ghost_scene_settled
#include "../net/client.h"
#include "../net/protocol.h"
#include "../offsets.h"
#include "checkpoint.h"                   // fetch_from_custody (stage 3d)
#include "custody.h"                      // available (stage 3d)
#include "inventory_capture.h"            // last().in_power_armor
#include "inventory_restore.h"            // L5 realtime R2: the record comes back after the reload
#include "lifecycle.h"                    // requeue_death_reload, loads_requested, exiting, load_in_flight

namespace fw::persist::death {

namespace {

// Actor::Resurrect(resetInventory, attach3D) is vtable slot 0xCC (the
// engine's own callers, e.g. funcs_0190.md:517, call it as (this, 1,
// attach)); PlayerCharacter's override takes only `this`.
constexpr std::size_t    kResurrectSlot      = 0xCC;
const std::uintptr_t kKillCamRestoreRva  = FW_RVA(0x010265B0, 0x01026AE0);   // sub_1410265B0(PlayerCamera*)
const std::uintptr_t kCamGetStateRva     = FW_RVA(0x0102B100, 0x0102B630);   // (cam, index): index 0 = FirstPersonState
const std::uintptr_t kSetCamStateRva     = FW_RVA(0x00827A80, 0x00827DD0);   // (cam, state)
constexpr std::size_t    kCamCurrentStateOff = 0x28;
constexpr int            kVerifyFrames       = 30;
constexpr int            kProcessWaitFrames  = 120;     // ~2 s after the in-place re-attach, then the direct move
constexpr float          kHpRecovery         = 25.0f;   // the stand-down's own "restored" threshold
constexpr ULONGLONG      kTravelTimeoutMs    = 25000;   // the fast travel must have landed by then
constexpr ULONGLONG      kAfterReloadMaxMs   = 60000;   // a reload that never comes back closes the death
constexpr ULONGLONG      kReloadStartMs      = 10000;   // no load started by then: the engine did not take it
constexpr ULONGLONG      kRespawnAnswerMs    = 10000;   // stage 3d: the server's moved checkpoint must be named by then
constexpr ULONGLONG      kRespawnFetchMs     = 30000;   // ... and on this disk by then
constexpr ULONGLONG      kRespawnLoadMs      = 60000;   // ... and loaded by then
constexpr ULONGLONG      kProtectAfterMs     = 3000;    // untouchable for this long after landing
constexpr float          kArrivedUnits       = 768.0f;  // this close to the point = landed
constexpr ULONGLONG      kDeathRepeatMs      = 10000;   // kills on the corpse inside this window are the same death

// Idle -> (the reload queued) Armed -> Verifying -> WaitProcess -> Travelling
// -> Protected -> Idle; the fallbacks go through AfterReload (the engine
// reloads the last checkpoint, then the fast travel to the point) ->
// Travelling. From the resurrect to the landing the player is a ghost to
// the engine (Actor::SetGhost: no damage, no targeting; measured on the
// second live death, B was bitten by the flies it had died to while it
// waited for the move) and the screen is covered by a curtain (the
// render overlay draws it: the far move shows the loading of the
// destination and every ghost we render on it).
enum class Phase { Idle, Armed, Verifying, WaitProcess, Travelling, AfterReload, Protected,
                   // stage 3d: the server's moved checkpoint
                   WaitRespawnCkpt, FetchRespawnCkpt, AfterRespawnLoad };

// Stage 3d — the server's answer to this death. Written by the net thread
// under g_mx, read by the main thread.
struct RespawnCkpt {
    bool          arrived = false;
    bool          has = false;
    char          name[48] = {};
    std::uint8_t  sha256[32] = {};
    std::uint32_t size = 0;
};

std::mutex        g_mx;                  // the respawn point: written by the net thread
bool              g_have_point = false;
float             g_point[3] = {0.0f, 0.0f, 0.0f};
float             g_yaw = 0.0f;
bool              g_enabled = false;
bool              g_try_resurrect = false;   // death_resurrect in the ini; off = every death reloads
std::uintptr_t    g_base = 0;
std::atomic<bool> g_curtain{false};      // read by the render thread

// Main thread only from here on.
Phase          g_phase = Phase::Idle;
int            g_frames = 0;
float          g_hp_at_death = 0.0f;
ULONGLONG      g_died_ms = 0;
ULONGLONG      g_armed_ms = 0;
ULONGLONG      g_travel_ms = 0;
ULONGLONG      g_reload_ms = 0;
ULONGLONG      g_landed_ms = 0;
RespawnCkpt    g_rsp;                   // under g_mx
char           g_rsp_name[48] = {};     // main thread: the file being fetched and loaded
ULONGLONG      g_rsp_wait_ms = 0;
ULONGLONG      g_fetch_start_ms = 0;
std::atomic<int> g_fetch_state{0};      // 0 idle, 1 running, 2 on disk and verified, 3 failed
char           g_fetch_why[96] = {};    // under g_mx, written by the fetch thread
std::uint64_t  g_loads_before = 0;
std::uint32_t  g_marker_handle = 0;
bool           g_protected = false;     // SetGhost(true) is on the player
bool           g_death_open = false;    // from the first kill to the end of the protection
std::uint32_t  g_corpse_hits = 0;       // kills on the corpse after the first, this death
void*          g_mgr = nullptr;
std::uint32_t  g_deaths = 0;

std::uintptr_t module_base() noexcept {
    if (!g_base) g_base = reinterpret_cast<std::uintptr_t>(GetModuleHandleW(L"Fallout4.exe"));
    return g_base;
}

std::uint64_t wall_ms() noexcept {
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    const std::uint64_t t = (static_cast<std::uint64_t>(ft.dwHighDateTime) << 32) | ft.dwLowDateTime;
    return (t - 116444736000000000ull) / 10000ull;
}

void point_copy(float out[3], float* yaw) {
    std::lock_guard<std::mutex> lk(g_mx);
    out[0] = g_point[0]; out[1] = g_point[1]; out[2] = g_point[2];
    if (yaw) *yaw = g_yaw;
}

// 0 alive, 1 dying, 2 dead, 3 unconscious, 5 recycle, 7 essential down;
// 0xFFFFFFFF = unreadable.
std::uint32_t seh_life_state(void* player) noexcept {
    __try {
        const std::uint32_t flags = *reinterpret_cast<const std::uint32_t*>(
            static_cast<const std::uint8_t*>(player) + offsets::ACTOR_LIFESTATE_FLAGS_OFF);
        return (flags & offsets::ACTOR_LIFESTATE_MASK) >> offsets::ACTOR_LIFESTATE_SHIFT;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0xFFFFFFFFu;
    }
}

bool seh_player_pos(void* player, float out[3]) noexcept {
    __try {
        const float* p = reinterpret_cast<const float*>(
            static_cast<const std::uint8_t*>(player) + offsets::POS_OFF);
        out[0] = p[0]; out[1] = p[1]; out[2] = p[2];
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

float seh_player_yaw(void* player) noexcept {
    __try {
        return *reinterpret_cast<const float*>(
            static_cast<const std::uint8_t*>(player) + offsets::ROT_OFF + 8);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0.0f;
    }
}

bool seh_resurrect(void* player) noexcept {
    __try {
        void** vt = *reinterpret_cast<void***>(player);
        auto fn = reinterpret_cast<void(__fastcall*)(void*, std::uint8_t, std::uint8_t)>(vt[kResurrectSlot]);
        fn(player, 0, 1);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// The player's middle-high AI process (sub_140C5C830: the process at
// +0x300, then its middle-high part at (+8)+0x3E0). The Resurrect override
// makes a FRESH process; its middle-high part comes back with the
// engine's process update, which the in-place Actor::MoveTo of the boot
// primitive performs (measured on the second live death: the direct move
// after the resurrect left a whole process, the fast travel queued
// without it wrote at NULL+0x304 and crashed).
void* seh_middle_high_process(std::uintptr_t b, void* player) noexcept {
    __try {
        return reinterpret_cast<void*(__fastcall*)(void*, void*, void*)>(
            b + offsets::ACTOR_GET_MIDDLE_HIGH_PROCESS_RVA)(player, nullptr, nullptr);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return nullptr;
    }
}

// The kill-cam is VATS mode 1 (the death update enters it through
// sub_140E59410 -> sub_140E57E20(vats, 1)): slow motion, the blur, and the
// save gate closed (sub_140BFAE80 refuses while vats+0x40 != 0). The
// engine's own way out is what the load path does (sub_140C001F0): the
// target queue reset, mode 0, the global time multiplier back to 1.0.
// 0 = done (`before`/`after` say the mode seen), 1 = no VATS object, 2 = a
// fault.
int seh_end_kill_cam(std::uintptr_t b, std::uint32_t* before, std::uint32_t* after) noexcept {
    __try {
        void* vats = *reinterpret_cast<void**>(b + offsets::VATS_SINGLETON_RVA);
        if (!vats) return 1;
        *before = *reinterpret_cast<std::uint32_t*>(static_cast<std::uint8_t*>(vats) + offsets::VATS_MODE_OFF);
        if (*before != 0) {
            reinterpret_cast<void(__fastcall*)(void*, char, char, char)>(b + offsets::VATS_RESET_TARGETS_RVA)(vats, 1, 0, 0);
            reinterpret_cast<void(__fastcall*)(void*, int)>(b + offsets::VATS_SET_MODE_RVA)(vats, 0);
            reinterpret_cast<void(__fastcall*)(void*, float, char)>(b + offsets::TIME_MULT_SET_RVA)(
                reinterpret_cast<void*>(b + offsets::TIME_MULT_OBJECT_RVA), 1.0f, 1);
        }
        *after = *reinterpret_cast<std::uint32_t*>(static_cast<std::uint8_t*>(vats) + offsets::VATS_MODE_OFF);
        return 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 2;
    }
}

// The camera out of the kill-cam. 0 = done (`was_first` says whether the
// engine's own return already left it in the first person), 1 = no camera,
// 2 = a fault.
int seh_restore_camera(std::uintptr_t b, bool* was_first) noexcept {
    __try {
        void* cam = *reinterpret_cast<void**>(b + offsets::PLAYER_CAMERA_SINGLETON_RVA);
        if (!cam) return 1;
        reinterpret_cast<void(__fastcall*)(void*)>(b + kKillCamRestoreRva)(cam);
        void* cur = *reinterpret_cast<void**>(static_cast<std::uint8_t*>(cam) + kCamCurrentStateOff);
        void* fp  = reinterpret_cast<void*(__fastcall*)(void*, unsigned int)>(b + kCamGetStateRva)(cam, 0u);
        *was_first = (fp != nullptr && cur == fp);
        if (fp && cur != fp) {
            reinterpret_cast<void(__fastcall*)(void*, void*)>(b + kSetCamStateRva)(cam, fp);
        }
        return 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 2;
    }
}

void send_life(std::uint8_t event, const float pos[3]) {
    fw::net::PlayerLifePayload p{};
    p.event = event;
    p.pos[0] = pos[0]; p.pos[1] = pos[1]; p.pos[2] = pos[2];
    p.wall_ms = wall_ms();
    fw::net::client().enqueue_player_life(p);
}

// Untouchable, or not. Every path that ends a death goes through
// protect(false): a ghost flag left on the player would ride the next
// checkpoint (the gates hold checkpoints while a death is in progress,
// which includes the protection).
void protect(bool on) {
    if (g_protected == on) return;
    void* player = fw::engine::get_local_player();
    const bool ok = player && fw::engine::set_actor_ghost(player, on);
    if (ok) g_protected = on;
    FW_LOG("[death] protection %s%s", on ? "ON (the player is a ghost to the engine)" : "OFF",
           ok ? "" : " - the SetGhost call FAILED");
}

void drop_travel_marker() {
    if (g_marker_handle == 0) return;
    std::uint32_t h = g_marker_handle;
    g_marker_handle = 0;
    void* marker = fw::engine::resolve_refhandle(&h);
    if (!marker) return;
    const bool gone = fw::engine::destroy_world_refr(marker);
    FW_LOG("[death] the travel marker (handle 0x%08X) %s", h,
           gone ? "destroyed" : "could not be destroyed (see the SEH line)");
}

void close_death() {
    protect(false);
    g_curtain.store(false, std::memory_order_relaxed);
    drop_travel_marker();
    g_phase = Phase::Idle;
    g_mgr = nullptr;
    g_death_open = false;
}

// The engine reloads the last checkpoint (the stage-3a death); once that
// world is back, the fast travel takes the player to the point anyway.
void arm_after_reload(const char* why) {
    protect(false);   // a reload restores the checkpoint's player; the flag would not survive it anyway
    g_loads_before = fw::persist::loads_requested();
    g_reload_ms = GetTickCount64();
    g_phase = Phase::AfterReload;
    g_mgr = nullptr;
    g_curtain.store(true, std::memory_order_relaxed);
    FW_LOG("[death] %s: the engine reloads the last checkpoint; the fast travel to the respawn "
           "point follows once that world is back", why ? why : "?");
}

void fail(const char* why) {
    float pos[3] = {0.0f, 0.0f, 0.0f};
    void* player = fw::engine::get_local_player();
    if (player) (void)seh_player_pos(player, pos);
    FW_ERR("[death] respawn without a reload FAILED: %s -> the engine reloads the last "
           "checkpoint instead", why ? why : "?");
    drop_travel_marker();
    send_life(fw::net::kPlayerLifeReloadFallback, pos);
    fw::persist::requeue_death_reload(g_mgr);
    arm_after_reload("the fallback reload");
}

// Landed: the curtain lifts, the protection stays a few seconds more.
void report_respawned(void* player, const char* how) {
    float pos[3] = {0.0f, 0.0f, 0.0f};
    (void)seh_player_pos(player, pos);
    // Stage 3d: the checkpoint brought back the health and the radiation it
    // was written with; a respawn starts whole.
    fw::hooks::HealReport heal{};
    const bool healed = fw::hooks::heal_local_player(player, &heal);
    FW_LOG("[death] healed%s: rads %.1f -> %.1f, health damage %.1f -> %.1f",
           healed ? "" : " (INCOMPLETE: a read or the registry failed)",
           heal.rads_before, heal.rads_after, heal.health_damage_before, heal.health_damage_after);
    const ULONGLONG now = GetTickCount64();
    FW_LOG("[death] RESPAWNED at (%.1f, %.1f, %.1f): %s, %u ms after the death (death #%u of "
           "this session, %u more hit(s) on the corpse); untouchable for %u ms more",
           pos[0], pos[1], pos[2], how, unsigned(now - g_died_ms), g_deaths, g_corpse_hits,
           unsigned(kProtectAfterMs));
    send_life(fw::net::kPlayerLifeRespawned, pos);
    // Stage 3d: the stand-down's own detectors are guesses a respawn next to
    // the point defeats; this is the landing itself.
    fw::hooks::note_local_player_respawned();
    // Stage 3d: the others see the outfit the checkpoint brought back.
    fw::hooks::equip_announce_after_respawn();
    drop_travel_marker();
    g_curtain.store(false, std::memory_order_relaxed);
    g_landed_ms = now;
    g_phase = Phase::Protected;
    // L5 realtime D1: a respawn with no load behind it (the resurrect) gets
    // the record of the death all the same.
    fw::persist::restore::on_respawn_without_load();
    // 2026-10-04: the HUD of power armour is shown by the enter and hidden by
    // the exit ladder; a death in a frame answered with a checkpoint on foot
    // runs neither, and the Pip-Boy stayed in its power armour mode.
    fw::engine::sync_power_armor_hud("the respawn");
}

// The direct move: the Actor::MoveTo the boot uses. It works, but a far
// destination is loaded synchronously on the main thread (measured 50 s of
// "not responding" on the first live death): the fast travel is tried
// first, this is its fallback. The curtain covers what the screen shows
// meanwhile.
void teleport_directly(void* player, const char* why) {
    float point[3];
    float yaw;
    point_copy(point, &yaw);
    // 2026-09-30 (live test #21): from an interior the handoff writes the
    // point's coordinates inside the same cell and answers true; the player
    // never left the cellar and the death was reported landed at the point.
    // Neither this nor the fast travel has an exterior cell to aim at there:
    // the player stays where the reload put them, and says so.
    bool inside = false;
    if (fw::engine::player_in_interior(&inside) && inside) {
        FW_WRN("[death] no direct teleport to the respawn point (%s): the player is in an "
               "interior after the reload and this path cannot leave it; the respawn stays "
               "where the checkpoint was written", why);
        report_respawned(player, "in the interior of the checkpoint (no teleport out of it)");
        return;
    }
    const bool moved = fw::engine::actor_teleport_handoff(player, point[0], point[1], point[2], yaw);
    FW_WRN("[death] direct teleport to the respawn point (%s): %s", why,
           moved ? "done (the world loads synchronously)" : "FAILED (the player stays where it died)");
    report_respawned(player, moved ? "direct teleport" : "teleport FAILED, still at the death spot");
}

// The move: the engine's own fast travel (a loading screen, the destination
// loaded by the loader), the direct teleport as the fallback.
void start_travel(void* player) {
    protect(true);
    g_curtain.store(true, std::memory_order_relaxed);
    float point[3];
    float yaw;
    point_copy(point, &yaw);
    std::uint32_t marker = 0;
    if (fw::engine::player_fast_travel_to(point[0], point[1], point[2], yaw, &marker)) {
        g_marker_handle = marker;
        g_travel_ms = GetTickCount64();
        g_phase = Phase::Travelling;
        FW_LOG("[death] fast travel to (%.1f, %.1f, %.1f) queued (marker handle 0x%08X): the "
               "engine's loading screen takes it from here, %u s at most",
               point[0], point[1], point[2], marker, unsigned(kTravelTimeoutMs / 1000));
        return;
    }
    teleport_directly(player, "the fast travel could not be queued");
}

// Stage 3d — the server's moved checkpoint could not be used: the engine's
// reload of the last checkpoint runs, then the fast travel (stage 3c).
void respawn_fallback(const char* why) {
    FW_WRN("[death] the server's moved checkpoint is not used (%s): the engine reloads the last "
           "checkpoint, then the fast travel", why ? why : "?");
    float pos[3] = {0.0f, 0.0f, 0.0f};
    void* player = fw::engine::get_local_player();
    if (player) (void)seh_player_pos(player, pos);
    send_life(fw::net::kPlayerLifeReloadFallback, pos);
    fw::persist::requeue_death_reload(g_mgr);
    arm_after_reload("the fallback reload");
}

// Stage 3d — the fetch runs on its own thread (a TCP transfer of the whole
// checkpoint: tens of ms here, seconds over the internet); the main thread
// polls g_fetch_state.
void start_fetch(const RespawnCkpt& r) {
    std::memset(g_rsp_name, 0, sizeof(g_rsp_name));
    std::strncpy(g_rsp_name, r.name, sizeof(g_rsp_name) - 1);
    g_fetch_state.store(1, std::memory_order_release);
    g_fetch_start_ms = GetTickCount64();
    const std::string name(r.name);
    std::array<std::uint8_t, 32> sha{};
    std::memcpy(sha.data(), r.sha256, sha.size());
    const std::uint32_t size = r.size;
    try {
        std::thread([name, sha, size]() {
            char why[96] = {};
            const int rc = fw::persist::checkpoint::fetch_from_custody(name.c_str(), sha.data(), size,
                                                                       why, sizeof(why));
            {
                std::lock_guard<std::mutex> lk(g_mx);
                std::memset(g_fetch_why, 0, sizeof(g_fetch_why));
                std::strncpy(g_fetch_why, why, sizeof(g_fetch_why) - 1);
            }
            g_fetch_state.store(rc == 0 ? 2 : 3, std::memory_order_release);
        }).detach();
    } catch (...) {
        g_fetch_state.store(0, std::memory_order_release);
        respawn_fallback("the fetch thread could not start");
        return;
    }
    g_phase = Phase::FetchRespawnCkpt;
    FW_LOG("[death] the server moved '%s' onto the respawn point: fetching it from custody "
           "(%u bytes)", g_rsp_name, unsigned(size));
}

void run_respawn_ckpt(ULONGLONG now) {
    if (fw::persist::exiting()) {
        FW_LOG("[death] the exit ends the wait for the server's moved checkpoint");
        close_death();
        return;
    }
    if (g_phase == Phase::WaitRespawnCkpt) {
        RespawnCkpt r;
        {
            std::lock_guard<std::mutex> lk(g_mx);
            r = g_rsp;
        }
        if (r.arrived) {
            if (!r.has) { respawn_fallback("the server has no moved checkpoint for this death"); return; }
            start_fetch(r);
            return;
        }
        if (now - g_rsp_wait_ms >= kRespawnAnswerMs) {
            respawn_fallback("no answer from the server in time");
        }
        return;
    }
    if (g_phase == Phase::FetchRespawnCkpt) {
        const int st = g_fetch_state.load(std::memory_order_acquire);
        if (st == 2) {
            g_fetch_state.store(0, std::memory_order_relaxed);
            g_loads_before = fw::persist::loads_requested();
            g_reload_ms = now;
            FW_LOG("[death] '%s' is on this disk and matches the server's record (%u ms): the engine "
                   "loads it", g_rsp_name, unsigned(now - g_fetch_start_ms));
            if (!fw::engine::load_game_by_name(g_rsp_name)) {
                respawn_fallback("the engine refused to load it");
                return;
            }
            g_phase = Phase::AfterRespawnLoad;
            return;
        }
        if (st == 3) {
            char why[128];
            {
                std::lock_guard<std::mutex> lk(g_mx);
                std::snprintf(why, sizeof(why), "the fetch failed: %s", g_fetch_why);
            }
            g_fetch_state.store(0, std::memory_order_relaxed);
            respawn_fallback(why);
            return;
        }
        if (now - g_fetch_start_ms >= kRespawnFetchMs) {
            respawn_fallback("the fetch did not finish in time");
        }
        return;
    }
    // AfterRespawnLoad: the world of the moved checkpoint is back.
    if (fw::persist::loads_requested() > g_loads_before && !fw::persist::load_in_flight()
            && fw::engine::get_pc_parent_cell() != nullptr && fw::native::ghost_scene_settled()) {
        void* player = fw::engine::get_local_player();
        if (player) {
            char how[128];
            std::snprintf(how, sizeof(how), "the server's moved checkpoint loaded in %u ms, no fast "
                          "travel", unsigned(now - g_reload_ms));
            report_respawned(player, how);
            return;
        }
    }
    if (now - g_reload_ms >= kRespawnLoadMs) {
        FW_WRN("[death] the moved checkpoint's world did not come back in %u s: the death is "
               "closed where the player is", unsigned(kRespawnLoadMs / 1000));
        close_death();
    }
}

// Alive again: out of the kill-cam, the camera back, untouchable, and the
// AI process re-attached in place (the boot's MoveTo with the process
// update, zero distance) so the move that follows finds it whole.
void finish(void* player) {
    const std::uintptr_t b = module_base();
    std::uint32_t vats_before = 0, vats_after = 0;
    const int vats = seh_end_kill_cam(b, &vats_before, &vats_after);
    bool was_first = false;
    const int cam = seh_restore_camera(b, &was_first);
    FW_LOG("[death] kill-cam %s (VATS mode %u -> %u), camera %s",
           vats == 0 ? "ended" : (vats == 1 ? "NOT ended: no VATS object" : "NOT ended: fault"),
           vats_before, vats_after,
           cam == 0 ? (was_first ? "back in first person by the engine" : "set to first person by hand")
                    : (cam == 1 ? "NOT restored: no camera object" : "NOT restored: fault"));
    protect(true);
    g_curtain.store(true, std::memory_order_relaxed);
    float here[3] = {0.0f, 0.0f, 0.0f};
    if (seh_player_pos(player, here)) {
        const bool re = fw::engine::actor_teleport_handoff(player, here[0], here[1], here[2],
                                                           seh_player_yaw(player));
        FW_LOG("[death] AI process re-attached in place (MoveTo with the process update, zero "
               "distance): %s", re ? "done" : "FAILED");
    }
    g_phase = Phase::WaitProcess;
    g_frames = 0;
}

} // namespace

void configure(const fw::config::Settings& cfg) {
    g_enabled = cfg.persist_lifecycle;
    g_try_resurrect = cfg.death_resurrect;
    if (!g_enabled) {
        FW_LOG("[death] OFF (persist_lifecycle=false): a death reloads the last checkpoint and "
               "nothing follows");
        return;
    }
    FW_LOG("[death] armed: %s; the respawn point comes with the boot word",
           g_try_resurrect ? "the resurrect is tried first (death_resurrect=true)"
                           : "every death reloads the last checkpoint, then the fast travel to "
                             "the respawn point");
}

void set_respawn_point(bool has, const float pos[3], float yaw) {
    std::lock_guard<std::mutex> lk(g_mx);
    const bool changed = has != g_have_point
        || (has && (pos[0] != g_point[0] || pos[1] != g_point[1] || pos[2] != g_point[2] || yaw != g_yaw));
    g_have_point = has;
    if (has) {
        g_point[0] = pos[0]; g_point[1] = pos[1]; g_point[2] = pos[2];
        g_yaw = yaw;
    }
    if (changed) {
        if (has) {
            FW_LOG("[death] respawn point from the server: (%.1f, %.1f, %.1f) yaw %.2f",
                   pos[0], pos[1], pos[2], yaw);
        } else {
            FW_LOG("[death] the server names no respawn point: a death reloads the last checkpoint");
        }
    }
}

bool respawn_point_known() {
    std::lock_guard<std::mutex> lk(g_mx);
    return g_have_point;
}

bool respawn_in_progress() {
    return g_phase != Phase::Idle;
}

bool curtain_active() {
    return g_curtain.load(std::memory_order_relaxed);
}

void note_killed() {
    const ULONGLONG now = GetTickCount64();
    // The kill hook fires for every hit that lands on the corpse (41 times
    // on the first live death): one death is one report.
    if (g_death_open && now - g_died_ms < kDeathRepeatMs) {
        ++g_corpse_hits;
        return;
    }
    g_death_open = true;
    g_corpse_hits = 0;
    ++g_deaths;
    g_died_ms = now;
    // L5 realtime R2: the reload of this death loads an older inventory;
    // the record is asked for now and put back once that load is over.
    fw::persist::restore::on_death();
    float pos[3] = {0.0f, 0.0f, 0.0f};
    void* player = fw::engine::get_local_player();
    if (player) (void)seh_player_pos(player, pos);
    float hp = 0.0f;
    const bool have_hp = fw::hooks::local_player_hp_sum(&hp);
    FW_LOG("[death] local player KILLED at (%.1f, %.1f, %.1f), life state %u, hp-sum %.1f%s: the "
           "engine's death timer runs (fPlayerDeathReloadTime), %s",
           pos[0], pos[1], pos[2], player ? seh_life_state(player) : 0xFFFFFFFFu, hp,
           have_hp ? "" : " (unreadable)",
           !respawn_point_known() ? "no respawn point: the reload of the last checkpoint runs"
           : g_try_resurrect      ? "the resurrect takes the reload when it fires"
                                  : "the reload of the last checkpoint runs, then the fast travel "
                                    "to the respawn point");
    {
        // Stage 3d: the answer to THIS death is the one that counts.
        std::lock_guard<std::mutex> lk(g_mx);
        g_rsp = RespawnCkpt{};
    }
    // Stage 3d: what the player wears now, for the difference the respawn
    // sends (the checkpoint may bring back another outfit).
    fw::hooks::equip_announce_note_death();
    send_life(fw::net::kPlayerLifeDied, pos);
}

void on_respawn_checkpoint(bool has, const char* name, const std::uint8_t sha256[32],
                           std::uint32_t size) {
    std::lock_guard<std::mutex> lk(g_mx);
    g_rsp.arrived = true;
    g_rsp.has = has && name && *name;
    std::memset(g_rsp.name, 0, sizeof(g_rsp.name));
    if (g_rsp.has) std::strncpy(g_rsp.name, name, sizeof(g_rsp.name) - 1);
    if (sha256) std::memcpy(g_rsp.sha256, sha256, sizeof(g_rsp.sha256));
    g_rsp.size = size;
    FW_LOG("[death] the server's answer to the death: %s%s%s", g_rsp.has ? "load '" : "no moved checkpoint",
           g_rsp.has ? g_rsp.name : "", g_rsp.has ? "', moved onto the respawn point" : " (the reload runs)");
}

bool on_death_reload_queued(void* save_load_mgr) {
    if (!g_enabled || !save_load_mgr) return false;
    if (!respawn_point_known()) {
        FW_LOG("[death] no respawn point from the server: the reload runs");
        return false;
    }
    void* player = fw::engine::get_local_player();
    if (!player) {
        FW_LOG("[death] no player object: the reload runs");
        return false;
    }
    if (g_phase != Phase::Idle && g_phase != Phase::AfterReload && g_phase != Phase::Protected) {
        FW_LOG("[death] a respawn is already in progress: this reload request is swallowed too");
        return true;
    }
    if (g_phase == Phase::Idle && !g_try_resurrect && fw::persist::custody::available()) {
        // Stage 3d: the server answers the death with the checkpoint moved
        // onto the point (PLAYER_LIFE died went out at the kill, seconds
        // ago). The engine's reload waits here; it runs as the fallback.
        // Only on a fresh death: while a fallback reload is in flight the
        // same answer would send it into the fallback a second time.
        g_phase = Phase::WaitRespawnCkpt;
        g_mgr = save_load_mgr;
        g_rsp_wait_ms = GetTickCount64();
        if (g_died_ms == 0 || !g_death_open) { g_died_ms = g_rsp_wait_ms; g_death_open = true; }
        g_curtain.store(true, std::memory_order_relaxed);
        FW_LOG("[death] death reload SWALLOWED %u ms after the death: the server's moved checkpoint "
               "is loaded instead (%u s at most for its answer; the engine's reload is the fallback)",
               unsigned(g_rsp_wait_ms - g_died_ms), unsigned(kRespawnAnswerMs / 1000));
        return true;
    }
    const bool in_pa = fw::persist::inventory::last().in_power_armor;
    if (!g_try_resurrect || in_pa) {
        // 2026-09-28: every death goes through the reload (death.h): the
        // engine reloads the last checkpoint and the fast travel to the
        // point follows once that world is back. Inside a frame the
        // resurrect was never tried, even with the switch on.
        float pos[3] = {0.0f, 0.0f, 0.0f};
        (void)seh_player_pos(player, pos);
        send_life(fw::net::kPlayerLifeReloadFallback, pos);
        arm_after_reload(in_pa ? "the player died in power armour"
                               : "the death reloads the last checkpoint");
        return false;
    }
    const std::uint32_t ls = seh_life_state(player);
    if (ls != 1 && ls != 2) {
        FW_LOG("[death] life state %u is not dying/dead: the reload runs", ls);
        return false;
    }
    float hp = 0.0f;
    if (!fw::hooks::local_player_hp_sum(&hp)) hp = -1.0e9f;
    g_hp_at_death = hp;
    g_phase = Phase::Armed;
    g_frames = 0;
    g_mgr = save_load_mgr;
    g_armed_ms = GetTickCount64();
    if (g_died_ms == 0 || !g_death_open) { g_died_ms = g_armed_ms; g_death_open = true; }
    FW_LOG("[death] death reload SWALLOWED %u ms after the death (life state %u, hp-sum %.1f): "
           "the resurrect runs at the next frame", unsigned(g_armed_ms - g_died_ms), ls, hp);
    return true;
}

void run_pending(void* save_load_mgr) {
    if (g_phase == Phase::Idle) return;
    if (save_load_mgr && g_phase != Phase::AfterReload) g_mgr = save_load_mgr;
    const std::uintptr_t b = module_base();
    const ULONGLONG now = GetTickCount64();

    if (g_phase == Phase::Protected) {
        if (fw::persist::exiting() || now - g_landed_ms >= kProtectAfterMs) {
            FW_LOG("[death] the death is closed: the player is touchable again");
            close_death();
        }
        return;
    }

    if (g_phase == Phase::WaitRespawnCkpt || g_phase == Phase::FetchRespawnCkpt
            || g_phase == Phase::AfterRespawnLoad) {
        run_respawn_ckpt(now);
        return;
    }

    if (g_phase == Phase::AfterReload) {
        // Waiting for the engine's reload to bring a world back; then the
        // same move as the resurrect path.
        if (fw::persist::exiting()) { FW_LOG("[death] the exit ends the wait for the reload"); close_death(); return; }
        if (fw::persist::loads_requested() > g_loads_before && !fw::persist::load_in_flight()
                && fw::engine::get_pc_parent_cell() != nullptr && fw::native::ghost_scene_settled()) {
            void* player = fw::engine::get_local_player();
            if (player && seh_middle_high_process(b, player)) {
                FW_LOG("[death] the reload is back (%u ms): the fast travel to the respawn point",
                       unsigned(now - g_reload_ms));
                start_travel(player);
                return;
            }
        }
        // No load started at all: the engine did not take the reload. On
        // the fourth live test a reload queued for a player who was alive
        // never came and the curtain stayed up until the exit. The death is
        // closed where the player is; a player still dead gets the engine's
        // next death reload, five seconds later, which arms this again.
        if (fw::persist::loads_requested() == g_loads_before && now - g_reload_ms >= kReloadStartMs) {
            FW_WRN("[death] no load started %u s after the reload was queued: the death is closed "
                   "where the player is, the curtain lifts", unsigned(kReloadStartMs / 1000));
            close_death();
            return;
        }
        if (now - g_reload_ms >= kAfterReloadMaxMs) {
            FW_WRN("[death] no world came back from the reload in %u s: the death is closed where "
                   "the player is", unsigned(kAfterReloadMaxMs / 1000));
            close_death();
        }
        return;
    }

    if (fw::persist::exiting()) { fail("the world is going away (exit)"); return; }
    void* player = fw::engine::get_local_player();
    if (!player) { fail("the player object is gone"); return; }

    if (g_phase == Phase::Travelling) {
        // The fast travel's loading screen is a load of cells, not of a
        // save: nothing of ours gates it. Landed = near the point.
        float pos[3] = {0.0f, 0.0f, 0.0f};
        float point[3];
        point_copy(point, nullptr);
        if (seh_player_pos(player, pos)) {
            const float dx = pos[0] - point[0], dy = pos[1] - point[1], dz = pos[2] - point[2];
            if (dx * dx + dy * dy + dz * dz <= kArrivedUnits * kArrivedUnits) {
                char how[96];
                std::snprintf(how, sizeof(how), "the engine's fast travel landed after %u ms",
                              unsigned(now - g_travel_ms));
                report_respawned(player, how);
                return;
            }
        }
        if (now - g_travel_ms >= kTravelTimeoutMs) {
            drop_travel_marker();
            teleport_directly(player, "the fast travel did not land in time");
        }
        return;
    }

    if (fw::persist::load_in_flight()) { fail("a load is in flight"); return; }

    if (g_phase == Phase::Armed) {
        const std::uint32_t before = seh_life_state(player);
        float hp_before = 0.0f;
        (void)fw::hooks::local_player_hp_sum(&hp_before);
        // The override frees the AIProcess the tracer captured and makes a
        // new one: forget the pointer before it dangles.
        fw::hooks::forget_player_process();
        const bool ok = seh_resurrect(player);
        const std::uint32_t after = seh_life_state(player);
        float hp_after = 0.0f;
        (void)fw::hooks::local_player_hp_sum(&hp_after);
        FW_LOG("[death] Resurrect (vtable slot 0x%zX) %s: life state %u -> %u, hp-sum %.1f -> %.1f",
               kResurrectSlot, ok ? "returned" : "FAULTED", before, after, hp_before, hp_after);
        if (!ok) { fail("the Resurrect call faulted"); return; }
        g_phase = Phase::Verifying;
        g_frames = 0;
        return;
    }

    if (g_phase == Phase::WaitProcess) {
        ++g_frames;
        if (seh_middle_high_process(b, player)) {
            FW_LOG("[death] the AI process is whole again after %d frame(s): the move", g_frames);
            start_travel(player);
            return;
        }
        if (g_frames >= kProcessWaitFrames) {
            teleport_directly(player, "the AI process did not grow its middle-high part in time");
        }
        return;
    }

    // Verifying: the life state and the health, up to kVerifyFrames.
    ++g_frames;
    const std::uint32_t ls = seh_life_state(player);
    float hp = 0.0f;
    const bool have_hp = fw::hooks::local_player_hp_sum(&hp);
    const bool alive = (ls == 0) && have_hp && (g_hp_at_death < -1.0e8f || hp > g_hp_at_death + kHpRecovery);
    if (alive) {
        FW_LOG("[death] resurrect VERIFIED after %d frame(s): life state 0, hp-sum %.1f (was %.1f)",
               g_frames, hp, g_hp_at_death);
        finish(player);
        return;
    }
    if (g_frames >= kVerifyFrames) {
        char why[128];
        std::snprintf(why, sizeof(why), "still not alive after %d frames (life state %u, hp-sum %.1f, was %.1f)",
                      g_frames, ls, hp, g_hp_at_death);
        fail(why);
    }
}

} // namespace fw::persist::death
