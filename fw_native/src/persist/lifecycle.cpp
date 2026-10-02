#include "lifecycle.h"

#include <windows.h>
#include <intrin.h>

#include <atomic>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <unordered_map>

#include "../config.h"
#include "../hook_manager.h"
#include "../log.h"
#include "../main_thread_dispatch.h"
#include "../engine/engine_calls.h"   // get_pc_parent_cell: is there a world to protect
#include "../offsets.h"
#include "../net/protocol.h"          // kInvDigestWhyExit
#include "../render/chat_overlay.h"   // the player is told why nothing loaded
#include "checkpoint.h"               // the commanded save, served at the save point
#include "death.h"                    // L5 stage 3c: the respawn without a reload
#include "inventory_capture.h"        // the last digest goes out with the exit

#pragma intrinsic(_ReturnAddress)

namespace fw::persist {

namespace {

// ---------------------------------------------------------------- signatures
//
// All from the decomp of 1.11.191, read on 2026-09-27. Widths are the
// callee's own: where the decomp shows `int` or `char` the register is read
// as such and nothing wider is ever consumed.

// sub_140BFE4C0(mgr, flag): OR `flag` into the pending word at mgr+0x40,
// with side effects for 1 (gate + delay), 0x10 (quickload event) and 0x80.
using QueueFn = void (__fastcall*)(void* mgr, int flag);
// sub_140BFE820(mgr): the task processor, once per frame from Main::Update.
using ProcessFn = void (__fastcall*)(void* mgr);
// sub_140BF8E10(mgr, name, a3 = -1, a4 = 0, a5 = zlib): the named save.
// Returns 1 when the gate passed, whether or not the file was written.
using NamedSaveFn = std::int64_t (__fastcall*)(void* mgr, const char* name,
                                               std::uint32_t a3, int a4,
                                               std::uint8_t a5);
// sub_140BF9010(mgr, name, a3, a4, a5): freezes the job list and the
// Papyrus VM, writes, stores the name at mgr+0x60.
using SaveCoreFn = char (__fastcall*)(void* mgr, const char* name,
                                      std::uint32_t a3, int a4, std::uint8_t a5);
// sub_140BF93B0(mgr, name, a3, a4, a5, a6): posts the load job and pumps
// the main thread until it is done. a5 = 1 makes the loader store the name
// at mgr+0x60 (the death-reload target).
using LoadRequestFn = std::int64_t (__fastcall*)(void* mgr, const char* name,
                                                 int a3, int a4, char a5, char a6);
// sub_140C01E80(job): the load job body, on the loader thread.
using LoadJobFn = std::int64_t (__fastcall*)(void* job);
// sub_140BFD3C0(mgr): LoadGame(mgr+0x60) when set, else 0 (main menu).
using DeathReloadFn = char (__fastcall*)(void* mgr);
// sub_140C02500(&event): posts a SaveLoadMessageTypeEvent {type, flag}.
using PostEventFn = std::int64_t (__fastcall*)(void* event);
// sub_140AD2BA0(menu, message): the pause menu's Scaleform message handler.
using MenuProcessMessageFn = void (__fastcall*)(void* menu, void* message);
// sub_140C08280(): queue "PauseMenuBackOutFromLoadGame" to the open pause
// menu (the engine's own return path from a load that will not happen).
using BackOutFromLoadFn = std::int64_t (*)();

QueueFn       g_orig_queue        = nullptr;
MenuProcessMessageFn g_orig_pause_menu = nullptr;
BackOutFromLoadFn    g_back_out_from_load = nullptr;
ProcessFn     g_orig_process      = nullptr;
NamedSaveFn   g_orig_named_save   = nullptr;
SaveCoreFn    g_orig_save_core    = nullptr;
LoadRequestFn g_orig_load_request = nullptr;
LoadJobFn     g_orig_load_job     = nullptr;
DeathReloadFn g_orig_death_reload = nullptr;
PostEventFn   g_post_event        = nullptr;

std::atomic<std::uintptr_t> g_base{0};
std::atomic<bool>           g_exiting{false};   // see exiting() in the header
std::atomic<bool> g_installed{false};

// ---------------------------------------------------------------- policy
//
// Queue flags dropped before they are queued. The other bits pass: 4 (death
// reload, observed here and refused nowhere in stage 1), 0x4000 and 0x10000
// (the exit saves, whose write the save veto refuses while the exit itself
// proceeds), and anything this module has not catalogued, which is logged
// once per value so a new one is seen before it is judged.
constexpr std::uint32_t kFlagAutosave  = 0x1;
constexpr std::uint32_t kFlagManual    = 0x2;
constexpr std::uint32_t kFlagDeath     = 0x4;
constexpr std::uint32_t kFlagQuicksave = 0x8;
constexpr std::uint32_t kFlagQuickload = 0x10;
constexpr std::uint32_t kFlagQuicksaveCapture = 0x2000;   // rides with 8
constexpr std::uint32_t kFlagExitToMenu   = 0x4000;
constexpr std::uint32_t kFlagExitToDesktop = 0x10000;
constexpr std::uint32_t kDroppedFlags =
    kFlagAutosave | kFlagManual | kFlagQuicksave | kFlagQuickload | kFlagQuicksaveCapture;
constexpr std::uint32_t kKnownFlags =
    kDroppedFlags | kFlagDeath | kFlagExitToMenu | kFlagExitToDesktop;

constexpr int kDetourCount = 8;

// ---------------------------------------------------------------- state
thread_local int t_save_grant     = 0;
thread_local int t_commanded_load = 0;
// The death reload's own request: allowed by the stage-1 policy (the engine
// reloads the boot save; stage 3 replaces this with the server's respawn).
thread_local int t_death_reload   = 0;

std::atomic<int> g_load_request_depth{0};
std::atomic<int> g_load_job_depth{0};

// The verdict on the load request in flight, read by the load job on the
// loader thread: 0 no request (a job posted straight to the loader, the
// quickload path, gets no verdict and is refused), 1 allowed, 2 refused.
// One request is in flight at a time: the request pumps the main thread
// until its job is done. Nesting is handled by saving the previous value.
constexpr int kLoadNoRequest = 0;
constexpr int kLoadAllowed   = 1;
constexpr int kLoadRefused   = 2;
std::atomic<int> g_load_verdict{kLoadNoRequest};

std::atomic<std::uint64_t> g_queue_calls{0};
std::atomic<std::uint64_t> g_queue_dropped{0};
std::atomic<std::uint64_t> g_saves_vetoed{0};
std::atomic<std::uint64_t> g_saves_granted{0};
std::atomic<std::uint64_t> g_loads_requested{0};
std::atomic<std::uint64_t> g_loads_refused{0};
std::atomic<std::uint64_t> g_menu_loads_ignored{0};
std::atomic<std::uint64_t> g_load_jobs{0};
std::atomic<std::uint64_t> g_death_reloads{0};
std::atomic<std::uint64_t> g_settings_forced{0};

// ---------------------------------------------------------------- SEH helpers
//
// Kept out of the detours so those can hold objects with destructors.

std::uint32_t seh_u32_at(const void* p, std::size_t off) noexcept {
    if (!p) return 0;
    __try {
        return *reinterpret_cast<const std::uint32_t*>(
            reinterpret_cast<const std::uint8_t*>(p) + off);
    } __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
}

float seh_f32_at(const void* p, std::size_t off) noexcept {
    if (!p) return 0.0f;
    __try {
        return *reinterpret_cast<const float*>(
            reinterpret_cast<const std::uint8_t*>(p) + off);
    } __except (EXCEPTION_EXECUTE_HANDLER) { return 0.0f; }
}

const char* seh_cstr_at(const void* p, std::size_t off) noexcept {
    if (!p) return nullptr;
    __try {
        return *reinterpret_cast<const char* const*>(
            reinterpret_cast<const std::uint8_t*>(p) + off);
    } __except (EXCEPTION_EXECUTE_HANDLER) { return nullptr; }
}

// Copies at most n-1 characters of a string that may not be readable.
// Returns false (and an empty buffer) on a fault or a null pointer.
bool seh_copy_cstr(const char* s, char* out, std::size_t n) noexcept {
    if (!out || n == 0) return false;
    out[0] = '\0';
    if (!s) return false;
    __try {
        std::size_t i = 0;
        for (; i + 1 < n; ++i) {
            const char c = s[i];
            if (c == '\0') break;
            out[i] = c;
        }
        out[i] = '\0';
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        out[0] = '\0';
        return false;
    }
}

bool seh_read_u8(const void* p, std::uint8_t* out) noexcept {
    if (!p || !out) return false;
    __try {
        *out = *reinterpret_cast<const std::uint8_t*>(p);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

bool seh_write_u8(void* p, std::uint8_t v) noexcept {
    if (!p) return false;
    __try {
        *reinterpret_cast<std::uint8_t*>(p) = v;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

// A Setting object is {vtable, value at +8, name at +0x10}; `value_addr`
// points at the value. True when the name the object carries is exactly
// the one expected: the only proof this build's .data is the one the
// decomp describes, taken before any write.
bool setting_named(std::uintptr_t value_addr, const char* expected) noexcept {
    const char* name = seh_cstr_at(reinterpret_cast<const void*>(value_addr), 8);
    char buf[64];
    if (!seh_copy_cstr(name, buf, sizeof(buf))) return false;
    return std::strcmp(buf, expected) == 0;
}

bool seh_post_event(PostEventFn fn, std::int32_t type) noexcept {
    if (!fn) return false;
    struct { std::int32_t type; std::uint8_t flag; std::uint8_t pad[3]; } ev{type, 1, {0, 0, 0}};
    __try {
        fn(&ev);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

bool seh_back_out_from_load(BackOutFromLoadFn fn) noexcept {
    if (!fn) return false;
    __try {
        fn();
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

// ---------------------------------------------------------------- probe
//
// Stage 0 item (g): who saves, who loads, on which thread. Every detour
// reports its caller; the first eight hits of each (detour, caller) pair
// are logged in full and every 256th after that, so a leak shows up
// without a per-frame line.

std::mutex g_sites_mtx;
std::unordered_map<std::uint64_t, std::uint32_t> g_sites;

std::uintptr_t rva_of(const void* ret) noexcept {
    const auto base = g_base.load(std::memory_order_relaxed);
    const auto a = reinterpret_cast<std::uintptr_t>(ret);
    if (base && a >= base && a < base + 0x10000000ull) return a - base;
    return a;
}

// Returns true when this hit should be logged in full.
bool note_site(int kind, const void* ret) noexcept {
    const std::uint64_t key = (static_cast<std::uint64_t>(kind) << 56)
                            | (rva_of(ret) & 0x00FFFFFFFFFFFFFFull);
    std::lock_guard<std::mutex> lk(g_sites_mtx);
    const std::uint32_t n = ++g_sites[key];
    return n <= 8 || (n & 0xFF) == 0;
}

const char* thread_tag() noexcept {
    return GetCurrentThreadId() == fw::dispatch::main_thread_id() ? "main" : "other";
}

// ---------------------------------------------------------------- settings
//
// Forced in memory once per frame from the task processor, i.e. after the
// INI files were read and on the main thread. Fallout4Prefs.ini keeps its
// own copy of some of these (fAutosaveEveryXMins=10 sits there today) and
// the launcher only manages Fallout4Custom.ini, so the file is a courtesy
// and this is the guarantee. Each object is verified by name before its
// first write; a mismatch means the wrong binary and nothing is written.

struct BoolSetting {
    const char*    name;
    std::uintptr_t value_rva;
    std::uint8_t   want;
    int            verdict;     // 0 unknown, 1 verified, -1 refused
    bool           forced_logged;
};

BoolSetting g_bools[] = {
    {"bDisableAutoSave:SaveGame",          offsets::SETTING_DISABLE_AUTOSAVE_RVA,        1, 0, false},
    {"bAllowScriptedAutosave:SaveGame",    offsets::SETTING_ALLOW_SCRIPTED_AUTOSAVE_RVA, 0, 0, false},
    {"bAllowScriptedForceSave:SaveGame",   offsets::SETTING_ALLOW_SCRIPTED_FORCESAVE_RVA, 0, 0, false},
    {"bSaveOnRest",                        offsets::SETTING_SAVE_ON_REST_RVA,            0, 0, false},
    {"bSaveOnWait",                        offsets::SETTING_SAVE_ON_WAIT_RVA,            0, 0, false},
    {"bSaveOnTravel",                      offsets::SETTING_SAVE_ON_TRAVEL_RVA,          0, 0, false},
    {"bSaveOnPause",                       offsets::SETTING_SAVE_ON_PAUSE_RVA,           0, 0, false},
    {"bSaveGameOnQuitToMainMenu:General",  offsets::SETTING_SAVE_ON_QUIT_TO_MENU_RVA,    0, 0, false},
    {"bWorkshopAutoSaveOnExit:Workshop",   offsets::SETTING_WORKSHOP_AUTOSAVE_EXIT_RVA,  0, 0, false},
};

bool g_death_time_checked = false;

void enforce_settings() noexcept {
    const auto base = g_base.load(std::memory_order_relaxed);
    if (!base) return;
    for (auto& s : g_bools) {
        if (s.verdict < 0) continue;
        const std::uintptr_t value_addr = base + s.value_rva;
        if (s.verdict == 0) {
            if (!setting_named(value_addr, s.name)) {
                s.verdict = -1;
                FW_ERR("[lifecycle] setting %s not found at RVA 0x%llX (the "
                       "object there carries another name): left alone",
                       s.name, static_cast<unsigned long long>(s.value_rva));
                continue;
            }
            s.verdict = 1;
        }
        std::uint8_t cur = 0;
        if (!seh_read_u8(reinterpret_cast<const void*>(value_addr), &cur)) continue;
        if (cur == s.want) continue;
        if (seh_write_u8(reinterpret_cast<void*>(value_addr), s.want)) {
            g_settings_forced.fetch_add(1, std::memory_order_relaxed);
            if (!s.forced_logged) {
                s.forced_logged = true;
                FW_LOG("[lifecycle] setting %s forced %u -> %u in memory",
                       s.name, unsigned(cur), unsigned(s.want));
            } else {
                FW_DBG("[lifecycle] setting %s forced %u -> %u again",
                       s.name, unsigned(cur), unsigned(s.want));
            }
        }
    }
    if (!g_death_time_checked) {
        g_death_time_checked = true;
        const std::uintptr_t value_addr = base + offsets::SETTING_PLAYER_DEATH_RELOAD_TIME_RVA;
        if (setting_named(value_addr, "fPlayerDeathReloadTime")) {
            const float t = seh_f32_at(reinterpret_cast<const void*>(value_addr), 0);
            if (t > 0.0f) {
                FW_LOG("[lifecycle] fPlayerDeathReloadTime = %.2f s: the death "
                       "reload goes through the queue, where this module sees it", t);
            } else {
                FW_WRN("[lifecycle] fPlayerDeathReloadTime = %.2f: with a value "
                       "<= 0 the engine reloads through a MessageBox callback "
                       "that bypasses the queue; the death policy of stage 3 "
                       "needs it positive", t);
            }
        } else {
            FW_WRN("[lifecycle] fPlayerDeathReloadTime not found at its RVA; "
                   "the death reload path could not be checked");
        }
    }
}

// ---------------------------------------------------------------- detours

void __fastcall detour_queue(void* mgr, int flag) {
    const void* ret = _ReturnAddress();
    const std::uint32_t f = static_cast<std::uint32_t>(flag);
    const std::uint32_t dropped = f & kDroppedFlags;
    std::uint32_t kept = f & ~kDroppedFlags;
    g_queue_calls.fetch_add(1, std::memory_order_relaxed);
    const bool full = note_site(1, ret);

    if (dropped) {
        g_queue_dropped.fetch_add(1, std::memory_order_relaxed);
        if (full) {
            FW_LOG("[lifecycle] save/load request 0x%X from RVA 0x%llX (%s "
                   "thread): 0x%X dropped%s", f,
                   static_cast<unsigned long long>(rva_of(ret)), thread_tag(),
                   dropped, kept ? ", the rest queued" : "");
        }
    }
    if (kept == 0) return;

    if (kept & kFlagDeath) {
        g_death_reloads.fetch_add(1, std::memory_order_relaxed);
        char name[128];
        seh_copy_cstr(seh_cstr_at(mgr, offsets::SAVELOAD_MGR_RELOAD_NAME_OFF),
                      name, sizeof(name));
        // L5 stage 3c — the death policy: the respawn without a reload
        // takes the flag when it can (persist/death.cpp says when); the
        // reload of the last checkpoint runs otherwise, as in stage 3a.
        if (fw::persist::death::on_death_reload_queued(mgr)) {
            FW_LOG("[lifecycle] DEATH reload queued from RVA 0x%llX SWALLOWED: the respawn "
                   "without a reload takes it (target '%s' stays the reload target for the "
                   "fallback)", static_cast<unsigned long long>(rva_of(ret)),
                   name[0] ? name : "<none: main menu>");
            kept &= ~kFlagDeath;
            if (kept == 0) return;
        } else {
            FW_LOG("[lifecycle] DEATH reload queued from RVA 0x%llX: target '%s' (the last "
                   "checkpoint loaded or written); it runs",
                   static_cast<unsigned long long>(rva_of(ret)),
                   name[0] ? name : "<none: main menu>");
        }
    }
    if (kept & ~kKnownFlags) {
        if (full) {
            FW_WRN("[lifecycle] request 0x%X from RVA 0x%llX carries bits this "
                   "module has not catalogued (0x%X): queued as is, watch it",
                   f, static_cast<unsigned long long>(rva_of(ret)),
                   kept & ~kKnownFlags);
        }
    } else if (full && (kept & (kFlagExitToMenu | kFlagExitToDesktop))) {
        FW_LOG("[lifecycle] exit save request 0x%X from RVA 0x%llX queued; "
               "its write will be refused, the exit proceeds",
               kept, static_cast<unsigned long long>(rva_of(ret)));
        // L5 stage 3a — the last checkpoint: the player is leaving with the
        // world still loaded, and this is the save that keeps what happened
        // since the last commanded one. Written now, synchronously, before
        // the engine queues its own (refused) exit save. Then the last
        // digest (stage 2), best effort: the frames go out while the world
        // unloads, which takes seconds.
        const std::uintptr_t base = g_base.load(std::memory_order_relaxed);
        if (!g_exiting.load(std::memory_order_relaxed)) {
            fw::persist::checkpoint::run_now(mgr, fw::net::kCkptReasonExit);
            // L5 stage 3b — the bytes to the server before the process
            // goes: a few seconds at most, the next session catches up.
            fw::persist::checkpoint::wait_uploads(5000);
        }
        if (base) (void)fw::persist::inventory::capture_now(base, "exit");
        fw::persist::inventory::send_digest_now(fw::net::kInvDigestWhyExit);
        // From here on the world is going away: no tick of ours touches the
        // engine again until a new load starts.
        if (!g_exiting.exchange(true)) {
            FW_LOG("[lifecycle] exit in progress: world-spawn, capture and handle "
                   "resolution paused until the next load");
        }
    }
    if (g_orig_queue) g_orig_queue(mgr, static_cast<int>(kept));
}

std::uint32_t g_last_pending_logged = 0;

void __fastcall detour_process(void* mgr) {
    enforce_settings();
    // L5 stage 3c — the respawn without a reload, when one is pending:
    // before the checkpoint, so a checkpoint never runs on a dead player.
    fw::persist::death::run_pending(mgr);
    // The engine's own save point: a commanded checkpoint, if one is
    // pending, runs here and nowhere else (stage 2 test form, stage 3 real).
    fw::persist::checkpoint::run_pending(mgr);
    // Anything pending that the queue detour would have dropped got here by
    // a path this module does not own (the processor's own 0x200/0x400
    // follow-ups of 1 and 8 included). The save veto still stands; this
    // line is how such a path is found.
    const std::uint32_t pending = seh_u32_at(mgr, offsets::SAVELOAD_MGR_PENDING_FLAGS_OFF);
    const std::uint32_t leaked = pending & (kDroppedFlags | 0x200u | 0x400u);
    if (leaked && leaked != g_last_pending_logged) {
        g_last_pending_logged = leaked;
        FW_WRN("[lifecycle] pending flags 0x%X reached the task processor "
               "without passing the queue detour (0x%X of them are ones it "
               "drops); the save veto covers the write", pending, leaked);
    } else if (!leaked) {
        g_last_pending_logged = 0;
    }
    if (g_orig_process) g_orig_process(mgr);
}

std::int64_t __fastcall detour_named_save(void* mgr, const char* name,
                                          std::uint32_t a3, int a4, std::uint8_t a5)
{
    const void* ret = _ReturnAddress();
    char nm[128];
    seh_copy_cstr(name, nm, sizeof(nm));
    if (t_save_grant > 0) {
        g_saves_granted.fetch_add(1, std::memory_order_relaxed);
        FW_LOG("[lifecycle] save '%s' GRANTED (a3=%u a4=%d zlib=%u) from RVA "
               "0x%llX", nm[0] ? nm : "<auto>", a3, a4, unsigned(a5),
               static_cast<unsigned long long>(rva_of(ret)));
        return g_orig_named_save ? g_orig_named_save(mgr, name, a3, a4, a5) : 0;
    }
    g_saves_vetoed.fetch_add(1, std::memory_order_relaxed);
    if (note_site(2, ret)) {
        FW_LOG("[lifecycle] save '%s' REFUSED (a3=%u a4=%d zlib=%u) from RVA "
               "0x%llX on the %s thread: no grant, nothing written, the "
               "reload target is unchanged", nm[0] ? nm : "<auto>", a3, a4,
               unsigned(a5), static_cast<unsigned long long>(rva_of(ret)),
               thread_tag());
    }
    // The engine's own refusal posts event 6 ("You cannot save right now.")
    // under this exact condition; mirrored so the pause menu answers the
    // player the way the engine would.
    const std::uint32_t pending = seh_u32_at(mgr, offsets::SAVELOAD_MGR_PENDING_FLAGS_OFF);
    const bool autosave_name = nm[0] && _strnicmp(nm, "Autosave", 8) == 0;
    if (!autosave_name && (pending & kFlagManual) == 0) {
        seh_post_event(g_post_event, 6);
    }
    return 0;
}

char __fastcall detour_save_core(void* mgr, const char* name,
                                 std::uint32_t a3, int a4, std::uint8_t a5)
{
    const void* ret = _ReturnAddress();
    if (t_save_grant > 0) {
        return g_orig_save_core ? g_orig_save_core(mgr, name, a3, a4, a5) : 0;
    }
    // Every known caller is the named save above, already refused. A hit
    // here is a path that bypassed it, and worth a loud line.
    g_saves_vetoed.fetch_add(1, std::memory_order_relaxed);
    char nm[128];
    seh_copy_cstr(name, nm, sizeof(nm));
    if (note_site(3, ret)) {
        FW_WRN("[lifecycle] save core reached directly for '%s' from RVA "
               "0x%llX (%s thread) without a grant: refused",
               nm[0] ? nm : "<null>",
               static_cast<unsigned long long>(rva_of(ret)), thread_tag());
    }
    return 0;
}

// Who may load. The first live test (2026-09-27) showed why observing is
// not enough: the pause-menu Load went through (processor bit 0x40, caller
// sub_140BE9EC0), moved the player to another save's spawn, and because the
// loader stores every successful load at mgr+0x60 the next death reloaded
// THAT save instead of the boot one. So an uncommanded load while a world
// is loaded is refused. It is refused in the load JOB, never in the request:
// the loader itself returns 0 before touching the world when the file
// cannot be read, so every caller already handles "0, world intact" (the
// console prints an error, the processor frees the request and moves on),
// and mgr+0x60 is written only on success. In the main menu (no player in
// a cell) a load is let through: the menu's own state machine expects the
// loading screen and would sit in "loading" forever otherwise, and there is
// no world to protect there.
const char* load_verdict_for(bool commanded, bool* allowed) noexcept {
    if (commanded) { *allowed = true; return "commanded by us"; }
    if (t_death_reload > 0) {
        *allowed = true;
        return "the death reload, allowed by the stage-1 policy";
    }
    // The player's parent cell is populated only once a save has placed
    // the player; null means the main menu (or a fault, read as "no world").
    if (fw::engine::get_pc_parent_cell() == nullptr) {
        *allowed = true;
        return "NOT commanded, allowed: no world is loaded (main menu)";
    }
    *allowed = false;
    return "NOT commanded while a world is loaded: REFUSED in the load job";
}

std::int64_t __fastcall detour_load_request(void* mgr, const char* name,
                                            int a3, int a4, char a5, char a6)
{
    const void* ret = _ReturnAddress();
    char nm[128];
    seh_copy_cstr(name, nm, sizeof(nm));
    g_loads_requested.fetch_add(1, std::memory_order_relaxed);
    if (g_exiting.exchange(false)) {
        FW_LOG("[lifecycle] a load request after an exit: the modules paused at "
               "the exit resume with it");
    }
    bool allowed = false;
    const char* why = load_verdict_for(t_commanded_load > 0, &allowed);
    FW_LOG("[lifecycle] LOAD request '%s' (a3=%d a4=%d a5=%d a6=%d) from RVA "
           "0x%llX on the %s thread: %s%s", nm[0] ? nm : "<null>", a3, a4,
           int(a5), int(a6), static_cast<unsigned long long>(rva_of(ret)),
           thread_tag(), why,
           (allowed && a5) ? " (a5=1: it becomes the death-reload target)" : "");
    // L5 stage 3 — the world manifest of the save about to load, handed
    // over BEFORE the engine loads: the request is synchronous (six seconds
    // on the boot) and the world may tick inside it, so the purge must be
    // queued ahead of the first placement. A load that fails clears it.
    if (allowed) fw::persist::checkpoint::note_load_request(nm[0] ? nm : nullptr);
    const int prev_verdict = g_load_verdict.exchange(
        allowed ? kLoadAllowed : kLoadRefused, std::memory_order_seq_cst);
    g_load_request_depth.fetch_add(1, std::memory_order_acq_rel);
    std::int64_t r = 0;
    if (g_orig_load_request) r = g_orig_load_request(mgr, name, a3, a4, a5, a6);
    g_load_request_depth.fetch_sub(1, std::memory_order_acq_rel);
    g_load_verdict.store(prev_verdict, std::memory_order_seq_cst);
    FW_LOG("[lifecycle] LOAD request '%s' returned %lld", nm[0] ? nm : "<null>",
           static_cast<long long>(r));
    if (allowed && r == 0) fw::persist::checkpoint::note_load_request(nullptr);
    if (!allowed) {
        // A line of ours so the player knows it is a rule, not a broken
        // file. No engine event: SaveLoadMessageTypeEvent 5 turned out to be
        // "No quicksave found" on screen, not "failed to load".
        fw::render::chat::notice(
            "(loading a save is off: this world lives on the server)");
    }
    return r;
}

// The pause menu's "load this save" message, before it does anything. The
// menu's handler hides itself (sub_141B196B0(menu, 0)) and raises a
// transition flag (sub_1403A1710) BEFORE it queues the load, counting on the
// loading screen to take over; when the load was refused downstream nothing
// ever put the menu back, and the first live test ended with a blurred
// screen, no menu and no way out. Ignoring the message alone was not enough
// either (second test): the SWF side, having sent the load, waits for the
// menu to close and takes no input. The engine has the answer for that
// wait, used when the missing-content dialog is declined: the UI message
// "PauseMenuBackOutFromLoadGame", which makes the menu invoke the SWF's
// BackOutFromLoadGame and return the save list to the main list. The save
// message (9) is left to the named-save veto, whose "You cannot save right
// now." event the menu already handles (afterSaveLoadCheck).
void __fastcall detour_pause_menu(void* menu, void* message) {
    const std::uint32_t type = seh_u32_at(message, offsets::UI_MESSAGE_TYPE_OFF);
    if (type == offsets::PAUSE_MENU_MSG_LOAD_GAME && t_commanded_load == 0
            && fw::engine::get_pc_parent_cell() != nullptr) {
        g_menu_loads_ignored.fetch_add(1, std::memory_order_relaxed);
        const bool backed_out = seh_back_out_from_load(g_back_out_from_load);
        FW_LOG("[lifecycle] pause menu LOAD ignored while a world is loaded: "
               "nothing queued, %s",
               backed_out ? "the menu is sent back to its main list"
                          : "and the back-out message could not be posted");
        fw::render::chat::notice(
            "(loading a save is off: this world lives on the server)");
        return;
    }
    if (g_orig_pause_menu) g_orig_pause_menu(menu, message);
}

std::int64_t __fastcall detour_load_job(void* job) {
    const void* ret = _ReturnAddress();
    g_load_jobs.fetch_add(1, std::memory_order_relaxed);
    char nm[128];
    seh_copy_cstr(seh_cstr_at(job, 8), nm, sizeof(nm));
    const int verdict = g_load_verdict.load(std::memory_order_seq_cst);
    if (verdict != kLoadAllowed) {
        // 0 is what the loader returns for a file it cannot read: the world
        // is untouched, the reload target is untouched, the caller copes.
        g_loads_refused.fetch_add(1, std::memory_order_relaxed);
        FW_LOG("[lifecycle] load job '%s' REFUSED on the %s thread (tid=%lu) "
               "from RVA 0x%llX: %s; the world stays as it is",
               nm[0] ? nm : "<null>", thread_tag(),
               static_cast<unsigned long>(GetCurrentThreadId()),
               static_cast<unsigned long long>(rva_of(ret)),
               verdict == kLoadNoRequest
                   ? "posted straight to the loader with no request (quickload)"
                   : "the request was not commanded");
        return 0;
    }
    FW_LOG("[lifecycle] load job '%s' starts on the %s thread (tid=%lu) from "
           "RVA 0x%llX", nm[0] ? nm : "<null>", thread_tag(),
           static_cast<unsigned long>(GetCurrentThreadId()),
           static_cast<unsigned long long>(rva_of(ret)));
    g_load_job_depth.fetch_add(1, std::memory_order_acq_rel);
    std::int64_t r = 0;
    if (g_orig_load_job) r = g_orig_load_job(job);
    g_load_job_depth.fetch_sub(1, std::memory_order_acq_rel);
    FW_LOG("[lifecycle] load job '%s' done: %lld", nm[0] ? nm : "<null>",
           static_cast<long long>(r));
    return r;
}

char __fastcall detour_death_reload(void* mgr) {
    const void* ret = _ReturnAddress();
    char nm[128];
    seh_copy_cstr(seh_cstr_at(mgr, offsets::SAVELOAD_MGR_RELOAD_NAME_OFF),
                  nm, sizeof(nm));
    FW_LOG("[lifecycle] DEATH reload runs from RVA 0x%llX: target '%s'. "
           "Stage 1 policy: the engine reloads the boot save (no other load "
           "can change the target now); the respawn without a reload (server "
           "option, Sanctuary by default) is stage 3",
           static_cast<unsigned long long>(rva_of(ret)),
           nm[0] ? nm : "<none: main menu>");
    ++t_death_reload;
    const char r = g_orig_death_reload ? g_orig_death_reload(mgr) : 0;
    --t_death_reload;
    return r;
}

bool install_one(std::uintptr_t base, std::uintptr_t rva, void* detour,
                 void** original, const char* what)
{
    void* target = reinterpret_cast<void*>(base + rva);
    const bool ok = fw::hooks::install(target, detour, original);
    if (ok) {
        FW_LOG("[lifecycle] %s hooked at RVA 0x%llX", what,
               static_cast<unsigned long long>(rva));
    } else {
        FW_ERR("[lifecycle] %s NOT hooked at RVA 0x%llX: that path stays "
               "vanilla", what, static_cast<unsigned long long>(rva));
    }
    return ok;
}

} // namespace

// ---------------------------------------------------------------- public

int install_lifecycle(std::uintptr_t module_base, const fw::config::Settings& cfg) {
    if (!cfg.persist_lifecycle) {
        FW_LOG("[lifecycle] persist_lifecycle=false in fw_config.ini: the "
               "engine saves and loads as vanilla");
        return 0;
    }
    if (g_installed.exchange(true)) return 0;
    g_base.store(module_base, std::memory_order_release);
    g_post_event = reinterpret_cast<PostEventFn>(
        module_base + offsets::SAVELOAD_EVENT_POST_RVA);
    g_back_out_from_load = reinterpret_cast<BackOutFromLoadFn>(
        module_base + offsets::PAUSE_MENU_BACK_OUT_FROM_LOAD_RVA);

    int n = 0;
    n += install_one(module_base, offsets::SAVELOAD_QUEUE_RVA,
                     reinterpret_cast<void*>(&detour_queue),
                     reinterpret_cast<void**>(&g_orig_queue), "save/load queue") ? 1 : 0;
    n += install_one(module_base, offsets::SAVELOAD_PROCESS_RVA,
                     reinterpret_cast<void*>(&detour_process),
                     reinterpret_cast<void**>(&g_orig_process), "task processor") ? 1 : 0;
    n += install_one(module_base, offsets::SAVE_NAMED_RVA,
                     reinterpret_cast<void*>(&detour_named_save),
                     reinterpret_cast<void**>(&g_orig_named_save), "named save") ? 1 : 0;
    n += install_one(module_base, offsets::SAVE_CORE_RVA,
                     reinterpret_cast<void*>(&detour_save_core),
                     reinterpret_cast<void**>(&g_orig_save_core), "save core") ? 1 : 0;
    n += install_one(module_base, offsets::LOAD_GAME_FN_RVA,
                     reinterpret_cast<void*>(&detour_load_request),
                     reinterpret_cast<void**>(&g_orig_load_request), "load request") ? 1 : 0;
    n += install_one(module_base, offsets::LOAD_JOB_RVA,
                     reinterpret_cast<void*>(&detour_load_job),
                     reinterpret_cast<void**>(&g_orig_load_job), "load job") ? 1 : 0;
    n += install_one(module_base, offsets::DEATH_RELOAD_RVA,
                     reinterpret_cast<void*>(&detour_death_reload),
                     reinterpret_cast<void**>(&g_orig_death_reload), "death reload") ? 1 : 0;
    n += install_one(module_base, offsets::PAUSE_MENU_PROCESS_MESSAGE_RVA,
                     reinterpret_cast<void*>(&detour_pause_menu),
                     reinterpret_cast<void**>(&g_orig_pause_menu), "pause menu messages") ? 1 : 0;
    FW_LOG("[lifecycle] %d/%d detours installed; saves refused without a grant, "
           "autosave/manual/quicksave/quickload requests dropped, the pause "
           "menu's Load ignored and any other uncommanded load refused while a "
           "world is loaded (the death reload excepted)",
           n, kDetourCount);
    return n;
}

bool load_in_flight() noexcept {
    return g_load_request_depth.load(std::memory_order_acquire) > 0
        || g_load_job_depth.load(std::memory_order_acquire) > 0;
}

bool exiting() noexcept {
    return g_exiting.load(std::memory_order_acquire);
}

void requeue_death_reload(void* save_load_mgr) noexcept {
    if (!g_orig_queue || !save_load_mgr) return;
    FW_LOG("[lifecycle] DEATH reload re-queued by the death policy's fallback: the engine "
           "reloads the last checkpoint");
    g_orig_queue(save_load_mgr, static_cast<int>(kFlagDeath));
}

std::uint64_t loads_requested() noexcept {
    return g_loads_requested.load(std::memory_order_relaxed);
}

void note_exit() noexcept {
    if (!g_exiting.exchange(true)) {
        FW_LOG("[lifecycle] exit in progress (window close): world-spawn, capture and "
               "handle resolution paused until the next load");
    }
}

CommandedLoadScope::CommandedLoadScope()  { ++t_commanded_load; }
CommandedLoadScope::~CommandedLoadScope() { --t_commanded_load; }

SaveGrant::SaveGrant()  { ++t_save_grant; }
SaveGrant::~SaveGrant() { --t_save_grant; }

Stats stats() noexcept {
    return Stats{
        g_queue_calls.load(std::memory_order_relaxed),
        g_queue_dropped.load(std::memory_order_relaxed),
        g_saves_vetoed.load(std::memory_order_relaxed),
        g_saves_granted.load(std::memory_order_relaxed),
        g_loads_requested.load(std::memory_order_relaxed),
        g_loads_refused.load(std::memory_order_relaxed),
        g_menu_loads_ignored.load(std::memory_order_relaxed),
        g_load_jobs.load(std::memory_order_relaxed),
        g_death_reloads.load(std::memory_order_relaxed),
        g_settings_forced.load(std::memory_order_relaxed),
    };
}

} // namespace fw::persist
