#include "main_menu_hook.h"
#include "equip_announce.h"   // Fase 3

#include <windows.h>
#include <atomic>
#include <chrono>
#include <cstring>
#include <cstdint>
#include <string>
#include <thread>

#include "../config.h"
#include "../diag/crash_veh.h"  // Build 69r — note_user_shutdown (ALT+F4 marker)
#include "../engine/engine_calls.h"
#include "../ghost/actor_hijack.h"
#include "equip_hook.h"  // M9 w4 v9: FW_MSG_DEFERRED_MESH_TX
#include "container_hook.h"  // loot rework L3.4: container_activation_tick
#include "../native/weapon_capture.h"  // M9.w4 PROPER (v0.4.2+): FW_MSG_WEAPON_CAPTURE_FINALIZE
#include "../native/spai_prewarm.h"    // SPAI Tier 1: FW_MSG_SPAI_PREWARM
// (synthetic_refr's earlier WM_APP message has been removed; the API is sync)
#include "../hook_manager.h"
#include "../log.h"
#include "../native/world_spawn.h"
#include "../native/map_marker.h"      // L5 D2 experiment (2026-10-15): the test key
#include "../native/map_markers.h"     // L5 realtime D2 (2026-10-15): death crates and players on the map
#include "../native/ghost_lifecycle.h"
#include "../net/client.h"   // the goodbye when the window closes
#include "../main_thread_dispatch.h"
#include "../native/scene_inject.h"
#include "../native/chargen_dump.h"    // character-creation catalogue capture
#include "../native/anatomy_probe.h"   // read-only local player 3D walk
#include "../native/chargen_selftest.h" // one-shot appearance apply from our code
#include "../native/appearance_recipe.h" // v20: publish my appearance on change
#include "../render/editor_overlay.h"  // the panel, and its input capture
#include "../render/chat_overlay.h"    // phase 4: Enter opens the chat, the chat takes the keyboard
#include "../native/chargen_stage.h"     // 2026-08-08: stage the player for creation
#include "../persist/inventory_capture.h" // L5 stage 2: the player's inventory, read once a second
#include "../persist/inventory_restore.h" // L5 realtime R2: the record back into the game after a load
#include "../persist/player_stats.h"      // L5 realtime R4: the character's numbers
#include "../persist/checkpoint.h"        // L5 stage 2: the test checkpoint key
#include "../persist/lifecycle.h"         // 2026-09-28: exiting(), the whole tick stops with the world
#include "../native/face_borrow.h"       // v20: build peers' faces locally
#include "../offsets.h"
#include "equip_cycle.h"  // B8: WndProc dispatches FW_MSG_FORCE_EQUIP_CYCLE_*

namespace fw::hooks {

namespace {

// ----------------------------------------------------------------- hook #1
// sub_140B01290 — MainMenu Scaleform registrar. Binds AS3→C++ callbacks
// for the main menu. Called on the main thread while the menu is being
// constructed. We use this as a "main menu is starting up" trigger; we do
// NOT call LoadGame from here directly — that fires before the menu is
// input-ready and leaves the engine's render state stuck on the menu
// background ("black screen" observed in v3 live test).
//
// Instead the detour sets g_menu_detected; a background worker waits N
// seconds then PostMessage's a custom WM_APP to the FO4 window. A WndProc
// subclass we install on that window catches the message (on the main
// thread, which dispatches WndProc) and performs the real LoadGame call
// — by then the menu is fully visible and idle.
using MainMenuRegisterFn = void* (*)(void* menu_obj);
MainMenuRegisterFn g_orig_main_menu_register = nullptr;

// Fire-once guard for the dispatch pipeline.
std::atomic<bool> g_menu_detected{false};
std::atomic<bool> g_load_queued{false};
std::atomic<bool> g_load_dispatched{false};

// Settings snapshot captured at install time.
std::string g_save_name;
std::uint32_t g_delay_ms = 4000;   // v4 default: 4s after registrar hit
// L5 stage 3a — the boot: the genesis save from the ini, and what the
// server's word made of it (the checkpoint's name and record number, the
// outcome code for BOOT_RESULT). Written by the boot worker, read on the
// main thread after it posted the load message.
std::string   g_genesis_name;
std::string   g_boot_name;
std::uint32_t g_boot_seq = 0;
std::uint8_t  g_boot_outcome = 5;   // kBootOutcomeNoDecision until the worker decides
constexpr DWORD kBootWaitMs = 20000;   // how long the boot waits for CKPT_BOOT
// v30 — the last known position the server sent with the boot, applied
// once the loaded scene has settled (the fallback for an exit that left
// no checkpoint: a crash, a kill). Written by the boot worker, consumed
// on the main thread.
std::atomic<bool> g_boot_pos_pending{false};
float         g_boot_pos[3] = {0.0f, 0.0f, 0.0f};
float         g_boot_yaw = 0.0f;
std::uint64_t g_boot_pos_ms = 0;
DWORD         g_boot_pos_since_ms = 0;   // when the load was accepted; the settle wait starts here
constexpr DWORD kBootPosSettleMaxMs = 90000;

// The position fallback: one teleport of the local player, when the scene
// the load produced has settled. Main thread (the tick block).
void boot_position_tick() {
    if (!g_boot_pos_pending.load(std::memory_order_relaxed)) return;
    if (g_boot_pos_since_ms == 0) return;   // the load has not been accepted yet
    const DWORD now = GetTickCount();
    if (!fw::native::ghost_scene_settled() || fw::persist::load_in_flight()
            || fw::engine::get_pc_parent_cell() == nullptr) {
        if (now - g_boot_pos_since_ms > kBootPosSettleMaxMs) {
            g_boot_pos_pending.store(false, std::memory_order_relaxed);
            FW_WRN("[boot] last position NOT restored: the scene never settled in %u ms",
                   unsigned(kBootPosSettleMaxMs));
        }
        return;
    }
    g_boot_pos_pending.store(false, std::memory_order_relaxed);
    void* player = fw::engine::get_local_player();
    const bool ok = player && fw::engine::actor_teleport_handoff(
        player, g_boot_pos[0], g_boot_pos[1], g_boot_pos[2], g_boot_yaw);
    FW_LOG("[boot] last position %s: (%.1f, %.1f, %.1f) yaw %.2f, the server's word from "
           "after the checkpoint (%u ms after the load)",
           ok ? "restored" : "NOT restored (teleport failed)",
           g_boot_pos[0], g_boot_pos[1], g_boot_pos[2], g_boot_yaw,
           unsigned(now - g_boot_pos_since_ms));
}
// 2026-08-08 — virtual-key code that toggles the character editor, cached from
// the ini at install. Read on the main thread from the subclass below; there is
// no global config accessor in this project, every module is handed what it
// needs at init. 0 = the key is not configured.
std::uint32_t g_editor_key = 0;
std::uint32_t g_checkpoint_key = 0;   // L5 stage 2: asks for a test checkpoint
std::uint32_t g_map_marker_key = 0;   // L5 D2 experiment: a map marker made at runtime

// ----------------------------------------------------------------- WndProc subclass
//
// We replace the FO4 main-window WndProc. Our proc forwards all unrelated
// messages to the original via CallWindowProcW; when it sees our custom
// WM_APP it invokes LoadGame — guaranteed on the main thread because
// Win32 dispatches WndProc on whichever thread owns the window's message
// pump, and the main FO4 window is pumped by the engine's main thread.
constexpr UINT  FW_MSG_LOAD_GAME = WM_APP + 0x42;
HWND           g_fo4_hwnd        = nullptr;
WNDPROC        g_orig_wndproc    = nullptr;

// Find the FO4 main top-level window owned by our (this) process.
HWND find_fo4_hwnd() {
    struct Ctx { DWORD pid; HWND found; };
    Ctx ctx{ GetCurrentProcessId(), nullptr };
    EnumWindows([](HWND hwnd, LPARAM lp) -> BOOL {
        auto* c = reinterpret_cast<Ctx*>(lp);
        DWORD wpid = 0;
        GetWindowThreadProcessId(hwnd, &wpid);
        if (wpid != c->pid) return TRUE;
        if (!IsWindowVisible(hwnd)) return TRUE;
        wchar_t cls[64] = {};
        GetClassNameW(hwnd, cls, 63);
        if (std::wcscmp(cls, L"Fallout4") == 0) {
            c->found = hwnd;
            return FALSE;
        }
        return TRUE;
    }, reinterpret_cast<LPARAM>(&ctx));
    return ctx.found;
}

// The WndProc heartbeat.
//
// The tick block below is the only place in this project that touches the
// scene graph, and it runs once per window MESSAGE. What that means was
// measured on 2026-09-18: client A, first in and standing still, received B's
// join from the network at 15:03:14.462 and the main thread looked at it at
// 15:03:29.166. Fourteen seconds, seven of them in the queue, because a player
// who does not move generates no messages and rendering generates none at
// all. B's ghost appeared three seconds AFTER A's on the other client, which
// had done a whole load in the meantime.
//
// WM_TIMER is the right answer precisely because of how Windows treats it: it
// is synthesised only when the queue is empty, so it cannot add load when
// there is traffic already. It raises the FLOOR, from zero to thirty a second,
// and leaves the ceiling where it was. The modules in the block are all
// written as polls (self-throttled, idempotent, one of them literally says to
// retry "while the save is still loading") and already saw 26 to 40 messages a
// second whenever something moved: this makes idleness look like movement,
// not the other way round.
constexpr UINT_PTR kHeartbeatTimerId = 0xFA11;
constexpr UINT     kHeartbeatMs      = 33;

// THE HEARTBEAT IS THERE, BUT IT KEEPS QUIET WHILE THE ENGINE LOADS.
//
// The bisection of 2026-09-18 gave a clean answer: with the heartbeat on,
// client B died 19 seconds after rejoining; with it off it stayed alive past
// two minutes. Thirty extra ticks a second on the main thread, INSIDE the
// loading window, were what killed it, and that window the original design
// kept empty with a 15 to 30 second grace, for the reason the user had
// written down: loading things during the initial load crashed.
//
// So the heartbeat comes back where it is useful and goes away where it is
// lethal: off when LoadGame is invoked, on again when the gate declares the
// scene settled, which is 120 consecutive ticks AND at least two real seconds
// with no load in flight and no cell change. The user's grace, measured
// instead of timed.
//
// Outside a load it is needed: without it the tick block runs only on real
// messages, and a player standing still can go 14.7 seconds without a tick
// (measured), with a standing peer's join queued for all of that time.

LRESULT CALLBACK fw_wndproc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    // Armed from here and not from install_wndproc_subclass, because here it
    // is certain that this is the thread that owns the window, the only place
    // a window timer can be armed without questions. The heartbeat state lives
    // here for the same reason: SetTimer and KillTimer want the thread that
    // owns the window, and this is it.
    static bool s_heartbeat_on = false;
    {
        const bool want = fw::native::ghost_scene_settled();
        if (want && !s_heartbeat_on) {
            if (SetTimer(hwnd, kHeartbeatTimerId, kHeartbeatMs, nullptr)) {
                s_heartbeat_on = true;
                FW_LOG("[main_menu] tick heartbeat ON: the scene is settled, "
                       "WM_TIMER every %u ms so a standing-still player still "
                       "gets a tick", kHeartbeatMs);
            } else {
                FW_WRN("[main_menu] SetTimer failed (err=%lu) — the tick keeps "
                       "running only on real window messages", GetLastError());
            }
        } else if (!want && s_heartbeat_on) {
            KillTimer(hwnd, kHeartbeatTimerId);
            s_heartbeat_on = false;
            FW_LOG("[main_menu] tick heartbeat OFF: the scene is not settled "
                   "(a load, a cell change or a 3D rebuild) — staying out of "
                   "the engine's way until it is");
        }
    }

    // 2026-09-28 — from the exit save request on, every message of ours
    // (WM_APP range: container/door/lock/NPC applies, equip and mesh applies,
    // the SPAI prewarm, the ghost bone tick and pose applies) is dropped
    // unread: each of them does engine work, and the engine is going away.
    if (msg >= WM_APP && msg < WM_APP + 0x100 && fw::persist::exiting()) {
        return 0;
    }

    // L5 stage 2: the test checkpoint key. F10 (the default) is a SYSTEM key
    // on Windows: it arrives as WM_SYSKEYDOWN, never as WM_KEYDOWN, which is
    // why the first live test pressed it and nothing happened. Both messages
    // are accepted; the key only files the request, the save runs at the
    // engine's save point on a later frame. Swallowed, so F10 does not also
    // activate the window menu. Not while a chat line is being typed.
    if ((msg == WM_KEYDOWN || msg == WM_SYSKEYDOWN) && (lp & 0x40000000) == 0 &&
        !fw::render::chat::typing() && g_checkpoint_key != 0 &&
        static_cast<std::uint32_t>(wp) == g_checkpoint_key) {
        fw::persist::checkpoint::request_test("key");
        return 0;
    }
    // L5 D2 experiment (2026-10-15): the map marker test key, same shape
    // (both messages, no repeat, not while typing, swallowed). The engine
    // calls run here, on the main thread the window is pumped by.
    if ((msg == WM_KEYDOWN || msg == WM_SYSKEYDOWN) && (lp & 0x40000000) == 0 &&
        !fw::render::chat::typing() && g_map_marker_key != 0 &&
        static_cast<std::uint32_t>(wp) == g_map_marker_key) {
        fw::native::map_marker::on_test_key();
        return 0;
    }

    // THE TOGGLE KEY COMES FIRST. Before the editor is offered the message,
    // because the editor swallows WM_KEYDOWN while it is open — so handling the
    // toggle after it meant the key that CLOSES the panel could never arrive.
    // That is a trap-the-user bug and it existed for exactly one build.
    // Not while a chat line is being typed: F-keys make no WM_CHAR, so the
    // chat would not notice, and the panel would open under the text.
    if (msg == WM_KEYDOWN && (lp & 0x40000000) == 0 &&
        !fw::render::chat::typing()) {
        const std::uint32_t want = g_editor_key;
        if (want != 0 && static_cast<std::uint32_t>(wp) == want) {
            const bool now_open = !fw::native::appearance::editing();
            fw::native::appearance::set_editing(now_open);
            FW_LOG("[editor] key 0x%02X -> editor %s",
                   want, now_open ? "OPEN" : "CLOSED");
            // The key only moves the flag here too. overlay::on_frame takes and
            // releases the input capture from the flag itself, so a ritual the
            // server asked for gets the same capture a keypress would.
            // The key only moves the FLAG. chargen_stage::sync does the teleport
            // on the next tick, and that is the point: the staging used to hang
            // off this key handler, so a ritual the SERVER asked for opened the
            // panel and left the player on the ground. One driver now, whoever
            // asks.
            return 0;   // swallow it; nothing downstream wants this key
        }
        // CAMERA CALIBRATION KEY (F3), and it is deliberately hard-wired rather
        // than configurable: it is a temporary aid that disappears the moment the
        // camera's yaw offset is known. It sits here beside the toggle for the
        // same reason the toggle is first — the editor swallows WM_KEYDOWN while
        // it is open, so a key handled after it would never arrive.
        if ((static_cast<std::uint32_t>(wp) == VK_F3 ||
             static_cast<std::uint32_t>(wp) == VK_F4) &&
            fw::native::appearance::editing()) {
            fw::native::chargen_stage::nudge_camera_yaw(
                static_cast<std::uint32_t>(wp) == VK_F4);
            return 0;
        }
        if ((static_cast<std::uint32_t>(wp) == VK_F5 ||
             static_cast<std::uint32_t>(wp) == VK_F6) &&
            fw::native::appearance::editing()) {
            // F6 out, F5 in. A larger setting value is further away.
            fw::native::chargen_stage::nudge_camera_zoom(
                /*further=*/static_cast<std::uint32_t>(wp) == VK_F6);
            return 0;
        }
    }

    // THE EDITOR EATS INPUT NEXT, when it is open.
    //
    // Before anything else looks at the message, because while the panel is up
    // the mouse and keyboard belong to it. Returns true only for messages it
    // consumed; everything else falls through untouched, and when the editor is
    // closed this costs one atomic read.
    //
    // WM_ACTIVATE is never handed over: it is the only path that restores the
    // engine's input gate and resumes audio, so swallowing it would strand both.
    if (msg != WM_ACTIVATE &&
        fw::render::editor::wndproc(hwnd, msg, wp, lp)) {
        return (msg == WM_SETCURSOR) ? TRUE : 0;
    }
    // THE CHAT, after the editor and before the tick block. Closed, it wants
    // one message: a fresh Enter, which opens it. Open, it feeds the keyboard
    // to ImGui and keeps the game from reading keys and mouse, releases
    // excepted (chat_overlay.h). Everything it does not consume falls through
    // exactly as before, WM_ACTIVATE included.
    if (msg != WM_ACTIVATE &&
        fw::render::chat::wndproc(hwnd, msg, wp, lp)) {
        return 0;
    }
    // Build 67 — main-thread liveness heartbeat (stall watchdog forensics).
    // Win32 dispatches this proc on the window-owning thread = the game main
    // thread, so a stale heartbeat == the main thread stopped pumping.
    fw::dispatch::note_main_thread_alive();
    // Build 69r (2026-08-04) — user-requested ALT+F4 marker. A force-close
    // tears the process down with threads still running, and our
    // first-priority VEH faithfully logs the dying process's AVs as if they
    // were gameplay crashes (documented teardown signature 0x16632B9,
    // CHANGELOG v0.6.1) — which twice sent a crash hunt down a false trail.
    // Stamp the log the moment the close is requested and tell the VEH, so
    // every later AV line carries teardown=1.
    if (msg == WM_CLOSE ||
        (msg == WM_SYSCOMMAND && (wp & 0xFFF0) == SC_CLOSE)) {
        FW_LOG("ALT+F4 DETECTED BY USER — window close requested; any AV "
               "logged after this line is process-teardown fallout, NOT a "
               "gameplay crash");
        // L5 stage 3a — the last checkpoint, BEFORE the goodbye: a window
        // close is an exit the engine queues no save for, and the first
        // live test lost 50 s of walking to it. Written now, reported at
        // once on this thread; then the modules stand still for the
        // teardown, then the goodbye.
        if (!fw::persist::exiting()) {
            fw::persist::checkpoint::run_now_here(fw::net::kCkptReasonExit, /*immediate=*/true);
            // L5 stage 3b — the bytes to the server before the goodbye: a
            // few seconds at most, the next session catches up.
            fw::persist::checkpoint::wait_uploads(5000);
        }
        fw::persist::note_exit();
        fw::diag::note_user_shutdown();
        // The server is told WHILE this process can still speak. From here on
        // the process is going down and the network thread may never run
        // again, so the goodbye is sent at once, on this thread. Without it
        // the others see this player standing for another five seconds, and a
        // worn power armor does not return to the world until the timeout.
        fw::net::client().send_goodbye_now(/*reason=*/0);
    }
    // Build 68.4 — bone-cache lifetime sweep. Hosted here because this is the
    // one unconditional main-thread tick we have that keeps running regardless
    // of ownership, cell state or whether any NPC is being mirrored. It
    // self-throttles to ~250 ms internally.
    fw::native::sweep_npc_bone_caches();
    // 2026-08-06 — character-creation catalogue. Self-disarming: it walks
    // TESDataHandler's form arrays once, as soon as they hold anything, and
    // never runs again. A no-op unless the dump was armed from the ini.
    // 2026-08-08 — the editor toggle key. Handled BEFORE the appearance tick
    // below so that opening the editor and face_borrow standing aside happen on
    // the same frame, with no window in which a borrow could start.
    //
    // WM_KEYDOWN is safe to read here and cannot double-fire a game action: the
    // game's own window procedure has no WM_KEYDOWN case, it reads keyboard
    // exclusively through WM_INPUT, and it registers raw input with flags 0 (no
    // RIDEV_NOLEGACY) so the legacy messages are still generated for us.
    //
    // The repeat-count guard matters — holding the key down otherwise flips the
    // flag every auto-repeat.
    // THE TICK BLOCK DOES NOT RUN INSIDE ITSELF.
    //
    // Found on 2026-09-18 with the symbol map that had just been added:
    // client B hung for good right after the loading screen, its main thread
    // parked in a wait inside ntdll, and `fw_wndproc` was on the stack TWICE.
    // Only one reading fits: something in here calls the engine, the engine
    // pumps the message queue, and this WndProc re-enters while the previous
    // pass is still halfway through. If that pass holds a lock, and several
    // are taken in here, from the armour map to the canonical list, the
    // nested pass asks for it again, and a std::mutex is not reentrant. That
    // is the whole hang.
    //
    // Who pumps, in here: face_borrow calls Actor::Reset3D, chargen_stage
    // teleports, world_spawn places objects. All of them take a while during
    // a load.
    //
    // Why it blew up THEN is documented just as well: this block used to run
    // only on real messages, and with no ghost present the bone heartbeat
    // sent none. Since that day a WM_TIMER arrives every 33 ms and a bone tick
    // every 50, so the block runs DURING the load too, which is exactly the
    // window the old thirty-second grace kept clear "for safety, because
    // loading during the initial load crashed".
    //
    // The guard is a main-thread variable and nothing more: a nested pass
    // skips the block. Nothing is lost, because everything in here is a poll:
    // what this pass does not do, the next one does, thirty-three
    // milliseconds later.
    struct TickReentryGuard {
        static bool& flag() { static bool in_tick = false; return in_tick; }
        bool taken;
        TickReentryGuard() : taken(!flag()) { if (taken) flag() = true; }
        ~TickReentryGuard() { if (taken) flag() = false; }
    } tick_guard;
    // 2026-09-28 — and not after the exit save request: everything in here
    // polls the engine, and the engine is going away.
    if (tick_guard.taken && !fw::persist::exiting()) {
        static const std::uintptr_t s_base = reinterpret_cast<std::uintptr_t>(
            GetModuleHandleW(L"Fallout4.exe"));
        fw::native::chargen_dump::maybe_dump_catalogue(s_base);
        // 2026-08-07 — the anatomy probe MUST run here and nowhere else:
        // it reads the live scene graph, which is main-thread-only. The
        // chargen catalogue moved off this tick because the WndProc is not
        // installed when auto_load_save is empty; the probe does not have
        // that problem, since looking at the player presupposes a loaded
        // game and a loaded game presupposes this subclass.
        fw::native::anatomy_probe::maybe_dump(s_base);
        // 2026-08-08 — same reason as the probe above: it touches
        // engine appearance state and must be on the main thread.
        fw::native::chargen_selftest::maybe_run(s_base);
        // v20 — publish my appearance to the server when it changes.
        // Main thread: it reads the live TESNPC. Self-throttled.
        fw::native::appearance::publish_if_changed(s_base);
        // v20 — build any peer face we have a recipe for but no master.
        // One at a time; cheap when there is nothing to do.
        fw::native::face_borrow::tick(s_base);
        // Bring the staged world into line with the editor's flag: teleport up
        // when it goes on, back down when it goes off, retrying while the save
        // is still loading. Here rather than in Present because it teleports,
        // and the teleport has always run on this tick.
        fw::native::chargen_stage::sync(s_base);
        // And the input capture, for the same reason and in the same place. It is
        // also reconciled from overlay::on_frame, but that runs on Present's main
        // thread, which starts late: the log showed the capture landing ten
        // seconds after the server asked for the ritual, and the game reads the
        // mouse for every one of those seconds. This tick runs first. Both call
        // sites are idempotent -- they act only when the state disagrees.
        {
            const bool want = fw::native::appearance::editing();
            if (fw::render::editor::input_captured() != want) {
                fw::render::editor::set_input_captured(s_base, want);
            }
        }
        // Keeps collision off while staged; Reset3D undoes it.
        fw::native::chargen_stage::tick(s_base);
        // B6.14 - place spawned world objects the server relayed. Engine
        // work, so it lives on this tick like everything else that touches
        // the scene.
        fw::native::world_spawn::tick(s_base);
        // v30 — the boot's position fallback, once the loaded scene settled.
        boot_position_tick();
        // Phase 2: the peers' ghosts are born and die with the session
        // lifecycle instead of with a timer. It lives here for the same reason
        // as everything else: every scene graph mutation is main-thread only,
        // and this is the one unconditional tick there is.
        fw::native::ghost_lifecycle::tick(s_base);
        // Phase 3: the worn outfit, announced at every session start as soon
        // as the scene has settled. See equip_announce.h.
        fw::hooks::equip_announce_tick();
        // Loot rework L3.3: the containers the server knows are aligned when
        // the scene settles and at every change of cell, before the player
        // looks at them. See Client::container_sweep_tick.
        fw::net::client().container_sweep_tick();
        // Loot rework L3.4: a container activated before the engine built
        // its runtime list is aligned again as soon as the list exists.
        fw::hooks::container_activation_tick();
        // L5 stage 2: the player's inventory, read as the save writes it,
        // once a second, in observation only.
        fw::persist::inventory::tick(s_base);
        // L5 realtime R2: once the load after a boot or a death is over, the
        // player gets the server's record of the inventory back.
        fw::persist::restore::tick(s_base);
        // L5 realtime R4: XP, level, perks and SPECIAL, sent when they change.
        fw::persist::charstats::tick(s_base);
        // L5 realtime D2: the death crates and the other players on the map
        // and the compass (once a second inside).
        fw::native::map_markers::tick(s_base);
        // 2026-10-05: a player on foot left with the power armour race by a
        // death inside a frame gets the human race back (the Pip-Boy opened
        // blurred with no device at the wrist, every boot of that save).
        fw::engine::power_armor_race_watch();
    }
    // The heartbeat stops here: the tick block above has already consumed
    // it, and the game knows nothing about this timer.
    if (msg == WM_TIMER && wp == kHeartbeatTimerId) return 0;

    if (msg == FW_MSG_LOAD_GAME) {
        // We're on the main (UI) thread — MinHook-level guarantees don't
        // apply here (no MinHook involved), but Win32 semantics do:
        // WndProc is dispatched on the thread that owns the window.
        bool expected = false;
        if (!g_load_dispatched.compare_exchange_strong(expected, true)) {
            FW_DBG("[main_menu] FW_MSG_LOAD_GAME received but already dispatched");
            return 0;
        }
        FW_LOG("[main_menu] WM_APP+0x42 received on WndProc main thread — "
               "invoking engine LoadGame('%s')", g_save_name.c_str());
        // No ghost may be built while inside this call. It BLOCKS for seconds
        // (six, measured) and the engine pumps the message queue meanwhile.
        // Since 2026-09-18 the tick block above does not run inside itself
        // (TickReentryGuard), so nothing is drained from this WndProc during
        // the load; the bracket stays because the drain runs again on the
        // first pass after this call returns, and the scene is not stable
        // until the load has settled. See the gate above ghost_scene_is_stable.
        fw::native::ghost_note_load_begin();
        bool ok = fw::engine::load_game_by_name(g_save_name.c_str());
        fw::native::ghost_note_load_end();
        // L5 stage 3a — a checkpoint the engine refuses (rc 0: unreadable,
        // wrong version) falls back to the genesis save, and the server is
        // told so it counts a failed boot against that checkpoint.
        if (!ok && g_boot_outcome == fw::net::kBootOutcomeCheckpoint
                && !g_genesis_name.empty() && g_genesis_name != g_save_name) {
            FW_WRN("[boot] checkpoint '%s' was refused by the engine: the genesis "
                   "save '%s' boots instead", g_save_name.c_str(), g_genesis_name.c_str());
            g_boot_outcome = fw::net::kBootOutcomeLoadFailed;
            g_save_name = g_genesis_name;
            fw::native::ghost_note_load_begin();
            ok = fw::engine::load_game_by_name(g_save_name.c_str());
            fw::native::ghost_note_load_end();
        }
        {
            fw::net::BootResultPayload r{};
            r.seq     = g_boot_seq;
            r.outcome = g_boot_outcome;
            std::snprintf(r.name, sizeof(r.name), "%s", ok ? g_save_name.c_str() : "");
            r.wall_ms = static_cast<std::uint64_t>(
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count());
            fw::net::client().enqueue_boot_result(r);
            FW_LOG("[boot] BOOT_RESULT sent: outcome %u, loaded '%s' (checkpoint seq %u)",
                   unsigned(r.outcome), r.name, r.seq);
        }
        if (!ok) {
            g_boot_pos_pending.store(false, std::memory_order_relaxed);
            FW_WRN("[main_menu] LoadGame returned failure — main menu stays up");
            return 0;
        }
        g_boot_pos_since_ms = GetTickCount();   // v30: the settle wait of the position fallback
        // B8 force-equip-cycle — DISABLED 2026-05-08.
        //
        // Was: post-LoadGame BipedAnim normalize via direct engine call to
        // ActorEquipManager::Unequip + Equip on the Vault Suit. Workaround
        // for an M8P3-era ghost-pointer-sharing bug where the first equip
        // event after peer-connect crashed due to "semi-allocated"
        // BipedAnim state. See `re/B8_force_equip_cycle.log` and the
        // `offsets.h` "B8 force-equip-cycle" comment block for the
        // original architectural rationale.
        //
        // Why disabled: B8's engine call AV'd internally on every boot
        // (caught by our SEH wrapper, hidden from the user). The half-
        // completed equip left engine state subtly corrupted; the
        // corruption was dormant during normal play but surfaced as a
        // deterministic main-thread freeze when crossing the Sanctuary→
        // Red Rocket bridge — heavy exterior cell-streaming re-triggered
        // the corrupted auto-equip code path on a BSJobs PostMainRender
        // worker, killing it silently and wedging JobListMgr+0x60 on an
        // INFINITE wait. Live test 2026-05-08 confirmed: B8 enabled =
        // bridge crashes, B8 disabled = bridge works + clothes change
        // still works (the original M8P3 bug B8 was fixing has been
        // resolved as a side effect of later M9 work).
        //
        // The secondary role B8 played as a side effect — broadcasting
        // initial apparel state to peers via the engine equip events it
        // generated — is done by `hooks/equip_announce` since the session
        // lifecycle's phase 3 (2026-09-23): a passive read of the equipped
        // stacks of the local player's inventory at every session start, no
        // engine call. The May scaffold that stood in its place was never
        // invoked; it has been replaced, not wired up.
        //
        // Files left in repo for archeological reference:
        //   - hooks/equip_cycle.{h,cpp} (still compiled but never invoked)
        //   - offsets.h B8 block (rationale + RE'd engine fn signatures)
        //
        // To revive: uncomment the arm call below. Don't, until the
        // engine AV inside sub_140CE5900 is understood and fixed at the
        // arg/timing level — see `re/B8_force_equip_cycle.log` for the
        // deepest level of stack/arg analysis we have.
        // fw::hooks::arm_equip_cycle_after_loadgame(10000);
        return 0;
    }
    // B1.l: CONTAINER_BCAST apply. Drains any container ops that the net
    // thread enqueued via fw::dispatch::enqueue_container_apply. This is
    // the main-thread-safe counterpart to engine::apply_container_op_to_
    // engine — Bethesda's engine requires inventory mutations to happen
    // on the main thread, otherwise stale ContainerMenu view state can
    // corrupt the player's inventory (observed 2026-04-21 live test).
    if (msg == fw::dispatch::FW_MSG_CONTAINER_APPLY) {
        fw::dispatch::drain_container_apply_queue();
        return 0;
    }
    // B6.1: drain remote door-activate queue on main thread. Same rationale
    // as container apply — Activate worker fires anim graph notify which
    // mutates the scene's per-cell anim state; not net-thread-safe.
    if (msg == fw::dispatch::FW_MSG_DOOR_APPLY) {
        fw::dispatch::drain_door_apply_queue();
        return 0;
    }
    // B6.3 v0.5.3: drain remote lock events. Each op resolves form_id +
    // (base, cell) identity, then calls Papyrus binding sub_141158640
    // with ai_notify=0 — no minigame, no key consumption, no AI events.
    if (msg == fw::dispatch::FW_MSG_LOCK_APPLY) {
        fw::dispatch::drain_lock_apply_queue();
        return 0;
    }
    // B6.5w3.b: drain remote NPC state-broadcast entries. Each entry
    // resolves form_id, writes pos/yaw directly to Actor fields, and
    // sets anim graph variables to drive the engine's animation tree
    // (no AI suppression yet — B6.5w4 lands the local-tick filter).
    if (msg == fw::dispatch::FW_MSG_NPC_STATE_APPLY) {
        fw::dispatch::drain_npc_state_apply_queue();
        return 0;
    }
    // Build 65.c.10 — owner-driven STATE_FROM_OWNER apply (receiver side).
    // Drains entries the net thread queued from server-relayed owner state.
    if (msg == fw::dispatch::FW_MSG_NPC_OWNER_STATE_APPLY) {
        fw::dispatch::drain_npc_owner_state_apply_queue();
        return 0;
    }
    // Build 65.c.47 WEDGE3 — owner-driven DEATH_FROM_OWNER apply (non-owner
    // side). Drains relayed owner deaths: un-keyframe → place at synced pos →
    // engine Actor::Kill (under ApplyingRemoteGuard). Main-thread-required:
    // the engine death handler touches cell + anim + Havok state.
    if (msg == fw::dispatch::FW_MSG_NPC_DEATH_APPLY) {
        fw::dispatch::drain_npc_death_apply_queue();
        return 0;
    }
    // HP bar (vita-locale-dal-pool) — set each tracked NPC's LOCAL Health to the
    // shared server pool so the vanilla enemy-health bar reads it. Main-thread-
    // required (AVO getter + the HP funnel are main-thread-affine).
    if (msg == fw::dispatch::FW_MSG_NPC_POOL_HEALTH_APPLY) {
        fw::dispatch::drain_npc_pool_health_queue();
        return 0;
    }
    // B6.6w1: drain remote NPC fire events. Each op resolves form_id →
    // Actor* and calls engine::fire_actor_weapon — Projectile::Launch +
    // muzzle flash + audio + damage. Native fns touch equipManager +
    // projectile lists not lock-protected → main thread required.
    if (msg == fw::dispatch::FW_MSG_NPC_FIRE) {
        fw::dispatch::drain_npc_fire_queue();
        // Build 62 — drain perception trigger queue on the same wake-up.
        // Both queues need main-thread engine calls; sharing the WndProc
        // message avoids a second PostMessage round-trip. Order doesn't
        // matter (perception triggers cause CCF810 alloc, fires use the
        // result — but they're separately enqueued by net thread).
        fw::dispatch::drain_npc_perception_trigger_queue();
        return 0;
    }
    // M9 wedge 2: drain remote equip events. Each op resolves form_id →
    // ARMA → 3rd-person NIF path and attaches/detaches on the ghost.
    // Engine NIF loader + scene graph mutation = main-thread-required.
    // See offsets.h "M9 wedge 2" comment block for layout + flow.
    if (msg == fw::dispatch::FW_MSG_EQUIP_APPLY) {
        fw::dispatch::drain_equip_apply_queue();
        return 0;
    }
    // M9 wedge 4 v9: drain remote mesh-blob events. Each blob carries N
    // BSGeometry leaves (positions + indices + per-mesh metadata) and the
    // main thread reconstructs them on the matching ghost weapon root via
    // the engine's clone factory. Like equip apply, this MUST run on the
    // main thread (scene graph mutation; allocator TLS cookies).
    if (msg == fw::dispatch::FW_MSG_MESH_BLOB_APPLY) {
        fw::dispatch::drain_mesh_blob_apply_queue();
        return 0;
    }
    // M9 w4 v9 deferred mesh-tx: 300ms post-equip walker re-run on the
    // sender side. Lets the engine's runtime weapon assembly complete
    // before we capture mesh data → fixes "walker returned 0 meshes"
    // on rapid/subsequent equips.
    if (msg == fw::hooks::FW_MSG_DEFERRED_MESH_TX) {
        fw::hooks::on_deferred_mesh_tx_message();
        return 0;
    }
    // 2026-05-07 — auto re-equip cycle (sender-side workaround for the
    // off-by-one render bug on the ghost). See equip_hook.cpp on_auto_re_
    // equip_message comment block.
    if (msg == fw::hooks::FW_MSG_AUTO_RE_EQUIP) {
        fw::hooks::on_auto_re_equip_message(wp);
        return 0;
    }
    // SPAI Tier 1: force-prewarm one weapon NIF into the engine resmgr.
    // Posted by spai::prewarm_worker (background thread, throttled 1
    // post per ~10–15 ms) for each entry in the offline-generated weapon
    // catalog. Drives a single internal cursor — past the end is a
    // no-op modulo a one-shot summary log line.
    if (msg == fw::dispatch::FW_MSG_SPAI_PREWARM) {
        fw::native::spai::on_prewarm_message();
        return 0;
    }
    // M9.w4 PROPER (v0.4.2+, 2026-05-04): TTL expiration of a weapon capture
    // window. Worker thread spawned by weapon_capture::arm() posts this msg
    // after `ttl_ms` so finalize_and_ship() runs on the engine main thread
    // (where extraction + wire ship are safe). Phase 1: log-only finalize.
    if (msg == fw::native::weapon_capture::FW_MSG_WEAPON_CAPTURE_FINALIZE) {
        fw::native::weapon_capture::on_finalize_message();
        return 0;
    }
    // M9 closure (2026-05-07) note: an earlier iteration used a
    // FW_MSG_REFR_POLL pump for an async synthetic-REFR design. That
    // design was retired (see re/COLLAB_FOLLOWUP_vt170.md — vt[170]
    // was a flag-setter, not a loader). The current path is fully
    // synchronous (synthetic_refr::assemble_modded_weapon returns
    // BSFadeNode* directly), so no pump is needed here.
    // Z.2 (Path B): spawn ghost actor on main thread. PlaceAtMe is
    // TLS-sensitive and takes the REFR cell-attach lock — must run
    // here, not on the net thread where request_spawn is issued.
    if (msg == fw::ghost::FW_MSG_SPAWN_GHOST) {
        fw::ghost::on_spawn_message();
        return 0;
    }
    // Strada B M1: attach a debug NiNode to the ShadowSceneNode. Main-
    // thread affinity required (scene graph array has implicit locks held
    // by the render walk; our allocator call writes TLS cookies). Posted
    // by fw::native::arm_injection_after_boot's worker ~30s after DLL init.
    if (msg == fw::native::FW_MSG_STRADAB_INJECT) {
        fw::native::on_inject_message();
        return 0;
    }
    // Strada B M3: per-frame cube position update from remote snapshot.
    // Posted by fw::native::arm_worker's tracker loop (up to ~10/sec).
    if (msg == fw::native::FW_MSG_STRADAB_POS_UPDATE) {
        fw::native::on_pos_update_message();
        return 0;
    }
    // Strada B M7.b: bone-copy tick from local player to ghost. Posted
    // by bone_tick_worker at 20Hz. Runs regardless of peer activity.
    if (msg == fw::native::FW_MSG_STRADAB_BONE_TICK) {
        fw::native::on_bone_tick_message();
        return 0;
    }
    // M8P3.15: apply received remote pose (POSE_BROADCAST) to ghost.
    // Posted by net thread after stashing quats into shared slot.
    if (msg == fw::native::FW_MSG_STRADAB_POSE_APPLY) {
        fw::native::on_pose_apply_message();
        return 0;
    }
    // v16: apply received remote crouch (POSE_CROUCH_BROADCAST) to ghost —
    // SEPARATE additive channel beside the rotation pose above. Posted by
    // net thread after stashing the COM/Pelvis translations.
    if (msg == fw::native::FW_MSG_STRADAB_CROUCH_APPLY) {
        fw::native::on_pose_crouch_apply_message();
        return 0;
    }
    // c.37.0: apply received NPC pose (NPC_POSE_FROM_OWNER) to the mirror
    // Actor. Posted by net thread after stashing quats into the per-fid slot.
    if (msg == fw::native::FW_MSG_STRADAB_NPC_POSE_APPLY) {
        fw::native::on_npc_pose_apply_message();
        return 0;
    }
    // B8: post-LoadGame BipedAnim normalize cycle. Two-phase:
    //   - WM_APP+0x4A → unequip Vault Suit
    //   - WM_APP+0x4B → re-equip Vault Suit (500ms later, posted by worker)
    // Both run on this thread (main/UI thread guaranteed by Win32 WndProc
    // dispatch). Engine ActorEquipManager calls take per-actor locks +
    // mutate BipedAnim — main-thread is required.
    // See offsets.h "B8 force-equip-cycle" comment block for rationale.
    if (msg == (WM_APP + 0x4A)) {
        fw::hooks::on_force_equip_cycle_unequip_message();
        return 0;
    }
    if (msg == (WM_APP + 0x4B)) {
        fw::hooks::on_force_equip_cycle_equip_message();
        return 0;
    }
    // Forward everything else to the original WndProc.
    if (g_orig_wndproc) {
        return CallWindowProcW(g_orig_wndproc, hwnd, msg, wp, lp);
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

// Install the WndProc subclass once we have a valid HWND. Called from the
// worker thread after the main menu registrar has fired (by then the
// window definitely exists — it had to exist to render the menu anyway).
bool install_wndproc_subclass() {
    if (g_orig_wndproc) return true;  // already installed
    g_fo4_hwnd = find_fo4_hwnd();
    if (!g_fo4_hwnd) {
        FW_WRN("[main_menu] find_fo4_hwnd returned nullptr — cannot subclass WndProc");
        return false;
    }
    // SetWindowLongPtrW returns the previous value (original WndProc).
    // We save it for CallWindowProcW forwarding.
    const LONG_PTR prev = SetWindowLongPtrW(
        g_fo4_hwnd, GWLP_WNDPROC,
        reinterpret_cast<LONG_PTR>(&fw_wndproc));
    if (prev == 0) {
        FW_ERR("[main_menu] SetWindowLongPtr(GWLP_WNDPROC) failed (err=%lu)",
               GetLastError());
        return false;
    }
    g_orig_wndproc = reinterpret_cast<WNDPROC>(prev);
    FW_LOG("[main_menu] WndProc subclassed on hwnd=%p (orig=%p)",
           g_fo4_hwnd, g_orig_wndproc);

    // B1.l: share the HWND with the main-thread dispatch queue so net
    // thread can post FW_MSG_CONTAINER_APPLY for remote container ops.
    fw::dispatch::set_target_hwnd(g_fo4_hwnd);
    return true;
}

// ----------------------------------------------------------------- worker
//
// Background thread:
//   1) Waits for g_menu_detected (set by the MainMenu registrar detour).
//   2) Sleeps g_delay_ms to let the menu fully render + become idle.
//   3) Installs WndProc subclass on FO4 hwnd.
//   4) PostMessage(FW_MSG_LOAD_GAME) → main thread catches it via WndProc.
std::thread g_worker_thread;
std::atomic<bool> g_worker_should_stop{false};

void worker_thread_main() {
    FW_LOG("[main_menu] worker armed, delay=%ums after registrar hit",
           g_delay_ms);
    while (!g_worker_should_stop.load() && !g_menu_detected.load()) {
        Sleep(50);
    }
    if (g_worker_should_stop.load()) return;

    const auto t0 = std::chrono::steady_clock::now();
    const auto deadline = t0 + std::chrono::milliseconds(g_delay_ms);
    while (std::chrono::steady_clock::now() < deadline) {
        if (g_worker_should_stop.load()) return;
        Sleep(50);
    }

    // L5 stage 3a — which save boots: the server's word, up to 20 s. The
    // session was opened at DLL start, so CKPT_BOOT (the first bootstrap
    // stage) is normally here long before the menu is; the wait is for a
    // slow server, and its end is the genesis save, said in the log.
    if (!g_genesis_name.empty()) {
        const auto b0 = std::chrono::steady_clock::now();
        fw::net::Client::BootCheckpoint bc{};
        int st = 0;
        while (std::chrono::steady_clock::now() - b0 < std::chrono::milliseconds(kBootWaitMs)) {
            if (g_worker_should_stop.load()) return;
            st = fw::net::client().boot_decision(&bc);
            if (st != 0) break;
            Sleep(100);
        }
        const unsigned waited = static_cast<unsigned>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - b0).count());
        if (st == 0) {
            g_boot_outcome = fw::net::kBootOutcomeNoDecision;
            FW_LOG("[boot] no word from the server in %u ms: the genesis save '%s' boots",
                   waited, g_genesis_name.c_str());
        } else if (st == 1) {
            g_boot_outcome = fw::net::kBootOutcomeNoneOffered;
            FW_LOG("[boot] the server has no checkpoint for this identity: the genesis "
                   "save '%s' boots", g_genesis_name.c_str());
        }
        // v30 — the last known position, for either decision.
        if (st != 0 && bc.has_pos) {
            g_boot_pos[0] = bc.pos[0]; g_boot_pos[1] = bc.pos[1]; g_boot_pos[2] = bc.pos[2];
            g_boot_yaw = bc.yaw;
            g_boot_pos_ms = bc.pos_ms;
            g_boot_pos_pending.store(true, std::memory_order_relaxed);
            FW_LOG("[boot] the server also sent a last position newer than the save: "
                   "(%.1f, %.1f, %.1f); applied once the scene has settled",
                   bc.pos[0], bc.pos[1], bc.pos[2]);
        }
        if (st == 2) {
            char why[96] = "";
            const int v = fw::persist::checkpoint::verify_file(bc.name, bc.sha256, bc.size,
                                                               why, sizeof(why));
            g_boot_seq  = bc.seq;
            g_boot_name = bc.name;
            if (v == 0) {
                g_save_name    = bc.name;
                g_boot_outcome = fw::net::kBootOutcomeCheckpoint;
                FW_LOG("[boot] checkpoint '%s' verified on disk (%u bytes, sha256 matches "
                       "the record, %u ms): it boots instead of '%s'", bc.name, bc.size,
                       waited, g_genesis_name.c_str());
            } else {
                // L5 stage 3b — not on this disk (another machine, a wiped
                // Saves folder) or not the recorded bytes: the server's
                // custody, then the older candidates, on this disk or
                // fetched, newest first. Only then the genesis save.
                FW_LOG("[boot] checkpoint '%s' is not usable on this disk (%s): trying the "
                       "server's custody and the older checkpoints", bc.name, why);
                bool booted = false;
                for (std::uint8_t i = 0; i < bc.n_candidates && !booted; ++i) {
                    const fw::net::CkptCandidate& c = bc.candidates[i];
                    char cname[fw::net::kCkptNameLen];
                    std::memcpy(cname, c.name, sizeof(cname));
                    cname[sizeof(cname) - 1] = '\0';
                    if (!cname[0]) continue;
                    const bool is_pick = std::strcmp(cname, bc.name) == 0;
                    char cw[96] = "";
                    int cv = is_pick ? v
                                     : fw::persist::checkpoint::verify_file(cname, c.sha256, c.size,
                                                                            cw, sizeof(cw));
                    const char* how = "on this disk";
                    if (cv != 0) {
                        if (!c.custody) {
                            FW_LOG("[boot] candidate '%s': not on this disk and not in the "
                                   "server's custody", cname);
                            continue;
                        }
                        cv = fw::persist::checkpoint::fetch_from_custody(cname, c.sha256, c.size,
                                                                         cw, sizeof(cw));
                        how = "fetched from the server's custody";
                        if (cv != 0) {
                            FW_WRN("[boot] candidate '%s': fetch failed (%s)", cname, cw);
                            continue;
                        }
                    }
                    g_save_name    = cname;
                    g_boot_name    = cname;
                    g_boot_seq     = c.seq;
                    g_boot_outcome = fw::net::kBootOutcomeCheckpoint;
                    FW_LOG("[boot] checkpoint '%s' (%s%s) boots instead of '%s'", cname, how,
                           is_pick ? "" : ", an older checkpoint", g_genesis_name.c_str());
                    booted = true;
                }
                if (!booted) {
                    g_boot_outcome = (v == 2) ? fw::net::kBootOutcomeMissing
                                              : fw::net::kBootOutcomeMismatch;
                    FW_WRN("[boot] checkpoint '%s' NOT usable (%s) and no candidate could be "
                           "had: the genesis save '%s' boots; the server is told",
                           bc.name, why, g_genesis_name.c_str());
                }
            }
        }
    }

    // Now the menu should be fully visible and idle. Install subclass +
    // post the message.
    bool expected = false;
    if (!g_load_queued.compare_exchange_strong(expected, true)) {
        FW_DBG("[main_menu] worker: load already queued");
        return;
    }
    if (!install_wndproc_subclass()) {
        FW_ERR("[main_menu] worker: subclass install failed — LoadGame will NOT fire");
        return;
    }
    if (!PostMessageW(g_fo4_hwnd, FW_MSG_LOAD_GAME, 0, 0)) {
        FW_ERR("[main_menu] worker: PostMessage failed (err=%lu)", GetLastError());
    } else {
        FW_LOG("[main_menu] worker: FW_MSG_LOAD_GAME posted to hwnd=%p", g_fo4_hwnd);
    }
}

// ----------------------------------------------------------------- detour

void* __fastcall detour_main_menu_register(void* menu_obj) {
    // Let the original registrar complete first — AS3 bindings must be in
    // place or the menu breaks.
    void* rv = g_orig_main_menu_register(menu_obj);

    // One-shot detection. MinHook invokes the detour on the caller's
    // thread, so this runs on the engine's main UI thread.
    bool expected = false;
    if (!g_menu_detected.compare_exchange_strong(expected, true)) {
        FW_DBG("[main_menu] registrar re-entry (submenu) — ignoring");
        return rv;
    }

    if (g_save_name.empty()) {
        FW_LOG("[main_menu] registrar hit (menu_obj=%p) — auto-load disabled "
               "(auto_load_save empty in fw_config.ini)", menu_obj);
        return rv;
    }

    FW_LOG("[main_menu] registrar hit (menu_obj=%p) — deferred LoadGame "
           "scheduled in %ums (worker thread will post WM_APP to WndProc)",
           menu_obj, g_delay_ms);
    return rv;
}

} // namespace

bool install_main_menu_hook(std::uintptr_t module_base,
                            const fw::config::Settings& cfg)
{
    g_save_name = cfg.auto_load_save;
    g_genesis_name = cfg.auto_load_save;
    g_editor_key = cfg.editor_key;
    g_checkpoint_key = cfg.checkpoint_test_key;
    g_map_marker_key = cfg.map_marker_test_key;
    if (g_editor_key) {
        FW_LOG("[editor] toggle key armed: virtual-key 0x%02X", g_editor_key);
    }
    // Reuse `auto_continue_delay_ms` as the worker delay. Clamp so a
    // misconfigured 0 doesn't race the menu.
    g_delay_ms = cfg.auto_continue_delay_ms;
    if (g_delay_ms < 1000)  g_delay_ms = 1000;
    if (g_delay_ms > 30000) g_delay_ms = 30000;

    const auto target_ea = module_base + offsets::MAIN_MENU_REGISTRAR_RVA;
    void* target = reinterpret_cast<void*>(target_ea);

    const bool ok = install(
        target,
        reinterpret_cast<void*>(&detour_main_menu_register),
        reinterpret_cast<void**>(&g_orig_main_menu_register));
    if (!ok) {
        FW_ERR("[main_menu] hook install FAILED at 0x%llX",
               static_cast<unsigned long long>(target_ea));
        return false;
    }
    if (g_save_name.empty()) {
        FW_LOG("[main_menu] hook installed at 0x%llX — auto_load_save empty, "
               "no load action configured",
               static_cast<unsigned long long>(target_ea));
        return true;  // don't spin worker if nothing to do
    }

    FW_LOG("[main_menu] hook installed at 0x%llX — auto-load target: '%s' "
           "(delay %ums after registrar hit)",
           static_cast<unsigned long long>(target_ea),
           g_save_name.c_str(), g_delay_ms);

    // Spawn worker thread. Detached; lifecycle tied to process exit.
    g_worker_thread = std::thread(&worker_thread_main);
    g_worker_thread.detach();
    return true;
}

} // namespace fw::hooks
