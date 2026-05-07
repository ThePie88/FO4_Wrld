#include "main_menu_hook.h"

#include <windows.h>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <string>
#include <thread>

#include "../config.h"
#include "../engine/engine_calls.h"
#include "../ghost/actor_hijack.h"
#include "equip_hook.h"  // M9 w4 v9: FW_MSG_DEFERRED_MESH_TX
#include "../native/weapon_capture.h"  // M9.w4 PROPER (v0.4.2+): FW_MSG_WEAPON_CAPTURE_FINALIZE
#include "../native/spai_prewarm.h"    // SPAI Tier 1: FW_MSG_SPAI_PREWARM
// (synthetic_refr's earlier WM_APP message has been removed; the API is sync)
#include "../hook_manager.h"
#include "../log.h"
#include "../main_thread_dispatch.h"
#include "../native/scene_inject.h"
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

LRESULT CALLBACK fw_wndproc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
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
        const bool ok = fw::engine::load_game_by_name(g_save_name.c_str());
        if (!ok) {
            FW_WRN("[main_menu] LoadGame returned failure — main menu stays up");
            return 0;
        }
        // B8 — arm force-equip-cycle worker NOW (after LoadGame native
        // returns; timing measured from this point, not DLL inject).
        // 10s delay lands the cycle ~5s after the loading screen ends
        // (LoadGame is async — kicks off load, returns immediately;
        // loading screen typically takes 3-5s). The cycle fires before
        // any peer can connect (net thread handshake takes ~15s+ from
        // boot), satisfying the "before ghost spawn" precondition that
        // makes BipedAnim normalize work. Per user empirical validation
        // 2026-04-28: cycle pre-peer = no crash, post-peer = crash.
        // See offsets.h "B8 force-equip-cycle" for full rationale.
        fw::hooks::arm_equip_cycle_after_loadgame(10000);
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
