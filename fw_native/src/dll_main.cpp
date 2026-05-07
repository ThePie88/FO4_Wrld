// DLL entry point. Bootstraps the FoM-lite native side inside Fallout4.exe.
//
// Order of operations (from init_thread):
//   1. Open the log file next to the DLL (= game root).
//   2. Verify Fallout4.exe version matches our RE fingerprint.
//   3. If match: init MinHook. In B0.2 no hooks are installed yet.
//      Hook installation lands in B0.3 (kill, container, pos tick).
//   4. On mismatch: STAY INERT. Still log + forward dxgi so the game boots
//      normally. The user is notified via fw_native.log and can update
//      this DLL (or revert FO4) to get hooks back.
//
// We do nothing meaningful in DllMain itself — loader lock rules. A
// separate thread does the real work after a small settle delay.

#include <windows.h>
#include <filesystem>
#include <string>

#include "config.h"
#include "log.h"
#include "version.h"
#include "hook_manager.h"
#include "hooks/install_all.h"
#include "net/client.h"
#include "engine/engine_calls.h"
#include "render/present_hook.h"
#include "render/body_render.h"
#include "assets/fwn_loader.h"
#include "ghost/actor_hijack.h"
#include "native/scene_inject.h"
#include "native/spai_prewarm.h"

namespace fs = std::filesystem;

namespace {

HMODULE g_self = nullptr;

fs::path self_directory() {
    wchar_t buf[MAX_PATH];
    const DWORD n = GetModuleFileNameW(g_self, buf, MAX_PATH);
    if (n == 0 || n == MAX_PATH) return fs::current_path();
    return fs::path(buf).parent_path();
}

DWORD WINAPI init_thread(LPVOID) {
    // Brief grace — give the loader time to settle before we touch the
    // filesystem. Also spreads load so we never compete for the loader
    // lock on a borderline path.
    Sleep(50);

    const auto dir = self_directory();

    // --- Load config BEFORE log.init so we honor log_level ---
    const auto cfg = fw::config::load(dir / "fw_config.ini");
    fw::log::Level lvl = fw::log::Level::Info;
    if      (cfg.log_level == "error") lvl = fw::log::Level::Error;
    else if (cfg.log_level == "warn")  lvl = fw::log::Level::Warn;
    else if (cfg.log_level == "debug") lvl = fw::log::Level::Debug;
    fw::log::init((dir / L"fw_native.log").wstring(), lvl);

    const DWORD pid = GetCurrentProcessId();
    const HMODULE game = GetModuleHandleW(L"Fallout4.exe");
    const auto base = reinterpret_cast<uintptr_t>(game);

    FW_LOG("=== FoM-lite B0.5 hello ===");
    FW_LOG("pid=%lu fallout4_base=0x%llX",
           pid, static_cast<unsigned long long>(base));
    FW_LOG("self_dir=%s", dir.string().c_str());

    if (!game) {
        FW_WRN("Fallout4.exe module handle null at init (early load); skipping version check");
        // Can't check version without the module; also can't install hooks
        // since our RVAs are relative to this module. Stay inert.
        return 0;
    }

    // --- Version gate ---
    std::string actual;
    const auto vr = fw::version::check(&actual);
    switch (vr) {
    case fw::version::Result::Match:
        FW_LOG("version: Fallout4.exe = %s (expected %s) OK",
               actual.c_str(), fw::version::EXPECTED);
        break;
    case fw::version::Result::Mismatch:
        FW_ERR("version MISMATCH: got %s, expected %s. "
               "RVAs from re/reference_fo4_offsets.md are NOT guaranteed to apply. "
               "Staying inert — no hooks will be installed. "
               "Rebuild this DLL against the new binary or revert the game.",
               actual.c_str(), fw::version::EXPECTED);
        return 0;
    case fw::version::Result::Unresolvable:
        FW_ERR("version: could not resolve Fallout4.exe VERSIONINFO. "
               "Staying inert as a precaution.");
        return 0;
    }

    // --- Engine call resolution (LookupByFormID, Disable/Enable) ---
    if (!fw::engine::init(base)) {
        FW_ERR("engine: resolver init failed — staying inert");
        return 0;
    }

    // --- MinHook bring-up ---
    if (!fw::hooks::init()) {
        FW_ERR("hook manager init failed — staying inert");
        return 0;
    }

    // --- Install hooks ---
    const auto summary = fw::hooks::install_all(base, cfg);
    FW_LOG("hooks: %zu/5 installed", summary.success_count());

    // --- STRADA A (custom D3D11) — DORMANT dal 2026-04-23 ---
    //
    // The pivot to Strada B (native Creation Engine integration —
    // BSFadeNode injection into ShadowSceneNode) was decided after
    // hitting depth-buffer issues with the D3D11 custom-render path.
    // Strada A code in src/render/* is left COMPILED but DORMANT for
    // reference / future retrofit (the ReShade-style DSV tracking +
    // pixel-shader depth discard plan is fully designed, just not
    // implemented).
    //
    // To re-enable Strada A:
    //   1. Uncomment the init_present_hook + init_body_asset block below.
    //   2. For the depth fix: implement ReShade strategy (draw-call
    //      tracking per DSV + ClearDepthStencilView hook +
    //      CopyResource backup + SRV-based depth discard in PS).
    //   3. Optionally hook BSGraphics::State viewProjMat to fix the
    //      VP shake (requires F4SE AddressLibrary RVA).
    //
    // What stays ACTIVE of Strada A even in dormant mode:
    //   - Nothing. Without init_present_hook + init_body_asset the
    //     custom rendering path doesn't run. Files are compile-only.
    //
    // Cosa di Strada A siamo sicuri FUNZIONI (verified live):
    //   - MaleBody.fwn load + upload GPU
    //   - Skinned vertex shader (col-major VP, identity bones T-pose)
    //   - Head placeholder sphere generator + render
    //   - Network remote pos/rot sync → body follows Client B
    //   - Pitch tracking via player rot[0]
    //
    // What did NOT work and triggered the pivot:
    //   - Depth occlusion (DSV capture catches shadow/post-proc, not scene)
    //   - Shake while walking (VP mismatch with the game's true VP)
    //   - Both require architecturally knowing which DSV is the main
    //     scene and which is the real game VP — long battles against
    //     the parallelism of our custom D3D11 pipeline.
    //
    // -----------------------------------------------------------------
    // === Strada A init — COMMENTED OUT (D3D11 custom renderer path) ===
    // -----------------------------------------------------------------
    // if (!fw::render::init_present_hook()) {
    //     FW_WRN("[render] Present hook init failed — B5 features disabled");
    // }
    // {
    //     const auto fwn_path = dir / "assets" / "compiled" / "MaleBody.fwn";
    //     if (!fs::exists(fwn_path)) {
    //         FW_WRN("[body] init: '%s' not found — body render disabled",
    //                fwn_path.string().c_str());
    //     } else if (!fw::render::init_body_asset(fwn_path)) {
    //         FW_ERR("[body] init_body_asset failed — body render disabled");
    //     }
    // }
    FW_LOG("[render] Strada A (custom D3D11) DORMANT — see "
           "docs/PIVOT_StradaA_to_StradaB.md");

    // --- STRADA B M1: native scene graph injection (2026-04-23) ---
    //
    // Arm a worker thread that, after a boot delay, posts
    // FW_MSG_STRADAB_INJECT to the main FO4 window. The WndProc subclass
    // (installed by main_menu_hook after auto_load_save LoadGame dispatch)
    // catches the message on the main thread and calls
    // fw::native::on_inject_message → inject_debug_node at a fixed test
    // position.
    //
    // 30s delay is conservative: MainMenu registrar usually fires within
    // a few seconds of boot, auto-load is scheduled 4s later, save load
    // itself takes 5-15s on NG. By 30s we should be in-world with SSN
    // populated.
    //
    // On success the log will show "[native] M1 INJECT: success" and
    // the player is free to move around — if 10+ frames pass without
    // crash, Strada B feasibility is PROVED.
    fw::native::arm_injection_after_boot(30000);
    FW_LOG("[native] Strada B M1: injection armed (30s delay)");

    // --- SPAI Tier 1: force-prewarm of weapon NIF resmgr (2026-05-05) ---
    //
    // Loads tools/spai_enum_weapons.py output (weapon_nif_catalog.manifest)
    // and dispatches one prewarm load per WM_APP message to the main
    // thread, throttled at ~12 ms/load. With ~1300 paths the full pass
    // completes in ~16 s of game time — comfortably inside the loading
    // screen + first 60 s of world play.
    //
    // Why prewarm: M9.w4 PROPER's RESMGR-LOOKUP path needs every shipped
    // weapon mod NIF in the engine resmgr so receivers can attach them
    // by m_name even without the local player ever having held them.
    // Without prewarm only what the receiver's player has personally
    // equipped is in the cache.
    //
    // Tier 2 (server-federated user-mod catalog) and Tier 3 (auto-learn
    // via OMOD RE) build on this same machinery — they only swap the
    // catalog source. See native/spai_prewarm.h for design.
    {
        const auto manifest =
            dir / "assets" / "weapon_nif_catalog.manifest";
        if (fw::native::spai::load_catalog(manifest)) {
            // 60 s delay > arm_injection_after_boot's 30 s + B8's
            // post-LoadGame 10 s cycle, so prewarm starts after the
            // engine's own auto-load + equip-cycle has settled.
            // 12 ms throttle: see header for rationale.
            fw::native::spai::arm_prewarm(/*delay_ms=*/ 60000,
                                           /*throttle_ms=*/ 12);
        } else {
            FW_WRN("[spai] catalog load failed — Tier 1 prewarm DISABLED. "
                   "Re-run tools/spai_enum_weapons.py and ensure the "
                   "manifest is deployed to <game>\\assets\\.");
        }
    }

    // Ghost module (Path B) kept dormant. init is a cheap no-op — no
    // spawn happens because the net trigger is commented out in
    // client.cpp dispatch.
    fw::ghost::init(base);

    // --- Start networking client (connects, HELLO handshake, main loop) ---
    if (!fw::net::client().start(cfg)) {
        FW_ERR("net: client failed to start — hooks are up but no sync");
    } else {
        FW_LOG("B0.5 complete — hooks + engine calls + network client ready. "
               "Awaiting WELCOME from %s:%u.",
               cfg.server_host.c_str(), cfg.server_port);
    }

    return 0;
}

} // namespace

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID /*reserved*/) {
    switch (reason) {
    case DLL_PROCESS_ATTACH: {
        g_self = hModule;
        DisableThreadLibraryCalls(hModule);
        const HANDLE h = CreateThread(nullptr, 0, init_thread, nullptr, 0, nullptr);
        if (h) CloseHandle(h);
        break;
    }
    case DLL_PROCESS_DETACH:
        fw::net::client().stop();
        fw::ghost::shutdown();
        fw::native::shutdown();               // Strada B M1 cleanup
        fw::render::release_body_resources();
        fw::hooks::stop_all();
        fw::hooks::shutdown();
        fw::log::close();
        break;
    }
    return TRUE;
}
