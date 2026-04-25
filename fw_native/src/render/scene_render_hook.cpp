#include "scene_render_hook.h"
#include "body_render.h"

#include <windows.h>
#include <atomic>

#include "../hook_manager.h"
#include "../log.h"
#include "../offsets.h"

namespace fw::render {

namespace {

// sub_140C38F80 signature. Taken from RE report: "walks an array at
// a1+8 (count a1+24)" — so a1 is the only documented parameter. We
// declare 4 pointer args because x64 __fastcall always materializes
// RCX/RDX/R8/R9; if the function ignores the extra three that's a
// no-op, if it uses them they pass through unchanged via our detour.
using SceneWalkFn = void (__fastcall*)(void* a1, void* a2, void* a3, void* a4);

SceneWalkFn       g_orig_scene_walk = nullptr;
std::atomic<bool> g_hooked{false};
std::atomic<std::uint64_t> g_frame_count{0};

void __fastcall detour_scene_walk(void* a1, void* a2, void* a3, void* a4) {
    // Let the engine finish its 3D scene pass normally. After this
    // returns: all cells have been submitted, BSBatchRenderer has
    // dispatched draws, D3D state is still bound for scene, and
    // NiCamera+0x120 holds the VP that was used.
    if (g_orig_scene_walk) {
        g_orig_scene_walk(a1, a2, a3, a4);
    }

    const auto n = g_frame_count.fetch_add(1, std::memory_order_relaxed);
    if (n < 5) {
        FW_LOG("[scene_hook] frame #%llu — sub_140C38F80 trailing, "
               "about to inject body draw", n);
    } else if ((n % 600) == 0) {
        FW_DBG("[scene_hook] frame #%llu tick (heartbeat)", n);
    }

    // β.6 IMPORTANT: body draw via this hook is DISABLED.
    //
    // Live test 2026-04-22 showed NiCamera+0x120 at this hook point
    // does NOT hold the scene VP we need — it's some other matrix
    // (shadow? HUD overlay?) that produces nonsensical NDC for a
    // body in front of the camera. See scene_render_hook.h for
    // details. The hook remains installed because:
    //   (a) it's a proven useful render-stage entry point,
    //   (b) we'll reuse it for depth-buffer capture / integration
    //       once we source the scene VP from the correct place
    //       (RenderGlobals or CB_Map_A/B intercept).
    //
    // For now body falls back to Present-time draw (body_render sees
    // g_body.scene_hook_active=false via its own check and draws at
    // Present). Result: body visible WITH shake — known limit until
    // correct VP source is located.
}

} // namespace

bool install_scene_render_hook(std::uintptr_t module_base) {
    if (g_hooked.load(std::memory_order_acquire)) {
        FW_DBG("[scene_hook] already installed");
        return true;
    }
    if (!module_base) {
        FW_ERR("[scene_hook] install: module_base=0");
        return false;
    }

    void* target = reinterpret_cast<void*>(
        module_base + offsets::SCENE_RENDER_RVA);

    const bool ok = fw::hooks::install(
        target,
        reinterpret_cast<void*>(&detour_scene_walk),
        reinterpret_cast<void**>(&g_orig_scene_walk));
    if (!ok) {
        FW_ERR("[scene_hook] MinHook install FAILED at target=%p "
               "(RVA 0x%llX)",
               target,
               static_cast<unsigned long long>(offsets::SCENE_RENDER_RVA));
        return false;
    }

    g_hooked.store(true, std::memory_order_release);
    FW_LOG("[scene_hook] installed at %p (RVA 0x%llX) — body draw "
           "will run at scene-end instead of Present",
           target,
           static_cast<unsigned long long>(offsets::SCENE_RENDER_RVA));
    return true;
}

} // namespace fw::render
