// B5 Step 1: hook IDXGISwapChain::Present via kiero-style vtable capture.
//
// Goal: get a per-frame callback inside Fallout4's D3D11 pipeline. The
// callback is the entry point for every future B5 step — hello-triangle
// overlay, static mesh draw, skinned body render, animated ghost.
//
// Approach (kiero pattern, references DLBB MILESTONE_TEXTURE_HOOK.md):
//   1. At DLL init time, create a minimal D3D11 device + dummy swapchain
//      on a hidden window. The swapchain's vtable is what we care about —
//      the actual device/swapchain is thrown away immediately after.
//   2. Read vtable slot 8 = IDXGISwapChain::Present. That function
//      pointer is process-wide (all IDXGISwapChain instances share the
//      same vtable in the same process), so hooking it once catches the
//      game's swapchain too.
//   3. MinHook on that pointer. Detour logs + passthrough for now.
//
// Feature-level requirement: D3D11 (feature level 11_0). FO4 NG is D3D11
// exclusive; no fallback needed.
//
// Why not IDXGIFactory proxy? We'd have to reimplement the full IDXGI
// COM surface passthrough (~15 methods). Kiero pattern is ~40 lines and
// equally reliable in practice.
//
// Thread safety: init is called once from the DLL init thread. The
// detour fires on the engine's render thread (same as the game's D3D11
// calls). Logging is already thread-safe via fw::log.

// 2026-08-08 — REVIVED for the character editor's overlay, and narrowed.
//
// This hook is not new and not unproven: it is what carried the whole of
// "Strada A" in April — MaleBody.fwn upload, the skinned vertex shader, the
// head placeholder, network-driven position — all of which dll_main records as
// "verified live". Strada A was abandoned over depth occlusion and view-matrix
// shake, never over this hook.
//
// That history is why the overlay uses it instead of detouring the game's own
// present wrapper at RVA 0x1817F60. A private wrapper would avoid any chance of
// colliding with ENB, ReShade or the Steam overlay on the process-shared DXGI
// vtable — a real argument — but it would mean discarding live-verified code for
// an untested reverse-engineered address. Two further points settle it:
// hooking Present itself means skipped frames never reach us at all (the game's
// wrapper is called on frames that do not present, and guarding that would be
// our problem), and both routes are reached from the same four call sites, so
// neither has a thread advantage.
//
// What DID change: the detour used to drive Strada A's renderer directly.
// Those calls are now behind arm_strada_a(), default off, because
// draw_triangle() lazily initialises itself from the swapchain — enabling this
// hook as it stood would have put a triangle back on screen.

#pragma once

#include <cstdint>

namespace fw::render {

// Initializes the Present hook. Returns true on success. Safe to call
// exactly once; subsequent calls return true without re-hooking.
//
// Must be called AFTER fw::hooks::init() because we rely on MinHook
// being ready. `module_base` is Fallout4.exe's base, used to resolve the
// renderer globals below.
bool init_present_hook(std::uintptr_t module_base);

// Arm the archived Strada A draw calls (triangle + body + camera probes).
// Default OFF. Nothing calls this today; it exists so reviving that path is a
// one-line change rather than an edit to the detour.
void arm_strada_a(bool on) noexcept;

// Optional: current frame counter (atomic load). Exposed for future
// diagnostics / frame-limited logic downstream.
unsigned long long frame_count();

// The game's own D3D11 objects, read from fixed globals rather than from the
// swapchain, so no QueryInterface and no refcount juggling is needed.
//
// Renderer data D lives at RVA 0x3A0F410 (a pointer to it is also kept at RVA
// 0x38CAAA0); device is D+0x48, context D+0x50, HWND D+0x58, swapchain D+0x70,
// and the back-buffer render target view D+0x88.
//
// The RTV matters most: reading the game's live one every frame means the
// overlay owns no render target, so there is nothing to release before the
// game's ResizeBuffers and nothing to rebuild after — every resolution change
// and fullscreen transition is handled for free.
//
// All fields are runtime-initialised, so these return null before the renderer
// has come up. MAIN THREAD, inside the frame.
struct GameD3D {
    void* device      = nullptr;
    void* context     = nullptr;
    void* swap_chain  = nullptr;
    void* backbuf_rtv = nullptr;
    void* hwnd        = nullptr;
};
GameD3D game_d3d() noexcept;

} // namespace fw::render
