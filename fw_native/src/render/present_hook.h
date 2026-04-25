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

#pragma once

namespace fw::render {

// Initializes the Present hook. Returns true on success. Safe to call
// exactly once; subsequent calls return true without re-hooking.
//
// Must be called AFTER fw::hooks::init() because we rely on MinHook
// being ready.
bool init_present_hook();

// Optional: current frame counter (atomic load). Exposed for future
// diagnostics / frame-limited logic downstream.
unsigned long long frame_count();

} // namespace fw::render
