// B5 Step 2 — hello triangle overlay in world space.
//
// Goal: render a colored triangle anchored to a fixed offset from the
// player's current position, on every frame, via our Present hook. If
// the triangle appears reasonably near the player's view direction, it
// validates:
//   - We can acquire the game's D3D11 device/context from the swapchain
//   - We can compile HLSL at runtime via D3DCompile
//   - We can create VB/IB/CB/layout/shaders and bind them
//   - We can compute a view+proj matrix approximating the game's camera
//   - We can draw into the swapchain's back buffer without corrupting
//     the game's render state (saved + restored around our draw)
//
// Scope (choices locked by B5 Step 2 plan 2026-04-21):
//   - World-space 3D (not screen-space overlay) — direct path to Step 3
//     mesh rendering, no throwaway code.
//   - Post-UI render (we're at Present hook, after the game finished
//     its frame — we draw ON TOP of everything, including Pip-Boy).
//   - Create-once cached resources with device-reset handler (if
//     DXGI_ERROR_DEVICE_REMOVED fires, we mark dirty and recreate).
//   - HLSL compiled at runtime via D3DCompile (not precompiled blobs).
//     Gives us iteration speed without rebuild cycles.
//
// Timing: called from inside the Present detour BEFORE g_orig_present.
// If this function throws/fails, the detour logs and falls through to
// g_orig — the game never loses a frame because of us.

#pragma once

struct IDXGISwapChain;

namespace fw::render {

// Draw the triangle into the swapchain's current back buffer. Safe to
// call every frame; internally caches expensive resources. No-op if
// initialization has permanently failed (logged once).
void draw_triangle(IDXGISwapChain* swap_chain);

// Release all cached D3D resources. Called on DLL unload, or on device-
// reset detection. Idempotent.
void release_triangle_resources();

} // namespace fw::render
