// β.6 scene render hook — status: INSTALLED & FIRING but NOT usable
// for VP read as originally hypothesized.
//
// sub_140C38F80 @ RVA 0xC38F80 is the engine's 3D scene walker. Called
// ONCE per frame on the main thread, AFTER PlayerCamera::Update has
// published the frame's final view state, and BEFORE Scaleform UI
// composes. Hook install works, detour fires every frame.
//
// WHAT WE LEARNED (live test 2026-04-22):
// At the trailing edge of sub_140C38F80, the matrix at NiCamera+0x120
// does NOT contain the scene world-to-clip VP. Both col-vec and
// row-vec interpretations produce nonsensical NDC for a body that
// should be visible in front of the camera (clip.w negative in one
// case, NDC.y≈56 in the other). The matrix at that point is likely:
//   - A shadow-pass camera matrix that overwrites worldToCam after
//     the main scene draws, or
//   - The FirstPersonState's cached NiCamera is NOT the scene camera
//     (might be a HUD overlay / weapon sway / other), or
//   - The matrix gets updated mid-scene by a later sub-pass.
//
// WHAT THIS HOOK IS STILL GOOD FOR (future work):
//   - Depth buffer capture: at this moment the scene depth buffer is
//     fully populated. Useful for correct occlusion of bodies drawn
//     at Present time (β.6b or later).
//   - Integration with scene: injecting draws here ensures they're
//     after opaque geometry but before UI compositing.
//   - Custom post-process hooks: the scene RTV is still bound here.
//
// For VP capture, the next attempt should target:
//   - sub_140C38910 trailing edge (RenderGlobals publish point), OR
//   - The BSGraphics CB upload helpers (CB_Map_A/B @ 0x21A0680/5E0)
//     which write matrices directly into the GPU-bound constant buffer
//     — those bytes ARE what shaders read, no ambiguity.
//
// The hook installation happens AFTER body GPU upload (so we have a
// valid device/context) — triggered from body_render's first-frame init.
// Currently the body draw path via this hook is DISABLED (body falls
// back to Present-time draw) until a better VP source is identified.

#pragma once

#include <cstdint>

namespace fw::render {

// Install the scene-render detour. Idempotent: safe to call multiple
// times; returns true if already installed. Returns false on MinHook
// failure (which means body will fall back to Present-time draw).
bool install_scene_render_hook(std::uintptr_t module_base);

} // namespace fw::render
