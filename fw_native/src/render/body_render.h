// B5 Fase β — ghost body mesh rendering.
//
// Owns the CPU-side MeshAsset (loaded via fwn_loader from a .fwn file)
// AND the GPU-side ID3D11Buffer objects for the static mesh data
// (vertex buffer + index buffer). In β.1 we only do the GPU upload and
// log stats. β.2 adds the skinned vertex shader, β.3 adds the bone
// palette constant buffer, β.4 issues the actual indexed draw.
//
// Thread model:
//   init_body_asset()  — called from DllMain's init thread (off render)
//   draw_body()        — called every frame from the Present detour
//                        (game's D3D11 render thread)
//   release_body_*     — called from DLL_PROCESS_DETACH on unload
//
// The CPU→GPU handoff is synchronized via an acquire/release atomic
// flag so the render thread sees a fully-constructed MeshAsset before
// it reads from it.

#pragma once

#include <filesystem>

struct IDXGISwapChain;

namespace fw::render {

// Load a .fwn file from disk and retain the parsed MeshAsset for later
// GPU upload. Call ONCE at boot from the init thread (not the render
// thread — load_fwn does blocking I/O). Returns false on I/O, parse,
// or size-validation failure (all errors logged via FW_ERR).
//
// On success the asset is kept alive for the lifetime of the DLL (or
// until release_body_resources() is called).
bool init_body_asset(const std::filesystem::path& fwn_path);

// Render-thread entry point. Called every frame from the Present
// detour. On first call after init_body_asset succeeded, acquires the
// game's D3D11 device from the swapchain and uploads the mesh to GPU
// buffers (VB/IB) + installs the scene-render hook.
//
// After scene-render hook is installed, the actual body draw happens
// from draw_body_at_scene_end() (called by the hook detour). This
// function still handles:
//   - first-frame init (device acquisition, GPU upload, pipeline state)
//   - scene-render hook installation (once, after init succeeds)
//   - a fallback draw at Present if the scene-render hook failed to
//     install (so body is still visible, just with shake)
//
// Safe no-op if init_body_asset was never called or failed. Never
// throws — swallows all exceptions so a renderer bug cannot take down
// the game's frame.
void draw_body(IDXGISwapChain* swap);

// β.6 NEW: body draw issued from the scene-render hook
// (sub_140C38F80 trailing edge). At this moment in the frame the
// engine has:
//   - Just finished all 3D scene draw calls.
//   - VP matrix written to NiCamera+0x120 (frame-accurate).
//   - D3D state (RTV, DSV, shaders, CBs) still bound for scene.
// Our draw runs here and inherits frame-accurate timing → no shake.
// Safe no-op if the body hasn't been initialized yet (first-frame
// init still happens via draw_body at Present time).
void draw_body_at_scene_end();

// Release all CPU + GPU body resources. Idempotent; safe to call even
// if init_body_asset was never called.
void release_body_resources();

} // namespace fw::render
