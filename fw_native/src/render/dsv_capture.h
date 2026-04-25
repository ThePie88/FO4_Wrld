// B5 β.6 — DSV capture via ID3D11DeviceContext::OMSetRenderTargets hook.
//
// Why: when our Present hook fires, the game has already unbound its
// depth buffer in preparation for UI composite. To get depth occlusion
// on our body render we need to capture the scene DSV EARLIER in the
// frame — during the game's 3D pass. We do that by detouring slot 33
// of the device context vtable (OMSetRenderTargets) and snapshotting
// the DSV pointer every time the game binds one.
//
// Snapshot semantics: "last non-null DSV set in the frame". Because
// games typically issue: shadows(smaller DSV) → scene(full-screen DSV)
// → UI(nullDSV), the last non-null capture is the scene DSV. If the
// game's pipeline differs we'll add a dimension filter in a follow-up.

#pragma once

struct ID3D11DeviceContext;
struct ID3D11DepthStencilView;

namespace fw::render {

// Install the vtable hook on the provided game context. Idempotent —
// safe to call multiple times, only first actually hooks. Returns
// false on MinHook failure or null context.
bool install_dsv_capture(ID3D11DeviceContext* ctx);

// Set the expected backbuffer dimensions for filtering. Only DSVs of
// this size are accepted as the scene depth; smaller (shadow maps) or
// different-sized (half-res post) DSVs are ignored. Call this after
// the body renderer knows the backbuffer size.
void set_expected_dsv_size(unsigned int width, unsigned int height);

// Return the most recently captured non-null scene DSV with an
// AddRef'd reference. Caller MUST Release when done. Returns nullptr
// if no DSV has been captured yet.
ID3D11DepthStencilView* acquire_scene_dsv();

// Release cached DSV. Does NOT uninstall the hook (that happens at
// DLL detach via MinHook global shutdown). Safe to call repeatedly.
void release_cached_dsv();

} // namespace fw::render
