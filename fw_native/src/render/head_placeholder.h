// β.6 head placeholder — procedurally generated sphere rendered at the
// body's neck position.
//
// Rationale: MaleBody.nif contains the torso, arms, hands, and legs but
// NO HEAD (Bethesda bodies expect a dynamically-assembled head from the
// BGSHeadPart system). Extracting a vanilla head NIF requires manual
// BAE extraction from Fallout4 - Meshes.ba2, which is a slow loop. For
// the multiplayer MVP we draw a simple UV-sphere at the neck so remote
// bodies look like "a person", not "a headless torso".
//
// The sphere shares the body's camera CB (VP + model anchor) but does
// its own translation to lift to neck height. No skinning — it's a
// rigid placeholder that follows the body's yaw via the shared model
// matrix. Upgrade path: replace this with a fwn-loaded real head mesh
// once we have BA2 extraction working (or use community-extracted
// vanilla heads).
//
// Thread model + lifecycle mirrors body_render:
//   init_head_placeholder()  — at DLL init (builds mesh + shader)
//   draw_head(swap)          — called from body_render's draw pass
//   release_head_resources() — on DLL unload

#pragma once

#include <cstdint>

struct IDXGISwapChain;
struct ID3D11Device;
struct ID3D11DeviceContext;

namespace fw::render {

// Build the sphere mesh + pipeline state. Can only run once a D3D11
// device is available (get it from body_render via first-frame init).
// Returns false on any failure; body_render logs + continues without
// a head in that case.
bool init_head_placeholder(ID3D11Device* dev, ID3D11DeviceContext* ctx);

// Render the head sphere using the given camera constants. Anchored
// to (anchor_x, anchor_y, anchor_z + NECK_Z_OFFSET). Shares the VP
// matrix logic with body_render (we pass the same game_vp + eye_world).
//
// Expected call: AFTER body_render.draw_skinned_body(). Shares RTV/DSV
// of the body (same frame state).
//
// game_vp: 16 floats, column-major (same as body)
// eye_world: 3 floats (same as body)
// anchor: 3 floats, body pelvis world position
// yaw:  body yaw in radians (for head-follows-body)
void draw_head(ID3D11DeviceContext* ctx,
               const float game_vp[16],
               const float eye_world[3],
               const float anchor[3],
               float yaw);

void release_head_resources();

} // namespace fw::render
