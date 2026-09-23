// =============================================================================
// nametags — each peer's name above their ghost's head (session lifecycle,
// phase 4).
// =============================================================================
//
// WHAT IT DRAWS. The peer's display name (or their id when they set none) in
// bold white with a black outline, about 30 cm above the top of the ghost's
// head, centred, smaller and fainter with distance and gone beyond ~60 m.
// Visible through walls: nothing here tests line of sight.
//
// WHY IT DOES NOT SHAKE — the thing Strada A never got right. Strada A drew a
// body with a view-projection it built itself from the FIRST-PERSON camera's
// matrix and the player's foot position, and the body shook while walking
// ("VP mismatch with the game's true VP", dll_main.cpp). Two things are
// different here, and both are measured facts, not hopes:
//
//   * THE CAMERA. It is the World SceneGraph's own root camera — the
//     "WorldRoot Camera" at SceneGraph("World")+0x140, the one the frame
//     function re-parents under "WorldRoot CameraNode" every frame
//     (re/STRUCT_world_scenegraph.md). Its world transform and frustum are
//     read as they are, with the axis convention taken from the engine's own
//     NiCamera::WindowPointToRay (see nametags.cpp): the ROWS of the world
//     rotation are forward, up and right. The first build used Gamebryo's
//     columns instead, and the tag moved with the view. The log calls that
//     same engine function on the pixel where the tag is drawn and prints
//     how far its ray passes from the anchor, so the projection is checked
//     against the engine every session, not trusted.
//   * THE MOMENT. This runs at Present, which is the main thread in-world
//     (present_hook.cpp, verified over 27,000 frames), after the frame was
//     drawn and before the next update. The camera and the ghost's Head bone
//     are read in the same state the frame was drawn from.
//
// THE ANCHOR. The Head bone of the ghost's own skeleton (ghost_head_anchors),
// because the face is skin and is drawn where that bone is: the tag follows
// crouching, power armour stature and animation for free.
//
// MAIN THREAD ONLY, inside the ImGui frame run by overlay::on_frame.
// =============================================================================

#pragma once

#include <cstdint>

namespace fw::render::nametags {

// Anything to draw this frame? Also takes this frame's snapshot of the ghosts'
// heads, which draw() then uses, so the two agree.
bool wants_frame(std::uintptr_t module_base);

// Draw the tags into the background draw list, under the chat and the editor.
void draw(std::uintptr_t module_base);

}  // namespace fw::render::nametags
