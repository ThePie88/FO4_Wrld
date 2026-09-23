// Character editor overlay (2026-08-08) — the panel itself.
//
// SEPARATE FROM present_hook ON PURPOSE
//   present_hook owns "when is a frame". This owns "what is drawn". Keeping them
//   apart means the frame callback stays a dozen lines that can be reasoned about
//   on its own, and the editor can grow without touching the hook.
//
// WHERE IT DRAWS, AND WHY IT OWNS NOTHING
//   Into the game's OWN backbuffer render target view, read from a fixed global
//   every frame (CHARGEN_PLAN §28). The overlay therefore holds no D3D resource
//   of its own beyond ImGui's font atlas and vertex buffers, which means there is
//   nothing to release before the game's ResizeBuffers and nothing to rebuild
//   after — every resolution change and fullscreen transition is handled for free.
//
// THE DOCK IS ON THE RIGHT
//   Not a style preference. In third person, with the camera swung round to look
//   at the player's face, the camera sits slightly right of centre, so the free
//   screen space is on the right. That came from playing the game, not from
//   reading it.
//
// WHAT USED TO BE "NOT HERE YET"
//   This header said, until 2026-09-23, that input and real data were missing.
//   Both landed long ago: the input capture is below, and every list is read
//   from the game's own data through chargen_catalog.
//
// WHO OWNS IMGUI (since 2026-09-23)
//   Not this file any more. The chat and the nametags draw every frame in the
//   world, while this panel draws only during character creation, so the ImGui
//   context, its fonts and the frame itself moved to render/overlay. This file
//   keeps what is the editor's: the style, the panel, and the input capture.
//
// MAIN THREAD ONLY, and only from inside a frame.

#pragma once

#include <cstdint>

namespace fw::render::editor {

// The editor's look — dark panel, Pip-Boy green, square corners. It is the
// style of the whole ImGui context, so overlay applies it once at init and the
// chat inherits it.
void apply_style();

// Before the ImGui frame, while the editor is open: take the input back off
// the game (it reclaims it every time one of its modal pumps runs) and build
// the option lists once the game data is there.
void prepare_frame(std::uintptr_t module_base);

// Inside the ImGui frame, while the editor is open: the panel.
void draw(std::uintptr_t module_base);

// ---------------------------------------------------------------------- input
//
// Take the mouse and keyboard, or give them back. Called when the editor opens
// and closes. MAIN THREAD ONLY — it touches engine singletons.
//
// Three things happen, and each is the engine's own mechanism rather than a
// fight with it:
//
//   1. `byte_142F26E4C` is zeroed. That is the byte the engine's OWN modal
//      pumps use to mean "input dispatch is illegal right now": its window
//      procedure checks it before handling WM_INPUT, WM_MOUSEMOVE and WM_CHAR,
//      and falls straight through to DefWindowProc when it is clear. Our
//      subclass runs BEFORE the game's procedure, so we still see every message
//      and can feed ImGui, while the game sees none of them. That is what stops
//      the camera turning and the weapon firing while the panel is up.
//
//   2. The MenuCursor request refcount is incremented, exactly as a menu does.
//      The frame pump reads that refcount and stops calling ClipCursor and
//      SetCursorPos, which is what releases the mouse. Refcounted, so nesting
//      is safe.
//
//   3. ShowCursor. The engine NEVER shows the OS cursor over its client area in
//      any state — it draws its own Scaleform sprite — so this is the one part
//      that cannot be borrowed and must be done by us, together with answering
//      WM_SETCURSOR in the subclass.
void set_input_captured(std::uintptr_t module_base, bool on);
bool input_captured() noexcept;

// Feed a window message to ImGui. Returns true when the message was consumed
// and must NOT be passed to the game.
//
// Safe to call for every message; it does nothing at all while the editor is
// closed, so the cost when the panel is not up is one atomic read.
bool wndproc(void* hwnd, unsigned int msg, unsigned long long wparam,
             long long lparam);

}  // namespace fw::render::editor
