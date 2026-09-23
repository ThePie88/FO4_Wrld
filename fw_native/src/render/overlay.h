// =============================================================================
// overlay — the one ImGui context of the DLL, and the one frame everything that
// draws on screen goes into (2026-09-23, session lifecycle phase 4).
// =============================================================================
//
// WHY IT EXISTS. ImGui used to belong to the character editor, which brought it
// up the first time the panel opened and ran a frame only while it was open.
// The chat and the nametags draw during normal play, so the context, the fonts
// and the frame moved here, and the three of them draw into the same frame:
//
//   nametags   under everything, in the background draw list
//   chat       the history on the left, and the input box while typing
//   editor     the character creation panel, only while it is open
//
// WHERE IT DRAWS. Into the game's own backbuffer RTV, read from a fixed global
// every frame (present_hook's GameD3D), exactly as the editor always did: no
// render target of our own, so nothing to rebuild on a resolution change.
//
// COST WHEN IDLE. on_frame returns before touching ImGui when nothing wants to
// draw: no editor, no chat line, no ghost in view. A session that never sees
// another player or a chat line never brings ImGui up at all.
//
// MAIN THREAD ONLY. Called from the Present detour, which checks the thread
// first: one of Present's four call sites is the loading screen's worker.
// =============================================================================

#pragma once

#include <cstdint>

struct ImFont;

namespace fw::render::overlay {

// One frame. Lazily brings ImGui up against the game's device the first time
// something wants to draw.
void on_frame(std::uintptr_t module_base);

// Release ImGui and keep it down for the rest of the session. The Present
// detour calls it after a fault inside the overlay. Safe to call when ImGui
// was never brought up.
void shutdown();

// True once ImGui has a context and both backends are up.
bool ready() noexcept;

// The fonts, loaded once at init from the Windows font folder. Null when the
// file was missing, and ImGui::PushFont(nullptr, size) then keeps the default
// font at the requested size, so callers do not need to check.
ImFont* chat_font() noexcept;   // Segoe UI
ImFont* tag_font() noexcept;    // Segoe UI Bold

// True while the game is in menu mode: Pip-Boy, console, containers, the
// pause menu. It is the byte Papyrus Utility.IsInMenuMode() returns —
// Main (qword_1432D2020) + 0x1D0 — so it means exactly what the game means
// by it. Any thread, one guarded read.
bool in_menu_mode(std::uintptr_t module_base) noexcept;

}  // namespace fw::render::overlay
