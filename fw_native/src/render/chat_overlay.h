// =============================================================================
// chat_overlay — the global chat (session lifecycle, phase 4).
// =============================================================================
//
// WHAT THE PLAYER SEES. A small, see-through box on the left of the screen with
// the last lines, each one "name: text", always on while in the world. Enter
// opens an input box under it with the cursor already in it; the game's
// controls pause while it is open, so typing never moves the character. Enter
// again sends, Escape closes without sending.
//
// WHERE A LINE COMES FROM. Only from the server. A sent line is not shown
// locally: the server echoes it back to its sender too, so every client shows
// the same order and a line appears only once the server has taken it. When
// there is no session the box says so instead of eating the line.
//
// HOW THE GAME STOPS READING THE KEYBOARD. The game reads keyboard and mouse
// only through WM_INPUT (raw input registered with flags 0, which is also why
// the legacy WM_KEYDOWN/WM_CHAR still arrive for ImGui), and our window
// subclass sees every message before the game's procedure does. While the box
// is open WM_INPUT is swallowed, EXCEPT key and mouse-button releases: a key
// held down when Enter was pressed has already reached the game as pressed,
// and swallowing its release would leave the character walking by itself
// after the box closes. The engine only acts on a change of state, so a
// release of a key it never saw pressed does nothing.
//
// WHAT IT NEVER TOUCHES. The OS keys (WM_SYSKEYDOWN and friends: ALT+F4,
// ALT+TAB), focus and activation, and the cursor, which stays hidden: the
// editor learnt the first two the hard way, and this box needs no mouse.
//
// WHEN ENTER OPENS IT. In the world, with the scene settled, outside menu mode
// (Pip-Boy, console, containers — the byte Utility.IsInMenuMode reads) and
// outside character creation. Anywhere else Enter goes to the game untouched,
// so the console's own Enter keeps working.
// =============================================================================

#pragma once

#include <cstdint>
#include <string>

namespace fw::render::chat {

// A line the server relayed. `sender_id` is the peer_id the server stamped;
// the name shown is resolved here, once, through peer_names. ANY THREAD —
// the network thread calls it.
void on_line(const std::string& sender_id, const std::string& text);

// A line of our own, shown without a name, for something the player would
// otherwise only find in the log: a take the server refused and undid. ANY
// THREAD.
void notice(const std::string& text);

// MAIN THREAD, from overlay::on_frame: is there anything to draw this frame?
bool wants_frame(std::uintptr_t module_base);

// MAIN THREAD, inside the ImGui frame.
void draw(std::uintptr_t module_base);

// MAIN THREAD, from the window subclass, after the editor has had its turn.
// True when the message was consumed and must NOT reach the game.
bool wndproc(void* hwnd, unsigned int msg, unsigned long long wparam,
             long long lparam);

// True while the input box is open.
bool typing() noexcept;

}  // namespace fw::render::chat
