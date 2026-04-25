// Not a MinHook detour — a dedicated polling thread that reads player
// position from the PlayerCharacter singleton every N ms and logs when
// it moves. Parallel to the Frida JS `setInterval` approach.
//
// Gated on: player singleton != null AND player.parentCell != null
// (same guard used in the Frida JS bridge to avoid shipping garbage pos
// during main-menu phases).
//
// In B0.3 the thread only logs; in B0.4 it will push POS_STATE frames
// onto the network send queue.

#pragma once

#include <cstdint>

namespace fw::hooks {

// Starts the poll thread. `module_base` is Fallout4.exe base address.
// Returns true if the thread was spawned (not a guarantee that it will
// ever read valid data — that depends on the player entering the world).
bool start_player_pos_poll(std::uintptr_t module_base);

// Signals the thread to stop and joins it. Safe to call even if start
// was never called.
void stop_player_pos_poll();

} // namespace fw::hooks
