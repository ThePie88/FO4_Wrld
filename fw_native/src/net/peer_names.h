// =============================================================================
// peer_names — the name to show for a peer, for the chat and the nametags
// (session lifecycle, phase 4).
// =============================================================================
//
// Every peer is identified by its peer_id, the id it sent in HELLO. The name a
// player chose in the launcher travels separately, as the display_name of the
// PEER_JOIN the server sends about them, and until phase 4 nothing on the
// client read it. This is where it is kept.
//
// WHAT IS SHOWN: the display name when the player set one, the peer_id when
// they did not. A client started by hand without the launcher has an empty
// name and shows up as its id, "player_B" for example. That is deliberate:
// an empty label would hide that the peer exists at all.
//
// COSMETIC AND UNTRUSTED. The server already strips everything but printable
// ASCII from the name; identity stays the peer_id, never this.
//
// ANY THREAD. Written from the network thread (PEER_JOIN, PEER_LEAVE, WELCOME),
// read from the main thread (the overlay), behind one mutex.
// =============================================================================

#pragma once

#include <string>

namespace fw::net::peer_names {

// Our own id and name, so our own chat lines, echoed back by the server with
// our id, show the name we chose.
void set_self(const std::string& peer_id, const std::string& display_name);

void on_join(const std::string& peer_id, const std::string& display_name);
void on_leave(const std::string& peer_id);

// The display name, or the peer_id when the name is empty or unknown.
std::string display(const std::string& peer_id);

}  // namespace fw::net::peer_names
