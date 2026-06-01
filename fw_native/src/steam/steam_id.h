// B6.6w5 — Steam ID reader.
//
// Future-proof client identity scaffolding. Reads the local Steam ID
// via the SteamAPI flat C exports (`SteamAPI_ISteamUser_GetSteamID`).
// Works identically for:
//   - Real Steam (Client A): real account ID, e.g. 76561198000000000.
//   - Goldberg emulator (Client B): whatever ID is set in the
//     game-dir-relative steam_settings/ folder.
//
// Eventual uses:
//   - Authenticate clients at HELLO (replace hand-set peer_id strings).
//   - Anti-piracy / multiplayer whitelist on the server.
//   - Stable per-client ghost-fid registry for cross-client target sync.
#pragma once

#include <cstdint>

namespace fw::steam {

// Returns the local Steam ID, or 0 if unavailable.
// Result is cached after first success; safe to call from any thread.
// First call may return 0 if steam_api64.dll hasn't been loaded yet by
// the host process — subsequent calls will retry until success.
std::uint64_t get_local_steam_id() noexcept;

}  // namespace fw::steam
