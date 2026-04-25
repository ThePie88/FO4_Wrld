// Minimal INI-ish config loader. No sections, just `key = value` pairs.
// Comments start with # or ;. Whitespace is trimmed. Unknown keys are
// silently ignored (forward-compat with future additions).
//
// Location: same directory as fw_native dxgi.dll (= game root).
// The launcher writes a different fw_config.ini per side (A/B) so
// peer_id and ghost_map differ while everything else is shared.

#pragma once

#include <cstdint>
#include <filesystem>
#include <string>

namespace fw::config {

struct Settings {
    std::string   server_host = "127.0.0.1";
    std::uint16_t server_port = 31337;
    std::string   client_id   = "player_A";

    // ghost_map maps a REMOTE peer_id to a LOCAL formid we drive as their
    // avatar. Format: "peer_id=0xHEX". Single entry for MVP.
    std::string   ghost_map_peer_id;  // e.g. "player_B"
    std::uint32_t ghost_map_form_id = 0;  // e.g. 0x1CA7D

    // "error" / "warn" / "info" / "debug"
    std::string   log_level = "info";

    // B3.b: if non-empty, the DLL hooks the MainMenu registrar and, once
    // the engine is ready (post-registrar, main thread), invokes the
    // engine's LoadGame native directly with this save name. The main
    // menu never shows — the game transitions straight to the load
    // screen. Empty disables the feature.
    //
    // The save name is the bare filename as it appears in %USERPROFILE%\
    // Documents\My Games\Fallout4\Saves\ without the .fos extension.
    // Example: "Save9_99999999_Filippo_Sanctuary_000C34"
    std::string   auto_load_save;

    // Legacy keys from the keystroke-based B3.b v1/v2 approach. `auto_continue`
    // itself is no longer used, but `auto_continue_delay_ms` was repurposed
    // by v4 as the delay between "MainMenu registrar fires" and "DLL
    // actually posts the LoadGame message to the WndProc". Longer delay =
    // safer (menu fully rendered + idle) at the cost of a visible menu
    // flash before load. Default 4000ms tuned against observed v3 timing
    // (LoadGame ran 4s after registrar hit when it worked).
    bool          auto_continue = false;
    std::uint32_t auto_continue_delay_ms = 4000;

    // Where we read from, for log diagnostics.
    std::filesystem::path source_path;
};

// Reads the given file. If the file is missing or unreadable, returns a
// default-initialized Settings + logs at WRN. Never throws.
Settings load(const std::filesystem::path& path);

} // namespace fw::config
