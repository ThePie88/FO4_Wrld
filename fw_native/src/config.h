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
#include <vector>

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
    // Example: "Save9_99999999_PlayerName_Sanctuary_000C34"
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

    // Build 69 — A/B switch for the mirror combat suppression (c.36b).
    //
    // When true (default, shipping behaviour) a non-owner writes 1 to
    // HighProcess+0x189 on every mirrored NPC each frame. RE established that
    // byte is the engine's OWN StopCombat request flag — the only two vanilla
    // writers are the two Actor::StopCombat implementations — so the
    // orchestrator answers it by dispatching event 98, which frees the
    // 400-byte HighProcess and zeroes the combat-target handle.
    //
    // The 2026-08-02 hp-churn probe measured the consequence: across 181,728
    // sampled ticks on two clients, ZERO suppression writes survived a frame,
    // and all 106 HighProcess allocations died within exactly 1 tick.
    //
    // Set to false to run the control experiment: if STABLE ticks appear in
    // the [hp-churn] log with this off, our byte is proven to be the cause.
    // EXPECT the old symptoms back while it is off — mirrors aim at the local
    // player and the combat-crouch "sliding" returns. This is a measurement
    // setting, not a shipping one.
    bool          suppress_mirror_combat = true;

    // Build 69r (2026-08-04) — the Build 69q death-recohere sweep, now OFF
    // by default and kept only as an A/B lever.
    //
    // WHAT WE BELIEVED (69q): MoveTo(cell=NULL, do_process_update=1) at the
    // death instant would "re-attach the AI-process + cell at the current
    // coords", re-aligning parentCell with coordinates before the respawn
    // LoadGame walks the refs.
    // WHAT THE DECOMP PROVED (10-agent audit, funcs_0175.md:8877-8930 +
    // funcs_0301.md:6090-6127): with cell=NULL and marker=NULL the MoveTo
    // performs NO cell re-file at all (sub_140514C50(a1,0,0) early-outs) —
    // instead it queues a "moved" changeform AND unconditionally plants an
    // ExtraBadPosition marker on every swept actor; both payloads are
    // consumed by the LoadGame/detach-family walkers. At the 17:46 crash the
    // sweep ran BEFORE the release wave (ordering flip) and MoveTo'd the
    // victim raider 7.1s before the fault — the only fw touch it ever had.
    // The sweep armed the load instead of protecting it.
    bool          death_recohere_sweep = false;

    // PIENUVO v0 (v19) — auth material minted by the external launcher.
    // `auth_blob` in the ini is "pubkeyhex:challengehex:sighex"
    // (64+64+128 hex chars). The DLL does NO crypto: it just forwards the
    // triple in HELLO. Empty vectors = launch without launcher = HELLO goes
    // out unauthenticated (server policy decides if that is accepted).
    std::vector<std::uint8_t> auth_pubkey;     // 32B when present
    std::vector<std::uint8_t> auth_challenge;  // 32B when present
    std::vector<std::uint8_t> auth_signature;  // 64B when present
    // Cosmetic display name (ASCII ≤15). Identity is the KEY, never the name.
    std::string   player_name;

    // Where we read from, for log diagnostics.
    std::filesystem::path source_path;
};

// Reads the given file. If the file is missing or unreadable, returns a
// default-initialized Settings + logs at WRN. Never throws.
Settings load(const std::filesystem::path& path);

} // namespace fw::config
