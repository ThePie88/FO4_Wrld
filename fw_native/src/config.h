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

    // Ghost 1P full-body animation (2026-08-05). When the local camera is in
    // first person the engine parks the third-person animation graph
    // (BSAnimationGraphManager+0xD8 activeGraph flips to 1) and the remote
    // ghost of this player freezes into the graph's default V/T pose. With
    // this on, the DLL gives graphs[0] the same per-frame flush+update the
    // engine gives the active graph, so the 3P skeleton keeps producing real
    // animation and the pose stream carries it. Costs one extra graph
    // evaluation per frame for the local player only. Set false to fall back
    // to the pose-stream HOLD (ghost keeps its last good 3P pose).
    // 2026-08-05 — DEFAULT OFF after the live verdict below.
    //
    // The reverse engineering was right and the recipe was executed exactly:
    // the parked third-person graph WAS revived (hkbBehaviorGraph m_isActive
    // raised, confirmed in-game), and the engine's own per-frame sequence ran
    // on it — bound-channel flush, pose generate, and the pose-apply call
    // that is the actual NiAVObject writer. Zero faults, thousands of clean
    // iterations. The third-person skeleton's bone matrices still did not
    // move: identical to three decimals across 17 seconds of walking.
    // Something further along the chain still refuses a graph the engine
    // considers parked, and it is not any of the three gates that were
    // proven and cleared.
    // Meanwhile the attempt cost a real regression (a muted output channel
    // leaking into third person and stopping WASD movement — now fixed by
    // save/restore, but the lesson stands). Left in the tree as a documented,
    // reproducible experiment; set true only to resume that investigation.
    // 2026-08-05 late — back ON for the forced-context attempt. The probe
    // proved the earlier failure was a measurement error on my side: the
    // parked graph is write-ready (95 bones, valid arrays, physics gate
    // false, and its root IS the tree the pose capture reads), and the drive
    // was handing it the engine's first-person update context, whose LOD
    // throttle resolves a hidden third-person body to "generate nothing".
    // Now it builds the forced context the engine's own bind path uses.
    // The regression that made this dangerous (a muted output channel
    // leaking into third person) is fixed by save/restore.
    // 2026-08-05 round 6 — OFF again, and this is where the investigation
    // stands. Everything the drive needs is now proven present: the graph is
    // revived, events are mirrored to it, variables already reach it, the
    // physics gate is false, the forced context defeats the LOD throttle, and
    // it genuinely generates and writes 95 bones every frame. It still
    // renders one frozen frame, because the delta time never reaches Havok:
    // Update builds the hkb context from the character and the physics world
    // only, so the clip clock does not advance. Whatever steps hkb time for
    // the active graph has not been located yet. Off until it is, so the pose
    // capture falls back to HOLD and the ghost keeps its last good
    // third-person pose instead of a stub.
    bool          first_person_graph_drive = true;

    // 2026-08-05 — experiment switch. false (default) = the pose stream is
    // HELD while the sender is in first person, so the peer's ghost keeps
    // its last good third-person pose. true = keep streaming, which is only
    // useful while the first-person capture is under investigation (two
    // attempts have shipped a V-pose ghost with a deformed head; the
    // [pose-1p] diagnostic runs either way and says which tree the sender
    // is reading and whether it is moving).
    bool          stream_pose_in_first_person = false;

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
