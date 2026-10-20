// L5 realtime persistence, R4 (2026-10-03) — the character's numbers.
//
// Every death reloads the last checkpoint, so until R4 the XP, the levels and
// the perks earned since it were lost at every death and at every crash.
// This module reads them off the player (XP = the Experience actor value, the
// level, the perk points, the seven SPECIAL base values, health, action
// points, rads, and every perk of the game the player holds with its rank),
// sends them to the server whenever they change (STATS_STATE), and after a
// load puts back what the record holds and the game lacks:
//   - the missing XP, awarded the way PlayerCharacter::SetLevel does it
//     (the engine runs the level-ups);
//   - the SPECIAL base values, raised: checked in the tick ~2.5 s AFTER the
//     perks (2026-10-15), because the SPECIAL ranks of the perk chart, the
//     bobbleheads and the magazines are perks that raise the base value
//     themselves a frame after AddPerk, and raising it first counted every
//     rank twice; only what is still missing then is raised (console, scripts);
//   - the perk ranks, added one by one;
//   - then the perk points, set to the record's (the level-ups just gave
//     some of their own).
// Nothing is ever lowered: a record behind the game must not take anything
// away. Health, action points and rads are captured and recorded but not put
// back yet (R4b): at a death the respawn heals anyway.
// Every engine read and call is SEH-caged; the actor value pointers are
// checked to be ActorValueInfo forms once, and a capture with any read
// failed is not sent.

#pragma once

#include <cstdint>
#include <vector>

namespace fw::config { struct Settings; }

namespace fw::persist::charstats {

struct Snapshot {
    std::uint16_t level = 0;
    float         xp = 0.0f;
    std::uint8_t  perk_points = 0;
    float         special[7] = {};
    float         health = 0.0f;
    float         action_points = 0.0f;
    float         rads = 0.0f;
    std::vector<std::pair<std::uint32_t, std::uint8_t>> perks;   // (form, rank), sorted
    bool          perks_read = false;
};

// On with the inventory capture (inventory_capture).
void configure(const fw::config::Settings& cfg);

// Main thread, every tick: captures once a second (the perks every five
// seconds, or at once when the level or the perk points moved) and sends a
// STATS_STATE when the numbers changed, while the record is open.
void tick(std::uintptr_t module_base);

// The last STATS_STATE number this process sent (0 = none). Main thread.
std::uint32_t last_sent_seq();

struct ApplyResult {
    float         xp_awarded = 0.0f;
    std::uint16_t level_before = 0, level_after = 0;
    std::uint32_t special_raised = 0;   // always 0 since 2026-10-15: the SPECIAL is checked in the tick
    std::uint32_t perks_added = 0;      // ranks added
    std::uint32_t perks_unresolved = 0; // perks whose rank could not be reached
    bool          points_set = false;
    bool          ok = false;           // false: the player could not be read
};

// Puts back what `want` holds and the game lacks (see the header). Main
// thread, after the inventory alignment, behind the restore's curtain.
ApplyResult apply(std::uintptr_t module_base, const Snapshot& want);

} // namespace fw::persist::charstats
