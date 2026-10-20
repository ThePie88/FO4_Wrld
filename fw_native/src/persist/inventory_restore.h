// L5 realtime persistence, R2 (2026-10-03) — the player's record back into
// the game after every load.
//
// The owner's decision of 2026-10-03: Alt+F4, a crash and a death lose
// nothing. The server holds the player's inventory as a record kept current
// by the captures of R1 (INV_STATE) and by the container ops it accepts; the
// engine, after a load, holds the inventory of the checkpoint it loaded,
// which is older. This module puts the record back:
//   1. a load is coming (the first CKPT_BOOT of the process; a death, whose
//      reload follows): the record is closed (no INV_STATE, a capture taken
//      over the old checkpoint would write the past over it) and asked for
//      (RESTORE_REQUEST, with the last capture this process sent);
//   2. the server answers with the record (PLAYER_INV, after the descriptors
//      of its named instances);
//   3. once the load that followed the request is over and the scene has
//      settled, behind a curtain: one complete capture, the difference with
//      the record line by line (base, fingerprint), the surplus removed and
//      the shortfall built with the writers of stage 4b, a capture to
//      check, RESTORE_DONE; from then the captures are the record again.
// A line nobody could read (kFpUnknown) on either side stands for any
// instance of its base: it absorbs a difference of the same base instead
// of having it removed or built, and is never removed or built itself.
// R2b (2026-10-05): once the lines are the record's, what the record says
// is worn is worn: the armour and weapons the engine wears that the record
// does not flag are taken off, the ones the record flags and the engine
// does not wear are put on (the stack of the record's instance when it is
// there, the first stack of the base otherwise), through the SEH-caged
// equip_cycle primitives; the Pip-Boy, the frame's body armour and a player
// inside a frame are never touched. A worn instance of the same base
// stands for the record's (the alignment keeps it worn).
// Failure is said, never hidden: no answer, no complete capture or no load
// within the limits closes the attempt with RESTORE_DONE failed and the
// record stays closed for this process, so nothing of this session is
// written over it.

#pragma once

#include <cstddef>
#include <cstdint>

namespace fw::config { struct Settings; }
namespace fw::net { struct PlayerInvHeader; struct InvStateEntry; struct PlayerStatsHeader; struct PerkRankEntry; }

namespace fw::persist::restore {

// On with the inventory capture (inventory_capture): without captures there
// is nothing to compare, and no INV_STATE either.
void configure(const fw::config::Settings& cfg);

// The first CKPT_BOOT of the process (net thread): the boot load is next.
void on_boot_word();

// The local player died (main thread, the kill hook, once per death): the
// reload of the death is next.
void on_death();

// L5 realtime D1: the respawn of a death is over (main thread, the death
// module). Nothing when a load came after the death, the usual path; with
// no load (the resurrect, death_resurrect=true) the record goes into the
// game as it is: the server moved the inventory into the crate.
void on_respawn_without_load();

// One PLAYER_INV chunk (net thread).
void on_player_inv(const fw::net::PlayerInvHeader& h, const fw::net::InvStateEntry* entries,
                   std::size_t n);

// One PLAYER_STATS chunk (net thread, L5 realtime R4): the record's numbers,
// put back after the inventory (persist/player_stats).
void on_player_stats(const fw::net::PlayerStatsHeader& h, const fw::net::PerkRankEntry* perks,
                     std::size_t n);

// Main thread, every tick.
void tick(std::uintptr_t module_base);

// INV_STATE may be sent: the game holds the record. Any thread.
bool record_open() noexcept;

// The overlay covers the screen: a load is over and the record is not back
// in the game yet. Any thread.
bool curtain_active() noexcept;

} // namespace fw::persist::restore
