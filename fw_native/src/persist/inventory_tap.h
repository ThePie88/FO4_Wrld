// L5 stage 2 (2026-09-27) — the boundary tap: every item that enters or
// leaves the player's inventory, seen at the two engine functions all of
// them go through, with its cause.
//
// The dossier counted 23 ways an item crosses into or out of the player
// (menus, pickups, drops, crafting, scrap, barter, scripts, consumption,
// ammo, grenades, power armour, workshop) and found no pair of functions
// that sees them all at the level of "why". The two cores see them all at
// the level of "what": sub_140502940 adds a stack to a REFR, sub_140500870
// removes one. This module observes both, for the player only, records
// (base, count, cause) into a ring, and the 1 Hz capture drains it and
// checks that the deltas it measured are explained by the events seen.
// Whatever is not explained is logged: that list is the census of the
// flows the later stages must cover. Observe-only: the originals always
// run and nothing they do is changed.
//
// One duty beyond observation since 2026-09-27: a removal whose reason is
// DROP (3, the Pip-Boy drop) leaves a new world REFR behind, and the core
// hands its handle back through the out parameter. After the original has
// returned, the tap resolves that handle and passes the REFR to the world-
// spawn sender (hooks/world_spawn_hook.cpp: report_world_drop), which is
// the whole reason dropped items exist on the other clients. Still nothing
// the engine does is changed.

#pragma once

#include <cstddef>
#include <cstdint>

namespace fw::config { struct Settings; }

namespace fw::persist::tap {

struct Event {
    std::uint64_t wall_ms;
    std::uint32_t base_id;
    std::int32_t  delta;       // +count added, -count removed
    std::uint32_t cause;       // add: caller RVA; remove: 0x80000000 | reason
    std::uint32_t other;       // form id of the other container / world REFR, 0 if none
    std::uint8_t  during_load; // the loader was running (the whole save's inventory)
    std::uint8_t  pad[3];
    std::uint32_t tid;         // the thread the core ran on: a fact for the log, not a verdict
};

constexpr std::size_t RING = 512;

// Installs the two detours. Returns how many went in (0 when both
// inventory_capture and world_spawn_sync are off: the first is the census,
// the second the drop announce, and either needs the detours).
int install(std::uintptr_t module_base, const fw::config::Settings& cfg);

// Moves the events recorded since the last drain into `out` (at most `max`).
// Returns how many; `dropped` gets the count lost to a full ring.
std::size_t drain(Event* out, std::size_t max, std::uint32_t* dropped);

// A readable name for an add-core caller, or nullptr.
const char* cause_name(std::uint32_t cause);

// L5 realtime R1: how many adds and removes the cores have made on the
// player since the start. The capture compares it with the value at its last
// pass and captures again at once when it moved. Any thread.
std::uint64_t events_seen() noexcept;

} // namespace fw::persist::tap
