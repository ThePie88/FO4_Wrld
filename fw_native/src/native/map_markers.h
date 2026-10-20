// L5 realtime D2 (2026-10-15) — the engine's own map markers for the death
// crates and the other players.
//
// WHAT. On the Pip-Boy map and the compass, with the engine's icons and the
// name under the mouse: the local player's death crates ("LATEST DEATH" for
// the newest crate made, "CORPSE #n" for the others, map only) and every
// peer with a live ghost (their name, moved with the ghost). No fast travel
// to any of them. Faction: a stub, everyone sees everyone (TODO).
//
// HOW (the experiment of 2026-10-15, RESEARCH_L5.md "D2 rivisto"): a marker
// is a REFR with a MapMarkerData (name, flags, icon type) filed through
// ExtraDataList::SetMapMarkerData. The compass and the Pip-Boy map take
// their markers from ONE array of handles on the player (+1848), which the
// engine fills from the worldspace's persistent cell: a REFR made at runtime
// goes in by hand, under the engine's lock. The compass reads that array
// every frame (same worldspace, within fHUDCompassLocationMaxDist); the map
// rebuilds its entries only on the "marker list changed" event, fired here
// with TRUE after every change (a rebuild is total, so once per batch). A
// marker is moved by moving its REFR: the compass follows at once, the map
// at the next rebuild, fired while the Pip-Boy is open and a player moved.
// What hides from the compass but not from the map (CORPSE #n) is a handle
// taken OUT of the array right after the rebuild: the map keeps its entry
// until the next rebuild, the compass drops the handle on the next frame.
//
// LIFETIME. The REFRs are the mod's (base MapMarker 0x10, TEMPORARY, never
// in a save): each tick checks every handle still resolves to the REFR it
// was (form id, base, our data) and remakes the marker when not (a load,
// a purge); the engine refilling the array (a worldspace change) is seen
// on the player's worldspace field and answered by a new publish. All
// engine work on the MAIN THREAD (the heartbeat tick), SEH-caged, POD
// frames; a fault leaves the marker for the next tick and says so.
#pragma once

#include <cstddef>
#include <cstdint>

namespace fw::config { struct Settings; }
namespace fw::net { struct DeathCrateEntry; }

namespace fw::native::map_markers {

void init(std::uintptr_t module_base, const fw::config::Settings& cfg);

// Network thread: a DEATH_CRATES message (the whole list replaces the last;
// `death_count` tells the latest crate: the one whose ordinal equals it).
void on_death_crates(std::uint32_t death_count, const fw::net::DeathCrateEntry* entries,
                     std::size_t n);

// MAIN THREAD, every heartbeat tick (it paces itself to once a second).
void tick(std::uintptr_t module_base);

// A checkpoint is about to be written (persist/checkpoint.cpp, main
// thread): every marker REFR leaves the world first, destroyed the engine's
// way, and the tick remakes them after. The exit checkpoint of 2026-10-16
// 20:02 crashed inside the engine's save (an AV in sub_140BF6DD0 reading a
// null form) on a crate marker whose cell had unloaded and whose form id a
// purged object had just freed: no marker REFR exists while a save runs.
void suspend_for_save();
void resume_after_save();

// The faction stub (TODO, 2026-10-15): whether the local player gets to see
// `peer_id` on the map and the compass. Everyone, for now.
bool peer_visible_to_local(const char* peer_id);

}  // namespace fw::native::map_markers
