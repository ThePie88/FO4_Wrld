// L5 realtime D2, the experiment (2026-10-15) — a map marker made at runtime.
//
// D2 wants the engine's own markers (the Pip-Boy map, the compass, the name
// under the mouse) for the death crates and for the other players. The
// decomp gave the pieces (RESEARCH_L5.md, "D2 rivisto"): a MapMarkerData
// (24 bytes: a TESFullName, a flag byte, an icon type) attached to a REFR
// of the MapMarker base (0x10) through an ExtraMapMarker, which
// ExtraDataList::SetMapMarkerData (sub_14027A680) allocates and files;
// AddToMap (sub_141152F40) is what the Papyrus native does on top. What
// the decomp did not tell is whether the map and the compass pick such a
// marker up when it is made at runtime instead of at the load of the
// worldspace: the test key answers that live, in three presses:
//   1. a marker placed at the player: name "FW TEST", visible, NO fast
//      travel, the icon type of the config; its handle pushed into the
//      player's marker array (the compass reads it from there) and the
//      engine's "marker list changed" event fired (the Pip-Boy map
//      rebuilds its entries only on it);
//   2. AddToMap on it (the engine's discovery path: message and event);
//   3. the data taken off and the REFR disabled.
// Every engine call is SEH-caged in a POD frame; a fault is logged and the
// state stays where it was. MAIN THREAD (the WndProc key path).
#pragma once

#include <cstdint>

namespace fw::config { struct Settings; }

namespace fw::native::map_marker {

void init(std::uintptr_t module_base, const fw::config::Settings& cfg);

// The test key was pressed (main thread).
void on_test_key();

}  // namespace fw::native::map_marker
