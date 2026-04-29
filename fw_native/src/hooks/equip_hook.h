// M9 wedge 1 — equipment-event sender hook (OBSERVE-only).
//
// Detours ActorEquipManager::EquipObject (sub_140CE5900) and ::UnequipObject
// (sub_140CE5DA0). Filters to LOCAL-PLAYER-only fires (a2's TESForm.formID
// == 0x14). On match: extracts item TESForm.formID + slot.formID + count,
// enqueues EQUIP_OP via fw::net::client, then chains to g_orig.
//
// **No mutation, no ghost touch.** This is the lesson hard-learned by 3
// days of crashes (re/M9_y_post_bmod_crash_dossier.txt). Wedge 1 is
// telemetry-only. Wedge 2 will add ghost-side apply now that B8 has
// stabilized BipedAnim allocator state.
//
// Forward-compat hook for wedge 2: respects `tls_applying_remote` (the
// shared B6.1 / container-hook re-entry guard). When wedge 2 lands and
// we apply remote EQUIP_BCAST locally on the ghost actor by re-invoking
// the engine functions, that re-entry will set tls_applying_remote and
// our detour skips broadcast — no ping-pong.
//
// Hook target RVAs come from offsets.h ENGINE_EQUIP_OBJECT_RVA and
// ENGINE_UNEQUIP_OBJECT_RVA (both already pinned by B8 force-equip-cycle).

#pragma once

#include <cstdint>

namespace fw::hooks {

// Install both detours. Returns true iff BOTH hooks succeed. Partial
// success returns false but does not roll back the successful one
// (matches install_pipboy_hook pattern from the rolled-back B7 attempt).
bool install_equip_hook(std::uintptr_t module_base);

} // namespace fw::hooks
