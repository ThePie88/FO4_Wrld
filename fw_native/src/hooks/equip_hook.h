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

#include <windows.h>
#include <cstdint>

#include "../net/protocol.h"   // EquipModRecord

namespace fw::hooks {

// v24 — read the OMOD form ids attached to the SINGULAR stack of
// `item_form_id` inside any REFR's inventory (PA frames included — the
// walk is the generic +0xF8 layout). Returns the number written to
// out_mods (at most cap). Reuses the w4 extractor that has snapshotted
// equip mods since M9.w4. Main thread.
std::uint8_t read_item_mod_forms(void* refr, std::uint32_t item_form_id,
                                 std::uint32_t* out_mods, std::uint8_t cap);

// Phase 3 (2026-09-23) — the wire form of an item a REFR is already WEARING,
// built exactly as the live equip hook builds it when the player equips
// something: the same OMOD records (form, attach index, rank) from the same
// w4 extractor, and the same effective priority from the same helper, fed
// with the BGSObjectInstanceExtra the extractor finds on the stack.
//
// `item_form` is the TESBoundObject* of the inventory entry, `item_form_id`
// its form id. Writes at most `cap` records to `out_mods` and the priority
// to `*out_priority` (0 when the item has no instance data, which the
// receiver reads as "use the form's default", exactly as for a live equip).
// Returns the number of records written. Main thread.
//
// Shares the extractor's one known imprecision with the live path: with two
// stacks of the same form, the first stack carrying instance data is read,
// not necessarily the worn one. Unchanged here on purpose — the announce
// has to say what a live equip would say, not something subtly different.
std::uint8_t read_worn_item_for_wire(void* refr, void* item_form,
                                     std::uint32_t item_form_id,
                                     fw::net::EquipModRecord* out_mods,
                                     std::uint8_t cap,
                                     std::uint16_t* out_priority);

// Install both detours. Returns true iff BOTH hooks succeed. Partial
// success returns false but does not roll back the successful one
// (matches install_pipboy_hook pattern from the rolled-back B7 attempt).
bool install_equip_hook(std::uintptr_t module_base);

// M9 w4 v9 — deferred mesh-tx infrastructure. Posted via PostMessage
// 300ms after each equip event so the engine has time to finish
// runtime weapon assembly. WndProc dispatches → on_deferred_mesh_tx_message
// → walks player's bipedAnim → ships mesh-blob if non-empty.
inline constexpr UINT FW_MSG_DEFERRED_MESH_TX = WM_APP + 0x4E;
void on_deferred_mesh_tx_message();

// 2026-05-07 — AUTO RE-EQUIP CYCLE. Posted ~50ms after each user equip.
// Handler fires UnequipObject + EquipObject for the same form, generating
// EQUIP-X / UNEQUIP-X / EQUIP-X on the wire so the receiver gets a "magic
// re-equip" event that renders the modded weapon correctly on the ghost.
// Without this, the first apply of a modded weapon renders stock or as
// the previous weapon (off-by-one). Replicates the manual manganello
// workflow that the user confirmed works.
// 2026-05-07 — picked 0x4F to avoid collision with FW_MSG_EQUIP_APPLY
// (also at WM_APP+0x4C, which would match first in the WndProc dispatch
// table and route our auto-cycle messages to drain_equip_apply_queue
// instead of on_auto_re_equip_message). Keep an eye on the numbering
// table in equip_cycle.cpp's comment block before adding new IDs.
inline constexpr UINT FW_MSG_AUTO_RE_EQUIP = WM_APP + 0x4F;
void on_auto_re_equip_message(WPARAM wp);

} // namespace fw::hooks
