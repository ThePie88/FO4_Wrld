// v26 — PA station edits are state too.
//
// The pieces ledger (B6.13 / world_spawn.cpp) learns about a frame's
// contents from the container hooks: a TAKE or a PUT on the frame fires a
// deferred report_frame_pieces and the settled state ships. A paint job,
// a lining upgrade or a repair done at the power armor station changes
// the pieces IN PLACE, no transfer, no hook, no report: the local player
// sees the flames, the peer's replica keeps the stock torso until the
// next take/put or until the wearer enters and exits the frame (the user
// measured exactly that on 2026-09-15).
//
// First attempt (same day): detour the two ExamineMenu workers that apply
// a mod / set health on an inventory owner (sub_14098AE30, sub_14098E400).
// Measured: zero fires across a whole station session. The station is
// not the ExamineMenu: it is its own menu class, PowerArmorModMenu
// (registered by sub_140AF2170, created by sub_140AF2400, destroyed by
// sub_140AF2310), and the ExamineMenu confirm path (sub_14103D3E0) only
// reaches sub_14098AE30 for an ACTOR owner — the frame is a FURN refr.
// The PA menu's own apply path adds mods to the stack's instance extra
// through the sub_1402480F0 family (eight callers in the 0x14098-0x14099
// menu code), none of which carries the owner refr. Chasing that path is
// a rabbit hole with a cheap exit:
//
//   while the PowerArmorModMenu is open (and for 3 s after it closes),
//   world_spawn's tick polls every bound frame near the player and ships
//   a pieces report whenever the live content differs from the ledger.
//
// The menu is a local user action, so the poll never runs on a client
// that did not touch anything, which is the echo safety the ledger
// design relies on. This file provides the open/closed signal (creator +
// destructor detours) and keeps the ExamineMenu detours as diagnostics
// that now log every fire with the owner's identity.

#pragma once

#include <cstdint>

namespace fw::hooks {

bool install_workbench_hook(std::uintptr_t module_base);

// True between PowerArmorModMenu creation and destruction.
bool pa_mod_menu_open() noexcept;
// GetTickCount64 of the last destruction, 0 if never closed.
std::uint64_t pa_mod_menu_closed_ms() noexcept;

} // namespace fw::hooks
