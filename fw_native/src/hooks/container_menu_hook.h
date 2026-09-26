// Loot rework L3.1 (2026-09-24) — the open ContainerMenu, rebuilt by hand.
//
// The ContainerMenu keeps its two Scaleform lists in step with the inventory
// through a BGSInventoryList event sink (sub_140A54BD0) that understands two
// event types only: "entry inserted at row N" and "entry removed at row N".
// A stack the engine's own RemoveItem destroys on our behalf (the remote
// apply of another player's take, an alignment, a rollback) produced neither
// on screen: measured live on 2026-09-24, seven clicks on a row whose item
// was already gone, no transfer, until the menu was closed and reopened.
// Additions went through the insert path and showed at once.
//
// So after every change we make to a container that is on screen, the menu's
// own rebuild is called: vtable slot 32 of ContainerMenu (sub_14103E700,
// UpdateList(bool container_side)) refills "containerListArray" or
// "playerListArray" from the inventory list and refreshes weight and caps,
// and then, as the engine does after every UpdateList pair of its own, the
// Scaleform "InvalidateLists" is invoked on the menu object: the rebuild
// alone changed the arrays and not one row on screen (live 2026-09-24,
// thirteen rebuilds on B, rows still stale).
//
// The instance comes from the factory the UI registers on the name
// "ContainerMenu" (sub_1410412B0), hooked to remember what it returns. It is
// used only while the engine's own query (sub_141A7FD40 on the UI singleton)
// says a ContainerMenu is open, while the remembered object still carries
// ContainerMenu's vtable, and while the handle it shows is the container that
// changed: a closed and freed menu is never touched.

#pragma once

#include <cstdint>

namespace fw::hooks {

bool install_container_menu_hook(std::uintptr_t module_base);

// MAIN THREAD ONLY (the menu's rebuild touches Scaleform). Rebuilds the lists
// of the open ContainerMenu when it shows `container_refr`: the container
// column with `container_side`, the player's column with `player_side`.
// True when a rebuild ran; false when no menu is open on that container.
bool refresh_container_menu(void* container_refr, bool container_side,
                            bool player_side);

} // namespace fw::hooks
