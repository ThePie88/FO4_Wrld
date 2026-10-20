// B8 force equip cycle — exercise BipedAnim through ActorEquipManager once
// post-LoadGame, BEFORE peer-connect, to normalize the player skeleton's
// allocator state. See offsets.h "B8 force-equip-cycle" comment block for
// the full architectural rationale + RVA documentation.
//
// Why this is its own module (not just inline in main_menu_hook):
//   - Separation of concerns: main_menu_hook owns the LoadGame trigger;
//     equip_cycle owns the post-load skeleton normalization.
//   - Easier to disable for diagnostic A/B testing (just don't install).
//   - Future B9/B10 equip features may want to share the engine-call
//     wrappers; centralized here.

#pragma once

#include <cstdint>

namespace fw::hooks {

// Arms a worker thread that, after `delay_ms` from now, posts
// FW_MSG_FORCE_EQUIP_CYCLE_UNEQUIP to the FO4 main window. After another
// 500ms it posts FW_MSG_FORCE_EQUIP_CYCLE_EQUIP. The WndProc subclass in
// main_menu_hook routes both messages to handlers in this module.
//
// `delay_ms` should be long enough for the player to be IN-WORLD (loading
// screen done, save-game post-restore stage complete). Recommend 8000-10000
// (8-10s). Too short and the engine may be mid-restoration; too long and
// the peer might have already connected (defeats the "before peer" goal).
//
// Idempotent: calling twice is safe (the cycle internally tracks state and
// no-ops after the first run completes). One-shot per game session UNLESS
// arm_equip_cycle_for_peer_join is called to re-arm.
//
// Safe to call from any thread (just spawns a worker).
void arm_equip_cycle_after_loadgame(unsigned int delay_ms);

// Re-arm the cycle when a new peer joins MID-SESSION. Same behavior as
// arm_equip_cycle_after_loadgame but allows transition DONE → ARMED
// (the boot-time arm only allows IDLE → ARMED).
//
// Why this exists: the boot cycle's UNEQUIP+EQUIP broadcasts go nowhere
// when no peer is connected yet (server discards or no-ops). When peer
// B connects 5 minutes later, A doesn't re-broadcast its current
// equipment state → B's ghost-of-A renders without clothing.
//
// On PEER_JOIN net event, calling this function re-fires the cycle with
// a short delay (`delay_ms` should be ~1500-2000ms — engine is already
// stable in-world, no need for the long boot delay). The new UNEQUIP+
// EQUIP broadcasts reach the just-joined peer, who applies them via
// the wedge 2 receiver pipeline.
//
// If a cycle is already in-progress (ARMED / UNEQUIP_FIRED), calling
// this is a no-op (we don't want to interrupt an ongoing cycle).
//
// Safe to call from any thread.
void arm_equip_cycle_for_peer_join(unsigned int delay_ms);

// Main-thread WndProc handlers, dispatched by main_menu_hook's fw_wndproc.
// Call only from the engine's UI/main thread — these invoke
// ActorEquipManager::UnequipObject / EquipObject which take engine locks
// and write per-actor state (race-unsafe from worker threads).
void on_force_equip_cycle_unequip_message();
void on_force_equip_cycle_equip_message();

// L5 realtime R2b (2026-10-05) — one equip, one unequip, for the restore
// after a load (persist/inventory_restore.cpp): what the record says is
// worn is worn. The same engine calls as the cycle above
// (ActorEquipManager::EquipObject / UnequipObject), each SEH-caged, the
// refs resolved at the call. equip_form wears `stack_id` of the item's
// chain (0 = the head; the decompiled EquipObject reads that stack's
// instance data through sub_140505440 when the object pair carries none,
// so a modded weapon is worn as itself, not as a plain roll); unequip_form
// takes off whatever stack of the form is worn (stack 0 = the engine finds
// it). True = the call ran without a fault; the engine's own return byte
// is logged, not trusted (its early exits return 1 too). MAIN THREAD.
bool equip_form(std::uint32_t form_id, std::uint32_t stack_id);
bool unequip_form(std::uint32_t form_id);

// Called from DLL_PROCESS_DETACH. Stops the arming worker if still
// sleeping. Idempotent.
void shutdown_equip_cycle();

} // namespace fw::hooks
