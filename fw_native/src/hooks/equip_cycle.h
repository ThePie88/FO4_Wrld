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
// no-ops after the first run completes). One-shot per game session.
//
// Safe to call from any thread (just spawns a worker).
void arm_equip_cycle_after_loadgame(unsigned int delay_ms);

// Main-thread WndProc handlers, dispatched by main_menu_hook's fw_wndproc.
// Call only from the engine's UI/main thread — these invoke
// ActorEquipManager::UnequipObject / EquipObject which take engine locks
// and write per-actor state (race-unsafe from worker threads).
void on_force_equip_cycle_unequip_message();
void on_force_equip_cycle_equip_message();

// Called from DLL_PROCESS_DETACH. Stops the arming worker if still
// sleeping. Idempotent.
void shutdown_equip_cycle();

} // namespace fw::hooks
