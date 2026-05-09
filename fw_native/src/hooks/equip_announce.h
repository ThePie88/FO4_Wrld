// =============================================================================
// equip_announce — boot/peer-join APPAREL bootstrap broadcast (Option B).
// =============================================================================
//
// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
// !!! STATUS: NON TESTATO — UNTESTED — NOT INVOKED AT RUNTIME (2026-05-08) !!!
// !!!                                                                       !!!
// !!! This module is SCAFFOLDING ONLY. It compiles clean and links into     !!!
// !!! the DLL, but `arm_equip_announce_*` is NOT called from anywhere.      !!!
// !!! The B8 force-equip-cycle (its predecessor) is also disabled — see     !!!
// !!! `hooks/main_menu_hook.cpp:112` and `net/client.cpp:1726` for the      !!!
// !!! `CRASH-HUNT 2026-05-08` markers where its arm calls are commented.    !!!
// !!!                                                                       !!!
// !!! Reason it was written without testing: the original rationale         !!!
// !!! disappeared as a side effect of a crash hunt that disabled B8 and     !!!
// !!! revealed that:                                                        !!!
// !!!   1. Weapons modded loadouts already work via the M9 witness pipeline !!!
// !!!      (event-driven on real engine equip events, fires whenever the    !!!
// !!!      sender draws a weapon during play — boot-time hack not needed).  !!!
// !!!   2. Apparel slots that are passively worn at LoadGame and never      !!!
// !!!      re-equipped during the session DON'T fire any equip event, so    !!!
// !!!      the receiver's ghost stays naked (visible bug — confirmed in     !!!
// !!!      live screenshot 2026-05-08, ghost holds modded pistol but no     !!!
// !!!      pants).                                                          !!!
// !!!                                                                       !!!
// !!! Server-side persistence (Option A) was the design alternative,        !!!
// !!! deferred until the server gains an equipment-state snapshot section   !!!
// !!! (likely B7+). When that happens, the wire format produced by THIS     !!!
// !!! module becomes the input that the server stores+replays on peer       !!!
// !!! join, with no protocol change.                                        !!!
// !!! !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
//
// -----------------------------------------------------------------------------
// Architecture summary
// -----------------------------------------------------------------------------
//
// On a defined trigger (boot post-LoadGame, or peer join) a worker thread
// sleeps for `delay_ms`, then PostMessages FW_MSG_EQUIP_ANNOUNCE_FIRE
// (WM_APP + 0x52) to the FO4 main window. The WndProc subclass routes
// the message to `on_equip_announce_fire_message()` which runs on the main
// thread and is therefore safe to walk PlayerCharacter's BipedAnim.
//
// The main-thread handler is purely a *passive enumeration*: it reads the
// equipment that's ALREADY in place on the local player (per the loaded
// save) and emits one EQUIP_OP per non-empty APPAREL slot via the existing
// `fw::net::client().enqueue_equip_op(...)` API. NO engine call is made
// — no equip, no unequip, no force-cycle. This is the architectural
// difference from B8 (which crashed because of the force-cycle's engine
// call AVing internally — see `re/B8_force_equip_cycle.log` for full
// post-mortem).
//
// Slots emitted: APPAREL only (kArmorSlots from `re/biped_slots.md` —
// vault suit, helmet, glasses, eyewear, body armor, etc.). NOT weapon
// slots — those are already covered by the M9 witness pipeline whenever
// the sender actively draws a weapon during gameplay.
//
// Receiver side: NO changes needed. The existing M9 wedge 2 EQUIP_BCAST
// receiver in `dispatch::drain_equip_apply_queue` resolves form_id →
// ARMO → ARMA → 3rd-person NIF and attaches to the ghost. Since this
// module emits via the same wire format as runtime equip events, peers
// process it identically.
//
// -----------------------------------------------------------------------------
// Why this is OPTION B (client-side) and how to upgrade to OPTION A later
// -----------------------------------------------------------------------------
//
// Option B (this module): client enumerates its own equipment locally and
// announces. Server is a relay. Persistent across crashes only via "sender
// re-runs the announce on rejoin".
//
// Option A (future, server-side persistence): server stores
// `peer_id → [equipped_form_ids]` derived from EQUIP_BCAST history.
// On peer connect, server replays the stored state to the new peer as
// individual EQUIP_BCAST frames. Survives sender crashes, prevents
// trivial spoofing (server knows last-confirmed state).
//
// THE WIRE FORMAT IS THE SAME. Option A doesn't need a new protocol —
// it just needs the server to start tracking what it's already relaying.
// Designing this module's payload to match the existing EquipOpPayload
// (M9 wedge 2 + wedge 4 PROPER) means Option A's promotion is a server-
// only change, no client recompile.
//
// -----------------------------------------------------------------------------
// To wire up at test time (FUTURE WORK)
// -----------------------------------------------------------------------------
//
// 1. Implement the BipedAnim enumeration in `on_equip_announce_fire_message`
//    (currently a TODO block — see the CPP file). This requires RE'ing:
//      - PlayerCharacter::BipedAnim offset (Actor or PlayerCharacter base)
//      - Slot count (apparel slots only, not weapons)
//      - Per-slot equipped TESForm* layout
//    Decomp source: `D:\falloutworld_decomp\out\10_decomp\` — search for
//    "BipedAnim", "BGSBipedObjectForm", and the player-singleton xrefs.
//    Existing offsets.h notes (line ~733): biped slot bitmask at +0x1E8 of
//    TESObjectARMO; that's the form-side, not the runtime per-slot table.
//
// 2. Add the FW_MSG dispatch wiring in main_menu_hook.cpp's fw_wndproc:
//      if (msg == FW_MSG_EQUIP_ANNOUNCE_FIRE) {
//          fw::hooks::on_equip_announce_fire_message();
//          return 0;
//      }
//
// 3. Replace the `CRASH-HUNT 2026-05-08` blocks at:
//      - hooks/main_menu_hook.cpp:112  (post-LoadGame arm)
//      - net/client.cpp:1726           (peer-join arm)
//    by calling `fw::hooks::arm_equip_announce_after_loadgame(10000)` and
//    `fw::hooks::arm_equip_announce_for_peer_join(1500)` respectively.
//    Leave the disabled `arm_equip_cycle_*` lines commented for history.
//
// 4. Test scenario:
//      - Save game with player wearing vault suit + helmet + glasses
//      - Boot client A, wait for ghost spawn on client B
//      - Verify client B's ghost is wearing the same items via the
//        existing M9 wedge 2 visual pipeline.
//      - Cross the Sanctuary→Red Rocket bridge to confirm B8's crash
//        does NOT come back (the engine-call AV that B8 hit is avoided
//        because we don't call the engine equip path at all).
//
// 5. If the test passes, B8 (`hooks/equip_cycle.{h,cpp}`) becomes dead
//    code. Remove via a separate cleanup commit; preserve git history
//    via `git rm` not destructive editing.
// =============================================================================

#pragma once

namespace fw::hooks {

// Arm a worker thread that, after `delay_ms` from now, posts
// FW_MSG_EQUIP_ANNOUNCE_FIRE (WM_APP + 0x52) to the FO4 main window.
// The handler runs on the main thread (safe to read PlayerCharacter)
// and emits one EQUIP_OP per non-empty apparel slot via
// `fw::net::client().enqueue_equip_op(...)`.
//
// Idempotent across a session: subsequent calls during an in-flight
// announce are no-ops (state machine in the .cpp handles ARMED → DONE).
// Use `arm_equip_announce_for_peer_join` to re-fire after a previous
// cycle completed (DONE → ARMED transition).
//
// Safe to call from any thread (just spawns a worker).
//
// !!! NON TESTATO — UNTESTED. See header banner. !!!
void arm_equip_announce_after_loadgame(unsigned int delay_ms);

// Re-arm the announce when a new peer joins MID-SESSION. Same behavior
// as arm_equip_announce_after_loadgame but allows the DONE → ARMED
// transition (the boot-time arm only allows IDLE → ARMED).
//
// Replaces the prior `arm_equip_cycle_for_peer_join` semantics: the new
// peer needs to know what apparel the local player is currently wearing,
// since they joined after our boot-time announce. Re-fire fixes that.
//
// !!! NON TESTATO — UNTESTED. See header banner. !!!
void arm_equip_announce_for_peer_join(unsigned int delay_ms);

// WndProc dispatch entry — called from main_menu_hook's fw_wndproc when
// it receives FW_MSG_EQUIP_ANNOUNCE_FIRE. Runs on the main thread.
//
// Walks PlayerCharacter::BipedAnim, identifies non-empty APPAREL slots
// (NOT weapons — those are covered by M9 witness pipeline), and emits
// one EQUIP_OP per slot via fw::net::client().enqueue_equip_op.
//
// !!! NON TESTATO — UNTESTED. The BipedAnim walk is currently a TODO.
//     See the CPP file for the enumeration TODO block + decomp refs. !!!
void on_equip_announce_fire_message();

// Set worker shutdown flag. Called at DLL_PROCESS_DETACH to let the
// worker exit cleanly if it's still sleeping. Safe to call multiple times.
void shutdown_equip_announce();

} // namespace fw::hooks
