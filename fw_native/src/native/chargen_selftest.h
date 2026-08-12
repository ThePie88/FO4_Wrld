// Chargen self-test (2026-08-08) — drive the engine's own appearance
// functions from our code, on the LOCAL PLAYER, and watch the screen.
//
// WHY THIS EXISTS
//   Everything so far was observation: the three apply functions were
//   watched with real arguments, never called. The donor architecture
//   (CHARGEN_PLAN §12) rests on the receiving client applying a recipe to a
//   TESNPC and letting ITS engine do the work — so the first thing that must
//   be proven is that OUR code can make the engine change an appearance at
//   all. The player is the right subject: it is the one thing that
//   definitely has a TESNPC.
//
// WHAT IT DOES
//   One shot, from the main thread, once the player is loaded:
//     1. resolve the configured form id,
//     2. check its form type so a typo cannot hand a random form to the
//        engine,
//     3. call the matching apply function on the player's TESNPC,
//     4. log, and leave the rest to the eye.
//
//   Colour forms (type 137) go to sub_140654DF0, head parts (type 15) to
//   sub_140655010. Both signatures are validated empirically, not guessed:
//   the capture detours chained through them 108 and 186 times respectively
//   across several sessions without a fault. That matters — a wrong arity is
//   what crashed New Game on 2026-08-08.
//
// WHAT IT DELIBERATELY DOES NOT DO
//   It does not call REFRESH. Two of that function's nine arguments are
//   still unidentified, and inventing them is the exact mistake this project
//   keeps paying for. So the test answers a real question either way:
//   if the change shows up, the apply alone is enough and no rebuild trigger
//   is needed; if it does not, the rebuild trigger is the next target and we
//   will know it is genuinely required rather than assuming so.
//
// SAFETY
//   Off unless `chargen_selftest` holds a form id. Main thread only. It
//   mutates the player's own appearance in a running game — cosmetic, not
//   persisted unless the game is saved afterwards.

#pragma once

#include <cstdint>

namespace fw::native::chargen_selftest {

// Arm from config. `form_id` 0 means disabled. `delay_s` holds the apply back
// until that many seconds after the player first becomes available — the
// difference between "the apply updates a head that already exists" and "the
// apply merely arrived before the head was built". The first run fired 8 s
// after load and the hair did come out red, which does not separate those two.
void init(std::uint32_t form_id, std::uint32_t delay_s);

// Donor demonstration. `npc_form_id` is an NPC_ record that will receive the
// LOCAL PLAYER'S recipe — read off the player, written onto that NPC through
// the engine's own apply calls. Its next 3D build renders it with the
// player's face, which is the donor architecture (CHARGEN_PLAN §12) shown
// end to end without creating a single form.
//
// It mutates a SHARED base record, so every actor using it is affected. That
// is fine for a demonstration and costs nothing permanent: form records are
// runtime state, and a restart restores them unless the game is saved.
// 0x0020593F (LCharWorkshopNPC) is the obvious subject — settlers use it.
void init_donor(std::uint32_t npc_form_id);

// True while armed and not yet fired.
bool enabled() noexcept;

// Resolve, validate, apply. MAIN THREAD ONLY. Self-disarming: retries until
// the player is available, runs once, never again.
void maybe_run(std::uintptr_t module_base) noexcept;

}  // namespace fw::native::chargen_selftest
