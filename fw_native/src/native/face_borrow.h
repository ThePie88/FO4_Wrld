// Face borrow (2026-08-08) — build a PEER's face using the local engine.
//
// THE PROBLEM
//   On this machine only the engine can build a head, and only from a TESNPC.
//   A peer's ghost has no TESNPC — it is an assembled NiNode tree. The only
//   TESNPC available is the local player's. So producing peer X's face means
//   borrowing it:
//
//       save my recipe -> apply X's -> Reset3D -> wait -> clone -> restore mine
//
//   The result is parked in face_cache as X's master, and every later ghost
//   assembly clones from that. One borrow per peer per appearance, not per
//   assembly — the ghost is reassembled on every cell change and respawn, and
//   flickering the local character that often would be unacceptable.
//
// WHY A STATE MACHINE AND NOT A FUNCTION
//   Reset3D is ASYNCHRONOUS (CHARGEN_PLAN §18): it queues work and the head
//   builder runs a frame or more later. There is nothing to clone at the
//   moment of the call. So the borrow spans ticks, and "the rebuild finished"
//   is OBSERVED — the player's face node pointer becomes a different node —
//   never assumed from a return code.
//
// THE INVARIANT THAT MATTERS
//   Once the peer's recipe has been written to the local player, the local
//   player is WRONG until it is undone. Restore is therefore not the last
//   step of a happy path: it is unconditional. Every failure, every timeout,
//   every SEH lands in the restoring state. The saved recipe is captured
//   BEFORE anything is touched, and if the restore itself cannot be verified
//   the module refuses to start another borrow rather than compound the
//   damage.
//
// COST, STATED PLAINLY
//   For a frame or two the local character wears someone else's face. In first
//   person that is invisible; in third person it is a flicker. It happens once
//   per peer per appearance. At join, with several peers, borrows are
//   serialised — never concurrent, because they would fight over the one
//   TESNPC they all need.
//
// MAIN THREAD ONLY.

#pragma once

#include <cstdint>
#include <string>

namespace fw::native::face_borrow {

// Arm a SYNTHETIC peer, for testing the borrow with no network and no ghost.
//
// It registers a fake peer whose recipe is the LOCAL player's own with the
// hair colour swapped to `hair_form_id`. That makes the borrow observable and
// unambiguous: the built master must have the swapped colour (so the clone
// captured the REBUILT face, not the original), and the local player must end
// up back on its own colour (so the restore worked). Both are visible in the
// log; the swap is also briefly visible on screen.
//
// This isolates the dangerous half — writing another appearance onto the local
// player and undoing it — from the ghost plumbing, so a failure has one
// possible cause instead of two. 0 = off.
void arm_test_peer(std::uint32_t hair_form_id);

// Drive the machine. Call once per main-thread tick; it is cheap when idle.
// Picks up peers that have a recipe in face_cache but no matching master, and
// builds them one at a time.
void tick(std::uintptr_t module_base);

// True while a borrow is in flight — i.e. the local player is currently
// wearing somebody else's appearance. Anything that reads the local player's
// appearance MUST consult this: publishing during a borrow would broadcast
// the borrowed face as our own and make every other client wrong too.
bool in_progress() noexcept;

// Human-readable state, for the log and for diagnosing a stuck borrow.
const char* state_name() noexcept;

// How many borrows completed, and how many had to be abandoned. A non-zero
// abandon count is the signal to look at the log rather than the screen.
std::uint32_t completed() noexcept;
std::uint32_t abandoned() noexcept;

}  // namespace fw::native::face_borrow
