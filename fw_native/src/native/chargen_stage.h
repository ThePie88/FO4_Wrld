// Chargen staging (2026-08-08) — put the player somewhere isolated to be
// created, and take them out of it again.
//
// WHY THIS EXISTS
//   Character creation happens once, on first entry to a server, and it needs
//   the player to hold still somewhere nothing can interrupt. The user's design:
//   teleport away, create, and let the ending put you where the server wants you.
//
// WHY THERE IS NO PAUSE
//   This project removed it — pausing is meaningless in a shared world, and the
//   game is deliberately kept running when ESC is pressed. So the isolation has
//   to be physical rather than temporal, which is exactly what the teleport is
//   for: at altitude, nothing reaches you.
//
// WHY GRAVITY IS NOT A PROBLEM
//   Collision is turned off — the same thing the `tcl` console command does, via
//   the same engine setter its handler calls. Collision-off is a single flag bit
//   (0x800) on the 3D root's NiAVObject flags, so a floating player costs one
//   word.
//
//   An earlier attempt keyframed the Havok body instead, on the strength of what
//   the project does to mirrored NPCs. It failed live and the log measured the
//   failure: the player fell 1950 units in two seconds. The player is moved by a
//   character controller rather than by rigid-body integration, and the NPC
//   recipe needs BOTH a keyframe AND a bailed FinishPhysicsStep — only one of
//   which had been applied.
//
// WHAT THE ENDING WILL BE, AND WHY IT IS NOT THAT YET
//   The intended ending is that confirming the character sets the motion type
//   back to Dynamic, so the player falls, dies, and the server respawns them at
//   its spawn point. The fall IS the transition — no return teleport, nothing to
//   restore. That needs the server's spawn system, which does not exist yet, so
//   until it does the exit is a plain teleport back to the origin. Temporary, and
//   not a safety measure: falling simply has nowhere to land you today.
//
// WHAT IS DELIBERATELY ABSENT
//   No origin file, no crash-recovery persistence. An earlier draft had both,
//   built on the assumption that the FO4 save is authoritative for position. It
//   is not — the server is authoritative and persistent, so a crash mid-creation
//   puts the player wherever the server says, never in the sky.
//
// MAIN THREAD ONLY. Every engine call it makes says so.

#pragma once

#include <cstdint>

namespace fw::native::chargen_stage {

// Arm from config. `z_offset` is how far up to go, in game units (the player is
// roughly 120 units tall, so a few thousand is clearly airborne). 0 disables the
// module entirely and every function below becomes a no-op.
void init(float z_offset);
bool armed() noexcept;

// True while the player is staged: keyframed, airborne, camera forced.
bool staged() noexcept;

// Stage or unstage. Idempotent in both directions.
//
// Staging: save the origin, force third person, keyframe the Havok body, and
// teleport up by the configured offset. Unstaging: teleport back to the saved
// origin, restore collision to whatever it was, and leave the camera where the
// user left it — the camera is theirs once they are on the ground again.
//
// Returns true if the state changed.
bool stage(std::uintptr_t module_base);
bool unstage(std::uintptr_t module_base);

// Re-assert what the engine keeps undoing. Call once per main-thread tick; it
// is a single word read when there is nothing to do, and a no-op when not
// staged.
//
// It exists because something in the engine re-enables collision on essentially
// every frame — measured at 1581 re-asserts over eighty seconds. Who clears it is
// not identified; this wins the fight because our write lands after theirs, and
// without it the player is handed back to gravity within a frame.
void tick(std::uintptr_t module_base);

// The position to report to the server while staged.
//
// The ritual holds appearance publishing, but position streaming has its own
// path and would otherwise send peers our sky coordinates — their ghosts of us
// would fly up too. Silence would be safe (the server refreshes liveness on ANY
// frame, not only POS_STATE) but reporting the ORIGIN is better: it keeps
// liveness unconditional and shows peers where we will actually be when this is
// over, which is truthful rather than merely quiet.
//
// Returns false when not staged, in which case the caller sends the live
// position as usual. Safe to call from the position-poll thread.
// Reconcile the staged world with the editor's own flag, and retry until it
// takes. MAIN THREAD ONLY; safe and cheap to call every tick.
//
// WHY THIS EXISTS. stage() and unstage() used to be called from the F2 key
// handler and nowhere else, which quietly meant the ritual only ever happened
// because somebody pressed a key. When the SERVER asked for it -- the WELCOME
// payload's chargen_required, which is the real trigger the whole feature is for
// -- the flag went up, the panel appeared, and the player stayed standing on the
// ground: the editor and the staging were being driven by two different things.
// The visible symptom was having to cycle F2 twice before the character showed up
// in the sky, which read like a timing bug and was actually a missing caller.
//
// Driving it from the flag instead makes one rule out of two: whoever raises the
// flag -- the key, the server, or a future CONFIRM path -- gets the staging that
// belongs with it. It also gets the retry for free, which matters because the
// flag is raised while the save is still loading and the first several attempts
// cannot possibly succeed.
void sync(std::uintptr_t module_base);

bool report_pos(float out_xyz[3]) noexcept;

// Turn the staged camera around the character, an eighth of a turn at a time.
//
// Began as a calibration aid -- AutoVanityState's orbit angle has no documented
// zero, so it was walked round on screen until the face came front-on at 45
// degrees, which is now the default. Kept afterwards because inspecting the model
// from another side is a thing a character creator should let you do.
void nudge_camera_yaw(bool backwards) noexcept;

// Move the staged camera in or out, ten units at a time.
//
// `further` increases fDefaultAutoVanityZoom, because a larger value is further
// away -- established from vanilla's 300 framing the whole character against 35
// framing it from the nose down. The default, 65, is head and shoulders.
void nudge_camera_zoom(bool further) noexcept;

}  // namespace fw::native::chargen_stage
