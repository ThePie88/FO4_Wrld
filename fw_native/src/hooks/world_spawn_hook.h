// B6.14 — world-object spawn sync, the sending half (2026-08-12).
//
// A MinHook detour on the engine's PlaceAtMe native (RVA 0x1159C10) — the
// single funnel every "create a REFR in the world" call goes through, console
// `player.placeatme` included. The detour OBSERVES after the fact: it chains
// to the original first and only then reports, so it can never change what
// the engine does (the M9 equip-hook discipline, which ended a three-day
// crash hunt, applies unchanged here).
//
// FILTERS, in order:
//   1. The internal-place scope — our OWN PlaceAtMe calls (ghost donor,
//      chargen donor, and the receiver half of this very feature) must never
//      re-broadcast, or two clients would ping-pong spawns forever.
//   2. anchor == the local player. Console spawns, script spawns on the
//      player and dropped-at-player creations all anchor there; the engine's
//      internal uses (projectiles, leveled markers) do not. Everything
//      filtered is still logged at DBG with its identity, so the next wedge
//      knows what flows through this funnel before widening the gate —
//      observe first, arm later.
//
// The observed REFR is flagged TEMPORARY on the spot: from the moment the
// server records the spawn, the SERVER owns the object's lifetime, and a
// save that persisted the original would duplicate it against the join
// replay on the spawner's next session.

#pragma once

#include <cstdint>

namespace fw::net { struct PaPieceEntry; }

namespace fw::hooks {

bool install_world_spawn_hook(std::uintptr_t module_base);

// L5 stage 2 (2026-09-27) — a world REFR the player just DROPPED from the
// Pip-Boy (the remove core's drop branch, reason 3; persist/inventory_tap.cpp
// resolves the handle and calls this). No anchor to check: the engine made
// it for the player by definition. Announced as a SELF-DESCRIBED spawn
// (flags bit1): pieces[0] carries the REFR's own base, world count,
// condition and mods, read from its extra list, so the other clients place
// the same item and not a fresh roll of the base. `count_hint` is the
// count the remove asked for, used only when the list cannot be read (a
// bare descriptor is sent then, and the log says so). Harmless on every
// state: null REFR, zero identity, a REFR already bound to a wid, a session
// with world_spawn_sync=false (nothing installed, nothing sent). MAIN
// THREAD (the drop runs on it).
void report_world_drop(void* refr, std::uint32_t handle, std::int32_t count_hint);

// The announce itself, for a REFR some other module has decided is world
// state (native/world_spawn.cpp announces a rested drop through it): pose,
// TEMPORARY flag, the wire, one log line. `handle` binds the echo to the
// object (0 = fid only, the legacy binding). MAIN THREAD.
void announce_world_refr(void* refr, std::uint32_t handle, std::uint8_t flags,
                         const fw::net::PaPieceEntry* pieces, std::uint8_t pn,
                         const char* what);

}  // namespace fw::hooks
