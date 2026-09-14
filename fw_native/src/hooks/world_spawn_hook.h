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

namespace fw::hooks {

bool install_world_spawn_hook(std::uintptr_t module_base);

}  // namespace fw::hooks
