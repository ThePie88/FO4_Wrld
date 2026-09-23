// =============================================================================
// equip_announce — what the local player is WEARING, announced at every
// session start (session lifecycle, phase 3).
// =============================================================================
//
// WHAT IT SOLVES. An item already worn when the save loads fires no engine
// equip event, so nothing ever told the server — or the other clients — that
// the player had it on. A peer who never changed clothes during a session
// replayed naked, and a server restart made it worse: the stored outfit came
// back from the snapshot empty (measured 2026-09-23: the peer wearing the
// Vault 111 suit had 0 items stored, the other had 2).
//
// WHAT IT DOES. At every session start — first join, resume after a drop,
// resume after a server restart — once the local scene has settled, it walks
// the local player's inventory, keeps the stacks the engine marks as
// equipped and whose form is apparel, and sends one EQUIP per item through
// the ordinary equip path. The server records each one in the stored outfit
// (which it forgets at every (re)join, see clear_presence_outfit) and relays
// it to the others, whose ghosts get dressed exactly as if the player had
// equipped the item in front of them.
//
// THE MEASUREMENT IT STANDS ON (2026-09-23). The engine's own filter for an
// equipped stack is (stack flags byte at +0x24 & 7) != 0 — documented above
// the PA inventory dump in pa_pipeline_trace.cpp, but until that day only
// ever measured on a power-armor frame, where it is always zero. On the local
// player, against the truth the user reported:
//
//   0x0001EED7 Vault 111 suit   type 0x1D  flags 0x01   worn        yes
//   0x00021B3B Pip-Boy          type 0x1D  flags 0x01   worn        yes
//   0x00004822 10mm pistol      type 0x2B  flags 0x01   equipped    yes
//   0x0008C14D baton            type 0x2B  flags 0x00   not         no
//   0x00023736 stimpak (x2)     type 0x30  flags 0x00   not         no
//   0x0001F276 10mm ammo (49)   type 0x2C  flags 0x00   not         no
//
// Three true positives, four true negatives. The baton is the proof that
// matters: the same form type as the pistol, and the only difference between
// the two is that bit. The form type byte is at +0x1A of the bound object:
// 0x1D apparel, 0x2B weapon, 0x30 consumable, 0x2C ammo.
//
// WHAT THE MAY 2026 SCAFFOLD THAT LIVED HERE GOT WRONG. It planned to walk
// BipedAnim, which was never reverse-engineered, and left the walk as a TODO.
// Three of its guesses are now contradicted by measurement, and are written
// down because each is exactly what someone would rebuild in good faith:
//   * "FORM_TYPE_WEAP (0x29) at TESForm+0x40" — a weapon is 0x2B at +0x1A.
//   * "Skip the PIPBOY, it's always there" — the ghost attaches the Pip-Boy
//     like any other piece, under PipboyBone since v0.6.5, so it is sent.
//   * "effective_priority 0, apparel has no OMOD priority" — armor with
//     Lite/Mid/Heavy upgrades picks its ARMA tier from exactly that number.
//
// WHAT IT KEPT FROM THAT SCAFFOLD, because it was right:
//   * NO ENGINE CALL. B8, the force-equip cycle this replaces, crashed inside
//     the engine's own equip path. This only reads memory.
//   * THE WIRE IS THE ORDINARY EQUIP. The receiver needs no new code and
//     cannot tell an announce from a live equip. The scaffold called this
//     "Option B, client-side" and predicted that "Option A", a server-side
//     outfit store, would one day consume it with no protocol change. That
//     day was v0.8.0: the store is the server's presence record.
//
// WEAPONS ARE NOT ANNOUNCED. The equipped pistol shows up in the walk, but a
// weapon reaches the ghost through its own path, with the mesh descriptors
// the witness pipeline captures when it is drawn; an EQUIP without them
// degrades the weapon to its base mesh. Left to that path on purpose.
//
// THREADING. equip_announce_on_session_start is called from the NETWORK
// thread at WELCOME and only raises a flag. equip_announce_tick runs on the
// MAIN thread from the WndProc tick, and is the only place that reads the
// inventory: every inventory mutation path this project knows is main-thread
// too, which is why the list lock at +0x78 is not taken (the PA dump reasons
// the same way).
// =============================================================================

#pragma once

namespace fw::hooks {

// A session has just started (WELCOME accepted). Asks the tick to announce
// the local player's worn items as soon as the scene has settled. Any thread.
void equip_announce_on_session_start();

// MAIN THREAD, from the WndProc tick. Does nothing until a session start has
// asked for an announce AND the stability gate says the scene has settled
// (player in the world, a cell, no load in flight, no 3D rebuild under us),
// then walks the inventory once and sends one EQUIP per worn apparel item.
void equip_announce_tick();

} // namespace fw::hooks
