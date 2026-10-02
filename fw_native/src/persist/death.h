// L5 stage 3c (2026-09-28) — death without a reload.
//
// DECISION 2026-09-28, after the fourth live test: EVERY DEATH GOES THROUGH
// THE RELOAD. The engine reloads the last checkpoint, which resets
// everything the resurrect had to rebuild by hand (the AI process, VATS,
// the camera), and the fast travel to the server's respawn point follows
// once that world is back: the path that landed on the fourth live test.
// The resurrect described below is kept behind `death_resurrect` in the
// ini, off. A respawn point chosen by the server's founder in an .ini,
// used at death and at the first entry, is a later task.
//
// STAGE 3d, 2026-09-29: the reload lands on the point. The server answers
// a death (PLAYER_LIFE died) with CKPT_RESPAWN: the player's boot
// checkpoint moved onto the respawn point and booked in custody. This
// module swallows the engine's reload, fetches that file from custody and
// loads it (the boot's commanded load): one loading screen, the
// destination loaded by the load itself, no fast travel. Any failure, no
// answer within ten seconds, or an answer without a checkpoint (power
// armour, an interior, no custody) runs the engine's reload and the fast
// travel as before.
//
// Vanilla: five seconds after the player dies (fPlayerDeathReloadTime),
// PlayerCharacter's death update (sub_140D7AD20) queues the death reload
// (flag 4 on the save/load manager, sub_140BFE4C0) and the engine loads
// the last save. In this world that was the last checkpoint: the server's
// world rewound in the player's eyes (every replica destroyed and placed
// again, the containers bootstrapped again), and a death ten seconds after
// a checkpoint put the player back into the fight it had just lost.
//
// Here the lifecycle module hands that queued flag to this module first.
// When the server gave a respawn point (CKPT_BOOT; a server option,
// `--respawn`, Sanctuary by default), the player is dead and not in power
// armour, the flag is swallowed and, at the next frame, from the task
// processor's detour (main thread, the engine's own save point):
//   1. the player's own Resurrect: vtable slot 0xCC, PlayerCharacter's
//      override sub_140D5DDC0, which frees the AIProcess and makes a new
//      one, then the base Actor::Resurrect (sub_140C61CF0: health and
//      limbs restored, the dead flags cleared, the life state back to
//      alive; the inventory is never reset on the player). Our captured
//      pointer to the old process is forgotten right before.
//   2. up to thirty frames watching the life state and the health cell
//      (Actor+0x444) until both say alive;
//   3. the camera out of the kill-cam (sub_1410265B0, the engine's own
//      return to the first person, then the first-person state by hand if
//      it is still elsewhere), the teleport to the respawn point (the
//      Actor::MoveTo with the process update the boot already uses), and
//      PLAYER_LIFE to the server.
// Any failure, and a death in power armour, re-queue the flag through the
// engine's own function: the reload of the last checkpoint runs as in
// stage 3a. Every step is logged with the life state and the health it
// saw, because the first live death will decide what the engine forgot to
// give back (controls, HUD) and this log is where that is read.
//
// What a death costs in this stage: nothing. Health and limbs come back,
// the inventory, XP and perks stay (decision 2 of the dossier, open).

#pragma once

#include <cstdint>

namespace fw::config { struct Settings; }

namespace fw::persist::death {

// The switch (persist_lifecycle) and the module base.
void configure(const fw::config::Settings& cfg);

// CKPT_BOOT (net thread): the server's respawn point, or none.
void set_respawn_point(bool has, const float pos[3], float yaw);
bool respawn_point_known();

// True while a death is being handled (from the swallowed reload to the
// landing, or through the fallback reload): the checkpoint gates read it.
bool respawn_in_progress();

// True from the resurrect to the landing (and through a fallback reload):
// the render overlay covers the screen with a curtain, because the far
// move shows the loading of the destination and every ghost we render on
// it. Any thread.
bool curtain_active();

// v33 (net thread): the server's answer to the death, the checkpoint it
// moved onto the respawn point (has) or none.
void on_respawn_checkpoint(bool has, const char* name, const std::uint8_t sha256[32],
                           std::uint32_t size);

// The kill hook (main thread, inside the engine's Kill): the local player
// just died. Reported to the server at once.
void note_killed();

// The lifecycle's queue detour (main thread): the engine queued the death
// reload. True = swallowed, this module respawns the player; false = the
// reload runs: every death by default (see the decision above), then the
// fast travel to the point once that world is back.
bool on_death_reload_queued(void* save_load_mgr);

// The task processor's detour, once per frame on the main thread: the
// resurrect, the verification, the teleport, or the fallback.
void run_pending(void* save_load_mgr);

} // namespace fw::persist::death
