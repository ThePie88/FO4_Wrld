// Build 70m — POWER ARMOR PIPELINE TRACER. OBSERVE-ONLY, zero writes.
//
// Purpose, stated by the user in plain terms: stop patching around symptoms
// and LOG whether the Creation Engine's own PA pipeline runs correctly, step
// by step, when a player enters a frame. Every hook below sits on an RVA
// reverse engineered and (where marked) read end to end in
// re/pa_system_model.md + re/sweep_pa_settlements/DEEP_140989A40.md.
//
// The engine's enter/exit machine (state byte = ExtraPowerArmor+0x28):
//
//   state 7 (no extra)
//     ENTER  sub_140989A40(actor, frame, mode)        [hooked, sig verified]
//       1  GetOrCreate extra 0xBB (sub_140290450), SetState(1)
//       2  six PowerArmor*Condition AVs pushed
//       3  LINK: frame handle -> extra+0x18 (sub_140290560)
//       4  armo = sub_140987BA0(actor, 0); inventory flag
//       5  conflicting-equipment strip (the mass unequip on the wire)
//       6  RACE SWITCH: PA race -> extra+0x20 (sub_140290640, race from
//          sub_140374740) — Actor::GetRace returns extra+0x20 from now on
//       7  frame side: furniture marker, inventory, piece transfer
//       8  equip armo (sub_140502940)
//       9  player only: camera + CamTarget save
//      10  MODEL RELOAD: sub_140D35EA0(proc, 1312)    [hooked]
//          + sub_140D020E0(proc, actor, 1)            [hooked]
//      11  sub_140337EE0 = frame made PERSISTENT
//      12  frame DISABLED via deferred task 74
//      13  SetState(2) = FULLY IN
//     EXIT REQUEST sub_14098BAF0(actor, x)            [hooked]
//     REPLAY sub_14098C9D0(actor)                     [hooked, sig verified]
//          = the save loader's "put this actor back into its armor"
//
// Each detour logs [pa-trace] with: actor/frame fids, the extra-0xBB triple
// (state byte, frame handle, race ptr) BEFORE and AFTER, the actor's 3D
// root, and the PA-race global for comparison. The log answers, per enter:
// did the extra appear, did the race switch, did the reload fire, did the
// state reach 2 — and on which exact step the pipeline diverged.

#pragma once

#include <cstdint>

namespace fw::hooks {

bool install_pa_pipeline_trace(std::uintptr_t module_base);

// Build 70q — tick count (GetTickCount64) of the LOCAL PLAYER's most recent
// PA transition (enter, exit request, or save-load replay). 0 = never.
// Any-thread safe. The equip drain uses it to DEFER the ghost's PA armor
// attach while the local player's own PA 3D build may be in flight — the
// measured 70j-era corruption window (our cache load + postproc landing
// inside the engine's rebuild).
std::uint64_t last_local_pa_transition_ms();

// Build 70u — REPLAY THE ENGINE'S OWN MODEL RELOAD ON THE LOCAL PLAYER.
//
// The strongest fact in this whole hunt is that the SECOND power-armour
// body build after a ghost PA attach is always correct: whatever the attach
// perturbs, a build repairs on its way through. So instead of hunting the
// perturbation, force the second build.
//
// This is not a synthetic operation — it is exactly what the enter pipeline
// itself issues at its step 10, captured live by the tracer below:
//     sub_140D35EA0(process, 1312)      // PA skeleton rebuild
//     sub_140D020E0(process, actor, 1)  // 3D rebuild from the current race
// with the process pointer the ENGINE passed for the player, not one we
// derived. Main thread only; SEH-caged; no-op until the tracer has seen a
// player reload (i.e. until the engine itself has run this pair once).
//
// Returns true if the pair was issued.
bool force_local_pa_model_reload();

// E0 (PA pieces milestone, 2026-08-16) — [pa-inv] dump of a REFR's
// inventory (entries, stacks, counts, the +0x24 flags byte the engine
// filters mounted stacks with). Layout from sub_14051F050, the engine's
// own walker. Read-only, SEH-caged, main thread. Used by the PA enter
// detour (mounted set before/after the native piece transfer) and by
// world_spawn on frame rebirth at exit (the state a departing player
// leaves for others to replicate).
void dump_refr_inventory(const char* tag, void* refr);

}  // namespace fw::hooks
