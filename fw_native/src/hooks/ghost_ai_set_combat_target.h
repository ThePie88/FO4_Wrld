// B6.6w0 hook (REAL combat target writer) — `AIProcess::SetCombatTarget`.
//
// Per A1+A2 dossiers: this is the canonical writer of
// `*(AIProcess+0x6C) = target.formID` — the field the AI's combat
// decisions ACTUALLY read from. (Our previous `ghost_ai_combat_target`
// hook on `sub_140C5CCE0` is a pure mirror — it copies AIProcess+0x6C
// to Actor+0x380 for Papyrus; behavioral effect = nil.)
//
// Signature per A1 disasm (text_0093.asm:686-688):
//   void __fastcall sub_14087AB30(AIProcess* rcx, Actor* rdx);
//   - rcx = AIProcess* (the actor's AIProcess, owner identified via
//     our npc_ai_suppress reverse map: aiproc→fid)
//   - rdx = Actor*    (the NEW combat target — what we want to substitute)
//
// PHASE 1 (this commit): DIAGNOSTIC ONLY. Log first N fires with
// owner fid + target fid. Confirms hook semantics + that owner→fid
// lookup works for this call site. Substitution comes later when
// raider_brain is wired into main.py.
//
// PHASE 2 (future): for owner Actors in tracked set with
// `cache.combat_target_form_id != 0`, lookup_form_id the server's
// target and replace rdx Actor* before passing to original. The new
// target propagates to AIProcess+0x6C → AI's aim/fire pipeline uses
// our target on this client.
#pragma once

#include <cstdint>

namespace fw::hooks {

bool install_ghost_ai_set_combat_target(std::uintptr_t module_base);

std::uint64_t get_ghost_ai_set_combat_target_fires();
std::uint64_t get_ghost_ai_set_combat_target_substitutions();
std::uint64_t get_ghost_ai_set_combat_target_seh_failures();

} // namespace fw::hooks
