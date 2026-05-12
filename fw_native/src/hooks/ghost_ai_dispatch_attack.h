// B6.6w0 hook (dispatch attack action) — `Actor::DispatchAttackAction`.
//
// C1 dossier identified this as the universal attack-action funnel:
// after any CBT leaf decides to fire/swing (single-shot, burst,
// suppressive, melee, power attack), this is the single function the
// engine calls to:
//   1. Construct BGSActionData on stack
//   2. vfcall TESActionData::vtable+40
//   3. Emit anim graph event "WeaponFire" (or melee equivalent)
//
// Signature per pseudo-C (funcs_0334.md:7289):
//   __int64 __fastcall sub_140E6F830(__int64 a1, int a2, int a3);
//
// a1 = Actor* (the attacker), per C1 chain context "Actor::DispatchAttackAction"
// a2 = int   = action_id (3D/3E/23/27/...)
// a3 = int   = flags?
//
// BAIL strategy: if Actor* in rcx is tracked AND not player (0x14),
// return 0 — no anim event, no projectile, no melee swing. Catches
// ALL fire variants and ALL melee attacks in a single hook.
//
// Compared to `CombatBehaviorGunFire::DecideAndFire @ 0x86FCA0`
// (also hooked, single-shot only), this hook is the universal funnel
// and should catch burst-fire / suppressive-fire / melee raiders.
#pragma once

#include <cstdint>

namespace fw::hooks {

bool install_ghost_ai_dispatch_attack(std::uintptr_t module_base);

std::uint64_t get_ghost_ai_dispatch_attack_fires();
std::uint64_t get_ghost_ai_dispatch_attack_bails();
std::uint64_t get_ghost_ai_dispatch_attack_seh_failures();

} // namespace fw::hooks
