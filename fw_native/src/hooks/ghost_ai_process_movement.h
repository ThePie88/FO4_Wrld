// B6.6w0 hook (process packages movement) — `AIProcess::ProcessPackages_Movement`.
//
// Per B1 dossier: this is the per-frame movement DECISION funnel for
// NPCs at RVA 0xCEEC30. Sits upstream of the pos writers we already
// hook (SetPosition_NiPoint3, vt[202], Havok FinishPhysicsStep).
// Iterates the actor's AIPackages, switches on package type, and
// drives pos writes via `sub_140513A80(actor, target_pos)`.
//
// Size 0x844, NON-inlined (B1 caller chain verified).
//
// Signature per pseudo-C (funcs_0309.md:3588):
//   __int64 __fastcall sub_140CEEC30(__int64 a1, __m128 *a2, char a3);
// where:
//   a1 = AIProcess*  (rcx)
//   a2 = Actor*      (rdx) — IDA inferred __m128* but it's a TESForm
//   a3 = char        (r8b)  — flag (probably "should commit pos")
//
// BAIL strategy: if Actor* in rdx is tracked, return 0 — skip movement
// decision entirely. Defense in depth with downstream pos hooks.
#pragma once

#include <cstdint>

namespace fw::hooks {

bool install_ghost_ai_process_movement(std::uintptr_t module_base);

std::uint64_t get_ghost_ai_process_movement_fires();
std::uint64_t get_ghost_ai_process_movement_bails();
std::uint64_t get_ghost_ai_process_movement_seh_failures();

} // namespace fw::hooks
