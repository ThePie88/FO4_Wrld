// Build 70 (Piano B Fase 0) — lifecycle tripwires. OBSERVE-ONLY.
//
// Two read-only detours that answer the question that has eaten whole test
// evenings: "WHO is destroying our objects?"
//
//   1. sub_140C23EC0 DestroyByHandle — every runtime object destruction in
//      the game funnels through here (read end to end this session,
//      funcs_0296.md). The detour logs dynamic (FF-space) refs with the
//      caller's return-address RVA, so the reaper names itself in one run.
//   2. sub_1403380C0 Unpersist(mgr, refr, tag, a4) — the power-armor EXIT
//      calls this on the frame, and it has a DESTRUCTION branch (verified
//      funcs_0143.md:11236): when `!parentCell || cell+0x44 == 0` it does
//      RemoveReference + GetHandle + DestroyByHandle. Mirroring a PA exit
//      while the frame's cell is unloaded DELETES the frame — the prime
//      suspect for the "armature sparite" class. The detour logs the
//      branch prediction before, and the nested-destroy count after.
//
// Neither detour writes engine state, bails, or filters the original call.
// Everything passes through untouched.

#pragma once

#include <cstdint>

namespace fw::hooks {

bool install_lifecycle_tripwire(std::uintptr_t module_base);

}  // namespace fw::hooks
