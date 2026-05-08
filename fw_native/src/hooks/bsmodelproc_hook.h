// ============================================================================
// DEAD-END / KEPT FOR MEMORY OF HOURS PASSED — M9.w4 RE phase, Apr-May 2026
// ============================================================================
//
// This file represents a failed approach to M9.w4 (modded weapon
// visualization on the ghost). The working path landed in v0.5.0
// (see CHANGELOG.md) and uses the engine's `sub_140434DA0` per-OMOD
// attach helper plus BSConnectPoint pairing — implemented in
// scene_inject.cpp::ghost_attach_assembled_weapon.
//
// What was tried here: diagnostic hook on sub_1402FC0E0
// (BSModelProcessor post-hook), used to learn how the engine applies
// OMODs to a freshly-parsed BSFadeNode tree on a real engine call.
// Theory: synthetic load + fabricated BGSObjectInstanceExtra would
// reach this branch and apply OMODs in-place.
//
// Why it failed: live test showed weapon NIFs carry NO
// BGSObjectInstanceExtra (type 0x35) in their extra-data chain when
// the parser runs. The OMOD-apply branch in this post-hook NEVER
// fires for our use case. The static decomp suggested it would; the
// live receiver path doesn't reach it. Documented in CHANGELOG v0.5.0
// "Refuted along the way" section.
//
// Install call disabled in install_all.cpp; kept on disk because the
// arg-capture machinery is reusable for any future post-hook RE.
// ============================================================================
//
// Diagnostic hook for sub_1402FC0E0 — the BSModelProcessor post-hook
// where OMODs are applied to a freshly-parsed BSFadeNode tree.
//
// Per re/COLLAB_ALPHA_equip_chain.md §3.2:
//   Inside the NIF parser, if opts.flags has bit 0x08 AND the
//   BSModelProcessor singleton is non-null, the parser invokes
//   `MEMORY[0x1430E0290]->vt[1] = sub_1402FC0E0`. That function reads
//   the node's extra-data chain via `sub_141730390(*node)`, finds a
//   form-info entry, then calls `(form->vt[41])(form, *node + 4, 0)`
//   which is the actual OMOD-attach virtual.
//
// PURPOSE OF THIS HOOK
// ====================
// Capture in run-time:
//   • Each call's arguments (4 register args + stack)
//   • The node pointer (`*node`) and its extra-data chain
//   • Whether we hit the OMOD-apply branch (flag check)
//   • The form-info path (sub_141730390 → vt[39] → +0xC0)
//   • Whether the form's vt[41] is reached
//
// This tells us EXACTLY:
//   • What an "OMOD-bearing extra-data chain" looks like in memory
//   • Where the form pointer comes from on a real engine call
//   • What we'd need to construct to make this branch fire on our
//     own synthetic load
//
// TRIGGER
// =======
// Equipping a modded weapon (any way: Pipboy, hotkey, console) triggers
// a NIF parse for the weapon's mods, which goes through the parser
// post-hook. So we don't need 3D preview / Pipboy.

#pragma once

#include <cstdint>

namespace fw::hooks {

bool install_bsmodelproc_hook(std::uintptr_t module_base);

} // namespace fw::hooks
