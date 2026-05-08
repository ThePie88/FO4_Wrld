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
// What was tried here: diagnostic hook on sub_1404580C0 to capture
// real engine arg layout. Theory: this is the engine's load+clone+wrap
// helper, and with opts byte 0x2D (bit 0x08 set) it would trigger
// BSModelProcessor → OMOD apply in-place, threading our fabricated
// BGSObjectInstanceExtra via the 4th arg.
//
// Why it failed: sub_1404580C0 returns a stock NIF clone with no
// OMOD context. The 4th arg is BSFixedString* for SetName, NOT
// modelExtraData (refuted by separate follow-up agent decoding the
// function body). Documented in re/COLLAB_FOLLOWUP_sub1404580C0.md
// and CHANGELOG v0.5.0 "Refuted along the way" section.
//
// Install call disabled in install_all.cpp; kept on disk because the
// arg-capture rate-limited logging machinery is reusable for any
// future engine-internal RE.
// ============================================================================
//
// Diagnostic hook for sub_1404580C0 — the engine's "load NIF + clone +
// wrap" function (DELTA §8 candidate for our synthetic-load path).
//
// PURPOSE
// =======
// We don't yet know the exact signature of sub_1404580C0 nor the layout
// of its 4th argument (`modelExtraData`, per DELTA §10.a). Instead of
// burning another RE round on static decomp, this hook captures the
// args at run-time when the engine itself calls the function — most
// fertilely when the user hovers a modded weapon in the Pipboy 3D
// preview. By comparing logs from 3 trigger conditions:
//   • vanilla weapon (no OMODs)
//   • same weapon + 1 OMOD
//   • same weapon + 2 OMODs (e.g. scope + suppressor)
// we learn:
//   • which arg carries the modelPath (BSFixedString or const char*)
//   • where opts lives (the byte with bit 0x08 toggling BSModelProcessor)
//   • where modelExtraData lives + its layout (BGSObjectInstanceExtra*
//     direct, or wrapper struct with OIE inside)
//   • whether the function is sync (returns BSFadeNode*) or async
//     (returns task handle / void)
//
// We log: (a) the 4 register args (RCX/RDX/R8/R9) as raw qwords, (b)
// stack args 5+ as raw qwords, (c) hex dumps of pointer-shaped args
// (first 0x80 bytes), (d) the return value, (e) any non-null *out
// pointer the engine wrote.
//
// RATE LIMIT
// ==========
// First N fires per session, where N is small (default 12). The engine
// can call this from cell streaming, drop-weapon spawn, etc. — we want
// to capture the focused Pipboy traces without flooding the log.
//
// HOW TO USE
// ==========
// 1. Build + deploy the DLL.
// 2. Start FO4. Get into worldspace.
// 3. Open Pipboy → Items → Weapons.
// 4. Hover (cycle through) a vanilla weapon, then a modded weapon, then
//    a different modded weapon. Each hover triggers the load.
// 5. Read fw_native.log lines tagged "[subload-hook]". The deltas
//    between fires will identify each arg.

#pragma once

#include <cstdint>

namespace fw::hooks {

// Install MinHook detour at sub_1404580C0. Idempotent.
// Returns true on success.
bool install_subload_hook(std::uintptr_t module_base);

} // namespace fw::hooks
