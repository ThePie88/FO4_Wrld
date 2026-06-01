// Build 38 (2026-05-16) — combat target ENGAGE cell-gate defeater.
//
// Hooks `sub_140CF6100` (RVA `COMBAT_ENGAGE_GATE_RVA = 0x00CF6100`),
// the engine's target engagement / cell-gated commit function.
//
// Problem: ghost was spawned with `AttachREFR` bypassed → ghost+0xB8
// (parent_cell) is stale (Sanctuary cell from spawn time) while PC
// teleports to other cells (Concord). The engine's gate at
// funcs_0309.md:9926 reads `PC.parent_cell == target.parent_cell`
// and if mismatch goes to LABEL_28 (no commit). Result: raider
// stays in weapon-ready pose, never advances to fire / swing.
//
// Build 37 attempted to satisfy this by DIRECT write
// `ghost+0xB8 = PC.parent_cell` every PEER_POS tick. That triggered
// catastrophic crash because per-tick walkers OUTSIDE the gate
// then processed the ghost as in-cell and iterated baseForm
// sublists with incomplete vt[103] (PlayerNPC entries with sentinel
// past vtable end).
//
// Build 38 strategy: TRANSIENT cell swap INSIDE the hook detour.
// Save+write+orig+restore — the swap is visible ONLY to the call
// stack of `sub_140CF6100` itself. Per-tick walkers run between
// engine calls and see stale ghost.cell → don't process ghost as
// in-cell → no crash.
//
// Verified callees of sub_140CF6100 that DON'T read target.cell:
//   - sub_140CF42F0 (primary commit path) — calls sub_140CF1130
//     directly; reads PC singleton + target flags, not target.cell
//   - sub_140CF1130 (final commit) — calls sub_140CE9940 (thread-
//     safe target swap on AIProcess), sub_14028A780, sub_140CFCC70,
//     sub_14087B780 (activate target.AIProcess); none read cell
//   - sub_140CE9940 — pure thread-safe slot swap, no cell access
//
// Coverage: this hook addresses the COMBAT engage gate only. The
// pathfinding gate at sub_140B63AA0:7476 (same pattern) is NOT
// patched yet — melee raiders may still fail to approach the
// ghost. Ranged raiders (the primary symptom) should now fire.
#pragma once

#include <cstdint>

namespace fw::hooks {

bool install_cross_cell_gate(std::uintptr_t module_base);

std::uint64_t get_cross_cell_gate_fires();
std::uint64_t get_cross_cell_gate_swaps();
std::uint64_t get_cross_cell_gate_passthroughs();
std::uint64_t get_cross_cell_gate_seh_failures();

} // namespace fw::hooks
