// Build 30 Fix 2 — Hostility-rank baseForm guard.
//
// Hooks `sub_140C8DFF0` (RVA 0xC8DFF0, funcs_0303.md:2895) — the engine's
// per-actor relationship-rank evaluator used inside IsHostile checks and
// AddTarget's validation loop. The function reads `*(a1+0xE0)+0xB8` =
// TESActorBase factions BSTArray for both args. When a1 is a STALE
// known_target Actor* (handle freed but engine never purged from
// controller+32 known_targets[]), baseForm garbage → BSTArray walk into
// unmapped memory → AV at `sub_140308AA0` (Agent 1 dossier 2026-05-16).
//
// This hook validates baseForm sanity (formType byte 0x2D/0x2E for
// TESNPC/LCHAR, factions header readable) BEFORE the call. If either arg
// has invalid baseForm → return 0 (= "no hostility") instead of letting
// the engine crash. The crash chain that previously caused spinlock leak
// at AddTarget (Build 29.2 freeze) → main-thread freeze is preempted.
//
// Performance note: this hook is on a HOT PATH (every IsHostile evaluation).
// The validation cost is 3 reads + 1 SEH cage per call. Negligible vs
// the cost of the original function (factions list walk + multiple sub-calls).
#pragma once

#include <cstdint>

namespace fw::hooks {

// Install the MinHook detour. Idempotent.
bool install_ghost_hostility_guard(std::uintptr_t module_base);

// Build 65.c.29 — install the DIRECT collector guard on sub_140308AA0 (the
// faction-list collector that actually AVs at RVA 0x308AE7). Covers all 15
// hostility/relation callers at one choke point. Call UNCONDITIONALLY — it's
// the anti-crash net Build 64 disabled as collateral damage. Idempotent.
bool install_ghost_faction_collect_guard(std::uintptr_t module_base);

// Build 65.c.30 — install the crash guard on sub_1404CAE90 (RVA 0x4CAE90).
// Prevents the AV at RVA 0x4CAF43 (read of nulled player-target singleton
// [2131]+0x50) during the player-death → reload cell-teardown window. Returns
// 0 (= "no target") when global[2131] is null. Idempotent. Call UNCONDITIONALLY.
bool install_ghost_target_resolve_guard(std::uintptr_t module_base);

// Counter accessors for diagnostics.
std::uint64_t get_hostility_guard_bypass_count();
std::uint64_t get_hostility_guard_passthrough_count();
std::uint64_t get_hostility_guard_seh_count();
std::uint64_t get_faction_collect_bail_count();
std::uint64_t get_faction_collect_pass_count();
std::uint64_t get_death_guard_bail_count();
std::uint64_t get_death_guard_pass_count();
std::uint64_t get_death_guard_seh_count();

} // namespace fw::hooks
