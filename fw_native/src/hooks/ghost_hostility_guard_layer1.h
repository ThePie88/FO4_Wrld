// Build 50 Strada A — Layer-1 IsHostile gateway hook.
//
// Hooks sub_140C7AD40 (RVA 0xC7AD40), the LAYER-1 IsHostile gateway that
// sits ABOVE the existing hostility_guard hook on sub_140C8DFF0 (LAYER 3).
//
// Why a second hook: the existing guard on C8DFF0 never fires in production
// because sub_140C7AD40 short-circuits on cached, in-combat-state-3,
// has-owner, or has-rank-record paths. The engine reaches C8DFF0 only via
// sub_140C7AD40 LABEL_55, gated by 4 conditions that all happen to be
// FALSE in the ghost case. By hooking layer 1 we catch every perception /
// combat-target-validate / AlarmPackage::ScanTargets query that touches
// the ghost.
//
// Force-return-1 contract: when (a1 == ghost) OR (a2 == ghost), return 1
// (= hostile). The engine's downstream EnterCombat / AddTarget / target-
// selector chains accept this and promote the raider to combat tier vs
// the ghost. From there gate D (alive count) auto-flips when the 0x190
// combat extension is allocated. Gates B (weapon-state class) and C (aim
// solver) are the remaining unknowns; they MAY auto-prime via the combat
// orchestrator's aim-update chain after EnterCombat, or they MAY require
// the puppet-fire fallback documented in NPCs.md.
//
// SAFETY: SEH-caged. Replicates the engine's `a2 == a1 -> 0` self-check
// before the ghost-equality test to avoid ghost-vs-ghost returning 1.
// Skips the engine's per-record cache write at +0x48|=4 for ghost-
// involving pairs (next query recomputes; cost ~negligible). Suppresses
// event-#7 dispatch via sub_140618520(7,...) for ghost-involving pairs;
// vanilla FO4 has no event-7 listener registered, so no observable effect.
//
// Verified by 4-agent RE arena (re/strada_A_ishostile_master/):
//   - A_AGENT_body_decomp.md (92% conf, GREEN)
//   - B_AGENT_caller_xref.md (85% conf, GREEN; ~95% coverage of acquire/
//     enter-combat flows; top perception callers: AlarmPackage::ScanTargets,
//     Combat::ProcessTarget, EnterCombatWith)
//   - C_AGENT_side_effects.md (60% conf, YELLOW-GREEN; gates B+C remain
//     unproven; downstream auto-prime is the load-bearing unknown)
//   - SUPERVISOR_SYNTHESIS.md (60% aggregate, GREEN to ship; SAFE)
#pragma once

#include <cstdint>

namespace fw::hooks {

// Install the MinHook detour. Idempotent.
bool install_ghost_hostility_guard_layer1(std::uintptr_t module_base);

// Counter accessors for diagnostics.
std::uint64_t get_hostility_guard_l1_force_count();
std::uint64_t get_hostility_guard_l1_passthrough_count();
std::uint64_t get_hostility_guard_l1_seh_count();
std::uint64_t get_hostility_guard_l1_self_check_count();

} // namespace fw::hooks
