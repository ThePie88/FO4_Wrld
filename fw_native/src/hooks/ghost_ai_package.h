// B6.5w12 Ghost AI — hook #1: TESPackage::EvaluateConditions detour.
//
// MinHook on sub_140768CC0 (RVA 0x00768CC0). Per agent 3 dossier
// (re/B6.5w12_round1_AGENT_3.md), this is a pure boolean predicate
// called once per candidate package by the engine's package selector
// (AIProcess::EvaluatePackages_And_Execute at 0x00CEEC30). The selector
// gathers candidates, sorts by priority, and calls EvaluateConditions
// for each in order — first TRUE wins the active-package slot, the
// engine installs that package and runs its procedure executor natively.
//
// Ghost AI hook strategy (Phase 4, not landed in this step):
//   For form_ids in our tracked-NPC set, return TRUE iff the package's
//   form_id matches the server's chosen package_form_id (cache field,
//   B6.5w12 wire proto v14). The engine then naturally picks our
//   server-chosen package without us touching the executor, state
//   machines, or anim graph.
//
// THIS STEP (B6.5w12 Phase 2 step B — SKELETON ONLY):
//   The detour fires + logs + passes through to original. No tracked-set
//   lookup, no package_form_id read, no return-value substitution. The
//   only goal is to prove the hook installs at the right address and
//   fires under live AI activity. Once verified, Phase 4 wires the
//   decision logic.

#pragma once

#include <atomic>
#include <cstdint>

namespace fw::hooks {

// Install MinHook detour on PKG_EVAL_CONDITIONS_RVA (0x00768CC0).
// Returns true on success, false if MinHook rejected (address invalid,
// already hooked, etc.).
//
// Idempotent — repeat calls log a "already installed" line and return
// true without re-installing.
bool install_ghost_ai_package(std::uintptr_t module_base);

// Diagnostic counters (relaxed loads, thread-safe). Useful for log
// throttling + sanity checks during live test.
std::uint64_t get_ghost_ai_package_fires();
std::uint64_t get_ghost_ai_package_seh_failures();

// Cross-hook bridge: the npc_ai_suppress detour on Actor::Update_PerFrame
// is the universal AI tick funnel (single entry per actor per frame). It
// writes the current actor's form_id here at function entry and restores
// at exit. Any sub-call within Update_PerFrame's body (including the
// package selector AND any quest/dialog condition check using
// sub_140768CC0) can read the current actor from this atomic.
//
// Discovered live (2026-05-11): the package selector sub_140CEEC30 has an
// internal early-bail on vt[+0x2E0] which fires truthy for in-combat
// actors → the inner predicate is NEVER called from the selector body
// for hostile NPCs. Bridging at Update_PerFrame instead of at the
// selector entry covers ALL inner predicate fires for tracked actors
// regardless of combat state.
//
// AI tick is single-threaded (engine main thread), so relaxed memory
// order suffices. The save/restore at Update_PerFrame boundary supports
// any recursive AI tick paths.
extern std::atomic<std::uint32_t> g_current_actor_fid;
extern std::atomic<const void*>   g_current_actor_ptr;

} // namespace fw::hooks
