// B6.6w0 PUPPET — Update_PerFrame replacement body for tracked NPCs.
//
// Per `re/B6.6w0_update_perframe_structural_AGENT.md`, the vanilla
// `sub_140C636A0` runs 106 call sites: a mix of rendering /
// bookkeeping (KEEP-ALWAYS) and AI decisions (SKIP-IF-PUPPET).
//
// This module implements the KEEP-ALWAYS subset as a single
// `puppet_update_perframe()` function. The npc_ai_suppress detour
// calls it INSTEAD of fully bailing for tracked actors, so the puppet:
//   * Looks alive (anim graph tick, bone tree update, NIF transforms).
//   * Doesn't break engine invariants other walkers assume (cell
//     membership, extra-data parity, water broadcasts).
//   * Doesn't take ANY AI decision (no target select, no movement
//     intent, no combat engage, no package step, no dialogue init).
//
// All puppet behavior (hostility flag, combat target, aim, fire) is
// orchestrated by other hooks consuming server state.
#pragma once

#include <cstdint>

namespace fw::hooks {

// Resolve engine function pointers from the module base. Idempotent;
// safe to call multiple times. Must run before any
// `puppet_update_perframe()` invocation — call from `install_all` once.
void puppet_init(std::uintptr_t module_base) noexcept;

// SEH-safe replacement body for `Actor::Update_PerFrame` when invoked
// on a tracked NPC. Runs the 14-step KEEP-ALWAYS subset; never calls
// the vanilla function or its trampoline.
void puppet_update_perframe(void* actor, float sim_time) noexcept;

// Diagnostic counters (atomic, lock-free reads).
std::uint64_t get_puppet_fires() noexcept;
std::uint64_t get_puppet_seh_failures() noexcept;

} // namespace fw::hooks
