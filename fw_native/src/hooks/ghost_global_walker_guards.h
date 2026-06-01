// ============================================================================
// Build 57 (2026-05-23) — Global walker guards for ghost survival.
//
// ARCHITECTURAL CONTEXT
// ---------------------
// The ghost player proxy (form_id 0xFF000001, a memcpy'd PC duplicate or
// PlaceAtMe-spawned Actor) is registered in the engine's global FormID→Form
// hash table by its constructor side-effects. From that point on, engine
// global walkers iterate the table, parent cell ref-lists, combat controller
// arrays, perception/hostility caches, death-cleanup queues, and per-frame
// dispatch lists — and dispatch virtuals on the ghost. Because the ghost's
// sub-objects (AIProcess, MovementController, FacegenAnim, +0x418 hostility
// cache, etc.) are incomplete or PlayerNPC-special-cased, the virtual
// dispatches AV.
//
// HISTORY
// -------
// Builds 1-29   — per-leaf patching (fix individual NULL+8 derefs)
// Builds 30-49  — per-vt-slot guards (hostility_guard, vt197_guard,
//                 event_dispatch_guard, hit_applier, action_execute, ...)
// Build 56      — Option C (deregister from global form table) FAILED:
//                 sub_140315740 erase + lock_acq_w sequence SEH'd inside
//                 the lock acquisition. Ghost remained in table → walkers
//                 still reached it → identical crash 0xE98860.
//
// THIS BUILD'S APPROACH
// ---------------------
// Reverse-engineered all walkers in 6 parallel RE arenas:
//   AGENT A — Form table walkers (qword_1430DBF78[2506])
//   AGENT B — Cell ref-list walkers (parentCell.+0x60 / +0x88)
//   AGENT C — Combat controller walkers (known_targets[]/allies[]/selectors[])
//   AGENT D — Death/cleanup walkers (sub_140E98860, sub_140E988A0, siblings)
//   AGENT E — Perception/hostility walkers (vt[197], HostilityCore callers)
//   AGENT F — Global per-frame walkers (BD5xxx thunks, ProcessLists tiers)
//
// Each HIGH-RISK walker identified gets a MinHook detour here. Detour
// pattern (uniform across all hooks):
//
//   detour_<walker>(args...) {
//     __try {
//       if (is_ghost_in_collection_about_to_be_walked(args...)) {
//         // Three strategies depending on walker type:
//         //   (a) skip-entry: scrub ghost from the collection then call orig
//         //   (b) whole-fn-skip: return early with safe value
//         //   (c) substitute-args: pass a different collection / actor
//       }
//       return g_orig(args...);
//     } __except (EXCEPTION_EXECUTE_HANDLER) {
//       // SEH cage so even if our scrubbing logic faults the game
//       // continues (we lose this frame's walker, but no AV).
//     }
//   }
//
// SCHEMA
// ------
// Each walker hook has:
//   constexpr RVA
//   typed function pointer trampoline
//   detour with SEH cage
//   atomic counters (fires, ghost-hits, SEH)
//   install_<hook_N>(module_base) -> bool
//
// All counters exposed via getters at the bottom of the file for the
// periodic stats dumper.
//
// THREADING
// ---------
// Most walkers run main thread only (per-frame, post-cell-load, on-death).
// Some (Havok physics walkers) run on a worker. Counters are atomic; the
// `get_ghost_duplicate()` call is atomic-load. No shared mutable state in
// the detour body besides counters.
// ============================================================================

#pragma once

#include <cstddef>
#include <cstdint>

namespace fw::hooks {

// Master install — installs ALL walker guards documented in
// re/walker_inventory/MASTER.md. Returns true if ≥80% installed (some are
// best-effort; one or two failures don't tank the system because each
// guard is independent). Logs per-hook install status.
bool install_ghost_global_walker_guards(std::uintptr_t module_base);

// Diagnostic counter getters — used by the periodic stats dumper to
// report per-walker activity. All atomic-relaxed loads.

// Total fires across all installed walker guards.
std::uint64_t get_walker_guards_total_fires();

// Total times a guard observed ghost in the walked collection.
std::uint64_t get_walker_guards_ghost_hits();

// Total times a guard chose to bail/scrub/skip on ghost-hit.
std::uint64_t get_walker_guards_actions_taken();

// Total SEH faults caught inside guard detours (a non-zero count means
// our scrubbing logic itself faulted — usually a stale ptr we tried to
// read; benign because we swallow and fall through).
std::uint64_t get_walker_guards_seh_count();

// Per-walker counter snapshots (compact tuple for periodic dump).
struct WalkerGuardSnapshot {
    std::uint64_t fires;
    std::uint64_t ghost_hits;
    std::uint64_t actions;
    std::uint64_t seh;
    const char*   name;   // static string lifetime, e.g. "death_walker_E98860"
};

// Fills out an array with one entry per registered walker guard.
// Returns the number of entries written.
std::size_t snapshot_all_walker_guards(WalkerGuardSnapshot* out, std::size_t max_count);

} // namespace fw::hooks
