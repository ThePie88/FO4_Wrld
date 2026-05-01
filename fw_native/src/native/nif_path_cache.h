// M9 wedge 4 (witness pattern, step 1) — NIF path cache.
//
// PURPOSE:
//   Witness-pattern receiver-side mod NIF rendering needs the SENDER (peer A)
//   to figure out which NIFs the engine loaded for its modded weapon. The
//   public NIF loader sub_1417B3E90 is the single funnel through which every
//   NIF asset (weapon body, scope, suppressor, paint material, etc.) is
//   pulled from the BA2. By detouring that one function and recording
//   (returned BSFadeNode*, path) on each successful load, we get a runtime
//   reverse-index: given any NiAVObject* we encounter while walking peer
//   A's BipedAnim weapon subtree, we can recover the .nif path that birthed
//   it.
//
// DESIGN:
//   - Single global hashmap NiAVObject* → std::string (path),
//     protected by a shared_mutex (many readers / one writer).
//   - Soft cap on size; when exceeded we drop the cache entirely and start
//     fresh (cell-transition / loading-screen churn shouldn't grow it past
//     a few hundred entries in typical play, so this is conservative).
//   - SEH-safe path read (vanilla nif_load_by_path can be called with an
//     ANSI path that vanishes mid-call if the asset stream is exotic — our
//     detour copies the string out before chaining and never reads through
//     the engine's pointer post-chain).
//   - Detour chains to the original FIRST, captures (path, *out) AFTER.
//     The original may fail (rc != 0) or return *out=null — in that case
//     we don't insert anything.
//
// THREADING:
//   The engine calls nif_load_by_path predominantly on the main thread,
//   but BSResource has an async streaming path that occasionally fires off-
//   thread. The cache mutex covers both. The lookup() helper is wait-free
//   for readers via shared_lock.
//
// LIFETIME:
//   Cache is process-global. Entries are NOT removed on engine-side
//   NiAVObject release — we have no hook on the dtor. Stale entries remain
//   but become unreachable (no one queries them). Cap-and-clear handles
//   pathological growth.
//
// QUERY PATTERN (used in step 2 — walker):
//   After A's equip_hook → g_orig_equip returns and engine has assembled
//   the weapon's mod NIFs into the BipedAnim, walk the player's loaded3D
//   weapon subtree. For each child NiAVObject:
//     std::string p = nif_path_cache::lookup(node);
//     if (!p.empty()) record_descriptor(node, p);

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace fw::native::nif_path_cache {

// Install the MinHook detour on sub_1417B3E90. Idempotent — second call is
// a no-op that returns true. Must be called AFTER fw::hooks::init().
//
// Returns false if the underlying MH_CreateHook / MH_EnableHook fail.
bool install(std::uintptr_t module_base);

// Lookup the cached .nif path for `node`. Returns empty string if not
// known. Safe to call from any thread — uses a shared_lock internally.
//
// NOTE: `node` is keyed by raw pointer, so callers must hold the engine's
// scene-graph guarantees (don't query for a node that has already been
// released — the cache entry might still be present but you can't
// dereference the pointer anyway).
std::string lookup(void* node);

// Diagnostic: number of entries currently in the cache + number of detour
// invocations seen so far. Cheap (atomic loads).
std::size_t entry_count();
std::uint64_t total_invocations();
std::uint64_t total_evictions();

} // namespace fw::native::nif_path_cache
