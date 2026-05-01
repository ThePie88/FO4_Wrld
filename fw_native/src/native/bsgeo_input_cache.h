// M9 wedge 4 — Path B-alt-1 — BSGeometry factory input cache.
//
// PURPOSE
//   Hook sub_14182FFD0 (the M2 GEO BUILDER factory) and capture the
//   raw input arrays (positions, indices, vert/tri counts) BEFORE the
//   factory packs them and frees the CPU side copies.
//
//   Iter 11c proved that on the static-mesh factory path, after factory
//   completes:
//     - positions are uploaded to GPU; CPU-side temp buffers freed
//     - indices end up wrapped in a BSStreamBuffer (helper +0x10)
//     - aux (normals/uvs) wrapped at helper +0x08
//   So an extraction at "snapshot time" cannot see positions on CPU.
//   This module solves that by capturing inputs AT FACTORY TIME and
//   keying by the returned BSTriShape* pointer for later lookup.
//
// SCOPE
//   Diagnostic-only first build: counts invocations, logs the first N
//   entries (with vc/tc/sample positions), identifies whether weapon
//   NIFs flow through this factory at all. If they do, a second pass
//   adds an actual deep copy of (positions, indices) into the cache.
//
// THREADING
//   The factory is called from the NIF parser, which runs on whichever
//   thread initiated the load (mostly main + BSResource workers). The
//   cache shared_mutex covers both. lookup() is wait-free for readers.
//
// LIFETIME
//   Process-global. Entries leak (no dtor hook). Cap-and-clear at a
//   bounded size (default 8192 entries × ~few KB each = ~10s of MB).

#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace fw::native::bsgeo_input_cache {

struct CapturedMeshInput {
    std::uint16_t vert_count = 0;
    std::uint32_t tri_count  = 0;
    std::vector<float>         positions;  // 3*vc floats (xyz per vertex)
    std::vector<std::uint16_t> indices;    // 3*tc u16
};

// Install the hook on the geometry builder factory.
// Returns false on hook install failure (logged).
bool install(std::uintptr_t module_base);

// Look up the captured mesh inputs for a returned BSTriShape pointer.
// Returns nullptr if not in cache (factory wasn't invoked for this
// shape, or entry was evicted).
//
// Caller must NOT mutate or free the returned pointer; it is owned by
// the cache and lives until cap-and-clear.
const CapturedMeshInput* lookup(const void* trishape);

// Diagnostic counters.
std::uint64_t total_invocations();
std::size_t   entry_count();
std::uint64_t total_evictions();

} // namespace fw::native::bsgeo_input_cache
