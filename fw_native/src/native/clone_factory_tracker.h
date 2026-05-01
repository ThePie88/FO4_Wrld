// M9 wedge 4 — Path B-alt-2 follow-up — BSTriShape clone factory tracker.
//
// PURPOSE
//   Iter 12 alloc-tracker proved every weapon BSTriShape is allocated
//   from caller_rva 0x16D9A5C — inside sub_1416D99E0, the BSTriShape
//   CLONE FACTORY. That factory takes a source template `a1` and
//   produces a new shape `v8` that shares the source's vertex/index
//   buffer pointers.
//
//   The live read of "v8 +0x148" shows a struct with non-BSPositionData
//   layout. To understand WHAT this struct really is, this module hooks
//   the clone factory at entry and dumps the source's +0x148 contents
//   as hex bytes — the actual memory tells us the layout.
//
//   In addition, the module records (clone_ptr → source_ptr) mappings
//   so a later walker can look up a weapon BSTriShape and find its
//   source template, where the original mesh data is intact.
//
// USAGE
//   For diagnostic / RE only at this stage. Once we know the struct
//   layout, this module becomes the basis for actual mesh extraction.

#pragma once

#include <cstddef>
#include <cstdint>

namespace fw::native::clone_factory_tracker {

struct CloneTrace {
    const void*  source;       // a1 of clone factory (template)
    std::uint64_t timestamp_ms;
};

// Hook the clone factory sub_1416D99E0. Returns false on hook install
// failure.
bool install(std::uintptr_t module_base);

// Look up the source template for a given clone pointer. Returns nullptr
// if not in cache.
const CloneTrace* lookup(const void* clone);

// Diagnostic counters.
std::uint64_t total_invocations();
std::size_t   entry_count();

} // namespace fw::native::clone_factory_tracker
