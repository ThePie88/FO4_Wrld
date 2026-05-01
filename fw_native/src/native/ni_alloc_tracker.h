// M9 wedge 4 — Path B-alt-2 — NiObject pool allocator tracker.
//
// PURPOSE
//   12 iters of static RE + 4 hook layers (sub_1417B3E90 public NIF API,
//   sub_1417B3480 worker, sub_1416A6D00 cache resolver, sub_14182FFD0
//   GEO BUILDER factory) all failed to capture weapon NIFs in FO4 NG.
//   The weapon construction path is HIDDEN somewhere we haven't found.
//
//   This module takes a different approach: hook the ROOT allocator
//   (sub_1416579C0, the pool allocator that EVERY NiObject derives from)
//   and capture the CALLER RIP via _ReturnAddress(). When our walker
//   later finds a BSTriShape weapon leaf, it looks up that pointer in
//   our cache → gets the call site RVA → maps it back to a function in
//   IDA → we know who allocated this BSTriShape, and from there can
//   identify the construction path.
//
//   Filter: only sizes matching BSTriShape (0x170) and BSDynamicTriShape
//   (0x190) are kept, to bound memory + log volume. NiNode (0x140) is
//   skipped — too frequent and not the answer.
//
// THREADING
//   Allocator can be called from any thread (main + BSResource workers).
//   shared_mutex covers all writers.
//
// LIMITATIONS
//   - Only captures 1 frame back (caller RIP). If the parser uses an
//     intermediate inline helper, we get the helper's RIP, not the
//     parent. Walking 2-3 frames back is doable but RtlCaptureStackBackTrace
//     adds overhead — 1 frame is enough for first triage.
//   - Cap at 16384 entries → cap-and-clear if exceeded (rare).

#pragma once

#include <cstddef>
#include <cstdint>

namespace fw::native::ni_alloc_tracker {

struct AllocTrace {
    std::size_t   size;          // bytes allocated
    void*         caller_rip;    // return address of the call into the allocator
    std::uint64_t timestamp_ms;  // wall clock at capture
};

// Hook the allocator. Returns false on hook install failure.
bool install(std::uintptr_t module_base);

// Lookup the call site for a given allocated pointer. Returns nullptr
// if not in cache.
const AllocTrace* lookup(const void* ptr);

// Diagnostic counters.
std::uint64_t total_invocations();   // total filtered-size allocs seen
std::size_t   entry_count();
std::uint64_t total_evictions();

// Compute caller RVA (caller_rip - module_base). Returns 0 if module
// base unknown.
std::uintptr_t caller_rva(const AllocTrace* tr);

} // namespace fw::native::ni_alloc_tracker
