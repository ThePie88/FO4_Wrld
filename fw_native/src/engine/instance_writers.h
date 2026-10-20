// L5 stage 4b (2026-10-03) — moving one exact instance in or out of an
// inventory.
//
// Every world-side writer of the loot layer used to pick stacks by base: the
// Papyrus RemoveItem takes the head of the chain, the Papyrus AddItem rolls a
// template and drags a stack of ammo after a weapon. Measured live in 4a: B
// took "a pistol" and A's engine destroyed A's modded one; each deposit made
// a different pistol on the other client. These two primitives move what the
// server's line names instead:
//   - remove_instance: the stacks of one base whose fingerprint matches,
//     each by its own chain index, through the engine's RemoveItem with a
//     stack list (vt[0x6D]), the way the container menu moves one row;
//   - add_instance: a stack built from the descriptor (OIE with its template
//     and its mods, the condition) handed to the container's vt[0x7A], so the
//     engine has nothing to roll and drags nothing in.
// Main thread only (the dispatch drain), every engine call SEH-caged, every
// precondition checked first; a failure says so and moves nothing more.

#pragma once

#include <cstddef>
#include <cstdint>

namespace fw::net { struct InstanceDesc; }

namespace fw::engine::instances {

struct Line {
    std::uint32_t base;
    std::uint64_t fp;
    std::int32_t  count;
};

// The stacks of `refr` (only `base` when non-zero, transient ones left out)
// folded into (base, fp) lines; a stack that cannot be read to the end is a
// kFpUnknown line. False when the list could not be read at all (no list,
// the engine holding its write lock): then nothing is known. `reasons_out`
// (2026-10-20) gets the capture's reason bits, so the caller can say which
// of the two it was: inside the take detour the engine holds the list's
// write lock on this very thread, and every seed scan of a Take All was
// refused for it (logged as "walk faulted" until then).
bool scan_lines(void* refr, std::uint32_t base, Line* out, std::size_t max,
                std::size_t* n_out, std::uint32_t* reasons_out = nullptr);

// How many units of (base, fp) `refr` holds now; -1 when unreadable.
int count_of(void* refr, std::uint32_t base, std::uint64_t fp);

// The descriptor of a stack of (base, fp) `refr` holds now. False when it
// holds none, or the stack cannot be read to the end.
bool describe(void* refr, std::uint32_t base, std::uint64_t fp, fw::net::InstanceDesc* out);

// Moves up to `count` units of the instance `fp` of `base` out of `refr`,
// into `dest` (nullptr = destroyed). Returns the units that left.
int remove_instance(void* refr, std::uint32_t base, std::uint64_t fp, int count, void* dest);

// Builds `count` units of the instance `d` of `base` and adds them to
// `refr`. Returns the units added; the caller compares what the engine made
// with what it asked for (count_of on the fingerprint).
int add_instance(void* refr, std::uint32_t base, const fw::net::InstanceDesc& d, int count);

// Resolves the engine functions once. Main thread, from engine init.
void init(std::uintptr_t module_base);

} // namespace fw::engine::instances
