// Ghost 1P full-body animation (2026-08-05) — "tell the engine to tick the
// third-person graph too".
//
// THE DEFECT. While the local camera sits in FirstPersonState the remote
// ghost of that player animates wrong: it holds a V/T stub pose. Measured
// long ago (M8P3.22) and misdiagnosed twice, because the 3P bones DO keep
// receiving writes — they just receive the graph's default pose, which is
// why every pose-content heuristic failed to discriminate.
//
// THE GATE, decomp-proven (2026-08-05 RE pass):
//   BSAnimationGraphManager holds BOTH player graphs at once:
//     +0x40 small-array flags (bit31 = data is inline at +0x48, else ptr)
//     +0x48 graphs data           +0x50 graphs.size
//     +0xC8 spinlock ownerThreadId  +0xCC lock count
//     +0xD8 activeGraph (uint32)  <-- the gate
//   BSAnimationGraphManager::Update (sub_14130E240) dispatches the per-frame
//   BShkbAnimationGraph::Update (sub_141320530) to graphs[activeGraph] ONLY,
//   preceded by an event flush (sub_141320EA0) to that same graph.
//   PlayerCharacter keeps the invariant activeGraph == isFirstPerson, i.e.
//   graphs[0] = third person, graphs[1] = first person. The camera-driven
//   toggle is sub_140D79000 (`active ^= 1`, guarded by size == 2), reached
//   from sub_140D7DDB0 which reads PlayerCamera::IsInCameraState(0).
//   Nothing about the 3P graph is disabled — it simply stops being ticked.
//
// THE FIX. Do NOT flip the index (that would starve the local player's own
// first-person arms). Instead, after the engine's Update returns, run the
// same two calls the engine would have run for graphs[0], under the
// manager's own spinlock. The 1P graph keeps its normal update; the 3P
// graph resumes producing real poses, so the existing pose-tx capture
// streams real animation with zero changes to the network path.
//
// Self-limiting by construction: only a manager with exactly TWO graphs
// currently on index 1 is touched, which is the engine's own definition of
// "the player, in first person" (sub_140D79000 uses the same size == 2
// test). Gated further on an active connection and a config kill switch.
//
// Cost: one extra graph evaluation per frame for the local player only —
// exactly the work the engine was skipping. Watch for doubled animation
// events (footsteps, sounds) in live testing; none observed so far.

#pragma once

#include <cstdint>

namespace fw::hooks {

bool install_first_person_graph(std::uintptr_t module_base);

// Config kill switch, applied after install (mirrors the c.36b pattern).
void set_first_person_graph_drive(bool enabled) noexcept;

// Whether the pose capture keeps STREAMING while the sender is in first
// person. Default false = HOLD (the ghost keeps its last good third-person
// pose, the only first-person state that has ever looked right). Set true
// from the ini to run first-person streaming experiments; the [pose-1p]
// diagnostic records the tree contents either way.
void set_stream_pose_in_first_person(bool enabled) noexcept;
bool stream_pose_in_first_person() noexcept;

// True once the extra 3P tick is actually running (hook installed, switch on,
// and at least one update issued). The pose-tx capture consults this: while
// the drive works the sender STREAMS through first person; if it is off or
// failed to install, the capture falls back to holding the last good 3P pose
// instead of shipping the graph's default stub.
bool fp_graph_is_driving() noexcept;

// Diagnostics.
std::uint64_t get_fp_graph_fires();   // extra 3P updates actually issued
std::uint64_t get_fp_graph_seh();     // SEH escapes inside the extra call

} // namespace fw::hooks
