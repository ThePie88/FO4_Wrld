// Local player anatomy probe (2026-08-07).
//
// WHY
//   The plan to give a peer's ghost a real face died on a fact: a ghost has
//   no TESNPC. The PlaceAtMe proxy Actor is vestigial and kill-switched
//   (Build 65.c.34 — it was the structural root of the death-reload crash
//   family), and the visual ghost is `g_injected_cube` + `g_injected_head`,
//   plain NiNodes. The engine's three appearance functions all take a
//   TESNPC*, so none of them can ever be pointed at a ghost.
//
//   What is left is better anyway: copy the RESULT. The local engine already
//   ran FaceGen, baked the morphs into the vertex buffer and mounted every
//   head part as a child of the head node. Photocopying that subtree onto the
//   ghost is 1:1 by construction, and the creator then only has to work on
//   the local player.
//
//   Before cloning anything into a live scene graph, look. This probe does
//   nothing but read: it walks the local player's 3D and writes the tree out.
//   Its output is what tells us which node is the head, what it is called,
//   what hangs off it, and which nodes carry geometry worth copying.
//
// SAFETY
//   Read-only. No writes to engine memory, no attach, no clone, no refcount
//   touch. Every read is SEH-caged, recursion is depth-limited, and the
//   children pointer is sanity-checked before it is followed — the same
//   pattern the M2.1 scene walker has used since April. Main thread only.
//   Off unless the `anatomy_probe` config key is set; when off it costs one
//   relaxed atomic load per call.
//
// OUTPUT
//   fw_anatomy.log next to the executable, truncated per process.
//   One tab-separated record per node:
//       <depth>  <ptr>  <vt_rva>  <class>  <name>  <pos>  <children>  <geom>
//   Written once, when the player's 3D first becomes readable.

#pragma once

#include <cstdint>
#include <string>

namespace fw::native::anatomy_probe {

// Open the output file. Called from dll_main when the config key is set.
void init(const std::wstring& dir, bool enabled);

// True while the probe is armed and has not yet run.
bool enabled() noexcept;

// Resolve the local player's 3D and dump it. Self-disarming: it retries
// until the player's 3D exists, dumps once, and never runs again.
// MAIN THREAD ONLY — it reads the live scene graph.
void maybe_dump(std::uintptr_t module_base) noexcept;

}  // namespace fw::native::anatomy_probe
