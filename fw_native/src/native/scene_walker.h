// Strada B M2.1 — scene graph diagnostic walker.
//
// Purpose: once M1 has proven we can attach to the scene graph, we need
// to UNDERSTAND what's in the scene so M2 can (a) find a BSTriShape
// from which to clone a BSLightingShaderProperty and (b) sanity-check
// our expected member layout against real live objects.
//
// The walker recursively descends from a root, logging each node's:
//   - pointer
//   - vtable RVA (for identification: NiNode 0x267C888, BSFadeNode
//     0x28FA3E8, BSTriShape 0x267E948, etc.)
//   - name (NiFixedString at +0x10)
//   - local translation (+0x54)
//   - children count (at +0x132, valid only for NiNode-derived)
//   - children ptr (at +0x128)
//
// Depth-limited and SEH-caged to avoid blowing up if a node has a
// nonstandard layout. Output goes to fw_native.log at INFO level.

#pragma once

namespace fw::native {

// Walk starting from `root`, descending up to `max_depth` levels.
// Safe to call on any object — if it doesn't have children-array
// semantics at the expected offsets, we just log 0 children and don't
// recurse. Must be called on the main thread (reads live scene graph).
//
// Side effect: during the walk we track the first BSTriShape encountered
// (vt_rva == 0x267E948) and stash it in a module-level slot. M2.3 reads
// that ptr to clone its shader+alpha properties. Resets on each walk.
void walk_and_dump_scene(void* root, int max_depth);

// Returns the first BSTriShape pointer observed during the most recent
// walk_and_dump_scene() call, or nullptr if no walk has run yet or none
// was found. Safe to read from the main thread only (not SEH-caged —
// the ptr itself could be stale if SSN re-created between calls, so
// M2.3 should re-walk first).
void* get_first_bstri_shape();

// Returns the ShadowSceneNode pointer observed during the most recent
// walk (vt_rva == 0x2908F40). nullptr if not found. The M1/M2 dossiers
// both misidentified the SSN singleton (qword_143E47A10 and
// SceneGraph+0x140 BOTH point to a NiCamera, not SSN). The walker is
// the only reliable way we have to get SSN right now — it just looks
// for the vtable match in the scene.
void* get_shadow_scene_node();

} // namespace fw::native
