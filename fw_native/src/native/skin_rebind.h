// Skin instance rebind — post-load surgery on BSDismemberSkinInstance
// =====================================================================
//
// PROBLEM (M7 dossier + Frida captures #1-3):
//   Loading MaleBody.nif standalone via sub_1417B3E90 succeeds in
//   building BSFadeNode + BSSubIndexTriShape + BSDismemberSkinInstance,
//   BUT the skin instance's bone array is bound to fallback "_skin"
//   stub bones (created by sub_1403F85E0 when no skeleton is in scope).
//   Vanilla pipeline goes through sub_140458740 which has skeleton
//   context; standalone does not. Result: bones with names like
//   "Bip01 Spine" don't drive the mesh — only the stubs do, and stubs
//   are static.
//
// SOLUTION (this module):
//   1. Load skeleton.nif separately as a standalone BSFadeNode tree.
//   2. After body NIF load, walk the body's BSDismemberSkinInstance.
//   3. For each entry in the bone-pointer array whose target name
//      ends with "_skin", look up the matching bone in the skeleton
//      tree (real "Bip01 Spine" lives there).
//   4. Refcount-safe swap: increment ref on real bone, write to
//      skin->bones[i], decrement ref on stub (free if hits 0).
//   5. After swap, animating the skeleton's named bones drives the
//      body mesh — what M7 wanted.
//
// Layout details (from re/M8P3_skin_instance_dossier.txt — TBD by agent):
//   BSDismemberSkinInstance layout:
//     +0x??  vtable
//     +0x??  refcount (NiRefObject base)
//     +0x??  skel_root  NiAVObject*  (the "skeleton" the skin assumes)
//     +0x??  bones      NiAVObject** (pointer array, length=bone_count)
//     +0x??  bone_count u32
//     +0x??  bone_data  per-bone struct (inverse-bind matrices, etc.)
//
//   BSGeometry skin instance pointer slot:
//     +0x140 OR +0x148 OR +0x150 — TBD by agent

#pragma once

#include <cstdint>

namespace fw::native::skin_rebind {

// Swap stub bones in `body_root`'s skin instance for real bones found in
// `skel_root`. body_root and skel_root are BSFadeNode* (or any NiAVObject*
// that is the root of a parsed NIF tree).
//
// Returns the number of bones successfully swapped, or -1 on error.
// SEH-protected internally.
//
// Idempotent: safe to call multiple times. After first successful call,
// no more "_skin" stubs remain in body's skin instance, so subsequent
// calls return 0.
//
// Threading: main thread (WndProc) only. Holds no scene-graph locks.
int swap_skin_bones_to_skeleton(void* body_root, void* skel_root);

// Walk the body's BSGeometry tree and collect all unique skin
// instances. Useful for debugging — log the names of stub bones the
// rebinder would target.
//
// Returns count of stub bones found across all skin instances in the
// subtree. Does not mutate anything.
int diagnose_skin_stubs(void* body_root);

// Step 2: walk a skeleton.nif subtree and log every NiNode name + addr.
// `skel_root` should be a freshly-loaded BSFadeNode from
// `nif_load_by_path("Actors\\Character\\CharacterAssets\\skeleton.nif", ...)`.
// Caller still owns the refcount; this is read-only.
//
// Returns count of nodes visited (capped at 1000). -1 on null input.
int dump_skeleton_bones(void* skel_root);

// ---- Step 3 — cache + swap ----------------------------------------

// Try to cache a freshly-loaded skeleton.nif root globally. If no
// previous cache exists, takes ownership of caller's refcount (caller
// must NOT release). If a cache already exists (race), releases
// caller's copy refcount-safely. Either way, on return the global
// cache is non-null.
void cache_or_release_skeleton(void* skel_root);

// Returns the cached skeleton root, or nullptr if not yet cached.
// Non-owning — caller does not release.
void* get_cached_skeleton();

// Walk `body_root` finding every BSGeometry, and for each skin
// instance, swap the entries in skin->bones_fb (skin+0x10) with
// the matching named NiNode from `skel_root`'s subtree. Also
// rebinds skin->skel_root (skin+0x48) to skel_root.
//
// Refcount-safe (matches engine niptr-swap pattern).
//
// Returns the count of bone entries swapped, or -1 on error.
int swap_skin_bones_to_skeleton(void* body_root, void* skel_root);

// Look up a bone NiNode by name in the cached skeleton tree. Returns
// nullptr if no skeleton is cached or no matching name is found.
// Useful for driving animations: get the bone, then write to its
// +0x30..+0x54 (rotation 3x3) or +0x54..+0x60 (translation vec3)
// fields, then call update_downward(body) to propagate.
//
// WARNING: this returns a bone from the CACHED skeleton tree, which
// may NOT be the same NiAVObject* that bones_pri[] points to after
// swap (the cached skel can contain multiple bones with the same
// name in subtrees, and find_node_by_name returns the FIRST match
// depth-first, while swap may have used a different match for a
// specific skin instance). For the GPU-correct bone, use
// find_bone_in_bones_pri below.
void* get_bone_by_name(const char* name);

// Iterate `skin`'s bones_pri[] array (skin+0x28..0x38) and return the
// first entry whose NiAVObject's name strcmp-matches `name`. This is
// the bone the GPU dereferences via SRV at draw time, so it is the
// CORRECT bone to register in the override hook.
//
// Use this instead of get_bone_by_name() for skin-binding work.
// Returns nullptr if skin null, name null, no match, or AV.
void* find_bone_in_bones_pri(void* skin, const char* name);

// Find the first BSSkin::Instance under `body_root`'s subtree.
// Walks NiNode children depth-first, returns the first BSGeometry's
// skin instance (skin@geom+0x140). Used by the bone-drive test to
// reach `bones_pri` matrix array at skin+0x28. Returns nullptr if
// no skinned geometry found.
void* find_body_skin_instance(void* body_root);

// Walk `root` subtree and collect ALL BSSkin::Instance pointers from
// every BSGeometry encountered. Writes up to `max_count` pointers to
// `out_array`. Returns the actual count written (capped at max_count).
//
// Use case: a ghost has multiple skinned NIFs attached as children of
// the body root (body, head, hands). Each has its own skin instance.
// To drive animations consistently, we need to write matrices to all.
int find_all_skin_instances(void* root, void** out_array, int max_count);

// ---- M8P3.7 — engine UpdateWorldData hook ------------------------

// Install MinHook detour on NiAVObject::UpdateWorldData (RVA 0x16C85A0).
// The detour calls orig first (engine computes world for the bone),
// then if the NiAVObject is in our ghost-bone registry, overwrites
// the world matrix at +0x70..+0xAC with the per-bone override matrix
// stored in g_bone_overrides.
//
// Idempotent — safe to call multiple times, only first install does work.
// Returns true on success.
bool install_world_update_hook(std::uintptr_t module_base);

// Add a bone (NiAVObject*) to the ghost-bone registry. After this,
// every UpdateWorldData call for this bone will check `set_bone_world`
// for an override.
void register_ghost_bone(void* bone);

// Set the override world matrix for a bone. 4x4 column-major,
// 16 floats = 64 bytes. The hook will memcpy this into bone+0x70 each
// frame after engine's UpdateWorldData runs (last write wins).
//
// If bone wasn't registered, this is a no-op (use register_ghost_bone first).
void set_bone_world(void* bone, const float* mat16);

// Empty the ghost-bone registry and per-bone override cache.
// Call on shutdown / disconnect.
void clear_ghost_bones();

// Read + reset hook call counters. Returns total UpdateWorldData calls
// since last reset and how many of those hit our override path.
// Useful to verify the hook is firing.
void get_and_reset_hook_stats(std::uint64_t& total, std::uint64_t& overrides);

// Write a translation row (12 bytes: x, y, z) into bones_pri[idx]'s
// matrix struct. The matrix struct is reached via:
//   bones_pri_head = *(skin+0x28)
//   matrix_struct_ptr = bones_pri_head[idx]   (each entry is a pointer)
//   write at matrix_struct_ptr + write_offset
// Returns 0 on success, -1 on AV / out-of-range.
int write_bones_pri_translation(void* skin, int idx,
                                int write_offset,
                                float x, float y, float z);

} // namespace fw::native::skin_rebind
