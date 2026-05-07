// M9 closure (2026-05-07) — Modded weapon assembly via direct NIF loader.
//
// PURPOSE
// =======
// Produces a fully-assembled, OMOD-applied BSFadeNode* given just
// (weapon_form_id, omod_form_ids[]). The result is a ready-to-attach
// scene-graph node; the caller parents it under the ghost's WEAPON bone.
//
// HISTORY (read this before changing anything)
// ============================================
// Iteration #1: synthetic TESObjectREFR via sub_1404F1160 + vt[170] +
// loaded3D polling. Reasoning: the engine's Inventory3DManager (Pipboy 3D
// preview) uses this exact pattern to render OMOD-correct meshes.
//
// REFUTED 2026-05-07 by `re/COLLAB_FOLLOWUP_vt170.md` (99% confidence,
// pure decomp + static scan of all 197 REFR vtable slots): vt[170] is
// `sub_140513760` — a 0x28-byte function that ONLY writes the form
// pointer to refr+0xE0 and toggles a flag bit. No NIF load, no async
// queue submit. NONE of the 197 REFR vtable slots calls a NIF loader.
// The Inventory3DManager actually loads via a 248-byte
// NewInventoryMenuItemLoadTask submitted to BSResource queue at
// sub_14105C2F0:6892-6922 — separate from vt[170]. Path C as written
// in COLLAB_GAMMA_alt_paths.md §6.2 cannot work; polling loaded3D
// would hang forever because no load was ever triggered.
//
// Iteration #2 (current): direct synchronous call to `sub_1404580C0`
// (DELTA §8 path). This is the engine's load+clone+wrap helper used
// by the dropped-item / cell-streaming codepath. With opts byte 0x2D
// (bit 0x08 set) it triggers BSModelProcessor — which applies OMODs
// IN-PLACE on the cached BSFadeNode. The 4th arg (`modelExtraData`)
// threads our fabricated BGSObjectInstanceExtra to the post-hook.
//
// Build the OIE via `re/COLLAB_FOLLOWUP_oie_construction.md` recipe
// (Path B): alloc 40-byte shell, write 6 ctor fields, call
// sub_1402480F0 once per OMOD. Pure mutation, no engine-state pull-in.
//
// THREADING
// =========
// MAIN THREAD ONLY. The TLS slot at [0x143E5C658]+2496 is used by the
// resmgr/parser for load priority — calling from a non-engine thread
// writes to undefined memory. Project routes all visual ops through
// main_thread_dispatch.cpp; we follow the same pattern.
//
// COSTS
// =====
// Synchronous engine call. Internally allocates + fills a BSFadeNode
// (0x1C0 bytes), parses the .nif file (cache hit on second call for
// the same modelPath fingerprint), runs BSModelProcessor (which loads
// each OMOD's sub-NIF and parents it under the right placeholder
// inside the cached tree on first parse — subsequent equips share the
// modded tree), produces a clone (vt[26] DeepClone, ~10-50 µs).
// First call for a given (form, OMOD-fingerprint) combo: 1-50 ms.
// Repeat calls (cache hit): ~50-200 µs. Acceptable on the main thread.

#pragma once

#include <cstddef>
#include <cstdint>

namespace fw::native::synthetic_refr {

// Result kinds reported via the synchronous `error_kind` out-pointer.
// Caller passes a `const char**` and receives a static-storage string
// or nullptr on success.
constexpr const char* kErrFormNotResolved   = "form_not_resolved";
constexpr const char* kErrFormPathEmpty     = "form_path_empty";
constexpr const char* kErrOieAllocFailed    = "oie_alloc_failed";
constexpr const char* kErrLoaderSeh         = "loader_seh";
constexpr const char* kErrLoaderRcNonzero   = "loader_rc_nonzero";
constexpr const char* kErrInternal          = "internal";

// Synchronously assemble a modded weapon. Returns the freshly-loaded
// BSFadeNode* on success, with refcount = 1 (caller now owns that ref).
//
// The caller is expected to:
//   • parent the node under some target NiNode (which bumps refcount to 2)
//   • refdec their +1 so the parent slot becomes the sole owner
// See ghost_set_weapon's pattern in scene_inject.cpp for reference.
//
// On failure: returns nullptr; *out_err (if non-null) points to one of
// the kErr* constants (static storage; do not free).
//
// `omod_form_ids` may be nullptr if num_omods == 0 (stock weapon).
// num_omods is capped internally at 32.
//
// Threading: MAIN THREAD ONLY.
void* assemble_modded_weapon(
    std::uint32_t        weapon_form_id,
    const std::uint32_t* omod_form_ids,
    std::size_t          num_omods,
    const char**         out_err);

// Best-effort cleanup of any resources cached by repeated assembly
// calls. Currently a no-op (stateless API), kept for symmetry with
// scene_inject's shutdown wiring.
void shutdown();

} // namespace fw::native::synthetic_refr
