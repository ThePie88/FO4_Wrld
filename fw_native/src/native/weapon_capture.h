// M9.w4 PROPER (v0.4.2+) — sender-side weapon-mesh capture pipeline.
//
// REPLACES the v0.4.0 PoC walker (weapon_witness::snapshot_player_weapon_meshes)
// which walked the local player's bipedAnim 300ms post-equip to grab the
// already-assembled weapon mesh. The walker had three known flaws documented
// in CHANGELOG v0.4.0 §"Why this was extremely hard":
//   - Race condition with the engine's async weapon assembly (sometimes
//     captured empty trees, sometimes captured the previous weapon).
//   - Cross-form mesh contamination (bipedAnim still held bgsm references
//     from previous weapon; walker mixed them in).
//   - Hunting Rifle invisible (engine never produced a complete subtree
//     under the WEAPON bone — walker found nothing to capture).
//
// This pipeline catches the geometry AT CLONE TIME from the SOURCE
// BSTriShape, not from the rendered tree. TTD analysis 2026-05-04 proved
// every modded weapon equip causes ~5-15 invocations of the engine's
// BSTriShape clone factory (sub_1416D99E0) inside a per-frame loop. We
// hook the factory and snapshot the source's vertex/index buffers
// directly via the +0x148 helper struct (iter 11 RE: vstream_desc at
// helper+0x08, istream_desc at helper+0x10, raw GPU buffers at offset
// +0x08 within each desc).
//
// FLOW:
//   1. equip_hook::detour_equip_object (post-orig) calls arm(form_id, 500ms)
//   2. clone_factory_tracker detour_clone_factory calls record_clone(source)
//      for each BSTriShape clone within the armed window
//   3. After ttl_ms, a one-shot worker thread posts WM_APP+0x4F to main
//      thread; finalize_and_ship() runs on main thread, packages staged
//      ExtractedMesh records into MESH_BLOB_OP chunks (existing v9 wire
//      protocol), ships, clears state.
//
// PHASE 1 NOTE (2026-05-04 ship): finalize_and_ship() is LOG-ONLY for now.
// Wire shipping is wired up but commented behind FW_PHASE2_SHIP. This lets
// us verify extraction works against the v0.4.0 baseline before flipping
// the sender — compare logged captures vs walker captures, then enable
// phase 2 when confidence is HIGH.
//
// THREADING: arm() and finalize_and_ship() are MAIN THREAD ONLY.
// record_clone() runs on whatever thread the engine calls the factory
// from (per TTD analysis: always game main thread, frame 17 = thread
// entry, single-threaded equip path). State guarded by mutex regardless.

#pragma once

#include <cstdint>
#include <cstddef>

namespace fw::native::weapon_capture {

// Arm a capture window for an equip event.
//
// `form_id`: the TESForm ID of the equipped item (correlation key for
//            the eventual MESH_BLOB record).
// `ttl_ms` : how long the window stays open. Typical 500ms — covers
//            engine assembly latency including modded firearms with
//            10+ sub-pieces. Past 500ms the engine should be done; if
//            another clone fires later it's likely unrelated.
//
// If a window is already armed, it is FINALIZED first (its data shipped,
// state cleared) before the new arm starts. This handles spam-equip:
// each new equip closes the previous capture.
//
// MAIN THREAD ONLY.
void arm(std::uint32_t form_id, std::uint32_t ttl_ms);

// Record one BSTriShape clone factory invocation.
// Called from clone_factory_tracker::detour_clone_factory.
//
// `source`: a1 of the factory = the source BSTriShape being cloned.
// `clone` : return value of the factory = the freshly-allocated clone
//           (refcount-bumped, owned by engine).
//
// If not currently armed: no-op (cheap fast-path check).
// If armed: extract source's geometry data and append to staged list.
//
// SEH-caged: per-source extraction failures don't poison the whole window.
// Threading: caller-thread-safe via internal mutex.
void record_clone(const void* source, const void* clone);

// Quick "is the window currently open" check. Used by clone_factory_tracker
// for a cheap branch before paying the mutex cost. Atomic load.
bool is_armed();

// M9.w4 PROPER (v0.4.2+, Path NIF-CAPTURE) — record a NIF path the engine
// just loaded during the armed equip window. Called from nif_path_cache's
// worker AND resolver detours. Filters to weapon-related paths only.
//
// This is the simplest way to know which mod NIFs the engine uses for an
// equip event: hook the loader and listen. No OMOD struct RE, no factory
// reconstruction, no shader hand-built. Receiver loads same paths and
// engine handles all binding naturally.
//
// SEH not needed (string copy already SEH-caged in caller's helper).
// Threading: caller-thread-safe via internal mutex.
void record_loaded_path(const char* path);

// Finalize the current capture window: package staged data, ship via
// wire (Phase 2) or log (Phase 1), reset state.
//
// Called on:
//   - TTL expiration (one-shot worker → WM_APP+0x4F)
//   - Next arm() supersedes (immediate flush before new arm)
//   - Shutdown / cell-change (defensive)
//
// MAIN THREAD ONLY.
void finalize_and_ship();

// Public — main_menu_hook WndProc dispatches FW_MSG_WEAPON_CAPTURE_FINALIZE
// to this function (same pattern as on_deferred_mesh_tx_message).
inline constexpr unsigned FW_MSG_WEAPON_CAPTURE_FINALIZE = 0x8000 + 0x4F;
void on_finalize_message();

// Diagnostic counters.
std::uint64_t total_arms();
std::uint64_t total_records();
std::uint64_t total_finalizes();

} // namespace fw::native::weapon_capture
