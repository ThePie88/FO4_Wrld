// SPAI Tier 1 — force-prewarm of the engine's NIF resmgr at boot.
//
// Background. M9.w4 PROPER (RESMGR-LOOKUP) lets the receiver attach a
// shared, engine-loaded BSFadeNode to its ghost weapon by looking the
// node up in the BSResource::EntryDB<BSModelDB> singleton via m_name.
// That lookup only works if the receiver's engine has actually loaded
// the corresponding NIF at some point — which it has NOT, because the
// receiver never equipped that mod itself.
//
// SPAI Tier 1 closes the gap by force-loading every weapon NIF shipped
// in the BA2 archives at boot. After prewarm, every shipped weapon mod
// NIF is in the resmgr and findable by m_name regardless of whether the
// local player ever held it. The catalog of paths is generated offline
// by tools/spai_enum_weapons.py and shipped as a plain-text manifest
// next to the DLL (assets/weapon_nif_catalog.manifest).
//
// Why a manifest, not BA2 enumeration in the DLL: keeps this module
// dependency-free (no BA2 parser inside the DLL), the catalog is stable
// across the user's session (BA2s don't change at runtime), and the
// generation tool can be re-run any time the modset changes. Tier 2
// (server-federated catalog for community mods) and Tier 3 (auto-learn
// via OMOD properties RE) build on the same machinery and replace the
// manifest source.
//
// Loading is throttled: each prewarm load is dispatched to the main
// thread one at a time (FW_MSG_SPAI_PREWARM) with a configurable
// throttle between dispatches. ~10–15 ms gives the engine room to
// breathe and avoids spiking frame time during boot. With ~1300 paths
// the full pass takes ~15–20 s of game time, which we spread over the
// loading screen + first minute of world play. None of it is on the
// critical path: a miss before prewarm completes simply means we fall
// back to "no mod parts on this ghost weapon yet" for one equip cycle.

#pragma once

#include <cstddef>
#include <filesystem>

namespace fw::native::spai {

// Load the plain-text manifest from disk. Format (ASCII):
//   '#' lines  — comment, ignored
//   blank      — ignored
//   <path>     — added to the prewarm list
//
// Paths are taken verbatim — they should already be relative to the
// engine's "Meshes\" root, e.g. "Weapons\10mm\10mm.nif" (the BA2 enum
// tool strips the leading "meshes\" prefix for us).
//
// Returns true if at least one path was successfully read. False on
// I/O error or fully-empty manifest. Idempotent: a second call replaces
// the previous catalog (useful for hot-reload during development).
//
// Threading: any thread (call once from DLL init).
bool load_catalog(const std::filesystem::path& manifest_path);

// How many paths are currently queued for prewarm. 0 if load_catalog
// hasn't been called or failed.
std::size_t catalog_size();

// Spawn a one-shot worker thread that, after `delay_ms`, posts
// FW_MSG_SPAI_PREWARM to the FO4 main window once per `throttle_ms` —
// one message per catalog entry. The main-thread WndProc dispatches
// each message to on_prewarm_message() (below) which pops one path
// and force-loads it.
//
// `delay_ms` should be long enough for the engine's own boot-time NIF
// loads (auto-load save, world streaming kickoff) to settle. ~45–60 s
// is a good baseline on NG.
//
// Calling arm_prewarm() before load_catalog() is a no-op (logged).
//
// Threading: any thread; safe to call from DLL init.
void arm_prewarm(unsigned int delay_ms, unsigned int throttle_ms);

// Main-thread WndProc handler — pops one path off the catalog and
// invokes fw::native::spai_force_load_path(path).
//
// Drives a single internal cursor; safe to call repeatedly. When the
// cursor reaches catalog_size() the function logs the final summary
// (loads attempted / loads succeeded / time elapsed) and is a no-op
// thereafter.
//
// Threading: MAIN THREAD ONLY — called from main_menu_hook's WndProc
// subclass on FW_MSG_SPAI_PREWARM.
void on_prewarm_message();

// Returns true iff the calling thread is currently inside a prewarm
// load (i.e. between the spai_force_load_path enter/exit on the main
// thread). Used by weapon_capture::record_loaded_path to ignore the
// engine's nif_load_by_path callbacks triggered by SPAI itself —
// otherwise our prewarm pollutes the per-equip path-capture window
// with random weapon-NIF paths from the catalog (e.g. HMAR rifle
// parts surfacing in a 10mm-pistol equip), shipping nonsense to the
// receiver.
//
// Threading: any thread (TLS read).
bool in_prewarm_load();

}  // namespace fw::native::spai
