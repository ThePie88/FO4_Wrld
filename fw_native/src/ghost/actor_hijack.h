// Path B — ghost rendering via engine actor hijack.
//
// Strategy: spawn N hidden in-engine Actors (one per remote player),
// teleport them every frame to the live position received via
// POS_BROADCAST, mute their AI. The engine renders them for free
// with native skinning, animation, depth, lighting, shadows, decals,
// and equipment layering.
//
// Replaces the custom D3D11 body renderer (archived under
// fw_native/src/render/body_render.*).
//
// Phases (see session todo):
//   Z.1 — module skeleton (this file) + disable custom render
//   Z.2 — spawn one hidden actor via PlaceAtMe native
//   Z.3 — teleport to remote pos via direct REFR+0xD0 write
//   Z.4 — mute AI (SetAlly + IgnoreFriendlyHits + StopCombat)
//   Z.5 — live A+B test
//   Z.6 — per-peer pool + disconnect cleanup
//   Z.7 — cross-cell MoveTo functor path
//   Z.8 — Race/Outfit match for player identity
//
// RE basis: re/actor_hijack_feasibility.txt, re/placeatme_decomp.txt,
// re/hijack_primitives_decomp.txt (2026-04-21 session).

#pragma once

#include <windows.h>
#include <cstdint>

namespace fw::ghost {

// Main-thread dispatch message. Co-exists with:
//   WM_APP+0x42 FW_MSG_LOAD_GAME           (main_menu_hook)
//   WM_APP+0x43 FW_MSG_CONTAINER_APPLY     (main_thread_dispatch)
//   WM_APP+0x44 FW_MSG_SPAWN_GHOST         (this module)
constexpr UINT FW_MSG_SPAWN_GHOST = WM_APP + 0x44;

// Called once from DllMain's init thread after the engine resolver is
// up. Reads config (currently hardcoded template NPC form id), stores
// image base, wires the per-frame sync into the net snapshot path.
// Returns false on fatal setup error (engine call resolver not ready).
bool init(std::uintptr_t module_base);

// Called once per frame from inside the Present detour (or a later
// hook we migrate to per RE agent 2). Reads the net RemotePlayerSnapshot
// and applies it to the spawned ghost actor. No-op if no actor spawned
// or no remote state yet.
void tick_per_frame();

// Callable from any thread. If no ghost actor has been spawned yet AND
// the WndProc main-thread dispatcher is up, PostMessage FW_MSG_SPAWN_GHOST
// so the main thread performs the PlaceAtMe call safely. Subsequent
// calls while a spawn is pending are no-ops. Typical caller: net
// thread on first valid POS_BROADCAST received.
void request_spawn();

// WndProc-handler entry point (main thread). Called exclusively by
// main_menu_hook's subclass when it receives FW_MSG_SPAWN_GHOST.
// Invokes fw::engine::spawn_ghost_actor and stores the result.
// Idempotent — second call is a no-op if the first succeeded.
void on_spawn_message();

// Thread-safe getter for the currently spawned ghost actor. Returns
// nullptr if no ghost has been spawned yet. Consumers (e.g. the
// per-frame teleport in Z.3) use this to know whether there's anything
// to drive.
void* get_ghost_actor();

// Called from DllMain's DLL_PROCESS_DETACH. Disables / deletes any
// spawned ghost actors so we don't leak save bloat. Idempotent.
void shutdown();

} // namespace fw::ghost
