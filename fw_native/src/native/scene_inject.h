// Strada B — scene graph injection.
//
// Goal for M1: allocate a native NiNode via the engine's own allocator,
// in-place construct it, name it, and attach it as a child of the
// ShadowSceneNode (SSN). NO geometry yet — an empty NiNode will not
// render but WILL be walked by the scene graph on every frame. If it
// survives 10+ frames without crashing the engine, feasibility is
// proven and M2 (adding BSDynamicTriShape geometry) becomes viable.
//
// Threading: ALL mutation functions (inject/detach) MUST be called on
// the engine's main thread. The allocator writes to TEB+0x9C0 (TLS
// cookie), the scene graph array has implicit locks held by the render
// thread walk, AttachChild touches atomic refcounts on live objects.
// The WM_APP+0x45 dispatcher ensures main-thread affinity — worker
// thread posts the message, WndProc subclass drains it on main.
//
// Lifetime: the injected node is stored in a module-level singleton.
// On DLL unload we DetachChild + Release it so the engine doesn't hold
// a dangling pointer past our unmap. On cell transitions the SSN
// re-creates itself — we must re-attach after each load. Hook on
// LoadGame completion is out of scope for M1 (the first live test can
// be done with one manual inject post-boot, after ~30s boot delay).

#pragma once

#include <windows.h>

namespace fw::native {

// WM_APP offsets (across the whole DLL):
//   0x42 = FW_MSG_LOAD_GAME          (main_menu_hook.cpp)
//   0x43 = FW_MSG_CONTAINER_APPLY    (main_thread_dispatch.cpp)
//   0x44 = FW_MSG_SPAWN_GHOST        (ghost/actor_hijack.h)
//   0x45 = FW_MSG_STRADAB_INJECT     (this module)
//   0x46 = FW_MSG_STRADAB_POS_UPDATE (this module — M3)
//   0x47 = FW_MSG_STRADAB_BONE_TICK  (this module — M7.b, 20Hz timer)
constexpr UINT FW_MSG_STRADAB_INJECT     = WM_APP + 0x45;
constexpr UINT FW_MSG_STRADAB_POS_UPDATE = WM_APP + 0x46;
constexpr UINT FW_MSG_STRADAB_BONE_TICK  = WM_APP + 0x47;

// Arm a worker thread that, after delay_ms milliseconds, PostMessages
// FW_MSG_STRADAB_INJECT to the main FO4 window. The WndProc subclass
// then invokes on_inject_message() on the main thread.
//
// Safe to call from DLL init (net thread / init_thread). The worker
// joins on DLL unload. delay_ms should be long enough for the player
// to have completed LoadGame — 30000 (30s) is conservative.
void arm_injection_after_boot(unsigned int delay_ms);

// Called from main_menu_hook's WndProc when msg == FW_MSG_STRADAB_INJECT.
// Attempts a one-shot inject at a fixed test position. On success the
// node ptr is stored in the module-level singleton; on failure we log
// and bail (no retry — M1 is pass/fail per boot).
void on_inject_message();

// M3: per-frame positioning. Called from main_menu_hook's WndProc when
// msg == FW_MSG_STRADAB_POS_UPDATE. Reads fresh remote snapshot and
// updates the cube's local.translate to track the remote player.
void on_pos_update_message();

// M3.1 event-driven: called from the net thread right after a new
// POS_BROADCAST has been written into the remote snapshot. Posts
// FW_MSG_STRADAB_POS_UPDATE to the main window so the handler runs
// on the main thread with zero polling lag. Thread-safe, cheap —
// just a PostMessage. No-op if HWND not ready or no cube injected yet.
void notify_remote_pos_changed();

// M7.b: bone-copy tick handler. Called from WndProc when a
// FW_MSG_STRADAB_BONE_TICK arrives. Copies the local player's
// per-frame animated bone transforms onto the ghost body's matching
// bones. Must run on main thread (touches scene graph transforms +
// calls UpdateDownwardPass). No-op if ghost not injected yet.
void on_bone_tick_message();

// Called from DLL_PROCESS_DETACH. Stops the arm worker thread (if still
// sleeping), then calls detach_debug_node(). Idempotent.
void shutdown();

// --- M2.2: BSDynamicTriShape allocation (empty, no geometry yet) -----------

// Allocate + in-place-ctor a BSDynamicTriShape via the engine's allocator,
// name it "fw_debug_cube_dyn", set position, mark movable, attach to the
// World SceneGraph (as a sibling of the M1 empty NiNode).
//
// In M2.2 there's NO geometry yet — no vertex buffer, no shader, no alpha.
// The engine's render walk will visit this object every frame, call its
// vtable methods (Update, ComputeBoundingSphere, etc.) and find empty
// geometry → skip the draw. We just want to prove the OBJECT allocates,
// constructs and survives the scene walk.
//
// M2.3 will clone shader+alpha into it, M2.4 will populate vertex data.
//
// Main thread only (scene graph lock, allocator TLS).
bool inject_debug_cube(float x, float y, float z);

// Detaches + releases the cube if injected. Called from shutdown().
void detach_debug_cube();

// Called once from main thread (via WM_APP dispatcher) after the game
// reaches a stable state (LoadGame complete, SSN singleton non-null).
//
// Returns true if a node was allocated AND attached. False if:
//   - SSN singleton is still null (we're inside a loading screen)
//   - allocator returned null (pool OOM — should never happen in practice)
//   - AttachChild call crashed / was skipped (see log)
//
// Side effects on success:
//   - A NiNode is allocated via sub_1416579C0 at our tracked ptr
//   - Its vtable points to NiNode::vftable (verifiable in IDA)
//   - Its name is "fw_debug_cube" (NiFixedString, deduped engine-side)
//   - local.translate is set to (x, y, z) in worldspace units
//   - flags has kIsMovable (0x800) set
//   - refcount is 1 (SSN holds it; our local temp refs undone)
bool inject_debug_node(float x, float y, float z);

// Called from DLL_PROCESS_DETACH via main-thread guarantee only if the
// game hasn't already torn down (engine exit is unsafe to touch). We
// DetachChild + Release to free the node cleanly. No-op if never injected.
//
// Rationale: leaving our ptr attached past DLL unload means SSN's child
// array has a live pointer into an unmapped vtable. Next tree walk =
// instant crash. Detach is required before unload.
void detach_debug_node();

// Diagnostic: returns the raw engine-side NiNode* (opaque here — no
// struct definition exposed). nullptr if not injected. Caller must not
// dereference outside main thread unless holding scene lock.
void* get_debug_node();

// Number of times we successfully re-attached across cell transitions.
// Starts at 0; increments once per inject_debug_node() that succeeded.
// Useful for the live test — we expect monotone growth as we cross
// worldspace boundaries.
unsigned int get_attach_count();

} // namespace fw::native
