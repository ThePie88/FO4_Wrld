// Thin wrappers around the few Fallout4.exe native functions we invoke
// from outside the game's main thread. All routed through typed function
// pointers resolved at DLL init (after version check).
//
// RVAs are defined in src/offsets.h. This header decouples callers (net
// dispatch) from the resolution mechanism and gives us SEH cages.
//
// Thread safety:
// - `lookup_by_form_id` walks an internal hashmap; it's read-only and
//   multi-thread safe in practice (the Frida era did exactly this).
// - `disable_ref` / `enable_ref` go through the engine's deferred-op
//   queue — they're `enqueue_*` functions, designed to be called from
//   arbitrary threads.
// - `write_pos_rot_raw` writes directly to REFR+0xD0 / +0xC0 from the
//   net thread. Race with Havok is possible (same behavior as Frida era);
//   the "flicker" is a known limit resolved in B5 via D3D11 render.

#pragma once

#include <cstddef>
#include <cstdint>

namespace fw::engine {

// Set once at init. Read by the call wrappers below. Must be non-zero
// before any function in this namespace is invoked.
bool init(std::uintptr_t module_base);

// Returns the REFR* for `form_id`, or nullptr if not found in the engine's
// form table (already despawned, unloaded cell, wrong id, etc).
void* lookup_by_form_id(std::uint32_t form_id);

// Reads REFR.flags (+0x10). Returns 0 on null/unreadable.
std::uint32_t read_flags(void* ref);

// Sends the REFR through the engine's disable-enqueue path (effectively
// what console `disable` does). Idempotent: already-disabled refs ignored
// by the engine.
void disable_ref(void* ref, bool fade_out);

// Enable path — two functions: cleanup + apply. The game only applies
// enable if the disable flag is set, so calling on already-enabled refs
// is a no-op.
void enable_ref(void* ref);

// Resolve form_id, verify (base_id, cell_id) match the expected identity,
// then apply disable or enable. Returns true if applied, false if lookup
// failed, identity mismatched, or the state was already correct.
// This is the C++ port of `set_disabled_validated` from the Frida JS era.
bool set_disabled_validated(
    std::uint32_t form_id,
    std::uint32_t expected_base_id,
    std::uint32_t expected_cell_id,
    bool disabled);

// Raw write of position + rotation on the REFR at form_id. No identity
// check (caller is responsible — typically the ghost path where identity
// is not enforced because we're driving a local ref as an avatar).
// Fails silently if form_id doesn't resolve.
void write_ghost_pos_rot(
    std::uint32_t form_id,
    float x, float y, float z,
    float rx, float ry, float rz);

// B3.b: Invoke the engine's LoadGame routine with a save file name.
// Replicates the sequence the `LoadGame` console command executes:
//   1) precondition check (save device available)
//   2) prep call
//   3) set "load in progress" flag
//   4) TESSaveLoadManager::LoadGame(filename, -1, 0, 1, 0)
//
// Returns:
//   true  — LoadGame succeeded (engine will transition to load screen).
//   false — precondition failed, or the engine reported inability to load
//           the named savefile (filename doesn't exist? profile missing?).
//           Check fw_native.log for the game's own error line.
//
// MUST be called from the main (UI/engine) thread. Safe to call exactly
// once per process — the "load in progress" flag it sets is not cleared
// by us. Calling twice without the engine finishing the first load is
// undefined behavior.
bool load_game_by_name(const char* save_name);

// B4.e: Apply a GlobalVar.SetValue received from another peer.
//
// Writes `*(float*)(TESGlobal + 0x30) = value` directly. Safe from any
// thread (plain memory write, SEH-caged). Refuses if the global has the
// const-flag set (bit 0x40 in TESForm.flags at +0x10), mirroring the
// Papyrus native's own gate so we don't silently violate mod constraints.
//
// Returns true on applied write, false if lookup failed, global was null,
// flag was const, or the write SEH-faulted.
bool apply_global_var(std::uint32_t global_form_id, float value);

// B1.j.1: force-materialize the runtime BGSInventoryList for a container
// REFR if it hasn't been populated yet. The engine materializes the list
// lazily the first time the container is interacted with (inside
// sub_140502940). We call the same materializer directly (sub_140511F10)
// BEFORE our pre-op scan so the list has the full inventory.
//
// Steps:
//   1. Read REFR+0xF8. If non-null, nothing to do (already materialized).
//   2. Read baseForm at REFR+0xE0. Call sub_140313570(baseForm, 'CONT')
//      to get the BGSContainer component. If null (REFR isn't a container
//      base), return false.
//   3. Call sub_140511F10(refr, bgscont). The engine allocates a 0x80
//      byte BGSInventoryList, populates entries from the base CONT, and
//      writes the pointer to REFR+0xF8.
//
// Returns true if REFR+0xF8 is non-null after the call (materialization
// succeeded OR was already done). False on any failure.
//
// Thread safety: must run on the main thread. No TLS reads in the
// materializer itself, but the allocator it uses may touch thread-local
// state. In practice we only ever call this from vt[0x7A] detour which
// is guaranteed main-thread by MinHook.
bool force_materialize_inventory(void* container_ref);

// B1.k.3: decode a ContainerMenu inventory entry pointer to a TESForm*.
//
// ContainerMenu keeps a 32-byte-per-entry array at this+512 (player side)
// and this+640 (container side). The entry's first qword is NOT a direct
// form pointer — it's an opaque structure that the engine decodes via
// sub_1403478E0(*qword_1430E1370, entry). This helper is a thin wrapper
// around that call (SEH-caged; returns nullptr on any failure).
//
// The returned TESForm* is the base item form (TESObjectMISC / WEAP /
// ARMO / etc.) — what we want to read FORMID_OFF (+0x14) from to emit
// a CONTAINER_OP.
void* resolve_inventory_entry_form(void* entry_ptr);

// B1.k.2: resolve a BGSObjectRefHandle to a TESObjectREFR*.
//
// The engine stores handles (32-bit opaque ids) in many places instead of
// raw REFR pointers, so that if the REFR is destroyed the handle becomes
// stale but doesn't dangle. ContainerMenu stores its target container
// this way at `this+1064`. To reach the REFR* we call the engine's
// resolver sub_14021E230 — signature:
//
//   void sub_14021E230(
//       TESObjectREFR** out,       // output slot (written to)
//       BGSObjectRefHandle* handle); // input handle pointer
//
// `out` receives the REFR* or null (if handle is stale). The helper also
// increments a refcount internally, but since we only READ the handle's
// target identity (not store the REFR long-term), that's fine.
//
// Returns the REFR* on success, nullptr on any failure (null handle,
// stale handle, SEH raise).
void* resolve_refhandle(void* handle_ptr);

// B1.g: apply a peer-authored container op (TAKE/PUT) to our local engine.
//
// Called when we receive a CONTAINER_BCAST from the server: the REFR whose
// form_id matches `container_form_id` on our side is resolved, identity-
// checked against (expected_base_id, expected_cell_id), and if matched,
// we invoke the engine's real AddItem (sub_1411735A0) for PUT or
// RemoveItem (sub_1411825A0) for TAKE.
//
// kind: 1 = TAKE (remove count×item from the container)
//       2 = PUT  (add    count×item to   the container)
//
// Returns true on apply, false if:
//   - lookup_by_form_id(container_form_id) returned null
//   - identity mismatch (wrong base_id or cell_id)
//   - lookup_by_form_id(item_base_id) returned null (item form missing)
//   - kind not in {TAKE, PUT}
//   - SEH raised inside the engine call
//
// NOTE on feedback loop: the engine's real AddItem/RemoveItem may internally
// invoke vt[0x7A] AddObjectToContainer (our hooked slot). The caller is
// responsible for setting the thread-local `g_applying_remote` flag (in
// container_hook) before/after this call so our detour bypasses the
// observe/submit path and just runs g_orig_add — otherwise we'd echo the
// remote op back to the server as a new CONTAINER_OP (infinite loop).
bool apply_container_op_to_engine(
    std::uint32_t kind,
    std::uint32_t container_form_id,
    std::uint32_t expected_base_id,
    std::uint32_t expected_cell_id,
    std::uint32_t item_base_id,
    std::int32_t  count);

// B6.1 — apply a remote door activation by invoking the engine's
// Activate worker (sub_140514180 @ RVA 0x514180) on the local REFR
// matching the broadcast identity.
//
// Pipeline:
//   1. lookup_by_form_id(door_form_id) → local REFR
//   2. validate (base, cell) match the expected values from the sender
//   3. invoke sub_140514180(local_refr, nullptr, nullptr, 1, 0, 0, 0)
//      — args 2-7 use the same shape we observed during phase 1.b
//        (activator=null, force=1). The engine fires the door's
//        animation graph notify automatically, propagating to physics
//        + persistence (vt[0x99] save-load slot stays consistent).
//
// Caller MUST be inside an fw::hooks::ApplyingRemoteGuard scope so the
// door_hook detour sees `tls_applying_remote=true` and skips the observe
// + broadcast path on this re-entry — otherwise we'd echo the remote
// activation back to the server (infinite ping-pong between peers).
//
// Returns true on apply, false if:
//   - lookup_by_form_id returned null (REFR not loaded in our world)
//   - identity mismatch (wrong base_id or cell_id)
//   - SEH raised inside the engine call
bool apply_door_op_to_engine(
    std::uint32_t door_form_id,
    std::uint32_t expected_base_id,
    std::uint32_t expected_cell_id);

// B5 scene view-proj capture: read the 4x4 matrix at NiCamera+288
// owned by PlayerCamera.states[0] (FirstPersonState — always populated)
// plus the player eye world position. Hypothesis: captured matrix is
// the camera-relative VP (game pre-subtracts eye_pos from world to
// reduce float-precision artifacts at FO4's 10^5-unit world scale).
//
// Returns true if all reads succeeded, false on null singleton / SEH.
// Output matrix is row-major-as-written in memory (16 floats).
bool read_scene_view_proj(float out_view_proj[16], float out_eye_world[3]);

// β.6 shake fix: read the LIVE camera world transform from the
// PlayerCamera's NiCamera (NiAVObject::world). This is the game's
// frame-perfect eye pos + orientation, including head-bob, smoothing,
// and any engine interpolation applied this frame. Using this instead
// of deriving eye from (player.pos + EYE_HEIGHT) removes shake because
// our VP matches exactly what the game's scenery is rendered with.
//
//   out_eye_world[3]   : world-space eye pos (frame-perfect, w/ bob)
//   out_basis_rows[9]  : 3x3 world rotation, 3 rows of 3 floats each
//                        row 0 = camera right  (in world basis)
//                        row 1 = camera up     (in world basis)
//                        row 2 = camera forward(in world basis)
//                        Row interpretation per NetImmerse/Gamebryo
//                        convention: NiMatrix3 stores rows.
//
// Returns true on full success, false on null singleton / SEH.
bool read_camera_world_transform(float out_eye_world[3],
                                  float out_basis_rows[9]);

// β.6 shake fix v2: extract the frame-perfect FORWARD direction from
// the captured worldToCam matrix (NiCamera+0x120). In row-major VP,
// row 3 encodes the camera-forward as (fx, fy, fz, 0) — unit length.
// Using this instead of actor-derived yaw/pitch eliminates rotation
// mismatch vs. the game's render frame (which uses smoothed camera
// orientation, not raw actor rot[]).
//
// Returns true on success, false on null singleton / non-unit row
// (unreliable matrix — e.g., captured mid-write or from a different
// render pass).
bool read_camera_forward(float out_fwd[3]);

// β.6b v5 depth fix: read the LIVE near/far from NiFrustum inside
// PlayerCamera.states[0].NiCamera (+0x160 base, +0x10 near, +0x14 far).
// These are the ACTUAL near/far used by the scene camera this frame,
// not static .rdata guesses. Used to build a matching reverse-Z
// projection for depth occlusion.
//
// Returns false on any null/SEH. Output values in game units.
bool read_camera_frustum_near_far(float& out_near, float& out_far);

// B5 camera probe (diagnostic): at the first valid player pose we scan
// the PlayerCamera singleton's first 0x200 bytes for any qword that
// dereferences to a NiCamera vtable (VA = module_base + 0x267DD50).
// Every match is logged as "[camprobe] PlayerCamera+0xNN -> NiCamera*".
// One-shot: flips an atomic after first successful probe. Safe from any
// thread (SEH-caged). Lets us resolve OFF_NICAM empirically given the
// multiple-inheritance ambiguity from IDA static analysis.
void probe_camera_layout_once();

// β.6 shake fix: periodic probe of candidate "frame-perfect eye" fields
// inside PlayerCamera and FirstPersonState. Agent RE (2026-04-22) found:
//   - PlayerCamera+0x188 : bufferedCameraPos (NiPoint3) + flag at +0x1A7
//   - FirstPersonState+0x30..0x60: SSE reference suggests lastPosition,
//     lastFrameSpringVelocity, dampeningOffset (each NiPoint3).
// Dumping these live while the user walks/runs will show which tracks
// the true render eye with bob. Logs every ~5s.
void probe_camera_eye_fields();

// Parallel: scan the MainCullingCamera singleton instance for NiCamera
// pointers. MCC is the scene render camera (BSTSingletonSDM). If it
// holds a NiCamera, that one is the TRUE scene VP source.
void probe_main_culling_camera_once();

// Z.2 (Path B): spawn a fresh Actor by invoking the engine's PlaceAtMe
// Papyrus native directly. Anchors to the player's REFR so the new
// actor inherits the player's current cell. Returns the raw Actor*
// (0x490 B) on success, nullptr on failure (lookup miss, null player,
// SEH).
//
// Post-spawn we OR the TEMPORARY flag (0x4000) into the new REFR's
// flags field to prevent save bloat — PlaceAtMe hardcodes only 0x1000000.
//
// MAIN THREAD ONLY. PlaceAtMe reads TLS (NtCurrentTeb) and takes the
// REFR cell-attach lock; calling from the net thread or any D3D11
// hook thread causes heap corruption. Always dispatch via
// fw::dispatch::FW_MSG_SPAWN_GHOST.
void* spawn_ghost_actor(std::uint32_t template_form_id);

// B1.e: walk the runtime BGSInventoryList on a container REFR and produce
// (item_base_id, count) pairs.
//
// Layout (from B1.c RE pass on sub_140507660):
//   list = *(REFR + 0xF8)   — may be null for never-touched containers.
//                             When null, fall back to scanning the baseForm
//                             BGSContainer (the "default" loot table). For
//                             now we skip null-list containers; the seed is
//                             best-effort.
//   entries = *(list + 0x58)
//   count   = *(u32)(list + 0x68)
//   stride  = 0x10 bytes per entry
//   entry[0x00] = TESBoundObject*  (item template)
//   per-entry count = sub_140349B30(entry)
//   skip entries where (*entry[0] + 0x1A) == 0x38 (LVLI leveled item)
//
// Caller supplies `out_pairs` buffer of size >= max_items. Returns number
// of entries written. Fails (returns 0) on any SEH / null-list.
std::size_t scan_container_inventory(
    void* container_ref,
    std::uint32_t* out_item_ids,     // buffer [max_items]
    std::int32_t*  out_counts,       // buffer [max_items]
    std::size_t    max_items);

} // namespace fw::engine
