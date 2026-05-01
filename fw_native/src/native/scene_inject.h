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
#include <cstddef>
#include <cstdint>

namespace fw::native {

// WM_APP offsets (across the whole DLL):
//   0x42 = FW_MSG_LOAD_GAME          (main_menu_hook.cpp)
//   0x43 = FW_MSG_CONTAINER_APPLY    (main_thread_dispatch.cpp)
//   0x44 = FW_MSG_SPAWN_GHOST        (ghost/actor_hijack.h)
//   0x45 = FW_MSG_STRADAB_INJECT     (this module)
//   0x46 = FW_MSG_STRADAB_POS_UPDATE (this module — M3)
//   0x47 = FW_MSG_STRADAB_BONE_TICK  (this module — M7.b, 20Hz timer)
//   0x48 = FW_MSG_STRADAB_POSE_APPLY (this module — M8P3.15 net pose)
constexpr UINT FW_MSG_STRADAB_INJECT     = WM_APP + 0x45;
constexpr UINT FW_MSG_STRADAB_POS_UPDATE = WM_APP + 0x46;
constexpr UINT FW_MSG_STRADAB_BONE_TICK  = WM_APP + 0x47;
constexpr UINT FW_MSG_STRADAB_POSE_APPLY = WM_APP + 0x48;

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

// M8P3.15: net thread → main thread handoff for received pose data.
// store_remote_pose() is called from the net thread on POSE_BROADCAST
// receive: stashes quats in a mutex-protected slot and posts
// FW_MSG_STRADAB_POSE_APPLY to the FO4 main window.
//
// on_pose_apply_message() is called from WndProc when that message
// arrives — it reads the slot, walks the ghost body's bones, and
// writes received quaternions into each bone's m_kLocal rotation.
// Engine's UpdateDownwardPass propagates to m_kWorld, hook overrides
// already apply on top (no conflict).
//
// quats[i] order matches walk_player_nested traversal of the body
// (sorted by bone name) — both sender and receiver walk identical
// NIFs so the index correspondence is deterministic.
void store_remote_pose(std::uint64_t ts_ms,
                       const void* quats_buf,
                       std::size_t bone_count);
void on_pose_apply_message();

// Called from DLL_PROCESS_DETACH. Stops the arm worker thread (if still
// sleeping), then calls detach_debug_node(). Idempotent.
void shutdown();

// === M9 wedge 2 — armor visual sync on the ghost body =====================
//
// Approach: when the receiver gets EQUIP_BCAST(form_id) for a peer, we
// resolve the form to its 3rd-person NIF path (via TESObjectARMO struct
// walk — see offsets.h "M9 wedge 2"), load the NIF via the canonical
// engine loader (g_r.nif_load_by_path), and attach it as a child of the
// ghost root NiNode (via g_r.attach_child_direct).
//
// The ghost shares the LOCAL player's skeleton through M8P3 swap, so the
// armor NIF's BSDismemberSkinInstance resolver finds bone names ("Pelvis",
// "SPINE1", ...) in the ghost subtree and skins to them — same bones the
// body uses, so the armor follows the same animation.
//
// Wedge 2 limitations (deliberately accepted, see CHANGELOG):
//   - Single-peer scope: the SINGLE g_injected_cube ghost is used for
//     all attached armor regardless of peer_id. Multi-peer ghosts are
//     a future wedge.
//   - No material swap variants — only the base ARMA path is loaded.
//     Items with cosmetic variants (rusty/clean/painted raider) show
//     the default skin.
//   - No biped slot mask hiding — base body geometry is fully visible
//     under the armor; if the armor doesn't fully cover (most don't,
//     OK), no visible glitch. If it tries to hide body parts (Vault
//     Suit hides arms), there may be minor body-clip at the edges.
//   - Power Armor not supported — multi-piece + animation integration
//     requires a separate architecture.
//
// Threading: both functions are MAIN-THREAD-ONLY. Called from the WndProc
// drain of FW_MSG_EQUIP_APPLY (queued by net thread). Engine NIF loader
// + scene graph mutations require main-thread affinity.
//
// State: per-peer attached-NIF map kept in scene_inject's anonymous
// namespace, keyed by (peer_id, item_form_id) → loaded NiNode* + bsfade
// parent slot. UNEQUIP looks up the entry, detaches, drops refcount,
// removes from map.
//
// peer_id parameter: ASCII null-terminated, max 15 chars (FixedClientId
// from protocol). Used as map key. Currently we just log it; visually
// only ONE ghost is updated regardless of which peer's BCAST we got.
//
// Returns true if the operation completed without SEH or null-deref.
// Logs success/failure details (NIF path, parent node ptr, error code).
bool ghost_attach_armor(const char* peer_id, std::uint32_t item_form_id);
bool ghost_detach_armor(const char* peer_id, std::uint32_t item_form_id);

// M9 wedge 2 — flush deferred armor ops accumulated while the ghost
// wasn't yet spawned. Pending queue addresses the boot-time race where
// peer A's force-equip-cycle (B8) broadcasts EQUIP/UNEQUIP for the
// Vault Suit BEFORE peer B's ghost has been injected → without queueing
// those events would be permanently lost (no later broadcast unless A
// changes equipment again, which they typically don't).
//
// Called after inject_debug_cube success (i.e. ghost_attach_armor will
// no longer skip with "no ghost yet"). Idempotent: calling with no
// pending ops is a cheap no-op.
//
// Internally it swaps the queue out under a mutex and processes each op
// by calling ghost_attach_armor / ghost_detach_armor — same path as
// fresh RX. Order is FIFO per peer (matches send order, so a
// UNEQUIP→EQUIP cycle resolves correctly even with cancellation).
//
// Main thread only.
void flush_pending_armor_ops();

// === M9 wedge 7 — weapon visual sync on the ghost body ====================
//
// Mirror of ghost_attach_armor / ghost_detach_armor for TESObjectWEAP forms.
// Differences from armor path:
//   - Weapons are RIGID (not skinned). No skin_rebind needed — the weapon
//     NIF is attached as a child of a SINGLE bone (the "WEAPON" attach node
//     parented under RArm_Hand in the cached skel) and inherits its
//     world transform automatically.
//   - Single 3rd-person model in TESObjectWEAP — no addon array walk,
//     no male/female/1P scoring. Just resolve TESModel.path at the right
//     offset (probed at runtime, see offsets.h "M9 wedge 7" block).
//   - The dispatcher tries ARMOR first, then WEAPON if armor returned
//     false (form wasn't ARMO). Either path may queue on boot race; the
//     duplicate harmless because the wrong-type flush will silently
//     fail and the right-type flush will succeed (idempotent skip).
//
// Limitations (deliberately accepted, see CHANGELOG M9 closure):
//   - No weapon-mod (BGSMod) attachments — scope/silencer/paint variants
//     not synced. Same w4-deferred case as armor mods.
//   - No two-handed support pose adjustment — the 2H rifle attaches to the
//     RArm WEAPON node only; the LArm holding-the-foregrip pose is whatever
//     the body anim graph drives (which we sync via POSE_BROADCAST). Should
//     look right because the player's anim graph rig already poses the
//     hands correctly when a 2H weapon is equipped.
//   - No holstered-weapon rendering — when peer rinfodera the weapon, our
//     UNEQUIP detaches the NIF entirely (peer renders empty-handed). Vanilla
//     would show holstered on hip/back; that's a future enhancement.
//   - Finger curl on grip — the ghost's finger joints don't articulate
//     (they live in havok hkx, not the rendered scene tree — see README
//     known limitations). Result: weapon grip pose is hand-rest, not
//     curled. Cosmetic.
//
// Threading: MAIN-THREAD-ONLY (same as armor). Called from
// drain_equip_apply_queue.
//
// Returns true on success (NIF loaded + attached). False if form isn't
// WEAP / not loaded / NIF load failed / SEH. Logs details either way.
//
// M9 w4 v8 — `nif_descs` and `nif_count` carry the witness NIF descriptors
// the SENDER captured by walking its own BipedAnim post-equip. After
// loading + attaching the base weapon NIF, the receiver iterates these
// descriptors: for each one, load the mod NIF, find the parent_name
// node inside the loaded weapon root, apply the local_transform, and
// attach as a child. nif_count=0 → stock weapon, no extra mods to attach.
//
// Forward-declared as `void*` to avoid pulling protocol.h into this
// header. Pass &PendingEquipOp::nif_descs[0] / .nif_count from the
// dispatcher.
bool ghost_attach_weapon(const char* peer_id, std::uint32_t item_form_id,
                          const void*  nif_descs = nullptr,
                          std::uint8_t nif_count = 0,
                          const char*  nif_path_override = nullptr);
bool ghost_detach_weapon(const char* peer_id, std::uint32_t item_form_id);

// Drain the pending weapon ops queue accumulated while the ghost wasn't
// spawned yet. Mirror of flush_pending_armor_ops. Idempotent. Called from
// the same post-inject_debug_cube callback.
void flush_pending_weapon_ops();

// === M9 wedge 4 v9 — raw mesh weapon attach via wire blob =================
//
// Receiver-side reconstruction of a peer's modded weapon from raw mesh
// data (positions + indices + per-mesh metadata + local_transform). The
// peer's sender-side walker extracts BSGeometry leaves under their
// player's bipedAnim WEAPON node and ships them via MESH_BLOB_BCAST
// (chunked over reliable UDP). This function takes the decoded mesh
// records and rebuilds geometry on the matching ghost.
//
// Pipeline:
//   1. Allocate a fresh NiNode "WeaponRoot_<peer>" if not yet present
//      for this peer; attach it under the cached skeleton's RArm_Hand
//      bone. Cache in g_ghost_weapon_root[peer_id].
//   2. For each mesh record:
//        a. Call sub_14182FFD0 (g_r.geo_builder) with positions, indices
//           and NULL for the optional fields (UVs, normals, tangents,
//           skin weights, etc. — first PoC ships positions+indices only).
//        b. Write the mesh's local_transform (16 floats) into bs+0x30.
//        c. Attach BSTriShape as child of weapon root.
//      All steps SEH-protected; per-mesh failure logged + skipped.
//   3. Engine's render walk picks up the new BSTriShapes next frame.
//      Without proper materials they may render pink/purple — Step 4d
//      adds material binding via apply_materials_walker.
//
// `meshes_blob_ptr` is treated as `std::vector<PendingMeshRecord>*` —
// passed as void* to keep this header decoupled from main_thread_dispatch.h.
// Type erasure resolved on the .cpp side.
//
// Returns the count of meshes successfully attached. -1 on failure
// (resolver not ready / no ghost spawned / no cached skeleton).
//
// REPLACEMENT semantics: if a weapon was already attached for this peer,
// we DESTROY the previous weapon root (cascades destroy of all child
// BSTriShapes via refcount) before creating the new one. This is why
// we replace EQUIP_BCAST's legacy ghost_attach_weapon — those would
// fight us on the same parent slot.
//
// Threading: MAIN THREAD ONLY. Called from drain_mesh_blob_apply_queue.
int ghost_attach_mesh_blob(const char* peer_id, std::uint32_t item_form_id,
                            std::uint32_t equip_seq,
                            const void*  meshes_blob_ptr);

// Mirror: detach the weapon root for `peer_id`. Cascades destroy of all
// child BSTriShapes via refcount. Idempotent (no-op if no weapon root
// exists for this peer). Returns true on success (or no-op).
bool ghost_detach_mesh_blob(const char* peer_id);

// Form-type probe — returns true iff `item_form_id` resolves to a
// TESObjectWEAP (i.e. its TESModel path matches the "Weapons\\..." pattern
// used by resolve_weapon_nif_path). Wraps the engine lookup + struct walk;
// does NOT mutate state. SEH-protected internally.
//
// Used by equip_hook's mesh-tx gate to ensure mesh extraction fires only
// for actual weapons (not e.g. Vault Suit with a legendary OMOD that
// passed the older `!wire_mods.empty()` proxy filter).
bool is_weapon_form(std::uint32_t item_form_id);

// === M9 wedge 4 v9.1 — UNIFIED ghost weapon state machine ================
//
// Single source of truth: each peer has at most ONE weapon attached at any
// time. All wire events (EQUIP_BCAST, UNEQUIP_BCAST, MESH_BLOB_BCAST) go
// through ghost_set_weapon / ghost_clear_weapon. Atomic transitions, no
// accumulation, no stale weapons.
//
// Path resolution: caller supplies a list of candidate NIF paths in
// preferred order. The function tries each via nif_load_by_path until one
// succeeds. Falls back to resolve_weapon_nif_path (legacy probe with
// Dummy-placeholder filter) if all caller candidates fail.
//
// Downgrade protection: if the resolved path is a placeholder (e.g.
// "RecieverDummy.nif") AND the current slot has a non-placeholder path
// for the same form_id, the call is REJECTED — refuses to overwrite a
// proper path with a worse one. This handles the race where EQUIP_BCAST
// arrives AFTER MESH_BLOB has installed the proper path.
//
// Returns true on success or no-op (idempotent), false on hard failure
// (no candidate path loaded; existing slot left untouched).
//
// Threading: MAIN THREAD ONLY. Internal mutex guards the slot map.
bool ghost_set_weapon(const char* peer_id,
                       std::uint32_t item_form_id,
                       const char* const* candidate_paths,
                       std::size_t num_candidates);

// Clears the peer's weapon slot atomically. Pass `expected_form_id` to
// guard against spurious clears: if the slot has a different form_id than
// expected (i.e. peer already switched to a different weapon by the time
// the UNEQUIP arrives), the call is a no-op. Pass 0 to force-clear.
//
// Returns true on success / no-op. Threading: main thread only.
bool ghost_clear_weapon(const char* peer_id,
                         std::uint32_t expected_form_id);

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
