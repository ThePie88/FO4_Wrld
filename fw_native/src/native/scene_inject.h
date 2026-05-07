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
// effective_priority (v10, M9.w2 PROPER): OMOD-modified ARMA priority
// extracted by sender via sub_140436820. 0 = use form default ARMO+0x2A6
// (back-compat for non-ARMO or pre-v10 callers). Receiver feeds into
// resolve_armor_nif_path's PrioritySelect filter.
bool ghost_attach_armor(const char* peer_id, std::uint32_t item_form_id,
                        std::uint16_t effective_priority = 0);
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

// M9.5 — re-apply skin swap on every currently-attached ghost armor.
// Rationale: when local player equips an armor whose NIF is in the engine's
// resource cache (the same instance also used by ghost_attach_armor), the
// engine's EquipObject post-attach skin re-bind walks the SHARED instance
// and points its skin's bones[] at the LOCAL player's skel. Ghost armors
// (sharing that NIF) silently lose their bone bindings to the ghost skel
// — visually the ghost's suit "detaches" / floats / appears unequipped
// even though our internal map still records it as attached.
//
// Calling this AFTER chain-through of g_orig_equip / g_orig_unequip
// reverses the engine's re-bind by re-running swap_skin_bones_to_skeleton
// on every ghost armor. niptr_swap is idempotent so this is safe: if the
// armor wasn't actually mutated by the engine, the swap is a 0-write
// no-op. If it was, our writes restore ghost-skel binding.
//
// Side effect: the local player's armor (same shared instance) will have
// its bones briefly pointing to the ghost skel after our swap. The engine
// re-binds again on the next animation frame so the local player sees a
// 1-frame mis-render at most — acceptable cost vs persistent ghost bug.
//
// Main thread only.
void reapply_ghost_skin_swaps(const char* trigger_label);

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

// === M9.w4 PROPER (v0.4.2+) — captured-mesh receiver reconstruction ========
//
// POD view of one captured mesh from sender's clone-factory pipeline.
// All pointers reference caller-owned storage; the function copies what
// it needs into engine-owned BSTriShape allocations during the call.
struct CapturedMeshView {
    const char*         m_name;             // null-terminated, e.g. "10mmSuppressor:0"
    const char*         parent_placeholder; // attach-target NiNode name, may be empty
    const float*        positions;          // 3*vert_count floats (12B/vert)
    const std::uint16_t* indices;           // 3*tri_count u16
    std::uint16_t       vert_count;
    std::uint32_t       tri_count;
    const float*        local_transform;    // 16 floats; nullptr = identity
};

// Reconstruct + attach captured weapon-mod meshes to the ghost's already-
// loaded base weapon NIF. Caller must have invoked ghost_set_weapon FIRST
// to load the base; this function adds the mod meshes ON TOP of it.
//
// Per mesh:
//   1. Dedup by m_name (engine clones some pieces twice; keep first).
//   2. Build BSTriShape via factory `sub_14182FFD0` from positions+indices.
//   3. Set local_transform at +0x30..+0x6C.
//   4. Find `parent_placeholder` NiNode in the loaded base NIF tree.
//   5. attach_child_direct(parent, geom).
//
// No shader/material binding in this initial cut — geometry renders
// with default (likely pink/white). Material binding is a follow-up.
//
// Returns count of meshes successfully attached, or -1 on hard failure
// (no ghost weapon slot, factory not resolved, etc.).
//
// Threading: MAIN THREAD ONLY. Called from drain_mesh_blob_apply_queue
// after ghost_set_weapon succeeds.
int attach_captured_meshes_to_ghost_weapon(
    const char*               peer_id,
    std::uint32_t             item_form_id,
    const CapturedMeshView*   meshes,
    std::size_t               mesh_count);

// === M9.w4 PROPER (v0.4.2+, Path Y) — disk-loaded mod NIFs ================
//
// ALTERNATIVE to the factory-reconstruct path. Instead of building
// BSTriShape from raw vertex/index data captured by the sender, this
// function uses the captured `parent_placeholder` (= mod sub-NIF root
// name, e.g. "10mmSuppressor") + `bgsm_path` (gives us the base folder)
// to derive a disk path for each mod's sub-NIF and load it via the
// engine's standard nif_load_by_path. The engine handles shader binding
// + material resolution naturally — no vertex format mismatch crash
// (which is what doomed the donor-clone approach in v0.4.0 + v0.4.2 P3.1).
//
// Per UNIQUE parent_placeholder (deduped):
//   1. Collect base folder from the captured bgsm_path's parent dir.
//   2. Build candidate disk paths:
//        Weapons\<base_folder>\<placeholder>.nif
//        Weapons\<base_folder>\Mods\<placeholder>.nif
//   3. nif_load_by_path on each candidate; first success wins.
//   4. apply_materials walker on the loaded mod NIF.
//   5. attach_child_direct to ghost's base weapon root.
//
// Skips entries whose m_name appears in the base NIF tree (= stock
// parts already in the loaded base, no need to add a duplicate).
//
// Returns count of mod NIFs successfully loaded + attached.
//
// Threading: MAIN THREAD ONLY.
int attach_mod_nifs_via_disk(
    const char*               peer_id,
    std::uint32_t             item_form_id,
    const CapturedMeshView*   meshes,
    std::size_t               mesh_count);

// === M9.w4 PROPER (v0.4.2+) — BSResource::EntryDB live probe ==============
//
// Dumps first N non-null entries from the NIF resource manager singleton
// to settle 4-agent disagreement on Entry+0x10 layout. Logs raw qwords +
// per-field interpretation attempts (BSFixedString-like, raw char*,
// FO4 +0x18 pool entry). Threading: SEH-caged, can run from any thread.
void dump_resmgr_first_entries(int count_max);

// Spawn a one-shot worker thread that calls dump_resmgr_first_entries(8)
// after `delay_ms`. Use 60-90s delay to give the player time to load
// game + walk around + equip a weapon (so resmgr has weapon entries).
void arm_resmgr_probe(unsigned int delay_ms);

// M9.w4 PROPER (v0.4.2+, RESMGR-LOOKUP) — find a cached NIF by its
// BSFadeNode m_name. Walks the BSResource::EntryDB<BSModelDB> bucket
// array, returns the first node matching `target_name`.
//
// Caller must REFBUMP the returned node before attaching to ghost
// (the singleton holds its own ref, but attach_child_direct pulls
// another ref for the parent slot — without a pre-bump, detach
// could free it from under the cache).
//
// Returns nullptr on miss / engine not ready.
//
// SEH-caged. Threading: main thread.
void* find_loaded_nif_by_m_name(const char* target_name);

// Path NIF-CAPTURE — load `path` via nif_load_by_path + apply_materials,
// attach as child of the ghost's already-loaded base weapon NIF (slot's
// nif_node, set by ghost_set_weapon). Returns true on success.
//
// Used by drain_mesh_blob_apply_queue when handling a path-only blob:
// the FIRST path goes through ghost_set_weapon (slot replacement),
// subsequent paths go through this helper (additive attach).
//
// Threading: MAIN THREAD ONLY.
// 2026-05-06 — slot_name added so disk-loaded mods route to the same
// resolved placeholder as resmgr-share path. Pass nullptr or empty for
// the legacy "attach at base_root" behaviour.
bool attach_extra_nif_to_ghost_weapon(const char* peer_id,
                                       const char* path,
                                       const char* slot_name = nullptr);

// 2026-05-06 LATE evening (M9 closure, PLAN B — NiStream serialization).
// SENDER side: serialize the LOCAL player's assembled weapon subtree
// (= first child of WEAPON bone, the engine-assembled weapon with all
// OMODs applied) to a byte buffer, ship via fw::net::client over the
// MESH_BLOB_OP wire path with num_meshes=0xFF sentinel, free the
// buffer. Returns the number of chunks queued (0 = nothing sent).
//
// Called from weapon_capture::finalize_pending() when an equip event
// settles. Bypasses the per-leaf ExtractedMesh capture pipeline entirely
// — instead of trying to reconstruct the assembled weapon on the
// receiver from primitive parts (which kept failing), we let the engine
// serialize what it already assembled and let the engine on the other
// side load it back.
//
// `item_form_id` correlates with EQUIP_OP/BCAST.
// Threading: MAIN THREAD (uses NiStream which touches engine globals).
std::size_t serialize_and_ship_player_weapon(std::uint32_t item_form_id);

// RECEIVER side: deserialize a NIF byte buffer and attach the resulting
// root subtree to the ghost's WEAPON bone. Replaces the per-mesh
// receiver path for nif_blob frames. Returns true on success.
//
// The deserialized root is tracked in slot.extra_mods for cleanup on
// next equip. SEH-caged at every engine call.
//
// Threading: MAIN THREAD ONLY.
bool deserialize_and_attach_nif_blob(const char* peer_id,
                                       std::uint32_t item_form_id,
                                       const void* nif_buf,
                                       std::size_t nif_size);

// M9.w4 PROPER (v0.4.2+, RESMGR-SHARE) — refbump-share an existing
// engine-loaded BSFadeNode (returned by find_loaded_nif_by_m_name) and
// attach it as child of the ghost's loaded base weapon NIF.
//
// Refbump is required: the singleton holds 1 ref already, but
// attach_child_direct grabs ANOTHER ref for the parent slot. Without a
// pre-bump, on detach the engine could free the node from under the cache.
//
// `display_name` is the parent_placeholder string captured by the
// sender (e.g. "Pistol10mmReceiver" — the mod NIF root's m_name). It
// is used purely as the resmgr-share KEY (matching the cached
// BSFadeNode m_name) and as a log label. Do NOT use it as the slot
// search key — that's what `slot_name` is for.
//
// `slot_name` is the m_name of the placeholder NiNode INSIDE the base
// weapon NIF where this mod should attach (e.g. "PistolReceiver"). The
// sender extracts this by walking one level above the mod root in its
// own assembled weapon tree (= grand-parent of the captured
// BSGeometry leaf). The receiver runs find_node_by_name on the loaded
// base weapon root looking for an NiNode with this exact name and
// attaches the mod as a child of THAT.
//
// Pass nullptr or empty for `slot_name` if unavailable (e.g. pre-fix
// sender DLL): the mod is then attached at base_root and the log marks
// it FALLBACK. Same fallback fires if the slot name is non-empty but
// no placeholder by that name is found inside the base subtree.
//
// `local_transform` is 16 floats (3x4 rotation + 3 translation + 1
// scale) captured by the sender from its own engine post mod-assembly.
// We write them to NIAV_LOCAL_ROTATE_OFF on the mod node so it lands
// where the engine put it on the sender side. Pass nullptr to skip the
// transform write (mod will inherit whatever transform it had — usually
// identity for a fresh resmgr entry, which is wrong, so don't skip
// unless you know what you're doing).
//
// Returns true on attach success (placeholder OR fallback). Threading:
// main thread only.
bool attach_extra_node_to_ghost_weapon(const char* peer_id,
                                        void* node,
                                        const char* display_name,
                                        const char* slot_name,
                                        const float local_transform[16]);

// 2026-05-05 — hide a ghost weapon's "default" base geometry when the
// blob carries mod descriptors. Walks the loaded base subtree and sets
// NIAV_FLAG_APP_CULLED on every BSGeometry-derived leaf (BSTriShape,
// BSSITF, BSDynamicTriShape).
//
// Why: FO4 weapons aren't "base + mod patches", they're "all parts are
// mods, including a default receiver/barrel/grip etc.". When we load
// e.g. 10mmRecieverDummy.nif (which despite the name carries the
// stock-pistol geometry) and then attach the user-chosen mods on top
// (Pistol10mmReceiver, 10mmHeavyBarrel, …), the user sees the default
// geometry AND the chosen mods overlapping ("two pistols stacked"
// visual). Culling the base geometry leaves makes only the mods
// visible — i.e. the actual modded loadout the sender has.
//
// Returns the count of leaves culled (zero is fine — means the base
// was already empty / structural). Returns -1 if the peer has no
// active ghost weapon slot (call ghost_set_weapon first).
//
// Idempotent per-peer per-base — internally we set a `base_culled`
// flag on the slot after the first call so subsequent invocations
// during repeat equips of the same cached base don't re-walk into
// previously-attached mod subtrees (which would cull the mods'
// geometry too, the symptom that produced the "floating fragments
// after second equip" bug observed 2026-05-05).
//
// Threading: main thread only.
int cull_base_geometry_for_modded_weapon(const char* peer_id);

// === M9 closure (Phase 1, 2026-05-06) — OMOD-derived mod NIF paths ===
//
// The sender already ships the list of equipped OMOD form-ids in the
// EQUIP_BCAST tail (decoded at client.cpp ~L1063). Without them, the
// receiver was guessing mod NIF paths via bgsm-derive heuristics + 18
// fallback subfolder patterns — fragile (e.g. file basename `10mmReflexSight.nif`
// vs runtime m_name `10mmReflexDot` mismatch).
//
// With OMOD form-ids in hand, each one resolves DETERMINISTICALLY to
// its NIF file path via the engine: lookup_by_form_id(omod) → TESForm*
// (validated as OMOD by form-tag byte +0x1A == 0x90), then read
// TESModel.modelPath at OMOD +0x50 (BSFixedString handle pattern). This
// is the same path Bethesda's engine itself uses during runtime mod
// assembly — ground truth.
//
// We stash the per-peer OMOD list at EQUIP_BCAST decode time (net
// thread, via set_peer_omod_forms) and consume it in
// drain_mesh_blob_apply_queue (main thread).

// Stash the OMOD form-ids attached to peer_id's currently-equipped
// weapon. Called from net-thread EQUIP_BCAST decode after the wire
// tail is parsed. `forms` is a non-owning view; we copy into the
// internal storage. Pass form_count=0 to clear (UNEQUIP, peer
// disconnect, etc.). Threading: any thread.
void set_peer_omod_forms(const char* peer_id,
                          const std::uint32_t* forms,
                          std::uint8_t form_count);

// Resolve an OMOD form-id to the NIF file path stored in its
// TESModel.modelPath sub-object. Returns nullptr if the form isn't
// loaded, isn't an OMOD (form-tag byte +0x1A != 0x90), or has no
// modelPath. The returned pointer is stable for the form's lifetime
// (BSFixedString pool entry). Threading: main thread only (engine
// form lookup is main-thread-affine).
const char* resolve_omod_model_path(std::uint32_t omod_form_id);

// Snapshot the per-peer OMOD form-id list set by set_peer_omod_forms.
// Caller passes a buffer; receives the count actually copied (≤ buffer
// capacity, which is bounded internally to 32). Threading: any thread.
std::uint8_t snapshot_peer_omod_forms_public(const char* peer_id,
                                              std::uint32_t* out_buf,
                                              std::size_t out_cap);

// 2026-05-06 — diagnostic: dump the loaded ghost weapon subtree as
// indented [name + vtable RVA] lines. Used to discover empirically
// which placeholder NiNode names exist inside a base weapon NIF
// (10mmPistol.nif etc.) — those are the INNT names where mod NIFs
// should attach. We don't yet have a way to extract INNT from OMOD
// records (engine's serialization format is non-trivial), so this
// gives us ground truth from the loaded tree itself.
//
// `max_depth` caps the recursion (typical weapon NIFs are 3-5 deep).
// Threading: main thread only.
void dump_ghost_weapon_subtree(const char* peer_id, int max_depth);

// 2026-05-06 LATE evening — diagnostic dump of the WEAPON attach node
// state (what the engine actually sees, vs what our slot map says).
// Logs:
//   • parent chain from WEAPON UP to scene root
//   • full WEAPON subtree (DFS, vtable + name + parent + culled flag)
//   • global g_owned_clones tracker size
//   • per-peer slot summary
// Call at strategic moments (post-set-weapon, post-clear-weapon,
// post-mesh-blob-attach) to diff what's REALLY attached vs what we
// think is attached. `event_tag` is a free-form string included in
// every log line for grep-ability.
void dump_weapon_attach_state(const char* event_tag);

// 2026-05-05 — detach + refdec every cached mod node previously
// attached via attach_extra_node_to_ghost_weapon for `peer_id`.
//
// Called by drain_mesh_blob_apply_queue at the START of each equip's
// mod-attach loop, BEFORE the new attach pass. Without this, the
// cached BSFadeNode of the ghost weapon base (shared across equip
// cycles in the engine resmgr) accumulates child entries: each prior
// equip's mods stay attached, and on rendering they overlap with the
// current equip's mods → "weapon-soup" / "armi doppie" visual the
// user reported.
//
// Idempotent: calling on a peer with no extras is a no-op.
//
// Threading: main thread only.
void clear_ghost_extra_mods(const char* peer_id);

// === M9 closure (2026-05-07) — synthetic-REFR ghost weapon attach =========
//
// Bridges fw::native::synthetic_refr (which produces a fully-assembled,
// OMOD-applied BSFadeNode* asynchronously) to the existing ghost weapon
// machinery (g_ghost_weapon_slot, g_owned_clones, attach_child_direct).
//
// Caller passes (peer_id, weapon_form_id, omod_form_ids[]). We:
//   1. Schedule a synthetic_refr::assemble_modded_weapon_async call.
//   2. Inside the resulting callback (main thread, ~100-300ms later):
//      a. clear_ghost_extra_mods(peer_id) — release the previous equip
//      b. find ghost WEAPON bone via skin_rebind::get_bone_by_name
//      c. attach assembled_root as child of the bone
//      d. record in g_ghost_weapon_slot for next-equip cleanup
//
// Returns true if the assembly was scheduled. Returns false (and fires
// nothing) if synthetic_refr couldn't even queue the request. The
// caller can fall back to the legacy ghost_set_weapon path on false.
//
// Threading: MAIN THREAD ONLY. Schedules the assembly via the in-process
// poll worker; callback fires on main thread via WM_APP message.
bool ghost_attach_assembled_weapon(const char* peer_id,
                                     std::uint32_t weapon_form_id,
                                     const std::uint32_t* omod_form_ids,
                                     std::size_t num_omods);

// SPAI Tier 1 — force-prewarm a single NIF path into the engine's
// BSResource::EntryDB<BSModelDB> cache. Wraps the canonical load
// sequence (texture-resolver killswitch ON → nif_load_by_path with
// FADE_WRAP|POSTPROC → apply_materials → killswitch restore) so that
// the resulting BSFadeNode is fully shader/material-bound and shows up
// in resmgr lookups by m_name from then on.
//
// We do NOT attach the node to anything. The engine's resmgr holds its
// own ref, and the loader's out-pointer ref is intentionally dropped on
// the floor — we only want the side effect of "this NIF is now cached".
// Subsequent ghost equips can then resolve the node via
// find_loaded_nif_by_m_name and attach via attach_extra_node_to_ghost_weapon.
//
// Returns true on rc==0 + non-null node. False on resolver-not-ready,
// loader rc!=0, or null out-node. SEH-caged.
//
// Threading: MAIN THREAD ONLY (resolver init + apply_materials + scene
// graph internal allocator state are all main-thread-affine — same
// rationale as the body/head/equip load paths).
bool spai_force_load_path(const char* path);

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
