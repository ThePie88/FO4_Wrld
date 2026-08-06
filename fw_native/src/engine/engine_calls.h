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

// B6.3 v0.5.3: Apply a remote LOCK_BCAST on the local REFR.
//
// Resolves form_id via lookup_by_form_id, verifies (base_id, cell_id)
// match identity, then calls Papyrus binding sub_141158640 with
// ai_notify=0:
//
//   sub_141158640(0, 0, refr, locked ? 1 : 0, 0)
//
// The binding allocates ExtraLock if the REFR doesn't already have one,
// flips the LOCKED bit, clears partial-pick state, and triggers a visual
// refresh — without consuming a key, opening the lockpicking minigame, or
// firing AI events. Recurses internally into ForceUnlock/ForceLock; the
// caller MUST set tls_applying_remote before invoking so the recursive
// hook fire doesn't echo back as a fresh LOCK_OP.
//
// Returns true on apply, false if:
//   - lookup_by_form_id returned null (REFR not loaded yet)
//   - identity mismatch (wrong base or cell)
//   - SEH inside the engine call
bool apply_lock_op_to_engine(
    std::uint32_t lock_form_id,
    std::uint32_t expected_base_id,
    std::uint32_t expected_cell_id,
    bool          locked);

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

// === B6.5w3.b — NPC continuous-state apply ===============================
// Receiver-side application of one NPCStateEntry (per-NPC snapshot
// broadcast by the server brain at 10 Hz). Pipeline per call:
//   1. lookup_by_form_id(form_id) → local Actor* or null
//   2. SEH-caged write of pos at Actor+0xD0 and yaw at Actor+0xC0+8
//      (other rotation axes left untouched — body yaw is what matters
//      for visible facing direction)
//   3. // #STATE MINIMAL for now: anim_state → SetGraphVariable* writes
//      - 0 IDLE     : no-op (let vanilla idle animations play)
//      - 1 WALKING  : SpeedSampled=100.0 + Direction=0.0
//      - 2 RUNNING  : SpeedSampled=200.0 + Direction=0.0
//      - others (AIMING/FIRING/RELOADING/DEAD): not handled in w3.b,
//        layered in by B6.6 / B6.5w4 (suppression).
//
// `yaw_deg_math` is in degrees, math convention (0 = +X, CCW). We
// convert internally to Bethesda radians (0 = +Y, CW): beth_yaw_rad =
// (90 - yaw_deg_math) * pi/180.
//
// Returns true if Actor was resolved + at least the pos write succeeded;
// false if lookup_by_form_id returned null (most common — NPC's cell
// not loaded on this client) or the pos write SEH-faulted.
//
// MUST be called from the main thread WHEN `skip_anim_graph` is false.
// The anim graph setter recurses into the BSAnimationGraphManager
// smart-pointer fetch, which is rebuilt by scene-graph mutations on the
// main thread — net thread would race. Always dispatch via
// fw::dispatch::FW_MSG_NPC_STATE_APPLY for the full apply.
//
// `skip_anim_graph=true` makes the call thread-safe (pos/yaw writes are
// pure memory ops, no engine recursion). Used by the net-thread fallback
// path when PostMessage to the WndProc fails (e.g. HWND stale during
// game window recreation on cell transition / menu open). Loses anim
// state sync but preserves world-pos sync until the WndProc is healthy
// again — better than no sync at all.
bool apply_npc_state_to_engine(
    std::uint32_t form_id,
    float pos_x, float pos_y, float pos_z,
    float yaw_deg_math,
    std::uint8_t anim_state,
    bool skip_anim_graph = false);

// B6.5w4 round 2: same apply, but takes the Actor* directly (skips the
// lookup_by_form_id step). Used by the Update_PerFrame detour which
// already has Actor* from the function arg. Caller must be on main
// thread when skip_anim_graph=false (typical, since the detour runs on
// the engine main thread).
bool apply_npc_state_to_actor(
    void* actor,
    float pos_x, float pos_y, float pos_z,
    float yaw_deg_math,
    std::uint8_t anim_state,
    bool skip_anim_graph = false);

// B6.5w4 round 5: silence the actor's AI completely by clearing bit 2 of
// actor.flags_720 (+0x2D0). The ProcessLists tier walkers gate on this
// bit before calling Update_PerFrame, so this stops AI from running at
// all for the actor. Call ONCE per tracked NPC at registration; the
// engine side-effect (re-equip dispatch) is non-trivial — repeated calls
// are wasteful, not unsafe. SEH-caged. No-op if actor null or init not
// complete.
void set_actor_ai_enabled(void* actor, bool enabled);

// B6.5w4 round 7 — Atomic teleport silver bullet.
// Calls the engine's own `Actor::MoveTo` worker (RVA 0x00C60BE0) which
// atomically updates pos + NIF world + Havok body + anim graph + cell
// attachment. The 6-round fight is bypassed entirely — engine handles
// all caches itself. Call once per server tick (~10 Hz) per tracked
// NPC. Returns true on call success, false if actor null / init not
// ready / SEH fault.
//
// `yaw_rad` is in Bethesda convention (radians, 0 = +Y axis, CW).
// Caller is responsible for the math→bethesda conversion:
//   yaw_rad = (90.0f - yaw_deg_math) * PI / 180.0f
//
// MAIN THREAD ONLY. The teleport reads TLS, touches cell attachment,
// and walks NIF subtree — all main-thread-affine.
bool actor_atomic_teleport(void* actor,
                          float pos_x, float pos_y, float pos_z,
                          float yaw_rad);

// Build 65.c.44 — HANDOFF COMMIT teleport. Same Actor::MoveTo worker as
// actor_atomic_teleport but with doProcessUpdate=1 so the engine REATTACHES the
// AI-process + parent cell to the target pos (not just the visible Actor+0xD0 /
// NIF). This is what makes B's engine GROUND-TRUTH = the synced pos at an
// ownership handoff: the light doProcessUpdate=0 variant skips the reattach, so
// the AI ground-truth would stay at its diverged default and re-snap there.
// One-shot per handoff (MoveTo flushes the anim graph). MAIN THREAD ONLY.
bool actor_teleport_handoff(void* actor,
                            float pos_x, float pos_y, float pos_z,
                            float yaw_rad);

// One-shot per tracked NPC: set the actor's Havok motion type to
// Keyframed (=2). After this, Havok stops driving the body — our atomic
// teleport calls become the sole pos authority. Internally:
//   1. actor->Get3D() to find NIF root
//   2. sub_1418763E0(root, 2 /*Keyframed*/, 1, 0, 0)
// Idempotent. SEH-caged.
//
// MAIN THREAD ONLY.
bool set_actor_motion_keyframed(void* actor);

// Build 62.8 — Reverse of set_actor_motion_keyframed. Sets Havok motion
// type to Dynamic (=4) so the engine can integrate the rigid body normally.
// Required when a raider that was keyframed at cell-load time enters
// native combat tier via trigger_npc_perception and needs to move/path.
bool set_actor_motion_dynamic(void* actor);

// Build 65.c.47 — WEDGE3 death-sync. Kill an actor via the engine's own
// `Actor::Kill` worker (sub_140C612E0 @ RVA KILL_ENGINE_RVA). This is the
// SAME function our kill_hook detours; calling it here is how a NON-OWNER
// applies a relayed owner death so its mirror becomes a corpse (otherwise a
// live mirror of a dead-on-owner entity is shootable → the @0xC0F510
// use-after-free in form-record deserialization).
//
// Signature (decomp funcs_0301.md:6338):
//   _DWORD* __fastcall sub_140C612E0(victim, killer, float a3, char silent, char a5)
// killer=nullptr is fully supported by the engine (many vanilla call sites
// pass 0 — e.g. funcs_0299.md:11151, funcs_0287.md:6675): the body then uses
// the default killer id (dword_1430DA180) and still transitions to the death
// state + fires the engine's own death/ragdoll handler (sub_140C45EA0). For
// the MINIMAL build we pass killer=nullptr, a3=0, silent=1, a5=0 — no
// directional impulse, the corpse death-flops via the engine's handler.
//
// Caller MUST un-keyframe the body FIRST (set_actor_motion_dynamic) — a
// Keyframed Havok body cannot ragdoll. Caller MUST also wrap this in an
// fw::hooks::ApplyingRemoteGuard so kill_hook::detour_kill sees
// applying_remote()==true and does NOT re-report this relayed kill (echo
// loop). SEH-caged; no-op if actor null / init not ready / fn-ptr unresolved.
// MAIN THREAD ONLY (the death handler touches cell + anim + Havok state).
//
// Returns true on call success, false on null actor / not-ready / SEH.
bool kill_actor(void* victim, void* killer) noexcept;

// B6.5w12 hook #4: write `bAnimationDriven` graph variable on the actor's
// anim graph holder (= actor + 0x48). Setting to false prevents the anim
// graph's root motion from translating the actor — without this, running
// animations would still move the actor forward even though the movement
// integrator is bailed by hook #4. SEH-caged. Returns true on success.
//
// Cheap to call per-frame (idempotent: same value = no anim transition).
// MAIN THREAD ONLY (anim graph setter has internal locking).
bool set_actor_anim_driven(void* actor, bool value);

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
//
// DEPRECATED in B6.6w5: PlaceAtMe is a console/Papyrus shim that creates
// a generic Actor, not a real PlayerCharacter. Use spawn_ghost_player()
// instead — engine AI keys on PlayerCharacter identity (singleton +
// secondary @0x1431E2D50), and only spawn_ghost_player() produces an
// Actor that perception treats as another player. Kept compilable for
// any callsite that still references it; not wired into the active
// ghost path.
void* spawn_ghost_actor(std::uint32_t template_form_id);

// B6.6w5 — read the engine's "load in progress" flag at byte_1432D1FEA.
// Set to 1 by load_game_by_name before invoking the engine's LoadGame
// native, and cleared by the engine when the full load + cell-attach
// sequence completes. Used by the ghost spawn gate to defer the spawn
// until the engine is fully out of any load transition (the player
// singleton's parentCell can be transiently populated mid-load before
// the engine has finished setting up the world).
//
// Returns false if init didn't run or the pointer was null. true means
// a load is currently in progress; false means the engine is idle.
//
// WARNING (Build 65.c.28.1): this reads byte_1432D1FEA which our own B3.b
// auto-load sets to 1 at boot and never clears in the bypass path — so it
// can be STUCK TRUE for the whole session. Do NOT use it to gate per-frame
// NPC writes (it suppressed all sync in c.28). Use recently_teleported().
bool is_load_in_progress() noexcept;

// Build 65.c.28.1 — returns true while NPC engine writes must be suspended
// because the local player just crossed a cell boundary (teleport / coc /
// door / exterior stream). Watches the player's parentCell pointer; arms a
// ~1.5s window on any transition + always true while parentCell is null.
// Use this — NOT is_load_in_progress() — to gate apply_npc_pos / puppet-fire
// against the cell-hash deadlock that froze the main thread in c.25/c.27.
// Main-thread only.
bool recently_teleported() noexcept;

// B6.6w5 Build 7 — engine-native ghost via MEMCPY from local player
// (replaces both PlaceAtMe and the engine PC ctor approach).
//
// Builds 1-6 invoked the engine PlayerCharacter ctor `sub_140D52350` on a
// fresh alloc. Every build crashed because the ctor has hundreds of
// side-effects (event-sink registration, secondary-singleton clobber,
// AIProcess sub-buffer alloc, etc.) and the engine has 30+ "is this the
// player?" code paths that assume singleton-only PC. After 2 deep audits
// the side-effect set was still incomplete.
//
// Build 7 approach (user insight): instead of asking the engine to
// CONSTRUCT a fresh PC, MEMCPY the local player's existing 0xE10-byte
// struct into a fresh allocation. The local player has been fully
// initialized by the engine for minutes — every internal pointer is
// valid (AIProcess @+0x300, MovementController @+0x318, parentCell @+0xB8,
// NIF root, inventory list, anim graph holder, faction). The duplicate
// inherits VALID pointers (shared with real player). We patch only the
// fields that must differ:
//   - form_id at +0x14 → unique value (0xFF000001+)
//   - flags at +0x10 → OR in TEMPORARY (0x4000)
//
// Same pattern as the existing M8P3 bone-copy and M9 equipment-clone
// systems: "copy from the real player's working state". Proven approach
// extended to the actor struct itself.
//
// NO engine-side registrations are performed:
//   - NO event-sink registration (engine globals point to REAL_PLAYER's
//     sub-objects, not the duplicate's)
//   - NO ProcessLists registration
//   - NO cell-attach
//   - NO secondary singleton write
//
// The duplicate is a "phantom" — exists in memory ONLY as a target pointer
// our hooks pass to engine code. When a raider's combat_target is set to
// the duplicate, the engine reads duplicate.{pos, parentCell, vtable, ...}
// which are all valid (memcpy'd or post-patched).
//
// Shared-pointer caveats (managed by future hooks, not by this function):
//   1. duplicate.Get3D() returns REAL_PLAYER's NIF — aim resolution
//      requires a vtable[140] hook to redirect to body renderer ghost.
//   2. duplicate.AIProcess is shared — duplicate must never be made to
//      ATTACK (only be a target).
//   3. duplicate.inventory is shared — damage routing is server-mediated
//      via DAMAGE_SYNC (B.3), not engine.HandleHit on duplicate.
//
// Returns the duplicate PlayerCharacter Actor* on success, nullptr on
// any failure (init not ready, alloc fail, memcpy SEH, missing real
// player).
//
// Threading: MAIN THREAD ONLY. The memcpy reads the real player's live
// state; the actor must not be mid-update during the read.
//
// Convention: `ghost_form_id` should be in the 0xFF000000+ range
// (engine "transient" mod-index space) — see offsets::GHOST_FORMID_BASE.
// Currently the 2-peer MVP uses 0xFF000001 unconditionally; this will
// need per-peer uniqueness when scaling beyond 2 clients.
void* spawn_ghost_player(std::uint32_t ghost_form_id) noexcept;

// B6.6w5 Build 28 (2026-05-13 late night) — engine-native proxy spawn via
// PlaceAtMe. Replaces the memcpy-duplicate architecture entirely.
//
// Architecture decision: after 27 builds proved duplicate-as-memcpy
// crashes in 30+ engine subsystems, AGENT P1A+P1B audits identified
// the canonical Bethesda spawn path. PlaceAtMe (sub_141159C10 @ RVA
// 0x1159C10) runs the FULL Actor ctor, populates every sub-buffer with
// per-instance allocations, registers in handle table, and produces
// an Actor that the engine treats as a normal NPC. Zero aliasing with
// real_player's owned heap.
//
// Side-effect mitigation per Build 28 strategy:
//   * Temporary flag (refr+16 |= 0x4000) — skip save serialization.
//   * Handle and form-id are engine-assigned; we register the proxy
//     pointer under `ghost_form_id` in our client-side lookup so the
//     existing set_combat_target hook resolves server-sent
//     0xFF000001 → proxy_ptr unchanged.
//   * `Disabled` and `Ghost` flags NOT applied at first (we want the
//     raider's perception to detect the proxy so the engine drives
//     combat naturally). If raiders attack but also blow up the proxy
//     visually, add SetDisabled in a follow-up.
//
// Verified RVAs (decomp at D:\falloutworld_decomp\out\10_decomp\):
//   PlaceAtMe sub_141159C10 size 0x393 funcs_0401.md:1809
//   SetDisabled sub_140519410 size 0x41 funcs_0175.md:12328
//   SetGhost sub_140C5CE40 size 0xB6 funcs_0301.md:2959
//     -> AIProcess+0x58 + 44 |= 0x100000 (line 2997 verified)
//
// `base_form_id`: a TESNPC form to use as base. Default 0x0020593F
// (LCharWorkshopNPC) per AGENT P1B; any valid TESNPC works.
//
// Returns the spawned Actor* (= TESObjectREFR* in C terms) or nullptr.
// MUST be called from main thread (PlaceAtMe touches TLS at funcs_0137.md:6544).
void* spawn_ghost_proxy(std::uint32_t ghost_form_id,
                        std::uint32_t base_form_id) noexcept;

// Update the proxy's position. Calls engine's SetPosition (sub_140513A80).
// SEH-cased; safe-no-op if proxy is null. Main thread only.
void update_ghost_proxy_position(void* proxy, float x, float y, float z) noexcept;

// Update the proxy's rotation. Calls engine's SetRotation (sub_140513790).
// SEH-cased. Main thread only.
void update_ghost_proxy_rotation(void* proxy, float rx, float ry, float rz) noexcept;

// B6.6w5 Build 9 — client-side fid → duplicate-ptr registry.
//
// register_ghost_duplicate is called by spawn_ghost_player after the
// memcpy + vtable swap succeed. The pair (fid, ptr) is stored in an
// atomic registry. lookup_by_form_id() consults this registry BEFORE
// the engine form-table lookup — if `form_id` matches the registered
// fid, returns the duplicate ptr directly.
//
// Use case: ghost_ai_set_combat_target hook calls
// `lookup_by_form_id(server_broadcasted_combat_target_fid)`. When the
// server says raider X should aggro the OTHER peer (= the duplicate on
// this client), the server fills combat_target_form_id = 0xFF000001
// and our override resolves it to the duplicate ptr. The hook then
// passes that ptr to the engine SetCombatTarget, and the raider's
// AIProcess+0x6C ends up holding the duplicate as its combat target.
void register_ghost_duplicate(std::uint32_t fid, void* ptr) noexcept;

// Returns the currently-registered duplicate ptr, or nullptr if no
// ghost has been spawned yet. Atomic acquire-load. Safe from any thread.
void* get_ghost_duplicate() noexcept;

// B6.6w5 Build 23 — engine handle for the duplicate, allocated once at
// `spawn_ghost_player` time and cached. Returns 0 if spawn hasn't run
// or the allocator failed. Used by the set_combat_target hook to write
// directly to aiproc+0x6C without re-entering the engine handle
// allocator (which corrupts heap when given the memcpy'd duplicate per
// agent 8 of the 10-agent crash audit).
std::uint32_t get_ghost_duplicate_handle() noexcept;

// ============================================================================
// Build 56 (2026-05-23) — Option C: surgical ghost deregister from global
// form table.
//
// Source: re/option_C_deregister_ghost/AGENT_deregister_analysis.md
//         re/crash_death_vtable_cascade/AGENT_crash_analysis.md
//
// Architectural fix for the vtable-cascade crash family (vt[51] sub_140C06AC0,
// vt[197] sub_140CA85C0, sub_140E988A0 death-walker, etc.). Root cause:
// ghost duplicate/proxy is inserted into the global FormID→Form hash table
// at qword_1430DBF78[2506] (= MEMORY[0x1430E0DC8]) by the spawn path. From
// that moment ~25+ engine global walkers iterate the table and dispatch
// virtuals on every entry — when one reaches the ghost the incomplete
// sub-objects (or PlayerNPC special-case derefs) AV.
//
// Solution: after spawn, call the engine's own form-table erase primitive
// (sub_140315740) under the global BSReadWriteLock at MEMORY[0x1430E0E18]
// to atomically REMOVE the ghost from the table. The ghost ptr remains
// alive (held by our private g_ghost_duplicate_ptr map → lookup_by_form_id
// resolves it via the private path first), but no engine global walker
// can reach it anymore. Crash family collapses in one stroke.
//
// Pipeline (RVAs verified against decomp at D:\falloutworld_decomp):
//   1. Read ghost.fid at Actor+0x14 (SEH-caged). Reject 0 / 0xFFFFFFFF.
//   2. Ensure private map registration is intact (re-register if needed
//      so lookup_by_form_id keeps working post-erase).
//   3. Acquire write lock @ &qword_1430DBF78[2516] via sub_141659060.
//   4. Call sub_140315740(&qword_1430DBF78[2506], &ghost_fid, &out_form).
//      Returns u8 nonzero if the entry was found and erased.
//   5. Release write lock via sub_1416592C0.
//
// Idempotent: re-running on an already-erased ghost returns false but is
// safe (the erase primitive handles missing entries cleanly).
//
// Thread safety: SEH-caged across the full lock+erase+unlock window with
// guaranteed unlock on exception. Lock primitives are reentrant-safe
// per BSReadWriteLock semantics. Call from MAIN THREAD ONLY (the engine
// treats the form table as main-thread-affine for writes; reads from
// other threads are tolerated because we use a private path).
//
// Returns true if the ghost was actually present in the table and erased,
// false on any failure (init not ready, null ghost, fid invalid, fn-ptrs
// not resolved, SEH inside the lock window, or entry not found).
bool deregister_ghost_from_form_table(void* ghost_actor) noexcept;

// B6.6w5 Build 12 (Fix 1) — server-push combat target apply.
//
// Resolves the raider's AIProcess pointer (Actor+0x300) and calls the
// engine's AIProcess::SetCombatTarget directly with the resolved target.
// The MinHook detour on this engine function (ghost_ai_set_combat_target.cpp)
// will fire and do its substitution logic — if cache says
// combat_target_form_id == target_form_id, the substitution is a no-op
// and we end up with raider.combat_target = target.
//
// `target_form_id == 0` is allowed: the engine clears combat_target.
// Build 11's null-passthrough guard in the hook protects against the
// engine's v5[224] null deref on raw clear, BUT here we're calling
// SetCombatTarget with a non-null target (the looked-up actor) when
// target_form_id != 0. If target_form_id resolves to null (e.g. 0x14
// looked up but real player not yet in world), we passthrough.
//
// Returns true on engine call success, false on:
//   - actor null or actor.aiprocess null
//   - target_form_id resolves to null
//   - SEH in engine call
//
// MAIN THREAD ONLY. Engine SetCombatTarget reads TLS + global handle
// table; cross-thread calls would race.
bool apply_npc_combat_target(void* actor, std::uint32_t target_form_id) noexcept;

// B6.6w5 Build 9 — write peer's pos onto the duplicate.
//
// Direct field write to Actor+0xD0 (POS_OFF). No engine API call —
// the duplicate is invisible to engine subsystems (not in ProcessLists,
// not in cell list, not in scene graph), so the only consumer of
// duplicate.pos is the raider AI reading combat_target.pos for aim.
// That's a field read; we don't need pos-change broadcasts.
//
// Caller: POS_BROADCAST receive path on the net thread is FINE — no
// engine code paths read duplicate.pos concurrently with this write
// because the duplicate is not in any engine iteration. SEH-caged.
//
// Returns true on write, false if no duplicate registered or SEH-fault.
bool apply_ghost_pos(float x, float y, float z) noexcept;

// Ghost 1P fix (2026-08-04) — true iff the LOCAL player's camera is in
// FirstPersonState right now. In 1P the engine drives the 3P body tree to a
// V/T stub pose (M8P3.22 measurement), so the pose capture must HOLD instead
// of streaming garbage. Vtable compare against FirstPersonState (RTTI), SEH
// caged, fail-open: any unreadable step returns false so the stream behaves
// exactly as before this fix.
bool local_player_in_first_person() noexcept;

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

// B6.6w4 (REWRITTEN): server-driven fire trigger via WeaponFireHandler.
// Calls `sub_140DFF6B0(0, actor, nullptr)`:
//   - first arg `unused`: never deref'd in body (verified funcs_0325.md:9573).
//   - second arg `actor`: passed to internal slot resolver (sub_140CD0A60)
//     which walks equipManager — no dependency on fragile global slot id.
//   - third arg `anim_event_arg`: if null, takes the slot-resolver branch
//     instead of the atoi-string branch.
//
// Returns true on the success path inside WeaponFireHandler (it returns 1
// always at its tail; we treat true == "call completed without SEH").
//
// Thread safety: must be called from main thread. Caller responsible for
// marshalling.
bool fire_actor_weapon(void* actor) noexcept;

// ============================================================================
// PUPPET FIRE PHASE 1 (2026-05-17) — Scenario A recipe (raider already in
// natural combat, HighProcess + CombatAimController present).
//
// Source dossiers:
//   re/puppet_fire_phase1/AGENT_A_weapon_state_setter.md  (Worker A)
//   re/puppet_fire_phase1/AGENT_B_combat_aim_controller.md (Worker B)
//   re/puppet_fire_phase1/AGENT_C_aim_setter.md            (Worker C)
//   re/puppet_fire_phase1/SUPERVISOR_SYNTHESIS.md          (verified recipe)
//
// VERDICT: YELLOW. Works for Scenario A only. For Scenario B (raider
// without HighProcess — the 5 ghost-aggro Concord raiders in current
// production scenario), additional RE needed (see §8.6 verification
// agent output `B_AGENT_section_8_6_verify.md` for primary-AIProcess
// fallback path).
// ============================================================================

// Resolve a raider's CombatAimController for the firing slot.
//
// Walks `Actor+0x328 (HighProcess) → +0x98 BSTArray → entry where vtable
// matches CombatAimController class (RVA 0x2578C28) AND entry+0x30 low
// byte matches slot id`.
//
// Returns nullptr when:
//   - actor null
//   - Actor+0x328 NULL (raider not in combat tier — Scenario B)
//   - BSTArray empty / oversized
//   - no matching entry (no Stage-1 leaf has fired for this slot yet)
//
// Fully SEH-caged. Must be called from main thread (HighProcess
// dtor is main-thread only, serializes naturally).
void* resolve_actor_aim_controller_for_slot(void* actor,
                                            std::uint32_t slot) noexcept;

// Drive raider's weapon-state class via sub_140CD1830.
//
// Resolves slot internally via sub_140CD0A60 (slot resolver / equipment
// walker). For puppet-fire use `new_class = 15` (ready-to-fire).
// WeaponFireHandler will advance to 16/17 internally based on weapon
// flags.
//
// Does NOT require Actor+0x328 — safe on actors without HighProcess.
// Preconditions: Actor+0x300 (primary AIProcess) non-null AND a slot
// record exists for the resolved slot.
//
// Returns false on no-weapon-equipped, SEH, or fn-pointer-not-resolved.
bool set_actor_weapon_state_class(void* actor, int new_class) noexcept;

// Write aim target on a resolved CombatAimController.
// Calls sub_140E65820(aim_ctrl, &xyz). Writes:
//   aim_ctrl+0x18..+0x20 = (x, y, z)
//   aim_ctrl+0x34       |= 0x1   (valid-aim flag)
//   aim_ctrl+0x38        = g_game_time anchor
//   aim_ctrl+0x3C        = 0
//
// Returns false on null inputs or SEH.
bool aim_set_target(void* aim_controller,
                    float x, float y, float z) noexcept;

// Top-level puppet-fire orchestrator (Scenario A).
//
// Called from main-thread NPC_FIRE dispatch with the raider's local
// Actor* + the server-provided target position. Drives the 3-call
// recipe (weapon-state class + aim target + fire) to emit a visible
// projectile on this client.
//
// Returns true if WeaponFireHandler returned non-zero (= handler
// claimed success; does NOT guarantee Stage-4 actually emitted a
// projectile — Stage-4 has its own silencers).
//
// Tolerates the missing-AimController case (Scenario B): step 3 is
// skipped, step 4 still fires but produces no visible projectile in
// the current architecture. Diagnostic counters
// (`g_puppet_fire_aim_missing` etc.) signal this telemetry path.
bool fire_actor_at_target(void* raider_actor,
                          float target_x, float target_y, float target_z) noexcept;

// ============================================================================
// PUPPET FIRE PHASE 1.5 — Direct EnterCombat call (D agent verified).
// Source: re/puppet_fire_phase1/D_AGENT_enter_combat.md
//
// Calls sub_140CCF810(raider, ghost, NULL) directly to break the
// chicken-and-egg of "raider needs HighProcess to engage ghost but only
// gets HighProcess via natural perception which doesn't see cross-cell
// ghost".
//
// On success:
//   - raider.+0x328 (HighProcess) allocated (0x190 bytes)
//   - HighProcess+0x40 = CombatController allocated (0x128 bytes)
//   - controller.known_targets[] contains ghost
//   - controller.handles[] contains raider
//   - g_ghost_combat_controllers + g_ghost_engaged_raider_fids populated
//     (via internal call to install_fixed_selector_on_raider)
//   - ghost_combat_force alive-counter / post-pick / cell-loaded overrides
//     become live on the next per-frame tick
//   - Engine's combat brain ticks raider against ghost naturally
//
// 5 internal guards check raider state before the call:
//   1. raider primary aiproc (+0x300) non-null
//   2. raider+ghost baseForms valid (formType 0x2D/0x2E)
//   3. raider combat-disable bit (+0x208+0x1D8 bit 2) NOT SET
//   4. raider not frozen (+0x2D0 bit 0x800 NOT SET)
//   5. ghost.pos transient-snapped to raider.pos for distance gate
//
// Idempotent on existing combat tier — if raider+0x328 is already non-null,
// routes through install_fixed_selector_on_raider instead (AddCombatTarget
// path).
//
// Returns true if Actor+0x328 is non-null post-call. False on any guard
// rejection, SEH, or post-alloc verification failure.
//
// Thread safety: main thread only. Caller responsible.
// c.45 FIX 1a — `is_player=true` engages a REAL local player target: skips the
// ghost.pos pre-snap (never move the player) and the ghost-specific
// fixed-selector/AddAlly tail (the vanilla combat group forms naturally around a
// real target — and that tail carries the c.25/c.33 crash history). The core
// (guards + EnterCombat + post-alloc verify) runs for both.
bool enter_combat_raider_vs_ghost(void* raider_actor,
                                  void* ghost_actor,
                                  bool is_player = false) noexcept;

// ============================================================================
// Build 62 (2026-05-24) — Generic perception trigger wrapper.
//
// Per re/arena_synthesis/SUPERVISOR_SYNTHESIS.md: P-ALPHA wins. The
// canonical engine EnterCombat (sub_140CCF810) is the single function
// that needs to be invoked when server-side proximity sphere detects
// a peer's ghost has entered an NPC's perception range.
//
// This is a SEMANTIC ALIAS of enter_combat_raider_vs_ghost — same body,
// but the parameter names reflect the more general design: ANY observer
// NPC perceiving ANY target Actor (not just "raider vs ghost"). The
// underlying engine call accepts any (observer, target, NULL) tuple.
//
// Called from main_thread_dispatch::handle_npc_perception_trigger upon
// receipt of MSG_NPC_PERCEPTION_TRIGGER from server.
//
// MAIN THREAD ONLY. CombatController alloc reads TLS recursion counter.
//
// Returns true if observer+0x328 (HighProcess) is non-NULL post-call.
bool trigger_npc_perception(void* observer_actor,
                            void* target_actor) noexcept;

// ============================================================================
// Build 62 — Posture detection helpers.
//
// Per re/arena_synthesis/SUPERVISOR_SYNTHESIS.md §3: posture is encoded
// in Actor+0x134, bits 11-13 (mask 0x3800):
//   0x0000 = Stand
//   0x0800 = Sneak
//   0x1000 = Walk
//   0x1800 = Run
//   0x2000 = Sprint
//
// Triple-verified canonical writer: Papyrus IsSneaking native, combat
// orchestrator posture gate, Actor::SetSneaking. Flag is MASTER; anim
// graph variable iIsInSneak is downstream replica.
//
// Used by client to encode local player posture into POS_BROADCAST,
// which server reads to scale per-peer perception sphere radius
// (sneak shrinks sphere, sprint expands it).
// ============================================================================

// Returns true if the actor's movement state == sneak. SEH-safe.
bool is_actor_sneaking(const void* actor) noexcept;

// Returns posture as a 3-bit-encodable byte:
//   0 = Stand, 1 = Sneak, 2 = Walk, 3 = Run, 4 = Sprint.
// Suitable for packing into 3 bits of a POS_BROADCAST flag byte.
// SEH-safe; returns 0 (Stand) on null actor or unmapped read.
std::uint8_t read_actor_posture_byte(const void* actor) noexcept;

// Build 62 — accessor for local player Actor*. Reads
// g_player_singleton_slot which is set in init().
// Returns nullptr if singleton not bound yet or SEH fault.
void* get_local_player() noexcept;

// c.45-light — seed a raider's combat-target handle = `target` directly (no
// EnterCombat, no allocation). Writes AIProcess+0x6C (AIProcess = Actor+0x328).
// Returns false (no-op) if the raider has no HighProcess yet. SEH-caged.
bool seed_combat_target_handle(void* actor, void* target) noexcept;

// ============================================================================
// STRADA B.2 — Manual synthesis of HighProcess + CombatAimController.
// Source: re/strada_B2_synthesize_highprocess/SUPERVISOR_SYNTHESIS.md (1168
// lines, 4-agent RE arena 2026-05-22, aggregate confidence 85% YELLOW).
//
// Why this exists:
//   Build 45/47/50 live tests proved that sub_140CCF810 (EnterCombat) refuses
//   5/5 Concord raiders via the combat-disable gate at line 4549
//   (Actor+0x208+0x1D8 & 2 == 1 on raiders pre-aggro'd vs player_A). The
//   gate is EnterCombat-specific; the underlying allocation orchestrator
//   sub_140ED2390 has no such gate.
//
// Strategy: call sub_140ED2390 directly. It does the FULL alloc + ctor +
// AddAlly/AddTarget + wire Actor+0x328 in ~70 lines of engine code. Then we
// allocate 2 CombatAimController instances (slot variants, +0x30=slot and
// +0x30=slot|0x100 for wstate coverage) via sub_140E653D0, set the slot
// filter + valid flag, write target_pos via sub_140E65820.
//
// Required prior infrastructure:
//   - ghost_hostility_guard FORCE-HOSTILE (sub_140C8DFF0) — intercepts the
//     bilateral hostility check inside sub_140ED2390.
//   - ghost_combat_force surgical hooks — fire on success.
//   - ghost_ai_set_combat_target BYPASS-FROM-DUP — re-enable for safety on
//     the 2nd target transition (Build 22-26 cleanup-chain prevention).
//
// Returns true when BOTH (a) Actor+0x328 is non-null post-call AND (b) at
// least one CombatAimController was successfully constructed for the
// raider's weapon slot. False on any precondition failure or SEH.
//
// Thread safety: main thread only. Caller responsible for dispatch.
//
// Cost per call: ~880 bytes engine heap (HighProcess 0x190 + CombatController
// 0x128 + 2× CombatAimController 0x40 + 4 sub-objects inside HighProcess ctor).
bool synthesize_combat_extension_for_ghost_target(
    void* raider_actor,
    void* ghost_actor,
    float target_x, float target_y, float target_z) noexcept;

// Diagnostic counters for synthesize_combat_extension_for_ghost_target.
std::uint64_t get_synth_calls();
std::uint64_t get_synth_success();
std::uint64_t get_synth_seh();

// ============================================================================
// BUILD 54 — Visual aim alignment for puppet-fire.
//
// Rotates a raider to face a target world position and activates the
// "aiming gun" + "attacking" anim graph variables, so the weapon node's
// world forward direction (read by Stage-4 sub_140479680) points toward
// the target. Without this, raiders fire projectiles in their natural
// idle facing direction (user observation: "punti fissi ma diversi").
//
// Math: yaw = atan2(target.x - raider.x, target.y - raider.y).
// Pitch is not currently computed (deferred to a later refinement).
//
// Call once per NPC_FIRE event, immediately BEFORE fire_actor_at_target.
// Idempotent and cheap (~3 engine fn calls + 2 SEH-caged reads/writes).
//
// MAIN THREAD ONLY (SetGraphVariable* is not net-thread-safe).
//
// Returns true if rotation was applied; false on null inputs, missing fn
// pointers, or SEH during read/write.
bool aim_actor_at_target(void* raider_actor,
                         float target_x, float target_y, float target_z) noexcept;

// Build 55f — Lightweight 60Hz rotation override.
//
// Same as aim_actor_at_target but takes pre-computed yaw_rad (no math)
// and SKIPS the anim graph variable writes (bIsAimingGun, bIsAttacking).
// Designed for 60Hz invocation from npc_ai_suppress detour POST orig:
// reapplies the most recent puppet-fire yaw so vanilla AI's per-tick
// rotation writes don't override our 2Hz puppet-fire writes.
//
// Cheap: one engine SetRotation call + SEH cage. Anim graph state is
// already set by the upstream aim_actor_at_target (full version) at
// each NPC_FIRE event; we only need to re-write +0xC0 here.
//
// MAIN THREAD ONLY.
//
// Returns true on success.
bool aim_actor_at_target_rotation_only(void* raider_actor,
                                       float yaw_rad) noexcept;

// B6.6w4: engine-native movement-controller disable. REJECTED in live
// test — sub_140DC80B0 is a state-toggle (puts actor into scripted
// follow state, NOT clean disable). Kept here as defunct; do not call.
bool disable_actor_movement(void* actor) noexcept;

// B6.6w5: server-driven pos apply on receiver. Calls Actor::vt[202]
// (sub_140C60630) with a3=0 — the minimal-side-effect path:
//   1. sub_140513A80 writes Actor+0xD0/+0xD4/+0xD8 (leaf pos writer)
//      and emits actor->vt[13](2) cell-change broadcast.
//   2. actor->vt[140] (= Get3DRoot, sub_14050D990) returns NIF root NiNode.
//   3. If root != player.vt[139](1): writes pos into root+0x60/+0x64/+0x68.
//
// AVOIDS the a3=1 block which would identity-overwrite Havok controller
// rotation (frozen NPC's facing would reset every tick).
//
// Uses ApplyingRemoteGuard TLS pattern (same as container_hook) so our
// own ghost_ai_pos_belt / ghost_ai_actor_setpos detours passthrough
// when this is called from the receiver dispatch path.
//
// Must run on the main thread. Caller responsible for marshalling.
//
// Verified file:line: funcs_0301.md:5712 (vt[202] body),
// funcs_0175.md:7953 (sub_140513A80 body),
// re/B6.6w5_vt202_unknowns.md (a3=0 sufficiency proof).
bool apply_npc_pos(void* actor, float x, float y, float z) noexcept;

// Build 65.c.46 — DEADLOCK-SAFE pos pin for the non-owner keyframed mirror.
//
// `apply_npc_pos` goes through Actor::vt[202] (sub_140C60630) which calls
// sub_140513A80 → the cell spatial-grid remove/re-add pair
// (sub_140576030 / sub_140575E20). BOTH grab a single PROCESS-GLOBAL cell-grid
// spinlock (`qword_1430DBF78[135834]`, _InterlockedCompareExchange+Sleep-spin).
// If the streaming thread holds that lock mid-cell-load, vt[202] spins → the
// c.27/c.28 main-thread freeze. `recently_teleported()` exists to suspend
// vt[202] for exactly that window.
//
// This function is the SAFE alternative for use DURING that window: it does
// the render-relevant SUBSET of vt[202] as pure SEH-caged memory writes, with
// ZERO engine call → it can NEVER touch the cell-grid lock → can NEVER deadlock:
//   - Actor+0xD0/D4/D8   (logical pos; what vt[202]'s sub_140513A80 writes)
//   - NIF root +0x60     (local.translate; what vt[202] writes via v16[24..26])
//   - NIF root +0xA0     (world.translate; the value the renderer reads)
// On a non-owner the raider has no local combat target, its MovementController
// drives nothing, FinishPhysicsStep is bailed (ghost_ai_havok_step) and the
// Havok body is Keyframed (c.41b) → NOTHING fights these writes. The engine's
// render-phase NiAVObject::UpdateWorldData (independent of Update_PerFrame)
// re-derives child world matrices from the root, so the whole skeleton follows
// — same mechanism that already renders the raider between the 60 Hz vt[202]
// applies today. It does NOT update the cell spatial partition (irrelevant for
// a mirror; vt[202] re-fixes it the first frame after the guard releases).
//
// Main-thread only by convention (matches apply_npc_pos). SEH-caged; first
// 10 + every 100th logged.
bool apply_npc_pos_raw(void* actor, float x, float y, float z) noexcept;

// Build 66 — NATIVE char-controller proxy snap (the missing native-pos sync).
//
// apply_npc_pos / apply_npc_pos_raw pin only the VISIBLE pos (Actor+0xD0 + NIF).
// The AI-locomotion proxy (bhkCharacterController, a SEPARATE Havok object from
// the rigid body c.41b keyframes) keeps an independent NATIVE pos that the
// non-owner's AI advances → it diverges from the owner and surfaces on
// handoff/gap (the "walks in place / not at owner's spot" native divergence).
//
// This snaps the proxy to (x,y,z) world-units using the engine's OWN setter:
//   cc = sub_140C5C830(actor)  (pure accessor: AIProc@+0x300 → *(*(AIProc+8)+992))
//   sub_141894670(cc, {x,y,z}) (×0.0142875 units->meters, vtbl[+416](pos, warp=1))
// NO anim-graph flush, NO cell-grid spinlock — the lock-free counterpart of the
// engine's init snap sub_1418946E0(cc, actor+0xD0) (sub_140E0DAF0:2337).
//
// Caller passes the SAME world-units pos it pins to Actor+0xD0. SEH-caged,
// null-guarded (returns false if no AIProcess / no proxy). Main-thread only.
// CALLER MUST gate out during a cell-stream (the vtbl[+416] leaf body is
// unread — RE in progress — so we conservatively avoid it while streaming).
bool push_native_proxy_pos(void* actor, float x, float y, float z) noexcept;

// Build 68.1 — resolve a 32-bit ObjectRefHandle (e.g. the combat-target slot
// at Actor+0x380 — decomp-proven to be a HANDLE, not a form id) to the target
// actor's form id via the global handle table, with full active-bit +
// generation + actor cross-check validation. Returns 0 on null/stale/SEH.
std::uint32_t resolve_handle_to_formid(std::uint32_t handle) noexcept;

// Build 68.7 — MIRROR LOCOMOTION INPUT. Drives the mirror's own anim graph
// with the owner's relayed locomotion state (anim_state 0=IDLE 1=WALKING
// 2=RUNNING → SpeedSampled 0/100/200 + Direction 0) via the pre-minted
// BSFixedStrings and the engine's SetGraphVariableFloat. This is the fix for
// the "wooden log" mirrors: legs were ALWAYS animated by the mirror's local
// graph, and a graph needs a speed INPUT to play a walk — we translated the
// body while telling the graph "you are standing still".
//
// The setter machinery is the same one the deprecated c.19
// apply_npc_state_to_actor used; the c.21 crash was NOT the setter itself but
// calling it during a cell-stream (graph-holder smart-ptr mid-init). CALLER
// CONTRACT: main thread only, and NEVER while the teleport/stream guard is
// active (`suspended`) or the fid is dying. Returns false on missing
// prerequisites / SEH.
bool apply_npc_locomotion(void* actor, std::uint8_t anim_state) noexcept;

// ============================================================================
// B6.6w5 Build 29 — Engine-native CombatTargetSelectorFixed installation.
//
// Make a raider commit to `ghost_proxy` as its combat target THROUGH the
// engine's own promoter pipeline (sub_14087B080 @ RVA 0x87B080, called per-
// frame from Actor::vt[255] orchestrator). Replaces the 28-build whack-a-mole
// of writing aiproc+0x6C from a SetCombatTarget detour (which the promoter
// stomps every frame from CombatController.known_targets[]).
//
// Pipeline (all RVAs verified in `offsets.h` block "Build 29"):
//   1. Resolve raider.AIProcess (Actor+0x300) → raider.controller
//      (AIProcess+0x40).
//   2. Call `sub_140E91D70(controller, ghost_proxy)` — AddTarget. Inserts
//      a 208-byte record into `controller.known_targets[]`. Required
//      because the Fixed selector's vt[5] refresh validates the cached
//      target against this list (via sub_140E98250); if missing, sets
//      selector flag bit 1 → promoter skips → no promotion.
//   3. Allocate a 40-byte block via `sub_1416579C0(&unk_143E5E0F0, 0x28, 0, 0)`
//      — the engine's own NiHeap descriptor that vanilla
//      funcs_0358.md:4906 uses for its Fixed selector call.
//   4. Call `sub_140EE9780(block, aiproc, ghost_proxy, 3)` — the
//      CombatTargetSelectorFixed ctor with priority 3 (Standard=1,
//      Preferred=2). The ctor self-registers into `aiproc+0x100`
//      BSTArray. From the next promoter tick, our selector wins the
//      sort (priority DESC; comparator sub_140880A10 verified at
//      funcs_0240.md:11045).
//
// Idempotent within a process: a per-aiproc dedup set prevents double-
// installation (would leak a 40-byte block and add a redundant entry to
// aiproc+0x100).
//
// Caller responsibilities:
//   - `raider_actor` must be a real Actor* (NOT our ghost proxy).
//   - `ghost_proxy` must have Disabled flag CLEAR (bit 0x800 at +0x10);
//     otherwise sub_140E98250's (flags & 0x820)==0 check fails and the
//     selector remains disqualified each frame.
//   - Must be called from the main thread (the BSTArray at aiproc+0x100
//     is not thread-safe; the engine treats it as main-thread-only).
//
// Returns true on successful install (selector constructed + registered),
// false on any failure (null actor, AddTarget rejected, alloc failed,
// SEH faulted). Idempotent return: re-installing on an already-equipped
// aiproc returns true without doing anything.
//
// Live verification (post-deploy):
//   - log `[fixed-sel] installed raider=... ghost=... aiproc=... block=...`
//   - within ~16ms (1 frame), promoter should write ghost handle to
//     aiproc+0x6C natively. Cross-check by reading aiproc+0x6C from the
//     existing ghost_ai_combat_target hook (passthrough mode).
bool install_fixed_selector_on_raider(void* raider_actor, void* ghost_proxy) noexcept;

// Build 30 Fix 3 — Walks `controller+0x20 known_targets[]`, zeroes the
// 4-byte handle field of any entry whose resolved Actor* has invalid
// baseForm (= stale handle pointing to freed memory). Engine's resolve-
// or-skip logic then skips zeroed entries instead of crashing. Called
// internally by install_fixed_selector_on_raider before AddTarget, but
// exposed in case manual purge is needed elsewhere. Returns true on
// success (walk completed), false on SEH or invalid controller.
bool purge_stale_known_targets(void* controller) noexcept;

// Build 31 Phase 1 — Composite purge for one Actor's full stale-state.
//
// Resolves the actor's combat AIProcess (at Actor+0x328) and its
// CombatController (aiproc+0x40), then runs:
//   - purge_stale_known_targets(controller)  -- existing Fix 3
//   - selectors[] validation at aiproc+0x100 -- drops invalid heap ptrs
//   - raw Actor* cache zero at aiproc+0x178/+0x180 -- engine repopulates
//
// Designed to be called from `npc_ai_suppress::detour_actor_update_perframe`
// on each actor's FIRST tick post-LoadGame (D2 recommendation). Idempotent;
// re-running on a clean actor is a no-op walk. SEH-safe at every step.
// Main thread only.
//
// Returns true if at least one purge sub-step ran successfully.
bool purge_stale_actor_state(void* actor) noexcept;

// Reset the per-aiproc dedup set. Called on ghost despawn / DLL unload /
// LoadGame transitions so we re-install on the next ProcessLists pass.
void reset_fixed_selector_tracking() noexcept;

// Build 42 (2026-05-17) — query if a CombatController has been registered
// as engaged with our ghost (via install_fixed_selector_on_raider). The
// `ghost_combat_force` alive-counter detour uses this to decide whether
// to force-boost the controller+0x110 alive count.
//
// Background: sub_140E9E650 (the engine's alive-counter) iterates
// controller+0x20 (ally array, 24-byte stride) and counts entries whose
// resolved Actor has a non-NULL HighProcess (+0x328) with alive byte
// (+0x48 → +0x6C) == 0. Our tracked raiders' allies don't have
// allocated HighProcess (we keep them in low-process tier), so the
// count stays 0 → controller+0x110 = 0 → sub_140E988A0 dispatch gate
// (at funcs_0337.md:7135) skips entire combat block → raider idle.
//
// Adding ghost to known_targets[] via AddTarget doesn't help because
// alive-counter walks the OTHER array. We need to FORCE the alive
// count to >= 1 on controllers that should be engaged with the ghost.
bool is_ghost_combat_controller(void* controller) noexcept;

// Build 43 (2026-05-17) — query if a raider form_id has ever been
// engaged with the ghost (via install_fixed_selector_on_raider).
//
// Used by `should_silence_combat` in npc_ai_suppress to make
// fire/dispatch attack hooks NEVER bail for cross-peer-engaged
// raiders, even when the cache.combat_target_form_id oscillates
// to 0 between NPC_STATE_BCAST updates. Without this sticky flag,
// the raider's brain dies (fire/grenade/swing all BAILed) within
// seconds of cache flicker → state machine drops to idle.
bool is_ghost_engaged_raider_fid(std::uint32_t form_id) noexcept;

// Build 62.9 — query whether a raider is currently in NATIVE combat tier
// (= trigger_npc_perception SUCCESS path ran for this fid). Used by the
// 4 legacy motion-writer hooks (ghost_ai_havok_step, ghost_ai_movement,
// ghost_ai_pos_belt, ghost_ai_actor_setpos) to SKIP their freeze bail
// for raiders whose Havok body must be free to move under native combat
// AI. Without this gate, the puppet-fire era's movement_override=1 from
// raider_brain keeps re-freezing the body every Havok step.
//
// Returns false for fid==0 / fid==-1. Thread-safe (internal mutex).
bool native_combat_fid_exists(std::uint32_t form_id);

// ============================================================================
// Build 35 (2026-05-16) — ONE-HOOK BASEFORM SWAP API.
//
// The ghost is born with baseForm = PlayerNPC (formID 0x07). PlayerNPC is
// special-cased in 155+ engine functions ("is this the player?"); every
// one of those special-cases derefs sub-objects the ghost lacks → crash.
// We've been patching individual leaf paths (F2 IAGMH, F5 MagicTarget vt[4]
// immune, F9 AIProcess zeros, isPlayer bits) — each a single hole in a
// ship full of holes.
//
// The architectural cut: swap ghost->baseForm to a NON-PlayerNPC TESNPC
// at runtime. From that moment every `*(ghost+0xE0)` read returns a
// vanilla NPC pointer → no PlayerNPC special-case fires → entire crash
// taxonomy collapses.
//
// API:
//   try_acquire_safe_npc_base(candidate_actor)
//     Called from the per-frame walker for every non-ghost, non-player
//     actor. If the cache is empty AND the candidate has a valid
//     TESNPC baseForm (formType == 0x2D, formID != 0x07), atomically
//     install the candidate's baseForm pointer in the cache. Idempotent
//     and SEH-caged. Cheap on the hot path once the cache is filled
//     (single atomic-load early-out).
//
//   get_safe_npc_base()
//     Returns the cached pointer, or nullptr if not yet observed. Atomic
//     acquire-load, callable from any thread.
//
//   try_swap_ghost_baseform(ghost_actor)
//     If the ghost's current baseForm is PlayerNPC AND the cache holds
//     a valid non-PlayerNPC TESNPC pointer, overwrite ghost+0xE0 with
//     the cached pointer. Logs once per swap. Returns true on swap,
//     false on skip (no cache, or already swapped). SEH-caged. Main
//     thread only — called from the per-frame walker right after we
//     update the safe-base cache.
//
// Threading: the cache is a single `std::atomic<void*>` with seq-cst
// CAS install. The swap itself is a plain 8-byte qword write to
// ghost+0xE0 — atomic on x64. Race-free against engine readers: every
// engine reader does a single `mov rax, [actor+0xE0]` that's atomic
// w.r.t. our write.
// ============================================================================

void  try_acquire_safe_npc_base(void* candidate_actor) noexcept;
void* get_safe_npc_base() noexcept;
bool  try_swap_ghost_baseform(void* ghost_actor) noexcept;

// Build 38 (2026-05-16) — read PlayerCharacter's current parent_cell.
//
// Returns the live `TESObjectCELL*` from the local player REFR
// (player_singleton+0xB8). Returns nullptr if the singleton hasn't
// been bound yet OR if reading faults. Atomic-ish: PC.parent_cell
// is updated by the engine on cell transitions (teleports, fast-
// travel, exterior crossings) — we read a snapshot.
//
// Consumer: `cross_cell_gate` hook does TRANSIENT write
//     ghost+0xB8 = get_pc_parent_cell()
// for the duration of the `sub_140CF6100` call, restores on return.
// This satisfies the engine's PC.cell == target.cell gate without
// keeping the dangerous "ghost is in cell X" state visible to
// per-tick walkers that crash on PlayerNPC sublists.
void* get_pc_parent_cell() noexcept;

} // namespace fw::engine
