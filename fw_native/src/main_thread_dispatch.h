// B1.l main-thread dispatch queue for remote engine calls.
//
// Problem this solves: CONTAINER_BCAST (and future similar events) must
// mutate the local engine's inventory state on the MAIN thread, not the
// net thread. Prior to B1.l we called engine::apply_container_op_to_engine
// directly from the net thread dispatch — which corrupted player B's
// inventory when B had a ContainerMenu open while peer A spammed takes
// (main thread paused in menu, net thread writing behind its back →
// ContainerMenu's cached iterator state got out of sync → user clicks
// in menu remove wrong items from player inventory).
//
// Fix: net thread enqueues a "pending container op" POD and PostMessage's
// a custom WM_APP to the FO4 main window. The WndProc subclass (installed
// by main_menu_hook for B3.b LoadGame; shared with us here) catches the
// message on the main thread and drains the queue, calling
// apply_container_op_to_engine from a thread the engine trusts.
//
// This mirrors the pattern used for B3.b LoadGame (FW_MSG_LOAD_GAME =
// WM_APP + 0x42). Our message uses WM_APP + 0x43.
//
// Thread safety: enqueue/drain use a shared std::mutex. HWND is set once
// after WndProc subclass installs (see main_menu_hook.cpp's
// install_wndproc_subclass) and read lock-free after that.

#pragma once

#include <windows.h>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "net/protocol.h"  // M9 w4 v8: NifDescriptor for witness pattern

namespace fw::dispatch {

// WM_APP offsets (CORRECTED 2026-04-27 after collision bug;
//   re-corrected 2026-05-05 after second collision: SPAI_PREWARM was
//   originally 0x4E which already belonged to DEFERRED_MESH_TX. Symptom:
//   1257 prewarm messages got silently swallowed by the equip-hook
//   handler — no progress beacons, no DONE summary. Moved SPAI to 0x50.):
//   0x42 = FW_MSG_LOAD_GAME (B3.b)             — main_menu_hook.cpp
//   0x43 = FW_MSG_CONTAINER_APPLY (B1.l)       — owned here
//   0x44 = FW_MSG_SPAWN_GHOST                  — ghost/actor_hijack.h
//   0x45 = FW_MSG_STRADAB_INJECT               — native/scene_inject.h
//   0x46 = FW_MSG_STRADAB_POS_UPDATE           — native/scene_inject.h
//   0x47 = FW_MSG_STRADAB_BONE_TICK            — native/scene_inject.h
//   0x48 = FW_MSG_STRADAB_POSE_APPLY           — native/scene_inject.h
//   0x49 = FW_MSG_DOOR_APPLY (B6.1)            — owned here
//   0x4A = FW_MSG_FORCE_EQUIP_CYCLE_UNEQUIP    — hooks/equip_cycle.cpp
//   0x4B = FW_MSG_FORCE_EQUIP_CYCLE_EQUIP      — hooks/equip_cycle.cpp
//   0x4C = FW_MSG_EQUIP_APPLY (M9 wedge 2)     — owned here
//   0x4D = FW_MSG_MESH_BLOB_APPLY (M9 w4 v9)   — owned here
//   0x4E = FW_MSG_DEFERRED_MESH_TX (M9 w4 v9)  — hooks/equip_hook.h
//   0x4F = FW_MSG_WEAPON_CAPTURE_FINALIZE      — native/weapon_capture.h
//   0x50 = FW_MSG_SPAI_PREWARM (Tier 1)        — owned here
//   0x51 = FW_MSG_LOCK_APPLY (B6.3 v0.5.3)     — owned here
//   0x52 = FW_MSG_EQUIP_ANNOUNCE_FIRE          — hooks/equip_announce.cpp
//                                                (NON TESTATO 2026-05-08,
//                                                 not dispatched yet)
//
// PRE-FIX BUG (commit landed 2026-04-27 evening): DOOR_APPLY was set
// to 0x47 in the initial Phase 2 ship, colliding with STRADAB_BONE_TICK.
// Result: 20Hz pose-tx never fired (bone tick worker posted 0x47, our
// WndProc dispatched it as DOOR_APPLY → empty drain → on_bone_tick_message
// never called → ghost body stuck in T-pose for receivers). Fixed by
// moving DOOR_APPLY to 0x49.
constexpr UINT FW_MSG_CONTAINER_APPLY = WM_APP + 0x43;
constexpr UINT FW_MSG_DOOR_APPLY      = WM_APP + 0x49;
constexpr UINT FW_MSG_EQUIP_APPLY     = WM_APP + 0x4C;
constexpr UINT FW_MSG_MESH_BLOB_APPLY = WM_APP + 0x4D;  // M9 w4 v9
constexpr UINT FW_MSG_SPAI_PREWARM    = WM_APP + 0x50;  // SPAI Tier 1
constexpr UINT FW_MSG_LOCK_APPLY      = WM_APP + 0x51;  // B6.3 v0.5.3
constexpr UINT FW_MSG_NPC_STATE_APPLY = WM_APP + 0x53;  // B6.5w3.b
constexpr UINT FW_MSG_NPC_FIRE        = WM_APP + 0x54;  // B6.6w1 server-driven shoot
constexpr UINT FW_MSG_NPC_OWNER_STATE_APPLY = WM_APP + 0x55;  // Build 65.c.10 — owner-driven STATE_FROM_OWNER apply
constexpr UINT FW_MSG_NPC_DEATH_APPLY = WM_APP + 0x56;  // Build 65.c.47 WEDGE3 — owner-driven DEATH_FROM_OWNER apply
constexpr UINT FW_MSG_NPC_POOL_HEALTH_APPLY = WM_APP + 0x57;  // HP bar — set mirror Health = shared pool

struct PendingContainerOp {
    std::uint32_t kind;               // 1=TAKE, 2=PUT
    std::uint32_t container_form_id;  // sender's form_id (from v5 wire)
    std::uint32_t container_base_id;  // identity check component
    std::uint32_t container_cell_id;  // identity check component
    std::uint32_t item_base_id;       // what to add/remove
    std::int32_t  count;              // how many (>0)
};

struct PendingDoorOp {
    std::uint32_t door_form_id;   // sender's form_id (lookup_by_form_id)
    std::uint32_t door_base_id;   // identity check
    std::uint32_t door_cell_id;   // identity check
};

// B6.3 v0.5.3 — lock state apply.
// Receiver gets LOCK_BCAST(form_id, base_id, cell_id, locked), enqueues
// this struct, posts FW_MSG_LOCK_APPLY. Main thread drains and calls
// fw::engine::apply_lock_op_to_engine on each, under
// fw::hooks::ApplyingRemoteGuard so the recursive ForceUnlock/ForceLock
// fires in our own hooks don't echo back as a fresh LOCK_OP.
struct PendingLockOp {
    std::uint32_t lock_form_id;   // sender's form_id (lookup_by_form_id)
    std::uint32_t lock_base_id;   // identity check
    std::uint32_t lock_cell_id;   // identity check
    std::uint8_t  locked;         // 0 = unlocked, 1 = locked
};

// M9 wedge 2: armor visual sync.
// Receiver gets EQUIP_BCAST(item_form_id, kind), enqueues this struct,
// posts FW_MSG_EQUIP_APPLY. Main thread drains and either attaches the
// armor's 3rd-person NIF to the ghost (kind=EQUIP) or detaches+releases
// the previously attached NIF (kind=UNEQUIP). Per-peer attribution via
// peer_id (matches ghost lookup once multi-peer ghost lands; for now
// the SINGLE g_injected_cube ghost is used).
//
// item_form_id is plugin-stable (same form on both clients since they
// share the same Fallout4.esm). Receiver resolves via lookup_by_form_id
// and walks TESObjectARMO → TESObjectARMA → TESModel → BSFixedString
// path. See offsets.h "M9 wedge 2" comment block for layout.
struct PendingEquipOp {
    char           peer_id[16];   // null-terminated, ASCII (FixedClientId)
    std::uint32_t  item_form_id;
    std::uint8_t   kind;          // EquipOpKind (1=EQUIP, 2=UNEQUIP)
    std::uint32_t  slot_form_id;  // BGSEquipSlot.formID, 0 = auto
    std::int32_t   count;

    // M9 w2 PROPER (v10) — OMOD-modified ARMA priority. Sender extracts via
    // engine helper sub_140436820 from the equipped item's InstanceData+0x56
    // (or ARMO+0x2A6 default). Receiver feeds it to resolve_armor_nif_path's
    // PrioritySelect filter (RE'd from sub_1404626A0 = TESObjectARMO::
    // ForEachAddonInstance) so the right ARMA tier (Lite/Mid/Heavy) is
    // picked. 0 means "use default" (form has no OMOD or non-ARMO form).
    std::uint16_t  effective_priority;

    // M9 w4 v8 — witness NIF descriptors. Sender walked its own BipedAnim
    // post-equip; each descriptor names a mod .nif file the engine attached,
    // its parent node name, and the local transform. Receiver replays in
    // ghost_attach_weapon AFTER the base NIF is loaded and attached.
    // Empty (nif_count=0) means stock weapon — no extra mods to attach.
    std::uint8_t          nif_count;
    fw::net::NifDescriptor nif_descs[fw::net::MAX_NIF_DESCRIPTORS];

    // 2026-05-07 — OMOD form-ids INLINE. Each EQUIP_BCAST decode copies
    // the OMOD list directly into the op so the main-thread apply has
    // everything it needs without a global lookup. Capacity 32 mirrors
    // MAX_EQUIP_MODS protocol cap.
    std::uint8_t   omod_count;
    std::uint32_t  omod_form_ids[32];
};

// Net thread → enqueues op and posts FW_MSG_CONTAINER_APPLY to the FO4
// main window. If the HWND isn't set yet (subclass not installed at
// boot), the op stays queued; main_menu_hook flushes once it subclasses
// via set_target_hwnd(). Safe at any time; no-ops if dispatch_ready()
// returns false AND no handler is configured.
void enqueue_container_apply(const PendingContainerOp& op);

// Main thread (WndProc dispatcher) only. Drains all pending ops in one
// shot and calls fw::engine::apply_container_op_to_engine on each,
// under an fw::hooks::ApplyingRemoteGuard to suppress feedback from any
// internal vt[0x7A] re-entry.
void drain_container_apply_queue();

// B6.1: door apply queue — same pattern as container.
void enqueue_door_apply(const PendingDoorOp& op);
void drain_door_apply_queue();

// B6.3 v0.5.3: lock apply queue — same pattern as door.
void enqueue_lock_apply(const PendingLockOp& op);
void drain_lock_apply_queue();

// M9 wedge 2: equip apply queue — visual armor on ghost.
//   enqueue_equip_apply: net thread, after EQUIP_BCAST decode
//   drain_equip_apply_queue: main thread (WndProc dispatch),
//     resolves form_id → ARMO → ARMA → 3rd-person NIF path,
//     loads via nif_load_by_path, attaches to ghost via attach_child_direct
void enqueue_equip_apply(const PendingEquipOp& op);
void drain_equip_apply_queue();

// M9 wedge 4 v9 — raw mesh blob apply queue.
// Receiver decodes the reassembled MESH_BLOB_BCAST into a sequence of
// PendingMeshRecord (one per BSGeometry leaf the sender extracted), wraps
// them in a PendingMeshBlob, posts FW_MSG_MESH_BLOB_APPLY to the FO4 main
// window. Main thread drains and rebuilds each mesh on the matching peer's
// ghost weapon root via the engine's clone factory (sub_14182FFD0).
//
// All buffers are owned (std::vector / std::string) — net thread builds
// the struct from the decoded blob and the main thread reads it. Vectors
// move in / out of the queue; no shared mutable state across threads.
struct PendingMeshRecord {
    std::string                m_name;
    std::string                parent_placeholder;  // mod NIF root m_name (resmgr key)
    std::string                slot_name;            // slot placeholder name in base NIF
    std::string                bgsm_path;
    std::uint16_t              vert_count = 0;
    std::uint32_t              tri_count  = 0;
    float                      local_transform[16] = {};
    std::vector<float>         positions;   // 3 * vert_count floats
    std::vector<std::uint16_t> indices;     // 3 * tri_count u16s
};

struct PendingMeshBlob {
    char                          peer_id[16] = {};   // null-terminated, ASCII
    std::uint32_t                 item_form_id = 0;   // pairs with EQUIP_BCAST
    std::uint32_t                 equip_seq    = 0;   // sender's per-equip id
    std::vector<PendingMeshRecord> meshes;
    // 2026-05-06 (M9 closure, PLAN B) — when set (non-empty), this is a
    // raw NIF byte buffer from the engine's NiStream::Save. `meshes` is
    // ignored. Sender marks via num_meshes=0xFF in MeshBlobHeader.
    std::vector<std::uint8_t>     nif_blob_bytes;
};

void enqueue_mesh_blob_apply(PendingMeshBlob op);
void drain_mesh_blob_apply_queue();

// B6.5w3.b: NPC continuous-state apply queue.
// Net thread (client.cpp NPC_STATE_BCAST dispatch case) decodes one
// frame's worth of entries (≤ MAX_NPC_STATES_PER_FRAME = 26 typical),
// pushes a flat list, PostMessages FW_MSG_NPC_STATE_APPLY. Main thread
// drains all queued entries and applies each via
// fw::engine::apply_npc_state_to_engine — see engine_calls.h.
//
// Why flat queue (not batches): at 10 Hz × 2-10 NPCs the queue depth is
// tiny; batching adds complexity without measurable wins. Drain swaps
// the whole deque atomically so partial drains aren't a concern.
struct PendingNPCStateEntry {
    std::uint32_t form_id;
    float         pos_x;
    float         pos_y;
    float         pos_z;
    float         yaw_deg_math;   // math convention (0=+X, CCW), degrees
    std::uint8_t  anim_state;     // see AnimState enum (server/npc_brain.py)
    // B6.6w5 Build 12 (Fix 1) — server-push combat target apply.
    //
    // The MinHook detour on AIProcess::SetCombatTarget only fires when
    // the engine's LOCAL AI naturally tries to set a target. For raiders
    // tracked by server-authoritative brain (npc_ai_suppress hook silences
    // local AI), the engine never calls SetCombatTarget → our hook never
    // intercepts → server's combat_target decision never reaches engine.
    //
    // Fix: client receives NPC_STATE_BCAST with this field set per raider;
    // drain handler on main thread calls engine SetCombatTarget directly.
    // Set to 0 = no server opinion; drain skips combat-target apply for
    // this entry (pos/yaw/anim still applied as usual).
    std::uint32_t combat_target_form_id;
    // Build 12: flag to indicate which apply operations to perform.
    // Bit 0 (0x01) = apply pos/yaw/anim (gated by movement_override at
    //                enqueue time)
    // Bit 1 (0x02) = apply combat_target (gated by combat_target_form_id
    //                != 0 at enqueue time)
    std::uint8_t  apply_flags;
};

void enqueue_npc_state_apply(const std::vector<PendingNPCStateEntry>& entries);
void drain_npc_state_apply_queue();

// === Build 65.c.10 — Owner-driven NPC state apply (receiver-side) ========
//
// Net thread receives NPC_STATE_FROM_OWNER (server-relayed authoritative
// state from the NPC's elected owner peer), validates the entry list, and
// builds a flat queue of `PendingNPCOwnerState` records. PostMessage
// FW_MSG_NPC_OWNER_STATE_APPLY wakes the main thread, which drains the
// queue and writes pos to each tracked Actor via `engine::apply_npc_pos`.
//
// Scope (cautious): POS ONLY. Yaw/anim/aim/velocity capture from the
// owner is deferred to a later wedge — they require additional engine
// calls (SetGraphVariable, CombatAimController) that have not yet been
// verified to be safe to call from the receiver-side hot path. For
// MVP-A "raiders move on both screens" the pos write is sufficient.
//
// Skip rules at drain time:
//   - fid == 0 or 0xFFFFFFFF (sentinel)
//   - fid == 0x14 (the local PlayerCharacter — never overwritten)
//   - fid == ghost proxy (we never re-apply our own ghost actor)
//   - lookup_by_form_id returns null (actor not loaded locally)
//   - is_owner_of(fid) is true (we are the authority; do not self-apply)
//
// The apply call (`apply_npc_pos`) goes through `Actor::vt[202]` which
// is the same vanilla path used for engine teleports — already SEH-
// hardened in engine_calls.cpp and tagged with the TLS bypass flags
// our motion hooks use to passthrough on non-owner.
struct PendingNPCOwnerState {
    std::uint32_t form_id;
    std::uint32_t epoch;       // for diagnostic + late-stale rejection
    float         pos_x;
    float         pos_y;
    float         pos_z;
    // Build 65.c.14 — yaw apply alongside pos. Without yaw the non-owner
    // sees the actor at the correct position but facing whatever direction
    // the local engine last picked, which on a frozen actor stays at the
    // spawn-time yaw → looks like a statue regardless of pos accuracy.
    // `yaw_rad` is engine convention (radians, Actor+0xC0[2]).
    float         yaw_rad;
    // Build 65.c.18 — anim_state byte from owner. Bit 0 = InCombat. Drives
    // the receiver's anim-graph transition via apply_npc_state_to_actor
    // (SetGraphVariable bIsCombat / bIsAimingGun). Without this the
    // engine AI tick is bailed and anim driver stays in idle pose →
    // "raider come tronchi" symptom.
    std::uint8_t  anim_state;
};

void enqueue_npc_owner_state_apply(
    const std::vector<PendingNPCOwnerState>& entries);
void drain_npc_owner_state_apply_queue();

// Build 67 — MAIN-THREAD liveness heartbeat + stall watchdog.
//
// The 2026-06-11 fatal freeze left zero forensics: the main thread stopped
// draining (qsize 11→55) with no exception, no stack, no RIP — and the
// process was killed before the stall could be characterized. This is the
// fix: fw_wndproc calls note_main_thread_alive() on every message; the first
// call records the main thread id and spawns a watchdog thread. When the
// heartbeat goes stale >1.5s the watchdog SuspendThread's the main thread,
// reads RIP/RSP via GetThreadContext, scans the stack for game/DLL return
// addresses, resumes, then logs everything as RVAs ([mt-watchdog] lines).
// One capture per stall episode (re-arms when the heartbeat resumes), max 5
// per session. A captured stack ends any future where-did-it-hang debate.
void note_main_thread_alive() noexcept;

// Build 65.c.22 — InCombat-flag propagation cache for non-owner side.
//
// Diagnosi (Agent 2 forensics): pos+yaw apply 100% riuscito, MA bit 0x4000
// (Actor+0x2D0) cleared dall'engine perception walker su receiver ogni
// Update_PerFrame (60Hz, no enemy perceived locally → InCombat cleared).
// Drain setta il bit 10Hz → engine clear 60Hz → bit raramente set quando
// behavior tree legge → raider vede "patrol/idle" pose → user vede
// "animazioni come avrebbe contro client B" (= il locale engine sceglie
// idle anim invece di combat anim).
//
// Fix: drain aggiorna questa cache per ogni STATE_FROM_OWNER applicato.
// npc_ai_suppress detour legge DOPO orig (= dopo che engine ha cleared)
// e re-setta bit 0x4000 60Hz. Bit ora persiste tra orig consecutivi →
// behavior tree drives combat anims.
//
// Staleness: entry scaduta se più vecchia di 2s (= ~20 cicli drain mancati
// = owner offline / disconnesso / handoff).
//
// Returns true + writes *out se non-stale entry presente.
bool get_latest_owner_anim_state(std::uint32_t form_id,
                                  std::uint8_t* out_anim_state);

// Build 65.c.23 — Owner-state pair cache for 60Hz interpolation/
// extrapolation on the non-owner side.
//
// Drain (10Hz) updates prev = cur, cur = new entry on every
// STATE_FROM_OWNER arrival. The npc_ai_suppress detour (60Hz/actor) reads
// via `get_interpolated_owner_state` and linearly extrapolates from
// (prev, cur) to "now", producing a smooth visual instead of the 100 ms
// snap-teleport pattern Agent 1 forensics identified as the visible
// flicker source post-c.22.
//
// Extrapolation: t = (now - cur.ts) / (cur.ts - prev.ts). Capped at
// kMaxExtrapolation = 1.5 (50 % past current snapshot) to avoid runaway
// if owner stops emitting but state remains in the map.
//
// Yaw wrap-around: handled via shortest-arc π logic (see impl).
// Both pos and yaw use the same `t` factor (rotation/translation are
// usually correlated for combat AI).
//
// Threading: shared_mutex; hot path is 60 Hz × N tracked = small but
// concurrent across the 4 motion hooks. shared_lock for read, unique_lock
// for write (drain updates).
struct InterpolatedOwnerState {
    float pos_x;
    float pos_y;
    float pos_z;
    float yaw_rad;
    std::uint8_t anim_state;
};

// `now_ms` should be `GetTickCount64()`. Returns true + writes *out only
// when a non-stale (< 500 ms since cur) entry exists. Older than that
// means the owner has stopped or handed off; we yield to the engine.
bool get_interpolated_owner_state(std::uint32_t form_id,
                                   std::uint64_t now_ms,
                                   InterpolatedOwnerState* out);

// Build 65.c.30 — handoff smoothing (hold + short lerp on ownership handoff).
//
// Fixes the visible SNAP when a peer dies / releases NPC ownership: while B is
// the non-owner its visible pos is pinned to the owner's relayed pose, but B's
// engine sim diverges; on handoff the override stops and the engine's diverged
// pos jumps in. We blend FROM (last interp pose) → TO (B's engine pose) over
// HANDOFF_BLEND_MS instead of snapping. A FROM→TO gap larger than
// HANDOFF_BLEND_MAX_DIST is treated as a real teleport/cell-change (not blended).
// See re/reteleport_on_death_AGENT.md §5 (Option A). All calls are main-thread.
constexpr std::uint64_t HANDOFF_BLEND_MS       = 220;      // blend duration
constexpr float         HANDOFF_BLEND_MAX_DIST = 4096.0f;  // ~1 cell; cap

// Call every frame the fid IS non-owner-tracked, with the interp pose just
// applied. Records FROM + marks the fid so a later handoff arms the blend.
void note_non_owner_interp_pose(std::uint32_t form_id,
                                float x, float y, float z, float yaw_rad);

// Call every frame the fid is NOT non-owner-tracked, with B's current engine
// pose (TO). Returns true + writes the lerped pose into *out while a handoff
// blend is active; false otherwise (caller then leaves the engine pose as-is).
bool poll_handoff_blend(std::uint32_t form_id, std::uint64_t now_ms,
                        float eng_x, float eng_y, float eng_z, float eng_yaw,
                        InterpolatedOwnerState* out);

// Build 65.c.44 — handoff COMMIT (supersedes the c.30 visible-blend for the
// owner-driven raider case). On the FIRST frame after a non-owner period, writes
// the last-synced owner pose (FROM) into the out params and returns true ONCE,
// then consumes the entry. The caller actor_teleport_handoff()s B's ENGINE
// (AI-process + cell + Havok) to it, so B's ground-truth becomes the synced pos
// instead of its internally-diverged default → the raider stops respawning at
// its pre-aggro spot on handoff. Main-thread only.
bool consume_handoff_commit(std::uint32_t form_id,
                            float* out_x, float* out_y, float* out_z,
                            float* out_yaw);

// Build 65.c.24 — Recent-fire timestamp cache (per fid) used as Signal 3
// of the multi-signal anim_state aggregation on the owner side.
//
// Background (Judge B65_c23_JUDGE.md): bit 0x4000 at Actor+0x2D0 is a
// 1-tick mirror of CombatController+0x98, which IS volatile per-frame
// even on the owner — when the engine's perception walker decides "no
// hostile in LOS this frame", it clears both. The owner then captures
// anim_state=0 and that's what we send to non-owners.
//
// Fix part 1: capture anim_state POST orig call (see npc_ai_suppress.cpp)
// so we see the engine's MOST-RECENT verdict, not pre-tick state.
//
// Fix part 2: aggregate 3 signals via OR:
//   S1 = (Actor+0x2D0 & 0x4000) != 0                       (volatile mirror)
//   S2 = (CombatController+0x98) != 0                       (volatile upstream)
//   S3 = `recently_fired(fid, RECENT_FIRE_WINDOW_MS)`       (sticky 1500 ms)
//
// S3 fires whenever ghost_ai_fire's owner detour calls `mark_owner_actor_
// fired(fid)`. Even if S1/S2 are 0 in the capture frame (engine's combat
// brain temporarily lost target), S3 remains TRUE for the configured
// window — the raider just fired its weapon, it IS in combat. This bridges
// the per-frame oscillation that c.22 / c.23 failed to handle.
//
// Threading: shared_mutex; writer = ghost_ai_fire (main-thread detour),
// reader = npc_ai_suppress (main-thread detour). No cross-thread races.

constexpr std::uint64_t RECENT_FIRE_WINDOW_MS = 1500;

// Called from ghost_ai_fire.cpp when the owner-side detour observes a
// fire-decision succeed (= the engine is about to call the weapon-fire
// engine path). Stamps GetTickCount64() in g_recent_fire_ts[fid].
void mark_owner_actor_fired(std::uint32_t form_id);

// Returns true iff `form_id` was marked fired within `window_ms`.
// Reads g_recent_fire_ts under shared_lock; staleness via GetTickCount64().
bool recently_fired(std::uint32_t form_id, std::uint64_t window_ms);

// Fallback drain path: invoked from the net thread when PostMessage to
// the WndProc fails (HWND stale during game-window recreation, etc.).
// Skips the anim-graph setter calls (main-thread-only) and applies pos
// + yaw only. Loses animation sync until the WndProc subclass is
// re-installed by main_menu_hook on the new window, at which point full
// apply resumes via the normal drain_npc_state_apply_queue path.
void drain_npc_state_apply_queue_pos_only();

// B6.6w1 — server-driven fire trigger. Net thread receives NPC_FIRE and
// enqueues this. Main thread (WndProc on FW_MSG_NPC_FIRE) drains, looks
// up Actor* via lookup_by_form_id, and calls engine::fire_actor_weapon.
//
// Build 55a (proto v15, 2026-05-23) — adds target_kind:
//   0 (LOCAL) — recipient peer's local player IS the target; vanilla
//               engine AI fires at them naturally. Puppet-fire NO-OP.
//   1 (GHOST) — recipient peer's GHOST proxy represents the aggro target.
//               Puppet-fire path runs (aim_actor_at_target +
//               fire_actor_at_target). Vanilla fire on this raider is
//               BAILED via should_silence_combat while raider is in
//               g_ghost_targeted_raiders set, so vanilla AI doesn't
//               compete for Actor+0xC0 rotation.
struct PendingNPCFire {
    std::uint32_t raider_form_id;
    std::uint32_t target_form_id;   // informational; 0 = unknown
    std::uint32_t flags;            // reserved for burst-count / weapon-hint
    std::uint8_t  target_kind;      // 0=LOCAL, 1=GHOST (proto v15)
};
void enqueue_npc_fire(const PendingNPCFire& op);
void drain_npc_fire_queue();

// ============================================================================
// Build 65.c.47 — WEDGE3 owner-authoritative DEATH apply (receiver side).
//
// Net thread receives NPC_DEATH_FROM_OWNER (server-relayed from the NPC's
// owner, to NON-OWNERS only — main.py:1422), enqueues this POD, and
// PostMessages FW_MSG_NPC_DEATH_APPLY. The main thread (WndProc) drains and,
// per entry (all SEH-caged):
//   a. lookup_by_form_id(form_id) → Actor*; null → skip (mirror not loaded).
//   b. mark_dying(fid) — sticky so c.41b never re-keyframes the corpse.
//   c. dedup against a killed_fids set — a re-delivered death must not
//      double-kill (idempotent).
//   d. set_actor_motion_dynamic(actor) — un-keyframe so the body can ragdoll
//      (a Keyframed Havok body can't flop).
//   e. apply_npc_pos_raw(actor, pos) — place the corpse at the synced death
//      pos (deadlock-safe pure memory write; no engine cell-lock).
//   f. engine::kill_actor(actor, nullptr) inside an ApplyingRemoteGuard so
//      kill_hook::detour_kill does NOT re-report this relayed kill (echo).
//
// This is THE WEDGE3 fix: it guarantees a dead-on-owner entity is also a
// corpse on the non-owner, so there is never a "live mirror of a dead-on-
// owner entity" to shoot → no @0xC0F510 use-after-free.
//
// pos[3] = the owner's last-seen death position (NPCDeathFromOwnerPayload
// pos_x/y/z). ragdoll dir is unused in this MINIMAL build (no impulse).
struct PendingNPCDeath {
    std::uint32_t form_id;
    std::uint32_t killer_form_id;   // informational; kill is applied killer=null
    float         pos_x;
    float         pos_y;
    float         pos_z;
};
void enqueue_npc_death_apply(const PendingNPCDeath& op);
void drain_npc_death_apply_queue();

// HP bar (vita-locale-dal-pool) — set the NPC's LOCAL Health so the vanilla
// enemy-health bar reads the SHARED server pool. Net thread enqueues on each
// NPC_HP_POOL_BCAST (set_npc_pool_hp); main thread (WndProc) drains, resolves
// lookup_by_form_id, and calls engine apply_pool_health_to_actor. Tiny POD,
// event-driven (≈ per damage claim), main-thread-required (AVO call).
struct PendingNpcPoolHealth {
    std::uint32_t form_id;
    float         hp_cur;
    float         hp_max;
};
void enqueue_npc_pool_health(const PendingNpcPoolHealth& op);
void drain_npc_pool_health_queue();

// Build 62 (2026-05-24) — sphere-proximity perception trigger.
//
// Net thread enqueues; main thread drains. The handler invokes
// engine::trigger_npc_perception(observer, target) which calls
// sub_140CCF810 (Actor::EnterCombat) — engine then allocates
// HighProcess + CombatController + AddTarget natively in 1 frame.
//
// Replaces the synth/Tier1/Tier2/puppet-fire fragile pipeline.
// Per re/arena_synthesis/SUPERVISOR_SYNTHESIS.md.
struct PendingNPCPerceptionTrigger {
    std::uint32_t npc_fid;       // OBSERVER actor (NPC perceiving)
    std::uint32_t peer_id_hash;  // hash(peer_id_string); matches local
                                 // peer if hash(local_peer_id) == this
};
void enqueue_npc_perception_trigger(const PendingNPCPerceptionTrigger& op);
void drain_npc_perception_trigger_queue();

// Build 62 — register the LOCAL peer's ID string. Called once at PEER_HELLO_ACK
// receipt (when server confirms our peer_id). Internally FNV-1a-hashes it
// to 32 bits and stores in atomic. Used by drain_npc_perception_trigger_queue
// to decide if a server-side trigger targets us (= LOCAL PC) or the other
// peer (= GHOST duplicate).
//
// MUST match the server-side stable hash function (FNV-1a 32-bit on the
// raw peer_id string bytes).
void register_local_peer_id_hash(const char* peer_id_str) noexcept;

// Build 55a — per-raider ghost-target window tracker.
//
// Set by npc_fire_with_ghost_aim when target_kind=GHOST: marks the
// raider as "currently puppet-fire targeting ghost" with an expiry
// timestamp ~5 seconds in the future. ghost_ai_fire's should_silence_combat
// returns true while the raider is in the set, BAILing the vanilla
// engine fire path so it doesn't compete with our puppet-fire on the
// same rotation field.
//
// Thread-safe (mutex-guarded unordered_map). O(1) lookup by fid.
//
// Returns true iff the fid is currently in the ghost-targeted window.
bool is_raider_currently_ghost_targeted(std::uint32_t form_id);
// Internal use: called from npc_fire_with_ghost_aim. Public for tests.
void mark_raider_ghost_targeted(std::uint32_t form_id,
                                std::uint64_t expiry_ms);
// Diagnostic count of raiders currently in the ghost-target set.
std::size_t ghost_targeted_raiders_count();

// Build 55f — Per-raider rotation override map.
//
// Populated by aim_actor_at_target when it computes a yaw toward the
// ghost. Consumed by npc_ai_suppress's POST orig Update_PerFrame hook
// to re-apply the yaw every frame for raiders in the ghost-target
// window. This prevents vanilla AI's 60Hz rotation writes from beating
// our 1-2Hz puppet-fire rotation writes (the "laggy 2Hz" visual the
// user reported in Build 55e).
//
// Lifetime: same 5s expiry as ghost_targeted_raiders. When the window
// expires, no more rotation override → vanilla AI resumes naturally.
//
// Thread-safe (mutex-guarded). Returns true + writes *out_yaw_rad if
// the fid has a non-expired entry.
bool get_ghost_targeted_yaw(std::uint32_t form_id,
                            float* out_yaw_rad);
void mark_raider_ghost_targeted_yaw(std::uint32_t form_id,
                                    float yaw_rad,
                                    std::uint64_t expiry_ms);

// =========================================================================
// B6.5w4 round 2 — Per-NPC state cache (for in-detour POST-hook apply)
// =========================================================================
//
// Round 1 strategy was to BAIL out of Actor::Update_PerFrame for tracked
// form_ids. Numbers confirmed the hook fired correctly (~80 suppress
// fires/sec per actor) but visually NPCs froze mid-vanilla-state.
// Root cause: skipping Update_PerFrame also skips the engine's internal
// NIF-sync pass that propagates Actor+0xD0 → BSFadeNode.world.translate;
// our pos writes landed in memory but never reached the renderer.
//
// Round 2 strategy: let original Update_PerFrame run (so NIF sync, anim
// graph evaluation, collision all happen), then in the detour POST-call
// overwrite pos/yaw/anim from our cache. Our writes become the LAST of
// the frame → renderer sees them.
//
// The net thread updates the cache on every NPC_STATE_BCAST (10 Hz).
// The main-thread detour reads the cache on every Update_PerFrame fire
// (~60 Hz per tracked actor) and applies, so visible state advances at
// engine tick rate even though server only emits at 10 Hz (NPC freezes
// briefly between server samples; could add interpolation later).
//
// Thread safety: update + get share a std::mutex. Critical section is
// a single map operation; contention is negligible at this rate.

struct CachedNPCState {
    float          pos_x;
    float          pos_y;
    float          pos_z;
    float          yaw_deg_math;  // server brain emits in math conv (atan2 deg)
    std::uint8_t   anim_state;    // AnimState enum (server/npc_brain.py)
    std::uint64_t  last_update_ms;

    // B6.5w12 v14 — Ghost AI server-authoritative state.
    // Each field has a corresponding MinHook detour in hooks/ghost_ai_*.cpp
    // that reads from this cache (via get_cached_npc_state) and substitutes
    // the server's value for tracked NPCs. Zero = "server has no opinion;
    // pass through to vanilla AI logic".
    std::uint32_t  package_form_id;        // hook: TESPackage::EvaluateConditions
    std::uint32_t  combat_target_form_id;  // hook: SyncCombatTargetFromAIProcess
    float          velocity_x;             // hook: Actor::TickMovementController
    float          velocity_y;
    float          velocity_z;
    std::uint8_t   movement_override;      // 1 = bail movement (use server velocity);
                                           // 0 = vanilla movement
};

// Net thread (client.cpp NPC_STATE_BCAST handler): cache the latest server
// state for one NPC. Idempotent on repeats; just overwrites the entry.
//
// `package_form_id` (B6.5w12 v14): if non-zero, the Ghost AI predicate hook
// will force the engine to select this specific TESPackage for the actor
// (assuming the package is in the actor's candidate list). Zero leaves the
// vanilla AI selection untouched.
//
// `combat_target_form_id` (B6.5w12 v14): if non-zero, the Ghost AI combat-
// target hook will write this form_id into Actor+0x380 and force the
// InCombat flag, instead of letting AIProcess+0x6C drive it. Zero leaves
// the engine's natural combat-target tracking untouched.
//
// `velocity_x/y/z` (B6.5w12 v14): server's velocity vector for the actor.
// Consumed by the movement hook when `movement_override` is non-zero.
//
// `movement_override` (B6.5w12 v14): if non-zero, the movement hook
// BAILS the engine's TickMovementController for this actor — pos is
// expected to be driven elsewhere (server pos write or velocity-integration
// in the hook itself; current MVP uses BAIL + freeze for visual verify).
void update_npc_cache(std::uint32_t form_id,
                     float pos_x, float pos_y, float pos_z,
                     float yaw_deg_math,
                     std::uint8_t anim_state,
                     std::uint32_t package_form_id = 0,
                     std::uint32_t combat_target_form_id = 0,
                     float velocity_x = 0.0f,
                     float velocity_y = 0.0f,
                     float velocity_z = 0.0f,
                     std::uint8_t movement_override = 0);

// Main thread (suppression detour): fetch the latest cached state for
// one form_id. Returns true if present (= tracked); fills `*out` only on
// true. Pass nullptr `out` for presence-only check.
bool get_cached_npc_state(std::uint32_t form_id, CachedNPCState* out);

// Diagnostic: number of NPCs in the cache.
std::size_t tracked_npc_count();

// Snapshot of all cached NPC states. Used by the scene_render hook
// (B6.5w4 round 4) to iterate every tracked NPC and apply state
// late in the frame pipeline — after Havok physics, before render
// reads NIF.world.translate.
std::vector<std::pair<std::uint32_t, CachedNPCState>> get_all_cached_npcs();

// B6.5w4 round 9 — client-side interpolation.
//
// To kill the 10 Hz visual flicker (server BCAST cadence) we keep TWO
// snapshots per NPC: prev (older) and current (latest). Every render
// frame (~60 Hz) we linearly LERP between prev and current based on
// elapsed time since `current.last_update_ms`, producing a smooth
// per-frame pos for the renderer. Both clients run the same lerp on
// the same two endpoints → sync preserved, motion smooth.
//
// `now_ms` = local steady_clock millis (caller responsibility — the
// cache stores its own millis from the BCAST handler so both sides
// agree on time deltas, not absolute time).
//
// Returns false if no data for this form_id.
struct InterpolatedNPCState {
    float pos_x;
    float pos_y;
    float pos_z;
    float yaw_deg_math;
    std::uint8_t anim_state;
};

bool get_interpolated_npc_state(std::uint32_t form_id,
                               std::uint64_t now_ms,
                               InterpolatedNPCState* out);

// Wires the HWND of the main FO4 window. Called exactly once from
// main_menu_hook after SetWindowLongPtr succeeds. Also flushes any ops
// that accumulated before the HWND was known (sends one PostMessage so
// the main thread drains).
void set_target_hwnd(HWND hwnd);

// Diagnostic: how many ops currently pending. Returned under the lock
// for a point-in-time snapshot; no atomicity guarantee vs concurrent
// enqueues.
std::size_t pending_count();

// Expose the main window handle to other modules (e.g. ghost actor
// hijack) that need to PostMessage onto the main thread. Returns
// nullptr if set_target_hwnd hasn't been called yet.
HWND get_target_hwnd();

} // namespace fw::dispatch
