// FoM-lite network client. Owns:
//   - UDP socket to the Python server
//   - ReliableChannel (seq, retransmit, ACK)
//   - Worker thread running the main recv/send loop
//   - Thread-safe enqueue methods called from hook code
//
// Lifecycle:
//   client().start(cfg)   — spawn worker thread, connect + HELLO handshake
//   hook code calls client().enqueue_* (thread-safe)
//   client().stop()       — graceful DISCONNECT + join thread
//
// Singleton-by-convention. Access via `fw::net::client()`. Not thread-safe
// for start/stop (call from a single controller thread — dll_main's init).

#pragma once

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "../config.h"
#include "protocol.h"
#include "reliable.h"
#include "udp_socket.h"

namespace fw::net {

// Snapshot of the most recent remote-player pose received via POS_BROADCAST.
// Produced by the net worker thread, consumed by the render thread (body
// renderer). has_state=false until at least one POS_BROADCAST has landed.
//
// Rotation convention matches the local player singleton (rot[0]=pitch,
// rot[1]=roll, rot[2]=yaw, radians). Positions are FO4 world units.
struct RemotePlayerSnapshot {
    bool          has_state      = false;
    std::string   peer_id;                           // for logging
    float         pos[3]         = { 0.0f, 0.0f, 0.0f };
    float         rot[3]         = { 0.0f, 0.0f, 0.0f };
    std::uint64_t server_ts_ms   = 0;                // from payload
    std::uint64_t received_at_ms = 0;                // local GetTickCount64
    std::uint32_t cell_id        = 0;                // v11: peer's parentCell.formID (B6 prologue)
};

// M9.w4 v9 — POD shape for mesh blob serialization (decoupled from
// weapon_witness.h to keep the net layer dependency-free). Caller fills
// it from an ExtractedMesh and hands the array to enqueue_mesh_blob_for_equip.
//
// All buffers are non-owning views into caller-owned memory (the
// ExtractedMesh fields live inside std::vector / std::string in
// weapon_witness::ExtractedMesh, which stays alive for the duration of
// the enqueue call). The enqueue copies the bytes into the queue
// payload, so the caller can drop the source mesh data after return.
struct MeshBlobMesh {
    const char*           m_name;                // null-terminated, ≤255 chars
    const char*           parent_placeholder;    // null-terminated, ≤255 chars
    // Slot name in the base weapon NIF — i.e. m_name of the placeholder
    // NiNode that the mod root attaches to inside the base. May be null
    // or empty for stock weapons (no mod under this leaf) and pre-fix
    // sender DLLs (which left this field unpopulated; receiver falls back
    // to attaching at base root). 2026-05-05 fix.
    const char*           slot_name;             // null-terminated, ≤65535 chars
    const char*           bgsm_path;             // null-terminated, ≤65535 chars
    std::uint16_t         vert_count;
    std::uint32_t         tri_count;
    const float*          local_transform;       // 16 floats; nullptr → identity
    const float*          positions;             // 3*vert_count floats
    const std::uint16_t*  indices;               // 3*tri_count u16s
};

struct Stats {
    std::atomic<std::uint64_t> pos_sent{0};
    std::atomic<std::uint64_t> pos_broadcast_received{0};
    std::atomic<std::uint64_t> kills_sent{0};
    std::atomic<std::uint64_t> kills_broadcast_received{0};
    std::atomic<std::uint64_t> container_ops_sent{0};
    std::atomic<std::uint64_t> container_ops_received{0};
    std::atomic<std::uint64_t> reliable_sent{0};
    std::atomic<std::uint64_t> reliable_received{0};
    std::atomic<std::uint64_t> heartbeats_sent{0};
    std::atomic<std::uint64_t> world_state_entries{0};
    std::atomic<std::uint64_t> container_state_entries{0};
};

class Client {
public:
    Client();
    ~Client();

    Client(const Client&) = delete;
    Client& operator=(const Client&) = delete;

    bool start(const config::Settings& cfg);
    void stop();

    // THE GOODBYE, sent AT ONCE on the caller's thread.
    //
    // Not an enqueue like everything else, because when it is needed the
    // process is dying: the window received WM_CLOSE, the player pressed
    // ALT+F4, and the network thread may never run again. A queue here would
    // be drained by nobody.
    //
    // Without it a peer's exit is discovered only by the server's timeout:
    // five seconds in which its ghost stands there lying, and its power
    // armor stays "worn" so it does not return to the world. The server
    // already handles DISCONNECT with the full teardown: it releases the
    // NPCs, re-announces the frame at the last position and sends PEER_LEAVE
    // to the others. All that was missing was someone telling it.
    //
    // Sent NOT reliable and repeated a few times, because a reliable frame
    // would want retransmissions from a thread about to vanish. Losing it is
    // no drama: it falls back on the timeout, which is how it worked before.
    // Idempotent: calling it twice sends two goodbyes and the second finds
    // the session already closed.
    //
    // Any thread, in practice the window's thread.
    void send_goodbye_now(std::uint8_t reason = 0);

    bool is_connected() const noexcept { return connected_.load(); }
    bool is_dead()      const noexcept { return dead_.load(); }
    std::uint32_t session_id() const noexcept { return session_id_.load(); }

    // --- thread-safe enqueue entry points for hook modules ---

    // Unreliable. Caller fills the struct; we take ownership.
    void enqueue_pos_state(const PosStatePayload& p);

    // M8P3.15 — variable-length pose snapshot (per-bone quaternions).
    // header_ts_ms = client wall clock; bones[] = 0..MAX_POSE_BONES quaternions
    // in deterministic name-sorted order (matches receiver's walk).
    // Unreliable. Drops if disconnected or queue saturated.
    void enqueue_pose_state(std::uint64_t header_ts_ms,
                            const PoseBoneEntry* bones,
                            std::size_t bone_count);

    // v16 — ghost crouch. SEPARATE additive channel beside enqueue_pose_state:
    // carries the vertical COM/Pelvis local translations (PoseCrouchEntry,
    // keyed by canonical bone index). Server fans out as POSE_CROUCH_BROADCAST.
    // Unreliable. Drops if disconnected or queue saturated.
    void enqueue_pose_crouch_state(const PoseCrouchEntry* entries,
                                   std::size_t count,
                                   std::uint64_t header_ts_ms);

    // c.37.0 — per-bone rotation snapshot for ONE owned NPC, keyed by
    // form_id. Same quaternion format as enqueue_pose_state; the server
    // validates ownership and fans NPC_POSE_FROM_OWNER out to non-owners,
    // who drive their mirror copy of this NPC. Unreliable.
    void enqueue_npc_pose_state(std::uint32_t form_id,
                                std::uint64_t header_ts_ms,
                                const PoseBoneEntry* bones,
                                std::size_t bone_count);

    // NPC crouch — COM/Pelvis LOCAL TRANSLATION snapshot for ONE owned NPC,
    // keyed by form_id. The NPC analogue of enqueue_pose_crouch_state; same
    // PoseCrouchEntry payload (keyed by canonical bone index), prefixed with
    // form_id. The server validates ownership and fans NPC_CROUCH_FROM_OWNER
    // out to non-owners, who lower their mirror copy of this NPC. Unreliable.
    void enqueue_npc_crouch(std::uint32_t form_id,
                            const PoseCrouchEntry* entries,
                            std::size_t count,
                            std::uint64_t header_ts_ms);

    // c.39b — report that the local player dealt `amount` damage to NPC
    // `form_id`. Accumulates per fid and self-throttles to ~6 Hz/fid (sends
    // the batched amount), so rapid-fire weapons don't flood. Unreliable.
    void enqueue_npc_damage_claim(std::uint32_t form_id, float amount,
                                  float max_hp = 0.0f);  // N3: max_hp for the shared HP pool

    // Reliable.
    void enqueue_actor_event(const ActorEventPayload& a);

    // Loot rework L2 (2026-09-23): the engine has ALREADY moved the items
    // when this is called. Stamps op.client_op_id, remembers the op until
    // its CONTAINER_OP_ACK, queues it reliable. Never waits: the verdict
    // arrives on the network thread, and a refusal is undone on the main
    // thread through the dispatch queue (a PendingContainerOp flagged
    // rollback). An op still without a verdict when the session drops is
    // sent again after the next WELCOME; the server answers a repeat with
    // the verdict it stored. Returns the op id, 0 when the client is
    // shutting down and nothing was queued.
    std::uint32_t submit_container_op(ContainerOpPayload op);

    // --- loot rework L3 (2026-09-24): the engine follows the server ---
    // True when the server's view of this container is held here (the
    // bootstrap or a live push carried it). ANY THREAD.
    bool container_known(std::uint32_t form_id);
    // Loot rework L4.1 (2026-09-25): a death makes a new corpse with a new
    // loot roll, so the mirror entry and the seed mark of that actor are
    // dropped and the first take seeds the new corpse. Called on the net
    // thread when a death message without the replay flag arrives (before
    // any later CONTAINER_STATE is read, so a fresh record is never dropped
    // by an older death) and on the main thread by the local kill hook.
    void forget_container(std::uint32_t form_id);
    // Whether a seed for this container left in this session with no push
    // answering it yet; with `mark`, records that one just did. ANY THREAD.
    bool seed_in_flight(std::uint32_t form_id, bool mark);
    // Align the local container to the server's view: nothing when the
    // view is not held, deferred when one of our own ops on it still waits
    // for its verdict (the ACK queues the alignment again). True when the
    // REFR was found and is now aligned (or already was). MAIN THREAD
    // ONLY: engine inventory calls, under ApplyingRemoteGuard.
    bool reconverge_container(std::uint32_t form_id);

    // Loot rework L3.3 (2026-09-24): the save is the world's definition and
    // the server its history. Every launch reloads the save, so a container
    // the server knows emptied is full again in the engine until something
    // aligns it; the join bootstrap runs before the world is loaded ("not
    // loaded, nothing to align") and the activation runs at the menu, where
    // the items were seen to vanish on both clients, with the quick-loot HUD
    // showing the save's contents until then. This tick, from the main-thread
    // heartbeat, aligns every known container once the scene has settled and
    // again at every change of the player's cell, so what the HUD shows is
    // the server's before anyone opens anything. MAIN THREAD.
    void container_sweep_tick();

    // Reliable CONTAINER_SEED — chunked. entries will be split across frames
    // if > MAX entries per chunk. No ACK correlation (fire-and-forget).
    void enqueue_container_seed(std::uint32_t form_id,
                                std::uint32_t base_id, std::uint32_t cell_id,
                                const ContainerStateEntry* entries,
                                std::size_t num_entries);

    // B4.d: reliable GLOBAL_VAR_SET — fire-and-forget. Server broadcasts to
    // other peers; sender applies optimistically via the engine hook itself.
    void enqueue_global_var_set(std::uint32_t global_form_id, double value);

    // v20 — APPEARANCE_SET. `recipe` is the appearance recipe LINE
    // (appearance_recipe::to_line): ASCII, ~150 bytes, engine form ids only.
    // Sent reliably; the server stores it against this peer's identity and
    // relays it, and re-sending an unchanged recipe is a server-side no-op,
    // so a caller may send on every join without spamming the session.
    void enqueue_appearance_set(const std::string& recipe);

    // B6.1: reliable DOOR_OP — fire-and-forget. Server broadcasts to other
    // peers as DOOR_BCAST. Toggle semantics — the receiver re-invokes its
    // local Activate worker on the matching REFR; both sides converge as
    // long as they started from the same world_base save.
    void enqueue_door_op(std::uint32_t door_form_id,
                         std::uint32_t door_base_id,
                         std::uint32_t door_cell_id,
                         std::uint64_t timestamp_ms);

    // B6.3 v0.5.3: reliable LOCK_OP — sender broadcasts when ForceUnlock
    // / ForceLock fires for a REFR. `locked` carries the new state
    // (0 = unlocked, 1 = locked). Identity (form_id, base_id, cell_id)
    // lets the receiver look up its local REFR and validate before
    // applying via Papyrus binding sub_141158640.
    void enqueue_lock_op(std::uint32_t lock_form_id,
                         std::uint32_t lock_base_id,
                         std::uint32_t lock_cell_id,
                         bool          locked,
                         std::uint64_t timestamp_ms);

    // B6.14 v22 - report a REFR this client just created in its world.
    // pos/rot are 3-float arrays; flags bit0 = transient.
    // v23: pieces = the frame's inventory at announce time (null/0 for
    // everything that is not a PA frame).
    void enqueue_world_spawn_op(std::uint32_t base_form_id,
                                std::uint32_t local_form_id,
                                const float pos[3], const float rot[3],
                                std::uint32_t cell_id, std::uint8_t flags,
                                std::uint64_t timestamp_ms,
                                const PaPieceEntry* pieces = nullptr,
                                std::uint8_t piece_n = 0);

    // v23 - full piece list for a bound wid after a manual take/put on a
    // PA frame (fire-and-forget; the server ledger replaces and rebroadcasts).
    void enqueue_world_pa_pieces_op(std::uint32_t wid,
                                    const PaPieceEntry* pieces,
                                    std::uint8_t piece_n,
                                    std::uint64_t timestamp_ms);

    // B6.14 v22 - report that spawned object `wid` died in this world.
    void enqueue_world_despawn_op(std::uint32_t wid, std::uint8_t reason,
                                  std::uint64_t timestamp_ms);

    // B6.6w2: reliable NPC_DISCOVER — sender emits when its
    // npc_ai_suppress detour first auto-tracks a hostile NPC (vanilla
    // AI set the InCombat flag bit 0x4000 at Actor+0x2D0). Server
    // dynamically registers the actor into raider_brain so combat
    // sync covers raiders not present in the waypoint JSON seed.
    // Idempotent server-side (duplicates ignored), but reliable to
    // avoid the case where a single dropped packet means the server
    // never knows this raider exists.
    void enqueue_npc_discover(std::uint32_t form_id,
                              std::uint32_t base_id,
                              std::uint32_t cell_id,
                              float pos_x, float pos_y, float pos_z);

    // B6.6w5: reliable PEER_GHOST_REGISTER — sender emits after its
    // local ghost-actor (the engine REFR that represents the other
    // peer on its screen) has been spawned. The form_id is dynamic
    // per-client (engine-allocated at PlaceAtMe time). Server stores
    // and uses in project_for_peer so the raider's combat target
    // points at the correct local actor on each viewer.
    void enqueue_peer_ghost_register(std::uint32_t ghost_form_id);

    // Build 65 — owner-driven NPC sync (Solver 2) TX entry points.
    //
    // NPC_OBSERVED (reliable): the suppression detour saw a new NPC and
    // tells the server about it. Server's OwnershipRegistry elects an
    // owner (cell-first + closeness + 3s stickiness). Deduplication is
    // the caller's responsibility — `ownership_manager::notify_observation`
    // wraps this with a per-(fid) once-per-session filter.
    void enqueue_npc_observed(std::uint32_t form_id,
                              std::uint32_t base_id,
                              std::uint32_t cell_id,
                              float pos_x, float pos_y, float pos_z,
                              float observer_distance_sq);

    // NPC_OWNER_HEARTBEAT (unreliable, batched). Periodically (~2 Hz)
    // proves to the server that we still own + know the current epoch
    // of every NPC in our owned set. Server's health-gate releases any
    // owner stale > 2.5s.
    void enqueue_npc_owner_heartbeat(const NPCOwnerHeartbeatEntry* entries,
                                     std::size_t count);

    // NPC_UNLOAD (reliable). Owner voluntarily releases one NPC — the
    // server frees the record (epoch-checked) and broadcasts the change so
    // other peers can re-claim on their next observe. Build 69q
    // (2026-08-04): used at local player DEATH to despawn the ownership
    // sphere explicitly instead of leaking it to the 8s heartbeat timeout
    // (the "raiders turn to B only when the body despawns" lag).
    void enqueue_npc_unload(const NPCUnloadPayload& p);

    // NPC_STATE_FROM_OWNER (unreliable, batched). Periodically (~10 Hz)
    // owner emits authoritative state for its owned NPCs. Server
    // validates ownership + epoch then relays to non-owners. Each entry
    // carries pos/yaw/anim/aim/velocity in 76 B (see protocol.h).
    void enqueue_npc_state_from_owner(const NPCOwnerStateEntry* entries,
                                      std::size_t count);

    // NPC_FIRE_FROM_OWNER (unreliable, event-driven). Build 65.c.16 —
    // owner-side GunFire DecideAndFire detour calls this when the engine
    // decides to fire for an NPC we own. Server validates ownership
    // and relays to non-owner peers, who replay via
    // engine::fire_actor_weapon (projectile + muzzle flash + audio).
    void enqueue_npc_fire_from_owner(const NPCFireFromOwnerPayload& p);

    // NPC_DEATH_FROM_OWNER (RELIABLE, event-driven). Build 65.c.47 WEDGE3 —
    // owner-side kill_hook::detour_kill calls this when the engine kills an
    // NPC we own. Server validates ownership and relays to NON-OWNER peers
    // (main.py:1422), who corpse their mirror via engine::kill_actor. Reliable
    // because a dropped death = a permanent live-mirror-of-a-dead-entity = the
    // @0xC0F510 use-after-free when that mirror is shot. This is THE fix.
    void enqueue_npc_death_from_owner(const NPCDeathFromOwnerPayload& p);

    // NPC_ENGAGEMENT_CLAIM (unreliable, ~1 Hz max per fid). Build 65.c.23 —
    // npc_ai_suppress detour calls this when LOCAL engine has InCombat
    // flag (Actor+0x2D0 bit 0x4000) set on a TRACKED non-owned NPC. The
    // signal tells the server "my player is the actual combat opponent
    // of this raider; if the current owner isn't engaging it, hand off
    // to me". Server rules in ownership.on_engagement_claim() prevent
    // ping-pong via COMBAT_HANDOFF_STICKINESS_MS.
    //
    // Internal dedup: per-fid 2 s cooldown (anti-flood). Returns true if
    // the claim was actually sent; false if rate-limited or no peer_id.
    bool enqueue_engagement_claim_dedup(std::uint32_t form_id);

    // M9 wedge 1: reliable EQUIP_OP — fire-and-forget. Sender hooks
    // ActorEquipManager::Equip/UnequipObject in the engine and forwards
    // each LOCAL-PLAYER fire here. Server fans out as EQUIP_BCAST to
    // other peers. In wedge 1 receivers just log (observe-only); wedge 2
    // will swap visuals on the M8P3 ghost body.
    //
    // `kind` is EquipOpKind cast to u8 (1=EQUIP, 2=UNEQUIP) — keeping the
    // arg as plain u8 avoids a header include of protocol.h's enum class
    // in callers that already cast at the call site.
    //
    // `slot_form_id` is 0 when the engine auto-resolved the slot (which
    // is the typical case from PipBoy UI equip clicks). Receivers in
    // wedge 2 will pass null for the slot* arg of EquipObject when this
    // is 0, letting their engine auto-resolve again.
    //
    // M9.w4: optional `mods` array carries the OMOD (BGSMod::Attachment::
    // Mod) attachments extracted from the equipped weapon's
    // BGSObjectInstanceExtra. mod_count=0 means "weapon has no mods" (e.g.
    // melee or stock pistol). Wire layout (post-fixed-payload):
    //   u8 mod_count, then mod_count × EquipModRecord (8 B each).
    // Cap MAX_EQUIP_MODS = 32 (clamped on encode).
    //
    // M9.w4 v8 — witness: optional `nif_descs` array captures which .nif
    // files the engine actually loaded for the modded weapon (sender walks
    // its own BipedAnim post-equip and queries nif_path_cache). Receiver
    // replays each descriptor by loading the NIF and attaching to the
    // matching named parent in the assembled weapon tree on the ghost.
    // Wire layout: appended AFTER the OMOD tail —
    //   u8 nif_count, then nif_count × NifDescriptor (variable size).
    // Cap MAX_NIF_DESCRIPTORS = 8 (clamped on encode).
    void enqueue_equip_op(std::uint32_t item_form_id,
                          std::uint8_t  kind,
                          std::uint32_t slot_form_id,
                          std::int32_t  count,
                          std::uint64_t timestamp_ms,
                          std::uint16_t effective_priority = 0,  // v10: M9.w2 PROPER
                          const EquipModRecord* mods       = nullptr,
                          std::uint8_t          mod_count  = 0,
                          const NifDescriptor* nif_descs   = nullptr,
                          std::uint8_t          nif_count  = 0);

    // Phase 4 — one line of global chat, reliable. Returns false when there
    // is no session to send it on, so the caller can say so instead of
    // letting the line vanish. The line is NOT shown locally: the server
    // sends it back to us like to everyone else, which is what keeps the
    // order identical on every client. Any thread.
    //
    // Wire: the Python ChatPayload, unchanged since v1 — sender FixedString(15)
    // + u16 length + UTF-8 text. The server ignores the sender field and
    // stamps the session's own peer_id; ours goes in only because the layout
    // has the field.
    bool send_chat(const std::string& text);

    // M9.w4 v9 — chunked mesh blob for an equip event.
    //
    // Sender extracts mesh data via weapon_witness::snapshot_player_weapon_meshes(),
    // serializes it into a single linear byte buffer (MeshBlobHeader + N
    // MeshRecordHeader + per-mesh strings + positions + indices), splits
    // into 1388-byte chunks, and enqueues each chunk as a reliable
    // MESH_BLOB_OP frame. Receiver (server fans out unchanged) buffers
    // chunks keyed on equip_seq, reassembles, decodes, and reconstructs
    // the meshes on the matching ghost weapon root.
    //
    // - `item_form_id` correlates with the EQUIP_OP that triggered this
    //   blob (receiver pairs by item_form_id within the same equip_seq).
    // - `meshes` / `num_meshes` come from the extractor.
    // - Returns the number of chunks queued (0 = nothing sent / error).
    //
    // Caller MUST own the meshes for the duration of the call (we deep-copy
    // into queue payload bytes — safe to drop after return).
    std::size_t enqueue_mesh_blob_for_equip(
        std::uint32_t item_form_id,
        const struct MeshBlobMesh* meshes,
        std::size_t  num_meshes);

    // 2026-05-06 (M9 closure, PLAN B) — ship a serialized NIF buffer
    // (engine NiStream::SaveToMemory output) using the same MESH_BLOB_OP
    // wire format. Encoded with num_meshes=0xFF sentinel — receiver
    // detects this and deserializes the payload via NiStream::Load
    // instead of decoding per-mesh records.
    std::size_t enqueue_nif_blob_for_equip(
        std::uint32_t item_form_id,
        const void*   nif_buf,
        std::size_t   nif_size);

    const Stats& stats() const noexcept { return stats_; }

    // --- ε.pivot: remote player state for custom renderer ---
    // Returns a snapshot-by-copy under lock. Safe to call from any
    // thread (render thread uses this every frame).
    RemotePlayerSnapshot get_remote_snapshot() const;

    // The same, but for ONE specific peer. This is the right accessor: the
    // one without arguments returns "the last one heard from", which with
    // two remote players is not an answer but a coin toss.
    //
    // has_state=false when nothing has arrived from that peer yet.
    RemotePlayerSnapshot get_remote_snapshot(const std::string& peer_id) const;

    // How many remote peers have been heard from at least once. Diagnostics.
    std::size_t remote_peer_count() const;

private:
    struct QueuedSend {
        MessageType msg_type;
        std::vector<std::uint8_t> payload_bytes;
        bool reliable;
    };

    void run_loop();

    // 2026-09-18 — the outcome of one handshake attempt.
    //
    //   Ok    = session open
    //   Retry = try again later (server down, full, or this client's old
    //           session has yet to expire)
    //   Fatal = will never improve by itself: incompatible version, identity
    //           refused. Stop and write the reason.
    enum class HandshakeOutcome { Ok, Retry, Fatal };

    // `use_resume` sceglie la forma: HELLO_RESUME col token che il server ci
    // ha dato l'ultima volta, oppure HELLO normale.
    HandshakeOutcome do_handshake(bool use_resume);

    // Attesa del WELCOME (o del rifiuto), condivisa dai due ingressi.
    HandshakeOutcome await_welcome(bool was_resume);

    // Traduce il motivo del rifiuto in "riprova" o "smetti".
    HandshakeOutcome on_rejected(std::uint8_t code, bool was_resume,
                                 std::uint8_t server_major,
                                 std::uint8_t server_minor);

    // Drops all the state that belongs to ONE session, before opening
    // another. Only from the worker thread.
    void reset_session_state();

    // Attesa fra due tentativi, a fette, controllando `stopping_`. Torna
    // false se nel frattempo ci hanno chiesto di fermarci.
    bool backoff_wait(unsigned attempt);

    // Loot rework L2: after a WELCOME, every container op still waiting for
    // its verdict goes out again. reset_session_state dropped the queued
    // copies, so nothing leaves twice from this side; a repeat the server
    // did see is answered with the stored verdict.
    void resend_pending_container_ops();

    // Messages are queued until asked to stop, even while the session is
    // down: what is reliable must wait for the rejoin, not vanish. Container
    // ops included since loot rework L2: the engine has applied them, so the
    // server must hear of them or refuse them, never lose them.
    bool accepting_enqueue() const noexcept { return !stopping_.load(); }

    // Insertion into the queue WITH the ceiling. Returns false when the
    // message was dropped.
    //
    // NOT the only insertion point, despite what this used to say: four
    // producers do a direct queue_.push_back and bypass the ceiling, the
    // MESH_BLOB chunks, the NIF_BLOB chunks, the CONTAINER_SEED chunks and
    // submit_container_op. The first three are precisely the bulkiest, so
    // kSendQueueMax does not limit what would most need a limit; the
    // container ops bypass it because the engine has already applied them
    // and they must not be the ones a full queue drops.
    bool push_queued(QueuedSend&& q);

    // Ceiling of the outgoing queue. The largest message is a full pose,
    // about 1.3 KB, so the ceiling stays under a megabyte. Before phase 1
    // there was no limit at all: the only thing keeping the queue short was
    // that everything was dropped while disconnected.
    static constexpr std::size_t kSendQueueMax = 512;

    // Dispatch a delivered frame to the appropriate in-process handler.
    // In B0.4 these are stubs that just count; B0.5 fills them in.
    void dispatch(const Delivered& d);

    // --- config ---
    config::Settings cfg_;
    std::string server_host_;
    std::uint16_t server_port_ = 0;

    // --- lifecycle ---
    std::atomic<bool> stopping_{false};
    std::atomic<bool> connected_{false};
    std::atomic<bool> dead_{false};
    std::atomic<std::uint32_t> session_id_{0};
    // v26 — the credential that lets this client come back without going
    // through the launcher again, whose login proof is single use. Lives
    // only in memory and only on the worker thread: never on disk, never in
    // the logs.
    std::vector<std::uint8_t> resume_token_;
    // The character creation ritual is done once per process: doing it at
    // every WELCOME would bring the editor up mid-game when the client
    // rejoins.
    bool chargen_ritual_seen_ = false;
    // Time of the last frame received from the server, of any kind: any
    // frame proves the server is alive. It is the only way to notice a dead
    // server, because a client that only sends (unreliable) positions has
    // nothing in flight to retransmit and the channel never declares itself
    // dead.
    std::atomic<std::uint64_t> last_server_frame_ms_{0};
    // Time of the last POSITION actually sent, for the brake in the drain:
    // the server's validator rejects two positions arriving less than 20 ms
    // apart. Worker thread only.
    std::chrono::steady_clock::time_point last_pos_sent_at_{};

    // --- I/O state (owned by run_loop thread) ---
    UdpSocket socket_;
    ReliableChannel channel_;

    // --- send queue (written by hook threads, drained by run_loop) ---
    std::mutex queue_mutex_;
    std::deque<QueuedSend> queue_;

    // --- worker thread ---
    std::thread thread_;

    // --- the server's view of the containers (loot rework L1 + L3) ---
    // Keyed by the container REFR's form_id. Since L3 this is what the
    // engine is aligned to: fed by the CONTAINER_STATE bootstrap and by the
    // live pushes (a record the server created, replaced or refilled),
    // adjusted by CONTAINER_BCAST and by this client's own ACCEPTED
    // verdicts, but never CREATED by those two: the server broadcasts ops
    // on partial records as well, and a view built from one op would empty
    // the container of everything else. A container present here with no
    // items is KNOWN EMPTY (the sentinel entry): its local copy is emptied.
    struct MirrorContainer {
        std::uint32_t base_id = 0;
        std::uint32_t cell_id = 0;
        std::unordered_map<std::uint32_t, std::int32_t> items;
    };
    std::mutex container_mirror_mutex_;
    std::unordered_map<std::uint32_t, MirrorContainer> container_mirror_;
    // The containers named by the CONTAINER_STATE chunks of one sequence,
    // in order of first appearance; aligned when the last chunk lands (a
    // container's lines may straddle two chunks). Network thread only.
    std::vector<std::uint32_t> state_sequence_fids_;
    // Seeds sent this session and not yet answered by a push: one seed per
    // container per session. Cleared with the session, so a server that
    // lost its state is seeded again.
    std::mutex seeds_mutex_;
    std::unordered_set<std::uint32_t> seeds_in_flight_;
    // The sweep (L3.3): checked twice a second on the main thread; a sweep
    // when the scene settles and when the player's cell changes.
    std::uint64_t sweep_checked_ms_ = 0;
    std::uint32_t sweep_cell_ = 0;
    bool          sweep_settled_ = false;
    void sweep_known_containers(const char* why);

    // --- M9 w4 v9 mesh blob reassembly state -----------------------------
    // Net worker thread owns this map exclusively (read+write from
    // dispatch() only). Keyed on (peer_id, equip_seq). Value holds the
    // partially-filled blob buffer + a chunk-received bitmap.
    //
    // Lifecycle:
    //   - First chunk → insert entry, allocate buffer, mark chunk
    //   - Subsequent chunks → write slice, mark chunk, check completion
    //   - Last chunk → decode, dispatch to main thread, drop entry
    //   - GC: any entry older than MESH_BLOB_REASSEMBLY_TIMEOUT_MS is
    //     dropped on each chunk arrival (cheap, no separate timer needed)
    struct MeshBlobReassemblyKey {
        std::string  peer_id;     // empty for OP (own client; not used yet)
        std::uint32_t equip_seq;
    };
    struct MeshBlobReassemblyKeyHash {
        std::size_t operator()(const MeshBlobReassemblyKey& k) const noexcept {
            // FNV-style mix of equip_seq and peer_id
            std::size_t h = std::hash<std::string>{}(k.peer_id);
            h ^= static_cast<std::size_t>(k.equip_seq) +
                 0x9E3779B97F4A7C15ull + (h << 6) + (h >> 2);
            return h;
        }
    };
    struct MeshBlobReassemblyKeyEq {
        bool operator()(const MeshBlobReassemblyKey& a,
                        const MeshBlobReassemblyKey& b) const noexcept {
            return a.equip_seq == b.equip_seq && a.peer_id == b.peer_id;
        }
    };
    struct MeshBlobReassemblyEntry {
        std::uint32_t              total_blob_size = 0;
        std::uint16_t              total_chunks    = 0;
        std::uint16_t              received_count  = 0;
        std::vector<std::uint8_t>  buf;            // resized to total_blob_size on first chunk
        std::vector<std::uint8_t>  chunk_received; // 1 byte per chunk (0/1)
        std::uint64_t              first_chunk_at_ms = 0;
    };
    std::unordered_map<MeshBlobReassemblyKey,
                       MeshBlobReassemblyEntry,
                       MeshBlobReassemblyKeyHash,
                       MeshBlobReassemblyKeyEq> mesh_blob_reasm_;
    static constexpr std::uint64_t MESH_BLOB_REASSEMBLY_TIMEOUT_MS = 5000;

    // --- loot rework L2: container ops waiting for their verdict ---
    // Keyed by client_op_id, the full op so a refusal can be undone and a
    // drop can send it again. The id is a per-process random epoch in the
    // high 16 bits and a sequence in the low 16: the server remembers
    // verdicts per PEER across sessions, and the epoch keeps a relaunched
    // client's first ops from being answered with the verdicts of the
    // previous process. 0 is never issued (fire-and-forget on the wire).
    std::uint16_t op_epoch_ = 0;                // set in the constructor
    std::atomic<std::uint32_t> next_op_seq_{1};
    std::mutex pending_ops_mutex_;
    std::unordered_map<std::uint32_t, ContainerOpPayload> pending_container_ops_;

    // --- the remote peers' snapshot ---
    //
    // Written by dispatch() on the network thread at every POS_BROADCAST,
    // read by the renderer at every Present and by the scene tick.
    //
    // 2026-09-18 — the promised map arrived. The comment here said "MVP
    // holds ONE remote player, the most recently heard from. When multi-peer
    // lands this becomes a peer_id -> snapshot map": this is it.
    //
    // `remote_snapshot_` STAYS, and it is not a leftover: it is the last one
    // heard from, and it is what the consumers read that do not yet know
    // WHOSE body they are drawing. With a single remote peer, today's case,
    // it is identical to the map entry, so this step changes nobody's
    // behaviour. It goes away when the consumers hold a peer_id, that is
    // when the body enters the record.
    mutable std::mutex remote_mutex_;
    RemotePlayerSnapshot remote_snapshot_;
    std::unordered_map<std::string, RemotePlayerSnapshot> remote_by_peer_;

    // --- stats ---
    Stats stats_;
};

// Process-wide singleton (lazy-initialized on first access).
Client& client();

} // namespace fw::net
