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

    // Reliable.
    void enqueue_actor_event(const ActorEventPayload& a);

    // Fire-and-forget reliable CONTAINER_OP (legacy, B0 semantics — no wait).
    // Prefer submit_container_op_blocking for B1+ pre-mutation block.
    void enqueue_container_op(const ContainerOpPayload& op);

    // Reliable CONTAINER_SEED — chunked. entries will be split across frames
    // if > MAX entries per chunk. No ACK correlation (fire-and-forget).
    void enqueue_container_seed(std::uint32_t base_id, std::uint32_t cell_id,
                                const ContainerStateEntry* entries,
                                std::size_t num_entries);

    // B4.d: reliable GLOBAL_VAR_SET — fire-and-forget. Server broadcasts to
    // other peers; sender applies optimistically via the engine hook itself.
    void enqueue_global_var_set(std::uint32_t global_form_id, double value);

    // B6.1: reliable DOOR_OP — fire-and-forget. Server broadcasts to other
    // peers as DOOR_BCAST. Toggle semantics — the receiver re-invokes its
    // local Activate worker on the matching REFR; both sides converge as
    // long as they started from the same world_base save.
    void enqueue_door_op(std::uint32_t door_form_id,
                         std::uint32_t door_base_id,
                         std::uint32_t door_cell_id,
                         std::uint64_t timestamp_ms);

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

    // B1.d: Blocking submit. Fills op.client_op_id from an internal counter,
    // sends reliable, waits up to `timeout_ms` on a condvar for the matching
    // CONTAINER_OP_ACK from the server. Returns:
    //   - populated ContainerOpAckPayload if ACK arrived (status may be
    //     ACCEPTED or any REJ_*).
    //   - std::nullopt if the wait timed out or the client is not connected.
    //     Caller treats timeout as conservative REJECT (do not mutate).
    std::optional<ContainerOpAckPayload> submit_container_op_blocking(
        ContainerOpPayload op, std::uint32_t timeout_ms = 100);

    const Stats& stats() const noexcept { return stats_; }

    // --- ε.pivot: remote player state for custom renderer ---
    // Returns a snapshot-by-copy under lock. Safe to call from any
    // thread (render thread uses this every frame).
    RemotePlayerSnapshot get_remote_snapshot() const;

private:
    struct QueuedSend {
        MessageType msg_type;
        std::vector<std::uint8_t> payload_bytes;
        bool reliable;
    };

    void run_loop();
    bool do_handshake();

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

    // --- I/O state (owned by run_loop thread) ---
    UdpSocket socket_;
    ReliableChannel channel_;

    // --- send queue (written by hook threads, drained by run_loop) ---
    std::mutex queue_mutex_;
    std::deque<QueuedSend> queue_;

    // --- worker thread ---
    std::thread thread_;

    // --- local mirror of authoritative server state ---
    // Keyed by (base_id, cell_id). Value map: item_base_id -> count.
    // Populated from CONTAINER_STATE bootstrap + maintained via CONTAINER_BCAST.
    // Currently used only for telemetry / debugging; a future block may
    // plug it into the container hook for optimistic-apply.
    struct ContainerKey { std::uint32_t base, cell; };
    struct ContainerKeyHash {
        std::size_t operator()(const ContainerKey& k) const noexcept {
            return (static_cast<std::size_t>(k.base) << 32) ^ k.cell;
        }
    };
    struct ContainerKeyEq {
        bool operator()(const ContainerKey& a, const ContainerKey& b) const noexcept {
            return a.base == b.base && a.cell == b.cell;
        }
    };
    std::mutex container_mirror_mutex_;
    std::unordered_map<ContainerKey, std::unordered_map<std::uint32_t, std::int32_t>,
                       ContainerKeyHash, ContainerKeyEq> container_mirror_;

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

    // --- B1.d pending-op table for CONTAINER_OP_ACK correlation ---
    // Sender hook thread allocates a fresh client_op_id (atomic counter),
    // stashes a PendingOp on the heap and keys it in the map, then waits on
    // the condvar. The net worker thread wakes it when the server's ACK
    // lands in dispatch().
    struct PendingOp {
        std::mutex mtx;
        std::condition_variable cv;
        bool ready = false;
        ContainerOpAckPayload ack{};
    };
    std::atomic<std::uint32_t> next_op_id_{1};  // 0 reserved for fire-and-forget
    std::mutex pending_ops_mutex_;
    std::unordered_map<std::uint32_t, std::shared_ptr<PendingOp>> pending_ops_;

    // --- ε.pivot: latest remote player snapshot ---
    // Written by dispatch() (net worker thread) on every POS_BROADCAST;
    // read by the body renderer on every Present. MVP holds ONE remote
    // player — the most recently heard from. When multi-peer lands this
    // becomes a peer_id → snapshot map.
    mutable std::mutex remote_mutex_;
    RemotePlayerSnapshot remote_snapshot_;

    // --- stats ---
    Stats stats_;
};

// Process-wide singleton (lazy-initialized on first access).
Client& client();

} // namespace fw::net
