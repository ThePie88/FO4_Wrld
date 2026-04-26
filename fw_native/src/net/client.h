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
