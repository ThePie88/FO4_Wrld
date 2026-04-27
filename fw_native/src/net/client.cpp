#include "client.h"

#include <windows.h>
#include <chrono>
#include <cstring>
#include <thread>

#include "../log.h"
#include "../engine/engine_calls.h"
#include "../ghost/actor_hijack.h"
#include "../hooks/container_hook.h"
#include "../main_thread_dispatch.h"
#include "../native/scene_inject.h"

namespace fw::net {

namespace {

std::uint64_t now_ms_wall() {
    using namespace std::chrono;
    return duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
}

} // namespace

Client& client() {
    static Client instance;
    return instance;
}

Client::Client() = default;

Client::~Client() {
    stop();
}

RemotePlayerSnapshot Client::get_remote_snapshot() const {
    std::lock_guard lk(remote_mutex_);
    return remote_snapshot_;   // copy out; caller gets stable data
}

bool Client::start(const config::Settings& cfg) {
    if (thread_.joinable()) {
        FW_WRN("net: client.start() called twice — ignoring");
        return true;
    }
    cfg_ = cfg;
    server_host_ = cfg.server_host;
    server_port_ = cfg.server_port;
    stopping_.store(false);
    connected_.store(false);
    dead_.store(false);

    thread_ = std::thread([this] { this->run_loop(); });
    return true;
}

void Client::stop() {
    if (!thread_.joinable()) return;
    stopping_.store(true);
    thread_.join();
}

// ---------------------------------------------------------------- enqueue

void Client::enqueue_pos_state(const PosStatePayload& p) {
    if (!connected_.load() || stopping_.load()) return;
    QueuedSend q;
    q.msg_type = MessageType::POS_STATE;
    q.reliable = false;
    q.payload_bytes.resize(sizeof(p));
    std::memcpy(q.payload_bytes.data(), &p, sizeof(p));
    {
        std::lock_guard lk(queue_mutex_);
        queue_.push_back(std::move(q));
    }
}

void Client::enqueue_pose_state(std::uint64_t header_ts_ms,
                                const PoseBoneEntry* bones,
                                std::size_t bone_count)
{
    if (!connected_.load() || stopping_.load()) return;
    if (bone_count > MAX_POSE_BONES) bone_count = MAX_POSE_BONES;

    QueuedSend q;
    q.msg_type = MessageType::POSE_STATE;
    q.reliable = false;
    const std::size_t total = sizeof(PoseStateHeader)
                            + bone_count * sizeof(PoseBoneEntry);
    q.payload_bytes.resize(total);

    PoseStateHeader hdr{};
    hdr.timestamp_ms = header_ts_ms;
    hdr.bone_count   = static_cast<std::uint16_t>(bone_count);
    std::memcpy(q.payload_bytes.data(), &hdr, sizeof(hdr));
    if (bone_count > 0 && bones != nullptr) {
        std::memcpy(q.payload_bytes.data() + sizeof(hdr),
                    bones, bone_count * sizeof(PoseBoneEntry));
    }
    {
        std::lock_guard lk(queue_mutex_);
        queue_.push_back(std::move(q));
    }
}

void Client::enqueue_actor_event(const ActorEventPayload& a) {
    if (!connected_.load() || stopping_.load()) return;
    QueuedSend q;
    q.msg_type = MessageType::ACTOR_EVENT;
    q.reliable = true;
    q.payload_bytes.resize(sizeof(a));
    std::memcpy(q.payload_bytes.data(), &a, sizeof(a));
    {
        std::lock_guard lk(queue_mutex_);
        queue_.push_back(std::move(q));
    }
}

void Client::enqueue_container_op(const ContainerOpPayload& op) {
    if (!connected_.load() || stopping_.load()) return;
    QueuedSend q;
    q.msg_type = MessageType::CONTAINER_OP;
    q.reliable = true;
    q.payload_bytes.resize(sizeof(op));
    std::memcpy(q.payload_bytes.data(), &op, sizeof(op));
    {
        std::lock_guard lk(queue_mutex_);
        queue_.push_back(std::move(q));
    }
}

void Client::enqueue_global_var_set(std::uint32_t global_form_id, double value) {
    if (!connected_.load() || stopping_.load()) return;
    if (global_form_id == 0) return;

    GlobalVarSetPayload p{};
    p.global_form_id = global_form_id;
    p.value = value;
    {
        using namespace std::chrono;
        p.timestamp_ms = duration_cast<milliseconds>(
            system_clock::now().time_since_epoch()).count();
    }
    QueuedSend q;
    q.msg_type = MessageType::GLOBAL_VAR_SET;
    q.reliable = true;
    q.payload_bytes.resize(sizeof(p));
    std::memcpy(q.payload_bytes.data(), &p, sizeof(p));
    {
        std::lock_guard lk(queue_mutex_);
        queue_.push_back(std::move(q));
    }
}

void Client::enqueue_door_op(std::uint32_t door_form_id,
                             std::uint32_t door_base_id,
                             std::uint32_t door_cell_id,
                             std::uint64_t timestamp_ms)
{
    if (!connected_.load() || stopping_.load()) return;
    if (door_form_id == 0 || door_base_id == 0) return;

    DoorOpPayload p{};
    p.door_form_id  = door_form_id;
    p.door_base_id  = door_base_id;
    p.door_cell_id  = door_cell_id;
    p.timestamp_ms  = timestamp_ms;

    QueuedSend q;
    q.msg_type = MessageType::DOOR_OP;
    q.reliable = true;
    q.payload_bytes.resize(sizeof(p));
    std::memcpy(q.payload_bytes.data(), &p, sizeof(p));
    {
        std::lock_guard lk(queue_mutex_);
        queue_.push_back(std::move(q));
    }
}

void Client::enqueue_container_seed(std::uint32_t base_id, std::uint32_t cell_id,
                                    const ContainerStateEntry* entries,
                                    std::size_t num_entries)
{
    if (!connected_.load() || stopping_.load()) return;

    constexpr std::size_t max_per_chunk = (MAX_PAYLOAD_SIZE - sizeof(ChunkHeader))
                                          / sizeof(ContainerStateEntry); // 87

    const std::uint16_t total_chunks = static_cast<std::uint16_t>(
        (num_entries + max_per_chunk - 1) / max_per_chunk);
    const std::uint16_t clamp_chunks = total_chunks == 0 ? 1 : total_chunks;

    for (std::uint16_t ci = 0; ci < clamp_chunks; ++ci) {
        const std::size_t off = static_cast<std::size_t>(ci) * max_per_chunk;
        const std::size_t remain = (num_entries > off) ? (num_entries - off) : 0;
        const std::size_t this_chunk = remain < max_per_chunk ? remain : max_per_chunk;

        QueuedSend q;
        q.msg_type = MessageType::CONTAINER_SEED;
        q.reliable = true;
        q.payload_bytes.resize(sizeof(ChunkHeader)
                               + this_chunk * sizeof(ContainerStateEntry));
        ChunkHeader h{};
        h.num_entries  = static_cast<std::uint16_t>(this_chunk);
        h.chunk_index  = ci;
        h.total_chunks = clamp_chunks;
        std::memcpy(q.payload_bytes.data(), &h, sizeof(h));

        // Each entry's container_base_id/cell_id should already be populated
        // by the caller (matching base_id/cell_id). We don't rewrite — we
        // trust the caller built the list correctly.
        if (this_chunk > 0) {
            std::memcpy(q.payload_bytes.data() + sizeof(ChunkHeader),
                        entries + off,
                        this_chunk * sizeof(ContainerStateEntry));
        }

        // Silence unused-when-debug-off warning on some compilers
        (void)base_id; (void)cell_id;

        {
            std::lock_guard lk(queue_mutex_);
            queue_.push_back(std::move(q));
        }
    }
}

std::optional<ContainerOpAckPayload> Client::submit_container_op_blocking(
    ContainerOpPayload op, std::uint32_t timeout_ms)
{
    if (!connected_.load() || stopping_.load()) {
        FW_WRN("net: submit_container_op_blocking called while disconnected");
        return std::nullopt;
    }

    // Allocate fresh op id (never 0).
    std::uint32_t id = next_op_id_.fetch_add(1);
    if (id == 0) id = next_op_id_.fetch_add(1);
    op.client_op_id = id;

    auto pending = std::make_shared<PendingOp>();
    {
        std::lock_guard lk(pending_ops_mutex_);
        pending_ops_[id] = pending;
    }

    // Enqueue reliable CONTAINER_OP. Use same path as fire-and-forget; the
    // ACK correlation happens purely via client_op_id.
    {
        QueuedSend q;
        q.msg_type = MessageType::CONTAINER_OP;
        q.reliable = true;
        q.payload_bytes.resize(sizeof(op));
        std::memcpy(q.payload_bytes.data(), &op, sizeof(op));
        std::lock_guard lk(queue_mutex_);
        queue_.push_back(std::move(q));
    }

    // Wait for ACK or timeout.
    std::unique_lock lk(pending->mtx);
    const bool ok = pending->cv.wait_for(
        lk, std::chrono::milliseconds(timeout_ms),
        [&]{ return pending->ready; });

    // Always unmap: a late ACK after timeout has nothing to wake.
    {
        std::lock_guard lk2(pending_ops_mutex_);
        pending_ops_.erase(id);
    }

    if (!ok) {
        FW_WRN("net: submit_container_op_blocking timeout op_id=%u "
               "kind=%u base=0x%X cell=0x%X item=0x%X count=%d",
               id, op.kind, op.container_base_id, op.container_cell_id,
               op.item_base_id, op.count);
        return std::nullopt;
    }
    return pending->ack;
}

// ---------------------------------------------------------------- main loop

bool Client::do_handshake() {
    HelloPayload h{};
    h.client_id.set(cfg_.client_id);
    h.client_version_major = 1;
    h.client_version_minor = 0;

    auto frame = channel_.send_reliable(
        MessageType::HELLO, &h, sizeof(h));
    if (!socket_.send(frame.data(), frame.size())) {
        FW_ERR("net: initial HELLO send failed (err=%d)", socket_.last_error());
        return false;
    }
    stats_.reliable_sent.fetch_add(1);

    // Wait up to 5 seconds for WELCOME, re-driving retransmits via tick.
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    std::uint8_t rxbuf[MAX_FRAME_SIZE];

    while (std::chrono::steady_clock::now() < deadline) {
        if (stopping_.load()) return false;

        // Run tick for retransmit of HELLO if needed.
        const auto now = std::chrono::steady_clock::now();
        auto retx = channel_.tick(now);
        for (auto& f : retx) {
            socket_.send(f.data(), f.size());
        }
        if (channel_.is_dead()) {
            FW_ERR("net: channel dead during handshake");
            return false;
        }

        // Recv with small timeout.
        const int n = socket_.recv(rxbuf, sizeof(rxbuf), 200);
        if (n <= 0) continue;

        std::vector<std::uint8_t> ack_bytes;
        auto delivered = channel_.on_receive(rxbuf, static_cast<std::size_t>(n),
                                              now, &ack_bytes);
        if (!ack_bytes.empty()) {
            socket_.send(ack_bytes.data(), ack_bytes.size());
        }
        if (!delivered) continue;
        stats_.reliable_received.fetch_add(1);

        if (delivered->header.msg_type ==
            static_cast<std::uint16_t>(MessageType::WELCOME))
        {
            if (delivered->payload.size() < sizeof(WelcomePayload)) {
                FW_ERR("net: WELCOME payload too short");
                return false;
            }
            WelcomePayload w{};
            std::memcpy(&w, delivered->payload.data(), sizeof(w));
            if (!w.accepted) {
                FW_ERR("net: server rejected HELLO (server_ver=%u.%u)",
                       w.server_version_major, w.server_version_minor);
                return false;
            }
            session_id_.store(w.session_id);
            connected_.store(true);
            FW_LOG("net: WELCOME session_id=%u server=%u.%u tick=%uHz",
                   w.session_id, w.server_version_major, w.server_version_minor,
                   w.tick_rate_hz);
            return true;
        }
        // Other messages during handshake are unusual but OK; just dispatch.
        dispatch(*delivered);
    }

    FW_ERR("net: timeout waiting for WELCOME (5s)");
    return false;
}

void Client::run_loop() {
    FW_LOG("net: client thread starting  server=%s:%u  client_id=%s",
           server_host_.c_str(), server_port_, cfg_.client_id.c_str());

    if (!socket_.open(server_host_, server_port_)) {
        FW_ERR("net: socket open failed — client will not run");
        dead_.store(true);
        return;
    }

    if (!do_handshake()) {
        dead_.store(true);
        socket_.close();
        return;
    }

    constexpr auto HEARTBEAT_INTERVAL = std::chrono::milliseconds(1500);
    constexpr auto STATS_INTERVAL     = std::chrono::seconds(10);
    auto next_heartbeat = std::chrono::steady_clock::now() + HEARTBEAT_INTERVAL;
    auto next_stats     = std::chrono::steady_clock::now() + STATS_INTERVAL;

    std::uint8_t rxbuf[MAX_FRAME_SIZE];

    while (!stopping_.load()) {
        const auto now = std::chrono::steady_clock::now();

        // -------- 1. Drain outbound queue --------
        std::deque<QueuedSend> drained;
        {
            std::lock_guard lk(queue_mutex_);
            drained.swap(queue_);
        }
        for (auto& q : drained) {
            std::vector<std::uint8_t> frame;
            if (q.reliable) {
                frame = channel_.send_reliable(q.msg_type,
                    q.payload_bytes.data(), q.payload_bytes.size());
                stats_.reliable_sent.fetch_add(1);
            } else {
                frame = channel_.send_unreliable(q.msg_type,
                    q.payload_bytes.data(), q.payload_bytes.size());
            }
            socket_.send(frame.data(), frame.size());

            // Per-msg-type counter for stats
            switch (q.msg_type) {
            case MessageType::POS_STATE:    stats_.pos_sent.fetch_add(1); break;
            case MessageType::ACTOR_EVENT:  stats_.kills_sent.fetch_add(1); break;
            case MessageType::CONTAINER_OP: stats_.container_ops_sent.fetch_add(1); break;
            default: break;
            }
        }

        // -------- 2. Tick channel (retransmits) --------
        auto retx = channel_.tick(now);
        for (auto& f : retx) {
            socket_.send(f.data(), f.size());
        }
        if (channel_.is_dead()) {
            FW_ERR("net: channel dead — stopping client loop");
            dead_.store(true);
            break;
        }

        // -------- 3. Recv one datagram if available (50ms max wait) --------
        const int n = socket_.recv(rxbuf, sizeof(rxbuf), 50);
        if (n > 0) {
            std::vector<std::uint8_t> ack_bytes;
            auto delivered = channel_.on_receive(
                rxbuf, static_cast<std::size_t>(n), now, &ack_bytes);
            if (!ack_bytes.empty()) {
                socket_.send(ack_bytes.data(), ack_bytes.size());
            }
            if (delivered) {
                stats_.reliable_received.fetch_add(1);
                dispatch(*delivered);
            }
        } else if (n < 0) {
            FW_WRN("net: recv error %d", socket_.last_error());
        }

        // -------- 4. Opportunistic ACK flush even without new recv --------
        std::vector<std::uint8_t> opportunistic_ack;
        if (channel_.maybe_emit_ack(&opportunistic_ack)) {
            socket_.send(opportunistic_ack.data(), opportunistic_ack.size());
        }

        // -------- 5. Periodic heartbeat --------
        if (now >= next_heartbeat) {
            HeartbeatPayload hb{};
            hb.timestamp_ms = now_ms_wall();
            auto frame = channel_.send_unreliable(
                MessageType::HEARTBEAT, &hb, sizeof(hb));
            socket_.send(frame.data(), frame.size());
            stats_.heartbeats_sent.fetch_add(1);
            next_heartbeat = now + HEARTBEAT_INTERVAL;
        }

        // -------- 6. Periodic stats log --------
        if (now >= next_stats) {
            FW_LOG("net: stats  pos_sent=%llu  pos_bcast=%llu  "
                   "kills_sent=%llu  kills_bcast=%llu  "
                   "cont_sent=%llu  cont_recv=%llu  "
                   "reliable_sent=%llu  reliable_recv=%llu  "
                   "world_state_entries=%llu  container_state_entries=%llu",
                   static_cast<unsigned long long>(stats_.pos_sent.load()),
                   static_cast<unsigned long long>(stats_.pos_broadcast_received.load()),
                   static_cast<unsigned long long>(stats_.kills_sent.load()),
                   static_cast<unsigned long long>(stats_.kills_broadcast_received.load()),
                   static_cast<unsigned long long>(stats_.container_ops_sent.load()),
                   static_cast<unsigned long long>(stats_.container_ops_received.load()),
                   static_cast<unsigned long long>(stats_.reliable_sent.load()),
                   static_cast<unsigned long long>(stats_.reliable_received.load()),
                   static_cast<unsigned long long>(stats_.world_state_entries.load()),
                   static_cast<unsigned long long>(stats_.container_state_entries.load()));
            next_stats = now + STATS_INTERVAL;
        }
    }

    // -------- graceful shutdown: DISCONNECT reliable, best-effort flush --------
    if (connected_.load()) {
        DisconnectPayload d{};
        d.reason = 0;
        auto frame = channel_.send_reliable(
            MessageType::DISCONNECT, &d, sizeof(d));
        socket_.send(frame.data(), frame.size());
        // Brief drain so the UDP flush reaches the server.
        Sleep(100);
    }
    connected_.store(false);
    socket_.close();

    // Wake all pending blocking submitters with a synthetic "no answer".
    // They see ready=false in ack — treated as "reject/timeout" → do not mutate.
    // We leave ack zeroed; the caller already has timeout logic for
    // "wait_for returned false" but here we set ready=true so it doesn't
    // stall for the full timeout at shutdown. Status=0 (ACCEPTED) would be
    // wrong, so we use REJ_RATE as a harmless reject sentinel.
    {
        std::lock_guard lk(pending_ops_mutex_);
        for (auto& [id, p] : pending_ops_) {
            {
                std::lock_guard pl(p->mtx);
                p->ack.client_op_id = id;
                p->ack.status = static_cast<std::uint8_t>(
                    ContainerOpAckStatus::REJ_RATE);
                p->ready = true;
            }
            p->cv.notify_all();
        }
    }

    FW_LOG("net: client thread exiting");
}

// ---------------------------------------------------------------- dispatch

void Client::dispatch(const Delivered& d) {
    switch (d.header.msg_type) {
    case static_cast<std::uint16_t>(MessageType::POSE_BROADCAST): {
        if (d.payload.size() < sizeof(PoseBroadcastHeader)) break;
        PoseBroadcastHeader hdr{};
        std::memcpy(&hdr, d.payload.data(), sizeof(hdr));
        if (hdr.bone_count > MAX_POSE_BONES) break;
        const std::size_t need = sizeof(hdr)
                                 + hdr.bone_count * sizeof(PoseBoneEntry);
        if (d.payload.size() < need) break;
        const PoseBoneEntry* bones = reinterpret_cast<const PoseBoneEntry*>(
            d.payload.data() + sizeof(hdr));
        // Hand off to main thread (stashes + posts WM_APP).
        fw::native::store_remote_pose(hdr.timestamp_ms, bones, hdr.bone_count);
        break;
    }

    case static_cast<std::uint16_t>(MessageType::POS_BROADCAST): {
        stats_.pos_broadcast_received.fetch_add(1);
        if (d.payload.size() < sizeof(PosBroadcastPayload)) break;
        PosBroadcastPayload p{};
        std::memcpy(&p, d.payload.data(), sizeof(p));

        const std::string peer = p.peer_id.get();

        // Legacy ghost_map path (B1) — KEPT as dev-marker during
        // custom-render-engine build-out. Flickers as before (Havok
        // fights memory writes) but gives the user a visible anchor
        // to know where peer A/B are physically in each other's world
        // while the D3D11 ghost render is still being polished. Will
        // be removed only once the custom renderer is feature-complete.
        if (cfg_.ghost_map_form_id != 0 && peer == cfg_.ghost_map_peer_id) {
            fw::engine::write_ghost_pos_rot(
                cfg_.ghost_map_form_id,
                p.x, p.y, p.z, p.rx, p.ry, p.rz);
        }

        // ε.pivot: publish snapshot for the custom body renderer. One
        // slot, last-writer-wins (single remote peer in MVP).
        {
            std::lock_guard lk(remote_mutex_);
            remote_snapshot_.has_state      = true;
            remote_snapshot_.peer_id        = peer;
            remote_snapshot_.pos[0]         = p.x;
            remote_snapshot_.pos[1]         = p.y;
            remote_snapshot_.pos[2]         = p.z;
            remote_snapshot_.rot[0]         = p.rx;
            remote_snapshot_.rot[1]         = p.ry;
            remote_snapshot_.rot[2]         = p.rz;
            remote_snapshot_.server_ts_ms   = p.timestamp_ms;
            remote_snapshot_.received_at_ms = GetTickCount64();
        }

        // M3.1 event-driven cube tracking (Strada B): post WM_APP+0x46 to
        // the main window so the injected cube's local.translate updates
        // to the fresh remote pos within 1 frame. No-op if no cube
        // injected yet or WndProc not subclassed.
        fw::native::notify_remote_pos_changed();

        // Z.2d (Path B) — DEAD. Re-tested 2026-04-26 in 1.11.191 next-gen:
        // PlaceAtMe SEH reproduces identically to 2026-04-22. Heap state
        // corrupts even with __try/__except (Side B crashes, Side A
        // limps until later). Definitive verdict: hijack via PlaceAtMe
        // from WndProc thread is impossible in this game version.
        // Pivoting to Plan A: build 3D from scratch via M8P2 sub_140458390
        // entry point. fw_native/src/ghost/* kept as archeology.
        //
        // fw::ghost::request_spawn();
        break;
    }

    case static_cast<std::uint16_t>(MessageType::ACTOR_EVENT): {
        stats_.kills_broadcast_received.fetch_add(1);
        if (d.payload.size() < sizeof(ActorEventPayload)) break;
        ActorEventPayload a{};
        std::memcpy(&a, d.payload.data(), sizeof(a));

        // KILL/DISABLE -> disable local ref; SPAWN/ENABLE -> enable.
        const bool is_dead =
            a.kind == static_cast<std::uint32_t>(ActorEventKind::KILL) ||
            a.kind == static_cast<std::uint32_t>(ActorEventKind::DISABLE);
        // Only apply if we have full identity (protects against legacy
        // entries and the 0xFF______ aliasing class of bug).
        if (a.actor_base_id != 0 && a.cell_id != 0) {
            // B1.n: feedback-loop guard. When we apply a remote DISABLE
            // via set_disabled_validated → disable_ref, the engine may
            // also invoke sub_140500430 internally as part of the
            // ExtraContainerChanges rebuild (or related inventory
            // housekeeping). Our pickup_hook detour MUST see this as a
            // "we're applying remote, don't re-emit" via the shared TLS.
            fw::hooks::ApplyingRemoteGuard guard;
            fw::engine::set_disabled_validated(
                a.form_id, a.actor_base_id, a.cell_id, is_dead);
        }
        break;
    }

    case static_cast<std::uint16_t>(MessageType::GLOBAL_VAR_BCAST): {
        if (d.payload.size() < sizeof(GlobalVarBroadcastPayload)) break;
        GlobalVarBroadcastPayload b{};
        std::memcpy(&b, d.payload.data(), sizeof(b));
        FW_LOG("net: GLOBAL_VAR_BCAST from %s — 0x%X = %g",
               b.peer_id.get().c_str(), b.global_form_id, b.value);
        // Direct memory write — safe from any thread with SEH cage.
        fw::engine::apply_global_var(
            b.global_form_id, static_cast<float>(b.value));
        break;
    }

    case static_cast<std::uint16_t>(MessageType::CONTAINER_OP_ACK): {
        if (d.payload.size() < sizeof(ContainerOpAckPayload)) break;
        ContainerOpAckPayload ack{};
        std::memcpy(&ack, d.payload.data(), sizeof(ack));
        std::shared_ptr<PendingOp> pending;
        {
            std::lock_guard lk(pending_ops_mutex_);
            auto it = pending_ops_.find(ack.client_op_id);
            if (it != pending_ops_.end()) pending = it->second;
        }
        if (pending) {
            {
                std::lock_guard pl(pending->mtx);
                pending->ack = ack;
                pending->ready = true;
            }
            pending->cv.notify_one();
        } else {
            // Late ACK (past timeout) or id=0 (fire-and-forget) — log and drop.
            FW_DBG("net: unmatched CONTAINER_OP_ACK op_id=%u status=%u",
                   ack.client_op_id, ack.status);
        }
        break;
    }

    case static_cast<std::uint16_t>(MessageType::CONTAINER_BCAST): {
        stats_.container_ops_received.fetch_add(1);
        if (d.payload.size() < sizeof(ContainerBroadcastPayload)) break;
        ContainerBroadcastPayload b{};
        std::memcpy(&b, d.payload.data(), sizeof(b));
        if (b.container_base_id == 0 || b.container_cell_id == 0) break;

        // Mirror update (shadow container state). Same as pre-B1.g.
        {
            std::lock_guard lk(container_mirror_mutex_);
            auto& bucket = container_mirror_[{b.container_base_id, b.container_cell_id}];
            const auto it = bucket.find(b.item_base_id);
            std::int32_t current = (it == bucket.end()) ? 0 : it->second;
            std::int32_t new_count = current;
            if (b.kind == static_cast<std::uint32_t>(ContainerOpKind::TAKE)) {
                new_count = (b.count >= current) ? 0 : (current - b.count);
            } else if (b.kind == static_cast<std::uint32_t>(ContainerOpKind::PUT)) {
                new_count = current + b.count;
            }
            if (new_count == 0) bucket.erase(b.item_base_id);
            else               bucket[b.item_base_id] = new_count;
        }

        // B1.l (replaces B1.g.2 hotfix): enqueue the op on the main-
        // thread dispatch queue instead of calling engine apply directly
        // from the net thread. The WndProc subclass installed by
        // main_menu_hook picks up the FW_MSG_CONTAINER_APPLY message
        // and drains the queue on the main thread, where the engine's
        // inventory mutation is safe (no race with ContainerMenu's
        // cached iterator state that caused B's inventory to be
        // destroyed in the B1.g live test).
        //
        // If container_form_id is missing (legacy/zero), we can't apply
        // (no way to resolve the local REFR); fall back to mirror-only.
        // If the dispatch HWND isn't set yet (pre-subclass boot), the
        // op is queued and flushed when main_menu_hook finishes its
        // subclass install.
        if (b.container_form_id != 0) {
            fw::dispatch::PendingContainerOp op{};
            op.kind               = b.kind;
            op.container_form_id  = b.container_form_id;
            op.container_base_id  = b.container_base_id;
            op.container_cell_id  = b.container_cell_id;
            op.item_base_id       = b.item_base_id;
            op.count              = b.count;
            fw::dispatch::enqueue_container_apply(op);
            FW_DBG("net: CONTAINER_BCAST enqueued for main-thread apply "
                   "peer=%s kind=%u cfid=0x%X base=0x%X cell=0x%X "
                   "item=0x%X count=%d",
                   b.peer_id.get().c_str(), b.kind,
                   b.container_form_id, b.container_base_id,
                   b.container_cell_id, b.item_base_id, b.count);
        } else {
            FW_DBG("net: CONTAINER_BCAST no container_form_id (legacy?) "
                   "peer=%s base=0x%X cell=0x%X — mirror-only",
                   b.peer_id.get().c_str(),
                   b.container_base_id, b.container_cell_id);
        }
        break;
    }

    case static_cast<std::uint16_t>(MessageType::DOOR_BCAST): {
        if (d.payload.size() < sizeof(DoorBroadcastPayload)) break;
        DoorBroadcastPayload b{};
        std::memcpy(&b, d.payload.data(), sizeof(b));
        if (b.door_form_id == 0 || b.door_base_id == 0) break;

        // Enqueue main-thread apply (same pattern as CONTAINER_BCAST).
        // Direct call from net thread would race with the engine's
        // animation-graph manager which lives on the main thread.
        fw::dispatch::PendingDoorOp op{};
        op.door_form_id  = b.door_form_id;
        op.door_base_id  = b.door_base_id;
        op.door_cell_id  = b.door_cell_id;
        fw::dispatch::enqueue_door_apply(op);
        FW_DBG("net: DOOR_BCAST enqueued for main-thread apply "
               "peer=%s form=0x%X base=0x%X cell=0x%X",
               b.peer_id.get().c_str(),
               b.door_form_id, b.door_base_id, b.door_cell_id);
        break;
    }

    case static_cast<std::uint16_t>(MessageType::WORLD_STATE): {
        if (d.payload.size() < sizeof(ChunkHeader)) break;
        ChunkHeader h{};
        std::memcpy(&h, d.payload.data(), sizeof(h));
        stats_.world_state_entries.fetch_add(h.num_entries);
        FW_LOG("net: WORLD_STATE chunk %u/%u  entries=%u",
               h.chunk_index + 1, h.total_chunks, h.num_entries);

        // Apply each entry via engine validated disable/enable.
        const std::size_t expected_size =
            sizeof(ChunkHeader) + h.num_entries * sizeof(WorldActorEntry);
        if (d.payload.size() < expected_size) break;

        const auto* entries = reinterpret_cast<const WorldActorEntry*>(
            d.payload.data() + sizeof(ChunkHeader));
        std::size_t applied = 0, skipped = 0;
        for (std::uint16_t i = 0; i < h.num_entries; ++i) {
            const auto& e = entries[i];
            if (e.base_id == 0 || e.cell_id == 0) { ++skipped; continue; }
            const bool disabled = (e.alive == 0);
            if (fw::engine::set_disabled_validated(
                    e.form_id, e.base_id, e.cell_id, disabled)) {
                ++applied;
            }
        }
        FW_LOG("net: WORLD_STATE applied=%zu skipped=%zu of %u",
               applied, skipped, h.num_entries);
        break;
    }

    case static_cast<std::uint16_t>(MessageType::CONTAINER_STATE): {
        if (d.payload.size() < sizeof(ChunkHeader)) break;
        ChunkHeader h{};
        std::memcpy(&h, d.payload.data(), sizeof(h));
        stats_.container_state_entries.fetch_add(h.num_entries);
        FW_LOG("net: CONTAINER_STATE chunk %u/%u  entries=%u",
               h.chunk_index + 1, h.total_chunks, h.num_entries);

        const std::size_t expected_size =
            sizeof(ChunkHeader) + h.num_entries * sizeof(ContainerStateEntry);
        if (d.payload.size() < expected_size) break;

        const auto* entries = reinterpret_cast<const ContainerStateEntry*>(
            d.payload.data() + sizeof(ChunkHeader));
        std::lock_guard lk(container_mirror_mutex_);
        for (std::uint16_t i = 0; i < h.num_entries; ++i) {
            const auto& e = entries[i];
            if (e.container_base_id == 0 || e.container_cell_id == 0) continue;
            auto& bucket = container_mirror_[{e.container_base_id, e.container_cell_id}];
            if (e.count > 0) bucket[e.item_base_id] = e.count;
            else             bucket.erase(e.item_base_id);
        }
        break;
    }

    case static_cast<std::uint16_t>(MessageType::PEER_JOIN): {
        if (d.payload.size() < sizeof(PeerJoinPayload)) break;
        PeerJoinPayload p{};
        std::memcpy(&p, d.payload.data(), sizeof(p));
        FW_LOG("net: peer joined: %s (sid=%u)", p.peer_id.get().c_str(), p.session_id);
        break;
    }

    case static_cast<std::uint16_t>(MessageType::PEER_LEAVE): {
        if (d.payload.size() < sizeof(PeerLeavePayload)) break;
        PeerLeavePayload p{};
        std::memcpy(&p, d.payload.data(), sizeof(p));
        FW_LOG("net: peer left: %s (reason=%u)", p.peer_id.get().c_str(), p.reason);
        break;
    }

    case static_cast<std::uint16_t>(MessageType::HEARTBEAT):
    case static_cast<std::uint16_t>(MessageType::CHAT):
        // not meaningful in B0.5; future blocks handle these
        break;

    default:
        FW_DBG("net: unhandled msg_type 0x%04X", d.header.msg_type);
        break;
    }
}

} // namespace fw::net
