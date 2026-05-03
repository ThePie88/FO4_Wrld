#include "client.h"

#include <windows.h>
#include <chrono>
#include <cstring>
#include <thread>

#include "../log.h"
#include "../engine/engine_calls.h"
#include "../ghost/actor_hijack.h"
#include "../hooks/container_hook.h"
#include "../hooks/equip_cycle.h"   // M9 v0.3.x: re-arm cycle on PEER_JOIN
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

void Client::enqueue_equip_op(std::uint32_t item_form_id,
                              std::uint8_t  kind,
                              std::uint32_t slot_form_id,
                              std::int32_t  count,
                              std::uint64_t timestamp_ms,
                              std::uint16_t effective_priority,
                              const EquipModRecord* mods,
                              std::uint8_t          mod_count,
                              const NifDescriptor*  nif_descs,
                              std::uint8_t          nif_count)
{
    if (!connected_.load() || stopping_.load()) return;
    if (item_form_id == 0) return;  // sender filters this too, defensive
    if (kind != static_cast<std::uint8_t>(EquipOpKind::EQUIP)
        && kind != static_cast<std::uint8_t>(EquipOpKind::UNEQUIP)) {
        // Out-of-band kind value — drop. Could be sender bug.
        return;
    }

    // Clamp mod_count to MAX_EQUIP_MODS (sanity: vanilla weapons ≤12 OMODs;
    // Far Harbor / Nuka World ≤20; 32 is generous).
    if (!mods) mod_count = 0;
    if (mod_count > MAX_EQUIP_MODS) mod_count = MAX_EQUIP_MODS;

    // Clamp nif_count to MAX_NIF_DESCRIPTORS. Witness pattern walks ≤8
    // descriptors typically (mods on a weapon).
    if (!nif_descs) nif_count = 0;
    if (nif_count > MAX_NIF_DESCRIPTORS) nif_count = MAX_NIF_DESCRIPTORS;

    EquipOpPayload p{};
    p.item_form_id       = item_form_id;
    p.kind               = kind;
    p.slot_form_id       = slot_form_id;
    p.count              = count;
    p.timestamp_ms       = timestamp_ms;
    p.effective_priority = effective_priority;  // v10

    // Compute upper bound on payload size:
    //   fixed (21) + u8 mod_count + N×8 + u8 nif_count + sum(per-desc max)
    // We over-allocate to a safe ceiling; encode_nif_descriptors handles
    // truncation if we'd ever exceed the actual remaining budget.
    std::size_t nif_max_bytes = 1; // u8 count
    for (std::uint8_t i = 0; i < nif_count; ++i) {
        nif_max_bytes += nif_descriptor_wire_size(nif_descs[i]);
    }
    const std::size_t fixed_part =
        sizeof(p) + 1 + (std::size_t)mod_count * sizeof(EquipModRecord);
    const std::size_t total_size = fixed_part + nif_max_bytes;

    QueuedSend q;
    q.msg_type = MessageType::EQUIP_OP;
    q.reliable = true;
    q.payload_bytes.resize(total_size);

    std::uint8_t* dst = q.payload_bytes.data();
    std::memcpy(dst, &p, sizeof(p));
    dst += sizeof(p);
    *dst++ = mod_count;
    if (mod_count > 0) {
        // Defensive: zero the pad byte of each record on serialize (engine
        // leaves byte +7 as uninitialised garbage at runtime).
        for (std::uint8_t i = 0; i < mod_count; ++i) {
            EquipModRecord rec = mods[i];
            rec.pad = 0;
            std::memcpy(dst, &rec, sizeof(rec));
            dst += sizeof(rec);
        }
    }

    // === v8: witness NIF descriptor tail ===
    const std::size_t consumed_so_far =
        static_cast<std::size_t>(dst - q.payload_bytes.data());
    const std::size_t nif_buf_remaining =
        q.payload_bytes.size() - consumed_so_far;
    const std::size_t nif_written = encode_nif_descriptors(
        dst, nif_buf_remaining, nif_descs, nif_count);
    // Final size = fixed bytes + actually-encoded NIF tail
    q.payload_bytes.resize(consumed_so_far + nif_written);

    {
        std::lock_guard lk(queue_mutex_);
        queue_.push_back(std::move(q));
    }
}

// M9.w4 v9 — sender side of MESH_BLOB chunked replication.
// Builds a single linear blob from `meshes`, splits it into 1388-byte
// chunks, enqueues each as a reliable MESH_BLOB_OP frame.
//
// Threading: caller (equip detour) holds source mesh memory alive for the
// duration of this call. We deep-copy into per-chunk QueuedSend buffers
// before returning.
std::size_t Client::enqueue_mesh_blob_for_equip(
    std::uint32_t item_form_id,
    const MeshBlobMesh* meshes,
    std::size_t num_meshes)
{
    if (!connected_.load() || stopping_.load()) return 0;
    if (!meshes || num_meshes == 0) return 0;
    if (item_form_id == 0) return 0;
    if (num_meshes > MAX_MESHES_PER_BLOB) {
        FW_WRN("[mesh-tx] num_meshes %zu > MAX_MESHES_PER_BLOB=%u — clamping",
               num_meshes,
               static_cast<unsigned>(MAX_MESHES_PER_BLOB));
        num_meshes = MAX_MESHES_PER_BLOB;
    }

    // Allocate a fresh per-equip sequence number (never 0).
    static std::atomic<std::uint32_t> s_next_equip_seq{1};
    std::uint32_t equip_seq = s_next_equip_seq.fetch_add(1, std::memory_order_relaxed);
    if (equip_seq == 0) equip_seq = s_next_equip_seq.fetch_add(1, std::memory_order_relaxed);

    // ---- Pass 1: compute total blob size up front so we can resize once.
    std::size_t blob_size = sizeof(MeshBlobHeader);
    for (std::size_t i = 0; i < num_meshes; ++i) {
        const auto& m = meshes[i];
        const std::size_t name_len = m.m_name ? std::strlen(m.m_name) : 0;
        const std::size_t parent_len = m.parent_placeholder ? std::strlen(m.parent_placeholder) : 0;
        const std::size_t bgsm_len = m.bgsm_path ? std::strlen(m.bgsm_path) : 0;
        if (name_len > 255 || parent_len > 255 || bgsm_len > 65535) {
            FW_WRN("[mesh-tx] mesh[%zu] string lengths exceed wire caps "
                   "(name=%zu parent=%zu bgsm=%zu) — dropping blob",
                   i, name_len, parent_len, bgsm_len);
            return 0;
        }
        if (m.tri_count > 0 && (m.tri_count > (0xFFFFFFFFu / 6))) {
            FW_WRN("[mesh-tx] mesh[%zu] tri_count %u absurd — dropping blob",
                   i, m.tri_count);
            return 0;
        }
        blob_size += sizeof(MeshRecordHeader);
        blob_size += name_len + parent_len + bgsm_len;
        blob_size += static_cast<std::size_t>(m.vert_count) * 3 * sizeof(float);
        blob_size += static_cast<std::size_t>(m.tri_count) * 3 * sizeof(std::uint16_t);
        if (blob_size > MAX_BLOB_SIZE) {
            FW_WRN("[mesh-tx] mesh[%zu] would push blob over MAX_BLOB_SIZE=%u "
                   "(blob_size=%zu) — dropping blob",
                   i, MAX_BLOB_SIZE, blob_size);
            return 0;
        }
    }

    // ---- Pass 2: serialize into a single linear buffer.
    std::vector<std::uint8_t> blob;
    blob.resize(blob_size);
    std::uint8_t* dst = blob.data();

    {
        MeshBlobHeader hdr{};
        hdr.item_form_id = item_form_id;
        hdr.equip_seq    = equip_seq;
        hdr.num_meshes   = static_cast<std::uint8_t>(num_meshes);
        hdr.reserved     = 0;
        std::memcpy(dst, &hdr, sizeof(hdr));
        dst += sizeof(hdr);
    }

    static constexpr float identity_xform[16] = {
        1.0f, 0.0f, 0.0f, 0.0f,
        0.0f, 1.0f, 0.0f, 0.0f,
        0.0f, 0.0f, 1.0f, 0.0f,
        0.0f, 0.0f, 0.0f, 1.0f,
    };

    for (std::size_t i = 0; i < num_meshes; ++i) {
        const auto& m = meshes[i];
        const std::size_t name_len = m.m_name ? std::strlen(m.m_name) : 0;
        const std::size_t parent_len = m.parent_placeholder ? std::strlen(m.parent_placeholder) : 0;
        const std::size_t bgsm_len = m.bgsm_path ? std::strlen(m.bgsm_path) : 0;

        MeshRecordHeader rh{};
        rh.m_name_len             = static_cast<std::uint8_t>(name_len);
        rh.parent_placeholder_len = static_cast<std::uint8_t>(parent_len);
        rh.bgsm_path_len          = static_cast<std::uint16_t>(bgsm_len);
        rh.vert_count             = m.vert_count;
        rh.reserved               = 0;
        rh.tri_count              = m.tri_count;
        const float* xform = m.local_transform ? m.local_transform : identity_xform;
        std::memcpy(rh.local_transform, xform, sizeof(rh.local_transform));
        std::memcpy(dst, &rh, sizeof(rh));
        dst += sizeof(rh);

        if (name_len)   { std::memcpy(dst, m.m_name, name_len); dst += name_len; }
        if (parent_len) { std::memcpy(dst, m.parent_placeholder, parent_len); dst += parent_len; }
        if (bgsm_len)   { std::memcpy(dst, m.bgsm_path, bgsm_len); dst += bgsm_len; }

        const std::size_t pos_bytes = static_cast<std::size_t>(m.vert_count) * 3 * sizeof(float);
        if (pos_bytes) {
            if (!m.positions) {
                FW_WRN("[mesh-tx] mesh[%zu] vc=%u but positions ptr null — dropping blob",
                       i, m.vert_count);
                return 0;
            }
            std::memcpy(dst, m.positions, pos_bytes);
            dst += pos_bytes;
        }
        const std::size_t idx_bytes = static_cast<std::size_t>(m.tri_count) * 3 * sizeof(std::uint16_t);
        if (idx_bytes) {
            if (!m.indices) {
                FW_WRN("[mesh-tx] mesh[%zu] tc=%u but indices ptr null — dropping blob",
                       i, m.tri_count);
                return 0;
            }
            std::memcpy(dst, m.indices, idx_bytes);
            dst += idx_bytes;
        }
    }

    // Sanity: dst should now equal blob.data() + blob_size.
    if (dst != blob.data() + blob_size) {
        FW_ERR("[mesh-tx] blob size mismatch: wrote %zu bytes, expected %zu",
               static_cast<std::size_t>(dst - blob.data()), blob_size);
        return 0;
    }

    // ---- Pass 3: split into chunks, enqueue each as MESH_BLOB_OP.
    //
    // CRITICAL: chunks must size for the SMALLER of {OP=1388, BCAST=1372}
    // because the server relays our OP chunks verbatim as BCAST (which has
    // 16-byte peer_id prefix overhead). If we size at OP_MAX=1388, the
    // BCAST encode raises ProtocolError(1388 > 1372) and the fan-out loop
    // explodes silently — peer never receives chunks. Bug observed
    // 2026-05-01 15:14 session: B sent 46 chunks at 1388 each, A's
    // [mesh-rx] never fired. Fix: use BCAST_MAX as the sender chunk size.
    // Cost: ~1.2% more chunks per blob (negligible).
    constexpr std::size_t chunk_data_max = MESH_BLOB_BCAST_CHUNK_DATA_MAX;  // 1372
    const std::size_t total_chunks_sz = (blob_size + chunk_data_max - 1) / chunk_data_max;
    if (total_chunks_sz == 0 || total_chunks_sz > 0xFFFF) {
        FW_WRN("[mesh-tx] total_chunks=%zu out of u16 range — dropping blob",
               total_chunks_sz);
        return 0;
    }
    const std::uint16_t total_chunks = static_cast<std::uint16_t>(total_chunks_sz);

    std::size_t enqueued = 0;
    {
        std::lock_guard lk(queue_mutex_);
        std::size_t off = 0;
        for (std::uint16_t ci = 0; ci < total_chunks; ++ci) {
            const std::size_t this_chunk = (blob_size - off) < chunk_data_max
                ? (blob_size - off) : chunk_data_max;

            QueuedSend q;
            q.msg_type = MessageType::MESH_BLOB_OP;
            q.reliable = true;
            q.payload_bytes.resize(sizeof(MeshBlobChunkHeader) + this_chunk);

            MeshBlobChunkHeader ch{};
            ch.equip_seq        = equip_seq;
            ch.total_blob_size  = static_cast<std::uint32_t>(blob_size);
            ch.chunk_index      = ci;
            ch.total_chunks     = total_chunks;
            std::memcpy(q.payload_bytes.data(), &ch, sizeof(ch));
            std::memcpy(q.payload_bytes.data() + sizeof(ch),
                        blob.data() + off, this_chunk);
            queue_.push_back(std::move(q));

            off += this_chunk;
            ++enqueued;
        }
    }

    FW_LOG("[mesh-tx] queued mesh blob: form=0x%X equip_seq=%u meshes=%zu "
           "blob=%zu B chunks=%u",
           item_form_id, equip_seq, num_meshes, blob_size,
           static_cast<unsigned>(total_chunks));
    return enqueued;
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

        // Legacy ghost_map path (B1) — DISABLED 2026-04-29.
        //   Was KEPT as dev-marker during custom-render-engine build-out:
        //   it hijacked a vanilla actor (default GHOST_TEMPLATE_FORM_ID =
        //   Codsworth 0x0001CA7D) by writing the remote peer's pos/rot
        //   directly into its TESObjectREFR fields, giving the user a
        //   visible (flickering — Havok fights the writes) anchor to
        //   see where peer A/B were physically in each other's world.
        //   Now disabled because the M8P3 custom ghost body + M9 clothing
        //   sync render the remote peer correctly on their own; the
        //   Codsworth marker became a confusing duplicate next to the
        //   real ghost. Kept as commented-out code (not deleted) in case
        //   we need to re-enable it for a future debugging session.
        //
        // if (cfg_.ghost_map_form_id != 0 && peer == cfg_.ghost_map_peer_id) {
        //     fw::engine::write_ghost_pos_rot(
        //         cfg_.ghost_map_form_id,
        //         p.x, p.y, p.z, p.rx, p.ry, p.rz);
        // }

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

    case static_cast<std::uint16_t>(MessageType::EQUIP_BCAST): {
        // M9 wedge 2 — apply equip event to peer's ghost body visually.
        // Pipeline: net thread (here) → enqueue PendingEquipOp →
        // PostMessage FW_MSG_EQUIP_APPLY → main thread WndProc drains
        // → fw::native::ghost_attach_armor / ghost_detach_armor.
        //
        // Direct call from net thread would race with the engine's
        // scene-graph mutations (NIF loader allocates BSFadeNode via
        // pool, attach_child mutates parent's child array — both
        // main-thread-affinity). Same pattern we use for CONTAINER_BCAST
        // (B1.l) and DOOR_BCAST (B6.1).
        //
        // Protocol v7 (M9.w4): the payload may have an OMOD tail after
        // the fixed 37-byte EquipBroadcastPayload — { u8 mod_count; N×8B
        // EquipModRecord }. We decode + log the mods here for wire-
        // verification. The actual apply on the ghost weapon is deferred
        // to iter 6 (Bridge-dispatch RE for receiver).
        if (d.payload.size() < sizeof(EquipBroadcastPayload)) break;
        EquipBroadcastPayload b{};
        std::memcpy(&b, d.payload.data(), sizeof(b));
        if (b.item_form_id == 0) break;

        const char* kind_str =
            (b.kind == static_cast<std::uint8_t>(EquipOpKind::EQUIP))   ? "EQUIP" :
            (b.kind == static_cast<std::uint8_t>(EquipOpKind::UNEQUIP)) ? "UNEQUIP" :
                                                                          "?";
        FW_LOG("[equip-rx] EQUIP_BCAST peer=%s %s item=0x%X slot=0x%X count=%d "
               "eff_prio=%u ts=%llu — enqueueing for main-thread apply",
               b.peer_id.get().c_str(),
               kind_str,
               b.item_form_id, b.slot_form_id, b.count,
               static_cast<unsigned>(b.effective_priority),
               static_cast<unsigned long long>(b.timestamp_ms));

        // === Protocol v7 OMOD-list tail (M9.w4) ===
        std::uint8_t mod_count = 0;
        const std::size_t tail_off = sizeof(EquipBroadcastPayload);
        if (d.payload.size() >= tail_off + 1) {
            mod_count = d.payload[tail_off];
            if (mod_count > MAX_EQUIP_MODS) mod_count = MAX_EQUIP_MODS;
            const std::size_t needed = tail_off + 1 +
                static_cast<std::size_t>(mod_count) * sizeof(EquipModRecord);
            if (d.payload.size() < needed) {
                FW_WRN("[equip-rx] EQUIP_BCAST tail truncated "
                       "(payload=%zu < needed=%zu, mod_count=%u) — drop tail",
                       d.payload.size(), needed,
                       static_cast<unsigned>(mod_count));
                mod_count = 0;
            }
        }
        if (mod_count > 0) {
            FW_LOG("[equip-rx]   peer=%s has %u OMOD attachments:",
                   b.peer_id.get().c_str(),
                   static_cast<unsigned>(mod_count));
            const auto* mods = reinterpret_cast<const EquipModRecord*>(
                d.payload.data() + tail_off + 1);
            for (std::uint8_t i = 0; i < mod_count; ++i) {
                FW_LOG("[equip-rx]     mod[%u] form=0x%X attach=%u rank=%u",
                       static_cast<unsigned>(i),
                       mods[i].form_id,
                       static_cast<unsigned>(mods[i].attach_index),
                       static_cast<unsigned>(mods[i].rank));
            }
        }
        // === end v7 tail ===

        // === Protocol v8 — witness NIF descriptor tail ===
        // After the OMOD tail (1 + mod_count*8 bytes from tail_off),
        // optionally a u8 nif_count + nif_count × variable-length records.
        std::uint8_t  nif_count = 0;
        NifDescriptor nif_descs[MAX_NIF_DESCRIPTORS]{};
        const std::size_t omod_total_size =
            1 + static_cast<std::size_t>(mod_count) * sizeof(EquipModRecord);
        const std::size_t nif_off = tail_off + omod_total_size;
        if (d.payload.size() > nif_off) {
            const std::size_t nif_remaining =
                d.payload.size() - nif_off;
            const std::size_t consumed = decode_nif_descriptors(
                d.payload.data() + nif_off,
                nif_remaining,
                nif_descs,
                nif_count);
            if (consumed == 0 && nif_remaining > 0) {
                FW_WRN("[equip-rx] EQUIP_BCAST v8 NIF tail malformed "
                       "(remaining=%zu) — drop tail",
                       nif_remaining);
                nif_count = 0;
            }
        }
        if (nif_count > 0) {
            FW_LOG("[equip-rx]   peer=%s has %u witness NIF descriptors:",
                   b.peer_id.get().c_str(),
                   static_cast<unsigned>(nif_count));
            for (std::uint8_t i = 0; i < nif_count; ++i) {
                const auto& nd = nif_descs[i];
                FW_LOG("[equip-rx]     nif[%u] parent='%s' path='%s' "
                       "trans=(%.2f,%.2f,%.2f) scale=%.3f",
                       static_cast<unsigned>(i),
                       nd.parent_name, nd.nif_path,
                       nd.local_transform[12],
                       nd.local_transform[13],
                       nd.local_transform[14],
                       nd.local_transform[15]);
            }
        }
        // === end v8 tail ===

        // Enqueue + PostMessage. Main-thread WndProc handler resolves
        // form_id → NIF path and attaches to ghost (or detaches on
        // UNEQUIP). See main_thread_dispatch.cpp::drain_equip_apply_queue.
        // PendingEquipOp now carries the v8 witness NIF descriptors so
        // the main-thread apply can attach mod NIFs on top of the base
        // weapon NIF.
        fw::dispatch::PendingEquipOp op{};
        const std::string peer = b.peer_id.get();
        const std::size_t pn = peer.size() < 15 ? peer.size() : 15;
        std::memcpy(op.peer_id, peer.data(), pn);
        op.peer_id[pn] = 0;
        op.item_form_id       = b.item_form_id;
        op.kind               = b.kind;
        op.slot_form_id       = b.slot_form_id;
        op.count              = b.count;
        op.effective_priority = b.effective_priority;  // v10
        op.nif_count          = nif_count;
        if (nif_count > 0) {
            std::memcpy(op.nif_descs, nif_descs,
                        nif_count * sizeof(NifDescriptor));
        }
        fw::dispatch::enqueue_equip_apply(op);
        break;
    }

    case static_cast<std::uint16_t>(MessageType::MESH_BLOB_OP):
    case static_cast<std::uint16_t>(MessageType::MESH_BLOB_BCAST): {
        // M9 w4 v9 — chunked mesh blob from a peer (BCAST) or echo of our
        // own send (OP, observed during loopback testing). Both share the
        // reassembly path; only the header + peer_id extraction differ.
        const bool is_bcast = (d.header.msg_type ==
            static_cast<std::uint16_t>(MessageType::MESH_BLOB_BCAST));
        const std::size_t hdr_size = is_bcast
            ? sizeof(MeshBlobChunkBroadcastHeader)
            : sizeof(MeshBlobChunkHeader);
        if (d.payload.size() < hdr_size) {
            FW_WRN("[mesh-rx] chunk frame too short: %zu < %zu",
                   d.payload.size(), hdr_size);
            break;
        }

        std::string peer_id_str;
        std::uint32_t equip_seq;
        std::uint32_t total_blob_size;
        std::uint16_t chunk_index;
        std::uint16_t total_chunks;
        const std::uint8_t* chunk_data;
        std::size_t chunk_data_len;

        if (is_bcast) {
            MeshBlobChunkBroadcastHeader h{};
            std::memcpy(&h, d.payload.data(), sizeof(h));
            peer_id_str = h.peer_id.get();
            equip_seq        = h.equip_seq;
            total_blob_size  = h.total_blob_size;
            chunk_index      = h.chunk_index;
            total_chunks     = h.total_chunks;
            chunk_data       = d.payload.data() + sizeof(h);
            chunk_data_len   = d.payload.size() - sizeof(h);
        } else {
            MeshBlobChunkHeader h{};
            std::memcpy(&h, d.payload.data(), sizeof(h));
            peer_id_str.clear();   // own send, no peer attribution
            equip_seq        = h.equip_seq;
            total_blob_size  = h.total_blob_size;
            chunk_index      = h.chunk_index;
            total_chunks     = h.total_chunks;
            chunk_data       = d.payload.data() + sizeof(h);
            chunk_data_len   = d.payload.size() - sizeof(h);
        }

        // Sanity / cap checks before allocating the buffer.
        if (total_blob_size == 0 || total_blob_size > MAX_BLOB_SIZE) {
            FW_WRN("[mesh-rx] chunk peer=%s equip_seq=%u total_blob_size=%u "
                   "out of range (cap %u) — dropping",
                   peer_id_str.c_str(), equip_seq,
                   total_blob_size, MAX_BLOB_SIZE);
            break;
        }
        if (total_chunks == 0 || chunk_index >= total_chunks) {
            FW_WRN("[mesh-rx] chunk peer=%s equip_seq=%u bogus indexing "
                   "ci=%u total=%u — dropping",
                   peer_id_str.c_str(), equip_seq,
                   static_cast<unsigned>(chunk_index),
                   static_cast<unsigned>(total_chunks));
            break;
        }
        // Per-chunk slice expected size — sender ALWAYS sizes chunks at
        // MESH_BLOB_BCAST_CHUNK_DATA_MAX (1372) regardless of whether they
        // ship as OP or BCAST, so the BCAST relay path doesn't overflow.
        // See enqueue_mesh_blob_for_equip "CRITICAL" comment.
        constexpr std::size_t SENDER_CHUNK_DATA_MAX = MESH_BLOB_BCAST_CHUNK_DATA_MAX;
        const std::size_t expected_slice = static_cast<std::size_t>(
            (chunk_index + 1u == total_chunks)
            ? (total_blob_size - static_cast<std::size_t>(chunk_index)
                                   * SENDER_CHUNK_DATA_MAX)
            : SENDER_CHUNK_DATA_MAX);
        if (chunk_data_len != expected_slice) {
            FW_WRN("[mesh-rx] peer=%s equip_seq=%u ci=%u/%u: chunk_data_len=%zu "
                   "expected=%zu — dropping",
                   peer_id_str.c_str(), equip_seq,
                   static_cast<unsigned>(chunk_index),
                   static_cast<unsigned>(total_chunks),
                   chunk_data_len, expected_slice);
            break;
        }

        // GC pass — drop any entries older than the reassembly timeout.
        const std::uint64_t now_ms = now_ms_wall();
        for (auto it = mesh_blob_reasm_.begin(); it != mesh_blob_reasm_.end(); ) {
            if (now_ms - it->second.first_chunk_at_ms
                    > MESH_BLOB_REASSEMBLY_TIMEOUT_MS) {
                FW_WRN("[mesh-rx] GC: dropping incomplete reassembly "
                       "peer=%s equip_seq=%u (received %u/%u chunks; aged %llu ms)",
                       it->first.peer_id.c_str(), it->first.equip_seq,
                       static_cast<unsigned>(it->second.received_count),
                       static_cast<unsigned>(it->second.total_chunks),
                       static_cast<unsigned long long>(
                           now_ms - it->second.first_chunk_at_ms));
                it = mesh_blob_reasm_.erase(it);
            } else {
                ++it;
            }
        }

        // Lookup or insert reassembly entry.
        MeshBlobReassemblyKey key{peer_id_str, equip_seq};
        auto [it, inserted] = mesh_blob_reasm_.try_emplace(key);
        auto& entry = it->second;
        if (inserted) {
            entry.total_blob_size = total_blob_size;
            entry.total_chunks    = total_chunks;
            entry.received_count  = 0;
            entry.buf.assign(total_blob_size, 0);
            entry.chunk_received.assign(total_chunks, 0);
            entry.first_chunk_at_ms = now_ms;
            FW_LOG("[mesh-rx] new reassembly peer=%s equip_seq=%u "
                   "blob=%u B chunks=%u",
                   peer_id_str.c_str(), equip_seq,
                   total_blob_size,
                   static_cast<unsigned>(total_chunks));
        } else {
            // Defensive: if any param differs across chunks (shouldn't,
            // but corruption is possible) → drop entry.
            if (entry.total_blob_size != total_blob_size
                || entry.total_chunks != total_chunks) {
                FW_WRN("[mesh-rx] mismatched chunk params for existing "
                       "key peer=%s equip_seq=%u (got blob=%u/%u chunks=%u/%u) "
                       "— dropping reassembly",
                       peer_id_str.c_str(), equip_seq,
                       total_blob_size, entry.total_blob_size,
                       static_cast<unsigned>(total_chunks),
                       static_cast<unsigned>(entry.total_chunks));
                mesh_blob_reasm_.erase(it);
                break;
            }
        }

        // If we already have this chunk, ignore (duplicate retransmit).
        if (entry.chunk_received[chunk_index]) {
            FW_DBG("[mesh-rx] duplicate chunk peer=%s equip_seq=%u ci=%u — ignored",
                   peer_id_str.c_str(), equip_seq,
                   static_cast<unsigned>(chunk_index));
            break;
        }

        // Compute write offset and copy slice. Sender uses SENDER_CHUNK_DATA_MAX
        // for the stride (see comment above) regardless of OP/BCAST type.
        const std::size_t off = static_cast<std::size_t>(chunk_index)
            * SENDER_CHUNK_DATA_MAX;
        if (off + chunk_data_len > entry.buf.size()) {
            FW_WRN("[mesh-rx] chunk overrun peer=%s equip_seq=%u ci=%u "
                   "off=%zu + len=%zu > buf=%zu — dropping reassembly",
                   peer_id_str.c_str(), equip_seq,
                   static_cast<unsigned>(chunk_index),
                   off, chunk_data_len, entry.buf.size());
            mesh_blob_reasm_.erase(it);
            break;
        }
        std::memcpy(entry.buf.data() + off, chunk_data, chunk_data_len);
        entry.chunk_received[chunk_index] = 1;
        ++entry.received_count;

        FW_DBG("[mesh-rx] chunk peer=%s equip_seq=%u ci=%u/%u stored "
               "(received %u/%u)",
               peer_id_str.c_str(), equip_seq,
               static_cast<unsigned>(chunk_index),
               static_cast<unsigned>(total_chunks),
               static_cast<unsigned>(entry.received_count),
               static_cast<unsigned>(entry.total_chunks));

        // Completion: all chunks received → decode + dispatch to main thread.
        if (entry.received_count == entry.total_chunks) {
            // Move buf out before erasing entry.
            std::vector<std::uint8_t> blob = std::move(entry.buf);
            mesh_blob_reasm_.erase(it);

            // Decode the blob.
            if (blob.size() < sizeof(MeshBlobHeader)) {
                FW_WRN("[mesh-rx] decoded blob too small: %zu < %zu",
                       blob.size(), sizeof(MeshBlobHeader));
                break;
            }
            MeshBlobHeader bh{};
            std::memcpy(&bh, blob.data(), sizeof(bh));
            if (bh.equip_seq != equip_seq) {
                FW_WRN("[mesh-rx] blob header equip_seq=%u != chunk equip_seq=%u",
                       bh.equip_seq, equip_seq);
            }
            if (bh.num_meshes == 0 || bh.num_meshes > MAX_MESHES_PER_BLOB) {
                FW_WRN("[mesh-rx] blob num_meshes=%u out of range",
                       static_cast<unsigned>(bh.num_meshes));
                break;
            }

            fw::dispatch::PendingMeshBlob pop{};
            const std::size_t pn = peer_id_str.size() < 15 ? peer_id_str.size() : 15;
            std::memcpy(pop.peer_id, peer_id_str.data(), pn);
            pop.peer_id[pn]  = 0;
            pop.item_form_id = bh.item_form_id;
            pop.equip_seq    = bh.equip_seq;

            // Walk per-mesh records.
            std::size_t roff = sizeof(MeshBlobHeader);
            bool decode_ok = true;
            for (std::uint8_t mi = 0; mi < bh.num_meshes; ++mi) {
                if (roff + sizeof(MeshRecordHeader) > blob.size()) {
                    FW_WRN("[mesh-rx] mesh[%u] header truncated at off=%zu "
                           "(blob size %zu)",
                           static_cast<unsigned>(mi), roff, blob.size());
                    decode_ok = false; break;
                }
                MeshRecordHeader rh{};
                std::memcpy(&rh, blob.data() + roff, sizeof(rh));
                roff += sizeof(rh);

                const std::size_t name_len   = rh.m_name_len;
                const std::size_t parent_len = rh.parent_placeholder_len;
                const std::size_t bgsm_len   = rh.bgsm_path_len;
                const std::size_t pos_bytes  =
                    static_cast<std::size_t>(rh.vert_count) * 3 * sizeof(float);
                const std::size_t idx_bytes  =
                    static_cast<std::size_t>(rh.tri_count) * 3 * sizeof(std::uint16_t);
                const std::size_t need = name_len + parent_len + bgsm_len
                                       + pos_bytes + idx_bytes;
                if (roff + need > blob.size()) {
                    FW_WRN("[mesh-rx] mesh[%u] body truncated: roff=%zu "
                           "need=%zu have=%zu",
                           static_cast<unsigned>(mi), roff, need,
                           blob.size() - roff);
                    decode_ok = false; break;
                }

                fw::dispatch::PendingMeshRecord rec;
                rec.m_name.assign(reinterpret_cast<const char*>(
                    blob.data() + roff), name_len);
                roff += name_len;
                rec.parent_placeholder.assign(reinterpret_cast<const char*>(
                    blob.data() + roff), parent_len);
                roff += parent_len;
                rec.bgsm_path.assign(reinterpret_cast<const char*>(
                    blob.data() + roff), bgsm_len);
                roff += bgsm_len;
                rec.vert_count = rh.vert_count;
                rec.tri_count  = rh.tri_count;
                std::memcpy(rec.local_transform, rh.local_transform,
                            sizeof(rec.local_transform));
                if (pos_bytes > 0) {
                    rec.positions.resize(static_cast<std::size_t>(rh.vert_count) * 3);
                    std::memcpy(rec.positions.data(), blob.data() + roff, pos_bytes);
                    roff += pos_bytes;
                }
                if (idx_bytes > 0) {
                    rec.indices.resize(static_cast<std::size_t>(rh.tri_count) * 3);
                    std::memcpy(rec.indices.data(), blob.data() + roff, idx_bytes);
                    roff += idx_bytes;
                }
                pop.meshes.push_back(std::move(rec));
            }

            if (decode_ok) {
                FW_LOG("[mesh-rx] reassembled+decoded peer=%s form=0x%X "
                       "equip_seq=%u meshes=%zu blob=%zu B → dispatch to main",
                       peer_id_str.c_str(),
                       pop.item_form_id, pop.equip_seq,
                       pop.meshes.size(), blob.size());
                fw::dispatch::enqueue_mesh_blob_apply(std::move(pop));
            } else {
                FW_WRN("[mesh-rx] decode FAILED peer=%s equip_seq=%u — drop",
                       peer_id_str.c_str(), equip_seq);
            }
        }
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
        FW_LOG("net: peer joined: %s (sid=%u) — re-arming equip cycle to "
               "re-broadcast our current equipment state to the new peer",
               p.peer_id.get().c_str(), p.session_id);

        // M9 v0.3.x — boot-timing race fix.
        //
        // Problem: at boot, the equip cycle (B8) UNEQUIP+EQUIP fires once
        // ~10s post-LoadGame. If no peer is connected yet, the EQUIP
        // broadcast goes nowhere. When peer B joins 5 minutes later, B's
        // ghost-of-A is rendered without clothing because B never
        // received A's equipment state.
        //
        // Fix: every time ANY peer joins, re-fire our cycle with a short
        // delay. The new peer (and any others) receive the EQUIP_BCAST
        // and apply via wedge 2 receiver pipeline. Cost: 2s of "no
        // clothing → re-equip" flicker on the LOCAL player every time
        // someone connects (acceptable trade for visual sync correctness).
        //
        // Delay: 1500ms — short because we're already in-world (no
        // engine startup state to wait for) but still gives a small
        // buffer in case the just-joined peer's ghost spawn / WELCOME
        // exchange takes a moment.
        fw::hooks::arm_equip_cycle_for_peer_join(1500);
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
