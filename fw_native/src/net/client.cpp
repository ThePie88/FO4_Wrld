#include "client.h"

#include <windows.h>
#include <chrono>
#include <cmath>
#include <cstring>
#include <mutex>
#include <thread>
#include <tuple>
#include <unordered_map>

#include "../log.h"
#include "../engine/engine_calls.h"
#include "../ghost/actor_hijack.h"
#include "../hooks/container_hook.h"
#include "../steam/steam_id.h"      // B6.6w5: local Steam ID for HELLO auth scaffolding
#include "../hooks/equip_cycle.h"   // M9 v0.3.x: re-arm cycle on PEER_JOIN
#include "../hooks/npc_ai_suppress.h" // B6.5w4: suppress/passthrough counters
#include "../hooks/ownership_manager.h" // Build 65: NPC owner-driven sync
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

void Client::enqueue_pose_crouch_state(const PoseCrouchEntry* entries,
                                       std::size_t count,
                                       std::uint64_t header_ts_ms)
{
    if (!connected_.load() || stopping_.load()) return;
    if (count > MAX_POSE_CROUCH_BONES) count = MAX_POSE_CROUCH_BONES;

    QueuedSend q;
    q.msg_type = MessageType::POSE_CROUCH_STATE;
    q.reliable = false;
    const std::size_t total = sizeof(PoseCrouchStateHeader)
                            + count * sizeof(PoseCrouchEntry);
    q.payload_bytes.resize(total);

    PoseCrouchStateHeader hdr{};
    hdr.timestamp_ms = header_ts_ms;
    hdr.count        = static_cast<std::uint8_t>(count);
    std::memcpy(q.payload_bytes.data(), &hdr, sizeof(hdr));
    if (count > 0 && entries != nullptr) {
        std::memcpy(q.payload_bytes.data() + sizeof(hdr),
                    entries, count * sizeof(PoseCrouchEntry));
    }
    {
        std::lock_guard lk(queue_mutex_);
        queue_.push_back(std::move(q));
    }
}

void Client::enqueue_npc_pose_state(std::uint32_t form_id,
                                    std::uint64_t header_ts_ms,
                                    const PoseBoneEntry* bones,
                                    std::size_t bone_count)
{
    if (!connected_.load() || stopping_.load()) return;
    if (bone_count > MAX_POSE_BONES) bone_count = MAX_POSE_BONES;

    QueuedSend q;
    q.msg_type = MessageType::NPC_POSE_FROM_OWNER;
    q.reliable = false;
    const std::size_t total = sizeof(NpcPoseHeader)
                            + bone_count * sizeof(PoseBoneEntry);
    q.payload_bytes.resize(total);

    NpcPoseHeader hdr{};
    hdr.form_id      = form_id;
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

void Client::enqueue_npc_crouch(std::uint32_t form_id,
                                const PoseCrouchEntry* entries,
                                std::size_t count,
                                std::uint64_t header_ts_ms)
{
    if (!connected_.load() || stopping_.load()) return;
    if (count > MAX_POSE_CROUCH_BONES) count = MAX_POSE_CROUCH_BONES;

    QueuedSend q;
    q.msg_type = MessageType::NPC_CROUCH_FROM_OWNER;
    q.reliable = false;
    const std::size_t total = sizeof(NpcCrouchHeader)
                            + count * sizeof(PoseCrouchEntry);
    q.payload_bytes.resize(total);

    NpcCrouchHeader hdr{};
    hdr.form_id      = form_id;
    hdr.timestamp_ms = header_ts_ms;
    hdr.count        = static_cast<std::uint8_t>(count);
    std::memcpy(q.payload_bytes.data(), &hdr, sizeof(hdr));
    if (count > 0 && entries != nullptr) {
        std::memcpy(q.payload_bytes.data() + sizeof(hdr),
                    entries, count * sizeof(PoseCrouchEntry));
    }
    {
        std::lock_guard lk(queue_mutex_);
        queue_.push_back(std::move(q));
    }
}

void Client::enqueue_npc_damage_claim(std::uint32_t form_id, float amount,
                                      float max_hp) {
    if (!connected_.load() || stopping_.load()) return;
    if (form_id == 0 || form_id == 0xFFFFFFFFu || amount <= 0.0f) return;

    // Accumulate per fid; flush at most ~6 Hz/fid (batch rapid-fire hits).
    // N3 (v17): also carry the latest max_hp so the server can bootstrap the
    // shared HP pool. max_hp is ~constant per raider; keep the freshest > 0.
    float to_send = 0.0f;
    float to_send_max = 0.0f;
    {
        using namespace std::chrono;
        const std::uint64_t now = duration_cast<milliseconds>(
            steady_clock::now().time_since_epoch()).count();
        struct DmgAccum { float sum; std::uint64_t last_ms; float max_hp; };
        static std::mutex s_dmg_mtx;
        static std::unordered_map<std::uint32_t, DmgAccum> s_accum;
        std::lock_guard lk(s_dmg_mtx);
        auto& e = s_accum[form_id];          // {sum, last_send_ms, max_hp}, zero-init
        e.sum += amount;
        if (max_hp > 0.0f) e.max_hp = max_hp;
        if (now - e.last_ms >= 160ULL) {     // ~6 Hz/fid; first hit sends now
            to_send = e.sum;
            to_send_max = e.max_hp;
            e.sum = 0.0f;
            e.last_ms = now;
        }
    }
    if (to_send <= 0.0f) return;

    QueuedSend q;
    q.msg_type = MessageType::NPC_DAMAGE_CLAIM;
    q.reliable = false;
    NpcDamageClaim p{ form_id, to_send, to_send_max };
    q.payload_bytes.resize(sizeof(p));
    std::memcpy(q.payload_bytes.data(), &p, sizeof(p));
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

void Client::enqueue_lock_op(std::uint32_t lock_form_id,
                             std::uint32_t lock_base_id,
                             std::uint32_t lock_cell_id,
                             bool          locked,
                             std::uint64_t timestamp_ms)
{
    if (!connected_.load() || stopping_.load()) return;
    if (lock_form_id == 0 || lock_base_id == 0) return;

    LockOpPayload p{};
    p.lock_form_id  = lock_form_id;
    p.lock_base_id  = lock_base_id;
    p.lock_cell_id  = lock_cell_id;
    p.locked        = locked ? std::uint8_t{1} : std::uint8_t{0};
    p.timestamp_ms  = timestamp_ms;

    QueuedSend q;
    q.msg_type = MessageType::LOCK_OP;
    q.reliable = true;
    q.payload_bytes.resize(sizeof(p));
    std::memcpy(q.payload_bytes.data(), &p, sizeof(p));
    {
        std::lock_guard lk(queue_mutex_);
        queue_.push_back(std::move(q));
    }
}

void Client::enqueue_peer_ghost_register(std::uint32_t ghost_form_id) {
    if (!connected_.load() || stopping_.load()) return;
    if (ghost_form_id == 0 || ghost_form_id == 0xFFFFFFFFu) return;

    PeerGhostRegisterPayload p{};
    p.ghost_form_id = ghost_form_id;

    QueuedSend q;
    q.msg_type = MessageType::PEER_GHOST_REGISTER;
    q.reliable = true;
    q.payload_bytes.resize(sizeof(p));
    std::memcpy(q.payload_bytes.data(), &p, sizeof(p));
    {
        std::lock_guard lk(queue_mutex_);
        queue_.push_back(std::move(q));
    }
}

void Client::enqueue_npc_discover(std::uint32_t form_id,
                                  std::uint32_t base_id,
                                  std::uint32_t cell_id,
                                  float pos_x, float pos_y, float pos_z)
{
    if (!connected_.load() || stopping_.load()) return;
    if (form_id == 0 || form_id == 0xFFFFFFFFu || form_id == 0x14u) return;

    NPCDiscoverPayload p{};
    p.form_id = form_id;
    p.base_id = base_id;
    p.cell_id = cell_id;
    p.pos_x   = pos_x;
    p.pos_y   = pos_y;
    p.pos_z   = pos_z;

    QueuedSend q;
    q.msg_type = MessageType::NPC_DISCOVER;
    q.reliable = true;
    q.payload_bytes.resize(sizeof(p));
    std::memcpy(q.payload_bytes.data(), &p, sizeof(p));
    {
        std::lock_guard lk(queue_mutex_);
        queue_.push_back(std::move(q));
    }
}

// === Build 65 — owner-driven TX entry points ==============================

void Client::enqueue_npc_observed(std::uint32_t form_id,
                                  std::uint32_t base_id,
                                  std::uint32_t cell_id,
                                  float pos_x, float pos_y, float pos_z,
                                  float observer_distance_sq)
{
    if (!connected_.load() || stopping_.load()) return;
    if (form_id == 0 || form_id == 0xFFFFFFFFu || form_id == 0x14u) return;

    NPCObservedPayload p{};
    p.form_id              = form_id;
    p.base_id              = base_id;
    p.cell_id              = cell_id;
    p.pos_x                = pos_x;
    p.pos_y                = pos_y;
    p.pos_z                = pos_z;
    p.observer_distance_sq = observer_distance_sq;

    QueuedSend q;
    q.msg_type = MessageType::NPC_OBSERVED;
    q.reliable = true;
    q.payload_bytes.resize(sizeof(p));
    std::memcpy(q.payload_bytes.data(), &p, sizeof(p));
    {
        std::lock_guard lk(queue_mutex_);
        queue_.push_back(std::move(q));
    }
}

void Client::enqueue_npc_owner_heartbeat(
    const NPCOwnerHeartbeatEntry* entries, std::size_t count)
{
    if (!connected_.load() || stopping_.load()) return;
    if (entries == nullptr || count == 0) return;
    if (count > MAX_HEARTBEAT_ENTRIES) count = MAX_HEARTBEAT_ENTRIES;

    // Wire: u16 num + u16 reserved + N * NPCOwnerHeartbeatEntry.
    NPCOwnerHeartbeatHeader hdr{};
    hdr.num_entries = static_cast<std::uint16_t>(count);
    hdr.reserved    = 0;

    QueuedSend q;
    q.msg_type = MessageType::NPC_OWNER_HEARTBEAT;
    q.reliable = false;
    q.payload_bytes.resize(sizeof(hdr) + count * sizeof(*entries));
    std::memcpy(q.payload_bytes.data(), &hdr, sizeof(hdr));
    std::memcpy(q.payload_bytes.data() + sizeof(hdr),
                entries, count * sizeof(*entries));
    {
        std::lock_guard lk(queue_mutex_);
        queue_.push_back(std::move(q));
    }
}

void Client::enqueue_npc_state_from_owner(
    const NPCOwnerStateEntry* entries, std::size_t count)
{
    if (!connected_.load() || stopping_.load()) return;
    if (entries == nullptr || count == 0) return;
    if (count > MAX_OWNER_STATES_PER_FRAME) count = MAX_OWNER_STATES_PER_FRAME;

    NPCStateFromOwnerHeader hdr{};
    hdr.num_entries = static_cast<std::uint16_t>(count);
    hdr.reserved    = 0;

    QueuedSend q;
    q.msg_type = MessageType::NPC_STATE_FROM_OWNER;
    q.reliable = false;
    q.payload_bytes.resize(sizeof(hdr) + count * sizeof(*entries));
    std::memcpy(q.payload_bytes.data(), &hdr, sizeof(hdr));
    std::memcpy(q.payload_bytes.data() + sizeof(hdr),
                entries, count * sizeof(*entries));
    {
        std::lock_guard lk(queue_mutex_);
        queue_.push_back(std::move(q));
    }
}

void Client::enqueue_npc_fire_from_owner(const NPCFireFromOwnerPayload& p)
{
    if (!connected_.load() || stopping_.load()) return;
    if (p.form_id == 0 || p.form_id == 0xFFFFFFFFu) return;

    QueuedSend q;
    q.msg_type = MessageType::NPC_FIRE_FROM_OWNER;
    q.reliable = false;   // event-driven cosmetic; one dropped frame =
                          // one missed muzzle flash, not a desync.
    q.payload_bytes.resize(sizeof(p));
    std::memcpy(q.payload_bytes.data(), &p, sizeof(p));
    {
        std::lock_guard lk(queue_mutex_);
        queue_.push_back(std::move(q));
    }
}

void Client::enqueue_npc_death_from_owner(const NPCDeathFromOwnerPayload& p)
{
    if (!connected_.load() || stopping_.load()) return;
    if (p.form_id == 0 || p.form_id == 0xFFFFFFFFu) return;

    QueuedSend q;
    q.msg_type = MessageType::NPC_DEATH_FROM_OWNER;
    q.reliable = true;    // Build 65.c.47 WEDGE3 — death MUST arrive: a dropped
                          // death leaves a live mirror of a dead-on-owner entity
                          // → @0xC0F510 use-after-free when it's shot.
    q.payload_bytes.resize(sizeof(p));
    std::memcpy(q.payload_bytes.data(), &p, sizeof(p));
    {
        std::lock_guard lk(queue_mutex_);
        queue_.push_back(std::move(q));
    }
}

// Build 65.c.23 — FNV-1a 32-bit (matches Python `fnv1a_hash` used server-
// side for peer_id hashing). Constants per RFC: offset=2166136261,
// prime=16777619. Loop over raw bytes.
static std::uint32_t fnv1a_32(const std::string& s) noexcept {
    std::uint32_t h = 0x811C9DC5u;
    for (char c : s) {
        h ^= static_cast<std::uint8_t>(c);
        h *= 0x01000193u;
    }
    return h;
}

bool Client::enqueue_engagement_claim_dedup(std::uint32_t form_id)
{
    if (!connected_.load() || stopping_.load()) return false;
    if (form_id == 0 || form_id == 0xFFFFFFFFu) return false;
    if (form_id == 0x00000014u) return false;   // never claim on player

    // Per-fid dedup: 2s cooldown. The npc_ai_suppress detour runs at the
    // engine's Update_PerFrame rate (~60 Hz per tracked actor) and reads
    // the InCombat bit on every fire. Without dedup we'd flood the
    // server with ~60 Hz × N raiders claims — Hz-scale waste.
    //
    // 2s strikes the balance: long enough to not flood, short enough
    // to react to "owner just stopped engaging, I should take over"
    // within one ENGAGEMENT_OWNERSHIP_GRACE_MS window (= 3s, server-side).
    static std::mutex                                  s_dedup_mtx;
    static std::unordered_map<std::uint32_t, std::uint64_t> s_last_sent_ms;
    constexpr std::uint64_t kClaimCooldownMs = 2000;

    const auto now_ms = static_cast<std::uint64_t>(GetTickCount64());
    {
        std::lock_guard lk(s_dedup_mtx);
        auto it = s_last_sent_ms.find(form_id);
        if (it != s_last_sent_ms.end() &&
            now_ms - it->second < kClaimCooldownMs)
        {
            return false;
        }
        s_last_sent_ms[form_id] = now_ms;
    }

    NPCEngagementClaimPayload p{};
    p.form_id      = form_id;
    p.peer_id_hash = fnv1a_32(cfg_.client_id);
    p.ts_ms        = now_ms;

    QueuedSend q;
    q.msg_type = MessageType::NPC_ENGAGEMENT_CLAIM;
    q.reliable = false;   // ~1 claim per 2s per fid; loss is fine — the
                          // next fire that re-passes the 2s window
                          // triggers a resend, and InCombat persists as
                          // long as the engine sees a target.
    q.payload_bytes.resize(sizeof(p));
    std::memcpy(q.payload_bytes.data(), &p, sizeof(p));
    {
        std::lock_guard lk(queue_mutex_);
        queue_.push_back(std::move(q));
    }

    static std::atomic<std::uint64_t> g_claims_sent{0};
    const auto n = g_claims_sent.fetch_add(1, std::memory_order_relaxed);
    if (n < 20 || (n % 200) == 0) {
        FW_LOG("net: NPC_ENGAGEMENT_CLAIM tx #%llu fid=0x%08X "
               "peer_hash=0x%08X (Build 65.c.23 combat-driven handoff)",
               static_cast<unsigned long long>(n), form_id,
               p.peer_id_hash);
    }
    return true;
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
        const std::size_t slot_len = m.slot_name ? std::strlen(m.slot_name) : 0;
        const std::size_t bgsm_len = m.bgsm_path ? std::strlen(m.bgsm_path) : 0;
        if (name_len > 255 || parent_len > 255 || slot_len > 65535 || bgsm_len > 65535) {
            FW_WRN("[mesh-tx] mesh[%zu] string lengths exceed wire caps "
                   "(name=%zu parent=%zu slot=%zu bgsm=%zu) — dropping blob",
                   i, name_len, parent_len, slot_len, bgsm_len);
            return 0;
        }
        if (m.tri_count > 0 && (m.tri_count > (0xFFFFFFFFu / 6))) {
            FW_WRN("[mesh-tx] mesh[%zu] tri_count %u absurd — dropping blob",
                   i, m.tri_count);
            return 0;
        }
        blob_size += sizeof(MeshRecordHeader);
        blob_size += name_len + parent_len + slot_len + bgsm_len;
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
        const std::size_t slot_len = m.slot_name ? std::strlen(m.slot_name) : 0;
        const std::size_t bgsm_len = m.bgsm_path ? std::strlen(m.bgsm_path) : 0;

        MeshRecordHeader rh{};
        rh.m_name_len             = static_cast<std::uint8_t>(name_len);
        rh.parent_placeholder_len = static_cast<std::uint8_t>(parent_len);
        rh.bgsm_path_len          = static_cast<std::uint16_t>(bgsm_len);
        rh.vert_count             = m.vert_count;
        rh.slot_name_len          = static_cast<std::uint16_t>(slot_len);
        rh.tri_count              = m.tri_count;
        const float* xform = m.local_transform ? m.local_transform : identity_xform;
        std::memcpy(rh.local_transform, xform, sizeof(rh.local_transform));
        std::memcpy(dst, &rh, sizeof(rh));
        dst += sizeof(rh);

        // Variable section. Order matches MeshRecordHeader comment block:
        // m_name → parent_placeholder → slot_name → bgsm_path → positions → indices.
        if (name_len)   { std::memcpy(dst, m.m_name, name_len); dst += name_len; }
        if (parent_len) { std::memcpy(dst, m.parent_placeholder, parent_len); dst += parent_len; }
        if (slot_len)   { std::memcpy(dst, m.slot_name, slot_len); dst += slot_len; }
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

// 2026-05-06 LATE evening (M9 closure, PLAN B) — ship a serialized NIF
// blob via the same MESH_BLOB_OP wire path. Encoding piggybacks on the
// existing MeshBlobHeader: num_meshes=0xFF is a sentinel meaning "the
// payload after the header is a raw NIF byte buffer, not per-mesh
// records". Receiver detects the sentinel in
// drain_mesh_blob_apply_queue and routes to nistream_deserialize +
// attach instead of the per-mesh attach path.
//
// Reuses the chunking + reassembly infrastructure (no new packet type
// needed), maintains backward compat with old senders/receivers (they
// see num_meshes=0xFF and either skip or interpret garbage as 255 mesh
// records — sanity checks elsewhere will reject).
std::size_t Client::enqueue_nif_blob_for_equip(
    std::uint32_t item_form_id,
    const void*   nif_buf,
    std::size_t   nif_size)
{
    if (!connected_.load() || stopping_.load()) return 0;
    if (!nif_buf || nif_size == 0) return 0;
    if (item_form_id == 0) return 0;

    static std::atomic<std::uint32_t> s_next_equip_seq{0x80000000u};
    std::uint32_t equip_seq = s_next_equip_seq.fetch_add(1,
        std::memory_order_relaxed);
    if (equip_seq == 0) {
        equip_seq = s_next_equip_seq.fetch_add(1, std::memory_order_relaxed);
    }

    const std::size_t blob_size = sizeof(MeshBlobHeader) + nif_size;
    if (blob_size > MAX_BLOB_SIZE) {
        FW_WRN("[nif-tx] blob_size=%zu > MAX_BLOB_SIZE=%u — dropping",
               blob_size, MAX_BLOB_SIZE);
        return 0;
    }

    std::vector<std::uint8_t> blob;
    blob.resize(blob_size);
    {
        MeshBlobHeader hdr{};
        hdr.item_form_id = item_form_id;
        hdr.equip_seq    = equip_seq;
        hdr.num_meshes   = 0xFF;  // sentinel: raw NIF buffer follows
        hdr.reserved     = 0;
        std::memcpy(blob.data(), &hdr, sizeof(hdr));
        std::memcpy(blob.data() + sizeof(hdr), nif_buf, nif_size);
    }

    constexpr std::size_t chunk_data_max = MESH_BLOB_BCAST_CHUNK_DATA_MAX;
    const std::size_t total_chunks_sz =
        (blob_size + chunk_data_max - 1) / chunk_data_max;
    if (total_chunks_sz == 0 || total_chunks_sz > 0xFFFF) {
        FW_WRN("[nif-tx] total_chunks=%zu out of range", total_chunks_sz);
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

    FW_LOG("[nif-tx] queued NIF blob: form=0x%X equip_seq=%u nif_bytes=%zu "
           "total_blob=%zu chunks=%u",
           item_form_id, equip_seq, nif_size, blob_size,
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
    // B6.6w5 — local Steam ID (real Steam returns user's account ID;
    // Goldberg emulator returns the configured ID from steam_settings/).
    // 0 = unavailable (steam_api64.dll not loaded by host process yet).
    h.steam_id = fw::steam::get_local_steam_id();
    FW_LOG("net: HELLO with client_id='%s' steam_id=%llu (0x%llX)",
           cfg_.client_id.c_str(),
           static_cast<unsigned long long>(h.steam_id),
           static_cast<unsigned long long>(h.steam_id));

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
            // Build 65 — once the server has accepted us, hand our
            // canonical peer_id to the ownership manager so PHASE_2
            // payloads can be compared byte-for-byte against the
            // 16 B FixedClientId encoding the server uses on the wire.
            fw::ownership::set_local_peer_id(cfg_.client_id);
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

        // -------- 5.b Build 65 — owner-driven periodic emit ----------
        // Internally rate-limited (HEARTBEAT 2 Hz, STATE 10 Hz).
        // Cheap when ownership map is empty (no allocations).
        fw::ownership::tick_periodic(now_ms_wall());

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
            // B6.5w4 diagnostic: dump AI suppression hook counters + tracked
            // set size. If suppress=0 → hook isn't matching any tracked
            // form_id (registration bug or wrong hook RVA). If passthrough
            // grows but NPCs still wander → AI source is elsewhere.
            FW_LOG("npc-ai: tracked=%zu  suppress_fires=%llu  passthrough_fires=%llu  "
                   "seh_failures=%llu",
                   fw::dispatch::tracked_npc_count(),
                   static_cast<unsigned long long>(
                       fw::hooks::get_npc_ai_suppress_fires()),
                   static_cast<unsigned long long>(
                       fw::hooks::get_npc_ai_passthrough_fires()),
                   static_cast<unsigned long long>(
                       fw::hooks::get_npc_ai_seh_failures()));
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

    // v16 — ghost crouch. SEPARATE additive channel beside POSE_BROADCAST.
    // Server relays a peer's COM/Pelvis local translations; stash + post
    // FW_MSG_STRADAB_CROUCH_APPLY so the main thread lowers the ghost body.
    case static_cast<std::uint16_t>(MessageType::POSE_CROUCH_BROADCAST): {
        if (d.payload.size() < sizeof(PoseCrouchBroadcastHeader)) break;
        PoseCrouchBroadcastHeader hdr{};
        std::memcpy(&hdr, d.payload.data(), sizeof(hdr));
        if (hdr.count > MAX_POSE_CROUCH_BONES) break;
        const std::size_t need = sizeof(hdr)
                                 + hdr.count * sizeof(PoseCrouchEntry);
        if (d.payload.size() < need) break;
        const PoseCrouchEntry* entries = reinterpret_cast<const PoseCrouchEntry*>(
            d.payload.data() + sizeof(hdr));
        fw::native::store_remote_crouch(hdr.timestamp_ms, entries, hdr.count);
        break;
    }

    // c.37.0 — full NPC pose replication. Server relays the owner's
    // per-bone snapshot for one NPC (keyed by form_id). Stash into a
    // per-fid slot + post WM_APP; main thread drives the mirror Actor.
    case static_cast<std::uint16_t>(MessageType::NPC_POSE_FROM_OWNER): {
        { static std::atomic<std::uint64_t> s_d{0};
          const auto dc = s_d.fetch_add(1, std::memory_order_relaxed);
          if (dc < 10 || (dc % 200) == 0)
            FW_LOG("[npc-pose-net] DISPATCH recv payloadsz=%zu hdr=%zu",
                   d.payload.size(), sizeof(NpcPoseHeader)); }
        if (d.payload.size() < sizeof(NpcPoseHeader)) break;
        NpcPoseHeader hdr{};
        std::memcpy(&hdr, d.payload.data(), sizeof(hdr));
        if (hdr.bone_count > MAX_POSE_BONES) break;
        const std::size_t need = sizeof(hdr)
                                 + hdr.bone_count * sizeof(PoseBoneEntry);
        if (d.payload.size() < need) break;
        const PoseBoneEntry* bones = reinterpret_cast<const PoseBoneEntry*>(
            d.payload.data() + sizeof(hdr));
        fw::native::store_remote_npc_pose(
            hdr.form_id, hdr.timestamp_ms, bones, hdr.bone_count);
        break;
    }

    // NPC crouch — owner's COM/Pelvis translation for one NPC (keyed by
    // form_id). NO separate window message (unlike the ghost crouch): the
    // apply happens in the 60 Hz post-orig drive (apply_npc_pose_to_actor),
    // so we just stash into the per-fid cache here.
    case static_cast<std::uint16_t>(MessageType::NPC_CROUCH_FROM_OWNER): {
        if (d.payload.size() < sizeof(NpcCrouchHeader)) break;
        NpcCrouchHeader hdr{};
        std::memcpy(&hdr, d.payload.data(), sizeof(hdr));
        if (hdr.count > MAX_POSE_CROUCH_BONES) break;
        const std::size_t need = sizeof(hdr)
                                 + hdr.count * sizeof(PoseCrouchEntry);
        if (d.payload.size() < need) break;
        const PoseCrouchEntry* entries = reinterpret_cast<const PoseCrouchEntry*>(
            d.payload.data() + sizeof(hdr));
        fw::native::store_npc_crouch(hdr.form_id, entries, hdr.count);
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
            remote_snapshot_.cell_id        = p.cell_id;   // v11 — B6 prologue
        }

        // M3.1 event-driven cube tracking (Strada B): post WM_APP+0x46 to
        // the main window so the injected cube's local.translate updates
        // to the fresh remote pos within 1 frame. No-op if no cube
        // injected yet or WndProc not subclassed.
        fw::native::notify_remote_pos_changed();

        // B6.6w5 Build 9 — sync the engine-native ghost duplicate's pos
        // to the peer's pos. The duplicate is invisible to engine
        // iteration (no ProcessLists, no cell list); its only consumer
        // is raider AI reading combat_target.pos for aim. Pure field
        // write — safe from net thread. No-op until duplicate is spawned
        // (post-T+30s body inject piggyback).
        fw::engine::apply_ghost_pos(p.x, p.y, p.z);

        // B6.6w5 Build 5 — spawn trigger MOVED to scene_inject's
        // on_inject_message. The POS_BROADCAST path triggered spawn the
        // moment the player's parentCell became non-null, which happens
        // MID-LoadGame (the engine populates parentCell before finishing
        // the cell-attach + autosave sweep). Spawning then registered the
        // ghost into a transient world state and the engine crashed ~7s
        // later (Build 3 live test 2026-05-13 01:57).
        //
        // The body renderer's inject path already implements the right
        // timing (arm_worker 30s grace + local_player_in_world() check +
        // remote snapshot poll). Tying our engine-native spawn to the
        // same event guarantees the engine is fully stable when we run
        // the PlayerCharacter ctor. See scene_inject.cpp on_inject_message.
        //
        // fw::ghost::request_spawn();  // disabled — see comment above
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

    case static_cast<std::uint16_t>(MessageType::LOCK_BCAST): {
        if (d.payload.size() < sizeof(LockBroadcastPayload)) break;
        LockBroadcastPayload b{};
        std::memcpy(&b, d.payload.data(), sizeof(b));
        if (b.lock_form_id == 0 || b.lock_base_id == 0) break;

        fw::dispatch::PendingLockOp op{};
        op.lock_form_id  = b.lock_form_id;
        op.lock_base_id  = b.lock_base_id;
        op.lock_cell_id  = b.lock_cell_id;
        op.locked        = b.locked ? std::uint8_t{1} : std::uint8_t{0};
        fw::dispatch::enqueue_lock_apply(op);
        FW_DBG("net: LOCK_BCAST enqueued for main-thread apply "
               "peer=%s form=0x%X base=0x%X cell=0x%X locked=%u",
               b.peer_id.get().c_str(),
               b.lock_form_id, b.lock_base_id, b.lock_cell_id,
               static_cast<unsigned>(b.locked));
        break;
    }

    case static_cast<std::uint16_t>(MessageType::NPC_STATE_BCAST): {
        // B6.5w3.b — decode + enqueue all entries. The main thread
        // (WndProc dispatcher) drains and applies each via
        // engine::apply_npc_state_to_engine.
        //
        // Server emits at 10 Hz × N tracked NPCs; we trim each frame
        // into ≤ MAX_NPC_STATES_PER_FRAME entries and push them all
        // in one mutex acquisition + one PostMessage.
        if (d.payload.size() < sizeof(NPCStateBroadcastHeader)) break;
        NPCStateBroadcastHeader hdr{};
        std::memcpy(&hdr, d.payload.data(), sizeof(hdr));
        if (hdr.num_entries == 0) break;
        if (hdr.num_entries > MAX_NPC_STATES_PER_FRAME) {
            FW_DBG("net: NPC_STATE_BCAST count=%u > MAX=%u — drop",
                   static_cast<unsigned>(hdr.num_entries),
                   static_cast<unsigned>(MAX_NPC_STATES_PER_FRAME));
            break;
        }
        const std::size_t need =
            sizeof(hdr) +
            static_cast<std::size_t>(hdr.num_entries) * sizeof(NPCStateEntry);
        if (d.payload.size() < need) {
            FW_DBG("net: NPC_STATE_BCAST truncated need=%zu got=%zu",
                   need, d.payload.size());
            break;
        }

        // B6.5w12 deprecation: the OLD per-BCAST apply pipeline
        // (enqueue → PostMessage FW_MSG_NPC_STATE_APPLY → drain →
        // apply_npc_state_to_engine writing pos/yaw/anim onto Actor) is
        // CLOSED. It was the third write path of the rounds 1-11 output-
        // override approach; missed during the initial deprecation pass
        // (only scene_render_hook and npc_ai_suppress detour bodies were
        // commented). With it still active, every 10 Hz BCAST teleported
        // the actor to the server's pos field — and since the server
        // hasn't been rewritten yet to broadcast meaningful pos for
        // companion-class NPCs (Codsworth/Dogmeat use script-driven AI,
        // not package selector), the BCAST pos was effectively a static
        // spawn-point, causing the actor to flicker between its local AI
        // pose and the server's stale snapshot.
        //
        // Ghost AI does NOT apply pos via per-BCAST writes. Pos changes
        // come from the engine's natural movement integration after our
        // hook on Actor::TickMovementController (Phase 4) substitutes
        // velocity. Until that hook lands, tracked NPCs simply move via
        // vanilla AI — same as untracked NPCs. The cache is still kept
        // updated below for the Ghost AI hooks that consume v14 fields
        // (package_form_id is wired now; combat target / aim / velocity
        // / anim states wire in subsequent phases).
        const std::uint8_t* p = d.payload.data() + sizeof(hdr);
        std::vector<fw::dispatch::PendingNPCStateEntry> to_apply;
        to_apply.reserve(hdr.num_entries);
        for (std::uint16_t i = 0; i < hdr.num_entries; ++i) {
            NPCStateEntry wire{};
            std::memcpy(&wire, p + i * sizeof(NPCStateEntry), sizeof(wire));
            // B6.6w0 (2026-05-12): `movement_override` now derives from
            // `flags` bit 1 (= is_raider_tracked) which the server sets
            // unconditionally for every raider registered in
            // `raider_brain`.
            const std::uint8_t mov_override =
                (wire.flags & 0x02) ? 1u : 0u;
            fw::dispatch::update_npc_cache(
                wire.form_id,
                wire.pos_x, wire.pos_y, wire.pos_z,
                wire.yaw, wire.anim_state,
                wire.package_form_id,
                wire.combat_target_form_id,
                wire.velocity_x, wire.velocity_y, wire.velocity_z,
                mov_override);
            // B6.6w5 — enqueue pos apply for tracked NPCs.
            //
            // Guards:
            //   1. SKIP (0,0,0) sentinel — JSON entries without verified
            //      coords; broadcasting/applying these teleports raiders
            //      to origin and they "disappear".
            //   2. Dedup against cached previous pos — if server's pos
            //      for this fid matches what we already applied (within
            //      1 unit per axis), skip enqueue. Avoids 10Hz cell-
            //      tracking churn inside vt[202] which displaces raiders.
            //
            // Build 12 (Fix 1) — orthogonal combat_target enqueue. Even
            // when pos isn't apply-ready (deduped, sentinel, or
            // movement_override clear), if the server has a combat_target
            // opinion (combat_target_form_id != 0) we still enqueue so
            // the main-thread drain applies it via engine SetCombatTarget.
            std::uint8_t apply_flags = 0;
            if (mov_override != 0 && wire.form_id != 0) {
                const bool is_zero_sentinel =
                    wire.pos_x == 0.0f && wire.pos_y == 0.0f &&
                    wire.pos_z == 0.0f;
                if (!is_zero_sentinel) {
                    // Per-fid last-applied memo to dedup repeats.
                    static std::mutex s_last_applied_mtx;
                    static std::unordered_map<
                        std::uint32_t,
                        std::tuple<float, float, float>>
                        s_last_applied;
                    bool should_apply = false;
                    {
                        std::lock_guard lk(s_last_applied_mtx);
                        const auto it = s_last_applied.find(wire.form_id);
                        if (it == s_last_applied.end()) {
                            should_apply = true;
                        } else {
                            const auto& [lx, ly, lz] = it->second;
                            const float dx = std::abs(wire.pos_x - lx);
                            const float dy = std::abs(wire.pos_y - ly);
                            const float dz = std::abs(wire.pos_z - lz);
                            if (dx > 1.0f || dy > 1.0f || dz > 1.0f) {
                                should_apply = true;
                            }
                        }
                        if (should_apply) {
                            s_last_applied[wire.form_id] = {
                                wire.pos_x, wire.pos_y, wire.pos_z};
                        }
                    }
                    if (should_apply) {
                        apply_flags |= 0x01;  // bit 0 = apply pos
                    }
                }
            }
            // Build 64 (2026-05-25) — combat_target apply BUILD64_DISABLED.
            //
            // Under the MVP-A strategy (re/BUILD64_strategy/STRATEGY.md)
            // each client runs vanilla engine AI for combat. Server's
            // combat_target_form_id field stays in the cache (might be
            // read by future hooks for telemetry) but we never call
            // engine::apply_npc_combat_target from the BCAST path.
            //
            // Previous behavior (Build 12+): set apply_flags |= 0x02
            // when server had a non-zero target, drain calls
            // SetCombatTarget on the engine. That path is part of the
            // cross-peer aggro experiment that the 13 builds (62.x → 63)
            // proved architecturally unstable. Removing the trigger
            // here is belt-and-braces — the engine fn pointer call site
            // in drain_npc_state_apply_queue is also commented out.
            (void)0;  // apply_flags |= 0x02 intentionally skipped
            if (apply_flags != 0) {
                fw::dispatch::PendingNPCStateEntry pe{};
                pe.form_id               = wire.form_id;
                pe.pos_x                 = wire.pos_x;
                pe.pos_y                 = wire.pos_y;
                pe.pos_z                 = wire.pos_z;
                pe.yaw_deg_math          = wire.yaw;
                pe.anim_state            = wire.anim_state;
                pe.combat_target_form_id = wire.combat_target_form_id;
                pe.apply_flags           = apply_flags;
                to_apply.push_back(pe);
            }
        }
        if (!to_apply.empty()) {
            fw::dispatch::enqueue_npc_state_apply(to_apply);
        }
        // Spot-check log of the first entry — useful for confirming the
        // pipeline is live without spamming at 10 Hz.
        if (hdr.num_entries > 0) {
            NPCStateEntry first{};
            std::memcpy(&first, p, sizeof(first));
            FW_DBG("net: NPC_STATE_BCAST count=%u first formid=0x%X pos=(%.1f,%.1f,%.1f) "
                   "yaw=%.2f anim=%u pkg=0x%X — cache updated, no per-BCAST apply",
                   static_cast<unsigned>(hdr.num_entries),
                   first.form_id,
                   first.pos_x, first.pos_y, first.pos_z,
                   first.yaw,
                   static_cast<unsigned>(first.anim_state),
                   first.package_form_id);
        }
        break;
    }

    case static_cast<std::uint16_t>(MessageType::NPC_FIRE): {
        // B6.6w1 — server-driven shoot. Server raider_brain decided this
        // raider should fire NOW (cooldown elapsed + target in range +
        // line of sight). Both peers receive the same message, look up
        // their local Actor* for raider_form_id, and trigger
        // engine::fire_actor_weapon → projectile + muzzle flash + audio
        // + damage. Visuals stay in sync because the same event fires
        // on both clients.
        if (d.payload.size() < sizeof(NPCFirePayload)) {
            FW_DBG("net: NPC_FIRE undersized payload=%zu < %zu",
                   d.payload.size(), sizeof(NPCFirePayload));
            break;
        }
        NPCFirePayload pay{};
        std::memcpy(&pay, d.payload.data(), sizeof(pay));
        if (pay.raider_form_id == 0 || pay.raider_form_id == 0xFFFFFFFFu) {
            FW_DBG("net: NPC_FIRE invalid raider_form_id=0x%X — drop",
                   pay.raider_form_id);
            break;
        }
        FW_DBG("net: NPC_FIRE raider=0x%X target=0x%X flags=0x%X kind=%u "
               "— enqueueing",
               pay.raider_form_id, pay.target_form_id, pay.flags,
               static_cast<unsigned>(pay.target_kind));
        fw::dispatch::PendingNPCFire op{
            pay.raider_form_id,
            pay.target_form_id,
            pay.flags,
            pay.target_kind,
        };
        fw::dispatch::enqueue_npc_fire(op);
        break;
    }

    case static_cast<std::uint16_t>(MessageType::NPC_PERCEPTION_TRIGGER): {
        // Build 62 (2026-05-24) — sphere-proximity perception trigger.
        //
        // Per re/arena_synthesis/SUPERVISOR_SYNTHESIS.md: server's
        // proximity-sphere check fired this when ghost.pos entered NPC's
        // perception range. Receiver invokes engine sub_140CCF810
        // (Actor::EnterCombat) which allocates HighProcess +
        // CombatController + AddTarget natively in 1 frame.
        //
        // Wire payload: 8 bytes (npc_fid u32, peer_id u32 hashed).
        // The peer_id field is hash(peer_id_string) at server side. On
        // each client, we compare against hash(local_peer_id) to decide
        // if target is the LOCAL PC or the OTHER peer's ghost duplicate.
        if (d.payload.size() < sizeof(NpcPerceptionTriggerPayload)) {
            FW_DBG("net: NPC_PERCEPTION_TRIGGER undersized payload=%zu < %zu",
                   d.payload.size(), sizeof(NpcPerceptionTriggerPayload));
            break;
        }
        NpcPerceptionTriggerPayload pay{};
        std::memcpy(&pay, d.payload.data(), sizeof(pay));
        if (pay.npc_fid == 0 || pay.npc_fid == 0xFFFFFFFFu) {
            FW_DBG("net: NPC_PERCEPTION_TRIGGER invalid npc_fid=0x%X — drop",
                   pay.npc_fid);
            break;
        }
        FW_DBG("net: NPC_PERCEPTION_TRIGGER npc_fid=0x%X peer_id_hash=0x%X "
               "— enqueueing for main-thread dispatch",
               pay.npc_fid, pay.peer_id);
        fw::dispatch::PendingNPCPerceptionTrigger op{
            pay.npc_fid,
            pay.peer_id,
        };
        fw::dispatch::enqueue_npc_perception_trigger(op);
        break;
    }

    // === Build 65 — owner-driven NPC sync RX handlers =====================
    //
    // Phase A scope (Build 65.c): the DLL only mirrors server-pushed
    // ownership state into `fw::ownership` and parses/validates the new
    // payload classes. No engine behavior change yet — the predicate flip
    // that lets non-owners stop running vanilla AI lands in 65.d together
    // with the dead-hook cleanup.
    //
    // For state/fire/death/damage relays we drop entries whose epoch
    // doesn't match our local view (catches stale post-handoff packets).

    case static_cast<std::uint16_t>(MessageType::NPC_OWNERSHIP_BCAST): {
        if (d.payload.size() < sizeof(NPCOwnershipBcastHeader)) {
            FW_DBG("net: NPC_OWNERSHIP_BCAST truncated hdr (%zu)",
                   d.payload.size());
            break;
        }
        NPCOwnershipBcastHeader hdr{};
        std::memcpy(&hdr, d.payload.data(), sizeof(hdr));
        const std::size_t expected =
            sizeof(hdr) + std::size_t(hdr.num_entries) * sizeof(NPCOwnershipBcastEntry);
        if (d.payload.size() < expected) {
            FW_DBG("net: NPC_OWNERSHIP_BCAST truncated body got=%zu want=%zu",
                   d.payload.size(), expected);
            break;
        }
        if (hdr.num_entries > MAX_OWNERSHIP_BCAST_ENTRIES) {
            FW_WRN("net: NPC_OWNERSHIP_BCAST count=%u > max %u — clamp",
                   hdr.num_entries, MAX_OWNERSHIP_BCAST_ENTRIES);
        }
        const auto count = std::min<std::uint16_t>(
            hdr.num_entries, MAX_OWNERSHIP_BCAST_ENTRIES);
        const auto* entries = reinterpret_cast<const NPCOwnershipBcastEntry*>(
            d.payload.data() + sizeof(hdr));
        fw::ownership::on_bcast(entries, count);
        break;
    }

    case static_cast<std::uint16_t>(MessageType::NPC_OWNERSHIP_HANDOFF_PHASE_2): {
        if (d.payload.size() < sizeof(NPCOwnershipHandoffPhase2Payload)) {
            FW_DBG("net: PHASE_2 undersized payload=%zu", d.payload.size());
            break;
        }
        NPCOwnershipHandoffPhase2Payload pay{};
        std::memcpy(&pay, d.payload.data(), sizeof(pay));
        fw::ownership::on_phase2(pay);
        break;
    }

    case static_cast<std::uint16_t>(MessageType::NPC_OWNERSHIP_HANDOFF_PHASE_1): {
        // Phase A: server never emits this. Log if it ever appears so we
        // notice when Phase B (full two-phase handoff) ships.
        FW_DBG("net: PHASE_1 received (Phase A no-op) size=%zu",
               d.payload.size());
        break;
    }

    case static_cast<std::uint16_t>(MessageType::NPC_OWNERSHIP_RELEASE_ACK): {
        // Phase A: client never emits this (server too). Silent drop.
        break;
    }

    case static_cast<std::uint16_t>(MessageType::NPC_STATE_FROM_OWNER): {
        // Owner-authoritative state batch relayed by server. Receiver
        // applies each entry whose epoch matches the local view. The
        // actual engine-side apply (vt[202] pos write, anim graph vars,
        // etc.) lands in 65.c.2; here we parse + epoch-gate + count.
        if (d.payload.size() < sizeof(NPCStateFromOwnerHeader)) {
            FW_DBG("net: NPC_STATE_FROM_OWNER truncated hdr (%zu)",
                   d.payload.size());
            break;
        }
        NPCStateFromOwnerHeader hdr{};
        std::memcpy(&hdr, d.payload.data(), sizeof(hdr));
        const std::size_t expected =
            sizeof(hdr) + std::size_t(hdr.num_entries) * sizeof(NPCOwnerStateEntry);
        if (d.payload.size() < expected) {
            FW_DBG("net: NPC_STATE_FROM_OWNER truncated body got=%zu want=%zu",
                   d.payload.size(), expected);
            break;
        }
        if (hdr.num_entries > MAX_OWNER_STATES_PER_FRAME) {
            FW_WRN("net: NPC_STATE_FROM_OWNER count=%u > max %u",
                   hdr.num_entries, MAX_OWNER_STATES_PER_FRAME);
        }
        const auto count = std::min<std::uint16_t>(
            hdr.num_entries, MAX_OWNER_STATES_PER_FRAME);
        const auto* entries = reinterpret_cast<const NPCOwnerStateEntry*>(
            d.payload.data() + sizeof(hdr));

        // Build 65.c.10 — collect valid entries and enqueue them for
        // main-thread apply via engine::apply_npc_pos. Anim/aim/velocity
        // capture deferred — pos write alone is enough to stop the
        // "raider stuck at last engine pos" symptom on non-owner peers.
        std::vector<fw::dispatch::PendingNPCOwnerState> apply_batch;
        apply_batch.reserve(count);
        for (std::uint16_t i = 0; i < count; ++i) {
            const auto& e = entries[i];
            std::uint32_t local_epoch = 0;
            if (!fw::ownership::epoch_for(e.form_id, &local_epoch)) {
                // We don't know about this NPC yet — skip (we'll catch
                // up via PHASE_2 / BCAST bootstrap on the next tick).
                continue;
            }
            if (e.epoch != local_epoch) {
                // Stale owner state — server should have dropped it but
                // belt-and-braces here too.
                continue;
            }
            if (fw::ownership::is_owner_of(e.form_id)) {
                // Defence in depth: server already filters owner self-
                // relay, but during handoff transients we might receive
                // one of our own packets bounced back. Drop silently.
                continue;
            }
            fw::dispatch::PendingNPCOwnerState p{};
            p.form_id    = e.form_id;
            p.epoch      = e.epoch;
            p.pos_x      = e.pos_x;
            p.pos_y      = e.pos_y;
            p.pos_z      = e.pos_z;
            p.yaw_rad    = e.yaw_rad;       // Build 65.c.14
            p.anim_state = e.anim_state;    // Build 65.c.18
            apply_batch.push_back(p);
        }
        if (!apply_batch.empty()) {
            fw::dispatch::enqueue_npc_owner_state_apply(apply_batch);
        }
        break;
    }

    case static_cast<std::uint16_t>(MessageType::NPC_FIRE_FROM_OWNER): {
        if (d.payload.size() < sizeof(NPCFireFromOwnerPayload)) {
            FW_DBG("net: NPC_FIRE_FROM_OWNER undersized (%zu)", d.payload.size());
            break;
        }
        NPCFireFromOwnerPayload pay{};
        std::memcpy(&pay, d.payload.data(), sizeof(pay));
        std::uint32_t local_epoch = 0;
        if (!fw::ownership::epoch_for(pay.form_id, &local_epoch)) {
            FW_DBG("ownership: FIRE for unknown fid=0x%X — drop", pay.form_id);
            break;
        }
        if (fw::ownership::is_owner_of(pay.form_id)) {
            // Defence-in-depth: server should already filter owner self-
            // relay, but a handoff transient could leak one packet back.
            // Don't double-fire on the authority side.
            break;
        }
        // Build 65.c.16 — dispatch to main thread, replay the shot via
        // engine::fire_actor_weapon. Reuse the existing PendingNPCFire
        // queue + drain (Build 60-era, well-tested) so we don't ship a
        // new dispatch lane for a single new opcode.
        FW_DBG("ownership: FIRE fid=0x%X target=0x%X aim=(%.1f,%.1f,%.1f)",
               pay.form_id, pay.target_form_id,
               pay.aim_x, pay.aim_y, pay.aim_z);
        fw::dispatch::PendingNPCFire op{};
        op.raider_form_id = pay.form_id;
        op.target_form_id = pay.target_form_id;
        op.flags          = 0;
        // Build 65.c.27 — FIX target_kind LOCAL → GHOST.
        //
        // We reach this branch only when `!is_owner_of(pay.form_id)` (the
        // owner self-relay guard above already returned). So WE are the
        // NON-OWNER of this raider. The owner's raider is attacking the
        // OWNER's local player. On OUR screen that player is rendered by
        // the local ghost proxy. Therefore the muzzle flash + projectile
        // must point at the GHOST, not at our local player.
        //
        // Pre-c.27 this was hardcoded LOCAL → drain_npc_fire_queue's
        // `target_kind==LOCAL` branch SKIPPED the puppet-fire entirely
        // (expecting OUR vanilla AI to fire the raider at us). But the
        // raider is a non-owner puppet here — its vanilla fire is bailed
        // (ghost_ai_fire) and its aim is overridden by the owner's yaw via
        // c.23 INTERP-APPLY. So LOCAL meant "nobody fires" → the shots A
        // emitted never rendered on B (confirmed c.26 forensics: B logged
        // `kind=LOCAL — skipping puppet`, A's 10 OWNER-EMITs lost).
        //
        // GHOST routes to `npc_fire_with_ghost_aim(refr)` which spawns the
        // muzzle flash + projectile toward get_ghost_actor()'s position =
        // exactly where the owner's player is rendered locally. Bidirectional
        // by construction: A-owned raider fires at ghost_A on B; B-owned
        // raider fires at ghost_B on A.
        op.target_kind    = NPC_FIRE_TARGET_GHOST;
        fw::dispatch::enqueue_npc_fire(op);
        break;
    }

    case static_cast<std::uint16_t>(MessageType::NPC_DEATH_FROM_OWNER): {
        if (d.payload.size() < sizeof(NPCDeathFromOwnerPayload)) {
            FW_DBG("net: NPC_DEATH_FROM_OWNER undersized (%zu)", d.payload.size());
            break;
        }
        NPCDeathFromOwnerPayload pay{};
        std::memcpy(&pay, d.payload.data(), sizeof(pay));

        // Build 65.c.47 WEDGE3 — corpse the local mirror so there's never a
        // live mirror of a dead-on-owner entity to shoot (= the @0xC0F510
        // use-after-free root cause). The server only relays this to NON-
        // OWNERS (main.py:1422), and we WERE the non-owner at kill time. We
        // do NOT add the FIRE-path owner self-relay guard here: a death is
        // sticky/idempotent (drain dedups via killed_fids), so even if a
        // handoff transient delivered one packet to a peer who just became
        // owner, the worst case is a harmless idempotent corpse — strictly
        // safer than risking a missed death (which is the crash).
        FW_LOG("ownership: DEATH fid=0x%X killer=0x%X pos=(%.1f,%.1f,%.1f) dmg=%.1f hz=%u",
               pay.form_id, pay.killer_form_id,
               pay.pos_x, pay.pos_y, pay.pos_z, pay.damage,
               static_cast<unsigned>(pay.hit_zone));

        // Dispatch to the main thread: lookup → mark_dying → un-keyframe →
        // place at synced pos → engine Actor::Kill (under ApplyingRemoteGuard).
        // Engine death handler is main-thread-affine (cell/anim/Havok).
        fw::dispatch::PendingNPCDeath dop{};
        dop.form_id        = pay.form_id;
        dop.killer_form_id = pay.killer_form_id;
        dop.pos_x          = pay.pos_x;
        dop.pos_y          = pay.pos_y;
        dop.pos_z          = pay.pos_z;
        fw::dispatch::enqueue_npc_death_apply(dop);
        break;
    }

    case static_cast<std::uint16_t>(MessageType::NPC_DAMAGE_FROM_OWNER): {
        if (d.payload.size() < sizeof(NPCDamageFromOwnerPayload)) {
            FW_DBG("net: NPC_DAMAGE_FROM_OWNER undersized (%zu)", d.payload.size());
            break;
        }
        NPCDamageFromOwnerPayload pay{};
        std::memcpy(&pay, d.payload.data(), sizeof(pay));
        // Pure cosmetic — 65.c.2 will dispatch to engine::play_hit_react.
        FW_DBG("ownership: DAMAGE fid=0x%X attacker=0x%X wpn=0x%X dmg=%.1f",
               pay.form_id, pay.attacker_form_id,
               pay.weapon_form_id, pay.damage);
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

        // 2026-05-07 — STASH ONLY ON EQUIP. The engine fires UNEQUIP for
        // the previously-held weapon RIGHT after EQUIP of the new one,
        // and that UNEQUIP carries 0 mods. If we let UNEQUIP wipe the
        // stash (as we did pre-fix), drain_equip_apply_queue's snapshot
        // sees count=0 and the name-match path attaches a stock weapon.
        // Live test 2026-05-07 06:26:51.606..608 captured exactly this:
        //   set 6 forms (EQUIP modded)
        //   set 0 forms (UNEQUIP previous, wipe!)
        //   set 0 forms (another UNEQUIP, wipe!)
        //   [name-match] attached=0/0
        //
        // Now: only EQUIP touches the stash. UNEQUIP leaves it alone —
        // ghost_clear_weapon doesn't need it (it works from form_id).
        // When the peer re-equips, the new EQUIP overwrites with the
        // correct mods. Edge case: peer goes from modded → stock weapon
        // is handled because the new EQUIP ships mod_count=0, which
        // we explicitly clear (still gated on EQUIP).
        const bool is_equip = (b.kind ==
            static_cast<std::uint8_t>(EquipOpKind::EQUIP));
        if (is_equip) {
            std::uint32_t form_ids[32]{};
            const std::uint8_t copy_n = mod_count > 32
                ? static_cast<std::uint8_t>(32) : mod_count;
            for (std::uint8_t i = 0; i < copy_n; ++i) {
                const auto* mods = reinterpret_cast<const EquipModRecord*>(
                    d.payload.data() + tail_off + 1);
                form_ids[i] = mods[i].form_id;
            }
            fw::native::set_peer_omod_forms(
                b.peer_id.get().c_str(),
                copy_n > 0 ? form_ids : nullptr, copy_n);
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

        // 2026-05-07 — embed OMOD form_ids INLINE in the op. Removes the
        // race where a refresh fires 500ms later, by which time the
        // global stash (set_peer_omod_forms) has been overwritten by a
        // SUBSEQUENT equip event for a different weapon. Capture once
        // here, no global lookup at apply time.
        op.omod_count = mod_count;
        if (mod_count > 0) {
            const auto* mods = reinterpret_cast<const EquipModRecord*>(
                d.payload.data() + tail_off + 1);
            const std::uint8_t copy_n = mod_count > 32
                ? static_cast<std::uint8_t>(32) : mod_count;
            for (std::uint8_t i = 0; i < copy_n; ++i) {
                op.omod_form_ids[i] = mods[i].form_id;
            }
            op.omod_count = copy_n;
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
            // 2026-05-06 LATE evening (M9 closure, PLAN B) — sentinel
            // num_meshes=0xFF means the rest of the blob is an opaque
            // NIF byte buffer (engine NiStream::Save output) instead of
            // per-mesh records. Receiver routes to nistream_deserialize
            // + attach instead of the per-mesh attach path.
            if (bh.num_meshes == 0xFFu) {
                fw::dispatch::PendingMeshBlob pop_nif{};
                const std::size_t pn_nif = peer_id_str.size() < 15
                    ? peer_id_str.size() : 15;
                std::memcpy(pop_nif.peer_id, peer_id_str.data(), pn_nif);
                pop_nif.peer_id[pn_nif]  = 0;
                pop_nif.item_form_id = bh.item_form_id;
                pop_nif.equip_seq    = bh.equip_seq;
                const std::size_t nif_off = sizeof(MeshBlobHeader);
                const std::size_t nif_size = (blob.size() > nif_off)
                    ? (blob.size() - nif_off) : 0;
                if (nif_size > 0) {
                    pop_nif.nif_blob_bytes.assign(
                        blob.data() + nif_off,
                        blob.data() + nif_off + nif_size);
                }
                FW_LOG("[nif-rx] reassembled NIF blob peer=%s form=0x%X "
                       "equip_seq=%u nif_bytes=%zu → dispatch to main",
                       peer_id_str.c_str(), bh.item_form_id, bh.equip_seq,
                       nif_size);
                fw::dispatch::enqueue_mesh_blob_apply(std::move(pop_nif));
                FW_LOG("dispatch: nif-blob enqueued peer=%s form=0x%X "
                       "equip_seq=%u nif_bytes=%zu",
                       peer_id_str.c_str(), bh.item_form_id, bh.equip_seq,
                       nif_size);
                break;  // done with this reassembled blob
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
                const std::size_t slot_len   = rh.slot_name_len;
                const std::size_t bgsm_len   = rh.bgsm_path_len;
                const std::size_t pos_bytes  =
                    static_cast<std::size_t>(rh.vert_count) * 3 * sizeof(float);
                const std::size_t idx_bytes  =
                    static_cast<std::size_t>(rh.tri_count) * 3 * sizeof(std::uint16_t);
                const std::size_t need = name_len + parent_len + slot_len + bgsm_len
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
                // 2026-05-05 — slot_name added (uses former `reserved` u16
                // slot in MeshRecordHeader). Pre-fix sender DLLs wrote 0,
                // which yields slot_len=0 here → empty string → receiver
                // attach falls back to base root.
                rec.slot_name.assign(reinterpret_cast<const char*>(
                    blob.data() + roff), slot_len);
                roff += slot_len;
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
        //
        // B8 force-equip-cycle re-arm DISABLED 2026-05-08 — see
        // `hooks/main_menu_hook.cpp` and the CHANGELOG entry for the
        // bridge-crash post-mortem. Future replacement for the
        // initial-apparel-broadcast role: `hooks/equip_announce.h`
        // (NON TESTATO scaffold).
        // fw::hooks::arm_equip_cycle_for_peer_join(1500);
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
