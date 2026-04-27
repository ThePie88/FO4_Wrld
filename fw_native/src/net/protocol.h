// FoM-lite wire protocol — C++ port of net/protocol.py (SSOT).
//
// This header is hand-written to match protocol.py byte-for-byte. Any
// change to the Python spec MUST be mirrored here; the test suite on the
// Python side catches silent format drift (structs are struct.Struct()
// with explicit sizes), so regressions should fail fast at roundtrip.
//
// When the port to Rust happens (B7), the same exercise applies — keep
// protocol.py authoritative, derive .h and .rs from it.
//
// Endianness: little-endian everywhere (matches struct '<' prefix).
// Packing: #pragma pack(push, 1) on all payload structs so MSVC lays
// them out identically to `struct.Struct("<...")` in Python.

#pragma once

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace fw::net {

// -------------------------------------------------------------- constants

constexpr std::uint8_t  PROTOCOL_MAGIC    = 0xFA;
// v5: B1.g container apply-to-engine. ContainerOpPayload and
//     ContainerBroadcastPayload gain `container_form_id` (u32) so receivers
//     can resolve their local REFR via lookup_by_form_id + (base, cell)
//     identity check, then invoke engine::apply_container_op_to_engine
//     (AddItem/RemoveItem real). Wire grows by 4 bytes per CONTAINER_OP
//     (32→36) and CONTAINER_BCAST (44→48).
// v4: B4 world-state expansion — QUEST_STAGE_SET/BCAST, GLOBAL_VAR_SET/BCAST,
//     bootstrap snapshots for quests + globals. Payloads defined only on
//     the Python side for now; C++ DLL just tolerates the bumped version
//     in HELLO. Full payload mirror lands with B4.d (DLL hooks).
// v3: ContainerOpPayload carries client_op_id so the server can echo it
//     back in CONTAINER_OP_ACK. Enables sender-side pre-mutation block
//     (DLL waits on condvar keyed on op_id before letting the engine's
//     AddObjectToContainer proceed). Closes the container dup race.
constexpr std::uint8_t  PROTOCOL_VERSION  = 5;
constexpr std::size_t   HEADER_SIZE       = 12;
constexpr std::size_t   MAX_PAYLOAD_SIZE  = 1400;
constexpr std::size_t   MAX_FRAME_SIZE    = HEADER_SIZE + MAX_PAYLOAD_SIZE;
constexpr std::size_t   MAX_CLIENT_ID_LEN = 15;

constexpr std::uint8_t  FLAG_RELIABLE     = 0x01;
constexpr std::uint8_t  FLAG_ACK_CARRIER  = 0x02;

// -------------------------------------------------------------- message types

enum class MessageType : std::uint16_t {
    HELLO           = 0x0001,
    WELCOME         = 0x0002,
    PEER_JOIN       = 0x0003,
    PEER_LEAVE      = 0x0004,
    HEARTBEAT       = 0x0005,
    DISCONNECT      = 0x0006,

    ACK             = 0x0010,

    WORLD_STATE     = 0x0020,
    CONTAINER_STATE = 0x0021,

    POS_STATE       = 0x0100,
    POS_BROADCAST   = 0x0101,
    POSE_STATE      = 0x0110,   // M8P3.15: per-bone rotation (client -> server)
    POSE_BROADCAST  = 0x0111,   // M8P3.15: per-bone rotation (server -> peers)

    ACTOR_EVENT     = 0x0200,
    CONTAINER_OP    = 0x0201,
    CONTAINER_BCAST = 0x0202,
    CONTAINER_SEED  = 0x0203,   // v3: client -> server full inventory dump
    CONTAINER_OP_ACK = 0x0204,  // v3: server -> sender verdict
    DOOR_OP         = 0x0230,   // B6.1: client -> server door activated
    DOOR_BCAST      = 0x0231,   // B6.1: server -> other peers door activated

    CHAT            = 0x0300,

    // v4: world-state replication
    QUEST_STATE           = 0x0400,   // legacy reservation — prefer QUEST_STAGE_*
    QUEST_STAGE_SET       = 0x0401,
    QUEST_STAGE_BCAST     = 0x0402,
    QUEST_STATE_BOOT      = 0x0022,   // in the 0x002X bootstrap class
    GLOBAL_VAR_SET        = 0x0411,
    GLOBAL_VAR_BCAST      = 0x0412,
    GLOBAL_VAR_STATE_BOOT = 0x0023,
};

enum class ActorEventKind : std::uint32_t {
    SPAWN   = 1,
    KILL    = 2,
    DISABLE = 3,
    ENABLE  = 4,
};

enum class ContainerOpKind : std::uint32_t {
    TAKE = 1,
    PUT  = 2,
};

// v3: verdict the server ships back in CONTAINER_OP_ACK.
enum class ContainerOpAckStatus : std::uint8_t {
    ACCEPTED        = 0,
    REJ_RATE        = 1,   // rate-limited
    REJ_IDENTITY    = 2,   // missing / zero identity
    REJ_COUNT       = 3,   // count <= 0 or absurd
    REJ_KIND        = 4,   // unknown op kind
    REJ_INSUFFICIENT = 5,  // TAKE count > what the container has (race loser)
};

// -------------------------------------------------------------- header

#pragma pack(push, 1)

// Wire format: <BBHIHBB>
struct FrameHeader {
    std::uint8_t  magic;
    std::uint8_t  version;
    std::uint16_t msg_type;
    std::uint32_t seq;
    std::uint16_t payload_len;
    std::uint8_t  flags;
    std::uint8_t  reserved;
};
static_assert(sizeof(FrameHeader) == HEADER_SIZE,
    "FrameHeader must be 12 bytes — #pragma pack alignment bug?");

// -------------------------------------------------------------- payloads

// Helper: fixed null-terminated string buffer. Python writes MAX_CLIENT_ID_LEN
// bytes of ASCII + 1 null byte = 16 bytes. We mirror that exactly.
struct FixedClientId {
    char bytes[MAX_CLIENT_ID_LEN + 1];

    void set(const std::string& s) {
        std::memset(bytes, 0, sizeof(bytes));
        const std::size_t n = (s.size() < MAX_CLIENT_ID_LEN)
            ? s.size() : MAX_CLIENT_ID_LEN;
        std::memcpy(bytes, s.data(), n);
    }
    std::string get() const {
        const std::size_t n = ::strnlen(bytes, MAX_CLIENT_ID_LEN);
        return std::string(bytes, n);
    }
};
static_assert(sizeof(FixedClientId) == MAX_CLIENT_ID_LEN + 1, "FixedClientId size");

// HELLO (client → server). Python: FixedString(15) + BB = 16 + 2 = 18 bytes
struct HelloPayload {
    FixedClientId client_id;
    std::uint8_t  client_version_major;
    std::uint8_t  client_version_minor;
};
static_assert(sizeof(HelloPayload) == 18, "HelloPayload size");

// WELCOME (server → client). Python: I B B B H = 9 bytes
struct WelcomePayload {
    std::uint32_t session_id;
    std::uint8_t  accepted;  // 0 or 1
    std::uint8_t  server_version_major;
    std::uint8_t  server_version_minor;
    std::uint16_t tick_rate_hz;
};
static_assert(sizeof(WelcomePayload) == 9, "WelcomePayload size");

// PEER_JOIN (server → client). Python: FixedString(15) + I = 20 bytes
struct PeerJoinPayload {
    FixedClientId peer_id;
    std::uint32_t session_id;
};
static_assert(sizeof(PeerJoinPayload) == 20, "PeerJoinPayload size");

// PEER_LEAVE (server → client). Python: FixedString(15) + B = 17 bytes
struct PeerLeavePayload {
    FixedClientId peer_id;
    std::uint8_t  reason;  // 0=timeout, 1=disconnect, 2=kick
};
static_assert(sizeof(PeerLeavePayload) == 17, "PeerLeavePayload size");

// HEARTBEAT. Python: Q = 8 bytes
struct HeartbeatPayload {
    std::uint64_t timestamp_ms;
};
static_assert(sizeof(HeartbeatPayload) == 8, "HeartbeatPayload size");

// DISCONNECT. Python: B = 1 byte
struct DisconnectPayload {
    std::uint8_t reason;  // 0=graceful, 1=error, 2=version_mismatch
};
static_assert(sizeof(DisconnectPayload) == 1, "DisconnectPayload size");

// ACK. Python: I I = 8 bytes
struct AckPayload {
    std::uint32_t highest_contiguous_seq;
    std::uint32_t sack_bitmap;  // bit N = highest+N+1 received
};
static_assert(sizeof(AckPayload) == 8, "AckPayload size");

// POS_STATE (client → server). Python: 6f Q = 32 bytes
struct PosStatePayload {
    float x, y, z;
    float rx, ry, rz;
    std::uint64_t timestamp_ms;
};
static_assert(sizeof(PosStatePayload) == 32, "PosStatePayload size");

// POS_BROADCAST (server → client). Python: FixedString(15) + 6f Q = 48 bytes
struct PosBroadcastPayload {
    FixedClientId peer_id;
    float x, y, z;
    float rx, ry, rz;
    std::uint64_t timestamp_ms;
};
static_assert(sizeof(PosBroadcastPayload) == 48, "PosBroadcastPayload size");

// ---- M8P3.15 POSE replication ---------------------------------------------
// Wire layout:
//   POSE_STATE     = PoseStateHeader + bone_count × PoseBoneEntry
//   POSE_BROADCAST = PoseBroadcastHeader + bone_count × PoseBoneEntry
//
// Each bone = quaternion (qx, qy, qz, qw) representing the bone's
// CURRENT m_kLocal rotation (animation-driven, parent-relative).
// Receiver maps bone-by-NAME-INDEX (sorted alphabetically — both
// sides walk identical NIF, so identical sort order).
//
// Quaternion is more compact (16B) than 3x3 (36B) → fits in
// MAX_PAYLOAD_SIZE=1400 with bone_count up to 64.
// At 16 bytes per quat (full-precision float), the wire-format math:
//   POSE_BROADCAST max = 26 hdr + N*16 ≤ 1400 (MAX_PAYLOAD_SIZE)
//   → N ≤ 85. Use 80 for headroom.
constexpr std::uint16_t MAX_POSE_BONES = 80;

struct PoseStateHeader {
    std::uint64_t timestamp_ms;
    std::uint16_t bone_count;
    // followed by bone_count × float[4] = qx, qy, qz, qw
};
static_assert(sizeof(PoseStateHeader) == 10, "PoseStateHeader size");

struct PoseBroadcastHeader {
    FixedClientId peer_id;          // 16
    std::uint64_t timestamp_ms;     // 8
    std::uint16_t bone_count;       // 2
    // followed by bone_count × float[4] = qx, qy, qz, qw
};
static_assert(sizeof(PoseBroadcastHeader) == 26, "PoseBroadcastHeader size");

struct PoseBoneEntry {
    float qx, qy, qz, qw;  // quaternion
};
static_assert(sizeof(PoseBoneEntry) == 16, "PoseBoneEntry size");
// Max payload sizes:
//   POSE_STATE     = 10 + 64*16 = 1034 bytes < 1400 ✓
//   POSE_BROADCAST = 26 + 64*16 = 1050 bytes < 1400 ✓

// ACTOR_EVENT. Python v2: I I I f f f I I = 32 bytes
struct ActorEventPayload {
    std::uint32_t kind;           // ActorEventKind
    std::uint32_t form_id;        // session-scoped ref id
    std::uint32_t actor_base_id;  // TESForm.formID of baseForm
    float         x, y, z;
    std::uint32_t extra;
    std::uint32_t cell_id;        // TESForm.formID of parentCell
};
static_assert(sizeof(ActorEventPayload) == 32, "ActorEventPayload size");

// CONTAINER_OP (client → server). Python v5: I I I I i Q I I = 36 bytes.
// `client_op_id` (v3) — monotonic per client, echoed back in CONTAINER_OP_ACK.
// Sender waits on a condvar keyed on that id to decide allow/block the
// engine-level AddObjectToContainer before it mutates inventory.
// `container_form_id` (v5) — sender's engine form_id for the touched
// container REFR. Receivers use it to find their local REFR via
// LookupByFormID + (base, cell) identity check, then invoke
// engine::apply_container_op_to_engine (real AddItem/RemoveItem).
struct ContainerOpPayload {
    std::uint32_t kind;                // ContainerOpKind
    std::uint32_t container_base_id;
    std::uint32_t container_cell_id;
    std::uint32_t item_base_id;
    std::int32_t  count;               // signed, >0 in practice
    std::uint64_t timestamp_ms;
    std::uint32_t client_op_id;        // v3
    std::uint32_t container_form_id;   // v5
};
static_assert(sizeof(ContainerOpPayload) == 36, "ContainerOpPayload size");

// CONTAINER_OP_ACK (server → sender only). Python v3: I B I I I i = 21 bytes.
// Identified by `client_op_id` that echoes back to the sender.
struct ContainerOpAckPayload {
    std::uint32_t client_op_id;
    std::uint8_t  status;              // ContainerOpAckStatus
    std::uint32_t container_base_id;
    std::uint32_t container_cell_id;
    std::uint32_t item_base_id;
    std::int32_t  final_count;         // post-op server snapshot count
};
static_assert(sizeof(ContainerOpAckPayload) == 21, "ContainerOpAckPayload size");

// v4: QUEST_STAGE_SET (client → server). Python <IHQ = 14 bytes.
struct QuestStageSetPayload {
    std::uint32_t quest_form_id;
    std::uint16_t new_stage;
    std::uint64_t timestamp_ms;
};
static_assert(sizeof(QuestStageSetPayload) == 14, "QuestStageSetPayload size");

// v4: QUEST_STAGE_BCAST (server → other peers). FixedClientId + <IHQ = 30 bytes.
struct QuestStageBroadcastPayload {
    FixedClientId peer_id;
    std::uint32_t quest_form_id;
    std::uint16_t new_stage;
    std::uint64_t timestamp_ms;
};
static_assert(sizeof(QuestStageBroadcastPayload) == 30, "QuestStageBroadcastPayload size");

// v4: GLOBAL_VAR_SET (client → server). Python <IdQ = 20 bytes.
struct GlobalVarSetPayload {
    std::uint32_t global_form_id;
    double        value;      // f64 on wire; the engine stores f32 but we
                              // widen for lossless i32 globals on the wire
    std::uint64_t timestamp_ms;
};
static_assert(sizeof(GlobalVarSetPayload) == 20, "GlobalVarSetPayload size");

// v4: GLOBAL_VAR_BCAST (server → other peers). FixedClientId + <IdQ = 36 bytes.
struct GlobalVarBroadcastPayload {
    FixedClientId peer_id;
    std::uint32_t global_form_id;
    double        value;
    std::uint64_t timestamp_ms;
};
static_assert(sizeof(GlobalVarBroadcastPayload) == 36, "GlobalVarBroadcastPayload size");

// CONTAINER_BCAST (server → client). Python v5: FixedString(15+1) + I I I I i Q I = 48 bytes
// container_form_id (v5) — see ContainerOpPayload. Used by receivers to
// resolve their local REFR and invoke engine::apply_container_op_to_engine.
struct ContainerBroadcastPayload {
    FixedClientId peer_id;
    std::uint32_t kind;
    std::uint32_t container_base_id;
    std::uint32_t container_cell_id;
    std::uint32_t item_base_id;
    std::int32_t  count;
    std::uint64_t timestamp_ms;
    std::uint32_t container_form_id;   // v5
};
static_assert(sizeof(ContainerBroadcastPayload) == 48, "ContainerBroadcastPayload size");

// B6.1 — DOOR_OP / DOOR_BCAST. Toggle semantics; receiver re-invokes
// engine Activate worker (sub_140514180) on the matching local REFR.
// Python: I I I Q = 20 bytes (DoorOpPayload), 16 + 20 = 36 (Broadcast).
// C++ pack(1) makes struct size == wire size — clean memcpy both ways.
struct DoorOpPayload {
    std::uint32_t door_form_id;    // sender's REFR form_id (lookup_by_form_id receiver)
    std::uint32_t door_base_id;    // base TESObjectACTI/DOOR formID (identity)
    std::uint32_t door_cell_id;    // cell formID (identity)
    std::uint64_t timestamp_ms;    // sender wall clock
};
static_assert(sizeof(DoorOpPayload) == 20, "DoorOpPayload size");

struct DoorBroadcastPayload {
    FixedClientId peer_id;         // 16 bytes
    std::uint32_t door_form_id;
    std::uint32_t door_base_id;
    std::uint32_t door_cell_id;
    std::uint64_t timestamp_ms;
};
static_assert(sizeof(DoorBroadcastPayload) == 36, "DoorBroadcastPayload size");

// WORLD_STATE entry. Python: I I I B = 13 bytes
struct WorldActorEntry {
    std::uint32_t form_id;
    std::uint32_t base_id;
    std::uint32_t cell_id;
    std::uint8_t  alive;
};
static_assert(sizeof(WorldActorEntry) == 13, "WorldActorEntry size");

// CONTAINER_STATE entry. Python: I I I i = 16 bytes
struct ContainerStateEntry {
    std::uint32_t container_base_id;
    std::uint32_t container_cell_id;
    std::uint32_t item_base_id;
    std::int32_t  count;
};
static_assert(sizeof(ContainerStateEntry) == 16, "ContainerStateEntry size");

// Chunked-payload header (shared by WORLD_STATE and CONTAINER_STATE).
// Python: H H H = 6 bytes (num_entries, chunk_index, total_chunks)
struct ChunkHeader {
    std::uint16_t num_entries;
    std::uint16_t chunk_index;
    std::uint16_t total_chunks;
};
static_assert(sizeof(ChunkHeader) == 6, "ChunkHeader size");

constexpr std::size_t WORLD_STATE_MAX_ENTRIES_PER_FRAME =
    (MAX_PAYLOAD_SIZE - sizeof(ChunkHeader)) / sizeof(WorldActorEntry); // 107
constexpr std::size_t CONTAINER_STATE_MAX_ENTRIES_PER_FRAME =
    (MAX_PAYLOAD_SIZE - sizeof(ChunkHeader)) / sizeof(ContainerStateEntry); // 87

#pragma pack(pop)

// -------------------------------------------------------------- encode helpers

// Build a full frame (header + payload bytes) into `out`. Clears out first.
// The payload pointer/size is opaque here — caller copied its POD struct into
// a byte buffer (or passed a variable-length chunk buffer for STATE messages).
inline void encode_frame(
    std::vector<std::uint8_t>& out,
    MessageType msg_type,
    std::uint32_t seq,
    const void* payload, std::size_t payload_len,
    bool reliable)
{
    out.clear();
    out.resize(HEADER_SIZE + payload_len);

    FrameHeader h{};
    h.magic       = PROTOCOL_MAGIC;
    h.version     = PROTOCOL_VERSION;
    h.msg_type    = static_cast<std::uint16_t>(msg_type);
    h.seq         = seq;
    h.payload_len = static_cast<std::uint16_t>(payload_len);
    h.flags       = reliable ? FLAG_RELIABLE : 0;
    h.reserved    = 0;

    std::memcpy(out.data(), &h, HEADER_SIZE);
    if (payload_len) {
        std::memcpy(out.data() + HEADER_SIZE, payload, payload_len);
    }
}

// Returns false if the bytes aren't a valid frame (bad magic/version/len).
inline bool decode_header(const std::uint8_t* data, std::size_t size,
                          FrameHeader* out)
{
    if (size < HEADER_SIZE) return false;
    std::memcpy(out, data, HEADER_SIZE);
    if (out->magic != PROTOCOL_MAGIC) return false;
    if (out->version != PROTOCOL_VERSION) return false;
    if (out->payload_len > MAX_PAYLOAD_SIZE) return false;
    if (size < HEADER_SIZE + out->payload_len) return false;
    return true;
}

} // namespace fw::net
