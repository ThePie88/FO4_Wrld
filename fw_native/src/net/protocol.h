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
// v9: M9 wedge 4 — raw mesh replication. Adds MESH_BLOB_OP (0x0250) and
//     MESH_BLOB_BCAST (0x0251). Each frame carries one CHUNK of a serialized
//     mesh blob (multiple BSGeometry leaves extracted from a modded weapon).
//     Sender extracts via weapon_witness::snapshot_player_weapon_meshes(),
//     serializes the MeshSnapshot into a linear byte buffer (positions,
//     indices, m_name, parent_placeholder, bgsm_path, local_transform),
//     splits into 1388-byte chunks (1372 for BCAST), enqueues each as a
//     reliable frame. Receiver buffers chunks keyed on (peer_id, equip_seq);
//     when all arrive it reassembles + decodes + reconstructs each
//     BSTriShape on the ghost via factory sub_14182FFD0. See protocol.py
//     "M9.w4 v9" block for the wire format details.
// v8: M9 wedge 4 (witness pattern) — extends the EQUIP_OP / EQUIP_BCAST tail
//     with a SECOND variable-length section after the OMOD list: a sequence
//     of NifDescriptor records that capture which .nif files the engine
//     actually loaded for the modded weapon, plus where each mod was attached
//     in the assembled tree.
//
//     Wire (post-OMOD-tail):
//       u8 nif_count                              ← if 0, no NIF tail
//       nif_count × {
//         u8 path_len; path_len bytes (ASCII);
//         u8 parent_name_len; parent_name_len bytes;
//         16 × f32 local_transform;               ← raw NiTransform (64B)
//       }
//
//     Sender extracts these by walking the local player's BipedAnim weapon
//     subtree and querying the NIF path cache (sub_1417B3E90 detour). Each
//     cache hit BELOW the base weapon root is a mod attachment. Receiver
//     loads each mod NIF, looks up the parent node by name in the already-
//     loaded ghost weapon tree, and attaches the mod NIF as a child with
//     the captured transform.
//
//     Why this exists: 4 IDA iterations + 8 RE agents proved the engine's
//     mod-assembly pipeline (BGSMod descriptors → BipedAnim::ProcessTechniques
//     → BGSNamedNodeAttach) is fused with REFR vt[119]/vt[136] Reset3D and
//     cannot be invoked on a non-Actor receiver. The witness pattern routes
//     the engine's OWN assembly result to the receiver via wire.
//
//     Cap MAX_NIF_DESCRIPTORS = 8. Vanilla mods per weapon ≤6 typical; cap
//     also bounded by MAX_PAYLOAD_SIZE (≈ 1100 B available for the NIF tail
//     after fixed payload + OMOD records, ≈ 8 average descriptors).
// v7: M9 wedge 4 — extends EQUIP_OP / EQUIP_BCAST with a variable-length
//     tail of OMOD attachments (BGSMod::Attachment::Mod form_ids). When
//     a peer equips a modded weapon (e.g. 10mm pistol w/ Long Barrel +
//     Reflex Sight), the sender extracts the OMOD list from the inventory
//     item's BGSObjectInstanceExtra and ships it. Receiver uses the list
//     to assemble the modded NIF on the ghost weapon instead of the bare
//     dummy NIF (which is otherwise invisible for ranged weapons).
//
//     Wire (post-fixed-payload): u8 mod_count, then mod_count × 8B records
//       record = { u32 form_id; u8 attach_index; u8 rank; u8 flag; u8 pad; }
//     Cap mod_count at 32 (vanilla weapons rarely exceed 12; DLC up to ~20).
//     Empty list (mod_count=0) is valid and means "weapon in default config".
// v6: M9 wedge 1 equipment-event observation. Adds EQUIP_OP (client→server)
//     and EQUIP_BCAST (server→peers) carrying {item_form_id, kind=
//     equip|unequip, slot_form_id, count, timestamp_ms}. Sender hooks
//     ActorEquipManager::EquipObject + UnequipObject, filters local-player
//     events, broadcasts. Receiver in wedge 1 just logs RX (no apply on
//     ghost yet — that's wedge 2). 25 wire bytes for OP, 41 for BCAST.
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
constexpr std::uint8_t  PROTOCOL_VERSION  = 9;
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
    EQUIP_OP        = 0x0240,   // M9 w1: client -> server: I equipped/unequipped item X
    EQUIP_BCAST     = 0x0241,   // M9 w1: server -> other peers: peer X equipped/unequipped item Y
    MESH_BLOB_OP    = 0x0250,   // M9 w4 v9: client -> server: chunked mesh blob for an equip event
    MESH_BLOB_BCAST = 0x0251,   // M9 w4 v9: server -> peers: chunked mesh blob (peer-attributed)

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

// M9 w1: discriminator for EQUIP_OP / EQUIP_BCAST.
//   EQUIP   = local player just equipped an item (post-Equip detour fire)
//   UNEQUIP = local player just unequipped an item
// On the receiver in wedge 1 we only log; in wedge 2 we'll branch on this
// to call ActorEquipManager::EquipObject vs ::UnequipObject on the ghost.
enum class EquipOpKind : std::uint8_t {
    EQUIP   = 1,
    UNEQUIP = 2,
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

// M9 w1 — EQUIP_OP / EQUIP_BCAST. Carries the result of an
// ActorEquipManager::EquipObject or ::UnequipObject fire that we observed
// on the LOCAL player. Identity is the item form_id (resolvable via
// lookup_by_form_id on the receiver in wedge 2). Slot_form_id is the
// BGSEquipSlot's TESForm.formID — when the engine auto-resolved (no
// explicit slot was passed), we record 0 and the receiver also lets the
// engine auto-resolve.
//
// Wire layout — Python: I B I i Q  =  4+1+4+4+8 = 21 bytes (pack=1).
struct EquipOpPayload {
    std::uint32_t item_form_id;    // TESForm.formID (e.g. 0x1EED7 = Vault Suit 111)
    std::uint8_t  kind;            // EquipOpKind (1=equip, 2=unequip)
    std::uint32_t slot_form_id;    // BGSEquipSlot.formID, 0 = engine auto-pick
    std::int32_t  count;           // signed; in practice ≥1 (stack size)
    std::uint64_t timestamp_ms;    // sender wall clock for telemetry / ordering
};
static_assert(sizeof(EquipOpPayload) == 21, "EquipOpPayload size");

// Server → other peers fan-out. Adds peer_id for attribution. Same shape
// as DoorBroadcastPayload extended-with-peer-id.
//
// Wire layout — 16 (FixedClientId) + 21 (op fields) = 37 bytes.
struct EquipBroadcastPayload {
    FixedClientId peer_id;         // 16 bytes ASCII + 1 null
    std::uint32_t item_form_id;
    std::uint8_t  kind;
    std::uint32_t slot_form_id;
    std::int32_t  count;
    std::uint64_t timestamp_ms;
};
static_assert(sizeof(EquipBroadcastPayload) == 37, "EquipBroadcastPayload size");

// === M9 wedge 4 — variable-length OMOD-list tail ============================
// Protocol v7: appended AFTER the fixed EquipOpPayload (or
// EquipBroadcastPayload) bytes, in the same datagram, NOT a separate message.
// Layout:
//   [fixed payload (21 or 37 bytes)]
//   u8 mod_count                            ← if 0, no tail follows
//   mod_count × EquipModRecord (8 B each)
//
// Each EquipModRecord mirrors the runtime ObjectModifier struct in OIE:
//   form_id      — BGSMod::Attachment::Mod's TESForm.formID (formType 0x90)
//   attach_index — slot index inside the parent weapon (always 0 in observed
//                  data; the slot info is actually inside the BGSMod itself)
//   rank         — index2/rank field (always 1 in observed data)
//   flag         — runtime flag byte (always 0 in observed data)
//   pad          — padding; receiver MUST zero on encode (engine leaves
//                  garbage in this byte at runtime)
//
// Cap: MAX_EQUIP_MODS = 32. Vanilla weapons have ≤12 OMODs; Far Harbor /
// Nuka World can stack to ~20. 32 is safe ceiling. Receiver discards any
// records past the cap on parse; sender clamps on encode.
struct EquipModRecord {
    std::uint32_t form_id;
    std::uint8_t  attach_index;
    std::uint8_t  rank;
    std::uint8_t  flag;
    std::uint8_t  pad;             // MUST be zeroed on encode
};
static_assert(sizeof(EquipModRecord) == 8, "EquipModRecord size");

constexpr std::uint8_t MAX_EQUIP_MODS = 32;

// === M9 wedge 4 (v8) — witness NIF descriptor records ======================
//
// Each NifDescriptor names one .nif file the engine attached during mod
// assembly, plus where it was attached and the local transform the engine
// computed for it. The sender produces these from a post-equip walk of
// the LOCAL player's BipedAnim weapon subtree, querying nif_path_cache
// (RVA 0x017B3E90 detour) for each NiAVObject encountered.
//
// In-memory: fixed-size buffers (so structs can be passed by-value across
// module boundaries without dragging std::string into the wire layer).
// On wire: variable-length encoding (length-prefixed strings) — see the
// helpers encode_nif_descriptors / decode_nif_descriptors below.
//
// Path lengths chosen to match observed vanilla:
//   Weapons\10mmPistol\Mods\Barrel_Long.nif  = 41 chars (typical)
//   Weapons\AssaultRifle\Mods\Receivers\Powerful.nif = 48 chars
//   Worst observed (Far Harbor harpoon mods): ~96 chars.
// Parent nodes are short — typically NiNode inner names (BarrelAttachNode,
// ScopeAttachNode, MuzzleAttachNode, etc.). 64 chars cap.
constexpr std::size_t  MAX_NIF_PATH_LEN     = 192;   // bytes (not incl null)
constexpr std::size_t  MAX_NIF_NAME_LEN     = 64;
constexpr std::uint8_t MAX_NIF_DESCRIPTORS  = 8;

#pragma pack(pop)
struct NifDescriptor {
    char  nif_path[MAX_NIF_PATH_LEN + 1];     // null-terminated, max 192 chars
    char  parent_name[MAX_NIF_NAME_LEN + 1];  // null-terminated, max 64 chars
    float local_transform[16];                // raw NiTransform (rot 3x4 + trans 3 + scale 1)
};
#pragma pack(push, 1)

// Length-prefixed wire size of a single descriptor.
// 1 (path_len) + path_bytes + 1 (parent_len) + parent_bytes + 64 (xform).
inline std::size_t nif_descriptor_wire_size(const NifDescriptor& d) {
    const std::size_t pl = std::strlen(d.nif_path);
    const std::size_t nl = std::strlen(d.parent_name);
    return 1 + pl + 1 + nl + sizeof(d.local_transform);
}

// Encode N descriptors into a buffer prefixed by u8 count. Returns total
// bytes written (≥ 1). On overflow (would exceed dst_remaining) drops the
// last descriptors and writes the count of those actually serialised.
// Caller is responsible for sizing dst_remaining; a safe upper bound for
// `n` descriptors is n × (1+MAX_NIF_PATH_LEN+1+MAX_NIF_NAME_LEN+64).
inline std::size_t encode_nif_descriptors(
    std::uint8_t* dst,
    std::size_t   dst_remaining,
    const NifDescriptor* descs,
    std::uint8_t  n)
{
    if (!dst || dst_remaining < 1) return 0;
    if (n > MAX_NIF_DESCRIPTORS) n = MAX_NIF_DESCRIPTORS;

    std::uint8_t* count_slot = dst;       // we'll fill this last
    *count_slot = 0;
    std::size_t  written = 1;

    for (std::uint8_t i = 0; i < n; ++i) {
        const NifDescriptor& d = descs[i];
        std::size_t pl = std::strlen(d.nif_path);
        std::size_t nl = std::strlen(d.parent_name);
        if (pl > MAX_NIF_PATH_LEN) pl = MAX_NIF_PATH_LEN;
        if (nl > MAX_NIF_NAME_LEN) nl = MAX_NIF_NAME_LEN;
        const std::size_t need = 1 + pl + 1 + nl + sizeof(d.local_transform);
        if (written + need > dst_remaining) break;  // truncate

        dst[written++] = static_cast<std::uint8_t>(pl);
        std::memcpy(dst + written, d.nif_path, pl);
        written += pl;
        dst[written++] = static_cast<std::uint8_t>(nl);
        std::memcpy(dst + written, d.parent_name, nl);
        written += nl;
        std::memcpy(dst + written, d.local_transform,
                    sizeof(d.local_transform));
        written += sizeof(d.local_transform);
        ++(*count_slot);
    }
    return written;
}

// Decode descriptors from a buffer that starts with u8 count. Writes up
// to MAX_NIF_DESCRIPTORS into `out`. Returns bytes consumed (≥ 1) or 0
// if the buffer is malformed (truncated record, oversized lengths).
// On success, `count_out` reflects how many records were successfully
// parsed (≤ MAX_NIF_DESCRIPTORS).
inline std::size_t decode_nif_descriptors(
    const std::uint8_t* src,
    std::size_t         src_remaining,
    NifDescriptor*      out,
    std::uint8_t&       count_out)
{
    count_out = 0;
    if (!src || src_remaining < 1) return 0;
    std::uint8_t  n = src[0];
    std::size_t   off = 1;
    if (n > MAX_NIF_DESCRIPTORS) n = MAX_NIF_DESCRIPTORS;

    for (std::uint8_t i = 0; i < n; ++i) {
        if (off + 1 > src_remaining) return 0;
        std::uint8_t pl = src[off++];
        if (pl > MAX_NIF_PATH_LEN || off + pl + 1 > src_remaining) return 0;
        std::memcpy(out[i].nif_path, src + off, pl);
        out[i].nif_path[pl] = 0;
        off += pl;

        std::uint8_t nl = src[off++];
        if (nl > MAX_NIF_NAME_LEN
            || off + nl + sizeof(out[i].local_transform) > src_remaining)
            return 0;
        std::memcpy(out[i].parent_name, src + off, nl);
        out[i].parent_name[nl] = 0;
        off += nl;

        std::memcpy(out[i].local_transform, src + off,
                    sizeof(out[i].local_transform));
        off += sizeof(out[i].local_transform);
        ++count_out;
    }
    return off;
}

// === M9 wedge 4 v9 — MESH_BLOB chunked frames =============================
// See protocol.py "M9.w4 v9" block for full design notes. Summary:
//   - One MESH_BLOB_OP frame = one chunk of one logical mesh blob.
//   - The blob contains a u32 item_form_id + u32 equip_seq + u8 num_meshes
//     header followed by N serialized ExtractedMesh records.
//   - Sender splits the blob into 1388-byte chunks (1372 for BCAST), each
//     wrapped in MeshBlobChunkHeader. Receiver buffers by (peer, equip_seq)
//     and decodes once total_chunks arrive.
//   - All multi-byte fields little-endian, #pragma pack(1).
constexpr std::uint8_t  MAX_MESHES_PER_BLOB           = 32;
constexpr std::uint32_t MAX_BLOB_SIZE                 = 4u * 1024 * 1024;  // 4 MB hard ceiling

// MESH_BLOB_OP wire layout (12 B fixed header + variable chunk_data):
//   u32 equip_seq           — sender's per-equip monotonic counter
//   u32 total_blob_size     — bytes of the full assembled blob
//   u16 chunk_index         — 0 .. total_chunks-1
//   u16 total_chunks
//   N   chunk_data          — slice of the assembled blob
struct MeshBlobChunkHeader {
    std::uint32_t equip_seq;
    std::uint32_t total_blob_size;
    std::uint16_t chunk_index;
    std::uint16_t total_chunks;
};
static_assert(sizeof(MeshBlobChunkHeader) == 12, "MeshBlobChunkHeader size");

// MESH_BLOB_BCAST wire layout (16 B peer + 12 B chunk header + chunk_data).
struct MeshBlobChunkBroadcastHeader {
    FixedClientId peer_id;          // 16
    std::uint32_t equip_seq;
    std::uint32_t total_blob_size;
    std::uint16_t chunk_index;
    std::uint16_t total_chunks;
};
static_assert(sizeof(MeshBlobChunkBroadcastHeader) == 28,
    "MeshBlobChunkBroadcastHeader size");

constexpr std::size_t MESH_BLOB_OP_CHUNK_DATA_MAX =
    MAX_PAYLOAD_SIZE - sizeof(MeshBlobChunkHeader);            // 1388
constexpr std::size_t MESH_BLOB_BCAST_CHUNK_DATA_MAX =
    MAX_PAYLOAD_SIZE - sizeof(MeshBlobChunkBroadcastHeader);   // 1372

// MeshBlob top-level header (10 B, prepended to the assembled blob bytes
// BEFORE chunking). Followed by num_meshes × per-mesh records (variable).
struct MeshBlobHeader {
    std::uint32_t item_form_id;     // correlates with EQUIP_OP/BCAST
    std::uint32_t equip_seq;        // per-equip monotonic; matches chunk header
    std::uint8_t  num_meshes;
    std::uint8_t  reserved;         // = 0
};
static_assert(sizeof(MeshBlobHeader) == 10, "MeshBlobHeader size");

// Per-mesh record header (76 B fixed prefix). Followed by:
//   m_name_len bytes (UTF-8/ASCII)
//   parent_placeholder_len bytes
//   bgsm_path_len bytes
//   3*vert_count × f32 positions   (12 * vc bytes)
//   3*tri_count × u16 indices       (6 * tc bytes)
struct MeshRecordHeader {
    std::uint8_t  m_name_len;
    std::uint8_t  parent_placeholder_len;
    std::uint16_t bgsm_path_len;
    std::uint16_t vert_count;
    std::uint16_t reserved;         // = 0; align
    std::uint32_t tri_count;        // index_count = 3 * tri_count
    float         local_transform[16];
};
static_assert(sizeof(MeshRecordHeader) == 76, "MeshRecordHeader size");

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
