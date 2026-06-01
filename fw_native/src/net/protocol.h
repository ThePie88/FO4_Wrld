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
// v14: B6.5w12 Ghost AI decision-point sync — extends NPCStateEntry
//     (53 → 98 B) with AI state the server pre-computes for the DLL's
//     MinHook detours on engine decision functions to consume:
//       - package_form_id (u32) → TESPackage::EvaluateConditions @ 0x00768CC0
//       - combat_target_form_id (u32) → SyncCombatTargetFromAIProcess @ 0x00C5CCE0
//       - aim_x/y/z (f32×3) → CombatAimController::SetAimTarget @ 0x00E65820
//       - velocity_x/y/z (f32×3) → TickMovementController @ 0x00C65E20
//       - weapon_state / sighted / sprinting / sneaking / gun_down /
//         aggression / loco_state_pack / sandbox_marker_handle /
//         sandbox_idle_index → 7 anim-graph state-transition entry points.
//     Replaces the v13-era "override engine output" pattern (B6.5w4
//     rounds 1-11, closed) with "redirect engine input" so the engine
//     still does all rendering/anim/IK/physics natively. Wire growth:
//     +45 B per NPC. MAX_NPC_STATES_PER_FRAME drops 26 → 14 (MTU 1400
//     still trivial; 4 packets/tick at 50 NPCs).
// v13: B6.5w2 NPC continuous-state sync — adds NPC_STATE_BCAST (0x0270).
//     Server-authoritative: the Python NPCBrain (server/npc_brain.py)
//     ticks all tracked NPCs at npc_tick_hz (default 10 Hz) and
//     broadcasts a batched snapshot per tick. Receiver looks up local
//     Actor by form_id via lookup_by_form_id (RVA 0x311850), writes
//     pos at Actor+0xD0 / rot at Actor+0xC0, sets anim graph variables
//     on the IAnimationGraphManagerHolder (Actor+0x48) via
//     SetGraphVariable* at RVA 0x818D60/D80/DA0
//     (re/B6.5_npc_pipeline_AGENT_B.md). Wire: 53 B / NPCStateEntry,
//     ≤26 entries per frame at MTU 1400 + 4 B header (count u16 +
//     reserved u16). Unreliable channel — drops tolerable, next tick
//     resends fresh state. w3.a (this DLL revision) decodes + logs RX
//     only; w3.b adds the engine apply (PendingNPCStateBatch +
//     main-thread drain in npc_apply.cpp).
// v12: B6.3 lock state sync — adds LOCK_OP (0x0260) / LOCK_BCAST (0x0261)
//     opcodes. Sender hooks ForceUnlock (sub_140563320) and ForceLock
//     (sub_140563360); broadcast carries (form_id, base_id, cell_id,
//     locked, timestamp_ms). Receiver applies via Papyrus binding
//     sub_141158640 with ai_notify=0 — bypasses minigame and key
//     consumption. Fires for lockpick success, terminal hack, AI lock
//     packages, perk auto-unlock, and savefile load (server dedups
//     by state). LockOpPayload = 25 bytes, LockBroadcastPayload = 41.
// v11: B6.PROLOGUE (cell-aware ghost) — extends PosStatePayload and
//     PosBroadcastPayload with a `u32 cell_id` field at the end. Sender
//     reads it from PlayerCharacter.parentCell.formID (offset 0xB8 + 0x14).
//     Receiver compares with its own local cell every pos update and flips
//     NIAV_FLAG_APP_CULLED on the ghost BSFadeNode when cells differ. This
//     fixes the "ghost stays frozen at the door" bug when peer A enters an
//     interior cell that peer B isn't loaded into. PosState 32→36 bytes,
//     PosBroadcast 48→52 bytes.
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
// v10: M9 wedge 2 PROPER (May 3 2026) — extends EQUIP_OP / EQUIP_BCAST
//     fixed payload with `u16 effective_priority`. Sender extracts via engine
//     helper sub_140436820 (ARMO_INSTANCE_HOLDER_BUILD): when OMOD InstanceData
//     exists, reads its +0x56 priority; else falls back to ARMO+0x2A6 default.
//     Receiver feeds it to PrioritySelect (RE'd from sub_1404626A0 = TES
//     ObjectARMO::ForEachAddonInstance) to pick the OMOD-modified tier on the
//     ghost (Combat Armor Heavy upgrade → priority=3 → Heavy ARMA renders
//     instead of Lite). Sizeof bumped: EquipOpPayload 21→23, EquipBcast 37→39.
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
// v16: ghost crouch — adds POSE_CROUCH_STATE (0x028E, C→S) and
//     POSE_CROUCH_BROADCAST (0x028F, S→peers). A SEPARATE, additive channel
//     beside the working POSE_STATE/POSE_BROADCAST rotation pose: it
//     replicates the vertical COM/Pelvis LOCAL TRANSLATION a crouch produces
//     (rotation-only pose left the body at standing height → ghost feet
//     "flew"). PoseCrouchEntry = {u16 bone_index; f32 tx,ty,tz} = 14 B, keyed
//     on the SAME shared canonical bone index as the rotation pose. Tiny
//     count (≤8; COM + Pelvis). Does NOT modify PoseBoneEntry, the canonical
//     filter, or the rotation capture/apply loops.
constexpr std::uint8_t  PROTOCOL_VERSION  = 16;
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
    PEER_GHOST_REGISTER = 0x0007,  // B6.6w5: client -> server, local ghost form_id

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
    DOOR_OP         = 0x0230,   // B6.0: client -> server door activated
    DOOR_BCAST      = 0x0231,   // B6.0: server -> other peers door activated

    EQUIP_OP        = 0x0240,   // M9 w1: client -> server: I equipped/unequipped item X
    EQUIP_BCAST     = 0x0241,   // M9 w1: server -> other peers: peer X equipped/unequipped item Y
    MESH_BLOB_OP    = 0x0250,   // M9 w4 v9: client -> server: chunked mesh blob for an equip event
    MESH_BLOB_BCAST = 0x0251,   // M9 w4 v9: server -> peers: chunked mesh blob (peer-attributed)
    LOCK_OP         = 0x0260,   // B6.3 v0.5.3: client -> server lock state changed
    LOCK_BCAST      = 0x0261,   // B6.3 v0.5.3: server -> other peers lock state changed
    NPC_STATE_BCAST = 0x0270,   // B6.5w2 v13: server -> peers batched NPC pos/anim state (unreliable, ~10 Hz)
    NPC_FIRE        = 0x0271,   // B6.6w1 v15: server -> peers "this raider fires its equipped weapon NOW" (unreliable, event-driven)
    NPC_DISCOVER    = 0x0272,   // B6.6w2 v16: client -> server "I auto-tracked this hostile NPC; register it" (reliable, event-driven)
    NPC_PERCEPTION_TRIGGER = 0x0273,   // Build 62 v17: server -> peers "NPC X perceives peer Y's ghost — call CCF810 locally" (reliable, event-driven, debounced 5s server-side)

    // Build 65 owner-driven NPC sync (Solver 2). Phase A ships the single-
    // phase variant (no PHASE_1 / RELEASE_ACK dance — server emits PHASE_2
    // directly on every ownership change). Opcodes for full two-phase are
    // reserved so the wire stays stable when Phase B lands.
    NPC_OWNERSHIP_BCAST          = 0x0280,  // S→peer: bootstrap snapshot (chunked, reliable)
    NPC_OWNERSHIP_HANDOFF_PHASE_1 = 0x0281, // S→old+new owners: release request (RESERVED Phase A no-op)
    NPC_OWNERSHIP_RELEASE_ACK    = 0x0282,  // C→S: old owner ack (RESERVED Phase A no-op)
    NPC_OWNERSHIP_HANDOFF_PHASE_2 = 0x0283, // S→all: new owner active for one NPC (reliable)
    NPC_OWNER_HEARTBEAT          = 0x0284,  // C→S: list of owned (fid, epoch) — proof of life (unreliable, ~2 Hz)
    NPC_STATE_FROM_OWNER         = 0x0285,  // C→S→all: owner authoritative state batch (unreliable, ~10-30 Hz)
    NPC_OBSERVED                 = 0x0286,  // C→S: election input — "I see NPC X at dist² D" (reliable)
    NPC_UNLOAD                   = 0x0287,  // C→S: cell unload — release owner role (reliable)
    NPC_FIRE_FROM_OWNER          = 0x0288,  // C→S→all: owner fire event (unreliable, event-driven)
    NPC_DEATH_FROM_OWNER         = 0x0289,  // C→S→all: owner death event (reliable, event-driven)
    NPC_DAMAGE_FROM_OWNER        = 0x028A,  // C→S→all: owner hit-applier event for ragdoll/visual (unreliable)
    NPC_ENGAGEMENT_CLAIM         = 0x028B,  // Build 65.c.23 — C→S: non-owner peer's engine has InCombat flag on tracked NPC; server force-handoff if owner disengaged for > ENGAGEMENT_OWNERSHIP_GRACE_MS (unreliable, dedup'd client-side 2s/fid)
    NPC_POSE_FROM_OWNER          = 0x028C,  // c.37.0 — C→S→all: owner's per-bone rotation snapshot for ONE owned NPC, keyed by form_id (full pose replication, ~15-20 Hz/NPC, unreliable)
    NPC_DAMAGE_CLAIM             = 0x028D,  // c.39b — C→S: local player dealt D damage to NPC X (drives damage-based ownership/aggro). Unreliable, client-throttled.
    NPC_CROUCH_FROM_OWNER        = 0x0290,  // NPC crouch — C→S→all: owner's COM/Pelvis LOCAL TRANSLATION snapshot for ONE owned NPC, keyed by form_id. NPC analogue of POSE_CROUCH (rotation pose bends raider legs but leaves body at standing height → feet fly; this carries the vertical drop). Unreliable.

    // v16 — ghost crouch. SEPARATE additive channel beside POSE_STATE/BROADCAST.
    POSE_CROUCH_STATE     = 0x028E,  // v16: C→S: my crouch bone translations (COM/Pelvis +0x60 local translate)
    POSE_CROUCH_BROADCAST = 0x028F,  // v16: S→peers: peer X's crouch bone translations

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

// HELLO (client → server). B6.6w5: extended with steam_id u64 (8 bytes
// at end). Wire format: FixedString(15) + BB + Q = 16 + 2 + 8 = 26 bytes.
// Python side decodes the steam_id tail leniently — if a client sends
// only the legacy 18-byte form, server treats steam_id as 0.
struct HelloPayload {
    FixedClientId client_id;
    std::uint8_t  client_version_major;
    std::uint8_t  client_version_minor;
    std::uint64_t steam_id;   // 0 = unavailable (steam_api64.dll not loaded yet)
};
static_assert(sizeof(HelloPayload) == 26, "HelloPayload size (v15)");

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

// POS_STATE (client → server). Python: 6f Q I = 36 bytes (v11)
struct PosStatePayload {
    float x, y, z;
    float rx, ry, rz;
    std::uint64_t timestamp_ms;
    std::uint32_t cell_id;          // v11: parentCell.formID (B6 prologue)
};
static_assert(sizeof(PosStatePayload) == 36, "PosStatePayload size");

// POS_BROADCAST (server → client). Python: FixedString(15) + 6f Q I = 52 bytes (v11)
struct PosBroadcastPayload {
    FixedClientId peer_id;
    float x, y, z;
    float rx, ry, rz;
    std::uint64_t timestamp_ms;
    std::uint32_t cell_id;          // v11: peer's parentCell.formID (B6 prologue)
};
static_assert(sizeof(PosBroadcastPayload) == 52, "PosBroadcastPayload size");

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
    float qx, qy, qz, qw;  // quaternion (local rotation, +0x30)
};
static_assert(sizeof(PoseBoneEntry) == 16, "PoseBoneEntry size");

// ---- v16 POSE_CROUCH replication -------------------------------------------
// A SEPARATE, additive channel beside POSE_STATE/POSE_BROADCAST. The rotation
// pose (PoseBoneEntry, above) is UNTOUCHED and keeps working; this channel
// only carries the vertical COM/Pelvis LOCAL TRANSLATION (the vec3 at bone
// +0x60) that a crouch produces. Each entry is keyed on the SAME shared
// canonical bone index as the rotation pose (both clients walk the identical,
// sorted, UNFILTERED canonical list → index is a reliable cross-client key).
// count is tiny (≤8; COM + Pelvis today).
//
// Wire layout mirrors POSE_STATE → POSE_BROADCAST:
//   POSE_CROUCH_STATE     = PoseCrouchStateHeader     + count × PoseCrouchEntry
//   POSE_CROUCH_BROADCAST = PoseCrouchBroadcastHeader + count × PoseCrouchEntry
constexpr std::uint8_t MAX_POSE_CROUCH_BONES = 8;

struct PoseCrouchEntry {
    std::uint16_t bone_index;   // canonical index (shared with rotation pose)
    float tx, ty, tz;           // bone m_kLocal.translate (+0x60) vec3
};
static_assert(sizeof(PoseCrouchEntry) == 14, "PoseCrouchEntry size (v16)");

struct PoseCrouchStateHeader {
    std::uint64_t timestamp_ms;  // 8
    std::uint8_t  count;         // 1
    // followed by count × PoseCrouchEntry
};
static_assert(sizeof(PoseCrouchStateHeader) == 9, "PoseCrouchStateHeader size (v16)");

struct PoseCrouchBroadcastHeader {
    FixedClientId peer_id;       // 16
    std::uint64_t timestamp_ms;  // 8
    std::uint8_t  count;         // 1
    // followed by count × PoseCrouchEntry
};
static_assert(sizeof(PoseCrouchBroadcastHeader) == 25, "PoseCrouchBroadcastHeader size (v16)");

// c.37.0 — NPC pose replication (owner → mirror, keyed by form_id).
// Same quaternion bone payload as POSE_STATE, prefixed with the NPC's
// form_id so the receiver resolves the mirror Actor via lookup_by_form_id
// and drives ITS skeleton (like player→ghost). ONE message type for both
// C→S and S→peers (owner-driven pattern); server validates owner + fans
// out unchanged. Layout matches Python NPCPoseFromOwnerPayload "<IQH".
struct NpcPoseHeader {
    std::uint32_t form_id;          // 4 @ 0
    std::uint64_t timestamp_ms;     // 8 @ 4 (pack(1) — no align padding)
    std::uint16_t bone_count;       // 2 @ 12
    // followed by bone_count × PoseBoneEntry (qx,qy,qz,qw)
};
static_assert(sizeof(NpcPoseHeader) == 14, "NpcPoseHeader size");

// NPC crouch — owner's COM/Pelvis LOCAL TRANSLATION snapshot for ONE owned
// NPC, keyed by form_id. The NPC analogue of POSE_CROUCH_STATE: reuses the
// SAME PoseCrouchEntry (14 B: u16 bone_index + f32 tx,ty,tz) keyed on the
// shared canonical bone index, prefixed with the NPC's form_id so the
// receiver resolves the mirror Actor via lookup_by_form_id and lowers ITS
// skeleton — exactly like NpcPoseHeader does for the rotation pose. ONE
// message type for both C→S and S→peers (owner-driven relay). Layout matches
// Python NPCCrouchFromOwnerPayload "<IQB".
struct NpcCrouchHeader {
    std::uint32_t form_id;          // 4 @ 0
    std::uint64_t timestamp_ms;     // 8 @ 4 (pack(1) — no align padding)
    std::uint8_t  count;            // 1 @ 12
    // followed by count × PoseCrouchEntry (bone_index, tx, ty, tz)
};
static_assert(sizeof(NpcCrouchHeader) == 13, "NpcCrouchHeader size");

// c.39b — "my local player dealt `amount` damage to NPC `form_id`". Client→
// server; the threat table accumulates a per-peer decayed damage sum per NPC
// and ownership follows the biggest recent damager. Matches Python "<If".
struct NpcDamageClaim {
    std::uint32_t form_id;   // 4
    float         amount;    // 4
};
static_assert(sizeof(NpcDamageClaim) == 8, "NpcDamageClaim size");
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

// B6.3 v0.5.3 — LOCK_OP / LOCK_BCAST. ForceUnlock/ForceLock fired on
// sender, receiver applies via Papyrus binding sub_141158640. Identity
// is (form_id, base_id, cell_id) like doors — receiver looks up REFR
// via lookup_by_form_id, then validates against base+cell.
//
// Wire layout — Python: I I I B Q  =  4+4+4+1+8 = 21 bytes (pack=1).
// Note: pack(push, 1) at the top of the file ensures no padding,
// otherwise MSVC would align to 8 → 24 bytes.
struct LockOpPayload {
    std::uint32_t lock_form_id;    // sender's REFR form_id
    std::uint32_t lock_base_id;    // base form id (identity)
    std::uint32_t lock_cell_id;    // cell form id (identity)
    std::uint8_t  locked;          // 0 = unlocked, 1 = locked
    std::uint64_t timestamp_ms;    // sender wall clock
};
static_assert(sizeof(LockOpPayload) == 21, "LockOpPayload size");

struct LockBroadcastPayload {
    FixedClientId peer_id;         // 16 bytes
    std::uint32_t lock_form_id;
    std::uint32_t lock_base_id;
    std::uint32_t lock_cell_id;
    std::uint8_t  locked;
    std::uint64_t timestamp_ms;
};
static_assert(sizeof(LockBroadcastPayload) == 37, "LockBroadcastPayload size");

// M9 w1 — EQUIP_OP / EQUIP_BCAST. Carries the result of an
// ActorEquipManager::EquipObject or ::UnequipObject fire that we observed
// on the LOCAL player. Identity is the item form_id (resolvable via
// lookup_by_form_id on the receiver in wedge 2). Slot_form_id is the
// BGSEquipSlot's TESForm.formID — when the engine auto-resolved (no
// explicit slot was passed), we record 0 and the receiver also lets the
// engine auto-resolve.
//
// Wire layout — Python: I B I i Q H  =  4+1+4+4+8+2 = 23 bytes (pack=1).
//
// v10 added `effective_priority` (last u16) for M9.w2 PROPER ARMA tier
// selection on the receiver. Sender extracts via the engine helper at
// sub_140436820 — for ARMOs with OMOD InstanceData, reads InstanceData+0x56;
// else falls back to ARMO+0x2A6. Receiver feeds it to PrioritySelect (the
// algorithm RE'd from sub_1404626A0 / TESObjectARMO::ForEachAddonInstance)
// so the right ARMA tier (Lite/Mid/Heavy) is picked. For non-ARMO forms
// (weapons, ammo) the field is set to 0 and ignored.
struct EquipOpPayload {
    std::uint32_t item_form_id;    // TESForm.formID (e.g. 0x1EED7 = Vault Suit 111)
    std::uint8_t  kind;            // EquipOpKind (1=equip, 2=unequip)
    std::uint32_t slot_form_id;    // BGSEquipSlot.formID, 0 = engine auto-pick
    std::int32_t  count;           // signed; in practice ≥1 (stack size)
    std::uint64_t timestamp_ms;    // sender wall clock for telemetry / ordering
    std::uint16_t effective_priority; // v10: OMOD-modified priority (or ARMO+0x2A6 fallback)
};
static_assert(sizeof(EquipOpPayload) == 23, "EquipOpPayload size (v10)");

// Server → other peers fan-out. Adds peer_id for attribution. Same shape
// as DoorBroadcastPayload extended-with-peer-id.
//
// Wire layout — 16 (FixedClientId) + 23 (op fields) = 39 bytes (v10).
struct EquipBroadcastPayload {
    FixedClientId peer_id;         // 16 bytes ASCII + 1 null
    std::uint32_t item_form_id;
    std::uint8_t  kind;
    std::uint32_t slot_form_id;
    std::int32_t  count;
    std::uint64_t timestamp_ms;
    std::uint16_t effective_priority; // v10: see EquipOpPayload comment
};
static_assert(sizeof(EquipBroadcastPayload) == 39, "EquipBroadcastPayload size (v10)");

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

// === B6.5w12 (v14) — NPC continuous-state broadcast ========================
// Mirror of protocol.py::NPCStateEntry + NPCStateBroadcastPayload. Wire
// MUST match byte-for-byte: 98 B per entry, no padding (pack=1). Server
// (server/npc_brain.py) emits at 10 Hz. Unreliable channel.
//
// Receiver pipeline (Ghost AI, B6.5w12+):
//   1. lookup_by_form_id(entry.form_id) → local Actor* (or null if not loaded)
//   2. populate per-NPC cache with v14 fields (main_thread_dispatch).
//   3. MinHook detours on engine decision functions read from the cache
//      and substitute the server's value for tracked form_ids:
//        - TESPackage::EvaluateConditions @ 0x00768CC0  → package_form_id
//        - Actor::SyncCombatTargetFromAIProcess @ 0x00C5CCE0
//                                                       → combat_target_form_id
//        - CombatAimController::SetAimTarget   @ 0x00E65820  → aim_x/y/z
//        - Actor::TickMovementController       @ 0x00C65E20  → velocity_x/y/z
//        - DrawWeapon dispatch                 @ 0x00C5D080  → weapon_state
//        - SetSightedState                     @ 0x00CB13F0  → sighted
//        - SetSprintState                      @ 0x00CA6030  → sprinting
//        - SetSneakState                       @ 0x00CA6220  → sneaking
//        - ResolveCombatStance                 @ 0x00CD6870  → gun_down
//        - LocoEventDispatch                   @ 0x00CEC200  → loco_state_pack
//        - UpdateAggressionToGraph             @ 0x00E4D8A0  → aggression
//   4. Engine continues with the server's decision as input — runs
//      pathfinder, plays anim transition, fires projectiles natively.
//
// The legacy v13 receiver pipeline (apply_npc_state_to_engine with
// Actor::MoveTo every tick) is closed; see B6.5w12 deprecation commit.

constexpr std::uint8_t MAX_NPC_STATES_PER_FRAME = 14;  // (MTU 1400 - 4 hdr) / 98 = 14

struct NPCStateEntry {
    // v13 baseline (53 B) ----------------------------------------------
    std::uint32_t form_id;
    std::uint32_t base_id;
    std::uint32_t cell_id;
    float         pos_x;
    float         pos_y;
    float         pos_z;
    float         yaw;
    float         pitch;
    std::uint64_t target_id;
    std::uint64_t timestamp_ms;
    std::uint8_t  anim_state;
    std::uint8_t  aggro_state;
    std::uint8_t  hp_pct;
    std::uint8_t  target_kind;
    std::uint8_t  flags;
    // v14 Ghost AI additions (45 B) ------------------------------------
    std::uint32_t package_form_id;          // hook: TESPackage::EvaluateConditions
    std::uint32_t combat_target_form_id;    // hook: SyncCombatTargetFromAIProcess
    float         aim_x;                    // hook: CombatAimController::SetAimTarget
    float         aim_y;
    float         aim_z;
    float         velocity_x;               // hook: TickMovementController
    float         velocity_y;
    float         velocity_z;
    std::uint8_t  weapon_state;             // hook: DrawWeapon dispatch
                                            //   0=none/1=drawing/2=drawn/3=holstering
    std::uint8_t  sighted;                  // hook: SetSightedState (0/1)
    std::uint8_t  sprinting;                // hook: SetSprintState (0/1)
    std::uint8_t  sneaking;                 // hook: SetSneakState (0/1)
    std::uint8_t  gun_down;                 // hook: ResolveCombatStance (0/1)
    std::uint8_t  aggression;               // hook: UpdateAggressionToGraph (0..100)
    std::uint16_t loco_state_pack;          // hook: LocoEventDispatch — 6 sync ints:
                                            //   bit 0    : iSyncIdleLocomotion
                                            //   bits 1-2 : iSyncTurnState
                                            //   bit 3    : iSyncForwardState
                                            //   bits 4-5 : iSyncStrafeState
                                            //   bits 6-7 : iSyncJumpState
                                            //   bit 8    : iSyncSwimState
                                            //   bits 9-15: reserved
    std::uint32_t sandbox_marker_handle;    // BGSProcedureSandbox state +88 — 0 if unused
    std::uint8_t  sandbox_idle_index;       // Sandbox state +100/+104 — 0 if unused
};
static_assert(sizeof(NPCStateEntry) == 98, "NPCStateEntry size (v14)");

struct NPCStateBroadcastHeader {
    std::uint16_t num_entries;   // <= MAX_NPC_STATES_PER_FRAME
    std::uint16_t reserved;      // 0 — alignment + future flags
};
static_assert(sizeof(NPCStateBroadcastHeader) == 4,
              "NPCStateBroadcastHeader size (v14)");

// B6.6w1 v15 — NPC_FIRE opcode payload. Server emits ONE per fire decision
// (raider_brain.py applies cooldown + visibility logic before sending).
// Client RX:
//   1. lookup_by_form_id(raider_form_id) → Actor* or null
//   2. if non-null AND raider is in our tracked-bail set, dispatch to
//      main thread engine::fire_actor_weapon(actor)
//
// `target_form_id` is informational for logging only — Actor::FireWeapon
// auto-resolves the actual target via the combatTarget chain we already
// keep pointing at PLAYER (force_in_combat_flag triple-write). Useful
// later when we add aim-direction injection.
struct NPCFirePayload {
    std::uint32_t raider_form_id;
    std::uint32_t target_form_id;   // 0x14 = player; 0 = unknown
    std::uint32_t flags;            // 0 = reserved; future: burst count / weapon hint
    // Build 55a (proto v15) — server picks per-raider per-window whether
    // this fire is aimed at LOCAL (vanilla AI handles) or GHOST (client
    // puppet-fire path). Eliminates dual-target flicker from competing
    // aim writes on Actor+0xC0 rotation.
    std::uint8_t  target_kind;      // 0=LOCAL, 1=GHOST
};
static_assert(sizeof(NPCFirePayload) == 13, "NPCFirePayload size (v15)");

constexpr std::uint8_t NPC_FIRE_TARGET_LOCAL = 0;
constexpr std::uint8_t NPC_FIRE_TARGET_GHOST = 1;

// B6.6w2 v16 — NPC_DISCOVER. Client emits ONE per first-time auto-track
// (Path 2 in npc_ai_suppress: actor's InCombat flag bit 0x4000 was set
// by vanilla AI → client decides "this is a hostile worth tracking").
//
// Reliable channel: discovery is event-driven (~once per encounter)
// and dropping would mean the server never knows this raider exists →
// no cross-peer sync for them. ACK ensures delivery.
//
// Wire: 24 bytes. The client reads these directly off the local Actor
// pointer (offsets from re/reference_fo4_offsets.md):
//   form_id  = *(u32*)(actor + FORMID_OFF=0x14)
//   base_id  = *(u32*)(*(TESForm**)(actor + BASE_FORM_OFF=0xE0) + 0x14)
//   cell_id  = *(u32*)(*(REFR**)(actor + PARENT_CELL_OFF=0xB8) + 0x14)
//   pos_x/y/z = (float*)(actor + POS_OFF=0xD0)[0..2]
struct NPCDiscoverPayload {
    std::uint32_t form_id;
    std::uint32_t base_id;
    std::uint32_t cell_id;
    float         pos_x;
    float         pos_y;
    float         pos_z;
};
static_assert(sizeof(NPCDiscoverPayload) == 24,
              "NPCDiscoverPayload size (v16)");

// B6.6w5 v17 — PEER_GHOST_REGISTER. Sender: client, after the engine
// spawns the local ghost-actor that represents the other peer.
// Receiver: server stores in PeerSession.ghost_form_id and uses it in
// project_for_peer to set combat_target_form_id correctly per-viewer.
struct PeerGhostRegisterPayload {
    std::uint32_t ghost_form_id;
};
static_assert(sizeof(PeerGhostRegisterPayload) == 4,
              "PeerGhostRegisterPayload size (v17)");

// Build 62 v17 — NPC_PERCEPTION_TRIGGER. Server-side proximity sphere
// fires this when a peer's ghost enters NPC X's perception radius.
//
// Per re/arena_synthesis/SUPERVISOR_SYNTHESIS.md: receiving client
// resolves both ends (lookup_by_form_id(npc_fid) for observer,
// peer_registry.get_ghost_actor_for_peer(peer_id) for target — or
// local PC if peer_id == self) and calls
// trigger_npc_perception(observer, target). Engine handles
// HighProcess+CombatController+AddTarget allocation in 1 frame.
//
// Server-side debounced 5s per (npc_fid, peer_id) pair to prevent
// re-trigger spam.
//
// Wire: 8 bytes (1+4+4 if opcode-prefixed; the packet header carries
// the opcode separately so this struct is 8B).
struct NpcPerceptionTriggerPayload {
    std::uint32_t npc_fid;     // the OBSERVER (NPC that should perceive)
    std::uint32_t peer_id;     // the TARGET (peer whose ghost is the threat)
};
static_assert(sizeof(NpcPerceptionTriggerPayload) == 8,
              "NpcPerceptionTriggerPayload size (Build 62 v17)");

// === Build 65 — owner-driven NPC sync (Solver 2) ===========================
//
// Wire format mirrors net/protocol.py (Build 65.a). All payloads are MTU-
// safe (≤ 1400 B framed) at the documented MAX_*_PER_FRAME caps.
//
// Phase A: server fires PHASE_2 directly on every ownership change. The
// old owner is expected to stop emitting state in ≤ 1 RTT; server rejects
// stale state via the epoch gate. PHASE_1 / RELEASE_ACK opcodes are
// reserved (handlers are no-op for now) so a future Phase B can layer on
// without a wire bump.
//
// PEER_ID encoding: 16-byte FixedClientId (UTF-8, NUL-padded, truncated).
// All-zero = "unowned" sentinel (only valid for PHASE_2 release frames).

constexpr std::size_t  PEER_ID_BYTES = 16;

// 0x0286 — NPC_OBSERVED. C→S, reliable. Wire 28 B.
struct NPCObservedPayload {
    std::uint32_t form_id;
    std::uint32_t base_id;
    std::uint32_t cell_id;
    float         pos_x;
    float         pos_y;
    float         pos_z;
    float         observer_distance_sq;
};
static_assert(sizeof(NPCObservedPayload) == 28,
              "NPCObservedPayload size (Build 65)");

// 0x0287 — NPC_UNLOAD. C→S, reliable. Wire 26 B.
struct NPCUnloadPayload {
    std::uint32_t form_id;
    std::uint32_t epoch;
    float         last_pos_x;
    float         last_pos_y;
    float         last_pos_z;
    float         last_yaw;
    std::uint8_t  last_anim_state;
    std::uint8_t  last_hp_pct;
};
static_assert(sizeof(NPCUnloadPayload) == 26,
              "NPCUnloadPayload size (Build 65)");

// 0x0284 — NPC_OWNER_HEARTBEAT. Body = u16 count + u16 reserved + N entries.
struct NPCOwnerHeartbeatEntry {
    std::uint32_t form_id;
    std::uint32_t epoch;
};
static_assert(sizeof(NPCOwnerHeartbeatEntry) == 8,
              "NPCOwnerHeartbeatEntry size (Build 65)");

struct NPCOwnerHeartbeatHeader {
    std::uint16_t num_entries;
    std::uint16_t reserved;     // 0 — alignment + future flags
};
static_assert(sizeof(NPCOwnerHeartbeatHeader) == 4,
              "NPCOwnerHeartbeatHeader size (Build 65)");

// MTU 1400 - 4 hdr = 1396; / 8 per entry = 174 → cap 170 (Python side).
constexpr std::uint16_t MAX_HEARTBEAT_ENTRIES = 170;

// 0x0281 — NPC_OWNERSHIP_HANDOFF_PHASE_1. S→old+new owners, reliable.
// Wire 48 B. Phase A: server does NOT emit this; handler logs + drops.
struct NPCOwnershipHandoffPhase1Payload {
    std::uint32_t form_id;
    std::uint32_t old_epoch;
    std::uint8_t  old_owner_peer_id[PEER_ID_BYTES];
    std::uint8_t  new_owner_peer_id[PEER_ID_BYTES];
    std::uint64_t deadline_ms;
};
static_assert(sizeof(NPCOwnershipHandoffPhase1Payload) == 48,
              "NPCOwnershipHandoffPhase1Payload size (Build 65)");

// 0x0282 — NPC_OWNERSHIP_RELEASE_ACK. C→S, reliable. Wire 32 B.
// Phase A: client does NOT emit this; reserved.
struct NPCOwnershipReleaseAckPayload {
    std::uint32_t form_id;
    std::uint32_t old_epoch;
    std::uint8_t  acker_peer_id[PEER_ID_BYTES];
    std::uint64_t ack_ts_ms;
};
static_assert(sizeof(NPCOwnershipReleaseAckPayload) == 32,
              "NPCOwnershipReleaseAckPayload size (Build 65)");

// 0x0283 — NPC_OWNERSHIP_HANDOFF_PHASE_2. S→all, reliable. Wire 32 B.
//
// Authoritative ownership change. Receiver updates local map:
//   g_ownership[form_id] = { new_epoch, new_owner_peer_id }
// All-zero new_owner_peer_id = release (NPC becomes unowned).
struct NPCOwnershipHandoffPhase2Payload {
    std::uint32_t form_id;
    std::uint32_t new_epoch;
    std::uint8_t  new_owner_peer_id[PEER_ID_BYTES];
    std::uint64_t handed_off_at_ms;
};
static_assert(sizeof(NPCOwnershipHandoffPhase2Payload) == 32,
              "NPCOwnershipHandoffPhase2Payload size (Build 65)");

// 0x0280 — NPC_OWNERSHIP_BCAST. S→peer (bootstrap on join) or S→all (post-
// handoff cleanup). Reliable. Header u16 count + u16 reserved + N entries.
struct NPCOwnershipBcastEntry {
    std::uint32_t form_id;
    std::uint32_t epoch;
    std::uint8_t  owner_peer_id[PEER_ID_BYTES];
};
static_assert(sizeof(NPCOwnershipBcastEntry) == 24,
              "NPCOwnershipBcastEntry size (Build 65)");

struct NPCOwnershipBcastHeader {
    std::uint16_t num_entries;
    std::uint16_t reserved;
};
static_assert(sizeof(NPCOwnershipBcastHeader) == 4,
              "NPCOwnershipBcastHeader size (Build 65)");

// MTU 1400 - 4 hdr = 1396; / 24 per entry = 58 → cap 57 (Python side).
constexpr std::uint16_t MAX_OWNERSHIP_BCAST_ENTRIES = 57;

// 0x0285 — NPC_STATE_FROM_OWNER. C→S→all, unreliable. Body = header + N
// entries × 76 B. Receiver gates each entry on (owner == fid's known
// owner, epoch == known epoch); drops stale.
struct NPCOwnerStateEntry {
    std::uint32_t form_id;
    std::uint32_t epoch;
    float         pos_x;
    float         pos_y;
    float         pos_z;
    float         yaw_rad;
    float         pitch_rad;
    std::uint32_t combat_target_fid;
    float         aim_x;
    float         aim_y;
    float         aim_z;
    float         velocity_x;
    float         velocity_y;
    float         velocity_z;
    std::uint8_t  anim_state;
    std::uint8_t  aggro_state;
    std::uint8_t  hp_pct;
    std::uint8_t  weapon_state;     // bit 3 = fire_this_tick
    std::uint8_t  sighted;
    std::uint8_t  sprinting;
    std::uint8_t  sneaking;
    std::uint8_t  gun_down;
    std::uint8_t  aggression;
    std::uint8_t  _pad;             // u8 padding to align loco_state_pack
    std::uint16_t loco_state_pack;
    std::uint64_t ts_ms;            // owner's monotonic ms
};
static_assert(sizeof(NPCOwnerStateEntry) == 76,
              "NPCOwnerStateEntry size (Build 65)");

struct NPCStateFromOwnerHeader {
    std::uint16_t num_entries;
    std::uint16_t reserved;
};
static_assert(sizeof(NPCStateFromOwnerHeader) == 4,
              "NPCStateFromOwnerHeader size (Build 65)");

// MTU 1400 - 4 hdr = 1396; / 76 = 18 → cap 17 (Python side).
constexpr std::uint16_t MAX_OWNER_STATES_PER_FRAME = 17;

// 0x0288 — NPC_FIRE_FROM_OWNER. C→S→all, unreliable. Wire 32 B.
struct NPCFireFromOwnerPayload {
    std::uint32_t form_id;
    std::uint32_t target_form_id;
    std::uint32_t weapon_form_id;
    float         aim_x;
    float         aim_y;
    float         aim_z;
    std::uint64_t ts_ms;
};
static_assert(sizeof(NPCFireFromOwnerPayload) == 32,
              "NPCFireFromOwnerPayload size (Build 65)");

// 0x0289 — NPC_DEATH_FROM_OWNER. C→S→all, reliable. Wire 48 B.
struct NPCDeathFromOwnerPayload {
    std::uint32_t form_id;
    std::uint32_t killer_form_id;   // 0 = environmental
    float         pos_x;
    float         pos_y;
    float         pos_z;
    float         ragdoll_x;
    float         ragdoll_y;
    float         ragdoll_z;
    float         damage;
    std::uint8_t  hit_zone;
    std::uint8_t  flags;
    std::uint16_t _pad;
    std::uint64_t ts_ms;
};
static_assert(sizeof(NPCDeathFromOwnerPayload) == 48,
              "NPCDeathFromOwnerPayload size (Build 65)");

// 0x028A — NPC_DAMAGE_FROM_OWNER. C→S→all, unreliable. Wire 28 B.
// Cosmetic: HP authority is the owner; this drives receiver-side hit
// react + ragdoll direction visuals.
struct NPCDamageFromOwnerPayload {
    std::uint32_t form_id;          // victim
    std::uint32_t attacker_form_id;
    std::uint32_t weapon_form_id;
    float         damage;
    std::uint8_t  hit_zone;
    std::uint8_t  flags;
    std::uint16_t _pad;
    std::uint64_t ts_ms;
};
static_assert(sizeof(NPCDamageFromOwnerPayload) == 28,
              "NPCDamageFromOwnerPayload size (Build 65)");

// 0x028B — NPC_ENGAGEMENT_CLAIM. C→S, unreliable. Wire 16 B.
//
// Build 65.c.23 — Non-owner peer's local engine has InCombat flag set
// (Actor+0x2D0 bit 0x4000) on a tracked NPC. Server uses this to force
// ownership handoff if current owner has not been reporting engagement
// (anim_state >= 3) for >= ENGAGEMENT_OWNERSHIP_GRACE_MS (= 3000 ms).
//
// Per-fid client-side dedup at 2s cooldown prevents flood. peer_id_hash
// is FNV-1a 32-bit of the local peer_id string, included as a sanity
// cross-check against the session-bound sender peer_id on the server.
struct NPCEngagementClaimPayload {
    std::uint32_t form_id;          // NPC whose InCombat flag is set
    std::uint32_t peer_id_hash;     // FNV-1a 32-bit hash of local peer_id
    std::uint64_t ts_ms;            // client monotonic ms (diag only)
};
static_assert(sizeof(NPCEngagementClaimPayload) == 16,
              "NPCEngagementClaimPayload size (Build 65.c.23)");

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
//   parent_placeholder_len bytes  — m_name of immediate parent of the
//                                   BSGeometry leaf; in practice this is
//                                   the mod NIF root's m_name (e.g.
//                                   "Pistol10mmReceiver"). Used as KEY
//                                   for resmgr-share lookup on receiver.
//   slot_name_len bytes           — m_name of the grand-parent of the
//                                   BSGeometry leaf; in practice this is
//                                   the slot placeholder INSIDE the base
//                                   weapon NIF (e.g. "PistolReceiver").
//                                   Used by receiver to position the mod
//                                   under the correct slot in the loaded
//                                   base weapon NIF. (Was `reserved` u16
//                                   before 2026-05-05; old blobs that
//                                   wrote 0 are still decodable and
//                                   simply skip the slot-aware attach.)
//   bgsm_path_len bytes
//   3*vert_count × f32 positions   (12 * vc bytes)
//   3*tri_count × u16 indices       (6 * tc bytes)
struct MeshRecordHeader {
    std::uint8_t  m_name_len;
    std::uint8_t  parent_placeholder_len;
    std::uint16_t bgsm_path_len;
    std::uint16_t vert_count;
    std::uint16_t slot_name_len;    // (was `reserved`; see comment above)
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
