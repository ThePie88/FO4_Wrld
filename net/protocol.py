"""
FalloutWorld wire protocol v1.

Design principles:
- Pure data + pure functions. No I/O. No global state.
- Every wire-format field has explicit width and endianness (little-endian).
- Structs map 1:1 to Rust (dataclass frozen slots -> #[derive(Serialize)] bincode).
- Errors raised as ProtocolError (never silent corruption).
- Forward/backward compat: unknown msg_type decoded as RawMessage.

Frame layout (header is fixed 12 bytes, payload variable):

  offset  size  field
  0       1     magic       (0xFA)
  1       1     version     (currently 1)
  2       2     msg_type    (u16 LE, see MessageType)
  4       4     seq         (u32 LE, per-connection monotonic)
  8       2     payload_len (u16 LE, <= MAX_PAYLOAD_SIZE)
  10      1     flags       (bitmask: FLAG_RELIABLE, ...)
  11      1     reserved    (0)
  12      N     payload     (N = payload_len bytes)

Total frame size: 12 + payload_len bytes.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from enum import IntEnum
from typing import ClassVar, Union

# ------------------------------------------------------------------ constants

PROTOCOL_MAGIC: int = 0xFA
PROTOCOL_VERSION: int = 16
# v16 (2026-05-31): ghost crouch — adds POSE_CROUCH_STATE (0x028E, C->S) and
# POSE_CROUCH_BROADCAST (0x028F, S->peers). A SEPARATE, additive channel
# alongside the working POSE_STATE/POSE_BROADCAST rotation pose: it replicates
# the vertical COM/Pelvis LOCAL TRANSLATION that a crouch produces (the body
# lowering), which the rotation-only pose could not carry (legs bent but body
# stayed at standing height → ghost feet "flew"). PoseCrouchEntry is
# {u16 bone_index; f32 tx,ty,tz} = 14 B, keyed on the SAME shared canonical
# bone index as the rotation pose. Tiny count (<=8, just COM + Pelvis). Does
# NOT touch PoseBoneEntry, the canonical bone filter, or the rotation
# capture/apply loops.
# v14 (2026-05-11): B6.5w12 Ghost AI decision-point sync — extends
# NPCStateEntry (53 → 98 B) with AI state fields the server pre-computes
# and pushes so the DLL's MinHook detours on engine decision functions
# (TESPackage::EvaluateConditions, Actor::SyncCombatTargetFromAIProcess,
# CombatAimController::SetAimTarget, Actor::TickMovementController, and
# the 7 anim-graph state-transition entry points) can substitute the
# server's value instead of letting local AI decide. This replaces the
# v13 "override engine output" pattern (B6.5w4 rounds 1-11, closed) with
# the inverse "redirect engine input" pattern — the engine still does
# all rendering, animation, IK, physics, collision natively. Wire growth
# per NPC: +45 B (package_form_id, combat_target_form_id, aim xyz,
# velocity xyz, weapon_state, sighted, sprinting, sneaking, gun_down,
# aggression, loco_state_pack, sandbox_marker_handle, sandbox_idle_index).
# MAX_NPC_STATES_PER_FRAME drops 26 → 14 (MTU 1400 still trivial; at
# 50 tracked NPCs the server emits 4 packets/tick instead of 2).
# v13 (2026-05-10): B6.5w2 NPC continuous state sync — adds
# NPC_STATE_BCAST (0x0270). Server-authoritative: the Python brain ticks
# all tracked NPCs at npc_tick_hz (default 10 Hz) and broadcasts a batched
# snapshot of (form_id, base_id, cell_id, pos, rot, anim_state, aggro,
# hp_pct, target, flags, ts) per NPC. Unreliable channel — drops are
# tolerable since the next tick resends. No peer_id (not relayed peer
# activity, fully server-authoritative). Wire growth: 53 B/NPC + 4 B
# header per frame, batched up to MAX_NPC_STATES_PER_FRAME = 26 entries
# per frame at MTU 1400. Receiver-side apply is B6.5w3 (engine bridge in
# fw_native using pos_update_seh + IAnimationGraphManagerHolder
# SetGraphVariable* RVAs from re/B6.5_npc_pipeline_AGENT_B.md). AI tick
# suppression on the receiver is B6.5w4. The DLL must rebuild + bump
# CLIENT_VERSION to handle this opcode; the receiver-less Python client
# parses + logs RX for end-to-end protocol verification.
# v12 (2026-05-08): B6.3 lock state sync — adds LOCK_OP (0x0240) and
# LOCK_BCAST (0x0241). Sender hooks engine ForceUnlock / ForceLock,
# broadcasts (form_id, base_id, cell_id, locked, timestamp_ms).
# Receiver applies via Papyrus binding sub_141158640 with ai_notify=0
# — bypasses the lockpicking minigame and key consumption. Server
# persists last-known state per (base_id, cell_id) and replays it to
# new peers on join. LockOpPayload = 21 B, LockBroadcastPayload = 37 B.
# v11 (2026-05-08): B6 prologue — cell-aware ghost. PosStatePayload and
# PosBroadcastPayload extended with `cell_id: u32` (parentCell.formID).
# Sender reads it from PlayerCharacter.parentCell.formID. Receiver compares
# with its own local cell every pos update and flips NIAV_FLAG_APP_CULLED
# on the ghost BSFadeNode when cells differ. Fixes the "ghost frozen at the
# door" bug when peer A enters an interior cell that peer B isn't loaded
# into. PosState 32→36 bytes, PosBroadcast 48→52 bytes.
# v9 (2026-04-30): M9 wedge 4 — raw mesh replication. New message types
# MESH_BLOB_OP (client→server) and MESH_BLOB_BCAST (server→peers) carry
# CHUNKS of a serialized mesh blob extracted from the local player's
# modded weapon. After 12 RE iterations + 4 failed hook strategies for
# the witness (NIF-path) pattern, we go BELOW the engine's mod-assembly
# pipeline and ship raw geometry: positions (decoded from packed half-prec
# stream), indices (u16), per-mesh metadata (m_name, parent_placeholder,
# bgsm_path), local transform. Receiver reconstructs each BSTriShape via
# the engine's clone factory (sub_14182FFD0) and attaches under the
# ghost's weapon root. See re/M9_w4_iter12_AGENT_analysis.md for the
# extraction layout (BSGeometryStreamHelper 32B at clone+0x148 →
# BSStreamDesc → raw vertex/index buffers).
# Wire format: chunked (per-mesh-blob), see MeshBlobChunkHeader below.
# Each MESH_BLOB_OP frame carries a slice of one logical mesh blob; the
# blob contains N meshes serialized linearly. Receiver reassembles by
# (peer_id, equip_seq) into the full blob then decodes the N meshes.
# v6 (2026-04-28): M9 wedge 1 equipment-event observation. New message types
# EQUIP_OP (client→server) and EQUIP_BCAST (server→peers) carrying
# {item_form_id, kind=equip|unequip, slot_form_id, count, timestamp_ms}.
# Sender hooks ActorEquipManager::EquipObject + UnequipObject in Fallout4.exe,
# filters local-player-only events, broadcasts. Receiver in wedge 1 just
# logs RX (no apply on ghost yet — wedge 2 will swap visuals on the M8P3
# ghost body using the same singleton + RVAs proven stable in B8).
# Wire growth: 21B for OP, 37B for BCAST.
# v5 (2026-04-21): B1.g container apply-to-engine. ContainerOpPayload and
# ContainerBroadcastPayload gain `container_form_id` (u32) — the sender's
# engine form_id for the touched container REFR. Receivers use
# `lookup_by_form_id(container_form_id)` + identity check (base, cell) to
# find their local REFR and invoke engine::apply_container_op_to_engine
# (AddItem/RemoveItem real). This is what finally makes "peer A takes
# item → peer B sees it disappear in their container UI" work end-to-end.
# Backward-compat: field defaults to 0 on Python side so existing call-
# sites stay valid; wire format grows by 4 bytes per CONTAINER_OP / BCAST.
# v4 (2026-04-20): B4 world-state expansion. New message types
# QUEST_STAGE_SET / QUEST_STAGE_BCAST, GLOBAL_VAR_SET / GLOBAL_VAR_BCAST,
# QUEST_STATE_BOOTSTRAP / GLOBAL_VAR_STATE_BOOTSTRAP for chunked snapshot
# on new-peer connect. Rationale §3.2 of the brainstorm: "10 player = 1
# entità narrativa" → quest progress is global, not per-peer. SetStage and
# GlobalVariable changes propagate to ALL peers, validator trivially
# monotonic (the engine already enforces it at the Papyrus level).
# v3 (2026-04-20): ContainerOpPayload carries `client_op_id` (monotonic per
# client) so the server can echo it back in CONTAINER_OP_ACK. The sender
# matches ACK-to-op via this id, enabling pre-mutation block: the C++ DLL
# holds a condvar keyed on op_id and waits ~100ms for the verdict before
# letting the engine's AddObjectToContainer proceed. Closes the container
# dup race that was a known limit after B0.
# v2 (2026-04-19): identity tuple (base_id, cell_id) — see above.
HEADER_SIZE: int = 12
MAX_PAYLOAD_SIZE: int = 1400   # stay under typical MTU 1500 minus IP+UDP headers
MAX_FRAME_SIZE: int = HEADER_SIZE + MAX_PAYLOAD_SIZE
MAX_CLIENT_ID_LEN: int = 15   # ASCII, null-terminated in 16 bytes

# Flag bitmask
FLAG_RELIABLE: int = 0x01   # sender requires ACK for this frame
FLAG_ACK_CARRIER: int = 0x02  # this frame piggybacks an ACK (future)


class MessageType(IntEnum):
    """Wire-level message type. Value is the u16 on wire."""

    # Connection management (0x00XX)
    HELLO         = 0x0001   # client -> server: introduce self
    WELCOME       = 0x0002   # server -> client: session accepted
    PEER_JOIN     = 0x0003   # server -> client: new peer
    PEER_LEAVE    = 0x0004   # server -> client: peer gone
    HEARTBEAT     = 0x0005   # client <-> server: keepalive
    DISCONNECT    = 0x0006   # either side: graceful close
    PEER_GHOST_REGISTER = 0x0007  # B6.6w5: client -> server: my local ghost-actor form_id (= the actor that represents the OTHER peer on my screen). Used by project_for_peer to substitute combat_target with the right local fid per-viewer.

    # Reliability
    ACK           = 0x0010   # server/client: acknowledges reliable frames

    # Bootstrap (0x002X) — server authoritative state to new/reconnecting clients
    WORLD_STATE           = 0x0020   # server -> client: world actor alive/dead snapshot
    CONTAINER_STATE       = 0x0021   # server -> client: container inventory snapshot (chunked)
    QUEST_STATE_BOOT      = 0x0022   # v4: server -> client: quest-stage snapshot (chunked)
    GLOBAL_VAR_STATE_BOOT = 0x0023   # v4: server -> client: global-var snapshot (chunked)

    # State replication (0x01XX) — unreliable, best-effort
    POS_STATE     = 0x0100   # client -> server: my pos+rot
    POS_BROADCAST = 0x0101   # server -> client: other peer's pos+rot
    POSE_STATE    = 0x0110   # M8P3.15: client -> server: my per-bone rotations
    POSE_BROADCAST = 0x0111  # M8P3.15: server -> client: other peer's per-bone rotations

    # Game events (0x02XX) — reliable, ack required
    ACTOR_EVENT      = 0x0200   # spawn/kill/disable actor
    CONTAINER_OP     = 0x0201   # client -> server: take/put in container
    CONTAINER_BCAST  = 0x0202   # server -> client: relay of container op (authoritative)
    CONTAINER_SEED   = 0x0203   # client -> server: full inventory dump at first-open
    CONTAINER_OP_ACK = 0x0204   # server -> sender: verdict (accepted / rejected + reason)
    DOOR_OP          = 0x0230   # B6.1: client -> server: I activated door X (toggle)
    DOOR_BCAST       = 0x0231   # B6.1: server -> other peers: peer X activated door Y
    EQUIP_OP         = 0x0240   # M9 w1: client -> server: I equipped/unequipped item X
    EQUIP_BCAST      = 0x0241   # M9 w1: server -> other peers: peer X equipped/unequipped item Y
    MESH_BLOB_OP     = 0x0250   # M9 w4 v9: client -> server: chunked mesh blob for an equip event
    MESH_BLOB_BCAST  = 0x0251   # M9 w4 v9: server -> peers: chunked mesh blob (peer-attributed)
    LOCK_OP          = 0x0260   # B6.3 v0.5.3: client -> server: lock state changed (locked/unlocked)
    LOCK_BCAST       = 0x0261   # B6.3 v0.5.3: server -> peers: lock state changed
    NPC_STATE_BCAST  = 0x0270   # B6.5w2 v13: server -> peers: batched NPC pos/anim state (unreliable, ~10 Hz)
    NPC_FIRE         = 0x0271   # B6.6w1 v15: server -> peers: "this raider fires its equipped weapon NOW" (event-driven)
    NPC_DISCOVER     = 0x0272   # B6.6w2 v16: client -> server: "I auto-tracked hostile NPC X (form+base+cell+pos)" (reliable, event-driven)
    NPC_PERCEPTION_TRIGGER = 0x0273  # Build 62 v17: server -> peers: "NPC X perceives peer Y's ghost — invoke CCF810 locally" (reliable, server-side sphere debounced 5s)

    # Build 65 — Owner-driven NPC sync (Solver 2 in re/agents_20/SOLVER_02_owner_driven.md).
    # Server elects one peer as the owner of each NPC. Owner runs full vanilla
    # engine AI; non-owners suppress local Update_PerFrame and apply the owner's
    # broadcast state. Wire opcodes ride alongside v15 — Phase A (server-only)
    # adds infrastructure that doesn't fire until Phase B (DLL) is matched.
    NPC_OWNERSHIP_BCAST           = 0x0280  # S→peer: bootstrap ownership snapshot (reliable, chunked) — sent on peer-join
    NPC_OWNERSHIP_HANDOFF_PHASE_1 = 0x0281  # S→old+new owner: release request for one NPC (reliable)
    NPC_OWNERSHIP_RELEASE_ACK     = 0x0282  # C→S: old owner acknowledges release (reliable)
    NPC_OWNERSHIP_HANDOFF_PHASE_2 = 0x0283  # S→all: new owner active for one NPC (reliable)
    NPC_OWNER_HEARTBEAT           = 0x0284  # C→S: list of fids+epochs we still own (unreliable, 2 Hz proof-of-life)
    NPC_STATE_FROM_OWNER          = 0x0285  # C→S→all: owner's authoritative state batch (unreliable, ~20-30 Hz)
    NPC_OBSERVED                  = 0x0286  # C→S: "I see NPC X at pos P, distance D" — election input (reliable)
    NPC_UNLOAD                    = 0x0287  # C→S: "NPC X left my loaded cell" — owner release / non-owner forget (reliable)
    NPC_FIRE_FROM_OWNER           = 0x0288  # C→S→all: owner's fire event (unreliable, replaces server-driven NPC_FIRE)
    NPC_DEATH_FROM_OWNER          = 0x0289  # C→S→all: owner's death event (reliable)
    NPC_DAMAGE_FROM_OWNER         = 0x028A  # C→S→all: owner's hit-applier event (unreliable, for ragdoll dir + visual cues)
    NPC_ENGAGEMENT_CLAIM          = 0x028B  # Build 65.c.23 — C→S: non-owner peer reports its local engine has InCombat flag set on a tracked NPC. Server uses this to force handoff if current owner hasn't reported engagement in last 3s. Fixes "wrong owner" architectural mismatch where first-observer wins but isn't the actual fighter.
    NPC_POSE_FROM_OWNER           = 0x028C  # c.37.0 — C→S→all: owner's per-bone rotation snapshot for ONE owned NPC, keyed by form_id. Full pose replication (like player→ghost) so the mirror animates bone-by-bone instead of the coarse pos/yaw/anim-enum relay. Unreliable, ~15-20 Hz per NPC.
    NPC_DAMAGE_CLAIM              = 0x028D  # c.39b — C→S: "my local player dealt D damage to NPC X". Drives damage-based ownership/aggro (chi fa più danno possiede). Unreliable, client-throttled ~6 Hz/fid.
    NPC_CROUCH_FROM_OWNER         = 0x0290  # NPC crouch — C→S→all: owner's COM/Pelvis LOCAL TRANSLATION snapshot for ONE owned NPC, keyed by form_id. The NPC analogue of POSE_CROUCH (rotation pose bends the raider's legs but leaves the body at standing height → feet "fly"; this carries the vertical drop). Unreliable, ~same rate as NPC_POSE_FROM_OWNER.

    # v16 — ghost crouch. SEPARATE additive channel beside POSE_STATE/BROADCAST.
    # Replicates the vertical COM/Pelvis local translation a crouch produces
    # (rotation-only pose left the body at standing height → feet flew).
    POSE_CROUCH_STATE     = 0x028E  # v16: client -> server: my crouch bone translations (COM/Pelvis +0x60 local translate)
    POSE_CROUCH_BROADCAST = 0x028F  # v16: server -> other peers: peer X's crouch bone translations

    # Social (0x03XX) — reliable
    CHAT          = 0x0300

    # World state replication (0x04XX) — reliable, applied in-order per key
    QUEST_STATE       = 0x0400   # DEPRECATED legacy constant — use QUEST_STAGE_*
    QUEST_STAGE_SET   = 0x0401   # v4: client -> server: I set quest X to stage N
    QUEST_STAGE_BCAST = 0x0402   # v4: server -> other peers: peer X set quest Y to stage N
    GLOBAL_VAR_SET    = 0x0411   # v4: client -> server: I set GlobalVar X to value V
    GLOBAL_VAR_BCAST  = 0x0412   # v4: server -> other peers: peer X set GlobalVar Y to V


class ProtocolError(Exception):
    """Raised for any wire-format violation."""


# ------------------------------------------------------------------ header

@dataclass(frozen=True, slots=True)
class FrameHeader:
    msg_type: int      # u16 (MessageType value; raw int to support unknown)
    seq: int           # u32
    payload_len: int   # u16
    flags: int = 0     # u8

    # Constants duplicated for Rust portability (const VALUE in struct)
    MAGIC: ClassVar[int] = PROTOCOL_MAGIC
    VERSION: ClassVar[int] = PROTOCOL_VERSION
    SIZE: ClassVar[int] = HEADER_SIZE

    def __post_init__(self) -> None:
        if not 0 <= self.msg_type <= 0xFFFF:
            raise ProtocolError(f"msg_type out of u16 range: {self.msg_type}")
        if not 0 <= self.seq <= 0xFFFFFFFF:
            raise ProtocolError(f"seq out of u32 range: {self.seq}")
        if not 0 <= self.payload_len <= MAX_PAYLOAD_SIZE:
            raise ProtocolError(f"payload_len invalid: {self.payload_len}")
        if not 0 <= self.flags <= 0xFF:
            raise ProtocolError(f"flags out of u8 range: {self.flags}")

    @property
    def is_reliable(self) -> bool:
        return bool(self.flags & FLAG_RELIABLE)


_HEADER_STRUCT = struct.Struct("<BBHIHBB")  # magic, ver, mtype, seq, plen, flags, reserved


def encode_header(h: FrameHeader) -> bytes:
    """Serialize header to exactly HEADER_SIZE bytes."""
    return _HEADER_STRUCT.pack(
        PROTOCOL_MAGIC, PROTOCOL_VERSION,
        h.msg_type, h.seq, h.payload_len, h.flags, 0,
    )


def decode_header(data: bytes) -> FrameHeader:
    """Deserialize header from (at least) HEADER_SIZE bytes."""
    if len(data) < HEADER_SIZE:
        raise ProtocolError(f"header truncated: got {len(data)} bytes, need {HEADER_SIZE}")
    magic, ver, mtype, seq, plen, flags, _reserved = _HEADER_STRUCT.unpack_from(data, 0)
    if magic != PROTOCOL_MAGIC:
        raise ProtocolError(f"bad magic: 0x{magic:02X}")
    if ver != PROTOCOL_VERSION:
        raise ProtocolError(f"unsupported protocol version: {ver}")
    if plen > MAX_PAYLOAD_SIZE:
        raise ProtocolError(f"payload too big: {plen}")
    return FrameHeader(msg_type=mtype, seq=seq, payload_len=plen, flags=flags)


# ------------------------------------------------------------------ payloads

# Each payload class exposes .encode() -> bytes and classmethod .decode(data) -> Self.
# This symmetry makes code generation (to Rust) trivial.

def _encode_fixed_string(s: str, max_len: int) -> bytes:
    data = s.encode("ascii", errors="strict")
    if len(data) > max_len:
        raise ProtocolError(f"string too long ({len(data)} > {max_len}): {s!r}")
    return data.ljust(max_len + 1, b"\x00")[: max_len + 1]  # include null terminator


def _decode_fixed_string(buf: bytes, max_len: int) -> str:
    field = buf[: max_len + 1]
    null = field.find(b"\x00")
    if null < 0:
        raise ProtocolError("fixed string not null-terminated")
    return field[:null].decode("ascii", errors="strict")


@dataclass(frozen=True, slots=True)
class HelloPayload:
    client_id: str            # ASCII max 15
    client_version_major: int # u8
    client_version_minor: int # u8
    steam_id: int = 0         # u64; 0 = unavailable (B6.6w5+)

    _STRUCT_HEAD: ClassVar[struct.Struct] = struct.Struct("<BB")
    _STRUCT_TAIL: ClassVar[struct.Struct] = struct.Struct("<Q")

    def encode(self) -> bytes:
        return (
            _encode_fixed_string(self.client_id, MAX_CLIENT_ID_LEN)
            + self._STRUCT_HEAD.pack(
                self.client_version_major, self.client_version_minor)
            + self._STRUCT_TAIL.pack(self.steam_id & 0xFFFFFFFFFFFFFFFF)
        )

    @classmethod
    def decode(cls, data: bytes) -> "HelloPayload":
        off = MAX_CLIENT_ID_LEN + 1   # 16
        head_size = cls._STRUCT_HEAD.size   # 2
        tail_size = cls._STRUCT_TAIL.size   # 8
        if len(data) < off + head_size:
            raise ProtocolError("HELLO truncated (head)")
        cid = _decode_fixed_string(data, MAX_CLIENT_ID_LEN)
        vma, vmi = cls._STRUCT_HEAD.unpack_from(data, off)
        # B6.6w5: steam_id tail is OPTIONAL for backwards compat.
        # Legacy 18-byte HELLO from old clients → steam_id defaults to 0.
        steam_id = 0
        if len(data) >= off + head_size + tail_size:
            (steam_id,) = cls._STRUCT_TAIL.unpack_from(
                data, off + head_size)
        return cls(cid, vma, vmi, steam_id)


@dataclass(frozen=True, slots=True)
class WelcomePayload:
    session_id: int          # u32, server-assigned
    accepted: bool           # u8 (0/1)
    server_version_major: int
    server_version_minor: int
    tick_rate_hz: int        # u16, how often server broadcasts state

    _STRUCT: ClassVar[struct.Struct] = struct.Struct("<IBBBH")

    def encode(self) -> bytes:
        return self._STRUCT.pack(
            self.session_id,
            1 if self.accepted else 0,
            self.server_version_major,
            self.server_version_minor,
            self.tick_rate_hz,
        )

    @classmethod
    def decode(cls, data: bytes) -> "WelcomePayload":
        if len(data) < cls._STRUCT.size:
            raise ProtocolError("WELCOME truncated")
        sid, acc, vma, vmi, tick = cls._STRUCT.unpack_from(data, 0)
        return cls(sid, bool(acc), vma, vmi, tick)


@dataclass(frozen=True, slots=True)
class PeerJoinPayload:
    peer_id: str             # ASCII, max 15
    session_id: int          # u32

    _STRUCT: ClassVar[struct.Struct] = struct.Struct("<I")

    def encode(self) -> bytes:
        return (
            _encode_fixed_string(self.peer_id, MAX_CLIENT_ID_LEN)
            + self._STRUCT.pack(self.session_id)
        )

    @classmethod
    def decode(cls, data: bytes) -> "PeerJoinPayload":
        off = MAX_CLIENT_ID_LEN + 1
        if len(data) < off + cls._STRUCT.size:
            raise ProtocolError("PEER_JOIN truncated")
        pid = _decode_fixed_string(data, MAX_CLIENT_ID_LEN)
        (sid,) = cls._STRUCT.unpack_from(data, off)
        return cls(pid, sid)


@dataclass(frozen=True, slots=True)
class PeerLeavePayload:
    peer_id: str
    reason: int              # u8: 0=timeout, 1=disconnect, 2=kick

    _STRUCT: ClassVar[struct.Struct] = struct.Struct("<B")

    def encode(self) -> bytes:
        return (
            _encode_fixed_string(self.peer_id, MAX_CLIENT_ID_LEN)
            + self._STRUCT.pack(self.reason)
        )

    @classmethod
    def decode(cls, data: bytes) -> "PeerLeavePayload":
        off = MAX_CLIENT_ID_LEN + 1
        if len(data) < off + cls._STRUCT.size:
            raise ProtocolError("PEER_LEAVE truncated")
        pid = _decode_fixed_string(data, MAX_CLIENT_ID_LEN)
        (reason,) = cls._STRUCT.unpack_from(data, off)
        return cls(pid, reason)


@dataclass(frozen=True, slots=True)
class HeartbeatPayload:
    timestamp_ms: int        # u64, sender wall clock
    _STRUCT: ClassVar[struct.Struct] = struct.Struct("<Q")
    def encode(self) -> bytes: return self._STRUCT.pack(self.timestamp_ms)
    @classmethod
    def decode(cls, data: bytes) -> "HeartbeatPayload":
        if len(data) < cls._STRUCT.size: raise ProtocolError("HEARTBEAT truncated")
        return cls(cls._STRUCT.unpack_from(data, 0)[0])


@dataclass(frozen=True, slots=True)
class AckPayload:
    """Selective ACK: acks all frames up to highest_contiguous_seq,
    plus a 32-bit bitmap where bit N means highest_contiguous_seq+N+1 was received."""

    highest_contiguous_seq: int  # u32
    sack_bitmap: int             # u32

    _STRUCT: ClassVar[struct.Struct] = struct.Struct("<II")

    def encode(self) -> bytes:
        return self._STRUCT.pack(self.highest_contiguous_seq, self.sack_bitmap)

    @classmethod
    def decode(cls, data: bytes) -> "AckPayload":
        if len(data) < cls._STRUCT.size:
            raise ProtocolError("ACK truncated")
        return cls(*cls._STRUCT.unpack_from(data, 0))


@dataclass(frozen=True, slots=True)
class PosStatePayload:
    """Current local player pos+rot snapshot. Unreliable.

    v11 (B6 prologue): adds cell_id (parentCell.formID) so the receiver
    can compare with its own local cell and CULL the ghost when peers
    are in different cells.
    """
    x: float; y: float; z: float   # world coords (float32)
    rx: float; ry: float; rz: float # rotation radians (float32)
    timestamp_ms: int              # u64 client wall clock (for RTT/interp)
    cell_id: int = 0               # v11: parentCell.formID (u32)

    _STRUCT: ClassVar[struct.Struct] = struct.Struct("<6fQI")

    def encode(self) -> bytes:
        return self._STRUCT.pack(self.x, self.y, self.z,
                                  self.rx, self.ry, self.rz,
                                  self.timestamp_ms,
                                  self.cell_id)

    @classmethod
    def decode(cls, data: bytes) -> "PosStatePayload":
        if len(data) < cls._STRUCT.size:
            raise ProtocolError("POS_STATE truncated")
        return cls(*cls._STRUCT.unpack_from(data, 0))


@dataclass(frozen=True, slots=True)
class PosBroadcastPayload:
    """Pos+rot of a remote peer, as relayed by server. Extends PosState with peer_id.

    v11 (B6 prologue): adds cell_id, mirrored from PosStatePayload.
    """
    peer_id: str
    x: float; y: float; z: float
    rx: float; ry: float; rz: float
    timestamp_ms: int
    cell_id: int = 0               # v11: peer's parentCell.formID (u32)

    _STRUCT: ClassVar[struct.Struct] = struct.Struct("<6fQI")

    def encode(self) -> bytes:
        return (
            _encode_fixed_string(self.peer_id, MAX_CLIENT_ID_LEN)
            + self._STRUCT.pack(self.x, self.y, self.z,
                                 self.rx, self.ry, self.rz,
                                 self.timestamp_ms,
                                 self.cell_id)
        )

    @classmethod
    def decode(cls, data: bytes) -> "PosBroadcastPayload":
        off = MAX_CLIENT_ID_LEN + 1
        if len(data) < off + cls._STRUCT.size:
            raise ProtocolError("POS_BROADCAST truncated")
        pid = _decode_fixed_string(data, MAX_CLIENT_ID_LEN)
        x, y, z, rx, ry, rz, ts, cell = cls._STRUCT.unpack_from(data, off)
        return cls(pid, x, y, z, rx, ry, rz, ts, cell)


# ---- M8P3.15 POSE replication ----------------------------------------------
# Header: <Q H = 10 bytes (timestamp_ms, bone_count)
# Tail:   bone_count × <ffff = 16 bytes (qx, qy, qz, qw)
# Max payload at 64 bones: 10 + 64*16 = 1034 bytes < MAX_PAYLOAD_SIZE 1400 ✓

MAX_POSE_BONES = 80   # M8P3.17: bumped from 64 (skel.nif has ~70 joints)


@dataclass(frozen=True, slots=True)
class PoseStatePayload:
    """Per-bone rotation snapshot (quaternions) of local player. Unreliable."""
    timestamp_ms: int          # u64
    quats: tuple[tuple[float, float, float, float], ...]
    # quats[i] = (qx, qy, qz, qw) for bone i in deterministic sort order

    _HEADER: ClassVar[struct.Struct] = struct.Struct("<QH")
    _ENTRY:  ClassVar[struct.Struct] = struct.Struct("<ffff")

    def encode(self) -> bytes:
        if len(self.quats) > MAX_POSE_BONES:
            raise ProtocolError(f"too many bones: {len(self.quats)}")
        head = self._HEADER.pack(self.timestamp_ms, len(self.quats))
        body = b''.join(self._ENTRY.pack(*q) for q in self.quats)
        return head + body

    @classmethod
    def decode(cls, data: bytes) -> "PoseStatePayload":
        if len(data) < cls._HEADER.size:
            raise ProtocolError("POSE_STATE truncated header")
        ts, n = cls._HEADER.unpack_from(data, 0)
        if n > MAX_POSE_BONES:
            raise ProtocolError(f"POSE_STATE bone_count too high: {n}")
        need = cls._HEADER.size + n * cls._ENTRY.size
        if len(data) < need:
            raise ProtocolError("POSE_STATE truncated body")
        quats = tuple(
            cls._ENTRY.unpack_from(data, cls._HEADER.size + i * cls._ENTRY.size)
            for i in range(n)
        )
        return cls(ts, quats)


@dataclass(frozen=True, slots=True)
class PoseBroadcastPayload:
    """Per-bone rotation of a remote peer, relayed by server."""
    peer_id: str
    timestamp_ms: int
    quats: tuple[tuple[float, float, float, float], ...]

    _HEADER: ClassVar[struct.Struct] = struct.Struct("<QH")
    _ENTRY:  ClassVar[struct.Struct] = struct.Struct("<ffff")

    def encode(self) -> bytes:
        if len(self.quats) > MAX_POSE_BONES:
            raise ProtocolError(f"too many bones: {len(self.quats)}")
        return (
            _encode_fixed_string(self.peer_id, MAX_CLIENT_ID_LEN)
            + self._HEADER.pack(self.timestamp_ms, len(self.quats))
            + b''.join(self._ENTRY.pack(*q) for q in self.quats)
        )

    @classmethod
    def decode(cls, data: bytes) -> "PoseBroadcastPayload":
        off = MAX_CLIENT_ID_LEN + 1
        if len(data) < off + cls._HEADER.size:
            raise ProtocolError("POSE_BROADCAST truncated header")
        pid = _decode_fixed_string(data, MAX_CLIENT_ID_LEN)
        ts, n = cls._HEADER.unpack_from(data, off)
        if n > MAX_POSE_BONES:
            raise ProtocolError(f"POSE_BROADCAST bone_count too high: {n}")
        need = off + cls._HEADER.size + n * cls._ENTRY.size
        if len(data) < need:
            raise ProtocolError("POSE_BROADCAST truncated body")
        quats = tuple(
            cls._ENTRY.unpack_from(data, off + cls._HEADER.size + i * cls._ENTRY.size)
            for i in range(n)
        )
        return cls(pid, ts, quats)


# ---- v16 POSE_CROUCH replication -------------------------------------------
# A SEPARATE, additive channel beside POSE_STATE/POSE_BROADCAST. The rotation
# pose (PoseBoneEntry, 16 B) is unchanged and keeps working; this channel only
# carries the vertical COM/Pelvis LOCAL TRANSLATION that a crouch produces.
# Each entry is keyed on the SAME shared canonical bone index as the rotation
# pose (both clients walk the identical, sorted, UNFILTERED canonical list, so
# the index is a reliable cross-client key). count is tiny (<= 8 — just COM
# and Pelvis today).
#
# Header (STATE): <Q B = 9 bytes (timestamp_ms, count)
# Header (BCAST): FixedString(15+1) + <Q B = 25 bytes (peer_id, ts, count)
# Entry:          <H fff = 14 bytes (bone_index, tx, ty, tz)

MAX_POSE_CROUCH_BONES = 8


@dataclass(frozen=True, slots=True)
class PoseCrouchStatePayload:
    """Per-bone local-translation snapshot (crouch) of the local player.

    Unreliable. entries[i] = (bone_index, tx, ty, tz) where bone_index is the
    canonical index shared with the rotation pose. Mirrors the
    PoseStatePayload -> PoseBroadcastPayload server fan-out pattern.
    """
    timestamp_ms: int          # u64
    entries: tuple[tuple[int, float, float, float], ...]
    # entries[i] = (bone_index, tx, ty, tz)

    _HEADER: ClassVar[struct.Struct] = struct.Struct("<QB")
    _ENTRY:  ClassVar[struct.Struct] = struct.Struct("<Hfff")

    def encode(self) -> bytes:
        if len(self.entries) > MAX_POSE_CROUCH_BONES:
            raise ProtocolError(f"too many crouch bones: {len(self.entries)}")
        head = self._HEADER.pack(self.timestamp_ms, len(self.entries))
        body = b''.join(self._ENTRY.pack(*e) for e in self.entries)
        return head + body

    @classmethod
    def decode(cls, data: bytes) -> "PoseCrouchStatePayload":
        if len(data) < cls._HEADER.size:
            raise ProtocolError("POSE_CROUCH_STATE truncated header")
        ts, n = cls._HEADER.unpack_from(data, 0)
        if n > MAX_POSE_CROUCH_BONES:
            raise ProtocolError(f"POSE_CROUCH_STATE count too high: {n}")
        need = cls._HEADER.size + n * cls._ENTRY.size
        if len(data) < need:
            raise ProtocolError("POSE_CROUCH_STATE truncated body")
        entries = tuple(
            cls._ENTRY.unpack_from(data, cls._HEADER.size + i * cls._ENTRY.size)
            for i in range(n)
        )
        return cls(ts, entries)


@dataclass(frozen=True, slots=True)
class PoseCrouchBroadcastPayload:
    """Crouch bone translations of a remote peer, relayed by server.

    Extends PoseCrouchStatePayload with peer_id (mirrors PoseBroadcastPayload).
    """
    peer_id: str
    timestamp_ms: int
    entries: tuple[tuple[int, float, float, float], ...]

    _HEADER: ClassVar[struct.Struct] = struct.Struct("<QB")
    _ENTRY:  ClassVar[struct.Struct] = struct.Struct("<Hfff")

    def encode(self) -> bytes:
        if len(self.entries) > MAX_POSE_CROUCH_BONES:
            raise ProtocolError(f"too many crouch bones: {len(self.entries)}")
        return (
            _encode_fixed_string(self.peer_id, MAX_CLIENT_ID_LEN)
            + self._HEADER.pack(self.timestamp_ms, len(self.entries))
            + b''.join(self._ENTRY.pack(*e) for e in self.entries)
        )

    @classmethod
    def decode(cls, data: bytes) -> "PoseCrouchBroadcastPayload":
        off = MAX_CLIENT_ID_LEN + 1
        if len(data) < off + cls._HEADER.size:
            raise ProtocolError("POSE_CROUCH_BROADCAST truncated header")
        pid = _decode_fixed_string(data, MAX_CLIENT_ID_LEN)
        ts, n = cls._HEADER.unpack_from(data, off)
        if n > MAX_POSE_CROUCH_BONES:
            raise ProtocolError(f"POSE_CROUCH_BROADCAST count too high: {n}")
        need = off + cls._HEADER.size + n * cls._ENTRY.size
        if len(data) < need:
            raise ProtocolError("POSE_CROUCH_BROADCAST truncated body")
        entries = tuple(
            cls._ENTRY.unpack_from(data, off + cls._HEADER.size + i * cls._ENTRY.size)
            for i in range(n)
        )
        return cls(pid, ts, entries)


@dataclass(frozen=True, slots=True)
class NPCPoseFromOwnerPayload:
    """c.37.0 — owner's per-bone rotation snapshot for ONE owned NPC.

    C→S→all (relayed unchanged). Same quaternion bone format as POSE_STATE,
    prefixed with the NPC's form_id so the receiver resolves the mirror
    actor via lookup_by_form_id and drives ITS skeleton exactly like the
    player→ghost pose path. Bone i aligns by the shared canonical joint-name
    list (identical human skeleton on both clients). Sentinel qw=2.0 means
    "joint absent on owner" → receiver skips that bone (keeps bind pose).

    Server validates the sender owns `form_id`, then fans the SAME frame out
    to every non-owner. No epoch gate: pose is cosmetic best-effort, a few
    stale frames during a handoff are invisible under the new owner's stream.

    Wire: 14 (header) + N × 16.
    """
    form_id: int
    timestamp_ms: int
    quats: tuple[tuple[float, float, float, float], ...]

    _HEADER: ClassVar[struct.Struct] = struct.Struct("<IQH")  # form_id, ts, bone_count
    _ENTRY:  ClassVar[struct.Struct] = struct.Struct("<ffff")

    def encode(self) -> bytes:
        if len(self.quats) > MAX_POSE_BONES:
            raise ProtocolError(f"NPC_POSE too many bones: {len(self.quats)}")
        head = self._HEADER.pack(
            self.form_id & 0xFFFFFFFF,
            self.timestamp_ms & 0xFFFFFFFFFFFFFFFF,
            len(self.quats),
        )
        body = b''.join(self._ENTRY.pack(*q) for q in self.quats)
        return head + body

    @classmethod
    def decode(cls, data: bytes) -> "NPCPoseFromOwnerPayload":
        if len(data) < cls._HEADER.size:
            raise ProtocolError("NPC_POSE truncated header")
        fid, ts, n = cls._HEADER.unpack_from(data, 0)
        if n > MAX_POSE_BONES:
            raise ProtocolError(f"NPC_POSE bone_count too high: {n}")
        need = cls._HEADER.size + n * cls._ENTRY.size
        if len(data) < need:
            raise ProtocolError("NPC_POSE truncated body")
        quats = tuple(
            cls._ENTRY.unpack_from(data, cls._HEADER.size + i * cls._ENTRY.size)
            for i in range(n)
        )
        return cls(fid, ts, quats)


@dataclass(frozen=True, slots=True)
class NPCCrouchFromOwnerPayload:
    """NPC crouch — owner's COM/Pelvis LOCAL TRANSLATION snapshot for ONE owned NPC.

    C→S→all (relayed unchanged). The NPC analogue of PoseCrouchStatePayload:
    same {bone_index, tx, ty, tz} entry format (the +0x60 m_kLocal.translate of
    the COM/Pelvis bones), prefixed with the NPC's form_id so the receiver
    resolves the mirror actor via lookup_by_form_id and lowers ITS skeleton —
    exactly like NPCPoseFromOwnerPayload does for the rotation pose. The
    rotation pose (NPC_POSE_FROM_OWNER) bends the legs but leaves the body at
    standing height; this carries the vertical drop so the raider's feet stop
    "flying". Entries keyed on the SAME shared canonical bone index as the
    rotation pose. count is tiny (<= MAX_POSE_CROUCH_BONES; COM + Pelvis today).

    Server validates the sender owns `form_id`, then fans the SAME frame out to
    every non-owner (mirrors `_handle_npc_pose_from_owner`). No epoch gate.

    Wire: 13 (header <IQB) + N × 14 (entry <Hfff).
    """
    form_id: int
    timestamp_ms: int
    entries: tuple[tuple[int, float, float, float], ...]
    # entries[i] = (bone_index, tx, ty, tz)

    _HEADER: ClassVar[struct.Struct] = struct.Struct("<IQB")  # form_id, ts, count
    _ENTRY:  ClassVar[struct.Struct] = struct.Struct("<Hfff")

    def encode(self) -> bytes:
        if len(self.entries) > MAX_POSE_CROUCH_BONES:
            raise ProtocolError(
                f"NPC_CROUCH too many bones: {len(self.entries)}")
        head = self._HEADER.pack(
            self.form_id & 0xFFFFFFFF,
            self.timestamp_ms & 0xFFFFFFFFFFFFFFFF,
            len(self.entries),
        )
        body = b''.join(self._ENTRY.pack(*e) for e in self.entries)
        return head + body

    @classmethod
    def decode(cls, data: bytes) -> "NPCCrouchFromOwnerPayload":
        if len(data) < cls._HEADER.size:
            raise ProtocolError("NPC_CROUCH truncated header")
        fid, ts, n = cls._HEADER.unpack_from(data, 0)
        if n > MAX_POSE_CROUCH_BONES:
            raise ProtocolError(f"NPC_CROUCH count too high: {n}")
        need = cls._HEADER.size + n * cls._ENTRY.size
        if len(data) < need:
            raise ProtocolError("NPC_CROUCH truncated body")
        entries = tuple(
            cls._ENTRY.unpack_from(data, cls._HEADER.size + i * cls._ENTRY.size)
            for i in range(n)
        )
        return cls(fid, ts, entries)


@dataclass(frozen=True, slots=True)
class NPCDamageClaimPayload:
    """c.39b — C→S: the local player dealt `amount` damage to NPC `form_id`.

    Used by the threat table to make ownership/aggro follow the real fighter:
    the server accumulates a per-peer decayed damage sum per NPC, and the peer
    with the most recent damage wins ownership (even if both peers are engaged,
    which the combat-target signal alone can't disambiguate). Unreliable;
    client throttles to ~6 Hz/fid (accumulating between sends).

    Wire: 8 bytes.
    """
    form_id: int
    amount: float

    _STRUCT: ClassVar[struct.Struct] = struct.Struct("<If")  # form_id, amount

    def encode(self) -> bytes:
        return self._STRUCT.pack(self.form_id & 0xFFFFFFFF, float(self.amount))

    @classmethod
    def decode(cls, data: bytes) -> "NPCDamageClaimPayload":
        if len(data) < cls._STRUCT.size:
            raise ProtocolError("NPC_DAMAGE_CLAIM truncated")
        fid, amount = cls._STRUCT.unpack_from(data, 0)
        return cls(form_id=fid, amount=amount)


class ActorEventKind(IntEnum):
    SPAWN   = 1
    KILL    = 2
    DISABLE = 3
    ENABLE  = 4


@dataclass(frozen=True, slots=True)
class ActorEventPayload:
    """A significant actor state change. Reliable (requires ACK).

    Identity fields (protocol v2+):
      - form_id      : session-scoped ref id. Stable for 0x00______ placed refs,
                       session-scoped for 0xFF______ runtime refs. Used as a
                       hint for fast-path LookupByFormID on the receiving peer.
      - actor_base_id: TESForm.formID of the ref's baseForm (stable across
                       processes — plugin-loaded). Part of the persistence key.
      - cell_id      : TESForm.formID of the ref's parentCell (stable across
                       processes). Second part of the persistence key.

    The server keys its authoritative world state on (actor_base_id, cell_id),
    NOT on form_id. This prevents the 0xFF______ aliasing bug where the same
    runtime id points to different objects in two separate Fallout4.exe
    processes.
    """
    kind: int                # ActorEventKind
    form_id: int             # u32 refid hint (0xFF_______ for runtime spawns)
    actor_base_id: int       # u32 base form id (identity key for persistence)
    x: float; y: float; z: float  # for SPAWN: location
    extra: int               # u32 flags (kind-specific)
    cell_id: int = 0         # u32 parentCell formid (identity key). 0 = unknown.

    _STRUCT: ClassVar[struct.Struct] = struct.Struct("<IIIfffII")

    def encode(self) -> bytes:
        return self._STRUCT.pack(self.kind, self.form_id, self.actor_base_id,
                                  self.x, self.y, self.z, self.extra,
                                  self.cell_id)

    @classmethod
    def decode(cls, data: bytes) -> "ActorEventPayload":
        if len(data) < cls._STRUCT.size:
            raise ProtocolError("ACTOR_EVENT truncated")
        kind, fid, base, x, y, z, extra, cell = cls._STRUCT.unpack_from(data, 0)
        return cls(kind=kind, form_id=fid, actor_base_id=base,
                   x=x, y=y, z=z, extra=extra, cell_id=cell)


@dataclass(frozen=True, slots=True)
class ChatPayload:
    sender_id: str           # ASCII max 15
    text: str                # UTF-8, length-prefixed u16

    def encode(self) -> bytes:
        sender = _encode_fixed_string(self.sender_id, MAX_CLIENT_ID_LEN)
        text_b = self.text.encode("utf-8")
        if len(text_b) > MAX_PAYLOAD_SIZE - len(sender) - 2:
            raise ProtocolError("chat text too long")
        return sender + struct.pack("<H", len(text_b)) + text_b

    @classmethod
    def decode(cls, data: bytes) -> "ChatPayload":
        off = MAX_CLIENT_ID_LEN + 1
        if len(data) < off + 2:
            raise ProtocolError("CHAT truncated header")
        sender = _decode_fixed_string(data, MAX_CLIENT_ID_LEN)
        (tlen,) = struct.unpack_from("<H", data, off)
        off += 2
        if len(data) < off + tlen:
            raise ProtocolError("CHAT truncated text")
        text = data[off:off + tlen].decode("utf-8", errors="replace")
        return cls(sender, text)


@dataclass(frozen=True, slots=True)
class DisconnectPayload:
    reason: int              # u8: 0=graceful, 1=error, 2=version_mismatch
    _STRUCT: ClassVar[struct.Struct] = struct.Struct("<B")
    def encode(self) -> bytes: return self._STRUCT.pack(self.reason)
    @classmethod
    def decode(cls, data: bytes) -> "DisconnectPayload":
        if len(data) < cls._STRUCT.size: raise ProtocolError("DISCONNECT truncated")
        return cls(cls._STRUCT.unpack_from(data, 0)[0])


@dataclass(frozen=True, slots=True)
class WorldActorEntry:
    """One actor's authoritative alive/dead state.

    The persistence identity key is (base_id, cell_id), both stable across
    processes. The form_id is a hint — useful for fast-path LookupByFormID on
    placed refs (0x00______) where ref_id is itself stable, but must be
    validated against (base_id, cell_id) before applying any state change
    because runtime refs (0xFF______) alias across processes.
    """
    form_id: int        # u32 — last-known ref_id (hint, not key). 0 if unknown.
    alive: bool         # u8 (0/1)
    base_id: int = 0    # u32 — TESForm.formID of baseForm. 0 = legacy entry.
    cell_id: int = 0    # u32 — TESForm.formID of parentCell. 0 = legacy entry.


@dataclass(frozen=True, slots=True)
class WorldStatePayload:
    """Full world-actor snapshot from server to client.

    Variable-length list of actor states. The client applies these to its
    local FO4 instance so everyone starts from the same authoritative view.

    Wire format (protocol v2):
        u16  num_entries
        u16  chunk_index
        u16  total_chunks
        per entry (13B):
            u32 form_id   (ref_id hint)
            u32 base_id   (TESForm.formID of baseForm — identity key)
            u32 cell_id   (TESForm.formID of parentCell — identity key)
            u8  alive     (0/1)

    Entries per frame cap: (1400 - 6) // 13 = 107. Multi-chunk via
    `chunk_index` + `total_chunks`.
    """

    entries: tuple[WorldActorEntry, ...]
    chunk_index: int = 0     # u16 — 0-based
    total_chunks: int = 1    # u16 — total in this bootstrap sequence

    _ENTRY_STRUCT: ClassVar[struct.Struct] = struct.Struct("<IIIB")  # 13B
    _HEADER_STRUCT: ClassVar[struct.Struct] = struct.Struct("<HHH")  # 6B

    MAX_ENTRIES_PER_FRAME: ClassVar[int] = (
        (MAX_PAYLOAD_SIZE - 6) // 13  # 107 entries per chunk at MTU 1400
    )

    def encode(self) -> bytes:
        if len(self.entries) > self.MAX_ENTRIES_PER_FRAME:
            raise ProtocolError(
                f"WORLD_STATE too many entries: {len(self.entries)} > {self.MAX_ENTRIES_PER_FRAME}"
            )
        parts = [self._HEADER_STRUCT.pack(len(self.entries), self.chunk_index, self.total_chunks)]
        for e in self.entries:
            parts.append(self._ENTRY_STRUCT.pack(
                e.form_id, e.base_id, e.cell_id, 1 if e.alive else 0
            ))
        return b"".join(parts)

    @classmethod
    def decode(cls, data: bytes) -> "WorldStatePayload":
        if len(data) < cls._HEADER_STRUCT.size:
            raise ProtocolError("WORLD_STATE header truncated")
        num, chunk_idx, total = cls._HEADER_STRUCT.unpack_from(data, 0)
        expected_size = cls._HEADER_STRUCT.size + num * cls._ENTRY_STRUCT.size
        if len(data) < expected_size:
            raise ProtocolError(f"WORLD_STATE payload truncated: got {len(data)}, need {expected_size}")
        entries = []
        off = cls._HEADER_STRUCT.size
        for _ in range(num):
            fid, base, cell, alive = cls._ENTRY_STRUCT.unpack_from(data, off)
            entries.append(WorldActorEntry(
                form_id=fid, alive=bool(alive),
                base_id=base, cell_id=cell,
            ))
            off += cls._ENTRY_STRUCT.size
        return cls(
            entries=tuple(entries),
            chunk_index=chunk_idx,
            total_chunks=total,
        )


class ContainerOpKind(IntEnum):
    """Kind of container modification."""
    TAKE = 1   # player removed N items from container
    PUT  = 2   # player added N items to container


class EquipOpKind(IntEnum):
    """M9 w1: kind of equipment-state change observed on the local player.

    Wedge 1 is OBSERVE-only: server fans out, peers log. Wedge 2 will branch
    on this enum to call ActorEquipManager::EquipObject vs ::UnequipObject
    on the M8P3 ghost body representing the originating peer.
    """
    EQUIP   = 1   # local player equipped (post-Equip detour fire)
    UNEQUIP = 2   # local player unequipped


@dataclass(frozen=True, slots=True)
class ContainerOpPayload:
    """Client -> server: a take/put operation on a container's inventory.

    v3: adds `client_op_id` (monotonic per client) so the server can echo
    it back in CONTAINER_OP_ACK for sender-side correlation. The sender
    uses it to wake a condvar-gated pre-mutation wait: if accepted, the
    engine's AddObjectToContainer proceeds; if rejected, the sender
    skips the call (blocks the mutation) before the item transfer happens.

    Identity is the (container_base_id, container_cell_id) tuple — same
    rationale as Option B for actors (stable across processes). item_base_id
    is a TESForm.formID of the item template (stable plugin-loaded).

    For v1 we don't carry extra-data (weapon mods, enchantments, leveled
    variants) — a modded 10mm and a vanilla 10mm are treated as the same
    item. TODO once container UX forces the issue.

    count is SIGNED i32 for future-proofing but MUST be > 0 at send time.
    The OP kind (TAKE/PUT) conveys the direction; count stays positive.
    """
    kind: int                    # ContainerOpKind (1 or 2)
    container_base_id: int       # u32
    container_cell_id: int       # u32
    item_base_id: int            # u32
    count: int                   # i32, must be > 0
    timestamp_ms: int            # u64, client wall clock
    client_op_id: int = 0        # u32 — v3; echoed back in CONTAINER_OP_ACK.
    container_form_id: int = 0   # u32 — v5; sender's engine form_id for the
                                 # touched container REFR. Receivers use this
                                 # to find their local REFR via engine's
                                 # LookupByFormID, then validate (base, cell)
                                 # match, then invoke real AddItem/RemoveItem.
                                 # 0 = legacy / unknown → receiver can't apply.

    _STRUCT: ClassVar[struct.Struct] = struct.Struct("<IIIIiQII")  # 36B (v5: +4 for container_form_id)

    def encode(self) -> bytes:
        return self._STRUCT.pack(
            self.kind, self.container_base_id, self.container_cell_id,
            self.item_base_id, self.count, self.timestamp_ms,
            self.client_op_id, self.container_form_id,
        )

    @classmethod
    def decode(cls, data: bytes) -> "ContainerOpPayload":
        if len(data) < cls._STRUCT.size:
            raise ProtocolError("CONTAINER_OP truncated")
        kind, cbase, ccell, ibase, cnt, ts, op_id, cfid = cls._STRUCT.unpack_from(data, 0)
        return cls(
            kind=kind, container_base_id=cbase, container_cell_id=ccell,
            item_base_id=ibase, count=cnt, timestamp_ms=ts,
            client_op_id=op_id, container_form_id=cfid,
        )


@dataclass(frozen=True, slots=True)
class ContainerBroadcastPayload:
    """Server -> client: authoritative broadcast of a container op by a peer.

    Mirrors ContainerOpPayload but carries peer_id (the originating session's
    user id) so receivers can attribute the change and for telemetry/UI.
    """
    peer_id: str                 # ASCII max MAX_CLIENT_ID_LEN
    kind: int
    container_base_id: int
    container_cell_id: int
    item_base_id: int
    count: int
    timestamp_ms: int
    container_form_id: int = 0   # u32 — v5; sender's engine form_id for the
                                 # touched container REFR. Receivers use
                                 # lookup_by_form_id + identity check on
                                 # (base, cell) to find their local REFR and
                                 # invoke engine::apply_container_op_to_engine.
                                 # 0 = legacy / unknown → receiver can't apply.

    _STRUCT: ClassVar[struct.Struct] = struct.Struct("<IIIIiQI")  # 28B (v5: +4 for container_form_id)

    def encode(self) -> bytes:
        return (
            _encode_fixed_string(self.peer_id, MAX_CLIENT_ID_LEN)
            + self._STRUCT.pack(
                self.kind, self.container_base_id, self.container_cell_id,
                self.item_base_id, self.count, self.timestamp_ms,
                self.container_form_id,
            )
        )

    @classmethod
    def decode(cls, data: bytes) -> "ContainerBroadcastPayload":
        off = MAX_CLIENT_ID_LEN + 1
        if len(data) < off + cls._STRUCT.size:
            raise ProtocolError("CONTAINER_BCAST truncated")
        pid = _decode_fixed_string(data, MAX_CLIENT_ID_LEN)
        kind, cbase, ccell, ibase, cnt, ts, cfid = cls._STRUCT.unpack_from(data, off)
        return cls(
            peer_id=pid, kind=kind,
            container_base_id=cbase, container_cell_id=ccell,
            item_base_id=ibase, count=cnt, timestamp_ms=ts,
            container_form_id=cfid,
        )


@dataclass(frozen=True, slots=True)
class ContainerStateEntry:
    """One (container, item) pair with its authoritative count.

    A container with N distinct item types produces N entries. A fully
    looted container produces 0 entries (not a single entry with count=0).
    Bootstrap rebuilds the container's inventory by aggregating all entries
    matching the same (container_base_id, container_cell_id).
    """
    container_base_id: int       # u32
    container_cell_id: int       # u32
    item_base_id: int            # u32
    count: int                   # i32 (signed for future; >= 0 in practice)


@dataclass(frozen=True, slots=True)
class ContainerStatePayload:
    """Chunked snapshot of all container inventories on the server.

    Wire format (protocol v2):
        u16  num_entries
        u16  chunk_index
        u16  total_chunks
        per entry (16B):
            u32 container_base_id
            u32 container_cell_id
            u32 item_base_id
            i32 count

    Entries per frame cap: (1400 - 6) // 16 = 87. Multi-chunk via
    chunk_index + total_chunks, same pattern as WorldStatePayload.
    """

    entries: tuple[ContainerStateEntry, ...]
    chunk_index: int = 0
    total_chunks: int = 1

    _ENTRY_STRUCT: ClassVar[struct.Struct] = struct.Struct("<IIIi")  # 16B
    _HEADER_STRUCT: ClassVar[struct.Struct] = struct.Struct("<HHH")  # 6B

    MAX_ENTRIES_PER_FRAME: ClassVar[int] = (
        (MAX_PAYLOAD_SIZE - 6) // 16  # 87 entries per chunk at MTU 1400
    )

    def encode(self) -> bytes:
        if len(self.entries) > self.MAX_ENTRIES_PER_FRAME:
            raise ProtocolError(
                f"CONTAINER_STATE too many entries: {len(self.entries)} > {self.MAX_ENTRIES_PER_FRAME}"
            )
        parts = [self._HEADER_STRUCT.pack(len(self.entries), self.chunk_index, self.total_chunks)]
        for e in self.entries:
            parts.append(self._ENTRY_STRUCT.pack(
                e.container_base_id, e.container_cell_id,
                e.item_base_id, e.count,
            ))
        return b"".join(parts)

    @classmethod
    def decode(cls, data: bytes) -> "ContainerStatePayload":
        if len(data) < cls._HEADER_STRUCT.size:
            raise ProtocolError("CONTAINER_STATE header truncated")
        num, chunk_idx, total = cls._HEADER_STRUCT.unpack_from(data, 0)
        expected_size = cls._HEADER_STRUCT.size + num * cls._ENTRY_STRUCT.size
        if len(data) < expected_size:
            raise ProtocolError(f"CONTAINER_STATE payload truncated: got {len(data)}, need {expected_size}")
        entries = []
        off = cls._HEADER_STRUCT.size
        for _ in range(num):
            cbase, ccell, ibase, cnt = cls._ENTRY_STRUCT.unpack_from(data, off)
            entries.append(ContainerStateEntry(
                container_base_id=cbase, container_cell_id=ccell,
                item_base_id=ibase, count=cnt,
            ))
            off += cls._ENTRY_STRUCT.size
        return cls(
            entries=tuple(entries),
            chunk_index=chunk_idx,
            total_chunks=total,
        )


class ContainerOpAckStatus(IntEnum):
    """Verdict the server ships back to the sender of a CONTAINER_OP."""
    ACCEPTED        = 0
    REJ_RATE        = 1   # rate-limited
    REJ_IDENTITY    = 2   # missing / zero identity
    REJ_COUNT       = 3   # count <= 0 or absurd
    REJ_KIND        = 4   # unknown op kind
    REJ_INSUFFICIENT = 5  # TAKE count > what the container has (race loser)


@dataclass(frozen=True, slots=True)
class ContainerOpAckPayload:
    """Server -> sender only: verdict for a previously-sent CONTAINER_OP.

    Identified by the client-supplied `client_op_id` (monotonic per client).
    The DLL/Python-client stamps each outgoing TAKE/PUT with an id and waits
    on a condvar keyed on that id. On receipt, the worker fires the waiter.
    A timeout on the waiter means "treat as rejected + log".

    status: one of ContainerOpAckStatus. On ACCEPTED the op is effective;
    the server also broadcasts a CONTAINER_BCAST to the OTHER peers.
    On any REJ_* the state is unchanged and no broadcast is emitted.
    """
    client_op_id: int           # u32 — echo of sender's id
    status: int                 # u8 (ContainerOpAckStatus)
    # Snapshot of the final server-side count for this item in this container
    # AFTER the op was processed. Lets the sender reconcile its local mirror
    # without a full bootstrap.
    container_base_id: int      # u32
    container_cell_id: int      # u32
    item_base_id: int           # u32
    final_count: int            # i32

    _STRUCT: ClassVar[struct.Struct] = struct.Struct("<IBIIIi")  # 21 bytes

    def encode(self) -> bytes:
        return self._STRUCT.pack(
            self.client_op_id, self.status,
            self.container_base_id, self.container_cell_id,
            self.item_base_id, self.final_count,
        )

    @classmethod
    def decode(cls, data: bytes) -> "ContainerOpAckPayload":
        if len(data) < cls._STRUCT.size:
            raise ProtocolError("CONTAINER_OP_ACK truncated")
        op_id, status, cbase, ccell, ibase, fcnt = cls._STRUCT.unpack_from(data, 0)
        return cls(
            client_op_id=op_id, status=status,
            container_base_id=cbase, container_cell_id=ccell,
            item_base_id=ibase, final_count=fcnt,
        )


@dataclass(frozen=True, slots=True)
class ContainerSeedPayload:
    """Client -> server: full inventory of a container that the player just
    opened for the first time this session.

    Replaces the server's state for that (base, cell) with the client's
    ground truth. This is what closes the "trust-the-client on first TAKE"
    loophole from B0 — once the server knows the full inventory, subsequent
    TAKEs can be validated with INSUFFICIENT_ITEMS.

    Wire format identical to CONTAINER_STATE (shared chunked-list primitive):
      u16 num_entries
      u16 chunk_index
      u16 total_chunks
      u32 container_base_id   (repeated in each entry for alignment w/ CONTAINER_STATE,
      u32 container_cell_id    but in SEED all entries share the same container)
      u32 item_base_id
      i32 count

    Small inventories (<87 items) ship in a single chunk. For very large
    containers (unlikely in FO4; >87 unique item types) we chunk.
    """
    entries: tuple["ContainerStateEntry", ...]
    chunk_index: int = 0
    total_chunks: int = 1

    _ENTRY_STRUCT: ClassVar[struct.Struct] = struct.Struct("<IIIi")
    _HEADER_STRUCT: ClassVar[struct.Struct] = struct.Struct("<HHH")

    MAX_ENTRIES_PER_FRAME: ClassVar[int] = (
        (MAX_PAYLOAD_SIZE - 6) // 16
    )

    def encode(self) -> bytes:
        if len(self.entries) > self.MAX_ENTRIES_PER_FRAME:
            raise ProtocolError(
                f"CONTAINER_SEED too many entries: {len(self.entries)} > {self.MAX_ENTRIES_PER_FRAME}"
            )
        parts = [self._HEADER_STRUCT.pack(len(self.entries), self.chunk_index, self.total_chunks)]
        for e in self.entries:
            parts.append(self._ENTRY_STRUCT.pack(
                e.container_base_id, e.container_cell_id,
                e.item_base_id, e.count,
            ))
        return b"".join(parts)

    @classmethod
    def decode(cls, data: bytes) -> "ContainerSeedPayload":
        if len(data) < cls._HEADER_STRUCT.size:
            raise ProtocolError("CONTAINER_SEED header truncated")
        num, chunk_idx, total = cls._HEADER_STRUCT.unpack_from(data, 0)
        expected_size = cls._HEADER_STRUCT.size + num * cls._ENTRY_STRUCT.size
        if len(data) < expected_size:
            raise ProtocolError(
                f"CONTAINER_SEED payload truncated: got {len(data)}, need {expected_size}"
            )
        entries = []
        off = cls._HEADER_STRUCT.size
        for _ in range(num):
            cbase, ccell, ibase, cnt = cls._ENTRY_STRUCT.unpack_from(data, off)
            entries.append(ContainerStateEntry(
                container_base_id=cbase, container_cell_id=ccell,
                item_base_id=ibase, count=cnt,
            ))
            off += cls._ENTRY_STRUCT.size
        return cls(
            entries=tuple(entries),
            chunk_index=chunk_idx,
            total_chunks=total,
        )


# =================================================================== B4
#
# World-state expansion: quest-stage sync + global-variable sync.
#
# Design notes:
#   - Quest progress is GLOBAL across all peers (brainstorm §3.2). No per-
#     peer filtering. SetStage is effectively monotonic at the Papyrus
#     level (the engine refuses to go backwards unless ResetQuest is
#     called), so the server validator is trivial: accept everything,
#     last-write-wins, broadcast to other peers.
#   - Global variables can be ints, shorts, or floats in the engine.
#     We represent them uniformly as f64 on the wire — f32 globals are
#     lossless, i32 globals fit in f64's 53-bit mantissa exactly.
#   - Both types follow the CONTAINER_OP/BCAST pattern: a client-side SET
#     payload and a server-side BCAST payload (BCAST adds peer_id).
#   - Bootstrap snapshots (QUEST_STATE_BOOT, GLOBAL_VAR_STATE_BOOT) use
#     the shared chunked-list primitive (ChunkHeader HHH prefix).

@dataclass(frozen=True, slots=True)
class QuestStageSetPayload:
    """Client -> server: "I just set quest X to stage N"."""
    quest_form_id: int       # u32
    new_stage: int           # u16 (engine stages fit u16; the few with
                             # >65535 stages are script-driven globals anyway)
    timestamp_ms: int        # u64, client wall clock

    _STRUCT: ClassVar[struct.Struct] = struct.Struct("<IHQ")  # 14 bytes; H padded to Q-align

    def encode(self) -> bytes:
        return self._STRUCT.pack(self.quest_form_id, self.new_stage, self.timestamp_ms)

    @classmethod
    def decode(cls, data: bytes) -> "QuestStageSetPayload":
        if len(data) < cls._STRUCT.size:
            raise ProtocolError("QUEST_STAGE_SET truncated")
        fid, stage, ts = cls._STRUCT.unpack_from(data, 0)
        return cls(quest_form_id=fid, new_stage=stage, timestamp_ms=ts)


@dataclass(frozen=True, slots=True)
class QuestStageBroadcastPayload:
    """Server -> other peers: authoritative relay of a SetStage event."""
    peer_id: str             # ASCII max MAX_CLIENT_ID_LEN
    quest_form_id: int
    new_stage: int
    timestamp_ms: int

    _STRUCT: ClassVar[struct.Struct] = struct.Struct("<IHQ")

    def encode(self) -> bytes:
        return (
            _encode_fixed_string(self.peer_id, MAX_CLIENT_ID_LEN)
            + self._STRUCT.pack(self.quest_form_id, self.new_stage, self.timestamp_ms)
        )

    @classmethod
    def decode(cls, data: bytes) -> "QuestStageBroadcastPayload":
        off = MAX_CLIENT_ID_LEN + 1
        if len(data) < off + cls._STRUCT.size:
            raise ProtocolError("QUEST_STAGE_BCAST truncated")
        pid = _decode_fixed_string(data, MAX_CLIENT_ID_LEN)
        fid, stage, ts = cls._STRUCT.unpack_from(data, off)
        return cls(peer_id=pid, quest_form_id=fid, new_stage=stage, timestamp_ms=ts)


@dataclass(frozen=True, slots=True)
class QuestStageStateEntry:
    """One (quest_form_id, stage) pair for the bootstrap snapshot."""
    quest_form_id: int
    stage: int


@dataclass(frozen=True, slots=True)
class QuestStateBootPayload:
    """Server -> client: chunked quest-stage snapshot on new-peer connect.

    Wire format: ChunkHeader (HHH) + per entry (I H = 6 bytes).
    """
    entries: tuple[QuestStageStateEntry, ...]
    chunk_index: int = 0
    total_chunks: int = 1

    _ENTRY_STRUCT: ClassVar[struct.Struct] = struct.Struct("<IH")
    _HEADER_STRUCT: ClassVar[struct.Struct] = struct.Struct("<HHH")

    MAX_ENTRIES_PER_FRAME: ClassVar[int] = (
        (MAX_PAYLOAD_SIZE - 6) // 6  # 232 entries per chunk at MTU 1400
    )

    def encode(self) -> bytes:
        if len(self.entries) > self.MAX_ENTRIES_PER_FRAME:
            raise ProtocolError(
                f"QUEST_STATE_BOOT too many entries: {len(self.entries)} > "
                f"{self.MAX_ENTRIES_PER_FRAME}"
            )
        parts = [self._HEADER_STRUCT.pack(
            len(self.entries), self.chunk_index, self.total_chunks)]
        for e in self.entries:
            parts.append(self._ENTRY_STRUCT.pack(e.quest_form_id, e.stage))
        return b"".join(parts)

    @classmethod
    def decode(cls, data: bytes) -> "QuestStateBootPayload":
        if len(data) < cls._HEADER_STRUCT.size:
            raise ProtocolError("QUEST_STATE_BOOT header truncated")
        num, chunk_idx, total = cls._HEADER_STRUCT.unpack_from(data, 0)
        expected = cls._HEADER_STRUCT.size + num * cls._ENTRY_STRUCT.size
        if len(data) < expected:
            raise ProtocolError(
                f"QUEST_STATE_BOOT payload truncated: got {len(data)}, need {expected}")
        entries = []
        off = cls._HEADER_STRUCT.size
        for _ in range(num):
            fid, stage = cls._ENTRY_STRUCT.unpack_from(data, off)
            entries.append(QuestStageStateEntry(quest_form_id=fid, stage=stage))
            off += cls._ENTRY_STRUCT.size
        return cls(entries=tuple(entries), chunk_index=chunk_idx, total_chunks=total)


@dataclass(frozen=True, slots=True)
class GlobalVarSetPayload:
    """Client -> server: "I just set GlobalVar X to value V"."""
    global_form_id: int      # u32
    value: float             # f64 — carries i32/f32 globals losslessly
    timestamp_ms: int        # u64

    _STRUCT: ClassVar[struct.Struct] = struct.Struct("<IdQ")  # 20 bytes

    def encode(self) -> bytes:
        return self._STRUCT.pack(self.global_form_id, self.value, self.timestamp_ms)

    @classmethod
    def decode(cls, data: bytes) -> "GlobalVarSetPayload":
        if len(data) < cls._STRUCT.size:
            raise ProtocolError("GLOBAL_VAR_SET truncated")
        fid, val, ts = cls._STRUCT.unpack_from(data, 0)
        return cls(global_form_id=fid, value=val, timestamp_ms=ts)


@dataclass(frozen=True, slots=True)
class GlobalVarBroadcastPayload:
    """Server -> other peers: authoritative relay of a GlobalVar.SetValue."""
    peer_id: str
    global_form_id: int
    value: float
    timestamp_ms: int

    _STRUCT: ClassVar[struct.Struct] = struct.Struct("<IdQ")

    def encode(self) -> bytes:
        return (
            _encode_fixed_string(self.peer_id, MAX_CLIENT_ID_LEN)
            + self._STRUCT.pack(self.global_form_id, self.value, self.timestamp_ms)
        )

    @classmethod
    def decode(cls, data: bytes) -> "GlobalVarBroadcastPayload":
        off = MAX_CLIENT_ID_LEN + 1
        if len(data) < off + cls._STRUCT.size:
            raise ProtocolError("GLOBAL_VAR_BCAST truncated")
        pid = _decode_fixed_string(data, MAX_CLIENT_ID_LEN)
        fid, val, ts = cls._STRUCT.unpack_from(data, off)
        return cls(peer_id=pid, global_form_id=fid, value=val, timestamp_ms=ts)


@dataclass(frozen=True, slots=True)
class GlobalVarStateEntry:
    global_form_id: int
    value: float


@dataclass(frozen=True, slots=True)
class GlobalVarStateBootPayload:
    """Server -> client: chunked global-var snapshot on new-peer connect.

    Wire format: ChunkHeader (HHH) + per entry (I d = 12 bytes).
    """
    entries: tuple[GlobalVarStateEntry, ...]
    chunk_index: int = 0
    total_chunks: int = 1

    _ENTRY_STRUCT: ClassVar[struct.Struct] = struct.Struct("<Id")
    _HEADER_STRUCT: ClassVar[struct.Struct] = struct.Struct("<HHH")

    MAX_ENTRIES_PER_FRAME: ClassVar[int] = (
        (MAX_PAYLOAD_SIZE - 6) // 12  # 116 entries per chunk at MTU 1400
    )

    def encode(self) -> bytes:
        if len(self.entries) > self.MAX_ENTRIES_PER_FRAME:
            raise ProtocolError(
                f"GLOBAL_VAR_STATE_BOOT too many entries: {len(self.entries)} > "
                f"{self.MAX_ENTRIES_PER_FRAME}"
            )
        parts = [self._HEADER_STRUCT.pack(
            len(self.entries), self.chunk_index, self.total_chunks)]
        for e in self.entries:
            parts.append(self._ENTRY_STRUCT.pack(e.global_form_id, e.value))
        return b"".join(parts)

    @classmethod
    def decode(cls, data: bytes) -> "GlobalVarStateBootPayload":
        if len(data) < cls._HEADER_STRUCT.size:
            raise ProtocolError("GLOBAL_VAR_STATE_BOOT header truncated")
        num, chunk_idx, total = cls._HEADER_STRUCT.unpack_from(data, 0)
        expected = cls._HEADER_STRUCT.size + num * cls._ENTRY_STRUCT.size
        if len(data) < expected:
            raise ProtocolError(
                f"GLOBAL_VAR_STATE_BOOT payload truncated: got {len(data)}, need {expected}")
        entries = []
        off = cls._HEADER_STRUCT.size
        for _ in range(num):
            fid, val = cls._ENTRY_STRUCT.unpack_from(data, off)
            entries.append(GlobalVarStateEntry(global_form_id=fid, value=val))
            off += cls._ENTRY_STRUCT.size
        return cls(entries=tuple(entries), chunk_index=chunk_idx, total_chunks=total)


@dataclass(frozen=True, slots=True)
class DoorOpPayload:
    """B6.1: client -> server: 'I just activated door X'.

    Toggle semantics — sub_140514180 (engine Activate worker) flips the
    door's open state on every call. The op is identity-only; the new
    state isn't carried because we don't need it: the receiver invokes
    its own Activate worker on the matching local REFR, which performs
    the same flip from whatever local state was. Both clients converge
    as long as they started from the same world_base save (engine load
    applies persisted state via vt[0x99] = sub_140510CE0 → all doors
    start in the save's recorded state).

    Identity is the (door_base_id, door_cell_id) tuple, plus form_id
    for the receiver to look up its local REFR. Same approach used by
    container ops — proven in B1 + B5.
    """
    door_form_id: int    # u32 — sender's REFR form_id (lookup_by_form_id on receiver)
    door_base_id: int    # u32 — base TESObjectACTI/DOOR formID (identity check)
    door_cell_id: int    # u32 — cell formID (identity check)
    timestamp_ms: int    # u64 — sender wall clock for ordering / telemetry

    _STRUCT: ClassVar[struct.Struct] = struct.Struct("<IIIQ")  # 20B

    def encode(self) -> bytes:
        return self._STRUCT.pack(
            self.door_form_id, self.door_base_id,
            self.door_cell_id, self.timestamp_ms,
        )

    @classmethod
    def decode(cls, data: bytes) -> "DoorOpPayload":
        if len(data) != cls._STRUCT.size:
            raise ValueError(
                f"DoorOpPayload: expected {cls._STRUCT.size} bytes, got {len(data)}")
        fid, bid, cid, ts = cls._STRUCT.unpack(data)
        return cls(door_form_id=fid, door_base_id=bid,
                   door_cell_id=cid, timestamp_ms=ts)


@dataclass(frozen=True, slots=True)
class DoorBroadcastPayload:
    """B6.1: server -> other peers: 'peer X activated door Y'.

    Mirrors DoorOpPayload but adds peer_id for attribution / telemetry.
    No validation server-side; doors are toggle-only and self-correcting
    (next press resyncs).
    """
    peer_id: str                 # ASCII max MAX_CLIENT_ID_LEN
    door_form_id: int
    door_base_id: int
    door_cell_id: int
    timestamp_ms: int

    _STRUCT: ClassVar[struct.Struct] = struct.Struct("<IIIQ")  # 20B + 16B peer_id = 36B total

    def encode(self) -> bytes:
        return (
            _encode_fixed_string(self.peer_id, MAX_CLIENT_ID_LEN)
            + self._STRUCT.pack(
                self.door_form_id, self.door_base_id,
                self.door_cell_id, self.timestamp_ms,
            )
        )

    @classmethod
    def decode(cls, data: bytes) -> "DoorBroadcastPayload":
        expected = MAX_CLIENT_ID_LEN + 1 + cls._STRUCT.size  # 16 + 20 = 36
        if len(data) != expected:
            raise ValueError(
                f"DoorBroadcastPayload: expected {expected} bytes, got {len(data)}")
        peer = _decode_fixed_string(data[: MAX_CLIENT_ID_LEN + 1], MAX_CLIENT_ID_LEN)
        fid, bid, cid, ts = cls._STRUCT.unpack(data[MAX_CLIENT_ID_LEN + 1:])
        return cls(peer_id=peer, door_form_id=fid, door_base_id=bid,
                   door_cell_id=cid, timestamp_ms=ts)


@dataclass(frozen=True, slots=True)
class LockOpPayload:
    """B6.3 v0.5.3 — client -> server: 'I just changed lock state on REFR X'.

    Identity is (lock_form_id, lock_base_id, lock_cell_id) like doors —
    receiver looks up its local REFR via lookup_by_form_id and validates
    against base+cell. New state in `locked`: 0=unlocked, 1=locked.
    Sender hooks engine ForceUnlock (sub_140563320) and ForceLock
    (sub_140563360). Receiver applies via Papyrus binding sub_141158640
    with ai_notify=0 — bypasses minigame and key consumption.
    """
    lock_form_id: int    # u32 — sender's REFR form_id
    lock_base_id: int    # u32 — base form id (identity check)
    lock_cell_id: int    # u32 — cell form id (identity check)
    locked: int          # u8  — 0 = unlocked, 1 = locked
    timestamp_ms: int    # u64 — sender wall clock for ordering / dedup

    _STRUCT: ClassVar[struct.Struct] = struct.Struct("<IIIBQ")  # 21B

    def encode(self) -> bytes:
        return self._STRUCT.pack(
            self.lock_form_id, self.lock_base_id, self.lock_cell_id,
            self.locked & 0xFF, self.timestamp_ms,
        )

    @classmethod
    def decode(cls, data: bytes) -> "LockOpPayload":
        if len(data) != cls._STRUCT.size:
            raise ValueError(
                f"LockOpPayload: expected {cls._STRUCT.size} bytes, got {len(data)}")
        fid, bid, cid, locked, ts = cls._STRUCT.unpack(data)
        return cls(lock_form_id=fid, lock_base_id=bid, lock_cell_id=cid,
                   locked=locked, timestamp_ms=ts)


@dataclass(frozen=True, slots=True)
class LockBroadcastPayload:
    """B6.3 v0.5.3 — server -> other peers: 'peer X changed lock state on REFR Y'."""
    peer_id: str
    lock_form_id: int
    lock_base_id: int
    lock_cell_id: int
    locked: int
    timestamp_ms: int

    _STRUCT: ClassVar[struct.Struct] = struct.Struct("<IIIBQ")  # 21B + 16B peer_id = 37B total

    def encode(self) -> bytes:
        return (
            _encode_fixed_string(self.peer_id, MAX_CLIENT_ID_LEN)
            + self._STRUCT.pack(
                self.lock_form_id, self.lock_base_id, self.lock_cell_id,
                self.locked & 0xFF, self.timestamp_ms,
            )
        )

    @classmethod
    def decode(cls, data: bytes) -> "LockBroadcastPayload":
        expected = MAX_CLIENT_ID_LEN + 1 + cls._STRUCT.size
        if len(data) != expected:
            raise ValueError(
                f"LockBroadcastPayload: expected {expected} bytes, got {len(data)}")
        peer = _decode_fixed_string(data[: MAX_CLIENT_ID_LEN + 1], MAX_CLIENT_ID_LEN)
        fid, bid, cid, locked, ts = cls._STRUCT.unpack(data[MAX_CLIENT_ID_LEN + 1:])
        return cls(peer_id=peer, lock_form_id=fid, lock_base_id=bid,
                   lock_cell_id=cid, locked=locked, timestamp_ms=ts)


@dataclass(frozen=True, slots=True)
class EquipModRecord:
    """M9.w4 v7 — single OMOD attachment record (8 B).

    Mirrors the runtime ObjectModifier in BGSObjectInstanceExtra.inner.data.
    Each weapon/armor with mods carries an array of these. form_id is the
    TESForm.formID of a BGSMod::Attachment::Mod (formType=0x90); the
    receiver looks it up locally and applies to the ghost weapon NIF.

    Empirically across vanilla weapons: attach_index = 0 and rank = 1 in
    nearly all observed records (the actual attach-slot info is inside
    the BGSMod itself, not the OIE record). flag is always 0. pad must
    be 0 on encode (engine leaves uninitialised garbage at runtime, the
    DLL zeros it before send).
    """
    form_id: int        # u32 — BGSMod::Attachment::Mod.formID (formType 0x90)
    attach_index: int   # u8  — slot index (typically 0)
    rank: int           # u8  — index2/rank (typically 1)
    flag: int           # u8  — engine flag (typically 0)
    pad: int = 0        # u8  — MUST be zero on encode

    _STRUCT: ClassVar[struct.Struct] = struct.Struct("<IBBBB")  # 4+1+1+1+1 = 8B

    def encode(self) -> bytes:
        return self._STRUCT.pack(
            self.form_id, self.attach_index, self.rank, self.flag, 0)

    @classmethod
    def decode(cls, data: bytes) -> "EquipModRecord":
        if len(data) != cls._STRUCT.size:
            raise ValueError(
                f"EquipModRecord: expected {cls._STRUCT.size} bytes, got {len(data)}")
        f, ai, rk, fl, _pad = cls._STRUCT.unpack(data)
        return cls(form_id=f, attach_index=ai, rank=rk, flag=fl, pad=0)


# Cap on per-weapon mod count. Vanilla ≤12; DLC up to ~20; 32 = safe ceiling.
MAX_EQUIP_MODS: int = 32


# === M9.w4 (witness) v8 — NIF descriptor records ===========================

# Cap on per-weapon NIF descriptors that the witness walker captures.
# Vanilla mods on a single weapon ≤6 typical; cap also bounded by
# MAX_PAYLOAD_SIZE remaining after fixed payload + OMOD records.
MAX_NIF_DESCRIPTORS: int = 8

# Per-string caps. Observed vanilla NIF paths max ~96 chars (Far Harbor
# harpoon mods); 192 cap leaves headroom for community mods. Parent node
# names are short — typically named NiNode attach points like
# "BarrelAttachNode" or "ScopeAttachNode". 64 cap is generous.
MAX_NIF_PATH_LEN: int = 192
MAX_NIF_NAME_LEN: int = 64


@dataclass(frozen=True, slots=True)
class NifDescriptor:
    """M9.w4 v8 — single NIF descriptor for a mod attached to a weapon.

    Sender extracts these by walking its own BipedAnim weapon subtree
    after the engine has finished mod assembly (post-equip). For each
    NiAVObject in the subtree that's a cache-hit on the nif_load_by_path
    detour (RVA 0x017B3E90), it records the .nif path, the parent node
    name, and the local NiTransform (16 floats = rotation 3x4 + translate
    vec3 + scale).

    Wire layout (variable-length per record):
        u8  path_len           # 0..192
        path_bytes (ASCII)
        u8  parent_name_len    # 0..64
        parent_name_bytes
        16 × float local_transform  # 64 bytes raw
    """
    nif_path: str
    parent_name: str
    # 16 floats = NiTransform from node+0x30..+0x70 (rot 3x4 SIMD + vec3 + scale).
    # Indices 12,13,14 hold local translate; index 15 holds local scale.
    local_transform: tuple  # tuple of 16 floats

    _XFORM_STRUCT: ClassVar[struct.Struct] = struct.Struct("<16f")  # 64B

    def encode(self) -> bytes:
        path_b = self.nif_path.encode("utf-8")[:MAX_NIF_PATH_LEN]
        name_b = self.parent_name.encode("utf-8")[:MAX_NIF_NAME_LEN]
        if len(self.local_transform) != 16:
            raise ValueError(
                f"NifDescriptor.local_transform: expected 16 floats, "
                f"got {len(self.local_transform)}")
        return (
            bytes([len(path_b)]) + path_b
            + bytes([len(name_b)]) + name_b
            + self._XFORM_STRUCT.pack(*self.local_transform)
        )

    @classmethod
    def decode_from(cls, data: bytes, offset: int = 0):
        """Decode a single NifDescriptor starting at `offset`. Returns
        (descriptor, bytes_consumed). Raises ValueError on malformed data.
        """
        if offset + 1 > len(data):
            raise ValueError("NifDescriptor: truncated path_len")
        pl = data[offset]
        if pl > MAX_NIF_PATH_LEN:
            raise ValueError(
                f"NifDescriptor: path_len {pl} exceeds cap {MAX_NIF_PATH_LEN}")
        off = offset + 1
        if off + pl + 1 > len(data):
            raise ValueError("NifDescriptor: truncated path / parent_len")
        path = data[off:off + pl].decode("utf-8", errors="replace")
        off += pl
        nl = data[off]
        if nl > MAX_NIF_NAME_LEN:
            raise ValueError(
                f"NifDescriptor: parent_name_len {nl} exceeds cap "
                f"{MAX_NIF_NAME_LEN}")
        off += 1
        if off + nl + cls._XFORM_STRUCT.size > len(data):
            raise ValueError("NifDescriptor: truncated parent_name / xform")
        name = data[off:off + nl].decode("utf-8", errors="replace")
        off += nl
        xf = cls._XFORM_STRUCT.unpack(data[off:off + cls._XFORM_STRUCT.size])
        off += cls._XFORM_STRUCT.size
        return cls(nif_path=path, parent_name=name, local_transform=xf), off - offset


def _encode_nif_tail(descs: tuple) -> bytes:
    """Encode a [u8 count][N × NifDescriptor] tail. Caps at MAX_NIF_DESCRIPTORS."""
    n = min(len(descs), MAX_NIF_DESCRIPTORS)
    out = bytearray([n])
    for d in descs[:n]:
        out.extend(d.encode())
    return bytes(out)


def _decode_nif_tail(data: bytes, offset: int) -> tuple:
    """Decode [u8 count][N × NifDescriptor] starting at `offset`. Returns
    a tuple of NifDescriptor (possibly empty). Tolerates `offset == len(data)`
    (no tail present, returns empty tuple)."""
    if offset >= len(data):
        return ()
    n = data[offset]
    n = min(n, MAX_NIF_DESCRIPTORS)
    off = offset + 1
    out: list = []
    for _ in range(n):
        try:
            d, used = NifDescriptor.decode_from(data, off)
        except ValueError:
            # Malformed — drop the rest of the tail (defensive).
            break
        out.append(d)
        off += used
    return tuple(out)


@dataclass(frozen=True, slots=True)
class EquipOpPayload:
    """M9 w1+w4: client -> server: 'I just equipped/unequipped item X'.

    Sender hooks ActorEquipManager::EquipObject (sub_140CE5900) and
    ::UnequipObject (sub_140CE5DA0) in the engine — both fire 11-arg with
    args 4-5-6 in DIFFERENT ORDER between equip and unequip (a4=count is
    common; a5/a6 are stack_id vs slot vs swapped — this trapped M9 day 1).
    Detour observes, filters to actor==player (form_id == 0x14), enqueues
    this payload, then chains to g_orig.

    M9.w4 (protocol v7): when the equipped weapon has OMOD attachments
    (BGSObjectInstanceExtra in inventory), they are appended as a tail
    after the fixed payload — { u8 mod_count; mod_count × EquipModRecord }.
    UNEQUIP events typically ship mod_count=0 (the receiver tracks attached
    mods by form_id locally and detaches everything for that weapon).

    Identity: item_form_id is a TESForm.formID, plugin-stable. slot_form_id
    is the BGSEquipSlot.formID; pass 0 to mean "engine auto-resolves from
    the item's biped data". count is signed for symmetry with container
    ops; in practice always >= 1.
    """
    item_form_id: int    # u32 — e.g. 0x1EED7 = Vault Suit 111
    kind: int            # u8 — EquipOpKind (1=EQUIP, 2=UNEQUIP)
    slot_form_id: int    # u32 — BGSEquipSlot.formID, 0 = auto
    count: int           # i32 — stack count (always positive in practice)
    timestamp_ms: int    # u64 — sender wall clock for ordering
    effective_priority: int = 0  # u16 — v10: OMOD-modified priority (or ARMO+0x2A6 default); 0 for non-ARMO
    mods: tuple = ()     # tuple[EquipModRecord, ...] — w4 OMOD list (empty if no mods)
    nif_descs: tuple = ()  # tuple[NifDescriptor, ...] — w4 v8 witness data

    _STRUCT: ClassVar[struct.Struct] = struct.Struct("<IBIiQH")  # v10: 4+1+4+4+8+2 = 23B (fixed)

    def encode(self) -> bytes:
        head = self._STRUCT.pack(
            self.item_form_id, self.kind, self.slot_form_id,
            self.count, self.timestamp_ms, self.effective_priority,
        )
        n = min(len(self.mods), MAX_EQUIP_MODS)
        omod_tail = bytes([n]) + b"".join(m.encode() for m in self.mods[:n])
        nif_tail = _encode_nif_tail(self.nif_descs)
        return head + omod_tail + nif_tail

    @classmethod
    def decode(cls, data: bytes) -> "EquipOpPayload":
        if len(data) < cls._STRUCT.size:
            raise ValueError(
                f"EquipOpPayload: expected >={cls._STRUCT.size} bytes, got {len(data)}")
        ifid, kind, sfid, cnt, ts, eff_prio = cls._STRUCT.unpack(data[:cls._STRUCT.size])
        mods: tuple = ()
        omod_size = 0  # bytes consumed by the OMOD tail (incl count byte)
        # v7 OMOD tail (optional — older v6 senders won't include this)
        if len(data) > cls._STRUCT.size:
            n = data[cls._STRUCT.size]
            n = min(n, MAX_EQUIP_MODS)
            tail_off = cls._STRUCT.size + 1
            needed = tail_off + n * EquipModRecord._STRUCT.size
            if len(data) >= needed and n > 0:
                stride = EquipModRecord._STRUCT.size
                mods = tuple(
                    EquipModRecord.decode(data[tail_off + i * stride
                                                : tail_off + (i+1) * stride])
                    for i in range(n)
                )
                omod_size = 1 + n * stride
            else:
                # mod_count=0 still counted the byte itself
                omod_size = 1
        # v8 NIF descriptor tail (after OMOD tail)
        nif_descs = _decode_nif_tail(data, cls._STRUCT.size + omod_size)
        return cls(item_form_id=ifid, kind=kind, slot_form_id=sfid,
                   count=cnt, timestamp_ms=ts,
                   effective_priority=eff_prio,
                   mods=mods, nif_descs=nif_descs)


@dataclass(frozen=True, slots=True)
class EquipBroadcastPayload:
    """M9 w1+w4: server -> other peers: 'peer X equipped/unequipped item Y'.

    Mirrors EquipOpPayload + peer_id for attribution. Carries the OMOD list
    (mods tuple) verbatim from the originating EquipOpPayload via server
    fanout. Server fan-out is pure (no validation, no rate-limiting).
    """
    peer_id: str
    item_form_id: int
    kind: int
    slot_form_id: int
    count: int
    timestamp_ms: int
    effective_priority: int = 0  # u16 — v10: see EquipOpPayload
    mods: tuple = ()     # w4 OMOD list, mirror of EquipOpPayload.mods
    nif_descs: tuple = ()  # w4 v8 witness data, mirror of EquipOpPayload.nif_descs

    _STRUCT: ClassVar[struct.Struct] = struct.Struct("<IBIiQH")  # v10: 23B fixed

    def encode(self) -> bytes:
        head = (
            _encode_fixed_string(self.peer_id, MAX_CLIENT_ID_LEN)
            + self._STRUCT.pack(
                self.item_form_id, self.kind, self.slot_form_id,
                self.count, self.timestamp_ms, self.effective_priority,
            )
        )
        n = min(len(self.mods), MAX_EQUIP_MODS)
        omod_tail = bytes([n]) + b"".join(m.encode() for m in self.mods[:n])
        nif_tail = _encode_nif_tail(self.nif_descs)
        return head + omod_tail + nif_tail

    @classmethod
    def decode(cls, data: bytes) -> "EquipBroadcastPayload":
        fixed = MAX_CLIENT_ID_LEN + 1 + cls._STRUCT.size  # v10: 16 + 23 = 39
        if len(data) < fixed:
            raise ValueError(
                f"EquipBroadcastPayload: expected >={fixed} bytes, got {len(data)}")
        peer = _decode_fixed_string(data[: MAX_CLIENT_ID_LEN + 1], MAX_CLIENT_ID_LEN)
        ifid, kind, sfid, cnt, ts, eff_prio = cls._STRUCT.unpack(
            data[MAX_CLIENT_ID_LEN + 1 : fixed])
        mods: tuple = ()
        omod_size = 0
        if len(data) > fixed:
            n = data[fixed]
            n = min(n, MAX_EQUIP_MODS)
            tail_off = fixed + 1
            needed = tail_off + n * EquipModRecord._STRUCT.size
            if len(data) >= needed and n > 0:
                stride = EquipModRecord._STRUCT.size
                mods = tuple(
                    EquipModRecord.decode(data[tail_off + i * stride
                                                : tail_off + (i+1) * stride])
                    for i in range(n)
                )
                omod_size = 1 + n * stride
            else:
                omod_size = 1
        nif_descs = _decode_nif_tail(data, fixed + omod_size)
        return cls(peer_id=peer, item_form_id=ifid, kind=kind,
                   slot_form_id=sfid, count=cnt, timestamp_ms=ts,
                   effective_priority=eff_prio,
                   mods=mods, nif_descs=nif_descs)


# =================================================================== M9.w4 v9
#
# MESH_BLOB — chunked raw-mesh replication for modded weapons.
#
# Why this exists: the witness pattern (NIF-path replay, v8) failed across
# 4 hook strategies because Fallout 4 builds modded-weapon geometry IN
# MEMORY at runtime — there is no on-disk .nif for "10mm pistol with Long
# Barrel + Reflex Sight". After 12 RE iterations we extract the resulting
# BSTriShape leaves directly from the player's loaded3D, decode positions
# from the packed half-prec stream and indices from the u16 index buffer,
# and ship the whole thing to peers as a chunked blob (single equip event
# = ~10 KB × 8 meshes = ~80 KB total → ~60 UDP frames).
#
# Reliability: each chunk is a reliable frame. Receiver buffers chunks
# keyed on (peer_id, equip_seq) and applies once all chunks land. Drops
# the buffer on partial timeout (5 s).
#
# Layout of one mesh blob (linear bytes — what gets chunked across N
# MESH_BLOB_OP frames):
#
#   BLOB HEADER (10 bytes):
#     u32 item_form_id            -- correlates with the EQUIP_OP that
#                                    triggered this blob; receiver uses it
#                                    to pair with the EQUIP_BCAST it just
#                                    applied (ghost weapon root).
#     u32 equip_seq               -- sender's per-equip monotonic counter;
#                                    same value used in chunk header.
#     u8  num_meshes              -- 0..MAX_MESHES_PER_BLOB
#     u8  reserved                -- (=0; align)
#
#   PER MESH (×num_meshes):
#     u8  m_name_len              -- 0..255
#     u8  parent_placeholder_len  -- 0..255
#     u16 bgsm_path_len           -- 0..65535
#     u16 vert_count
#     u16 reserved                -- (=0; align)
#     u32 tri_count               -- index_count = 3 * tri_count
#     16 × f32 local_transform    -- 64B raw NiTransform
#     m_name_len bytes (UTF-8)
#     parent_placeholder_len bytes
#     bgsm_path_len bytes
#     3 * vert_count × f32 positions   -- 12 * vc bytes (xyz per vertex)
#     3 * tri_count × u16 indices       -- 6 * tc bytes
#
# A typical 10mm pistol modded: 8 meshes × ~10 KB = ~80 KB.
# Cap MAX_MESHES_PER_BLOB = 32 (vanilla weapons ≤8; heavy-mod stacks ≤16).
# Cap MAX_BLOB_SIZE = 4 MB (hard ceiling to defend against malformed input).
#
# Chunk frame (MESH_BLOB_OP):
#   u32 equip_seq             -- correlation id (echo of blob header)
#   u32 total_blob_size       -- byte size of full assembled blob
#   u16 chunk_index           -- 0..total_chunks-1
#   u16 total_chunks          -- chunks for THIS blob
#   N bytes of payload        -- blob slice [chunk_index*CHUNK_SIZE..]
#
# Chunk frame (MESH_BLOB_BCAST): same + 16 B FixedClientId prefix.
# At MAX_PAYLOAD_SIZE=1400, per-chunk data slice:
#   OP    : 1400 - 12 = 1388 B
#   BCAST : 1400 - 28 = 1372 B
#
# Receiver reassembly state machine:
#   key = (peer_id, equip_seq)
#   value = { total_blob_size, total_chunks, received: bitset, buf: bytearray }
#   on chunk: write slice into buf[off..off+len]; mark received[chunk_idx]=1
#   when popcount(received) == total_chunks: decode_blob(buf), drop key
#   timeout 5 s without all chunks → drop key + warn

MAX_MESHES_PER_BLOB: int = 32
MAX_BLOB_SIZE: int = 4 * 1024 * 1024   # 4 MB hard ceiling

# Chunk header sizes (for derivation; see classes below)
_MESH_BLOB_OP_CHUNK_HEADER_SIZE: int = 12     # IIHH
_MESH_BLOB_BCAST_CHUNK_HEADER_SIZE: int = 28  # 16+IIHH

MESH_BLOB_OP_CHUNK_DATA_MAX: int = MAX_PAYLOAD_SIZE - _MESH_BLOB_OP_CHUNK_HEADER_SIZE     # 1388
MESH_BLOB_BCAST_CHUNK_DATA_MAX: int = MAX_PAYLOAD_SIZE - _MESH_BLOB_BCAST_CHUNK_HEADER_SIZE  # 1372


@dataclass(frozen=True, slots=True)
class ExtractedMesh:
    """One BSGeometry leaf extracted from a modded weapon assembly.

    `positions` is a flat tuple of 3*vert_count floats (xyz xyz xyz ...).
    `indices`   is a flat tuple of 3*tri_count u16 (one triangle = 3 indices).
    """
    m_name: str
    parent_placeholder: str
    bgsm_path: str
    vert_count: int
    tri_count: int
    local_transform: tuple   # 16 floats
    positions: tuple         # 3 * vert_count floats
    indices: tuple           # 3 * tri_count u16

    _MESH_HDR: ClassVar[struct.Struct] = struct.Struct("<BBHHHI16f")
    # Layout: u8 m_name_len, u8 parent_placeholder_len, u16 bgsm_path_len,
    #         u16 vert_count, u16 reserved, u32 tri_count, 16 × f32 transform.
    # Size = 1+1+2+2+2+4+64 = 76 bytes.

    def encode(self) -> bytes:
        m_name_b = self.m_name.encode("utf-8")[:255]
        parent_b = self.parent_placeholder.encode("utf-8")[:255]
        bgsm_b = self.bgsm_path.encode("utf-8")[:65535]
        if len(self.positions) != 3 * self.vert_count:
            raise ProtocolError(
                f"ExtractedMesh: positions len {len(self.positions)} != 3*vc {3*self.vert_count}")
        if len(self.indices) != 3 * self.tri_count:
            raise ProtocolError(
                f"ExtractedMesh: indices len {len(self.indices)} != 3*tc {3*self.tri_count}")
        if len(self.local_transform) != 16:
            raise ProtocolError(
                f"ExtractedMesh: local_transform len {len(self.local_transform)} != 16")

        head = self._MESH_HDR.pack(
            len(m_name_b), len(parent_b), len(bgsm_b),
            self.vert_count, 0, self.tri_count,
            *self.local_transform,
        )
        positions_b = struct.pack(f"<{3*self.vert_count}f", *self.positions)
        indices_b = struct.pack(f"<{3*self.tri_count}H", *self.indices)
        return head + m_name_b + parent_b + bgsm_b + positions_b + indices_b

    @classmethod
    def decode_from(cls, data: bytes, offset: int = 0):
        """Returns (mesh, bytes_consumed)."""
        if offset + cls._MESH_HDR.size > len(data):
            raise ProtocolError("ExtractedMesh: header truncated")
        (m_name_len, parent_len, bgsm_len, vc, _resv, tc,
         *xform) = cls._MESH_HDR.unpack_from(data, offset)
        off = offset + cls._MESH_HDR.size
        positions_size = 3 * vc * 4
        indices_size = 3 * tc * 2
        total_need = m_name_len + parent_len + bgsm_len + positions_size + indices_size
        if off + total_need > len(data):
            raise ProtocolError(
                f"ExtractedMesh: body truncated: off={off} need={total_need} have={len(data)-off}")

        m_name = data[off:off + m_name_len].decode("utf-8", errors="replace")
        off += m_name_len
        parent = data[off:off + parent_len].decode("utf-8", errors="replace")
        off += parent_len
        bgsm = data[off:off + bgsm_len].decode("utf-8", errors="replace")
        off += bgsm_len

        positions = struct.unpack_from(f"<{3*vc}f", data, off)
        off += positions_size
        indices = struct.unpack_from(f"<{3*tc}H", data, off)
        off += indices_size

        return cls(
            m_name=m_name,
            parent_placeholder=parent,
            bgsm_path=bgsm,
            vert_count=vc,
            tri_count=tc,
            local_transform=tuple(xform),
            positions=tuple(positions),
            indices=tuple(indices),
        ), off - offset


@dataclass(frozen=True, slots=True)
class MeshBlobPayload:
    """Top-level mesh blob (assembled from chunks on the receiver, or
    serialized on the sender BEFORE chunking).

    Encoded as a single linear byte buffer that's then split into
    MeshBlobChunkPayload frames for transport. NOT sent directly as a
    single frame — the encoded bytes are passed through the chunker.
    """
    item_form_id: int        # u32; correlates with EQUIP_OP/BCAST
    equip_seq: int           # u32; sender's per-equip monotonic counter
    meshes: tuple            # tuple[ExtractedMesh, ...]

    _BLOB_HDR: ClassVar[struct.Struct] = struct.Struct("<IIBB")  # 10B

    def encode(self) -> bytes:
        n = len(self.meshes)
        if n > MAX_MESHES_PER_BLOB:
            raise ProtocolError(
                f"MeshBlobPayload: {n} meshes > MAX_MESHES_PER_BLOB={MAX_MESHES_PER_BLOB}")
        head = self._BLOB_HDR.pack(self.item_form_id, self.equip_seq, n, 0)
        body = b"".join(m.encode() for m in self.meshes)
        out = head + body
        if len(out) > MAX_BLOB_SIZE:
            raise ProtocolError(
                f"MeshBlobPayload: encoded size {len(out)} > MAX_BLOB_SIZE={MAX_BLOB_SIZE}")
        return out

    @classmethod
    def decode(cls, data: bytes) -> "MeshBlobPayload":
        if len(data) < cls._BLOB_HDR.size:
            raise ProtocolError("MeshBlobPayload: header truncated")
        item_form_id, equip_seq, n, _resv = cls._BLOB_HDR.unpack_from(data, 0)
        if n > MAX_MESHES_PER_BLOB:
            raise ProtocolError(
                f"MeshBlobPayload: num_meshes {n} > MAX={MAX_MESHES_PER_BLOB}")
        meshes: list = []
        off = cls._BLOB_HDR.size
        for _ in range(n):
            mesh, used = ExtractedMesh.decode_from(data, off)
            meshes.append(mesh)
            off += used
        return cls(
            item_form_id=item_form_id,
            equip_seq=equip_seq,
            meshes=tuple(meshes),
        )


@dataclass(frozen=True, slots=True)
class MeshBlobChunkPayload:
    """Single MESH_BLOB_OP frame — one chunk of a serialized MeshBlobPayload.

    Wire format (12 B header + chunk_data):
        u32 equip_seq
        u32 total_blob_size
        u16 chunk_index
        u16 total_chunks
        N   chunk_data        (slice of the assembled blob)

    The receiver buffers chunks keyed on (peer_id, equip_seq); when all
    arrive it concatenates them in chunk_index order and decodes via
    MeshBlobPayload.decode().
    """
    equip_seq: int
    total_blob_size: int
    chunk_index: int
    total_chunks: int
    chunk_data: bytes

    _HDR: ClassVar[struct.Struct] = struct.Struct("<IIHH")  # 12B

    def encode(self) -> bytes:
        if len(self.chunk_data) > MESH_BLOB_OP_CHUNK_DATA_MAX:
            raise ProtocolError(
                f"MeshBlobChunkPayload: chunk_data {len(self.chunk_data)}B "
                f"> MAX={MESH_BLOB_OP_CHUNK_DATA_MAX}")
        return self._HDR.pack(
            self.equip_seq, self.total_blob_size,
            self.chunk_index, self.total_chunks,
        ) + self.chunk_data

    @classmethod
    def decode(cls, data: bytes) -> "MeshBlobChunkPayload":
        if len(data) < cls._HDR.size:
            raise ProtocolError("MeshBlobChunkPayload: header truncated")
        eq, sz, ci, tc = cls._HDR.unpack_from(data, 0)
        return cls(
            equip_seq=eq,
            total_blob_size=sz,
            chunk_index=ci,
            total_chunks=tc,
            chunk_data=bytes(data[cls._HDR.size:]),
        )


@dataclass(frozen=True, slots=True)
class MeshBlobChunkBroadcastPayload:
    """Server -> peers: one chunk of a serialized MeshBlobPayload, attributed.

    Wire format (28 B header + chunk_data):
        FixedString(16) peer_id
        u32 equip_seq
        u32 total_blob_size
        u16 chunk_index
        u16 total_chunks
        N   chunk_data
    """
    peer_id: str
    equip_seq: int
    total_blob_size: int
    chunk_index: int
    total_chunks: int
    chunk_data: bytes

    _HDR: ClassVar[struct.Struct] = struct.Struct("<IIHH")  # 12B (post peer_id)

    def encode(self) -> bytes:
        if len(self.chunk_data) > MESH_BLOB_BCAST_CHUNK_DATA_MAX:
            raise ProtocolError(
                f"MeshBlobChunkBroadcastPayload: chunk_data {len(self.chunk_data)}B "
                f"> MAX={MESH_BLOB_BCAST_CHUNK_DATA_MAX}")
        return (
            _encode_fixed_string(self.peer_id, MAX_CLIENT_ID_LEN)
            + self._HDR.pack(
                self.equip_seq, self.total_blob_size,
                self.chunk_index, self.total_chunks,
            )
            + self.chunk_data
        )

    @classmethod
    def decode(cls, data: bytes) -> "MeshBlobChunkBroadcastPayload":
        peer_off = MAX_CLIENT_ID_LEN + 1
        if len(data) < peer_off + cls._HDR.size:
            raise ProtocolError("MeshBlobChunkBroadcastPayload: header truncated")
        peer = _decode_fixed_string(data[:peer_off], MAX_CLIENT_ID_LEN)
        eq, sz, ci, tc = cls._HDR.unpack_from(data, peer_off)
        return cls(
            peer_id=peer,
            equip_seq=eq,
            total_blob_size=sz,
            chunk_index=ci,
            total_chunks=tc,
            chunk_data=bytes(data[peer_off + cls._HDR.size:]),
        )


def chunk_mesh_blob(blob_bytes: bytes,
                    chunk_data_max: int = MESH_BLOB_OP_CHUNK_DATA_MAX
                    ) -> "list[tuple[int, int, bytes]]":
    """Split a serialized mesh blob into chunks.

    Returns a list of (chunk_index, total_chunks, chunk_data) triples.
    Caller wraps each in a MeshBlobChunkPayload (or BCAST variant) with
    the per-equip equip_seq and total_blob_size.
    """
    if len(blob_bytes) > MAX_BLOB_SIZE:
        raise ProtocolError(
            f"chunk_mesh_blob: blob {len(blob_bytes)}B > MAX={MAX_BLOB_SIZE}")
    if not blob_bytes:
        return []
    total_chunks = (len(blob_bytes) + chunk_data_max - 1) // chunk_data_max
    if total_chunks > 0xFFFF:
        raise ProtocolError(
            f"chunk_mesh_blob: total_chunks {total_chunks} > u16 max")
    out: list = []
    off = 0
    for ci in range(total_chunks):
        end = min(off + chunk_data_max, len(blob_bytes))
        out.append((ci, total_chunks, blob_bytes[off:end]))
        off = end
    return out


# ============================================================================
# B6.5w2 (v13) — NPC continuous-state broadcast
# ============================================================================
#
# Server-authoritative NPC sync. The Python brain (server/npc_brain.py) ticks
# every tracked NPC at npc_tick_hz (default 10) and emits NPC_STATE_BCAST to
# every connected peer. Receiver looks up the local Actor by form_id and
# applies pos/rot via the existing pos_update_seh pattern (B6.5w3) and anim
# graph variables via IAnimationGraphManagerHolder::SetGraphVariable*
# (RVA 0x818D60/D80/DA0; holder = Actor + 0x48; names from interned pool at
# qword_1430DBF78[2700..3020] — see re/B6.5_npc_pipeline_AGENT_B.md).
#
# Wire layout per entry (98 B in v14, no padding):
#
#   v13 baseline (53 B):
#     u32 form_id           # placed REFR formID — stable across processes
#     u32 base_id           # TESNPC base — validation hint
#     u32 cell_id           # parent cell formID
#     f32 pos_x, pos_y, pos_z
#     f32 yaw, pitch        # atan2 convention; receiver translates to engine heading
#     u64 target_id         # legacy general-purpose target (peer_id hash or form_id)
#     u64 timestamp_ms      # server tick timestamp
#     u8  anim_state        # legacy AnimState enum (server/npc_brain.py)
#     u8  aggro_state       # AggroState enum
#     u8  hp_pct            # 0..100, server-authoritative
#     u8  target_kind       # 0=NONE, 1=PEER, 2=NPC
#     u8  flags             # bit 0 = visible, bit 1 = invulnerable, bit 2 = essential
#
#   v14 additions for Ghost AI (45 B):
#     u32 package_form_id         # server-chosen TESPackage (hook on
#                                 # TESPackage::EvaluateConditions @ 0x00768CC0)
#     u32 combat_target_form_id   # combat target form_id (hook on
#                                 # Actor::SyncCombatTargetFromAIProcess @ 0x00C5CCE0)
#     f32 aim_x, aim_y, aim_z     # aim world pos (hook on
#                                 # CombatAimController::SetAimTarget @ 0x00E65820)
#     f32 velocity_x, _y, _z      # server-decreed velocity (hook on
#                                 # Actor::TickMovementController @ 0x00C65E20)
#     u8  weapon_state            # 0=none/1=drawing/2=drawn/3=holstering
#                                 # (hook on DrawWeapon dispatch @ 0x00C5D080)
#     u8  sighted                 # 0/1 ADS (hook on SetSightedState @ 0x00CB13F0)
#     u8  sprinting               # 0/1 (hook on SetSprintState @ 0x00CA6030)
#     u8  sneaking                # 0/1 (hook on SetSneakState @ 0x00CA6220)
#     u8  gun_down                # 0/1 gun lowered (hook on ResolveCombatStance @ 0x00CD6870)
#     u8  aggression              # 0..100 (hook on UpdateAggressionToGraph @ 0x00E4D8A0)
#     u16 loco_state_pack         # 6 sync ints packed (hook on LocoEventDispatch @ 0x00CEC200):
#                                 #   bits 0    : iSyncIdleLocomotion (1 bit)
#                                 #   bits 1-2  : iSyncTurnState      (2 bits, 0..2)
#                                 #   bits 3    : iSyncForwardState   (1 bit)
#                                 #   bits 4-5  : iSyncStrafeState    (2 bits, 0..2)
#                                 #   bits 6-7  : iSyncJumpState      (2 bits, 0/1/3)
#                                 #   bits 8    : iSyncSwimState      (1 bit)
#                                 #   bits 9-15 : reserved
#     u32 sandbox_marker_handle   # Sandbox marker ref handle (BGSProcedureSandbox state +88)
#                                 # — 0 if NPC not in Sandbox or marker unset
#     u8  sandbox_idle_index      # Sandbox idle index (state +100/+104), 0 = unused
#
# Frame layout:
#     u16 count             # number of entries (≤ MAX_NPC_STATES_PER_FRAME)
#     u16 reserved          # 0 — alignment + future flags
#     count × NPCStateEntry # 98 B each (v14)
#
# Bandwidth ceiling: at 10 NPC × 10 Hz × 98 B = 9.8 KB/s/peer outbound. At
# 50 NPC the chunked frames stay under MTU 1400 (4 packets / tick).
# ============================================================================


# v14 loco_state_pack helpers — pack/unpack the 6 sync ints into 16 bits.
def pack_loco_state(
    idle_loco: int = 0,    # 0..1
    turn: int = 0,         # 0..2
    forward: int = 0,      # 0..1
    strafe: int = 0,       # 0..2
    jump: int = 0,         # 0..3 (engine uses 0/1/3 but 2 bits cover them)
    swim: int = 0,         # 0..1
) -> int:
    """Pack 6 locomotion sync ints into a u16 per v14 wire layout."""
    return (
        (idle_loco & 0x1)
        | ((turn & 0x3) << 1)
        | ((forward & 0x1) << 3)
        | ((strafe & 0x3) << 4)
        | ((jump & 0x3) << 6)
        | ((swim & 0x1) << 8)
    ) & 0xFFFF


def unpack_loco_state(pack: int) -> tuple[int, int, int, int, int, int]:
    """Reverse of pack_loco_state. Returns (idle, turn, fwd, strafe, jump, swim)."""
    return (
        pack & 0x1,
        (pack >> 1) & 0x3,
        (pack >> 3) & 0x1,
        (pack >> 4) & 0x3,
        (pack >> 6) & 0x3,
        (pack >> 8) & 0x1,
    )


@dataclass(frozen=True, slots=True)
class NPCStateEntry:
    """One NPC's authoritative state. Width = 98 B (v14)."""
    # v13 fields ---------------------------------------------------------
    form_id: int
    base_id: int
    cell_id: int
    pos_x: float
    pos_y: float
    pos_z: float
    yaw: float
    pitch: float
    target_id: int
    timestamp_ms: int
    anim_state: int
    aggro_state: int
    hp_pct: int
    target_kind: int
    flags: int
    # v14 Ghost AI additions ---------------------------------------------
    package_form_id: int = 0
    combat_target_form_id: int = 0
    aim_x: float = 0.0
    aim_y: float = 0.0
    aim_z: float = 0.0
    velocity_x: float = 0.0
    velocity_y: float = 0.0
    velocity_z: float = 0.0
    weapon_state: int = 0
    sighted: int = 0
    sprinting: int = 0
    sneaking: int = 0
    gun_down: int = 0
    aggression: int = 0
    loco_state_pack: int = 0
    sandbox_marker_handle: int = 0
    sandbox_idle_index: int = 0

    # 53 B v13 prefix + 45 B v14 suffix = 98 B
    _STRUCT: ClassVar[struct.Struct] = struct.Struct(
        "<IIIfffffQQBBBBB"          # v13 (53 B)
        "IIffffffBBBBBBHIB"         # v14 (45 B): pkg/tgt + aim + vel + 6 u8 + u16 + u32 + u8
    )

    def encode(self) -> bytes:
        return self._STRUCT.pack(
            # v13
            self.form_id & 0xFFFFFFFF,
            self.base_id & 0xFFFFFFFF,
            self.cell_id & 0xFFFFFFFF,
            self.pos_x, self.pos_y, self.pos_z,
            self.yaw, self.pitch,
            self.target_id & 0xFFFFFFFFFFFFFFFF,
            self.timestamp_ms & 0xFFFFFFFFFFFFFFFF,
            self.anim_state & 0xFF,
            self.aggro_state & 0xFF,
            self.hp_pct & 0xFF,
            self.target_kind & 0xFF,
            self.flags & 0xFF,
            # v14
            self.package_form_id & 0xFFFFFFFF,
            self.combat_target_form_id & 0xFFFFFFFF,
            self.aim_x, self.aim_y, self.aim_z,
            self.velocity_x, self.velocity_y, self.velocity_z,
            self.weapon_state & 0xFF,
            self.sighted & 0xFF,
            self.sprinting & 0xFF,
            self.sneaking & 0xFF,
            self.gun_down & 0xFF,
            self.aggression & 0xFF,
            self.loco_state_pack & 0xFFFF,
            self.sandbox_marker_handle & 0xFFFFFFFF,
            self.sandbox_idle_index & 0xFF,
        )

    @classmethod
    def decode(cls, data: bytes) -> "NPCStateEntry":
        if len(data) != cls._STRUCT.size:
            raise ProtocolError(
                f"NPCStateEntry: expected {cls._STRUCT.size} B, got {len(data)}")
        return cls(*cls._STRUCT.unpack(data))


# Cap derived from MTU: header (4) + N × 98 ≤ MAX_PAYLOAD_SIZE (1400).
MAX_NPC_STATES_PER_FRAME: int = (MAX_PAYLOAD_SIZE - 4) // 98  # = 14 (v14)


@dataclass(frozen=True, slots=True)
class NPCStateBroadcastPayload:
    """B6.5w2 — server -> all peers: batched NPC authoritative state.

    Unreliable channel. Server emits at npc_tick_hz; drops are tolerable
    because the next tick resends. Receivers apply pos/rot/anim to the
    local Actor identified by ``form_id`` (B6.5w3) and suppress local AI
    tick for tracked form_ids (B6.5w4).

    Cell-aware filtering / interest management is **not yet** implemented:
    every peer receives every tracked NPC regardless of cell. Filtering
    lands in B6.7+.
    """
    entries: tuple[NPCStateEntry, ...]

    _HEADER: ClassVar[struct.Struct] = struct.Struct("<HH")   # count, reserved

    def encode(self) -> bytes:
        if len(self.entries) > MAX_NPC_STATES_PER_FRAME:
            raise ProtocolError(
                f"NPCStateBroadcastPayload: too many entries "
                f"({len(self.entries)} > {MAX_NPC_STATES_PER_FRAME}); "
                f"caller must chunk")
        head = self._HEADER.pack(len(self.entries), 0)
        body = b"".join(e.encode() for e in self.entries)
        return head + body

    @classmethod
    def decode(cls, data: bytes) -> "NPCStateBroadcastPayload":
        if len(data) < cls._HEADER.size:
            raise ProtocolError("NPC_STATE_BCAST: truncated header")
        count, _reserved = cls._HEADER.unpack_from(data, 0)
        if count > MAX_NPC_STATES_PER_FRAME:
            raise ProtocolError(
                f"NPC_STATE_BCAST: count {count} > "
                f"MAX={MAX_NPC_STATES_PER_FRAME}")
        ent_size = NPCStateEntry._STRUCT.size
        need = cls._HEADER.size + count * ent_size
        if len(data) < need:
            raise ProtocolError(
                f"NPC_STATE_BCAST: truncated body "
                f"(need {need} B, got {len(data)})")
        entries = tuple(
            NPCStateEntry.decode(
                data[cls._HEADER.size + i * ent_size :
                     cls._HEADER.size + (i + 1) * ent_size])
            for i in range(count)
        )
        return cls(entries=entries)


@dataclass(frozen=True, slots=True)
class PeerGhostRegisterPayload:
    """B6.6w5 — client tells server its local ghost-actor form_id.

    The "ghost" is the engine-spawned Actor that represents the OTHER
    peer on this client's screen (currently a single global ghost; 2-peer
    MVP assumption). The form_id is dynamic per-client (allocated by
    PlaceAtMe at spawn). Server uses this to substitute the combat
    target in NPC_STATE_BCAST per-viewer: when a raider's aggro target
    is a remote peer, the broadcast carries the VIEWER's local ghost
    form_id so the engine targets the right thing visually.

    Send-side: client calls this once after ghost spawn succeeds.
    Server-side: latest registration wins (e.g., on re-spawn after
    cell reload).

    Wire: 4 bytes (u32 form_id).
    """
    ghost_form_id: int

    _STRUCT: ClassVar[struct.Struct] = struct.Struct("<I")

    def encode(self) -> bytes:
        return self._STRUCT.pack(self.ghost_form_id & 0xFFFFFFFF)

    @classmethod
    def decode(cls, data: bytes) -> "PeerGhostRegisterPayload":
        if len(data) < cls._STRUCT.size:
            raise ProtocolError(
                f"PEER_GHOST_REGISTER: expected {cls._STRUCT.size} B, "
                f"got {len(data)}")
        (fid,) = cls._STRUCT.unpack_from(data, 0)
        return cls(ghost_form_id=fid)


@dataclass(frozen=True, slots=True)
class NPCDiscoverPayload:
    """B6.6w2 — client -> server: "I auto-tracked hostile NPC X".

    Emitted by the client when its npc_ai_suppress detour first
    auto-tracks an actor (Path 2: vanilla AI set the InCombat flag bit
    0x4000 on the actor). The client reads identity + position off the
    Actor* directly via the stable offsets:

      form_id  = *(u32*)(actor + 0x14)
      base_id  = *(u32*)(*(TESForm**)(actor + 0xE0) + 0x14)
      cell_id  = *(u32*)(*(REFR**)(actor + 0xB8) + 0x14)
      pos_x/y/z = (float*)(actor + 0xD0)[0..2]

    Server uses this to register the raider dynamically in raider_brain
    so it participates in aggro selection + fire timing + sync without
    needing to be in the waypoint JSON.

    Reliable channel: discovery should not be dropped. Server is
    idempotent — duplicate discoveries are ignored.

    Wire: 24 bytes.
    """
    form_id: int
    base_id: int
    cell_id: int
    pos_x: float
    pos_y: float
    pos_z: float

    _STRUCT: ClassVar[struct.Struct] = struct.Struct("<IIIfff")

    def encode(self) -> bytes:
        return self._STRUCT.pack(
            self.form_id & 0xFFFFFFFF,
            self.base_id & 0xFFFFFFFF,
            self.cell_id & 0xFFFFFFFF,
            float(self.pos_x),
            float(self.pos_y),
            float(self.pos_z),
        )

    @classmethod
    def decode(cls, data: bytes) -> "NPCDiscoverPayload":
        if len(data) < cls._STRUCT.size:
            raise ProtocolError(
                f"NPC_DISCOVER: expected {cls._STRUCT.size} B, "
                f"got {len(data)}")
        fid, bid, cid, x, y, z = cls._STRUCT.unpack_from(data, 0)
        return cls(form_id=fid, base_id=bid, cell_id=cid,
                   pos_x=x, pos_y=y, pos_z=z)


@dataclass(frozen=True, slots=True)
class NPCPerceptionTriggerPayload:
    """Build 62 (2026-05-24) — server -> all peers: "NPC X perceives
    peer Y's ghost — invoke CCF810 locally so engine allocates combat
    tier naturally."

    Emitted by the server's proximity-sphere check when a peer's pos
    enters an NPC's effective perception sphere (base 1024 units,
    scaled by peer posture: sneak=0.4x, walk=0.7x, stand/run=1.0x,
    sprint=1.3x). Server-side debounce: 5s per (npc_fid, peer_id) pair
    to prevent re-trigger spam.

    Receiver (each client):
      observer = lookup_by_form_id(npc_fid)
      target   = peer_registry.get_ghost_actor_for_peer(peer_id)
                 (or local PC if peer_id == self)
      trigger_npc_perception(observer, target)
        -> engine sub_140CCF810 allocates HighProcess+CombatController+
           AddTarget in 1 frame.

    Reliable channel: do not drop. Idempotent on engine side (re-call
    routes through merge path sub_140ED2490).

    Wire: 8 bytes (2 × u32).
    """
    npc_fid: int          # OBSERVER (the NPC that should perceive)
    peer_id: int          # TARGET   (peer whose ghost is the threat)

    _STRUCT: ClassVar[struct.Struct] = struct.Struct("<II")

    def encode(self) -> bytes:
        return self._STRUCT.pack(
            self.npc_fid & 0xFFFFFFFF,
            self.peer_id & 0xFFFFFFFF,
        )

    @classmethod
    def decode(cls, data: bytes) -> "NPCPerceptionTriggerPayload":
        if len(data) < cls._STRUCT.size:
            raise ProtocolError(
                f"NPC_PERCEPTION_TRIGGER: expected {cls._STRUCT.size} B, "
                f"got {len(data)}")
        nfid, pid = cls._STRUCT.unpack_from(data, 0)
        return cls(npc_fid=nfid, peer_id=pid)


@dataclass(frozen=True, slots=True)
class NPCFirePayload:
    """B6.6w1 — server -> all peers: "this raider fires its equipped
    weapon NOW".

    Emitted by the server's raider_brain when an aggro'd raider's fire
    cooldown elapses + a player is in line-of-sight + visible. Both peers
    receive the same event so the muzzle flash + projectile + audio +
    damage all play synchronously.

    Build 55a (proto v15, 2026-05-23) — adds `target_kind` byte. Server
    picks per-raider per-window (3-8 sec) whether the raider's current
    fire is aimed at LOCAL (= peer's natural target, vanilla AI handles)
    or at GHOST (= the cross-peer ghost; puppet-fire path on client).
    Eliminates the dual-target flicker where engine vanilla AI was
    competing with our puppet-fire on the same actor rotation field.

    Wire: 13 bytes (3 × u32 + 1 × u8).
    """
    TARGET_LOCAL: ClassVar[int] = 0
    TARGET_GHOST: ClassVar[int] = 1

    raider_form_id: int
    target_form_id: int   # 0x14 = player; 0 = unknown
    flags: int            # reserved (0); future: burst count / weapon hint
    target_kind: int = 0  # 0=LOCAL (vanilla AI), 1=GHOST (client puppet-fire)

    _STRUCT: ClassVar[struct.Struct] = struct.Struct("<IIIB")

    def encode(self) -> bytes:
        return self._STRUCT.pack(
            self.raider_form_id & 0xFFFFFFFF,
            self.target_form_id & 0xFFFFFFFF,
            self.flags & 0xFFFFFFFF,
            self.target_kind & 0xFF,
        )

    @classmethod
    def decode(cls, data: bytes) -> "NPCFirePayload":
        if len(data) < cls._STRUCT.size:
            raise ProtocolError(
                f"NPC_FIRE: expected {cls._STRUCT.size} B, got {len(data)}")
        r, t, f, tk = cls._STRUCT.unpack_from(data, 0)
        return cls(raider_form_id=r, target_form_id=t,
                   flags=f, target_kind=tk)


# ============================================================================
# Build 65 — Owner-driven NPC sync payloads (Solver 2 design).
#
# All 11 opcodes (0x0280-0x028A) introduced here. C++ mirrors at
# `fw_native/src/net/protocol.h`. Phase A ships these data structures +
# server-side registry; Phase B wires DLL handlers.
#
# Sizing kept compact; all u32 fids, ts_ms as u64 monotonic, peer_id as
# 16-byte FixedClientId (matches PeerJoinPayload).
# ============================================================================

PEER_ID_BYTES: int = 16  # FixedClientId byte length (matches PeerJoinPayload)


@dataclass(frozen=True, slots=True)
class NPCObservedPayload:
    """C→S: "I see NPC X at pos P". Election input — server uses
    reporter distance + cell load timing to decide ownership.

    Wire: 28 bytes (3 × u32 + 4 × f32).
    """
    form_id: int
    base_id: int
    cell_id: int
    pos_x: float
    pos_y: float
    pos_z: float
    observer_distance_sq: float   # server short-circuits election compute

    _STRUCT: ClassVar[struct.Struct] = struct.Struct("<IIIffff")

    def encode(self) -> bytes:
        return self._STRUCT.pack(
            self.form_id & 0xFFFFFFFF,
            self.base_id & 0xFFFFFFFF,
            self.cell_id & 0xFFFFFFFF,
            self.pos_x, self.pos_y, self.pos_z,
            self.observer_distance_sq,
        )

    @classmethod
    def decode(cls, data: bytes) -> "NPCObservedPayload":
        if len(data) < cls._STRUCT.size:
            raise ProtocolError(
                f"NPC_OBSERVED: expected {cls._STRUCT.size} B, got {len(data)}")
        f, b, c, px, py, pz, d = cls._STRUCT.unpack_from(data, 0)
        return cls(form_id=f, base_id=b, cell_id=c,
                   pos_x=px, pos_y=py, pos_z=pz,
                   observer_distance_sq=d)


@dataclass(frozen=True, slots=True)
class NPCUnloadPayload:
    """C→S: "NPC X left my loaded cell — I'm no longer eligible to own it".
    Triggers owner release (if reporter was owner) and forgets the NPC on
    the non-owner side.

    Wire: 26 bytes (2 × u32 + 4 × f32 + 2 × u8).
    """
    form_id: int
    epoch: int                  # proof-of-ownership at unload time
    last_pos_x: float
    last_pos_y: float
    last_pos_z: float
    last_yaw: float
    last_anim_state: int        # u8
    last_hp_pct: int            # u8

    _STRUCT: ClassVar[struct.Struct] = struct.Struct("<IIffffBB")

    def encode(self) -> bytes:
        return self._STRUCT.pack(
            self.form_id & 0xFFFFFFFF,
            self.epoch & 0xFFFFFFFF,
            self.last_pos_x, self.last_pos_y, self.last_pos_z,
            self.last_yaw,
            self.last_anim_state & 0xFF,
            self.last_hp_pct & 0xFF,
        )

    @classmethod
    def decode(cls, data: bytes) -> "NPCUnloadPayload":
        if len(data) < cls._STRUCT.size:
            raise ProtocolError(
                f"NPC_UNLOAD: expected {cls._STRUCT.size} B, got {len(data)}")
        f, e, px, py, pz, yaw, anim, hp = cls._STRUCT.unpack_from(data, 0)
        return cls(form_id=f, epoch=e,
                   last_pos_x=px, last_pos_y=py, last_pos_z=pz,
                   last_yaw=yaw,
                   last_anim_state=anim, last_hp_pct=hp)


@dataclass(frozen=True, slots=True)
class NPCOwnerHeartbeatEntry:
    """Single (fid, epoch) tuple in NPC_OWNER_HEARTBEAT body."""
    form_id: int
    epoch: int

    _STRUCT: ClassVar[struct.Struct] = struct.Struct("<II")

    def encode(self) -> bytes:
        return self._STRUCT.pack(
            self.form_id & 0xFFFFFFFF,
            self.epoch & 0xFFFFFFFF,
        )

    @classmethod
    def decode(cls, data: bytes, offset: int = 0) -> "NPCOwnerHeartbeatEntry":
        if len(data) - offset < cls._STRUCT.size:
            raise ProtocolError("HeartbeatEntry: truncated")
        f, e = cls._STRUCT.unpack_from(data, offset)
        return cls(form_id=f, epoch=e)


@dataclass(frozen=True, slots=True)
class NPCOwnerHeartbeatPayload:
    """C→S: "I still own these fids at these epochs". 2 Hz from every
    peer for every NPC it owns. Server uses last-seen ts as health-gate
    input. Unreliable — drop tolerance is generous (next tick recovers).

    Wire: 4 (header: num_entries u16 + reserved u16) + N × 8.
    """
    entries: tuple[NPCOwnerHeartbeatEntry, ...]

    _HEADER: ClassVar[struct.Struct] = struct.Struct("<HH")

    MAX_ENTRIES: ClassVar[int] = 170   # 4 + 170*8 = 1364 ≤ MTU 1400

    def encode(self) -> bytes:
        if len(self.entries) > self.MAX_ENTRIES:
            raise ProtocolError(
                f"NPC_OWNER_HEARTBEAT: {len(self.entries)} > "
                f"max {self.MAX_ENTRIES} entries")
        buf = bytearray(self._HEADER.pack(len(self.entries), 0))
        for e in self.entries:
            buf.extend(e.encode())
        return bytes(buf)

    @classmethod
    def decode(cls, data: bytes) -> "NPCOwnerHeartbeatPayload":
        if len(data) < cls._HEADER.size:
            raise ProtocolError("NPC_OWNER_HEARTBEAT: truncated header")
        num, _reserved = cls._HEADER.unpack_from(data, 0)
        entry_size = NPCOwnerHeartbeatEntry._STRUCT.size
        if len(data) < cls._HEADER.size + num * entry_size:
            raise ProtocolError(
                f"NPC_OWNER_HEARTBEAT: truncated body "
                f"(num={num}, len={len(data)})")
        out: list[NPCOwnerHeartbeatEntry] = []
        off = cls._HEADER.size
        for _ in range(num):
            out.append(NPCOwnerHeartbeatEntry.decode(data, off))
            off += entry_size
        return cls(entries=tuple(out))


@dataclass(frozen=True, slots=True)
class NPCOwnershipHandoffPhase1Payload:
    """S→old+new owners: release request for one NPC. Reliable.

    The OLD owner must respond with NPC_OWNERSHIP_RELEASE_ACK before
    `deadline_ms`; the NEW owner waits silently until phase 2 announces it
    can start broadcasting state.

    Wire: 4 + 4 + 16 + 16 + 8 = 48 bytes.
    """
    form_id: int
    old_epoch: int
    old_owner_peer_id: bytes    # 16 B FixedClientId
    new_owner_peer_id: bytes    # 16 B
    deadline_ms: int            # u64 monotonic ms — hard ACK cutoff

    _STRUCT: ClassVar[struct.Struct] = struct.Struct("<II16s16sQ")

    def __post_init__(self) -> None:
        if len(self.old_owner_peer_id) != 16:
            raise ProtocolError("PHASE1: old_owner_peer_id must be 16B")
        if len(self.new_owner_peer_id) != 16:
            raise ProtocolError("PHASE1: new_owner_peer_id must be 16B")

    def encode(self) -> bytes:
        return self._STRUCT.pack(
            self.form_id & 0xFFFFFFFF,
            self.old_epoch & 0xFFFFFFFF,
            self.old_owner_peer_id,
            self.new_owner_peer_id,
            self.deadline_ms & 0xFFFFFFFFFFFFFFFF,
        )

    @classmethod
    def decode(cls, data: bytes) -> "NPCOwnershipHandoffPhase1Payload":
        if len(data) < cls._STRUCT.size:
            raise ProtocolError(
                f"PHASE1: expected {cls._STRUCT.size} B, got {len(data)}")
        f, oe, ooid, noid, dl = cls._STRUCT.unpack_from(data, 0)
        return cls(form_id=f, old_epoch=oe,
                   old_owner_peer_id=ooid, new_owner_peer_id=noid,
                   deadline_ms=dl)


@dataclass(frozen=True, slots=True)
class NPCOwnershipReleaseAckPayload:
    """C→S: old owner acknowledges release. Reliable.

    Wire: 4 + 4 + 16 + 8 = 32 bytes.
    """
    form_id: int
    old_epoch: int
    acker_peer_id: bytes        # 16 B — must match registered old owner
    ack_ts_ms: int              # u64

    _STRUCT: ClassVar[struct.Struct] = struct.Struct("<II16sQ")

    def __post_init__(self) -> None:
        if len(self.acker_peer_id) != 16:
            raise ProtocolError("RELEASE_ACK: acker_peer_id must be 16B")

    def encode(self) -> bytes:
        return self._STRUCT.pack(
            self.form_id & 0xFFFFFFFF,
            self.old_epoch & 0xFFFFFFFF,
            self.acker_peer_id,
            self.ack_ts_ms & 0xFFFFFFFFFFFFFFFF,
        )

    @classmethod
    def decode(cls, data: bytes) -> "NPCOwnershipReleaseAckPayload":
        if len(data) < cls._STRUCT.size:
            raise ProtocolError(
                f"RELEASE_ACK: expected {cls._STRUCT.size} B, got {len(data)}")
        f, oe, pid, ts = cls._STRUCT.unpack_from(data, 0)
        return cls(form_id=f, old_epoch=oe,
                   acker_peer_id=pid, ack_ts_ms=ts)


@dataclass(frozen=True, slots=True)
class NPCOwnershipHandoffPhase2Payload:
    """S→all: new owner active for one NPC. All peers update their local
    g_owner_map[fid] = new_owner_peer_id, epoch = new_epoch. Reliable.

    Wire: 4 + 4 + 16 + 8 = 32 bytes.
    """
    form_id: int
    new_epoch: int
    new_owner_peer_id: bytes
    handed_off_at_ms: int

    _STRUCT: ClassVar[struct.Struct] = struct.Struct("<II16sQ")

    def __post_init__(self) -> None:
        if len(self.new_owner_peer_id) != 16:
            raise ProtocolError("PHASE2: new_owner_peer_id must be 16B")

    def encode(self) -> bytes:
        return self._STRUCT.pack(
            self.form_id & 0xFFFFFFFF,
            self.new_epoch & 0xFFFFFFFF,
            self.new_owner_peer_id,
            self.handed_off_at_ms & 0xFFFFFFFFFFFFFFFF,
        )

    @classmethod
    def decode(cls, data: bytes) -> "NPCOwnershipHandoffPhase2Payload":
        if len(data) < cls._STRUCT.size:
            raise ProtocolError(
                f"PHASE2: expected {cls._STRUCT.size} B, got {len(data)}")
        f, ne, pid, ts = cls._STRUCT.unpack_from(data, 0)
        return cls(form_id=f, new_epoch=ne,
                   new_owner_peer_id=pid, handed_off_at_ms=ts)


@dataclass(frozen=True, slots=True)
class NPCOwnershipBcastEntry:
    """Single (fid, epoch, owner_peer_id) entry in OWNERSHIP_BCAST."""
    form_id: int
    epoch: int
    owner_peer_id: bytes        # 16 B; all-zero = unowned (server-relayed)

    _STRUCT: ClassVar[struct.Struct] = struct.Struct("<II16s")

    def encode(self) -> bytes:
        if len(self.owner_peer_id) != 16:
            raise ProtocolError("OWNERSHIP_BCAST entry: peer_id must be 16B")
        return self._STRUCT.pack(
            self.form_id & 0xFFFFFFFF,
            self.epoch & 0xFFFFFFFF,
            self.owner_peer_id,
        )

    @classmethod
    def decode(cls, data: bytes, offset: int = 0) -> "NPCOwnershipBcastEntry":
        if len(data) - offset < cls._STRUCT.size:
            raise ProtocolError("OWNERSHIP_BCAST entry: truncated")
        f, e, pid = cls._STRUCT.unpack_from(data, offset)
        return cls(form_id=f, epoch=e, owner_peer_id=pid)


@dataclass(frozen=True, slots=True)
class NPCOwnershipBcastPayload:
    """S→peer (bootstrap on connect) or S→all (post-handoff cleanup).
    Carries up to ~50 ownership records per frame. Reliable.

    Wire: 4 + N × 24.
    """
    entries: tuple[NPCOwnershipBcastEntry, ...]

    _HEADER: ClassVar[struct.Struct] = struct.Struct("<HH")

    MAX_ENTRIES: ClassVar[int] = 57   # 4 + 57*24 = 1372 ≤ MTU 1400

    def encode(self) -> bytes:
        if len(self.entries) > self.MAX_ENTRIES:
            raise ProtocolError(
                f"OWNERSHIP_BCAST: {len(self.entries)} > max {self.MAX_ENTRIES}")
        buf = bytearray(self._HEADER.pack(len(self.entries), 0))
        for e in self.entries:
            buf.extend(e.encode())
        return bytes(buf)

    @classmethod
    def decode(cls, data: bytes) -> "NPCOwnershipBcastPayload":
        if len(data) < cls._HEADER.size:
            raise ProtocolError("OWNERSHIP_BCAST: truncated header")
        num, _reserved = cls._HEADER.unpack_from(data, 0)
        es = NPCOwnershipBcastEntry._STRUCT.size
        if len(data) < cls._HEADER.size + num * es:
            raise ProtocolError(
                f"OWNERSHIP_BCAST: truncated body (num={num}, len={len(data)})")
        out: list[NPCOwnershipBcastEntry] = []
        off = cls._HEADER.size
        for _ in range(num):
            out.append(NPCOwnershipBcastEntry.decode(data, off))
            off += es
        return cls(entries=tuple(out))


@dataclass(frozen=True, slots=True)
class NPCOwnerStateEntry:
    """Single NPC state record inside NPC_STATE_FROM_OWNER.

    Same field set as NPCStateEntry (Build 55a v15) plus `epoch` for
    non-owner gating. Sized to keep batched packets MTU-safe.

    Wire: 76 bytes.
    """
    form_id: int
    epoch: int
    pos_x: float
    pos_y: float
    pos_z: float
    yaw_rad: float
    pitch_rad: float
    combat_target_fid: int      # owner's local AI's current combat target
    aim_x: float
    aim_y: float
    aim_z: float
    velocity_x: float
    velocity_y: float
    velocity_z: float
    anim_state: int             # u8
    aggro_state: int            # u8
    hp_pct: int                 # u8
    weapon_state: int           # u8 (bit 3 = fire_this_tick)
    sighted: int                # u8
    sprinting: int              # u8
    sneaking: int               # u8
    gun_down: int               # u8
    aggression: int             # u8
    _pad: int = 0               # u8 padding to align ts_ms
    loco_state_pack: int = 0    # u16
    ts_ms: int = 0              # u64 owner's monotonic ms

    _STRUCT: ClassVar[struct.Struct] = struct.Struct(
        "<II"          # form_id, epoch
        "fff"          # pos xyz
        "ff"           # yaw, pitch
        "I"            # combat_target_fid
        "fff"          # aim xyz
        "fff"          # velocity xyz
        "BBBBBBBBB"    # anim, aggro, hp, weapon, sighted, sprint, sneak, gun_down, aggression
        "B"            # pad
        "H"            # loco_state_pack
        "Q"            # ts_ms
    )

    def encode(self) -> bytes:
        return self._STRUCT.pack(
            self.form_id & 0xFFFFFFFF, self.epoch & 0xFFFFFFFF,
            self.pos_x, self.pos_y, self.pos_z,
            self.yaw_rad, self.pitch_rad,
            self.combat_target_fid & 0xFFFFFFFF,
            self.aim_x, self.aim_y, self.aim_z,
            self.velocity_x, self.velocity_y, self.velocity_z,
            self.anim_state & 0xFF, self.aggro_state & 0xFF,
            self.hp_pct & 0xFF, self.weapon_state & 0xFF,
            self.sighted & 0xFF, self.sprinting & 0xFF,
            self.sneaking & 0xFF, self.gun_down & 0xFF,
            self.aggression & 0xFF, self._pad & 0xFF,
            self.loco_state_pack & 0xFFFF,
            self.ts_ms & 0xFFFFFFFFFFFFFFFF,
        )

    @classmethod
    def decode(cls, data: bytes, offset: int = 0) -> "NPCOwnerStateEntry":
        if len(data) - offset < cls._STRUCT.size:
            raise ProtocolError("NPCOwnerStateEntry: truncated")
        unpacked = cls._STRUCT.unpack_from(data, offset)
        (f, ep, px, py, pz, yaw, pitch, ctf,
         ax, ay, az, vx, vy, vz,
         anim, aggro, hp, ws, sight, spr, sne, gd, ag, pad,
         loco, ts) = unpacked
        return cls(form_id=f, epoch=ep,
                   pos_x=px, pos_y=py, pos_z=pz,
                   yaw_rad=yaw, pitch_rad=pitch,
                   combat_target_fid=ctf,
                   aim_x=ax, aim_y=ay, aim_z=az,
                   velocity_x=vx, velocity_y=vy, velocity_z=vz,
                   anim_state=anim, aggro_state=aggro,
                   hp_pct=hp, weapon_state=ws,
                   sighted=sight, sprinting=spr, sneaking=sne,
                   gun_down=gd, aggression=ag, _pad=pad,
                   loco_state_pack=loco, ts_ms=ts)


@dataclass(frozen=True, slots=True)
class NPCStateFromOwnerPayload:
    """C→S→all (relayed): owner's authoritative state batch. Unreliable.

    Owner client emits at 20-30 Hz. Server validates ownership + epoch,
    fans out the filtered entries to every non-owner. Receivers gate on
    `entry.epoch >= local_epoch[fid]` and drop stale entries.

    Wire: 4 (header) + N × 80.
    """
    entries: tuple[NPCOwnerStateEntry, ...]

    _HEADER: ClassVar[struct.Struct] = struct.Struct("<HH")

    MAX_ENTRIES: ClassVar[int] = 17   # 4 + 17*80 = 1364 ≤ MTU 1400

    def encode(self) -> bytes:
        if len(self.entries) > self.MAX_ENTRIES:
            raise ProtocolError(
                f"NPC_STATE_FROM_OWNER: {len(self.entries)} > max "
                f"{self.MAX_ENTRIES}")
        buf = bytearray(self._HEADER.pack(len(self.entries), 0))
        for e in self.entries:
            buf.extend(e.encode())
        return bytes(buf)

    @classmethod
    def decode(cls, data: bytes) -> "NPCStateFromOwnerPayload":
        if len(data) < cls._HEADER.size:
            raise ProtocolError("NPC_STATE_FROM_OWNER: truncated header")
        num, _reserved = cls._HEADER.unpack_from(data, 0)
        es = NPCOwnerStateEntry._STRUCT.size
        if len(data) < cls._HEADER.size + num * es:
            raise ProtocolError(
                f"NPC_STATE_FROM_OWNER: truncated body "
                f"(num={num}, len={len(data)})")
        out: list[NPCOwnerStateEntry] = []
        off = cls._HEADER.size
        for _ in range(num):
            out.append(NPCOwnerStateEntry.decode(data, off))
            off += es
        return cls(entries=tuple(out))


@dataclass(frozen=True, slots=True)
class NPCFireFromOwnerPayload:
    """C→S→all: owner's fire event. Unreliable.

    Replaces server-driven NPC_FIRE. Owner reports a single weapon
    discharge with a target hint. Receivers spawn muzzle flash + projectile
    + audio on the local replica.

    Wire: 4 + 4 + 4 + 12 + 8 = 32 bytes (form, target_fid, weapon_form,
    aim_xyz, ts_ms).
    """
    form_id: int               # raider
    target_form_id: int        # target hint (0x14 = local PC; 0 = unknown)
    weapon_form_id: int
    aim_x: float
    aim_y: float
    aim_z: float
    ts_ms: int                 # u64 owner monotonic ms

    _STRUCT: ClassVar[struct.Struct] = struct.Struct("<IIIfffQ")

    def encode(self) -> bytes:
        return self._STRUCT.pack(
            self.form_id & 0xFFFFFFFF,
            self.target_form_id & 0xFFFFFFFF,
            self.weapon_form_id & 0xFFFFFFFF,
            self.aim_x, self.aim_y, self.aim_z,
            self.ts_ms & 0xFFFFFFFFFFFFFFFF,
        )

    @classmethod
    def decode(cls, data: bytes) -> "NPCFireFromOwnerPayload":
        if len(data) < cls._STRUCT.size:
            raise ProtocolError(
                f"NPC_FIRE_FROM_OWNER: expected {cls._STRUCT.size} B, "
                f"got {len(data)}")
        f, tf, wf, ax, ay, az, ts = cls._STRUCT.unpack_from(data, 0)
        return cls(form_id=f, target_form_id=tf, weapon_form_id=wf,
                   aim_x=ax, aim_y=ay, aim_z=az, ts_ms=ts)


@dataclass(frozen=True, slots=True)
class NPCDeathFromOwnerPayload:
    """C→S→all: owner's death event. Reliable.

    When the owner's vanilla AI observes HP reaching zero (or scripted
    kill), it reports the death. Non-owners apply `Actor::Kill` locally.

    Wire: 4 + 4 + 12 + 12 + 4 + 1 + 1 + 2 + 8 = 48 bytes.
    """
    form_id: int
    killer_form_id: int          # 0 = environmental
    pos_x: float                 # last-seen pos
    pos_y: float
    pos_z: float
    ragdoll_x: float
    ragdoll_y: float
    ragdoll_z: float
    damage: float
    hit_zone: int                # u8
    flags: int                   # u8 reserved (silent_kill etc.)
    _pad: int = 0                # u16 align
    ts_ms: int = 0               # u64

    _STRUCT: ClassVar[struct.Struct] = struct.Struct(
        "<IIfffffffBBHQ")

    def encode(self) -> bytes:
        return self._STRUCT.pack(
            self.form_id & 0xFFFFFFFF,
            self.killer_form_id & 0xFFFFFFFF,
            self.pos_x, self.pos_y, self.pos_z,
            self.ragdoll_x, self.ragdoll_y, self.ragdoll_z,
            self.damage,
            self.hit_zone & 0xFF,
            self.flags & 0xFF,
            self._pad & 0xFFFF,
            self.ts_ms & 0xFFFFFFFFFFFFFFFF,
        )

    @classmethod
    def decode(cls, data: bytes) -> "NPCDeathFromOwnerPayload":
        if len(data) < cls._STRUCT.size:
            raise ProtocolError(
                f"NPC_DEATH_FROM_OWNER: expected {cls._STRUCT.size} B, "
                f"got {len(data)}")
        (f, k, px, py, pz, rx, ry, rz, dmg,
         hz, fl, pad, ts) = cls._STRUCT.unpack_from(data, 0)
        return cls(form_id=f, killer_form_id=k,
                   pos_x=px, pos_y=py, pos_z=pz,
                   ragdoll_x=rx, ragdoll_y=ry, ragdoll_z=rz,
                   damage=dmg, hit_zone=hz, flags=fl,
                   _pad=pad, ts_ms=ts)


@dataclass(frozen=True, slots=True)
class NPCDamageFromOwnerPayload:
    """C→S→all: owner's hit-applier event. Unreliable (purely cosmetic —
    HP authority is the owner; this is for receiver-side hit-react +
    ragdoll-direction visuals).

    Wire: 4 + 4 + 4 + 4 + 1 + 1 + 2 + 8 = 28 bytes.
    """
    form_id: int                 # victim
    attacker_form_id: int        # who hit them (0 = unknown)
    weapon_form_id: int
    damage: float
    hit_zone: int                # u8
    flags: int                   # u8 reserved
    _pad: int = 0                # u16 align
    ts_ms: int = 0               # u64

    _STRUCT: ClassVar[struct.Struct] = struct.Struct("<IIIfBBHQ")

    def encode(self) -> bytes:
        return self._STRUCT.pack(
            self.form_id & 0xFFFFFFFF,
            self.attacker_form_id & 0xFFFFFFFF,
            self.weapon_form_id & 0xFFFFFFFF,
            self.damage,
            self.hit_zone & 0xFF,
            self.flags & 0xFF,
            self._pad & 0xFFFF,
            self.ts_ms & 0xFFFFFFFFFFFFFFFF,
        )

    @classmethod
    def decode(cls, data: bytes) -> "NPCDamageFromOwnerPayload":
        if len(data) < cls._STRUCT.size:
            raise ProtocolError(
                f"NPC_DAMAGE_FROM_OWNER: expected {cls._STRUCT.size} B, "
                f"got {len(data)}")
        f, a, w, d, hz, fl, pad, ts = cls._STRUCT.unpack_from(data, 0)
        return cls(form_id=f, attacker_form_id=a, weapon_form_id=w,
                   damage=d, hit_zone=hz, flags=fl, _pad=pad, ts_ms=ts)


@dataclass(frozen=True, slots=True)
class NPCEngagementClaimPayload:
    """Build 65.c.23 — C→S: peer claims engagement with NPC.

    Sent by a non-owner peer when its LOCAL engine has the InCombat flag
    (bit 0x4000 at Actor+0x2D0) set on a tracked NPC. This is the engine's
    own evidence that the peer's player IS the natural combat opponent
    of that NPC — not a server prediction, not a heuristic.

    Server uses this to force handoff if the current owner has not been
    reporting engagement (i.e. their last STATE_FROM_OWNER carried
    anim_state < 3 for >= ENGAGEMENT_OWNERSHIP_GRACE_MS = 3000 ms).
    Fixes the "wrong owner" mismatch where first-observer claims a raider
    but isn't the one actually fighting it.

    Anti-spam: client dedups per fid with a 2 s cooldown. Server further
    rejects claims when handoff stickiness floor is not yet elapsed.

    Wire: 4 + 4 + 8 = 16 bytes (form_id, peer_id_hash, ts_ms).
    """
    form_id: int                # NPC the peer's engine has in combat
    peer_id_hash: int           # FNV-1a 32-bit of local peer_id (sanity)
    ts_ms: int                  # peer monotonic ms; for diag only

    _STRUCT: ClassVar[struct.Struct] = struct.Struct("<IIQ")

    def encode(self) -> bytes:
        return self._STRUCT.pack(
            self.form_id & 0xFFFFFFFF,
            self.peer_id_hash & 0xFFFFFFFF,
            self.ts_ms & 0xFFFFFFFFFFFFFFFF,
        )

    @classmethod
    def decode(cls, data: bytes) -> "NPCEngagementClaimPayload":
        if len(data) < cls._STRUCT.size:
            raise ProtocolError(
                f"NPC_ENGAGEMENT_CLAIM: expected {cls._STRUCT.size} B, "
                f"got {len(data)}")
        f, h, ts = cls._STRUCT.unpack_from(data, 0)
        return cls(form_id=f, peer_id_hash=h, ts_ms=ts)


@dataclass(frozen=True, slots=True)
class RawMessage:
    """Fallback for unknown msg_type — preserves payload for forward compat."""
    msg_type: int
    payload: bytes


# ------------------------------------------------------------------ codec

# Typed union for clarity
Payload = Union[
    HelloPayload, WelcomePayload, PeerJoinPayload, PeerLeavePayload,
    HeartbeatPayload, AckPayload, PosStatePayload, PosBroadcastPayload,
    ActorEventPayload, ChatPayload, DisconnectPayload,
    WorldStatePayload,
    ContainerOpPayload, ContainerBroadcastPayload, ContainerStatePayload,
    ContainerOpAckPayload, ContainerSeedPayload,
    QuestStageSetPayload, QuestStageBroadcastPayload, QuestStateBootPayload,
    GlobalVarSetPayload, GlobalVarBroadcastPayload, GlobalVarStateBootPayload,
    DoorOpPayload, DoorBroadcastPayload,
    EquipOpPayload, EquipBroadcastPayload,
    MeshBlobChunkPayload, MeshBlobChunkBroadcastPayload,
    LockOpPayload, LockBroadcastPayload,
    NPCStateEntry, NPCStateBroadcastPayload,
    NPCFirePayload, NPCDiscoverPayload,
    NPCPerceptionTriggerPayload,
    # Build 65 owner-driven (Solver 2)
    NPCObservedPayload, NPCUnloadPayload,
    NPCOwnerHeartbeatPayload,
    NPCOwnershipHandoffPhase1Payload, NPCOwnershipReleaseAckPayload,
    NPCOwnershipHandoffPhase2Payload, NPCOwnershipBcastPayload,
    NPCStateFromOwnerPayload,
    NPCFireFromOwnerPayload, NPCDeathFromOwnerPayload,
    NPCDamageFromOwnerPayload,
    NPCEngagementClaimPayload,   # Build 65.c.23 — combat-driven handoff
    PeerGhostRegisterPayload,
    RawMessage,
]


_TYPE_TO_PAYLOAD_CLS: dict[int, type] = {
    MessageType.HELLO:            HelloPayload,
    MessageType.WELCOME:          WelcomePayload,
    MessageType.PEER_JOIN:        PeerJoinPayload,
    MessageType.PEER_LEAVE:       PeerLeavePayload,
    MessageType.HEARTBEAT:        HeartbeatPayload,
    MessageType.DISCONNECT:       DisconnectPayload,
    MessageType.ACK:              AckPayload,
    MessageType.POS_STATE:        PosStatePayload,
    MessageType.POS_BROADCAST:    PosBroadcastPayload,
    MessageType.POSE_STATE:       PoseStatePayload,
    MessageType.POSE_BROADCAST:   PoseBroadcastPayload,
    MessageType.POSE_CROUCH_STATE:     PoseCrouchStatePayload,      # v16
    MessageType.POSE_CROUCH_BROADCAST: PoseCrouchBroadcastPayload,  # v16
    MessageType.ACTOR_EVENT:      ActorEventPayload,
    MessageType.CHAT:             ChatPayload,
    MessageType.WORLD_STATE:      WorldStatePayload,
    MessageType.CONTAINER_OP:     ContainerOpPayload,
    MessageType.CONTAINER_BCAST:  ContainerBroadcastPayload,
    MessageType.CONTAINER_STATE:  ContainerStatePayload,
    MessageType.CONTAINER_SEED:   ContainerSeedPayload,
    MessageType.CONTAINER_OP_ACK: ContainerOpAckPayload,
    MessageType.QUEST_STAGE_SET:       QuestStageSetPayload,
    MessageType.QUEST_STAGE_BCAST:     QuestStageBroadcastPayload,
    MessageType.QUEST_STATE_BOOT:      QuestStateBootPayload,
    MessageType.GLOBAL_VAR_SET:        GlobalVarSetPayload,
    MessageType.GLOBAL_VAR_BCAST:      GlobalVarBroadcastPayload,
    MessageType.GLOBAL_VAR_STATE_BOOT: GlobalVarStateBootPayload,
    MessageType.DOOR_OP:               DoorOpPayload,
    MessageType.DOOR_BCAST:            DoorBroadcastPayload,
    MessageType.EQUIP_OP:              EquipOpPayload,
    MessageType.EQUIP_BCAST:           EquipBroadcastPayload,
    MessageType.MESH_BLOB_OP:          MeshBlobChunkPayload,
    MessageType.MESH_BLOB_BCAST:       MeshBlobChunkBroadcastPayload,
    MessageType.LOCK_OP:               LockOpPayload,
    MessageType.LOCK_BCAST:            LockBroadcastPayload,
    MessageType.NPC_STATE_BCAST:       NPCStateBroadcastPayload,
    MessageType.NPC_FIRE:              NPCFirePayload,
    MessageType.NPC_DISCOVER:          NPCDiscoverPayload,
    MessageType.NPC_PERCEPTION_TRIGGER: NPCPerceptionTriggerPayload,  # Build 62 v17
    # Build 65 — owner-driven NPC sync (Solver 2)
    MessageType.NPC_OBSERVED:                   NPCObservedPayload,
    MessageType.NPC_UNLOAD:                     NPCUnloadPayload,
    MessageType.NPC_OWNER_HEARTBEAT:            NPCOwnerHeartbeatPayload,
    MessageType.NPC_OWNERSHIP_HANDOFF_PHASE_1:  NPCOwnershipHandoffPhase1Payload,
    MessageType.NPC_OWNERSHIP_RELEASE_ACK:      NPCOwnershipReleaseAckPayload,
    MessageType.NPC_OWNERSHIP_HANDOFF_PHASE_2:  NPCOwnershipHandoffPhase2Payload,
    MessageType.NPC_OWNERSHIP_BCAST:            NPCOwnershipBcastPayload,
    MessageType.NPC_STATE_FROM_OWNER:           NPCStateFromOwnerPayload,
    MessageType.NPC_FIRE_FROM_OWNER:            NPCFireFromOwnerPayload,
    MessageType.NPC_DEATH_FROM_OWNER:           NPCDeathFromOwnerPayload,
    MessageType.NPC_DAMAGE_FROM_OWNER:          NPCDamageFromOwnerPayload,
    MessageType.NPC_ENGAGEMENT_CLAIM:           NPCEngagementClaimPayload,
    MessageType.NPC_POSE_FROM_OWNER:            NPCPoseFromOwnerPayload,
    MessageType.NPC_CROUCH_FROM_OWNER:          NPCCrouchFromOwnerPayload,
    MessageType.NPC_DAMAGE_CLAIM:               NPCDamageClaimPayload,
    MessageType.PEER_GHOST_REGISTER:   PeerGhostRegisterPayload,
}


@dataclass(frozen=True, slots=True)
class Frame:
    """Full decoded frame: header + typed payload."""
    header: FrameHeader
    payload: Payload


def encode_frame(msg_type: int, seq: int, payload: Payload, *, reliable: bool = False) -> bytes:
    """Encode a full frame (header + payload) to bytes."""
    if isinstance(payload, RawMessage):
        payload_bytes = payload.payload
    else:
        payload_bytes = payload.encode()
    if len(payload_bytes) > MAX_PAYLOAD_SIZE:
        raise ProtocolError(f"payload {len(payload_bytes)}B exceeds max {MAX_PAYLOAD_SIZE}")
    flags = FLAG_RELIABLE if reliable else 0
    header = FrameHeader(msg_type=int(msg_type), seq=seq, payload_len=len(payload_bytes), flags=flags)
    return encode_header(header) + payload_bytes


def decode_frame(data: bytes) -> Frame:
    """Decode a full frame from raw bytes (header + payload).

    Unknown msg_type is returned as RawMessage so the receiver can drop or forward.
    """
    header = decode_header(data)
    expected_total = HEADER_SIZE + header.payload_len
    if len(data) < expected_total:
        raise ProtocolError(f"frame truncated: expected {expected_total}B, got {len(data)}B")
    payload_bytes = data[HEADER_SIZE:expected_total]

    cls = _TYPE_TO_PAYLOAD_CLS.get(header.msg_type)
    if cls is None:
        return Frame(header=header, payload=RawMessage(msg_type=header.msg_type, payload=payload_bytes))
    try:
        payload = cls.decode(payload_bytes)
    except struct.error as e:
        raise ProtocolError(f"payload decode failed for {MessageType(header.msg_type).name}: {e}") from e
    return Frame(header=header, payload=payload)
