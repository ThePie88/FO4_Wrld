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
PROTOCOL_VERSION: int = 6
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

    _STRUCT: ClassVar[struct.Struct] = struct.Struct("<BB")

    def encode(self) -> bytes:
        return (
            _encode_fixed_string(self.client_id, MAX_CLIENT_ID_LEN)
            + self._STRUCT.pack(self.client_version_major, self.client_version_minor)
        )

    @classmethod
    def decode(cls, data: bytes) -> "HelloPayload":
        off = MAX_CLIENT_ID_LEN + 1
        if len(data) < off + cls._STRUCT.size:
            raise ProtocolError("HELLO truncated")
        cid = _decode_fixed_string(data, MAX_CLIENT_ID_LEN)
        vma, vmi = cls._STRUCT.unpack_from(data, off)
        return cls(cid, vma, vmi)


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
    """Current local player pos+rot snapshot. Unreliable."""
    x: float; y: float; z: float   # world coords (float32)
    rx: float; ry: float; rz: float # rotation radians (float32)
    timestamp_ms: int              # u64 client wall clock (for RTT/interp)

    _STRUCT: ClassVar[struct.Struct] = struct.Struct("<6fQ")

    def encode(self) -> bytes:
        return self._STRUCT.pack(self.x, self.y, self.z,
                                  self.rx, self.ry, self.rz,
                                  self.timestamp_ms)

    @classmethod
    def decode(cls, data: bytes) -> "PosStatePayload":
        if len(data) < cls._STRUCT.size:
            raise ProtocolError("POS_STATE truncated")
        return cls(*cls._STRUCT.unpack_from(data, 0))


@dataclass(frozen=True, slots=True)
class PosBroadcastPayload:
    """Pos+rot of a remote peer, as relayed by server. Extends PosState with peer_id."""
    peer_id: str
    x: float; y: float; z: float
    rx: float; ry: float; rz: float
    timestamp_ms: int

    _STRUCT: ClassVar[struct.Struct] = struct.Struct("<6fQ")

    def encode(self) -> bytes:
        return (
            _encode_fixed_string(self.peer_id, MAX_CLIENT_ID_LEN)
            + self._STRUCT.pack(self.x, self.y, self.z,
                                 self.rx, self.ry, self.rz,
                                 self.timestamp_ms)
        )

    @classmethod
    def decode(cls, data: bytes) -> "PosBroadcastPayload":
        off = MAX_CLIENT_ID_LEN + 1
        if len(data) < off + cls._STRUCT.size:
            raise ProtocolError("POS_BROADCAST truncated")
        pid = _decode_fixed_string(data, MAX_CLIENT_ID_LEN)
        x, y, z, rx, ry, rz, ts = cls._STRUCT.unpack_from(data, off)
        return cls(pid, x, y, z, rx, ry, rz, ts)


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
class EquipOpPayload:
    """M9 w1: client -> server: 'I just equipped/unequipped item X'.

    Sender hooks ActorEquipManager::EquipObject (sub_140CE5900) and
    ::UnequipObject (sub_140CE5DA0) in the engine — both fire 11-arg with
    args 4-5-6 in DIFFERENT ORDER between equip and unequip (a4=count is
    common; a5/a6 are stack_id vs slot vs swapped — this trapped M9 day 1).
    Detour observes, filters to actor==player (form_id == 0x14), enqueues
    this payload, then chains to g_orig.

    Wedge 1 receiver: just log + telemetry — NO apply on the ghost yet.
    The ghost body is fragile to scene-graph mutation (root cause of the
    3-day crash hunt resolved by B8 force-equip-cycle on game start).
    Wedge 2 will add the safe apply path now that B8 has stabilized
    BipedAnim allocator state.

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

    _STRUCT: ClassVar[struct.Struct] = struct.Struct("<IBIiQ")  # 4+1+4+4+8 = 21B

    def encode(self) -> bytes:
        return self._STRUCT.pack(
            self.item_form_id, self.kind, self.slot_form_id,
            self.count, self.timestamp_ms,
        )

    @classmethod
    def decode(cls, data: bytes) -> "EquipOpPayload":
        if len(data) != cls._STRUCT.size:
            raise ValueError(
                f"EquipOpPayload: expected {cls._STRUCT.size} bytes, got {len(data)}")
        ifid, kind, sfid, cnt, ts = cls._STRUCT.unpack(data)
        return cls(item_form_id=ifid, kind=kind, slot_form_id=sfid,
                   count=cnt, timestamp_ms=ts)


@dataclass(frozen=True, slots=True)
class EquipBroadcastPayload:
    """M9 w1: server -> other peers: 'peer X equipped/unequipped item Y'.

    Mirrors EquipOpPayload + peer_id for attribution. Server fan-out is
    pure (no validation, no rate-limiting) — wedge 1 is OBSERVE-only on
    receivers so worst-case a flood of equip events is just log spam.
    Wedge 2 may add rate-limit when ghost mutation lands.
    """
    peer_id: str
    item_form_id: int
    kind: int
    slot_form_id: int
    count: int
    timestamp_ms: int

    _STRUCT: ClassVar[struct.Struct] = struct.Struct("<IBIiQ")  # 21B + 16B peer_id = 37B total

    def encode(self) -> bytes:
        return (
            _encode_fixed_string(self.peer_id, MAX_CLIENT_ID_LEN)
            + self._STRUCT.pack(
                self.item_form_id, self.kind, self.slot_form_id,
                self.count, self.timestamp_ms,
            )
        )

    @classmethod
    def decode(cls, data: bytes) -> "EquipBroadcastPayload":
        expected = MAX_CLIENT_ID_LEN + 1 + cls._STRUCT.size  # 16 + 21 = 37
        if len(data) != expected:
            raise ValueError(
                f"EquipBroadcastPayload: expected {expected} bytes, got {len(data)}")
        peer = _decode_fixed_string(data[: MAX_CLIENT_ID_LEN + 1], MAX_CLIENT_ID_LEN)
        ifid, kind, sfid, cnt, ts = cls._STRUCT.unpack(data[MAX_CLIENT_ID_LEN + 1:])
        return cls(peer_id=peer, item_form_id=ifid, kind=kind,
                   slot_form_id=sfid, count=cnt, timestamp_ms=ts)


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
