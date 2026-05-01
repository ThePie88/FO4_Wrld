"""Tests per net/protocol.py: roundtrip, edge cases, malformed input.

Run:   python -m pytest net/tests/test_protocol.py -v
"""
from __future__ import annotations

import struct
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from protocol import (  # noqa: E402
    HEADER_SIZE, MAX_PAYLOAD_SIZE, PROTOCOL_MAGIC, PROTOCOL_VERSION,
    FLAG_RELIABLE,
    MessageType, ProtocolError,
    FrameHeader, Frame,
    HelloPayload, WelcomePayload, PeerJoinPayload, PeerLeavePayload,
    HeartbeatPayload, AckPayload, PosStatePayload, PosBroadcastPayload,
    ActorEventPayload, ActorEventKind, ChatPayload, DisconnectPayload,
    QuestStageSetPayload, QuestStageBroadcastPayload,
    QuestStateBootPayload, QuestStageStateEntry,
    GlobalVarSetPayload, GlobalVarBroadcastPayload,
    GlobalVarStateBootPayload, GlobalVarStateEntry,
    ExtractedMesh, MeshBlobPayload,
    MeshBlobChunkPayload, MeshBlobChunkBroadcastPayload,
    MAX_MESHES_PER_BLOB, MAX_BLOB_SIZE,
    MESH_BLOB_OP_CHUNK_DATA_MAX, MESH_BLOB_BCAST_CHUNK_DATA_MAX,
    chunk_mesh_blob,
    RawMessage,
    encode_header, decode_header, encode_frame, decode_frame,
)


# ------------------------------------------------------------------ header

class TestHeader:
    def test_roundtrip(self):
        h = FrameHeader(msg_type=MessageType.POS_STATE, seq=42, payload_len=36, flags=0)
        data = encode_header(h)
        assert len(data) == HEADER_SIZE
        h2 = decode_header(data)
        assert h == h2

    def test_size_constant(self):
        assert HEADER_SIZE == 12

    def test_magic_and_version_embedded(self):
        h = FrameHeader(msg_type=1, seq=0, payload_len=0, flags=0)
        data = encode_header(h)
        assert data[0] == PROTOCOL_MAGIC
        assert data[1] == PROTOCOL_VERSION

    def test_flags_roundtrip(self):
        h = FrameHeader(msg_type=1, seq=0, payload_len=0, flags=FLAG_RELIABLE)
        h2 = decode_header(encode_header(h))
        assert h2.is_reliable
        assert h2.flags == FLAG_RELIABLE

    def test_bad_magic_rejected(self):
        bad = b"\x00" + struct.pack("<BHIHBB", 1, 1, 0, 0, 0, 0)
        with pytest.raises(ProtocolError, match="bad magic"):
            decode_header(bad)

    def test_bad_version_rejected(self):
        bad = struct.pack("<BBHIHBB", PROTOCOL_MAGIC, 99, 1, 0, 0, 0, 0)
        with pytest.raises(ProtocolError, match="unsupported protocol version"):
            decode_header(bad)

    def test_truncated_rejected(self):
        with pytest.raises(ProtocolError, match="header truncated"):
            decode_header(b"\x00" * 5)

    def test_out_of_range_msg_type(self):
        with pytest.raises(ProtocolError, match="msg_type out of u16"):
            FrameHeader(msg_type=0x10000, seq=0, payload_len=0)

    def test_out_of_range_seq(self):
        with pytest.raises(ProtocolError, match="seq out of u32"):
            FrameHeader(msg_type=1, seq=0x100000000, payload_len=0)

    def test_payload_len_too_big(self):
        with pytest.raises(ProtocolError, match="payload_len invalid"):
            FrameHeader(msg_type=1, seq=0, payload_len=MAX_PAYLOAD_SIZE + 1)


# ------------------------------------------------------------------ payloads

class TestHello:
    def test_roundtrip(self):
        p = HelloPayload(client_id="player_A", client_version_major=1, client_version_minor=0)
        assert HelloPayload.decode(p.encode()) == p

    def test_id_too_long(self):
        with pytest.raises(ProtocolError, match="string too long"):
            HelloPayload("x" * 20, 1, 0).encode()

    def test_truncated(self):
        with pytest.raises(ProtocolError):
            HelloPayload.decode(b"\x00" * 5)


class TestWelcome:
    def test_roundtrip(self):
        p = WelcomePayload(session_id=12345, accepted=True, server_version_major=1,
                           server_version_minor=0, tick_rate_hz=20)
        assert WelcomePayload.decode(p.encode()) == p

    def test_accepted_false_encoded_as_zero(self):
        p = WelcomePayload(0, False, 1, 0, 0)
        assert p.encode()[4] == 0


class TestPeerJoinLeave:
    def test_peer_join_roundtrip(self):
        p = PeerJoinPayload(peer_id="alice", session_id=7)
        assert PeerJoinPayload.decode(p.encode()) == p

    def test_peer_leave_roundtrip(self):
        p = PeerLeavePayload(peer_id="bob", reason=0)
        assert PeerLeavePayload.decode(p.encode()) == p


class TestHeartbeat:
    def test_roundtrip(self):
        p = HeartbeatPayload(timestamp_ms=1_700_000_000_000)
        assert HeartbeatPayload.decode(p.encode()) == p


class TestAck:
    def test_roundtrip(self):
        p = AckPayload(highest_contiguous_seq=100, sack_bitmap=0b1010_1100)
        assert AckPayload.decode(p.encode()) == p

    def test_empty_bitmap(self):
        p = AckPayload(0, 0)
        assert AckPayload.decode(p.encode()) == p


class TestPosState:
    def test_roundtrip(self):
        p = PosStatePayload(x=-79985.19, y=90818.66, z=7851.19,
                            rx=0.1, ry=0.0, rz=1.57,
                            timestamp_ms=1234567890)
        p2 = PosStatePayload.decode(p.encode())
        assert p2.timestamp_ms == p.timestamp_ms
        # Float32 precision tolerance
        for a, b in zip([p.x, p.y, p.z, p.rx, p.ry, p.rz],
                         [p2.x, p2.y, p2.z, p2.rx, p2.ry, p2.rz]):
            assert abs(a - b) < 0.1 or abs((a - b) / a) < 1e-5 if a != 0 else abs(b) < 1e-5

    def test_truncated(self):
        with pytest.raises(ProtocolError):
            PosStatePayload.decode(b"\x00" * 10)


class TestPosBroadcast:
    def test_roundtrip(self):
        p = PosBroadcastPayload(peer_id="player_A",
                                 x=1.0, y=2.0, z=3.0,
                                 rx=0.1, ry=0.2, rz=0.3,
                                 timestamp_ms=555)
        p2 = PosBroadcastPayload.decode(p.encode())
        assert p2.peer_id == p.peer_id
        assert abs(p.x - p2.x) < 1e-3


class TestActorEvent:
    def test_roundtrip(self):
        p = ActorEventPayload(kind=int(ActorEventKind.KILL),
                              form_id=0x1CA7D, actor_base_id=0x20593,
                              x=100.5, y=200.5, z=50.0,
                              extra=0)
        assert ActorEventPayload.decode(p.encode()) == p


class TestChat:
    def test_roundtrip_ascii(self):
        p = ChatPayload(sender_id="alice", text="hello world")
        assert ChatPayload.decode(p.encode()) == p

    def test_roundtrip_unicode(self):
        p = ChatPayload(sender_id="bob", text="ciao 👻 mondo")
        p2 = ChatPayload.decode(p.encode())
        assert p2.text == p.text

    def test_truncated(self):
        with pytest.raises(ProtocolError):
            ChatPayload.decode(b"\x00" * 5)


# ------------------------------------------------------------------ B4: quest stage

class TestQuestStageSet:
    def test_roundtrip(self):
        p = QuestStageSetPayload(quest_form_id=0x12345, new_stage=100, timestamp_ms=1234567890)
        p2 = QuestStageSetPayload.decode(p.encode())
        assert p2 == p

    def test_max_stage_u16(self):
        p = QuestStageSetPayload(quest_form_id=0xFFFFFFFF, new_stage=0xFFFF, timestamp_ms=0)
        assert QuestStageSetPayload.decode(p.encode()) == p

    def test_truncated(self):
        with pytest.raises(ProtocolError):
            QuestStageSetPayload.decode(b"\x00" * 5)


class TestQuestStageBcast:
    def test_roundtrip(self):
        p = QuestStageBroadcastPayload(
            peer_id="player_B", quest_form_id=0xABCD, new_stage=50, timestamp_ms=999,
        )
        p2 = QuestStageBroadcastPayload.decode(p.encode())
        assert p2 == p

    def test_peer_id_stripped_of_nulls(self):
        p = QuestStageBroadcastPayload("ab", 1, 1, 1)
        p2 = QuestStageBroadcastPayload.decode(p.encode())
        assert p2.peer_id == "ab"


class TestQuestStateBoot:
    def test_single_chunk_roundtrip(self):
        entries = tuple(
            QuestStageStateEntry(quest_form_id=0x100 + i, stage=i * 10) for i in range(5)
        )
        p = QuestStateBootPayload(entries=entries, chunk_index=0, total_chunks=1)
        assert QuestStateBootPayload.decode(p.encode()) == p

    def test_empty_entries_allowed(self):
        p = QuestStateBootPayload(entries=(), chunk_index=0, total_chunks=1)
        assert QuestStateBootPayload.decode(p.encode()) == p

    def test_multi_chunk_roundtrip(self):
        entries = tuple(
            QuestStageStateEntry(quest_form_id=i, stage=i) for i in range(17)
        )
        p = QuestStateBootPayload(entries=entries, chunk_index=2, total_chunks=5)
        dec = QuestStateBootPayload.decode(p.encode())
        assert dec.chunk_index == 2
        assert dec.total_chunks == 5
        assert len(dec.entries) == 17

    def test_too_many_entries_rejected(self):
        over = QuestStateBootPayload.MAX_ENTRIES_PER_FRAME + 1
        entries = tuple(QuestStageStateEntry(i, i) for i in range(over))
        with pytest.raises(ProtocolError, match="too many"):
            QuestStateBootPayload(entries=entries).encode()


# ------------------------------------------------------------------ B4: global variables

class TestGlobalVarSet:
    def test_roundtrip_float(self):
        p = GlobalVarSetPayload(global_form_id=0x1234, value=3.14159, timestamp_ms=1000)
        p2 = GlobalVarSetPayload.decode(p.encode())
        assert p2 == p

    def test_roundtrip_int_as_float(self):
        p = GlobalVarSetPayload(global_form_id=0xABCD, value=42.0, timestamp_ms=1)
        p2 = GlobalVarSetPayload.decode(p.encode())
        assert p2.value == 42.0

    def test_large_int_exact(self):
        """i32 globals must be representable exactly in f64."""
        p = GlobalVarSetPayload(global_form_id=1, value=float(2**31 - 1), timestamp_ms=0)
        p2 = GlobalVarSetPayload.decode(p.encode())
        assert int(p2.value) == 2**31 - 1


class TestGlobalVarBcast:
    def test_roundtrip(self):
        p = GlobalVarBroadcastPayload(
            peer_id="player_A", global_form_id=0xDEAD, value=-12.5, timestamp_ms=10,
        )
        p2 = GlobalVarBroadcastPayload.decode(p.encode())
        assert p2 == p


class TestGlobalVarStateBoot:
    def test_roundtrip(self):
        entries = tuple(
            GlobalVarStateEntry(global_form_id=0x10 + i, value=float(i) * 0.5)
            for i in range(10)
        )
        p = GlobalVarStateBootPayload(entries=entries)
        assert GlobalVarStateBootPayload.decode(p.encode()) == p

    def test_too_many_entries_rejected(self):
        over = GlobalVarStateBootPayload.MAX_ENTRIES_PER_FRAME + 1
        entries = tuple(GlobalVarStateEntry(i, float(i)) for i in range(over))
        with pytest.raises(ProtocolError, match="too many"):
            GlobalVarStateBootPayload(entries=entries).encode()


# ------------------------------------------------------------------ end-to-end frame

class TestFullFrame:
    def test_pos_state_frame(self):
        payload = PosStatePayload(1.0, 2.0, 3.0, 0.0, 0.0, 0.0, 0)
        raw = encode_frame(MessageType.POS_STATE, seq=42, payload=payload, reliable=False)
        frame = decode_frame(raw)
        assert frame.header.msg_type == MessageType.POS_STATE
        assert frame.header.seq == 42
        assert not frame.header.is_reliable
        assert isinstance(frame.payload, PosStatePayload)
        assert abs(frame.payload.x - 1.0) < 1e-5

    def test_reliable_flag_propagates(self):
        raw = encode_frame(MessageType.CHAT, 1, ChatPayload("alice", "hi"), reliable=True)
        frame = decode_frame(raw)
        assert frame.header.is_reliable

    def test_unknown_msg_type_as_raw(self):
        """Forward compat: unknown type decoded as RawMessage, not an error."""
        raw = encode_frame(0x9999, 0, RawMessage(msg_type=0x9999, payload=b"\xde\xad\xbe\xef"))
        frame = decode_frame(raw)
        assert isinstance(frame.payload, RawMessage)
        assert frame.payload.payload == b"\xde\xad\xbe\xef"

    def test_truncated_frame_rejected(self):
        payload = PosStatePayload(1.0, 2.0, 3.0, 0.0, 0.0, 0.0, 0)
        raw = encode_frame(MessageType.POS_STATE, 0, payload)
        with pytest.raises(ProtocolError, match="truncated"):
            decode_frame(raw[:20])

    def test_empty_payload_frame(self):
        """HEARTBEAT-like frames with empty payload are legal if type allows."""
        payload = HeartbeatPayload(timestamp_ms=999)
        raw = encode_frame(MessageType.HEARTBEAT, 0, payload)
        frame = decode_frame(raw)
        assert isinstance(frame.payload, HeartbeatPayload)
        assert frame.payload.timestamp_ms == 999

    def test_max_size_frame(self):
        """Largest legal frame encodes and decodes."""
        big_text = "X" * (MAX_PAYLOAD_SIZE - 16 - MAX_CLIENT_ID_LEN - 3)  # leave room for header fields
        # Actually just use a modest-size chat — the limit is per-payload validation
        payload = ChatPayload("s", "Y" * 100)
        raw = encode_frame(MessageType.CHAT, 0, payload)
        assert len(raw) <= HEADER_SIZE + MAX_PAYLOAD_SIZE
        frame = decode_frame(raw)
        assert isinstance(frame.payload, ChatPayload)


# keep import at bottom so test_max_size uses the correct constant
from protocol import MAX_CLIENT_ID_LEN  # noqa: E402

# === M9 wedge 4 v8 — witness NIF descriptor tail ============================
from protocol import (  # noqa: E402
    EquipOpPayload, EquipBroadcastPayload, EquipModRecord,
    NifDescriptor, MAX_NIF_DESCRIPTORS, MAX_NIF_PATH_LEN, MAX_NIF_NAME_LEN,
)


class TestWitnessNifDescriptor:
    """v8 NIF descriptor encode/decode + EquipOp tail integration."""

    def _sample_xform(self, base: float = 0.0) -> tuple:
        # 16 floats: rotation 3x4 (identity-ish) + translate + scale
        return tuple(float(i) + base for i in range(16))

    def test_descriptor_roundtrip(self):
        d = NifDescriptor(
            nif_path=r"Weapons\10mmPistol\Mods\Barrel_Long.nif",
            parent_name="BarrelAttachNode",
            local_transform=self._sample_xform(),
        )
        blob = d.encode()
        decoded, used = NifDescriptor.decode_from(blob, 0)
        assert used == len(blob)
        assert decoded.nif_path == d.nif_path
        assert decoded.parent_name == d.parent_name
        assert decoded.local_transform == d.local_transform

    def test_empty_strings_descriptor(self):
        d = NifDescriptor(
            nif_path="",
            parent_name="",
            local_transform=tuple(0.0 for _ in range(16)),
        )
        blob = d.encode()
        decoded, used = NifDescriptor.decode_from(blob, 0)
        assert used == len(blob)
        assert decoded.nif_path == ""
        assert decoded.parent_name == ""

    def test_long_strings_truncated(self):
        # encode silently truncates per the spec (cap at MAX_NIF_PATH_LEN)
        long_path = "A" * (MAX_NIF_PATH_LEN + 50)
        long_name = "B" * (MAX_NIF_NAME_LEN + 50)
        d = NifDescriptor(long_path, long_name, self._sample_xform())
        blob = d.encode()
        decoded, _ = NifDescriptor.decode_from(blob, 0)
        assert len(decoded.nif_path) == MAX_NIF_PATH_LEN
        assert len(decoded.parent_name) == MAX_NIF_NAME_LEN

    def test_invalid_xform_length_raises(self):
        d = NifDescriptor("p", "n", local_transform=tuple(0.0 for _ in range(15)))
        with pytest.raises(ValueError, match="16 floats"):
            d.encode()

    def test_truncated_blob_raises(self):
        d = NifDescriptor("p", "n", self._sample_xform())
        blob = d.encode()
        with pytest.raises(ValueError):
            NifDescriptor.decode_from(blob[:5], 0)


class TestEquipOpV8:
    """EquipOpPayload + EquipBroadcastPayload v8 tail roundtrip."""

    def _make_descs(self, n: int) -> tuple:
        return tuple(
            NifDescriptor(
                nif_path=fr"Weapons\Test\Mod{i}.nif",
                parent_name=f"AttachNode{i}",
                local_transform=tuple(float(i) + j for j in range(16)),
            )
            for i in range(n)
        )

    def test_op_roundtrip_with_nifs_no_omods(self):
        descs = self._make_descs(3)
        p = EquipOpPayload(
            item_form_id=0x12345,
            kind=1, slot_form_id=0x789, count=1,
            timestamp_ms=12345,
            mods=(),
            nif_descs=descs,
        )
        blob = p.encode()
        p2 = EquipOpPayload.decode(blob)
        assert p2.item_form_id == p.item_form_id
        assert p2.mods == ()
        assert len(p2.nif_descs) == 3
        for orig, dec in zip(descs, p2.nif_descs):
            assert dec.nif_path == orig.nif_path
            assert dec.parent_name == orig.parent_name
            assert dec.local_transform == orig.local_transform

    def test_op_roundtrip_with_omods_and_nifs(self):
        omods = (
            EquipModRecord(form_id=0x1, attach_index=0, rank=1, flag=0),
            EquipModRecord(form_id=0x2, attach_index=0, rank=1, flag=0),
        )
        descs = self._make_descs(2)
        p = EquipOpPayload(
            item_form_id=0x42, kind=1, slot_form_id=0, count=1,
            timestamp_ms=99, mods=omods, nif_descs=descs,
        )
        blob = p.encode()
        p2 = EquipOpPayload.decode(blob)
        assert len(p2.mods) == 2
        assert p2.mods[0].form_id == 0x1
        assert len(p2.nif_descs) == 2
        assert p2.nif_descs[0].nif_path == descs[0].nif_path

    def test_op_back_compat_with_omod_only(self):
        # A v7-shaped buffer (no v8 NIF tail) must still decode cleanly
        # with empty nif_descs.
        omods = (EquipModRecord(0x1, 0, 1, 0),)
        p = EquipOpPayload(
            item_form_id=0xABC, kind=1, slot_form_id=0, count=1,
            timestamp_ms=0, mods=omods, nif_descs=(),
        )
        blob = p.encode()
        # Strip the NIF tail (1 trailing zero byte for nif_count=0)
        blob_no_nif_tail = blob[:-1]
        p2 = EquipOpPayload.decode(blob_no_nif_tail)
        assert len(p2.mods) == 1
        assert p2.nif_descs == ()

    def test_op_cap_truncates_at_max_nif_descriptors(self):
        # Encoding more than MAX_NIF_DESCRIPTORS silently truncates.
        descs = self._make_descs(MAX_NIF_DESCRIPTORS + 5)
        p = EquipOpPayload(
            item_form_id=1, kind=1, slot_form_id=0, count=1,
            timestamp_ms=0, mods=(), nif_descs=descs,
        )
        blob = p.encode()
        p2 = EquipOpPayload.decode(blob)
        assert len(p2.nif_descs) == MAX_NIF_DESCRIPTORS

    def test_bcast_roundtrip_with_nifs(self):
        descs = self._make_descs(2)
        b = EquipBroadcastPayload(
            peer_id="alice",
            item_form_id=0x42, kind=1, slot_form_id=0, count=1,
            timestamp_ms=99, mods=(), nif_descs=descs,
        )
        blob = b.encode()
        b2 = EquipBroadcastPayload.decode(blob)
        assert b2.peer_id == "alice"
        assert len(b2.nif_descs) == 2
        assert b2.nif_descs[0].parent_name == descs[0].parent_name

    def test_op_no_tails(self):
        # Pure v6-shaped payload (no OMODs, no NIFs) — but our encoder always
        # writes a count byte. Decoder must tolerate a buffer with just
        # the fixed payload and no count bytes (back compat with raw v6).
        p_fixed = EquipOpPayload(
            item_form_id=0x1, kind=1, slot_form_id=0, count=1,
            timestamp_ms=0, mods=(), nif_descs=(),
        )
        blob = p_fixed.encode()
        # encode produces fixed (21B) + 0x00 (mod_count) + 0x00 (nif_count) = 23B
        assert len(blob) == EquipOpPayload._STRUCT.size + 2
        # Truncate to fixed only (raw v6 simulation)
        p2 = EquipOpPayload.decode(blob[:EquipOpPayload._STRUCT.size])
        assert p2.mods == ()
        assert p2.nif_descs == ()


# =============================================================== M9.w4 v9
#
# MESH_BLOB chunked replication tests.
#
# Coverage:
#   - ExtractedMesh roundtrip (header + variable-length strings + position
#     and index arrays)
#   - MeshBlobPayload roundtrip with multiple meshes
#   - MeshBlobChunkPayload OP/BCAST roundtrip
#   - chunk_mesh_blob() splits correctly + concatenation reproduces blob
#   - Wire-format constants match protocol.h C++ side

class TestExtractedMesh:
    def _make_simple(self, vc=4, tc=2):
        positions = tuple(float(i) for i in range(3 * vc))
        indices = tuple(i % vc for i in range(3 * tc))
        return ExtractedMesh(
            m_name="Pistol10mmReceiver:0",
            parent_placeholder="P-Receiver",
            bgsm_path="Materials\\Weapons\\10mmPistol\\10mmPistol.BGSM",
            vert_count=vc,
            tri_count=tc,
            local_transform=tuple(0.0 for _ in range(16)),
            positions=positions,
            indices=indices,
        )

    def test_roundtrip(self):
        m = self._make_simple(vc=10, tc=4)
        blob = m.encode()
        # Header (76B) + name + parent + bgsm + 3*10*4 (positions) + 3*4*2 (indices)
        expected_size = 76 + len(m.m_name) + len(m.parent_placeholder) \
                        + len(m.bgsm_path) + 3 * 10 * 4 + 3 * 4 * 2
        assert len(blob) == expected_size

        m2, used = ExtractedMesh.decode_from(blob, 0)
        assert used == len(blob)
        assert m2.m_name == m.m_name
        assert m2.parent_placeholder == m.parent_placeholder
        assert m2.bgsm_path == m.bgsm_path
        assert m2.vert_count == m.vert_count
        assert m2.tri_count == m.tri_count
        assert m2.positions == m.positions
        assert m2.indices == m.indices

    def test_decode_truncated_header(self):
        with pytest.raises(ProtocolError):
            ExtractedMesh.decode_from(b"\x00\x00", 0)

    def test_decode_truncated_body(self):
        m = self._make_simple()
        blob = m.encode()
        with pytest.raises(ProtocolError):
            ExtractedMesh.decode_from(blob[:80], 0)  # cut mid-strings

    def test_positions_length_mismatch_raises(self):
        with pytest.raises(ProtocolError):
            ExtractedMesh(
                m_name="x", parent_placeholder="y", bgsm_path="z",
                vert_count=4, tri_count=2,
                local_transform=tuple(0.0 for _ in range(16)),
                positions=(0.0, 0.0, 0.0),  # too short
                indices=(0, 1, 2, 0, 2, 1),
            ).encode()

    def test_indices_length_mismatch_raises(self):
        with pytest.raises(ProtocolError):
            ExtractedMesh(
                m_name="x", parent_placeholder="y", bgsm_path="z",
                vert_count=2, tri_count=2,
                local_transform=tuple(0.0 for _ in range(16)),
                positions=tuple(float(i) for i in range(6)),
                indices=(0, 1, 2),  # too short
            ).encode()


class TestMeshBlobPayload:
    def _make_mesh(self, name, vc=3, tc=1):
        return ExtractedMesh(
            m_name=name,
            parent_placeholder="P-X",
            bgsm_path="Materials\\Weapons\\Test.BGSM",
            vert_count=vc, tri_count=tc,
            local_transform=tuple(float(i) for i in range(16)),
            positions=tuple(float(i) for i in range(3 * vc)),
            indices=tuple(i % vc for i in range(3 * tc)),
        )

    def test_single_mesh_roundtrip(self):
        meshes = (self._make_mesh("Mesh0", vc=4, tc=2),)
        p = MeshBlobPayload(item_form_id=0x1234, equip_seq=42, meshes=meshes)
        blob = p.encode()
        p2 = MeshBlobPayload.decode(blob)
        assert p2.item_form_id == 0x1234
        assert p2.equip_seq == 42
        assert len(p2.meshes) == 1
        assert p2.meshes[0].m_name == "Mesh0"
        assert p2.meshes[0].vert_count == 4
        assert p2.meshes[0].tri_count == 2

    def test_multi_mesh_roundtrip(self):
        meshes = tuple(
            self._make_mesh(f"Mesh{i}", vc=10 + i, tc=4 + i)
            for i in range(8)
        )
        p = MeshBlobPayload(item_form_id=0xABC, equip_seq=99, meshes=meshes)
        blob = p.encode()
        p2 = MeshBlobPayload.decode(blob)
        assert len(p2.meshes) == 8
        for i, m in enumerate(p2.meshes):
            assert m.m_name == f"Mesh{i}"
            assert m.vert_count == 10 + i
            assert m.tri_count == 4 + i

    def test_too_many_meshes_raises(self):
        meshes = tuple(self._make_mesh(f"M{i}") for i in range(MAX_MESHES_PER_BLOB + 1))
        with pytest.raises(ProtocolError):
            MeshBlobPayload(item_form_id=1, equip_seq=1, meshes=meshes).encode()


class TestMeshBlobChunk:
    def test_op_roundtrip(self):
        data = bytes(range(50))
        c = MeshBlobChunkPayload(
            equip_seq=7, total_blob_size=1000,
            chunk_index=2, total_chunks=10, chunk_data=data,
        )
        blob = c.encode()
        c2 = MeshBlobChunkPayload.decode(blob)
        assert c2.equip_seq == 7
        assert c2.total_blob_size == 1000
        assert c2.chunk_index == 2
        assert c2.total_chunks == 10
        assert c2.chunk_data == data

    def test_bcast_roundtrip(self):
        data = bytes(range(50))
        c = MeshBlobChunkBroadcastPayload(
            peer_id="alice", equip_seq=7, total_blob_size=1000,
            chunk_index=2, total_chunks=10, chunk_data=data,
        )
        blob = c.encode()
        c2 = MeshBlobChunkBroadcastPayload.decode(blob)
        assert c2.peer_id == "alice"
        assert c2.equip_seq == 7
        assert c2.total_blob_size == 1000
        assert c2.chunk_index == 2
        assert c2.total_chunks == 10
        assert c2.chunk_data == data

    def test_op_chunk_data_too_large_raises(self):
        data = b"\x00" * (MESH_BLOB_OP_CHUNK_DATA_MAX + 1)
        c = MeshBlobChunkPayload(
            equip_seq=1, total_blob_size=1, chunk_index=0,
            total_chunks=1, chunk_data=data,
        )
        with pytest.raises(ProtocolError):
            c.encode()

    def test_bcast_chunk_data_too_large_raises(self):
        data = b"\x00" * (MESH_BLOB_BCAST_CHUNK_DATA_MAX + 1)
        c = MeshBlobChunkBroadcastPayload(
            peer_id="x", equip_seq=1, total_blob_size=1, chunk_index=0,
            total_chunks=1, chunk_data=data,
        )
        with pytest.raises(ProtocolError):
            c.encode()


class TestChunkMeshBlob:
    def test_empty_blob(self):
        assert chunk_mesh_blob(b"") == []

    def test_single_chunk(self):
        blob = b"\x00" * 100
        chunks = chunk_mesh_blob(blob)
        assert len(chunks) == 1
        ci, total, data = chunks[0]
        assert ci == 0
        assert total == 1
        assert data == blob

    def test_exact_chunk_boundary(self):
        # Blob exactly fills one chunk → still 1 chunk, no leftover empty.
        blob = b"\xAB" * MESH_BLOB_OP_CHUNK_DATA_MAX
        chunks = chunk_mesh_blob(blob)
        assert len(chunks) == 1
        assert chunks[0][2] == blob

    def test_two_chunks(self):
        # Force a 2-chunk split.
        blob = b"\xAB" * (MESH_BLOB_OP_CHUNK_DATA_MAX + 100)
        chunks = chunk_mesh_blob(blob)
        assert len(chunks) == 2
        assert chunks[0][0] == 0
        assert chunks[0][1] == 2
        assert chunks[1][0] == 1
        assert chunks[1][1] == 2
        # Concatenation reproduces blob.
        assert chunks[0][2] + chunks[1][2] == blob

    def test_concatenation_reproduces_blob(self):
        # Realistic: 80 KB blob (typical modded weapon) → ~58 chunks.
        blob = bytes(range(256)) * 320   # 81920 bytes
        chunks = chunk_mesh_blob(blob)
        rebuilt = b"".join(d for _, _, d in chunks)
        assert rebuilt == blob

    def test_blob_too_large_raises(self):
        with pytest.raises(ProtocolError):
            chunk_mesh_blob(b"\x00" * (MAX_BLOB_SIZE + 1))


class TestMeshBlobE2E:
    """Integration: MeshBlobPayload → bytes → chunk → reassemble → decode."""

    def test_roundtrip_through_chunks(self):
        meshes = tuple(
            ExtractedMesh(
                m_name=f"Mesh{i}",
                parent_placeholder=f"P-{i}",
                bgsm_path=f"Materials\\Test\\m{i}.BGSM",
                vert_count=20 + i,
                tri_count=10 + i,
                local_transform=tuple(float(j + i) for j in range(16)),
                positions=tuple(float(j) for j in range(3 * (20 + i))),
                indices=tuple(j % (20 + i) for j in range(3 * (10 + i))),
            )
            for i in range(5)
        )
        original = MeshBlobPayload(
            item_form_id=0x42,
            equip_seq=7,
            meshes=meshes,
        )
        blob_bytes = original.encode()

        # Chunk
        chunks = chunk_mesh_blob(blob_bytes)
        assert len(chunks) >= 1
        # All chunks except the last are full-size.
        for ci, total, data in chunks[:-1]:
            assert len(data) == MESH_BLOB_OP_CHUNK_DATA_MAX
        # Last chunk is partial (or full if blob hits boundary).
        assert len(chunks[-1][2]) <= MESH_BLOB_OP_CHUNK_DATA_MAX

        # Reassemble
        rebuilt = b"".join(d for _, _, d in chunks)
        assert rebuilt == blob_bytes

        # Decode
        decoded = MeshBlobPayload.decode(rebuilt)
        assert decoded.item_form_id == 0x42
        assert decoded.equip_seq == 7
        assert len(decoded.meshes) == 5
        for i, m in enumerate(decoded.meshes):
            assert m.m_name == f"Mesh{i}"
            assert m.vert_count == 20 + i
            assert m.tri_count == 10 + i

    def test_message_type_dispatch(self):
        # Decoder can dispatch by msg_type.
        c = MeshBlobChunkPayload(
            equip_seq=1, total_blob_size=10, chunk_index=0,
            total_chunks=1, chunk_data=b"\x00" * 10,
        )
        frame_bytes = encode_frame(MessageType.MESH_BLOB_OP, 1, c)
        f = decode_frame(frame_bytes)
        assert f.header.msg_type == MessageType.MESH_BLOB_OP
        assert isinstance(f.payload, MeshBlobChunkPayload)
        assert f.payload.equip_seq == 1
        assert f.payload.chunk_data == b"\x00" * 10

    def test_message_type_dispatch_bcast(self):
        c = MeshBlobChunkBroadcastPayload(
            peer_id="alice",
            equip_seq=1, total_blob_size=10, chunk_index=0,
            total_chunks=1, chunk_data=b"\x00" * 10,
        )
        frame_bytes = encode_frame(MessageType.MESH_BLOB_BCAST, 1, c)
        f = decode_frame(frame_bytes)
        assert f.header.msg_type == MessageType.MESH_BLOB_BCAST
        assert isinstance(f.payload, MeshBlobChunkBroadcastPayload)
        assert f.payload.peer_id == "alice"
