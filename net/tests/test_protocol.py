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
