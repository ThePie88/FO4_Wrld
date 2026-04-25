"""B4 quest stage + global variable sync tests.

Coverage:
  - ServerState.record_quest_stage / record_global_var (last-write-wins,
    reject zero form_id, reject NaN)
  - ServerProtocol handlers: broadcast to other peers, record on server
  - Bootstrap on peer join: server ships QUEST_STATE_BOOT + GLOBAL_VAR_STATE_BOOT
"""
from __future__ import annotations

import asyncio
import math
import socket
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from protocol import (  # noqa: E402
    MessageType, PROTOCOL_VERSION,
    HelloPayload, WelcomePayload, AckPayload,
    QuestStageSetPayload, QuestStageBroadcastPayload,
    QuestStateBootPayload, QuestStageStateEntry,
    GlobalVarSetPayload, GlobalVarBroadcastPayload,
    GlobalVarStateBootPayload, GlobalVarStateEntry,
    encode_frame, decode_frame,
)
from server.state import ServerState, QuestStageState, GlobalVarState  # noqa: E402
from server.main import ServerProtocol  # noqa: E402


# ------------------------------------------------------------------ state unit tests

class TestQuestStageStateUnit:
    def test_first_set_creates_entry(self):
        s = ServerState()
        q = s.record_quest_stage(0x100, 10, "alice", 1000.0)
        assert q is not None
        assert q.quest_form_id == 0x100
        assert q.stage == 10
        assert q.last_owner_peer_id == "alice"

    def test_second_set_updates(self):
        s = ServerState()
        s.record_quest_stage(0x100, 10, "alice", 1000.0)
        q = s.record_quest_stage(0x100, 50, "bob", 2000.0)
        assert q.stage == 50
        assert q.last_owner_peer_id == "bob"

    def test_reset_to_lower_stage_accepted(self):
        """Last-write-wins: ResetQuest dropping the stage is legitimate."""
        s = ServerState()
        s.record_quest_stage(0x100, 100, "alice", 1000.0)
        q = s.record_quest_stage(0x100, 0, "alice", 2000.0)
        assert q.stage == 0

    def test_reject_zero_form_id(self):
        s = ServerState()
        assert s.record_quest_stage(0, 10, "alice", 1000.0) is None

    def test_reject_out_of_range_stage(self):
        s = ServerState()
        assert s.record_quest_stage(0x100, -1, "alice", 0.0) is None
        assert s.record_quest_stage(0x100, 0x10000, "alice", 0.0) is None

    def test_all_quest_stages_returns_list(self):
        s = ServerState()
        s.record_quest_stage(0x100, 10, "a", 0.0)
        s.record_quest_stage(0x200, 20, "b", 0.0)
        all_q = s.all_quest_stages()
        assert len(all_q) == 2


class TestGlobalVarStateUnit:
    def test_first_set(self):
        s = ServerState()
        g = s.record_global_var(0xDEAD, 3.14, "alice", 1000.0)
        assert g is not None
        assert g.value == pytest.approx(3.14)

    def test_overwrite(self):
        s = ServerState()
        s.record_global_var(0xDEAD, 3.14, "alice", 1000.0)
        g = s.record_global_var(0xDEAD, -99.0, "bob", 2000.0)
        assert g.value == -99.0
        assert g.last_owner_peer_id == "bob"

    def test_reject_zero_form_id(self):
        s = ServerState()
        assert s.record_global_var(0, 1.0, "alice", 0.0) is None

    def test_reject_nan(self):
        s = ServerState()
        assert s.record_global_var(0x100, float("nan"), "alice", 0.0) is None

    def test_reject_inf(self):
        s = ServerState()
        assert s.record_global_var(0x100, float("inf"), "alice", 0.0) is None
        assert s.record_global_var(0x100, float("-inf"), "alice", 0.0) is None


# ------------------------------------------------------------------ end-to-end via raw UDP

async def _start_server_with_state(state: ServerState, port: int):
    loop = asyncio.get_running_loop()
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: ServerProtocol(state),
        local_addr=("127.0.0.1", port),
    )
    from net.tests.test_server_integration import _periodic_tick_driver
    loop.create_task(_periodic_tick_driver(protocol, 20))
    return transport, protocol


async def _raw_peer_hello(sock: socket.socket, server_addr, client_id: str) -> int:
    hello = HelloPayload(client_id=client_id, client_version_major=1, client_version_minor=0)
    raw = encode_frame(MessageType.HELLO, 0, hello, reliable=True)
    sock.sendto(raw, server_addr)
    sock.setblocking(False)
    deadline = asyncio.get_running_loop().time() + 2.0
    while asyncio.get_running_loop().time() < deadline:
        try:
            data, _ = sock.recvfrom(4096)
        except BlockingIOError:
            await asyncio.sleep(0.02)
            continue
        frame = decode_frame(data)
        if frame.header.msg_type == int(MessageType.WELCOME):
            ack = AckPayload(highest_contiguous_seq=frame.header.seq, sack_bitmap=0)
            sock.sendto(encode_frame(MessageType.ACK, 0, ack, reliable=False), server_addr)
            assert frame.payload.accepted
            return frame.payload.session_id
    raise AssertionError("HELLO -> WELCOME timed out")


async def _collect_frames(sock: socket.socket, duration_s: float) -> list:
    out = []
    loop = asyncio.get_running_loop()
    deadline = loop.time() + duration_s
    sock.setblocking(False)
    while loop.time() < deadline:
        try:
            data, addr = sock.recvfrom(4096)
        except BlockingIOError:
            await asyncio.sleep(0.01)
            continue
        try:
            frame = decode_frame(data)
        except Exception:
            continue
        out.append((frame, addr))
        if frame.header.flags & 0x01:
            ack = AckPayload(highest_contiguous_seq=frame.header.seq, sack_bitmap=0)
            sock.sendto(encode_frame(MessageType.ACK, 0, ack, reliable=False), addr)
    return out


@pytest.mark.asyncio
async def test_quest_stage_set_broadcasts_to_other_peers():
    """Peer A sends QUEST_STAGE_SET → server records + broadcasts to peer B.
    Server's own copy reflects the new stage; sender gets NO echo."""
    port = 31520
    state = ServerState()
    transport, protocol_obj = await _start_server_with_state(state, port)
    try:
        server_addr = ("127.0.0.1", port)
        sock_a = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock_b = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock_a.bind(("127.0.0.1", 0)); sock_b.bind(("127.0.0.1", 0))
        try:
            await asyncio.gather(
                _raw_peer_hello(sock_a, server_addr, "peer_qA"),
                _raw_peer_hello(sock_b, server_addr, "peer_qB"),
            )
            # Drain any bootstrap / peer-join noise
            await _collect_frames(sock_b, 0.3)
            await _collect_frames(sock_a, 0.0)

            # A sets quest 0xABCD to stage 50
            op = QuestStageSetPayload(quest_form_id=0xABCD, new_stage=50, timestamp_ms=100)
            sock_a.sendto(encode_frame(MessageType.QUEST_STAGE_SET, 1, op, reliable=True),
                          server_addr)

            frames_b = await _collect_frames(sock_b, 0.8)
            frames_a = await _collect_frames(sock_a, 0.1)

            bcasts_b = [f.payload for f, _ in frames_b
                        if f.header.msg_type == int(MessageType.QUEST_STAGE_BCAST)]
            bcasts_a = [f.payload for f, _ in frames_a
                        if f.header.msg_type == int(MessageType.QUEST_STAGE_BCAST)]

            assert len(bcasts_b) == 1, f"B should receive 1 bcast, got {bcasts_b}"
            assert len(bcasts_a) == 0, f"A (sender) should receive NO echo, got {bcasts_a}"
            assert bcasts_b[0].peer_id == "peer_qA"
            assert bcasts_b[0].quest_form_id == 0xABCD
            assert bcasts_b[0].new_stage == 50

            # Server state updated
            q = state.quest_stage(0xABCD)
            assert q is not None and q.stage == 50 and q.last_owner_peer_id == "peer_qA"
        finally:
            sock_a.close(); sock_b.close()
    finally:
        transport.close()


@pytest.mark.asyncio
async def test_global_var_set_broadcasts_to_other_peers():
    """Same pattern for GlobalVar.SetValue."""
    port = 31521
    state = ServerState()
    transport, protocol_obj = await _start_server_with_state(state, port)
    try:
        server_addr = ("127.0.0.1", port)
        sock_a = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock_b = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock_a.bind(("127.0.0.1", 0)); sock_b.bind(("127.0.0.1", 0))
        try:
            await asyncio.gather(
                _raw_peer_hello(sock_a, server_addr, "peer_gA"),
                _raw_peer_hello(sock_b, server_addr, "peer_gB"),
            )
            await _collect_frames(sock_b, 0.3)
            await _collect_frames(sock_a, 0.0)

            op = GlobalVarSetPayload(global_form_id=0x1234, value=42.5, timestamp_ms=0)
            sock_a.sendto(encode_frame(MessageType.GLOBAL_VAR_SET, 1, op, reliable=True),
                          server_addr)

            frames_b = await _collect_frames(sock_b, 0.8)
            frames_a = await _collect_frames(sock_a, 0.1)

            bcasts_b = [f.payload for f, _ in frames_b
                        if f.header.msg_type == int(MessageType.GLOBAL_VAR_BCAST)]
            bcasts_a = [f.payload for f, _ in frames_a
                        if f.header.msg_type == int(MessageType.GLOBAL_VAR_BCAST)]

            assert len(bcasts_b) == 1
            assert len(bcasts_a) == 0
            assert bcasts_b[0].peer_id == "peer_gA"
            assert bcasts_b[0].global_form_id == 0x1234
            assert bcasts_b[0].value == pytest.approx(42.5)

            g = state.global_var(0x1234)
            assert g is not None and g.value == pytest.approx(42.5)
        finally:
            sock_a.close(); sock_b.close()
    finally:
        transport.close()


@pytest.mark.asyncio
async def test_bootstrap_ships_existing_quest_and_global_state():
    """Peer connecting to a seeded server receives QUEST_STATE_BOOT +
    GLOBAL_VAR_STATE_BOOT snapshots on WELCOME."""
    port = 31522
    state = ServerState()
    # Pre-seed server
    state.record_quest_stage(0x1001, 100, "seeder", 0.0)
    state.record_quest_stage(0x1002, 200, "seeder", 0.0)
    state.record_global_var(0x2001, 1.5, "seeder", 0.0)

    transport, protocol_obj = await _start_server_with_state(state, port)
    try:
        server_addr = ("127.0.0.1", port)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 0))
        try:
            sid = await _raw_peer_hello(sock, server_addr, "peer_boot")
            assert sid > 0
            frames = await _collect_frames(sock, 0.8)

            quest_boot = [f.payload for f, _ in frames
                          if f.header.msg_type == int(MessageType.QUEST_STATE_BOOT)]
            global_boot = [f.payload for f, _ in frames
                           if f.header.msg_type == int(MessageType.GLOBAL_VAR_STATE_BOOT)]

            # Collect all entries across any chunks
            q_entries = [e for p in quest_boot for e in p.entries]
            g_entries = [e for p in global_boot for e in p.entries]
            q_map = {e.quest_form_id: e.stage for e in q_entries}
            g_map = {e.global_form_id: e.value for e in g_entries}
            assert q_map == {0x1001: 100, 0x1002: 200}
            assert g_map[0x2001] == pytest.approx(1.5)
        finally:
            sock.close()
    finally:
        transport.close()


@pytest.mark.asyncio
async def test_reject_zero_form_id_no_broadcast():
    """QUEST_STAGE_SET with quest_form_id=0 → rejected, no broadcast, server state unchanged."""
    port = 31523
    state = ServerState()
    transport, protocol_obj = await _start_server_with_state(state, port)
    try:
        server_addr = ("127.0.0.1", port)
        sock_a = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock_b = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock_a.bind(("127.0.0.1", 0)); sock_b.bind(("127.0.0.1", 0))
        try:
            await asyncio.gather(
                _raw_peer_hello(sock_a, server_addr, "peer_rA"),
                _raw_peer_hello(sock_b, server_addr, "peer_rB"),
            )
            await _collect_frames(sock_b, 0.3)
            rejections_before = protocol_obj.stats()["rejections"]

            op = QuestStageSetPayload(quest_form_id=0, new_stage=10, timestamp_ms=0)
            sock_a.sendto(encode_frame(MessageType.QUEST_STAGE_SET, 1, op, reliable=True),
                          server_addr)

            frames_b = await _collect_frames(sock_b, 0.6)
            bcasts = [f for f, _ in frames_b
                      if f.header.msg_type == int(MessageType.QUEST_STAGE_BCAST)]
            assert len(bcasts) == 0
            assert state.all_quest_stages() == []
            assert protocol_obj.stats()["rejections"] >= rejections_before + 1
        finally:
            sock_a.close(); sock_b.close()
    finally:
        transport.close()
