"""L5 stage 4b (2026-10-03): item instances on the container wire.

Until v33 a container line was (base, count): a modded pistol and a plain
one were the same item, an observer's AddItem rolled its own instance and a
base-only removal took whatever stack sat at the head of the chain. Measured
live in 4a (2026-10-03): A deposited a "Compensated Hardened 10mm Auto
Pistol", B's engine made a "10mm Auto Pistol" of its own, B took it, and A's
modded pistol was the one A's engine destroyed. Every line now carries the
instance fingerprint of what it holds, and the descriptor that rebuilds it.
"""
from __future__ import annotations

import asyncio
import json
import socket
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from protocol import (  # noqa: E402
    MessageType, ProtocolError,
    ContainerOpPayload, ContainerBroadcastPayload, ContainerOpAckPayload,
    ContainerOpAckStatus, ContainerOpKind,
    ContainerStateEntry, ContainerStatePayload, ContainerSeedPayload,
    InstanceDescriptor, InstanceDefEntry, InstanceDefsPayload,
    INSTANCE_FLAG_OIE, INSTANCE_FLAG_HEALTH, INSTANCE_MAX_MODS,
    FP_PLAIN, FP_UNKNOWN, instance_fp,
    encode_frame, decode_frame,
)
from server.state import ServerState, PeerSession, SessionState  # noqa: E402
from server.validator import validate_container_op, RejectReason  # noqa: E402
from server.persistence import snapshot, load_into  # noqa: E402
from net.tests.test_container import (  # noqa: E402
    _start_server_with_state, _raw_peer_hello, _collect_frames,
)
from net.tests.test_container_reconverge import _two_raw_peers  # noqa: E402

TRUNK_FID = 0x1F3A2
TRUNK_BASE = 0xDEAD01
TRUNK_CELL = 0x1696A
PISTOL = 0x4822
STIMPAK = 0x23736

# The two pistols of the 4a test, read off the live logs.
PLAIN_PISTOL = InstanceDescriptor(
    template=2, flags=INSTANCE_FLAG_OIE,
    mods=((0x91FC4, 0, 1), (0x231AB, 0, 1), (0x100E27, 0, 1),
          (0x91FC2, 0, 1), (0x148409, 0, 1), (0x4F21D, 0, 1)))
AUTO_PISTOL = InstanceDescriptor(
    template=4, flags=INSTANCE_FLAG_OIE,
    mods=((0x100E2E, 0, 1), (0x231AB, 0, 1), (0x100E27, 0, 1),
          (0x91FC2, 0, 1), (0x148409, 0, 1), (0x4F21D, 0, 1)))


def _session(peer_id: str = "alice") -> PeerSession:
    return PeerSession(
        session_id=1, peer_id=peer_id, addr=("1.2.3.4", 5000),
        client_version=(1, 0), state=SessionState.ACTIVE,
        joined_at_ms=0.0, last_seen_ms=0.0,
    )


def _op(kind: ContainerOpKind, item: int, count: int, desc: InstanceDescriptor | None,
        fp: int | None = None, op_id: int = 0) -> ContainerOpPayload:
    d = desc if desc is not None else InstanceDescriptor()
    return ContainerOpPayload(
        kind=int(kind), container_form_id=TRUNK_FID,
        container_base_id=TRUNK_BASE, container_cell_id=TRUNK_CELL,
        item_base_id=item, count=count, timestamp_ms=0, client_op_id=op_id,
        item_fp=instance_fp(item, d) if fp is None else fp, instance=d,
    )


# ------------------------------------------------------------------ fingerprint

class TestFingerprint:
    def test_plain_is_zero(self):
        assert instance_fp(STIMPAK, InstanceDescriptor()) == FP_PLAIN

    def test_reserved_values_never_name_an_instance(self):
        fp = instance_fp(PISTOL, PLAIN_PISTOL)
        assert fp not in (FP_PLAIN, FP_UNKNOWN)

    def test_shared_vector_with_the_dll(self):
        # The same value is checked by the DLL at startup
        # (fw_native/src/persist/instance_fp.cpp, self_check): the two
        # implementations must agree byte for byte or every line diverges.
        assert instance_fp(PISTOL, PLAIN_PISTOL) == 0x5EC6921B06D17B4B

    def test_mod_order_is_not_part_of_the_instance(self):
        shuffled = InstanceDescriptor(
            template=2, flags=INSTANCE_FLAG_OIE, mods=tuple(reversed(PLAIN_PISTOL.mods)))
        assert instance_fp(PISTOL, shuffled) == instance_fp(PISTOL, PLAIN_PISTOL)

    def test_template_base_mods_and_health_are(self):
        base = instance_fp(PISTOL, PLAIN_PISTOL)
        assert instance_fp(PISTOL, AUTO_PISTOL) != base
        other_tmpl = InstanceDescriptor(template=3, flags=INSTANCE_FLAG_OIE,
                                        mods=PLAIN_PISTOL.mods)
        assert instance_fp(PISTOL, other_tmpl) != base
        assert instance_fp(PISTOL + 1, PLAIN_PISTOL) != base
        worn = InstanceDescriptor(template=2, flags=INSTANCE_FLAG_OIE | INSTANCE_FLAG_HEALTH,
                                  health=0.5, mods=PLAIN_PISTOL.mods)
        assert instance_fp(PISTOL, worn) != base

    def test_health_rounds_half_away_from_zero_like_the_dll(self):
        # 0.0625 * 1000 = 62.5 exactly in f32: std::lround gives 63, Python's
        # round() would give 62. The spec is the DLL's.
        a = InstanceDescriptor(flags=INSTANCE_FLAG_HEALTH, health=0.0625)
        b = InstanceDescriptor(flags=INSTANCE_FLAG_HEALTH, health=0.063)
        assert instance_fp(PISTOL, a) == instance_fp(PISTOL, b)

    def test_too_many_mods_refused(self):
        many = InstanceDescriptor(flags=INSTANCE_FLAG_OIE,
                                  mods=tuple((0x1000 + i, 0, 1) for i in range(INSTANCE_MAX_MODS + 1)))
        with pytest.raises(ProtocolError):
            many.encode()


# ------------------------------------------------------------------ wire

class TestWire:
    def test_descriptor_roundtrip(self):
        d = InstanceDescriptor(template=5, flags=INSTANCE_FLAG_OIE | INSTANCE_FLAG_HEALTH,
                               health=0.75, mods=AUTO_PISTOL.mods)
        raw = d.encode()
        assert len(raw) == InstanceDescriptor.SIZE == 104
        back, off = InstanceDescriptor.decode(raw, 0)
        assert back == d and off == 104

    def test_op_carries_fp_and_descriptor(self):
        p = _op(ContainerOpKind.PUT, PISTOL, 1, PLAIN_PISTOL, op_id=9)
        assert len(p.encode()) == 148
        f = decode_frame(encode_frame(MessageType.CONTAINER_OP, 1, p, reliable=True))
        assert f.payload == p

    def test_bcast_carries_fp_and_descriptor(self):
        b = ContainerBroadcastPayload(
            peer_id="alice", kind=int(ContainerOpKind.PUT),
            container_base_id=TRUNK_BASE, container_cell_id=TRUNK_CELL,
            item_base_id=PISTOL, count=1, timestamp_ms=5, container_form_id=TRUNK_FID,
            item_fp=instance_fp(PISTOL, AUTO_PISTOL), instance=AUTO_PISTOL)
        f = decode_frame(encode_frame(MessageType.CONTAINER_BCAST, 2, b, reliable=True))
        assert f.payload == b

    def test_ack_carries_fp(self):
        a = ContainerOpAckPayload(client_op_id=3, status=0, container_base_id=TRUNK_BASE,
                                  container_cell_id=TRUNK_CELL, item_base_id=PISTOL,
                                  final_count=1, item_fp=instance_fp(PISTOL, PLAIN_PISTOL))
        assert len(a.encode()) == 29
        f = decode_frame(encode_frame(MessageType.CONTAINER_OP_ACK, 3, a, reliable=True))
        assert f.payload == a

    def test_state_entry_carries_fp(self):
        e = ContainerStateEntry(TRUNK_FID, TRUNK_BASE, TRUNK_CELL, PISTOL, 1,
                                item_fp=instance_fp(PISTOL, PLAIN_PISTOL))
        s = ContainerStatePayload(entries=(e,))
        f = decode_frame(encode_frame(MessageType.CONTAINER_STATE, 4, s, reliable=True))
        assert f.payload == s
        assert ContainerStatePayload.MAX_ENTRIES_PER_FRAME == 49
        seed = ContainerSeedPayload(entries=(e,))
        f = decode_frame(encode_frame(MessageType.CONTAINER_SEED, 5, seed, reliable=True))
        assert f.payload == seed

    def test_instance_defs_roundtrip(self):
        entries = (InstanceDefEntry(PISTOL, instance_fp(PISTOL, PLAIN_PISTOL), PLAIN_PISTOL),
                   InstanceDefEntry(PISTOL, instance_fp(PISTOL, AUTO_PISTOL), AUTO_PISTOL))
        p = InstanceDefsPayload(entries=entries, chunk_index=0, total_chunks=1)
        f = decode_frame(encode_frame(MessageType.INSTANCE_DEFS, 6, p, reliable=True))
        assert f.payload == p
        assert InstanceDefsPayload.MAX_ENTRIES_PER_FRAME == 12


# ------------------------------------------------------------------ server state

class TestRecords:
    def test_two_instances_of_one_base_are_two_lines(self):
        s = ServerState()
        s.record_container_op(_op(ContainerOpKind.PUT, PISTOL, 1, PLAIN_PISTOL), "alice", 0.0)
        s.record_container_op(_op(ContainerOpKind.PUT, PISTOL, 1, AUTO_PISTOL), "alice", 0.0)
        c = s.container_state(TRUNK_FID)
        assert c.items == {(PISTOL, instance_fp(PISTOL, PLAIN_PISTOL)): 1,
                           (PISTOL, instance_fp(PISTOL, AUTO_PISTOL)): 1}

    def test_a_put_registers_the_descriptor(self):
        s = ServerState()
        s.record_container_op(_op(ContainerOpKind.PUT, PISTOL, 1, AUTO_PISTOL), "alice", 0.0)
        assert s.instance_def(instance_fp(PISTOL, AUTO_PISTOL)) == (PISTOL, AUTO_PISTOL)

    def test_take_removes_the_instance_named(self):
        s = ServerState()
        s.create_container(TRUNK_FID, TRUNK_BASE, TRUNK_CELL,
                           {(PISTOL, instance_fp(PISTOL, PLAIN_PISTOL)): 1,
                            (PISTOL, instance_fp(PISTOL, AUTO_PISTOL)): 1}, "seed", 0.0)
        s.record_container_op(_op(ContainerOpKind.TAKE, PISTOL, 1, AUTO_PISTOL), "bob", 0.0)
        assert s.container_state(TRUNK_FID).items == {
            (PISTOL, instance_fp(PISTOL, PLAIN_PISTOL)): 1}

    def test_a_legacy_line_answers_any_instance(self):
        # A v33 record knew the base and the count, not the instance.
        s = ServerState()
        s.create_container(TRUNK_FID, TRUNK_BASE, TRUNK_CELL,
                           {(PISTOL, FP_UNKNOWN): 2}, "seed", 0.0)
        op = _op(ContainerOpKind.TAKE, PISTOL, 1, AUTO_PISTOL)
        assert validate_container_op(_session(), op, s.container_state(TRUNK_FID), 0.0).ok
        s.record_container_op(op, "bob", 0.0)
        assert s.container_state(TRUNK_FID).items == {(PISTOL, FP_UNKNOWN): 1}

    def test_take_with_an_unknown_instance_uses_the_base(self):
        s = ServerState()
        s.create_container(TRUNK_FID, TRUNK_BASE, TRUNK_CELL,
                           {(PISTOL, instance_fp(PISTOL, PLAIN_PISTOL)): 1}, "seed", 0.0)
        op = _op(ContainerOpKind.TAKE, PISTOL, 1, None, fp=FP_UNKNOWN)
        assert validate_container_op(_session(), op, s.container_state(TRUNK_FID), 0.0).ok
        s.record_container_op(op, "bob", 0.0)
        assert s.container_state(TRUNK_FID).items == {}


class TestValidator:
    def test_take_of_an_instance_the_container_does_not_hold_is_insufficient(self):
        # The swap of 4a, refused at the boundary: the record holds the plain
        # pistol, a client claims to have taken another instance of it.
        s = ServerState()
        s.create_container(TRUNK_FID, TRUNK_BASE, TRUNK_CELL,
                           {(PISTOL, instance_fp(PISTOL, PLAIN_PISTOL)): 1}, "seed", 0.0)
        r = validate_container_op(_session(), _op(ContainerOpKind.TAKE, PISTOL, 1, AUTO_PISTOL),
                                  s.container_state(TRUNK_FID), 0.0)
        assert not r.ok and r.reason == RejectReason.INSUFFICIENT_ITEMS

    def test_a_plain_line_does_not_answer_an_instance(self):
        s = ServerState()
        s.create_container(TRUNK_FID, TRUNK_BASE, TRUNK_CELL, {(PISTOL, FP_PLAIN): 1}, "seed", 0.0)
        r = validate_container_op(_session(), _op(ContainerOpKind.TAKE, PISTOL, 1, AUTO_PISTOL),
                                  s.container_state(TRUNK_FID), 0.0)
        assert not r.ok and r.reason == RejectReason.INSUFFICIENT_ITEMS

    def test_a_descriptor_that_does_not_make_the_fingerprint_is_refused(self):
        op = _op(ContainerOpKind.PUT, PISTOL, 1, AUTO_PISTOL,
                 fp=instance_fp(PISTOL, PLAIN_PISTOL))
        r = validate_container_op(_session(), op, None, 0.0)
        assert not r.ok and r.reason == RejectReason.INSTANCE_MISMATCH

    def test_a_plain_fingerprint_with_a_modded_descriptor_is_refused(self):
        op = _op(ContainerOpKind.PUT, PISTOL, 1, AUTO_PISTOL, fp=FP_PLAIN)
        r = validate_container_op(_session(), op, None, 0.0)
        assert not r.ok and r.reason == RejectReason.INSTANCE_MISMATCH


class TestInstanceDefs:
    def test_a_valid_def_is_kept(self):
        s = ServerState()
        fp = instance_fp(PISTOL, AUTO_PISTOL)
        assert s.record_instance_def(PISTOL, fp, AUTO_PISTOL) is True
        assert s.instance_def(fp) == (PISTOL, AUTO_PISTOL)

    def test_a_def_whose_fingerprint_lies_is_refused(self):
        s = ServerState()
        assert s.record_instance_def(PISTOL, instance_fp(PISTOL, PLAIN_PISTOL), AUTO_PISTOL) is False
        assert s.instance_def(instance_fp(PISTOL, PLAIN_PISTOL)) is None


class TestServerHandlers:
    """The server's half on the wire: what a client receives."""

    @staticmethod
    def _frames_of(frames, mtype):
        return [f.payload for f, _ in frames if f.header.msg_type == int(mtype)]

    @pytest.mark.asyncio
    async def test_put_ack_and_bcast_carry_the_instance(self):
        port = 31580
        transport, protocol_obj = await _start_server_with_state(ServerState(), port)
        try:
            server_addr, sock_a, sock_b = await _two_raw_peers(port)
            try:
                op = _op(ContainerOpKind.PUT, PISTOL, 1, AUTO_PISTOL, op_id=0x10001)
                sock_a.sendto(encode_frame(MessageType.CONTAINER_OP, 1, op, reliable=True),
                              server_addr)
                frames_a, frames_b = await asyncio.gather(
                    _collect_frames(sock_a, 0.5), _collect_frames(sock_b, 0.5))
                acks = self._frames_of(frames_a, MessageType.CONTAINER_OP_ACK)
                assert len(acks) == 1
                assert acks[0].status == int(ContainerOpAckStatus.ACCEPTED)
                assert acks[0].item_fp == instance_fp(PISTOL, AUTO_PISTOL)
                assert acks[0].final_count == 1
                bcasts = self._frames_of(frames_b, MessageType.CONTAINER_BCAST)
                assert len(bcasts) == 1
                assert bcasts[0].item_fp == instance_fp(PISTOL, AUTO_PISTOL)
                assert bcasts[0].instance == AUTO_PISTOL
            finally:
                sock_a.close(); sock_b.close()
        finally:
            transport.close()

    @pytest.mark.asyncio
    async def test_a_lying_descriptor_is_refused_with_rej_instance(self):
        port = 31581
        transport, protocol_obj = await _start_server_with_state(ServerState(), port)
        try:
            server_addr, sock_a, sock_b = await _two_raw_peers(port)
            try:
                op = _op(ContainerOpKind.PUT, PISTOL, 1, AUTO_PISTOL,
                         fp=instance_fp(PISTOL, PLAIN_PISTOL), op_id=0x10002)
                sock_a.sendto(encode_frame(MessageType.CONTAINER_OP, 1, op, reliable=True),
                              server_addr)
                frames_a, frames_b = await asyncio.gather(
                    _collect_frames(sock_a, 0.5), _collect_frames(sock_b, 0.5))
                acks = self._frames_of(frames_a, MessageType.CONTAINER_OP_ACK)
                assert [a.status for a in acks] == [int(ContainerOpAckStatus.REJ_INSTANCE)]
                assert self._frames_of(frames_b, MessageType.CONTAINER_BCAST) == []
                assert protocol_obj.state.container_state(TRUNK_FID) is None
            finally:
                sock_a.close(); sock_b.close()
        finally:
            transport.close()

    @pytest.mark.asyncio
    async def test_a_seed_with_instances_reaches_the_others_with_its_descriptors(self):
        port = 31582
        transport, protocol_obj = await _start_server_with_state(ServerState(), port)
        try:
            server_addr, sock_a, sock_b = await _two_raw_peers(port)
            try:
                fp = instance_fp(PISTOL, AUTO_PISTOL)
                defs = InstanceDefsPayload(entries=(InstanceDefEntry(PISTOL, fp, AUTO_PISTOL),))
                seed = ContainerSeedPayload(entries=(
                    ContainerStateEntry(TRUNK_FID, TRUNK_BASE, TRUNK_CELL, PISTOL, 1, item_fp=fp),
                    ContainerStateEntry(TRUNK_FID, TRUNK_BASE, TRUNK_CELL, STIMPAK, 2),
                ))
                sock_a.sendto(encode_frame(MessageType.INSTANCE_DEFS, 1, defs, reliable=True),
                              server_addr)
                sock_a.sendto(encode_frame(MessageType.CONTAINER_SEED, 2, seed, reliable=True),
                              server_addr)
                frames_a, frames_b = await asyncio.gather(
                    _collect_frames(sock_a, 0.6), _collect_frames(sock_b, 0.6))
                assert protocol_obj.state.container_state(TRUNK_FID).items == {
                    (PISTOL, fp): 1, (STIMPAK, FP_PLAIN): 2}
                got_defs = [e for p in self._frames_of(frames_b, MessageType.INSTANCE_DEFS)
                            for e in p.entries]
                assert got_defs == [InstanceDefEntry(PISTOL, fp, AUTO_PISTOL)]
                lines = {(e.item_base_id, e.item_fp): e.count
                         for p in self._frames_of(frames_b, MessageType.CONTAINER_STATE)
                         for e in p.entries}
                assert lines == {(PISTOL, fp): 1, (STIMPAK, FP_PLAIN): 2}
            finally:
                sock_a.close(); sock_b.close()
        finally:
            transport.close()

    @pytest.mark.asyncio
    async def test_the_join_bootstrap_carries_the_descriptors(self):
        port = 31583
        state = ServerState()
        state.record_container_op(_op(ContainerOpKind.PUT, PISTOL, 1, PLAIN_PISTOL), "x", 0.0)
        state.container_state(TRUNK_FID).seeded = True
        transport, _ = await _start_server_with_state(state, port)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind(("127.0.0.1", 0))
            try:
                await _raw_peer_hello(sock, ("127.0.0.1", port), "peer_4b")
                frames = await _collect_frames(sock, 0.5)
                fp = instance_fp(PISTOL, PLAIN_PISTOL)
                got_defs = [e for p in self._frames_of(frames, MessageType.INSTANCE_DEFS)
                            for e in p.entries]
                assert got_defs == [InstanceDefEntry(PISTOL, fp, PLAIN_PISTOL)]
                lines = [(e.item_base_id, e.item_fp, e.count)
                         for p in self._frames_of(frames, MessageType.CONTAINER_STATE)
                         for e in p.entries]
                assert lines == [(PISTOL, fp, 1)]
            finally:
                sock.close()
        finally:
            transport.close()

    @pytest.mark.asyncio
    async def test_instance_defs_from_a_client_keep_only_the_true_ones(self):
        port = 31584
        transport, protocol_obj = await _start_server_with_state(ServerState(), port)
        try:
            server_addr, sock_a, sock_b = await _two_raw_peers(port)
            try:
                good = InstanceDefEntry(PISTOL, instance_fp(PISTOL, AUTO_PISTOL), AUTO_PISTOL)
                lying = InstanceDefEntry(PISTOL, instance_fp(PISTOL, PLAIN_PISTOL), AUTO_PISTOL)
                defs = InstanceDefsPayload(entries=(good, lying))
                sock_a.sendto(encode_frame(MessageType.INSTANCE_DEFS, 1, defs, reliable=True),
                              server_addr)
                await _collect_frames(sock_a, 0.3)
                st = protocol_obj.state
                assert st.instance_def(good.fp) == (PISTOL, AUTO_PISTOL)
                assert st.instance_def(lying.fp) is None
            finally:
                sock_a.close(); sock_b.close()
        finally:
            transport.close()


class TestSnapshot:
    def test_roundtrip_keeps_lines_and_their_descriptors(self, tmp_path: Path):
        s = ServerState()
        s.record_container_op(_op(ContainerOpKind.PUT, PISTOL, 1, AUTO_PISTOL), "alice", 0.0)
        s.record_container_op(_op(ContainerOpKind.PUT, STIMPAK, 3, None), "alice", 0.0)
        # A descriptor nothing references any more is not written.
        s.record_instance_def(PISTOL, instance_fp(PISTOL, PLAIN_PISTOL), PLAIN_PISTOL)
        path = tmp_path / "snap.json"
        snapshot(s, path)
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data["version"] == 15   # v15: partial-record ops, checkpoint world, world base per peer (2026-10-20)
        assert len(data["instances"]) == 1
        t = ServerState()
        load_into(t, path)
        assert t.container_state(TRUNK_FID).items == {
            (PISTOL, instance_fp(PISTOL, AUTO_PISTOL)): 1, (STIMPAK, FP_PLAIN): 3}
        assert t.instance_def(instance_fp(PISTOL, AUTO_PISTOL)) == (PISTOL, AUTO_PISTOL)

    def test_a_v10_record_becomes_unknown_lines(self, tmp_path: Path):
        s = ServerState()
        s.record_container_op(_op(ContainerOpKind.PUT, STIMPAK, 3, None), "alice", 0.0)
        path = tmp_path / "snap.json"
        snapshot(s, path)
        data = json.loads(path.read_text(encoding="utf-8"))
        # Rewrite as the v10 server wrote it: items keyed by the base alone.
        data["version"] = 10
        data.pop("instances", None)
        for c in data["containers"]:
            c["items"] = {"0x23736": 3}
        path.write_text(json.dumps(data), encoding="utf-8")
        t = ServerState()
        load_into(t, path)
        assert t.container_state(TRUNK_FID).items == {(STIMPAK, FP_UNKNOWN): 3}
