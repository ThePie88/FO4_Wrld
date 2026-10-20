"""Stage 1 of L5 (2026-09-27): the durable journal.

Until now the world lived in memory and touched the disk every 30 seconds,
so the ACK a client acted on could be forgotten by a crash a moment later:
the client had moved the items, the server had never heard of it. From this
stage every result that changes the world is appended to a journal, and no
reliable frame leaves the server before the record it depends on is on disk.
The snapshot is a compaction of the journal, not the truth.

Each test here failed on the code before the journal existed (the module
did not exist), and pins one property:

- a journal replayed over an empty state gives the same world;
- a torn tail (a crash mid-write) is dropped and writing continues, while a
  corrupt record with data after it refuses to open;
- an ACK and every other reliable frame wait for the durable LSN, in order;
- a broken journal makes item ops unavailable instead of silently accepted;
- the snapshot carries the LSN it covers and a boot replays only after it;
- the epoch bumps when the journal is found shorter than what was acked;
- resume tokens are stored hashed, and old clear-text snapshots still load;
- quests and globals survive the snapshot (they never did).
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import socket
import struct
import sys
import zlib
from dataclasses import fields
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from protocol import (  # noqa: E402
    MessageType, ActorEventPayload, ContainerOpAckPayload, ContainerOpAckStatus,
    EquipModRecord, encode_frame, decode_frame, HeartbeatPayload,
    FLAG_RELIABLE,
)
from server.journal import Journal, JournalCorrupt  # noqa: E402
from server.state import ServerState, OutfitEntry  # noqa: E402
from server.persistence import (  # noqa: E402
    snapshot, load_into, SNAPSHOT_FORMAT_VERSION,
)
from server.main import ServerProtocol  # noqa: E402
from net.tests.test_container import (  # noqa: E402
    TRUNK_BASE, TRUNK_CELL, TRUNK_FID, TWIN_FID, STIMPAK, _put, _take,
    _start_server_with_state, _collect_frames, _raw_peer_hello,
)


def _ack(count: int) -> ContainerOpAckPayload:
    kw = {f.name: 1 for f in fields(ContainerOpAckPayload)}
    kw["final_count"] = count
    return ContainerOpAckPayload(**kw)


def _mutate_everything(state: ServerState, now: float = 1_000.0) -> dict:
    """Every journaled mutation once. Returns what the caller compares."""
    state.create_container(TRUNK_FID, TRUNK_BASE, TRUNK_CELL, {STIMPAK: 5}, "alice", now)
    state.create_container(TWIN_FID, TRUNK_BASE, TRUNK_CELL, {STIMPAK: 1}, "alice", now)
    state.record_container_op(_put(TRUNK_FID, STIMPAK, 3), "alice", now)
    state.record_container_op(_take(TRUNK_FID, STIMPAK, 2, op_id=7), "bob", now)
    state.remember_container_verdict("bob", 7, _ack(6))
    state.reseed_container(TWIN_FID, {STIMPAK: 9, 0x77: 2}, "carol", now)
    state.forget_container(TWIN_FID)
    state.record_quest_stage(0x1A2B, 20, "alice", now)
    state.record_global_var(0x3C4D, 2.5, "alice", now)
    state.record_appearance("alice", "recipe-line")
    state.record_lock(0xB1, 0xC1, 0xF1, True, 123)
    first = state.record_world_spawn(
        spawner_peer="alice", base_form_id=0x2079E, spawner_local_fid=0xFF000001,
        px=1.0, py=2.0, pz=3.0, rx=0.0, ry=0.0, rz=0.0, cell_id=0xC1, flags=0,
        timestamp_ms=5)
    state.record_world_spawn(   # transient: consumes a wid, never stored
        spawner_peer="alice", base_form_id=0x1234, spawner_local_fid=0xFF000002,
        px=0.0, py=0.0, pz=0.0, rx=0.0, ry=0.0, rz=0.0, cell_id=0xC1, flags=1,
        timestamp_ms=6)
    frame = state.record_world_spawn(
        spawner_peer="bob", base_form_id=0x2079E, spawner_local_fid=0xFF000003,
        px=4.0, py=5.0, pz=6.0, rx=0.0, ry=0.0, rz=0.0, cell_id=0xC2, flags=0,
        timestamp_ms=7)
    state.set_world_spawn_pieces(frame.wid, ((0xAA, 1, (0xBB,), 100.0),))
    state.mark_world_spawn_worn(frame.wid, "bob", now)
    state.remove_world_spawn(first.wid)
    state.record_presence_name("alice", "Alice", now)
    state.record_presence_equip(
        "alice",
        OutfitEntry(item_form_id=0x10, slot_form_id=0x20, count=1,
                    effective_priority=3,
                    mods=(EquipModRecord(form_id=0x99, attach_index=0, rank=1, flag=0),),
                    timestamp_ms=9),
        True, now)
    state.record_presence_equip(
        "alice",
        OutfitEntry(item_form_id=0x11, slot_form_id=0x21, count=1,
                    effective_priority=1, timestamp_ms=9),
        True, now)
    state.drop_items_from_outfit("alice", [0x11])
    state.record_presence_worn_frame("alice", frame.wid, now)
    state.record_actor_event(
        ActorEventPayload(kind=2, form_id=0x5, actor_base_id=0x6, x=0.0, y=0.0,
                          z=0.0, extra=0, cell_id=0x7), "alice", now)
    return _world_view(state)


def _world_view(state: ServerState) -> dict:
    return {
        "containers": {c.form_id: (dict(c.items), c.seeded, c.last_owner_peer_id)
                       for c in state.all_containers()},
        "verdict": state.recall_container_verdict("bob", 7),
        "quests": {q.quest_form_id: q.stage for q in state.all_quest_stages()},
        "globals": {g.global_form_id: g.value for g in state.all_globals()},
        "appearances": dict(state.all_appearances()),
        "locks": {k: (v.form_id, v.locked, v.timestamp_ms)
                  for k, v in state.lock_state.items()},
        "spawns": {w.wid: (w.spawner_peer, w.base_form_id, w.pieces, w.worn_by_peer_id)
                   for w in state.all_world_spawns()},
        "next_wid": state.next_world_spawn_wid,
        "presence": {p.peer_id: (p.display_name, sorted(p.outfit), p.worn_frame_wid)
                     for p in state.all_presence()},
        "outfit_mods": tuple(
            state.presence("alice").outfit[0x10].mods) if state.presence("alice") else None,
        "actors": {(a.base_id, a.cell_id): a.alive for a in state.all_actors()},
    }


class FakeTransport:
    def __init__(self) -> None:
        self.sent: list[tuple[bytes, tuple[str, int]]] = []

    def sendto(self, raw: bytes, addr) -> None:
        self.sent.append((raw, addr))


# --------------------------------------------------------------- replay

class TestReplay:
    def test_replayed_journal_gives_the_same_world(self, tmp_path: Path):
        j = Journal.open(tmp_path / "journal")
        a = ServerState()
        a.journal = j
        before = _mutate_everything(a)
        assert j.head_lsn > 0
        j.flush()
        assert j.durable_lsn == j.head_lsn
        j.close()

        b = ServerState()
        j2 = Journal.open(tmp_path / "journal")
        n = j2.replay(b, after_lsn=0)
        assert n == j.head_lsn
        assert _world_view(b) == before
        assert b.applied_lsn == j.head_lsn
        assert j2.head_lsn == j.head_lsn
        j2.close()

    def test_replay_does_not_write_the_records_again(self, tmp_path: Path):
        j = Journal.open(tmp_path / "journal")
        a = ServerState()
        a.journal = j
        _mutate_everything(a)
        j.flush()
        head = j.head_lsn
        j.close()

        b = ServerState()
        j2 = Journal.open(tmp_path / "journal")
        b.journal = j2
        j2.replay(b, after_lsn=0)
        j2.flush()
        assert j2.head_lsn == head
        j2.close()

    def test_transient_spawns_keep_the_wid_counter_in_step(self, tmp_path: Path):
        j = Journal.open(tmp_path / "journal")
        a = ServerState()
        a.journal = j
        a.record_world_spawn(spawner_peer="a", base_form_id=1, spawner_local_fid=2,
                             px=0, py=0, pz=0, rx=0, ry=0, rz=0, cell_id=1,
                             flags=1, timestamp_ms=0)
        kept = a.record_world_spawn(spawner_peer="a", base_form_id=1, spawner_local_fid=3,
                                    px=0, py=0, pz=0, rx=0, ry=0, rz=0, cell_id=1,
                                    flags=0, timestamp_ms=0)
        assert kept.wid == 2
        j.flush()
        j.close()
        b = ServerState()
        Journal.open(tmp_path / "journal").replay(b, after_lsn=0)
        assert list(b.world_spawns) == [2]
        assert b.next_world_spawn_wid == 3


# --------------------------------------------------------------- file format

def _segments(directory: Path) -> list[Path]:
    return sorted(directory.glob("seg-*.jnl"))


class TestFileFormat:
    def test_records_are_length_and_crc_framed(self, tmp_path: Path):
        j = Journal.open(tmp_path / "journal")
        s = ServerState()
        s.journal = j
        s.record_quest_stage(1, 2, "a", 0.0)
        j.flush()
        j.close()
        (seg,) = _segments(tmp_path / "journal")
        raw = seg.read_bytes()
        length, crc = struct.unpack_from("<II", raw, 0)
        payload = raw[8:8 + length]
        assert zlib.crc32(payload) & 0xFFFFFFFF == crc
        rec = json.loads(payload)
        assert rec["lsn"] == 1 and rec["op"] == "record_quest_stage"
        assert rec["args"]["quest_form_id"] == 1

    def test_torn_tail_is_dropped_and_writing_continues(self, tmp_path: Path):
        j = Journal.open(tmp_path / "journal")
        s = ServerState()
        s.journal = j
        for stage in (1, 2, 3):
            s.record_quest_stage(0x10, stage, "a", 0.0)
        j.flush()
        j.close()
        (seg,) = _segments(tmp_path / "journal")
        raw = seg.read_bytes()
        seg.write_bytes(raw[:-5])          # the last record lost its tail

        j2 = Journal.open(tmp_path / "journal")
        b = ServerState()
        assert j2.replay(b, after_lsn=0) == 2
        assert b.quest_stage(0x10).stage == 2
        assert j2.head_lsn == 2
        b.journal = j2
        b.record_quest_stage(0x10, 4, "a", 0.0)   # lsn 3 again, on a clean tail
        j2.flush()
        j2.close()

        c = ServerState()
        j3 = Journal.open(tmp_path / "journal")
        assert j3.replay(c, after_lsn=0) == 3
        assert c.quest_stage(0x10).stage == 4
        j3.close()

    def test_corrupt_record_with_data_after_it_refuses_to_open(self, tmp_path: Path):
        j = Journal.open(tmp_path / "journal")
        s = ServerState()
        s.journal = j
        for stage in (1, 2, 3):
            s.record_quest_stage(0x10, stage, "a", 0.0)
        j.flush()
        j.close()
        (seg,) = _segments(tmp_path / "journal")
        raw = bytearray(seg.read_bytes())
        raw[12] ^= 0xFF                    # inside the first record's payload
        seg.write_bytes(bytes(raw))
        with pytest.raises(JournalCorrupt):
            Journal.open(tmp_path / "journal")

    def test_segments_roll_and_compaction_keeps_the_active_one(self, tmp_path: Path):
        j = Journal.open(tmp_path / "journal", segment_bytes=400)
        s = ServerState()
        s.journal = j
        for stage in range(1, 30):
            s.record_quest_stage(0x10, stage, "a", 0.0)
        j.flush()
        assert len(_segments(tmp_path / "journal")) >= 3
        removed = j.compact(up_to_lsn=j.durable_lsn)
        assert removed >= 2
        assert len(_segments(tmp_path / "journal")) == 1
        j.close()
        # Everything the remaining segment holds is at or after the cut, and
        # a boot from a snapshot at the head replays nothing.
        b = ServerState()
        j2 = Journal.open(tmp_path / "journal")
        assert j2.replay(b, after_lsn=29) == 0
        assert j2.head_lsn == 29
        j2.close()


# --------------------------------------------------------------- epoch

class TestEpoch:
    def test_epoch_bumps_when_the_journal_is_shorter_than_what_was_acked(self, tmp_path: Path):
        d = tmp_path / "journal"
        d.mkdir()
        (d / "epoch.json").write_text(json.dumps({"epoch": 3, "hwm_lsn": 10}))
        j = Journal.open(d)
        assert j.epoch == 4
        assert j.head_lsn == 0
        j.close()
        assert json.loads((d / "epoch.json").read_text())["epoch"] == 4

    def test_epoch_holds_when_nothing_was_lost(self, tmp_path: Path):
        d = tmp_path / "journal"
        j = Journal.open(d)
        s = ServerState()
        s.journal = j
        s.record_quest_stage(1, 1, "a", 0.0)
        j.flush()
        j.close()
        assert json.loads((d / "epoch.json").read_text()) == {"epoch": 1, "hwm_lsn": 1}
        j2 = Journal.open(d)
        assert j2.epoch == 1
        j2.close()


# --------------------------------------------------------------- the gate

def _accept(state: ServerState, peer: str, port: int):
    session, reason = state.accept_peer(("127.0.0.1", port), peer, (1, 0), 0.0)
    assert session is not None, reason
    return session


class TestDurabilityGate:
    def test_ack_and_broadcast_wait_for_the_durable_lsn(self, tmp_path: Path):
        state = ServerState()
        j = Journal.open(tmp_path / "journal")
        state.journal = j
        proto = ServerProtocol(state)
        fake = FakeTransport()
        proto.transport = fake
        j.set_notify(proto.on_durable, proto.on_journal_failure)
        alice = _accept(state, "alice", 1)
        bob = _accept(state, "bob", 2)
        state.create_container(TRUNK_FID, TRUNK_BASE, TRUNK_CELL, {STIMPAK: 5}, "seed", 0.0)
        j.flush()
        fake.sent.clear()

        op = _take(TRUNK_FID, STIMPAK, 2, op_id=41)
        proto._handle_container_op(alice, op, 10.0)
        # The verdict and the broadcast exist but nothing left the socket.
        assert state.recall_container_verdict("alice", 41) is not None
        assert fake.sent == []
        assert j.head_lsn > j.durable_lsn

        j.flush()   # the writer's fsync, then the notify
        kinds = [(decode_frame(raw).header.msg_type, addr[1]) for raw, addr in fake.sent]
        assert (int(MessageType.CONTAINER_OP_ACK), 1) in kinds
        assert (int(MessageType.CONTAINER_BCAST), 2) in kinds
        assert bob is not None
        j.close()

    def test_reliable_frames_keep_their_order_and_unreliable_ones_pass(self, tmp_path: Path):
        state = ServerState()
        j = Journal.open(tmp_path / "journal")
        state.journal = j
        proto = ServerProtocol(state)
        fake = FakeTransport()
        proto.transport = fake
        j.set_notify(proto.on_durable, proto.on_journal_failure)
        alice = _accept(state, "alice", 1)
        state.record_quest_stage(1, 1, "alice", 0.0)     # head 1, durable 0
        first = alice.channel.send_reliable(MessageType.QUEST_STAGE_BCAST,
                                            HeartbeatPayload(0), 0.0)
        proto._send(alice.addr, first)
        beat = encode_frame(MessageType.HEARTBEAT, 0, HeartbeatPayload(0), reliable=False)
        proto._send(alice.addr, beat)
        second = alice.channel.send_reliable(MessageType.QUEST_STAGE_BCAST,
                                             HeartbeatPayload(0), 0.0)
        proto._send(alice.addr, second)
        assert [raw for raw, _ in fake.sent] == [beat]
        j.flush()
        assert [raw for raw, _ in fake.sent] == [beat, first, second]
        j.close()

    def test_a_broken_journal_makes_item_ops_unavailable(self, tmp_path: Path):
        state = ServerState()
        j = Journal.open(tmp_path / "journal")
        state.journal = j
        proto = ServerProtocol(state)
        fake = FakeTransport()
        proto.transport = fake
        j.set_notify(proto.on_durable, proto.on_journal_failure)
        alice = _accept(state, "alice", 1)
        state.create_container(TRUNK_FID, TRUNK_BASE, TRUNK_CELL, {STIMPAK: 5}, "seed", 0.0)
        held = alice.channel.send_reliable(MessageType.QUEST_STAGE_BCAST,
                                           HeartbeatPayload(0), 0.0)
        proto._send(alice.addr, held)
        assert fake.sent == []

        j.mark_failed("disk full")
        # What was held goes out: the state it describes exists in memory
        # and nothing can take it back. From here on the server is read-only
        # for item ops.
        assert [raw for raw, _ in fake.sent] == [held]
        proto._handle_container_op(alice, _take(TRUNK_FID, STIMPAK, 1, op_id=5), 1.0)
        acks = [decode_frame(raw).payload for raw, _ in fake.sent[1:]
                if decode_frame(raw).header.msg_type == int(MessageType.CONTAINER_OP_ACK)]
        assert len(acks) == 1
        assert acks[0].status == int(ContainerOpAckStatus.REJ_UNAVAILABLE)
        assert state.container_state(TRUNK_FID).items[(STIMPAK, 0)] == 5
        assert state.recall_container_verdict("alice", 5) is None
        j.close()

    @pytest.mark.asyncio
    async def test_the_writer_thread_makes_acks_flow_end_to_end(self, tmp_path: Path):
        port = 31562
        state = ServerState()
        j = Journal.open(tmp_path / "journal")
        state.journal = j
        state.create_container(TRUNK_FID, TRUNK_BASE, TRUNK_CELL, {STIMPAK: 5}, "seed", 0.0)
        transport, proto = await _start_server_with_state(state, port)
        loop = asyncio.get_running_loop()
        j.set_notify(lambda lsn: loop.call_soon_threadsafe(proto.on_durable, lsn),
                     lambda err: loop.call_soon_threadsafe(proto.on_journal_failure, err))
        j.start_writer()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 0))
        try:
            await _raw_peer_hello(sock, ("127.0.0.1", port), "alice")
            op = _take(TRUNK_FID, STIMPAK, 2, op_id=9)
            sock.sendto(encode_frame(MessageType.CONTAINER_OP, 5, op, reliable=True),
                        ("127.0.0.1", port))
            frames = await _collect_frames(sock, 1.0)
            acks = [f.payload for f, _ in frames
                    if f.header.msg_type == int(MessageType.CONTAINER_OP_ACK)]
            assert acks and acks[0].status == int(ContainerOpAckStatus.ACCEPTED)
            assert j.durable_lsn >= j.head_lsn > 0
        finally:
            sock.close()
            transport.close()
            j.close()


# --------------------------------------------------------------- snapshot

class TestSnapshotAndJournal:
    def test_snapshot_carries_the_lsn_and_boot_replays_only_after_it(self, tmp_path: Path):
        d = tmp_path / "journal"
        snap = tmp_path / "snap.json"
        j = Journal.open(d)
        a = ServerState()
        a.journal = j
        a.create_container(TRUNK_FID, TRUNK_BASE, TRUNK_CELL, {STIMPAK: 5}, "seed", 0.0)
        a.record_container_op(_put(TRUNK_FID, STIMPAK, 3), "alice", 1.0)
        j.flush()
        snapshot(a, snap)
        a.record_container_op(_put(TRUNK_FID, STIMPAK, 4), "alice", 2.0)
        j.flush()
        j.close()
        data = json.loads(snap.read_text())
        assert data["version"] == SNAPSHOT_FORMAT_VERSION
        assert data["journal"] == {"lsn": 2, "epoch": 1}

        b = ServerState()
        load_into(b, snap)
        assert b.applied_lsn == 2
        j2 = Journal.open(d)
        assert j2.replay(b, after_lsn=b.applied_lsn) == 1
        assert b.container_state(TRUNK_FID).items[(STIMPAK, 0)] == 12
        j2.close()

    def test_quests_and_globals_survive_the_snapshot(self, tmp_path: Path):
        a = ServerState()
        a.record_quest_stage(0x1A2B, 20, "alice", 5.0)
        a.record_global_var(0x3C4D, 2.5, "bob", 6.0)
        snap = tmp_path / "snap.json"
        snapshot(a, snap)
        b = ServerState()
        load_into(b, snap)
        assert b.quest_stage(0x1A2B).stage == 20
        assert b.quest_stage(0x1A2B).last_owner_peer_id == "alice"
        assert b.global_var(0x3C4D).value == 2.5

    def test_resume_tokens_are_stored_hashed(self, tmp_path: Path):
        a = ServerState()
        session = _accept(a, "alice", 1)
        token = a.issue_resume_token(session, 1_000.0)
        snap = tmp_path / "snap.json"
        snapshot(a, snap)
        text = snap.read_text()
        assert token.hex() not in text
        assert hashlib.sha256(token).hexdigest() in text
        b = ServerState()
        load_into(b, snap)
        ticket, reason = b.consume_resume_token(token, 2_000.0)
        assert reason == "ok" and ticket.peer_id == "alice"

    def test_a_clear_text_token_from_an_old_snapshot_still_works(self, tmp_path: Path):
        token = bytes(range(32))
        snap = tmp_path / "snap.json"
        snap.write_text(json.dumps({
            "version": 6, "world_actors": [], "containers": [],
            "resume_tokens": [{
                "token": token.hex(), "peer_id": "alice", "identity_hex": "",
                "issued_at_ms": 1_000.0, "expires_at_ms": 100_000.0,
            }],
        }))
        b = ServerState()
        load_into(b, snap)
        ticket, reason = b.consume_resume_token(token, 2_000.0)
        assert reason == "ok" and ticket.peer_id == "alice"

    def test_token_journal_records_carry_the_hash_not_the_token(self, tmp_path: Path):
        d = tmp_path / "journal"
        j = Journal.open(d)
        a = ServerState()
        a.journal = j
        session = _accept(a, "alice", 1)
        token = a.issue_resume_token(session, 1_000.0)
        j.flush()
        j.close()
        raw = b"".join(p.read_bytes() for p in _segments(d))
        assert token.hex().encode() not in raw
        assert hashlib.sha256(token).hexdigest().encode() in raw
        b = ServerState()
        Journal.open(d).replay(b, after_lsn=0)
        ticket, reason = b.consume_resume_token(token, 2_000.0)
        assert reason == "ok"
