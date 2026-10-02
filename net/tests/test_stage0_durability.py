"""Stage 0 of L5 (2026-09-27): the live server bugs found by the L5
investigation, each pinned by a test that failed on the old code.

- A failed payload encode consumed a reliable sequence number, leaving a hole
  the receiver could never fill (retransmits, then a kick).
- A container count could grow past the i32 the wire packs: the ACK and the
  CONTAINER_STATE encoder raised inside the join bootstrap, so every later
  bootstrap stage was lost for every joiner, and the value was persisted.
- The snapshot was written without fsync, an unreadable snapshot started an
  empty world that overwrote every good copy within a few rotations, and the
  first write of a run never rotated the previous run's file.
- Persisted times used the monotonic clock, meaningless across restarts:
  a resume token from a previous boot could come back valid.
- Server configuration (tick rate, peer timeout) was restored from the world
  file, so a tuning knob could not be turned.
- An anonymous HELLO could claim the client id of an authenticated player.
- Item ops shared the position rate bucket, so a burst of position updates
  starved a Take All.
- One failing bootstrap stage aborted every stage after it.
"""
from __future__ import annotations

import asyncio
import json
import os
import socket
import struct
import sys
import time
from dataclasses import fields
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from protocol import (  # noqa: E402
    MessageType, HelloPayload, WelcomePayload, ContainerOpAckPayload,
    ContainerStatePayload, ContainerOpKind, ContainerOpPayload,
    encode_frame, decode_frame,
)
from channel import ReliableChannel  # noqa: E402
from server.state import ServerState, RESUME_TOKEN_TTL_S  # noqa: E402
from server.validator import validate_container_op, RejectReason  # noqa: E402
from server import persistence  # noqa: E402
from server.persistence import (  # noqa: E402
    snapshot, load_into, restore_state, SnapshotUnreadable, COUNT_MAX,
    SNAPSHOT_FORMAT_VERSION,
)
from server.main import ServerProtocol, _periodic_snapshot, _now_ms  # noqa: E402
from net.tests.test_container import (  # noqa: E402
    TRUNK_BASE, TRUNK_CELL, TRUNK_FID, STIMPAK,
    _put, _session, _seeded, _start_server_with_state, _collect_frames,
)


def _ack_with_count(count: int) -> ContainerOpAckPayload:
    kw = {f.name: 1 for f in fields(ContainerOpAckPayload)}
    kw["final_count"] = count
    return ContainerOpAckPayload(**kw)


# ---------------------------------------------------------------- channel

class TestReliableChannel:
    def test_failed_encode_does_not_consume_a_sequence(self):
        ch = ReliableChannel()
        before = ch.send.next_seq
        with pytest.raises(struct.error):
            ch.send_reliable(MessageType.CONTAINER_OP_ACK, _ack_with_count(2 ** 31), 0.0)
        assert ch.send.next_seq == before
        assert len(ch.send.in_flight) == 0
        raw = ch.send_reliable(MessageType.CONTAINER_OP_ACK, _ack_with_count(1), 0.0)
        assert decode_frame(raw).header.seq == before


# ---------------------------------------------------------------- counts

class TestCountBounds:
    def test_put_beyond_i32_is_refused_and_the_record_stays_packable(self):
        s = ServerState()
        _seeded(s, TRUNK_FID, {STIMPAK: 2_000_000_000})
        op = _put(TRUNK_FID, STIMPAK, 2_000_000_000)
        r = validate_container_op(_session(), op, s.container_state_for_op(op), 0.0)
        assert not r.ok and r.reason == RejectReason.COUNT_OVERFLOW
        assert s.record_container_op(op, "alice", 1.0) is None
        assert s.container_state(TRUNK_FID).items[STIMPAK] == 2_000_000_000
        entries = ServerProtocol._container_state_entries([s.container_state(TRUNK_FID)])
        ContainerStatePayload(entries=tuple(entries)).encode()

    def test_put_up_to_the_bound_is_accepted(self):
        s = ServerState()
        _seeded(s, TRUNK_FID, {STIMPAK: COUNT_MAX - 1})
        op = _put(TRUNK_FID, STIMPAK, 1)
        r = validate_container_op(_session(), op, s.container_state_for_op(op), 0.0)
        assert r.ok
        assert s.record_container_op(op, "alice", 1.0) is not None
        assert s.container_state(TRUNK_FID).items[STIMPAK] == COUNT_MAX

    def test_loader_clamps_counts_above_i32(self, tmp_path: Path):
        path = tmp_path / "big.json"
        path.write_text(json.dumps({
            "version": SNAPSHOT_FORMAT_VERSION, "timestamp_ms": 0,
            "server": {"tick_rate_hz": 20, "server_version": [1, 0]},
            "sessions": [], "world_actors": [],
            "containers": [{
                "form_id": f"0x{TRUNK_FID:X}", "base_id": f"0x{TRUNK_BASE:X}",
                "cell_id": f"0x{TRUNK_CELL:X}",
                "items": {f"0x{STIMPAK:X}": 4_000_000_000},
                "seeded": True, "last_owner": "alice", "last_update_ms": 0.0,
            }],
        }), encoding="utf-8")
        s = ServerState()
        load_into(s, path)
        assert s.container_state(TRUNK_FID).items[STIMPAK] == COUNT_MAX

    @pytest.mark.asyncio
    async def test_overflowing_put_is_answered_with_rej_count(self):
        port = 31560
        state = ServerState()
        _seeded(state, TRUNK_FID, {STIMPAK: 2_000_000_000}, by="first")
        transport, protocol_obj = await _start_server_with_state(state, port)
        try:
            server_addr = ("127.0.0.1", port)
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind(("127.0.0.1", 0))
            try:
                from net.tests.test_container import _raw_peer_hello
                await _raw_peer_hello(sock, server_addr, f"pA_{port}")
                await _collect_frames(sock, 0.3)
                op = ContainerOpPayload(
                    kind=int(ContainerOpKind.PUT), container_form_id=TRUNK_FID,
                    container_base_id=TRUNK_BASE, container_cell_id=TRUNK_CELL,
                    item_base_id=STIMPAK, count=2_000_000_000, timestamp_ms=0,
                    client_op_id=7)
                sock.sendto(encode_frame(MessageType.CONTAINER_OP, 1, op, reliable=True), server_addr)
                frames = await _collect_frames(sock, 0.6)
                acks = [f.payload for f, _ in frames
                        if f.header.msg_type == int(MessageType.CONTAINER_OP_ACK)]
                assert acks, "no ACK for the overflowing PUT"
                assert acks[0].status == 3  # REJ_COUNT
                assert protocol_obj.state.container_state(TRUNK_FID).items[STIMPAK] == 2_000_000_000
            finally:
                sock.close()
        finally:
            transport.close()


# ---------------------------------------------------------------- snapshot durability

class TestSnapshotDurability:
    def test_snapshot_fsyncs_before_replace(self, tmp_path: Path, monkeypatch):
        calls: list[str] = []
        real_fsync, real_replace = os.fsync, os.replace
        monkeypatch.setattr(persistence.os, "fsync", lambda fd: (calls.append("fsync"), real_fsync(fd)))
        monkeypatch.setattr(persistence.os, "replace", lambda a, b: (calls.append("replace"), real_replace(a, b)))
        snapshot(ServerState(), tmp_path / "snap.json")
        assert "fsync" in calls and "replace" in calls
        assert calls.index("fsync") < calls.index("replace")

    def test_snapshot_failure_leaves_the_previous_file_intact(self, tmp_path: Path, monkeypatch):
        path = tmp_path / "snap.json"
        s = ServerState()
        _seeded(s, TRUNK_FID, {STIMPAK: 3})
        snapshot(s, path)
        good = path.read_bytes()

        def boom(*a, **k):
            raise OSError("disk full")
        monkeypatch.setattr(persistence.json, "dump", boom)
        with pytest.raises(OSError):
            snapshot(ServerState(), path)
        assert path.read_bytes() == good
        assert list(tmp_path.glob(".snap.json*.tmp")) == []

    def test_restore_falls_back_to_a_rotated_copy_when_the_main_file_is_unreadable(self, tmp_path: Path):
        path = tmp_path / "snap.json"
        s = ServerState()
        _seeded(s, TRUNK_FID, {STIMPAK: 3})
        snapshot(s, path.with_name("snap.json.1"))
        path.write_text("{ this is not json", encoding="utf-8")
        dst = ServerState()
        loaded = restore_state(dst, path)
        assert loaded == path.with_name("snap.json.1")
        assert dst.container_state(TRUNK_FID).items == {STIMPAK: 3}
        # The unreadable file is kept for inspection under another name and
        # no longer sits where the next write would rotate it over the good copy.
        assert not path.exists()
        assert list(tmp_path.glob("snap.json.corrupt*"))

    def test_restore_refuses_to_start_when_every_copy_is_unreadable(self, tmp_path: Path):
        path = tmp_path / "snap.json"
        path.write_text("garbage", encoding="utf-8")
        path.with_name("snap.json.1").write_text("garbage too", encoding="utf-8")
        with pytest.raises(SnapshotUnreadable):
            restore_state(ServerState(), path)
        assert restore_state(ServerState(), path, allow_empty_world=True) is None

    def test_restore_starts_empty_when_no_snapshot_exists(self, tmp_path: Path):
        assert restore_state(ServerState(), tmp_path / "none.json") is None

    def test_restore_keeps_a_copy_of_the_file_it_loaded(self, tmp_path: Path):
        path = tmp_path / "snap.json"
        s = ServerState()
        _seeded(s, TRUNK_FID, {STIMPAK: 3})
        snapshot(s, path)
        assert restore_state(ServerState(), path) == path
        kept = path.with_name("snap.json.lastgood")
        assert kept.exists() and kept.read_bytes() == path.read_bytes()

    @pytest.mark.asyncio
    async def test_periodic_snapshot_rotates_the_previous_run_file_on_the_first_write(self, tmp_path: Path):
        path = tmp_path / "snap.json"
        path.write_text('{"version": 0, "from": "previous run"}', encoding="utf-8")
        old = path.read_bytes()
        protocol = ServerProtocol(ServerState())
        task = asyncio.create_task(_periodic_snapshot(protocol, path, interval_s=0.05, rotate_keep=3))
        await asyncio.sleep(0.12)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        # One or two ticks ran; the previous run's file must sit in the
        # rotation, not have been overwritten.
        rotated = [path.with_name(f"snap.json.{n}") for n in (1, 2, 3)]
        assert old in [p.read_bytes() for p in rotated if p.exists()]
        assert path.read_bytes() != old


# ---------------------------------------------------------------- clocks

class TestClocks:
    def test_server_clock_is_wall_clock_anchored_and_never_steps_back(self):
        a = _now_ms()
        assert abs(a - time.time() * 1000.0) < 5_000.0
        b = _now_ms()
        assert b >= a

    def test_resume_token_from_a_monotonic_era_snapshot_is_expired(self, tmp_path: Path):
        path = tmp_path / "tok.json"
        old_uptime_ms = 90_000_000.0
        path.write_text(json.dumps({
            "version": SNAPSHOT_FORMAT_VERSION, "timestamp_ms": 0,
            "server": {"tick_rate_hz": 20, "server_version": [1, 0]},
            "sessions": [], "world_actors": [], "containers": [],
            "resume_tokens": [{
                "token": "ab" * 16, "peer_id": "fw0000000000001", "identity_hex": "",
                "issued_at_ms": old_uptime_ms,
                "expires_at_ms": old_uptime_ms + 30 * 24 * 3600 * 1000.0,
            }],
        }), encoding="utf-8")
        s = ServerState()
        load_into(s, path)
        ticket, reason = s.consume_resume_token(bytes.fromhex("ab" * 16), _now_ms())
        assert ticket is None and reason == "resume_expired"

    def test_resume_token_issued_now_survives_a_reload(self, tmp_path: Path):
        path = tmp_path / "tok.json"
        now = _now_ms()
        path.write_text(json.dumps({
            "version": SNAPSHOT_FORMAT_VERSION, "timestamp_ms": 0,
            "server": {"tick_rate_hz": 20, "server_version": [1, 0]},
            "sessions": [], "world_actors": [], "containers": [],
            "resume_tokens": [{
                "token": "cd" * 16, "peer_id": "fw0000000000002", "identity_hex": "",
                "issued_at_ms": now, "expires_at_ms": now + RESUME_TOKEN_TTL_S * 1000.0,
            }],
        }), encoding="utf-8")
        s = ServerState()
        load_into(s, path)
        ticket, reason = s.consume_resume_token(bytes.fromhex("cd" * 16), now + 60_000.0)
        assert reason == "ok" and ticket is not None


# ---------------------------------------------------------------- configuration

class TestConfigIsNotState:
    def test_config_is_not_restored_from_the_snapshot(self, tmp_path: Path):
        src = ServerState(tick_rate_hz=42, peer_timeout_ms=7_777.0)
        path = tmp_path / "snap.json"
        snapshot(src, path)
        dst = ServerState()
        load_into(dst, path)
        assert dst.tick_rate_hz == ServerState().tick_rate_hz
        assert dst.peer_timeout_ms == ServerState().peer_timeout_ms


# ---------------------------------------------------------------- identity

@pytest.mark.asyncio
async def test_anonymous_hello_cannot_claim_an_authenticated_client_id():
    port = 31561
    transport, protocol_obj = await _start_server_with_state(ServerState(), port)
    try:
        server_addr = ("127.0.0.1", port)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 0))
        sock.setblocking(False)
        try:
            hello = HelloPayload(client_id="fw" + "a" * 13, client_version_major=1,
                                 client_version_minor=0)
            sock.sendto(encode_frame(MessageType.HELLO, 0, hello, reliable=True), server_addr)
            frames = await _collect_frames(sock, 0.6)
            welcomes = [f.payload for f, _ in frames
                        if f.header.msg_type == int(MessageType.WELCOME)]
            assert welcomes and isinstance(welcomes[0], WelcomePayload)
            assert welcomes[0].accepted is False
            assert protocol_obj.state.get_by_peer_id("fw" + "a" * 13) is None
        finally:
            sock.close()
    finally:
        transport.close()


# ---------------------------------------------------------------- rate buckets

class TestItemRateBucket:
    def test_a_position_burst_does_not_starve_a_take_all(self):
        s = ServerState()
        _seeded(s, TRUNK_FID, {STIMPAK: 5})
        sess = _session()
        while sess.rate.consume(0.0):
            pass
        op = _put(TRUNK_FID, STIMPAK, 1)
        r = validate_container_op(sess, op, s.container_state_for_op(op), 0.0)
        assert r.ok

    def test_item_ops_are_still_rate_limited_on_their_own_bucket(self):
        s = ServerState()
        _seeded(s, TRUNK_FID, {STIMPAK: 5})
        sess = _session()
        op = _put(TRUNK_FID, STIMPAK, 1)
        verdicts = [validate_container_op(sess, op, s.container_state_for_op(op), 0.0)
                    for _ in range(200)]
        assert any(not v.ok and v.reason == RejectReason.RATE_LIMITED for v in verdicts)
        assert sum(v.ok for v in verdicts) >= 30


# ---------------------------------------------------------------- bootstrap

def test_join_bootstrap_survives_one_failing_stage(monkeypatch):
    state = ServerState()
    protocol = ServerProtocol(state)
    sess, reason = state.accept_peer(("127.0.0.1", 40000), "bootstrap_a", (1, 0), 0.0)
    assert sess is not None, reason
    ran: list[str] = []

    def boom(session, now_ms):
        raise struct.error("simulated overflow in the container stage")
    monkeypatch.setattr(protocol, "_send_container_state_bootstrap", boom)
    monkeypatch.setattr(protocol, "_send_presence_bootstrap",
                        lambda session, now_ms: ran.append("presence"))
    monkeypatch.setattr(protocol, "_send_ownership_state_bootstrap",
                        lambda session, now_ms: ran.append("ownership"))
    protocol._send_join_bootstrap(sess, 0.0)
    assert ran == ["ownership", "presence"]
