"""Stage 3a of L5 (2026-09-28): the commanded checkpoint.

The character lives in an engine save the server commands. The server asks
each player in the world for one on a cadence, the client writes it at its
next quiet moment and reports name, hash and size; the server keeps the
last three per identity, names one at the next boot, and the client loads
it instead of the genesis save when the file on disk carries that hash.
Each test here failed on the code before the stage existed, and pins one
property:

- the four payloads have the sizes the DLL asserts and round-trip;
- a report is recorded under the identity, newest first, three deep, with
  the journal head as its watermark; a report that is not "ok", one from
  an anonymous session, or one under another identity's name is not; the
  same report twice (the exit report travels twice on purpose) is one
  record and one journal entry;
- the boot pick is the newest checkpoint fewer than two boots failed on,
  a boot result confirms or counts against it, and the first bootstrap
  stage tells the client which one (or none);
- the cadence asks a player in the world once per interval, asks again a
  minute after a deferral, and never asks an anonymous or absent player;
- the records survive the journal and the snapshot (v9).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from protocol import (  # noqa: E402
    MessageType, CkptRequestPayload, CkptDonePayload, CkptBootPayload, BootResultPayload,
    PosStatePayload, encode_frame, decode_frame,
)
from server.journal import Journal  # noqa: E402
from server.state import ServerState, CHECKPOINTS_KEPT  # noqa: E402
from server.persistence import (  # noqa: E402
    snapshot, load_into, SNAPSHOT_FORMAT_VERSION,
)
from server.main import ServerProtocol  # noqa: E402

SHA = bytes(range(32))
SHA2 = bytes(range(32, 64))


def _accept(state: ServerState, peer: str, port: int, identity: str = "abc123"):
    session, reason = state.accept_peer(("127.0.0.1", port), peer, (1, 0), 0.0)
    assert session is not None, reason
    session.identity_hex = identity
    return session


def _done(peer: str, n: int, seq: int = 1, status: int = 0, sha: bytes = SHA,
          size: int = 4_989_921) -> CkptDonePayload:
    return CkptDonePayload(seq=seq, status=status, name=f"fwck_{peer}_20260928_03{n:02d}00",
                           sha256=sha, size=size, digest=0xB7FE2A6E14E9E634, digest_seq=7,
                           wall_ms=1_700_000_000_000 + n)


class FakeTransport:
    def __init__(self):
        self.sent: list[tuple[tuple[str, int], bytes]] = []

    def sendto(self, data, addr):
        self.sent.append((addr, data))


def _frames_to(transport: FakeTransport, addr, mtype):
    out = []
    for a, raw in transport.sent:
        if a != addr:
            continue
        frame = decode_frame(raw)
        if frame.header.msg_type == mtype:
            out.append(frame.payload)
    return out


class TestCodec:
    def test_sizes_and_round_trips(self):
        req = CkptRequestPayload(seq=5, reason=0, deadline_s=30)
        assert len(req.encode()) == 7 and CkptRequestPayload.decode(req.encode()) == req
        done = _done("alice", 1)
        assert len(done.encode()) == 109 and CkptDonePayload.decode(done.encode()) == done
        boot = CkptBootPayload(has=True, seq=3, name="fwck_alice_20260928_030100", sha256=SHA,
                               size=12, digest=0xFFFFFFFFFFFFFFFF)
        # v31 (stage 3b): the boot word grew to 424 bytes (bulk port, token, candidates);
        # v32 (stage 3c): 441 with the respawn point.
        assert len(boot.encode()) == 441 and CkptBootPayload.decode(boot.encode()) == boot
        withpos = CkptBootPayload(has=False, seq=0, name="", sha256=b"", size=0, digest=0,
                                  has_pos=True, px=-79086.7, py=90716.2, pz=7935.3, yaw=1.5, pos_ms=77)
        back = CkptBootPayload.decode(withpos.encode())
        assert back.has_pos is True and back.pos_ms == 77 and abs(back.px - -79086.7) < 0.01
        none = CkptBootPayload(has=False, seq=0, name="", sha256=b"", size=0, digest=0)
        back = CkptBootPayload.decode(none.encode())
        assert back.has is False and back.name == "" and back.sha256 == b""
        res = BootResultPayload(seq=3, outcome=0, name="fwck_alice_20260928_030100", wall_ms=9)
        assert len(res.encode()) == 61 and BootResultPayload.decode(res.encode()) == res

    def test_the_frame_codec_knows_the_four(self):
        for mtype, p in ((MessageType.CKPT_REQUEST, CkptRequestPayload(1, 0, 30)),
                         (MessageType.CKPT_DONE, _done("alice", 2)),
                         (MessageType.CKPT_BOOT, CkptBootPayload(False, 0, "", b"", 0, 0)),
                         (MessageType.BOOT_RESULT, BootResultPayload(1, 1, "", 0))):
            frame = decode_frame(encode_frame(mtype, 1, p, reliable=True))
            assert frame.header.msg_type == mtype and frame.payload == p


class TestRecord:
    def test_a_report_is_recorded_newest_first_three_deep_with_the_watermark(self):
        state = ServerState()
        state.applied_lsn = 41
        proto = ServerProtocol(state)
        alice = _accept(state, "alice", 1)
        for n in range(1, 5):
            state.applied_lsn = 40 + n
            proto._handle_ckpt_done(alice, _done("alice", n, seq=n), 1_000.0 * n)
        recs = state.checkpoints("alice")
        assert len(recs) == CHECKPOINTS_KEPT == 3
        assert [r.name[-4:] for r in recs] == ["0400", "0300", "0200"]
        assert recs[0].watermark_lsn == 44 and recs[0].seq == 4
        assert recs[0].sha256_hex == SHA.hex() and recs[0].size == 4_989_921
        assert recs[0].status == "provisional" and recs[0].identity_hex == "abc123"
        assert alice.ckpt_last_done_ms == 4_000.0

    def test_not_ok_anonymous_or_foreign_names_are_not_recorded(self):
        state = ServerState()
        proto = ServerProtocol(state)
        alice = _accept(state, "alice", 1)
        proto._handle_ckpt_done(alice, _done("alice", 1, status=1), 1_000.0)   # deferred
        assert state.checkpoints("alice") == []
        assert alice.ckpt_retry_at_ms == 61_000.0
        proto._handle_ckpt_done(alice, _done("bob", 1), 2_000.0)               # bob's name
        assert state.checkpoints("alice") == []
        proto._handle_ckpt_done(alice, _done("alice", 1, sha=bytes(32)), 3_000.0)   # empty hash
        assert state.checkpoints("alice") == []
        anon = _accept(state, "carol", 2, identity="")
        proto._handle_ckpt_done(anon, _done("carol", 1), 4_000.0)
        assert state.checkpoints("carol") == []
        proto._handle_ckpt_done(alice, _done("alice", 2), 5_000.0)
        assert len(state.checkpoints("alice")) == 1

    def test_the_same_report_twice_is_one_record_and_one_journal_entry(self, tmp_path: Path):
        state = ServerState()
        state.journal = Journal.open(tmp_path / "journal")
        proto = ServerProtocol(state)
        alice = _accept(state, "alice", 1)
        proto._handle_ckpt_done(alice, _done("alice", 1), 1_000.0)
        lsn = state.applied_lsn
        events = alice.total_events
        proto._handle_ckpt_done(alice, _done("alice", 1), 1_050.0)   # the second datagram
        assert len(state.checkpoints("alice")) == 1
        assert state.applied_lsn == lsn and alice.total_events == events
        proto._handle_ckpt_done(alice, _done("alice", 1, sha=SHA2), 2_000.0)   # same name, other bytes
        recs = state.checkpoints("alice")
        assert len(recs) == 1 and recs[0].sha256_hex == SHA2.hex()
        assert state.applied_lsn == lsn + 1 and alice.total_events == events + 1
        state.journal.close()


class TestBoot:
    def test_the_pick_skips_a_checkpoint_two_boots_failed_on(self):
        state = ServerState()
        proto = ServerProtocol(state)
        alice = _accept(state, "alice", 1)
        proto._handle_ckpt_done(alice, _done("alice", 1), 1_000.0)
        proto._handle_ckpt_done(alice, _done("alice", 2, sha=SHA2), 2_000.0)
        newest = state.checkpoint_to_boot("alice")
        assert newest.name.endswith("0200")
        proto._handle_boot_result(alice, BootResultPayload(2, 3, newest.name, 0), 3_000.0)
        assert state.checkpoint_to_boot("alice").name.endswith("0200")   # one failure: still it
        proto._handle_boot_result(alice, BootResultPayload(2, 2, newest.name, 0), 4_000.0)
        assert state.checkpoint_to_boot("alice").name.endswith("0100")   # two: the previous
        assert newest.status == "failed" and newest.boot_failures == 2
        proto._handle_boot_result(alice, BootResultPayload(1, 0, "fwck_alice_20260928_030100", 0), 5_000.0)
        assert state.checkpoints("alice")[1].status == "confirmed"

    def test_the_first_bootstrap_stage_names_the_pick_or_none(self):
        state = ServerState()
        proto = ServerProtocol(state)
        transport = FakeTransport()
        proto.transport = transport
        alice = _accept(state, "alice", 1)
        proto._send_checkpoint_boot(alice, 1_000.0)
        boots = _frames_to(transport, alice.addr, MessageType.CKPT_BOOT)
        assert len(boots) == 1 and boots[0].has is False
        proto._handle_ckpt_done(alice, _done("alice", 1, sha=SHA2), 2_000.0)
        proto._send_checkpoint_boot(alice, 3_000.0)
        boots = _frames_to(transport, alice.addr, MessageType.CKPT_BOOT)
        assert boots[-1].has is True and boots[-1].name.endswith("0100")
        assert boots[-1].sha256 == SHA2 and boots[-1].size == 4_989_921
        anon = _accept(state, "carol", 2, identity="")
        proto._send_checkpoint_boot(anon, 4_000.0)
        assert _frames_to(transport, anon.addr, MessageType.CKPT_BOOT)[0].has is False

    def test_a_last_position_newer_than_the_checkpoint_rides_with_the_boot(self):
        state = ServerState()
        proto = ServerProtocol(state)
        transport = FakeTransport()
        proto.transport = transport
        alice = _accept(state, "alice", 1)
        proto._handle_ckpt_done(alice, _done("alice", 1), 10_000.0)
        # A position from BEFORE the checkpoint (a Quit writes its checkpoint
        # after the last report): nothing rides along.
        state.record_presence_pos("alice", PosStatePayload(1.0, 2.0, 3.0, 0.0, 0.0, 1.5, 0, 0), 9_000.0)
        proto._send_checkpoint_boot(alice, 20_000.0)
        assert _frames_to(transport, alice.addr, MessageType.CKPT_BOOT)[-1].has_pos is False
        # Within the two-second margin: still nothing.
        state.record_presence_pos("alice", PosStatePayload(1.0, 2.0, 3.0, 0.0, 0.0, 1.5, 0, 0), 11_500.0)
        proto._send_checkpoint_boot(alice, 20_000.0)
        assert _frames_to(transport, alice.addr, MessageType.CKPT_BOOT)[-1].has_pos is False
        # A crash 50 s later: the position is newer, the boot carries it.
        state.record_presence_pos("alice", PosStatePayload(4.0, 5.0, 6.0, 0.0, 0.0, 2.5, 0, 0), 60_000.0)
        proto._send_checkpoint_boot(alice, 70_000.0)
        boot = _frames_to(transport, alice.addr, MessageType.CKPT_BOOT)[-1]
        assert boot.has is True and boot.has_pos is True
        assert (boot.px, boot.py, boot.pz, boot.yaw, boot.pos_ms) == (4.0, 5.0, 6.0, 2.5, 60_000)
        # No checkpoint at all but a known position: the genesis boots there.
        bob = _accept(state, "bob", 3)
        state.record_presence_pos("bob", PosStatePayload(7.0, 8.0, 9.0, 0.0, 0.0, 0.5, 0, 0), 60_000.0)
        proto._send_checkpoint_boot(bob, 70_000.0)
        boot = _frames_to(transport, bob.addr, MessageType.CKPT_BOOT)[-1]
        assert boot.has is False and boot.has_pos is True and boot.px == 7.0


class TestCadence:
    def _in_world(self, session):
        session.last_pos_at_ms = 1.0

    def test_a_player_in_the_world_is_asked_once_per_interval(self):
        state = ServerState()
        proto = ServerProtocol(state)
        proto.checkpoint_every_ms = 10_000.0
        transport = FakeTransport()
        proto.transport = transport
        alice = _accept(state, "alice", 1)
        self._in_world(alice)
        proto._schedule_checkpoints(5_000.0)
        assert _frames_to(transport, alice.addr, MessageType.CKPT_REQUEST) == []
        proto._schedule_checkpoints(10_000.0)
        reqs = _frames_to(transport, alice.addr, MessageType.CKPT_REQUEST)
        assert len(reqs) == 1 and reqs[0].seq == 1 and reqs[0].deadline_s == 30
        proto._schedule_checkpoints(15_000.0)
        assert len(_frames_to(transport, alice.addr, MessageType.CKPT_REQUEST)) == 1
        proto._handle_ckpt_done(alice, _done("alice", 1, seq=1), 12_000.0)
        proto._schedule_checkpoints(21_000.0)
        assert len(_frames_to(transport, alice.addr, MessageType.CKPT_REQUEST)) == 1
        proto._schedule_checkpoints(22_000.0)
        reqs = _frames_to(transport, alice.addr, MessageType.CKPT_REQUEST)
        assert len(reqs) == 2 and reqs[1].seq == 2

    def test_a_deferral_is_asked_again_after_a_minute(self):
        state = ServerState()
        proto = ServerProtocol(state)
        proto.checkpoint_every_ms = 10_000.0
        transport = FakeTransport()
        proto.transport = transport
        alice = _accept(state, "alice", 1)
        self._in_world(alice)
        proto._schedule_checkpoints(10_000.0)
        proto._handle_ckpt_done(alice, _done("alice", 1, seq=1, status=1), 11_000.0)
        proto._schedule_checkpoints(30_000.0)
        assert len(_frames_to(transport, alice.addr, MessageType.CKPT_REQUEST)) == 1
        proto._schedule_checkpoints(71_000.0)
        assert len(_frames_to(transport, alice.addr, MessageType.CKPT_REQUEST)) == 2

    def test_anonymous_or_absent_players_are_never_asked(self):
        state = ServerState()
        proto = ServerProtocol(state)
        proto.checkpoint_every_ms = 10_000.0
        transport = FakeTransport()
        proto.transport = transport
        anon = _accept(state, "carol", 2, identity="")
        self._in_world(anon)
        absent = _accept(state, "dave", 3)   # authenticated, no position yet
        proto._schedule_checkpoints(100_000.0)
        assert _frames_to(transport, anon.addr, MessageType.CKPT_REQUEST) == []
        assert _frames_to(transport, absent.addr, MessageType.CKPT_REQUEST) == []

    def test_a_cadence_of_zero_never_asks(self):
        state = ServerState()
        proto = ServerProtocol(state)
        proto.checkpoint_every_ms = 0.0
        transport = FakeTransport()
        proto.transport = transport
        alice = _accept(state, "alice", 1)
        self._in_world(alice)
        proto._schedule_checkpoints(1_000_000.0)
        assert _frames_to(transport, alice.addr, MessageType.CKPT_REQUEST) == []


class TestDurability:
    def test_the_records_come_back_from_a_replay(self, tmp_path: Path):
        a = ServerState()
        j = Journal.open(tmp_path / "journal")
        a.journal = j
        a.record_checkpoint("alice", "abc", 1, "fwck_alice_20260928_030100", SHA.hex(),
                            10, 5, 1, 100, 1_000.0, 7, 0)
        a.record_checkpoint("alice", "abc", 2, "fwck_alice_20260928_030200", SHA2.hex(),
                            11, 6, 2, 200, 2_000.0, 9, 0)
        a.confirm_checkpoint("alice", "fwck_alice_20260928_030200", 3, 3_000.0)
        j.flush()
        j.close()
        b = ServerState()
        j2 = Journal.open(tmp_path / "journal")
        n = j2.replay(b, after_lsn=0)
        j2.close()
        assert n == 3
        recs = b.checkpoints("alice")
        assert [r.name[-4:] for r in recs] == ["0200", "0100"]
        assert recs[0].boot_failures == 1 and recs[0].watermark_lsn == 9
        assert recs[1].sha256_hex == SHA.hex()

    def test_the_records_survive_the_snapshot(self, tmp_path: Path):
        a = ServerState()
        a.record_checkpoint("alice", "abc", 1, "fwck_alice_20260928_030100", SHA.hex(),
                            10, 5, 1, 100, 1_000.0, 7, 0)
        a.record_checkpoint("alice", "abc", 2, "fwck_alice_20260928_030200", SHA2.hex(),
                            11, 0xFFFFFFFFFFFFFFFF, 2, 200, 2_000.0, 9, 2)
        a.confirm_checkpoint("alice", "fwck_alice_20260928_030200", 0, 3_000.0)
        snap = tmp_path / "snap.json"
        snapshot(a, snap)
        data = json.loads(snap.read_text())
        assert data["version"] == SNAPSHOT_FORMAT_VERSION == 15   # v15: partial-record ops, checkpoint world, world base per peer (2026-10-20)
        assert data["checkpoints"][0]["name"].endswith("0200")
        b = ServerState()
        load_into(b, snap)
        recs = b.checkpoints("alice")
        assert [r.name[-4:] for r in recs] == ["0200", "0100"]
        assert recs[0].status == "confirmed" and recs[0].digest == 0xFFFFFFFFFFFFFFFF
        assert recs[0].watermark_lsn == 9 and recs[0].reason == 2
        assert recs[1].received_ms == 1_000.0

    def test_a_v8_snapshot_without_the_section_loads_with_none(self, tmp_path: Path):
        snap = tmp_path / "snap.json"
        snap.write_text(json.dumps({"version": 8, "world_actors": [], "containers": []}))
        b = ServerState()
        load_into(b, snap)
        assert b.all_checkpoints() == []
