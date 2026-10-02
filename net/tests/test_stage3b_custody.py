"""Stage 3b of L5 (2026-09-28): custody of the checkpoint bytes.

The server keeps the bytes of every checkpoint next to its record, over a
TCP service under a per-session token, so a boot on another machine (or
after a wiped Saves folder) fetches the file instead of falling back to
the genesis save. Each test here failed on the code before the stage
existed, and pins one property:

- the boot word (CKPT_BOOT, wire v31) carries the bulk port, a token and
  up to three candidates newest first, each saying whether the server
  holds its bytes; the codec round-trips it;
- a PUT whose bytes hash to the record's sha marks the record in custody
  and lands on disk with its world manifest; a GET returns the same bytes;
- a PUT that arrives before its report is held and confirmed by the report;
- a bad token, another peer's name, a wrong hash and an oversize header are
  refused with their own status and nothing is stored;
- a GET of a checkpoint the server does not hold is refused;
- custody survives the journal and the snapshot (v10); a v9 snapshot loads
  with custody off;
- the files of records that dropped off the last three are deleted;
- a token ends with its session after a grace.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from protocol import (  # noqa: E402
    MessageType, CkptBootPayload, CkptCandidate, CKPT_CANDIDATES_MAX, CkptDonePayload,
    decode_frame,
)
from server.custody import (  # noqa: E402
    BulkServer, BulkTokens, CustodyStore, build_request, parse_reply, REPLY, TOKEN_GRACE_MS,
    OP_PUT, OP_GET, ST_OK, ST_BAD_TOKEN, ST_NOT_OWNED, ST_SHA_MISMATCH, ST_NOT_IN_CUSTODY,
    ST_TOO_BIG, ST_BAD_REQUEST,
)
from server.journal import Journal  # noqa: E402
from server.state import ServerState  # noqa: E402
from server.persistence import snapshot, load_into, SNAPSHOT_FORMAT_VERSION  # noqa: E402
from server.main import ServerProtocol  # noqa: E402

SAVE = bytes(range(256)) * 64 + b"FO4SAVEGAME"      # 16395 bytes, not a real .fos, the hash is what counts
SAVE_SHA = hashlib.sha256(SAVE).digest()
MANIFEST = b"# fwworld 1 fwck_alice_20260928_030100\nFF001188 0008C14D 60 -77833.90 91597.10 7825.10\n"


def _accept(state: ServerState, peer: str, port: int, identity: str = "abc123"):
    session, reason = state.accept_peer(("127.0.0.1", port), peer, (1, 0), 0.0)
    assert session is not None, reason
    session.identity_hex = identity
    return session


def _done(peer: str, n: int, sha: bytes = SAVE_SHA, size: int = len(SAVE)) -> CkptDonePayload:
    return CkptDonePayload(seq=0, status=0, name=f"fwck_{peer}_20260928_03{n:02d}00",
                           sha256=sha, size=size, digest=1, digest_seq=1, wall_ms=n)


class FakeTransport:
    def __init__(self):
        self.sent = []

    def sendto(self, data, addr):
        self.sent.append((addr, data))


def _boots_to(transport, addr):
    out = []
    for a, raw in transport.sent:
        if a != addr:
            continue
        frame = decode_frame(raw)
        if frame.header.msg_type == MessageType.CKPT_BOOT:
            out.append(frame.payload)
    return out


def _server(tmp_path: Path, clock=None):
    """A protocol with a store and tokens, and the TCP service on a free port."""
    state = ServerState()
    proto = ServerProtocol(state)
    proto.transport = FakeTransport()
    proto.custody = CustodyStore(tmp_path / "custody")
    now = {"ms": 1_000.0}
    bulk = BulkServer(proto, proto.custody, proto.bulk_tokens, lambda: now["ms"])
    return state, proto, bulk, now


async def _transfer(port: int, header: bytes, body: bytes = b"") -> tuple[int, int, int, bytes]:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(header + body)
    await writer.drain()
    raw = await reader.readexactly(REPLY.size)
    status, size, mlen = parse_reply(raw)
    # A PUT reply echoes the sizes it stored and carries no body; a GET does.
    payload = b""
    if status == ST_OK and header[5] == OP_GET and (size or mlen):
        payload = await reader.readexactly(size + mlen)
    writer.close()
    try:
        await writer.wait_closed()
    except Exception:  # noqa: BLE001
        pass
    return status, size, mlen, payload


class TestBootWord:
    def test_the_codec_round_trips_port_token_and_candidates(self):
        cands = tuple(CkptCandidate(f"fwck_alice_20260928_03000{i}", bytes([i + 1]) * 32, 100 + i, i, i == 1)
                      for i in range(3))
        p = CkptBootPayload(has=True, seq=2, name=cands[0].name, sha256=cands[0].sha256, size=100,
                            digest=7, bulk_port=31337, token=bytes(range(32)), candidates=cands)
        raw = p.encode()
        assert len(raw) == CkptBootPayload.SIZE == 441
        q = CkptBootPayload.decode(raw)
        assert q.bulk_port == 31337 and q.token == bytes(range(32))
        assert q.candidates == cands
        bare = CkptBootPayload.decode(CkptBootPayload(has=False, seq=0, name="", sha256=b"",
                                                      size=0, digest=0).encode())
        assert bare.bulk_port == 0 and bare.token == b"" and bare.candidates == ()

    def test_the_boot_word_lists_the_records_with_their_custody(self, tmp_path: Path):
        state, proto, bulk, now = _server(tmp_path)
        proto.bulk_port = 31338
        alice = _accept(state, "alice", 1)
        proto._handle_ckpt_done(alice, _done("alice", 1), 1_000.0)
        proto._handle_ckpt_done(alice, _done("alice", 2, sha=bytes(range(32))), 2_000.0)
        assert state.set_checkpoint_custody("alice", "fwck_alice_20260928_030100", SAVE_SHA.hex(), 2_500.0)
        proto._send_checkpoint_boot(alice, 3_000.0)
        word = _boots_to(proto.transport, alice.addr)[-1]
        assert word.has and word.name.endswith("0200")
        assert word.bulk_port == 31338 and len(word.token) == 32
        assert [c.name[-4:] for c in word.candidates] == ["0200", "0100"]
        assert [c.custody for c in word.candidates] == [False, True]
        assert alice.bulk_token == word.token
        assert proto.bulk_tokens.lookup(word.token, 3_000.0) == ("alice", "abc123")
        # No custody service: no port, no token, the candidates still ride.
        proto.custody = None
        proto.bulk_port = 0
        proto._send_checkpoint_boot(alice, 4_000.0)
        word = _boots_to(proto.transport, alice.addr)[-1]
        assert word.bulk_port == 0 and word.token == b"" and len(word.candidates) == 2
        anon = _accept(state, "carol", 2, identity="")
        proto._send_checkpoint_boot(anon, 5_000.0)
        assert _boots_to(proto.transport, anon.addr)[-1].candidates == ()


class TestTransfers:
    def test_a_put_lands_in_custody_and_a_get_returns_the_same_bytes(self, tmp_path: Path):
        state, proto, bulk, now = _server(tmp_path)
        alice = _accept(state, "alice", 1)
        proto._handle_ckpt_done(alice, _done("alice", 1), 1_000.0)
        token = proto.bulk_tokens.mint("alice", "abc123", 1_000.0)
        name = "fwck_alice_20260928_030100"

        async def run():
            server = await bulk.start("127.0.0.1", 0)
            try:
                st, size, mlen, _ = await _transfer(
                    bulk.port, build_request(OP_PUT, token, name, SAVE_SHA, len(SAVE), len(MANIFEST)),
                    SAVE + MANIFEST)
                assert (st, size, mlen) == (ST_OK, len(SAVE), len(MANIFEST))
                rec = state.checkpoints("alice")[0]
                assert rec.custody is True
                assert proto.custody.fos_path("alice", name).read_bytes() == SAVE
                assert proto.custody.manifest_path("alice", name).read_bytes() == MANIFEST
                st, size, mlen, payload = await _transfer(
                    bulk.port, build_request(OP_GET, token, name, SAVE_SHA, 0, 0))
                assert (st, size, mlen) == (ST_OK, len(SAVE), len(MANIFEST))
                assert payload == SAVE + MANIFEST
                # A GET without an expected hash is served too.
                st, size, mlen, payload = await _transfer(
                    bulk.port, build_request(OP_GET, token, name, b"", 0, 0))
                assert st == ST_OK and payload[:len(SAVE)] == SAVE
            finally:
                server.close()
                await server.wait_closed()

        asyncio.run(run())
        assert bulk.transfers == 3

    def test_a_put_before_its_report_is_held_then_confirmed(self, tmp_path: Path):
        state, proto, bulk, now = _server(tmp_path)
        alice = _accept(state, "alice", 1)
        token = proto.bulk_tokens.mint("alice", "abc123", 1_000.0)
        name = "fwck_alice_20260928_030100"

        async def run():
            server = await bulk.start("127.0.0.1", 0)
            try:
                st, _, _, _ = await _transfer(
                    bulk.port, build_request(OP_PUT, token, name, SAVE_SHA, len(SAVE), 0), SAVE)
                assert st == ST_OK
            finally:
                server.close()
                await server.wait_closed()

        asyncio.run(run())
        assert state.checkpoints("alice") == []
        assert proto.custody.has("alice", name, SAVE_SHA.hex())
        proto._handle_ckpt_done(alice, _done("alice", 1), 2_000.0)
        assert state.checkpoints("alice")[0].custody is True
        # The same name with other bytes reported later: not in custody.
        proto._handle_ckpt_done(alice, _done("alice", 1, sha=bytes(range(32))), 3_000.0)
        assert state.checkpoints("alice")[0].custody is False

    def test_bad_token_foreign_name_wrong_hash_and_oversize_are_refused(self, tmp_path: Path):
        state, proto, bulk, now = _server(tmp_path)
        alice = _accept(state, "alice", 1)
        proto._handle_ckpt_done(alice, _done("alice", 1), 1_000.0)
        token = proto.bulk_tokens.mint("alice", "abc123", 1_000.0)
        name = "fwck_alice_20260928_030100"

        async def run():
            server = await bulk.start("127.0.0.1", 0)
            try:
                st, *_ = await _transfer(bulk.port, build_request(OP_PUT, bytes(32), name, SAVE_SHA, len(SAVE), 0), SAVE)
                assert st == ST_BAD_TOKEN
                st, *_ = await _transfer(bulk.port, build_request(OP_PUT, token, "fwck_bob_20260928_030100", SAVE_SHA, len(SAVE), 0), SAVE)
                assert st == ST_NOT_OWNED
                st, *_ = await _transfer(bulk.port, build_request(OP_PUT, token, name, bytes(range(32)), len(SAVE), 0), SAVE)
                assert st == ST_SHA_MISMATCH
                st, *_ = await _transfer(bulk.port, build_request(OP_PUT, token, name, SAVE_SHA, 300 * 1024 * 1024, 0))
                assert st == ST_TOO_BIG
                st, *_ = await _transfer(bulk.port, b"NOPE" + bytes(124))
                assert st == ST_BAD_REQUEST
                now["ms"] = 1_000.0 + TOKEN_GRACE_MS + 1.0
                proto.bulk_tokens.end_session("alice", 1_000.0)
                st, *_ = await _transfer(bulk.port, build_request(OP_PUT, token, name, SAVE_SHA, len(SAVE), 0), SAVE)
                assert st == ST_BAD_TOKEN
            finally:
                server.close()
                await server.wait_closed()

        asyncio.run(run())
        assert state.checkpoints("alice")[0].custody is False
        assert proto.custody.names("alice") == []

    def test_a_get_of_a_checkpoint_not_held_is_refused(self, tmp_path: Path):
        state, proto, bulk, now = _server(tmp_path)
        alice = _accept(state, "alice", 1)
        proto._handle_ckpt_done(alice, _done("alice", 1), 1_000.0)
        token = proto.bulk_tokens.mint("alice", "abc123", 1_000.0)

        async def run():
            server = await bulk.start("127.0.0.1", 0)
            try:
                st, *_ = await _transfer(bulk.port, build_request(OP_GET, token, "fwck_alice_20260928_030100", SAVE_SHA, 0, 0))
                assert st == ST_NOT_IN_CUSTODY
                st, *_ = await _transfer(bulk.port, build_request(OP_GET, token, "fwck_alice_20260928_039900", SAVE_SHA, 0, 0))
                assert st == ST_NOT_IN_CUSTODY
            finally:
                server.close()
                await server.wait_closed()

        asyncio.run(run())


class TestRecords:
    def test_custody_survives_the_journal_and_the_snapshot_and_a_v9_file_loads_without_it(self, tmp_path: Path):
        a = ServerState()
        j = Journal.open(tmp_path / "journal")
        a.journal = j
        a.record_checkpoint("alice", "abc", 1, "fwck_alice_20260928_030100", SAVE_SHA.hex(),
                            10, 5, 1, 100, 1_000.0, 7, 0)
        assert a.set_checkpoint_custody("alice", "fwck_alice_20260928_030100", SAVE_SHA.hex(), 1_500.0)
        assert a.set_checkpoint_custody("alice", "fwck_alice_20260928_030100", "00" * 32, 1_600.0) is None
        lsn = a.applied_lsn
        assert a.set_checkpoint_custody("alice", "fwck_alice_20260928_030100", SAVE_SHA.hex(), 1_700.0)
        assert a.applied_lsn == lsn    # already in custody: nothing journaled
        j.flush()
        j.close()
        b = ServerState()
        j2 = Journal.open(tmp_path / "journal")
        assert j2.replay(b, after_lsn=0) == 2
        j2.close()
        assert b.checkpoints("alice")[0].custody is True
        snap = tmp_path / "snap.json"
        snapshot(b, snap)
        data = json.loads(snap.read_text())
        assert data["version"] == SNAPSHOT_FORMAT_VERSION == 10
        assert data["checkpoints"][0]["custody"] is True
        c = ServerState()
        load_into(c, snap)
        assert c.checkpoints("alice")[0].custody is True
        data["version"] = 9
        for entry in data["checkpoints"]:
            del entry["custody"]
        old = tmp_path / "v9.json"
        old.write_text(json.dumps(data))
        d = ServerState()
        load_into(d, old)
        assert d.checkpoints("alice")[0].custody is False

    def test_the_files_of_records_that_dropped_off_are_deleted(self, tmp_path: Path):
        state, proto, bulk, now = _server(tmp_path)
        alice = _accept(state, "alice", 1)
        for n in range(1, 4):
            name = f"fwck_alice_20260928_03{n:02d}00"
            proto.custody.store("alice", name, SAVE, b"", SAVE_SHA.hex())
            proto._handle_ckpt_done(alice, _done("alice", n), 1_000.0 * n)
        assert all(r.custody for r in state.checkpoints("alice"))
        assert len(proto.custody.names("alice")) == 3
        proto._handle_ckpt_done(alice, _done("alice", 4), 4_000.0)
        assert [r.name[-4:] for r in state.checkpoints("alice")] == ["0400", "0300", "0200"]
        assert proto.custody.names("alice") == ["fwck_alice_20260928_030200", "fwck_alice_20260928_030300"]

    def test_a_token_ends_with_its_session_after_a_grace(self):
        tokens = BulkTokens()
        t1 = tokens.mint("alice", "abc", 1_000.0)
        assert tokens.lookup(t1, 5_000.0) == ("alice", "abc")
        t2 = tokens.mint("alice", "abc", 6_000.0)          # a resumed session: the old one has the grace
        assert tokens.lookup(t1, 6_000.0 + TOKEN_GRACE_MS) == ("alice", "abc")
        assert tokens.lookup(t1, 6_000.0 + TOKEN_GRACE_MS + 1.0) is None
        tokens.end_session("alice", 10_000.0)
        assert tokens.lookup(t2, 10_000.0 + TOKEN_GRACE_MS) == ("alice", "abc")
        assert tokens.expire(10_000.0 + TOKEN_GRACE_MS + 1.0) == 1
        assert tokens.lookup(t2, 20_000.0 + TOKEN_GRACE_MS) is None
        assert len(tokens) == 0
