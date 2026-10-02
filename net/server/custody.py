"""L5 stage 3b (2026-09-28) — custody of the checkpoint bytes.

Stage 3a left every checkpoint on the disk of the machine that wrote it:
the server knew its name, hash and size, and a boot on another machine (or
after a wiped Saves folder) fell back to the genesis save. Here the server
keeps the bytes too. Next to its UDP port it opens a small TCP service: a
client PUTs a checkpoint right after writing and reporting it, and GETs one
back at boot when the file the boot word names is not on its disk. Every
transfer is one connection, one fixed header, one body, one reply.

Trust: a transfer carries a token the server minted for the session in the
boot word (CKPT_BOOT), which maps to a peer id; a PUT may only name that
peer's own checkpoints, a GET only its own records. The token outlives the
session by a grace period, because the exit checkpoint is uploaded while
the process is leaving, after its goodbye. The bytes of a PUT are hashed
here and held to the hash in the header; a record whose hash they match is
marked "in custody" (journaled), and a PUT that arrives before its report
is kept until the report comes (checkpoint.py side: main._handle_ckpt_done).

Files: <custody dir>/<peer id>/<name>.fos and <name>.world.txt (the world
manifest the client wrote with the save: the objects of ours the save
carries, purged at the next load of it on any machine). Only the files of
the records on the books stay; the rest are deleted with their records.

Framing (little-endian, fixed headers; the C++ twin is persist/custody.cpp):
  request 128 B: "FWBK", version 1, op (1 PUT, 2 GET), reserved u16,
                 token[32], name[48], sha256[32], size u32, manifest u32,
                 then for a PUT `size` bytes of the .fos and `manifest`
                 bytes of the world manifest;
  reply    16 B: "FWBR", status, reserved[3], size u32, manifest u32,
                 then for a GET that succeeded the same two bodies.
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import secrets
import struct
from pathlib import Path
from typing import Callable, Optional

log = logging.getLogger("custody")

BULK_MAGIC = b"FWBK"
BULK_REPLY_MAGIC = b"FWBR"
BULK_VERSION = 1
OP_PUT = 1
OP_GET = 2
HEADER = struct.Struct("<4sBBH32s48s32sII")   # 128 bytes
REPLY = struct.Struct("<4sB3sII")             # 16 bytes
assert HEADER.size == 128 and REPLY.size == 16

ST_OK = 0
ST_BAD_REQUEST = 1
ST_BAD_TOKEN = 2
ST_NOT_OWNED = 3
ST_SHA_MISMATCH = 4
ST_NOT_IN_CUSTODY = 5
ST_TOO_BIG = 6
ST_SERVER_ERROR = 7
STATUS_NAMES = {
    ST_OK: "ok", ST_BAD_REQUEST: "bad request", ST_BAD_TOKEN: "bad token",
    ST_NOT_OWNED: "not this peer's checkpoint", ST_SHA_MISMATCH: "sha256 mismatch",
    ST_NOT_IN_CUSTODY: "not in custody", ST_TOO_BIG: "too big", ST_SERVER_ERROR: "server error",
}

TOKEN_LEN = 32
NAME_MAX = 47                       # 48 bytes on the wire, null-terminated
MAX_SAVE_BYTES = 256 * 1024 * 1024  # the same ceiling the record accepts
MAX_MANIFEST_BYTES = 1024 * 1024
HEADER_TIMEOUT_S = 10.0
BODY_TIMEOUT_S = 180.0
TOKEN_GRACE_MS = 600_000.0          # after the session: the exit upload, a quick return


def name_is_sane(name: str) -> bool:
    """A checkpoint name as the client makes it: ASCII, no path characters."""
    if not name or len(name) > NAME_MAX or not name.isascii():
        return False
    return all(ch.isalnum() or ch in "_-" for ch in name)


class BulkTokens:
    """The tokens the boot word hands out: token -> (peer id, identity)."""

    def __init__(self) -> None:
        self._by_token: dict[bytes, tuple[str, str, Optional[float]]] = {}

    def mint(self, peer_id: str, identity_hex: str, now_ms: float) -> bytes:
        # An older token of the same peer keeps working for the grace only:
        # a resumed session gets a fresh one and the exit upload of the
        # previous one may still be on its way.
        for tok, (pid, ident, exp) in list(self._by_token.items()):
            if pid == peer_id and exp is None:
                self._by_token[tok] = (pid, ident, now_ms + TOKEN_GRACE_MS)
        token = secrets.token_bytes(TOKEN_LEN)
        self._by_token[token] = (peer_id, identity_hex, None)
        return token

    def lookup(self, token: bytes, now_ms: float) -> Optional[tuple[str, str]]:
        entry = self._by_token.get(token)
        if entry is None:
            return None
        pid, ident, exp = entry
        if exp is not None and now_ms > exp:
            del self._by_token[token]
            return None
        return pid, ident

    def end_session(self, peer_id: str, now_ms: float) -> None:
        for tok, (pid, ident, exp) in list(self._by_token.items()):
            if pid == peer_id and exp is None:
                self._by_token[tok] = (pid, ident, now_ms + TOKEN_GRACE_MS)

    def expire(self, now_ms: float) -> int:
        gone = [t for t, (_p, _i, exp) in self._by_token.items() if exp is not None and now_ms > exp]
        for t in gone:
            del self._by_token[t]
        return len(gone)

    def __len__(self) -> int:
        return len(self._by_token)


class CustodyStore:
    """The files: one directory per peer, the .fos and its world manifest."""

    def __init__(self, directory: Path) -> None:
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self._sha: dict[tuple[str, str], str] = {}   # (peer, name) -> sha256 hex of the file

    def _peer_dir(self, peer_id: str) -> Path:
        return self.directory / peer_id

    def fos_path(self, peer_id: str, name: str) -> Path:
        return self._peer_dir(peer_id) / f"{name}.fos"

    def manifest_path(self, peer_id: str, name: str) -> Path:
        return self._peer_dir(peer_id) / f"{name}.world.txt"

    def sha_of(self, peer_id: str, name: str) -> Optional[str]:
        """The sha256 of the stored .fos (hashed once, then remembered)."""
        key = (peer_id, name)
        if key in self._sha:
            return self._sha[key]
        p = self.fos_path(peer_id, name)
        if not p.is_file():
            return None
        h = hashlib.sha256()
        with p.open("rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        self._sha[key] = h.hexdigest()
        return self._sha[key]

    def has(self, peer_id: str, name: str, sha256_hex: str) -> bool:
        got = self.sha_of(peer_id, name)
        return got is not None and got == (sha256_hex or "").lower()

    def store(self, peer_id: str, name: str, data: bytes, manifest: bytes, sha256_hex: str) -> None:
        d = self._peer_dir(peer_id)
        d.mkdir(parents=True, exist_ok=True)
        for path, body in ((self.fos_path(peer_id, name), data),
                           (self.manifest_path(peer_id, name), manifest)):
            part = path.with_name(path.name + ".part")
            with part.open("wb") as f:
                f.write(body)
                f.flush()
                os.fsync(f.fileno())
            os.replace(part, path)
        self._sha[(peer_id, name)] = sha256_hex.lower()

    def read(self, peer_id: str, name: str) -> Optional[tuple[bytes, bytes]]:
        p = self.fos_path(peer_id, name)
        if not p.is_file():
            return None
        data = p.read_bytes()
        m = self.manifest_path(peer_id, name)
        manifest = m.read_bytes() if m.is_file() else b""
        return data, manifest

    def delete(self, peer_id: str, name: str) -> None:
        for p in (self.fos_path(peer_id, name), self.manifest_path(peer_id, name)):
            try:
                p.unlink()
            except FileNotFoundError:
                pass
            except OSError as e:
                log.warning("custody: %s not deleted: %s", p, e)
        self._sha.pop((peer_id, name), None)

    def names(self, peer_id: str) -> list[str]:
        d = self._peer_dir(peer_id)
        if not d.is_dir():
            return []
        return sorted(p.name[:-4] for p in d.glob("*.fos"))

    def keep_only(self, peer_id: str, names: set[str]) -> int:
        """Delete the files of checkpoints no longer on the books."""
        gone = 0
        for n in self.names(peer_id):
            if n not in names:
                self.delete(peer_id, n)
                gone += 1
        return gone


class BulkServer:
    """The TCP service. `protocol` is the ServerProtocol: it owns the state,
    the store, the tokens and the clock."""

    def __init__(self, protocol, store: CustodyStore, tokens: BulkTokens,
                 now_ms: Callable[[], float]) -> None:
        self.protocol = protocol
        self.store = store
        self.tokens = tokens
        self.now_ms = now_ms
        self.server: Optional[asyncio.AbstractServer] = None
        self.transfers = 0

    async def start(self, host: str, port: int) -> asyncio.AbstractServer:
        self.server = await asyncio.start_server(self._handle, host, port)
        return self.server

    @property
    def port(self) -> int:
        if self.server is None or not self.server.sockets:
            return 0
        return int(self.server.sockets[0].getsockname()[1])

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        self.transfers += 1
        try:
            await self._serve(reader, writer, peer)
        except (asyncio.IncompleteReadError, asyncio.TimeoutError, ConnectionError, OSError) as e:
            log.info("custody: transfer from %s ended early: %s", peer, e)
        except Exception as e:  # noqa: BLE001 - one bad transfer must not take the service down
            log.exception("custody: transfer from %s failed: %s", peer, e)
            try:
                await self._reply(writer, ST_SERVER_ERROR)
            except Exception:  # noqa: BLE001
                pass
        finally:
            try:
                writer.close()
            except Exception:  # noqa: BLE001
                pass

    async def _reply(self, writer: asyncio.StreamWriter, status: int, size: int = 0,
                     manifest: int = 0, bodies: tuple[bytes, ...] = ()) -> None:
        writer.write(REPLY.pack(BULK_REPLY_MAGIC, status & 0xFF, b"\0\0\0",
                                size & 0xFFFFFFFF, manifest & 0xFFFFFFFF))
        for b in bodies:
            writer.write(b)
        await writer.drain()

    async def _serve(self, reader, writer, peer) -> None:
        hdr = await asyncio.wait_for(reader.readexactly(HEADER.size), HEADER_TIMEOUT_S)
        magic, version, op, _res, token, name_raw, sha, size, mlen = HEADER.unpack(hdr)
        if magic != BULK_MAGIC or version != BULK_VERSION or op not in (OP_PUT, OP_GET):
            log.info("custody: %s sent a request this service does not speak", peer)
            await self._reply(writer, ST_BAD_REQUEST)
            return
        now = self.now_ms()
        who = self.tokens.lookup(token, now)
        if who is None:
            log.info("custody: %s: unknown or expired token, refused", peer)
            await self._reply(writer, ST_BAD_TOKEN)
            return
        peer_id, _identity = who
        name = name_raw.split(b"\0", 1)[0].decode("ascii", "replace")
        if not name_is_sane(name) or not name.startswith(f"fwck_{peer_id}_"):
            log.info("custody: %s (%s) named '%s', which is not its own: refused", peer, peer_id, name)
            await self._reply(writer, ST_NOT_OWNED)
            return
        if op == OP_PUT:
            await self._put(reader, writer, peer_id, name, sha, size, mlen, now)
        else:
            await self._get(writer, peer_id, name, sha)

    async def _put(self, reader, writer, peer_id: str, name: str, sha: bytes,
                   size: int, mlen: int, now: float) -> None:
        if size == 0 or size > MAX_SAVE_BYTES or mlen > MAX_MANIFEST_BYTES:
            log.info("custody: PUT '%s' from %s refused: %d + %d bytes", name, peer_id, size, mlen)
            await self._reply(writer, ST_TOO_BIG)
            return
        data = await asyncio.wait_for(reader.readexactly(size), BODY_TIMEOUT_S)
        manifest = await asyncio.wait_for(reader.readexactly(mlen), BODY_TIMEOUT_S) if mlen else b""
        got = hashlib.sha256(data).digest()
        if got != sha:
            log.warning("custody: PUT '%s' from %s: the bytes hash to %s…, the header says %s…: refused",
                        name, peer_id, got.hex()[:12], sha.hex()[:12])
            await self._reply(writer, ST_SHA_MISMATCH)
            return
        self.store.store(peer_id, name, data, manifest, got.hex())
        self.protocol.on_custody_put(peer_id, name, got.hex(), size, now)
        await self._reply(writer, ST_OK, size, mlen)

    async def _get(self, writer, peer_id: str, name: str, sha: bytes) -> None:
        rec = next((r for r in self.protocol.state.checkpoints(peer_id) if r.name == name), None)
        if rec is None or not rec.custody:
            log.info("custody: GET '%s' from %s: %s", name, peer_id,
                     "not on record" if rec is None else "not in custody")
            await self._reply(writer, ST_NOT_IN_CUSTODY)
            return
        if any(sha) and sha.hex() != rec.sha256_hex:
            log.info("custody: GET '%s' from %s: the client expects another hash", name, peer_id)
            await self._reply(writer, ST_SHA_MISMATCH)
            return
        found = self.store.read(peer_id, name)
        if found is None:
            log.warning("custody: GET '%s' from %s: the record says in custody but the file is gone",
                        name, peer_id)
            await self._reply(writer, ST_NOT_IN_CUSTODY)
            return
        data, manifest = found
        log.info("custody: GET '%s' by %s: %d bytes sent", name, peer_id, len(data))
        await self._reply(writer, ST_OK, len(data), len(manifest), (data, manifest))


def build_request(op: int, token: bytes, name: str, sha256: bytes, size: int, manifest: int) -> bytes:
    """A request header as the client sends it (tests and tools)."""
    return HEADER.pack(BULK_MAGIC, BULK_VERSION, op & 0xFF, 0,
                       (token or b"").ljust(TOKEN_LEN, b"\0")[:TOKEN_LEN],
                       name.encode("ascii")[:NAME_MAX].ljust(48, b"\0"),
                       (sha256 or b"").ljust(32, b"\0")[:32],
                       size & 0xFFFFFFFF, manifest & 0xFFFFFFFF)


def parse_reply(raw: bytes) -> tuple[int, int, int]:
    """(status, size, manifest) of a reply header."""
    magic, status, _res, size, manifest = REPLY.unpack(raw)
    if magic != BULK_REPLY_MAGIC:
        raise ValueError("not a custody reply")
    return status, size, manifest
