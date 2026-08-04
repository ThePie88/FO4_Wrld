"""FalloutWorld master server — the public server list.

Runs standalone, holds no game state, and never touches a save. Its only job:

    public game server  --MASTER_REGISTER-->  master        (every 30 s)
    game client         --MASTER_LIST_REQUEST-->  master
    game client         <-MASTER_LIST_RESPONSE--  master    (paged)

Design notes worth keeping:

* A registration carries NO address. The listed endpoint is the UDP SOURCE
  address of the heartbeat, so a server behind NAT is published at the address
  that actually works from outside, cannot claim someone else's endpoint, and
  the repeating heartbeat keeps its NAT mapping open.
* Listings EXPIRE. There is no goodbye message and none is wanted: a server
  that crashes, loses power or is unplugged simply stops heartbeating and drops
  off the list after MASTER_ENTRY_TTL_S. Silence is the disconnect protocol.
* Everything is stateless request/response over unreliable UDP. A lost list
  request costs the browser one retry, never a stuck state machine.

Run:
    python -m net.master.main --host 0.0.0.0 --port 31338
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import time
from typing import Optional

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))

from net.protocol import (  # noqa: E402
    MasterListRequestPayload,
    MasterListResponsePayload,
    MasterRegisterPayload,
    MasterServerEntry,
    MAX_SERVERS_PER_LIST_FRAME,
    MAX_SERVER_NAME_LEN,
    MessageType,
    ProtocolError,
    decode_frame,
    encode_frame,
)

log = logging.getLogger("master")

MASTER_ENTRY_TTL_S: float = 90.0
"""How long a listing survives without a heartbeat. Three missed heartbeats
(30 s each) before a server disappears — tolerant of packet loss and a brief
network hiccup, still quick enough that a dead server does not linger."""


def _now() -> float:
    return time.monotonic()


class MasterRegistry:
    """The list. Keyed by source address, so one host can run several servers
    on different ports and each gets its own row."""

    def __init__(self, ttl_s: float = MASTER_ENTRY_TTL_S) -> None:
        self.ttl_s = ttl_s
        self._servers: dict[tuple[str, int], tuple[MasterRegisterPayload, float]] = {}

    def register(self, addr: tuple[str, int], payload: MasterRegisterPayload,
                 now: Optional[float] = None) -> bool:
        """Record/refresh a listing. Returns True if this was a NEW server."""
        now = _now() if now is None else now
        is_new = addr not in self._servers
        self._servers[addr] = (payload, now)
        return is_new

    def prune(self, now: Optional[float] = None) -> list[tuple[str, int]]:
        """Drop listings that stopped heartbeating. Returns what was removed."""
        now = _now() if now is None else now
        dead = [a for a, (_, seen) in self._servers.items()
                if (now - seen) > self.ttl_s]
        for a in dead:
            del self._servers[a]
        return dead

    def entries(self, now: Optional[float] = None) -> list[MasterServerEntry]:
        """Live rows, newest-seen first so an empty browser still looks alive."""
        now = _now() if now is None else now
        rows = [
            (seen, MasterServerEntry(
                address=f"{a[0]}:{a[1]}",
                name=p.name[:MAX_SERVER_NAME_LEN],
                players=p.players,
                max_players=p.max_players,
                version_major=p.version_major,
                version_minor=p.version_minor,
                passworded=p.passworded,
            ))
            for a, (p, seen) in self._servers.items()
            if (now - seen) <= self.ttl_s
        ]
        rows.sort(key=lambda t: t[0], reverse=True)
        return [r for _, r in rows]

    def __len__(self) -> int:
        return len(self._servers)


class MasterProtocol(asyncio.DatagramProtocol):
    def __init__(self, registry: MasterRegistry) -> None:
        self.registry = registry
        self.transport: Optional[asyncio.DatagramTransport] = None
        self.counters = {"register_rx": 0, "list_rx": 0, "bad_rx": 0}

    def connection_made(self, transport) -> None:  # type: ignore[override]
        self.transport = transport
        log.info("master listening on %s", transport.get_extra_info("sockname"))

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        try:
            frame = decode_frame(data)
        except ProtocolError as e:
            self.counters["bad_rx"] += 1
            log.debug("bad frame from %s: %s", addr, e)
            return

        mtype = frame.header.msg_type

        if mtype == MessageType.MASTER_REGISTER:
            if not isinstance(frame.payload, MasterRegisterPayload):
                return
            self.counters["register_rx"] += 1
            if self.registry.register(addr, frame.payload):
                log.info("listed %s:%d as %r (%d/%d players)",
                         addr[0], addr[1], frame.payload.name,
                         frame.payload.players, frame.payload.max_players)
            return

        if mtype == MessageType.MASTER_LIST_REQUEST:
            if not isinstance(frame.payload, MasterListRequestPayload):
                return
            self.counters["list_rx"] += 1
            self._send_list(addr, frame.payload)
            return

        # Anything else is not our business — a master holds no game state.
        log.debug("ignoring msg 0x%04X from %s", mtype, addr)

    def _send_list(self, addr: tuple[str, int],
                   req: MasterListRequestPayload) -> None:
        rows = self.registry.entries()
        total = len(rows)
        start = min(req.offset, total)
        page = rows[start:start + MAX_SERVERS_PER_LIST_FRAME]
        resp = MasterListResponsePayload(
            nonce=req.nonce, offset=start, total=total, entries=tuple(page))
        raw = encode_frame(MessageType.MASTER_LIST_RESPONSE, 0, resp,
                           reliable=False)
        if self.transport is not None:
            self.transport.sendto(raw, addr)

    def error_received(self, exc: Exception) -> None:
        log.debug("transport error: %s", exc)


async def _prune_loop(protocol: MasterProtocol, interval_s: float = 15.0) -> None:
    while True:
        await asyncio.sleep(interval_s)
        for addr in protocol.registry.prune():
            log.info("de-listed %s:%d (no heartbeat for %.0fs)",
                     addr[0], addr[1], protocol.registry.ttl_s)


async def _stats_loop(protocol: MasterProtocol, interval_s: float = 60.0) -> None:
    while True:
        await asyncio.sleep(interval_s)
        log.info("servers=%d stats=%s", len(protocol.registry), protocol.counters)


async def run_master(host: str, port: int, log_level: str) -> None:
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )
    loop = asyncio.get_running_loop()
    registry = MasterRegistry()
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: MasterProtocol(registry), local_addr=(host, port))
    if sys.platform == "win32":
        _sock = transport.get_extra_info("socket")
        if _sock is not None:
            try:
                import ctypes
                _in = ctypes.c_ulong(0)
                _ret = ctypes.c_ulong(0)
                ctypes.windll.ws2_32.WSAIoctl(
                    ctypes.c_void_p(_sock.fileno()),
                    ctypes.c_ulong(0x9800000C),          # SIO_UDP_CONNRESET
                    ctypes.byref(_in), ctypes.c_ulong(ctypes.sizeof(_in)),
                    None, ctypes.c_ulong(0),
                    ctypes.byref(_ret), None, None)
            except Exception as e:
                log.debug("SIO_UDP_CONNRESET setup failed: %s", e)
    log.info("master ready — TTL %.0fs, page size %d",
             MASTER_ENTRY_TTL_S, MAX_SERVERS_PER_LIST_FRAME)
    try:
        await asyncio.gather(_prune_loop(protocol), _stats_loop(protocol))
    finally:
        transport.close()


def main() -> None:
    ap = argparse.ArgumentParser(description="FalloutWorld master server")
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=31338)
    ap.add_argument("--log-level", default="INFO",
                    choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    args = ap.parse_args()
    try:
        asyncio.run(run_master(args.host, args.port, args.log_level))
    except KeyboardInterrupt:
        log.info("shutdown")


if __name__ == "__main__":
    main()
