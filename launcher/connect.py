"""Connect flow for the external launcher (FiveM-style).

The launcher spawns `FoM.exe --connect <ip:port>`, reads our stdout LINE BY
LINE and mirrors each event into its overlay. So stdout is a machine channel:
one compact JSON object per line, flushed immediately. Human/debug logging goes
to stderr, which the launcher may show or ignore — it must never have to parse
around it.

The launcher displays `message` VERBATIM, so those strings are user-facing
copy, not diagnostics.

Events emitted, in order:
    {"event":"starting","server":"1.2.3.4:31337"}
    {"event":"probing","server":"1.2.3.4:31337"}
    {"event":"server_ok","name":"...","motd":"...","players":2,"max_players":8,
     "version":"1.0","ping_ms":14}
    {"event":"launching","side":"A"}
    {"event":"game_launched","pid":12345}
    {"event":"error","code":"...","message":"..."}

Error codes (the four the launcher already maps):
    server_unreachable  no reply to the info probe
    version_mismatch    server major version differs from this client's
    server_full         players >= max_players at probe time
    game_not_found      the game executable/install is missing

Why we probe BEFORE launching: Fallout 4 takes tens of seconds to reach the
main menu, and a failed join surfaces as an unexplained silence in-game. One
UDP round-trip up front turns "it didn't work" into a precise message while the
player is still looking at the launcher.
"""
from __future__ import annotations

import json
import socket
import sys
import time
from typing import Optional

from net.protocol import (
    MessageType,
    ProtocolError,
    ServerInfoRequestPayload,
    ServerInfoResponsePayload,
    decode_frame,
    encode_frame,
)

CLIENT_VERSION_MAJOR: int = 1
"""Must track fw_native/src/net/client.cpp (`h.client_version_major = 1`).
The server refuses a HELLO whose major differs, so probing it here lets us say
so plainly instead of letting the join fail silently later."""

PROBE_TIMEOUT_S: float = 1.5
PROBE_ATTEMPTS: int = 3


def emit(event: str, **fields) -> None:
    """One JSON object per line on stdout, flushed — the launcher reads it live."""
    payload = {"event": event}
    payload.update(fields)
    sys.stdout.write(json.dumps(payload, ensure_ascii=False) + "\n")
    sys.stdout.flush()


def emit_error(code: str, message: str) -> None:
    emit("error", code=code, message=message)


def parse_address(addr: str) -> Optional[tuple[str, int]]:
    """"host:port" -> (host, port). None if unparseable."""
    host, sep, port_s = addr.rpartition(":")
    if not sep or not host:
        return None
    try:
        port = int(port_s)
    except ValueError:
        return None
    if not (0 < port < 65536):
        return None
    return (host, port)


class ProbeResult:
    __slots__ = ("info", "ping_ms")

    def __init__(self, info: ServerInfoResponsePayload, ping_ms: int) -> None:
        self.info = info
        self.ping_ms = ping_ms


def probe_server(host: str, port: int,
                 attempts: int = PROBE_ATTEMPTS,
                 timeout_s: float = PROBE_TIMEOUT_S) -> Optional[ProbeResult]:
    """Ask a server who it is, without joining. None if it never answers.

    Retries because this is deliberately unreliable UDP: a dropped datagram is
    normal and costs one retry, not a failure.
    """
    nonce = int.from_bytes(socket.gethostname().encode()[:2] or b"\x01\x02",
                           "little") ^ (int(time.time()) & 0xFFFF)
    nonce &= 0xFFFFFFFF
    request = encode_frame(MessageType.SERVER_INFO_REQUEST, 0,
                           ServerInfoRequestPayload(nonce=nonce),
                           reliable=False)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout_s)
        for _ in range(attempts):
            sent_at = time.monotonic()
            try:
                sock.sendto(request, (host, port))
            except OSError:
                continue          # host unresolvable / network down — retry
            deadline = sent_at + timeout_s
            while time.monotonic() < deadline:
                try:
                    data, _ = sock.recvfrom(2048)
                except (socket.timeout, OSError):
                    break
                try:
                    frame = decode_frame(data)
                except ProtocolError:
                    continue
                payload = frame.payload
                if not isinstance(payload, ServerInfoResponsePayload):
                    continue
                if payload.nonce != nonce:
                    continue      # a stale reply to someone else's probe
                ping_ms = int((time.monotonic() - sent_at) * 1000.0)
                return ProbeResult(payload, ping_ms)
        return None
    finally:
        sock.close()


def preflight(address: str) -> Optional[ProbeResult]:
    """Probe + validate. Emits the precise error and returns None on failure."""
    parsed = parse_address(address)
    if parsed is None:
        emit_error("server_unreachable",
                   f"Indirizzo non valido: '{address}'. "
                   f"Usa il formato indirizzo:porta.")
        return None
    host, port = parsed

    emit("probing", server=f"{host}:{port}")
    result = probe_server(host, port)
    if result is None:
        emit_error("server_unreachable",
                   "Il server non risponde. Controlla che sia acceso e che "
                   "l'indirizzo e la porta siano corretti.")
        return None

    info = result.info
    if info.version_major != CLIENT_VERSION_MAJOR:
        emit_error("version_mismatch",
                   f"Versione incompatibile: il server richiede la "
                   f"{info.version_major}.{info.version_minor}, tu hai la "
                   f"{CLIENT_VERSION_MAJOR}.0. Aggiorna per entrare.")
        return None

    if info.max_players and info.players >= info.max_players:
        emit_error("server_full",
                   f"Server pieno ({info.players}/{info.max_players} "
                   f"giocatori). Riprova tra poco.")
        return None

    emit("server_ok",
         name=info.name, motd=info.motd,
         players=info.players, max_players=info.max_players,
         version=f"{info.version_major}.{info.version_minor}",
         ping_ms=result.ping_ms)
    return result
