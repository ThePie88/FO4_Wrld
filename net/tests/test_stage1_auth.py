"""Stage 1 of L5 (2026-09-27): mandatory authentication with a local dev
identity for the client that has no launcher to log in through.

The server refuses anonymous HELLOs (start_server.bat sets --require-auth
from this stage). The second local test client is started from a .bat, so
`launcher/dev_identity.py` gives it a stable key, asks the server for a
challenge over UDP like MENU_PRINCIPALE does, and signs it. The tests run
that whole path against a real server socket: the minted blob logs in, the
identity is the one the key derives, and the same key comes back from disk
so the character filed under it persists.
"""
from __future__ import annotations

import asyncio
import socket
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from protocol import (  # noqa: E402
    MessageType, HelloPayload, WelcomePayload, AckPayload, encode_frame,
    decode_frame, derive_client_id,
)
from server.state import ServerState  # noqa: E402
from net.tests.test_container import _start_server_with_state  # noqa: E402
from launcher import dev_identity  # noqa: E402


async def _hello_with(sock: socket.socket, server_addr, client_id: str,
                      blob: str) -> WelcomePayload:
    pk, ch, sig = (bytes.fromhex(part) for part in blob.split(":"))
    hello = HelloPayload(client_id=client_id, client_version_major=1,
                         client_version_minor=0, auth_pubkey=pk,
                         auth_challenge=ch, auth_signature=sig,
                         display_name="DEV-T")
    sock.sendto(encode_frame(MessageType.HELLO, 0, hello, reliable=True), server_addr)
    sock.setblocking(False)
    loop = asyncio.get_running_loop()
    deadline = loop.time() + 2.0
    while loop.time() < deadline:
        try:
            data, _ = sock.recvfrom(4096)
        except BlockingIOError:
            await asyncio.sleep(0.02)
            continue
        frame = decode_frame(data)
        if frame.header.msg_type == int(MessageType.WELCOME):
            ack = AckPayload(highest_contiguous_seq=frame.header.seq, sack_bitmap=0)
            sock.sendto(encode_frame(MessageType.ACK, 0, ack, reliable=False), server_addr)
            assert isinstance(frame.payload, WelcomePayload)
            return frame.payload
    raise AssertionError("no WELCOME")


@pytest.mark.asyncio
async def test_a_dev_identity_logs_in_where_anonymous_is_refused(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    port = 31563
    monkeypatch.setattr(dev_identity, "KEY_DIR", tmp_path / "keys")
    state = ServerState()
    transport, proto = await _start_server_with_state(state, port)
    proto.require_auth = True
    proto.auth_addrs = frozenset({f"127.0.0.1:{port}"})
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    try:
        # mint() blocks on a socket; the server lives on this loop, so the
        # call runs on a thread exactly as the launcher process is separate.
        loop = asyncio.get_running_loop()
        blob, client_id = await loop.run_in_executor(
            None, dev_identity.mint, "T", "127.0.0.1", port)
        assert blob and client_id
        seed, pub = dev_identity.load_or_create_key("T")
        assert client_id == derive_client_id(pub)
        assert (tmp_path / "keys" / "T.key").is_file()

        welcome = await _hello_with(sock, ("127.0.0.1", port), client_id, blob)
        assert welcome.accepted
        session = state.get_by_peer_id(client_id)
        assert session is not None
        assert session.identity_hex == pub.hex()
        assert session.display_name == "DEV-T"
    finally:
        sock.close()
        transport.close()


@pytest.mark.asyncio
async def test_the_key_on_disk_gives_the_same_identity_again(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(dev_identity, "KEY_DIR", tmp_path / "keys")
    seed1, pub1 = dev_identity.load_or_create_key("B")
    seed2, pub2 = dev_identity.load_or_create_key("B")
    assert seed1 == seed2 and pub1 == pub2
    assert derive_client_id(pub1) == derive_client_id(pub2)
    # A fresh side gets a different key.
    _seed3, pub3 = dev_identity.load_or_create_key("A")
    assert pub3 != pub1


def test_no_server_means_no_blob(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(dev_identity, "KEY_DIR", tmp_path / "keys")
    monkeypatch.setattr(dev_identity, "CHALLENGE_ATTEMPTS", 1)
    monkeypatch.setattr(dev_identity, "CHALLENGE_TIMEOUT_S", 0.05)
    blob, client_id = dev_identity.mint("T", "127.0.0.1", 1)
    assert blob is None and client_id is None
