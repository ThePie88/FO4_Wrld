r"""A stable local identity for a client started without the external
launcher (L5 stage 1, 2026-09-27).

The server now requires an authenticated HELLO (--require-auth): every
persistent record is filed under the identity a key derives, and characters
are about to persist. Player A logs in through MENU_PRINCIPALE, which mints
the login proof; the second local client is started from a .bat and had no
key at all, so it was anonymous and would be refused.

This module gives such a client a key of its own, kept in
`launcher/.dev_keys/<side>.key` (gitignored: it is a private key), asks the
server for a login challenge over UDP exactly as MENU_PRINCIPALE does, signs
it over the address being dialed and returns the `pk:ch:sig` blob the DLL
forwards in HELLO, plus the client_id the key derives. The identity is
stable across launches, so the character, appearance and presence filed
under it survive like any other player's.

It is a development convenience, not a login: anyone with the file IS that
player. Delete the file to become somebody new.
"""
from __future__ import annotations

import os
import secrets
import socket
import sys
import time
from pathlib import Path
from typing import Optional

from launcher import config

sys.path.insert(0, str(config.REPO_ROOT / "net"))

from protocol import (  # noqa: E402
    MessageType, AuthChallengeRequestPayload, AuthChallengeResponsePayload,
    auth_sign_message, derive_client_id, encode_frame, decode_frame,
    ProtocolError,
)
from vendor import ed25519  # noqa: E402

KEY_DIR: Path = config.REPO_ROOT / "launcher" / ".dev_keys"
CHALLENGE_ATTEMPTS: int = 3
CHALLENGE_TIMEOUT_S: float = 1.0


def key_path(side_name: str) -> Path:
    return KEY_DIR / f"{side_name.upper()}.key"


def load_or_create_key(side_name: str) -> tuple[bytes, bytes]:
    """(seed, public key). The seed is created on first use and never
    rotated by this code."""
    path = key_path(side_name)
    if path.is_file():
        seed = bytes.fromhex(path.read_text(encoding="ascii").strip())
        if len(seed) != 32:
            raise ValueError(f"{path}: not a 32-byte seed")
        return seed, _public_of(seed)
    KEY_DIR.mkdir(parents=True, exist_ok=True)
    seed, pub = ed25519.create_keypair()
    tmp = path.with_suffix(".key.tmp")
    tmp.write_text(seed.hex(), encoding="ascii")
    os.replace(tmp, path)
    return seed, pub


def _public_of(seed: bytes) -> bytes:
    """The public key of a stored seed: the derivation create_keypair runs
    on the seed it draws, applied to one read back from disk."""
    a, _prefix = ed25519._secret_expand(seed)
    return ed25519._point_compress(ed25519._scalar_mult(a, ed25519._B))


def request_challenge(host: str, port: int,
                      attempts: int = CHALLENGE_ATTEMPTS,
                      timeout_s: float = CHALLENGE_TIMEOUT_S) -> Optional[bytes]:
    """Ask the server for a login nonce. None if it never answers."""
    echo = secrets.randbits(64)
    request = encode_frame(MessageType.AUTH_CHALLENGE_REQUEST, 0,
                           AuthChallengeRequestPayload(nonce_echo=echo),
                           reliable=False)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout_s)
        for _ in range(attempts):
            try:
                sock.sendto(request, (host, port))
            except OSError:
                continue
            deadline = time.monotonic() + timeout_s
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
                if (isinstance(payload, AuthChallengeResponsePayload)
                        and payload.nonce_echo == echo):
                    return payload.challenge
        return None
    finally:
        sock.close()


def mint(side_name: str, host: str, port: int) -> tuple[Optional[str], Optional[str]]:
    """(auth_blob, client_id) for this side against host:port, or (None,
    None) when the server did not answer the challenge request. The blob is
    `pubkeyhex:challengehex:sighex`, what fw_config.ini's auth_blob takes."""
    seed, pub = load_or_create_key(side_name)
    challenge = request_challenge(host, port)
    if challenge is None:
        return None, None
    signature = ed25519.sign(seed, auth_sign_message(f"{host}:{port}", challenge))
    blob = f"{pub.hex()}:{challenge.hex()}:{signature.hex()}"
    return blob, derive_client_id(pub)
