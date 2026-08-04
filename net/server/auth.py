"""PIENUVO v0 — server-side login auth (protocol v19).

The launcher owns an Ed25519 keypair (private key encrypted on the player's
disk). Login proof is challenge-response:

    launcher                    server
       | -- AUTH_CHALLENGE_REQUEST -->|   (out-of-session, unreliable)
       |<-- AUTH_CHALLENGE_RESPONSE --|   32B single-use nonce, TTL'd
       |  ...spawns the game, which boots for ~40s...
    game                             |
       | -- HELLO + auth tail ------>|   (pubkey, challenge, signature)
       |<-- WELCOME ----------------- |   sig verified, challenge consumed

The signature covers the SERVER ADDRESS the launcher dialed, not just the
nonce (see protocol.auth_sign_message). That is what makes a proof
non-transferable: a hostile server can relay a victim server's nonce to the
player, but the proof it gets back names the attacker's address, so replaying
it at the victim fails. Address checking needs the server to know its own
public address — see `acceptable_addrs` below and the --public-addr flag.

Because the game process connects from a DIFFERENT UDP socket than the
launcher, the challenge is not bound to a source address: possession of an
unexpired unconsumed nonce plus a valid signature over (address, nonce) IS
the proof.
"""
from __future__ import annotations

import os
import time
from dataclasses import dataclass

from net.protocol import (
    AUTH_CHALLENGE_LEN,
    AUTH_PUBKEY_LEN,
    AUTH_SIGNATURE_LEN,
    auth_sign_message,
)
from net.vendor import ed25519

# The game takes ~40s to boot before its HELLO goes out; give the whole
# launcher->game handoff a comfortable margin.
CHALLENGE_TTL_S: float = 180.0
# Per-source-IP cap. The point is ISOLATION, not just a memory bound: a single
# global FIFO would let one flooder evict every other player's pending nonce
# with a few KB of spoofable traffic, silently blocking all logins. Evicting
# only within the requester's own bucket keeps the damage self-inflicted.
MAX_PER_SOURCE: int = 8
# Absolute backstop across all sources (spoofed source addresses give an
# attacker many buckets). Bounds memory, nothing more.
MAX_OUTSTANDING: int = 4096


@dataclass(frozen=True, slots=True)
class AuthResult:
    ok: bool
    # "ok" | "auth_unknown_challenge" | "auth_bad_signature" | "auth_wrong_server"
    reason: str
    identity_hex: str    # pubkey hex when ok, "" otherwise


class ChallengeRegistry:
    """Single-use login nonces, partitioned per source IP. Not thread-safe by
    design — the server is a single asyncio loop."""

    def __init__(self, ttl_s: float = CHALLENGE_TTL_S,
                 max_per_source: int = MAX_PER_SOURCE,
                 max_outstanding: int = MAX_OUTSTANDING) -> None:
        self._ttl_s = ttl_s
        self._max_per_source = max_per_source
        self._max = max_outstanding
        # challenge -> (issued_at, source_ip). Dicts iterate in insertion
        # order, so the first matching key is always the oldest.
        self._issued: dict[bytes, tuple[float, str]] = {}
        self.issued_total = 0
        self.consumed_total = 0
        self.rejected_total = 0

    def issue(self, source_ip: str = "", now_s: float | None = None) -> bytes:
        now = time.monotonic() if now_s is None else now_s
        self._prune(now)
        # Evict this source's own oldest first; only fall back to global
        # eviction when the absolute backstop is hit.
        mine = [c for c, (_, ip) in self._issued.items() if ip == source_ip]
        while len(mine) >= self._max_per_source:
            del self._issued[mine.pop(0)]
        while len(self._issued) >= self._max:
            self._issued.pop(next(iter(self._issued)))
        challenge = os.urandom(AUTH_CHALLENGE_LEN)
        self._issued[challenge] = (now, source_ip)
        self.issued_total += 1
        return challenge

    def _prune(self, now: float) -> None:
        dead = [c for c, (t, _) in self._issued.items() if (now - t) > self._ttl_s]
        for c in dead:
            del self._issued[c]

    def is_live(self, challenge: bytes, now_s: float | None = None) -> bool:
        """Non-destructive liveness check. Used BEFORE signature verification
        so a garbage packet cannot destroy someone else's pending login."""
        now = time.monotonic() if now_s is None else now_s
        rec = self._issued.get(challenge)
        return rec is not None and (now - rec[0]) <= self._ttl_s

    def consume(self, challenge: bytes, now_s: float | None = None) -> bool:
        """Burn the nonce. Call only once the login has fully succeeded —
        consuming earlier means a client bounced for `server_full` or
        `identity_taken` cannot retry without going back to the launcher."""
        now = time.monotonic() if now_s is None else now_s
        rec = self._issued.pop(challenge, None)
        if rec is None or (now - rec[0]) > self._ttl_s:
            return False
        self.consumed_total += 1
        return True

    @property
    def outstanding(self) -> int:
        return len(self._issued)

    def ttl_s(self) -> float:
        return self._ttl_s


def verify_hello_auth(registry: ChallengeRegistry,
                      pubkey: bytes, challenge: bytes, signature: bytes,
                      acceptable_addrs: frozenset[str] | None = None
                      ) -> AuthResult:
    """Check a login proof WITHOUT consuming the challenge — the caller
    consumes it after the whole join succeeds.

    `acceptable_addrs` is the set of address strings this server answers to
    (bind address plus any --public-addr). The signature is tried against each
    until one matches. None/empty = the server does not know its own public
    address, so address binding is skipped: the login still works but the
    relay attack described in the module docstring stays open. The server logs
    that state once at startup.

    Order matters: the cheap non-destructive liveness check runs first, so
    signature grinding requires a live nonce, and nonces are per-source capped."""
    if (len(pubkey) != AUTH_PUBKEY_LEN
            or len(challenge) != AUTH_CHALLENGE_LEN
            or len(signature) != AUTH_SIGNATURE_LEN):
        registry.rejected_total += 1
        return AuthResult(False, "auth_bad_signature", "")
    if not registry.is_live(challenge):
        registry.rejected_total += 1
        return AuthResult(False, "auth_unknown_challenge", "")

    addrs = list(acceptable_addrs or ())
    if not addrs:
        # Unbound mode: the message still commits to SOME address string, and
        # we cannot check which. Accept the signature over the empty address
        # only if the client also signed unbound — otherwise we would have to
        # brute-force the address, which is impossible. So we try the
        # canonical empty-address form and, failing that, report a wrong-server
        # verdict rather than silently accepting anything.
        if ed25519.verify(pubkey, auth_sign_message("", challenge), signature):
            return AuthResult(True, "ok", pubkey.hex())
        registry.rejected_total += 1
        return AuthResult(False, "auth_wrong_server", "")

    for a in addrs:
        if ed25519.verify(pubkey, auth_sign_message(a, challenge), signature):
            return AuthResult(True, "ok", pubkey.hex())
    registry.rejected_total += 1
    # Distinguishing "bad signature" from "signed for another server" would
    # require a second verify against a wildcard, so we report the more
    # informative case: a well-formed client that reaches here signed for an
    # address this server does not recognise.
    return AuthResult(False, "auth_wrong_server", "")


def sanitize_display_name(raw: str, max_len: int = 15) -> str:
    """Printable ASCII only. The name reaches server logs and other players'
    screens; CR/LF would let a client forge log lines (fake "peer joined"
    entries an admin might act on) and 0x1B would drive the operator's
    terminal. Identity is the key — the name is decoration and gets treated
    as hostile input."""
    return "".join(c for c in raw if 0x20 <= ord(c) < 0x7F)[:max_len].strip()
