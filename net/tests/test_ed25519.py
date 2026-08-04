"""Tests for net/vendor/ed25519.py (vendored pure-Python RFC 8032 Ed25519).

Run:   python -m pytest net/tests/test_ed25519.py -q
"""
from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from vendor import ed25519  # noqa: E402
from vendor.ed25519 import create_keypair, sign, verify  # noqa: E402

_L = 2 ** 252 + 27742317777372353535851937790883648493


# ---------------------------------------------------------------------------
# Official RFC 8032 section 7.1 test vectors
# ---------------------------------------------------------------------------

RFC8032_VECTORS = [
    # (name, seed_hex, pubkey_hex, message_hex, signature_hex)
    (
        "TEST 1 (empty message)",
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "",
        "e5564300c360ac729086e2cc806e828a"
        "84877f1eb8e5d974d873e06522490155"
        "5fb8821590a33bacc61e39701cf9b46b"
        "d25bf5f0595bbe24655141438e7a100b",
    ),
    (
        "TEST 2 (one byte 0x72)",
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "72",
        "92a009a9f0d4cab8720e820b5f642540"
        "a2b27b5416503f8fb3762223ebdb69da"
        "085ac1e43e15996e458f3613d0f11d8c"
        "387b2eaeb4302aeeb00d291612bb0c00",
    ),
    (
        "TEST 3 (two bytes af82)",
        "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        "af82",
        "6291d657deec24024827e69c3abe01a3"
        "0ce548a284743a445e3680d7db5ac3ac"
        "18ff9b538d16f290ae67f760984dc659"
        "4a7c15e9716ed28dc027beceea1ec40a",
    ),
]


@pytest.mark.parametrize(
    "name,seed_hex,pub_hex,msg_hex,sig_hex",
    RFC8032_VECTORS,
    ids=[v[0] for v in RFC8032_VECTORS],
)
def test_rfc8032_vector_sign_exact(name, seed_hex, pub_hex, msg_hex, sig_hex):
    seed = bytes.fromhex(seed_hex)
    pub = bytes.fromhex(pub_hex)
    msg = bytes.fromhex(msg_hex)
    expected_sig = bytes.fromhex(sig_hex)

    produced = sign(seed, msg)
    assert produced == expected_sig, f"{name}: sign() does not match RFC vector"
    assert verify(pub, msg, expected_sig) is True, f"{name}: verify() failed"


def test_rfc8032_derived_pubkey_matches():
    # Derive the public key from each RFC seed via create-keypair internals:
    # sign() embeds A; cross-check with verify against the RFC pubkey.
    for name, seed_hex, pub_hex, msg_hex, sig_hex in RFC8032_VECTORS:
        seed = bytes.fromhex(seed_hex)
        pub = bytes.fromhex(pub_hex)
        # A signature made with the seed must verify under the RFC pubkey.
        sig = sign(seed, b"cross-check")
        assert verify(pub, b"cross-check", sig) is True, name


# ---------------------------------------------------------------------------
# Round-trip
# ---------------------------------------------------------------------------

def test_round_trip_random_messages():
    priv, pub = create_keypair()
    assert isinstance(priv, bytes) and len(priv) == 32
    assert isinstance(pub, bytes) and len(pub) == 32
    for size in (0, 1, 17, 256, 4096):
        msg = os.urandom(size)
        sig = sign(priv, msg)
        assert len(sig) == 64
        assert verify(pub, msg, sig) is True


def test_keypairs_are_distinct():
    (priv1, pub1), (priv2, pub2) = create_keypair(), create_keypair()
    assert priv1 != priv2
    assert pub1 != pub2


# ---------------------------------------------------------------------------
# Negative cases — all must return False, never raise
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def signed_sample():
    priv, pub = create_keypair()
    msg = b"FalloutWorld login handshake PIENUVO v0"
    sig = sign(priv, msg)
    assert verify(pub, msg, sig) is True
    return pub, msg, sig


def test_flipped_bit_in_signature_fails(signed_sample):
    pub, msg, sig = signed_sample
    for byte_index in (0, 31, 32, 63):  # touch both R and S halves
        bad = bytearray(sig)
        bad[byte_index] ^= 0x01
        assert verify(pub, msg, bytes(bad)) is False


def test_flipped_bit_in_message_fails(signed_sample):
    pub, msg, sig = signed_sample
    bad_msg = bytearray(msg)
    bad_msg[0] ^= 0x80
    assert verify(pub, bytes(bad_msg), sig) is False


def test_wrong_pubkey_fails(signed_sample):
    _pub, msg, sig = signed_sample
    _priv2, pub2 = create_keypair()
    assert verify(pub2, msg, sig) is False


def test_truncated_and_oversized_signature_returns_false(signed_sample):
    pub, msg, sig = signed_sample
    assert verify(pub, msg, sig[:63]) is False
    assert verify(pub, msg, sig + b"\x00") is False
    assert verify(pub, msg, b"") is False


def test_truncated_and_oversized_pubkey_returns_false(signed_sample):
    pub, msg, sig = signed_sample
    assert verify(pub[:31], msg, sig) is False
    assert verify(pub + b"\x00", msg, sig) is False
    assert verify(b"", msg, sig) is False


def test_garbage_inputs_return_false_not_raise(signed_sample):
    pub, msg, sig = signed_sample
    assert verify(b"\xff" * 32, msg, sig) is False          # non-canonical y
    assert verify(b"\x00" * 32, msg, sig) is False          # small-order point
    assert verify(pub, msg, b"\x00" * 64) is False
    assert verify(None, msg, sig) is False                  # type: ignore[arg-type]
    assert verify(pub, None, sig) is False                  # type: ignore[arg-type]
    assert verify(pub, msg, None) is False                  # type: ignore[arg-type]
    assert verify("not-bytes", msg, sig) is False           # type: ignore[arg-type]


def test_s_greater_or_equal_L_rejected(signed_sample):
    """Malleability: re-encode a valid signature with S' = S + L; must fail."""
    pub, msg, sig = signed_sample
    R, S = sig[:32], int.from_bytes(sig[32:], "little")
    s_plus_l = S + _L
    assert s_plus_l < 2 ** 256  # still fits in 32 bytes
    malleated = R + int.to_bytes(s_plus_l, 32, "little")
    assert malleated != sig
    assert verify(pub, msg, malleated) is False
    # Boundary: S exactly == L must also fail.
    at_l = R + int.to_bytes(_L, 32, "little")
    assert verify(pub, msg, at_l) is False


def test_sign_rejects_bad_seed():
    with pytest.raises(ValueError):
        sign(b"\x00" * 31, b"msg")
    with pytest.raises(ValueError):
        sign(b"\x00" * 33, b"msg")


# ---------------------------------------------------------------------------
# Performance sanity — verify must stay well under ~50 ms
# ---------------------------------------------------------------------------

def test_verify_performance(signed_sample):
    pub, msg, sig = signed_sample
    verify(pub, msg, sig)  # warm-up
    t0 = time.perf_counter()
    n = 5
    for _ in range(n):
        assert verify(pub, msg, sig) is True
    per_call_ms = (time.perf_counter() - t0) * 1000 / n
    assert per_call_ms < 50, f"verify too slow: {per_call_ms:.1f} ms per call"
