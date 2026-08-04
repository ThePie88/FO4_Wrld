"""v19 PIENUVO auth: challenge lifecycle + HELLO verification paths."""
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from net.protocol import (  # noqa: E402
    AUTH_SIGN_DOMAIN,
    auth_sign_message,
    HelloPayload,
    MessageType,
    AuthChallengeRequestPayload,
    AuthChallengeResponsePayload,
    encode_frame,
    decode_frame,
)
from net.server.auth import ChallengeRegistry, verify_hello_auth  # noqa: E402
from net.vendor import ed25519  # noqa: E402

from server.main import ServerProtocol  # noqa: E402
from server.state import ServerState  # noqa: E402


# ---------------------------------------------------------------- registry

def test_challenge_single_use():
    reg = ChallengeRegistry()
    ch = reg.issue(now_s=100.0)
    assert reg.consume(ch, now_s=101.0) is True
    assert reg.consume(ch, now_s=101.5) is False   # replay


def test_challenge_ttl_expiry():
    reg = ChallengeRegistry(ttl_s=180.0)
    ch = reg.issue(now_s=100.0)
    assert reg.consume(ch, now_s=100.0 + 181.0) is False


def test_challenge_unknown_rejected():
    reg = ChallengeRegistry()
    assert reg.consume(os.urandom(32), now_s=1.0) is False


def test_flood_from_one_source_cannot_evict_another_players_nonce():
    """The whole point of per-source partitioning: a single flooder used to
    wipe every pending login on the server with a few KB of traffic."""
    reg = ChallengeRegistry(max_per_source=4, max_outstanding=4096)
    victim = reg.issue(source_ip="10.0.0.1", now_s=1.0)
    for _ in range(500):
        reg.issue(source_ip="10.0.0.99", now_s=1.0)
    assert reg.is_live(victim, now_s=2.0), "flooder evicted a legit nonce"
    assert reg.consume(victim, now_s=2.0) is True


def test_source_evicts_its_own_oldest():
    reg = ChallengeRegistry(max_per_source=4)
    mine = [reg.issue(source_ip="10.0.0.1", now_s=1.0) for _ in range(6)]
    assert reg.consume(mine[0], now_s=2.0) is False   # own oldest evicted
    assert reg.consume(mine[-1], now_s=2.0) is True


def test_global_backstop_bounds_memory():
    reg = ChallengeRegistry(max_per_source=4, max_outstanding=16)
    for i in range(200):
        reg.issue(source_ip=f"10.0.{i // 250}.{i % 250}", now_s=1.0)
    assert reg.outstanding <= 16


def test_signature_bound_to_server_address():
    reg = ChallengeRegistry()
    seed, pub = ed25519.create_keypair()
    ch = reg.issue()
    # signed for the attacker's server...
    sig = ed25519.sign(seed, auth_sign_message("evil.example:31337", ch))
    # ...replayed at the victim server: refused
    r = verify_hello_auth(reg, pub, ch, sig,
                          frozenset({"good.example:31337"}))
    assert not r.ok and r.reason == "auth_wrong_server"
    # and accepted by the server it was actually meant for
    ok = verify_hello_auth(reg, pub, ch, sig,
                           frozenset({"evil.example:31337"}))
    assert ok.ok


def test_sanitize_display_name():
    from net.server.auth import sanitize_display_name as san
    # forged second log line: CR/LF must not survive into a join message
    assert san("x\r\npeer joined:") == "xpeer joined:"
    assert san("\x1b[2Jboom") == "[2Jboom"
    assert len(san("A" * 40)) == 15


# ---------------------------------------------------------------- verify

def _login_material(reg):
    # Real clock on purpose: verify_hello_auth consumes with time.monotonic(),
    # so a fabricated issue timestamp would make every challenge look expired
    # and each test would "pass" on the wrong rejection reason.
    seed, pub = ed25519.create_keypair()
    ch = reg.issue()
    sig = ed25519.sign(seed, auth_sign_message("", ch))
    return seed, pub, ch, sig


def test_verify_ok_does_not_consume():
    """verify is now non-destructive: the caller consumes only once the whole
    join succeeded, so a player bounced for server_full can retry."""
    reg = ChallengeRegistry()
    _, pub, ch, sig = _login_material(reg)
    r = verify_hello_auth(reg, pub, ch, sig)
    assert r.ok and r.identity_hex == pub.hex()
    assert verify_hello_auth(reg, pub, ch, sig).ok      # still live
    assert reg.consume(ch) is True                       # explicit burn
    assert verify_hello_auth(reg, pub, ch, sig).reason == "auth_unknown_challenge"


def test_verify_bad_signature():
    reg = ChallengeRegistry()
    _, pub, ch, sig = _login_material(reg)
    bad = bytes([sig[0] ^ 1]) + sig[1:]
    r = verify_hello_auth(reg, pub, ch, bad)
    assert not r.ok
    # the nonce survives a garbage packet — otherwise anyone who sniffs a
    # challenge can permanently deny that player's login
    assert reg.is_live(ch)


def test_verify_signature_from_other_key():
    reg = ChallengeRegistry()
    _, pub, ch, _ = _login_material(reg)
    other_seed, _ = ed25519.create_keypair()
    sig = ed25519.sign(other_seed, auth_sign_message("", ch))
    r = verify_hello_auth(reg, pub, ch, sig)
    assert not r.ok


def test_verify_domain_separation():
    """A signature over the bare challenge (no domain prefix) must fail:
    proves the domain tag is actually part of the signed message."""
    reg = ChallengeRegistry()
    seed, pub = ed25519.create_keypair()
    ch = reg.issue()
    sig = ed25519.sign(seed, ch)   # missing AUTH_SIGN_DOMAIN
    r = verify_hello_auth(reg, pub, ch, sig)
    assert not r.ok


# ------------------------------------------------------- server integration

class _Xport:
    def __init__(self):
        self.sent = []

    def sendto(self, data, addr):
        self.sent.append((data, addr))


def _mkproto(require_auth=False):
    proto = ServerProtocol(ServerState())
    proto.transport = _Xport()
    proto.require_auth = require_auth
    return proto


def _hello_frames_for(proto, addr):
    out = []
    for data, a in proto.transport.sent:
        if a != addr:
            continue
        f = decode_frame(data)
        if f.header.msg_type == MessageType.WELCOME:
            out.append(f.payload)
    return out


def _request_challenge(proto, addr=("127.0.0.1", 40000)):
    frame = encode_frame(MessageType.AUTH_CHALLENGE_REQUEST, 0,
                         AuthChallengeRequestPayload(nonce_echo=7), reliable=False)
    proto.datagram_received(frame, addr)
    data, _ = proto.transport.sent[-1]
    f = decode_frame(data)
    assert f.header.msg_type == MessageType.AUTH_CHALLENGE_RESPONSE
    assert f.payload.nonce_echo == 7 and f.payload.ttl_s > 60
    return f.payload.challenge


def _send_hello(proto, addr, pub=b"", ch=b"", sig=b"", name="", peer="player_A"):
    hello = HelloPayload(peer, 1, 0, 0, pub, ch, sig, name)
    frame = encode_frame(MessageType.HELLO, 0, hello, reliable=True)
    proto.datagram_received(frame, addr)


def test_server_authenticated_login():
    proto = _mkproto()
    seed, pub = ed25519.create_keypair()
    ch = _request_challenge(proto)
    sig = ed25519.sign(seed, auth_sign_message("", ch))
    addr = ("127.0.0.1", 40001)
    _send_hello(proto, addr, pub, ch, sig, name="Filippo")
    welcomes = _hello_frames_for(proto, addr)
    assert welcomes and welcomes[-1].accepted
    sess = proto.state.get_by_addr(addr)
    assert sess.identity_hex == pub.hex()
    assert sess.display_name == "Filippo"


def test_server_rejects_forged_signature():
    proto = _mkproto()
    _, pub = ed25519.create_keypair()
    ch = _request_challenge(proto)
    addr = ("127.0.0.1", 40002)
    _send_hello(proto, addr, pub, ch, os.urandom(64))
    welcomes = _hello_frames_for(proto, addr)
    assert welcomes and not welcomes[-1].accepted
    assert proto.state.get_by_addr(addr) is None


def test_server_rejects_replayed_challenge():
    proto = _mkproto()
    seed, pub = ed25519.create_keypair()
    ch = _request_challenge(proto)
    sig = ed25519.sign(seed, auth_sign_message("", ch))
    a1 = ("127.0.0.1", 40003)
    _send_hello(proto, a1, pub, ch, sig)
    assert proto.state.get_by_addr(a1) is not None
    # same signed challenge from a different socket = replay
    a2 = ("127.0.0.1", 40004)
    _send_hello(proto, a2, pub, ch, sig, peer="player_B")
    welcomes = _hello_frames_for(proto, a2)
    assert welcomes and not welcomes[-1].accepted


def test_server_identity_taken():
    """Two DIFFERENT valid logins with the SAME key: second is refused while
    the first is alive — one live session per identity."""
    proto = _mkproto()
    seed, pub = ed25519.create_keypair()
    a1 = ("127.0.0.1", 40005)
    ch1 = _request_challenge(proto)
    _send_hello(proto, a1, pub, ch1,
                ed25519.sign(seed, auth_sign_message("", ch1)))
    assert proto.state.get_by_addr(a1).identity_hex == pub.hex()
    a2 = ("127.0.0.1", 40006)
    ch2 = _request_challenge(proto)
    _send_hello(proto, a2, pub, ch2,
                ed25519.sign(seed, auth_sign_message("", ch2)), peer="player_B")
    welcomes = _hello_frames_for(proto, a2)
    assert welcomes and not welcomes[-1].accepted
    assert proto.state.get_by_addr(a2) is None


def test_server_anonymous_allowed_by_default():
    proto = _mkproto(require_auth=False)
    addr = ("127.0.0.1", 40007)
    _send_hello(proto, addr)
    welcomes = _hello_frames_for(proto, addr)
    assert welcomes and welcomes[-1].accepted
    assert proto.state.get_by_addr(addr).identity_hex == ""


def test_server_anonymous_rejected_with_require_auth():
    proto = _mkproto(require_auth=True)
    addr = ("127.0.0.1", 40008)
    _send_hello(proto, addr)
    welcomes = _hello_frames_for(proto, addr)
    assert welcomes and not welcomes[-1].accepted
    assert proto.state.get_by_addr(addr) is None


def test_non_ascii_display_name_is_a_protocol_error_not_a_traceback():
    """A remote peer must never raise something the frame handler does not
    catch: UnicodeDecodeError is a ValueError, so it used to escape
    decode_frame and reach the server's blanket except as a full traceback —
    one spammable packet per log storm."""
    from net.protocol import ProtocolError
    h = HelloPayload("player_A", 1, 0, 0, b"\xaa" * 32, b"\xbb" * 32,
                     b"\xcc" * 64, "ok")
    raw = bytearray(encode_frame(MessageType.HELLO, 0, h, reliable=True))
    raw[-16] = 0xFF          # first byte of display_name
    try:
        decode_frame(bytes(raw))
        assert False, "malformed name decoded silently"
    except ProtocolError:
        pass


def test_hostile_display_name_never_reaches_the_join_log():
    proto = _mkproto()
    seed, pub = ed25519.create_keypair()
    ch = _request_challenge(proto)
    sig = ed25519.sign(seed, auth_sign_message("", ch))
    addr = ("127.0.0.1", 40009)
    _send_hello(proto, addr, pub, ch, sig, name="x\r\nfake")
    sess = proto.state.get_by_addr(addr)
    assert sess is not None
    assert "\r" not in sess.display_name
    assert "\n" not in sess.display_name


def test_rejected_join_does_not_burn_the_challenge():
    """server_full used to consume the nonce, so a bounced player had to go
    back to the launcher for a fresh one instead of simply retrying."""
    proto = _mkproto()
    proto.state.max_players = 1
    seed, pub = ed25519.create_keypair()
    seed2, pub2 = ed25519.create_keypair()
    ch1 = _request_challenge(proto)
    _send_hello(proto, ("127.0.0.1", 40010), pub, ch1,
                ed25519.sign(seed, auth_sign_message("", ch1)))
    ch2 = _request_challenge(proto)
    sig2 = ed25519.sign(seed2, auth_sign_message("", ch2))
    _send_hello(proto, ("127.0.0.1", 40011), pub2, ch2, sig2, peer="player_B")
    welcomes = _hello_frames_for(proto, ("127.0.0.1", 40011))
    assert welcomes and not welcomes[-1].accepted          # server_full
    assert proto.auth_challenges.is_live(ch2), "nonce burned on a full server"
