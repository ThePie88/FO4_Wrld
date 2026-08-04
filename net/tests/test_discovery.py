"""Discovery / server-browser: wire payloads, master registry, reconnect+capacity.

These cover the contract the in-game menu codes against, so a change that
breaks the browser fails here rather than in the game.
"""
from __future__ import annotations

import pytest

from net.protocol import (
    MAX_SERVERS_PER_LIST_FRAME,
    MasterListRequestPayload,
    MasterListResponsePayload,
    MasterRegisterPayload,
    MasterServerEntry,
    ProtocolError,
    ServerInfoRequestPayload,
    ServerInfoResponsePayload,
)
from net.master.main import MasterRegistry
from net.server.state import ServerState


# ------------------------------------------------------------------ wire


def _info(**kw) -> ServerInfoResponsePayload:
    base = dict(nonce=0xDEADBEEF, name="Wasteland HQ", motd="be nice",
                players=3, max_players=8, version_major=1, version_minor=0,
                tick_rate_hz=20, passworded=False, public=True)
    base.update(kw)
    return ServerInfoResponsePayload(**base)


def test_server_info_request_roundtrip():
    p = ServerInfoRequestPayload(nonce=12345)
    assert ServerInfoRequestPayload.decode(p.encode()) == p


def test_server_info_response_roundtrip():
    p = _info()
    assert ServerInfoResponsePayload.decode(p.encode()) == p


def test_server_info_nonce_is_echoed_verbatim():
    # The browser matches replies to rows by nonce; corrupting it would make
    # every row show another server's data.
    p = _info(nonce=0xFFFFFFFF)
    assert ServerInfoResponsePayload.decode(p.encode()).nonce == 0xFFFFFFFF


def test_server_info_empty_motd_survives():
    p = _info(motd="")
    assert ServerInfoResponsePayload.decode(p.encode()).motd == ""


def test_server_info_rejects_overlong_name():
    with pytest.raises(ProtocolError):
        _info(name="x" * 64).encode()


def test_master_register_roundtrip():
    p = MasterRegisterPayload(name="S", motd="m", players=1, max_players=4,
                              version_major=1, version_minor=0,
                              passworded=True)
    assert MasterRegisterPayload.decode(p.encode()) == p


def test_master_list_roundtrip_with_entries():
    e = [MasterServerEntry(address=f"10.0.0.{i}:31337", name=f"S{i}",
                           players=i, max_players=8, version_major=1,
                           version_minor=0, passworded=False)
         for i in range(3)]
    p = MasterListResponsePayload(nonce=7, offset=0, total=3, entries=tuple(e))
    got = MasterListResponsePayload.decode(p.encode())
    assert got == p
    assert got.entries[2].address == "10.0.0.2:31337"


def test_master_list_page_fits_one_datagram():
    e = MasterServerEntry(address="255.255.255.255:65535", name="x" * 31,
                          players=8, max_players=8, version_major=1,
                          version_minor=0, passworded=True)
    full = MasterListResponsePayload(
        nonce=1, offset=0, total=99,
        entries=tuple([e] * MAX_SERVERS_PER_LIST_FRAME))
    from net.protocol import MAX_PAYLOAD_SIZE
    assert len(full.encode()) <= MAX_PAYLOAD_SIZE


def test_master_list_refuses_overfull_page():
    e = MasterServerEntry(address="1.1.1.1:1", name="s", players=0,
                          max_players=1, version_major=1, version_minor=0,
                          passworded=False)
    too_many = tuple([e] * (MAX_SERVERS_PER_LIST_FRAME + 1))
    with pytest.raises(ProtocolError):
        MasterListResponsePayload(nonce=1, offset=0, total=1,
                                  entries=too_many).encode()


# ------------------------------------------------------------- registry


def _reg(name: str = "S", players: int = 0) -> MasterRegisterPayload:
    return MasterRegisterPayload(name=name, motd="", players=players,
                                 max_players=8, version_major=1,
                                 version_minor=0, passworded=False)


def test_registry_lists_by_source_address():
    # The listed endpoint must be where the heartbeat CAME FROM — that is the
    # address that works through NAT, and it cannot be spoofed by the payload.
    r = MasterRegistry()
    r.register(("203.0.113.9", 31337), _reg("Public"), now=0.0)
    rows = r.entries(now=1.0)
    assert len(rows) == 1
    assert rows[0].address == "203.0.113.9:31337"
    assert rows[0].name == "Public"


def test_registry_same_host_two_ports_are_two_rows():
    r = MasterRegistry()
    r.register(("10.0.0.1", 31337), _reg("A"), now=0.0)
    r.register(("10.0.0.1", 31338), _reg("B"), now=0.0)
    assert len(r.entries(now=1.0)) == 2


def test_registry_refresh_updates_player_count():
    r = MasterRegistry()
    addr = ("10.0.0.1", 31337)
    assert r.register(addr, _reg(players=0), now=0.0) is True   # new
    assert r.register(addr, _reg(players=5), now=1.0) is False  # refresh
    assert r.entries(now=1.0)[0].players == 5


def test_registry_expires_silent_server():
    # A crashed server sends no goodbye; silence must de-list it.
    r = MasterRegistry(ttl_s=90.0)
    r.register(("10.0.0.1", 31337), _reg(), now=0.0)
    assert len(r.entries(now=89.0)) == 1
    assert r.entries(now=91.0) == []


def test_registry_prune_reports_removed():
    r = MasterRegistry(ttl_s=10.0)
    r.register(("10.0.0.1", 31337), _reg(), now=0.0)
    assert r.prune(now=5.0) == []
    assert r.prune(now=20.0) == [("10.0.0.1", 31337)]
    assert len(r) == 0


# --------------------------------------------------- reconnect + capacity


def test_reconnect_from_new_port_replaces_stale_session():
    """Crash-relaunch: same peer_id, NEW source port, old session gone silent.
    Must be accepted — a dead session must not hold the id hostage."""
    st = ServerState()
    s1, why = st.accept_peer(("127.0.0.1", 5000), "player_A", (1, 0), 0.0)
    assert s1 is not None, why
    # Past peer_timeout_ms of silence: the old session is a corpse, not a rival.
    s2, why = st.accept_peer(("127.0.0.1", 6001), "player_A", (1, 0), 60_000.0)
    assert s2 is not None, why
    assert st.get_by_addr(("127.0.0.1", 6001)) is s2
    assert st.get_by_addr(("127.0.0.1", 5000)) is None   # stale one evicted
    assert len(st.all_sessions()) == 1


def test_server_full_is_rejected_with_reason():
    st = ServerState()
    st.max_players = 2
    assert st.accept_peer(("127.0.0.1", 1), "a", (1, 0), 0.0)[0] is not None
    assert st.accept_peer(("127.0.0.1", 2), "b", (1, 0), 0.0)[0] is not None
    sess, why = st.accept_peer(("127.0.0.1", 3), "c", (1, 0), 0.0)
    assert sess is None
    assert why == "server_full"


def test_rejoin_is_not_blocked_by_own_stale_slot_when_full():
    """Capacity is checked AFTER evicting the reconnecting peer's own stale
    session — otherwise a full server locks out the player who just crashed."""
    st = ServerState()
    st.max_players = 1
    assert st.accept_peer(("127.0.0.1", 1), "a", (1, 0), 0.0)[0] is not None
    sess, why = st.accept_peer(("127.0.0.1", 2), "a", (1, 0), 60_000.0)
    assert sess is not None, why


def test_max_players_zero_means_unlimited():
    st = ServerState()   # default 0
    for i in range(20):
        assert st.accept_peer(("127.0.0.1", i), f"p{i}", (1, 0), 0.0)[0] is not None


def test_live_duplicate_peer_id_still_rejected():
    """The protection that must survive the reconnect fix: a peer_id currently
    held by a client that is still heartbeating is a genuine collision."""
    st = ServerState()
    assert st.accept_peer(("1.2.3.4", 5000), "alice", (1, 0), 100.0)[0] is not None
    dup, why = st.accept_peer(("1.2.3.4", 5001), "alice", (1, 0), 200.0)
    assert dup is None
    assert why == "peer_id_taken"
