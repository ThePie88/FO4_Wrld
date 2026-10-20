"""L5 realtime R5 (2026-10-16) - a place discovered asks a checkpoint.

R5 stays vanilla by the owner's decision: the engine names the place, pays
the XP and lights the icon; the server keeps no places. The client only
tells the server that a map marker turned visible (LOCATION_DISCOVERED), and
the server asks a checkpoint so a crash a minute later does not undo the
discovery. Places found in a row share one request per 30 seconds.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from protocol import (  # noqa: E402
    MessageType, ProtocolError, LocationDiscoveredPayload, _TYPE_TO_PAYLOAD_CLS, decode_frame,
)
from net.tests.test_stage3d_respawn import _server  # noqa: E402

NOW = 5_000_000.0


def _requests(proto, session):
    out = []
    for addr, raw in proto.transport.sent:
        f = decode_frame(raw)
        if addr == session.addr and f.header.msg_type == MessageType.CKPT_REQUEST:
            out.append(f.payload)
    return out


class TestPayload:
    def test_round_trip(self):
        p = LocationDiscoveredPayload(marker_form_id=0x00024A3B, name="Sanctuary Hills")
        raw = p.encode()
        assert len(raw) == 68
        back = _TYPE_TO_PAYLOAD_CLS[MessageType.LOCATION_DISCOVERED].decode(raw)
        assert back == p

    def test_a_long_name_is_cut_and_an_empty_one_survives(self):
        long = "x" * 200
        back = LocationDiscoveredPayload.decode(LocationDiscoveredPayload(1, long).encode())
        assert back.marker_form_id == 1 and back.name == "x" * 63
        assert LocationDiscoveredPayload.decode(LocationDiscoveredPayload(2).encode()).name == ""
        with pytest.raises(ProtocolError):
            LocationDiscoveredPayload.decode(b"\x00" * 10)


class TestServer:
    def test_a_discovery_asks_a_checkpoint_on_demand(self, tmp_path):
        state, proto, session, store = _server(tmp_path)
        before = len(_requests(proto, session))
        proto._handle_location_discovered(
            session, LocationDiscoveredPayload(0x24A3B, "Sanctuary Hills"), NOW)
        reqs = _requests(proto, session)
        assert len(reqs) == before + 1
        assert reqs[-1].reason == 1          # on demand

    def test_places_found_in_a_row_share_one_request(self, tmp_path):
        state, proto, session, store = _server(tmp_path)
        before = len(_requests(proto, session))
        proto._handle_location_discovered(session, LocationDiscoveredPayload(1, "A"), NOW)
        proto._handle_location_discovered(session, LocationDiscoveredPayload(2, "B"), NOW + 5_000)
        proto._handle_location_discovered(session, LocationDiscoveredPayload(3, "C"), NOW + 29_000)
        assert len(_requests(proto, session)) == before + 1
        proto._handle_location_discovered(session, LocationDiscoveredPayload(4, "D"), NOW + 31_000)
        assert len(_requests(proto, session)) == before + 2

    def test_the_wrong_payload_is_ignored(self, tmp_path):
        state, proto, session, store = _server(tmp_path)
        before = len(_requests(proto, session))
        proto._handle_location_discovered(session, object(), NOW)
        assert len(_requests(proto, session)) == before
