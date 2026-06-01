"""Tests for Build 65 owner-driven NPC sync registry."""
from __future__ import annotations

import pytest

from net.protocol import (
    NPCObservedPayload,
    NPCOwnerHeartbeatEntry,
    NPCUnloadPayload,
)
from net.server.ownership import (
    CLAIM_GRACE_MS,
    CLOSENESS_THRESHOLD,
    HEARTBEAT_TIMEOUT_MS,
    STICKINESS_FLOOR_MS,
    OwnershipChange,
    OwnershipRegistry,
)


def _obs(fid: int, dist_sq: float, base: int = 0xCAFE, cell: int = 0xBABE,
         x: float = 100.0, y: float = 200.0, z: float = 50.0
         ) -> NPCObservedPayload:
    return NPCObservedPayload(
        form_id=fid, base_id=base, cell_id=cell,
        pos_x=x, pos_y=y, pos_z=z,
        observer_distance_sq=dist_sq,
    )


# ----------------------------------------------------------- Rule 1: claim


def test_first_observer_claims():
    r = OwnershipRegistry()
    change = r.on_observed(_obs(0x100, 1000.0), "peerA", now_ms=1000.0)
    assert change is not None
    assert change.phase == "claim"
    assert change.new_owner_peer_id == "peerA"
    assert change.old_owner_peer_id is None
    assert change.form_id == 0x100
    assert r.is_owner("peerA", 0x100)


def test_owner_reobservation_no_change():
    r = OwnershipRegistry()
    r.on_observed(_obs(0x100, 1000.0), "peerA", now_ms=1000.0)
    # Same peer reports again, even with different distance.
    change = r.on_observed(_obs(0x100, 500.0), "peerA", now_ms=2000.0)
    assert change is None
    rec = r.get(0x100)
    assert rec is not None
    assert rec.owner_distance_sq == 500.0


# ----------------------------------------------------- Rule 2: closeness


def test_closeness_blocked_by_stickiness():
    r = OwnershipRegistry()
    r.on_observed(_obs(0x100, 10000.0), "peerA", now_ms=1000.0)
    # Peer B reports much closer, but within stickiness window.
    now = 1000.0 + STICKINESS_FLOOR_MS - 1
    change = r.on_observed(_obs(0x100, 100.0), "peerB", now_ms=now)
    assert change is None
    assert r.is_owner("peerA", 0x100)


# Build 65.c.35 — closeness-via-on_observed handoff is DISABLED in threat
# mode (on_observed only records the engagement signal; handoff is decided
# centrally in reeval_threat_owners). These tests now exercise the threat path.

_AGGRO_SQ = 6000.0 * 6000.0


def test_threat_observer_claims():
    """The in-combat OBSERVER claims the NPC — not a random peer (fixes the
    c.27 RNG 'wrong owner': A observed but the dice gave it to B)."""
    r = OwnershipRegistry()
    c = r.assign_owner_by_threat(_obs(0x100, 100.0), "peerB", now_ms=0.0)
    assert c is not None
    assert c.phase == "claim"
    assert c.new_owner_peer_id == "peerB"
    assert c.reason == "threat-observer"
    assert r.is_owner("peerB", 0x100)


def test_threat_owner_kept_while_engaged():
    """An actively-engaged owner is NOT stolen by a merely-closer challenger
    (no pure-distance collapse; engagement dominates proximity)."""
    r = OwnershipRegistry()
    npc = _obs(0x100, 100.0, x=0.0, y=0.0, z=0.0)
    r.assign_owner_by_threat(npc, "peerA", now_ms=0.0)
    r.note_owner_engagement(0x100, "peerA", anim_state=3, now_ms=2000.0)
    # B is right on top of the NPC (closer) but NOT engaged. A still fighting.
    positions = {"peerA": (1500.0, 0.0, 0.0), "peerB": (0.0, 0.0, 0.0)}
    changes = r.reeval_threat_owners(positions, _AGGRO_SQ, now_ms=2100.0)
    assert changes == []
    assert r.is_owner("peerA", 0x100)


def test_threat_handoff_when_owner_disengages():
    """Owner A stops engaging (engagement decays) and walks away; B is now
    the one fighting it → tick reeval hands off A → B."""
    r = OwnershipRegistry()
    npc = _obs(0x100, 100.0, x=0.0, y=0.0, z=0.0)
    r.assign_owner_by_threat(npc, "peerA", now_ms=0.0)
    # B engages the same NPC at t=5000 (records engagement; returns None).
    assert r.on_observed(npc, "peerB", now_ms=5000.0) is None
    # A's engagement (t=0) has decayed past the window and A walked out of
    # range; B is engaged + on top of the NPC → B's threat dominates.
    positions = {"peerA": (9000.0, 0.0, 0.0), "peerB": (0.0, 0.0, 0.0)}
    changes = r.reeval_threat_owners(positions, _AGGRO_SQ, now_ms=5000.0)
    assert len(changes) == 1
    assert changes[0].phase == "handoff"
    assert changes[0].old_owner_peer_id == "peerA"
    assert changes[0].new_owner_peer_id == "peerB"
    assert r.is_owner("peerB", 0x100)


def test_closeness_blocked_by_threshold():
    r = OwnershipRegistry()
    r.on_observed(_obs(0x100, 10000.0), "peerA", now_ms=1000.0)
    now = 1000.0 + STICKINESS_FLOOR_MS + 100
    # Peer B only marginally closer (8000 vs threshold 6000).
    change = r.on_observed(_obs(0x100, 8000.0), "peerB", now_ms=now)
    assert change is None
    assert r.is_owner("peerA", 0x100)


def test_epoch_increments_on_handoff():
    r = OwnershipRegistry()
    npc = _obs(0x100, 100.0, x=0.0, y=0.0, z=0.0)
    e1 = r.assign_owner_by_threat(npc, "peerA", now_ms=0.0).new_epoch
    r.on_observed(npc, "peerB", now_ms=5000.0)
    positions = {"peerA": (9000.0, 0.0, 0.0), "peerB": (0.0, 0.0, 0.0)}
    changes = r.reeval_threat_owners(positions, 6000.0 * 6000.0, now_ms=5000.0)
    assert len(changes) == 1
    assert changes[0].new_epoch > e1


# ----------------------------------------------------------- Rule 5: health


def test_heartbeat_refreshes_last_seen():
    r = OwnershipRegistry()
    r.on_observed(_obs(0x100, 1000.0), "peerA", now_ms=0)
    # 1 sec later, heartbeat.
    r.on_heartbeat(
        [NPCOwnerHeartbeatEntry(form_id=0x100, epoch=r.get(0x100).epoch)],
        "peerA", now_ms=1000.0,
    )
    rec = r.get(0x100)
    assert rec.last_heartbeat_ms == 1000.0


def test_heartbeat_ignores_stale_epoch():
    r = OwnershipRegistry()
    r.on_observed(_obs(0x100, 1000.0), "peerA", now_ms=0)
    bad_epoch = r.get(0x100).epoch + 99
    r.on_heartbeat(
        [NPCOwnerHeartbeatEntry(form_id=0x100, epoch=bad_epoch)],
        "peerA", now_ms=1000.0,
    )
    # last_heartbeat_ms unchanged (still 0 from claim).
    assert r.get(0x100).last_heartbeat_ms == 0.0


def test_heartbeat_ignores_wrong_owner():
    r = OwnershipRegistry()
    r.on_observed(_obs(0x100, 1000.0), "peerA", now_ms=0)
    epoch = r.get(0x100).epoch
    r.on_heartbeat(
        [NPCOwnerHeartbeatEntry(form_id=0x100, epoch=epoch)],
        "peerB",  # not the owner
        now_ms=1000.0,
    )
    assert r.get(0x100).last_heartbeat_ms == 0.0


def test_health_gate_releases_stale_owner():
    r = OwnershipRegistry()
    r.on_observed(_obs(0x100, 1000.0), "peerA", now_ms=0)
    # No heartbeat. Tick after timeout.
    changes = r.periodic_tick(now_ms=HEARTBEAT_TIMEOUT_MS + 100)
    assert len(changes) == 1
    assert changes[0].phase == "release"
    assert changes[0].old_owner_peer_id == "peerA"
    assert changes[0].new_owner_peer_id is None
    assert r.get(0x100) is None


def test_health_gate_keeps_fresh_owner():
    r = OwnershipRegistry()
    r.on_observed(_obs(0x100, 1000.0), "peerA", now_ms=0)
    # Heartbeat keeps it alive.
    epoch = r.get(0x100).epoch
    for t in range(0, int(HEARTBEAT_TIMEOUT_MS) * 3, 500):
        r.on_heartbeat(
            [NPCOwnerHeartbeatEntry(form_id=0x100, epoch=epoch)],
            "peerA", now_ms=float(t),
        )
    changes = r.periodic_tick(now_ms=HEARTBEAT_TIMEOUT_MS * 3)
    assert changes == []
    assert r.is_owner("peerA", 0x100)


# ----------------------------------------------------------- unload + disco


def test_unload_releases_owner():
    r = OwnershipRegistry()
    r.on_observed(_obs(0x100, 1000.0), "peerA", now_ms=0)
    epoch = r.get(0x100).epoch
    change = r.on_unload(
        NPCUnloadPayload(
            form_id=0x100, epoch=epoch,
            last_pos_x=1.0, last_pos_y=2.0, last_pos_z=3.0,
            last_yaw=0.0, last_anim_state=0, last_hp_pct=100,
        ),
        "peerA", now_ms=2000.0,
    )
    assert change is not None
    assert change.phase == "release"
    assert r.get(0x100) is None


def test_unload_from_non_owner_ignored():
    r = OwnershipRegistry()
    r.on_observed(_obs(0x100, 1000.0), "peerA", now_ms=0)
    epoch = r.get(0x100).epoch
    change = r.on_unload(
        NPCUnloadPayload(
            form_id=0x100, epoch=epoch,
            last_pos_x=0, last_pos_y=0, last_pos_z=0,
            last_yaw=0, last_anim_state=0, last_hp_pct=100,
        ),
        "peerB", now_ms=2000.0,
    )
    assert change is None
    assert r.is_owner("peerA", 0x100)


def test_unload_stale_epoch_ignored():
    r = OwnershipRegistry()
    r.on_observed(_obs(0x100, 1000.0), "peerA", now_ms=0)
    change = r.on_unload(
        NPCUnloadPayload(
            form_id=0x100, epoch=99,  # wrong
            last_pos_x=0, last_pos_y=0, last_pos_z=0,
            last_yaw=0, last_anim_state=0, last_hp_pct=100,
        ),
        "peerA", now_ms=2000.0,
    )
    assert change is None


def test_peer_disconnect_releases_all_owned():
    r = OwnershipRegistry()
    r.on_observed(_obs(0x100, 1000.0), "peerA", now_ms=0)
    r.on_observed(_obs(0x101, 1000.0), "peerA", now_ms=0)
    r.on_observed(_obs(0x102, 1000.0), "peerB", now_ms=0)
    changes = r.on_peer_disconnect("peerA", now_ms=5000.0)
    assert len(changes) == 2
    fids = {c.form_id for c in changes}
    assert fids == {0x100, 0x101}
    assert all(c.phase == "release" for c in changes)
    assert all(c.old_owner_peer_id == "peerA" for c in changes)
    # peerB's NPC untouched.
    assert r.is_owner("peerB", 0x102)


# ----------------------------------------------------------- bootstrap iter


def test_iter_records_stable_order():
    r = OwnershipRegistry()
    r.on_observed(_obs(0x300, 1.0), "peerA", now_ms=0)
    r.on_observed(_obs(0x100, 1.0), "peerB", now_ms=0)
    r.on_observed(_obs(0x200, 1.0), "peerA", now_ms=0)
    fids = [rec.form_id for rec in r.iter_records()]
    assert fids == [0x100, 0x200, 0x300]


def test_owned_by_subset():
    r = OwnershipRegistry()
    r.on_observed(_obs(0x100, 1.0), "peerA", now_ms=0)
    r.on_observed(_obs(0x101, 1.0), "peerA", now_ms=0)
    r.on_observed(_obs(0x200, 1.0), "peerB", now_ms=0)
    assert set(r.owned_by("peerA")) == {0x100, 0x101}
    assert set(r.owned_by("peerB")) == {0x200}
    assert r.owned_by("peerC") == []
