"""Build 65 — Owner-driven NPC sync registry.

Per `re/agents_20/SOLVER_02_owner_driven.md`, the server is a relay+
arbiter, not a simulator. For each tracked NPC, the registry holds a
single authoritative owner (a connected peer). The owner client runs
full vanilla engine AI for that NPC and broadcasts the observable state
(pos/yaw/anim/fire/death) to non-owners. Non-owners suppress local AI
for tracked NPCs and apply the broadcast state.

Phase A scope (this file):
  - In-memory `OwnershipRegistry`.
  - Election rules 1+2: cell-first claim, closeness with 3s stickiness.
  - Health gate via heartbeat last-seen.
  - Peer disconnect → forced re-election.
  - Single-phase ownership announce (Phase 2 only — broadcast new owner).
    The reliable PHASE_1/RELEASE_ACK dance is deferred to a follow-up
    wedge; for the MVP we accept ~1 frame of overlap on handoff.

Threading: not thread-safe by itself. Callers (see `main.py`) hold the
asyncio-equivalent serialization implied by the single event loop. Same
pattern as `raider_brain.RaiderBrain`.

Public API:
  - `on_observed(payload, peer_id, now_ms) -> OwnershipChange | None`
  - `on_unload(payload, peer_id, now_ms) -> OwnershipChange | None`
  - `on_heartbeat(entries, peer_id, now_ms) -> None`
  - `on_peer_disconnect(peer_id, now_ms, candidates) -> list[OwnershipChange]`
  - `periodic_tick(now_ms, peers) -> list[OwnershipChange]`
  - `iter_records() -> Iterator[NPCOwnership]`  (for bootstrap snapshot)

Returned `OwnershipChange` objects are what `main.py` translates into
`NPC_OWNERSHIP_HANDOFF_PHASE_2` broadcasts.
"""
from __future__ import annotations

import logging
import math
import random
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator, Optional

# Server modules use the `from protocol import ...` pattern with sys.path
# augmented (see state.py for precedent). This keeps ownership.py
# importable by both `python -m net.server.main` and by pytest collected
# from the repo root.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from protocol import (  # noqa: E402
    NPCObservedPayload,
    NPCOwnerHeartbeatEntry,
    NPCUnloadPayload,
)


log = logging.getLogger("ownership")


# ---------------------------------------------------------------- tunables

# Time, in ms, an owner must hold ownership before closeness re-evaluation
# can transfer it to a "closer" peer. Prevents oscillation.
#
# Build 65.c.15 — bumped 3000 → 8000 ms. With 3 s, two peers in the same
# cell (e.g. both fighting Concord raiders from different angles) were
# triggering handoff every 3-5 s as distances fluctuated, producing the
# "sliding/flickering raider" symptom: STATE_FROM_OWNER from the new
# owner competing with the old owner's still-running engine AI integration
# until the old owner's client received PHASE_2 and bailed. 8 s gives a
# real combat encounter time to stabilise around a single owner.
STICKINESS_FLOOR_MS: float = 8000.0

# A challenger must be at least this much closer (linear distance squared
# ratio) than the current owner to win a closeness re-election.
#
# Build 65.c.15 — tightened 0.60 → 0.30. With 0.60 the challenger only
# needed √0.60 ≈ 77 % of the owner's distance to steal — easy to hit when
# both peers are inside the same Concord cell brawling. 0.30 requires
# √0.30 ≈ 55 % — challenger must be roughly halfway closer than the
# owner. Real handoffs (e.g. owner walks away, B stays at the NPC) still
# fire; small back-and-forth jitter no longer does.
CLOSENESS_THRESHOLD: float = 0.30   # challenger.dist_sq < 0.30 × owner.dist_sq

# If the owner's heartbeat is older than this, the registry forces a
# re-election (Rule 5 health gate). Set above the 2 Hz heartbeat period
# (500 ms) with comfortable slack for jittery networks.
HEARTBEAT_TIMEOUT_MS: float = 2500.0

# Grace period after a peer first claims an NPC: no other peer can
# preempt during this window. Avoids cell-load contention spam.
CLAIM_GRACE_MS: float = 500.0

# Build 65.c.27 — RNG AGGRO via ownership=target.
#
# When True, ownership is decided by `assign_owner_rng`: each raider
# independently coin-flips its owner among connected peers within aggro
# range. Owner = the player the raider will attack (its vanilla AI
# naturally aggros the owner's LOCAL player; non-owners mirror via
# STATE_FROM_OWNER → raider appears attacking the owner's ghost on their
# screen). This is the ONLY teardown-safe path (the engine only ever puts
# a live local PlayerCharacter in the CombatGroup it later cleans up — no
# transient ghost handle ever enters it, so the cell-unload decref walker
# never faults — confirmed B65_c27_JUDGE.md V3).
#
# "Static" for now: once assigned, ownership is STICKY — no closeness
# re-election, no combat-driven handoff. Both are SUPPRESSED below when
# this flag is set. Dynamic re-roll (periodic re-randomize / threat-based)
# is a future wedge.
STATIC_RNG_OWNERSHIP: bool = True

# Build 65.c.23 — Combat-driven handoff window.
#
# When a non-owner peer reports NPC_ENGAGEMENT_CLAIM, the registry checks
# if the current owner has been REPORTING engagement (= STATE_FROM_OWNER
# entries with anim_state >= 3 = AIMING/FIRING/STAGGER bits). If the
# owner's last engagement is older than this threshold, the registry
# does a combat-driven handoff to the claimer.
#
# Diagnosed by Agent 1 forensics of c.22 test: A claimed all 5 raiders
# (cell-first observation) but A never reached InCombat → emitted
# anim_state=0 for the whole 14s test → meanwhile B's vanilla AI was
# actually engaging 0x46458/0x46459 → ownership was on the wrong peer.
#
# 3 s is wider than the 2.5 s heartbeat health-gate so we don't race a
# stale-heartbeat forced-release: a peer that's owner AND actively
# fighting will refresh last_engaged_ms every drain (~10 Hz from the
# DLL's record_owned_state when its actor flag 0x4000 is set).
ENGAGEMENT_OWNERSHIP_GRACE_MS: float = 3000.0

# Stickiness for combat-driven handoff after it has fired. Prevents
# ping-pong if both peers' engines latch InCombat on the same NPC at the
# same moment (both will send claims; first wins, second is ignored for
# this window even if owner's last_engaged_ms is stale).
#
# Smaller than STICKINESS_FLOOR_MS because combat-driven handoff is a
# stronger signal than closeness — we WANT it to flip quickly when the
# real fighter shifts (e.g. one peer dies / disengages / steps back).
COMBAT_HANDOFF_STICKINESS_MS: float = 1500.0


# ---------------------------------------------------------------- c.35 THREAT
#
# Build 65.c.35 — THREAT-TABLE ownership (replaces RNG selection).
#
# Real MP games use a server-side threat table: each NPC holds a threat
# value per player (distance, damage, heal/taunt, LOS, recency) and attacks
# the highest-threat one. Creation Engine is NOT server-authoritative (each
# client runs its own copy of the NPC's AI), so we can't run the AI on the
# server — but in our owner-driven model the "threat table" reduces to ONE
# decision: WHICH client we assign as owner = which player the NPC attacks
# (the owner's vanilla AI aggros its LOCAL player; non-owners mirror).
#
# So c.35 = assign/keep ownership = the peer with the highest THREAT, where
# threat is composed from the inputs the server actually has:
#   - engagement (PRIMARY): the peer is actively observing/claiming the NPC
#     in-combat. NPC_OBSERVED is InCombat-gated, so an observation means that
#     peer's engine has LOS + perceived + aggro'd the NPC — our proxy for the
#     "LOS" input real games use. Decays over THREAT_ENGAGE_WINDOW_MS.
#   - distance (TIE-BREAK): closer = higher, from POS_STATE player positions.
#   - damage (FUTURE TODO): once we add damage-sync, the player dealing the
#     most damage holds aggro even if not closest = the real "tank holds
#     threat" behaviour. Plug a w_damage * damage_score term into
#     `_compute_threat` — NO re-architecture needed; the table is already here.
#
# Engagement is weighted FAR above distance so the NPC fights "whoever is
# actually engaging it", not merely "whoever is nearest" (avoids the pure-
# distance collapse: A 1 ft closer to everything ≠ A owns everything — only
# the peer whose engine is fighting it does). Distance only breaks ties among
# equally-(non-)engaged peers.
THREAT_OWNERSHIP: bool = True       # master switch: threat table vs legacy RNG

THREAT_W_ENGAGE: float = 10.0       # weight of active engagement (combat-target)
THREAT_W_DISTANCE: float = 1.0      # weight of proximity (tie-break)
# c.39b — damage is the DOMINANT real-threat input: ownership follows whoever
# actually deals the most damage. The damage term is a per-peer decayed sum
# normalized to [0,1] (full at DAMAGE_NORM accumulated), so W_DAMAGE > W_ENGAGE
# means "the one hitting it hardest wins, even if both are engaged" (breaks the
# both-engaged tie that combat-target alone can't resolve — the bossfight case).
THREAT_W_DAMAGE: float = 30.0           # c.40a: 25→30 (keep damage dominant)
# c.40a-fix — NORM back to 80 + the term is NO LONGER CAPPED at 1.0 (see
# _damage_term). The c.40a bump to 400 killed SHORT-BURST handoffs: a few hits
# (~30 dmg) gave term 0.075 → too small to clear the hysteresis, so aggro never
# moved (C2's sim assumed SUSTAINED hundreds-of-dmg DPS; real play is bursts).
# Removing the cap fixes BOTH at once: term = decayed/NORM scales linearly with
# recent damage — a burst flips (30/80≈0.38 → +11 threat), and in a sustained
# bossfight the bigger-DPS player keeps a proportionally bigger (uncapped) term
# instead of both saturating to a tie. The 4 s decay window bounds it to ~DPS×4.
THREAT_DAMAGE_NORM: float = 80.0        # damage that = term 1.0 (term may exceed 1)
THREAT_DAMAGE_WINDOW_MS: float = 4000.0  # damage recency decay window

# Engagement freshness: an observation/claim is "full threat" at t=0 and
# decays linearly to 0 over this window. Build 65.c.36a — widened 3000→4500
# so a brief LOS gap doesn't drop the real fighter's engage term to 0 and let
# a merely-closer peer steal (8-agent A2).
THREAT_ENGAGE_WINDOW_MS: float = 4500.0

# Hysteresis (anti-flicker), evaluated centrally in reeval_threat_owners:
#   - MIN_HOLD: an owner can't be displaced by threat in its first N ms.
#   - FLIP_MARGIN: a challenger must have threat ≥ owner_threat * MARGIN.
#   - MIN_ABS_DELTA: AND best−owner must exceed this ABSOLUTE floor. This is
#     the real anti-thrash: proximity alone contributes ≤ W_DISTANCE (~1), so a
#     delta ≥ 3 can only come from an ENGAGEMENT difference (W_ENGAGE=10). Thus
#     ownership flips on "who is actually fighting it", never on sub-unit
#     proximity noise (8-agent A2 — logs showed flips at 0.09 vs 0.07 etc.).
# Build 65.c.36a — MIN_HOLD 1500→3000, FLIP_MARGIN 1.25→2.0, + MIN_ABS_DELTA.
# c.39a — c.36a was over-tightened (it choked EVERY swap) because the real bug
# was a dead claim trigger (non-owners never signalled engagement), not loose
# hysteresis. With the claim fixed (combat-target) + damage threat (c.39b)
# creating big clean gaps, relax HOLD for responsiveness; keep ABS_DELTA so
# distance-jitter (~1) still can't flip — only engagement(10)/damage(25) can.
# c.40a — joint hysteresis sweep (C2): with NORM=400, FLIP=1.3 is the knee —
# B must out-damage A by ~55% sustained to steal aggro (a clear bigger-threat,
# not noise), while sub-second alternation yields ZERO handoffs. MIN_HOLD 2000
# guarantees an owner holds ≥2s. MIN_ABS_DELTA stays 3 (distance-jitter ≤1 can
# never flip — only engagement(10)/damage(30) clears it).
THREAT_MIN_HOLD_MS: float = 2000.0   # c.40a: 1500→2000
THREAT_FLIP_MARGIN: float = 1.3      # c.40a: 1.5→1.3
THREAT_MIN_ABS_DELTA: float = 3.0

# Build 65.c.45 (FIX 1b) — explicit anti-thrash COMMITMENT WINDOW, layered on top
# of the hard MIN_HOLD floor. For [MIN_HOLD, COMMIT_WINDOW_MS) after an owner
# takes a raider, a challenger may flip it ONLY with a CLEAR lead (best−owner ≥
# COMMIT_ABS_DELTA) — a decisively bigger gap than the steady ABS_DELTA(3). After
# COMMIT_WINDOW_MS the normal steady gates resume. Because this band is STRICTLY
# STRONGER than the steady gate and the steady gate is unchanged, enabling it can
# only REDUCE handoffs, never delay a legit switch that occurs after the window.
# It closes the "post-flip parity bounce": one isolated non-owner burst (a 20-dmg
# hit ≈ +7.5 threat) can no longer flip a freshly-handed raider back. 3500ms ≈
# the THREAT_DAMAGE_WINDOW_MS(4000) horizon, so by the band's end the loser's
# residual banked damage has decayed (any lead left is a real current lead).
# COMMIT_ABS_DELTA=8 sits just above a single burst's term + far above the
# distance ceiling(1). DISABLE: set COMMIT_WINDOW_MS = THREAT_MIN_HOLD_MS.
THREAT_COMMIT_WINDOW_MS: float = 3500.0
THREAT_COMMIT_ABS_DELTA: float = 8.0


# ---------------------------------------------------------------- records


@dataclass(slots=True)
class NPCOwnership:
    """Per-NPC ownership record."""
    form_id: int
    owner_peer_id: str
    epoch: int                       # incremented on every owner change
    last_heartbeat_ms: float         # peer.proof-of-life
    since_ms: float                  # when current owner took ownership

    # Last-known state (used during peer disconnect bootstrap / unload).
    base_id: int = 0
    cell_id: int = 0
    last_pos_x: float = 0.0
    last_pos_y: float = 0.0
    last_pos_z: float = 0.0

    # Distance metrics from the owner's last NPC_OBSERVED report. Drives
    # closeness re-election decisions.
    owner_distance_sq: float = math.inf

    # Build 65.c.23 — Last time the owner reported anim_state >= 3 in a
    # STATE_FROM_OWNER frame. Combat-driven handoff uses this: when a
    # non-owner sends NPC_ENGAGEMENT_CLAIM and (now - last_engaged_ms) >
    # ENGAGEMENT_OWNERSHIP_GRACE_MS, ownership transfers to the claimer.
    # 0.0 = owner has never reported engagement (just-claimed NPC).
    last_engaged_ms: float = 0.0

    # Build 65.c.28 — provisional flag for the RNG re-roll fix.
    #   True  = assigned when fewer than 2 peers were in aggro range
    #           (typically only the first-approaching player). Eligible for
    #           a ONE-TIME re-roll once a 2nd peer enters range.
    #   False = assigned with ≥2 candidates (already a fair coin-flip) OR
    #           already re-rolled → FINAL, sticky, never re-rolled again
    #           (honours the "static RNG" intent).
    provisional: bool = False

    # Build 65.c.35 — per-peer engagement timestamps for the threat table.
    #   peer_id → last ms that peer was observed/claimed/owner-engaged this
    #   NPC in-combat (= LOS+aggro proxy). Read by `_compute_threat`, decays
    #   over THREAT_ENGAGE_WINDOW_MS. (Future: a parallel per-peer damage dict
    #   for the damage-sync threat input.)
    threat_engaged: dict[str, float] = field(default_factory=dict)

    # c.39b — per-peer DAMAGE accumulator for the threat table. peer_id →
    # (decayed_sum, last_update_ms). Each NPC_DAMAGE_CLAIM adds to the sum after
    # decaying it toward 0 over THREAT_DAMAGE_WINDOW_MS. `_compute_threat` reads
    # it as the dominant term so ownership/aggro follows whoever hits hardest.
    threat_damage: dict[str, tuple[float, float]] = field(default_factory=dict)

    # N3 (shared HP) — server-authoritative HP pool, keyed by this fid (so it
    # survives ownership handoffs). Bootstrapped from the first damage claim
    # carrying max_hp; BOTH clients' claims deplete the SAME hp_cur. Round 1 is
    # log-only (no death command); round 2 drives the kill + the client clamp.
    hp_max: float = 0.0          # 0.0 = not yet bootstrapped
    hp_cur: float = 0.0
    hp_dead: bool = False        # latched True the first time hp_cur reaches 0
    hp_dmg_by_peer: dict[str, float] = field(default_factory=dict)  # cumulative, for validation


@dataclass(frozen=True, slots=True)
class OwnershipChange:
    """Returned from registry handlers when ownership is reassigned.

    `phase` indicates the broadcast type:
      - "claim"   : new owner for a previously-unowned NPC (single-phase
                    announce; broadcast OWNERSHIP_BCAST with the new owner)
      - "handoff" : owner reassignment (broadcast PHASE_2; old owner is
                    expected to stop emitting state in ≤ 1 RTT)
      - "release" : owner left / disconnected; NPC unowned until next
                    observation (broadcast PHASE_2 with all-zero peer_id)
    """
    form_id: int
    old_owner_peer_id: Optional[str]
    new_owner_peer_id: Optional[str]
    new_epoch: int
    phase: str
    reason: str                      # diagnostic only — never on the wire


# ---------------------------------------------------------------- registry


class OwnershipRegistry:
    """In-memory ownership table.

    Per Solver 2 §1.2 the election rules are evaluated in order:
        Rule 1  Cell-first claim — first observer of an unowned NPC owns
                it for `CLAIM_GRACE_MS`.
        Rule 2  Closeness — after grace, a challenger that is `CLOSENESS_
                THRESHOLD` closer than the current owner can preempt,
                provided the owner is past `STICKINESS_FLOOR_MS`.
        Rule 5  Health gate — owner whose heartbeat is older than
                `HEARTBEAT_TIMEOUT_MS` is forcibly released. The next
                observation re-elects.

    Rules 3 (cell-affinity) and 4 (Owner-stays-when-leaving-cell) are
    handled at the `on_unload` boundary, not here.
    """

    def __init__(self) -> None:
        self._records: dict[int, NPCOwnership] = {}
        self._next_epoch: int = 1
        # c.40a-fix — per-fid throttle for the "challenger higher but blocked"
        # diagnostic so a near-miss handoff is visible without spamming.
        self._threat_diag_last_ms: dict[int, float] = {}
        # FIX (resurrection) — sticky "this fid is dead" memory that SURVIVES the
        # record deletion done by _fire_npc_death. Without it, a still-in-combat
        # client re-OBSERVES the just-killed raider → a fresh record (hp_dead=
        # False) is created → reeval re-elects it → the new owner's handoff MoveTo
        # REVIVES the corpse = the "MORTO MA NON MORTO" zombie (+ the 0xC0F510
        # crash feeder). fid -> server-clock ms of death; entries older than
        # _DEAD_FID_TTL_MS are pruned so a legit respawn (cell reset, well after
        # the fight) can re-elect.
        self._dead_fids: dict[int, float] = {}
        # N3 first-shot fix — TTL buffer for damage claims whose fid is not yet
        # registered (the AGGRO shot: the client claims it before NPC_OBSERVED
        # registers the NPC, so apply_hp_claim returns None). fid ->
        # (sum_amount, max_hp, last_peer, ts_ms). Drained-on-create by
        # assign_owner_by_threat the instant the matching NPC_OBSERVED arrives, so
        # the aggro shot is folded into the fresh pool. NOTHING is pooled from here
        # alone — a real pool is only ever BORN from an InCombat-gated NPC_OBSERVED.
        self._pending_dmg: dict[int, tuple[float, float, str, float]] = {}
        # N3 first-shot fix — set by assign_owner_by_threat to (hp_cur, hp_max,
        # just_died) when a pending aggro claim was drained into the new record this
        # call, else None. main._handle_npc_observed reads + clears it to emit the
        # NPC_HP_POOL_BCAST (and death-on-zero) for the drained pool.
        self.last_drained_hp: Optional[tuple[float, float, bool]] = None

    # -------------------------------------------------------------- queries

    def get(self, form_id: int) -> Optional[NPCOwnership]:
        return self._records.get(form_id)

    def owner_of(self, form_id: int) -> Optional[str]:
        rec = self._records.get(form_id)
        return rec.owner_peer_id if rec is not None else None

    def is_owner(self, peer_id: str, form_id: int) -> bool:
        rec = self._records.get(form_id)
        return rec is not None and rec.owner_peer_id == peer_id

    def iter_records(self) -> Iterator[NPCOwnership]:
        """Stable iteration order (form_id ascending) for bootstrap snapshot."""
        for fid in sorted(self._records):
            yield self._records[fid]

    def owned_by(self, peer_id: str) -> list[int]:
        return [
            fid for fid, rec in self._records.items()
            if rec.owner_peer_id == peer_id
        ]

    def __len__(self) -> int:
        return len(self._records)

    # ----------------------------------------------------- dead-fid memory
    # FIX (resurrection) — 10-minute TTL: a raider stays "dead" long enough to
    # outlast any in-combat re-observe burst that would otherwise resurrect it,
    # but a genuine respawn (cell reset, much later) is allowed to re-elect.
    _DEAD_FID_TTL_MS = 600_000.0

    # N3 first-shot fix — how long a pre-registration damage claim survives waiting
    # for its NPC_OBSERVED. The observe round-trip after an aggro shot is ≤ ~120 ms;
    # 2 s is a safe margin and bounds the buffer for NPCs shot once but never tracked.
    _PENDING_DMG_TTL_MS = 2000.0

    def note_dead(self, fid: int, now_ms: float) -> None:
        """Record that `fid` was just killed (pool=0). Survives the record
        deletion _fire_npc_death does right after."""
        self._dead_fids[fid] = now_ms

    def is_recently_dead(self, fid: int, now_ms: float) -> bool:
        """True if `fid` died within the TTL → must NOT be re-created/re-elected
        (prevents the zombie). Lazily prunes the queried fid once expired."""
        t = self._dead_fids.get(fid)
        if t is None:
            return False
        if (now_ms - t) > self._DEAD_FID_TTL_MS:
            del self._dead_fids[fid]
            return False
        return True

    # ------------------------------------------------ N3 pending-damage buffer

    def stash_pending_damage(
        self, fid: int, peer_id: str, amount: float, max_hp: float, now_ms: float,
    ) -> None:
        """N3 first-shot fix — accumulate a damage claim for a NOT-yet-registered
        fid (the aggro shot). Called by main._handle_npc_damage_claim ONLY when
        apply_hp_claim returned None (unknown fid) AND max_hp > 0. Drained into the
        record by assign_owner_by_threat when the matching NPC_OBSERVED arrives.
        max_hp/last_peer take the freshest claim; amount ACCUMULATES. Refuses fids
        known recently-dead (don't resurrect a corpse via a late claim)."""
        if amount <= 0.0 or max_hp <= 0.0:
            return
        if self.is_recently_dead(fid, now_ms):
            return
        prev = self._pending_dmg.get(fid)
        prev_sum = prev[0] if prev is not None else 0.0
        self._pending_dmg[fid] = (prev_sum + amount, max_hp, peer_id, now_ms)

    def _drain_pending_damage(
        self, rec: "NPCOwnership", now_ms: float,
    ) -> Optional[tuple[float, float, bool]]:
        """N3 first-shot fix — fold any buffered pre-registration damage into a
        freshly-created record. Returns (hp_cur, hp_max, just_died) if a pending
        entry existed and was applied, else None. POPs the entry → drain-on-create,
        so the aggro damage is counted EXACTLY ONCE."""
        pending = self._pending_dmg.pop(rec.form_id, None)
        if pending is None:
            return None
        sum_amount, max_hp, last_peer, ts = pending
        if (now_ms - ts) > self._PENDING_DMG_TTL_MS:
            return None   # too old — the aggro burst is stale; ignore it
        if max_hp <= 0.0 or sum_amount <= 0.0:
            return None
        rec.hp_max = max_hp
        rec.hp_cur = max_hp
        rec.hp_dmg_by_peer[last_peer] = (
            rec.hp_dmg_by_peer.get(last_peer, 0.0) + sum_amount)
        prev = rec.hp_cur
        rec.hp_cur = max(0.0, rec.hp_cur - sum_amount)
        just_died = (prev > 0.0 and rec.hp_cur <= 0.0 and not rec.hp_dead)
        if just_died:
            rec.hp_dead = True
        log.info(
            "N3 first-shot DRAIN fid=0x%X +%.1f from %s -> pool %.0f/%.0f%s",
            rec.form_id, sum_amount, last_peer, rec.hp_cur, rec.hp_max,
            "  *** POOL=0 -> KILL ***" if just_died else "")
        return (rec.hp_cur, rec.hp_max, just_died)

    def prune_pending_damage(self, now_ms: float) -> None:
        """Lazily evict pending-damage entries past the TTL (fids shot once but
        never registered). Not required for correctness (drain re-checks the TTL)."""
        if not self._pending_dmg:
            return
        stale = [
            fid for fid, (_s, _m, _p, ts) in self._pending_dmg.items()
            if (now_ms - ts) > self._PENDING_DMG_TTL_MS
        ]
        for fid in stale:
            del self._pending_dmg[fid]

    # ---------------------------------------------------------- handler API

    def on_observed(
        self,
        payload: NPCObservedPayload,
        peer_id: str,
        now_ms: float,
    ) -> Optional[OwnershipChange]:
        """Process an NPC_OBSERVED report. Returns a change if ownership
        was assigned or transferred; None if no change."""
        fid = payload.form_id
        existing = self._records.get(fid)

        if existing is None:
            # FIX (resurrection) — refuse to re-create a record for a fid that
            # was just killed; a re-observe of the corpse must NOT bring it back.
            if self.is_recently_dead(fid, now_ms):
                return None
            # Rule 1 — first observer claims it.
            epoch = self._next_epoch
            self._next_epoch += 1
            self._records[fid] = NPCOwnership(
                form_id=fid,
                owner_peer_id=peer_id,
                epoch=epoch,
                last_heartbeat_ms=now_ms,
                since_ms=now_ms,
                base_id=payload.base_id,
                cell_id=payload.cell_id,
                last_pos_x=payload.pos_x,
                last_pos_y=payload.pos_y,
                last_pos_z=payload.pos_z,
                owner_distance_sq=payload.observer_distance_sq,
            )
            log.debug(
                "ownership: claim fid=0x%X owner=%s epoch=%d "
                "(first observer, dist²=%.0f)",
                fid, peer_id, epoch, payload.observer_distance_sq,
            )
            return OwnershipChange(
                form_id=fid,
                old_owner_peer_id=None,
                new_owner_peer_id=peer_id,
                new_epoch=epoch,
                phase="claim",
                reason="first-observer",
            )

        # Refresh last-known state on any observation.
        existing.last_pos_x = payload.pos_x
        existing.last_pos_y = payload.pos_y
        existing.last_pos_z = payload.pos_z
        if existing.base_id == 0:
            existing.base_id = payload.base_id
        if existing.cell_id == 0:
            existing.cell_id = payload.cell_id

        # Build 65.c.35 — record this peer's engagement (NPC_OBSERVED is
        # InCombat-gated, so observing == this peer's engine has LOS + aggro'd
        # the NPC = our threat "engagement" input). Feeds _compute_threat.
        if THREAT_OWNERSHIP:
            existing.threat_engaged[peer_id] = now_ms

        # If the observer IS the current owner, just refresh distance.
        if existing.owner_peer_id == peer_id:
            existing.owner_distance_sq = payload.observer_distance_sq
            return None

        # Build 65.c.35 — threat mode: a non-owner observing only records its
        # engagement (above). Ownership flips are decided CENTRALLY (with
        # hysteresis) in reeval_threat_owners on the server tick, never here —
        # so a momentary observation can't thrash ownership.
        if THREAT_OWNERSHIP:
            return None

        # Build 65.c.27 — STATIC RNG ownership: once a raider's owner is
        # RNG-assigned (= its aggro target), it is STICKY. A non-owner
        # observing the raider does NOT trigger a closeness handoff —
        # otherwise the geometrically-closer peer would steal aggro and
        # collapse the 50/50 RNG split back to "whoever is nearest". The
        # raider must KEEP attacking its assigned target even when the
        # other player is closer. Dynamic re-roll is a future wedge.
        if STATIC_RNG_OWNERSHIP:
            return None

        # Otherwise: closeness re-election check.
        age_ms = now_ms - existing.since_ms
        if age_ms < STICKINESS_FLOOR_MS:
            return None   # current owner is sticky

        challenger_dist_sq = payload.observer_distance_sq
        if challenger_dist_sq >= existing.owner_distance_sq * CLOSENESS_THRESHOLD:
            return None   # challenger not decisively closer

        # Closeness handoff.
        old_owner = existing.owner_peer_id
        new_epoch = self._next_epoch
        self._next_epoch += 1
        existing.owner_peer_id = peer_id
        existing.epoch = new_epoch
        existing.since_ms = now_ms
        existing.last_heartbeat_ms = now_ms
        existing.owner_distance_sq = challenger_dist_sq
        log.debug(
            "ownership: handoff fid=0x%X %s → %s epoch=%d "
            "(closeness: challenger dist²=%.0f < %.0f×%.2f)",
            fid, old_owner, peer_id, new_epoch,
            challenger_dist_sq, existing.owner_distance_sq, CLOSENESS_THRESHOLD,
        )
        return OwnershipChange(
            form_id=fid,
            old_owner_peer_id=old_owner,
            new_owner_peer_id=peer_id,
            new_epoch=new_epoch,
            phase="handoff",
            reason="closeness",
        )

    def assign_owner_rng(
        self,
        payload: NPCObservedPayload,
        candidate_peer_ids: list[str],
        now_ms: float,
    ) -> Optional[OwnershipChange]:
        """Build 65.c.27 — RNG AGGRO ownership assignment.

        Called by `main._handle_npc_observed` for a NOT-yet-owned raider.
        `candidate_peer_ids` = connected peers whose player is within aggro
        range of the raider (computed from POS_STATE in main.py).

        Each raider independently coin-flips its owner among the candidates
        (random.choice). Owner = the player the raider will attack:
          - Owner's vanilla AI naturally aggros the owner's LOCAL player
            (a live PlayerCharacter, faction-hostile, teardown-safe — no
            ghost ever enters the owner's CombatGroup).
          - Non-owners suppress local AI + mirror via STATE_FROM_OWNER, so
            on their screen the raider appears attacking the owner's GHOST
            (= where the owner's player is rendered locally).

        With 2 in-range peers this yields ~50/50 aggro split across the
        raider group, each raider rolling independently (could land 3-2,
        4-1, etc. — that's correct, not a bug).

        Returns a 'claim' OwnershipChange on assignment, None if already
        owned (sticky) or no candidates in range (leave unowned; the next
        observation retries once a peer is close enough).
        """
        fid = payload.form_id
        if fid in self._records:
            return None   # already assigned — STICKY
        if not candidate_peer_ids:
            # Nobody in aggro range yet. Leave unowned. The observer's
            # engine is in combat (OBSERVED is InCombat-gated) but the
            # range gate in main.py rejected everyone — likely a transient
            # position-staleness; the next OBSERVED retries.
            log.debug(
                "ownership: RNG-assign skip fid=0x%X — no in-range "
                "candidates", fid,
            )
            return None

        chosen = random.choice(candidate_peer_ids)
        epoch = self._next_epoch
        self._next_epoch += 1
        # Build 65.c.28 — PROVISIONAL if assigned with <2 candidates (only
        # one player in range so far). Such a raider is eligible for a
        # one-time re-roll once the 2nd player closes distance (see
        # reroll_provisional_owners). With ≥2 candidates the coin-flip is
        # already fair → FINAL immediately.
        provisional = len(candidate_peer_ids) < 2
        self._records[fid] = NPCOwnership(
            form_id=fid,
            owner_peer_id=chosen,
            epoch=epoch,
            last_heartbeat_ms=now_ms,
            since_ms=now_ms,
            base_id=payload.base_id,
            cell_id=payload.cell_id,
            last_pos_x=payload.pos_x,
            last_pos_y=payload.pos_y,
            last_pos_z=payload.pos_z,
            owner_distance_sq=payload.observer_distance_sq,
            provisional=provisional,
        )
        log.info(
            "ownership: RNG-AGGRO assign fid=0x%X owner=%s epoch=%d "
            "(candidates=%s provisional=%s — owner's vanilla AI will aggro "
            "its local player; non-owners mirror)",
            fid, chosen, epoch, candidate_peer_ids, provisional,
        )
        return OwnershipChange(
            form_id=fid,
            old_owner_peer_id=None,
            new_owner_peer_id=chosen,
            new_epoch=epoch,
            phase="claim",
            reason="rng-aggro",
        )

    def reroll_provisional_owners(
        self,
        player_positions: dict[str, tuple[float, float, float]],
        aggro_range_sq: float,
        now_ms: float,
    ) -> list[OwnershipChange]:
        """Build 65.c.28 — one-time re-roll of PROVISIONAL raiders.

        A raider becomes provisional when `assign_owner_rng` ran with only
        one in-range peer (the first-approaching player). This method, called
        every server tick from `main._periodic_tick`, recomputes the in-range
        candidate set FROM CURRENT PLAYER POSITIONS for each provisional
        raider. When 2+ peers are now in range, it re-rolls the owner among
        them (fair coin-flip) and marks the raider FINAL — sticky thereafter.

        `player_positions`: peer_id → (x, y, z), already freshness-filtered
        by the caller. `aggro_range_sq`: squared distance threshold (matches
        main._AGGRO_RANGE_SQ). Returns the list of OwnershipChanges to
        broadcast (may be empty).

        Fixes the c.27 timing flaw where player_A (always first to engage)
        owned 100% of the group because player_B was still out of range at
        first-observation. Now once B closes in, ~half the group re-rolls to
        B → 50/50 aggro split.
        """
        changes: list[OwnershipChange] = []
        for fid in list(self._records):
            rec = self._records[fid]
            if not rec.provisional:
                continue
            # Recompute in-range candidates from current player positions
            # vs the raider's last-known position.
            cands: list[str] = []
            for pid, (px, py, pz) in player_positions.items():
                dx = px - rec.last_pos_x
                dy = py - rec.last_pos_y
                dz = pz - rec.last_pos_z
                if (dx * dx + dy * dy + dz * dz) <= aggro_range_sq:
                    cands.append(pid)
            if len(cands) < 2:
                continue   # still only one player in range — stay provisional
            # 2+ candidates now — re-roll once and finalize.
            new_owner = random.choice(cands)
            rec.provisional = False   # FINAL — never re-roll again
            if new_owner == rec.owner_peer_id:
                # Coin-flip kept the same owner. Still finalize so we don't
                # re-roll every tick; no ownership change to broadcast.
                log.info(
                    "ownership: provisional re-roll fid=0x%X KEPT owner=%s "
                    "(candidates=%s — finalized)",
                    fid, new_owner, cands,
                )
                continue
            old_owner = rec.owner_peer_id
            new_epoch = self._next_epoch
            self._next_epoch += 1
            rec.owner_peer_id = new_owner
            rec.epoch = new_epoch
            rec.since_ms = now_ms
            rec.last_heartbeat_ms = now_ms
            rec.last_engaged_ms = 0.0
            log.info(
                "ownership: provisional re-roll fid=0x%X %s → %s epoch=%d "
                "(2nd player in range; candidates=%s — RNG aggro rebalance)",
                fid, old_owner, new_owner, new_epoch, cands,
            )
            changes.append(OwnershipChange(
                form_id=fid,
                old_owner_peer_id=old_owner,
                new_owner_peer_id=new_owner,
                new_epoch=new_epoch,
                phase="handoff",
                reason="rng-reroll",
            ))
        return changes

    # ------------------------------------------------------------ c.35 threat

    def _compute_threat(
        self,
        rec: NPCOwnership,
        peer_id: str,
        dist_sq: float,
        aggro_range_sq: float,
        now_ms: float,
    ) -> float:
        """Build 65.c.35 — threat of `peer_id` toward this NPC (higher = more
        likely owner).

            threat = W_ENGAGE * engage_score + W_DISTANCE * proximity_score
                     [+ W_DAMAGE * damage_score]      # TODO(damage-sync)

        engage_score: 1.0 if this peer engaged the NPC right now, decaying
          linearly to 0 over THREAT_ENGAGE_WINDOW_MS (our LOS+aggro proxy —
          observation/claim/owner-anim are InCombat-gated). Weighted high so
          "who is actually fighting it" dominates "who is merely nearest".
        proximity_score: 1.0 at the NPC, 0 at the aggro-range edge (tie-break).
        """
        engaged_ms = rec.threat_engaged.get(peer_id, 0.0)
        if engaged_ms > 0.0:
            age = now_ms - engaged_ms
            engage = max(0.0, 1.0 - age / THREAT_ENGAGE_WINDOW_MS)
        else:
            engage = 0.0
        if dist_sq < float("inf") and aggro_range_sq > 0.0:
            proximity = max(0.0, 1.0 - dist_sq / aggro_range_sq)
        else:
            proximity = 0.0
        # c.39b — damage is the DOMINANT term: ownership follows the real
        # fighter even when both peers are "engaged" (combat-target tie).
        damage = self._damage_term(rec, peer_id, now_ms)
        return (THREAT_W_ENGAGE * engage
                + THREAT_W_DISTANCE * proximity
                + THREAT_W_DAMAGE * damage)

    def _damage_term(
        self, rec: NPCOwnership, peer_id: str, now_ms: float,
    ) -> float:
        """c.40a-fix — recent decayed damage this peer dealt to the NPC, as a
        threat term. NOT capped at 1.0 (the c.40a cap caused both fighters to
        saturate to a tie in sustained fire AND made short bursts too weak to
        flip). The 4 s decay window already bounds the sum to ~DPS×4, so the
        term stays proportional to the recent DPS — bigger damager → bigger
        term, always. A high safety ceiling (50.0 ≈ DPS×4 of 1000) only guards
        against a single pathological multi-thousand-damage frame."""
        sum_, last = rec.threat_damage.get(peer_id, (0.0, 0.0))
        if sum_ <= 0.0:
            return 0.0
        age = max(0.0, now_ms - last)
        decayed = sum_ * max(0.0, 1.0 - age / THREAT_DAMAGE_WINDOW_MS)
        return min(50.0, decayed / THREAT_DAMAGE_NORM)

    def record_damage(
        self, form_id: int, peer_id: str, amount: float, now_ms: float,
    ) -> None:
        """c.39b — a peer dealt `amount` damage to this NPC. Decay the prior
        sum to now, add the new amount, and (like state/heartbeat) treat damage
        as proof-of-life + engagement so the damager's threat rises immediately."""
        if amount <= 0.0:
            return
        rec = self.get(form_id)
        if rec is None:
            return  # only tracked NPCs
        sum_, last = rec.threat_damage.get(peer_id, (0.0, now_ms))
        age = max(0.0, now_ms - last)
        decayed = sum_ * max(0.0, 1.0 - age / THREAT_DAMAGE_WINDOW_MS)
        rec.threat_damage[peer_id] = (decayed + amount, now_ms)
        # Dealing damage also counts as engagement (so the engage term + the
        # candidate set in reeval pick this peer up immediately).
        rec.threat_engaged[peer_id] = now_ms

    def apply_hp_claim(
        self, form_id: int, peer_id: str, amount: float, max_hp: float,
    ) -> Optional[tuple[float, float, bool]]:
        """N3 (shared HP) — deplete the per-fid shared HP pool by `amount`,
        bootstrapping the pool from `max_hp` on the first claim that carries it.
        Returns (hp_cur, hp_max, just_crossed_zero), or None if the NPC isn't
        tracked, or (0,0,False) if max is still unknown. NEVER kills — round 1
        is log-only at the call site; the kill command lands in round 2."""
        rec = self.get(form_id)
        if rec is None:
            return None
        # Bootstrap the pool max once (first claim carrying a non-zero max wins).
        if rec.hp_max <= 0.0 and max_hp > 0.0:
            rec.hp_max = max_hp
            rec.hp_cur = max_hp
        if rec.hp_max <= 0.0:
            return (0.0, 0.0, False)   # max still unknown — can't pool yet
        amt = max(0.0, amount)
        if amt > 0.0:
            rec.hp_dmg_by_peer[peer_id] = rec.hp_dmg_by_peer.get(peer_id, 0.0) + amt
        prev = rec.hp_cur
        rec.hp_cur = max(0.0, rec.hp_cur - amt)
        just_died = (prev > 0.0 and rec.hp_cur <= 0.0 and not rec.hp_dead)
        if just_died:
            rec.hp_dead = True
        return (rec.hp_cur, rec.hp_max, just_died)

    def assign_owner_by_threat(
        self,
        payload: NPCObservedPayload,
        observer_peer_id: str,
        now_ms: float,
    ) -> Optional[OwnershipChange]:
        """Build 65.c.35 — initial owner = the OBSERVER.

        Called by main._handle_npc_observed for a NOT-yet-owned NPC. Because
        NPC_OBSERVED is InCombat-gated, the observer is by definition the peer
        whose engine has LOS + perceived + aggro'd the NPC = the highest-threat
        peer at this instant. So it claims it. `reeval_threat_owners` (per tick)
        then refines ownership as positions/engagement evolve.

        Returns a 'claim' OwnershipChange, or None if already owned (sticky).
        """
        fid = payload.form_id
        if fid in self._records:
            self.last_drained_hp = None
            return None
        # FIX (resurrection) — don't re-elect a just-killed raider (its corpse is
        # re-observed while still loaded/in-combat on a client). See __init__.
        if self.is_recently_dead(fid, now_ms):
            self.last_drained_hp = None
            return None
        epoch = self._next_epoch
        self._next_epoch += 1
        rec = NPCOwnership(
            form_id=fid,
            owner_peer_id=observer_peer_id,
            epoch=epoch,
            last_heartbeat_ms=now_ms,
            since_ms=now_ms,
            base_id=payload.base_id,
            cell_id=payload.cell_id,
            last_pos_x=payload.pos_x,
            last_pos_y=payload.pos_y,
            last_pos_z=payload.pos_z,
            owner_distance_sq=payload.observer_distance_sq,
        )
        rec.threat_engaged[observer_peer_id] = now_ms
        rec.last_engaged_ms = now_ms
        self._records[fid] = rec
        # N3 first-shot fix — fold any buffered aggro-shot damage into the brand-new
        # pool (drain-on-create; counted exactly once). Carried out via
        # self.last_drained_hp for main to broadcast the corrected bar.
        self.last_drained_hp = self._drain_pending_damage(rec, now_ms)
        log.info(
            "ownership: THREAT assign fid=0x%X owner=%s epoch=%d "
            "(in-combat observer = highest threat; tick reeval refines)",
            fid, observer_peer_id, epoch,
        )
        return OwnershipChange(
            form_id=fid,
            old_owner_peer_id=None,
            new_owner_peer_id=observer_peer_id,
            new_epoch=epoch,
            phase="claim",
            reason="threat-observer",
        )

    def reeval_threat_owners(
        self,
        player_positions: dict[str, tuple[float, float, float]],
        aggro_range_sq: float,
        now_ms: float,
    ) -> list[OwnershipChange]:
        """Build 65.c.35 — per-tick threat re-evaluation (the real selection).

        For every tracked NPC, compute each candidate peer's threat from
        current positions + engagement recency, and hand ownership to the
        highest-threat peer when it DECISIVELY beats the current owner
        (hysteresis: MIN_HOLD + FLIP_MARGIN). This is the ONLY place ownership
        moves in threat mode — observe/claim/owner-anim only feed the
        engagement signal.

        `player_positions`: peer_id → (x,y,z), freshness-filtered by caller.
        `aggro_range_sq`: distance² normaliser for the proximity term.
        """
        changes: list[OwnershipChange] = []
        for fid in list(self._records):
            rec = self._records[fid]
            # FIX (resurrection) — never re-elect a dead record (belt-and-braces;
            # the create-path guard normally stops a dead record from existing).
            if rec.hp_dead or self.is_recently_dead(fid, now_ms):
                continue
            owner = rec.owner_peer_id

            # Per-peer distance² to the NPC's last-known position.
            dist_sq: dict[str, float] = {}
            for pid, (px, py, pz) in player_positions.items():
                dx = px - rec.last_pos_x
                dy = py - rec.last_pos_y
                dz = pz - rec.last_pos_z
                dist_sq[pid] = dx * dx + dy * dy + dz * dz

            # Candidates = peers in aggro range, plus any peer with a still-live
            # engagement signal (a peer fighting from just outside the range
            # gate still counts), plus the current owner (so it's always scored).
            candidates: set[str] = {
                pid for pid, d in dist_sq.items() if d <= aggro_range_sq
            }
            for pid, eng in rec.threat_engaged.items():
                if eng > 0.0 and (now_ms - eng) <= THREAT_ENGAGE_WINDOW_MS:
                    candidates.add(pid)
            if owner in player_positions:
                candidates.add(owner)
            if not candidates:
                continue

            threats = {
                pid: self._compute_threat(
                    rec, pid, dist_sq.get(pid, float("inf")),
                    aggro_range_sq, now_ms)
                for pid in candidates
            }
            best_peer = max(threats, key=threats.get)
            best_threat = threats[best_peer]
            owner_threat = threats.get(owner, 0.0)

            if best_peer == owner:
                continue
            if best_threat <= 0.0:
                continue   # don't hand to a zero-threat peer

            # c.40a-fix — diagnostic: a challenger out-threatens the owner but a
            # hysteresis gate holds the flip. This is the exact case that looked
            # like "aggro never switches" when NORM was too high — surface the
            # numbers (throttled 1.5 s/fid) so a near-miss is never invisible.
            block: Optional[str] = None
            if (now_ms - rec.since_ms) < THREAT_MIN_HOLD_MS:
                block = "MIN_HOLD"
            elif best_threat < owner_threat * THREAT_FLIP_MARGIN:
                block = "FLIP_MARGIN"
            elif (best_threat - owner_threat) < THREAT_MIN_ABS_DELTA:
                block = "ABS_DELTA"
            if block is not None:
                last = self._threat_diag_last_ms.get(fid, 0.0)
                if now_ms - last >= 1500.0:
                    self._threat_diag_last_ms[fid] = now_ms
                    log.info(
                        "ownership: THREAT held fid=0x%X owner=%s "
                        "challenger=%s (chal %.2f vs owner %.2f) blocked=%s",
                        fid, owner, best_peer, best_threat, owner_threat, block,
                    )
                continue

            # All gates cleared → hand off below.

            old_owner = owner
            new_epoch = self._next_epoch
            self._next_epoch += 1
            rec.owner_peer_id = best_peer
            rec.epoch = new_epoch
            rec.since_ms = now_ms
            rec.last_heartbeat_ms = now_ms
            rec.last_engaged_ms = rec.threat_engaged.get(best_peer, now_ms)
            log.info(
                "ownership: THREAT handoff fid=0x%X %s → %s epoch=%d "
                "(threat %.2f vs owner %.2f ×%.2f)",
                fid, old_owner, best_peer, new_epoch,
                best_threat, owner_threat, THREAT_FLIP_MARGIN,
            )
            changes.append(OwnershipChange(
                form_id=fid,
                old_owner_peer_id=old_owner,
                new_owner_peer_id=best_peer,
                new_epoch=new_epoch,
                phase="handoff",
                reason="threat",
            ))
        return changes

    def on_unload(
        self,
        payload: NPCUnloadPayload,
        peer_id: str,
        now_ms: float,
    ) -> Optional[OwnershipChange]:
        """Peer reports an NPC left their loaded cell. If the reporter
        is the owner, release ownership (other peers can re-claim via
        next observation)."""
        fid = payload.form_id
        rec = self._records.get(fid)
        if rec is None:
            return None
        if rec.owner_peer_id != peer_id:
            return None  # non-owners can't unload someone else's NPC
        if payload.epoch != rec.epoch:
            log.debug(
                "ownership: ignore stale unload fid=0x%X epoch=%d "
                "(current epoch=%d)",
                fid, payload.epoch, rec.epoch,
            )
            return None

        old_owner = rec.owner_peer_id
        new_epoch = self._next_epoch
        self._next_epoch += 1
        # Mark unowned by removing the record. State of the NPC is
        # preserved in the payload for next observer's claim.
        del self._records[fid]
        log.debug(
            "ownership: release fid=0x%X owner=%s (unload at %.1f,%.1f,%.1f)",
            fid, old_owner,
            payload.last_pos_x, payload.last_pos_y, payload.last_pos_z,
        )
        return OwnershipChange(
            form_id=fid,
            old_owner_peer_id=old_owner,
            new_owner_peer_id=None,
            new_epoch=new_epoch,
            phase="release",
            reason="unload",
        )

    def on_heartbeat(
        self,
        entries: list[NPCOwnerHeartbeatEntry],
        peer_id: str,
        now_ms: float,
    ) -> None:
        """Owner heartbeat refreshes last-seen timestamps. Stale entries
        (epoch mismatch) are ignored."""
        for e in entries:
            rec = self._records.get(e.form_id)
            if rec is None:
                continue
            if rec.owner_peer_id != peer_id:
                continue  # not your NPC
            if rec.epoch != e.epoch:
                continue  # stale epoch
            rec.last_heartbeat_ms = now_ms

    def on_peer_disconnect(
        self,
        peer_id: str,
        now_ms: float,
    ) -> list[OwnershipChange]:
        """Peer disconnected. Release all NPCs they owned. Each release
        becomes an unowned record (next observer claims)."""
        changes: list[OwnershipChange] = []
        for fid in list(self._records):
            rec = self._records[fid]
            if rec.owner_peer_id != peer_id:
                continue
            new_epoch = self._next_epoch
            self._next_epoch += 1
            del self._records[fid]
            log.info(
                "ownership: forced release fid=0x%X owner=%s "
                "(peer disconnect)",
                fid, peer_id,
            )
            changes.append(OwnershipChange(
                form_id=fid,
                old_owner_peer_id=peer_id,
                new_owner_peer_id=None,
                new_epoch=new_epoch,
                phase="release",
                reason="peer-disconnect",
            ))
        return changes

    def note_owner_engagement(
        self,
        form_id: int,
        peer_id: str,
        anim_state: int,
        now_ms: float,
    ) -> None:
        """Build 65.c.23 — Record that the current owner is REPORTING
        combat engagement (anim_state >= 3 in a STATE_FROM_OWNER entry).
        Called by `_handle_npc_state_from_owner` for each entry.

        Refreshes `rec.last_engaged_ms` so subsequent NPC_ENGAGEMENT_CLAIM
        from non-owner peers can determine whether the owner is the real
        fighter (and skip handoff) vs disengaged (and yield handoff).

        Silent no-op on stale epoch / wrong peer / unknown fid (defence
        in depth — the caller already validates).
        """
        if anim_state < 3:
            return
        rec = self._records.get(form_id)
        if rec is None:
            return
        if rec.owner_peer_id != peer_id:
            return
        rec.last_engaged_ms = now_ms
        # Build 65.c.35 — owner reporting combat anim is also a threat
        # "engagement" signal: keeps the owner's threat high while it actively
        # fights, so it isn't displaced by a merely-closer challenger.
        if THREAT_OWNERSHIP:
            rec.threat_engaged[peer_id] = now_ms

    def on_engagement_claim(
        self,
        form_id: int,
        peer_id: str,
        now_ms: float,
    ) -> Optional[OwnershipChange]:
        """Build 65.c.23 — Process NPC_ENGAGEMENT_CLAIM.

        Decision tree:
          (a) NPC unknown → ignore (let next OBSERVED claim it normally).
          (b) Claimer is already owner → refresh heartbeat + last_engaged
              (the claimer's engine IS in combat, so by definition the
              owner is engaged; this also handles the race where the
              claimer just won handoff but its DLL hasn't yet sent a
              STATE_FROM_OWNER with anim_state>=3).
          (c) Combat handoff stickiness not yet elapsed (rec.since_ms +
              COMBAT_HANDOFF_STICKINESS_MS > now) → reject.
          (d) Owner is currently engaged (now - last_engaged_ms <
              ENGAGEMENT_OWNERSHIP_GRACE_MS) → reject. Owner wins.
          (e) Otherwise → COMBAT-DRIVEN HANDOFF: claimer becomes owner.

        Stronger than closeness: bypasses STICKINESS_FLOOR_MS (8 s)
        because the engine's InCombat flag is decisive evidence that the
        claimer's local PC is the natural opponent, not a heuristic.
        """
        rec = self._records.get(form_id)
        if rec is None:
            return None
        # Build 65.c.35 — threat mode: a claim is an engagement signal. Record
        # it (and refresh heartbeat if the claimer is the owner so the health
        # gate doesn't false-release an actively-fighting owner). The actual
        # handoff decision is centralized in reeval_threat_owners (tick).
        if THREAT_OWNERSHIP:
            rec.threat_engaged[peer_id] = now_ms
            if rec.owner_peer_id == peer_id:
                rec.last_heartbeat_ms = now_ms
                rec.last_engaged_ms = now_ms
            return None
        # Build 65.c.27 — In STATIC RNG mode, ownership = the RNG-assigned
        # aggro target and is STICKY. Combat-driven handoff is SUPPRESSED:
        # if B's engine happens to engage an A-owned raider (because B is
        # also nearby), that must NOT steal the raider from A — it would
        # collapse the 50/50 split. The raider keeps attacking its assigned
        # target. (Still refresh heartbeat if the claimer IS the owner, so
        # the health-gate doesn't false-release an actively-fighting owner.)
        if STATIC_RNG_OWNERSHIP:
            if rec.owner_peer_id == peer_id:
                rec.last_heartbeat_ms = now_ms
                rec.last_engaged_ms = now_ms
            return None
        # Case (b): claimer IS already owner. Refresh and exit.
        if rec.owner_peer_id == peer_id:
            rec.last_heartbeat_ms = now_ms
            rec.last_engaged_ms = now_ms
            return None
        # Case (c): combat handoff stickiness floor (post-handoff window).
        if (now_ms - rec.since_ms) < COMBAT_HANDOFF_STICKINESS_MS:
            return None
        # Case (d): current owner is actively engaged.
        owner_engagement_age = now_ms - rec.last_engaged_ms
        if rec.last_engaged_ms > 0.0 and \
                owner_engagement_age < ENGAGEMENT_OWNERSHIP_GRACE_MS:
            return None
        # Case (e): force handoff to claimer.
        old_owner = rec.owner_peer_id
        new_epoch = self._next_epoch
        self._next_epoch += 1
        rec.owner_peer_id = peer_id
        rec.epoch = new_epoch
        rec.since_ms = now_ms
        rec.last_heartbeat_ms = now_ms
        rec.last_engaged_ms = now_ms      # claimer IS engaged by def
        # owner_distance_sq stays from previous owner's last observation —
        # not authoritative for combat-driven handoff but kept so
        # closeness re-election can still operate later.
        log.info(
            "ownership: combat-driven handoff fid=0x%X %s → %s epoch=%d "
            "(owner_engagement_age=%.0fms ≥ grace=%.0fms; sticky_ok=%.0fms)",
            form_id, old_owner, peer_id, new_epoch,
            owner_engagement_age, ENGAGEMENT_OWNERSHIP_GRACE_MS,
            now_ms - rec.since_ms,
        )
        return OwnershipChange(
            form_id=form_id,
            old_owner_peer_id=old_owner,
            new_owner_peer_id=peer_id,
            new_epoch=new_epoch,
            phase="handoff",
            reason="combat-engagement",
        )

    def periodic_tick(
        self,
        now_ms: float,
    ) -> list[OwnershipChange]:
        """Run the health gate. Owners whose heartbeat is older than
        `HEARTBEAT_TIMEOUT_MS` are forcibly released. Closeness re-
        election is opportunistic via `on_observed`, not run here."""
        changes: list[OwnershipChange] = []
        for fid in list(self._records):
            rec = self._records[fid]
            age = now_ms - rec.last_heartbeat_ms
            if age <= HEARTBEAT_TIMEOUT_MS:
                continue
            old_owner = rec.owner_peer_id
            new_epoch = self._next_epoch
            self._next_epoch += 1
            del self._records[fid]
            log.debug(
                "ownership: forced release fid=0x%X owner=%s "
                "(heartbeat stale by %.0fms)",
                fid, old_owner, age,
            )
            changes.append(OwnershipChange(
                form_id=fid,
                old_owner_peer_id=old_owner,
                new_owner_peer_id=None,
                new_epoch=new_epoch,
                phase="release",
                reason=f"heartbeat-timeout-{int(age)}ms",
            ))
        return changes
