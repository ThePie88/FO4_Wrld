"""
Server state: tracks all peer sessions and authoritative world state.

Pure data + mutation methods. No I/O, no asyncio here — main.py drives this.
"""
from __future__ import annotations

import dataclasses
import hashlib
import itertools
import logging
import math
import secrets
from collections import OrderedDict
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, ClassVar, Optional

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from channel import ReliableChannel  # noqa: E402
from protocol import (  # noqa: E402
    WorldItemOpPayload, WorldItemAckPayload, WORLD_ITEM_DROP, WORLD_ITEM_PICKUP,
    WORLD_SPAWN_FLAG_SELF_DESCRIBED, INSTANCE_FLAG_OIE, INSTANCE_FLAG_HEALTH,
    MessageType, MAX_CLIENT_ID_LEN,
    WelcomePayload, PeerJoinPayload, PeerLeavePayload,
    PosStatePayload, ActorEventPayload,
    ContainerOpPayload, ContainerOpKind, ContainerOpAckPayload,
    EquipModRecord,
    is_runtime_form_id,
    identities_conflict,
    COUNT_MAX,
    RejectCode, RESUME_TOKEN_LEN, RESUME_TOKEN_TTL_S,
    FP_PLAIN, FP_UNKNOWN, INSTANCE_MAX_MODS, InstanceDescriptor, instance_fp,
    INV_ENTRY_EQUIPPED,
    WORLD_SPAWN_FLAG_CONTAINER, wid_container_key,
    PA_FRAME_WEARABLES,
)

log = logging.getLogger("fw.state")


class SessionState(IntEnum):
    PENDING = 1   # received HELLO, WELCOME not yet acked
    ACTIVE = 2    # normal operation
    DEAD = 3      # timeout or disconnect, pending removal


# Token-bucket rate limiter: accept up to BURST packets, refill at RATE/sec
@dataclass(slots=True)
class RateTracker:
    capacity: int = 40            # burst allowance (2s at 20Hz pos + some events)
    refill_per_sec: float = 25.0  # steady-state tokens/sec
    _tokens: float = field(init=False, default=0.0)
    _last_refill_ms: Optional[float] = field(init=False, default=None)

    def __post_init__(self) -> None:
        # Bucket starts full so the first burst is allowed.
        self._tokens = float(self.capacity)

    def consume(self, now_ms: float, amount: float = 1.0) -> bool:
        """Try to consume `amount` tokens. Returns True if allowed, False if over rate."""
        self._refill(now_ms)
        if self._tokens < amount:
            return False
        self._tokens -= amount
        return True

    def _refill(self, now_ms: float) -> None:
        if self._last_refill_ms is None:
            self._last_refill_ms = now_ms
            return
        delta_s = max(0.0, (now_ms - self._last_refill_ms) / 1000.0)
        self._tokens = min(float(self.capacity),
                            self._tokens + delta_s * self.refill_per_sec)
        self._last_refill_ms = now_ms


@dataclass(slots=True)
class PeerSession:
    """One connected peer from the server's perspective."""

    session_id: int
    peer_id: str
    addr: tuple[str, int]
    client_version: tuple[int, int]
    state: SessionState
    joined_at_ms: float
    last_seen_ms: float

    channel: ReliableChannel = field(default_factory=ReliableChannel)
    rate: RateTracker = field(default_factory=RateTracker)
    # Stage 0 of L5 (2026-09-27): item ops (container take/put) get their own
    # bucket. They shared `rate` with the 20 Hz position stream, so a burst of
    # position updates could refuse a Take All with RATE_LIMITED, and a
    # refused take is undone on the client. 40 tokens cover a Take All of a
    # full container; 15/s is far above any hand-driven rate.
    item_rate: RateTracker = field(
        default_factory=lambda: RateTracker(capacity=40, refill_per_sec=15.0))

    # Tracking for validation + debug
    last_pos: Optional[PosStatePayload] = None
    last_pos_at_ms: float = 0.0
    total_pos_updates: int = 0
    total_events: int = 0

    # Build 69s (2026-08-04) — ownership quiescence for a dead/loading peer.
    # A death-release NPC_UNLOAD burst stamps this; while it is in the
    # future the peer is EXCLUDED from threat election (its POS_STATE keeps
    # streaming the corpse position through the whole death-cam + LoadGame,
    # and reeval was measured handing 7 NPCs TO the loading client 155ms
    # before a crash). Cleared by the respawn teleport (a large accepted
    # position jump) or by timeout.
    combat_dead_until_ms: float = 0.0

    # B6.6w5 — Steam ID auth scaffolding. Populated from HELLO.steam_id
    # when the client connects. 0 = unavailable (legacy client OR Steam
    # SDK not loaded on client at HELLO time). NOTE (v19): this is a CLAIM,
    # not an identity — Goldberg lets a pirate put any value here. The
    # verified identity is `identity_hex` below. Phase-2 PIENUVO (Steam
    # ticket check) is what will turn this claim into an attestation.
    steam_id: int = 0

    # v19 PIENUVO — verified identity: hex of the Ed25519 pubkey whose
    # challenge signature this session presented at HELLO. "" = the peer
    # connected unauthenticated (manual FoM start / legacy client).
    # Uniqueness across active sessions is enforced in accept_peer's
    # caller via ServerState.find_identity().
    identity_hex: str = ""
    # v19 — cosmetic display name from the HELLO auth tail. NEVER a key.
    display_name: str = ""
    # Phase 4 — when this peer's last chat messages were relayed, for the
    # flood limit in ServerProtocol._handle_chat. Only the current window is
    # kept, so it never grows past CHAT_BURST entries.
    chat_sent_ms: list[float] = field(default_factory=list)

    # B6.6w5 — local form_id of the engine ghost-actor that represents
    # the OTHER peer on this client's screen. Sent by the client via
    # PEER_GHOST_REGISTER after spawn. Used in raider_brain.project_for_peer
    # so combat_target_form_id substitution targets the right local fid
    # per viewer. 0 = unregistered (ghost not spawned yet, or spawn failed).
    ghost_form_id: int = 0
    # v26 — bootstrap frames waiting their turn, as (msg_type, payload).
    #
    # The join bootstrap used to be dumped into the socket in one synchronous
    # burst: every world object (up to 1024), every lock, every appearance,
    # every presence entry, all registered in flight at once. The receiver's
    # window is 32 frames wide, so anything past that was silently discarded
    # on arrival and had to be retransmitted; with a retransmit cap of 8 the
    # burst could kill the channel of the peer that had just joined. The
    # queue costs nothing and makes the burst much smaller.
    #
    # Corrected 2026-09-19: "impossible" was too strong. Five frame kinds go
    # through the queue (appearance, world spawn, lock, position, equip);
    # world state, container state, quests, global vars, ownership and the two
    # PEER_JOIN rounds still go straight into the socket inside the same
    # bootstrap. The in-flight cap does not cover those. Ordering holds only
    # because the unqueued ones are sent first, not because anything orders
    # them.
    pending_bootstrap: list = field(default_factory=list)
    # One-shot: says once, not sixty times a second, that this peer's
    # position is being withheld from the others pending character creation.
    chargen_hidden_logged: bool = False
    # L5 stage 3a — the checkpoint cadence, per session: the last request
    # number, when it went out, when the last one was reported written, and
    # when a deferred one may be asked again.
    ckpt_seq: int = 0
    ckpt_last_request_ms: float = 0.0
    # L5 realtime R5 (2026-10-16): the last checkpoint asked for a place discovered (the coalesce window).
    location_ckpt_ms: float = 0.0
    ckpt_last_done_ms: float = 0.0
    ckpt_retry_at_ms: float = 0.0
    # L5 stage 3b — the token this session uploads and fetches checkpoint
    # bytes under (minted for the boot word, see server/custody.py).
    bulk_token: bytes = b""

    def touch(self, now_ms: float) -> None:
        self.last_seen_ms = now_ms


@dataclass(slots=True)
class ContainerWorldState:
    """Authoritative inventory state for one container REFR.

    Loot rework L1 (2026-09-23): the key is `form_id`, the placed REFR's
    own id, stable across processes with the same load order. Until then
    the key was (base_id, cell_id), which merged every ref of one base in
    one cell (two identical toolboxes, two corpses of one NPC base) into a
    single record: emptying the first made the server refuse the second,
    and the B1 half-transaction block turned that refusal into a destroyed
    item. `base_id` and `cell_id` stay as the check an op must match and
    as the check the receiver runs on its own REFR. Runtime refs (0xFF
    prefix) are never stored: their ids alias across processes.

    `items` maps (item TESForm.formID, instance fingerprint) -> count (L5
    stage 4b, 2026-10-03; protocol.instance_fp). FP_PLAIN lines hold what
    has no instance data (ammo, aid, junk), one line per instance holds a
    weapon or an armour piece, and an FP_UNKNOWN line is a count of a base
    nobody can name the instance of (a record of a v33 server): it answers a
    take of any instance of its base. Entries with count == 0 are eagerly
    removed (no stale zero keys).

    Loot rework L3 (2026-09-23): `seeded` tells a record the server KNOWS
    (built from a client's full scan) from one it only INFERRED from the
    first op on a container nobody had scanned (the trust-the-client
    fallback). A partial record is never pushed to clients nor put in the
    bootstrap, because aligning an engine to it would destroy every item
    the server never heard of; the validator trusts the client on items a
    partial record has not seen; and the next seed replaces it whole.
    """
    form_id: int
    base_id: int
    cell_id: int
    items: dict[tuple[int, int], int] = field(default_factory=dict)   # (item_base_id, fp) -> count
    last_owner_peer_id: Optional[str] = None
    last_update_ms: float = 0.0
    seeded: bool = False
    # L5 realtime D1 (2026-10-03): the world spawn this container is, when
    # the server made it (the death crate): keyed wid_container_key(wid),
    # an 0xFF id no client ever names otherwise. 0 = a placed REFR.
    wid: int = 0
    # L5 realtime D2 (2026-10-15): whose death made this crate, the ordinal
    # of that death among the peer's (1, 2, 3..., durable) and when; "" / 0
    # for a container that is not a death crate. The owner's map names the
    # crate from the ordinal: the newest crate made is "LATEST DEATH", every
    # other "CORPSE #ordinal", so a crate changes name once at most.
    death_owner: str = ""
    death_ordinal: int = 0
    death_ms: int = 0
    # 2026-10-20: the ops applied to this record while it was PARTIAL, as
    # (peer_id, server ms, kind, item, fp, count) oldest first, and whether
    # the list hit PRE_SEED_OPS_MAX (then it is not trusted). The first full
    # scan that arrives afterwards may come from an engine that no longer
    # holds those ops: the scanner reloaded a save written before them.
    # Live 2026-10-20: a toolbox taken whole with every scan refused (the
    # engine held the list's write lock inside the take), a death 23 s
    # later, the reload of a checkpoint four minutes old, the stale scan of
    # the full toolbox became canonical and its 224 items existed twice. The
    # seed handler applies the scanner's own ops newer than the save its
    # world runs on over the scan (reconcile_scan). Cleared by the scan that
    # seeds the record; never pushed to clients.
    pre_seed_ops: list = field(default_factory=list)
    pre_seed_overflow: bool = False

    def __post_init__(self) -> None:
        # An int key is a plain line (the pre-4b shape): normalized here, so
        # a record built that way is not read as empty by take_order.
        if any(not isinstance(k, tuple) for k in self.items):
            self.items = normalize_items(self.items)

    def count_of(self, item: int, fp: int) -> int:
        """The count of one line."""
        return self.items.get((item, fp), 0)

    def base_total(self, item: int) -> int:
        """Every line of `item`, whatever its instance."""
        return sum(n for (iid, _), n in self.items.items() if iid == item)

    def take_order(self, item: int, fp: int) -> list[tuple[int, int]]:
        """The lines a take of (item, fp) may draw from, in order. A named
        instance: its own line, then the base's unknown line. An unknown
        instance (a client that could not read what it took): the unknown
        line, the plain one, then every other instance of the base in
        fingerprint order, so the choice is the same on every replay."""
        if fp == FP_UNKNOWN:
            rest = sorted(k for k in self.items
                          if k[0] == item and k[1] not in (FP_UNKNOWN, FP_PLAIN))
            return [(item, FP_UNKNOWN), (item, FP_PLAIN)] + rest
        return [(item, fp), (item, FP_UNKNOWN)]

    def available_for(self, item: int, fp: int) -> int:
        """How many a take of (item, fp) may draw."""
        return sum(self.items.get(k, 0) for k in self.take_order(item, fp))


def normalize_items(items: dict) -> dict[tuple[int, int], int]:
    """Container lines as (item, fp) -> count, clamped to the wire. An int
    key is a plain line (FP_PLAIN): the shape every caller used until stage
    4b, and still the natural one for a list of plain items."""
    out: dict[tuple[int, int], int] = {}
    for k, cnt in items.items():
        key = (int(k[0]), int(k[1])) if isinstance(k, tuple) else (int(k), FP_PLAIN)
        n = min(int(cnt), COUNT_MAX)
        if n > 0:
            out[key] = n
    return out


# 2026-10-20: how many ops a partial record remembers (see
# ContainerWorldState.pre_seed_ops); a Take All of a full container is at
# most 128 lines, the cap is for a record nobody ever scans.
PRE_SEED_OPS_MAX = 1024


def apply_op_lines(container: "ContainerWorldState", kind: int, item: int, fp: int,
                   count: int) -> bool:
    """Apply one TAKE/PUT to the lines of `container`: the one way a record
    changes by an op (record_container_op) and the way a scan is reconciled
    with the ops a partial record saw (reconcile_scan). A take draws from
    the lines take_order names, its own instance first; more than they hold
    empties them. False for a deposit that would overflow the wire's count
    (nothing changed)."""
    if kind == int(ContainerOpKind.TAKE):
        remaining = count
        for key in container.take_order(item, fp):
            have = container.items.get(key, 0)
            if have <= 0:
                continue
            used = min(have, remaining)
            if have - used > 0:
                container.items[key] = have - used
            else:
                container.items.pop(key, None)
            remaining -= used
            if remaining <= 0:
                break
        return True
    new_count = container.items.get((item, fp), 0) + count
    if new_count > COUNT_MAX:
        return False
    container.items[(item, fp)] = new_count
    return True


def reconcile_scan(container: "ContainerWorldState", items: dict, peer_id: str,
                   world_base: Optional[tuple[float, float]]
                   ) -> tuple[dict[tuple[int, int], int], int]:
    """The canonical lines a scan of a PARTIAL record makes: the scan, with
    the scanner's own ops that its engine no longer holds applied over it
    again: the ops newer than the save its world runs on and older than the
    load of that save (`world_base` = (save_ms, load_ms), the peer's last
    load as ServerState.note_world_base heard it). Its ops older than the
    save are in the save; its ops newer than the load were made live, in
    the engine the scan came from; another peer's ops may or may not be in
    its engine (whether it applied the broadcast is not known here) and are
    left alone, as before. `world_base` None (the server never heard the
    peer load a world) or an overflowed list keep the scan as it is.
    Returns the lines and how many ops went over the scan. Nothing in
    `container` changes."""
    scratch = ContainerWorldState(form_id=container.form_id, base_id=container.base_id,
                                  cell_id=container.cell_id, items=normalize_items(items))
    if world_base is None or container.pre_seed_overflow:
        return scratch.items, 0
    save_ms, load_ms = float(world_base[0]), float(world_base[1])
    n = 0
    for who, ms, kind, item, fp, count in container.pre_seed_ops:
        if who != peer_id or not (save_ms < float(ms) < load_ms):
            continue
        if apply_op_lines(scratch, int(kind), int(item), int(fp), int(count)):
            n += 1
    return scratch.items, n


@dataclass(slots=True)
class ActorWorldState:
    """Authoritative state for a game-world actor tracked by server.

    Identity key is (base_id, cell_id) — stable across processes.
    `last_known_form_id` is a hint: for placed refs (0x00______) it is stable
    and usable as a LookupByFormID fast-path on the client; for runtime refs
    (0xFF______) it's session-scoped and must be validated against
    (base_id, cell_id) before applying any state.
    """
    base_id: int                               # identity key part 1
    cell_id: int                               # identity key part 2
    alive: bool = True
    last_known_form_id: int = 0                # hint, not key
    last_owner_peer_id: Optional[str] = None   # who last modified it
    last_update_ms: float = 0.0


# B4: world-state replication (quest progress + global variables).
@dataclass(slots=True)
class CheckpointRecord:
    """L5 stage 3a (2026-09-28) — one checkpoint a client reported written.

    The character lives in this file, on the client's disk (custody on the
    server is stage 3b): name, hash and size are what the next boot is held
    to. `watermark_lsn` is the journal head when the report arrived: the
    world the checkpoint saw is the world up to that record, which is what
    stage 4 replays after it. `status`: provisional until a boot loaded it
    (confirmed); `boot_failures` counts the boots that could not use it, and
    two of them take it out of the boot pick.
    """
    peer_id: str
    identity_hex: str = ""
    seq: int = 0
    name: str = ""
    sha256_hex: str = ""
    size: int = 0
    digest: int = 0
    digest_seq: int = 0
    wall_ms: int = 0
    received_ms: float = 0.0
    watermark_lsn: int = 0
    reason: int = 0
    status: str = "provisional"
    boot_failures: int = 0
    # L5 stage 3b (2026-09-28): the server holds the bytes of this checkpoint
    # (an upload hashed to sha256_hex); a boot on any machine can fetch them.
    custody: bool = False
    # L5 realtime D1 (2026-10-04): whether the player saved in it is inside a
    # power armour frame (the inventory digest sent with it says), None
    # when that digest never came. A death puts the player back on foot, so
    # the respawn moves a checkpoint on foot: the newest one is kept past
    # CHECKPOINTS_KEPT while every newer one has them in a frame.
    in_pa: Optional[bool] = None
    # 2026-10-15: the frame (wid) the player wore when the checkpoint was
    # recorded, 0 when none was known. A departure keeps that frame worn
    # (they come back inside it) and the boot takes it back by this wid,
    # whatever form id the save knows it by: an adopted copy is bound to a
    # fid the server never saw, which doubled the frame of a kill inside it.
    in_pa_wid: int = 0
    # 2026-10-20: the server time of the report of the checkpoint whose
    # WORLD this one carries: received_ms for one a client wrote, the
    # source's for the copy a respawn moved, 0 for the genesis save moved
    # onto the point. A peer that loads it runs on a world without the ops
    # recorded after this time (ServerState.note_world_base, reconcile_scan).
    world_ms: float = 0.0


CHECKPOINTS_KEPT = 3

# L5 realtime D1 (2026-10-04): the wearable the engine equips on entering a
# power armour frame (ArmorPoweredFrame). Since 2026-10-05 one of
# protocol.PA_FRAME_WEARABLES: never inventory, never in a record.
PA_FRAME_WEARABLE = 0x0003E577


@dataclass(slots=True)
class InvDigestRecord:
    """L5 stage 2 (2026-09-27) — the last inventory digest a peer reported.

    ADVISORY: written by INV_DIGEST, read by nobody yet. Stage 3 compares a
    checkpoint against it, stage 4's ledger is what will judge an inventory.
    `count` is how many digests this peer has sent since the record was
    created, live and replayed alike; `received_ms` is the server clock.
    """
    peer_id: str
    seq: int = 0
    wall_ms: int = 0
    digest: int = 0
    entries: int = 0
    stacks: int = 0
    items: int = 0
    reasons: int = 0
    flags: int = 0
    why: int = 0
    received_ms: float = 0.0
    count: int = 0


# L5 realtime R1 (2026-10-03): bounds of a player's inventory record.
PLAYER_INV_MAX_LINES: int = 5120     # 64 frames of 80 lines (validator)
PLAYER_INV_MAX_PENDING: int = 4096   # accepted ops waiting for a capture


@dataclass(slots=True)
class PlayerInvRecord:
    """L5 realtime persistence, R1 (2026-10-03) - the player's inventory as
    the server holds it: the last capture the client sent, with the
    container ops the server accepted after it on top.

    The owner's decision of 2026-10-03: Alt+F4, a crash and a death lose
    nothing, so the server keeps the character current instead of waiting
    for the next checkpoint. `lines` is (item, fingerprint) -> count, the
    same lines a container holds; the descriptors of the instances are in
    the state's registry. A capture names the last op it includes
    (`watermark`, an op id of epoch `op_epoch`: a client process numbers its
    ops epoch << 16 | seq); the accepted ops of that epoch after it stay in
    `pending` and are applied again over the next capture that does not
    include them. An op of another epoch belongs to a process that is gone:
    the restore after the load absorbed it, and the first capture of the new
    process drops it. `captures` 0 = no capture under the record yet: ops
    alone are not an inventory and the restore must not align a player to
    them.

    R2 (2026-10-03): `open_session` is the process whose captures are the
    record. A new process gets the record back after its load (PLAYER_INV)
    and opens it with RESTORE_DONE; until then its captures are refused,
    because a capture taken over the old checkpoint would write the past
    over the record. A record with no capture under it is open to anyone,
    and the first capture of a new character opens it to its process.
    """
    peer_id: str
    lines: dict = field(default_factory=dict)       # (item, fp) -> count
    equipped: set = field(default_factory=set)      # (item, fp)
    session: int = 0
    seq: int = 0
    watermark: int = 0
    op_epoch: int = 0
    flags: int = 0
    digest: int = 0
    pending: list = field(default_factory=list)     # (op_id, kind, item, fp, count)
    captures: int = 0
    updated_ms: float = 0.0
    open_session: int = 0


def _frame_item_counts(pieces) -> dict[int, int]:
    """form -> count of a frame's content: (form, count) pairs or the ledger's
    (form, count, mods, health) entries. Malformed entries are skipped."""
    out: dict[int, int] = {}
    for p in pieces or ():
        try:
            form = int(p[0]) & 0xFFFFFFFF
            count = int(p[1]) if len(p) > 1 else 1
        except (TypeError, ValueError, IndexError):
            continue
        if form and count > 0:
            out[form] = out.get(form, 0) + count
    return out


def _take_from_lines(lines: dict, equipped: set, counts: dict[int, int]) -> dict:
    """Up to counts[base] units of each base out of `lines` ((item, fp) ->
    count), the equipped lines first (what is mounted is equipped); a line
    emptied goes, with its equipped mark. What left, by line."""
    left: dict = {}
    for base, want in counts.items():
        keys = sorted((k for k in lines if k[0] == base), key=lambda k: (k not in equipped, k[1]))
        for k in keys:
            if want <= 0:
                break
            n = min(int(lines[k]), want)
            if n <= 0:
                continue
            lines[k] -= n
            want -= n
            left[k] = left.get(k, 0) + n
            if lines[k] <= 0:
                del lines[k]
                equipped.discard(k)
    return left


def _seq16_after(a: int, b: int) -> bool:
    """True when the 16-bit op sequence number `a` comes after `b` (serial
    arithmetic: a process numbers more than 65535 ops by wrapping)."""
    d = (a - b) & 0xFFFF
    return 0 < d < 0x8000


def _inv_apply_op(lines: dict, kind: int, item: int, fp: int, count: int) -> int:
    """One accepted container op on a player's lines. A take adds its
    instance; a put removes its instance, then the unknown line of the item
    (the record may still hold the unread copy). Returns what a put found
    nothing to remove from: the record was behind the client, the next
    capture puts it right; never a negative count."""
    if kind == int(ContainerOpKind.TAKE):
        lines[(item, fp)] = min(COUNT_MAX, lines.get((item, fp), 0) + count)
        return 0
    if fp == FP_UNKNOWN:
        order = ((item, FP_UNKNOWN), (item, FP_PLAIN))
    else:
        order = ((item, fp), (item, FP_UNKNOWN))
    remaining = count
    for key in order:
        have = lines.get(key, 0)
        if have <= 0:
            continue
        used = min(have, remaining)
        if have - used > 0:
            lines[key] = have - used
        else:
            lines.pop(key, None)
        remaining -= used
        if remaining <= 0:
            break
    return remaining


@dataclass(slots=True)
class PlayerStatsRecord:
    """L5 realtime R4 (2026-10-03) - the character's numbers as the server
    holds them: the last stats capture of the process the inventory record
    belongs to (the same gate, see PlayerInvRecord.open_session). XP is the
    Experience actor value (the level follows from it in the engine),
    `special` the seven base values, `perks` perk form -> rank."""
    peer_id: str
    session: int = 0
    seq: int = 0
    level: int = 0
    xp: float = 0.0
    perk_points: int = 0
    special: tuple = (0.0,) * 7
    health: float = 0.0
    action_points: float = 0.0
    rads: float = 0.0
    perks: dict = field(default_factory=dict)
    captures: int = 0
    updated_ms: float = 0.0


@dataclass(slots=True)
class QuestStageState:
    """Authoritative stage for one quest.

    Keyed by quest_form_id (stable plugin-loaded TESForm.formID). The engine
    enforces stage monotonicity at the Papyrus level (SetStage refuses to
    go backwards unless ResetQuest is called), so the validator treats
    last-write-wins as a valid best-effort. If a reset happens, it just
    broadcasts the lower number and all peers catch up.
    """
    quest_form_id: int
    stage: int = 0
    last_owner_peer_id: Optional[str] = None
    last_update_ms: float = 0.0


@dataclass
class WorldSpawnState:
    """B6.14 v22 — one server-owned spawned world object.

    `wid` is the shared logical name; every client maps it to its own local
    REFR. `spawner_local_fid` matters only for the live echo to the spawner —
    on the join bootstrap everyone re-places from scratch, spawner included,
    because the local originals are TEMPORARY refs that die with the session.
    Transient spawns (flags bit0) are broadcast but never stored here.
    """
    wid: int
    spawner_peer: str
    base_form_id: int
    spawner_local_fid: int
    px: float
    py: float
    pz: float
    rx: float
    ry: float
    rz: float
    cell_id: int
    flags: int
    timestamp_ms: int
    # v23 — PA frame content: list of (form_id, count). The ledger here is
    # AUTHORITATIVE: spawn announces seed it, WORLD_PA_PIECES_OP replaces
    # it, every broadcast and the join bootstrap carry it.
    pieces: tuple = ()
    # v26 — who is WEARING this frame, "" when nobody is.
    #
    # Entering power armor makes the engine disable the frame REFR, which the
    # client reports as an ordinary death (reason 2). Before v26 the server
    # deleted the record, and since "removal persists by omission" that also
    # erased the piece ledger: if the wearer then quit or crashed, the exit
    # that would have re-announced the frame never arrived and the armour was
    # gone for everyone, in every future session. Now the record survives,
    # marked, and is skipped by the join bootstrap so no ghost frame is placed
    # in the world while somebody is inside it.
    worn_by_peer_id: str = ""
    worn_since_ms: float = 0.0


@dataclass(slots=True)
class LockWorldState:
    """B6.3 v0.5.3 — authoritative lock state for one REFR.

    Identity key is (base_id, cell_id) — same stability rationale as
    actor / container state. `form_id` is a hint for receiver-side
    LookupByFormID; not a key. `locked` is the boolean state. `level`
    and `key_form` are static world data and not tracked here (server
    only cares about state transitions).
    """
    base_id: int
    cell_id: int
    form_id: int = 0
    locked: bool = True
    timestamp_ms: int = 0


@dataclass(slots=True)
class GlobalVarState:
    """Authoritative value of one GlobalVariable (TESGlobal).

    Value stored as float — matches the engine's own internal representation
    (int-typed globals are floats rounded to int at Papyrus boundaries).
    """
    global_form_id: int
    value: float = 0.0
    last_owner_peer_id: Optional[str] = None
    last_update_ms: float = 0.0


@dataclass(frozen=True, slots=True)
class OutfitEntry:
    """One item a peer currently wears, as last seen on the wire.

    Equipment reaches the server as CHANGE notifications, never as a
    snapshot: one EQUIP_OP per item, and an UNEQUIP that carries nothing but
    the form id. So the replayable model is a dictionary keyed by item, an
    equip inserts or replaces, an unequip pops. Every field here is exactly
    what `EquipBroadcastPayload` needs, because the replay to a late joiner
    is that same message and nothing else: the client cannot tell a replayed
    outfit from a live equip, and that is the point.
    """
    item_form_id: int
    slot_form_id: int
    count: int
    effective_priority: int
    mods: tuple = ()          # tuple[EquipModRecord, ...]
    timestamp_ms: int = 0


@dataclass(slots=True)
class PeerPresence:
    """What a peer looks like right now, kept so somebody who joins later can
    be shown the same thing the peers already connected can see.

    Keyed by peer_id and deliberately NOT deleted when the peer leaves: that
    is what makes a late join work hours later, and it mirrors how the
    appearance recipe has always behaved.

    The outfit is only ever as complete as the equip events the server has
    witnessed. Items a player was already wearing when the save loaded fire
    no engine event at all, so they are missing here until the client learns
    to announce them (a later phase). This is a known, deliberate hole, not
    an oversight.
    """
    peer_id: str
    display_name: str = ""
    last_pos: Optional[Any] = None       # PosStatePayload
    last_pos_at_ms: float = 0.0
    outfit: dict = field(default_factory=dict)   # item_form_id -> OutfitEntry
    worn_frame_wid: int = 0
    updated_at_ms: float = 0.0


@dataclass(frozen=True, slots=True)
class ResumeTicket:
    """A minted resume token and what it entitles the bearer to.

    The launcher's login proof is single use and the game DLL holds no
    private key, so without this a client that drops cannot prove who it is
    and has to be relaunched through the launcher. The token is a bearer
    credential: whoever holds it gets the session. It is therefore bound to
    one identity, expires, and is rotated on every use.
    """
    peer_id: str
    identity_hex: str
    issued_at_ms: float
    expires_at_ms: float


def _token_deadline_ms(ticket: "ResumeTicket") -> float:
    """When a resume token stops being valid: the stored expiry, never later
    than issue time plus the TTL. Stage 0 of L5 (2026-09-27): persisted
    times were on the monotonic clock, so after a reboot a token minted at
    uptime 90,000 s came back with a deadline the new uptime would not reach
    for a day. The clamp makes a stored deadline mean what it says whatever
    clock wrote it; the server clock is wall-clock anchored since the same
    change, so new tokens compare correctly across restarts."""
    return min(ticket.expires_at_ms, ticket.issued_at_ms + RESUME_TOKEN_TTL_S * 1000.0)


def _token_key(token: bytes) -> bytes:
    """Resume tokens are bearer credentials, so what the server keeps (in
    memory, in the snapshot, in the journal) is their SHA-256, never the
    token: a copy of the world file no longer lets anyone rejoin as
    somebody else. Stage 1 of L5, 2026-09-27."""
    return hashlib.sha256(token).digest()


# ---------------------------------------------------------------- journal
#
# Every mutation of the world that `ServerState` accepts is described to
# the journal as (method name, arguments) and replayed by calling the same
# method again (stage 1 of L5, 2026-09-27; see server/journal.py). The
# arguments are made JSON-safe here: a payload dataclass is tagged with its
# class name, bytes travel as hex, a dict with integer keys as a list of
# pairs; lists come back as tuples, which every method here accepts. A
# method whose replay must not re-derive something (a world spawn's wid, a
# resume token's hash) has a `_restore_*` twin that takes the derived value.

_JOURNAL_TYPES: dict[str, type] = {
    cls.__name__: cls
    for cls in (ContainerOpPayload, ActorEventPayload, ContainerOpAckPayload,
                EquipModRecord, OutfitEntry, InstanceDescriptor,
                WorldItemOpPayload, WorldItemAckPayload)
}


def _jsonable(v: Any) -> Any:
    if dataclasses.is_dataclass(v) and not isinstance(v, type):
        return {"__cls__": type(v).__name__,
                "f": {f.name: _jsonable(getattr(v, f.name))
                      for f in dataclasses.fields(v)}}
    if isinstance(v, bytes):
        return {"__bytes__": v.hex()}
    if isinstance(v, dict):
        return {"__dict__": [[_jsonable(k), _jsonable(x)] for k, x in v.items()]}
    if isinstance(v, (list, tuple, set, frozenset)):
        return [_jsonable(x) for x in v]
    if v is None or isinstance(v, (bool, int, float, str)):
        return v
    raise TypeError(f"journal cannot encode {type(v).__name__}")


def _from_jsonable(v: Any) -> Any:
    if isinstance(v, dict):
        if "__cls__" in v:
            cls = _JOURNAL_TYPES[v["__cls__"]]
            return cls(**{k: _from_jsonable(x) for k, x in v["f"].items()})
        if "__bytes__" in v:
            return bytes.fromhex(v["__bytes__"])
        if "__dict__" in v:
            return {_from_jsonable(k): _from_jsonable(x) for k, x in v["__dict__"]}
        return {k: _from_jsonable(x) for k, x in v.items()}
    if isinstance(v, list):
        return tuple(_from_jsonable(x) for x in v)
    return v


# The methods a journal record may name, and what replays them. Anything
# else in a record is refused with a warning: a record from a newer server
# names nothing this one can run.
_JOURNAL_OPS: dict[str, str] = {
    "record_actor_event": "record_actor_event",
    "record_container_op": "record_container_op",
    "create_container": "create_container",
    "reseed_container": "reseed_container",
    "forget_container": "forget_container",
    "remember_container_verdict": "remember_container_verdict",
    "record_instance_def": "record_instance_def",
    "record_quest_stage": "record_quest_stage",
    "record_global_var": "record_global_var",
    "record_inv_digest": "record_inv_digest",
    "record_player_inventory": "record_player_inventory",
    "record_player_restored": "record_player_restored",
    "record_player_stats": "record_player_stats",
    "record_death_crate": "record_death_crate",
    "record_death": "record_death",
    "remove_wid_container": "remove_wid_container",
    "record_pieces_to_frame": "record_pieces_to_frame",
    "record_pieces_from_frame": "record_pieces_from_frame",
    "record_checkpoint": "record_checkpoint",
    "confirm_checkpoint": "confirm_checkpoint",
    "set_checkpoint_custody": "set_checkpoint_custody",
    "record_appearance": "record_appearance",
    "record_lock": "record_lock",
    "record_world_spawn": "_restore_world_spawn",
    "remove_world_spawn": "remove_world_spawn",
    "record_world_drop": "_restore_world_drop",
    "record_world_pickup": "record_world_pickup",
    "remember_world_item_verdict": "remember_world_item_verdict",
    "set_world_spawn_pieces": "set_world_spawn_pieces",
    "mark_world_spawn_worn": "mark_world_spawn_worn",
    "return_worn_frame": "return_worn_frame",
    "record_presence_name": "record_presence_name",
    "record_presence_equip": "record_presence_equip",
    "clear_presence_outfit": "clear_presence_outfit",
    "record_presence_worn_frame": "record_presence_worn_frame",
    "drop_items_from_outfit": "drop_items_from_outfit",
    "issue_resume_token": "_restore_resume_token",
    "retire_resume_tokens": "retire_resume_tokens",
    "forget_peer": "forget_peer",
    "note_world_base": "note_world_base",
    "consume_resume_token": "_consume_resume_token_hash",
}


def _peer_id_invalid(peer_id: str) -> bool:
    """The one place that decides whether a peer id is well formed."""
    if not peer_id or len(peer_id) > MAX_CLIENT_ID_LEN:
        return True
    if not peer_id.isascii() or not all(c.isalnum() or c in "_-" for c in peer_id):
        return True
    return False


@dataclass(slots=True)
class ServerState:
    """Total server-side state. Thread-unsafe — only one asyncio task may mutate."""

    tick_rate_hz: int = 20
    server_version: tuple[int, int] = (1, 0)
    # Five seconds, and it stays five seconds by decision, 2026-09-18.
    #
    # v26 had raised this to 15 s: with a resume token a rejoin is invisible,
    # so the timeout could afford to survive a network hiccup instead of
    # kicking on one. That raise NEVER took effect. The snapshot carries this
    # field and restores it on every boot, so the running servers kept the
    # 5 s written in an older snapshot while the code claimed 15 s — a knob
    # that no longer turned, and nobody noticed for a whole phase.
    #
    # Asked, and the answer was to keep five seconds: a ghost left standing
    # is the thing you SEE, a peer evicted on a hiccup is the thing you can
    # retry. The real fix for a clean exit is a goodbye on the wire, not a
    # longer timeout, and that is still owed. The number is written here to
    # match what actually runs; see load_snapshot, which now says out loud
    # when a snapshot overrides it.
    peer_timeout_ms: float = 5_000.0
    # Dedicated-server capacity. accept_peer refuses past this with a reason
    # the browser can show. 0 = unlimited (used by tests).
    max_players: int = 0
    # v21 — the entry ritual. When True, an identity the server has never seen
    # is told to create a character before it becomes visible to anyone.
    #
    # Default False, and deliberately so while the editor does not exist: a
    # server that demands a ritual no client can perform would leave every new
    # player invisible with no way out. Turn it on with the editor, not before.
    #
    # When False a new player simply spawns as the documented default — nude,
    # bald, no eyes — which is the settled skip behaviour, not a placeholder.
    require_chargen: bool = False

    # TESNPC base formIDs used as ghost avatars in the rendering layer.
    # Kill/disable events targeting these bases are rejected at the validator
    # to preserve the ghost pipeline. Resurrecting the avatar still works
    # (ENABLE/SPAWN pass through). Configurable at server construction.
    #
    # IMPORTANT: use the BASE (TESNPC) formID, NOT the REF (placed REFR).
    # For Codsworth on FO4 1.11.191 the pair is:
    #   ref  = 0x1CA7D (the placed reference in Sanctuary) — used client-side
    #                   for LookupByFormID to drive the ghost actor
    #   base = 0x179FF (the TESNPC "Codsworth" record in Fallout4.esm) —
    #                   used here for persistence exemption
    # Verified live via the Frida kill hook: kill on ref 0x1CA7D reports
    # base 0x179FF in its readRefIdentity() output.
    ghost_target_base_ids: frozenset[int] = frozenset({0x179FF})

    _sessions_by_addr: dict[tuple[str, int], PeerSession] = field(default_factory=dict)
    _sessions_by_peer_id: dict[str, PeerSession] = field(default_factory=dict)
    _session_id_counter: "itertools.count[int]" = field(
        default_factory=lambda: itertools.count(1)
    )
    # Primary index: identity tuple (base_id, cell_id) -> world state.
    # Never index by form_id directly — ref IDs alias across processes for
    # runtime (0xFF______) refs. See step 1 of Option B for rationale.
    _world_actors: dict[tuple[int, int], ActorWorldState] = field(default_factory=dict)
    # Container inventories, keyed by the placed REFR's form_id (loot rework
    # L1, see ContainerWorldState), NOT by the (base, cell) scheme above.
    _containers: dict[int, ContainerWorldState] = field(default_factory=dict)
    # L5 stage 4b: instance fingerprint -> (item base, descriptor), for every
    # instance a deposit, a seed or an INSTANCE_DEFS made known. What a
    # receiver needs to rebuild a line; the snapshot keeps the ones a line
    # still names.
    _instances: dict[int, tuple[int, InstanceDescriptor]] = field(default_factory=dict)
    # Loot rework L2: the verdicts of the last CONTAINER_OPs of every peer,
    # keyed by peer id because a rejoin is a new session. The client applies
    # its take at once and sends the op afterwards, so an op whose ACK died
    # with the session is sent again on the rejoin: it must get the same
    # verdict and be applied once. Not persisted: a server restart inside
    # that window is a known residue.
    CONTAINER_VERDICTS_KEPT: ClassVar[int] = 256
    # L5 realtime R1b (2026-10-05): the verdicts of the world item ops (drops
    # and pickups): the same op id sequence as the container ops, another ack.
    _world_item_verdicts: dict[str, "OrderedDict[int, WorldItemAckPayload]"] = field(
        default_factory=dict)
    # L5 realtime D2: how many deaths each peer had, durable (record_death in
    # the journal, death_counts in the snapshot). The crate of the n-th death
    # carries ordinal n; the client calls the crate whose ordinal equals the
    # count "LATEST DEATH", every other "CORPSE #n", so a death that leaves
    # no crate (nothing to drop) still turns the last crate into a corpse
    # (the first live test, 2026-10-15). Never below the ordinal of a crate
    # still in the world: a forgotten peer whose old crates stay starts
    # above them (two crates called #4 on the same map, same test).
    _death_counts: dict[str, int] = field(default_factory=dict)
    # 2026-10-20: per peer, (save_ms, load_ms): the server time of the report
    # of the checkpoint its world was loaded from (CheckpointRecord.world_ms;
    # 0 = the genesis save) and the time of that load. Its engine holds no op
    # recorded after the save and before the load (an op after the load is
    # in the engine, made live): a scan it sends of a container it changed
    # before anyone scanned it is reconciled with those ops (reconcile_scan).
    # Absent until the peer was heard loading a world. Journaled and in the
    # snapshot: the scan can come a server restart later.
    _world_base_ms: dict[str, tuple[float, float]] = field(default_factory=dict)
    _container_verdicts: dict[str, "OrderedDict[int, ContainerOpAckPayload]"] = field(
        default_factory=dict)
    # B4: quest stages, keyed by quest_form_id.
    _quests: dict[int, QuestStageState] = field(default_factory=dict)
    # B4: global variables, keyed by global_form_id.
    _globals: dict[int, GlobalVarState] = field(default_factory=dict)
    # L5 stage 2: peer_id -> the last inventory digest it reported (advisory).
    _inv_digests: dict[str, InvDigestRecord] = field(default_factory=dict)
    # L5 realtime R1: peer_id -> its inventory record (PlayerInvRecord).
    _player_inv: dict[str, PlayerInvRecord] = field(default_factory=dict)
    # L5 realtime R4: peer_id -> its stats record (PlayerStatsRecord).
    _player_stats: dict[str, PlayerStatsRecord] = field(default_factory=dict)
    # L5 stage 3a: peer_id -> its checkpoints, newest first, CHECKPOINTS_KEPT deep.
    _checkpoints: dict[str, list[CheckpointRecord]] = field(default_factory=dict)
    # v20 — peer_id -> appearance recipe line. See record_appearance for why
    # the server stores it verbatim and does not parse it.
    _appearances: dict[str, str] = field(default_factory=dict)
    # B6.3 v0.5.3: lock states keyed by (base_id, cell_id).
    lock_state: dict[tuple[int, int], LockWorldState] = field(default_factory=dict)
    # B6.14 — spawned world objects, keyed by wid. Server-owned lifetime.
    world_spawns: dict[int, WorldSpawnState] = field(default_factory=dict)
    next_world_spawn_wid: int = 1
    # v26 — peer_id -> PeerPresence. Survives the peer leaving, exactly like
    # the appearance recipe above, because that is what a late joiner needs.
    _presence: dict[str, PeerPresence] = field(default_factory=dict)
    # v26 — SHA-256 of the resume token -> ticket (hashed since stage 1 of
    # L5; see _token_key). In memory and in the snapshot, because a server
    # restart must not lock every client out.
    _resume_tokens: dict[bytes, ResumeTicket] = field(default_factory=dict)

    # Stage 1 of L5 (2026-09-27) — the durable journal, when the server runs
    # with one (server/journal.py). Every mutation below that returns
    # success appends a record through _journal(); `applied_lsn` is the LSN
    # of the last one, live or replayed, and the snapshot carries it so a
    # boot replays only what came after.
    journal: Any = field(default=None, repr=False)
    applied_lsn: int = 0
    _replaying: bool = field(default=False, repr=False)

    # ---------------------------------------------------------- journal

    def _journal(self, _op: str, **args: Any) -> None:
        # The name is private so no method argument can collide with it
        # (record_container_op passes its payload as `op`).
        if self._replaying or self.journal is None:
            return
        self.applied_lsn = self.journal.append(
            _op, {k: _jsonable(v) for k, v in args.items()})

    def begin_replay(self) -> None:
        self._replaying = True

    def end_replay(self) -> None:
        self._replaying = False

    def apply_journal_record(self, op: str, args: dict[str, Any], lsn: int) -> bool:
        """Run one journal record against this state. False when the record
        names nothing this server can run or the call raised; the world is
        left as it was before that record."""
        method = _JOURNAL_OPS.get(op)
        if method is None:
            log.warning("journal record lsn=%d names unknown op %r: skipped", lsn, op)
            return False
        try:
            kwargs = _from_jsonable(args)
            getattr(self, method)(**kwargs)
        except Exception as e:  # noqa: BLE001 - one bad record must not stop the boot
            log.warning("journal record lsn=%d (%s) could not be applied: %s",
                        lsn, op, e)
            return False
        self.applied_lsn = lsn
        return True

    # ---------------------------------------------------------- session mgmt

    def reset_world(self) -> None:
        """Drop every persisted world record, keeping the live sessions.

        Used by the boot restore when a snapshot copy fails to load half
        way through, so the next copy starts from a clean state instead of
        a mixture of two files (stage 0 of L5, 2026-09-27)."""
        self._world_actors.clear()
        self._containers.clear()
        self._container_verdicts.clear()
        self._world_item_verdicts.clear()
        self._quests.clear()
        self._globals.clear()
        self._inv_digests.clear()
        self._player_inv.clear()
        self._player_stats.clear()
        self._checkpoints.clear()
        self._appearances.clear()
        self.lock_state.clear()
        self.world_spawns.clear()
        self.next_world_spawn_wid = 1
        self._presence.clear()
        self._resume_tokens.clear()
        self._world_base_ms.clear()

    def accept_peer(
        self,
        addr: tuple[str, int],
        peer_id: str,
        client_version: tuple[int, int],
        now_ms: float,
        on_evict=None,
    ) -> tuple[Optional[PeerSession], str]:
        """Register a new peer. Returns (session, reason). session=None if rejected.

        Reasons for rejection:
        - "peer_id_taken": ID already used by an active peer
        - "peer_id_invalid": bad format
        - "version_mismatch": major version different from server

        `on_evict(session)` is called for every session this admission
        displaces, BEFORE it is removed. v26: without it the two eviction
        branches below dropped a session silently, so the NPCs that peer owned
        stayed owned by a peer that no longer existed and the other clients
        were never told it had gone. The callback lets the caller run the same
        teardown a timeout runs, which is the only correct answer.
        """
        if _peer_id_invalid(peer_id):
            return (None, "peer_id_invalid")

        # If same addr already has session (reconnection with same IP:port), replace it
        existing = self._sessions_by_addr.get(addr)
        if existing is not None:
            if on_evict is not None:
                on_evict(existing)
            self._remove_session(existing)

        # Same peer_id from a DIFFERENT address: either a genuine duplicate, or
        # the same player reconnecting after a crash (the relaunched process
        # gets a fresh UDP source port, so the addr-equality branch above
        # cannot recognise it). Tell them apart by whether the old session is
        # still ALIVE: a client that is still heartbeating is a real collision
        # and must be refused, exactly as before; one that has gone silent past
        # the timeout is a corpse and must not keep the id hostage.
        prior = self._sessions_by_peer_id.get(peer_id)
        if prior is not None:
            if (now_ms - prior.last_seen_ms) <= self.peer_timeout_ms:
                return (None, "peer_id_taken")
            if on_evict is not None:
                on_evict(prior)
            self._remove_session(prior)

        # Version check: same major required
        if client_version[0] != self.server_version[0]:
            return (None, "version_mismatch")

        # Capacity. Checked AFTER the reconnect eviction on purpose: a player
        # rejoining must not be told the server is full because their own ghost
        # session is still occupying a slot.
        if self.max_players > 0 and \
                len(self._sessions_by_peer_id) >= self.max_players:
            return (None, "server_full")

        session = PeerSession(
            session_id=next(self._session_id_counter),
            peer_id=peer_id,
            addr=addr,
            client_version=client_version,
            state=SessionState.ACTIVE,
            joined_at_ms=now_ms,
            last_seen_ms=now_ms,
        )
        self._sessions_by_addr[addr] = session
        self._sessions_by_peer_id[peer_id] = session
        return (session, "ok")

    def get_by_addr(self, addr: tuple[str, int]) -> Optional[PeerSession]:
        return self._sessions_by_addr.get(addr)

    def get_by_peer_id(self, peer_id: str) -> Optional[PeerSession]:
        return self._sessions_by_peer_id.get(peer_id)

    def find_live_identity(self, identity_hex: str,
                           now_ms: float) -> Optional[PeerSession]:
        """v19: the session currently holding this verified identity, if it is
        still alive (same staleness rule as the peer_id reconnect logic: a
        silent-past-timeout session is a corpse, not a holder). Linear scan —
        player counts here are single digits."""
        if not identity_hex:
            return None
        for s in self._sessions_by_addr.values():
            if (s.identity_hex == identity_hex
                    and (now_ms - s.last_seen_ms) <= self.peer_timeout_ms):
                return s
        return None

    def all_sessions(self) -> list[PeerSession]:
        return list(self._sessions_by_addr.values())

    def other_sessions(self, exclude_addr: tuple[str, int]) -> list[PeerSession]:
        return [s for s in self._sessions_by_addr.values() if s.addr != exclude_addr]

    def ghost_visible(self, peer_id: str) -> bool:
        """Whether this peer's body may be shown to the other clients yet.

        A peer who has not finished character creation has no business appearing
        in anyone else's world: their character does not exist yet, and the body
        that would be drawn is the documented default -- nude, bald, no eyes.
        Worse, they are parked ten thousand units up in the sky while they work,
        so the alternative to hiding them is a naked mannequin hanging over the
        map.

        Having submitted an appearance IS having finished: the client suppresses
        publishing for as long as the editor is open and publishes on the tick the
        flag goes down, so the recipe's arrival is the confirmation. No new message
        type and no extra state to keep in step.

        Only meaningful when the server asked for the ritual in the first place.
        With require_chargen off, nobody is expected to have a recipe and everyone
        is visible as before.
        """
        if not self.require_chargen:
            return True
        return self.appearance(peer_id) is not None

    def expire_stale(self, now_ms: float) -> list[PeerSession]:
        """Remove peers not heard from in peer_timeout_ms. Returns removed sessions."""
        stale: list[PeerSession] = []
        for s in list(self._sessions_by_addr.values()):
            if now_ms - s.last_seen_ms > self.peer_timeout_ms:
                stale.append(s)
                self._remove_session(s)
        return stale

    def remove(self, peer_id: str) -> Optional[PeerSession]:
        """Force-remove a peer by id. Returns the removed session or None."""
        s = self._sessions_by_peer_id.get(peer_id)
        if s is not None:
            self._remove_session(s)
        return s

    def _remove_session(self, s: PeerSession) -> None:
        self._sessions_by_addr.pop(s.addr, None)
        self._sessions_by_peer_id.pop(s.peer_id, None)
        s.state = SessionState.DEAD

    # ---------------------------------------------------------- game state

    def record_actor_event(
        self, event: ActorEventPayload, by_peer_id: str, now_ms: float
    ) -> Optional[ActorWorldState]:
        """Apply an ActorEvent to the authoritative world state.

        Returns the updated ActorWorldState, or None if the event lacked
        a stable identity (base_id=0 or cell_id=0). Events without identity
        are not persisted — they may still be broadcast by the caller, but
        they won't survive a server restart.
        """
        actor = self._apply_actor_event(event, by_peer_id, now_ms)
        if actor is None:
            return None
        self._journal("record_actor_event", event=event, by_peer_id=by_peer_id,
                      now_ms=now_ms)
        return actor

    def _apply_actor_event(
        self, event: ActorEventPayload, by_peer_id: str, now_ms: float
    ) -> Optional[ActorWorldState]:
        """The state side of record_actor_event, without the journal: the
        pickup of a REFR of the save (R1b, record_world_pickup) marks it
        inside its own journal record."""
        if event.actor_base_id == 0 or event.cell_id == 0:
            return None
        # ActorEventKind: SPAWN=1, KILL=2, DISABLE=3, ENABLE=4
        key = (event.actor_base_id, event.cell_id)
        actor = self._world_actors.get(key)
        if actor is None:
            actor = ActorWorldState(
                base_id=event.actor_base_id,
                cell_id=event.cell_id,
                alive=True,
            )
            self._world_actors[key] = actor
        if event.kind == 1:       # SPAWN
            actor.alive = True
        elif event.kind == 2:     # KILL
            actor.alive = False
        elif event.kind == 3:     # DISABLE
            actor.alive = False
        elif event.kind == 4:     # ENABLE
            actor.alive = True
        actor.last_known_form_id = event.form_id
        actor.last_owner_peer_id = by_peer_id
        actor.last_update_ms = now_ms
        return actor

    def actor_state(self, base_id: int, cell_id: int) -> Optional[ActorWorldState]:
        """Identity-keyed lookup."""
        if base_id == 0 or cell_id == 0:
            return None
        return self._world_actors.get((base_id, cell_id))

    def actor_state_for_event(
        self, event: ActorEventPayload
    ) -> Optional[ActorWorldState]:
        """Resolve the stored state matching this event's identity. Returns
        None if the event lacks identity (base/cell = 0) OR if the identity
        has never been seen before."""
        return self.actor_state(event.actor_base_id, event.cell_id)

    def all_actors(self) -> list[ActorWorldState]:
        return list(self._world_actors.values())

    # ---------------------------------------------------------- container state

    def record_container_op(
        self, op: ContainerOpPayload, by_peer_id: str, now_ms: float
    ) -> Optional[ContainerWorldState]:
        """Apply a TAKE/PUT op to authoritative container state.

        Returns the updated ContainerWorldState, or None if:
        - op lacks a usable identity (form_id 0 or a runtime ref, base=0
          or cell=0)
        - the REFR is known with another (base, cell): load-order drift,
          the record is left alone
        - op.count <= 0 (invalid — must be positive even for TAKE)
        - kind unknown

        Semantics:
          TAKE: decrement items[item_base_id] by count. If result <= 0,
                remove the key entirely (no stale zeros). If the container
                doesn't have that item or insufficient count, the op is
                still RECORDED (last-write-wins) but clamped to 0 — the
                validator upstream should have rejected truly invalid ones.
          PUT:  increment items[item_base_id] by count.
        """
        if (op.container_form_id == 0
                or op.container_base_id == 0 or op.container_cell_id == 0):
            return None
        if op.count <= 0:
            return None
        if op.kind not in (int(ContainerOpKind.TAKE), int(ContainerOpKind.PUT)):
            return None

        container = self._containers.get(op.container_form_id)
        # D1: an 0xFF key names a container of the server's (the death
        # crate) or nothing: runtime refs alias across processes.
        if is_runtime_form_id(op.container_form_id):
            if container is None or not container.wid:
                return None
            if container.base_id != op.container_base_id:
                return None
        elif container is None:
            # Inferred from one op, not scanned: partial (see `seeded`).
            container = ContainerWorldState(
                form_id=op.container_form_id,
                base_id=op.container_base_id,
                cell_id=op.container_cell_id,
                seeded=False,
            )
            self._containers[op.container_form_id] = container
        elif not container.wid and identities_conflict(
                container.base_id, container.cell_id,
                op.container_base_id, op.container_cell_id):
            return None

        # Trust-the-client policy for MVP: the server has no way to seed
        # container contents from the save file, so a TAKE against an
        # unknown-to-server item is interpreted as "the client observed
        # at least `count` of this item before the take; after the take,
        # 0 remain". No reject. PUT is straightforward additive.
        #
        # L5 stage 4b: a line is (item, instance fingerprint). A take draws
        # from the lines take_order names, its own instance first; more than
        # they hold empties them (the validator refused a seeded record's
        # shortfall upstream). A deposit of a named instance makes its
        # descriptor known, so the other clients can be told how to build it.
        item, fp = op.item_base_id, op.item_fp
        if not apply_op_lines(container, op.kind, item, fp, op.count):
            # The validator refuses this upstream (COUNT_OVERFLOW); this
            # is the last guard before a value the wire cannot pack.
            return None
        if (op.kind == int(ContainerOpKind.PUT) and fp not in (FP_PLAIN, FP_UNKNOWN)
                and instance_fp(item, op.instance) == fp):
            self._instances[fp] = (item, op.instance)
        if not container.seeded:
            # 2026-10-20: remembered until the first full scan (see the
            # record's pre_seed_ops); past the cap the list is not trusted.
            if len(container.pre_seed_ops) < PRE_SEED_OPS_MAX:
                container.pre_seed_ops.append(
                    (by_peer_id, float(now_ms), int(op.kind), int(item), int(fp),
                     int(op.count)))
            else:
                container.pre_seed_overflow = True

        container.last_owner_peer_id = by_peer_id
        container.last_update_ms = now_ms
        # L5 realtime R1: the player's side of the op, in this same journal
        # record: the container and the record never disagree on it.
        self._player_inv_op(by_peer_id, op)
        self._journal("record_container_op", op=op, by_peer_id=by_peer_id,
                      now_ms=now_ms)
        return container

    def container_state(self, form_id: int) -> Optional[ContainerWorldState]:
        """Lookup by the placed REFR's form_id."""
        if form_id == 0:
            return None
        return self._containers.get(form_id)

    def container_state_for_op(
        self, op: ContainerOpPayload
    ) -> Optional[ContainerWorldState]:
        return self.container_state(op.container_form_id)

    def create_container(
        self, form_id: int, base_id: int, cell_id: int, items: dict[int, int],
        by_peer_id: str, now_ms: float,
    ) -> Optional[ContainerWorldState]:
        """Create the record for a REFR the server has never seen, from a
        client's SEED scan: a seeded record. None (and nothing stored) for
        an unusable identity or a REFR that already has a record: the seed
        policy (first-seed-wins, refill of an emptied record, replacement
        of a partial one) is the caller's."""
        if (form_id == 0 or is_runtime_form_id(form_id)
                or base_id == 0 or cell_id == 0):
            return None
        if form_id in self._containers:
            return None
        container = ContainerWorldState(
            form_id=form_id, base_id=base_id, cell_id=cell_id,
            items=normalize_items(items),
            last_owner_peer_id=by_peer_id, last_update_ms=now_ms,
            seeded=True,
        )
        self._containers[form_id] = container
        self._journal("create_container", form_id=form_id, base_id=base_id,
                      cell_id=cell_id, items=dict(container.items),
                      by_peer_id=by_peer_id, now_ms=now_ms)
        return container

    def reseed_container(self, form_id: int, items: dict[int, int],
                         by_peer_id: str, now_ms: float) -> bool:
        """Replace the items of an existing record with a client's scan and
        mark it seeded: the two cases the seed handler allows (a partial
        record met its first full scan; an emptied record is refilled).
        False when there is no record. Stage 1 of L5: the one journaled
        way to overwrite a record's items."""
        container = self._containers.get(form_id)
        if container is None:
            return False
        container.items = normalize_items(items)
        container.seeded = True
        container.pre_seed_ops = []
        container.pre_seed_overflow = False
        container.last_owner_peer_id = by_peer_id
        container.last_update_ms = now_ms
        self._journal("reseed_container", form_id=form_id,
                      items=dict(container.items), by_peer_id=by_peer_id,
                      now_ms=now_ms)
        return True

    def forget_container(self, form_id: int) -> bool:
        """Drop the record of a REFR. Loot rework L4.1 (2026-09-25): a death
        makes a NEW corpse with a new roll, so the record of an actor's
        previous corpse is dropped when the server kills it again or an
        owner reports its death; the first scan of the new corpse seeds it.
        Measured before this: four raiders killed again in a new session
        were aligned to the previous session's looted-out records and their
        fresh loot vanished at the activation. True when a record existed."""
        existed = self._containers.pop(form_id, None) is not None
        if existed:
            self._journal("forget_container", form_id=form_id)
        return existed

    def record_instance_def(self, item: int, fp: int,
                            instance: InstanceDescriptor) -> bool:
        """Keep the descriptor of an instance a client named (INSTANCE_DEFS,
        stage 4b). Refused (False, nothing kept) unless it is a real
        instance of `item` that makes exactly `fp`: a client cannot attach a
        descriptor to a fingerprint it does not compute to."""
        if item == 0 or fp in (FP_PLAIN, FP_UNKNOWN):
            return False
        if len(instance.mods) > INSTANCE_MAX_MODS:
            return False
        if instance_fp(item, instance) != fp:
            return False
        if self._instances.get(fp) == (item, instance):
            return True
        self._instances[fp] = (item, instance)
        self._journal("record_instance_def", item=item, fp=fp, instance=instance)
        return True

    def instance_def(self, fp: int) -> Optional[tuple[int, InstanceDescriptor]]:
        """(item, descriptor) of an instance, or None when nobody said."""
        return self._instances.get(fp)

    def instance_defs_for(self, containers) -> list[tuple[int, int, InstanceDescriptor]]:
        """(fp, item, descriptor) of every named instance the lines of
        `containers` hold and the server can describe, sorted by fp."""
        seen: set[int] = set()
        out: list[tuple[int, int, InstanceDescriptor]] = []
        for c in containers:
            for (_, fp) in c.items:
                if fp in (FP_PLAIN, FP_UNKNOWN) or fp in seen:
                    continue
                seen.add(fp)
                known = self._instances.get(fp)
                if known is not None:
                    out.append((fp, known[0], known[1]))
        out.sort(key=lambda t: t[0])
        return out

    def seeded_containers(self) -> list[ContainerWorldState]:
        """The records a client may be aligned to: the scanned ones."""
        return [c for c in self._containers.values() if c.seeded]

    def all_containers(self) -> list[ContainerWorldState]:
        return list(self._containers.values())

    def remember_container_verdict(
        self, peer_id: str, client_op_id: int, ack: ContainerOpAckPayload
    ) -> None:
        """Keep the verdict of one op so a repeat of it (an ACK lost in a
        session drop, the op sent again after the rejoin) gets the same
        answer without being applied twice. Bounded per peer, oldest out."""
        verdicts = self._container_verdicts.setdefault(peer_id, OrderedDict())
        verdicts[client_op_id] = ack
        verdicts.move_to_end(client_op_id)
        while len(verdicts) > self.CONTAINER_VERDICTS_KEPT:
            verdicts.popitem(last=False)
        # Stage 1 of L5: the verdict IS the durable fact the client acts on,
        # so it is journaled before the ACK that carries it may leave.
        self._journal("remember_container_verdict", peer_id=peer_id,
                      client_op_id=client_op_id, ack=ack)

    def recall_container_verdict(
        self, peer_id: str, client_op_id: int
    ) -> Optional[ContainerOpAckPayload]:
        verdicts = self._container_verdicts.get(peer_id)
        if not verdicts:
            return None
        return verdicts.get(client_op_id)

    # ---------------------------------------------------------- quests (B4)

    def record_quest_stage(
        self, quest_form_id: int, stage: int, by_peer_id: str, now_ms: float
    ) -> Optional[QuestStageState]:
        """Apply a quest SetStage to authoritative state.

        Returns the updated QuestStageState, or None if quest_form_id is 0.

        Semantics: last-write-wins. We do NOT enforce monotonicity at the
        server because ResetQuest legitimately drops the stage. The engine
        on each peer enforces sane transitions at the Papyrus layer; our
        job is to replicate what actually happened.
        """
        if quest_form_id == 0:
            return None
        if not (0 <= stage <= 0xFFFF):
            return None
        q = self._quests.get(quest_form_id)
        if q is None:
            q = QuestStageState(quest_form_id=quest_form_id)
            self._quests[quest_form_id] = q
        q.stage = stage
        q.last_owner_peer_id = by_peer_id
        q.last_update_ms = now_ms
        self._journal("record_quest_stage", quest_form_id=quest_form_id,
                      stage=stage, by_peer_id=by_peer_id, now_ms=now_ms)
        return q

    def quest_stage(self, quest_form_id: int) -> Optional[QuestStageState]:
        return self._quests.get(quest_form_id) if quest_form_id else None

    def all_quest_stages(self) -> list[QuestStageState]:
        return list(self._quests.values())

    # ------------------------------------------------ inventory digests (L5 stage 2)

    def record_inv_digest(
        self, peer_id: str, seq: int, wall_ms: int, digest: int, entries: int,
        stacks: int, items: int, reasons: int, flags: int, why: int,
        now_ms: float, count: Optional[int] = None,
    ) -> Optional[InvDigestRecord]:
        """Keep the last inventory digest a peer reported. ADVISORY: nothing
        reads it yet. `count` is given only by the snapshot restore, which
        carries the running total; a live or replayed record adds one.
        None for a malformed peer id."""
        if _peer_id_invalid(peer_id):
            return None
        rec = self._inv_digests.get(peer_id)
        if rec is None:
            rec = InvDigestRecord(peer_id=peer_id)
            self._inv_digests[peer_id] = rec
        rec.seq = int(seq) & 0xFFFFFFFF
        rec.wall_ms = int(wall_ms) & 0xFFFFFFFFFFFFFFFF
        rec.digest = int(digest) & 0xFFFFFFFFFFFFFFFF
        rec.entries = int(entries) & 0xFFFFFFFF
        rec.stacks = int(stacks) & 0xFFFFFFFF
        rec.items = int(items) & 0xFFFFFFFF
        rec.reasons = int(reasons) & 0xFFFFFFFF
        rec.flags = int(flags) & 0xFF
        rec.why = int(why) & 0xFF
        rec.received_ms = float(now_ms)
        rec.count = int(count) if count is not None else rec.count + 1
        self._journal("record_inv_digest", peer_id=peer_id, seq=rec.seq,
                      wall_ms=rec.wall_ms, digest=rec.digest, entries=rec.entries,
                      stacks=rec.stacks, items=rec.items, reasons=rec.reasons,
                      flags=rec.flags, why=rec.why, now_ms=float(now_ms))
        return rec

    def inv_digest(self, peer_id: str) -> Optional[InvDigestRecord]:
        return self._inv_digests.get(peer_id) if peer_id else None

    def all_inv_digests(self) -> list[InvDigestRecord]:
        return list(self._inv_digests.values())

    # ------------------------------------------ L5 realtime R1: inventory record

    def record_player_inventory(
        self, peer_id: str, session: int, seq: int, watermark: int, op_epoch: int,
        flags: int, digest: int, entries, now_ms: float,
    ) -> Optional[PlayerInvRecord]:
        """A complete capture of `peer_id`'s inventory becomes its record.

        `entries` are (item, fp, count, flags) lines. None, and nothing
        changed, for a capture that cannot be one (a bad line, too many
        lines, session 0) or that is not newer than the record's (the same
        process, a number not above the last). The accepted ops of this
        process after `watermark` are applied again on top (see
        PlayerInvRecord); the ops of other processes are dropped."""
        if _peer_id_invalid(peer_id) or session == 0:
            return None
        entries = tuple(tuple(e) for e in entries)
        if len(entries) > PLAYER_INV_MAX_LINES:
            return None
        lines: dict = {}
        equipped: set = set()
        for e in entries:
            item, fp, count, eflags = int(e[0]), int(e[1]), int(e[2]), int(e[3])
            if item == 0 or not (1 <= count <= COUNT_MAX):
                return None
            if (item & 0xFFFFFFFF) in PA_FRAME_WEARABLES:
                continue   # the frame's body armour: never inventory (2026-10-05)
            key = (item & 0xFFFFFFFF, fp & 0xFFFF_FFFF_FFFF_FFFF)
            lines[key] = min(COUNT_MAX, lines.get(key, 0) + count)
            if eflags & INV_ENTRY_EQUIPPED:
                equipped.add(key)
        rec = self._player_inv.get(peer_id)
        if rec is not None and rec.session == session and seq <= rec.seq:
            return None
        # R2: a record with a capture under it belongs to the process that
        # opened it (RESTORE_DONE); the first capture of a record that has
        # none opens it.
        if rec is not None and rec.captures > 0 and rec.open_session != session:
            return None
        if rec is None:
            rec = PlayerInvRecord(peer_id=peer_id)
            self._player_inv[peer_id] = rec
        if rec.captures == 0:
            rec.open_session = session
        wm_in_epoch = watermark != 0 and (watermark >> 16) == op_epoch
        keep = []
        for p in rec.pending:
            if (p[0] >> 16) != op_epoch:
                continue
            if wm_in_epoch and not _seq16_after(p[0] & 0xFFFF, watermark & 0xFFFF):
                continue
            keep.append(p)
        for p in keep:
            _inv_apply_op(lines, p[1], p[2], p[3], p[4])
        rec.lines = lines
        rec.equipped = {k for k in equipped if k in lines}
        rec.session, rec.seq, rec.watermark, rec.op_epoch = session, seq, watermark, op_epoch
        rec.flags, rec.digest = flags, digest
        rec.pending = keep
        rec.captures += 1
        rec.updated_ms = now_ms
        self._journal("record_player_inventory", peer_id=peer_id, session=session,
                      seq=seq, watermark=watermark, op_epoch=op_epoch, flags=flags,
                      digest=digest, entries=entries, now_ms=now_ms)
        return rec

    def record_player_restored(self, peer_id: str, session: int, now_ms: float) -> bool:
        """R2: process `session` has the record back in its game (its
        RESTORE_DONE): its captures are the record from now. False for a
        missing peer id or session 0."""
        if _peer_id_invalid(peer_id) or session == 0:
            return False
        rec = self._player_inv.get(peer_id)
        if rec is None:
            rec = PlayerInvRecord(peer_id=peer_id)
            self._player_inv[peer_id] = rec
        rec.open_session = session
        rec.updated_ms = now_ms
        self._journal("record_player_restored", peer_id=peer_id, session=session,
                      now_ms=now_ms)
        return True

    def player_inventory_open_to(self, peer_id: str, session: int) -> bool:
        """Would a capture of process `session` be taken as the record?"""
        rec = self._player_inv.get(peer_id)
        return rec is None or rec.captures == 0 or rec.open_session == session

    # ------------------------------------------ L5 realtime D1: the death crate

    def record_death_crate(
        self, peer_id: str, wid: int, base_id: int, cell_id: int,
        px: float, py: float, pz: float, rz: float, keep_items, now_ms: float,
        frame_pieces=(), death_ordinal=None,
    ) -> Optional[tuple]:
        """A death: every line of `peer_id`'s record but `keep_items` (the
        Pip-Boy) goes into a new container of the server's, the world spawn
        `wid` at the death point, and the record keeps only those. One
        journal record: a crash never leaves the move half done. None, and
        nothing changed, when there is nothing to move or the wid is taken.
        The record's pending ops go too: what they moved is in the crate.
        `frame_pieces` ((form, count) pairs, D1 2026-10-04): what is
        mounted on the frame the player wore, the wearable with it; it is
        the frame's, given back where they fell: neither in the crate nor
        kept, the equipped lines first (what is mounted is equipped), a
        spare of the same base beyond the count is loot like the rest."""
        if _peer_id_invalid(peer_id) or not (0 < wid <= 0xFFFFFF) or base_id == 0:
            return None
        rec = self._player_inv.get(peer_id)
        if rec is None:
            return None
        keep = {int(x) for x in keep_items}
        on_frame = _frame_item_counts(frame_pieces)
        lines, equipped = dict(rec.lines), set(rec.equipped)
        _take_from_lines(lines, equipped, on_frame)
        # 2026-10-05: the frame's body armour is the frame's, never loot.
        moved = {k: v for k, v in lines.items()
                 if k[0] not in keep and k[0] not in PA_FRAME_WEARABLES}
        key = wid_container_key(wid)
        if not moved or wid in self.world_spawns or key in self._containers:
            return None
        spawn = WorldSpawnState(
            wid=wid, spawner_peer="", base_form_id=base_id, spawner_local_fid=0,
            px=px, py=py, pz=pz, rx=0.0, ry=0.0, rz=rz, cell_id=cell_id,
            flags=WORLD_SPAWN_FLAG_CONTAINER, timestamp_ms=int(now_ms), pieces=(),
        )
        self.world_spawns[wid] = spawn
        self.next_world_spawn_wid = max(self.next_world_spawn_wid, wid + 1)
        # D2: the crate of the n-th death carries n (`death_ordinal`, from
        # the record_death the caller made first). Without it (a journal from
        # before record_death existed, a caller that skipped it), or with a
        # number no death of theirs has or a crate still in the world
        # already carries, the death is counted here.
        ordinal = int(death_ordinal or 0)
        if (ordinal <= self._max_crate_ordinal(peer_id)
                or ordinal > self._death_counts.get(peer_id, 0)):
            ordinal = self.record_death(peer_id, now_ms)
        crate = ContainerWorldState(
            form_id=key, base_id=base_id, cell_id=cell_id, items=dict(moved),
            last_owner_peer_id=peer_id, last_update_ms=now_ms, seeded=True, wid=wid,
            death_owner=peer_id, death_ordinal=ordinal, death_ms=int(now_ms),
        )
        self._containers[key] = crate
        rec.lines = {k: v for k, v in lines.items() if k[0] in keep}
        rec.equipped = {k for k in equipped if k in rec.lines}
        rec.pending = []
        rec.updated_ms = now_ms
        self._journal("record_death_crate", peer_id=peer_id, wid=wid, base_id=base_id,
                      cell_id=cell_id, px=px, py=py, pz=pz, rz=rz,
                      keep_items=tuple(sorted(keep)), now_ms=now_ms,
                      frame_pieces=tuple(sorted(on_frame.items())), death_ordinal=ordinal)
        return spawn, crate

    # ------------------------------ L5 realtime D2: the owner's crates on the map

    def _max_crate_ordinal(self, peer_id: str) -> int:
        return max((int(c.death_ordinal) for c in self._containers.values()
                    if c.wid and c.death_owner == peer_id), default=0)

    def death_count(self, peer_id: str) -> int:
        """How many deaths `peer_id` had so far, never below the ordinal of a
        crate of theirs still in the world: the crate whose ordinal equals
        it is their latest death."""
        return max(self._death_counts.get(peer_id, 0), self._max_crate_ordinal(peer_id))

    def record_death(self, peer_id: str, now_ms: float) -> int:
        """A death of `peer_id`, with or without a crate: the count goes up
        (above every crate of theirs still in the world) and is journaled.
        The new count, 0 for a bad peer id."""
        if _peer_id_invalid(peer_id):
            return 0
        n = self.death_count(peer_id) + 1
        self._death_counts[peer_id] = n
        self._journal("record_death", peer_id=peer_id, now_ms=now_ms)
        return n

    def death_crates_of(self, peer_id: str) -> list[tuple]:
        """The death crates of `peer_id` still in the world, oldest first:
        (wid, ordinal, death_ms, px, py, pz, cell_id) each, the position and
        the cell those of the world spawn the crate is. A crate whose spawn
        is gone is not listed (nothing to show)."""
        out = []
        for c in self._containers.values():
            if c.wid == 0 or not c.death_owner or c.death_owner != peer_id:
                continue
            sp = self.world_spawns.get(c.wid)
            if sp is None:
                continue
            out.append((c.wid, int(c.death_ordinal), int(c.death_ms),
                        float(sp.px), float(sp.py), float(sp.pz), int(sp.cell_id)))
        out.sort(key=lambda t: (t[1], t[0]))
        return out

    def _restore_death_count(self, peer_id: str, count: int) -> None:
        """Snapshot load (persistence.py)."""
        if count > 0 and not _peer_id_invalid(peer_id):
            self._death_counts[peer_id] = int(count)

    def all_death_counts(self) -> dict[str, int]:
        return dict(self._death_counts)

    # ------------------------------ 2026-10-20: the save a peer's world runs on

    def note_world_base(self, peer_id: str, base_ms: float, now_ms: float = 0.0) -> None:
        """The peer loads a world now (`now_ms`): `base_ms` is the server
        time of the report of the checkpoint it loads
        (CheckpointRecord.world_ms), 0 for the genesis save. Its engine then
        holds no op recorded after `base_ms` and before `now_ms`:
        reconcile_scan applies those over the peer's next scan of a partial
        record. Heard twice for one load (the request and the result of a
        boot, the answer and the request of a death) it moves the load time
        by the seconds between, with no op in them: the game is loading.
        Journaled."""
        if _peer_id_invalid(peer_id):
            return
        base = max(0.0, float(base_ms))
        load = max(base, float(now_ms))
        self._world_base_ms[peer_id] = (base, load)
        self._journal("note_world_base", peer_id=peer_id, base_ms=base, now_ms=load)

    def world_base(self, peer_id: str) -> Optional[tuple[float, float]]:
        """(save_ms, load_ms); None until the peer was heard loading a world."""
        return self._world_base_ms.get(peer_id)

    def all_world_bases(self) -> dict[str, tuple[float, float]]:
        return dict(self._world_base_ms)

    # ------------------------------ L5 realtime D1: the pieces of a worn frame

    def record_pieces_to_frame(self, peer_id: str, pieces, now_ms: float) -> int:
        """The frame `peer_id` wore is a world object again, with `pieces`
        ((form, count) pairs: its ledger and the wearable): they leave the
        player's record, because they are the frame's now (the exit put them
        back natively; a death leaves the frame where they fell; a
        disconnect gives it back). Count-bounded by base, the equipped lines
        first: a spare of the same base stays. The items that left."""
        if _peer_id_invalid(peer_id):
            return 0
        rec = self._player_inv.get(peer_id)
        if rec is None:
            return 0
        left = _take_from_lines(rec.lines, rec.equipped, _frame_item_counts(pieces))
        if not left:
            return 0
        rec.updated_ms = now_ms
        self._journal("record_pieces_to_frame", peer_id=peer_id,
                      pieces=tuple(sorted(_frame_item_counts(pieces).items())), now_ms=now_ms)
        return sum(left.values())

    def record_pieces_from_frame(self, peer_id: str, pieces, now_ms: float) -> int:
        """The player boots inside the frame `pieces` is the ledger of (the
        standing frame taken back): the pieces and the wearable come back
        into the record as lines nobody read (FP_UNKNOWN): the restore keeps
        whatever instance of each base the save has, builds and removes
        nothing of them, and the next capture names them. A base the record
        holds by instance (a spare) and the mounted one are two lines; the
        wearable is one item however often it comes back. The items added."""
        if _peer_id_invalid(peer_id):
            return 0
        rec = self._player_inv.get(peer_id)
        if rec is None:
            return 0
        added = 0
        for base, count in sorted(_frame_item_counts(pieces).items()):
            key = (base, FP_UNKNOWN)
            if base in PA_FRAME_WEARABLES:
                continue   # never inventory (2026-10-05): the engine's own
            rec.lines[key] = min(rec.lines.get(key, 0) + count, COUNT_MAX)
            rec.equipped.add(key)
            added += count
        if not added:
            return 0
        rec.updated_ms = now_ms
        self._journal("record_pieces_from_frame", peer_id=peer_id,
                      pieces=tuple(sorted(_frame_item_counts(pieces).items())), now_ms=now_ms)
        return added

    def remove_wid_container(self, wid: int) -> bool:
        """A container of the server's goes, its world spawn with it (one
        journal record). True when either existed."""
        key = wid_container_key(wid)
        had_c = self._containers.pop(key, None) is not None
        had_s = self.world_spawns.pop(wid, None) is not None
        if had_c or had_s:
            self._journal("remove_wid_container", wid=wid)
        return had_c or had_s

    def _player_inv_op(self, peer_id: str, op: ContainerOpPayload) -> None:
        """The player's side of an accepted container op (called from
        record_container_op, inside its journal record)."""
        if _peer_id_invalid(peer_id):
            return
        rec = self._player_inv.get(peer_id)
        if rec is None:
            rec = PlayerInvRecord(peer_id=peer_id)
            self._player_inv[peer_id] = rec
        short = _inv_apply_op(rec.lines, op.kind, op.item_base_id, op.item_fp, op.count)
        if short:
            log.debug("inventory record of %s: a put of %d x 0x%X found %d it did not hold "
                      "(the record is behind; the next capture puts it right)",
                      peer_id, op.count, op.item_base_id, short)
        rec.equipped = {k for k in rec.equipped if k in rec.lines}
        rec.pending.append((op.client_op_id & 0xFFFFFFFF, int(op.kind), op.item_base_id,
                            op.item_fp, op.count))
        if len(rec.pending) > PLAYER_INV_MAX_PENDING:
            del rec.pending[0]

    def _restore_player_inventory(
        self, peer_id: str, lines: dict, equipped, session: int, seq: int,
        watermark: int, op_epoch: int, flags: int, digest: int, pending,
        captures: int, updated_ms: float, open_session: int = 0,
    ) -> None:
        """The snapshot loader's way in: the record as it was written."""
        if _peer_id_invalid(peer_id):
            return
        self._player_inv[peer_id] = PlayerInvRecord(
            peer_id=peer_id, lines=dict(lines), equipped=set(equipped),
            session=session, seq=seq, watermark=watermark, op_epoch=op_epoch,
            flags=flags, digest=digest, pending=[tuple(p) for p in pending],
            captures=captures, updated_ms=updated_ms, open_session=open_session)

    def record_player_stats(
        self, peer_id: str, session: int, seq: int, level: int, xp: float,
        perk_points: int, special, health: float, action_points: float, rads: float,
        perks, now_ms: float,
    ) -> Optional[PlayerStatsRecord]:
        """A complete stats capture of `peer_id` becomes its stats record.
        None, nothing changed, for a capture that cannot be one, that is not
        newer than the record's, or whose process has not had the record
        back yet (player_inventory_open_to)."""
        if _peer_id_invalid(peer_id) or session == 0:
            return None
        special = tuple(float(x) for x in special)
        perks = tuple((int(p[0]), int(p[1])) for p in perks)
        numbers = (float(xp), float(health), float(action_points), float(rads)) + special
        if len(special) != 7 or not all(math.isfinite(x) for x in numbers):
            return None
        if len(perks) > 2048 or any(f == 0 or not (1 <= r <= 255) for f, r in perks):
            return None
        if not self.player_inventory_open_to(peer_id, session):
            return None
        rec = self._player_stats.get(peer_id)
        if rec is not None and rec.session == session and seq <= rec.seq:
            return None
        if rec is None:
            rec = PlayerStatsRecord(peer_id=peer_id)
            self._player_stats[peer_id] = rec
        rec.session, rec.seq = session, seq
        rec.level, rec.xp, rec.perk_points = int(level), float(xp), int(perk_points)
        rec.special = special
        rec.health, rec.action_points, rec.rads = float(health), float(action_points), float(rads)
        rec.perks = dict(perks)
        rec.captures += 1
        rec.updated_ms = now_ms
        self._journal("record_player_stats", peer_id=peer_id, session=session, seq=seq,
                      level=level, xp=xp, perk_points=perk_points, special=special,
                      health=health, action_points=action_points, rads=rads, perks=perks,
                      now_ms=now_ms)
        return rec

    def _restore_player_stats(self, peer_id: str, **fields_) -> None:
        """The snapshot loader's way in."""
        if _peer_id_invalid(peer_id):
            return
        self._player_stats[peer_id] = PlayerStatsRecord(peer_id=peer_id, **fields_)

    def player_stats(self, peer_id: str) -> Optional[PlayerStatsRecord]:
        return self._player_stats.get(peer_id) if peer_id else None

    def all_player_stats(self) -> list[PlayerStatsRecord]:
        return list(self._player_stats.values())

    def player_inventory(self, peer_id: str) -> Optional[PlayerInvRecord]:
        return self._player_inv.get(peer_id) if peer_id else None

    def all_player_inventories(self) -> list[PlayerInvRecord]:
        return list(self._player_inv.values())

    def instance_defs_named(self) -> list[tuple[int, int, InstanceDescriptor]]:
        """(fp, item, descriptor) of every named instance a container line,
        a player's line or a pending op of a player names, sorted by fp:
        what the snapshot must keep to rebuild any of them."""
        fps: set[int] = set()
        for c in self._containers.values():
            fps.update(fp for (_, fp) in c.items)
        for r in self._player_inv.values():
            fps.update(fp for (_, fp) in r.lines)
            fps.update(p[3] for p in r.pending)
        out: list[tuple[int, int, InstanceDescriptor]] = []
        for fp in sorted(fps):
            if fp in (FP_PLAIN, FP_UNKNOWN):
                continue
            known = self._instances.get(fp)
            if known is not None:
                out.append((fp, known[0], known[1]))
        return out

    # ---------------------------------------------- checkpoints (L5 stage 3a)

    def record_checkpoint(
        self, peer_id: str, identity_hex: str, seq: int, name: str, sha256_hex: str,
        size: int, digest: int, digest_seq: int, wall_ms: int, now_ms: float,
        watermark_lsn: int, reason: int, status: str = "provisional",
        boot_failures: int = 0,
        custody: bool = False,
        in_pa: Optional[bool] = None,
        in_pa_wid: int = 0,
        world_ms: Optional[float] = None,
    ) -> Optional[CheckpointRecord]:
        """Keep a checkpoint a client reported written, newest first, the
        last CHECKPOINTS_KEPT per peer, plus the newest one that has the
        player on foot while the kept ones have them in power armour (D1:
        a death puts them back on foot). `watermark_lsn` is decided by the
        caller (the journal head at receipt) so a replay sees the same
        number. `status`/`boot_failures` are given by the snapshot restore
        only. None for a malformed peer id or name."""
        if _peer_id_invalid(peer_id):
            return None
        if not name or len(name) > 47 or not name.isascii():
            return None
        rec = CheckpointRecord(
            peer_id=peer_id, identity_hex=str(identity_hex or ""), seq=int(seq) & 0xFFFFFFFF,
            name=name, sha256_hex=str(sha256_hex or "").lower(), size=int(size) & 0xFFFFFFFF,
            digest=int(digest) & 0xFFFFFFFFFFFFFFFF, digest_seq=int(digest_seq) & 0xFFFFFFFF,
            wall_ms=int(wall_ms) & 0xFFFFFFFFFFFFFFFF, received_ms=float(now_ms),
            watermark_lsn=int(watermark_lsn), reason=int(reason) & 0xFF,
            status=str(status), boot_failures=int(boot_failures), custody=bool(custody),
            in_pa=None if in_pa is None else bool(in_pa),
            in_pa_wid=int(in_pa_wid or 0) & 0xFFFFFFFF,
            # 2026-10-20: a client's own checkpoint carries the world of
            # this instant; a copy says whose world it carries.
            world_ms=float(now_ms) if world_ms is None else max(0.0, float(world_ms)))
        lst = self._checkpoints.setdefault(peer_id, [])
        lst[:] = [r for r in lst if r.name != name]
        lst.insert(0, rec)
        kept = lst[:CHECKPOINTS_KEPT]
        if not any(r.in_pa is False for r in kept):
            for r in lst[CHECKPOINTS_KEPT:]:
                if r.in_pa is False:
                    kept.append(r)
                    break
        lst[:] = kept
        self._journal("record_checkpoint", peer_id=peer_id, identity_hex=rec.identity_hex,
                      seq=rec.seq, name=name, sha256_hex=rec.sha256_hex, size=rec.size,
                      digest=rec.digest, digest_seq=rec.digest_seq, wall_ms=rec.wall_ms,
                      now_ms=float(now_ms), watermark_lsn=rec.watermark_lsn, reason=rec.reason,
                      in_pa=rec.in_pa, in_pa_wid=rec.in_pa_wid, world_ms=rec.world_ms)
        return rec

    def confirm_checkpoint(self, peer_id: str, name: str, outcome: int,
                           now_ms: float) -> Optional[CheckpointRecord]:
        """A boot answered for `name`: outcome 0 confirms it, 2/3/4 count a
        failure against it (two take it out of the pick). None when the
        peer has no such checkpoint."""
        for rec in self._checkpoints.get(peer_id, []):
            if rec.name != name:
                continue
            if int(outcome) == 0:
                rec.status = "confirmed"
            elif int(outcome) in (2, 3, 4):
                rec.boot_failures += 1
                if rec.boot_failures >= 2:
                    rec.status = "failed"
            self._journal("confirm_checkpoint", peer_id=peer_id, name=name,
                          outcome=int(outcome), now_ms=float(now_ms))
            return rec
        return None

    def set_checkpoint_custody(self, peer_id: str, name: str, sha256_hex: str,
                               now_ms: float) -> Optional[CheckpointRecord]:
        """L5 stage 3b — the server holds the bytes of this checkpoint: an
        upload hashed to the record's sha. None when the peer has no such
        record or the hash is another's; a record already in custody is
        returned with nothing journaled."""
        want = (sha256_hex or "").lower()
        for rec in self._checkpoints.get(peer_id, []):
            if rec.name != name:
                continue
            if rec.sha256_hex != want:
                return None
            if rec.custody:
                return rec
            rec.custody = True
            self._journal("set_checkpoint_custody", peer_id=peer_id, name=name,
                          sha256_hex=want, now_ms=float(now_ms))
            return rec
        return None

    def checkpoint_to_boot(self, peer_id: str) -> Optional[CheckpointRecord]:
        """The newest checkpoint this peer may boot from: one that fewer than
        two boots failed on. None = the genesis save."""
        for rec in self._checkpoints.get(peer_id, []):
            if rec.boot_failures < 2:
                return rec
        return None

    def checkpoints(self, peer_id: str) -> list[CheckpointRecord]:
        return list(self._checkpoints.get(peer_id, []))

    def all_checkpoints(self) -> list[CheckpointRecord]:
        out: list[CheckpointRecord] = []
        for lst in self._checkpoints.values():
            out.extend(lst)
        return out

    # ---------------------------------------------------------- globals (B4)

    def record_global_var(
        self, global_form_id: int, value: float, by_peer_id: str, now_ms: float
    ) -> Optional[GlobalVarState]:
        """Apply a GlobalVariable.SetValue to authoritative state.

        Returns the updated GlobalVarState, or None if global_form_id is 0
        or value is not finite (NaN/Inf). Last-write-wins.
        """
        if global_form_id == 0:
            return None
        import math
        if not math.isfinite(value):
            return None
        g = self._globals.get(global_form_id)
        if g is None:
            g = GlobalVarState(global_form_id=global_form_id)
            self._globals[global_form_id] = g
        g.value = value
        g.last_owner_peer_id = by_peer_id
        g.last_update_ms = now_ms
        self._journal("record_global_var", global_form_id=global_form_id,
                      value=value, by_peer_id=by_peer_id, now_ms=now_ms)
        return g

    def global_var(self, global_form_id: int) -> Optional[GlobalVarState]:
        return self._globals.get(global_form_id) if global_form_id else None

    def all_globals(self) -> list[GlobalVarState]:
        return list(self._globals.values())

    # ------------------------------------------------ appearance (v20)
    #
    # Keyed by PEER ID, which is the client's stable identity — the same key
    # PIENUVO authenticates. That matters: an appearance belongs to a player,
    # not to a connection, so it has to survive a reconnect and be handed to
    # peers who join later.
    #
    # The value is the recipe LINE verbatim. The server deliberately does NOT
    # parse it: it is authoritative over WHO owns an appearance, not over what
    # a valid appearance is. Form ids only mean something to an engine, and
    # putting a parser here would mean teaching the server the head-part
    # catalogue and keeping the two in step forever. A client that sends
    # nonsense gets its own character wrong; it cannot corrupt anyone else's.

    def record_appearance(self, peer_id: str, recipe: str) -> bool:
        """Store a peer's appearance recipe. Last-write-wins.

        Returns True if this changed anything — the caller uses that to avoid
        re-broadcasting an unchanged appearance every time a client re-sends
        it (they re-send on every join, which is correct of them).
        """
        if not peer_id or not recipe:
            return False
        if self._appearances.get(peer_id) == recipe:
            return False
        self._appearances[peer_id] = recipe
        self._journal("record_appearance", peer_id=peer_id, recipe=recipe)
        return True

    def appearance(self, peer_id: str) -> Optional[str]:
        return self._appearances.get(peer_id)

    def all_appearances(self) -> list[tuple[str, str]]:
        return list(self._appearances.items())

    # --------------------------------------------------- presence (v26)
    #
    # Same contract as the appearance recipe above, for the same reason: a
    # player who joins hours after everyone else must see the others as they
    # are, not as a naked mannequin at the origin waiting for them to move or
    # change clothes. Keyed by peer_id, kept after the peer leaves, persisted.

    def _presence_for(self, peer_id: str) -> PeerPresence:
        rec = self._presence.get(peer_id)
        if rec is None:
            rec = PeerPresence(peer_id=peer_id)
            self._presence[peer_id] = rec
        return rec

    def record_presence_name(self, peer_id: str, display_name: str,
                             now_ms: float) -> None:
        rec = self._presence_for(peer_id)
        rec.display_name = display_name
        rec.updated_at_ms = now_ms
        self._journal("record_presence_name", peer_id=peer_id,
                      display_name=display_name, now_ms=now_ms)

    def record_presence_pos(self, peer_id: str, pos, now_ms: float) -> None:
        """Called from the POS path, AFTER validation, so a rejected update
        never becomes the position a late joiner is shown."""
        rec = self._presence_for(peer_id)
        rec.last_pos = pos
        rec.last_pos_at_ms = now_ms
        rec.updated_at_ms = now_ms

    def record_presence_equip(self, peer_id: str, entry: OutfitEntry,
                              equipped: bool, now_ms: float) -> None:
        """Apply one equip event to the stored outfit.

        An equip inserts or replaces by item form id; an unequip removes by
        form id, which is all an unequip carries. Weapons and apparel share
        the dictionary because the wire does not separate them either.
        """
        rec = self._presence_for(peer_id)
        if equipped:
            rec.outfit[entry.item_form_id] = entry
        else:
            rec.outfit.pop(entry.item_form_id, None)
        rec.updated_at_ms = now_ms
        self._journal("record_presence_equip", peer_id=peer_id, entry=entry,
                      equipped=equipped, now_ms=now_ms)

    def clear_presence_outfit(self, peer_id: str, now_ms: float) -> int:
        """Forget the stored outfit. Returns how many items it held.

        Phase 3 (2026-09-23). The stored outfit is a record of the LAST
        session, and nothing else ever makes it shrink except an explicit
        unequip — see drop_items_from_outfit for the one case that had to be
        handled by hand before this. A relaunch loads the save, and the save
        dresses the player in what the SAVE says. So at every (re)join the
        memory goes, and the client rebuilds it: at each session start it
        reads the items it actually wears from its inventory, with their
        OMODs, and announces them through the ordinary equip path.
        """
        rec = self._presence.get(peer_id)
        if rec is None or not rec.outfit:
            return 0
        n = len(rec.outfit)
        rec.outfit.clear()
        rec.updated_at_ms = now_ms
        self._journal("clear_presence_outfit", peer_id=peer_id, now_ms=now_ms)
        return n

    def record_presence_worn_frame(self, peer_id: str, wid: int,
                                   now_ms: float) -> None:
        rec = self._presence_for(peer_id)
        rec.worn_frame_wid = wid
        rec.updated_at_ms = now_ms
        self._journal("record_presence_worn_frame", peer_id=peer_id, wid=wid,
                      now_ms=now_ms)

    def drop_items_from_outfit(self, peer_id: str, form_ids) -> int:
        """Togli questi oggetti dal vestito memorizzato. Torna quanti erano li'.

        Serves one rule, the one that closes the fossil outfit: a power armor
        is worn by someone OR is an object in the world, never both. When the
        wearer leaves and the frame is re-announced where it was, the pieces
        become the frame's again and must disappear from what that peer
        "wears".

        Without this the stored outfit is a UNION that never shrinks: a dict
        a piece leaves only when an UNEQUIP with its form id arrives, and
        leaving the frame produces no six of them the server could see. The
        logs of 2026-09-18 showed the result: PA pieces from an hour earlier
        replayed at every join, with one leg missing because for that one
        the unequip had arrived. The ghost dressed in a fossil, and every
        fossil retargets the shared skeleton to the power armor bind, which
        is what stretched the body even without visible pieces.
        """
        rec = self._presence.get(peer_id)
        if rec is None:
            return 0
        dropped = 0
        gone: list[int] = []
        for fid in form_ids:
            if rec.outfit.pop(fid, None) is not None:
                dropped += 1
                gone.append(int(fid))
        if dropped:
            self._journal("drop_items_from_outfit", peer_id=peer_id,
                          form_ids=gone)
        return dropped

    def presence(self, peer_id: str) -> Optional[PeerPresence]:
        return self._presence.get(peer_id)

    def all_presence(self) -> list[PeerPresence]:
        return list(self._presence.values())

    # ----------------------------------------------- resume tokens (v26)

    def issue_resume_token(self, session: PeerSession, now_ms: float,
                           ttl_s: float = RESUME_TOKEN_TTL_S) -> bytes:
        """Mint a token for this session, retiring any it already held.

        Retiring the old one is what makes the token single use: the WELCOME
        that answers a resume carries a fresh token, so a captured one buys
        exactly one rejoin and only until the real client rejoins again.
        """
        self.retire_resume_tokens(session.peer_id)
        token = secrets.token_bytes(RESUME_TOKEN_LEN)
        key = _token_key(token)
        self._resume_tokens[key] = ResumeTicket(
            peer_id=session.peer_id,
            identity_hex=session.identity_hex,
            issued_at_ms=now_ms,
            expires_at_ms=now_ms + ttl_s * 1000.0,
        )
        # The journal gets the hash, exactly what memory holds.
        self._journal("issue_resume_token", token_hash=key.hex(),
                      peer_id=session.peer_id, identity_hex=session.identity_hex,
                      issued_at_ms=now_ms, expires_at_ms=now_ms + ttl_s * 1000.0)
        return token

    def _restore_resume_token(self, token_hash: str, peer_id: str,
                              identity_hex: str, issued_at_ms: float,
                              expires_at_ms: float) -> None:
        """A ticket by its stored hash: the journal replay and the snapshot
        loader come in here."""
        self._resume_tokens[bytes.fromhex(token_hash)] = ResumeTicket(
            peer_id=peer_id, identity_hex=identity_hex,
            issued_at_ms=float(issued_at_ms), expires_at_ms=float(expires_at_ms))

    def forget_peer(self, peer_id: str) -> dict:
        """2026-10-05 - the character of `peer_id` starts over: its inventory
        record, its numbers, its appearance, its checkpoints, its presence
        (position, outfit, name), its inventory digest and its resume tokens
        go, in one journal record. The next hello of that identity is a first
        entry: the genesis moved onto the point, the character creation when
        the server requires it, the genesis inventory. What the peer put in
        the world (its spawns, its crates) stays the world's. The caller
        deletes the custody files. Returns what went, by name, for the log."""
        if _peer_id_invalid(peer_id):
            return {}
        gone: dict = {}
        if self._player_inv.pop(peer_id, None) is not None:
            gone["inventory record"] = 1
        if self._player_stats.pop(peer_id, None) is not None:
            gone["stats record"] = 1
        ckpts = self._checkpoints.pop(peer_id, None)
        if ckpts:
            gone["checkpoints"] = len(ckpts)
        if self._appearances.pop(peer_id, None) is not None:
            gone["appearance"] = 1
        if self._presence.pop(peer_id, None) is not None:
            gone["presence"] = 1
        if self._inv_digests.pop(peer_id, None) is not None:
            gone["inventory digest"] = 1
        self._container_verdicts.pop(peer_id, None)   # runtime ack ring: a fresh op 1 must not meet an old verdict
        self._world_item_verdicts.pop(peer_id, None)
        self._death_counts.pop(peer_id, None)   # D2: a fresh identity starts at crate #1
        self._world_base_ms.pop(peer_id, None)  # 2026-10-20: and has loaded no world yet
        dead = [t for t, tk in self._resume_tokens.items() if tk.peer_id == peer_id]
        for t in dead:
            del self._resume_tokens[t]
        if dead:
            gone["resume tokens"] = len(dead)
        self._journal("forget_peer", peer_id=peer_id)
        return gone

    def retire_resume_tokens(self, peer_id: str) -> int:
        dead = [t for t, tk in self._resume_tokens.items() if tk.peer_id == peer_id]
        for t in dead:
            del self._resume_tokens[t]
        if dead:
            self._journal("retire_resume_tokens", peer_id=peer_id)
        return len(dead)

    def resume_refusal(self, addr: tuple[str, int], peer_id: str,
                       client_version: tuple[int, int]) -> Optional[str]:
        """What accept_peer would say to a resume, WITHOUT touching anything.

        None if it would accept. Exists so the resume handler can validate
        before it mutates: it used to spend the token and evict the previous
        session first, and only then learn from accept_peer that the server was
        full or the version wrong — leaving the player with neither the old
        seat nor the new one, and with a token already gone (v0.8.0 audit,
        holes 3 and its twin).

        It mirrors accept_peer for the state a resume leaves behind. The resume
        handler evicts this peer's own previous session unconditionally, so
        peer_id_taken cannot fire; what can is the id format, the version, and
        the capacity. Capacity counts the seats that will still be taken AFTER
        the resume evicts this peer's previous session and whatever sits on
        the address it arrives from: a player rejoining must not be told the
        server is full because their own corpse still holds a seat, which is
        the same rule accept_peer writes above its own capacity check.
        """
        if _peer_id_invalid(peer_id):
            return "peer_id_invalid"
        if client_version[0] != self.server_version[0]:
            return "version_mismatch"
        if self.max_players > 0:
            leaving = set()
            prior = self._sessions_by_peer_id.get(peer_id)
            if prior is not None:
                leaving.add(prior.session_id)
            here = self._sessions_by_addr.get(addr)
            if here is not None:
                leaving.add(here.session_id)
            staying = sum(1 for s in self._sessions_by_peer_id.values()
                          if s.session_id not in leaving)
            if staying >= self.max_players:
                return "server_full"
        return None

    def peek_resume_token(self, token: bytes,
                          now_ms: float) -> tuple[Optional[ResumeTicket], str]:
        """Look a token up WITHOUT spending it, unless it is dead.

        A live token stays where it is: the caller spends it with
        consume_resume_token only once the resume has actually gone through.
        That is the point of the split — a resume refused for capacity used to
        burn the token, and the client, which retries SERVER_FULL with the
        token it still holds, was answered RESUME_UNKNOWN, threw the token
        away, and fell back to a full HELLO whose launcher proof is single use
        and already spent.

        An EXPIRED token is still removed on sight, for the reason
        consume_resume_token gives: a stale one must not be retried in a loop.
        """
        key = _token_key(token)
        ticket = self._resume_tokens.get(key)
        if ticket is None:
            return (None, "resume_unknown")
        if now_ms > _token_deadline_ms(ticket):
            del self._resume_tokens[key]
            self._journal("consume_resume_token", token_hash=key.hex())
            return (None, "resume_expired")
        return (ticket, "ok")

    def consume_resume_token(self, token: bytes,
                             now_ms: float) -> tuple[Optional[ResumeTicket], str]:
        """Spend a token. Returns (ticket, reason); ticket is None on refusal.

        The token is removed whether it was live or expired, so a stale one
        cannot be retried in a loop.
        """
        key = _token_key(token)
        ticket = self._resume_tokens.pop(key, None)
        if ticket is None:
            return (None, "resume_unknown")
        self._journal("consume_resume_token", token_hash=key.hex())
        if now_ms > _token_deadline_ms(ticket):
            return (None, "resume_expired")
        return (ticket, "ok")

    def _consume_resume_token_hash(self, token_hash: str) -> None:
        self._resume_tokens.pop(bytes.fromhex(token_hash), None)

    def prune_resume_tokens(self, now_ms: float) -> int:
        dead = [t for t, tk in self._resume_tokens.items()
                if now_ms > _token_deadline_ms(tk)]
        for t in dead:
            del self._resume_tokens[t]
        return len(dead)

    # ---------------------------------------------------------- locks (B6.3)

    def all_locks(self) -> list[LockWorldState]:
        return list(self.lock_state.values())

    def record_lock(self, base_id: int, cell_id: int, form_id: int,
                    locked: bool, timestamp_ms: int) -> bool:
        """Store a lock transition. False when the state is already what the
        op says (the handler skips the broadcast then). Stage 1 of L5: the
        handler used to write the dictionary itself; this is the journaled
        way in."""
        key = (base_id, cell_id)
        prev = self.lock_state.get(key)
        if prev is not None and prev.locked == bool(locked):
            return False
        self.lock_state[key] = LockWorldState(
            base_id=base_id, cell_id=cell_id, form_id=form_id,
            locked=bool(locked), timestamp_ms=int(timestamp_ms))
        self._journal("record_lock", base_id=base_id, cell_id=cell_id,
                      form_id=form_id, locked=bool(locked),
                      timestamp_ms=int(timestamp_ms))
        return True

    def record_world_spawn(
        self,
        spawner_peer: str,
        base_form_id: int,
        spawner_local_fid: int,
        px: float, py: float, pz: float,
        rx: float, ry: float, rz: float,
        cell_id: int,
        flags: int,
        timestamp_ms: int,
        pieces: tuple = (),
    ) -> WorldSpawnState:
        """Assign a wid and (unless transient) store the object.

        Transient spawns still get a wid — the broadcast needs a name — but
        the server forgets them immediately: nothing to persist, nothing to
        replay at join. That is the whole meaning of the flag.
        """
        wid = self.next_world_spawn_wid
        self.next_world_spawn_wid += 1
        st = WorldSpawnState(
            wid=wid, spawner_peer=spawner_peer, base_form_id=base_form_id,
            spawner_local_fid=spawner_local_fid,
            px=px, py=py, pz=pz, rx=rx, ry=ry, rz=rz,
            cell_id=cell_id, flags=flags, timestamp_ms=timestamp_ms,
            pieces=tuple(pieces),
        )
        if not (flags & 1):
            self.world_spawns[wid] = st
        # Transient spawns are journaled too, with their wid: the counter
        # must come out of a replay exactly where it was, or the next wid
        # minted after a restart would collide with one already in use.
        self._journal("record_world_spawn", wid=wid, spawner_peer=spawner_peer,
                      base_form_id=base_form_id, spawner_local_fid=spawner_local_fid,
                      px=px, py=py, pz=pz, rx=rx, ry=ry, rz=rz, cell_id=cell_id,
                      flags=flags, timestamp_ms=timestamp_ms, pieces=tuple(pieces))
        return st

    def _restore_world_spawn(
        self, wid: int, spawner_peer: str, base_form_id: int,
        spawner_local_fid: int, px: float, py: float, pz: float,
        rx: float, ry: float, rz: float, cell_id: int, flags: int,
        timestamp_ms: int, pieces: tuple = (),
    ) -> None:
        """Replay twin of record_world_spawn: the wid is given, not minted."""
        st = WorldSpawnState(
            wid=int(wid), spawner_peer=spawner_peer, base_form_id=base_form_id,
            spawner_local_fid=spawner_local_fid,
            px=px, py=py, pz=pz, rx=rx, ry=ry, rz=rz,
            cell_id=cell_id, flags=flags, timestamp_ms=timestamp_ms,
            pieces=tuple(tuple(p) if isinstance(p, (list, tuple)) else p
                         for p in pieces),
        )
        if not (flags & 1):
            self.world_spawns[st.wid] = st
        if st.wid >= self.next_world_spawn_wid:
            self.next_world_spawn_wid = st.wid + 1

    def remove_world_spawn(self, wid: int) -> bool:
        """Forget a spawned object (it died, or its record was superseded).
        True when it existed."""
        if self.world_spawns.pop(wid, None) is None:
            return False
        self._journal("remove_world_spawn", wid=wid)
        return True

    # ---------------------------------------------- world item ops (R1b)

    def _world_item_line(self, peer_id: str, op: WorldItemOpPayload) -> int:
        """The record side of an accepted world item op: a drop leaves the
        record the way a put does, a pickup enters it the way a take does,
        and the op stays pending under that kind, so record_player_inventory
        re-applies it over a capture from before it without knowing it was
        not a container op. A named instance makes its descriptor known.
        Returns the record's line after the op."""
        rec = self._player_inv.get(peer_id)
        if rec is None:
            rec = PlayerInvRecord(peer_id=peer_id)
            self._player_inv[peer_id] = rec
        kind = (int(ContainerOpKind.PUT) if op.kind == WORLD_ITEM_DROP
                else int(ContainerOpKind.TAKE))
        short = _inv_apply_op(rec.lines, kind, op.item_base_id, op.item_fp, op.count)
        if short:
            log.debug("inventory record of %s: a drop of %d x 0x%X found %d it did not hold "
                      "(the record is behind; the next capture puts it right)",
                      peer_id, op.count, op.item_base_id, short)
        rec.equipped = {k for k in rec.equipped if k in rec.lines}
        rec.pending.append((op.client_op_id & 0xFFFFFFFF, kind, op.item_base_id,
                            op.item_fp, op.count))
        if len(rec.pending) > PLAYER_INV_MAX_PENDING:
            del rec.pending[0]
        if (op.item_fp not in (FP_PLAIN, FP_UNKNOWN)
                and instance_fp(op.item_base_id, op.instance) == op.item_fp):
            self._instances[op.item_fp] = (op.item_base_id, op.instance)
        return rec.lines.get((op.item_base_id, op.item_fp), 0)

    @staticmethod
    def _piece_of(op: WorldItemOpPayload) -> tuple:
        """pieces[0] of a self-described spawn, from the op's descriptor: the
        mods as form ids and the condition, what a replica is dressed with."""
        d = op.instance
        mods = (tuple(int(m[0]) & 0xFFFFFFFF for m in d.mods)
                if (d.flags & INSTANCE_FLAG_OIE) else ())
        health = float(d.health) if (d.flags & INSTANCE_FLAG_HEALTH) else -1.0
        return (op.item_base_id, op.count, mods, health)

    def record_world_drop(self, peer_id: str, op: WorldItemOpPayload,
                          now_ms: float) -> Optional[WorldSpawnState]:
        """L5 realtime R1b (2026-10-05) - a Pip-Boy drop of `peer_id` that has
        come to rest: the object enters the world (a wid, self-described by
        the op's descriptor) and its line leaves the record, in ONE journal
        record, so a crash of the server never leaves it half done. None,
        nothing changed, for an op that names nothing (no item, no REFR, no
        count): the validator refuses those upstream, this is the last guard
        before the journal."""
        if (_peer_id_invalid(peer_id) or op.kind != WORLD_ITEM_DROP
                or op.item_base_id == 0 or op.ref_form_id == 0
                or not (1 <= op.count <= COUNT_MAX)):
            return None
        wid = self.next_world_spawn_wid
        st = self._apply_world_drop(wid, peer_id, op, now_ms)
        self._journal("record_world_drop", wid=wid, peer_id=peer_id, op=op, now_ms=now_ms)
        return st

    def _restore_world_drop(self, wid: int, peer_id: str, op: WorldItemOpPayload,
                            now_ms: float) -> None:
        """Replay twin of record_world_drop: the wid is given, not minted."""
        self._apply_world_drop(int(wid), peer_id, op, now_ms)

    def _apply_world_drop(self, wid: int, peer_id: str, op: WorldItemOpPayload,
                          now_ms: float) -> WorldSpawnState:
        # A drop is never transient (bit 0) and never a crate: it is an item.
        flags = ((int(op.flags) | WORLD_SPAWN_FLAG_SELF_DESCRIBED)
                 & ~(WORLD_SPAWN_FLAG_CONTAINER | 1)) & 0xFF
        st = WorldSpawnState(
            wid=wid, spawner_peer=peer_id, base_form_id=op.item_base_id,
            spawner_local_fid=op.ref_form_id,
            px=op.px, py=op.py, pz=op.pz, rx=op.rx, ry=op.ry, rz=op.rz,
            cell_id=op.cell_id, flags=flags, timestamp_ms=op.timestamp_ms,
            pieces=(self._piece_of(op),),
        )
        self.world_spawns[wid] = st
        if wid >= self.next_world_spawn_wid:
            self.next_world_spawn_wid = wid + 1
        self._world_item_line(peer_id, op)
        return st

    def record_world_pickup(self, peer_id: str, op: WorldItemOpPayload,
                            now_ms: float) -> Optional[tuple[int, bool]]:
        """L5 realtime R1b - a world REFR `peer_id` took into the inventory:
        the world side (an object of the server's removed by wid, or a REFR
        of the save marked disabled by (base, cell), or nothing for a runtime
        REFR nobody knows: a drop never accepted) and the record side (the
        line enters it), in ONE journal record. Returns (the wid removed or
        0, whether a REFR of the save was marked); None, nothing changed, for
        an op that names nothing or a wid the world does not hold (the
        validator refuses those upstream)."""
        if (_peer_id_invalid(peer_id) or op.kind != WORLD_ITEM_PICKUP
                or op.item_base_id == 0 or not (1 <= op.count <= COUNT_MAX)):
            return None
        if op.wid and op.wid not in self.world_spawns and not self._replaying:
            return None
        removed = 0
        disabled = False
        if op.wid:
            if self.world_spawns.pop(op.wid, None) is not None:
                removed = op.wid
        elif op.ref_form_id and not is_runtime_form_id(op.ref_form_id):
            ev = ActorEventPayload(kind=3, form_id=op.ref_form_id,
                                   actor_base_id=op.item_base_id,
                                   x=op.px, y=op.py, z=op.pz, extra=0, cell_id=op.cell_id)
            disabled = self._apply_actor_event(ev, peer_id, now_ms) is not None
        self._world_item_line(peer_id, op)
        self._journal("record_world_pickup", peer_id=peer_id, op=op, now_ms=now_ms)
        return removed, disabled

    def remember_world_item_verdict(self, peer_id: str, client_op_id: int,
                                    ack: WorldItemAckPayload) -> None:
        """As remember_container_verdict, for the world item ops: the same
        op id sequence, another ack. Journaled before the ACK may leave."""
        verdicts = self._world_item_verdicts.setdefault(peer_id, OrderedDict())
        verdicts[client_op_id] = ack
        verdicts.move_to_end(client_op_id)
        while len(verdicts) > self.CONTAINER_VERDICTS_KEPT:
            verdicts.popitem(last=False)
        self._journal("remember_world_item_verdict", peer_id=peer_id,
                      client_op_id=client_op_id, ack=ack)

    def recall_world_item_verdict(self, peer_id: str, client_op_id: int
                                  ) -> Optional[WorldItemAckPayload]:
        verdicts = self._world_item_verdicts.get(peer_id)
        if not verdicts:
            return None
        return verdicts.get(client_op_id)

    def set_world_spawn_pieces(self, wid: int, pieces) -> bool:
        """Full-state replace of a PA frame's piece ledger."""
        st = self.world_spawns.get(wid)
        if st is None:
            return False
        st.pieces = tuple(tuple(p) if isinstance(p, (list, tuple)) else p
                          for p in pieces)
        self._journal("set_world_spawn_pieces", wid=wid, pieces=st.pieces)
        return True

    def mark_world_spawn_worn(self, wid: int, peer_id: str, now_ms: float) -> bool:
        """Somebody climbed into this frame: kept, marked, not placed for
        anyone until it is given back."""
        st = self.world_spawns.get(wid)
        if st is None:
            return False
        st.worn_by_peer_id = peer_id
        st.worn_since_ms = now_ms
        self._journal("mark_world_spawn_worn", wid=wid, peer_id=peer_id,
                      now_ms=now_ms)
        return True

    def return_worn_frame(self, wid: int, px: float, py: float, pz: float,
                          cell_id: int) -> bool:
        """The wearer left: the frame is a world object again, where they
        last stood."""
        st = self.world_spawns.get(wid)
        if st is None:
            return False
        st.px, st.py, st.pz = float(px), float(py), float(pz)
        st.cell_id = int(cell_id)
        st.worn_by_peer_id = ""
        st.worn_since_ms = 0.0
        self._journal("return_worn_frame", wid=wid, px=st.px, py=st.py,
                      pz=st.pz, cell_id=st.cell_id)
        return True

    def all_world_spawns(self) -> list[WorldSpawnState]:
        return list(self.world_spawns.values())


    # ---------------------------------------------------------- convenience

    def welcome_for(self, session: PeerSession,
                    resume_token: bytes = b"") -> WelcomePayload:
        # The ritual is required only when the server both wants it AND has
        # nothing stored for this identity. Asking a returning player to create
        # a character again would be a bug, not a ritual.
        needs_chargen = (
            self.require_chargen and self.appearance(session.peer_id) is None
        )
        return WelcomePayload(
            session_id=session.session_id,
            accepted=True,
            server_version_major=self.server_version[0],
            server_version_minor=self.server_version[1],
            tick_rate_hz=self.tick_rate_hz,
            chargen_required=needs_chargen,
            reject_code=RejectCode.NONE,
            resume_token=resume_token or b"",
        )

    def peer_join_for(self, session: PeerSession) -> PeerJoinPayload:
        # v26 — the name rides the join so peers can label each other without
        # a second round trip. It is cosmetic: the identity is the peer_id.
        return PeerJoinPayload(
            peer_id=session.peer_id,
            session_id=session.session_id,
            display_name=session.display_name or "",
        )

    def peer_leave_for(self, session: PeerSession, reason: int = 0) -> PeerLeavePayload:
        return PeerLeavePayload(peer_id=session.peer_id, reason=reason)
