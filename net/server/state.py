"""
Server state: tracks all peer sessions and authoritative world state.

Pure data + mutation methods. No I/O, no asyncio here — main.py drives this.
"""
from __future__ import annotations

import dataclasses
import hashlib
import itertools
import logging
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
    MessageType, MAX_CLIENT_ID_LEN,
    WelcomePayload, PeerJoinPayload, PeerLeavePayload,
    PosStatePayload, ActorEventPayload,
    ContainerOpPayload, ContainerOpKind, ContainerOpAckPayload,
    EquipModRecord,
    is_runtime_form_id,
    identities_conflict,
    COUNT_MAX,
    RejectCode, RESUME_TOKEN_LEN, RESUME_TOKEN_TTL_S,
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

    `items` maps item TESForm.formID -> count. Entries with count == 0 are
    eagerly removed (no stale zero keys).

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
    items: dict[int, int] = field(default_factory=dict)   # item_base_id -> count
    last_owner_peer_id: Optional[str] = None
    last_update_ms: float = 0.0
    seeded: bool = False


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


CHECKPOINTS_KEPT = 3


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
                EquipModRecord, OutfitEntry)
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
    "record_quest_stage": "record_quest_stage",
    "record_global_var": "record_global_var",
    "record_inv_digest": "record_inv_digest",
    "record_checkpoint": "record_checkpoint",
    "confirm_checkpoint": "confirm_checkpoint",
    "set_checkpoint_custody": "set_checkpoint_custody",
    "record_appearance": "record_appearance",
    "record_lock": "record_lock",
    "record_world_spawn": "_restore_world_spawn",
    "remove_world_spawn": "remove_world_spawn",
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
    # Loot rework L2: the verdicts of the last CONTAINER_OPs of every peer,
    # keyed by peer id because a rejoin is a new session. The client applies
    # its take at once and sends the op afterwards, so an op whose ACK died
    # with the session is sent again on the rejoin: it must get the same
    # verdict and be applied once. Not persisted: a server restart inside
    # that window is a known residue.
    CONTAINER_VERDICTS_KEPT: ClassVar[int] = 256
    _container_verdicts: dict[str, "OrderedDict[int, ContainerOpAckPayload]"] = field(
        default_factory=dict)
    # B4: quest stages, keyed by quest_form_id.
    _quests: dict[int, QuestStageState] = field(default_factory=dict)
    # B4: global variables, keyed by global_form_id.
    _globals: dict[int, GlobalVarState] = field(default_factory=dict)
    # L5 stage 2: peer_id -> the last inventory digest it reported (advisory).
    _inv_digests: dict[str, InvDigestRecord] = field(default_factory=dict)
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
        self._quests.clear()
        self._globals.clear()
        self._inv_digests.clear()
        self._checkpoints.clear()
        self._appearances.clear()
        self.lock_state.clear()
        self.world_spawns.clear()
        self.next_world_spawn_wid = 1
        self._presence.clear()
        self._resume_tokens.clear()

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
        self._journal("record_actor_event", event=event, by_peer_id=by_peer_id,
                      now_ms=now_ms)
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
        if (op.container_form_id == 0 or is_runtime_form_id(op.container_form_id)
                or op.container_base_id == 0 or op.container_cell_id == 0):
            return None
        if op.count <= 0:
            return None
        if op.kind not in (int(ContainerOpKind.TAKE), int(ContainerOpKind.PUT)):
            return None

        container = self._containers.get(op.container_form_id)
        if container is None:
            # Inferred from one op, not scanned: partial (see `seeded`).
            container = ContainerWorldState(
                form_id=op.container_form_id,
                base_id=op.container_base_id,
                cell_id=op.container_cell_id,
                seeded=False,
            )
            self._containers[op.container_form_id] = container
        elif identities_conflict(container.base_id, container.cell_id,
                                 op.container_base_id, op.container_cell_id):
            return None

        # Trust-the-client policy for MVP: the server has no way to seed
        # container contents from the save file, so a TAKE against an
        # unknown-to-server item is interpreted as "the client observed
        # at least `count` of this item before the take; after the take,
        # 0 remain". No reject. PUT is straightforward additive.
        item_is_new = op.item_base_id not in container.items
        current = container.items.get(op.item_base_id, 0)
        if op.kind == int(ContainerOpKind.TAKE):
            if item_is_new:
                # First time we observe this item. Assume had exactly `count`,
                # now has 0.
                new_count = 0
            else:
                new_count = max(0, current - op.count)
        else:  # PUT
            new_count = current + op.count
            if new_count > COUNT_MAX:
                # The validator refuses this upstream (COUNT_OVERFLOW); this
                # is the last guard before a value the wire cannot pack.
                return None

        if new_count == 0:
            container.items.pop(op.item_base_id, None)
        else:
            container.items[op.item_base_id] = new_count

        container.last_owner_peer_id = by_peer_id
        container.last_update_ms = now_ms
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
            items={iid: min(int(cnt), COUNT_MAX) for iid, cnt in items.items() if cnt > 0},
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
        container.items = {iid: min(int(cnt), COUNT_MAX)
                           for iid, cnt in items.items() if cnt > 0}
        container.seeded = True
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

    # ---------------------------------------------- checkpoints (L5 stage 3a)

    def record_checkpoint(
        self, peer_id: str, identity_hex: str, seq: int, name: str, sha256_hex: str,
        size: int, digest: int, digest_seq: int, wall_ms: int, now_ms: float,
        watermark_lsn: int, reason: int, status: str = "provisional",
        boot_failures: int = 0,
        custody: bool = False,
    ) -> Optional[CheckpointRecord]:
        """Keep a checkpoint a client reported written, newest first, the
        last CHECKPOINTS_KEPT per peer. `watermark_lsn` is decided by the
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
            status=str(status), boot_failures=int(boot_failures), custody=bool(custody))
        lst = self._checkpoints.setdefault(peer_id, [])
        lst[:] = [r for r in lst if r.name != name]
        lst.insert(0, rec)
        del lst[CHECKPOINTS_KEPT:]
        self._journal("record_checkpoint", peer_id=peer_id, identity_hex=rec.identity_hex,
                      seq=rec.seq, name=name, sha256_hex=rec.sha256_hex, size=rec.size,
                      digest=rec.digest, digest_seq=rec.digest_seq, wall_ms=rec.wall_ms,
                      now_ms=float(now_ms), watermark_lsn=rec.watermark_lsn, reason=rec.reason)
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
