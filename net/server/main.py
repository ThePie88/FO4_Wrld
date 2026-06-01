"""
FalloutWorld server v1 — asyncio DatagramProtocol entry point.

Responsibilities:
- Accept HELLO and respond WELCOME (handshake)
- Relay POS_STATE -> POS_BROADCAST to all other peers (unreliable)
- Authoritative validation + broadcast of ACTOR_EVENT (reliable)
- Timeout stale peers
- Periodic state snapshot to disk

Single-threaded asyncio loop. All state mutation in main task.
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import math
import time
from pathlib import Path
from typing import Optional

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from channel import ChannelError  # noqa: E402
from protocol import (  # noqa: E402
    MessageType, ProtocolError,
    HelloPayload, WelcomePayload, PeerJoinPayload, PeerLeavePayload,
    HeartbeatPayload, DisconnectPayload, PosStatePayload, PosBroadcastPayload,
    PoseStatePayload, PoseBroadcastPayload,
    PoseCrouchStatePayload, PoseCrouchBroadcastPayload,   # v16 — ghost crouch
    ActorEventPayload, ChatPayload, RawMessage,
    WorldStatePayload, WorldActorEntry,
    ContainerOpPayload, ContainerBroadcastPayload,
    ContainerStatePayload, ContainerStateEntry,
    ContainerSeedPayload, ContainerOpAckPayload, ContainerOpAckStatus,
    QuestStageSetPayload, QuestStageBroadcastPayload,
    QuestStateBootPayload, QuestStageStateEntry,
    GlobalVarSetPayload, GlobalVarBroadcastPayload,
    GlobalVarStateBootPayload, GlobalVarStateEntry,
    DoorOpPayload, DoorBroadcastPayload,
    LockOpPayload, LockBroadcastPayload,
    EquipOpPayload, EquipBroadcastPayload, EquipOpKind,
    MeshBlobChunkPayload, MeshBlobChunkBroadcastPayload,
    NPCStateEntry, NPCStateBroadcastPayload, MAX_NPC_STATES_PER_FRAME,
    NPCFirePayload, NPCDiscoverPayload, NPCPerceptionTriggerPayload,
    # Build 65 — owner-driven NPC sync (Solver 2)
    NPCObservedPayload, NPCUnloadPayload,
    NPCOwnerHeartbeatPayload, NPCOwnerHeartbeatEntry,
    NPCOwnershipBcastPayload, NPCOwnershipBcastEntry,
    NPCOwnershipHandoffPhase1Payload,
    NPCOwnershipHandoffPhase2Payload,
    NPCOwnershipReleaseAckPayload,
    NPCStateFromOwnerPayload, NPCOwnerStateEntry,
    NPCFireFromOwnerPayload,
    NPCDeathFromOwnerPayload,
    NPCDamageFromOwnerPayload,
    NPCEngagementClaimPayload,  # Build 65.c.23 — combat-driven handoff
    NPCPoseFromOwnerPayload,    # c.37.0 — full NPC pose replication
    NPCCrouchFromOwnerPayload,  # NPC crouch — COM/Pelvis vertical drop relay
    NPCDamageClaimPayload,      # c.39b — damage-based threat
    PeerGhostRegisterPayload,
    encode_frame, decode_frame,
)
from server.state import ServerState, PeerSession, SessionState, LockWorldState  # noqa: E402
from server.validator import (  # noqa: E402
    validate_pos_state, validate_actor_event, validate_container_op, RejectReason,
)
from server.persistence import snapshot, load_into, rotate_snapshots  # noqa: E402
from server.npc_brain import NPCBrain  # noqa: E402
from server.raider_brain import RaiderBrain  # noqa: E402
from server.ownership import (  # noqa: E402
    OwnershipRegistry, OwnershipChange,
)


log = logging.getLogger("server")


# ---------------------------------------------------------------- B6.7 — cell-aware broadcast filtering
#
# Distance threshold (Bethesda game units, "ft" in waypoint files) above
# which a peer does NOT receive state/fire events for a given NPC. This
# replaces the previous unconditional fan-out documented in
# protocol.py:2238-2241 ("Cell-aware filtering / interest management is
# not yet implemented: every peer receives every tracked NPC regardless
# of cell. Filtering lands in B6.7+.").
#
# Why distance and not cell_id strict-match: the waypoint JSON has
# placeholder `cell_id: 0` for every raider entry; populating accurate
# cell_id values requires re-authoring data. Distance-based filtering
# is robust to that gap and works for both inter-cell (Sanctuary vs
# Concord, ~80 000 units apart) and intra-cell scenarios.
#
# Empirically (Build 31.6 live-test 2026-05-16 18:32:59 + Agent F8
# dossier): server was sending NPC_STATE_BCAST + NPC_FIRE for Concord
# raiders to peer A even when A's loaded cell was Sanctuary. Client A
# then ran SetCombatTarget / pos teleport / fire on raiders whose
# engine-side REFR was in an unloaded or wrong cell → crash. With the
# distance filter, a Sanctuary peer no longer receives Concord raider
# state, eliminating that crash precondition.
#
# 10 000 ft (~ 100 m worldspace, far past visible LOD) is a deliberately
# generous radius: it covers the entire "loaded cell cluster" around a
# peer (the engine streams ~5 cells = ~25 600 ft in worldspace, but
# active perception/AI happens only within a few thousand ft). Peers in
# the same Concord cell will all stay within range of each raider.
NPC_BROADCAST_RANGE_FT = 10000.0
NPC_BROADCAST_RANGE_SQ = NPC_BROADCAST_RANGE_FT * NPC_BROADCAST_RANGE_FT


# ---------------------------------------------------------------- config

class Config:
    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 31337,
        tick_rate_hz: int = 20,
        snapshot_path: Optional[Path] = None,
        snapshot_interval_s: float = 30.0,
        log_level: str = "INFO",
        waypoints_dir: Optional[Path] = None,
        npc_tick_hz: int = 10,
    ) -> None:
        self.host = host
        self.port = port
        self.tick_rate_hz = tick_rate_hz
        self.snapshot_path = snapshot_path
        self.snapshot_interval_s = snapshot_interval_s
        self.log_level = log_level
        self.waypoints_dir = waypoints_dir
        self.npc_tick_hz = npc_tick_hz


# ---------------------------------------------------------------- protocol handler

class ServerProtocol(asyncio.DatagramProtocol):
    """Wires asyncio's UDP to our state machine. Owns the ServerState."""

    def __init__(self, state: ServerState) -> None:
        self.state = state
        self.transport: Optional[asyncio.DatagramTransport] = None
        # B6.6w2: optional handles to npc_brain + raider_brain so the
        # NPC_DISCOVER handler can call register_dynamic(). Set by run()
        # AFTER the brains are constructed but BEFORE the event loop
        # starts processing datagrams (atomicity: single-threaded
        # asyncio so no race on these fields).
        self.npc_brain: Optional[NPCBrain] = None
        self.raider_brain: Optional[RaiderBrain] = None
        # Build 65 — owner-driven NPC sync registry. See
        # `re/agents_20/SOLVER_02_owner_driven.md`. The registry is the
        # arbiter of which peer owns each tracked NPC at any moment.
        # Owners run vanilla AI locally; non-owners suppress + apply
        # broadcasted state. The server is a relay, not a simulator.
        self.ownership: OwnershipRegistry = OwnershipRegistry()
        self._counters = {
            "rx_frames": 0,
            "tx_frames": 0,
            "rx_invalid": 0,
            "rejections": 0,
            "ownership_changes": 0,
            "ownership_observed": 0,
            "ownership_state_relayed": 0,
            "ownership_heartbeats_rx": 0,
            "ownership_heartbeats_entries": 0,
            "ownership_state_rx": 0,
            "npc_pose_rx": 0,        # c.37.0
            "npc_pose_relayed": 0,   # c.37.0
            "npc_crouch_rx": 0,        # NPC crouch
            "npc_crouch_relayed": 0,   # NPC crouch
            "npc_damage_claims_rx": 0,  # c.39b
        }

    # ----- asyncio callbacks

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:  # type: ignore[override]
        self.transport = transport
        sockname = transport.get_extra_info("sockname")
        log.info("server listening on %s", sockname)

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        self._counters["rx_frames"] += 1
        now_ms = _now_ms()
        try:
            self._handle_incoming(data, addr, now_ms)
        except Exception as e:
            log.exception("unhandled error for %s: %s", addr, e)

    def error_received(self, exc: Exception) -> None:
        log.warning("transport error: %s", exc)

    # ----- dispatch

    def _handle_incoming(self, data: bytes, addr: tuple[str, int], now_ms: float) -> None:
        try:
            frame = decode_frame(data)
        except ProtocolError as e:
            self._counters["rx_invalid"] += 1
            log.debug("bad frame from %s: %s", addr, e)
            return

        mtype = frame.header.msg_type
        session = self.state.get_by_addr(addr)

        # HELLO: bootstrap session if new. Retransmits fall through to channel dedup.
        if mtype == MessageType.HELLO:
            if session is None:
                self._handle_hello_initial(addr, frame.payload, now_ms)
                session = self.state.get_by_addr(addr)
            # If session exists (new or retransmit), continue to channel processing
            # so ReceiveWindow tracks seq + emits ACK. HELLO retransmits will be
            # dedup'd and NOT redispatched.

        if session is None:
            # Non-HELLO from unknown addr: ignore
            log.debug("msg 0x%04X from unknown addr %s; ignoring", mtype, addr)
            return

        session.touch(now_ms)

        # Feed into reliability channel (decodes ACKs internally)
        delivered, ack_bytes = session.channel.on_receive(data, now_ms)
        if ack_bytes is not None:
            self._send(addr, ack_bytes)

        if delivered is None:
            return  # duplicate, ACK frame, or already-handled HELLO retransmit

        # Dispatch app-level payload. HELLO was already handled at bootstrap; skip.
        if delivered.header.msg_type == MessageType.HELLO:
            return

        self._dispatch(session, delivered.header.msg_type, delivered.payload, now_ms)

    def _dispatch(self, session: PeerSession, mtype: int, payload, now_ms: float) -> None:
        if mtype == MessageType.HEARTBEAT:
            return  # already touched
        if mtype == MessageType.DISCONNECT:
            self._handle_disconnect(session, payload, now_ms)
            return
        if mtype == MessageType.POS_STATE:
            self._handle_pos_state(session, payload, now_ms)
            return
        if mtype == MessageType.POSE_STATE:
            self._handle_pose_state(session, payload, now_ms)
            return
        if mtype == MessageType.POSE_CROUCH_STATE:
            self._handle_pose_crouch_state(session, payload, now_ms)
            return
        if mtype == MessageType.ACTOR_EVENT:
            self._handle_actor_event(session, payload, now_ms)
            return
        if mtype == MessageType.CONTAINER_OP:
            self._handle_container_op(session, payload, now_ms)
            return
        if mtype == MessageType.CONTAINER_SEED:
            self._handle_container_seed(session, payload, now_ms)
            return
        if mtype == MessageType.QUEST_STAGE_SET:
            self._handle_quest_stage_set(session, payload, now_ms)
            return
        if mtype == MessageType.GLOBAL_VAR_SET:
            self._handle_global_var_set(session, payload, now_ms)
            return
        if mtype == MessageType.DOOR_OP:
            self._handle_door_op(session, payload, now_ms)
            return
        if mtype == MessageType.LOCK_OP:
            self._handle_lock_op(session, payload, now_ms)
            return
        if mtype == MessageType.EQUIP_OP:
            self._handle_equip_op(session, payload, now_ms)
            return
        if mtype == MessageType.MESH_BLOB_OP:
            self._handle_mesh_blob_op(session, payload, now_ms)
            return
        if mtype == MessageType.NPC_DISCOVER:
            self._handle_npc_discover(session, payload, now_ms)
            return
        # Build 65 — owner-driven NPC sync (Solver 2).
        if mtype == MessageType.NPC_OBSERVED:
            self._handle_npc_observed(session, payload, now_ms)
            return
        if mtype == MessageType.NPC_UNLOAD:
            self._handle_npc_unload(session, payload, now_ms)
            return
        if mtype == MessageType.NPC_OWNER_HEARTBEAT:
            self._handle_npc_owner_heartbeat(session, payload, now_ms)
            return
        if mtype == MessageType.NPC_OWNERSHIP_RELEASE_ACK:
            self._handle_npc_release_ack(session, payload, now_ms)
            return
        if mtype == MessageType.NPC_STATE_FROM_OWNER:
            self._handle_npc_state_from_owner(session, payload, now_ms)
            return
        if mtype == MessageType.NPC_FIRE_FROM_OWNER:
            self._handle_npc_fire_from_owner(session, payload, now_ms)
            return
        if mtype == MessageType.NPC_DEATH_FROM_OWNER:
            self._handle_npc_death_from_owner(session, payload, now_ms)
            return
        if mtype == MessageType.NPC_DAMAGE_FROM_OWNER:
            self._handle_npc_damage_from_owner(session, payload, now_ms)
            return
        if mtype == MessageType.NPC_ENGAGEMENT_CLAIM:
            self._handle_npc_engagement_claim(session, payload, now_ms)
            return
        if mtype == MessageType.NPC_POSE_FROM_OWNER:
            self._handle_npc_pose_from_owner(session, payload, now_ms)
            return
        if mtype == MessageType.NPC_CROUCH_FROM_OWNER:
            self._handle_npc_crouch_from_owner(session, payload, now_ms)
            return
        if mtype == MessageType.NPC_DAMAGE_CLAIM:
            self._handle_npc_damage_claim(session, payload, now_ms)
            return
        if mtype == MessageType.PEER_GHOST_REGISTER:
            self._handle_peer_ghost_register(session, payload, now_ms)
            return
        if mtype == MessageType.CHAT:
            self._handle_chat(session, payload, now_ms)
            return
        log.debug("unhandled msg type 0x%04X from %s", mtype, session.peer_id)

    # ----- handlers

    def _handle_hello_initial(self, addr: tuple[str, int], payload, now_ms: float) -> None:
        if not isinstance(payload, HelloPayload):
            return
        session, reason = self.state.accept_peer(
            addr, payload.client_id,
            (payload.client_version_major, payload.client_version_minor),
            now_ms,
        )
        if session is None:
            log.warning("rejecting %s (%s): %s", addr, payload.client_id, reason)
            # Reply with rejection (best-effort, non-reliable)
            reject = WelcomePayload(
                session_id=0, accepted=False,
                server_version_major=self.state.server_version[0],
                server_version_minor=self.state.server_version[1],
                tick_rate_hz=self.state.tick_rate_hz,
            )
            raw = encode_frame(MessageType.WELCOME, 0, reject, reliable=False)
            self._send(addr, raw)
            self._counters["rejections"] += 1
            return

        # B6.6w5 — record Steam ID from HELLO. Future use: validate against
        # whitelist, derive canonical peer identity, ghost-fid registration.
        session.steam_id = int(getattr(payload, "steam_id", 0)) & 0xFFFFFFFFFFFFFFFF
        sid_str = (f"steam_id={session.steam_id}"
                   if session.steam_id else "steam_id=UNAVAILABLE")
        log.info("peer joined: %s from %s (sid=%d) %s",
                 session.peer_id, addr, session.session_id, sid_str)

        # WELCOME is reliable — client needs to know it's accepted
        welcome = self.state.welcome_for(session)
        raw = session.channel.send_reliable(MessageType.WELCOME, welcome, now_ms)
        self._send(addr, raw)

        # Bootstrap: send authoritative world state (dead/alive actors) to the new peer
        self._send_world_state_bootstrap(session, now_ms)
        # Bootstrap: container inventories (chunked)
        self._send_container_state_bootstrap(session, now_ms)
        # Bootstrap: quest stages (B4, chunked)
        self._send_quest_state_bootstrap(session, now_ms)
        # Bootstrap: global variables (B4, chunked)
        self._send_global_var_state_bootstrap(session, now_ms)
        # Bootstrap: lock states (B6.3 v0.5.3) — replay last-known state
        # for every (base, cell) the server has seen, as individual
        # LOCK_BCAST frames. Client treats them as fresh remote ops.
        self._send_lock_state_bootstrap(session, now_ms)
        # Bootstrap: NPC ownership table (Build 65 owner-driven sync).
        # Hands the new peer the current (fid, epoch, owner) map so it
        # can attach the correct local-vs-remote AI gate to every NPC
        # already loaded by other peers before it joined.
        self._send_ownership_state_bootstrap(session, now_ms)

        # Notify other peers (PEER_JOIN, reliable)
        join_msg = self.state.peer_join_for(session)
        for other in self.state.other_sessions(addr):
            raw = other.channel.send_reliable(MessageType.PEER_JOIN, join_msg, now_ms)
            self._send(other.addr, raw)

        # Announce existing peers to the new one (PEER_JOIN for each)
        for other in self.state.other_sessions(addr):
            existing = self.state.peer_join_for(other)
            raw = session.channel.send_reliable(MessageType.PEER_JOIN, existing, now_ms)
            self._send(addr, raw)

    def _send_world_state_bootstrap(self, session: PeerSession, now_ms: float) -> None:
        """Send authoritative world-actor snapshot to a newly-joined peer, chunked."""
        actors = self.state.all_actors()
        if not actors:
            log.debug("no world actors to bootstrap for %s", session.peer_id)
            return

        max_per = WorldStatePayload.MAX_ENTRIES_PER_FRAME
        total_chunks = (len(actors) + max_per - 1) // max_per
        log.info("bootstrap %s: %d actors in %d chunk(s)",
                 session.peer_id, len(actors), total_chunks)

        for chunk_idx in range(total_chunks):
            chunk = actors[chunk_idx * max_per : (chunk_idx + 1) * max_per]
            entries = tuple(
                WorldActorEntry(
                    form_id=a.last_known_form_id,
                    alive=a.alive,
                    base_id=a.base_id,
                    cell_id=a.cell_id,
                )
                for a in chunk
            )
            payload = WorldStatePayload(
                entries=entries,
                chunk_index=chunk_idx,
                total_chunks=total_chunks,
            )
            raw = session.channel.send_reliable(MessageType.WORLD_STATE, payload, now_ms)
            self._send(session.addr, raw)

    def _send_container_state_bootstrap(self, session: PeerSession, now_ms: float) -> None:
        """Send authoritative container inventories to a newly-joined peer.

        Flattens every (container, item_base_id, count) triple into
        ContainerStateEntry records, then chunks into MAX_ENTRIES_PER_FRAME
        (87 at MTU 1400) and sends each chunk reliably.
        """
        containers = self.state.all_containers()
        if not containers:
            log.debug("no container state to bootstrap for %s", session.peer_id)
            return

        # Flatten to entries. Skip empty containers — no point shipping them.
        entries: list[ContainerStateEntry] = []
        for c in containers:
            for item_id, count in c.items.items():
                entries.append(ContainerStateEntry(
                    container_base_id=c.base_id,
                    container_cell_id=c.cell_id,
                    item_base_id=item_id,
                    count=count,
                ))
        if not entries:
            return

        max_per = ContainerStatePayload.MAX_ENTRIES_PER_FRAME
        total_chunks = (len(entries) + max_per - 1) // max_per
        log.info("container bootstrap %s: %d entries in %d chunk(s)",
                 session.peer_id, len(entries), total_chunks)

        for chunk_idx in range(total_chunks):
            chunk = entries[chunk_idx * max_per : (chunk_idx + 1) * max_per]
            payload = ContainerStatePayload(
                entries=tuple(chunk),
                chunk_index=chunk_idx,
                total_chunks=total_chunks,
            )
            raw = session.channel.send_reliable(MessageType.CONTAINER_STATE, payload, now_ms)
            self._send(session.addr, raw)

    def _handle_disconnect(self, session: PeerSession, payload, now_ms: float) -> None:
        log.info("peer %s disconnecting", session.peer_id)
        self._remove_and_notify(session, reason=1, now_ms=now_ms)

    def _handle_pos_state(self, session: PeerSession, payload, now_ms: float) -> None:
        if not isinstance(payload, PosStatePayload):
            return
        result = validate_pos_state(session, payload, now_ms)
        if not result.ok:
            self._counters["rejections"] += 1
            # Build 65.c.12 — promoted to INFO. Stale `session.last_pos`
            # is the root cause of raider_brain firing at the wrong peer's
            # last-seen coords (e.g. melee raider running into a wall on
            # the owner's screen). Need visibility on WHICH validator
            # branch is firing so we can either fix the rule or carve a
            # legitimate exception.
            log.info("reject POS from %s: %s %s",
                     session.peer_id, RejectReason(result.reason).name, result.detail)
            return

        session.last_pos = payload
        session.last_pos_at_ms = now_ms
        session.total_pos_updates += 1

        # Broadcast to other peers (unreliable)
        broadcast = PosBroadcastPayload(
            peer_id=session.peer_id,
            x=payload.x, y=payload.y, z=payload.z,
            rx=payload.rx, ry=payload.ry, rz=payload.rz,
            timestamp_ms=payload.timestamp_ms,
            cell_id=payload.cell_id,    # v11: B6 prologue cell-aware ghost
        )
        for other in self.state.other_sessions(session.addr):
            raw = other.channel.send_unreliable(MessageType.POS_BROADCAST, broadcast)
            self._send(other.addr, raw)

    def _handle_pose_state(self, session: PeerSession, payload, now_ms: float) -> None:
        """M8P3.15 — relay per-bone rotation snapshot to other peers.
        No validation (trusted clients in this stage); pure fan-out."""
        if not isinstance(payload, PoseStatePayload):
            return
        broadcast = PoseBroadcastPayload(
            peer_id=session.peer_id,
            timestamp_ms=payload.timestamp_ms,
            quats=payload.quats,
        )
        for other in self.state.other_sessions(session.addr):
            raw = other.channel.send_unreliable(MessageType.POSE_BROADCAST, broadcast)
            self._send(other.addr, raw)

    def _handle_pose_crouch_state(self, session: PeerSession, payload, now_ms: float) -> None:
        """v16 — relay crouch bone-translation snapshot to other peers.
        Mirrors _handle_pose_state exactly: no validation (trusted clients in
        this stage); pure fan-out as POSE_CROUCH_BROADCAST."""
        if not isinstance(payload, PoseCrouchStatePayload):
            return
        broadcast = PoseCrouchBroadcastPayload(
            peer_id=session.peer_id,
            timestamp_ms=payload.timestamp_ms,
            entries=payload.entries,
        )
        for other in self.state.other_sessions(session.addr):
            raw = other.channel.send_unreliable(MessageType.POSE_CROUCH_BROADCAST, broadcast)
            self._send(other.addr, raw)

    def _handle_actor_event(self, session: PeerSession, payload, now_ms: float) -> None:
        if not isinstance(payload, ActorEventPayload):
            return
        actor_state = self.state.actor_state_for_event(payload)
        result = validate_actor_event(
            session, payload, actor_state, now_ms,
            ghost_target_base_ids=self.state.ghost_target_base_ids,
        )
        if not result.ok:
            self._counters["rejections"] += 1
            log.debug("reject ACTOR_EVENT from %s: %s %s",
                      session.peer_id, RejectReason(result.reason).name, result.detail)
            return

        # Apply to authoritative state
        self.state.record_actor_event(payload, session.peer_id, now_ms)
        session.total_events += 1

        # Broadcast to other peers (reliable)
        for other in self.state.other_sessions(session.addr):
            raw = other.channel.send_reliable(MessageType.ACTOR_EVENT, payload, now_ms)
            self._send(other.addr, raw)

        log.debug("actor event %s formid=0x%X by %s",
                  payload.kind, payload.form_id, session.peer_id)

    def _handle_container_op(self, session: PeerSession, payload, now_ms: float) -> None:
        if not isinstance(payload, ContainerOpPayload):
            return
        existing = self.state.container_state_for_op(payload)
        result = validate_container_op(session, payload, existing, now_ms)

        # --- B1: always emit an ACK to the sender (accept or reject). ---
        # The sender (DLL) holds a pre-mutation wait keyed on client_op_id,
        # woken by this ACK. On accept, engine's AddObjectToContainer is
        # allowed to proceed. On reject, the sender blocks the call and the
        # item transfer never happens — closing the container dup race.
        def _send_ack(status: ContainerOpAckStatus, final_count: int) -> None:
            if payload.client_op_id == 0:
                # Legacy B0 client — no op_id to correlate. Skip ACK.
                return
            ack = ContainerOpAckPayload(
                client_op_id=payload.client_op_id,
                status=int(status),
                container_base_id=payload.container_base_id,
                container_cell_id=payload.container_cell_id,
                item_base_id=payload.item_base_id,
                final_count=final_count,
            )
            raw = session.channel.send_reliable(MessageType.CONTAINER_OP_ACK, ack, now_ms)
            self._send(session.addr, raw)

        if not result.ok:
            self._counters["rejections"] += 1
            log.debug("reject CONTAINER_OP from %s: %s %s",
                      session.peer_id, RejectReason(result.reason).name, result.detail)
            # Map validator reject reason -> ACK status for the sender.
            status_map = {
                RejectReason.RATE_LIMITED:       ContainerOpAckStatus.REJ_RATE,
                RejectReason.MISSING_IDENTITY:   ContainerOpAckStatus.REJ_IDENTITY,
                RejectReason.INVALID_COUNT:      ContainerOpAckStatus.REJ_COUNT,
                RejectReason.INVALID_KIND:       ContainerOpAckStatus.REJ_KIND,
                RejectReason.INSUFFICIENT_ITEMS: ContainerOpAckStatus.REJ_INSUFFICIENT,
            }
            ack_status = status_map.get(
                RejectReason(result.reason), ContainerOpAckStatus.REJ_KIND)
            have = existing.items.get(payload.item_base_id, 0) if existing else 0
            _send_ack(ack_status, have)
            return

        # Apply to authoritative state (TAKE/PUT transitions, clamping)
        self.state.record_container_op(payload, session.peer_id, now_ms)
        session.total_events += 1

        # Lookup post-op count for the ACK
        updated = self.state.container_state_for_op(payload)
        final_count = updated.items.get(payload.item_base_id, 0) if updated else 0
        _send_ack(ContainerOpAckStatus.ACCEPTED, final_count)

        # Broadcast to other peers as CONTAINER_BCAST (reliable, with peer_id)
        # v5: forward container_form_id so receivers can resolve their local
        # REFR via lookup_by_form_id + (base, cell) identity check, then
        # invoke engine::apply_container_op_to_engine.
        broadcast = ContainerBroadcastPayload(
            peer_id=session.peer_id,
            kind=payload.kind,
            container_base_id=payload.container_base_id,
            container_cell_id=payload.container_cell_id,
            item_base_id=payload.item_base_id,
            count=payload.count,
            timestamp_ms=payload.timestamp_ms,
            container_form_id=payload.container_form_id,
        )
        for other in self.state.other_sessions(session.addr):
            raw = other.channel.send_reliable(MessageType.CONTAINER_BCAST, broadcast, now_ms)
            self._send(other.addr, raw)

        log.debug("container op kind=%d container=0x%X/0x%X item=0x%X count=%d by %s",
                  payload.kind, payload.container_base_id, payload.container_cell_id,
                  payload.item_base_id, payload.count, session.peer_id)

    def _handle_container_seed(self, session: PeerSession, payload, now_ms: float) -> None:
        """Record the client's ground-truth inventory scan for a container.

        B1.h policy (first-seed-wins, 2026-04-20 post-live-test hardening):
        ----------------------------------------------------------------
        We used to WHOLESALE-REPLACE server state on every SEED. That was
        catastrophic: a peer whose engine state had drifted (e.g., never
        received a CONTAINER_BCAST) would happily report an EMPTY container
        and erase legitimate contents that another peer had put there.

        Now: SEED is applied ONLY if this (base, cell) has no server state
        yet. Subsequent SEEDs for known containers are logged and dropped.
        The server's state is canonical from the first scan onward;
        downstream TAKE/PUT ops keep it correct via record_container_op.

        If a client's engine list has drifted, the server will reject its
        TAKEs with INSUFFICIENT_ITEMS (or over-count on PUT is harmless).
        The client's engine will be reconciled via BCAST apply (B1.g) or
        first-open snapshot push (B1.j) — both downstream of this handler.

        Chunking: a multi-chunk SEED for a single container is treated as
        additive per-item within the same message. If the container is new
        to us, all chunks merge into the initial seed. If we're rejecting
        (state exists), all chunks are dropped symmetrically.
        """
        if not isinstance(payload, ContainerSeedPayload):
            return
        if not payload.entries:
            log.debug("container SEED from %s: empty payload (chunk %u/%u)",
                      session.peer_id,
                      payload.chunk_index + 1, payload.total_chunks)
            return

        # Group by container identity.
        by_container: dict[tuple[int, int], dict[int, int]] = {}
        n_skipped_identity = 0
        for e in payload.entries:
            if e.container_base_id == 0 or e.container_cell_id == 0:
                n_skipped_identity += 1
                continue
            key = (e.container_base_id, e.container_cell_id)
            bucket = by_container.setdefault(key, {})
            if e.count > 0:
                bucket[e.item_base_id] = e.count
            # count==0 entries are silently dropped: they don't contribute
            # to the seed (we don't track absences explicitly; missing key
            # == count 0).

        n_created = 0
        n_refilled = 0
        n_rejected = 0
        for (base, cell), items in by_container.items():
            existing = self.state.container_state(base, cell)

            # First-seed-wins, refined after 2026-04-20 live test:
            #   - If no state exists: create it from SEED (the fresh case).
            #   - If state exists AND has items: REJECT the SEED. Protects
            #     against a drifted peer wiping legitimate contents.
            #   - If state exists BUT has items={} (empty): ACCEPT the SEED
            #     as a refill. Rationale:
            #       (a) Empty-state entries are legitimately created when
            #           all items are taken via record_container_op, but
            #           containers in FO4 respawn periodically — a fresh
            #           scan after respawn should re-populate.
            #       (b) Pre-B1.h sessions could corrupt state by accepting
            #           drifted-peer empty SEEDs as wholesale-replace. The
            #           snapshot carries that corruption forward; an empty
            #           entry is indistinguishable from "legitimately
            #           emptied", so allowing refill recovers gracefully.
            #     Risk: a currently-drifted peer could SEED leftover items
            #     into a legitimately-emptied container. Acceptable trade-
            #     off until B1.g/B1.j close the drift class.
            if existing is None:
                from server.state import ContainerWorldState
                container = ContainerWorldState(base_id=base, cell_id=cell)
                container.items = dict(items)
                container.last_owner_peer_id = session.peer_id
                container.last_update_ms = now_ms
                self.state._containers[(base, cell)] = container  # type: ignore[attr-defined]
                n_created += 1
            elif not existing.items:
                # Refill an empty container. Preserve the existing record
                # (keeps history), just fill in items.
                existing.items = dict(items)
                existing.last_owner_peer_id = session.peer_id
                existing.last_update_ms = now_ms
                n_refilled += 1
                log.info(
                    "container SEED from %s: REFILL empty base=0x%X cell=0x%X → "
                    "%d item(s)", session.peer_id, base, cell, len(items))
            else:
                n_rejected += 1
                log.debug(
                    "container SEED from %s: REJECT base=0x%X cell=0x%X — "
                    "state already canonical (%d items, owner=%s)",
                    session.peer_id, base, cell,
                    len(existing.items), existing.last_owner_peer_id)

        session.touch(now_ms)
        log.info(
            "container SEED from %s: %d created, %d refilled (empty), %d rejected "
            "(already canonical), %d entries w/ bad identity, chunk %u/%u",
            session.peer_id, n_created, n_refilled, n_rejected, n_skipped_identity,
            payload.chunk_index + 1, payload.total_chunks)

    # ----- B4: quest stage + global variable handlers -----

    def _handle_quest_stage_set(
        self, session: PeerSession, payload, now_ms: float
    ) -> None:
        if not isinstance(payload, QuestStageSetPayload):
            return
        if payload.quest_form_id == 0:
            self._counters["rejections"] += 1
            log.debug("reject QUEST_STAGE_SET from %s: quest_form_id=0", session.peer_id)
            return

        # Last-write-wins. No validator rejection for now — monotonicity is
        # enforced at the Papyrus layer on each peer; if ResetQuest drops
        # the stage, we replicate that faithfully.
        updated = self.state.record_quest_stage(
            payload.quest_form_id, payload.new_stage,
            session.peer_id, now_ms,
        )
        if updated is None:
            self._counters["rejections"] += 1
            log.debug("reject QUEST_STAGE_SET from %s: invalid (form=0x%X stage=%d)",
                      session.peer_id, payload.quest_form_id, payload.new_stage)
            return
        session.total_events += 1

        log.info("quest %s set stage 0x%X -> %d by %s",
                 "update" if updated is not None else "init",
                 payload.quest_form_id, payload.new_stage, session.peer_id)

        # Broadcast to other peers (BCAST carries peer_id).
        broadcast = QuestStageBroadcastPayload(
            peer_id=session.peer_id,
            quest_form_id=payload.quest_form_id,
            new_stage=payload.new_stage,
            timestamp_ms=payload.timestamp_ms,
        )
        for other in self.state.other_sessions(session.addr):
            raw = other.channel.send_reliable(
                MessageType.QUEST_STAGE_BCAST, broadcast, now_ms)
            self._send(other.addr, raw)

    def _handle_global_var_set(
        self, session: PeerSession, payload, now_ms: float
    ) -> None:
        if not isinstance(payload, GlobalVarSetPayload):
            return
        if payload.global_form_id == 0:
            self._counters["rejections"] += 1
            log.debug("reject GLOBAL_VAR_SET from %s: global_form_id=0",
                      session.peer_id)
            return

        updated = self.state.record_global_var(
            payload.global_form_id, payload.value,
            session.peer_id, now_ms,
        )
        if updated is None:
            self._counters["rejections"] += 1
            log.debug("reject GLOBAL_VAR_SET from %s: invalid "
                      "(form=0x%X value=%r)",
                      session.peer_id, payload.global_form_id, payload.value)
            return
        session.total_events += 1

        log.info("global set 0x%X -> %g by %s",
                 payload.global_form_id, payload.value, session.peer_id)

        broadcast = GlobalVarBroadcastPayload(
            peer_id=session.peer_id,
            global_form_id=payload.global_form_id,
            value=payload.value,
            timestamp_ms=payload.timestamp_ms,
        )
        for other in self.state.other_sessions(session.addr):
            raw = other.channel.send_reliable(
                MessageType.GLOBAL_VAR_BCAST, broadcast, now_ms)
            self._send(other.addr, raw)

    # ----- B4: bootstrap snapshot senders -----

    def _send_quest_state_bootstrap(
        self, session: PeerSession, now_ms: float
    ) -> None:
        quests = self.state.all_quest_stages()
        if not quests:
            log.debug("no quest stages to bootstrap for %s", session.peer_id)
            return
        entries = tuple(
            QuestStageStateEntry(quest_form_id=q.quest_form_id, stage=q.stage)
            for q in quests
        )
        max_per = QuestStateBootPayload.MAX_ENTRIES_PER_FRAME
        total_chunks = (len(entries) + max_per - 1) // max_per
        log.info("quest-state bootstrap %s: %d entries in %d chunk(s)",
                 session.peer_id, len(entries), total_chunks)
        for i in range(total_chunks):
            chunk = entries[i * max_per : (i + 1) * max_per]
            payload = QuestStateBootPayload(
                entries=chunk, chunk_index=i, total_chunks=total_chunks)
            raw = session.channel.send_reliable(
                MessageType.QUEST_STATE_BOOT, payload, now_ms)
            self._send(session.addr, raw)

    def _send_global_var_state_bootstrap(
        self, session: PeerSession, now_ms: float
    ) -> None:
        globs = self.state.all_globals()
        if not globs:
            log.debug("no globals to bootstrap for %s", session.peer_id)
            return
        entries = tuple(
            GlobalVarStateEntry(global_form_id=g.global_form_id, value=g.value)
            for g in globs
        )
        max_per = GlobalVarStateBootPayload.MAX_ENTRIES_PER_FRAME
        total_chunks = (len(entries) + max_per - 1) // max_per
        log.info("global-var bootstrap %s: %d entries in %d chunk(s)",
                 session.peer_id, len(entries), total_chunks)
        for i in range(total_chunks):
            chunk = entries[i * max_per : (i + 1) * max_per]
            payload = GlobalVarStateBootPayload(
                entries=chunk, chunk_index=i, total_chunks=total_chunks)
            raw = session.channel.send_reliable(
                MessageType.GLOBAL_VAR_STATE_BOOT, payload, now_ms)
            self._send(session.addr, raw)

    def _send_lock_state_bootstrap(
        self, session: PeerSession, now_ms: float
    ) -> None:
        """B6.3 v0.5.3 — replay every known lock state to the new peer.

        Each entry is shipped as a fresh LOCK_BCAST so the client
        treats it identically to a runtime lock change (peer_id is
        synthesized as 'server' for telemetry; client only cares about
        identity + state). Reliable channel — order doesn't matter
        because each entry is independent (different REFR identity).
        """
        locks = self.state.all_locks()
        if not locks:
            log.debug("no lock states to bootstrap for %s", session.peer_id)
            return
        log.info("lock bootstrap %s: %d entries", session.peer_id, len(locks))
        for lk in locks:
            payload = LockBroadcastPayload(
                peer_id="server",
                lock_form_id=lk.form_id,
                lock_base_id=lk.base_id,
                lock_cell_id=lk.cell_id,
                locked=1 if lk.locked else 0,
                timestamp_ms=lk.timestamp_ms,
            )
            raw = session.channel.send_reliable(
                MessageType.LOCK_BCAST, payload, now_ms)
            self._send(session.addr, raw)

    def _send_ownership_state_bootstrap(
        self, session: PeerSession, now_ms: float
    ) -> None:
        """Build 65 — replay current NPC ownership map to a new peer.

        Without this, a freshly joined peer would treat every NPC it
        encounters as 'first observer' and try to claim it — but the
        registry already has another peer as owner, so the claim is
        rejected and the new peer never learns the truth until a
        PHASE_2 broadcast happens (which only fires on ownership
        *change*). Bootstrap shoots one or more NPC_OWNERSHIP_BCAST
        frames so the new peer's local map matches the server's
        before its first NPC_OBSERVED ever flies.

        Chunked at MAX_ENTRIES per frame; reliable channel.
        """
        recs = list(self.ownership.iter_records())
        if not recs:
            log.debug("no ownership state to bootstrap for %s", session.peer_id)
            return
        max_per = NPCOwnershipBcastPayload.MAX_ENTRIES
        total = (len(recs) + max_per - 1) // max_per
        log.info("ownership bootstrap %s: %d entries in %d chunk(s)",
                 session.peer_id, len(recs), total)
        for chunk_idx in range(total):
            chunk = recs[chunk_idx * max_per : (chunk_idx + 1) * max_per]
            entries = tuple(
                NPCOwnershipBcastEntry(
                    form_id=rec.form_id,
                    epoch=rec.epoch,
                    owner_peer_id=self._peer_id_to_bytes(rec.owner_peer_id),
                )
                for rec in chunk
            )
            payload = NPCOwnershipBcastPayload(entries=entries)
            raw = session.channel.send_reliable(
                MessageType.NPC_OWNERSHIP_BCAST, payload, now_ms)
            self._send(session.addr, raw)

    def _handle_door_op(self, session: PeerSession, payload, now_ms: float) -> None:
        """B6.1 — door activation broadcast.

        Pure fan-out, no validation. Doors use toggle semantics (engine
        Activate worker flips the open state). Server doesn't track door
        state — receivers re-invoke their local Activate worker on the
        matching REFR, which preserves engine animation + persistence
        side effects. If clients diverge (rare missed BCAST), the next
        press resyncs them.
        """
        if not isinstance(payload, DoorOpPayload):
            return
        if payload.door_form_id == 0 or payload.door_base_id == 0:
            log.debug("door_op from %s: zero identity (form=0x%X base=0x%X) — drop",
                      session.peer_id, payload.door_form_id, payload.door_base_id)
            return

        broadcast = DoorBroadcastPayload(
            peer_id=session.peer_id,
            door_form_id=payload.door_form_id,
            door_base_id=payload.door_base_id,
            door_cell_id=payload.door_cell_id,
            timestamp_ms=payload.timestamp_ms,
        )
        for other in self.state.other_sessions(session.addr):
            raw = other.channel.send_reliable(
                MessageType.DOOR_BCAST, broadcast, now_ms)
            self._send(other.addr, raw)

        log.debug("door op form=0x%X base=0x%X cell=0x%X by %s",
                  payload.door_form_id, payload.door_base_id,
                  payload.door_cell_id, session.peer_id)

    def _handle_peer_ghost_register(
        self, session: PeerSession, payload, now_ms: float,
    ) -> None:
        """B6.6w5 — client reported its local ghost-actor form_id.

        The ghost is the engine REFR that represents the OTHER peer
        on this client's screen. Stored on the session and used in
        raider_brain.project_for_peer to set combat_target_form_id
        correctly per-viewer (so when server picks peer A as a
        raider's aggro target, peer B's broadcast carries A's ghost
        fid on B's screen → engine targets the right actor visually).
        """
        if not isinstance(payload, PeerGhostRegisterPayload):
            return
        new_fid = int(payload.ghost_form_id) & 0xFFFFFFFF
        if new_fid == 0 or new_fid == 0xFFFFFFFF:
            log.debug("peer_ghost_register: %s sent invalid fid 0x%X — drop",
                      session.peer_id, new_fid)
            return
        old_fid = session.ghost_form_id
        session.ghost_form_id = new_fid
        if old_fid != new_fid:
            log.info(
                "peer_ghost_register: %s ghost_form_id 0x%X -> 0x%X "
                "(used for cross-peer combat target substitution)",
                session.peer_id, old_fid, new_fid,
            )

    def _handle_npc_discover(
        self, session: PeerSession, payload, now_ms: float,
    ) -> None:
        """B6.6w2 — client auto-tracked a hostile NPC; register it.

        Client's ``npc_ai_suppress`` Path 2 fires when an Actor has the
        InCombat flag (bit 0x4000 at ``Actor+0x2D0``) set by vanilla AI.
        On the FIRST auto-track for a given form_id, the client emits
        this opcode so the server can sync it across peers.

        Idempotent: duplicate discoveries (same form_id) are ignored —
        common because both peers will independently auto-track and
        report. The first one wins; subsequent ones bump a duplicate
        counter for diagnostics.
        """
        if not isinstance(payload, NPCDiscoverPayload):
            return
        if self.raider_brain is None or self.npc_brain is None:
            log.debug("npc_discover: brains not available, ignoring "
                      "form=0x%X from %s",
                      payload.form_id, session.peer_id)
            return
        # Reject bogus form_ids.
        if (payload.form_id == 0 or payload.form_id == 0xFFFFFFFF
                or payload.form_id == 0x14):
            log.debug("npc_discover: invalid form=0x%X from %s — drop",
                      payload.form_id, session.peer_id)
            return
        # Already registered? UPDATE the runtime pos with the discover's
        # pos (client engine knows the REAL spawn pos; JSON spawn entries
        # with (0,0,0) need to be corrected from live data so distance-
        # based aggro can work).
        existing = self.raider_brain.raider_for(payload.form_id)
        if existing is not None:
            old_pos = (existing.ai.pos_x, existing.ai.pos_y, existing.ai.pos_z)
            new_pos = (payload.pos_x, payload.pos_y, payload.pos_z)
            # Only update if discover pos is non-zero AND differs notably.
            non_zero = any(abs(v) > 0.01 for v in new_pos)
            differs = any(abs(a - b) > 1.0 for a, b in zip(old_pos, new_pos))
            if non_zero and differs:
                existing.ai.pos_x = float(payload.pos_x)
                existing.ai.pos_y = float(payload.pos_y)
                existing.ai.pos_z = float(payload.pos_z)
                log.info(
                    "npc_discover: POS UPDATE form=0x%X "
                    "old=(%.1f,%.1f,%.1f) -> new=(%.1f,%.1f,%.1f) "
                    "(reporter=%s) — raider_brain can now distance-aggro",
                    payload.form_id,
                    old_pos[0], old_pos[1], old_pos[2],
                    new_pos[0], new_pos[1], new_pos[2],
                    session.peer_id,
                )
            else:
                log.debug("npc_discover: form=0x%X already tracked, "
                          "discover pos same/zero — skip (reporter=%s)",
                          payload.form_id, session.peer_id)
            return
        # Dynamic registration into BOTH brains:
        #   npc_brain.npcs[fid]    = NPCRuntime (broadcast surface)
        #   raider_brain.raiders[fid] = RaiderRuntime (combat brain)
        # Position from client report is the initial pos; subsequent
        # NPC_STATE_BCAST will broadcast it. Brain may evolve via combat
        # AI in later ticks.
        try:
            self.raider_brain.register_dynamic(
                npc_brain=self.npc_brain,
                form_id=payload.form_id,
                base_id=payload.base_id,
                cell_id=payload.cell_id,
                pos_x=payload.pos_x,
                pos_y=payload.pos_y,
                pos_z=payload.pos_z,
                reporter_peer_id=session.peer_id,
            )
            log.info(
                "npc_discover: REGISTERED form=0x%X base=0x%X cell=0x%X "
                "pos=(%.1f,%.1f,%.1f) reporter=%s "
                "(brain now has %d raider(s))",
                payload.form_id, payload.base_id, payload.cell_id,
                payload.pos_x, payload.pos_y, payload.pos_z,
                session.peer_id, self.raider_brain.count(),
            )
        except Exception as e:
            log.warning("npc_discover: register failed form=0x%X: %s",
                        payload.form_id, e)

    # ========================================================================
    # Build 65 — Owner-driven NPC sync handlers (Solver 2).
    #
    # `OwnershipRegistry.on_*` returns an `OwnershipChange` when ownership
    # actually changes; `_emit_ownership_change` translates the change to
    # a PHASE_2 broadcast to all peers. Single-phase model (Solver 2 §1.4
    # full two-phase deferred): the old owner is expected to stop emitting
    # state in ≤ 1 RTT after receiving the PHASE_2. Server drops stale
    # state from the old owner via the epoch gate.
    # ========================================================================

    def _emit_ownership_change(self, change: OwnershipChange, now_ms: float) -> None:
        """Translate an OwnershipChange into an NPC_OWNERSHIP_HANDOFF_PHASE_2
        broadcast to every connected peer. All-zero peer_id signals
        'unowned' (release)."""
        new_pid_bytes: bytes = b"\x00" * 16
        if change.new_owner_peer_id is not None:
            new_pid_bytes = self._peer_id_to_bytes(change.new_owner_peer_id)
        payload = NPCOwnershipHandoffPhase2Payload(
            form_id=change.form_id,
            new_epoch=change.new_epoch,
            new_owner_peer_id=new_pid_bytes,
            handed_off_at_ms=int(now_ms) & 0xFFFFFFFFFFFFFFFF,
        )
        for sess in self.state.all_sessions():
            try:
                raw = sess.channel.send_reliable(
                    MessageType.NPC_OWNERSHIP_HANDOFF_PHASE_2, payload, now_ms)
                self._send_raw(sess, raw)
            except ChannelError as e:
                log.debug("ownership PHASE_2 send failed peer=%s: %s",
                          sess.peer_id, e)
        self._counters["ownership_changes"] += 1
        log.debug(
            "ownership: PHASE_2 fid=0x%X %s → %s epoch=%d phase=%s (%s)",
            change.form_id,
            change.old_owner_peer_id or "<none>",
            change.new_owner_peer_id or "<none>",
            change.new_epoch, change.phase, change.reason,
        )

    @staticmethod
    def _peer_id_to_bytes(peer_id: str) -> bytes:
        """Encode peer_id as 16-byte FixedClientId (UTF-8, NUL-padded,
        truncated). Mirrors PeerJoinPayload encoding."""
        b = peer_id.encode("utf-8", errors="replace")[:16]
        return b.ljust(16, b"\x00")

    # Build 65.c.27 — aggro range for RNG ownership candidate selection.
    # A peer is a candidate to OWN (= be attacked by) a raider only if its
    # player is within this distance of the raider. 6000 units ≈ generous
    # FO4 detection radius; both players brawling the same raider group in
    # Concord are well inside it. A genuinely-distant peer is excluded so
    # we never assign a raider to someone whose engine can't engage.
    _AGGRO_RANGE_SQ: float = 6000.0 * 6000.0
    _POS_FRESH_MS: float = 3000.0

    def _in_range_peer_ids(
        self, rx: float, ry: float, rz: float, now_ms: float
    ) -> list[str]:
        """Build 65.c.27 — connected peers whose last-known player position
        is within _AGGRO_RANGE of the raider at (rx,ry,rz). Position from
        POS_STATE (PeerSession.last_pos, fields x/y/z); stale (>_POS_FRESH_MS)
        positions are skipped so a peer who just disconnected/teleported
        isn't picked as an owner who can't actually engage."""
        out: list[str] = []
        for sess in self.state.all_sessions():
            lp = sess.last_pos
            if lp is None:
                continue
            if (now_ms - sess.last_pos_at_ms) > self._POS_FRESH_MS:
                continue
            dx = lp.x - rx
            dy = lp.y - ry
            dz = lp.z - rz
            if (dx * dx + dy * dy + dz * dz) <= self._AGGRO_RANGE_SQ:
                out.append(sess.peer_id)
        return out

    def _handle_npc_observed(
        self, session: PeerSession, payload: NPCObservedPayload, now_ms: float
    ) -> None:
        self._counters["ownership_observed"] += 1

        # Build 65.c.27 — RNG AGGRO ownership election.
        #
        # For a NOT-yet-owned raider, instead of "first observer claims"
        # (which always made the first-engaging peer — usually player_A —
        # own everything → all aggro on A), RNG-assign the owner among
        # peers within aggro range. Owner = the player the raider attacks.
        # Each raider coin-flips independently → ~50/50 split across the
        # group with 2 in-range peers.
        #
        # The candidate list uses PLAYER positions (POS_STATE), NOT the
        # InCombat-gated observation: this breaks the chicken-and-egg where
        # a non-owner peer's puppeted raider never engages → never sends
        # OBSERVED → never gets ownership. By ranging on player pos we can
        # assign B as owner even though only A's engine observed the raider;
        # once B owns it, B stops puppeting → B's vanilla AI engages B.
        if self.ownership.get(payload.form_id) is None:
            # Build 65.c.35 — THREAT ownership: the observer (this peer, whose
            # InCombat-gated engine just reported the NPC) is by definition the
            # highest-threat peer right now, so it claims it. The per-tick
            # `reeval_threat_owners` then refines as positions/engagement
            # evolve. (Legacy RNG path `assign_owner_rng` retained in
            # ownership.py but disabled via THREAT_OWNERSHIP.)
            change = self.ownership.assign_owner_by_threat(
                payload, session.peer_id, now_ms)
            if change is not None:
                self._emit_ownership_change(change, now_ms)
            return

        # Already owned. on_observed refreshes pos/distance AND (threat mode)
        # records this peer's engagement signal into the threat table; the
        # actual handoff is decided centrally in reeval_threat_owners (tick).
        change = self.ownership.on_observed(payload, session.peer_id, now_ms)
        if change is not None:
            self._emit_ownership_change(change, now_ms)

    def _handle_npc_unload(
        self, session: PeerSession, payload: NPCUnloadPayload, now_ms: float
    ) -> None:
        change = self.ownership.on_unload(payload, session.peer_id, now_ms)
        if change is not None:
            self._emit_ownership_change(change, now_ms)

    def _handle_npc_owner_heartbeat(
        self, session: PeerSession, payload: NPCOwnerHeartbeatPayload,
        now_ms: float,
    ) -> None:
        n = len(payload.entries)
        self._counters["ownership_heartbeats_rx"] += 1
        self._counters["ownership_heartbeats_entries"] += n
        # First few + every 60 — diagnostic for "did this peer's heartbeat
        # actually reach us, or are claims dying of timeout in the dark?"
        rx = self._counters["ownership_heartbeats_rx"]
        if rx <= 5 or rx % 60 == 0:
            log.info(
                "ownership: HEARTBEAT rx #%d from %s entries=%d",
                rx, session.peer_id, n,
            )
        self.ownership.on_heartbeat(
            list(payload.entries), session.peer_id, now_ms,
        )

    def _handle_npc_release_ack(
        self, session: PeerSession,
        payload: NPCOwnershipReleaseAckPayload, now_ms: float,
    ) -> None:
        # Phase A simplification: no explicit two-phase dance. ACK is
        # logged for diagnostic but PHASE_2 already broadcast on the
        # original on_observed/on_unload. Future: gate PHASE_2 emit on
        # this ACK arriving within deadline_ms.
        log.debug("ownership: RELEASE_ACK fid=0x%X peer=%s epoch=%d (no-op)",
                  payload.form_id, session.peer_id, payload.old_epoch)

    def _handle_npc_engagement_claim(
        self, session: PeerSession, payload, now_ms: float,
    ) -> None:
        """Build 65.c.23 — Non-owner peer reports its local engine has
        InCombat flag set on a tracked NPC. Server uses this to force
        handoff if the current owner is not actively reporting engagement.

        Flow:
          1. Validate payload shape (defensive).
          2. Delegate decision to `ownership.on_engagement_claim` which
             enforces: known-fid, not-already-owner, post-stickiness, and
             owner-disengaged checks. Returns None to reject, otherwise
             an OwnershipChange with phase='handoff'.
          3. On change → broadcast PHASE_2 to all peers (same path used by
             closeness handoffs, so the receiver-side DLL has no need to
             distinguish reasons).

        Telemetry counter `ownership_engagement_claims_rx` increments on
        every valid claim; `ownership_engagement_handoffs` only when a
        handoff actually fires (= cause for ping-pong concern).
        """
        # Defensive shape check — protocol decoder already returned the
        # right type for known opcodes, but a future migration could
        # break this.
        if not isinstance(payload, NPCEngagementClaimPayload):
            log.debug(
                "engagement-claim: bad payload type %s from %s",
                type(payload).__name__, session.peer_id)
            return
        self._counters["ownership_engagement_claims_rx"] = \
            self._counters.get("ownership_engagement_claims_rx", 0) + 1
        change = self.ownership.on_engagement_claim(
            payload.form_id, session.peer_id, now_ms)
        if change is None:
            # Rejected (already owner / sticky / owner engaged). No-op.
            return
        # Combat-driven handoff fired — broadcast to all peers.
        self._counters["ownership_engagement_handoffs"] = \
            self._counters.get("ownership_engagement_handoffs", 0) + 1
        log.info(
            "ownership: combat-handoff fid=0x%X claimer=%s old_owner=%s "
            "(claims_rx=%d, total_handoffs=%d)",
            payload.form_id, session.peer_id, change.old_owner_peer_id,
            self._counters["ownership_engagement_claims_rx"],
            self._counters["ownership_engagement_handoffs"],
        )
        self._emit_ownership_change(change, now_ms)

    def _handle_npc_state_from_owner(
        self, session: PeerSession, payload: NPCStateFromOwnerPayload,
        now_ms: float,
    ) -> None:
        """Owner sends authoritative state batch; server validates each
        entry's ownership + epoch and relays to non-owners.

        Build 65.c.6 — STATE_FROM_OWNER also refreshes `last_heartbeat_ms`
        for each valid entry. The owner emitting state IS proof of life;
        treating it as such drops false health-gate timeouts when the
        explicit NPC_OWNER_HEARTBEAT cadence (4 Hz) lags behind the state
        cadence (10 Hz). Previously only the explicit heartbeat opcode
        refreshed the gate, so even peers actively replicating state for
        an NPC could see it released for "no heartbeat".
        """
        self._counters["ownership_state_rx"] += 1
        valid: list[NPCOwnerStateEntry] = []
        for entry in payload.entries:
            rec = self.ownership.get(entry.form_id)
            if rec is None:
                continue
            if rec.owner_peer_id != session.peer_id:
                continue  # not your NPC
            if entry.epoch != rec.epoch:
                continue  # stale epoch (post-handoff)
            # Implicit heartbeat — owner is actively replicating, so the
            # health-gate clock resets even without an explicit
            # NPC_OWNER_HEARTBEAT frame.
            rec.last_heartbeat_ms = now_ms
            # Build 65.c.23 — track combat engagement window. If the
            # owner is reporting anim_state >= 3 (= bit 0x4000 InCombat
            # set on the owner-side Actor at record_owned_state-capture
            # time, per fw_native/src/hooks/npc_ai_suppress.cpp:454), the
            # owner IS the real fighter. Note it so a competing peer's
            # NPC_ENGAGEMENT_CLAIM does NOT trigger combat-driven handoff.
            self.ownership.note_owner_engagement(
                entry.form_id, session.peer_id,
                entry.anim_state, now_ms)
            valid.append(entry)
        if not valid:
            return
        relay = NPCStateFromOwnerPayload(entries=tuple(valid))
        for sess in self.state.all_sessions():
            if sess.peer_id == session.peer_id:
                continue  # don't echo to sender
            try:
                raw = sess.channel.send_unreliable(
                    MessageType.NPC_STATE_FROM_OWNER, relay)
                self._send_raw(sess, raw)
            except ChannelError as e:
                log.debug("state-from-owner relay failed peer=%s: %s",
                          sess.peer_id, e)
        self._counters["ownership_state_relayed"] += len(valid)

    def _handle_npc_damage_claim(
        self, session: PeerSession, payload, now_ms: float,
    ) -> None:
        """c.39b — a peer reports damage it dealt to an NPC. Feed the threat
        table (damage is the dominant ownership/aggro signal). The per-tick
        `reeval_threat_owners` then picks up the new threat and hands off so the
        NPC turns to fight whoever is hitting it hardest."""
        if not isinstance(payload, NPCDamageClaimPayload):
            return
        self._counters["npc_damage_claims_rx"] += 1
        self.ownership.record_damage(
            payload.form_id, session.peer_id, float(payload.amount), now_ms)

    def _handle_npc_pose_from_owner(
        self, session: PeerSession, payload, now_ms: float,
    ) -> None:
        """c.37.0 — owner sends a per-bone pose snapshot for ONE owned NPC.

        Validate the sender owns that fid, then fan the SAME frame out to
        every non-owner (unreliable, best-effort visual). No epoch gate:
        pose is cosmetic, a few stale frames during handoff are invisible
        under the new owner's stream taking over. Mirrors the existing
        owner-driven relay shape (`_handle_npc_state_from_owner`)."""
        if not isinstance(payload, NPCPoseFromOwnerPayload):
            return
        rec = self.ownership.get(payload.form_id)
        if rec is None or rec.owner_peer_id != session.peer_id:
            return  # not your NPC (or unknown owner) — drop
        self._counters["npc_pose_rx"] += 1
        for sess in self.state.all_sessions():
            if sess.peer_id == session.peer_id:
                continue  # don't echo to sender
            try:
                raw = sess.channel.send_unreliable(
                    MessageType.NPC_POSE_FROM_OWNER, payload)
                self._send_raw(sess, raw)
            except ChannelError as e:
                log.debug("npc-pose relay failed peer=%s: %s",
                          sess.peer_id, e)
        self._counters["npc_pose_relayed"] += 1

    def _handle_npc_crouch_from_owner(
        self, session: PeerSession, payload, now_ms: float,
    ) -> None:
        """NPC crouch — owner sends a COM/Pelvis translation snapshot for ONE
        owned NPC (the vertical drop the rotation pose can't carry).

        Validate the sender owns that fid, then fan the SAME frame out to
        every non-owner (unreliable, best-effort visual). No epoch gate:
        crouch translation is cosmetic, like the rotation pose. Exact clone of
        `_handle_npc_pose_from_owner`."""
        if not isinstance(payload, NPCCrouchFromOwnerPayload):
            return
        rec = self.ownership.get(payload.form_id)
        if rec is None or rec.owner_peer_id != session.peer_id:
            return  # not your NPC (or unknown owner) — drop
        self._counters["npc_crouch_rx"] += 1
        for sess in self.state.all_sessions():
            if sess.peer_id == session.peer_id:
                continue  # don't echo to sender
            try:
                raw = sess.channel.send_unreliable(
                    MessageType.NPC_CROUCH_FROM_OWNER, payload)
                self._send_raw(sess, raw)
            except ChannelError as e:
                log.debug("npc-crouch relay failed peer=%s: %s",
                          sess.peer_id, e)
        self._counters["npc_crouch_relayed"] += 1

    def _handle_npc_fire_from_owner(
        self, session: PeerSession, payload: NPCFireFromOwnerPayload,
        now_ms: float,
    ) -> None:
        rec = self.ownership.get(payload.form_id)
        if rec is None or rec.owner_peer_id != session.peer_id:
            return
        for sess in self.state.all_sessions():
            if sess.peer_id == session.peer_id:
                continue
            try:
                raw = sess.channel.send_unreliable(
                    MessageType.NPC_FIRE_FROM_OWNER, payload)
                self._send_raw(sess, raw)
            except ChannelError:
                pass

    def _handle_npc_death_from_owner(
        self, session: PeerSession, payload: NPCDeathFromOwnerPayload,
        now_ms: float,
    ) -> None:
        rec = self.ownership.get(payload.form_id)
        # c.49 — BIDIRECTIONAL death-sync. Accept the death from ANY tracked
        # sender (owner OR non-owner), not just the owner. Fix: a NON-owner client
        # deals the lethal blow (e.g. B shoots a mosquito OWNED by A) → under the
        # old owner-only gate B's death was dropped → A's copy stayed ALIVE
        # ("killed on B, still alive on A"). The relay below already targets
        # all-except-sender, so A (the owner) receives it and corpses its real
        # copy. (rec is None = untracked entity the server doesn't know → can't
        # relay, drop.)
        if rec is None:
            return
        # Releases ownership on death — broadcast PHASE_2 + relay the death
        # packet to the other client(s).
        for sess in self.state.all_sessions():
            if sess.peer_id == session.peer_id:
                continue
            try:
                raw = sess.channel.send_reliable(
                    MessageType.NPC_DEATH_FROM_OWNER, payload, now_ms)
                self._send_raw(sess, raw)
            except ChannelError:
                pass
        # Forge an unload-style release.
        change = self.ownership.on_unload(
            NPCUnloadPayload(
                form_id=payload.form_id, epoch=rec.epoch,
                last_pos_x=payload.pos_x, last_pos_y=payload.pos_y,
                last_pos_z=payload.pos_z,
                last_yaw=0.0, last_anim_state=0, last_hp_pct=0,
            ),
            session.peer_id, now_ms,
        )
        if change is not None:
            self._emit_ownership_change(change, now_ms)

    def _handle_npc_damage_from_owner(
        self, session: PeerSession, payload: NPCDamageFromOwnerPayload,
        now_ms: float,
    ) -> None:
        rec = self.ownership.get(payload.form_id)
        if rec is None or rec.owner_peer_id != session.peer_id:
            return
        for sess in self.state.all_sessions():
            if sess.peer_id == session.peer_id:
                continue
            try:
                raw = sess.channel.send_unreliable(
                    MessageType.NPC_DAMAGE_FROM_OWNER, payload)
                self._send_raw(sess, raw)
            except ChannelError:
                pass

    def _send_raw(self, sess: PeerSession, raw: bytes) -> None:
        """Small helper for ownership handlers; mirrors the inline send
        pattern used by container/door/lock/equip handlers."""
        if self.transport is None or not raw:
            return
        try:
            self.transport.sendto(raw, sess.addr)
            self._counters["tx_frames"] += 1
        except OSError as e:
            log.debug("sendto %s failed: %s", sess.addr, e)

    def _handle_lock_op(self, session: PeerSession, payload, now_ms: float) -> None:
        """B6.3 v0.5.3 — lock state change broadcast + persistence.

        Sender hooks the engine's ForceUnlock (sub_140563320) and
        ForceLock (sub_140563360); both fire on real state transitions
        (lockpick success, terminal hack, key unlock, AI/quest, perk
        auto-unlock, savefile load).

        Server tracks last-known state per (base_id, cell_id) so new
        peers entering the cell get the right state replayed. Dedup:
        if the incoming state matches what we already have, skip the
        broadcast — saves traffic from the savefile-load fire on
        client (which fires for every locked REFR in the loaded cell
        regardless of whether it actually changed).
        """
        if not isinstance(payload, LockOpPayload):
            return
        if payload.lock_form_id == 0 or payload.lock_base_id == 0:
            log.debug("lock_op from %s: zero identity (form=0x%X base=0x%X) — drop",
                      session.peer_id, payload.lock_form_id, payload.lock_base_id)
            return

        new_locked = bool(payload.locked)
        key = (payload.lock_base_id, payload.lock_cell_id)
        prev = self.state.lock_state.get(key)
        if prev is not None and prev.locked == new_locked:
            log.debug("lock_op no-op (state unchanged) form=0x%X by %s",
                      payload.lock_form_id, session.peer_id)
            return

        self.state.lock_state[key] = LockWorldState(
            base_id=payload.lock_base_id,
            cell_id=payload.lock_cell_id,
            form_id=payload.lock_form_id,
            locked=new_locked,
            timestamp_ms=payload.timestamp_ms,
        )

        broadcast = LockBroadcastPayload(
            peer_id=session.peer_id,
            lock_form_id=payload.lock_form_id,
            lock_base_id=payload.lock_base_id,
            lock_cell_id=payload.lock_cell_id,
            locked=payload.locked,
            timestamp_ms=payload.timestamp_ms,
        )
        for other in self.state.other_sessions(session.addr):
            raw = other.channel.send_reliable(
                MessageType.LOCK_BCAST, broadcast, now_ms)
            self._send(other.addr, raw)

        log.debug("lock op form=0x%X base=0x%X cell=0x%X locked=%d by %s",
                  payload.lock_form_id, payload.lock_base_id,
                  payload.lock_cell_id, payload.locked, session.peer_id)

    def _handle_equip_op(self, session: PeerSession, payload, now_ms: float) -> None:
        """M9 wedge 1 — equipment-event broadcast.

        Pure fan-out, no validation. Sender hooked the engine's
        ActorEquipManager::EquipObject + UnequipObject and forwards each
        fire the local player triggered. Server just attributes (peer_id)
        and relays to all other peers as EQUIP_BCAST.

        No state tracking server-side: equip events are CHANGE notifications,
        not state — peers compose their own view of "what is peer X
        currently wearing" by accumulating equip/unequip diffs since
        connect. Initial state is implicit from the B8 force-equip-cycle
        (every client cycles its Vault Suit on game start, broadcasting
        an UNEQUIP+EQUIP pair, which gives joining peers a baseline).

        Wedge 1 is observe-only on receivers — no apply, just log RX.
        Wedge 2 lands the visual swap on the M8P3 ghost body.
        """
        if not isinstance(payload, EquipOpPayload):
            return
        if payload.item_form_id == 0:
            log.debug("equip_op from %s: zero item_form_id — drop",
                      session.peer_id)
            return

        # M9.w4: forward the OMOD list AND the v8 witness NIF descriptors
        # verbatim. Server doesn't interpret either tail — pure relay.
        # Receiver uses OMOD list for diagnostics + future engine apply,
        # NIF descriptors for the witness-pattern mod attach.
        broadcast = EquipBroadcastPayload(
            peer_id=session.peer_id,
            item_form_id=payload.item_form_id,
            kind=payload.kind,
            slot_form_id=payload.slot_form_id,
            count=payload.count,
            timestamp_ms=payload.timestamp_ms,
            effective_priority=payload.effective_priority,  # v10
            mods=payload.mods,
            nif_descs=payload.nif_descs,
        )
        for other in self.state.other_sessions(session.addr):
            raw = other.channel.send_reliable(
                MessageType.EQUIP_BCAST, broadcast, now_ms)
            self._send(other.addr, raw)

        kind_str = "EQUIP" if payload.kind == EquipOpKind.EQUIP else (
            "UNEQUIP" if payload.kind == EquipOpKind.UNEQUIP else f"?{payload.kind}?")
        log.debug(
            "equip_op %s item=0x%X slot=0x%X count=%d mods=%d nifs=%d by %s",
            kind_str, payload.item_form_id, payload.slot_form_id,
            payload.count, len(payload.mods), len(payload.nif_descs),
            session.peer_id)

    def _handle_mesh_blob_op(self, session: PeerSession, payload, now_ms: float) -> None:
        """M9 wedge 4 v9 — chunked mesh blob fan-out.

        Pure relay, identical pattern to EQUIP_OP. The server doesn't
        reassemble the blob (that costs RAM × peers and serves no
        validation purpose for a PoC) — each chunk is forwarded to other
        peers as MESH_BLOB_BCAST with the originating peer_id attached.

        Receivers buffer chunks per (peer_id, equip_seq) and decode once
        all arrive. Per-chunk reliable delivery means duplicates +
        retransmits are handled by the channel layer; receiver de-dupes
        on its end via chunk_received bitmap.

        Performance note: a typical modded weapon ships ~80 KB across
        ~60 chunks. With N peers we re-emit N*60 frames per equip event.
        At 2 peers and one equip-cycle this is ~240 KB total — well within
        a tick budget. If multi-peer sessions get heavier we'll batch
        multiple chunks per UDP datagram (currently 1:1) and/or ship a
        compressed blob via a single dedicated stream. Out of scope for
        v0.4.0.
        """
        if not isinstance(payload, MeshBlobChunkPayload):
            return
        # Defensive: cap chunk_data and total_blob_size before re-emitting.
        # Receiver already enforces these caps; server enforces them too so
        # malformed senders don't waste fan-out bandwidth.
        if payload.total_blob_size == 0:
            log.debug("mesh_blob_op from %s: zero total_blob_size — drop",
                      session.peer_id)
            return
        if payload.total_chunks == 0:
            log.debug("mesh_blob_op from %s: zero total_chunks — drop",
                      session.peer_id)
            return

        broadcast = MeshBlobChunkBroadcastPayload(
            peer_id=session.peer_id,
            equip_seq=payload.equip_seq,
            total_blob_size=payload.total_blob_size,
            chunk_index=payload.chunk_index,
            total_chunks=payload.total_chunks,
            chunk_data=payload.chunk_data,
        )
        for other in self.state.other_sessions(session.addr):
            raw = other.channel.send_reliable(
                MessageType.MESH_BLOB_BCAST, broadcast, now_ms)
            self._send(other.addr, raw)

        # Per-chunk logging would be too chatty. Log only the first and
        # last chunks of each blob.
        if payload.chunk_index == 0 or payload.chunk_index + 1 == payload.total_chunks:
            log.debug(
                "mesh_blob_op equip_seq=%u ci=%u/%u blob=%dB by %s",
                payload.equip_seq,
                payload.chunk_index, payload.total_chunks,
                payload.total_blob_size, session.peer_id)

    def _handle_chat(self, session: PeerSession, payload, now_ms: float) -> None:
        if not isinstance(payload, ChatPayload):
            return
        # Broadcast to all peers EXCEPT sender (reliable)
        log.info("[chat] <%s> %s", session.peer_id, payload.text[:80])
        for other in self.state.other_sessions(session.addr):
            raw = other.channel.send_reliable(MessageType.CHAT, payload, now_ms)
            self._send(other.addr, raw)

    # ----- B6.5w2: NPC state broadcast (v13)

    def broadcast_npc_states(
        self,
        npc_brain: NPCBrain,
        raider_brain: Optional[RaiderBrain],
        now_ms: float,
    ) -> None:
        """Emit NPC_STATE_BCAST to every connected peer.

        Called by ``_periodic_npc_brain_tick`` right after the brain
        advances. Unreliable channel — drops are tolerable since the
        next tick (~100 ms later at default 10 Hz) resends fresh state.

        B6.7 (2026-05-16) — distance-based cell-aware filtering: each
        peer receives state ONLY for NPCs within
        ``NPC_BROADCAST_RANGE_FT`` of the peer's last known position.
        Peers without a known position (just joined, or in main menu)
        receive everything (initial sync). See module-level constant
        comment for rationale.

        Chunks across frames if NPC count exceeds
        ``MAX_NPC_STATES_PER_FRAME`` (26 at MTU 1400).

        B6.6w0 (2026-05-12) — accepts an optional RaiderBrain. For
        NPCs registered there, the per-tick combat outputs
        (aim_target_xyz, fire_this_tick, anim_state combat overrides,
        combat_target_form_id) are folded into the broadcast entry.
        Fire is encoded in ``weapon_state`` bit 3 (bits 0..2 already
        reserved for sheath state; bits 3..7 reserved → bit 3 = fire
        this tick).
        """
        sessions = self.state.all_sessions()
        if not sessions:
            return
        npcs = npc_brain.all_npcs()
        if not npcs:
            return

        ts_ms = int(now_ms)
        max_per = MAX_NPC_STATES_PER_FRAME

        # Per-peer broadcast. The `combat_target_form_id` substitution
        # is PER-PEER (each client's own `0x14` for the chosen target
        # peer, 0 otherwise); the aim point is world-frame and shared
        # across peers; the fire bit (weapon_state bit 3) is shared.
        #
        # `flags` byte:
        #   bit 0 = visible (always 1 for now)
        #   bit 1 = is_raider_tracked (1 iff registered in raider_brain)
        #           — drives client-side `movement_override` independently
        #           of `combat_target_form_id` so the freeze stays on
        #           even for peers that are NOT the chosen aggro target.
        #           Without this, the freeze flickers off on peer B every
        #           time server picks A as the aggro target.
        n_aggro_active = 0
        n_fire_bits_set = 0
        n_filtered_out_of_range = 0  # B6.7 diagnostic
        n_emitted_entries = 0
        for sess in sessions:
            peer_id = sess.peer_id
            # B6.7 cell-aware filter — capture peer's known position. If
            # the peer hasn't yet sent a POS_STATE (just joined, main
            # menu, etc.), peer_pos is None and we send everything as
            # an initial-sync fallback (matches pre-B6.7 behavior for
            # that connection state).
            peer_pos: Optional[tuple[float, float, float]] = None
            if sess.last_pos is not None:
                peer_pos = (sess.last_pos.x, sess.last_pos.y,
                            sess.last_pos.z)
            entries: list[NPCStateEntry] = []
            for r in npcs:
                # B6.7 — drop this NPC for this peer if too far away.
                # NPC's current position is r.pos_x/y/z (server-tracked
                # authoritative position). Skips the whole entry build
                # so even the visible/idle bit doesn't reach the peer
                # for far-away NPCs.
                if peer_pos is not None:
                    dx = r.pos_x - peer_pos[0]
                    dy = r.pos_y - peer_pos[1]
                    dz = r.pos_z - peer_pos[2]
                    d2 = dx * dx + dy * dy + dz * dz
                    if d2 > NPC_BROADCAST_RANGE_SQ:
                        n_filtered_out_of_range += 1
                        continue

                raider = (raider_brain.raider_for(r.spec.form_id)
                          if raider_brain is not None else None)
                flags = 0x01    # bit 0 = visible
                if raider is not None:
                    proj = raider_brain.project_for_peer(
                        r.spec.form_id, peer_id,
                        viewer_ghost_form_id=sess.ghost_form_id)
                    aim_x = proj["aim_target_x"]
                    aim_y = proj["aim_target_y"]
                    aim_z = proj["aim_target_z"]
                    fire_bit = 0x08 if proj["fire_this_tick"] else 0x00
                    combat_target = proj["combat_target_form_id"]
                    flags |= 0x02    # bit 1 = is_raider_tracked
                else:
                    aim_x = aim_y = aim_z = 0.0
                    fire_bit = 0x00
                    combat_target = r.combat_target_form_id

                n_emitted_entries += 1
                entries.append(NPCStateEntry(
                    form_id=r.spec.form_id,
                    base_id=r.spec.base_id,
                    cell_id=r.spec.cell_id,
                    pos_x=r.pos_x, pos_y=r.pos_y, pos_z=r.pos_z,
                    yaw=r.yaw, pitch=r.pitch,
                    target_id=r.target_id,
                    timestamp_ms=ts_ms,
                    anim_state=r.anim_state,
                    aggro_state=r.aggro_state,
                    hp_pct=r.hp_pct,
                    target_kind=r.target_kind,
                    flags=flags,
                    package_form_id=r.package_form_id,
                    combat_target_form_id=combat_target,
                    aim_x=aim_x, aim_y=aim_y, aim_z=aim_z,
                    weapon_state=fire_bit,
                ))

            for off in range(0, len(entries), max_per):
                chunk = entries[off : off + max_per]
                payload = NPCStateBroadcastPayload(entries=tuple(chunk))
                raw = sess.channel.send_unreliable(
                    MessageType.NPC_STATE_BCAST, payload)
                self._send(sess.addr, raw)

        # Per-tick aggregate diagnostic (the per-peer loop above runs
        # per-session, so we tally once here from the brain side).
        if raider_brain is not None:
            for raider in raider_brain.all_raiders():
                if raider.aggro_peer_id is not None:
                    n_aggro_active += 1
                if raider.fire_this_tick:
                    n_fire_bits_set += 1
            if n_aggro_active > 0 or n_fire_bits_set > 0:
                log.debug(
                    "broadcast_npc_states: %d peer(s); %d raiders in "
                    "active aggro, fire bits set on %d; "
                    "emitted=%d filtered_oor=%d (range=%.0fft)",
                    len(sessions), n_aggro_active, n_fire_bits_set,
                    n_emitted_entries, n_filtered_out_of_range,
                    NPC_BROADCAST_RANGE_FT,
                )

    # ----- B6.6w1: NPC fire event broadcast (v15)

    def broadcast_npc_fires(
        self,
        raider_brain: Optional[RaiderBrain],
        now_ms: float,
    ) -> None:
        """Emit one NPC_FIRE event per raider that fired this tick.

        Called by ``_periodic_npc_brain_tick`` right after the brain
        advances and AFTER broadcast_npc_states (both read the same
        fire_this_tick state which the next tick will reset).

        B6.7 (2026-05-16) — per-peer cell-aware filtering: an NPC_FIRE
        event is sent to a peer ONLY if the firing raider is within
        ``NPC_BROADCAST_RANGE_FT`` of the peer's last known position.
        Same rationale as broadcast_npc_states: a Sanctuary peer must
        not receive fire events for Concord raiders, because the client
        would then try to dispatch the fire on a raider whose REFR is
        in an unloaded cell (a known crash precondition per Agent F8
        dossier and Build 31.6 live test).

        Unreliable channel — a dropped event means a missed shot on
        one client (visual desync of one bullet, no game-state desync
        because damage flow is separately authoritative).
        """
        if raider_brain is None:
            return
        sessions = self.state.all_sessions()
        if not sessions:
            return
        # Pre-compute peer positions once per tick.
        peer_positions: dict[str, Optional[tuple[float, float, float]]] = {}
        for sess in sessions:
            if sess.last_pos is not None:
                peer_positions[sess.peer_id] = (
                    sess.last_pos.x, sess.last_pos.y, sess.last_pos.z)
            else:
                peer_positions[sess.peer_id] = None  # initial-sync fallback

        n_emitted = 0
        n_filtered_oor = 0
        n_skipped_no_peer_in_range = 0

        # Build 55e (2026-05-23) — cross-peer-range-aware target picker.
        #
        # Conceptual model: the raider's perception cone exists only on
        # client(s) that have it physically loaded. If ONLY peer A is in
        # Concord with the raider, only A's vanilla AI engages — sending
        # target_kind=GHOST to peer B in Sanctuary is meaningless (B's
        # ghost-of-A is at A's pos = in Concord, but B's local raider
        # copy isn't in B's loaded cell so puppet-fire goes nowhere
        # visually).
        #
        # Per raider FIRE event:
        #   0 peers in range: skip (no client needs this event).
        #   1 peer in range: only that peer receives target_kind=LOCAL
        #     (vanilla AI on their machine handles fire). No GHOST sent.
        #   2+ peers in range: seeded-RNG pick ONE target peer per 5-sec
        #     window. Picked peer receives LOCAL, others GHOST (puppet).
        #     Both clients agree on the picked peer (same seed → same
        #     result). Window-based picking gives visible aggro
        #     alternation cross-client without per-shot chaos.
        #
        # Cross-peer puppet-fire is reserved exclusively for the
        # multi-peer co-location case.
        RAIDER_PERCEPTION_RANGE_FT = 2500.0  # ~ same as weapon_range_ft
        RAIDER_PERCEPTION_RANGE_SQ = (
            RAIDER_PERCEPTION_RANGE_FT * RAIDER_PERCEPTION_RANGE_FT)
        AGGRO_WINDOW_MS = 5000  # 5 sec target commitment per window

        for raider in raider_brain.all_raiders():
            if not raider.fire_this_tick:
                continue
            raider_fid = raider.ai.spec.form_id
            raider_pos = (raider.ai.pos_x, raider.ai.pos_y, raider.ai.pos_z)
            target_fid = raider.ai.combat_target_form_id

            # Build set of peers within raider's perception range.
            in_range_peers = []
            for sess in sessions:
                ppos = peer_positions.get(sess.peer_id)
                if ppos is None:
                    continue
                dx = raider_pos[0] - ppos[0]
                dy = raider_pos[1] - ppos[1]
                dz = raider_pos[2] - ppos[2]
                d2 = dx * dx + dy * dy + dz * dz
                if d2 <= RAIDER_PERCEPTION_RANGE_SQ:
                    in_range_peers.append(sess)
                elif d2 > NPC_BROADCAST_RANGE_SQ:
                    # Way out of even broadcast range — track for stats.
                    n_filtered_oor += 1

            if not in_range_peers:
                n_skipped_no_peer_in_range += 1
                continue

            # Pick target_peer: single peer or seeded RNG for multi-peer.
            if len(in_range_peers) == 1:
                target_peer = in_range_peers[0]
            else:
                # Multi-peer co-located: deterministic window-based pick.
                # Sort by peer_id for stability across server lifetimes.
                window_idx = int(now_ms // AGGRO_WINDOW_MS)
                in_range_sorted = sorted(in_range_peers,
                                         key=lambda s: s.peer_id)
                pick_idx = hash(
                    (raider_fid, window_idx)) % len(in_range_sorted)
                target_peer = in_range_sorted[pick_idx]

            # Emit NPC_FIRE only to in_range peers, with target_kind
            # reflecting whether they are the target.
            for sess in in_range_peers:
                target_kind = (NPCFirePayload.TARGET_LOCAL
                               if sess.peer_id == target_peer.peer_id
                               else NPCFirePayload.TARGET_GHOST)
                payload = NPCFirePayload(
                    raider_form_id=raider_fid,
                    target_form_id=target_fid,
                    flags=0,
                    target_kind=target_kind,
                )
                raw = sess.channel.send_unreliable(
                    MessageType.NPC_FIRE, payload)
                self._send(sess.addr, raw)
            n_emitted += 1
        if n_emitted > 0 or n_filtered_oor > 0 or n_skipped_no_peer_in_range > 0:
            log.debug(
                "broadcast_npc_fires: %d fire event(s) emitted; %d "
                "filtered_oor (peer-sends, range=%.0fft); %d skipped "
                "(no peer in perception range %.0fft); over %d peer(s)",
                n_emitted, n_filtered_oor, NPC_BROADCAST_RANGE_FT,
                n_skipped_no_peer_in_range, RAIDER_PERCEPTION_RANGE_FT,
                len(sessions),
            )

    def broadcast_npc_perception_triggers(
        self,
        triggers: list[tuple[int, str]],
        now_ms: float,
    ) -> None:
        """Build 62 — emit NPC_PERCEPTION_TRIGGER for each (npc_fid, peer_id)
        the brain's proximity-sphere check found this tick.

        Each event tells ALL peers' clients: "if you have npc_fid loaded
        locally, call sub_140CCF810(npc, target_for_peer_id) so engine
        allocates combat tier naturally."

        Sent RELIABLE (channel.send_reliable) so the perception event
        doesn't drop — debounce on server side prevents flood, but a single
        drop would leave the raider unaware.

        Each peer's CLIENT does the local lookup:
          - lookup_by_form_id(npc_fid): may return null if npc not in
            local cell → drop silently
          - target = self_ghost if peer_id == local_peer_id ELSE
                     ghost_for_peer(peer_id)
        Then trigger_npc_perception(observer, target).
        """
        if not triggers:
            return
        sessions = self.state.all_sessions()
        if not sessions:
            return

        for npc_fid, peer_id in triggers:
            # Build 62 — FNV-1a 32-bit hash (MUST match client-side
            # fw_native main_thread_dispatch.cpp::fnv1a32). Python's
            # built-in hash() is NOT stable across runs / processes —
            # using FNV-1a guarantees the same peer_id string hashes
            # to the same 32-bit value on server + every client.
            h: int = 2166136261
            for b in peer_id.encode("utf-8"):
                h = (h ^ b) * 16777619 & 0xFFFFFFFF
            payload = NPCPerceptionTriggerPayload(
                npc_fid=npc_fid,
                peer_id=h,
            )
            for sess in sessions:
                raw = sess.channel.send_reliable(
                    MessageType.NPC_PERCEPTION_TRIGGER, payload, now_ms)
                self._send(sess.addr, raw)

        log.info(
            "broadcast_npc_perception_triggers: %d trigger(s) emitted to %d peer(s)",
            len(triggers), len(sessions),
        )

    # ----- periodic tasks

    def tick(self, now_ms: float) -> None:
        """Called at tick_rate_hz. Drives retransmits, acks, timeouts."""
        # Per-session retransmit + ACK flush
        for session in self.state.all_sessions():
            try:
                retrans, ack = session.channel.tick(now_ms)
            except ChannelError:
                log.warning("peer %s channel dead (max retransmits); kicking",
                            session.peer_id)
                self._remove_and_notify(session, reason=1, now_ms=now_ms)
                continue
            for r in retrans:
                self._send(session.addr, r)
            if ack is not None:
                self._send(session.addr, ack)

        # Timeout detection
        stale = self.state.expire_stale(now_ms)
        for s in stale:
            log.info("peer %s timed out", s.peer_id)
            # Build 65 — release every NPC owned by the timed-out peer.
            for change in self.ownership.on_peer_disconnect(s.peer_id, now_ms):
                self._emit_ownership_change(change, now_ms)
            # Already removed from sessions; notify others
            leave = PeerLeavePayload(peer_id=s.peer_id, reason=0)
            for other in self.state.all_sessions():
                raw = other.channel.send_reliable(MessageType.PEER_LEAVE, leave, now_ms)
                self._send(other.addr, raw)

        # Build 65 — ownership health gate. The registry releases any
        # owner whose heartbeat is older than HEARTBEAT_TIMEOUT_MS;
        # changes are broadcast as PHASE_2 with all-zero new_owner_id.
        for change in self.ownership.periodic_tick(now_ms):
            self._emit_ownership_change(change, now_ms)

        # Build 65.c.28 — PROVISIONAL RE-ROLL (fixes c.27 timing flaw).
        #
        # c.27 RNG assigned ownership at first-observation. But the first
        # observer is whoever's engine engaged first (usually player_A,
        # who approached first); at that instant the OTHER player may still
        # be out of aggro range → candidates=['player_A'] → ALL raiders go
        # to A → all aggro on A, ghost_B ignored 100% (confirmed c.27 log).
        #
        # Fix: a raider assigned with <2 in-range candidates is PROVISIONAL.
        # Each tick we recompute in-range candidates FROM CURRENT PLAYER
        # POSITIONS (not InCombat-gated observations — a puppeted non-owner
        # never sends OBSERVED). When a provisional raider now has 2+ peers
        # in range (the second player has arrived), re-roll once among them
        # and mark FINAL (sticky thereafter → honours "static" intent). Net:
        # both players brawling the same group get ~50/50 of it within one
        # tick of the second player closing distance.
        player_positions = {
            sess.peer_id: (sess.last_pos.x, sess.last_pos.y, sess.last_pos.z)
            for sess in self.state.all_sessions()
            if sess.last_pos is not None
            and (now_ms - sess.last_pos_at_ms) <= 3000.0
        }
        # Build 65.c.35 — THREAT re-evaluation (replaces the c.28 RNG re-roll).
        # Every tick, recompute each NPC's owner from per-peer threat
        # (engagement recency + proximity, damage TODO) and hand off to the
        # decisively-highest-threat peer (hysteresis inside). This is where
        # ownership actually moves in threat mode → the NPC follows whoever is
        # really fighting it (fixes the RNG "wrong owner": A observed, dice
        # gave it to B). Runs with ≥1 player so an owner that disengages/leaves
        # can hand off to the remaining fighter. (Legacy `reroll_provisional_
        # owners` retained in ownership.py but unused under THREAT_OWNERSHIP.)
        if player_positions:
            for change in self.ownership.reeval_threat_owners(
                    player_positions, self._AGGRO_RANGE_SQ, now_ms):
                self._emit_ownership_change(change, now_ms)

    # ----- helpers

    def _remove_and_notify(self, session: PeerSession, *, reason: int, now_ms: float) -> None:
        # Build 65 — release every NPC owned by the departing peer. The
        # election triggered by the next observer's NPC_OBSERVED report
        # will pick a new owner; until then the NPCs are unowned and
        # non-owners freeze them (per npc_ai_suppress predicate).
        ownership_changes = self.ownership.on_peer_disconnect(
            session.peer_id, now_ms,
        )
        self.state.remove(session.peer_id)
        for change in ownership_changes:
            self._emit_ownership_change(change, now_ms)
        leave = PeerLeavePayload(peer_id=session.peer_id, reason=reason)
        for other in self.state.all_sessions():
            raw = other.channel.send_reliable(MessageType.PEER_LEAVE, leave, now_ms)
            self._send(other.addr, raw)

    def _send(self, addr: tuple[str, int], raw: bytes) -> None:
        if self.transport is None:
            return
        self.transport.sendto(raw, addr)
        self._counters["tx_frames"] += 1

    def stats(self) -> dict[str, int]:
        return dict(self._counters)


# ---------------------------------------------------------------- async loop

async def _periodic_tick(protocol: ServerProtocol, rate_hz: int) -> None:
    interval = 1.0 / rate_hz
    while True:
        await asyncio.sleep(interval)
        now_ms = _now_ms()
        protocol.tick(now_ms)


async def _periodic_npc_brain_tick(
    brain: NPCBrain,
    raider_brain: Optional[RaiderBrain],
    protocol: ServerProtocol,
    rate_hz: int,
) -> None:
    """B6.5w1+w2 + B6.6w0 — drive the NPC + raider brains and broadcast.

    Each tick:
      1. Snapshot live peer positions from `ServerState.all_sessions()`.
      2. Advance `NPCBrain` (waypoint patrollers — Dogmeat/Codsworth).
      3. Advance `RaiderBrain` (combat-aware Concord raiders) with the
         peer snapshot. The raider brain mutates the SAME `NPCRuntime`
         instances `NPCBrain` owns, adding combat fields
         (`combat_target_form_id`, `anim_state` overrides, aggro_state)
         and stashing per-tick combat outputs (aim_target_xyz,
         fire_this_tick) on its own `RaiderRuntime` wrappers.
      4. Broadcast NPC_STATE_BCAST. The broadcaster reads
         `RaiderRuntime` fields where available and folds them into
         each peer's entry.

    Logs at ~1 Hz so the operator sees liveness without drowning the
    log. Combat events (aggro change, fire) are logged in detail when
    they happen (rate-limited downstream).
    """
    interval = 1.0 / rate_hz
    last_ms = _now_ms()
    log_every = max(1, rate_hz)  # ~once per second
    tick_idx = 0
    # Track last-seen aggro target per raider so we log only on change.
    last_aggro: dict[int, Optional[str]] = {}
    while True:
        await asyncio.sleep(interval)
        now_ms = _now_ms()
        dt_s = (now_ms - last_ms) / 1000.0
        last_ms = now_ms

        # 1. Peer snapshot.
        peers_snapshot: dict[str, tuple[float, float, float, bool]] = {}
        for sess in protocol.state.all_sessions():
            if sess.last_pos is None:
                continue
            peers_snapshot[sess.peer_id] = (
                sess.last_pos.x, sess.last_pos.y, sess.last_pos.z,
                True,
            )

        # 2. Waypoint brain (idle patrollers). STAYS — these are Codsworth /
        # Dogmeat / settlers driven by simple waypoint logic, no combat
        # state, no contention with engine AI.
        n_npc = brain.tick(now_ms, dt_s)

        # 3. Combat brain (Concord raiders). Build 65.c.13 — Solver 2 Fix B.
        # raider_brain.tick was the server-side AI authority: it picked
        # aggro target, aim coord, fire cadence, and pushed all that via
        # NPC_STATE_BCAST + NPC_FIRE to every peer.
        #
        # Under owner-driven sync, that authority lives on the OWNER
        # CLIENT — whichever peer the OwnershipRegistry elected for each
        # raider. The owner runs vanilla engine AI (proper combat state,
        # local pos, full pathfinding) and emits authoritative state via
        # NPC_STATE_FROM_OWNER + NPC_FIRE_FROM_OWNER, which the server
        # only relays. The legacy raider_brain produced symptoms like
        # "raider stops firing when peer goes off-cell" (cached pos goes
        # stale + aggro switches to unreachable target) — the owner
        # client doesn't suffer that because it never had a server-cached
        # pos to begin with.
        #
        # Silenced:
        #   - raider_brain.tick() — no aggro / aim / fire decision
        #   - broadcast_npc_fires() — no NPC_FIRE wire frames for raiders
        #   - broadcast_npc_states() called with raider_brain=None below
        #     so raider state isn't folded into NPC_STATE_BCAST
        #   - compute_perception_triggers — depends on raider_brain state
        #
        # Kept for future use (e.g. resurrection of legacy path if owner-
        # driven proves insufficient): the raider_brain instance itself,
        # its config, its discover/register hooks. They're idle but loaded.
        n_raider = 0
        # Build 65.c.13 — pass raider_brain=None so the broadcast skips
        # the raider state-folding code path (combat target / aim / fire
        # bit) and only emits waypoint NPC state. Raider state on each
        # client comes from NPC_STATE_FROM_OWNER (relayed from owner).
        protocol.broadcast_npc_states(brain, None, now_ms)

        tick_idx += 1
        if tick_idx % log_every == 0:
            n_peers = len(protocol.state.all_sessions())
            n_peers_with_pos = len(peers_snapshot)
            n_aggro = 0
            if raider_brain is not None:
                n_aggro = sum(
                    1 for r in raider_brain.all_raiders()
                    if r.aggro_peer_id is not None
                )
            log.info(
                "npc tick: %d patroller(s), %d raider(s), %d aggro, "
                "%d peer(s) [%d w/pos] cells=%s",
                n_npc, n_raider, n_aggro,
                n_peers, n_peers_with_pos,
                brain.cells_loaded,
            )


async def _periodic_snapshot(
    protocol: ServerProtocol,
    path: Path,
    interval_s: float,
    *,
    rotate_keep: int = 5,
) -> None:
    """Periodically rotate + write a snapshot of server state.

    Rotation: before writing a fresh snapshot.json, the existing one is moved
    to snapshot.json.1 (and prior .1 to .2, etc., up to `rotate_keep`).
    This preserves a rolling history of the last N snapshots for debugging
    desync / rollback scenarios.
    """
    first_write = True
    while True:
        await asyncio.sleep(interval_s)
        try:
            if not first_write and path.exists():
                # Rotate existing snapshot before overwriting
                rotate_snapshots(path, keep=rotate_keep)
            snapshot(protocol.state, path)
            first_write = False
            log.debug("snapshot written to %s", path)
        except Exception as e:
            log.warning("snapshot failed: %s", e)


async def _stats_logger(protocol: ServerProtocol, interval_s: float = 10.0) -> None:
    while True:
        await asyncio.sleep(interval_s)
        n_peers = len(protocol.state.all_sessions())
        log.info("peers=%d stats=%s", n_peers, protocol.stats())


async def run_server(cfg: Config) -> None:
    logging.basicConfig(
        level=cfg.log_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )
    # B6.6w5 — also tee server log to file for cross-session diagnostics.
    # File path is next to snapshot so it's easy to find.
    try:
        from pathlib import Path
        log_path = Path(__file__).resolve().parent.parent.parent / "server.log"
        fh = logging.FileHandler(log_path, mode="w", encoding="utf-8")
        fh.setLevel(cfg.log_level)
        fh.setFormatter(logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%H:%M:%S"))
        logging.getLogger().addHandler(fh)
        log.info("server log mirrored to %s", log_path)
    except Exception as e:
        log.warning("could not set up server.log file mirror: %s", e)
    state = ServerState(tick_rate_hz=cfg.tick_rate_hz)

    # Restore authoritative world state from snapshot if available
    if cfg.snapshot_path is not None and cfg.snapshot_path.is_file():
        try:
            n = load_into(state, cfg.snapshot_path)
            log.info("restored %d world actors from snapshot %s", n, cfg.snapshot_path)
        except Exception as e:
            log.warning("snapshot restore failed (%s): starting with empty world", e)

    # B6.5w1 — load NPC brain from waypoint JSONs, if any. Brain is only
    # ticked when at least one NPC was loaded; an empty brain is a no-op
    # so legacy CLI invocations (no --waypoints-dir) are unaffected.
    #
    # B6.6w0 — same loop ALSO registers combat-eligible NPCs in
    # `raider_brain`. Eligibility is per-entry: the entry must declare
    # `combat_target_form_id` or a `combat` sub-object. Codsworth and
    # Dogmeat in sanctuary_mvp.json have neither, so they stay
    # pure-waypoint NPCs driven by NPCBrain alone.
    npc_brain = NPCBrain()
    raider_brain = RaiderBrain()
    if cfg.waypoints_dir is not None and cfg.waypoints_dir.is_dir():
        for jp in sorted(cfg.waypoints_dir.glob("*.json")):
            try:
                npc_brain.load_cell(jp)
            except Exception as e:
                log.warning("npc_brain: failed to load %s: %s", jp, e)
                continue
            try:
                raider_brain.load_cell(jp, npc_brain)
            except Exception as e:
                log.warning("raider_brain: failed to load %s: %s", jp, e)
        log.info(
            "npc_brain ready: %d npc(s) across %d cell(s); "
            "raider_brain has %d combat-eligible NPC(s)",
            npc_brain.count(), len(npc_brain.cells_loaded),
            raider_brain.count(),
        )
    elif cfg.waypoints_dir is not None:
        log.warning(
            "npc_brain: --waypoints-dir %s does not exist; brain idle",
            cfg.waypoints_dir,
        )

    loop = asyncio.get_running_loop()
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: ServerProtocol(state),
        local_addr=(cfg.host, cfg.port),
    )
    # B6.6w2: wire npc_brain + raider_brain into the protocol BEFORE
    # the event loop starts dispatching incoming datagrams.
    # Single-threaded asyncio so no race vs NPC_DISCOVER handler.
    # Always set — brains may start empty (no JSON seed) and grow via
    # NPC_DISCOVER events.
    protocol.npc_brain = npc_brain
    protocol.raider_brain = raider_brain
    try:
        tasks = [
            asyncio.create_task(_periodic_tick(protocol, cfg.tick_rate_hz)),
            asyncio.create_task(_stats_logger(protocol)),
        ]
        if cfg.snapshot_path is not None:
            tasks.append(asyncio.create_task(
                _periodic_snapshot(protocol, cfg.snapshot_path, cfg.snapshot_interval_s)
            ))
        if npc_brain.count() > 0:
            tasks.append(asyncio.create_task(
                _periodic_npc_brain_tick(
                    npc_brain,
                    # B6.6w2: always pass raider_brain (not conditional
                    # on JSON-seeded count). Brain may grow at runtime
                    # via NPC_DISCOVER messages, and the periodic tick
                    # must process those dynamic raiders.
                    raider_brain,
                    protocol,
                    cfg.npc_tick_hz,
                )
            ))
        log.info("server v1 ready")
        await asyncio.gather(*tasks)
    finally:
        transport.close()


def _now_ms() -> float:
    return time.monotonic() * 1000.0


# ---------------------------------------------------------------- cli

def parse_args() -> Config:
    ap = argparse.ArgumentParser(description="FalloutWorld server v1")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=31337)
    ap.add_argument("--tick-hz", type=int, default=20)
    ap.add_argument("--snapshot-path", type=Path, default=None,
                    help="if set, write JSON snapshot periodically")
    ap.add_argument("--snapshot-interval-s", type=float, default=30.0)
    ap.add_argument("--log-level", default="INFO",
                    choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    ap.add_argument("--waypoints-dir", type=Path, default=None,
                    help="if set, load every .json file from this dir into "
                         "the NPC brain at startup (B6.5+)")
    ap.add_argument("--npc-tick-hz", type=int, default=10,
                    help="NPC brain tick rate Hz (default 10)")
    args = ap.parse_args()
    return Config(
        host=args.host, port=args.port,
        tick_rate_hz=args.tick_hz,
        snapshot_path=args.snapshot_path,
        snapshot_interval_s=args.snapshot_interval_s,
        log_level=args.log_level,
        waypoints_dir=args.waypoints_dir,
        npc_tick_hz=args.npc_tick_hz,
    )


def main() -> None:
    cfg = parse_args()
    try:
        asyncio.run(run_server(cfg))
    except KeyboardInterrupt:
        log.info("shutdown")


if __name__ == "__main__":
    main()
