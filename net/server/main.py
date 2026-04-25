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
    ActorEventPayload, ChatPayload, RawMessage,
    WorldStatePayload, WorldActorEntry,
    ContainerOpPayload, ContainerBroadcastPayload,
    ContainerStatePayload, ContainerStateEntry,
    ContainerSeedPayload, ContainerOpAckPayload, ContainerOpAckStatus,
    QuestStageSetPayload, QuestStageBroadcastPayload,
    QuestStateBootPayload, QuestStageStateEntry,
    GlobalVarSetPayload, GlobalVarBroadcastPayload,
    GlobalVarStateBootPayload, GlobalVarStateEntry,
    encode_frame, decode_frame,
)
from server.state import ServerState, PeerSession, SessionState  # noqa: E402
from server.validator import (  # noqa: E402
    validate_pos_state, validate_actor_event, validate_container_op, RejectReason,
)
from server.persistence import snapshot, load_into, rotate_snapshots  # noqa: E402


log = logging.getLogger("server")


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
    ) -> None:
        self.host = host
        self.port = port
        self.tick_rate_hz = tick_rate_hz
        self.snapshot_path = snapshot_path
        self.snapshot_interval_s = snapshot_interval_s
        self.log_level = log_level


# ---------------------------------------------------------------- protocol handler

class ServerProtocol(asyncio.DatagramProtocol):
    """Wires asyncio's UDP to our state machine. Owns the ServerState."""

    def __init__(self, state: ServerState) -> None:
        self.state = state
        self.transport: Optional[asyncio.DatagramTransport] = None
        self._counters = {
            "rx_frames": 0,
            "tx_frames": 0,
            "rx_invalid": 0,
            "rejections": 0,
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

        log.info("peer joined: %s from %s (sid=%d)", session.peer_id, addr, session.session_id)

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
            log.debug("reject POS from %s: %s %s",
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
        )
        for other in self.state.other_sessions(session.addr):
            raw = other.channel.send_unreliable(MessageType.POS_BROADCAST, broadcast)
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

    def _handle_chat(self, session: PeerSession, payload, now_ms: float) -> None:
        if not isinstance(payload, ChatPayload):
            return
        # Broadcast to all peers EXCEPT sender (reliable)
        log.info("[chat] <%s> %s", session.peer_id, payload.text[:80])
        for other in self.state.other_sessions(session.addr):
            raw = other.channel.send_reliable(MessageType.CHAT, payload, now_ms)
            self._send(other.addr, raw)

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
            # Already removed from sessions; notify others
            leave = PeerLeavePayload(peer_id=s.peer_id, reason=0)
            for other in self.state.all_sessions():
                raw = other.channel.send_reliable(MessageType.PEER_LEAVE, leave, now_ms)
                self._send(other.addr, raw)

    # ----- helpers

    def _remove_and_notify(self, session: PeerSession, *, reason: int, now_ms: float) -> None:
        self.state.remove(session.peer_id)
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
    state = ServerState(tick_rate_hz=cfg.tick_rate_hz)

    # Restore authoritative world state from snapshot if available
    if cfg.snapshot_path is not None and cfg.snapshot_path.is_file():
        try:
            n = load_into(state, cfg.snapshot_path)
            log.info("restored %d world actors from snapshot %s", n, cfg.snapshot_path)
        except Exception as e:
            log.warning("snapshot restore failed (%s): starting with empty world", e)

    loop = asyncio.get_running_loop()
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: ServerProtocol(state),
        local_addr=(cfg.host, cfg.port),
    )
    try:
        tasks = [
            asyncio.create_task(_periodic_tick(protocol, cfg.tick_rate_hz)),
            asyncio.create_task(_stats_logger(protocol)),
        ]
        if cfg.snapshot_path is not None:
            tasks.append(asyncio.create_task(
                _periodic_snapshot(protocol, cfg.snapshot_path, cfg.snapshot_interval_s)
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
    args = ap.parse_args()
    return Config(
        host=args.host, port=args.port,
        tick_rate_hz=args.tick_hz,
        snapshot_path=args.snapshot_path,
        snapshot_interval_s=args.snapshot_interval_s,
        log_level=args.log_level,
    )


def main() -> None:
    cfg = parse_args()
    try:
        asyncio.run(run_server(cfg))
    except KeyboardInterrupt:
        log.info("shutdown")


if __name__ == "__main__":
    main()
