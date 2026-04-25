"""
FalloutWorld client v1 — one process per FO4 instance.

Does both: reads local player via Frida and sends POS_STATE; receives
POS_BROADCAST and writes to ghost actors in the local FO4.

CLI:
    python -m client.main \\
        --pid 23152 --id player_A \\
        --server 127.0.0.1:31337 \\
        --ghost-map other_peer_id=0xFF001345
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import signal
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from channel import ChannelError, ReliableChannel  # noqa: E402
from protocol import (  # noqa: E402
    MessageType, ProtocolError,
    HelloPayload, WelcomePayload, PeerJoinPayload, PeerLeavePayload,
    HeartbeatPayload, DisconnectPayload, PosStatePayload, PosBroadcastPayload,
    ActorEventPayload, ChatPayload,
    WorldStatePayload,
    ContainerOpPayload, ContainerBroadcastPayload, ContainerStatePayload,
    ContainerOpKind,
    encode_frame, decode_frame,
)
from protocol import ActorEventKind  # noqa: E402
from client.frida_bridge import FridaBridge, FakeFridaBridge, PlayerReading, KillEvent, ContainerCapture  # noqa: E402


log = logging.getLogger("client")


CLIENT_VERSION: tuple[int, int] = (1, 0)


# -------------------------------------------------------------- config

@dataclass
class ClientConfig:
    pid: int
    client_id: str
    server_host: str = "127.0.0.1"
    server_port: int = 31337
    tick_hz: int = 20
    # peer_id -> form_id (ghost actor formid to drive in local FO4 when this peer sends pos)
    ghost_map: dict[str, int] = field(default_factory=dict)
    use_fake_bridge: bool = False
    log_level: str = "INFO"


# -------------------------------------------------------------- protocol

class ClientProtocol(asyncio.DatagramProtocol):
    """UDP socket side of the client. Hands raw packets to FalloutWorldClient."""

    def __init__(self, client: "FalloutWorldClient") -> None:
        self.client = client
        self.transport: Optional[asyncio.DatagramTransport] = None

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:  # type: ignore[override]
        self.transport = transport

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        self.client.on_datagram(data, addr)


# -------------------------------------------------------------- client

class FalloutWorldClient:
    """The orchestrator. Owns Frida bridge + UDP socket + reliable channel."""

    def __init__(self, cfg: ClientConfig) -> None:
        self.cfg = cfg
        self.channel = ReliableChannel()
        self.server_addr: tuple[str, int] = (cfg.server_host, cfg.server_port)
        self.transport: Optional[asyncio.DatagramTransport] = None
        self.protocol: Optional[ClientProtocol] = None
        self.session_id: Optional[int] = None
        self.connected: bool = False
        self.known_peers: dict[str, int] = {}   # peer_id -> session_id
        self.bridge = (
            FakeFridaBridge(cfg.pid)
            if cfg.use_fake_bridge
            else FridaBridge(cfg.pid)
        )
        self._stop_event = asyncio.Event()
        self.stats = {
            "pos_sent": 0,
            "pos_broadcast_received": 0,
            "ghost_writes": 0,
            "reliable_sent": 0,
            "reliable_received": 0,
            "kills_captured": 0,
            "kills_broadcast_received": 0,
            "container_ops_sent": 0,
            "container_ops_received": 0,
            "container_ops_captured": 0,   # drained from bridge.container_queue
            "container_bootstrap_entries": 0,
        }

        # Local mirror of authoritative container state, keyed by (base, cell).
        # Each value is dict[item_base_id -> count]. Populated from bootstrap
        # chunks and kept in sync via CONTAINER_BCAST. Not yet pushed to the
        # Frida bridge (A.8 will add the engine AddItem/RemoveItem hooks).
        self.container_state: dict[tuple[int, int], dict[int, int]] = {}
        self._container_bootstrap_chunks_received: set[int] = set()
        self._container_bootstrap_total_chunks: int = 0
        self.container_bootstrap_complete: bool = False

        # Authoritative world state from server bootstrap.
        # Keyed by (base_id, cell_id) — the stable identity pair. Entries carry
        # last_known_form_id as the client-side LookupByFormID fast-path hint.
        # This keying eliminates the 0xFF______ cross-process aliasing bug.
        from protocol import WorldActorEntry  # local import to avoid shadowing
        self.world_state: dict[tuple[int, int], WorldActorEntry] = {}
        # Chunked WORLD_STATE reassembly: chunks seen so far for pending bootstrap
        self._bootstrap_chunks_received: set[int] = set()
        self._bootstrap_total_chunks: int = 0
        self.bootstrap_complete: bool = False

    # ---------------------------------------------------------- lifecycle

    async def run(self) -> None:
        logging.basicConfig(
            level=self.cfg.log_level,
            format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%H:%M:%S",
        )

        # 1. Start Frida bridge
        await self.bridge.start()

        # 2. Start UDP endpoint
        loop = asyncio.get_running_loop()
        self.transport, self.protocol = await loop.create_datagram_endpoint(
            lambda: ClientProtocol(self),
            local_addr=("0.0.0.0", 0),
        )

        # 3. Do handshake
        await self._handshake()

        # 4. Run main tasks
        tasks = [
            asyncio.create_task(self._send_pos_loop()),
            asyncio.create_task(self._send_kill_loop()),
            asyncio.create_task(self._send_container_loop()),
            asyncio.create_task(self._tick_loop()),
            asyncio.create_task(self._heartbeat_loop()),
            asyncio.create_task(self._stats_loop()),
            asyncio.create_task(self._manual_ops_loop()),
        ]

        try:
            await self._stop_event.wait()
        finally:
            for t in tasks:
                t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            await self._disconnect_gracefully()
            if self.transport is not None:
                self.transport.close()
            await self.bridge.stop()

    def stop(self) -> None:
        self._stop_event.set()

    # ---------------------------------------------------------- handshake

    async def _handshake(self) -> None:
        hello = HelloPayload(
            client_id=self.cfg.client_id,
            client_version_major=CLIENT_VERSION[0],
            client_version_minor=CLIENT_VERSION[1],
        )
        raw = self.channel.send_reliable(MessageType.HELLO, hello, _now_ms())
        self._send_to_server(raw)

        # Wait for WELCOME (up to 5s, with resends handled by reliable tick)
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            if self.connected:
                return
            # Drive retransmits meanwhile
            await self._tick_once()
            await asyncio.sleep(0.05)
        raise TimeoutError("server did not WELCOME within 5s")

    async def _disconnect_gracefully(self) -> None:
        if not self.connected:
            return
        log.info("sending graceful DISCONNECT")
        raw = self.channel.send_reliable(MessageType.DISCONNECT,
                                          DisconnectPayload(reason=0),
                                          _now_ms())
        self._send_to_server(raw)
        # Best-effort flush (no ack required in shutdown)
        await asyncio.sleep(0.1)

    # ---------------------------------------------------------- datagram handling

    def on_datagram(self, data: bytes, addr: tuple[str, int]) -> None:
        if addr != self.server_addr:
            # Drop anything not from our server (defense in depth)
            return
        now_ms = _now_ms()
        delivered, ack_bytes = self.channel.on_receive(data, now_ms)
        if ack_bytes is not None:
            self._send_to_server(ack_bytes)
        if delivered is None:
            return
        self._dispatch(delivered.header.msg_type, delivered.payload, now_ms)

    def _dispatch(self, mtype: int, payload, now_ms: float) -> None:
        if mtype == MessageType.WELCOME:
            self._handle_welcome(payload)
        elif mtype == MessageType.WORLD_STATE:
            self._handle_world_state(payload)
        elif mtype == MessageType.CONTAINER_STATE:
            self._handle_container_state(payload)
        elif mtype == MessageType.CONTAINER_BCAST:
            self._handle_container_broadcast(payload)
        elif mtype == MessageType.PEER_JOIN:
            self._handle_peer_join(payload)
        elif mtype == MessageType.PEER_LEAVE:
            self._handle_peer_leave(payload)
        elif mtype == MessageType.POS_BROADCAST:
            self._handle_pos_broadcast(payload)
        elif mtype == MessageType.ACTOR_EVENT:
            self._handle_actor_event(payload)
        elif mtype == MessageType.CHAT:
            self._handle_chat(payload)
        elif mtype == MessageType.HEARTBEAT:
            pass
        else:
            log.debug("unhandled mtype=0x%04X", mtype)

    # ---------------------------------------------------------- handlers

    def _handle_welcome(self, payload) -> None:
        if not isinstance(payload, WelcomePayload):
            return
        if not payload.accepted:
            log.error("server rejected our HELLO")
            self._stop_event.set()
            return
        self.session_id = payload.session_id
        self.connected = True
        log.info("welcomed: session_id=%d server_ver=%d.%d tick=%dHz",
                 payload.session_id,
                 payload.server_version_major, payload.server_version_minor,
                 payload.tick_rate_hz)

    def _handle_world_state(self, payload) -> None:
        if not isinstance(payload, WorldStatePayload):
            return
        # Merge entries into local view, keyed by identity. Entries without
        # full identity (base_id=0 or cell_id=0) are dropped — they'd be unsafe
        # to apply because we can't verify we're touching the right object.
        dropped = 0
        for e in payload.entries:
            if e.base_id == 0 or e.cell_id == 0:
                dropped += 1
                continue
            self.world_state[(e.base_id, e.cell_id)] = e
        if dropped:
            log.warning(
                "world_state: dropped %d entries lacking stable identity", dropped
            )
        # Track chunks
        self._bootstrap_total_chunks = payload.total_chunks
        self._bootstrap_chunks_received.add(payload.chunk_index)
        got = len(self._bootstrap_chunks_received)
        log.info("world_state chunk %d/%d received (%d entries this chunk, %d total known)",
                 payload.chunk_index + 1, payload.total_chunks,
                 len(payload.entries), len(self.world_state))
        if got == payload.total_chunks and not self.bootstrap_complete:
            self.bootstrap_complete = True
            log.info(
                "bootstrap COMPLETE: %d identity-keyed actors known. Applying to local FO4...",
                len(self.world_state),
            )
            self._apply_world_state_to_local()

    def _apply_world_state_to_local(self) -> None:
        """Apply the server's authoritative world state to the local FO4 instance.

        Uses set_disabled_validated: the JS side resolves the last-known ref_id
        via LookupByFormID, THEN verifies that the resolved ref's baseForm.formID
        and parentCell.formID match the expected identity tuple. Only on full
        match is the disable/enable applied. On mismatch the JS emits a
        `validate_miss` log and does nothing — preventing the 0xFF______
        aliasing bug where a persisted ref_id coincidentally resolves to a
        different object in this process.
        """
        applied_disable = 0
        applied_enable = 0
        for (base_id, cell_id), entry in self.world_state.items():
            self.bridge.set_disabled_validated(
                form_id=entry.form_id,           # last-known ref hint
                expected_base_id=base_id,
                expected_cell_id=cell_id,
                disabled=(not entry.alive),
            )
            if entry.alive:
                applied_enable += 1
            else:
                applied_disable += 1
        log.info(
            "apply_world_state: dispatched validated disable=%d enable=%d "
            "(JS rejects any identity mismatch)",
            applied_disable, applied_enable,
        )

    def _handle_peer_join(self, payload) -> None:
        if not isinstance(payload, PeerJoinPayload):
            return
        self.known_peers[payload.peer_id] = payload.session_id
        mapping = self.cfg.ghost_map.get(payload.peer_id)
        log.info("peer joined: %s (sid=%d), ghost formid: %s",
                 payload.peer_id, payload.session_id,
                 f"0x{mapping:X}" if mapping is not None else "<none>")

    def _handle_peer_leave(self, payload) -> None:
        if not isinstance(payload, PeerLeavePayload):
            return
        self.known_peers.pop(payload.peer_id, None)
        log.info("peer left: %s", payload.peer_id)
        # Invalidate ghost cache for that peer
        fid = self.cfg.ghost_map.get(payload.peer_id)
        if fid is not None:
            self.bridge.invalidate_ghost(fid)

    def _handle_pos_broadcast(self, payload) -> None:
        if not isinstance(payload, PosBroadcastPayload):
            return
        self.stats["pos_broadcast_received"] += 1
        # Defensive: reject non-finite or absurdly-large coords. A peer whose
        # Frida read garbage before save load completed can send NaN/Inf here,
        # and writing those to a local actor's position field makes the
        # engine stop rendering it (observed live: remote peer's Frida
        # attached mid-save-load -> garbage pos -> local ghost vanishes).
        import math
        coords = (payload.x, payload.y, payload.z,
                  payload.rx, payload.ry, payload.rz)
        if not all(math.isfinite(v) for v in coords) or \
           any(abs(v) > 1e7 for v in (payload.x, payload.y, payload.z)):
            log.warning(
                "rejecting pos_broadcast from %s: invalid coords (%r)",
                payload.peer_id, coords,
            )
            return
        form_id = self.cfg.ghost_map.get(payload.peer_id)
        if form_id is None:
            log.debug("no ghost mapping for peer %s", payload.peer_id)
            return
        self.bridge.write_ghost(
            form_id,
            payload.x, payload.y, payload.z,
            payload.rx, payload.ry, payload.rz,
        )
        self.stats["ghost_writes"] += 1

    def _handle_actor_event(self, payload) -> None:
        if not isinstance(payload, ActorEventPayload):
            return
        self.stats["kills_broadcast_received"] += 1
        log.info(
            "actor event: kind=%d formid=0x%X base=0x%X cell=0x%X (from other peer)",
            payload.kind, payload.form_id, payload.actor_base_id, payload.cell_id,
        )
        is_dead = payload.kind in (int(ActorEventKind.KILL), int(ActorEventKind.DISABLE))
        # Prefer the validated path when identity is available. The JS will
        # silently skip if the local ref doesn't match — which is the correct
        # behavior for the 0xFF______ aliasing bug.
        if payload.actor_base_id != 0 and payload.cell_id != 0:
            self.bridge.set_disabled_validated(
                form_id=payload.form_id,
                expected_base_id=payload.actor_base_id,
                expected_cell_id=payload.cell_id,
                disabled=is_dead,
            )
            from protocol import WorldActorEntry
            self.world_state[(payload.actor_base_id, payload.cell_id)] = (
                WorldActorEntry(
                    form_id=payload.form_id,
                    alive=not is_dead,
                    base_id=payload.actor_base_id,
                    cell_id=payload.cell_id,
                )
            )
        else:
            # Legacy event without identity. Safer to fall through to the old
            # unvalidated path but we log loudly — anything still emitting
            # these should be audited.
            log.warning(
                "actor event without identity — falling back to unvalidated apply "
                "for form_id=0x%X (base/cell missing)",
                payload.form_id,
            )
            self.bridge.set_disabled(form_id=payload.form_id, disabled=is_dead)

    def _handle_container_state(self, payload) -> None:
        """Consume a chunked CONTAINER_STATE bootstrap message and rebuild
        the local mirror of server container inventories."""
        if not isinstance(payload, ContainerStatePayload):
            return
        for e in payload.entries:
            if e.container_base_id == 0 or e.container_cell_id == 0:
                continue  # defensive: malformed entry
            key = (e.container_base_id, e.container_cell_id)
            bucket = self.container_state.setdefault(key, {})
            if e.count > 0:
                bucket[e.item_base_id] = e.count
            else:
                bucket.pop(e.item_base_id, None)
            self.stats["container_bootstrap_entries"] += 1
        self._container_bootstrap_total_chunks = payload.total_chunks
        self._container_bootstrap_chunks_received.add(payload.chunk_index)
        log.info(
            "container_state chunk %d/%d received (%d entries, %d containers known)",
            payload.chunk_index + 1, payload.total_chunks,
            len(payload.entries), len(self.container_state),
        )
        got = len(self._container_bootstrap_chunks_received)
        if got == payload.total_chunks and not self.container_bootstrap_complete:
            self.container_bootstrap_complete = True
            log.info(
                "container bootstrap COMPLETE: %d containers with %d total entries",
                len(self.container_state),
                sum(len(v) for v in self.container_state.values()),
            )
            # A.8 will plumb this through to the bridge for local apply.

    def _handle_container_broadcast(self, payload) -> None:
        """A peer's TAKE/PUT was accepted + broadcast by the server.
        Apply it to our local mirror (authoritative mutation already done
        server-side; we just mirror here for UI and future Frida apply)."""
        if not isinstance(payload, ContainerBroadcastPayload):
            return
        self.stats["container_ops_received"] += 1
        if payload.container_base_id == 0 or payload.container_cell_id == 0:
            return
        key = (payload.container_base_id, payload.container_cell_id)
        bucket = self.container_state.setdefault(key, {})
        current = bucket.get(payload.item_base_id, 0)
        if payload.kind == int(ContainerOpKind.TAKE):
            new_count = max(0, current - payload.count)
        elif payload.kind == int(ContainerOpKind.PUT):
            new_count = current + payload.count
        else:
            log.warning("unknown container op kind %d from peer %s",
                        payload.kind, payload.peer_id)
            return
        if new_count == 0:
            bucket.pop(payload.item_base_id, None)
        else:
            bucket[payload.item_base_id] = new_count
        log.info(
            "container op from %s: kind=%s container=0x%X/0x%X item=0x%X count=%d -> now %d",
            payload.peer_id,
            ContainerOpKind(payload.kind).name,
            payload.container_base_id, payload.container_cell_id,
            payload.item_base_id, payload.count, new_count,
        )
        # A.8 will apply the mutation to the local FO4 container via Frida.

    def send_container_op(
        self,
        *,
        kind: ContainerOpKind,
        container_base_id: int,
        container_cell_id: int,
        item_base_id: int,
        count: int,
    ) -> None:
        """Send a TAKE/PUT op to the server (reliable). Called by the
        Frida container-hook (A.8) or by tests / manual console triggers.

        Silently no-ops if not connected (HELLO still in flight or we've
        been disconnected). No retry — reliable channel handles that.

        Optimistic update: the sender's own mirror is updated IMMEDIATELY,
        before waiting for any server confirmation. Rationale: the server
        broadcasts only to `other_sessions(sender)`, so the sender never
        sees an echo of its own op. Without optimistic update the sender's
        mirror drifts behind until the next bootstrap. If the server
        happens to reject (rate limit, insufficient items), the drift is
        resolved at the next CONTAINER_STATE bootstrap (reconnect or
        restart).
        """
        if not self.connected or count <= 0:
            return
        if container_base_id == 0 or container_cell_id == 0:
            log.warning("refusing to send container op with missing identity")
            return

        # Optimistic local apply BEFORE transmit — keeps sender's mirror
        # in sync with what the server will accept in the common case.
        key = (container_base_id, container_cell_id)
        bucket = self.container_state.setdefault(key, {})
        current = bucket.get(item_base_id, 0)
        if kind == ContainerOpKind.TAKE:
            new_count = max(0, current - count)
        elif kind == ContainerOpKind.PUT:
            new_count = current + count
        else:
            log.warning("send_container_op: unknown kind %r", kind)
            return
        if new_count == 0:
            bucket.pop(item_base_id, None)
        else:
            bucket[item_base_id] = new_count

        payload = ContainerOpPayload(
            kind=int(kind),
            container_base_id=container_base_id,
            container_cell_id=container_cell_id,
            item_base_id=item_base_id,
            count=count,
            timestamp_ms=int(time.time() * 1000),
        )
        now_ms = _now_ms()
        raw = self.channel.send_reliable(MessageType.CONTAINER_OP, payload, now_ms)
        self._send_to_server(raw)
        self.stats["container_ops_sent"] += 1
        log.debug(
            "sent container op: kind=%s container=0x%X/0x%X item=0x%X count=%d -> local now %d",
            kind.name, container_base_id, container_cell_id,
            item_base_id, count, new_count,
        )

    def _handle_chat(self, payload) -> None:
        log.info("[chat] <%s> %s", payload.sender_id, payload.text[:80])

    # ---------------------------------------------------------- periodic tasks

    async def _send_pos_loop(self) -> None:
        """Drain Frida-read player positions and send POS_STATE."""
        while not self._stop_event.is_set():
            reading: PlayerReading = await self.bridge.player_queue.get()
            if not self.connected:
                continue
            payload = PosStatePayload(
                x=reading.x, y=reading.y, z=reading.z,
                rx=reading.rx, ry=reading.ry, rz=reading.rz,
                timestamp_ms=reading.ts_ms,
            )
            raw = self.channel.send_unreliable(MessageType.POS_STATE, payload)
            self._send_to_server(raw)
            self.stats["pos_sent"] += 1

    async def _send_kill_loop(self) -> None:
        """Drain Frida-captured kill events and send ACTOR_EVENT(KILL) reliably.

        Kill events MUST arrive — the server needs them to update its authoritative
        world state. Using reliable delivery with ACK + retransmit.
        """
        while not self._stop_event.is_set():
            kev: KillEvent = await self.bridge.kill_queue.get()
            if not self.connected:
                continue
            # Filter: don't report kills of the local player (they happen via ragdoll
            # and are user-initiated respawn, not a propagatable world event)
            # (local player formid is always 0x14)
            if kev.victim_form_id == 0x14:
                log.debug("local player death — not broadcasting")
                continue
            payload = ActorEventPayload(
                kind=int(ActorEventKind.KILL),
                form_id=kev.victim_form_id,
                actor_base_id=kev.victim_base_id,
                x=0.0, y=0.0, z=0.0,
                extra=kev.killer_form_id,
                cell_id=kev.victim_cell_id,
            )
            now_ms = _now_ms()
            raw = self.channel.send_reliable(MessageType.ACTOR_EVENT, payload, now_ms)
            self._send_to_server(raw)
            self.stats["kills_captured"] += 1
            log.info("captured kill: victim=0x%X killer=0x%X -> server",
                     kev.victim_form_id, kev.killer_form_id)

    async def _send_container_loop(self) -> None:
        """Drain container ops captured by the Frida AddObjectToContainer hook
        and forward them to the server via the reliable channel.

        Runs at queue-driven rate (blocks on get), so idle clients consume no
        CPU. Each captured op becomes a single reliable CONTAINER_OP message;
        send_container_op also applies it to the local mirror optimistically.
        """
        while not self._stop_event.is_set():
            cap: ContainerCapture = await self.bridge.container_queue.get()
            if not self.connected:
                continue
            kind = (ContainerOpKind.TAKE if cap.op_kind == "TAKE"
                    else ContainerOpKind.PUT if cap.op_kind == "PUT"
                    else None)
            if kind is None:
                log.warning("container capture with unknown op_kind=%r", cap.op_kind)
                continue
            self.stats["container_ops_captured"] += 1
            log.info(
                "captured container op: %s container=0x%X/0x%X item=0x%X count=%d",
                cap.op_kind, cap.container_base_id, cap.container_cell_id,
                cap.item_base_id, cap.count,
            )
            self.send_container_op(
                kind=kind,
                container_base_id=cap.container_base_id,
                container_cell_id=cap.container_cell_id,
                item_base_id=cap.item_base_id,
                count=cap.count,
            )

    async def _tick_loop(self) -> None:
        interval = 1.0 / max(1, self.cfg.tick_hz)
        while not self._stop_event.is_set():
            await self._tick_once()
            await asyncio.sleep(interval)

    async def _tick_once(self) -> None:
        now_ms = _now_ms()
        try:
            retrans, ack = self.channel.tick(now_ms)
        except ChannelError:
            log.error("channel dead (server unreachable); stopping")
            self._stop_event.set()
            return
        for r in retrans:
            self._send_to_server(r)
        if ack is not None:
            self._send_to_server(ack)

    async def _heartbeat_loop(self) -> None:
        """Send HEARTBEAT every 1.5s so the server doesn't time us out."""
        while not self._stop_event.is_set():
            await asyncio.sleep(1.5)
            if not self.connected:
                continue
            hb = HeartbeatPayload(timestamp_ms=int(time.time() * 1000))
            raw = self.channel.send_unreliable(MessageType.HEARTBEAT, hb)
            self._send_to_server(raw)

    async def _stats_loop(self) -> None:
        while not self._stop_event.is_set():
            await asyncio.sleep(10.0)
            log.info("stats: %s peers=%d", dict(self.stats), len(self.known_peers))

    async def _manual_ops_loop(self) -> None:
        """Poll a per-peer JSONL file for container ops and send them.

        Development aid for pre-Frida end-to-end validation (A.7.6). A separate
        CLI helper (`tools/container_op.py`) appends JSON lines to
        `<repo>/manual_ops_<client_id>.jsonl` and this loop drains them every
        500ms. A side-car `.offset` file tracks the last processed byte so
        restarts don't re-send old ops.

        On first run we skip to EOF — old lines from a prior session are NOT
        re-sent. Remove this loop once A.8 (Frida container hook) is live.
        """
        import json as _json
        repo = Path(__file__).resolve().parents[2]
        ops_path = repo / f"manual_ops_{self.cfg.client_id}.jsonl"
        offset_path = repo / f".manual_ops_{self.cfg.client_id}.offset"
        # Seek to EOF at startup so prior sessions' lines don't replay.
        try:
            initial = ops_path.stat().st_size if ops_path.exists() else 0
        except OSError:
            initial = 0
        try:
            offset_path.write_text(str(initial), encoding="utf-8")
        except OSError:
            pass
        processed_offset = initial

        while not self._stop_event.is_set():
            await asyncio.sleep(0.5)
            if not self.connected:
                continue
            try:
                if not ops_path.exists():
                    continue
                size = ops_path.stat().st_size
                if size <= processed_offset:
                    continue
                with ops_path.open("rb") as fh:
                    fh.seek(processed_offset)
                    new_bytes = fh.read()
                processed_offset += len(new_bytes)
                text = new_bytes.decode("utf-8", errors="replace")
                for line in text.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        cmd = _json.loads(line)
                    except _json.JSONDecodeError as e:
                        log.warning("manual op bad JSON: %r (%s)", line, e)
                        continue
                    self._dispatch_manual_op(cmd)
                try:
                    offset_path.write_text(str(processed_offset), encoding="utf-8")
                except OSError:
                    pass
            except Exception as e:
                log.debug("manual ops loop err: %s", e)

    def _dispatch_manual_op(self, cmd: dict) -> None:
        """Translate one manual-op dict into a typed send_container_op call."""
        def _parse_int(v) -> int:
            if isinstance(v, int):
                return v
            s = str(v).strip()
            return int(s, 16) if s.lower().startswith("0x") else int(s)

        op = str(cmd.get("op", "")).lower()
        kind = None
        if op == "take":
            kind = ContainerOpKind.TAKE
        elif op == "put":
            kind = ContainerOpKind.PUT
        if kind is None:
            log.warning("manual op unknown kind: %r", cmd)
            return
        try:
            cbase = _parse_int(cmd["container_base"])
            ccell = _parse_int(cmd["container_cell"])
            ibase = _parse_int(cmd["item_base"])
            count = int(cmd["count"])
        except (KeyError, TypeError, ValueError) as e:
            log.warning("manual op missing/bad field (%s): %r", e, cmd)
            return
        log.info("manual op: %s container=0x%X/0x%X item=0x%X count=%d",
                 kind.name, cbase, ccell, ibase, count)
        self.send_container_op(
            kind=kind,
            container_base_id=cbase,
            container_cell_id=ccell,
            item_base_id=ibase,
            count=count,
        )

    # ---------------------------------------------------------- internal

    def _send_to_server(self, raw: bytes) -> None:
        if self.protocol is None or self.protocol.transport is None:
            return
        self.protocol.transport.sendto(raw, self.server_addr)


def _now_ms() -> float:
    return time.monotonic() * 1000.0


# ---------------------------------------------------------------- CLI


def _parse_ghost_map(entries: list[str]) -> dict[str, int]:
    """Parse --ghost-map peer_id=0xFFXXXX style args."""
    out: dict[str, int] = {}
    for e in entries:
        if "=" not in e:
            raise ValueError(f"bad ghost-map entry {e!r}: expected peer_id=formid")
        peer, fid = e.split("=", 1)
        fid = fid.strip()
        out[peer.strip()] = int(fid, 16) if fid.lower().startswith("0x") else int(fid)
    return out


def _parse_server(s: str) -> tuple[str, int]:
    if ":" not in s:
        raise ValueError("server must be host:port")
    host, port = s.rsplit(":", 1)
    return (host, int(port))


def parse_args() -> ClientConfig:
    ap = argparse.ArgumentParser(description="FalloutWorld client v1")
    ap.add_argument("--pid", type=int, required=True, help="PID of Fallout4.exe to attach")
    ap.add_argument("--id", required=True, help="peer id (ASCII max 15 chars)")
    ap.add_argument("--server", default="127.0.0.1:31337")
    ap.add_argument("--tick-hz", type=int, default=20)
    ap.add_argument(
        "--ghost-map",
        action="append",
        default=[],
        help="map peer_id to ghost actor formid, e.g. --ghost-map bob=0xFF001345",
    )
    ap.add_argument("--fake-bridge", action="store_true",
                    help="don't attach Frida, use fake bridge (debug only)")
    ap.add_argument("--log-level", default="INFO",
                    choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    args = ap.parse_args()

    host, port = _parse_server(args.server)
    return ClientConfig(
        pid=args.pid,
        client_id=args.id,
        server_host=host, server_port=port,
        tick_hz=args.tick_hz,
        ghost_map=_parse_ghost_map(args.ghost_map),
        use_fake_bridge=args.fake_bridge,
        log_level=args.log_level,
    )


def main() -> None:
    cfg = parse_args()
    client = FalloutWorldClient(cfg)

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    def _sigint(*_):
        loop.call_soon_threadsafe(client.stop)

    try:
        signal.signal(signal.SIGINT, _sigint)
    except Exception:
        pass  # Windows quirk

    try:
        loop.run_until_complete(client.run())
    except KeyboardInterrupt:
        client.stop()
    finally:
        loop.close()


if __name__ == "__main__":
    main()
