"""
ReliableChannel: high-level API che combina protocol + reliable layer per un peer.

Wraps a SendWindow + ReceiveWindow pair and provides a clean callback-driven API.
Usable on both server-side (one channel per peer) and client-side (one channel to server).

The channel is pure logic — no sockets. Caller drives it with:
- send_reliable(msg_type, payload, now_ms)  -> bytes to transmit
- send_unreliable(msg_type, payload)         -> bytes to transmit
- on_receive(frame, now_ms)                  -> (delivered, outgoing_ack_frame_or_none)
- tick(now_ms)                               -> list of (bytes, is_retransmit) to send, or error
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from protocol import (
    Frame, FrameHeader, MessageType, Payload, AckPayload,
    encode_frame, decode_frame, ProtocolError,
    FLAG_RELIABLE,
)
from reliable import SendWindow, ReceiveWindow


class ChannelError(Exception):
    """Raised when a peer exceeds MAX_RETRANSMITS (dead connection)."""


@dataclass(slots=True)
class ReliableChannel:
    """Manages reliable + unreliable message flow to a single remote peer."""

    send: SendWindow = field(default_factory=SendWindow)
    recv: ReceiveWindow = field(default_factory=ReceiveWindow)

    # Unreliable side has its own independent seq (frames are not tracked)
    _next_unreliable_seq: int = 1

    # Ack emission policy: send ACK every N received reliable frames OR every ACK_PERIOD_MS
    _unacked_count: int = 0
    _last_ack_sent_at: float = 0.0
    ACK_BATCH: int = 8                # send ack after N received reliable frames
    ACK_PERIOD_MS: float = 50.0        # or every 50ms at most

    # Dead channel flag (set if MAX_RETRANSMITS hit)
    dead: bool = False

    # ------------------------------------------------------------- sending

    def send_unreliable(self, msg_type: MessageType, payload: Payload) -> bytes:
        """Build a non-reliable frame. Caller transmits the returned bytes."""
        seq = self._next_unreliable_seq
        self._next_unreliable_seq = (self._next_unreliable_seq + 1) & 0xFFFFFFFF
        return encode_frame(msg_type, seq, payload, reliable=False)

    def send_reliable(self, msg_type: MessageType, payload: Payload, now_ms: float) -> bytes:
        """Build and register a reliable frame. Must be re-sent on timeout via tick()."""
        if self.dead:
            raise ChannelError("channel is dead (max retransmits reached)")
        seq = self.send.allocate_seq()
        raw = encode_frame(msg_type, seq, payload, reliable=True)
        self.send.register_sent(seq, raw, now_ms)
        return raw

    # ------------------------------------------------------------- receiving

    def on_receive(
        self, raw: bytes, now_ms: float
    ) -> tuple[Optional[Frame], Optional[bytes]]:
        """Process an incoming frame from the wire.

        Returns (delivered_frame_or_None, outgoing_ack_frame_or_None):
        - delivered_frame: Frame if this frame is new and should be processed by app (None if dup/invalid)
        - outgoing_ack_frame: bytes to transmit as ACK, or None (caller may also get ACKs from tick())

        Special: ACK frames never "deliver" — they mutate sender state silently.
        """
        try:
            frame = decode_frame(raw)
        except ProtocolError:
            return (None, None)

        # ACK frames: mutate SendWindow, never reach application
        if frame.header.msg_type == MessageType.ACK:
            if isinstance(frame.payload, AckPayload):
                self.send.on_ack(
                    frame.payload.highest_contiguous_seq,
                    frame.payload.sack_bitmap,
                    now_ms,
                )
            return (None, None)

        # Reliable frames: dedup + register for ACK emission
        if frame.header.is_reliable:
            is_new = self.recv.on_receive(frame.header.seq)
            # Always ACK (even duplicates, so sender clears in-flight)
            self._unacked_count += 1
            ack_bytes = self._maybe_emit_ack(now_ms, force=False)
            return (frame if is_new else None, ack_bytes)

        # Unreliable frames: just deliver
        return (frame, None)

    # ------------------------------------------------------------- ticking

    def tick(self, now_ms: float) -> tuple[list[bytes], Optional[bytes]]:
        """Called periodically (e.g. every 50ms). Returns:
        - list of retransmit frames to send
        - pending ack frame if ACK_PERIOD_MS elapsed and we have unacked, or None

        Raises ChannelError if the peer missed too many retransmits (dead).
        """
        retransmits: list[bytes] = []

        for inf in self.send.due_for_retransmit(now_ms):
            alive = self.send.mark_retransmitted(inf.seq, now_ms)
            if not alive:
                self.dead = True
                raise ChannelError(f"peer dead: seq {inf.seq} exceeded max retransmits")
            retransmits.append(inf.payload_bytes)

        # Periodic ACK: if we owe an ACK and the timer elapsed
        ack_bytes = self._maybe_emit_ack(now_ms, force=False)
        return retransmits, ack_bytes

    # ------------------------------------------------------------- internal

    def _maybe_emit_ack(self, now_ms: float, *, force: bool) -> Optional[bytes]:
        """Emit an ACK frame if policy says so."""
        if self._unacked_count == 0 and not force:
            return None
        batch_ready = self._unacked_count >= self.ACK_BATCH
        timer_ready = (now_ms - self._last_ack_sent_at) >= self.ACK_PERIOD_MS
        if not (batch_ready or timer_ready or force):
            return None

        h, b = self.recv.ack_snapshot()
        ack_payload = AckPayload(highest_contiguous_seq=h, sack_bitmap=b)
        # ACK itself has its own unreliable seq (not tracked, just monotonic)
        seq = self._next_unreliable_seq
        self._next_unreliable_seq = (self._next_unreliable_seq + 1) & 0xFFFFFFFF
        raw = encode_frame(MessageType.ACK, seq, ack_payload, reliable=False)
        self._unacked_count = 0
        self._last_ack_sent_at = now_ms
        return raw
