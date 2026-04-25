"""
Reliability layer: selective-ACK + adaptive retransmit per frames con FLAG_RELIABLE.

Design:
- Sender side: SendWindow tracks in-flight frames, retransmits after RTO.
- Receiver side: ReceiveWindow tracks which seqs received, produces selective ACKs.
- RttEstimator: TCP RFC6298 style (SRTT + RTTVAR -> RTO).

All pure logic: the caller drives with wall-clock timestamps. No threads, no I/O.
Rust port path: SendWindow -> struct with HashMap<u32, InFlight>; same API.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

# ------------------------------------------------------------------ constants

INITIAL_RTO_MS: float = 300.0
MIN_RTO_MS: float = 100.0
MAX_RTO_MS: float = 3_000.0
SACK_WINDOW: int = 32              # selective-ack bitmap width
MAX_RETRANSMITS: int = 8           # after this many, drop the frame
BACKOFF_MULT: float = 2.0          # on each retransmit, double RTO (TCP style)


# ------------------------------------------------------------------ RTT

@dataclass(slots=True)
class RttEstimator:
    """TCP RFC6298 SRTT/RTTVAR estimator.

    Caller observes measured RTT samples; reads .rto_ms for current retransmit timeout.
    """

    srtt_ms: Optional[float] = None   # smoothed RTT
    rttvar_ms: Optional[float] = None # RTT variation
    alpha: float = 1.0 / 8.0          # smoothing factor for srtt
    beta: float = 1.0 / 4.0           # smoothing factor for rttvar
    k: float = 4.0                    # rto multiplier

    def observe(self, measured_rtt_ms: float) -> None:
        """Incorporate a new RTT sample."""
        if measured_rtt_ms <= 0:
            return  # protect against clock skew
        if self.srtt_ms is None:
            # First sample: bootstrap per RFC6298
            self.srtt_ms = measured_rtt_ms
            self.rttvar_ms = measured_rtt_ms / 2.0
        else:
            diff = abs(self.srtt_ms - measured_rtt_ms)
            assert self.rttvar_ms is not None
            self.rttvar_ms = (1 - self.beta) * self.rttvar_ms + self.beta * diff
            self.srtt_ms = (1 - self.alpha) * self.srtt_ms + self.alpha * measured_rtt_ms

    @property
    def rto_ms(self) -> float:
        """Current retransmission timeout in ms."""
        if self.srtt_ms is None or self.rttvar_ms is None:
            return INITIAL_RTO_MS
        rto = self.srtt_ms + self.k * self.rttvar_ms
        return max(MIN_RTO_MS, min(MAX_RTO_MS, rto))


# ------------------------------------------------------------------ sender

@dataclass(slots=True)
class InFlight:
    """A reliable frame that has been sent but not yet acked."""
    seq: int
    payload_bytes: bytes          # raw frame bytes (ready to re-send as-is)
    first_sent_at_ms: float       # when first transmitted (for RTT measurement)
    last_sent_at_ms: float        # when most recently transmitted (for timeout calc)
    retransmit_count: int = 0     # number of times retransmitted


@dataclass(slots=True)
class SendWindow:
    """Tracks in-flight reliable frames on the sender side."""

    rtt: RttEstimator = field(default_factory=RttEstimator)
    in_flight: dict[int, InFlight] = field(default_factory=dict)
    next_seq: int = 1

    def register_sent(self, seq: int, payload_bytes: bytes, now_ms: float) -> None:
        """Call when a reliable frame is first sent."""
        self.in_flight[seq] = InFlight(
            seq=seq,
            payload_bytes=payload_bytes,
            first_sent_at_ms=now_ms,
            last_sent_at_ms=now_ms,
        )

    def allocate_seq(self) -> int:
        """Allocate the next monotonic reliable-seq."""
        seq = self.next_seq
        self.next_seq = (self.next_seq + 1) & 0xFFFFFFFF
        if self.next_seq == 0:
            self.next_seq = 1  # skip 0 (reserved as "no data")
        return seq

    def on_ack(self, highest_contiguous: int, sack_bitmap: int, now_ms: float) -> list[int]:
        """Apply an incoming ACK. Returns list of seqs that were acked."""
        acked: list[int] = []
        # Contiguous ack: everything <= highest_contiguous
        for seq in list(self.in_flight):
            if _seq_leq(seq, highest_contiguous):
                inf = self.in_flight.pop(seq)
                # Only use RTT from non-retransmitted (Karn's algorithm)
                if inf.retransmit_count == 0:
                    self.rtt.observe(now_ms - inf.first_sent_at_ms)
                acked.append(seq)
        # Selective bits: bits set => highest_contiguous+N+1 received
        for bit in range(SACK_WINDOW):
            if sack_bitmap & (1 << bit):
                target = (highest_contiguous + bit + 1) & 0xFFFFFFFF
                inf = self.in_flight.pop(target, None)
                if inf is not None:
                    if inf.retransmit_count == 0:
                        self.rtt.observe(now_ms - inf.first_sent_at_ms)
                    acked.append(target)
        return acked

    def due_for_retransmit(self, now_ms: float) -> list[InFlight]:
        """Returns frames that have exceeded their RTO and should be re-sent.

        Caller sends them and then calls mark_retransmitted() for each.
        """
        timeout = self.rtt.rto_ms
        due: list[InFlight] = []
        for inf in self.in_flight.values():
            # Exponential backoff per retransmit
            effective_rto = timeout * (BACKOFF_MULT ** inf.retransmit_count)
            if now_ms - inf.last_sent_at_ms >= effective_rto:
                due.append(inf)
        return due

    def mark_retransmitted(self, seq: int, now_ms: float) -> bool:
        """Caller invokes after re-sending. Returns False if we've exceeded MAX_RETRANSMITS
        (caller should drop the frame / disconnect the peer)."""
        inf = self.in_flight.get(seq)
        if inf is None:
            return True  # already acked between check and mark, ok
        inf.retransmit_count += 1
        inf.last_sent_at_ms = now_ms
        if inf.retransmit_count > MAX_RETRANSMITS:
            del self.in_flight[seq]
            return False
        return True


def _seq_leq(a: int, b: int) -> bool:
    """Sequence-number comparison with u32 wraparound.
    Returns True if a <= b in the circular sense (half-range rule)."""
    return ((b - a) & 0xFFFFFFFF) < 0x80000000


# ------------------------------------------------------------------ receiver

@dataclass(slots=True)
class ReceiveWindow:
    """Tracks which reliable seqs we've received, to produce selective ACKs and drop dupes."""

    highest_contiguous: int = 0    # everything <= this is delivered
    sack_bitmap: int = 0           # bits for (highest_contiguous+1 .. +SACK_WINDOW)
    _delivered_out_of_order: set[int] = field(default_factory=set)

    def on_receive(self, seq: int) -> bool:
        """Register receipt of a reliable seq. Returns True if new, False if duplicate.

        The caller should:
        - If True: deliver the frame to application.
        - If False: drop (ACK again anyway).
        Either way, send an ACK so sender clears its in-flight state.
        """
        # Duplicates: already contiguously delivered
        if _seq_leq(seq, self.highest_contiguous) and seq != 0:
            return False
        # Duplicates: already seen out-of-order
        if seq in self._delivered_out_of_order:
            return False

        # Is this the next contiguous seq?
        next_contig = (self.highest_contiguous + 1) & 0xFFFFFFFF
        if seq == next_contig:
            self.highest_contiguous = seq
            # Advance through any contiguously-received out-of-order seqs
            while True:
                nxt = (self.highest_contiguous + 1) & 0xFFFFFFFF
                if nxt in self._delivered_out_of_order:
                    self._delivered_out_of_order.remove(nxt)
                    self.highest_contiguous = nxt
                else:
                    break
            self._rebuild_bitmap()
            return True

        # Future seq (out of order). Store if within window.
        gap = (seq - self.highest_contiguous) & 0xFFFFFFFF
        if gap == 0 or gap > SACK_WINDOW:
            # Out of window: drop silently (sender will retransmit)
            return False
        self._delivered_out_of_order.add(seq)
        self._rebuild_bitmap()
        return True

    def _rebuild_bitmap(self) -> None:
        self.sack_bitmap = 0
        for seq in self._delivered_out_of_order:
            bit = ((seq - self.highest_contiguous - 1) & 0xFFFFFFFF)
            if 0 <= bit < SACK_WINDOW:
                self.sack_bitmap |= (1 << bit)

    def ack_snapshot(self) -> tuple[int, int]:
        """(highest_contiguous, sack_bitmap) for next outgoing ACK."""
        return (self.highest_contiguous, self.sack_bitmap)
