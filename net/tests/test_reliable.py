"""Tests per net/reliable.py: RTT estimator, SendWindow, ReceiveWindow.

Simulate wall-clock with monotonically increasing `now_ms` floats — no real sleep.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from reliable import (  # noqa: E402
    INITIAL_RTO_MS, MIN_RTO_MS, MAX_RTO_MS, SACK_WINDOW, MAX_RETRANSMITS,
    RttEstimator, SendWindow, ReceiveWindow, _seq_leq,
)


# ------------------------------------------------------------------ RTT

class TestRttEstimator:
    def test_bootstrap_uses_first_sample(self):
        r = RttEstimator()
        r.observe(200.0)
        assert r.srtt_ms == 200.0
        assert r.rttvar_ms == 100.0

    def test_rto_default_before_samples(self):
        r = RttEstimator()
        assert r.rto_ms == INITIAL_RTO_MS

    def test_rto_clamped_to_min(self):
        r = RttEstimator()
        for _ in range(20):
            r.observe(1.0)
        assert r.rto_ms >= MIN_RTO_MS

    def test_rto_clamped_to_max(self):
        r = RttEstimator()
        r.observe(10_000.0)
        assert r.rto_ms <= MAX_RTO_MS

    def test_stable_rtt_converges(self):
        r = RttEstimator()
        for _ in range(100):
            r.observe(150.0)
        # After 100 samples at 150ms, srtt should be ~150
        assert 145 < r.srtt_ms < 155

    def test_noisy_rtt_increases_rttvar(self):
        r = RttEstimator()
        samples = [100.0, 300.0, 100.0, 300.0] * 10
        for s in samples:
            r.observe(s)
        # variance is big -> RTO larger than bare srtt
        assert r.rto_ms > r.srtt_ms

    def test_ignores_nonpositive(self):
        r = RttEstimator()
        r.observe(-5.0)
        r.observe(0)
        assert r.srtt_ms is None


# ------------------------------------------------------------------ seq compare

class TestSeqCompare:
    def test_basic(self):
        assert _seq_leq(5, 10)
        assert not _seq_leq(10, 5)
        assert _seq_leq(5, 5)

    def test_wraparound(self):
        # Near the u32 boundary, wrap should still compare correctly
        assert _seq_leq(0xFFFFFFF0, 0xFFFFFFFF)
        assert _seq_leq(0xFFFFFFFF, 1)   # wrap: 1 is "after" 0xFFFFFFFF
        assert not _seq_leq(1, 0xFFFFFFFF)


# ------------------------------------------------------------------ SendWindow

class TestSendWindow:
    def test_allocate_seq_monotonic(self):
        w = SendWindow()
        s1 = w.allocate_seq()
        s2 = w.allocate_seq()
        s3 = w.allocate_seq()
        assert s1 == 1 and s2 == 2 and s3 == 3

    def test_allocate_seq_skips_zero_on_wrap(self):
        w = SendWindow(next_seq=0xFFFFFFFF)
        s1 = w.allocate_seq()  # 0xFFFFFFFF
        s2 = w.allocate_seq()  # wraps to 1, not 0
        assert s1 == 0xFFFFFFFF
        assert s2 == 1

    def test_register_and_ack_contiguous(self):
        w = SendWindow()
        w.register_sent(1, b"payload1", now_ms=1000)
        w.register_sent(2, b"payload2", now_ms=1010)
        w.register_sent(3, b"payload3", now_ms=1020)

        acked = w.on_ack(highest_contiguous=3, sack_bitmap=0, now_ms=1100)
        assert sorted(acked) == [1, 2, 3]
        assert len(w.in_flight) == 0
        # RTT observed from first send
        assert w.rtt.srtt_ms is not None

    def test_ack_with_sack_bitmap(self):
        w = SendWindow()
        for i in range(1, 6):
            w.register_sent(i, f"p{i}".encode(), now_ms=1000 + i)

        # Ack: contiguous up to 1, sack bits for 3 and 5 (bits 1 and 3 after contig)
        # bit 1 => seq 1+1+1=3, bit 3 => seq 1+3+1=5
        sack = (1 << 1) | (1 << 3)
        acked = w.on_ack(highest_contiguous=1, sack_bitmap=sack, now_ms=1100)

        assert sorted(acked) == [1, 3, 5]
        # 2 and 4 still in flight
        assert set(w.in_flight.keys()) == {2, 4}

    def test_retransmit_triggers_after_rto(self):
        w = SendWindow()
        # No RTT samples yet => RTO = 300ms
        w.register_sent(1, b"p1", now_ms=0)
        # Before RTO: nothing due
        assert w.due_for_retransmit(now_ms=200) == []
        # After RTO: due
        due = w.due_for_retransmit(now_ms=350)
        assert len(due) == 1
        assert due[0].seq == 1

    def test_exponential_backoff(self):
        w = SendWindow()
        w.register_sent(1, b"p1", now_ms=0)

        # First retransmit at ~300ms
        due = w.due_for_retransmit(now_ms=350)
        assert len(due) == 1
        alive = w.mark_retransmitted(1, now_ms=350)
        assert alive is True

        # Second retransmit should need 2x RTO (600ms) after last_sent
        assert w.due_for_retransmit(now_ms=400) == []
        assert w.due_for_retransmit(now_ms=600) == []
        due = w.due_for_retransmit(now_ms=950)
        assert len(due) == 1

    def test_max_retransmits_drops_frame(self):
        """Time jumps must exceed exponentially-growing RTO each iteration."""
        w = SendWindow()
        w.register_sent(1, b"p1", now_ms=0)
        # Big increment: exceeds MAX_RTO_MS * 2^MAX_RETRANSMITS comfortably
        big_jump = 10 * 60 * 1000  # 10 min per step — always > any backoff
        t = 0.0
        for _ in range(MAX_RETRANSMITS):
            t += big_jump
            due = w.due_for_retransmit(now_ms=t)
            assert len(due) == 1
            alive = w.mark_retransmitted(1, now_ms=t)
            assert alive is True
        # Next retransmit attempt exceeds the cap
        t += big_jump
        due = w.due_for_retransmit(now_ms=t)
        assert len(due) == 1
        alive = w.mark_retransmitted(1, now_ms=t)
        assert alive is False
        assert 1 not in w.in_flight

    def test_karn_algorithm_ignores_retransmitted_rtt(self):
        """Retransmitted frames don't contribute RTT samples."""
        w = SendWindow()
        w.register_sent(1, b"p1", now_ms=0)
        w.mark_retransmitted(1, now_ms=350)
        # Now ack at 500 — RTT would be 500ms from first send, but retransmitted
        w.on_ack(highest_contiguous=1, sack_bitmap=0, now_ms=500)
        # No RTT sample recorded
        assert w.rtt.srtt_ms is None


# ------------------------------------------------------------------ ReceiveWindow

class TestReceiveWindow:
    def test_in_order_delivery(self):
        r = ReceiveWindow()
        assert r.on_receive(1) is True
        assert r.on_receive(2) is True
        assert r.on_receive(3) is True
        h, b = r.ack_snapshot()
        assert h == 3 and b == 0

    def test_duplicate_rejected(self):
        r = ReceiveWindow()
        r.on_receive(1)
        r.on_receive(2)
        assert r.on_receive(2) is False   # dup
        assert r.on_receive(1) is False   # dup
        h, _ = r.ack_snapshot()
        assert h == 2

    def test_out_of_order_with_bitmap(self):
        r = ReceiveWindow()
        assert r.on_receive(1) is True
        # Skip 2, get 3
        assert r.on_receive(3) is True
        h, b = r.ack_snapshot()
        assert h == 1
        assert b == (1 << 1)   # bit 1 => seq 3 (h+1+1)

        # Now get 4, still no 2
        assert r.on_receive(4) is True
        h, b = r.ack_snapshot()
        assert h == 1
        assert b == (1 << 1) | (1 << 2)

        # Finally 2 arrives; contiguous advances through 3, 4
        assert r.on_receive(2) is True
        h, b = r.ack_snapshot()
        assert h == 4 and b == 0

    def test_out_of_window_ignored(self):
        r = ReceiveWindow()
        r.on_receive(1)
        # Try seq far beyond SACK_WINDOW
        far = 1 + SACK_WINDOW + 10
        assert r.on_receive(far) is False
        h, _ = r.ack_snapshot()
        assert h == 1

    def test_multiple_gaps_filled(self):
        r = ReceiveWindow()
        r.on_receive(1)
        # 2,3 missing. Get 4,5
        r.on_receive(4)
        r.on_receive(5)
        h, b = r.ack_snapshot()
        assert h == 1
        # bits 2 and 3 set
        assert b == (1 << 2) | (1 << 3)

        # Fill 2
        r.on_receive(2)
        h, b = r.ack_snapshot()
        # h advances to 2. 4, 5 still OOO.
        assert h == 2
        assert b == (1 << 1) | (1 << 2)  # bits for 4,5 relative to new h=2

        # Fill 3
        r.on_receive(3)
        h, b = r.ack_snapshot()
        # h=5 (advances through 4,5), bitmap empty
        assert h == 5 and b == 0


# ------------------------------------------------------------------ end-to-end simulation

class TestSendRecvIntegration:
    def test_normal_delivery_cycle(self):
        """Simulate: sender sends 3 reliable frames, receiver ACKs, sender clears."""
        snd = SendWindow()
        rcv = ReceiveWindow()

        # Sender sends seq 1,2,3
        for seq in range(1, 4):
            snd.register_sent(seq, f"p{seq}".encode(), now_ms=1000 + seq)
            # Over-network delivery: receiver gets it
            assert rcv.on_receive(seq) is True

        # Receiver sends ACK
        h, b = rcv.ack_snapshot()
        assert h == 3 and b == 0

        # Sender processes ACK
        acked = snd.on_ack(h, b, now_ms=1100)
        assert sorted(acked) == [1, 2, 3]
        assert len(snd.in_flight) == 0

    def test_loss_and_retransmit(self):
        """Simulate: seq 2 is lost, sender retransmits after RTO."""
        snd = SendWindow()
        rcv = ReceiveWindow()

        for seq in range(1, 4):
            snd.register_sent(seq, f"p{seq}".encode(), now_ms=seq)
        # 1 arrives, 2 lost, 3 arrives
        rcv.on_receive(1)
        rcv.on_receive(3)
        # Ack with bitmap for 3
        h, b = rcv.ack_snapshot()
        assert h == 1 and b == (1 << 1)

        # Sender gets ACK: 1 and 3 cleared, 2 still in flight
        snd.on_ack(h, b, now_ms=50)
        assert set(snd.in_flight.keys()) == {2}

        # Retransmit after RTO
        due = snd.due_for_retransmit(now_ms=500)
        assert len(due) == 1 and due[0].seq == 2
        snd.mark_retransmitted(2, now_ms=500)

        # This time 2 arrives
        rcv.on_receive(2)
        h, b = rcv.ack_snapshot()
        assert h == 3 and b == 0

        snd.on_ack(h, b, now_ms=600)
        assert len(snd.in_flight) == 0
