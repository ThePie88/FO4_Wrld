"""Tests for ReliableChannel — integration between protocol + reliable layers."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from protocol import (  # noqa: E402
    MessageType, HelloPayload, ChatPayload, PosStatePayload, AckPayload,
    encode_frame, decode_frame,
)
from channel import ReliableChannel, ChannelError  # noqa: E402


def _dummy_hello(client_id: str = "alice") -> HelloPayload:
    return HelloPayload(client_id=client_id, client_version_major=1, client_version_minor=0)


class TestUnreliablePath:
    def test_unreliable_send_decodes(self):
        ch = ReliableChannel()
        raw = ch.send_unreliable(MessageType.POS_STATE,
                                  PosStatePayload(1, 2, 3, 0, 0, 0, 0))
        frame = decode_frame(raw)
        assert frame.header.msg_type == MessageType.POS_STATE
        assert not frame.header.is_reliable

    def test_unreliable_seq_monotonic(self):
        ch = ReliableChannel()
        seqs = []
        for _ in range(5):
            raw = ch.send_unreliable(MessageType.POS_STATE,
                                      PosStatePayload(0, 0, 0, 0, 0, 0, 0))
            seqs.append(decode_frame(raw).header.seq)
        assert seqs == sorted(seqs)

    def test_unreliable_delivers(self):
        ch = ReliableChannel()
        raw = encode_frame(MessageType.POS_STATE, 99,
                            PosStatePayload(1, 2, 3, 0, 0, 0, 0),
                            reliable=False)
        delivered, ack = ch.on_receive(raw, now_ms=0)
        assert delivered is not None
        assert ack is None  # no ack for unreliable


class TestReliablePath:
    def test_reliable_send_flag_set(self):
        ch = ReliableChannel()
        raw = ch.send_reliable(MessageType.CHAT, ChatPayload("a", "hi"), now_ms=0)
        frame = decode_frame(raw)
        assert frame.header.is_reliable
        assert frame.header.seq >= 1

    def test_reliable_registers_in_flight(self):
        ch = ReliableChannel()
        ch.send_reliable(MessageType.CHAT, ChatPayload("a", "x"), now_ms=0)
        assert len(ch.send.in_flight) == 1

    def test_ack_clears_in_flight(self):
        sender = ReliableChannel()
        receiver = ReliableChannel()

        # Sender transmits reliable frame
        sent = sender.send_reliable(MessageType.CHAT, ChatPayload("a", "hi"), now_ms=0)
        assert len(sender.send.in_flight) == 1

        # Receiver processes it → delivers + (eventually) produces ACK
        delivered, _ = receiver.on_receive(sent, now_ms=1)
        assert delivered is not None

        # Force ACK emission by ticking past ACK_PERIOD_MS
        _, ack_raw = receiver.tick(now_ms=100)
        assert ack_raw is not None

        # Sender receives ACK → clears in-flight, ack frame does NOT deliver
        delivered2, _ = sender.on_receive(ack_raw, now_ms=100)
        assert delivered2 is None
        assert len(sender.send.in_flight) == 0

    def test_duplicate_reliable_not_delivered_twice(self):
        ch = ReliableChannel()
        raw = encode_frame(MessageType.CHAT, 1, ChatPayload("a", "x"), reliable=True)

        delivered1, _ = ch.on_receive(raw, now_ms=0)
        delivered2, _ = ch.on_receive(raw, now_ms=1)
        assert delivered1 is not None
        assert delivered2 is None   # duplicate dropped

    def test_retransmit_on_loss(self):
        sender = ReliableChannel()
        receiver = ReliableChannel()

        sent = sender.send_reliable(MessageType.CHAT, ChatPayload("a", "x"), now_ms=0)
        # Simulate loss: receiver never sees it.

        # Tick past RTO
        retrans, _ack = sender.tick(now_ms=400)
        assert len(retrans) == 1
        # Retransmitted bytes are identical (same frame)
        assert retrans[0] == sent

        # Now receiver gets it (retransmitted copy). ACK_PERIOD_MS has elapsed
        # since channel init, so on_receive emits the ACK immediately.
        delivered, ack_raw = receiver.on_receive(retrans[0], now_ms=401)
        assert delivered is not None
        assert ack_raw is not None

        sender.on_receive(ack_raw, now_ms=402)
        assert len(sender.send.in_flight) == 0

    def test_dead_channel_after_max_retransmits(self):
        sender = ReliableChannel()
        sender.send_reliable(MessageType.CHAT, ChatPayload("a", "x"), now_ms=0)

        t = 0.0
        # Big enough jumps to exceed backoff every time
        for _ in range(20):
            t += 10 * 60 * 1000   # 10 minutes per tick
            try:
                sender.tick(now_ms=t)
            except ChannelError:
                assert sender.dead is True
                return
        pytest.fail("expected ChannelError after max retransmits")


class TestAckPolicy:
    def test_ack_batched_after_N_frames(self):
        ch = ReliableChannel()
        # Send ACK_BATCH reliable frames to ch
        for i in range(1, ch.ACK_BATCH + 1):
            raw = encode_frame(MessageType.CHAT, i, ChatPayload("a", f"m{i}"), reliable=True)
            _, ack = ch.on_receive(raw, now_ms=float(i))
            if i == ch.ACK_BATCH:
                assert ack is not None   # batch threshold → emit
            else:
                assert ack is None

    def test_ack_emitted_on_tick_after_period(self):
        ch = ReliableChannel()
        raw = encode_frame(MessageType.CHAT, 1, ChatPayload("a", "x"), reliable=True)
        _, ack = ch.on_receive(raw, now_ms=0)   # unacked, below batch
        assert ack is None

        # Wait past ACK_PERIOD_MS, tick → ack emitted
        _, ack = ch.tick(now_ms=ch.ACK_PERIOD_MS + 1)
        assert ack is not None


class TestRoundtripPair:
    def test_full_conversation(self):
        """Simulate a client + server pair exchanging messages with losses."""
        client = ReliableChannel()
        server = ReliableChannel()

        # Client sends HELLO (reliable)
        hello = client.send_reliable(MessageType.HELLO, _dummy_hello(), now_ms=0)
        delivered, _ = server.on_receive(hello, now_ms=1)
        assert delivered is not None
        assert delivered.header.msg_type == MessageType.HELLO

        # Server acks
        ack_due = 60.0
        _, ack = server.tick(now_ms=ack_due)
        assert ack is not None
        client.on_receive(ack, now_ms=ack_due + 1)
        assert len(client.send.in_flight) == 0

        # Client sends 3 position updates (unreliable). Second one is "lost".
        pos1 = client.send_unreliable(MessageType.POS_STATE,
                                       PosStatePayload(1, 2, 3, 0, 0, 0, 100))
        pos2 = client.send_unreliable(MessageType.POS_STATE,
                                       PosStatePayload(4, 5, 6, 0, 0, 0, 200))
        pos3 = client.send_unreliable(MessageType.POS_STATE,
                                       PosStatePayload(7, 8, 9, 0, 0, 0, 300))
        # pos2 dropped
        d1, _ = server.on_receive(pos1, now_ms=100)
        d3, _ = server.on_receive(pos3, now_ms=300)
        assert d1 is not None and d3 is not None
        # unreliable: no retransmit, no ack, loss silently absorbed

        # Client sends CHAT (reliable); first attempt lost
        chat_raw = client.send_reliable(MessageType.CHAT,
                                         ChatPayload("alice", "anyone there?"),
                                         now_ms=400)
        # Tick past RTO -> retransmit
        retrans, _ = client.tick(now_ms=800)
        assert len(retrans) == 1

        # Server receives retransmit; on_receive emits ACK since ACK_PERIOD passed
        delivered, ack = server.on_receive(retrans[0], now_ms=801)
        assert delivered is not None
        assert delivered.payload.text == "anyone there?"
        assert ack is not None

        client.on_receive(ack, now_ms=802)
        assert len(client.send.in_flight) == 0
