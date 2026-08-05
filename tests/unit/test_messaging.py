"""Unit tests for `cgatc.messaging` (paper §III-D)."""

from __future__ import annotations

import time
import unittest

from cgatc.core.constants import GENESIS_PREV_HASH
from cgatc.core.exceptions import (
    ChainError,
    EnvelopeError,
    HashMismatchError,
    ReplayError,
    SequenceError,
    SignatureVerificationError,
    StaleTimestampError,
)
from cgatc.core.types import AgentID, MessageType, SessionID, TaskID
from cgatc.crypto.primitives import generate_keypair
from cgatc.messaging import (
    ReplayGuard,
    SessionChainTracker,
    SignedEnvelope,
    build_envelope,
    sign_envelope,
    verify_envelope,
)


def _alice_bob():  # type: ignore[no-untyped-def]
    kp_a = generate_keypair()
    kp_b = generate_keypair()
    a = AgentID(b"\x01" * 32)
    b = AgentID(b"\x02" * 32)
    return (kp_a, a, kp_b, b)


def _send(session, task, seq, sender, receiver, payload, sk, prev_hash=GENESIS_PREV_HASH):  # type: ignore[no-untyped-def]
    env = build_envelope(
        session_id=session, task_id=task, seq=seq,
        sender_id=sender, receiver_id=receiver,
        msg_type=MessageType.REQUEST, payload=payload, prev_hash=prev_hash,
    )
    return sign_envelope(env, sk)


class TestEnvelopeRoundTrip(unittest.TestCase):
    def test_sign_verify_round_trip(self) -> None:
        kp_a, a, _kp_b, b = _alice_bob()
        s, t = SessionID.random(), TaskID.random()
        signed = _send(s, t, 0, a, b, b"payload", kp_a)
        verify_envelope(signed, sender_pubkey=kp_a.public_key, payload=b"payload",
                        expected_receiver=b)

    def test_json_round_trip(self) -> None:
        kp_a, a, _kp_b, b = _alice_bob()
        signed = _send(SessionID.random(), TaskID.random(), 0, a, b, b"x", kp_a)
        round_trip = SignedEnvelope.from_json(signed.to_json())
        verify_envelope(round_trip, sender_pubkey=kp_a.public_key, payload=b"x")


class TestEnvelopeRejection(unittest.TestCase):
    def test_rejects_wrong_signer(self) -> None:
        kp_a, a, kp_b, b = _alice_bob()
        signed = _send(SessionID.random(), TaskID.random(), 0, a, b, b"x", kp_a)
        with self.assertRaises(SignatureVerificationError):
            verify_envelope(signed, sender_pubkey=kp_b.public_key, payload=b"x")

    def test_rejects_payload_tamper(self) -> None:
        kp_a, a, _kp_b, b = _alice_bob()
        signed = _send(SessionID.random(), TaskID.random(), 0, a, b, b"good", kp_a)
        with self.assertRaises(HashMismatchError):
            verify_envelope(signed, sender_pubkey=kp_a.public_key, payload=b"BAD")

    def test_rejects_stale_timestamp(self) -> None:
        kp_a, a, _kp_b, b = _alice_bob()
        env = build_envelope(
            session_id=SessionID.random(), task_id=TaskID.random(), seq=0,
            sender_id=a, receiver_id=b, msg_type=MessageType.REQUEST,
            payload=b"x", timestamp=time.time() - 10_000,
        )
        signed = sign_envelope(env, kp_a)
        with self.assertRaises(StaleTimestampError):
            verify_envelope(signed, sender_pubkey=kp_a.public_key, payload=b"x")

    def test_rejects_wrong_receiver(self) -> None:
        kp_a, a, _kp_b, b = _alice_bob()
        signed = _send(SessionID.random(), TaskID.random(), 0, a, b, b"x", kp_a)
        with self.assertRaises(EnvelopeError):
            verify_envelope(signed, sender_pubkey=kp_a.public_key, payload=b"x",
                            expected_receiver=AgentID(b"\xff" * 32))


class TestSessionChainTracker(unittest.TestCase):
    def test_chain_advances_on_valid_sequence(self) -> None:
        kp_a, a, _kp_b, b = _alice_bob()
        s, t = SessionID.random(), TaskID.random()
        tracker = SessionChainTracker()

        m1 = _send(s, t, 0, a, b, b"hi", kp_a, prev_hash=GENESIS_PREV_HASH)
        verify_envelope(m1, sender_pubkey=kp_a.public_key, payload=b"hi")
        tracker.accept(m1)

        head = tracker.head(s, a)
        m2 = _send(s, t, 1, a, b, b"again", kp_a, prev_hash=head)
        verify_envelope(m2, sender_pubkey=kp_a.public_key, payload=b"again")
        tracker.accept(m2)
        self.assertEqual(tracker.seq(s, a), 1)

    def test_rejects_non_monotonic_seq(self) -> None:
        kp_a, a, _kp_b, b = _alice_bob()
        s, t = SessionID.random(), TaskID.random()
        tracker = SessionChainTracker()
        m0 = _send(s, t, 5, a, b, b"x", kp_a)
        tracker.accept(m0)
        m1 = _send(s, t, 4, a, b, b"y", kp_a, prev_hash=m0.envelope.digest())
        with self.assertRaises(SequenceError):
            tracker.accept(m1)

    def test_rejects_broken_prev_hash(self) -> None:
        kp_a, a, _kp_b, b = _alice_bob()
        s, t = SessionID.random(), TaskID.random()
        tracker = SessionChainTracker()
        m0 = _send(s, t, 0, a, b, b"x", kp_a)
        tracker.accept(m0)
        # Wrong prev_hash on the second message.
        m1 = _send(s, t, 1, a, b, b"y", kp_a, prev_hash=b"\xff" * 32)
        with self.assertRaises(ChainError):
            tracker.accept(m1)


class TestReplayGuard(unittest.TestCase):
    def test_rejects_duplicate_seq(self) -> None:
        kp_a, a, _kp_b, b = _alice_bob()
        s, t = SessionID.random(), TaskID.random()
        guard = ReplayGuard()
        m = _send(s, t, 0, a, b, b"x", kp_a)
        guard.check_and_record(m)
        with self.assertRaises(ReplayError):
            guard.check_and_record(m)


if __name__ == "__main__":
    unittest.main()
