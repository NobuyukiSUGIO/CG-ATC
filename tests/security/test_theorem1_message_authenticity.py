"""Theorem 1 — Message Authenticity (paper §III-D-1).

Statement (paraphrased): if the digital signature scheme is EUF-CMA
secure, then no probabilistic polynomial-time adversary can forge a
valid A2A message on behalf of an uncompromised agent except with
negligible probability.

Operationalisation in this test:

    The adversary may
        * see arbitrary signed envelopes from Alice,
        * pick any payload, headers, sequence numbers,
        * but does NOT know Alice's secret key.

    For ANY envelope/signature pair the adversary can produce,
    `verify_envelope` MUST reject it (returning False or raising).

We do not attempt to *break* Ed25519; we test the integration:
that we never inadvertently provide an oracle that returns a valid
envelope without the secret key.
"""

from __future__ import annotations

import os
import secrets
import unittest

from cgatc.core.exceptions import EnvelopeError, SignatureVerificationError
from cgatc.core.types import AgentID, MessageType, SessionID, TaskID
from cgatc.crypto.primitives import generate_keypair
from cgatc.messaging import build_envelope, sign_envelope, verify_envelope


def _alice():  # type: ignore[no-untyped-def]
    return generate_keypair(), AgentID(b"\xa1" * 32), AgentID(b"\xb0" * 32)


class TestForgeryWithoutKey(unittest.TestCase):
    """Property: any envelope fabricated without Alice's sk fails verification."""

    def test_random_signatures_never_verify(self) -> None:
        alice_kp, alice_id, bob_id = _alice()
        for _ in range(200):  # 200 random "forgeries"
            payload = os.urandom(32)
            env = build_envelope(
                session_id=SessionID.random(),
                task_id=TaskID.random(),
                seq=secrets.randbelow(10),
                sender_id=alice_id, receiver_id=bob_id,
                msg_type=MessageType.REQUEST, payload=payload,
            )
            forged_sig_hex = secrets.token_bytes(64).hex()
            from cgatc.messaging.envelope import SignedEnvelope
            signed = SignedEnvelope(envelope=env, signature_hex=forged_sig_hex)
            with self.assertRaises((SignatureVerificationError, EnvelopeError)):
                verify_envelope(signed, sender_pubkey=alice_kp.public_key, payload=payload)

    def test_using_other_keys_never_verifies_under_alice_pk(self) -> None:
        alice_kp, alice_id, bob_id = _alice()
        for _ in range(200):
            payload = os.urandom(32)
            env = build_envelope(
                session_id=SessionID.random(),
                task_id=TaskID.random(),
                seq=secrets.randbelow(10),
                sender_id=alice_id, receiver_id=bob_id,
                msg_type=MessageType.REQUEST, payload=payload,
            )
            mallory_kp = generate_keypair()
            signed = sign_envelope(env, mallory_kp)
            with self.assertRaises((SignatureVerificationError, EnvelopeError)):
                verify_envelope(signed, sender_pubkey=alice_kp.public_key, payload=payload)


class TestTamperingInvalidatesSignature(unittest.TestCase):
    """Even if the adversary observes Alice's signed envelope, modifying
    *any* byte of the envelope must invalidate the signature."""

    def test_payload_tamper(self) -> None:
        alice_kp, alice_id, bob_id = _alice()
        signed = sign_envelope(
            build_envelope(
                session_id=SessionID.random(), task_id=TaskID.random(), seq=0,
                sender_id=alice_id, receiver_id=bob_id,
                msg_type=MessageType.REQUEST, payload=b"original",
            ),
            alice_kp,
        )
        with self.assertRaises(Exception):
            verify_envelope(signed, sender_pubkey=alice_kp.public_key, payload=b"TAMPER")

    def test_field_tamper(self) -> None:
        alice_kp, alice_id, bob_id = _alice()
        env = build_envelope(
            session_id=SessionID.random(), task_id=TaskID.random(), seq=0,
            sender_id=alice_id, receiver_id=bob_id,
            msg_type=MessageType.REQUEST, payload=b"x",
        )
        signed = sign_envelope(env, alice_kp)
        # Bump the seq under the original signature.
        from cgatc.messaging.envelope import Envelope, SignedEnvelope
        bumped = Envelope.model_validate({**env.model_dump(mode="json"), "seq": 999})
        bad = SignedEnvelope(envelope=bumped, signature_hex=signed.signature_hex)
        with self.assertRaises(SignatureVerificationError):
            verify_envelope(bad, sender_pubkey=alice_kp.public_key, payload=b"x")


if __name__ == "__main__":
    unittest.main()
