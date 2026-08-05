"""Unit tests for `cgatc.identity` (paper §III-C)."""

from __future__ import annotations

import time
import unittest

from cgatc.core.exceptions import AgentCardVerificationError, EnvironmentAttestationError
from cgatc.crypto.primitives import generate_keypair
from cgatc.identity import (
    EnvAttest,
    SignedCard,
    build_card,
    collect_local_env_attest,
    compute_agent_id,
    compute_env_hash,
    compute_model_hash,
    compute_policy_hash,
    sign_card,
    verify_card,
)


def _fresh_card_pair():  # type: ignore[no-untyped-def]
    kp = generate_keypair()
    env = collect_local_env_attest(image_digest="sha256:test")
    card = build_card(
        keypair=kp,
        model_hash=compute_model_hash("strands-agents/test-model:1.0"),
        policy_hash=compute_policy_hash({"ver": 1}),
        env_attest=env,
        skills=["chat", "summarize"],
        scopes=["task:read", "task:write"],
        auth={"scheme": "ed25519"},
        expiry=time.time() + 3600,
        issuer="self",
    )
    return kp, sign_card(card, kp)


class TestComputeAgentID(unittest.TestCase):
    def test_deterministic(self) -> None:
        pk = b"\xaa" * 32
        a = compute_agent_id(pk, b"\x01" * 32, b"\x02" * 32, b"\x03" * 32)
        b = compute_agent_id(pk, b"\x01" * 32, b"\x02" * 32, b"\x03" * 32)
        self.assertEqual(a, b)

    def test_changes_with_any_field(self) -> None:
        pk = b"\xaa" * 32
        base = compute_agent_id(pk, b"\x00" * 32, b"\x00" * 32, b"\x00" * 32)
        for delta in (
            (b"\xff" * 32, b"\x00" * 32, b"\x00" * 32),
            (b"\x00" * 32, b"\xff" * 32, b"\x00" * 32),
            (b"\x00" * 32, b"\x00" * 32, b"\xff" * 32),
        ):
            self.assertNotEqual(base, compute_agent_id(pk, *delta))

    def test_rejects_short_keys(self) -> None:
        with self.assertRaises(ValueError):
            compute_agent_id(b"x", b"\x00" * 32, b"\x00" * 32, b"\x00" * 32)
        with self.assertRaises(ValueError):
            compute_agent_id(b"\xaa" * 32, b"\x00" * 31, b"\x00" * 32, b"\x00" * 32)


class TestSignAndVerifyCard(unittest.TestCase):
    def test_round_trip(self) -> None:
        _kp, signed = _fresh_card_pair()
        # Should not raise
        verify_card(signed)

    def test_rejects_tampered_skills(self) -> None:
        kp, signed = _fresh_card_pair()
        bad = signed.card.model_copy(update={"skills": signed.card.skills + ["ROOT"]})
        with self.assertRaises(AgentCardVerificationError):
            verify_card(SignedCard(card=bad, signature_hex=signed.signature_hex))

    def test_rejects_expired(self) -> None:
        kp = generate_keypair()
        env = collect_local_env_attest()
        expired = build_card(
            keypair=kp,
            model_hash=compute_model_hash("m"),
            policy_hash=compute_policy_hash({"v": 1}),
            env_attest=env,
            expiry=time.time() - 5,  # already expired
        )
        signed = sign_card(expired, kp)
        with self.assertRaises(AgentCardVerificationError):
            verify_card(signed)

    def test_rejects_wrong_signature(self) -> None:
        _kp1, signed = _fresh_card_pair()
        kp2 = generate_keypair()
        # Re-sign with a different key but keep the original public_key in card.
        bad = sign_card(signed.card, kp2).model_copy(
            update={"signature_hex": sign_card(signed.card, kp2).signature_hex}
        )
        with self.assertRaises(AgentCardVerificationError):
            verify_card(bad)

    def test_attestation_failure_propagates(self) -> None:
        kp, signed = _fresh_card_pair()
        # Corrupt the env_attest claims so its hash no longer matches what
        # ID_i was computed against.
        corrupt_card = signed.card.model_copy(
            update={"env_attest": {"kind": "local", "claims": {"x": 1}, "evidence": ""}}
        )
        # Card signature is over the canonical bytes — so we have to re-sign.
        bad_signed = sign_card(corrupt_card, kp)
        with self.assertRaises((AgentCardVerificationError, EnvironmentAttestationError)):
            verify_card(bad_signed)


class TestSignedCardSerialization(unittest.TestCase):
    def test_json_round_trip(self) -> None:
        _kp, signed = _fresh_card_pair()
        raw = signed.to_json()
        reread = SignedCard.from_json(raw)
        verify_card(reread)


class TestEnvAttestation(unittest.TestCase):
    def test_local_attestation_round_trip(self) -> None:
        att = collect_local_env_attest()
        from cgatc.identity.attestation import verify_env_attest
        verify_env_attest(att, compute_env_hash(att))


if __name__ == "__main__":
    unittest.main()
