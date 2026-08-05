"""Unit tests for `cgatc.detection` (paper §III-G)."""

from __future__ import annotations

import unittest

from cgatc.core.exceptions import (
    ChainError,
    ReplayError,
    SignatureVerificationError,
)
from cgatc.core.types import AgentID
from cgatc.detection import (
    BehavioralAnomalyKind,
    BehavioralDetector,
    CryptoViolationKind,
    RiskScoreUpdater,
    RiskWeights,
    classify_exception,
)


class TestCryptoDetector(unittest.TestCase):
    def test_signature_failure_classified(self) -> None:
        v = classify_exception(SignatureVerificationError("x"))
        self.assertIsNotNone(v)
        assert v is not None
        self.assertEqual(v.kind, CryptoViolationKind.INVALID_SIGNATURE)

    def test_chain_failure_classified(self) -> None:
        v = classify_exception(ChainError("x"))
        assert v is not None
        self.assertEqual(v.kind, CryptoViolationKind.INCONSISTENT_SEQUENCE)

    def test_replay_failure_classified(self) -> None:
        v = classify_exception(ReplayError("x"))
        assert v is not None
        self.assertEqual(v.kind, CryptoViolationKind.NONCE_REUSE)

    def test_unknown_exception_returns_none(self) -> None:
        self.assertIsNone(classify_exception(ValueError("x")))


class TestBehavioralDetector(unittest.TestCase):
    def test_delegation_spike_fires(self) -> None:
        det = BehavioralDetector(delegation_per_min_threshold=2)
        a = AgentID(b"\x01" * 32)
        self.assertIsNone(det.observe_delegation(a, when=0.0))
        self.assertIsNone(det.observe_delegation(a, when=1.0))
        anomaly = det.observe_delegation(a, when=2.0)
        self.assertIsNotNone(anomaly)
        assert anomaly is not None
        self.assertEqual(anomaly.kind, BehavioralAnomalyKind.DELEGATION_SPIKE)

    def test_card_churn(self) -> None:
        det = BehavioralDetector()
        a = AgentID(b"\x02" * 32)
        det.observe_card_change(a, b"\x00" * 32)
        flag = det.observe_card_change(a, b"\x01" * 32)
        self.assertIsNotNone(flag)
        assert flag is not None
        self.assertEqual(flag.kind, BehavioralAnomalyKind.AGENT_CARD_CHURN)


class TestRiskScore(unittest.TestCase):
    def test_recurrence_basic(self) -> None:
        # R_{t+1} = λR + αC + βB + γP + δD
        upd = RiskScoreUpdater(RiskWeights(
            lambda_decay=0.5, alpha_crypto=2.0, beta_behavior=1.0,
            gamma_policy=1.0, delta_downstream=1.0,
        ))
        a = AgentID(b"\x03" * 32)
        upd.add_crypto(a, 1.0)        # +2*1.0=2
        upd.add_behavior(a, 0.5)      # +1*0.5=0.5
        # initial risk = 0
        r1 = upd.tick(a)
        self.assertAlmostEqual(r1, 0.0 * 0.5 + 2.0 + 0.5)

        # No new contributions: risk decays by λ.
        r2 = upd.tick(a)
        self.assertAlmostEqual(r2, r1 * 0.5)

    def test_weights_validation(self) -> None:
        with self.assertRaises(ValueError):
            RiskWeights(lambda_decay=-0.1)
        with self.assertRaises(ValueError):
            RiskWeights(lambda_decay=1.1)
        with self.assertRaises(ValueError):
            RiskWeights(alpha_crypto=-1.0)


if __name__ == "__main__":
    unittest.main()
