"""Adversarial test: secret collusion among agents (paper §III-G).

Two compromised agents (Mallory and Eve) collude:

  1. Eve repeatedly *amplifies* Mallory's outputs into a third-party
     receiver (Bob).  CG-ATC's behavioural detector should flag
     `SUSPICIOUS_AMPLIFICATION` once Eve's source-risk crosses the
     threshold.
  2. They mutually reinforce a false claim: 3+ agents endorsing the
     same statement triggers `MUTUAL_REINFORCEMENT`.

Cryptographic-only checks (Theorem 1, 3) cannot stop authenticated
collusion; this test exercises the layered defence — behavioural
detection + risk score + scope reduction (paper §III-H).
"""

from __future__ import annotations

import unittest

from cgatc.containment import ScopeReducer
from cgatc.core.constants import TAU_1
from cgatc.core.types import AgentID, ContainmentLevel
from cgatc.detection import (
    BehavioralAnomalyKind,
    BehavioralDetector,
    RiskScoreUpdater,
    RiskWeights,
)


class TestSecretCollusion(unittest.TestCase):
    def test_amplification_of_high_risk_source_flagged(self) -> None:
        det = BehavioralDetector()
        eve = AgentID(b"\x0e" * 32)
        mallory = AgentID(b"\x0a" * 32)

        # Eve amplifies Mallory's output 3 times; Mallory's risk is high.
        det.observe_amplification(eve, mallory, source_risk=0.8)
        det.observe_amplification(eve, mallory, source_risk=0.8)
        anomaly = det.observe_amplification(eve, mallory, source_risk=0.8)

        self.assertIsNotNone(anomaly)
        assert anomaly is not None
        self.assertEqual(anomaly.kind, BehavioralAnomalyKind.SUSPICIOUS_AMPLIFICATION)

    def test_mutual_reinforcement_flagged(self) -> None:
        det = BehavioralDetector()
        ringleader = AgentID(b"\x0f" * 32)
        # Three peers all "agree" with ringleader's claim.
        anomaly = det.observe_mutual_claim(ringleader, peer_agreement_count=3)
        self.assertIsNotNone(anomaly)
        assert anomaly is not None
        self.assertEqual(anomaly.kind, BehavioralAnomalyKind.MUTUAL_REINFORCEMENT)

    def test_collusion_eventually_triggers_containment(self) -> None:
        """Even though every individual message is cryptographically valid,
        repeated suspicious behaviour pushes risk over τ_1 → INCREASED_MONITORING."""

        risk = RiskScoreUpdater(RiskWeights(
            lambda_decay=0.95, alpha_crypto=1.0, beta_behavior=1.0,
            gamma_policy=1.0, delta_downstream=1.0,
        ))
        scope = ScopeReducer()
        agent = AgentID(b"\x10" * 32)

        # Six high-severity behavioural anomalies in a row.
        for _ in range(6):
            risk.add_behavior(agent, 0.9)
            r = risk.tick(agent)
        level = scope.evaluate(agent, r)
        self.assertGreaterEqual(level, ContainmentLevel.INCREASED_MONITORING)
        self.assertGreater(r, TAU_1)


if __name__ == "__main__":
    unittest.main()
