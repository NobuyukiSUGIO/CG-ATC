"""Unit tests for `cgatc.containment` (paper §III-H)."""

from __future__ import annotations

import unittest

from cgatc.containment import (
    ActionDescriptor,
    ContainmentThresholds,
    HighRiskAction,
    HighRiskAuthorizer,
    ImpactGraph,
    ScopeReducer,
    radius_for_level,
    restrict_scopes,
)
from cgatc.core.types import AgentID, ContainmentLevel
from cgatc.crypto import generate_keypair, select_committee, vrf_eval, vrf_verify
from cgatc.crypto.threshold import MultiSigThresholdAuthority


class TestScopeReducer(unittest.TestCase):
    def test_monotonic_levels(self) -> None:
        sr = ScopeReducer(ContainmentThresholds(1.0, 2.0, 3.0, 4.0))
        levels = [sr.level_for(r) for r in (0, 0.5, 1.5, 2.4, 2.6, 3.4, 3.6, 4.5, 8.5)]
        for a, b in zip(levels, levels[1:]):
            self.assertLessEqual(int(a), int(b))

    def test_evaluate_only_escalates(self) -> None:
        sr = ScopeReducer()
        a = AgentID(b"\x01" * 32)
        sr.evaluate(a, 5.0)
        self.assertNotEqual(sr.current(a), ContainmentLevel.NORMAL)
        # Lower risk does NOT lower level
        sr.evaluate(a, 0.0)
        self.assertNotEqual(sr.current(a), ContainmentLevel.NORMAL)

    def test_restrict_scopes_strips_high_risk(self) -> None:
        scopes = ["tools.high_risk.send_email", "tools.search.read", "delegate.subagent"]
        out = restrict_scopes(scopes, ContainmentLevel.HIGH_RISK_TOOLS_DISABLED)
        self.assertNotIn("tools.high_risk.send_email", out)
        self.assertIn("tools.search.read", out)

    def test_restrict_scopes_read_only(self) -> None:
        scopes = ["tools.read", "tools.write"]
        out = restrict_scopes(scopes, ContainmentLevel.READ_ONLY)
        self.assertEqual(out, ["tools.read"])

    def test_restrict_scopes_isolated(self) -> None:
        self.assertEqual(restrict_scopes(["x.read", "y"], ContainmentLevel.NETWORK_ISOLATED), [])


class TestImpactGraph(unittest.TestCase):
    def test_bfs_radius(self) -> None:
        g = ImpactGraph()
        a = AgentID(b"\x01" * 32)
        b = AgentID(b"\x02" * 32)
        c = AgentID(b"\x03" * 32)
        d = AgentID(b"\x04" * 32)
        g.record_send(a, b)
        g.record_send(b, c)
        g.record_send(c, d)
        self.assertEqual(g.impact_set(a, max_radius=1), {b})
        self.assertEqual(g.impact_set(a, max_radius=2), {b, c})
        self.assertEqual(g.impact_set(a, max_radius=3), {b, c, d})
        self.assertEqual(g.impact_set(a, max_radius=0), set())

    def test_radius_for_level(self) -> None:
        self.assertGreater(radius_for_level(ContainmentLevel.NORMAL), 0)
        self.assertEqual(radius_for_level(ContainmentLevel.NETWORK_ISOLATED), 0)
        self.assertLess(
            radius_for_level(ContainmentLevel.DELEGATION_PROHIBITED),
            radius_for_level(ContainmentLevel.NORMAL),
        )


class TestThresholdAuthorityBasic(unittest.TestCase):
    def test_kofn_round_trip(self) -> None:
        signers = [generate_keypair() for _ in range(5)]
        authority = MultiSigThresholdAuthority(
            k=3, signer_pubkeys=[s.public_key for s in signers]
        )
        action = b"action: send_email | dest: alice@example.com"
        shares = [authority.make_share(i, signers[i], action) for i in (0, 2, 4)]
        signed = authority.authorize(action, shares)
        self.assertTrue(authority.verify(signed))


class TestHighRiskAuthorizer(unittest.TestCase):
    def test_authorize_email_action(self) -> None:
        signers = [generate_keypair() for _ in range(3)]
        authz = HighRiskAuthorizer.with_signers(
            k=2, signer_pubkeys=[s.public_key for s in signers]
        )
        action = ActionDescriptor(kind=HighRiskAction.SEND_EMAIL, target="ops@example.com")
        shares = [
            authz.authority.make_share(i, signers[i], action.encode())  # type: ignore[attr-defined]
            for i in (0, 1)
        ]
        signed = authz.authority.authorize(action.encode(), shares)
        authz.gate(action, signed)  # must not raise


class TestVRF(unittest.TestCase):
    def test_eval_and_verify(self) -> None:
        kp = generate_keypair()
        seed = b"taskID|epoch=42"
        out, proof = vrf_eval(seed, kp)
        self.assertTrue(vrf_verify(seed, out, proof, kp.public_key))

    def test_verify_rejects_wrong_pubkey(self) -> None:
        kp = generate_keypair()
        kp2 = generate_keypair()
        out, proof = vrf_eval(b"x", kp)
        self.assertFalse(vrf_verify(b"x", out, proof, kp2.public_key))

    def test_committee_is_deterministic(self) -> None:
        kp = generate_keypair()
        c1, _, _ = select_committee(b"seed", kp, n_candidates=10, k_committee=3)
        c2, _, _ = select_committee(b"seed", kp, n_candidates=10, k_committee=3)
        self.assertEqual(c1, c2)
        self.assertEqual(len(c1), 3)


if __name__ == "__main__":
    unittest.main()
