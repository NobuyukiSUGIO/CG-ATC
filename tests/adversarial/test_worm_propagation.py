"""Adversarial test: worm-style prompt propagation (paper §III-H-2).

A compromised agent attempts to propagate a malicious prompt to many
peers.  CG-ATC's `impact_radius` confines the spread.
"""

from __future__ import annotations

import unittest

from cgatc.containment import ImpactGraph, ScopeReducer, restrict_scopes
from cgatc.containment.impact_radius import radius_for_level
from cgatc.core.constants import TAU_4
from cgatc.core.types import AgentID, ContainmentLevel


class TestWormPropagation(unittest.TestCase):
    def test_radius_drops_when_isolated(self) -> None:
        sr = ScopeReducer()
        a = AgentID(b"\x01" * 32)
        # Drive risk way over τ_4 so the agent is isolated.
        sr.evaluate(a, TAU_4 * 3)
        level = sr.current(a)
        self.assertGreaterEqual(level, ContainmentLevel.NETWORK_ISOLATED)
        self.assertEqual(radius_for_level(level), 0)

    def test_propagation_bounded_by_radius(self) -> None:
        # 50 peers, malicious agent talks to all of them, but the impact
        # graph is queried with radius 0 once isolated.
        ag = ImpactGraph()
        attacker = AgentID(b"\x00" * 32)
        peers = [AgentID(bytes([i + 1]) * 32) for i in range(50)]
        for p in peers:
            ag.record_send(attacker, p)
        # Within radius 1, attacker reaches all peers.
        self.assertEqual(ag.impact_set(attacker, max_radius=1), set(peers))
        # Once isolated (radius 0), no impact.
        self.assertEqual(ag.impact_set(attacker, max_radius=0), set())

    def test_isolated_agent_loses_all_scopes(self) -> None:
        scopes = ["tools.read", "tools.write", "delegate.subagent",
                  "tools.high_risk.email"]
        out = restrict_scopes(scopes, ContainmentLevel.NETWORK_ISOLATED)
        self.assertEqual(out, [])


if __name__ == "__main__":
    unittest.main()
