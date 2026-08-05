"""Unit tests for `cgatc.policy`."""

from __future__ import annotations

import unittest

from cgatc.capability import PolicyAuthority
from cgatc.containment.threshold_authz import HighRiskAction
from cgatc.core.exceptions import CapabilityScopeError
from cgatc.core.types import AgentID, TaskID
from cgatc.policy import PolicyEvaluator, load_policy


_DOC = {
    "version": 1,
    "roles": {
        "analyst": {
            "may_exercise": ["tools.search.*", "data.public.*"],
            "may_accept": ["tools.report.write"],
            "constraints": {
                "max_output_size": 16384,
                "allowed_external_tools": ["search-1", "search-2"],
                "delegation_permitted": False,
            },
            "high_risk_actions": ["financial_operation"],
            "containment": {"tau_1": 1.0, "tau_2": 2.5, "tau_3": 5.0, "tau_4": 10.0},
        },
        "report_writer": {
            "may_exercise": ["tools.report.write"],
            "may_accept": ["tools.search.*", "data.public.*"],
        },
    },
}


class TestPolicyDSL(unittest.TestCase):
    def test_parses_known_roles(self) -> None:
        p = load_policy(_DOC)
        self.assertIn("analyst", p.roles)
        self.assertIn("report_writer", p.roles)
        self.assertEqual(
            p.roles["analyst"].constraints.allowed_external_tools,
            ["search-1", "search-2"],
        )
        self.assertEqual(
            p.roles["analyst"].high_risk_actions,
            (HighRiskAction.FINANCIAL_OPERATION,),
        )

    def test_canonical_hash_stable(self) -> None:
        p1 = load_policy(_DOC)
        p2 = load_policy(_DOC)
        self.assertEqual(p1.hash(), p2.hash())

    def test_unknown_high_risk_action_raises(self) -> None:
        bad = {
            "version": 1,
            "roles": {"x": {"high_risk_actions": ["fake_action"]}},
        }
        with self.assertRaises(ValueError):
            load_policy(bad)


class TestPolicyEvaluator(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = load_policy(_DOC)
        self.pa = PolicyAuthority()
        self.eval = PolicyEvaluator(policy=self.policy, authority=self.pa)
        self.alice = AgentID(b"\x01" * 32)
        self.bob = AgentID(b"\x02" * 32)
        self.task = TaskID.random()

    def test_issue_intersection(self) -> None:
        cap = self.eval.issue_capability(
            sender_role="analyst",
            subject=self.alice, audience=self.bob, task_id=self.task,
            requested_scopes=["tools.search.read", "tools.email.send"],
        )
        self.assertEqual(cap.capability.scopes, ["tools.search.read"])

    def test_issue_empty_intersection_rejected(self) -> None:
        with self.assertRaises(CapabilityScopeError):
            self.eval.issue_capability(
                sender_role="analyst",
                subject=self.alice, audience=self.bob, task_id=self.task,
                requested_scopes=["tools.email.send"],
            )

    def test_is_acceptable(self) -> None:
        self.assertTrue(self.eval.is_acceptable("report_writer", "tools.search.read"))
        self.assertFalse(self.eval.is_acceptable("report_writer", "tools.email.send"))

    def test_high_risk_lookup(self) -> None:
        self.assertTrue(self.eval.is_high_risk("analyst", HighRiskAction.FINANCIAL_OPERATION))
        self.assertFalse(self.eval.is_high_risk("analyst", HighRiskAction.SEND_EMAIL))


if __name__ == "__main__":
    unittest.main()
