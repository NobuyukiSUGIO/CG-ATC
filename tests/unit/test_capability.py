"""Unit tests for `cgatc.capability` (paper §III-E)."""

from __future__ import annotations

import time
import unittest

from cgatc.capability import (
    ActionRequest,
    Constraints,
    Enforcer,
    PolicyAuthority,
    SignedCapability,
)
from cgatc.core.exceptions import (
    CapabilityAudienceError,
    CapabilityExpiredError,
    CapabilityScopeError,
    SignatureVerificationError,
)
from cgatc.core.types import AgentID, TaskID


def _alice_bob():  # type: ignore[no-untyped-def]
    return AgentID(b"\x01" * 32), AgentID(b"\x02" * 32)


class TestPolicyAuthorityIssue(unittest.TestCase):
    def test_issued_capability_is_self_consistent(self) -> None:
        a, b = _alice_bob()
        pa = PolicyAuthority(issuer_id="PA-1")
        cap = pa.issue(subject=a, audience=b, task_id=TaskID.random(), scopes=["tools.read"])
        # signature must verify under the PA pubkey embedded in the cap
        from cgatc.crypto.primitives import Verify
        self.assertTrue(Verify(cap.capability.digest(), cap.signature, cap.issuer_pubkey))

    def test_json_round_trip(self) -> None:
        a, b = _alice_bob()
        pa = PolicyAuthority()
        cap = pa.issue(subject=a, audience=b, task_id=TaskID.random(), scopes=["x"])
        again = SignedCapability.from_json(cap.to_json())
        self.assertEqual(again.capability.scopes, ["x"])


class TestEnforcer(unittest.TestCase):
    def setUp(self) -> None:
        self.alice, self.bob = _alice_bob()
        self.task = TaskID.random()
        self.pa = PolicyAuthority()
        self.enforcer = Enforcer(trusted_pa_pubkeys=[self.pa.public_key])

    def _cap(self, **overrides) -> SignedCapability:  # type: ignore[no-untyped-def]
        kwargs = {
            "subject": self.alice,
            "audience": self.bob,
            "task_id": self.task,
            "scopes": ["tools.search.read"],
            "constraints": Constraints(),
        }
        kwargs.update(overrides)
        return self.pa.issue(**kwargs)

    def test_allows_in_scope_request(self) -> None:
        cap = self._cap()
        req = ActionRequest(subject=self.alice, audience=self.bob,
                            task_id=self.task, scope="tools.search.read")
        self.enforcer.check(cap, req)  # must not raise

    def test_denies_out_of_scope_request(self) -> None:
        cap = self._cap()
        req = ActionRequest(subject=self.alice, audience=self.bob,
                            task_id=self.task, scope="tools.email.send")
        with self.assertRaises(CapabilityScopeError):
            self.enforcer.check(cap, req)

    def test_denies_wrong_audience(self) -> None:
        cap = self._cap()
        req = ActionRequest(subject=self.alice, audience=AgentID(b"\xff" * 32),
                            task_id=self.task, scope="tools.search.read")
        with self.assertRaises(CapabilityAudienceError):
            self.enforcer.check(cap, req)

    def test_denies_wrong_subject(self) -> None:
        cap = self._cap()
        req = ActionRequest(subject=AgentID(b"\xee" * 32), audience=self.bob,
                            task_id=self.task, scope="tools.search.read")
        with self.assertRaises(CapabilityAudienceError):
            self.enforcer.check(cap, req)

    def test_denies_wrong_task(self) -> None:
        cap = self._cap()
        req = ActionRequest(subject=self.alice, audience=self.bob,
                            task_id=TaskID.random(), scope="tools.search.read")
        with self.assertRaises(CapabilityScopeError):
            self.enforcer.check(cap, req)

    def test_denies_expired(self) -> None:
        cap = self.pa.issue(
            subject=self.alice, audience=self.bob, task_id=self.task,
            scopes=["x"], ttl_seconds=1, not_before=time.time() - 5,
        )
        req = ActionRequest(subject=self.alice, audience=self.bob,
                            task_id=self.task, scope="x")
        with self.assertRaises(CapabilityExpiredError):
            self.enforcer.check(cap, req)

    def test_denies_unknown_pa(self) -> None:
        evil_pa = PolicyAuthority()
        cap = evil_pa.issue(subject=self.alice, audience=self.bob,
                            task_id=self.task, scopes=["x"])
        req = ActionRequest(subject=self.alice, audience=self.bob,
                            task_id=self.task, scope="x")
        with self.assertRaises(SignatureVerificationError):
            self.enforcer.check(cap, req)

    def test_constraints_max_output_size(self) -> None:
        cap = self._cap(constraints=Constraints(max_output_size=100))
        req = ActionRequest(subject=self.alice, audience=self.bob, task_id=self.task,
                            scope="tools.search.read", estimated_output_size=200)
        with self.assertRaises(CapabilityScopeError):
            self.enforcer.check(cap, req)

    def test_constraints_external_tool_allowlist(self) -> None:
        cap = self._cap(constraints=Constraints(allowed_external_tools=["search-1"]))
        bad = ActionRequest(subject=self.alice, audience=self.bob, task_id=self.task,
                            scope="tools.search.read", invokes_external_tool="search-2")
        with self.assertRaises(CapabilityScopeError):
            self.enforcer.check(cap, bad)
        good = ActionRequest(subject=self.alice, audience=self.bob, task_id=self.task,
                             scope="tools.search.read", invokes_external_tool="search-1")
        self.enforcer.check(cap, good)

    def test_constraints_delegation(self) -> None:
        cap = self._cap(constraints=Constraints(delegation_permitted=False))
        req = ActionRequest(subject=self.alice, audience=self.bob, task_id=self.task,
                            scope="tools.search.read", is_delegation=True)
        with self.assertRaises(CapabilityScopeError):
            self.enforcer.check(cap, req)


if __name__ == "__main__":
    unittest.main()
