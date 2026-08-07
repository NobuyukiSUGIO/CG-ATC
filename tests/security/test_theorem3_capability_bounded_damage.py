"""Theorem 3 — Capability-Bounded Containment (paper §III-E, §IV-C).

Statement (paraphrased): if capability tokens are unforgeable and every
protected resource enforces capability verification, then the direct
damage caused by a compromised agent A_i is bounded by the union of
scopes granted to A_i:

    Damage(A_i) ⊆ ⋃_{cap ∈ Caps_i} Scope(cap).

Operationalisation:

    For any action whose scope is OUTSIDE the union of granted scopes,
    `Enforcer.is_allowed(cap, request)` MUST return False — even if the
    adversary controls A_i's secret key (the capability is signed by the
    PA, not A_i, so the adversary cannot mint new capabilities).
"""

from __future__ import annotations

import secrets
import unittest

from cgatc.capability import (
    ActionRequest,
    Constraints,
    Enforcer,
    PolicyAuthority,
    SignedCapability,
)
from cgatc.core.types import AgentID, TaskID


class TestCapabilityBoundedDamage(unittest.TestCase):
    def setUp(self) -> None:
        self.pa = PolicyAuthority()
        self.enforcer = Enforcer(trusted_pa_pubkeys=[self.pa.public_key])
        self.alice = AgentID(b"\x01" * 32)
        self.bob = AgentID(b"\x02" * 32)
        self.task = TaskID.random()
        # Alice was granted exactly two scopes.
        self.granted = ["tools.search.read", "data.public.read"]
        self.cap = self.pa.issue(
            subject=self.alice, audience=self.bob, task_id=self.task,
            scopes=self.granted,
        )

    def test_in_scope_actions_allowed(self) -> None:
        for scope in self.granted:
            req = ActionRequest(subject=self.alice, audience=self.bob,
                                task_id=self.task, scope=scope)
            self.assertTrue(self.enforcer.is_allowed(self.cap, req))

    def test_arbitrary_out_of_scope_actions_denied(self) -> None:
        # Generate a large random sample of scope strings.  Any string that
        # isn't already in the granted list should be denied.
        for _ in range(500):
            scope = "_".join([
                secrets.token_hex(2) for _ in range(secrets.randbelow(4) + 1)
            ])
            if scope in self.granted:
                continue
            req = ActionRequest(subject=self.alice, audience=self.bob,
                                task_id=self.task, scope=scope)
            self.assertFalse(self.enforcer.is_allowed(self.cap, req),
                             msg=f"out-of-scope action accepted: {scope}")

    def test_compromised_agent_cannot_mint_capability(self) -> None:
        """The adversary holds Alice's sk but NOT the PA's sk.

        Therefore they cannot produce a capability signed by the PA over
        a different scope.  We simulate this by trying to swap in a
        capability with an inflated scope and verifying that the enforcer
        rejects it.
        """

        evil_pa = PolicyAuthority(issuer_id="EVIL")
        evil_cap = evil_pa.issue(subject=self.alice, audience=self.bob,
                                 task_id=self.task, scopes=["tools.email.send"])
        req = ActionRequest(subject=self.alice, audience=self.bob,
                            task_id=self.task, scope="tools.email.send")
        # Enforcer trusts only `self.pa`, not `evil_pa`.
        self.assertFalse(self.enforcer.is_allowed(evil_cap, req))

    def test_modified_scope_under_original_signature_rejected(self) -> None:
        """Tampering with the scopes list breaks the PA signature."""

        original = self.cap
        modified = original.capability.model_copy(
            update={"scopes": original.capability.scopes + ["tools.email.send"]}
        )
        bad = SignedCapability(
            capability=modified,
            issuer_pubkey_hex=original.issuer_pubkey_hex,
            signature_hex=original.signature_hex,
        )
        req = ActionRequest(subject=self.alice, audience=self.bob,
                            task_id=self.task, scope="tools.email.send")
        self.assertFalse(self.enforcer.is_allowed(bad, req))


if __name__ == "__main__":
    unittest.main()
