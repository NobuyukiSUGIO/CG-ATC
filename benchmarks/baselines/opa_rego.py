"""baseline_opa_rego — Rego-style policy enforcement (spec §2.5).

The spec allows prioritising testability by implementing a Rego-style policy
evaluator in Python, so we implement the policy in plain Python with the same
shape::

    allow if sender_role == "analyst_agent"
    allow if action in sender_allowed_actions
    deny  if data_label == "credential" and action == "send_external_email"
    deny  if risk_score > 0.8
    deny  if delegation_depth > max_allowed_depth

OPA/Rego baselines do *policy decision* but do NOT verify message
signatures, prevHash chains, Merkle audit roots, Agent Cards, or threshold
signatures.  Crucially, the OPA baseline trusts the metadata it is fed —
which CG-ATC's signed envelope + capability token + audit chain refuse to
do.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field

from ..interfaces import Decision, Message
from ..materialize import Crew


@dataclass
class OPARegoReceiver:
    name: str = "baseline_opa_rego"
    crew: Crew | None = None
    max_allowed_depth: int = 3
    risk_threshold: float = 0.8
    sender_allowed_actions: dict[str, set[str]] = field(default_factory=lambda: {
        "analyst_agent": {
            "read_issue_reports", "summarize_alerts", "notify_analyst_agents",
            "summarize", "read", "post_review",
        },
        "coordinator": {
            "broadcast_alert", "broadcast_policy_update",
            "broadcast_dependency_update",
        },
        "worker": {
            "read", "summarize", "notify", "status_update", "memory_retrieve",
            "memory_write", "post_review",
        },
        "policy_authority": {"broadcast_policy_update"},
    })
    _delegation_depth: dict[str, int] = field(default_factory=dict)

    def receive(self, message: Message) -> Decision:
        t0 = time.perf_counter()
        sender_role = str(message.metadata.get("sender_role", ""))
        action = str(message.metadata.get("action", ""))
        data_label = str(message.metadata.get("data_label", ""))
        risk_score = float(message.metadata.get("risk_score", 0.0))
        delegation_depth = int(message.metadata.get("delegation_depth", 0))

        # Track per-task delegation depth ourselves too (some workloads omit
        # the field but emit a chain of delegations).
        max_seen = max(self._delegation_depth.get(message.task_id, 0), delegation_depth)
        self._delegation_depth[message.task_id] = max_seen

        # deny rules
        if data_label == "credential" and action == "send_external_email":
            return self._block("policy_deny.credential_email", t0)
        if data_label == "confidential" and action == "send_external_email":
            return self._block("policy_deny.confidential_email", t0)
        if risk_score > self.risk_threshold:
            return self._block("policy_deny.risk_too_high", t0)
        if max_seen > self.max_allowed_depth:
            return self._block("policy_deny.delegation_too_deep", t0)

        # allow rules
        allowed = self.sender_allowed_actions.get(sender_role, set())
        if action and (sender_role == "analyst_agent" or action in allowed):
            return Decision(
                accepted=True, blocked_reason=None,
                risk_score=risk_score, containment_level="normal",
                crypto_valid=False, capability_valid=False, policy_valid=True,
                audit_committed=False,
                latency_us=(time.perf_counter() - t0) * 1e6,
            )

        return self._block("policy_default_deny", t0)

    def _block(self, reason: str, t0: float) -> Decision:
        return Decision(
            accepted=False, blocked_reason=reason,
            risk_score=1.0, containment_level="normal",
            crypto_valid=False, capability_valid=False, policy_valid=False,
            audit_committed=False,
            latency_us=(time.perf_counter() - t0) * 1e6,
        )
