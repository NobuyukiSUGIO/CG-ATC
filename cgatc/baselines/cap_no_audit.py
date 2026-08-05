"""Baseline 3: capability tokens but no tamper-evident audit log.

Equivalent to running the CG-ATC capability layer alone (§III-E) without
the §III-F hash-chain log or the §III-D message envelope.

Properties:
    * Damage is bounded (Theorem 3 holds).
    * No cryptographic message authenticity (anyone can spoof sender).
    * No retroactive audit.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..capability import ActionRequest, Enforcer, SignedCapability
from ..core.exceptions import CapabilityError, SignatureVerificationError
from ..core.types import AgentID, TaskID
from .base import Delivery, DeliveryResult, Verdict


@dataclass
class CapNoAuditReceiver:
    name = "cap_no_audit"
    enforcer: Enforcer
    audience: AgentID

    def deliver(self, msg: Delivery) -> DeliveryResult:
        cap_json = msg.metadata.get("capability_json")
        scope = str(msg.metadata.get("action_scope", ""))
        sender_id = msg.metadata.get("sender_id")
        task_id = msg.metadata.get("task_id")
        if cap_json is None or sender_id is None or task_id is None:
            return DeliveryResult(Verdict.REJECT, "missing_capability",
                                  detected_attack=True)
        cap = SignedCapability.from_json(cap_json)
        try:
            self.enforcer.check(
                cap,
                ActionRequest(
                    subject=AgentID(bytes.fromhex(sender_id)),
                    audience=self.audience,
                    task_id=TaskID(bytes.fromhex(task_id)),
                    scope=scope,
                ),
            )
        except (CapabilityError, SignatureVerificationError):
            return DeliveryResult(Verdict.REJECT, "capability_failed",
                                  detected_attack=True)
        return DeliveryResult(Verdict.ACCEPT, "ok")
