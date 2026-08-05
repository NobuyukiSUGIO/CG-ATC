"""baseline_capability_central_audit (spec §2.3).

Capability tokens for action authorisation, plus a single append-only
*centralised* audit server.  The trade-off the experiment exposes is:

* a capability check protects against scope escalation;
* but if the central audit server is compromised, the whole forensic record
  collapses (the spec calls out "delete / modify / reorder / insert fake
  event" as the audit-tampering experiment).

This baseline does NOT have per-agent local hash chains, Merkle inclusion
proofs, signed log roots, prevHash-based message causality, or
tamper-evident distributed audit.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from cgatc.capability import ActionRequest, Enforcer, SignedCapability
from cgatc.core.exceptions import CapabilityError, SignatureVerificationError
from cgatc.core.types import AgentID, TaskID

from ..interfaces import Decision, Message
from ..materialize import Crew


@dataclass
class CentralAuditServer:
    """Append-only event list (centralised audit log per spec §2.3)."""

    events: list[dict[str, Any]] = field(default_factory=list)
    _next_id: int = 1

    def append(self, ev: dict[str, Any]) -> str:
        eid = f"evt-{self._next_id:08d}"
        self._next_id += 1
        rec = {"event_id": eid, **ev}
        self.events.append(rec)
        return eid

    # --- tamper helpers (used by the additional evaluation in §2.3) -------
    def delete(self, event_id: str) -> bool:
        for i, e in enumerate(self.events):
            if e["event_id"] == event_id:
                self.events.pop(i)
                return True
        return False

    def modify(self, event_id: str, patch: dict[str, Any]) -> bool:
        for e in self.events:
            if e["event_id"] == event_id:
                e.update(patch)
                return True
        return False

    def insert_fake(self, before_id: str, fake: dict[str, Any]) -> str:
        for i, e in enumerate(self.events):
            if e["event_id"] == before_id:
                rec = {"event_id": f"evt-fake-{self._next_id:08d}", **fake}
                self._next_id += 1
                self.events.insert(i, rec)
                return rec["event_id"]
        return ""


@dataclass
class CapabilityCentralAuditReceiver:
    name: str = "baseline_capability_central_audit"
    crew: Crew | None = None
    audit: CentralAuditServer = field(default_factory=CentralAuditServer)

    def __post_init__(self) -> None:
        assert self.crew is not None, "CapabilityCentralAuditReceiver requires a crew"
        self.enforcer = Enforcer(trusted_pa_pubkeys=[self.crew.pa_pubkey])

    def receive(self, message: Message) -> Decision:
        t0 = time.perf_counter()
        cap_json = str(message.metadata.get("capability_json", ""))
        sender_id_hex = str(message.metadata.get("sender_agent_id_hex", ""))
        receiver_id_hex = str(message.metadata.get("receiver_agent_id_hex", ""))
        task_id_hex = str(message.metadata.get("task_id_hex", ""))
        scope = str(message.metadata.get("action_scope", ""))

        if not (cap_json and sender_id_hex and receiver_id_hex and task_id_hex):
            return self._reject(message, "missing_capability_metadata", t0)

        try:
            cap = SignedCapability.from_json(cap_json)
            self.enforcer.check(
                cap,
                ActionRequest(
                    subject=AgentID(bytes.fromhex(sender_id_hex)),
                    audience=AgentID(bytes.fromhex(receiver_id_hex)),
                    task_id=TaskID(bytes.fromhex(task_id_hex)),
                    scope=scope,
                ),
            )
        except (CapabilityError, SignatureVerificationError, ValueError):
            return self._reject(message, "capability_check_failed", t0)

        # Append to centralised audit log.
        self.audit.append({
            "timestamp": time.time(),
            "sender_id": sender_id_hex,
            "receiver_id": receiver_id_hex,
            "task_id": task_id_hex,
            "action": str(message.metadata.get("action", "")),
            "capability_id": cap.capability.cap_id_hex,
            "payload_hash": message.payload_hash,
        })
        return Decision(
            accepted=True, blocked_reason=None,
            risk_score=0.0, containment_level="normal",
            crypto_valid=False, capability_valid=True, policy_valid=False,
            audit_committed=True,
            latency_us=(time.perf_counter() - t0) * 1e6,
        )

    def _reject(self, message: Message, reason: str, t0: float) -> Decision:
        self.audit.append({
            "timestamp": time.time(),
            "sender_id": message.metadata.get("sender_agent_id_hex", ""),
            "receiver_id": message.metadata.get("receiver_agent_id_hex", ""),
            "task_id": message.metadata.get("task_id_hex", ""),
            "action": "rejected",
            "reason": reason,
            "payload_hash": message.payload_hash,
        })
        return Decision(
            accepted=False, blocked_reason=reason,
            risk_score=1.0, containment_level="normal",
            crypto_valid=False, capability_valid=False, policy_valid=False,
            audit_committed=True,
            latency_us=(time.perf_counter() - t0) * 1e6,
        )
