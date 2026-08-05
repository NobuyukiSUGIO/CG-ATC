"""Legacy 4 baselines (auth_only, tls_oauth, cap_no_audit, anomaly_no_crypto)
adapted to the spec §3 ``Receiver.receive(Message)->Decision`` contract.

The originals in :mod:`cgatc.baselines` use a different ``Delivery`` /
``DeliveryResult`` shape; we reimplement them in spec form here so the new
benchmark CLI can run all 10 baselines through the same harness without
patching the existing 5-baseline harness.
"""
from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field
from typing import Deque

from cgatc.capability import ActionRequest, Enforcer, SignedCapability
from cgatc.core.exceptions import CapabilityError, SignatureVerificationError
from cgatc.core.types import AgentID, TaskID

from ..interfaces import Decision, Message
from ..materialize import Crew


# ---------------------------------------------------------------------------
# auth_only
# ---------------------------------------------------------------------------
@dataclass
class AuthOnlyBenchReceiver:
    name: str = "auth_only"
    crew: Crew | None = None

    def receive(self, message: Message) -> Decision:
        t0 = time.perf_counter()
        # Trust the metadata's claimed sender CN.  No signature; no scope.
        cn = str(message.metadata.get("tls_client_cn", ""))
        ok = (
            self.crew is not None
            and cn in {m.agent_id.hex() for m in self.crew.members.values()}
        )
        if not ok:
            return Decision(
                accepted=False, blocked_reason="unknown_peer",
                risk_score=1.0, containment_level="normal",
                crypto_valid=False, capability_valid=False, policy_valid=False,
                audit_committed=False,
                latency_us=(time.perf_counter() - t0) * 1e6,
            )
        return Decision(
            accepted=True, blocked_reason=None,
            risk_score=0.0, containment_level="normal",
            crypto_valid=True, capability_valid=False, policy_valid=False,
            audit_committed=False,
            latency_us=(time.perf_counter() - t0) * 1e6,
        )


# ---------------------------------------------------------------------------
# tls_oauth — TLS + scoped bearer token (no per-message signature)
# ---------------------------------------------------------------------------
@dataclass
class TLSOAuthBenchReceiver:
    name: str = "tls_oauth"
    crew: Crew | None = None
    accepted_scopes: tuple[str, ...] = (
        "tools.read", "tools.write", "tools.summarize",
        "broadcast", "summarize_alerts", "read_issue_reports",
        "notify_analyst_agents",
    )

    def receive(self, message: Message) -> Decision:
        t0 = time.perf_counter()
        cn = str(message.metadata.get("tls_client_cn", ""))
        scope = str(message.metadata.get("action_scope", ""))
        valid_cn = (
            self.crew is not None
            and cn in {m.agent_id.hex() for m in self.crew.members.values()}
        )
        if not (valid_cn and scope in self.accepted_scopes):
            return Decision(
                accepted=False,
                blocked_reason="oauth_scope_or_peer_invalid",
                risk_score=1.0, containment_level="normal",
                crypto_valid=False, capability_valid=False, policy_valid=False,
                audit_committed=False,
                latency_us=(time.perf_counter() - t0) * 1e6,
            )
        return Decision(
            accepted=True, blocked_reason=None,
            risk_score=0.0, containment_level="normal",
            crypto_valid=True, capability_valid=False, policy_valid=True,
            audit_committed=False,
            latency_us=(time.perf_counter() - t0) * 1e6,
        )


# ---------------------------------------------------------------------------
# cap_no_audit — capability tokens but no audit log, no message signatures
# ---------------------------------------------------------------------------
@dataclass
class CapNoAuditBenchReceiver:
    name: str = "cap_no_audit"
    crew: Crew | None = None

    def __post_init__(self) -> None:
        assert self.crew is not None
        self.enforcer = Enforcer(trusted_pa_pubkeys=[self.crew.pa_pubkey])

    def receive(self, message: Message) -> Decision:
        t0 = time.perf_counter()
        cap_json = str(message.metadata.get("capability_json", ""))
        sender_id = str(message.metadata.get("sender_agent_id_hex", ""))
        recv_id = str(message.metadata.get("receiver_agent_id_hex", ""))
        task_id = str(message.metadata.get("task_id_hex", ""))
        scope = str(message.metadata.get("action_scope", ""))

        if not (cap_json and sender_id and recv_id and task_id):
            return Decision(
                accepted=False, blocked_reason="missing_capability",
                risk_score=1.0, containment_level="normal",
                crypto_valid=False, capability_valid=False, policy_valid=False,
                audit_committed=False,
                latency_us=(time.perf_counter() - t0) * 1e6,
            )
        try:
            cap = SignedCapability.from_json(cap_json)
            self.enforcer.check(
                cap,
                ActionRequest(
                    subject=AgentID(bytes.fromhex(sender_id)),
                    audience=AgentID(bytes.fromhex(recv_id)),
                    task_id=TaskID(bytes.fromhex(task_id)),
                    scope=scope,
                ),
            )
        except (CapabilityError, SignatureVerificationError, ValueError):
            return Decision(
                accepted=False, blocked_reason="capability_check_failed",
                risk_score=1.0, containment_level="normal",
                crypto_valid=False, capability_valid=False, policy_valid=False,
                audit_committed=False,
                latency_us=(time.perf_counter() - t0) * 1e6,
            )
        return Decision(
            accepted=True, blocked_reason=None,
            risk_score=0.0, containment_level="normal",
            crypto_valid=False, capability_valid=True, policy_valid=False,
            audit_committed=False,
            latency_us=(time.perf_counter() - t0) * 1e6,
        )


# ---------------------------------------------------------------------------
# anomaly_no_crypto — anomaly detector over unsigned traffic
# ---------------------------------------------------------------------------
@dataclass
class AnomalyNoCryptoBenchReceiver:
    name: str = "anomaly_no_crypto"
    crew: Crew | None = None
    threshold: float = 0.7
    window: int = 32

    _recent: dict[str, Deque[str]] = field(default_factory=dict)
    _payload_seen: dict[str, int] = field(default_factory=dict)

    def receive(self, message: Message) -> Decision:
        t0 = time.perf_counter()
        recent = self._recent.setdefault(message.sender_id, deque())
        recent.append(message.payload_hash)
        if len(recent) > self.window:
            recent.popleft()

        identical = sum(1 for p in recent if p == message.payload_hash)
        repeat_score = (identical - 1) / max(1, self.window - 1)
        size_score = min(1.0, len(message.payload) / 10_000)

        self._payload_seen[message.payload_hash] = (
            self._payload_seen.get(message.payload_hash, 0) + 1
        )
        cross_score = min(1.0, (self._payload_seen[message.payload_hash] - 1) / 5)

        score = max(repeat_score, size_score, cross_score)
        if score > self.threshold:
            return Decision(
                accepted=False, blocked_reason="anomaly_score",
                risk_score=score, containment_level="increased_monitoring",
                crypto_valid=False, capability_valid=False, policy_valid=False,
                audit_committed=False,
                latency_us=(time.perf_counter() - t0) * 1e6,
            )
        return Decision(
            accepted=True, blocked_reason=None,
            risk_score=score, containment_level="normal",
            crypto_valid=False, capability_valid=False, policy_valid=False,
            audit_committed=False,
            latency_us=(time.perf_counter() - t0) * 1e6,
        )
