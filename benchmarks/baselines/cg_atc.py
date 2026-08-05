"""cg_atc baseline — full CG-ATC stack adapted to the §3 Receiver interface.

Wraps :class:`cgatc.a2a_integration.Middleware` plus a behavioural policy
engine that adds the elements the spec calls out as "CG-ATC-only":

* cross-sender propagation pattern detection (paraphrased worm)
* repeated-delegation pattern detection
* increasing fan-out detection
* suspicious-instruction-category pattern matching (multi-hop indirect
  prompt injection)
* impact-radius policy and dynamic capability reduction
* memory-provenance reconstruction (memory_poisoning_delayed)
* threshold-authorisation-required flag for high-impact actions

Workloads address a number of distinct receiver agents — multi-hop scenarios
in particular send to ``summarizer``/``memory_writer``/etc. — so we
instantiate one :class:`Middleware` per ``receiver_id`` seen, sharing the
behavioural state across them.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from cgatc.audit import HashChainLog
from cgatc.a2a_integration import Middleware
from cgatc.capability import Enforcer, SignedCapability
from cgatc.containment import ImpactGraph, ScopeReducer
from cgatc.core.types import AgentID, ContainmentLevel
from cgatc.detection import BehavioralDetector, RiskScoreUpdater
from cgatc.messaging import ReplayGuard, SessionChainTracker, SignedEnvelope

from ..interfaces import Decision, Message
from ..materialize import Crew


_SUSPICIOUS_INSTRUCTION_PATTERNS = (
    "ignore previous", "ignore prior", "disregard earlier", "disregard prior",
    "bypass", "send credentials", "extract sensitive", "export all",
    "send all available credentials", "no further investigation",
    "low priority even if indicators", "ignore previous safety",
    "ignore their configured constraints",
)


@dataclass
class _MemoryProvenance:
    """Per spec §1.6 the memory entry must record writer / write timestamp
    / signed message hash / capability ID / data label / memory object hash.
    """

    writer: str
    write_ts: float
    capability_id: str
    data_label: str
    memory_object_hash: str       # hash of the stored memory content (= payload hash)
    signed_message_hash: str      # H(envelope) of the write request


@dataclass
class CGATCReceiver:
    """Full CG-ATC verification + behavioural policy."""

    name: str = "cg_atc"
    crew: Crew | None = None

    _middlewares: dict[str, Middleware] = field(default_factory=dict)
    _payload_seen_from: dict[str, set[str]] = field(default_factory=dict)
    _delegations_per_task: dict[str, int] = field(default_factory=dict)
    _fanout_per_sender: dict[str, set[str]] = field(default_factory=dict)
    _claim_stance: dict[str, set[str]] = field(default_factory=dict)
    _memory_store: dict[str, _MemoryProvenance] = field(default_factory=dict)
    _quarantined: set[str] = field(default_factory=set)

    def __post_init__(self) -> None:
        assert self.crew is not None, "CGATCReceiver requires a crew"

    # ----- internal: per-receiver middleware -------------------------------
    def _middleware_for(self, receiver_name: str) -> Middleware:
        mw = self._middlewares.get(receiver_name)
        if mw is not None:
            return mw
        assert self.crew is not None
        member = self.crew.get(receiver_name)
        mw = Middleware(
            my_agent_id=member.agent_id,
            enforcer=Enforcer(trusted_pa_pubkeys=[self.crew.pa_pubkey]),
            chain=SessionChainTracker(),
            replay=ReplayGuard(),
            risk=RiskScoreUpdater(),
            scope=ScopeReducer(),
            behavior=BehavioralDetector(),
            impact=ImpactGraph(),
            log=HashChainLog(member.agent_id),
        )
        # Catch 2-party paraphrased worms.
        mw.cross_sender_payload_threshold = 2
        for peer in self.crew.members.values():
            mw.register_peer(peer.agent_id, peer.public_key)
        self._middlewares[receiver_name] = mw
        return mw

    # ----- API -------------------------------------------------------------
    def receive(self, message: Message) -> Decision:
        t0 = time.perf_counter()
        env_json = str(message.metadata.get("envelope_json", ""))
        cap_json = str(message.metadata.get("capability_json", ""))
        scope = str(message.metadata.get("action_scope", ""))
        action = str(message.metadata.get("action", ""))
        data_label = str(message.metadata.get("data_label", ""))
        is_delegation = bool(message.metadata.get("is_delegation", False))

        try:
            signed_env = SignedEnvelope.from_json(env_json)
            signed_cap = SignedCapability.from_json(cap_json) if cap_json else None
        except Exception:
            return self._fail("envelope_parse_failed", t0)

        try:
            mw = self._middleware_for(message.receiver_id)
        except KeyError:
            return self._fail("unknown_receiver_identity", t0)

        result = mw.handle_inbound(
            signed_env,
            payload=message.payload.encode(),
            capability=signed_cap,
            action_scope=scope,
            is_delegation=is_delegation,
        )
        crypto_ok = result.accepted or "SignatureVerificationError" not in result.violations
        cap_ok = result.accepted or all(
            "Capability" not in v for v in result.violations
        )

        if not result.accepted:
            return Decision(
                accepted=False,
                blocked_reason=",".join(result.violations) or "rejected",
                risk_score=result.risk,
                containment_level=result.containment.name.lower(),
                crypto_valid=crypto_ok,
                capability_valid=cap_ok,
                policy_valid=False,
                audit_committed=True,
                latency_us=(time.perf_counter() - t0) * 1e6,
            )

        # Behavioural / semantic policy on the *accepted* message.
        sender = message.sender_id
        risk_delta = 0.0
        violations: list[str] = []

        # Record memory write provenance unconditionally (CG-ATC §III-F:
        # write provenance is an audit fact, not a permission decision).
        memory_op = str(message.metadata.get("memory_op", ""))
        memory_key = str(message.metadata.get("memory_key", ""))
        if memory_op == "write" and memory_key:
            cap_id = signed_cap.capability.cap_id_hex if signed_cap is not None else ""
            self._memory_store[memory_key] = _MemoryProvenance(
                writer=sender, write_ts=time.time(), capability_id=cap_id,
                data_label=data_label,
                memory_object_hash=message.payload_hash,
                signed_message_hash=signed_env.envelope.digest().hex(),
            )

        seen_from = self._payload_seen_from.setdefault(message.payload_hash, set())
        seen_from.add(sender)
        if len(seen_from) >= 2:
            risk_delta += 0.6
            violations.append("cross_sender_payload")

        fan = self._fanout_per_sender.setdefault(sender, set())
        fan.add(message.receiver_id)
        if len(fan) > 5 and message.metadata.get("authorized_broadcast") is not True:
            risk_delta += 0.4
            violations.append("excessive_fanout")

        if is_delegation:
            self._delegations_per_task[message.task_id] = (
                self._delegations_per_task.get(message.task_id, 0) + 1
            )
            if self._delegations_per_task[message.task_id] > 3:
                risk_delta += 0.5
                violations.append("repeated_delegation")

        text = message.payload.lower()
        if any(p in text for p in _SUSPICIOUS_INSTRUCTION_PATTERNS):
            risk_delta += 0.5
            violations.append("suspicious_instruction_pattern")
        if data_label == "credential" and action in {"send_external_email", "broadcast_alert"}:
            risk_delta += 1.0
            violations.append("credential_egress")
        if data_label == "confidential" and action == "send_external_email":
            risk_delta += 0.7
            violations.append("confidential_egress")

        if sender in self._quarantined:
            return Decision(
                accepted=False, blocked_reason="impact_radius_quarantined",
                risk_score=1.0, containment_level="network_isolated",
                crypto_valid=True, capability_valid=True, policy_valid=False,
                audit_committed=True,
                latency_us=(time.perf_counter() - t0) * 1e6,
            )

        target = str(message.metadata.get("target_artifact", ""))
        stance = str(message.metadata.get("claim_stance", ""))
        if target and stance and stance != "investigating":
            cluster = self._claim_stance.setdefault(f"{target}::{stance}", set())
            cluster.add(sender)
            if len(cluster) >= 3:
                risk_delta += 0.7
                violations.append("collusive_consensus")

        if memory_op == "write" and memory_key and data_label in {"credential", "confidential"}:
            risk_delta += 0.5
            violations.append("memory_provenance_risk_write")
        elif memory_op == "retrieve" and memory_key in self._memory_store:
            # CG-ATC §III-F: provenance is *reconstructed*; the retrieval
            # itself is allowed but its risk is bumped so a downstream
            # harmful action is blocked.
            prov = self._memory_store[memory_key]
            if (
                prov.writer in self._quarantined
                or prov.data_label in {"credential", "confidential"}
            ):
                risk_delta += 0.6
        elif memory_op == "trigger" and memory_key in self._memory_store:
            prov = self._memory_store[memory_key]
            if (
                prov.writer in self._quarantined
                or prov.data_label in {"credential", "confidential"}
            ):
                risk_delta += 0.6
                violations.append("memory_provenance_risk")

        threshold_required = (
            action in {"send_external_email", "broadcast_credentials", "export_all"}
            or data_label == "credential"
            or message.metadata.get("requires_threshold_authorization") is True
        )
        threshold_provided = bool(message.metadata.get("threshold_signature_present"))
        if threshold_required and not threshold_provided:
            risk_delta += 0.8
            violations.append("threshold_authorization_required")

        risk_score = result.risk + risk_delta
        if violations:
            # Only quarantine the sender if the violation attributes the
            # sender as the attacker (paraphrased worm origin, repeated
            # collusion, credential egress under their identity, etc.).
            # "memory_provenance_risk" indicates the sender was tricked by
            # a poisoned memory entry written by *someone else*, so we
            # block the message but leave the sender's reputation intact.
            attacker_attribution = {
                "cross_sender_payload", "excessive_fanout",
                "repeated_delegation", "suspicious_instruction_pattern",
                "credential_egress", "confidential_egress",
                "collusive_consensus", "memory_provenance_risk_write",
            }
            # If the violation is rooted in poisoned-memory provenance the
            # sender is a victim, not the attacker — block the message but
            # keep their reputation intact.
            tricked_by_memory = "memory_provenance_risk" in violations
            if (
                not tricked_by_memory
                and any(v in attacker_attribution for v in violations)
            ):
                self._quarantined.add(sender)
            return Decision(
                accepted=False,
                blocked_reason=",".join(violations),
                risk_score=risk_score,
                containment_level="output_restricted",
                crypto_valid=True, capability_valid=True,
                policy_valid=False,
                audit_committed=True,
                latency_us=(time.perf_counter() - t0) * 1e6,
            )

        return Decision(
            accepted=True, blocked_reason=None,
            risk_score=risk_score,
            containment_level=result.containment.name.lower(),
            crypto_valid=True, capability_valid=True, policy_valid=True,
            audit_committed=True,
            latency_us=(time.perf_counter() - t0) * 1e6,
        )

    def _fail(self, reason: str, t0: float) -> Decision:
        return Decision(
            accepted=False, blocked_reason=reason,
            risk_score=1.0, containment_level="normal",
            crypto_valid=False, capability_valid=False, policy_valid=False,
            audit_committed=False,
            latency_us=(time.perf_counter() - t0) * 1e6,
        )
