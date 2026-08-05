"""CG-ATC verification middleware (paper §III-J).

Single entry-point that bundles every per-message check defined in §III-D
through §III-G:

    1. parse the CG-ATC headers from `Message.metadata`
    2. verify the envelope signature, payload hash, freshness, receiver
    3. verify the chain (prev_hash + seq monotonicity)
    4. enforce capability constraints
    5. record the event to the local hash-chain log
    6. update the per-sender risk score
    7. consult the containment level — drop / quarantine if needed

Used by both the inbound side (server-side `StrandsA2AExecutor`) and
the outbound side (signing helper that builds a CG-ATC-aware Message).
"""

from __future__ import annotations

from dataclasses import dataclass

from ..audit.hashchain import HashChainLog
from ..capability import (
    ActionRequest,
    Constraints,
    Enforcer,
    SignedCapability,
)
from ..crypto.primitives import H
from ..core.exceptions import (
    CapabilityError,
    EnvelopeError,
    SignatureVerificationError,
)
from ..core.types import AgentID, ContainmentLevel
from ..containment import ScopeReducer
from ..containment.impact_radius import ImpactGraph, radius_for_level
from ..detection import (
    BehavioralDetector,
    RiskScoreUpdater,
    classify_exception,
)
from ..messaging import (
    ReplayGuard,
    SessionChainTracker,
    SignedEnvelope,
    verify_envelope,
)


@dataclass(frozen=True)
class VerificationResult:
    """Outcome of `Middleware.handle_inbound`."""

    accepted: bool
    sender_id: AgentID
    payload: bytes | None
    capability: SignedCapability | None
    containment: ContainmentLevel
    risk: float
    violations: tuple[str, ...]


@dataclass
class _PeerKnown:
    """Receiver-side state about one peer."""

    public_key: bytes


class Middleware:
    """Per-receiver verification pipeline."""

    def __init__(
        self,
        *,
        my_agent_id: AgentID,
        enforcer: Enforcer,
        chain: SessionChainTracker | None = None,
        replay: ReplayGuard | None = None,
        risk: RiskScoreUpdater | None = None,
        scope: ScopeReducer | None = None,
        behavior: BehavioralDetector | None = None,
        impact: ImpactGraph | None = None,
        log: HashChainLog | None = None,
    ) -> None:
        self.me = my_agent_id
        self.enforcer = enforcer
        self.chain = chain or SessionChainTracker()
        self.replay = replay or ReplayGuard()
        self.risk = risk or RiskScoreUpdater()
        self.scope = scope or ScopeReducer()
        self.behavior = behavior or BehavioralDetector()
        self.impact = impact or ImpactGraph()
        self.log = log or HashChainLog(my_agent_id)
        self._peers: dict[AgentID, _PeerKnown] = {}
        # Cross-sender payload fingerprints (paper §III-G-2 "mass
        # transmission of similar prompts to many agents").  Maps the
        # payload hash to the set of distinct senders that have presented
        # that payload to us recently.
        self._payload_fingerprints: dict[bytes, set[AgentID]] = {}
        self.cross_sender_payload_threshold = 3

    # ----------------------------------------------------------------------
    # Peer registration
    # ----------------------------------------------------------------------
    def register_peer(self, agent_id: AgentID, public_key: bytes) -> None:
        """Tell the middleware about a peer's verified public key.

        In a full deployment this would come from `verify_card(...)` over
        the peer's Agent Card.  Tests can wire this up directly.
        """

        self._peers[agent_id] = _PeerKnown(public_key=public_key)

    # ----------------------------------------------------------------------
    # Inbound: verify a CG-ATC-bearing message
    # ----------------------------------------------------------------------
    def handle_inbound(
        self,
        signed: SignedEnvelope,
        *,
        payload: bytes,
        capability: SignedCapability | None,
        action_scope: str,
        is_delegation: bool = False,
    ) -> VerificationResult:
        """Run the full §III-J workflow on one inbound envelope.

        Returns a `VerificationResult` with `accepted=False` if any check
        fails; the failure is also recorded in the audit log and bumps
        the sender's risk score.
        """

        sender = signed.envelope.sender_id
        peer = self._peers.get(sender)
        if peer is None:
            self._record_violation(sender, "unknown_peer", severity=1.0)
            return self._fail(sender, signed, capability, ("unknown_peer",))

        violations: list[str] = []
        try:
            verify_envelope(
                signed,
                sender_pubkey=peer.public_key,
                payload=payload,
                expected_receiver=self.me,
            )
        except (EnvelopeError, SignatureVerificationError) as exc:
            self._punish(sender, exc, "envelope")
            violations.append(type(exc).__name__)
            return self._fail(sender, signed, capability, tuple(violations), payload=payload)

        # Chain + replay checks (post signature/payload).
        try:
            self.chain.accept(signed)
            self.replay.check_and_record(signed)
        except Exception as exc:
            self._punish(sender, exc, "chain")
            violations.append(type(exc).__name__)
            return self._fail(sender, signed, capability, tuple(violations), payload=payload)

        # Capability gate.
        if capability is None:
            self._punish(sender, CapabilityError("missing capability"), "capability")
            violations.append("missing_capability")
            return self._fail(sender, signed, capability, tuple(violations), payload=payload)

        try:
            self.enforcer.check(
                capability,
                ActionRequest(
                    subject=sender,
                    audience=self.me,
                    task_id=signed.envelope.task_id,
                    scope=action_scope,
                    is_delegation=is_delegation,
                ),
            )
        except (CapabilityError, SignatureVerificationError) as exc:
            self._punish(sender, exc, "capability")
            violations.append(type(exc).__name__)
            return self._fail(sender, signed, capability, tuple(violations), payload=payload)

        # Behavioural cross-sender payload-fingerprint check.  If many
        # distinct senders push the same bytes at us, that is the worm /
        # contagious-jailbreak signal from paper §III-G-2.
        fp = H(payload)
        seen_from = self._payload_fingerprints.setdefault(fp, set())
        seen_from.add(sender)
        if len(seen_from) >= self.cross_sender_payload_threshold:
            self.risk.add_behavior(sender, 1.0)
            self.log.append({
                "type": "inbound.behavior.cross_sender_payload",
                "sender": sender.hex(),
                "distinct_senders_for_payload": len(seen_from),
            })
            # Re-tick risk and refuse the message.
            risk = self.risk.tick(sender)
            level = self.scope.evaluate(sender, risk)
            return VerificationResult(
                accepted=False, sender_id=sender, payload=None,
                capability=capability, containment=level, risk=risk,
                violations=("PromptFanout",),
            )

        # Containment-driven inbound block (e.g. sender is now isolated).
        risk = self.risk.tick(sender)
        level = self.scope.evaluate(sender, risk)
        if level >= ContainmentLevel.NETWORK_ISOLATED:
            self.log.append({
                "type": "inbound.dropped.isolated",
                "sender": sender.hex(),
                "level": int(level),
            })
            return VerificationResult(
                accepted=False, sender_id=sender, payload=None, capability=capability,
                containment=level, risk=risk, violations=("isolated",),
            )

        # Track impact graph for impact_set computations.
        self.impact.record_send(sender, self.me)

        self.log.append(
            {
                "type": "inbound.accepted",
                "sender": sender.hex(),
                "task": signed.envelope.task_id_hex,
                "scope": action_scope,
                "level": int(level),
            },
            envelope_bytes=signed.envelope.encode_canonical(),
            signature_bytes=signed.signature,
        )
        return VerificationResult(
            accepted=True, sender_id=sender, payload=payload, capability=capability,
            containment=level, risk=risk, violations=(),
        )

    # ----------------------------------------------------------------------
    # Outbound: enforce containment + impact radius before signing
    # ----------------------------------------------------------------------
    def can_send(self, *, to: AgentID) -> bool:
        my_level = self.scope.current(self.me)
        if my_level >= ContainmentLevel.NETWORK_ISOLATED:
            return False
        max_radius = radius_for_level(my_level)
        # If we're already over the radius limit (i.e. we've recently sent to
        # `max_radius`-many distinct peers), block.
        if max_radius == 0:
            return False
        reach = self.impact.impact_set(self.me, max_radius)
        if to not in reach and len(reach) >= max_radius:
            return False
        return True

    # ----------------------------------------------------------------------
    # Internals
    # ----------------------------------------------------------------------
    def _record_violation(self, sender: AgentID, kind: str, severity: float) -> None:
        self.risk.add_crypto(sender, severity)
        self.log.append({
            "type": "inbound.violation",
            "sender": sender.hex(),
            "kind": kind,
            "severity": severity,
        })

    def _punish(self, sender: AgentID, exc: Exception, layer: str) -> None:
        v = classify_exception(exc)
        severity = v.severity if v is not None else 0.5
        self.risk.add_crypto(sender, severity)
        self.log.append({
            "type": "inbound.violation",
            "sender": sender.hex(),
            "layer": layer,
            "exc": type(exc).__name__,
            "severity": severity,
        })

    def _fail(
        self,
        sender: AgentID,
        signed: SignedEnvelope,
        capability: SignedCapability | None,
        violations: tuple[str, ...],
        *,
        payload: bytes | None = None,
    ) -> VerificationResult:
        risk = self.risk.tick(sender)
        level = self.scope.evaluate(sender, risk)
        return VerificationResult(
            accepted=False, sender_id=sender, payload=None, capability=capability,
            containment=level, risk=risk, violations=violations,
        )
