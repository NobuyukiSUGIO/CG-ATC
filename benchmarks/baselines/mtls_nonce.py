"""baseline_mtls_nonce — TLS channel auth + per-message nonce (spec §2.1).

Verifies::

    sender is authenticated                       (mTLS client identity)
    nonce has not been used in the same session   (replay protection)
    timestamp is within freshness window
    payload_hash matches payload

Intentionally MISSING (per spec):
    per-message digital signature, capability token, causal prevHash,
    hash-chain audit log, impact-radius control, threshold authorization.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field

from ..interfaces import Decision, Message
from ..materialize import Crew
from cgatc.crypto.primitives import H


_FRESHNESS_S = 300


@dataclass
class MTLSNonceReceiver:
    name: str = "baseline_mtls_nonce"
    crew: Crew | None = None
    _seen_nonce: dict[tuple[str, str], set[str]] = field(default_factory=dict)

    def receive(self, message: Message) -> Decision:
        t0 = time.perf_counter()
        # mTLS identity: the workload puts the verified peer cert CN into
        # metadata["tls_client_cn"].  We authenticate the message iff this
        # CN is bound to a known crew member.
        cn = str(message.metadata.get("tls_client_cn", ""))
        crew_match = (
            self.crew is not None
            and cn in {m.agent_id.hex() for m in self.crew.members.values()}
        )
        if not crew_match:
            return self._reject("tls_unknown_peer", t0)

        # Nonce reuse within the same (session, sender)
        key = (message.session_id, message.sender_id)
        seen = self._seen_nonce.setdefault(key, set())
        if message.nonce is None or message.nonce in seen:
            return self._reject("nonce_reuse", t0)
        seen.add(message.nonce)

        # Freshness window
        if abs(time.time() - message.timestamp) > _FRESHNESS_S:
            return self._reject("stale_timestamp", t0)

        # Payload hash binding
        if H(message.payload.encode()).hex() != message.payload_hash:
            return self._reject("payload_hash_mismatch", t0)

        return Decision(
            accepted=True, blocked_reason=None,
            risk_score=0.0, containment_level="normal",
            crypto_valid=True, capability_valid=False, policy_valid=False,
            audit_committed=False,
            latency_us=(time.perf_counter() - t0) * 1e6,
        )

    def _reject(self, reason: str, t0: float) -> Decision:
        return Decision(
            accepted=False, blocked_reason=reason,
            risk_score=1.0, containment_level="normal",
            crypto_valid=False, capability_valid=False, policy_valid=False,
            audit_committed=False,
            latency_us=(time.perf_counter() - t0) * 1e6,
        )
