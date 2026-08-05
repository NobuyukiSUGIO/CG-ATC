"""baseline_signed_jwt — per-message signed JWT (spec §2.2).

Verifies the JWT's signature, ``iss/aud/exp/jti uniqueness/payload_hash/scope``.
Missing on purpose: prevHash chain, Merkle audit log, impact-radius policy,
risk-adaptive capability reduction, threshold authorisation.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field

from ..interfaces import Decision, Message
from ..materialize import Crew, parse_and_verify_jwt


@dataclass
class SignedJWTReceiver:
    name: str = "baseline_signed_jwt"
    crew: Crew | None = None
    accepted_scopes: tuple[str, ...] = (
        "tools.read", "tools.write", "tools.summarize",
        "broadcast", "summarize_alerts", "read_issue_reports",
        "notify_analyst_agents",
    )
    _seen_jti: set[str] = field(default_factory=set)

    def receive(self, message: Message) -> Decision:
        t0 = time.perf_counter()
        jwt = str(message.metadata.get("jwt", ""))
        sender_pk = bytes.fromhex(str(message.metadata.get("sender_pubkey_hex", "")) or "00")
        if not jwt or self.crew is None:
            return self._reject("missing_jwt", t0)

        claims = parse_and_verify_jwt(jwt, expected_pubkey=sender_pk)
        if claims is None:
            return self._reject("jwt_signature_invalid", t0)

        # iss must equal the sender_id (cryptographic identity).
        sender_id_hex = str(message.metadata.get("sender_agent_id_hex", ""))
        if claims.get("iss") != sender_id_hex:
            return self._reject("jwt_issuer_mismatch", t0)

        # aud must equal this receiver.
        receiver_id_hex = str(message.metadata.get("receiver_agent_id_hex", ""))
        if claims.get("aud") != receiver_id_hex:
            return self._reject("jwt_audience_mismatch", t0)

        # exp / iat freshness
        now = time.time()
        exp = float(claims.get("exp", 0))
        iat = float(claims.get("iat", 0))
        if now > exp or now < iat - 60:
            return self._reject("jwt_expired", t0)

        # jti uniqueness (replay defence within retention window)
        jti = str(claims.get("jti", ""))
        if jti in self._seen_jti or not jti:
            return self._reject("jti_replayed", t0)
        self._seen_jti.add(jti)

        # payload_hash binding
        if str(claims.get("payload_hash", "")) != message.payload_hash:
            return self._reject("payload_hash_mismatch", t0)

        # scope check
        scopes = list(claims.get("scope", []))
        action_scope = str(message.metadata.get("action_scope", ""))
        if action_scope and action_scope not in scopes:
            return self._reject("scope_violation", t0)
        if not any(s in self.accepted_scopes for s in scopes):
            return self._reject("scope_not_accepted", t0)

        return Decision(
            accepted=True, blocked_reason=None,
            risk_score=0.0, containment_level="normal",
            crypto_valid=True, capability_valid=True, policy_valid=False,
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
