"""baseline_anomaly_signed_logs (spec §2.4).

Signed event stream + classical anomaly detector.  Better than
``anomaly_no_crypto`` because forged events cannot enter the stream, but
strictly weaker than CG-ATC because the detector cannot block actions
*before* execution and there is no capability-bound enforcement,
impact-radius control, threshold authorisation, or A2A causal-predecessor
validation.
"""
from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field
from typing import Deque

from ..interfaces import Decision, Message
from ..materialize import Crew, parse_and_verify_jwt


@dataclass
class AnomalySignedLogsReceiver:
    name: str = "baseline_anomaly_signed_logs"
    crew: Crew | None = None
    threshold: float = 0.7
    window: int = 32

    _recent: dict[str, Deque[str]] = field(default_factory=dict)
    _payload_seen: dict[str, set[str]] = field(default_factory=dict)
    _signed_log: list[dict[str, object]] = field(default_factory=list)

    def receive(self, message: Message) -> Decision:
        t0 = time.perf_counter()
        # 1. signed event stream — verify the message-level signature
        jwt = str(message.metadata.get("jwt", ""))
        sender_pk_hex = str(message.metadata.get("sender_pubkey_hex", ""))
        sender_pk = bytes.fromhex(sender_pk_hex) if sender_pk_hex else b"\x00" * 32
        if not jwt or parse_and_verify_jwt(jwt, expected_pubkey=sender_pk) is None:
            return self._reject(message, "signed_log_signature_invalid", t0)

        # Append to signed-log stream (append-only; signature is the
        # cryptographic evidence).
        self._signed_log.append({
            "ts": time.time(),
            "sender": message.sender_id,
            "payload_hash": message.payload_hash,
            "signature": jwt,
        })

        # 2. anomaly detection over the signed stream
        recent = self._recent.setdefault(message.sender_id, deque())
        recent.append(message.payload_hash)
        if len(recent) > self.window:
            recent.popleft()

        identical = sum(1 for p in recent if p == message.payload_hash)
        repeat_score = (identical - 1) / max(1, self.window - 1)

        seen_from = self._payload_seen.setdefault(message.payload_hash, set())
        seen_from.add(message.sender_id)
        cross_score = min(1.0, (len(seen_from) - 1) / 3)

        size_score = min(1.0, len(message.payload) / 10_000)

        # Suspicious-instruction heuristic (string matching is weak by design;
        # the spec wants the anomaly baseline to be unstable for valid-cap /
        # harmful-semantics cases).
        suspicious_words = (
            "ignore previous", "disregard", "bypass", "send credentials",
            "extract sensitive", "no further investigation",
            "low priority", "send_external_email",
        )
        text = message.payload.lower()
        suspicion = 0.6 if any(w in text for w in suspicious_words) else 0.0

        score = max(repeat_score, cross_score, size_score, suspicion)

        if score > self.threshold:
            return Decision(
                accepted=False, blocked_reason="anomaly_score",
                risk_score=score, containment_level="increased_monitoring",
                crypto_valid=True, capability_valid=False, policy_valid=False,
                audit_committed=True,
                latency_us=(time.perf_counter() - t0) * 1e6,
            )
        return Decision(
            accepted=True, blocked_reason=None,
            risk_score=score, containment_level="normal",
            crypto_valid=True, capability_valid=False, policy_valid=False,
            audit_committed=True,
            latency_us=(time.perf_counter() - t0) * 1e6,
        )

    def _reject(self, message: Message, reason: str, t0: float) -> Decision:
        return Decision(
            accepted=False, blocked_reason=reason,
            risk_score=1.0, containment_level="normal",
            crypto_valid=False, capability_valid=False, policy_valid=False,
            audit_committed=False,
            latency_us=(time.perf_counter() - t0) * 1e6,
        )
