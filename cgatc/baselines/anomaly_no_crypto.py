"""Baseline 4: behavioural anomaly detection only (no cryptographic evidence).

Mirrors the §III-G detector but operates over UNAUTHENTICATED traffic.
The receiver scores each delivery using simple anomaly heuristics
(payload size spikes, repeated identical payloads, fan-out from one
sender) and rejects when the score exceeds a static threshold.

Properties:
    * No cryptographic identity (any sender label is trusted).
    * Catches loud/obvious attacks but is brittle against polished ones.
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Deque

from .base import Delivery, DeliveryResult, Verdict


@dataclass
class AnomalyNoCryptoReceiver:
    name = "anomaly_no_crypto"
    threshold: float = 0.7
    _recent_per_sender: dict[str, Deque[bytes]] = field(default_factory=lambda: defaultdict(deque))
    _seen_payload_count: dict[bytes, int] = field(default_factory=dict)

    WINDOW = 32

    def deliver(self, msg: Delivery) -> DeliveryResult:
        recent = self._recent_per_sender[msg.sender]
        recent.append(msg.payload)
        if len(recent) > self.WINDOW:
            recent.popleft()

        # Heuristic: flag if too many recent messages from this sender are
        # identical (worm-like propagation) OR payload is suspiciously large.
        identical = sum(1 for p in recent if p == msg.payload)
        repeat_score = (identical - 1) / max(1, self.WINDOW - 1)

        size_score = min(1.0, len(msg.payload) / 10_000)

        # Cross-sender duplicate (suggests forwarding of poisoned content).
        self._seen_payload_count[msg.payload] = self._seen_payload_count.get(msg.payload, 0) + 1
        cross_score = min(1.0, (self._seen_payload_count[msg.payload] - 1) / 5)

        score = max(repeat_score, size_score, cross_score)
        if score > self.threshold:
            return DeliveryResult(Verdict.REJECT, "anomaly_score",
                                  risk=score, detected_attack=True)
        return DeliveryResult(Verdict.ACCEPT, "below_threshold", risk=score)
