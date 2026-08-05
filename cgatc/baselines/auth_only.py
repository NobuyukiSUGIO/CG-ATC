"""Baseline 1: A2A authentication only (CLAUDE.md §6.2).

The receiver checks a static list of known-sender API keys / tokens
against the message metadata.  Anything that presents a known key is
accepted.

Properties:
    * No payload-binding signature → cannot detect tampering.
    * No capability scope → cannot bound damage.
    * No audit log → cannot retroactively detect.
"""

from __future__ import annotations

from .base import Delivery, DeliveryResult, Verdict


class AuthOnlyReceiver:
    name = "auth_only"

    def __init__(self, known_tokens: dict[str, str]) -> None:
        # mapping symbolic-sender -> static bearer token
        self._known = dict(known_tokens)

    def deliver(self, msg: Delivery) -> DeliveryResult:
        token = str(msg.metadata.get("auth_token", ""))
        if self._known.get(msg.sender) == token and token:
            return DeliveryResult(verdict=Verdict.ACCEPT, reason="token_known")
        return DeliveryResult(verdict=Verdict.REJECT, reason="token_unknown",
                              detected_attack=True)
