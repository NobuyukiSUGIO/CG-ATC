"""Baseline 2: TLS + OAuth-style bearer-token access control (CLAUDE.md §6.2).

Stronger than `auth_only` in that the bearer token includes a static
scope claim; the receiver checks the scope claim against a static
allow-list before accepting.

Still has no per-message signature, no causal chain, no audit log.
"""

from __future__ import annotations

from dataclasses import dataclass

from .base import Delivery, DeliveryResult, Verdict


@dataclass
class TLSOAuthReceiver:
    name = "tls_oauth"
    bearer_scopes: dict[str, list[str]]   # token -> static granted scopes
    accept_scopes: list[str]              # this receiver's accept-list

    def deliver(self, msg: Delivery) -> DeliveryResult:
        token = str(msg.metadata.get("oauth_bearer", ""))
        action_scope = str(msg.metadata.get("action_scope", ""))
        granted = self.bearer_scopes.get(token, [])
        if not granted:
            return DeliveryResult(Verdict.REJECT, "unknown_bearer", detected_attack=True)
        if action_scope not in granted:
            return DeliveryResult(Verdict.REJECT, "scope_not_in_bearer",
                                  detected_attack=True)
        if action_scope not in self.accept_scopes:
            return DeliveryResult(Verdict.REJECT, "scope_not_accepted",
                                  detected_attack=True)
        return DeliveryResult(Verdict.ACCEPT, "ok")
