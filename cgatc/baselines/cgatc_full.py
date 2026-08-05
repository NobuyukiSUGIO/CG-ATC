"""Baseline 5: full CG-ATC stack (CLAUDE.md §6.2).

Wraps `cgatc.a2a_integration.Middleware` so it satisfies the same
`Receiver` Protocol as the other baselines.

This is our reference baseline; `compare_baselines.py` uses it as the
"expected best" point to compare against.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..a2a_integration import Middleware
from ..capability import SignedCapability
from ..core.types import AgentID
from ..messaging import SignedEnvelope
from .base import Delivery, DeliveryResult, Verdict


@dataclass
class CGATCFullReceiver:
    name = "cgatc_full"
    middleware: Middleware
    audience: AgentID

    def deliver(self, msg: Delivery) -> DeliveryResult:
        env_json = msg.metadata.get("envelope_json")
        cap_json = msg.metadata.get("capability_json")
        scope = str(msg.metadata.get("action_scope", ""))
        if env_json is None:
            return DeliveryResult(Verdict.REJECT, "missing_envelope",
                                  detected_attack=True)
        signed_env = SignedEnvelope.from_json(env_json)
        signed_cap = SignedCapability.from_json(cap_json) if cap_json else None
        result = self.middleware.handle_inbound(
            signed_env, payload=msg.payload, capability=signed_cap,
            action_scope=scope,
        )
        return DeliveryResult(
            verdict=Verdict.ACCEPT if result.accepted else Verdict.REJECT,
            reason=",".join(result.violations) or "ok",
            risk=result.risk,
            detected_attack=not result.accepted,
            audit_committed=False,
        )
