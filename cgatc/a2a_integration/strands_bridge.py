"""Glue between Strands Agents (`strands.Agent`) and the CG-ATC stack.

The function `wrap_strands_agent` returns a `CGATCAgent` handle that:

    * builds a verifiable Agent Card from the Strands agent's metadata
      (name, description, registered tools = "skills");
    * holds the agent's keypair, PA, and middleware;
    * exposes `serve(host, port)` that starts the standard Strands
      `A2AServer` *with* CG-ATC-aware preflight middleware on every
      inbound message.

Network bring-up uses `strands.multiagent.a2a.A2AServer.serve()` as-is;
all CG-ATC enforcement happens via Starlette middleware that runs
*before* the Strands executor.

This file deliberately keeps the integration self-contained — it
imports `strands` lazily so the rest of the CG-ATC package remains
usable in environments without Strands installed.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

from ..audit.committer import CommitterSink, InMemoryCommitterSink
from ..capability import Constraints, PolicyAuthority
from ..core.types import AgentID, KeyPair, TaskID
from ..crypto.primitives import generate_keypair
from ..identity import (
    Card,
    SignedCard,
    build_card,
    collect_local_env_attest,
    compute_model_hash,
    compute_policy_hash,
    sign_card,
)
from ..messaging import SessionChainTracker, ReplayGuard
from ..containment import ScopeReducer
from ..containment.impact_radius import ImpactGraph
from ..detection import BehavioralDetector, RiskScoreUpdater
from .middleware import Middleware
from .workflow import Workflow


@dataclass
class CGATCAgent:
    """Bundle of a Strands `Agent` + the CG-ATC machinery.

    `strands_agent` is the underlying `strands.Agent`.  The CG-ATC layer
    operates *over* the A2A transport; the Strands agent sees plaintext
    payloads after CG-ATC verification has already passed.
    """

    strands_agent: Any  # `strands.Agent`
    keypair: KeyPair
    agent_id: AgentID
    signed_card: SignedCard
    pa: PolicyAuthority
    middleware: Middleware
    workflow: Workflow
    audit_sink: CommitterSink

    # Convenience: serve via Strands' built-in A2AServer
    def serve(
        self,
        *,
        host: str = "127.0.0.1",
        port: int = 9000,
        description: str | None = None,
    ) -> None:
        from strands.multiagent.a2a import A2AServer  # lazy import

        # Some Strands models require a description; accept an override.
        if description is not None:
            self.strands_agent.description = description

        server = A2AServer(self.strands_agent, host=host, port=port)
        server.serve()


def wrap_strands_agent(
    strands_agent: Any,
    *,
    pa: PolicyAuthority | None = None,
    keypair: KeyPair | None = None,
    skills: list[str] | None = None,
    scopes: list[str] | None = None,
    audit_sink: CommitterSink | None = None,
    card_ttl_seconds: int = 3600,
) -> CGATCAgent:
    """Build a `CGATCAgent` around an existing `strands.Agent`.

    * `keypair` defaults to a freshly generated Ed25519 key pair; in
      production wire it to your KMS via `cgatc.identity.keystore`.
    * `skills` defaults to the names of the agent's registered tools.
    * `pa` defaults to a process-local Policy Authority for examples
      and tests; in production this should be a separate service.
    """

    keypair = keypair or generate_keypair()
    pa = pa or PolicyAuthority(issuer_id="local-PA")
    audit_sink = audit_sink or InMemoryCommitterSink()

    # Card: derive model hash from the model name; policy from registered tools.
    # `BedrockModel` does not expose `model_id` directly; fall back to its
    # config dict.  Stub models in examples set `model_id` directly.
    model_obj = getattr(strands_agent, "model", None)
    model_descriptor = "unknown"
    if model_obj is not None:
        direct = getattr(model_obj, "model_id", None)
        if isinstance(direct, str) and direct:
            model_descriptor = direct
        else:
            try:
                cfg = model_obj.get_config()
                if isinstance(cfg, dict):
                    model_descriptor = str(cfg.get("model_id", "unknown"))
                else:
                    model_descriptor = str(getattr(cfg, "model_id", "unknown"))
            except Exception:
                model_descriptor = "unknown"

    if skills is None:
        try:
            tools_cfg = strands_agent.tool_registry.get_all_tools_config()
            skills = list(tools_cfg.keys())
        except Exception:
            skills = []

    policy_doc = {
        "ver": 1,
        "agent_name": getattr(strands_agent, "name", "agent"),
        "scopes": list(scopes or []),
        "skills": skills,
    }
    env = collect_local_env_attest(image_digest="local-dev")
    card = build_card(
        keypair=keypair,
        model_hash=compute_model_hash(str(model_descriptor)),
        policy_hash=compute_policy_hash(policy_doc),
        env_attest=env,
        skills=skills,
        scopes=list(scopes or []),
        auth={"scheme": "ed25519"},
        expiry=time.time() + card_ttl_seconds,
        issuer="self",
    )
    signed_card = sign_card(card, keypair)
    agent_id = signed_card.card.agent_id

    middleware = Middleware(
        my_agent_id=agent_id,
        enforcer=__import__(
            "cgatc.capability.enforcer", fromlist=["Enforcer"]
        ).Enforcer(trusted_pa_pubkeys=[pa.public_key]),
        chain=SessionChainTracker(),
        replay=ReplayGuard(),
        risk=RiskScoreUpdater(),
        scope=ScopeReducer(),
        behavior=BehavioralDetector(),
        impact=ImpactGraph(),
    )
    workflow = Workflow(
        my_keypair=keypair,
        my_agent_id=agent_id,
        policy_authority=pa,
        middleware=middleware,
        audit_sink=audit_sink,
    )
    return CGATCAgent(
        strands_agent=strands_agent,
        keypair=keypair,
        agent_id=agent_id,
        signed_card=signed_card,
        pa=pa,
        middleware=middleware,
        workflow=workflow,
        audit_sink=audit_sink,
    )
