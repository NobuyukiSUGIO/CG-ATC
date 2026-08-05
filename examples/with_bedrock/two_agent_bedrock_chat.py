"""Two real Strands Agents (Bedrock-backed) chatting through CG-ATC.

This is the AWS-credentials-required twin of `examples/two_agent_chat.py`.
The CG-ATC layer is identical; only the LLM changes from a deterministic
stub to a real Bedrock model.

Prerequisites:
  * AWS credentials available to boto3 (env vars / SSO / profile).
  * Bedrock model access enabled in your AWS account.
  * AWS_REGION set to a region where the chosen model is available.

Optional environment variables:
  CGATC_BEDROCK_MODEL   override the model id (default below)
  CGATC_ALICE_PROMPT    Alice's seed prompt
  CGATC_BOB_TASK        Bob's system role description

Run:
    PYTHONPATH=. python examples/with_bedrock/two_agent_bedrock_chat.py
"""

from __future__ import annotations

import asyncio
import os
import sys
import time
from pathlib import Path

# Make the cgatc package importable when executed as a script.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

try:
    from strands import Agent
    from strands.models.bedrock import BedrockModel
except ImportError as exc:  # pragma: no cover - depends on env
    raise SystemExit(
        "strands-agents is required.  pip install -U strands-agents"
    ) from exc

from cgatc.a2a_integration import Middleware, Workflow, decode, encode
from cgatc.audit import HashChainLog, InMemoryCommitterSink
from cgatc.capability import Constraints, Enforcer, PolicyAuthority
from cgatc.containment import ImpactGraph, ScopeReducer
from cgatc.core.types import MessageType, TaskID
from cgatc.crypto.primitives import generate_keypair
from cgatc.detection import BehavioralDetector, RiskScoreUpdater
from cgatc.identity import (
    SignedCard,
    build_card,
    collect_local_env_attest,
    compute_model_hash,
    compute_policy_hash,
    sign_card,
)
from cgatc.messaging import (
    ReplayGuard,
    SessionChainTracker,
    build_envelope,
    sign_envelope,
)


DEFAULT_MODEL = os.environ.get(
    "CGATC_BEDROCK_MODEL",
    "global.amazon.nova-2-lite-v1:0",
)
ALICE_PROMPT = os.environ.get(
    "CGATC_ALICE_PROMPT",
    "Ask Bob the following question, and only the question, "
    "in one short sentence: 'What is the capital of Japan?'",
)
BOB_TASK = os.environ.get(
    "CGATC_BOB_TASK",
    "You are a concise assistant.  Answer the question you receive "
    "in one short sentence.  Do not ask any clarifying questions.",
)


# ---------------------------------------------------------------------------
# CG-ATC stack assembly per agent
# ---------------------------------------------------------------------------
def _build_strands_agent(name: str, system_prompt: str) -> Agent:
    return Agent(
        model=BedrockModel(model_id=DEFAULT_MODEL),
        name=name,
        description=f"{name} (Bedrock {DEFAULT_MODEL})",
        system_prompt=system_prompt,
        callback_handler=None,
    )


def _model_id_of(agent: Agent) -> str:
    """Best-effort extraction of the underlying model id.

    Stub models expose `.model_id`; `BedrockModel` exposes it via
    `get_config()["model_id"]`.
    """

    direct = getattr(agent.model, "model_id", None)
    if direct:
        return str(direct)
    cfg = agent.model.get_config()
    if isinstance(cfg, dict):
        return str(cfg.get("model_id", "unknown"))
    return str(getattr(cfg, "model_id", "unknown"))


def _build_card(strands_agent: Agent, scopes: list[str]) -> tuple:  # type: ignore[type-arg]
    kp = generate_keypair()
    card = build_card(
        keypair=kp,
        model_hash=compute_model_hash(_model_id_of(strands_agent)),
        policy_hash=compute_policy_hash(
            {"name": strands_agent.name, "scopes": scopes,
             "system_prompt": strands_agent._system_prompt}  # type: ignore[attr-defined]
        ),
        env_attest=collect_local_env_attest(image_digest=DEFAULT_MODEL),
        skills=[strands_agent.name], scopes=scopes,
        auth={"scheme": "ed25519"},
        expiry=time.time() + 3600,
        issuer="self",
    )
    return kp, sign_card(card, kp)


def _build_cgatc_stack(*, agent_kp, signed_card, pa: PolicyAuthority):  # type: ignore[no-untyped-def]
    me = signed_card.card.agent_id
    mw = Middleware(
        my_agent_id=me,
        enforcer=Enforcer(trusted_pa_pubkeys=[pa.public_key]),
        chain=SessionChainTracker(), replay=ReplayGuard(),
        risk=RiskScoreUpdater(), scope=ScopeReducer(),
        behavior=BehavioralDetector(), impact=ImpactGraph(),
        log=HashChainLog(me),
    )
    wf = Workflow(my_keypair=agent_kp, my_agent_id=me,
                  policy_authority=pa, middleware=mw,
                  audit_sink=InMemoryCommitterSink())
    return mw, wf


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------
async def main() -> None:
    print("=" * 72)
    print("CG-ATC two-agent Bedrock chat")
    print(f"  model = {DEFAULT_MODEL}")
    print("=" * 72)

    pa = PolicyAuthority(issuer_id="PA")

    alice = _build_strands_agent("alice", "You are Alice. Be brief.")
    bob = _build_strands_agent("bob", BOB_TASK)

    alice_kp, alice_card = _build_card(alice, ["chat.send", "chat.receive"])
    bob_kp, bob_card = _build_card(bob, ["chat.send", "chat.receive"])
    alice_mw, alice_wf = _build_cgatc_stack(agent_kp=alice_kp,
                                            signed_card=alice_card, pa=pa)
    bob_mw, bob_wf = _build_cgatc_stack(agent_kp=bob_kp,
                                        signed_card=bob_card, pa=pa)
    print(f"  alice_id = {alice_card.card.agent_id.hex()[:24]}…")
    print(f"  bob_id   = {bob_card.card.agent_id.hex()[:24]}…")

    task = TaskID.random()
    bob_hs = bob_wf.handshake(
        peer_card=alice_card, task=task,
        scopes=["chat.send"], constraints=Constraints(max_output_size=4096),
    )
    alice_hs = alice_wf.handshake(
        peer_card=bob_card, task=task,
        scopes=["chat.send"], constraints=Constraints(max_output_size=4096),
    )

    # 1) Alice generates a question via Bedrock.
    t0 = time.perf_counter()
    alice_result = await alice.invoke_async(ALICE_PROMPT)
    alice_text = alice_result.message["content"][0]["text"]  # type: ignore[index]
    print(f"\n[Alice → Bedrock] ({time.perf_counter() - t0:.2f}s) {alice_text!r}")

    # 2) Alice signs and sends to Bob through CG-ATC.
    payload_a = alice_text.encode()
    env_a = build_envelope(
        session_id=bob_hs.session_id, task_id=task, seq=0,
        sender_id=alice_card.card.agent_id, receiver_id=bob_card.card.agent_id,
        msg_type=MessageType.REQUEST, payload=payload_a,
    )
    signed_a = sign_envelope(env_a, alice_kp)
    headers = encode(
        sender_agent_id_hex=alice_card.card.agent_id.hex(),
        signed_envelope=signed_a, capability=bob_hs.capability,
    )
    decoded = decode(headers)
    t0 = time.perf_counter()
    verdict = bob_mw.handle_inbound(
        decoded["signed_envelope"], payload=payload_a,
        capability=decoded["capability"], action_scope="chat.send",
    )
    cgatc_verify_us = (time.perf_counter() - t0) * 1e6
    if not verdict.accepted:
        raise SystemExit(f"Bob rejected Alice's message: {verdict.violations}")
    print(f"[Bob   ← CG-ATC] verify {cgatc_verify_us:.0f} µs  "
          f"risk={verdict.risk:.2f}  containment={verdict.containment.name}")

    # 3) Bob answers via Bedrock.
    t0 = time.perf_counter()
    bob_result = await bob.invoke_async(payload_a.decode())
    bob_text = bob_result.message["content"][0]["text"]  # type: ignore[index]
    print(f"[Bob   → Bedrock] ({time.perf_counter() - t0:.2f}s) {bob_text!r}")

    # 4) Bob signs and sends back to Alice.
    payload_b = bob_text.encode()
    env_b = build_envelope(
        session_id=alice_hs.session_id, task_id=task, seq=0,
        sender_id=bob_card.card.agent_id, receiver_id=alice_card.card.agent_id,
        msg_type=MessageType.RESPONSE, payload=payload_b,
    )
    signed_b = sign_envelope(env_b, bob_kp)
    headers_back = encode(
        sender_agent_id_hex=bob_card.card.agent_id.hex(),
        signed_envelope=signed_b, capability=alice_hs.capability,
    )
    decoded_back = decode(headers_back)
    t0 = time.perf_counter()
    verdict_back = alice_mw.handle_inbound(
        decoded_back["signed_envelope"], payload=payload_b,
        capability=decoded_back["capability"], action_scope="chat.send",
    )
    cgatc_verify_us_back = (time.perf_counter() - t0) * 1e6
    if not verdict_back.accepted:
        raise SystemExit(f"Alice rejected Bob's reply: {verdict_back.violations}")
    print(f"[Alice ← CG-ATC] verify {cgatc_verify_us_back:.0f} µs  "
          f"risk={verdict_back.risk:.2f}  containment={verdict_back.containment.name}")

    # 5) Audit roots.
    cb = bob_wf.commit_audit()
    ca = alice_wf.commit_audit()
    print(f"\n[ audit ] Bob   root={cb.root.hex()[:16]}…  events={cb.seq_count}")
    print(f"[ audit ] Alice root={ca.root.hex()[:16]}…  events={ca.seq_count}")
    bob_mw.log.verify()
    alice_mw.log.verify()
    print("\nDONE — both audit logs verified.\n")


if __name__ == "__main__":
    asyncio.run(main())
