"""Two real Strands Agents chatting through CG-ATC (mocked LLM).

Both agents are *real* `strands.Agent` instances, but their LLM is a
deterministic stub (`examples/_stub_model.StubModel`) so the example is
runnable without AWS credentials.

The CG-ATC layer is the production layer:
  * Each agent has a verifiable Agent Card and an Ed25519 keypair.
  * Each chat turn is wrapped in a signed envelope (paper §III-D),
    routed through the receiver's `Middleware`, and recorded in a
    tamper-evident audit log (paper §III-F).
  * The Policy Authority issues a short-lived capability for the
    chat scope (paper §III-E).

Run:
    PYTHONPATH=. python examples/two_agent_chat.py
"""

from __future__ import annotations

import asyncio
import os
import sys
import time
from pathlib import Path

# Make the examples package importable when run directly.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from strands import Agent

from _stub_model import StubModel  # noqa: E402

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


# ---------------------------------------------------------------------------
# Per-agent persona and LLM responder
# ---------------------------------------------------------------------------
def alice_responder(messages, system_prompt):  # type: ignore[no-untyped-def]
    """Alice asks one short factual question."""

    return "What is the capital of Japan? Please answer in one sentence."


def bob_responder(messages, system_prompt):  # type: ignore[no-untyped-def]
    """Bob answers using the inbound prompt as context."""

    last_user = ""
    for m in messages:
        if m.get("role") == "user":
            for block in m.get("content", []):
                if isinstance(block, dict) and "text" in block:
                    last_user = block["text"]
    if "capital of japan" in last_user.lower():
        return "Tokyo is the capital of Japan."
    return f"I received: {last_user!r} but I do not know the answer."


# ---------------------------------------------------------------------------
# CG-ATC stack assembly per agent
# ---------------------------------------------------------------------------
def _build_strands_agent(name: str, responder, system_prompt: str) -> Agent:  # type: ignore[no-untyped-def]
    return Agent(
        model=StubModel(responder=responder, model_id=f"stub:{name}"),
        name=name,
        description=f"{name} (stub-LLM, deterministic)",
        system_prompt=system_prompt,
        callback_handler=None,  # silence the default printer
    )


def _model_id_of(agent: Agent) -> str:
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
        env_attest=collect_local_env_attest(image_digest="stub-llm"),
        skills=[strands_agent.name],
        scopes=scopes,
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
    print("CG-ATC two-agent chat (real strands.Agent + stub LLM)")
    print("=" * 72)

    pa = PolicyAuthority(issuer_id="PA")

    # 1) Build two real Strands Agents with stub LLMs.
    alice_agent = _build_strands_agent(
        "alice", alice_responder,
        "You are Alice. Ask one short factual question.",
    )
    bob_agent = _build_strands_agent(
        "bob", bob_responder,
        "You are Bob. Answer questions concisely.",
    )

    # 2) Wrap each with CG-ATC: card + middleware + workflow.
    alice_kp, alice_card = _build_card(alice_agent, ["chat.send", "chat.receive"])
    bob_kp, bob_card = _build_card(bob_agent, ["chat.send", "chat.receive"])
    alice_mw, alice_wf = _build_cgatc_stack(agent_kp=alice_kp,
                                            signed_card=alice_card, pa=pa)
    bob_mw, bob_wf = _build_cgatc_stack(agent_kp=bob_kp,
                                        signed_card=bob_card, pa=pa)
    print(f"  alice_id = {alice_card.card.agent_id.hex()[:24]}…")
    print(f"  bob_id   = {bob_card.card.agent_id.hex()[:24]}…")

    # 3) Both sides handshake (paper §III-J steps 1-6).
    task = TaskID.random()
    bob_hs = bob_wf.handshake(
        peer_card=alice_card, task=task,
        scopes=["chat.send"],
        constraints=Constraints(max_output_size=4096),
    )
    alice_hs = alice_wf.handshake(
        peer_card=bob_card, task=task,
        scopes=["chat.send"],
        constraints=Constraints(max_output_size=4096),
    )
    print(f"  session  = {bob_hs.session_id.hex()[:24]}…")

    # 4) Alice generates a question via her stub LLM.
    alice_result = await alice_agent.invoke_async("Please ask Bob a question.")
    alice_text = alice_result.message["content"][0]["text"]  # type: ignore[index]
    print(f"\n[Alice → LLM] generated: {alice_text!r}")

    # 5) Alice signs a CG-ATC envelope and sends it to Bob.
    payload_alice = alice_text.encode()
    env_alice = build_envelope(
        session_id=bob_hs.session_id, task_id=task, seq=0,
        sender_id=alice_card.card.agent_id, receiver_id=bob_card.card.agent_id,
        msg_type=MessageType.REQUEST, payload=payload_alice,
    )
    signed_alice = sign_envelope(env_alice, alice_kp)
    headers = encode(
        sender_agent_id_hex=alice_card.card.agent_id.hex(),
        signed_envelope=signed_alice, capability=bob_hs.capability,
    )
    print(f"[Alice → wire] CG-ATC headers: {sorted(headers)}")

    # 6) Bob's middleware verifies, then Bob's LLM answers.
    decoded = decode(headers)
    verdict = bob_mw.handle_inbound(
        decoded["signed_envelope"], payload=payload_alice,
        capability=decoded["capability"], action_scope="chat.send",
    )
    if not verdict.accepted:
        raise SystemExit(f"Bob rejected Alice's message: {verdict.violations}")
    print(f"[Bob   ← verify] accepted ✓  risk={verdict.risk:.2f}  "
          f"containment={verdict.containment.name}")

    bob_result = await bob_agent.invoke_async(payload_alice.decode())
    bob_text = bob_result.message["content"][0]["text"]  # type: ignore[index]
    print(f"[Bob   → LLM]   generated: {bob_text!r}")

    # 7) Bob signs the response and sends it back to Alice.
    payload_bob = bob_text.encode()
    env_bob = build_envelope(
        session_id=alice_hs.session_id, task_id=task, seq=0,
        sender_id=bob_card.card.agent_id, receiver_id=alice_card.card.agent_id,
        msg_type=MessageType.RESPONSE, payload=payload_bob,
    )
    signed_bob = sign_envelope(env_bob, bob_kp)
    headers_back = encode(
        sender_agent_id_hex=bob_card.card.agent_id.hex(),
        signed_envelope=signed_bob, capability=alice_hs.capability,
    )
    decoded_back = decode(headers_back)
    verdict_back = alice_mw.handle_inbound(
        decoded_back["signed_envelope"], payload=payload_bob,
        capability=decoded_back["capability"], action_scope="chat.send",
    )
    if not verdict_back.accepted:
        raise SystemExit(f"Alice rejected Bob's reply: {verdict_back.violations}")
    print(f"[Alice ← verify] accepted ✓  risk={verdict_back.risk:.2f}  "
          f"containment={verdict_back.containment.name}")

    # 8) Both sides commit their audit roots (paper §III-J step 11).
    cb = bob_wf.commit_audit()
    ca = alice_wf.commit_audit()
    print(f"\n[ audit ] Bob   root={cb.root.hex()[:16]}…  events={cb.seq_count}")
    print(f"[ audit ] Alice root={ca.root.hex()[:16]}…  events={ca.seq_count}")
    bob_mw.log.verify()
    alice_mw.log.verify()
    print("\nDONE — both audit logs verified.\n")


if __name__ == "__main__":
    asyncio.run(main())
