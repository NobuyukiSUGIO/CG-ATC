"""Integration test: real strands.Agent + stub LLM + CG-ATC.

Mirrors `examples/two_agent_chat.py` but as a CI-runnable test that
asserts the chat round-trip succeeds and the audit log integrity holds.
"""

from __future__ import annotations

import asyncio
import sys
import time
import unittest
from pathlib import Path

# `examples/` is not a package; insert it on the path for the stub model.
_EXAMPLES = Path(__file__).resolve().parents[2] / "examples"
sys.path.insert(0, str(_EXAMPLES))

from strands import Agent  # noqa: E402

from _stub_model import StubModel  # noqa: E402

from cgatc.a2a_integration import Middleware, Workflow  # noqa: E402
from cgatc.audit import HashChainLog, InMemoryCommitterSink  # noqa: E402
from cgatc.capability import Constraints, Enforcer, PolicyAuthority  # noqa: E402
from cgatc.containment import ImpactGraph, ScopeReducer  # noqa: E402
from cgatc.core.types import MessageType, TaskID  # noqa: E402
from cgatc.crypto.primitives import generate_keypair  # noqa: E402
from cgatc.detection import BehavioralDetector, RiskScoreUpdater  # noqa: E402
from cgatc.identity import (  # noqa: E402
    build_card,
    collect_local_env_attest,
    compute_model_hash,
    compute_policy_hash,
    sign_card,
)
from cgatc.messaging import (  # noqa: E402
    ReplayGuard,
    SessionChainTracker,
    build_envelope,
    sign_envelope,
)


def _stub_responder(text: str):  # type: ignore[no-untyped-def]
    def _r(messages, _system_prompt):  # type: ignore[no-untyped-def]
        return text
    return _r


def _model_id_of(agent: Agent) -> str:
    direct = getattr(agent.model, "model_id", None)
    if direct:
        return str(direct)
    cfg = agent.model.get_config()
    if isinstance(cfg, dict):
        return str(cfg.get("model_id", "unknown"))
    return str(getattr(cfg, "model_id", "unknown"))


def _build_card_for(agent: Agent):  # type: ignore[no-untyped-def]
    kp = generate_keypair()
    card = build_card(
        keypair=kp,
        model_hash=compute_model_hash(_model_id_of(agent)),
        policy_hash=compute_policy_hash({"name": agent.name}),
        env_attest=collect_local_env_attest(),
        skills=[agent.name], scopes=["chat.send"],
        auth={"scheme": "ed25519"}, expiry=time.time() + 3600,
    )
    return kp, sign_card(card, kp)


def _build_stack(kp, signed_card, pa):  # type: ignore[no-untyped-def]
    me = signed_card.card.agent_id
    mw = Middleware(
        my_agent_id=me,
        enforcer=Enforcer(trusted_pa_pubkeys=[pa.public_key]),
        chain=SessionChainTracker(), replay=ReplayGuard(),
        risk=RiskScoreUpdater(), scope=ScopeReducer(),
        behavior=BehavioralDetector(), impact=ImpactGraph(),
        log=HashChainLog(me),
    )
    wf = Workflow(my_keypair=kp, my_agent_id=me, policy_authority=pa,
                  middleware=mw, audit_sink=InMemoryCommitterSink())
    return mw, wf


class TestStrandsChat(unittest.TestCase):
    def test_round_trip_with_stub_llm(self) -> None:
        async def _go() -> None:
            pa = PolicyAuthority()
            alice = Agent(
                model=StubModel(responder=_stub_responder("Q: capital of Japan?"),
                                model_id="stub:alice"),
                name="alice", description="alice",
                callback_handler=None,
            )
            bob = Agent(
                model=StubModel(responder=_stub_responder("A: Tokyo."),
                                model_id="stub:bob"),
                name="bob", description="bob",
                callback_handler=None,
            )

            kp_a, card_a = _build_card_for(alice)
            kp_b, card_b = _build_card_for(bob)
            mw_a, wf_a = _build_stack(kp_a, card_a, pa)
            mw_b, wf_b = _build_stack(kp_b, card_b, pa)

            task = TaskID.random()
            hs_b = wf_b.handshake(peer_card=card_a, task=task,
                                  scopes=["chat.send"],
                                  constraints=Constraints())
            hs_a = wf_a.handshake(peer_card=card_b, task=task,
                                  scopes=["chat.send"],
                                  constraints=Constraints())

            # Alice's LLM produces the question.
            r_a = await alice.invoke_async("ask bob")
            text_a = r_a.message["content"][0]["text"]  # type: ignore[index]
            self.assertEqual(text_a, "Q: capital of Japan?")

            # Alice → Bob over CG-ATC.
            payload_a = text_a.encode()
            env = build_envelope(
                session_id=hs_b.session_id, task_id=task, seq=0,
                sender_id=card_a.card.agent_id, receiver_id=card_b.card.agent_id,
                msg_type=MessageType.REQUEST, payload=payload_a,
            )
            signed = sign_envelope(env, kp_a)
            verdict = mw_b.handle_inbound(
                signed, payload=payload_a, capability=hs_b.capability,
                action_scope="chat.send",
            )
            self.assertTrue(verdict.accepted, msg=str(verdict.violations))

            # Bob's LLM replies.
            r_b = await bob.invoke_async(text_a)
            text_b = r_b.message["content"][0]["text"]  # type: ignore[index]
            self.assertEqual(text_b, "A: Tokyo.")

            # Bob → Alice over CG-ATC.
            payload_b = text_b.encode()
            env_back = build_envelope(
                session_id=hs_a.session_id, task_id=task, seq=0,
                sender_id=card_b.card.agent_id, receiver_id=card_a.card.agent_id,
                msg_type=MessageType.RESPONSE, payload=payload_b,
            )
            signed_back = sign_envelope(env_back, kp_b)
            verdict_back = mw_a.handle_inbound(
                signed_back, payload=payload_b, capability=hs_a.capability,
                action_scope="chat.send",
            )
            self.assertTrue(verdict_back.accepted)

            # Audit logs verify.
            wf_a.commit_audit()
            wf_b.commit_audit()
            mw_a.log.verify()
            mw_b.log.verify()

        asyncio.run(_go())


if __name__ == "__main__":
    unittest.main()
