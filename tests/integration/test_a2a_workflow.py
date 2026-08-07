"""Integration test for the §V-A 11-step workflow.

We do NOT spin up an HTTP server here; we exercise the workflow at the
Python API level (Card → Handshake → Capability → Envelope → Verify).
The end-to-end HTTP test lives in `tests/e2e/`.
"""

from __future__ import annotations

import unittest

from cgatc.a2a_integration import Middleware, Workflow, decode, encode
from cgatc.audit import HashChainLog, InMemoryCommitterSink
from cgatc.capability import Constraints, Enforcer, PolicyAuthority
from cgatc.containment import ImpactGraph, ScopeReducer
from cgatc.core.types import AgentID, MessageType, TaskID
from cgatc.crypto.primitives import generate_keypair
from cgatc.detection import BehavioralDetector, RiskScoreUpdater
from cgatc.identity import (
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


def _build_signed_card(name: str, scopes: list[str]):  # type: ignore[no-untyped-def]
    import time
    kp = generate_keypair()
    env = collect_local_env_attest()
    card = build_card(
        keypair=kp,
        model_hash=compute_model_hash(name),
        policy_hash=compute_policy_hash({"name": name, "scopes": scopes}),
        env_attest=env,
        skills=["chat"], scopes=scopes,
        auth={"scheme": "ed25519"},
        expiry=time.time() + 3600,
    )
    return kp, sign_card(card, kp)


class TestWorkflowEndToEnd(unittest.TestCase):
    def test_alice_to_bob_full_path(self) -> None:
        # ------ key & card setup ------------------------------------------------
        kp_a, signed_card_a = _build_signed_card("alice", ["tools.read", "tools.write"])
        kp_b, signed_card_b = _build_signed_card("bob", ["tools.read"])

        alice_id = signed_card_a.card.agent_id
        bob_id = signed_card_b.card.agent_id

        # ------ Bob's CG-ATC stack (the receiver) -------------------------------
        pa = PolicyAuthority(issuer_id="PA")
        sink = InMemoryCommitterSink()
        bob_middleware = Middleware(
            my_agent_id=bob_id,
            enforcer=Enforcer(trusted_pa_pubkeys=[pa.public_key]),
            chain=SessionChainTracker(),
            replay=ReplayGuard(),
            risk=RiskScoreUpdater(),
            scope=ScopeReducer(),
            behavior=BehavioralDetector(),
            impact=ImpactGraph(),
            log=HashChainLog(bob_id),
        )
        bob_wf = Workflow(
            my_keypair=kp_b, my_agent_id=bob_id,
            policy_authority=pa, middleware=bob_middleware,
            audit_sink=sink,
        )

        # ------ Steps 1-6: Bob receives Alice's card and handshakes -------------
        task = TaskID.random()
        hs = bob_wf.handshake(
            peer_card=signed_card_a, task=task,
            scopes=["tools.read"], constraints=Constraints(max_output_size=4096),
        )

        # ------ Step 7-8: Alice signs an envelope and sends it to Bob -----------
        payload = b"hello bob"
        envelope = build_envelope(
            session_id=hs.session_id, task_id=task, seq=0,
            sender_id=alice_id, receiver_id=bob_id,
            msg_type=MessageType.REQUEST, payload=payload,
        )
        signed_env = sign_envelope(envelope, kp_a)

        # Encode CG-ATC headers, simulate transport, decode again.
        metadata = encode(
            sender_agent_id_hex=alice_id.hex(),
            signed_envelope=signed_env,
            capability=hs.capability,
        )
        decoded = decode(metadata)

        # ------ Step 7-10: Bob verifies and updates risk ------------------------
        result = bob_middleware.handle_inbound(
            decoded["signed_envelope"],
            payload=payload,
            capability=decoded["capability"],
            action_scope="tools.read",
        )
        self.assertTrue(result.accepted, msg=f"violations={result.violations}")
        self.assertEqual(result.sender_id, alice_id)

        # ------ Step 11: Bob commits an audit root ------------------------------
        commitment = bob_wf.commit_audit()
        self.assertGreater(commitment.seq_count, 0)

        # The audit log of bob must verify cleanly.
        bob_middleware.log.verify()

    def test_inbound_rejects_out_of_scope(self) -> None:
        kp_a, signed_card_a = _build_signed_card("alice", ["tools.read"])
        kp_b, signed_card_b = _build_signed_card("bob", ["tools.read"])
        alice_id = signed_card_a.card.agent_id
        bob_id = signed_card_b.card.agent_id

        pa = PolicyAuthority()
        bob_mw = Middleware(
            my_agent_id=bob_id,
            enforcer=Enforcer(trusted_pa_pubkeys=[pa.public_key]),
        )
        bob_wf = Workflow(
            my_keypair=kp_b, my_agent_id=bob_id,
            policy_authority=pa, middleware=bob_mw,
            audit_sink=InMemoryCommitterSink(),
        )
        task = TaskID.random()
        hs = bob_wf.handshake(peer_card=signed_card_a, task=task, scopes=["tools.read"])

        payload = b"x"
        env = build_envelope(
            session_id=hs.session_id, task_id=task, seq=0,
            sender_id=alice_id, receiver_id=bob_id,
            msg_type=MessageType.REQUEST, payload=payload,
        )
        signed = sign_envelope(env, kp_a)

        # Bob asks for a write scope that the capability does NOT cover.
        result = bob_mw.handle_inbound(
            signed, payload=payload,
            capability=hs.capability,
            action_scope="tools.write",
        )
        self.assertFalse(result.accepted)
        self.assertGreater(result.risk, 0.0)


if __name__ == "__main__":
    unittest.main()
