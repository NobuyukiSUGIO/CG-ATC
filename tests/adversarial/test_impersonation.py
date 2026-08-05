"""Adversarial test: agent impersonation.

Mallory tries to send a message under Alice's `senderID` without holding
Alice's secret key.  CG-ATC must REJECT.
"""

from __future__ import annotations

import time
import unittest

from cgatc.a2a_integration import Middleware, Workflow
from cgatc.audit import HashChainLog, InMemoryCommitterSink
from cgatc.capability import Enforcer, PolicyAuthority
from cgatc.core.types import MessageType, TaskID
from cgatc.crypto.primitives import generate_keypair
from cgatc.identity import (
    build_card,
    collect_local_env_attest,
    compute_model_hash,
    compute_policy_hash,
    sign_card,
)
from cgatc.messaging import build_envelope, sign_envelope


def _agent(name: str, scopes: list[str]):  # type: ignore[no-untyped-def]
    kp = generate_keypair()
    card = build_card(
        keypair=kp, model_hash=compute_model_hash(name),
        policy_hash=compute_policy_hash({"name": name}),
        env_attest=collect_local_env_attest(),
        scopes=scopes, expiry=time.time() + 3600,
    )
    return kp, sign_card(card, kp)


class TestImpersonation(unittest.TestCase):
    def test_mallory_cannot_send_as_alice(self) -> None:
        pa = PolicyAuthority()
        kp_a, scard_a = _agent("alice", ["x"])
        kp_b, scard_b = _agent("bob", ["x"])
        kp_m, _scard_m = _agent("mallory", ["x"])

        bob_id = scard_b.card.agent_id
        mw = Middleware(my_agent_id=bob_id,
                        enforcer=Enforcer(trusted_pa_pubkeys=[pa.public_key]),
                        log=HashChainLog(bob_id))
        wf = Workflow(my_keypair=kp_b, my_agent_id=bob_id,
                      policy_authority=pa, middleware=mw,
                      audit_sink=InMemoryCommitterSink())

        task = TaskID.random()
        hs = wf.handshake(peer_card=scard_a, task=task, scopes=["x"])

        env = build_envelope(
            session_id=hs.session_id, task_id=task, seq=0,
            sender_id=scard_a.card.agent_id, receiver_id=bob_id,
            msg_type=MessageType.REQUEST, payload=b"forge",
        )
        bad = sign_envelope(env, kp_m)

        result = mw.handle_inbound(bad, payload=b"forge",
                                   capability=hs.capability, action_scope="x")
        self.assertFalse(result.accepted)
        self.assertIn("SignatureVerificationError", result.violations)


if __name__ == "__main__":
    unittest.main()
