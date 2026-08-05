"""Adversarial test: replay attack."""

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


class TestReplay(unittest.TestCase):
    def test_duplicate_envelope_rejected(self) -> None:
        pa = PolicyAuthority()
        kp_a, scard_a = _agent("alice", ["x"])
        kp_b, scard_b = _agent("bob", ["x"])
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
            msg_type=MessageType.REQUEST, payload=b"hi",
        )
        signed = sign_envelope(env, kp_a)

        ok = mw.handle_inbound(signed, payload=b"hi",
                               capability=hs.capability, action_scope="x")
        self.assertTrue(ok.accepted)

        replay = mw.handle_inbound(signed, payload=b"hi",
                                   capability=hs.capability, action_scope="x")
        self.assertFalse(replay.accepted)


if __name__ == "__main__":
    unittest.main()
