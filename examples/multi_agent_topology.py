"""Multi-agent topology demo (CLAUDE.md §3.2 examples/).

Builds a five-agent topology:

        analyst -> researcher -> editor -> publisher -> archive

Each hop:
  * verifies the inbound CG-ATC envelope (Theorem 1),
  * runs the capability gate (Theorem 3),
  * appends the event to its tamper-evident log (Theorem 2),
  * forwards to the next agent with a freshly-signed envelope.

We also drive the impact graph so the impact-radius of any one agent
is visible at the end.

Run:
    PYTHONPATH=. python examples/multi_agent_topology.py
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from cgatc.a2a_integration import Middleware, Workflow
from cgatc.audit import HashChainLog, InMemoryCommitterSink
from cgatc.capability import Constraints, Enforcer, PolicyAuthority, SignedCapability
from cgatc.containment import ImpactGraph, ScopeReducer
from cgatc.containment.impact_radius import ImpactGraph as _IG  # alias for typing
from cgatc.core.types import MessageType, SessionID, TaskID
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


@dataclass
class Node:
    name: str
    keypair: object
    signed_card: SignedCard
    middleware: Middleware
    workflow: Workflow


def _make_card(name: str, scopes: list[str]):  # type: ignore[no-untyped-def]
    kp = generate_keypair()
    card = build_card(
        keypair=kp, model_hash=compute_model_hash(name),
        policy_hash=compute_policy_hash({"name": name, "scopes": scopes}),
        env_attest=collect_local_env_attest(),
        skills=["chat"], scopes=scopes,
        auth={"scheme": "ed25519"}, expiry=time.time() + 3600,
    )
    return kp, sign_card(card, kp)


def _make_node(name: str, scopes: list[str], pa: PolicyAuthority,
               shared_impact: _IG) -> Node:
    kp, signed_card = _make_card(name, scopes)
    me = signed_card.card.agent_id
    mw = Middleware(
        my_agent_id=me,
        enforcer=Enforcer(trusted_pa_pubkeys=[pa.public_key]),
        chain=SessionChainTracker(), replay=ReplayGuard(),
        risk=RiskScoreUpdater(), scope=ScopeReducer(),
        behavior=BehavioralDetector(),
        impact=shared_impact,  # share so we can query global radius later
        log=HashChainLog(me),
    )
    wf = Workflow(my_keypair=kp, my_agent_id=me, policy_authority=pa,
                  middleware=mw, audit_sink=InMemoryCommitterSink())
    return Node(name=name, keypair=kp, signed_card=signed_card,
                middleware=mw, workflow=wf)


def _hop(*, sender: Node, receiver: Node, capability: SignedCapability,
         session_id: SessionID, task: TaskID, seq: int, payload: bytes,
         scope: str, prev_hash: bytes) -> tuple[bytes, bytes]:
    """Sign at sender, verify at receiver, return (new_chain_head, payload)."""

    env = build_envelope(
        session_id=session_id, task_id=task, seq=seq,
        sender_id=sender.signed_card.card.agent_id,
        receiver_id=receiver.signed_card.card.agent_id,
        msg_type=MessageType.REQUEST, payload=payload, prev_hash=prev_hash,
    )
    signed = sign_envelope(env, sender.keypair)
    result = receiver.middleware.handle_inbound(
        signed, payload=payload, capability=capability, action_scope=scope,
    )
    print(f"  {sender.name:>10s} -> {receiver.name:<10s}  "
          f"accepted={result.accepted}  risk={result.risk:.2f}  "
          f"containment={result.containment.name}")
    if not result.accepted:
        raise SystemExit(f"Hop rejected: {result.violations}")
    return env.digest(), payload


def main() -> None:
    print("=" * 64)
    print("CG-ATC multi-agent pipeline (analyst → publisher)")
    print("=" * 64)

    pa = PolicyAuthority(issuer_id="PA")
    impact = ImpactGraph()  # shared for global view

    nodes = [
        _make_node("analyst", ["pipeline.read", "pipeline.write"], pa, impact),
        _make_node("researcher", ["pipeline.read", "pipeline.write"], pa, impact),
        _make_node("editor", ["pipeline.read", "pipeline.write"], pa, impact),
        _make_node("publisher", ["pipeline.read", "pipeline.write"], pa, impact),
        _make_node("archive", ["pipeline.read"], pa, impact),
    ]

    # The first hop is initiated by analyst toward researcher; each
    # subsequent receiver also acts as next-hop sender.
    task = TaskID.random()
    payload = b"draft article v1"

    # Each receiver issues the capability that the *previous* hop will use.
    # We pre-mint capabilities for every (sender, receiver) pair.
    handshakes = []
    for sender, receiver in zip(nodes[:-1], nodes[1:]):
        hs = receiver.workflow.handshake(
            peer_card=sender.signed_card, task=task,
            scopes=["pipeline.write"],
            constraints=Constraints(max_output_size=64_000, delegation_permitted=True),
        )
        handshakes.append(hs)

    # Walk the chain.
    chain_state: dict[tuple[str, str], bytes] = {}
    seq_per_pair: dict[tuple[str, str], int] = {}
    for i, (sender, receiver) in enumerate(zip(nodes[:-1], nodes[1:])):
        key = (sender.name, receiver.name)
        prev = chain_state.get(key, b"\x00" * 32)
        seq = seq_per_pair.get(key, 0)
        new_head, payload = _hop(
            sender=sender, receiver=receiver,
            capability=handshakes[i].capability,
            session_id=handshakes[i].session_id,
            task=task, seq=seq, payload=payload,
            scope="pipeline.write", prev_hash=prev,
        )
        chain_state[key] = new_head
        seq_per_pair[key] = seq + 1

    # Each agent commits its local audit root.
    print("\n[ audit roots ]")
    for n in nodes:
        c = n.workflow.commit_audit()
        print(f"  {n.name:>10s} root={c.root.hex()[:16]}…  events={c.seq_count}")
        n.middleware.log.verify()

    # Impact view from the analyst.
    analyst = nodes[0].signed_card.card.agent_id
    reachable_1 = impact.impact_set(analyst, max_radius=1)
    reachable_3 = impact.impact_set(analyst, max_radius=3)
    print(f"\nanalyst impact set @ r=1: {len(reachable_1)} agents")
    print(f"analyst impact set @ r=3: {len(reachable_3)} agents")
    print("\nDONE.\n")


if __name__ == "__main__":
    main()
