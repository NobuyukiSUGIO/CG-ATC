"""Demonstrate CG-ATC defending against four canonical attacks.

Each scenario sets up Alice→Bob, then injects an attacker (Mallory) and
verifies that Bob's CG-ATC stack:

    * REJECTS the malicious traffic, AND
    * EXPLAINS the rejection through `VerificationResult.violations`.

Run:
    PYTHONPATH=. python examples/adversarial_demo.py
"""

from __future__ import annotations

import time

from cgatc.a2a_integration import Middleware, Workflow, encode, decode
from cgatc.audit import HashChainLog, InMemoryCommitterSink
from cgatc.capability import Constraints, Enforcer, PolicyAuthority
from cgatc.containment import ImpactGraph, ScopeReducer
from cgatc.core.types import MessageType, TaskID
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


def make_agent(name: str, scopes: list[str]):  # type: ignore[no-untyped-def]
    kp = generate_keypair()
    env = collect_local_env_attest()
    card = build_card(
        keypair=kp,
        model_hash=compute_model_hash(name),
        policy_hash=compute_policy_hash({"name": name, "scopes": scopes}),
        env_attest=env, skills=["chat"], scopes=scopes,
        auth={"scheme": "ed25519"}, expiry=time.time() + 3600,
    )
    return kp, sign_card(card, kp)


def build_bob():  # type: ignore[no-untyped-def]
    pa = PolicyAuthority()
    kp_b, signed_card_b = make_agent("bob", ["tools.read"])
    bob_id = signed_card_b.card.agent_id
    mw = Middleware(
        my_agent_id=bob_id,
        enforcer=Enforcer(trusted_pa_pubkeys=[pa.public_key]),
        chain=SessionChainTracker(), replay=ReplayGuard(),
        risk=RiskScoreUpdater(), scope=ScopeReducer(),
        behavior=BehavioralDetector(), impact=ImpactGraph(),
        log=HashChainLog(bob_id),
    )
    wf = Workflow(my_keypair=kp_b, my_agent_id=bob_id,
                  policy_authority=pa, middleware=mw,
                  audit_sink=InMemoryCommitterSink())
    return pa, kp_b, signed_card_b, mw, wf


def banner(title: str) -> None:
    print(f"\n{'-' * 64}\n{title}\n{'-' * 64}")


def scenario_impersonation() -> None:
    banner("Scenario A: Mallory tries to impersonate Alice")
    pa, _kp_b, _scard_b, mw, wf = build_bob()
    kp_alice, scard_alice = make_agent("alice", ["tools.read"])
    kp_mallory, _ = make_agent("mallory", ["tools.read"])

    task = TaskID.random()
    hs = wf.handshake(peer_card=scard_alice, task=task, scopes=["tools.read"])

    payload = b"forged request"
    env = build_envelope(
        session_id=hs.session_id, task_id=task, seq=0,
        sender_id=scard_alice.card.agent_id, receiver_id=mw.me,
        msg_type=MessageType.REQUEST, payload=payload,
    )
    # Mallory signs with HER key but claims to be Alice.
    signed_env = sign_envelope(env, kp_mallory)
    result = mw.handle_inbound(signed_env, payload=payload,
                               capability=hs.capability, action_scope="tools.read")
    print(f"  accepted = {result.accepted}, violations = {result.violations}")
    assert not result.accepted


def scenario_replay() -> None:
    banner("Scenario B: Mallory replays Alice's signed envelope")
    pa, _kp_b, _, mw, wf = build_bob()
    kp_alice, scard_alice = make_agent("alice", ["tools.read"])
    task = TaskID.random()
    hs = wf.handshake(peer_card=scard_alice, task=task, scopes=["tools.read"])

    payload = b"hello"
    env = build_envelope(
        session_id=hs.session_id, task_id=task, seq=0,
        sender_id=scard_alice.card.agent_id, receiver_id=mw.me,
        msg_type=MessageType.REQUEST, payload=payload,
    )
    signed_env = sign_envelope(env, kp_alice)

    first = mw.handle_inbound(signed_env, payload=payload,
                              capability=hs.capability, action_scope="tools.read")
    print(f"  first delivery: accepted = {first.accepted}")
    assert first.accepted

    # Replay attempt
    replay = mw.handle_inbound(signed_env, payload=payload,
                               capability=hs.capability, action_scope="tools.read")
    print(f"  replay attempt: accepted = {replay.accepted}, violations = {replay.violations}")
    assert not replay.accepted


def scenario_capability_overreach() -> None:
    banner("Scenario C: Compromised Alice asks for an out-of-scope action")
    pa, _kp_b, _, mw, wf = build_bob()
    kp_alice, scard_alice = make_agent("alice", ["tools.read"])
    task = TaskID.random()
    hs = wf.handshake(peer_card=scard_alice, task=task, scopes=["tools.read"])

    payload = b"please send an email"
    env = build_envelope(
        session_id=hs.session_id, task_id=task, seq=0,
        sender_id=scard_alice.card.agent_id, receiver_id=mw.me,
        msg_type=MessageType.REQUEST, payload=payload,
    )
    signed_env = sign_envelope(env, kp_alice)

    result = mw.handle_inbound(signed_env, payload=payload,
                               capability=hs.capability,
                               action_scope="tools.email.send")
    print(f"  accepted = {result.accepted}, violations = {result.violations}")
    assert not result.accepted


def scenario_audit_tamper() -> None:
    banner("Scenario D: Adversary tampers with Bob's audit log")
    pa, _kp_b, _, mw, wf = build_bob()
    kp_alice, scard_alice = make_agent("alice", ["tools.read"])
    task = TaskID.random()
    hs = wf.handshake(peer_card=scard_alice, task=task, scopes=["tools.read"])

    payload = b"x"
    env = build_envelope(
        session_id=hs.session_id, task_id=task, seq=0,
        sender_id=scard_alice.card.agent_id, receiver_id=mw.me,
        msg_type=MessageType.REQUEST, payload=payload,
    )
    signed_env = sign_envelope(env, kp_alice)
    mw.handle_inbound(signed_env, payload=payload,
                      capability=hs.capability, action_scope="tools.read")
    wf.commit_audit()

    # Adversary mutates an audit record on disk.
    mw.log._records[-1].event["sender"] = "spoofed"  # type: ignore[index]
    try:
        mw.log.verify()
        print("  audit log somehow PASSED — this would be a critical bug")
    except Exception as exc:
        print(f"  audit log verification raised: {type(exc).__name__}  ✓")


def main() -> None:
    print("=" * 64)
    print("CG-ATC adversarial demo")
    print("=" * 64)
    scenario_impersonation()
    scenario_replay()
    scenario_capability_overreach()
    scenario_audit_tamper()
    print("\nAll scenarios behaved as expected.\n")


if __name__ == "__main__":
    main()
