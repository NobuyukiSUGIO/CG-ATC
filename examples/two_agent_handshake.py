"""Demonstrate the §V-A 11-step workflow between two agents.

Run with:
    PYTHONPATH=. python examples/two_agent_handshake.py

Both agents are simulated in-process; the example exercises the full
CG-ATC stack (Card → Handshake → Capability → Envelope → Verify →
Audit commit) without spinning up an HTTP server.
"""

from __future__ import annotations

import time

from cgatc.a2a_integration import Middleware, Workflow, decode, encode
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


def make_signed_card(name: str, scopes: list[str]):  # type: ignore[no-untyped-def]
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


def main() -> None:
    print("=" * 64)
    print("CG-ATC two-agent handshake demo (paper §V-A)")
    print("=" * 64)

    pa = PolicyAuthority(issuer_id="PA")

    # --- Alice (sender) ---------------------------------------------------
    kp_alice, signed_card_alice = make_signed_card(
        "alice", ["tools.read", "tools.write"]
    )
    print(f"\n[1] Alice ID: {signed_card_alice.card.agent_id.hex()[:32]}…")

    # --- Bob (receiver) — full CG-ATC stack ------------------------------
    kp_bob, signed_card_bob = make_signed_card("bob", ["tools.read"])
    bob_id = signed_card_bob.card.agent_id
    print(f"[1] Bob   ID: {bob_id.hex()[:32]}…")

    bob_mw = Middleware(
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
        my_keypair=kp_bob, my_agent_id=bob_id,
        policy_authority=pa, middleware=bob_mw,
        audit_sink=InMemoryCommitterSink(),
    )

    # Steps 1-6 of paper §V-A: Bob ingests Alice's card and issues a cap.
    task = TaskID.random()
    hs = bob_wf.handshake(
        peer_card=signed_card_alice, task=task,
        scopes=["tools.read"],
        constraints=Constraints(max_output_size=4096),
    )
    print(f"\n[2-6] Handshake done. Session id = {hs.session_id.hex()[:32]}…")
    print(f"      Capability scope = {hs.capability.capability.scopes}")

    # Steps 7-10: Alice signs an envelope, Bob verifies.
    payload = b"please summarise the latest sales numbers"
    env = build_envelope(
        session_id=hs.session_id, task_id=task, seq=0,
        sender_id=signed_card_alice.card.agent_id,
        receiver_id=bob_id, msg_type=MessageType.REQUEST,
        payload=payload,
    )
    signed_env = sign_envelope(env, kp_alice)
    metadata = encode(
        sender_agent_id_hex=signed_card_alice.card.agent_id.hex(),
        signed_envelope=signed_env, capability=hs.capability,
    )
    print(f"\n[7] Alice sends an envelope (seq={env.seq}). Headers = {list(metadata)}")

    decoded = decode(metadata)
    result = bob_mw.handle_inbound(
        decoded["signed_envelope"], payload=payload,
        capability=decoded["capability"], action_scope="tools.read",
    )
    print(f"[8-10] Bob's verdict: accepted={result.accepted}  risk={result.risk:.3f}  "
          f"containment={result.containment.name}")
    assert result.accepted

    # Step 11: commit audit log root externally.
    commitment = bob_wf.commit_audit()
    print(f"\n[11] Bob committed audit root: {commitment.root.hex()[:32]}…  "
          f"(events={commitment.seq_count})")

    # Sanity: Bob's local audit log re-verifies.
    bob_mw.log.verify()
    print("\nDONE. Audit log integrity verified.\n")


if __name__ == "__main__":
    main()
