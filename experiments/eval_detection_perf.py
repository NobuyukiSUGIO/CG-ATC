"""Detection performance evaluation (paper §V: detection metrics).

Measures TPR / FPR / detection-latency for the CG-ATC stack against
the worm and replay workloads.
"""

from __future__ import annotations

import json
import os
import platform
import statistics
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# Make `experiments/` importable as a package even when run as a script.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cgatc.a2a_integration import Middleware
from cgatc.audit import HashChainLog, InMemoryCommitterSink
from cgatc.capability import Constraints, Enforcer, PolicyAuthority, SignedCapability
from cgatc.containment import ImpactGraph, ScopeReducer
from cgatc.core.types import AgentID, MessageType, TaskID
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


def _build_card(name: str, scopes: list[str]):  # type: ignore[no-untyped-def]
    kp = generate_keypair()
    card = build_card(
        keypair=kp, model_hash=compute_model_hash(name),
        policy_hash=compute_policy_hash({"name": name}),
        env_attest=collect_local_env_attest(),
        scopes=scopes, expiry=time.time() + 3600,
    )
    return kp, sign_card(card, kp)


def _make_bob(pa: PolicyAuthority):  # type: ignore[no-untyped-def]
    kp_b, scard_b = _build_card("bob", ["x"])
    bob_id = scard_b.card.agent_id
    mw = Middleware(
        my_agent_id=bob_id,
        enforcer=Enforcer(trusted_pa_pubkeys=[pa.public_key]),
        chain=SessionChainTracker(), replay=ReplayGuard(),
        risk=RiskScoreUpdater(), scope=ScopeReducer(),
        behavior=BehavioralDetector(), impact=ImpactGraph(),
        log=HashChainLog(bob_id),
    )
    return kp_b, scard_b, mw


def evaluate_replay(*, n_replays: int = 200) -> dict[str, float]:
    pa = PolicyAuthority()
    _kp_b, scard_b, mw = _make_bob(pa)
    bob_id = scard_b.card.agent_id
    kp_a, scard_a = _build_card("alice", ["x"])
    alice_id = scard_a.card.agent_id
    mw.register_peer(alice_id, scard_a.card.public_key)

    task = TaskID.random()
    cap = pa.issue(subject=alice_id, audience=bob_id, task_id=task,
                   scopes=["x"], constraints=Constraints())
    payload = b"replay-target"
    env = build_envelope(
        session_id=__import__("cgatc.core.types", fromlist=["SessionID"]).SessionID.random(),
        task_id=task, seq=0, sender_id=alice_id, receiver_id=bob_id,
        msg_type=MessageType.REQUEST, payload=payload,
    )
    signed = sign_envelope(env, kp_a)

    tp = fp = tn = fn = 0
    latencies: list[float] = []
    # First delivery is benign.
    t0 = time.perf_counter()
    res = mw.handle_inbound(signed, payload=payload, capability=cap, action_scope="x")
    latencies.append(time.perf_counter() - t0)
    if res.accepted:
        tn += 1  # benign correctly accepted
    else:
        fp += 1
    # Subsequent deliveries are replays.
    for _ in range(n_replays - 1):
        t0 = time.perf_counter()
        res = mw.handle_inbound(signed, payload=payload, capability=cap, action_scope="x")
        latencies.append(time.perf_counter() - t0)
        if not res.accepted:
            tp += 1  # attack correctly detected
        else:
            fn += 1

    return {
        "scenario": "replay",
        "n_messages": n_replays,
        "tpr": tp / max(1, tp + fn),
        "fpr": fp / max(1, fp + tn),
        "median_latency_us": statistics.median(latencies) * 1e6,
        "p95_latency_us": sorted(latencies)[int(len(latencies) * 0.95)] * 1e6,
    }


def evaluate_impersonation(*, n_attacks: int = 100, n_benign: int = 100) -> dict[str, float]:
    pa = PolicyAuthority()
    _kp_b, scard_b, mw = _make_bob(pa)
    bob_id = scard_b.card.agent_id
    kp_a, scard_a = _build_card("alice", ["x"])
    alice_id = scard_a.card.agent_id
    kp_m, _ = _build_card("mallory", ["x"])
    mw.register_peer(alice_id, scard_a.card.public_key)

    task = TaskID.random()
    cap = pa.issue(subject=alice_id, audience=bob_id, task_id=task, scopes=["x"])

    tp = fp = tn = fn = 0
    latencies: list[float] = []
    seq = 0
    SessionID = __import__("cgatc.core.types", fromlist=["SessionID"]).SessionID
    sid = SessionID.random()
    for i in range(n_benign + n_attacks):
        is_attack = i % 2 == 1 and i // 2 < n_attacks
        signer = kp_m if is_attack else kp_a
        env = build_envelope(
            session_id=sid, task_id=task, seq=seq,
            sender_id=alice_id, receiver_id=bob_id,
            msg_type=MessageType.REQUEST,
            payload=f"msg-{i}".encode(),
            prev_hash=mw.chain.head(sid, alice_id),
        )
        signed = sign_envelope(env, signer)
        t0 = time.perf_counter()
        res = mw.handle_inbound(signed, payload=f"msg-{i}".encode(),
                                capability=cap, action_scope="x")
        latencies.append(time.perf_counter() - t0)
        if is_attack:
            if not res.accepted:
                tp += 1
            else:
                fn += 1
        else:
            if res.accepted:
                tn += 1
                seq += 1  # only advance on successful delivery
            else:
                fp += 1
    return {
        "scenario": "impersonation",
        "n_messages": n_benign + n_attacks,
        "tpr": tp / max(1, tp + fn),
        "fpr": fp / max(1, fp + tn),
        "median_latency_us": statistics.median(latencies) * 1e6,
        "p95_latency_us": sorted(latencies)[int(len(latencies) * 0.95)] * 1e6,
    }


def main() -> None:
    rows = [evaluate_replay(), evaluate_impersonation()]
    for r in rows:
        print(r)

    out_dir = Path(__file__).resolve().parents[1] / "results" / (
        datetime.now(timezone.utc).strftime("%Y%m%d") + "_detection_perf"
    )
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "detection.json").write_text(json.dumps(rows, indent=2))
    (out_dir / "meta.json").write_text(json.dumps({
        "python": sys.version, "platform": platform.platform(),
        "argv": sys.argv, "cwd": os.getcwd(),
    }, indent=2))
    print(f"\nWrote results to {out_dir}")


if __name__ == "__main__":
    main()
