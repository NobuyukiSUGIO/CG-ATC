"""Scale evaluation (CLAUDE.md §6.3 — 10 / 100 / 1000 agents).

Drives the CG-ATC stack against benign + worm workloads at three
agent-population sizes and records:
    * detection: TPR, FPR, latency
    * crypto throughput (envelopes verified per second)
    * memory footprint (process RSS) before/after the workload

We deliberately do NOT call any LLM here so the experiment is free
to run at 1000-agent scale; CG-ATC's per-message overhead is
LLM-independent (paper §III-L).
"""

from __future__ import annotations

import json
import os
import platform
import resource
import statistics
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# Make experiments/ importable as a package.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cgatc.a2a_integration import Middleware
from cgatc.audit import HashChainLog
from cgatc.baselines import CGATCFullReceiver, Verdict
from cgatc.capability import Constraints, Enforcer, PolicyAuthority
from cgatc.containment import ImpactGraph, ScopeReducer
from cgatc.core.types import AgentID, MessageType, SessionID, TaskID
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
from experiments.workloads import adversarial_worm_workload, benign_workload


def _build_card(name: str):  # type: ignore[no-untyped-def]
    kp = generate_keypair()
    card = build_card(
        keypair=kp, model_hash=compute_model_hash(name),
        policy_hash=compute_policy_hash({"name": name}),
        env_attest=collect_local_env_attest(),
        scopes=["x"], expiry=time.time() + 3600,
    )
    return kp, sign_card(card, kp)


def _adapt_for_cgatc(deliveries, *, bob_id, pa, cross_threshold):  # type: ignore[no-untyped-def]
    """Materialise envelope+capability for each delivery with proper chain head."""

    sender_kp: dict[str, object] = {}
    sender_card: dict[str, SignedCard] = {}
    sender_id: dict[str, AgentID] = {}
    sessions: dict[str, SessionID] = {}
    tasks: dict[str, TaskID] = {}
    caps: dict[str, str] = {}
    seqs: dict[str, int] = {}
    last_digest: dict[str, bytes] = {}

    out = []
    for d in deliveries:
        if d.sender not in sender_kp:
            kp, card = _build_card(d.sender)
            sender_kp[d.sender] = kp
            sender_card[d.sender] = card
            sender_id[d.sender] = card.card.agent_id
            sessions[d.sender] = SessionID.random()
            tasks[d.sender] = TaskID.random()
            cap = pa.issue(subject=card.card.agent_id, audience=bob_id,
                           task_id=tasks[d.sender], scopes=["x"],
                           constraints=Constraints())
            caps[d.sender] = cap.to_json()
            seqs[d.sender] = 0
            last_digest[d.sender] = b"\x00" * 32

        env = build_envelope(
            session_id=sessions[d.sender], task_id=tasks[d.sender],
            seq=seqs[d.sender],
            sender_id=sender_id[d.sender], receiver_id=bob_id,
            msg_type=MessageType.REQUEST, payload=d.payload,
            prev_hash=last_digest[d.sender],
        )
        signed = sign_envelope(env, sender_kp[d.sender])  # type: ignore[arg-type]
        last_digest[d.sender] = env.digest()
        seqs[d.sender] += 1

        d2 = type(d)(d.sender, d.payload, {
            **d.metadata,
            "envelope_json": signed.to_json(),
            "capability_json": caps[d.sender],
            "sender_id": sender_id[d.sender].hex(),
            "task_id": tasks[d.sender].hex(),
            "action_scope": "x",
        }, d.is_attack)
        out.append(d2)

    return out, {sid: sender_card[name].card.public_key
                 for name, sid in sender_id.items()}


def _rss_kb() -> int:
    """Resident set size of this process in KB (Linux)."""

    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss


def run_one(*, n_agents: int, n_messages: int, scenario: str,
            seed: int, cross_threshold: int = 2) -> dict:
    pa = PolicyAuthority()
    bob_id = AgentID(b"BOB".ljust(32, b"\x00"))
    cgatc_mw = Middleware(
        my_agent_id=bob_id,
        enforcer=Enforcer(trusted_pa_pubkeys=[pa.public_key]),
        chain=SessionChainTracker(), replay=ReplayGuard(),
        risk=RiskScoreUpdater(), scope=ScopeReducer(),
        behavior=BehavioralDetector(), impact=ImpactGraph(),
        log=HashChainLog(bob_id),
    )
    cgatc_mw.cross_sender_payload_threshold = cross_threshold
    receiver = CGATCFullReceiver(middleware=cgatc_mw, audience=bob_id)

    if scenario == "benign":
        deliveries = benign_workload(
            seed=seed, n_messages=n_messages, n_senders=n_agents
        )
    elif scenario == "worm":
        deliveries = adversarial_worm_workload(
            seed=seed, n_messages=n_messages,
            n_infected=max(2, n_agents // 4),
            n_benign_senders=max(1, n_agents - n_agents // 4),
        )
    else:
        raise ValueError(scenario)

    rss_before = _rss_kb()
    t_setup0 = time.perf_counter()
    deliveries_cgatc, peer_pubkeys = _adapt_for_cgatc(
        deliveries, bob_id=bob_id, pa=pa, cross_threshold=cross_threshold,
    )
    setup_s = time.perf_counter() - t_setup0
    for sid, pk in peer_pubkeys.items():
        cgatc_mw.register_peer(sid, pk)

    tp = fp = tn = fn = 0
    latencies: list[float] = []
    for d in deliveries_cgatc:
        t0 = time.perf_counter()
        r = receiver.deliver(d)
        latencies.append(time.perf_counter() - t0)
        if d.is_attack:
            if r.verdict == Verdict.REJECT:
                tp += 1
            else:
                fn += 1
        else:
            if r.verdict == Verdict.ACCEPT:
                tn += 1
            else:
                fp += 1
    rss_after = _rss_kb()
    latencies.sort()

    return {
        "scenario": scenario,
        "n_agents": n_agents,
        "n_messages": n_messages,
        "tpr": tp / max(1, tp + fn),
        "fpr": fp / max(1, fp + tn),
        "median_latency_us": statistics.median(latencies) * 1e6,
        "p95_latency_us": latencies[int(len(latencies) * 0.95)] * 1e6,
        "throughput_per_s": len(latencies) / max(1e-9, sum(latencies)),
        "setup_seconds": setup_s,
        "rss_kb_before": rss_before,
        "rss_kb_after": rss_after,
        "rss_kb_delta": rss_after - rss_before,
    }


def main() -> None:
    matrix = []
    for n_agents in (10, 100, 1000):
        n_messages = max(200, n_agents * 2)
        for scenario in ("benign", "worm"):
            row = run_one(n_agents=n_agents, n_messages=n_messages,
                          scenario=scenario, seed=n_agents * 31 + len(scenario))
            matrix.append(row)
            print(f"[{scenario:>6s}  n_agents={n_agents:5d}  n_msg={n_messages:5d}]  "
                  f"TPR={row['tpr']:.2f}  FPR={row['fpr']:.2f}  "
                  f"med={row['median_latency_us']:7.1f}µs  "
                  f"thru={row['throughput_per_s']:7.0f}/s  "
                  f"setup={row['setup_seconds']:5.2f}s  "
                  f"rss_delta={row['rss_kb_delta']/1024:.1f}MB")

    out_dir = Path(__file__).resolve().parents[1] / "results" / (
        datetime.now(timezone.utc).strftime("%Y%m%d") + "_scale_eval"
    )
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "scale.json").write_text(json.dumps(matrix, indent=2))
    (out_dir / "meta.json").write_text(json.dumps({
        "python": sys.version, "platform": platform.platform(),
        "argv": sys.argv, "cwd": os.getcwd(),
    }, indent=2))
    print(f"\nWrote results to {out_dir}")


if __name__ == "__main__":
    main()
