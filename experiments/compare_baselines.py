"""Baseline comparison driver (CLAUDE.md §6.2).

Runs each of the five baselines from `cgatc/baselines/` against three
adversarial workloads from `experiments/workloads/` and reports
TPR / FPR / mean delivery latency.

The CG-ATC baseline needs more setup (envelope + capability) than the
others, so we synthesise the per-message metadata in this driver
rather than in the workload generators (which are baseline-agnostic).
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
from cgatc.audit import HashChainLog
from cgatc.baselines import (
    AnomalyNoCryptoReceiver,
    AuthOnlyReceiver,
    CapNoAuditReceiver,
    CGATCFullReceiver,
    Delivery,
    Receiver,
    TLSOAuthReceiver,
    Verdict,
)
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
from experiments.plotting import plot_baseline_comparison_csv, render_text_table
from experiments.workloads import (
    adversarial_collusion_workload,
    adversarial_replay_workload,
    adversarial_worm_workload,
    benign_workload,
)


def _ssid_random() -> SessionID:
    return SessionID.random()


def _build_card(name: str, scopes: list[str]):  # type: ignore[no-untyped-def]
    kp = generate_keypair()
    card = build_card(
        keypair=kp, model_hash=compute_model_hash(name),
        policy_hash=compute_policy_hash({"name": name}),
        env_attest=collect_local_env_attest(),
        scopes=scopes, expiry=time.time() + 3600,
    )
    return kp, sign_card(card, kp)


# ---------------------------------------------------------------------------
# Per-baseline metadata adaptation: attach what the receiver expects.
# ---------------------------------------------------------------------------
def adapt_for_auth_only(deliveries: list[Delivery]) -> list[Delivery]:
    return [
        Delivery(d.sender, d.payload,
                 {**d.metadata, "auth_token": f"static-{d.sender}"},
                 d.is_attack)
        for d in deliveries
    ]


def adapt_for_oauth(deliveries: list[Delivery]) -> list[Delivery]:
    return [
        Delivery(d.sender, d.payload,
                 {**d.metadata, "oauth_bearer": f"bearer-{d.sender}"},
                 d.is_attack)
        for d in deliveries
    ]


def adapt_for_cgatc(
    deliveries: list[Delivery],
    *,
    bob_id: AgentID,
    pa: PolicyAuthority,
) -> tuple[list[Delivery], dict[str, object]]:
    """Materialise envelopes + capabilities for each delivery.

    Each unique sender in the workload is given a fresh CG-ATC identity
    on first appearance.  Replay messages reuse the prior envelope.
    """

    sender_kp: dict[str, object] = {}
    sender_card: dict[str, SignedCard] = {}
    sender_id: dict[str, AgentID] = {}
    sessions: dict[str, SessionID] = {}
    tasks: dict[str, TaskID] = {}
    caps: dict[str, str] = {}      # sender -> capability JSON
    seqs: dict[str, int] = {}
    last_envelope: dict[str, str] = {}  # sender -> envelope JSON for replay
    last_payload: dict[str, bytes] = {}
    last_digest: dict[str, bytes] = {}  # sender -> digest of last envelope (chain head)

    out: list[Delivery] = []
    for d in deliveries:
        if d.sender not in sender_kp:
            kp, card = _build_card(d.sender, ["x"])
            sender_kp[d.sender] = kp
            sender_card[d.sender] = card
            sender_id[d.sender] = card.card.agent_id
            sessions[d.sender] = _ssid_random()
            tasks[d.sender] = TaskID.random()
            cap = pa.issue(
                subject=card.card.agent_id, audience=bob_id,
                task_id=tasks[d.sender], scopes=["x"],
                constraints=Constraints(),
            )
            caps[d.sender] = cap.to_json()
            seqs[d.sender] = 0
            last_digest[d.sender] = b"\x00" * 32  # GENESIS_PREV_HASH

        if d.metadata.get("is_replay") and d.sender in last_envelope:
            env_json = last_envelope[d.sender]
            payload = last_payload[d.sender]
        else:
            env = build_envelope(
                session_id=sessions[d.sender], task_id=tasks[d.sender],
                seq=seqs[d.sender],
                sender_id=sender_id[d.sender], receiver_id=bob_id,
                msg_type=MessageType.REQUEST, payload=d.payload,
                prev_hash=last_digest[d.sender],
            )
            signed = sign_envelope(env, sender_kp[d.sender])  # type: ignore[arg-type]
            env_json = signed.to_json()
            payload = d.payload
            last_envelope[d.sender] = env_json
            last_payload[d.sender] = payload
            last_digest[d.sender] = env.digest()
            seqs[d.sender] += 1

        meta = {
            **d.metadata,
            "envelope_json": env_json,
            "capability_json": caps[d.sender],
            "sender_id": sender_id[d.sender].hex(),
            "task_id": tasks[d.sender].hex(),
            "action_scope": "x",
        }
        out.append(Delivery(d.sender, payload, meta, d.is_attack))

    # Pre-register peers with Bob's middleware
    return out, {
        "peer_pubkeys": {
            sid: sender_card[name].card.public_key
            for name, sid in sender_id.items()
        },
    }


def adapt_for_capability(
    deliveries: list[Delivery],
    *,
    audience: AgentID,
    pa: PolicyAuthority,
) -> list[Delivery]:
    sender_id: dict[str, AgentID] = {}
    tasks: dict[str, TaskID] = {}
    caps: dict[str, str] = {}
    out: list[Delivery] = []
    for d in deliveries:
        if d.sender not in sender_id:
            sender_id[d.sender] = AgentID(d.sender.encode().ljust(32, b"\x00")[:32])
            tasks[d.sender] = TaskID.random()
            cap = pa.issue(
                subject=sender_id[d.sender], audience=audience,
                task_id=tasks[d.sender], scopes=["x"],
                constraints=Constraints(),
            )
            caps[d.sender] = cap.to_json()
        meta = {
            **d.metadata,
            "capability_json": caps[d.sender],
            "sender_id": sender_id[d.sender].hex(),
            "task_id": tasks[d.sender].hex(),
            "action_scope": "x",
        }
        out.append(Delivery(d.sender, d.payload, meta, d.is_attack))
    return out


# ---------------------------------------------------------------------------
# Per-receiver evaluation
# ---------------------------------------------------------------------------
def evaluate(receiver: Receiver, deliveries: list[Delivery]) -> dict[str, float]:
    tp = fp = tn = fn = 0
    latencies: list[float] = []
    for d in deliveries:
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
    latencies.sort()
    return {
        "baseline": receiver.name,
        "tpr": tp / max(1, tp + fn),
        "fpr": fp / max(1, fp + tn),
        "latency_us": statistics.median(latencies) * 1e6,
        "n_messages": len(deliveries),
    }


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------
def run_for_workload(workload_name: str, deliveries: list[Delivery]) -> list[dict[str, float]]:
    pa = PolicyAuthority()
    bob_id = AgentID(b"BOB".ljust(32, b"\x00"))

    # Receivers
    auth = AuthOnlyReceiver(known_tokens={
        s: f"static-{s}" for s in {d.sender for d in deliveries}
    })
    oauth = TLSOAuthReceiver(
        bearer_scopes={f"bearer-{s}": ["tools.read"] for s in {d.sender for d in deliveries}},
        accept_scopes=["tools.read"],
    )
    cap_only = CapNoAuditReceiver(
        enforcer=Enforcer(trusted_pa_pubkeys=[pa.public_key]),
        audience=bob_id,
    )
    anomaly = AnomalyNoCryptoReceiver(threshold=0.5)
    cgatc_mw = Middleware(
        my_agent_id=bob_id,
        enforcer=Enforcer(trusted_pa_pubkeys=[pa.public_key]),
        chain=SessionChainTracker(), replay=ReplayGuard(),
        risk=RiskScoreUpdater(), scope=ScopeReducer(),
        behavior=BehavioralDetector(), impact=ImpactGraph(),
        log=HashChainLog(bob_id),
    )
    # Stricter cross-sender payload threshold so 2-party collusion is
    # caught.  Production deployments would tune this per workload.
    cgatc_mw.cross_sender_payload_threshold = 2
    cgatc = CGATCFullReceiver(middleware=cgatc_mw, audience=bob_id)

    rows: list[dict[str, float]] = []
    rows.append({"workload": workload_name,
                 **evaluate(auth, adapt_for_auth_only(deliveries))})
    rows.append({"workload": workload_name,
                 **evaluate(oauth, adapt_for_oauth(deliveries))})
    rows.append({"workload": workload_name,
                 **evaluate(cap_only, adapt_for_capability(deliveries, audience=bob_id, pa=pa))})
    rows.append({"workload": workload_name,
                 **evaluate(anomaly, deliveries)})

    cgatc_deliveries, cgatc_state = adapt_for_cgatc(deliveries, bob_id=bob_id, pa=pa)
    for sid, pk in cgatc_state["peer_pubkeys"].items():  # type: ignore[union-attr]
        cgatc_mw.register_peer(sid, pk)
    rows.append({"workload": workload_name, **evaluate(cgatc, cgatc_deliveries)})
    return rows


def main() -> None:
    workloads = [
        ("benign", benign_workload(seed=1)),
        ("replay", adversarial_replay_workload(seed=2)),
        ("worm", adversarial_worm_workload(seed=3)),
        ("collusion", adversarial_collusion_workload(seed=4)),
    ]
    all_rows: list[dict[str, float]] = []
    for name, deliveries in workloads:
        all_rows.extend(run_for_workload(name, deliveries))

    out_dir = Path(__file__).resolve().parents[1] / "results" / (
        datetime.now(timezone.utc).strftime("%Y%m%d") + "_baseline_compare"
    )
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "baselines.json").write_text(json.dumps(all_rows, indent=2))
    (out_dir / "meta.json").write_text(json.dumps({
        "python": sys.version, "platform": platform.platform(),
        "argv": sys.argv, "cwd": os.getcwd(),
    }, indent=2))

    # Pretty-print + CSV/PNG
    headers = ["workload", "baseline", "tpr", "fpr", "latency_us", "n_messages"]
    print(render_text_table(all_rows, headers))
    plot_baseline_comparison_csv(all_rows, out_dir=out_dir)
    print(f"\nWrote results to {out_dir}")


if __name__ == "__main__":
    main()
