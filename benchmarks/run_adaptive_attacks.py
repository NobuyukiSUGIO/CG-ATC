"""CLI for adaptive-attack experiments (spec §4 "Experiment execution commands")::

    python benchmarks/run_adaptive_attacks.py \\
      --workload paraphrased_worm \\
      --baseline cg_atc \\
      --num-agents 100 \\
      --num-messages 1000 \\
      --seed 42 \\
      --output results/adaptive/paraphrased_worm_cg_atc.json

Output: a JSON file with the :class:`Metrics` payload plus a sibling
``meta.json`` carrying provenance ({workload, seed, num_agents,
num_messages, attack_ratio, policy, baseline, timestamp}).
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import sys
from datetime import datetime, timezone
from pathlib import Path

# Make the repo importable when this script is run as a file.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from benchmarks.baselines import list_baselines, make_baseline  # noqa: E402
from benchmarks.materialize import Crew  # noqa: E402
from benchmarks.runner import evaluate, metrics_to_dict  # noqa: E402
from benchmarks.workloads import list_workloads, make_workload  # noqa: E402


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="run_adaptive_attacks",
                                description="CG-ATC adaptive-attack benchmark CLI")
    p.add_argument("--workload", required=True, choices=list_workloads())
    p.add_argument("--baseline", required=True, choices=list_baselines())
    p.add_argument("--num-agents", type=int, default=100)
    p.add_argument("--num-messages", type=int, default=1000)
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--output", required=True,
                   help="Path to write the metrics JSON to.")
    p.add_argument("--replay-delay-sec", type=int, default=60,
                   help="Replay delay window for delayed_replay workload.")
    p.add_argument("--broadcast-unauthorized", action="store_true",
                   help="Run benign_broadcast in its unauthorised variant "
                        "(coordinator lacks the 'broadcast' scope).")
    p.add_argument("--save-events", action="store_true",
                   help="Also write per-message events to <output>.events.json.")
    return p


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    # Construct the workload (some take CLI knobs).
    wl_kwargs: dict[str, object] = {}
    if args.workload == "delayed_replay":
        wl_kwargs["replay_delay_sec"] = args.replay_delay_sec
    if args.workload == "benign_broadcast" and args.broadcast_unauthorized:
        wl_kwargs["authorized"] = False
    workload = make_workload(args.workload, **wl_kwargs)

    # Workload generates its own crew; we rebuild a fresh Crew with the same
    # seed for the receiver so it can pre-register peer pubkeys.  Both crews
    # are deterministic in (seed, agent_name).
    messages = workload.generate(
        seed=args.seed, num_agents=args.num_agents, num_messages=args.num_messages,
    )
    crew = Crew(seed=args.seed)
    # Each message's metadata["sender_role"] carries the canonical role the
    # workload used.  We replicate it here so the deterministic agent_id
    # derivation matches across workload and receiver crew.  Receivers that
    # appear only as audiences are looked up via metadata["receiver_role"]
    # if present, otherwise default to "worker".
    role_for: dict[str, str] = {}
    for m in messages:
        if m.sender_id not in role_for:
            role_for[m.sender_id] = str(m.metadata.get("sender_role", "worker"))
        if m.receiver_id not in role_for:
            role_for[m.receiver_id] = str(m.metadata.get("receiver_role", "worker"))
    for name, role in role_for.items():
        crew.make(name, role=role)
    receiver = make_baseline(args.baseline, crew=crew)

    metrics, events = evaluate(
        workload=workload,
        receiver=receiver,
        seed=args.seed,
        num_agents=args.num_agents,
        num_messages=args.num_messages,
        messages=messages,
    )

    out_path = Path(args.output).resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(metrics_to_dict(metrics), indent=2))

    # Sibling meta.json
    meta = {
        "workload": args.workload,
        "baseline": args.baseline,
        "seed": args.seed,
        "num_agents": args.num_agents,
        "num_messages": args.num_messages,
        "attack_ratio": _attack_ratio(messages),
        "policy": "default",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "argv": sys.argv,
        "cwd": os.getcwd(),
    }
    (out_path.parent / "meta.json").write_text(json.dumps(meta, indent=2))

    if args.save_events:
        ev_path = out_path.with_suffix(out_path.suffix + ".events.json")
        ev_path.write_text(json.dumps(events, indent=2, default=str))

    print(f"[{args.workload} / {args.baseline}] "
          f"ASR={metrics.attack_success_rate:.3f} "
          f"TPR={metrics.true_positive_rate:.3f} "
          f"FPR={metrics.false_positive_rate:.3f} "
          f"FCR={metrics.false_containment_rate:.3f} "
          f"depth={metrics.max_propagation_depth} "
          f"affected={metrics.num_affected_agents} "
          f"blocked={metrics.num_blocked_messages} "
          f"allowed_harmful={metrics.num_allowed_harmful_messages} "
          f"median_us={metrics.median_latency_us:.1f}")
    print(f"  → {out_path}")
    return 0


def _attack_ratio(messages: list) -> float:
    if not messages:
        return 0.0
    n_attack = sum(1 for m in messages if m.is_attack)
    return n_attack / len(messages)


def _role_for(name: str) -> str:
    if name.startswith("incident_") or "coordinator" in name:
        return "coordinator"
    if name.startswith("analyst_") or name == "analyst_audience":
        return "analyst_agent"
    return "worker"


if __name__ == "__main__":
    raise SystemExit(main())
