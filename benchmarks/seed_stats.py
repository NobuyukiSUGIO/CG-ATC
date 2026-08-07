"""Aggregate a multi-seed adaptive sweep into the seed-dependence figures
reported in the paper (§V-A).

Consumes the tree written by ``benchmarks/run_seed_sweep.sh``::

    <root>/seed<NN>/<workload>__<baseline>.json

and reports, for every defence:

* the per-workload mean and population standard deviation of the attack
  success rate (ASR) across seeds, over the *adversarial* workloads only;
* the worst single (workload, seed) ASR;
* whether the defence reaches ASR 1.000 on at least one adversarial workload
  at *every* seed — the property the paper claims separates CG-ATC from the
  baselines.

``benign_broadcast`` is excluded from the adversarial aggregates because it
carries no attack; its false-positive rate is reported separately.

Usage::

    PYTHONPATH=. python -m benchmarks.seed_stats --root results/adaptive/<run>
"""

from __future__ import annotations

import argparse
import json
import os
import statistics
from typing import Any

BENIGN = "benign_broadcast"

# Display order; matches the paper's table.
BASELINES = [
    "auth_only",
    "tls_oauth",
    "cap_no_audit",
    "anomaly_no_crypto",
    "baseline_mtls_nonce",
    "baseline_signed_jwt",
    "baseline_capability_central_audit",
    "baseline_anomaly_signed_logs",
    "baseline_opa_rego",
    "cg_atc",
]


def load(root: str) -> dict[tuple[str, str, int], dict[str, Any]]:
    """Load every result JSON under ``root`` keyed by (workload, baseline, seed)."""

    out: dict[tuple[str, str, int], dict[str, Any]] = {}
    for entry in sorted(os.listdir(root)):
        if not entry.startswith("seed"):
            continue
        seed = int(entry[4:])
        seed_dir = os.path.join(root, entry)
        for f in sorted(os.listdir(seed_dir)):
            if not f.endswith(".json") or f == "meta.json":
                continue
            workload, _, baseline = f[: -len(".json")].partition("__")
            with open(os.path.join(seed_dir, f), encoding="utf-8") as fh:
                out[(workload, baseline, seed)] = json.load(fh)
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--root", required=True, help="sweep directory containing seed<NN>/ subdirectories")
    ap.add_argument("--json-out", default=None, help="also write the aggregate as JSON")
    args = ap.parse_args()

    data = load(args.root)
    if not data:
        raise SystemExit(f"no results found under {args.root}")

    seeds = sorted({k[2] for k in data})
    workloads = sorted({k[0] for k in data})
    adversarial = [w for w in workloads if w != BENIGN]
    present = [b for b in BASELINES if any(k[1] == b for k in data)]

    print(f"root      : {args.root}")
    print(f"seeds     : {seeds[0]}-{seeds[-1]} ({len(seeds)})")
    print(f"workloads : {len(workloads)} ({len(adversarial)} adversarial + benign)")
    print(f"defences  : {len(present)}")
    print(f"runs      : {len(data)}\n")

    summary: dict[str, Any] = {"seeds": seeds, "defences": {}}

    for b in present:
        per_wl: dict[str, dict[str, float]] = {}
        worst = 0.0
        saturates_every_seed = True
        for w in adversarial:
            vals = [data[(w, b, s)]["attack_success_rate"] for s in seeds if (w, b, s) in data]
            if not vals:
                continue
            per_wl[w] = {
                "mean": statistics.fmean(vals),
                "sd": statistics.pstdev(vals),
                "max": max(vals),
            }
            worst = max(worst, max(vals))
        for s in seeds:
            hit = any(
                (w, b, s) in data and data[(w, b, s)]["attack_success_rate"] >= 1.0 for w in adversarial
            )
            if not hit:
                saturates_every_seed = False
        benign_fpr = [data[(BENIGN, b, s)]["false_positive_rate"] for s in seeds if (BENIGN, b, s) in data]

        summary["defences"][b] = {
            "per_workload": per_wl,
            "worst_asr": worst,
            "asr_1_every_seed": saturates_every_seed,
            "benign_fpr_mean": statistics.fmean(benign_fpr) if benign_fpr else None,
        }

        print(f"=== {b}")
        for w, st in sorted(per_wl.items()):
            print(f"    {w:38s} mean={st['mean']:.3f} +/- {st['sd']:.3f}   max={st['max']:.3f}")
        print(f"    worst (workload, seed) ASR            : {worst:.3f}")
        print(f"    reaches ASR 1.000 at every seed       : {saturates_every_seed}")
        if benign_fpr:
            print(f"    benign_broadcast FPR (mean over seeds): {statistics.fmean(benign_fpr):.3f}")
        print()

    others = [b for b in present if b != "cg_atc"]
    print("all non-CG-ATC defences reach ASR 1.000 on some adversarial workload at every seed: "
          f"{all(summary['defences'][b]['asr_1_every_seed'] for b in others)}")

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as fh:
            json.dump(summary, fh, indent=1, sort_keys=True)
        print(f"\nwrote {args.json_out}")


if __name__ == "__main__":
    main()
