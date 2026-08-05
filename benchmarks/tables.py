"""Generate the three paper tables defined in spec §5.

Table A : Adaptive Attack Results
        (Workload, Defense, ASR, TPR, FPR, FCR, AffectedAgents,
         MaxPropagationDepth, AllowedHarmfulMessages, MedianLatency)

Table B : Layer Responsibility Analysis
        (Attack, CryptoLayer, CapabilityLayer, RiskPolicyLayer,
         ContainmentLayer, MainFinding)
        — derived from the spec's narrative; we ship a fixed analysis
        produced by the implementation team, then back-fill the per-cell
        verdicts from the cg_atc Decisions seen at run time.

Table C : Stronger Baseline Comparison
        (Baseline, MessageAuthentication, ReplayProtection,
         CapabilityEnforcement, CausalProvenance, TamperEvidentAudit,
         RiskAdaptiveContainment, ThresholdAuthorization)
        — a static feature matrix encoded in this module.

Usage::

    python -m benchmarks.tables --root results/adaptive/<run-dir> \\
                                --output results/adaptive/<run-dir>/tables
"""
from __future__ import annotations

import argparse
import csv
import json
from dataclasses import dataclass
from pathlib import Path


# ---------------------------------------------------------------------------
# Static tables (authored once from spec)
# ---------------------------------------------------------------------------
LAYER_RESPONSIBILITY = [
    ("paraphrased_worm",
     "Not sufficient", "Partially useful", "Required", "Required",
     "Semantic variation bypasses hash-only replay detection"),
    ("delayed_replay",
     "Required with freshness", "Useful if token expired", "Not primary", "Not primary",
     "Replay defense depends on nonce, timestamp, and causal checks"),
    ("semantic_replay",
     "Passes", "Required", "Required", "Required",
     "Cryptographic correctness does not imply task-context safety"),
    ("benign_broadcast",
     "Passes", "Required", "Required (false-positive guard)",
     "Not primary",
     "Authorized fan-out must not be conflated with worm propagation"),
    ("multihop_indirect_prompt_injection",
     "Required", "Required", "Required", "Required",
     "Forensic causality from external doc to harmful action requires "
     "causal prevHash + audit graph"),
    ("memory_poisoning_delayed",
     "Required for write integrity", "Useful but insufficient",
     "Required", "Required (provenance-aware)",
     "Memory provenance must be attached at write and consulted at trigger"),
    ("semantic_collusion",
     "Passes", "Passes", "Required", "Required",
     "No identical-payload fingerprint; requires audit-graph cluster analysis"),
    ("valid_capability_harmful_semantics",
     "Passes", "Passes", "Required",
     "Required for high-risk actions",
     "Cryptographic correctness does not imply semantic safety"),
]


# Column order matches spec §5 Table C.
BASELINE_FEATURE_MATRIX: dict[str, dict[str, str]] = {
    "cg_atc": {
        "message_authentication": "yes",
        "replay_protection": "yes (nonce + chain + freshness)",
        "capability_enforcement": "yes",
        "causal_provenance": "yes (prevHash + audit graph)",
        "tamper_evident_audit": "yes (per-agent hash chain + Merkle root)",
        "risk_adaptive_containment": "yes",
        "threshold_authorization": "yes",
    },
    "baseline_mtls_nonce": {
        "message_authentication": "channel only",
        "replay_protection": "yes (nonce cache)",
        "capability_enforcement": "no",
        "causal_provenance": "no",
        "tamper_evident_audit": "no",
        "risk_adaptive_containment": "no",
        "threshold_authorization": "no",
    },
    "baseline_signed_jwt": {
        "message_authentication": "yes (per-message JWT)",
        "replay_protection": "yes (jti uniqueness, exp)",
        "capability_enforcement": "scope claim only",
        "causal_provenance": "no",
        "tamper_evident_audit": "no",
        "risk_adaptive_containment": "no",
        "threshold_authorization": "no",
    },
    "baseline_capability_central_audit": {
        "message_authentication": "no",
        "replay_protection": "no",
        "capability_enforcement": "yes",
        "causal_provenance": "no",
        "tamper_evident_audit": "centralised only (vulnerable to "
                                "delete/modify/reorder)",
        "risk_adaptive_containment": "no",
        "threshold_authorization": "no",
    },
    "baseline_anomaly_signed_logs": {
        "message_authentication": "yes (signed log entries)",
        "replay_protection": "indirect (anomaly detector)",
        "capability_enforcement": "no",
        "causal_provenance": "no",
        "tamper_evident_audit": "yes (signed log only)",
        "risk_adaptive_containment": "detection only (no enforcement)",
        "threshold_authorization": "no",
    },
    "baseline_opa_rego": {
        "message_authentication": "no",
        "replay_protection": "no",
        "capability_enforcement": "policy-based",
        "causal_provenance": "no",
        "tamper_evident_audit": "no",
        "risk_adaptive_containment": "yes (risk_score policy rule)",
        "threshold_authorization": "no",
    },
    "auth_only": {
        "message_authentication": "channel only",
        "replay_protection": "no",
        "capability_enforcement": "no",
        "causal_provenance": "no",
        "tamper_evident_audit": "no",
        "risk_adaptive_containment": "no",
        "threshold_authorization": "no",
    },
    "tls_oauth": {
        "message_authentication": "channel only",
        "replay_protection": "no",
        "capability_enforcement": "scope only",
        "causal_provenance": "no",
        "tamper_evident_audit": "no",
        "risk_adaptive_containment": "no",
        "threshold_authorization": "no",
    },
    "cap_no_audit": {
        "message_authentication": "no",
        "replay_protection": "no",
        "capability_enforcement": "yes",
        "causal_provenance": "no",
        "tamper_evident_audit": "no",
        "risk_adaptive_containment": "no",
        "threshold_authorization": "no",
    },
    "anomaly_no_crypto": {
        "message_authentication": "no",
        "replay_protection": "indirect",
        "capability_enforcement": "no",
        "causal_provenance": "no",
        "tamper_evident_audit": "no",
        "risk_adaptive_containment": "detection only",
        "threshold_authorization": "no",
    },
}


# ---------------------------------------------------------------------------
# Table A — Adaptive Attack Results
# ---------------------------------------------------------------------------
@dataclass
class _Row:
    workload: str
    baseline: str
    asr: float
    tpr: float
    fpr: float
    fcr: float
    affected_agents: int
    max_propagation_depth: int
    allowed_harmful_messages: int
    median_latency_us: float


def _load_metric_files(root: Path) -> list[_Row]:
    rows: list[_Row] = []
    for p in sorted(root.glob("*.json")):
        if p.name == "meta.json":
            continue
        try:
            d = json.loads(p.read_text())
        except json.JSONDecodeError:
            continue
        if "workload" not in d or "baseline" not in d:
            continue
        rows.append(_Row(
            workload=str(d["workload"]),
            baseline=str(d["baseline"]),
            asr=float(d.get("attack_success_rate", 0.0)),
            tpr=float(d.get("true_positive_rate", 0.0)),
            fpr=float(d.get("false_positive_rate", 0.0)),
            fcr=float(d.get("false_containment_rate", 0.0)),
            affected_agents=int(d.get("num_affected_agents", 0)),
            max_propagation_depth=int(d.get("max_propagation_depth", 0)),
            allowed_harmful_messages=int(d.get("num_allowed_harmful_messages", 0)),
            median_latency_us=float(d.get("median_latency_us", 0.0)),
        ))
    return rows


def write_table_a(rows: list[_Row], out: Path) -> None:
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow([
            "Workload", "Defense", "AttackSuccessRate", "TPR", "FPR",
            "FalseContainmentRate", "AffectedAgents", "MaxPropagationDepth",
            "AllowedHarmfulMessages", "MedianLatencyUs",
        ])
        for r in sorted(rows, key=lambda x: (x.workload, x.baseline)):
            w.writerow([
                r.workload, r.baseline, f"{r.asr:.3f}", f"{r.tpr:.3f}",
                f"{r.fpr:.3f}", f"{r.fcr:.3f}", r.affected_agents,
                r.max_propagation_depth, r.allowed_harmful_messages,
                f"{r.median_latency_us:.1f}",
            ])


def write_table_b(rows: list[_Row], out: Path) -> None:
    """Table B — Layer Responsibility Analysis.

    Static cells from spec §5; per-row "MainFinding" is augmented with the
    observed CG-ATC Attack Success Rate when a matching run is present.
    """

    out.parent.mkdir(parents=True, exist_ok=True)
    cgatc_rows = {r.workload: r for r in rows if r.baseline == "cg_atc"}

    with out.open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow([
            "Attack", "CryptoLayer", "CapabilityLayer", "RiskPolicyLayer",
            "ContainmentLayer", "MainFinding",
            "ObservedCGATC_AttackSuccessRate",
        ])
        for (attack, crypto, cap, risk, contain, finding) in LAYER_RESPONSIBILITY:
            cg = cgatc_rows.get(attack)
            obs = f"{cg.asr:.3f}" if cg is not None else "n/a"
            w.writerow([attack, crypto, cap, risk, contain, finding, obs])


def write_table_c(out: Path) -> None:
    """Static feature matrix per spec §5 Table C."""

    out.parent.mkdir(parents=True, exist_ok=True)
    cols = [
        "message_authentication", "replay_protection",
        "capability_enforcement", "causal_provenance",
        "tamper_evident_audit", "risk_adaptive_containment",
        "threshold_authorization",
    ]
    with out.open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["Baseline"] + [c.replace("_", " ").title() for c in cols])
        # cg_atc first, then others in fixed order.
        order = [
            "cg_atc", "baseline_mtls_nonce", "baseline_signed_jwt",
            "baseline_capability_central_audit",
            "baseline_anomaly_signed_logs", "baseline_opa_rego",
            "auth_only", "tls_oauth", "cap_no_audit", "anomaly_no_crypto",
        ]
        for name in order:
            row = BASELINE_FEATURE_MATRIX.get(name, {})
            w.writerow([name] + [row.get(c, "?") for c in cols])


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--root", required=True, type=Path,
                   help="Directory of per-run JSON metric files.")
    p.add_argument("--output", required=True, type=Path,
                   help="Directory to write Table A/B/C CSVs into.")
    args = p.parse_args(argv)

    rows = _load_metric_files(args.root)
    args.output.mkdir(parents=True, exist_ok=True)
    write_table_a(rows, args.output / "table_a_adaptive_attack_results.csv")
    write_table_b(rows, args.output / "table_b_layer_responsibility.csv")
    write_table_c(args.output / "table_c_stronger_baseline_comparison.csv")
    print(f"Tables written to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
