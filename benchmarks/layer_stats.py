"""Classify CG-ATC's per-message decisions by the layer that blocked them.

Regenerates the empirical layer-responsibility table of the paper (§V-D) from
the ``--save-events`` output of ``benchmarks/run_adaptive_attacks.py``::

    PYTHONPATH=. python benchmarks/run_adaptive_attacks.py \
        --workload paraphrased_worm --baseline cg_atc \
        --num-agents 100 --num-messages 1000 --seed 42 \
        --save-events --output <dir>/paraphrased_worm__cg_atc.json
    PYTHONPATH=. python -m benchmarks.layer_stats --root <dir>

Each blocked message is attributed to exactly one layer, in the order
crypto -> capability -> policy -> containment: a message stopped by a
signature failure is a crypto block even if its risk score was also high.
``blocked_reason`` may carry several comma-separated reasons; the
highest-precedence one wins.

``benign_broadcast`` contributes two rows when both variants have been run:
the authorised one (the default) and the unauthorised one, produced with
``--broadcast-unauthorized``. Give the two runs distinct output names so the
rows do not collide.

Any reason string the classifier does not recognise is counted in an
``unclassified`` column rather than silently folded into a layer.
"""

from __future__ import annotations

import argparse
import json
import os
from typing import Any

# Precedence order matters: the first matching layer claims the message.
CRYPTO = {
    "SignatureVerificationError",
    "SequenceError",
    "StaleTimestampError",
    "ChainError",
    "ReplayError",
    "EnvelopeError",
    "NonceReuseError",
    "AgentCardError",
    "AuditTamperingError",
}
CAPABILITY = {
    "CapabilityScopeError",
    "CapabilityExpiredError",
    "CapabilityAudienceError",
    "CapabilitySubjectError",
    "CapabilityTaskError",
    "CapabilitySignatureError",
    "CapabilityError",
}
POLICY = {
    "suspicious_instruction_pattern",
    "memory_provenance_risk_write",
    "memory_provenance_risk_read",
    "threshold_authorization_required",
    "PromptFanout",
    "policy_violation",
    "semantic_policy_violation",
    "collusive_consensus",
    "excessive_fanout",
}
CONTAINMENT = {
    "impact_radius_quarantined",
    "containment_isolated",
    "scope_reduced",
    "credentials_revoked",
}

LAYERS = ("crypto", "capability", "policy", "containment")


def classify(reason: str | None) -> str | None:
    """Return the layer that blocked a message, or None if it was accepted."""

    if not reason:
        return None
    parts = [p.strip() for p in reason.split(",") if p.strip()]
    for layer, vocab in zip(LAYERS, (CRYPTO, CAPABILITY, POLICY, CONTAINMENT), strict=True):
        if any(p in vocab for p in parts):
            return layer
    return "unclassified"


def summarise(events: list[dict[str, Any]]) -> dict[str, int]:
    row = dict.fromkeys(LAYERS, 0)
    row["unclassified"] = 0
    row["allowed_harmful"] = 0
    for e in events:
        layer = classify(e.get("blocked_reason"))
        if layer is None:
            if e.get("is_attack"):
                row["allowed_harmful"] += 1
        else:
            row[layer] += 1
    return row


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--root", required=True, help="directory holding *.events.json files")
    ap.add_argument("--csv-out", default=None)
    args = ap.parse_args()

    rows: list[tuple[str, dict[str, int]]] = []
    unknown: set[str] = set()

    for f in sorted(os.listdir(args.root)):
        if not f.endswith(".events.json"):
            continue
        workload = f.split("__")[0]
        with open(os.path.join(args.root, f), encoding="utf-8") as fh:
            events = json.load(fh)

        for e in events:
            r = e.get("blocked_reason")
            if r and classify(r) == "unclassified":
                unknown.update(p.strip() for p in r.split(","))

        rows.append((workload, summarise(events)))

    cols = [*LAYERS, "unclassified", "allowed_harmful"]
    width = max(len(r[0]) for r in rows) + 2
    print(f"{'workload':{width}s}" + "".join(f"{c:>16s}" for c in cols))
    for name, row in rows:
        print(f"{name:{width}s}" + "".join(f"{row[c]:16d}" for c in cols))

    if unknown:
        print(f"\nWARNING unclassified blocked_reason values: {sorted(unknown)}")
    else:
        print("\nall blocked_reason values classified")

    if args.csv_out:
        with open(args.csv_out, "w", encoding="utf-8") as fh:
            fh.write("Workload," + ",".join(cols) + "\n")
            for name, row in rows:
                fh.write(name + "," + ",".join(str(row[c]) for c in cols) + "\n")
        print(f"wrote {args.csv_out}")


if __name__ == "__main__":
    main()
