"""Workload×Receiver harness that produces :class:`Metrics`.

The harness:

1. iterates the message stream once,
2. calls ``receiver.receive(message)`` per message,
3. tallies attack-success / TPR / FPR / false-containment / latency / etc.
4. computes the spec's full :class:`Metrics` table.
"""
from __future__ import annotations

import statistics
from dataclasses import asdict
from typing import Iterable

from .interfaces import Decision, Message, Metrics, Receiver, Workload


def _percentile(xs: list[float], p: float) -> float:
    if not xs:
        return 0.0
    s = sorted(xs)
    k = max(0, min(len(s) - 1, int(round((p / 100.0) * (len(s) - 1)))))
    return s[k]


def evaluate(
    *,
    workload: Workload,
    receiver: Receiver,
    seed: int,
    num_agents: int,
    num_messages: int,
    messages: list[Message] | None = None,
) -> tuple[Metrics, list[dict[str, object]]]:
    """Run ``workload`` once through ``receiver`` and return Metrics + raw events.

    Re-using a pre-generated ``messages`` list keeps multiple baselines
    consuming the *same* attacker traffic (important for fair comparison).
    """

    if messages is None:
        messages = workload.generate(seed=seed, num_agents=num_agents, num_messages=num_messages)

    tp = fp = tn = fn = 0
    attack_succeeded = 0
    blocked_messages = 0
    allowed_harmful = 0
    affected_agents: set[str] = set()
    detection_latencies: list[int] = []
    containment_latencies: list[int] = []
    per_msg_latency_us: list[float] = []
    max_depth_attack = 0
    max_depth_attack_blocked = 0
    false_containment_count = 0
    benign_total = 0
    first_attack_seen_idx: int | None = None
    first_detection_idx: int | None = None
    first_containment_idx: int | None = None
    raw_events: list[dict[str, object]] = []

    for idx, msg in enumerate(messages):
        decision: Decision = receiver.receive(msg)
        per_msg_latency_us.append(decision.latency_us)
        contained = (
            (not decision.accepted)
            or decision.containment_level
            not in {"normal", "increased_monitoring"}
        )

        is_attack_msg = msg.is_attack
        ground_truth_block_required = msg.expected_block

        if is_attack_msg:
            if first_attack_seen_idx is None:
                first_attack_seen_idx = idx
            if not decision.accepted:
                tp += 1
                blocked_messages += 1
                if first_detection_idx is None:
                    first_detection_idx = idx
                if first_containment_idx is None and contained:
                    first_containment_idx = idx
                max_depth_attack_blocked = max(max_depth_attack_blocked, msg.hop_depth)
            else:
                fn += 1
                affected_agents.add(msg.sender_id)
                affected_agents.add(msg.receiver_id)
                if ground_truth_block_required:
                    attack_succeeded += 1
                    allowed_harmful += 1
                max_depth_attack = max(max_depth_attack, msg.hop_depth)
        else:
            benign_total += 1
            if decision.accepted:
                tn += 1
            else:
                fp += 1
                blocked_messages += 1
                if contained:
                    false_containment_count += 1

        raw_events.append({
            "idx": idx,
            "sender": msg.sender_id,
            "receiver": msg.receiver_id,
            "is_attack": is_attack_msg,
            "attack_kind": msg.attack_kind,
            "accepted": decision.accepted,
            "blocked_reason": decision.blocked_reason,
            "risk": decision.risk_score,
            "containment": decision.containment_level,
            "latency_us": decision.latency_us,
            "hop_depth": msg.hop_depth,
        })

    n_attacks = tp + fn
    metrics = Metrics(
        workload=workload.name,
        baseline=getattr(receiver, "name", type(receiver).__name__),
        num_agents=num_agents,
        num_messages=len(messages),
        attack_success_rate=(attack_succeeded / max(1, n_attacks)),
        true_positive_rate=(tp / max(1, n_attacks)),
        false_positive_rate=(fp / max(1, benign_total)),
        false_containment_rate=(false_containment_count / max(1, benign_total)),
        mean_time_to_detection=(
            float(first_detection_idx - first_attack_seen_idx)
            if first_attack_seen_idx is not None and first_detection_idx is not None
            else float("inf") if first_attack_seen_idx is not None else 0.0
        ),
        mean_time_to_containment=(
            float(first_containment_idx - first_attack_seen_idx)
            if first_attack_seen_idx is not None and first_containment_idx is not None
            else float("inf") if first_attack_seen_idx is not None else 0.0
        ),
        max_propagation_depth=max(max_depth_attack, max_depth_attack_blocked),
        num_affected_agents=len(affected_agents),
        num_blocked_messages=blocked_messages,
        num_allowed_harmful_messages=allowed_harmful,
        median_latency_us=(statistics.median(per_msg_latency_us) if per_msg_latency_us else 0.0),
        p95_latency_us=_percentile(per_msg_latency_us, 95.0),
    )
    return metrics, raw_events


def metrics_to_dict(m: Metrics) -> dict[str, object]:
    """JSON-safe encoding (replaces ``inf`` with ``None``)."""

    d = asdict(m)
    for k in ("mean_time_to_detection", "mean_time_to_containment"):
        v = d.get(k)
        if isinstance(v, float) and (v == float("inf") or v != v):
            d[k] = None
    return d
