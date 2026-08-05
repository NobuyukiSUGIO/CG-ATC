"""Common interfaces for adaptive-attack / stronger-baseline experiments.

These types implement the §3 "Common interface design" section of
``docs/spec_additional_experiments_and_baselines.pdf``.

The :class:`Message` here is deliberately a flat dataclass (not the rich
:class:`cgatc.messaging.SignedEnvelope` type) so that mTLS-only baselines and
JWT baselines can consume the same stream as CG-ATC without layering hacks.
Per-baseline cryptographic artefacts (signed envelope, JWT, etc.) ride in
``metadata``.

Ground-truth fields (``is_attack`` / ``attack_kind``) are populated by
workloads and consumed by the *runner* only.  Concrete :class:`Receiver`
implementations MUST NOT inspect them; doing so trivially defeats the
benchmark.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol


@dataclass
class Message:
    """Single message exchanged between agents in a benchmark scenario.

    Fields mirror the spec's §3 "Message Interface".  The receiver-visible
    cryptographic surface is:

    - :attr:`signature`     — per-message signature where the baseline expects one
    - :attr:`nonce`         — per-message nonce for replay protection
    - :attr:`capability_token` — optional capability artefact (JSON or JWT)
    - :attr:`prev_hash`     — previous-message digest for causal chains
    - :attr:`metadata`      — baseline-specific extras (envelope_json, jwt, …)

    Ground truth fields are after ``metadata`` and are NOT to be read by the
    receiver.  They exist only so the runner can compute TPR/FPR/etc.
    """

    session_id: str
    task_id: str
    seq: int
    sender_id: str
    receiver_id: str
    payload: str
    payload_hash: str
    timestamp: float
    nonce: str | None = None
    capability_token: str | None = None
    prev_hash: str | None = None
    signature: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    # ---- ground truth (runner-only) ---------------------------------------
    is_attack: bool = False
    attack_kind: str = ""
    # If True, the message *should* be blocked because the harm it triggers
    # exceeds the receiver's policy, even though the message is benign in
    # isolation (e.g. delayed retrieval after memory poisoning).
    expected_block: bool = False
    # Optional propagation depth at which this message sits, used to compute
    # max_propagation_depth in the spec's metrics.
    hop_depth: int = 0


@dataclass
class Decision:
    """Receiver verdict for a single :class:`Message`.

    Mirrors the spec's §3 "Decision" dataclass.  ``containment_level`` is a
    free-form string ("normal", "increased_monitoring", "isolated", ...) so
    each baseline can describe its own ladder; CG-ATC reports the
    :class:`cgatc.core.types.ContainmentLevel` name.
    """

    accepted: bool
    blocked_reason: str | None
    risk_score: float
    containment_level: str
    crypto_valid: bool
    capability_valid: bool
    policy_valid: bool
    audit_committed: bool
    latency_us: float


class Receiver(Protocol):
    """Receiver-side stack under test.

    Spec §3 "Receiver Interface".  Implementations are *stateful*: they
    accumulate per-sender history (replay caches, anomaly windows, audit
    logs) across calls.  Concrete classes also expose a ``name`` attribute
    (used for the ``baseline`` column in the metrics output).
    """

    name: str

    def receive(self, message: Message) -> Decision: ...


class Workload(Protocol):
    """Generator of benchmark traffic (spec §3 "Workload Interface").

    A workload is fully deterministic for a given ``seed`` so experiments
    can be reproduced from ``meta.json``.  ``num_messages`` is an upper
    bound; workloads with constrained semantics (e.g. multi-hop scenarios
    with a fixed hop count) may emit fewer.
    """

    name: str

    def generate(self, seed: int, num_agents: int, num_messages: int) -> list[Message]: ...


@dataclass
class Metrics:
    """Aggregated experiment metrics (spec §3 "Metrics Interface").

    Field order matches the spec.  ``attack_success_rate`` counts attack
    messages that were both accepted by the receiver AND would have caused
    real damage (i.e. ``expected_block=True``).  ``true_positive_rate`` is
    the standard detection TPR over messages with ``is_attack=True``.
    """

    workload: str
    baseline: str
    num_agents: int
    num_messages: int
    attack_success_rate: float
    true_positive_rate: float
    false_positive_rate: float
    false_containment_rate: float
    mean_time_to_detection: float
    mean_time_to_containment: float
    max_propagation_depth: int
    num_affected_agents: int
    num_blocked_messages: int
    num_allowed_harmful_messages: int
    median_latency_us: float
    p95_latency_us: float
