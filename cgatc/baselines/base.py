"""Common interface for the five baselines from CLAUDE.md §6.2.

A "baseline" is a pluggable receiver-side policy stack.  All baselines
expose the same `Receiver.deliver(...)` API so a single workload runner
(`compare_baselines.py`) can drive them with identical inputs and
compare the outcomes apples-to-apples.

Baselines:
    auth_only         — A2A authentication only.
    tls_oauth         — TLS + OAuth-style bearer-token gate.
    cap_no_audit      — capability tokens but no tamper-evident logging.
    anomaly_no_crypto — anomaly score only, no signatures.
    cgatc_full        — the full CG-ATC stack.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Protocol


class Verdict(str, Enum):
    ACCEPT = "accept"
    REJECT = "reject"


@dataclass(frozen=True)
class DeliveryResult:
    verdict: Verdict
    reason: str
    risk: float = 0.0
    audit_committed: bool = False
    detected_attack: bool = False  # the receiver flagged the message as attack


@dataclass(frozen=True)
class Delivery:
    """Inbound 'message' as seen by a baseline receiver.

    Concrete fields are deliberately loose — the workload generator
    fabricates whatever metadata each baseline cares about.
    """

    sender: str        # symbolic agent name (workload-defined)
    payload: bytes
    metadata: dict[str, Any]
    is_attack: bool    # GROUND TRUTH used only by the harness


class Receiver(Protocol):
    """Every baseline must implement this contract."""

    name: str

    def deliver(self, msg: Delivery) -> DeliveryResult: ...
