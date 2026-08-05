"""Behavioural and semantic detection (paper §III-G-2).

Implements the eight enumerated anomaly types as small per-agent rolling
counters.  The detector only reasons over **authenticated** evidence
(messages that already passed cryptographic verification), in line with
the paper's framing: "cryptography provides authenticated evidence,
while the anomaly detector reasons over the authenticated evidence".

Each call to `observe()` returns the contribution to `B_i^t` for that
event in [0, 1].  The thresholds are tunable via the constructor.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Deque

from ..core.types import AgentID, Timestamp, now


class BehavioralAnomalyKind(str, Enum):
    """The 8 anomaly examples enumerated in paper §III-G-2."""

    DELEGATION_SPIKE = "delegation_spike"
    AGENT_CARD_CHURN = "agent_card_churn"
    HIGH_PRIV_TOOL_PROBING = "high_priv_tool_probing"
    PROMPT_FANOUT = "prompt_fanout"
    UNSAFE_FORWARDING = "unsafe_forwarding"
    SUSPICIOUS_AMPLIFICATION = "suspicious_amplification"
    MUTUAL_REINFORCEMENT = "mutual_reinforcement"
    ABNORMAL_MEMORY_PATTERN = "abnormal_memory_pattern"


@dataclass(frozen=True)
class BehavioralAnomaly:
    kind: BehavioralAnomalyKind
    severity: float  # contribution to B_i^t in [0, 1]


@dataclass
class _PerAgentBehaviorState:
    delegations: Deque[Timestamp] = field(default_factory=deque)
    fanout: Deque[tuple[Timestamp, AgentID]] = field(default_factory=deque)
    high_priv_attempts: Deque[Timestamp] = field(default_factory=deque)
    last_card_hash: bytes | None = None
    card_changes: int = 0
    amplifies_from: dict[AgentID, int] = field(default_factory=dict)
    memory_writes: Deque[Timestamp] = field(default_factory=deque)


class BehavioralDetector:
    """Per-agent rolling-window anomaly detector."""

    def __init__(
        self,
        *,
        window_seconds: float = 60.0,
        delegation_per_min_threshold: int = 5,
        fanout_per_min_threshold: int = 8,
        high_priv_per_min_threshold: int = 3,
        memory_writes_per_min_threshold: int = 50,
    ) -> None:
        self.window = window_seconds
        self.delegation_threshold = delegation_per_min_threshold
        self.fanout_threshold = fanout_per_min_threshold
        self.high_priv_threshold = high_priv_per_min_threshold
        self.memory_threshold = memory_writes_per_min_threshold
        self._state: dict[AgentID, _PerAgentBehaviorState] = {}

    # ----------------------------------------------------------------------
    # Helpers
    # ----------------------------------------------------------------------
    def _state_for(self, agent_id: AgentID) -> _PerAgentBehaviorState:
        return self._state.setdefault(agent_id, _PerAgentBehaviorState())

    def _trim(self, dq: Deque[Timestamp], ts: float) -> None:
        cutoff = ts - self.window
        while dq and dq[0] < cutoff:
            dq.popleft()

    def _trim_pair(self, dq: Deque[tuple[Timestamp, AgentID]], ts: float) -> None:
        cutoff = ts - self.window
        while dq and dq[0][0] < cutoff:
            dq.popleft()

    # ----------------------------------------------------------------------
    # Public observation methods (one per anomaly)
    # ----------------------------------------------------------------------
    def observe_delegation(self, agent: AgentID, *, when: float | None = None) -> BehavioralAnomaly | None:
        ts = when if when is not None else now()
        st = self._state_for(agent)
        st.delegations.append(Timestamp(ts))
        self._trim(st.delegations, ts)
        if len(st.delegations) > self.delegation_threshold:
            return BehavioralAnomaly(BehavioralAnomalyKind.DELEGATION_SPIKE,
                                     severity=min(1.0, len(st.delegations) / (self.delegation_threshold * 2)))
        return None

    def observe_card_change(self, agent: AgentID, card_hash: bytes) -> BehavioralAnomaly | None:
        st = self._state_for(agent)
        if st.last_card_hash is not None and st.last_card_hash != card_hash:
            st.card_changes += 1
            return BehavioralAnomaly(BehavioralAnomalyKind.AGENT_CARD_CHURN,
                                     severity=min(1.0, st.card_changes / 3.0))
        st.last_card_hash = card_hash
        return None

    def observe_high_priv_probe(self, agent: AgentID, *, when: float | None = None) -> BehavioralAnomaly | None:
        ts = when if when is not None else now()
        st = self._state_for(agent)
        st.high_priv_attempts.append(Timestamp(ts))
        self._trim(st.high_priv_attempts, ts)
        if len(st.high_priv_attempts) > self.high_priv_threshold:
            return BehavioralAnomaly(BehavioralAnomalyKind.HIGH_PRIV_TOOL_PROBING,
                                     severity=min(1.0, len(st.high_priv_attempts) / (self.high_priv_threshold * 2)))
        return None

    def observe_send(
        self,
        agent: AgentID,
        receiver: AgentID,
        *,
        when: float | None = None,
        prompt_similarity_to_others: float = 0.0,
    ) -> BehavioralAnomaly | None:
        ts = when if when is not None else now()
        st = self._state_for(agent)
        st.fanout.append((Timestamp(ts), receiver))
        self._trim_pair(st.fanout, ts)
        unique_receivers = {r for _, r in st.fanout}
        if len(unique_receivers) > self.fanout_threshold and prompt_similarity_to_others > 0.8:
            return BehavioralAnomaly(BehavioralAnomalyKind.PROMPT_FANOUT,
                                     severity=min(1.0, len(unique_receivers) / (self.fanout_threshold * 2)))
        return None

    def observe_unsafe_forward(
        self, agent: AgentID, *, sanitised: bool, severity: float = 0.7
    ) -> BehavioralAnomaly | None:
        if not sanitised:
            return BehavioralAnomaly(BehavioralAnomalyKind.UNSAFE_FORWARDING, severity=severity)
        return None

    def observe_amplification(
        self, agent: AgentID, source: AgentID, *, source_risk: float
    ) -> BehavioralAnomaly | None:
        st = self._state_for(agent)
        st.amplifies_from[source] = st.amplifies_from.get(source, 0) + 1
        if source_risk > 0.5 and st.amplifies_from[source] >= 3:
            return BehavioralAnomaly(BehavioralAnomalyKind.SUSPICIOUS_AMPLIFICATION,
                                     severity=min(1.0, source_risk))
        return None

    def observe_mutual_claim(
        self, agent: AgentID, peer_agreement_count: int
    ) -> BehavioralAnomaly | None:
        # Simple proxy: flag if a small group keeps reinforcing the same claim.
        if peer_agreement_count >= 3:
            return BehavioralAnomaly(BehavioralAnomalyKind.MUTUAL_REINFORCEMENT,
                                     severity=min(1.0, peer_agreement_count / 5.0))
        return None

    def observe_memory_write(self, agent: AgentID, *, when: float | None = None) -> BehavioralAnomaly | None:
        ts = when if when is not None else now()
        st = self._state_for(agent)
        st.memory_writes.append(Timestamp(ts))
        self._trim(st.memory_writes, ts)
        if len(st.memory_writes) > self.memory_threshold:
            return BehavioralAnomaly(BehavioralAnomalyKind.ABNORMAL_MEMORY_PATTERN,
                                     severity=min(1.0, len(st.memory_writes) / (self.memory_threshold * 2)))
        return None
