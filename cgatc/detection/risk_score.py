"""Dynamic risk score (paper §III-G-2).

    R_i^{t+1} = λ R_i^t + α C_i^t + β B_i^t + γ P_i^t + δ D_i^t

`λ` is a decay factor; `C, B, P, D` are per-time-step scalar
contributions:

    C  cryptographic violation score (sum of `Violation.severity`)
    B  behavioural anomaly score   (sum of `BehavioralAnomaly.severity`)
    P  policy-violation score      (e.g. # capability rejections / time)
    D  downstream-damage score     (propagation indicator)

All weights are configurable so they can be tuned in `examples/configs/risk.yaml`
without touching code (CLAUDE.md §3.3 Phase 5: "externalise λ, α, β, γ, δ into a
configuration file").
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..core.constants import (
    DEFAULT_ALPHA,
    DEFAULT_BETA,
    DEFAULT_DELTA,
    DEFAULT_GAMMA,
    DEFAULT_LAMBDA,
)
from ..core.types import AgentID


@dataclass(frozen=True)
class RiskWeights:
    lambda_decay: float = DEFAULT_LAMBDA
    alpha_crypto: float = DEFAULT_ALPHA
    beta_behavior: float = DEFAULT_BETA
    gamma_policy: float = DEFAULT_GAMMA
    delta_downstream: float = DEFAULT_DELTA

    def __post_init__(self) -> None:
        for name, val in (
            ("lambda_decay", self.lambda_decay),
            ("alpha_crypto", self.alpha_crypto),
            ("beta_behavior", self.beta_behavior),
            ("gamma_policy", self.gamma_policy),
            ("delta_downstream", self.delta_downstream),
        ):
            if val < 0:
                raise ValueError(f"{name} must be non-negative")
        if not 0.0 <= self.lambda_decay <= 1.0:
            raise ValueError("lambda_decay must lie in [0, 1]")


@dataclass
class _Scores:
    crypto: float = 0.0
    behavior: float = 0.0
    policy: float = 0.0
    downstream: float = 0.0


@dataclass
class RiskState:
    """Accumulated state for one agent."""

    risk: float = 0.0
    pending: _Scores = field(default_factory=_Scores)


class RiskScoreUpdater:
    """Per-agent risk-score book-keeping."""

    def __init__(self, weights: RiskWeights | None = None) -> None:
        self.w = weights or RiskWeights()
        self._state: dict[AgentID, RiskState] = {}

    # ----------------------------------------------------------------------
    # Score contributions (collected over a tick)
    # ----------------------------------------------------------------------
    def add_crypto(self, agent: AgentID, severity: float) -> None:
        self._state.setdefault(agent, RiskState()).pending.crypto += severity

    def add_behavior(self, agent: AgentID, severity: float) -> None:
        self._state.setdefault(agent, RiskState()).pending.behavior += severity

    def add_policy(self, agent: AgentID, severity: float) -> None:
        self._state.setdefault(agent, RiskState()).pending.policy += severity

    def add_downstream(self, agent: AgentID, severity: float) -> None:
        self._state.setdefault(agent, RiskState()).pending.downstream += severity

    # ----------------------------------------------------------------------
    # Periodic tick
    # ----------------------------------------------------------------------
    def tick(self, agent: AgentID) -> float:
        """Apply the recurrence and return the new R_i^{t+1}."""

        st = self._state.setdefault(agent, RiskState())
        st.risk = (
            self.w.lambda_decay * st.risk
            + self.w.alpha_crypto * st.pending.crypto
            + self.w.beta_behavior * st.pending.behavior
            + self.w.gamma_policy * st.pending.policy
            + self.w.delta_downstream * st.pending.downstream
        )
        st.pending = _Scores()
        return st.risk

    def current(self, agent: AgentID) -> float:
        return self._state.get(agent, RiskState()).risk

    def reset(self, agent: AgentID) -> None:
        self._state.pop(agent, None)
