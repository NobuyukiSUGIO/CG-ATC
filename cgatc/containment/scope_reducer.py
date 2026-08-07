"""Dynamic capability reduction (paper §III-H).

Implements the seven-stage gradual containment ladder:

    1. increase monitoring and logging frequency
    2. restrict direct output to other agents
    3. disable high-risk external tools
    4. prohibit delegation
    5. switch the agent to read-only mode
    6. isolate the agent from the A2A network
    7. revoke its certificates, session keys, and capability tokens

Stages map to the `ContainmentLevel` enum.  `ScopeReducer.evaluate(R)`
returns the level for a given risk score using the configured τ
thresholds.  Higher-level callers translate the level into concrete
operational changes (PA stops issuing capabilities for revoked agents,
the messaging layer drops their envelopes, etc.).
"""

from __future__ import annotations

from dataclasses import dataclass

from ..core.constants import TAU_1, TAU_2, TAU_3, TAU_4
from ..core.types import AgentID, ContainmentLevel


@dataclass(frozen=True)
class ContainmentThresholds:
    """τ_1 < τ_2 < τ_3 < τ_4 (strictly monotonic)."""

    tau_1: float = TAU_1
    tau_2: float = TAU_2
    tau_3: float = TAU_3
    tau_4: float = TAU_4

    def __post_init__(self) -> None:
        if not (self.tau_1 < self.tau_2 < self.tau_3 < self.tau_4):
            raise ValueError("τ thresholds must be strictly monotonic")


class ScopeReducer:
    """Map a numeric risk score to a `ContainmentLevel`.

    The mapping is monotone non-decreasing in the risk score:

        R < τ_1   → NORMAL
        τ_1 ≤ R < τ_2 → INCREASED_MONITORING
        τ_2 ≤ R < (τ_2+τ_3)/2 → OUTPUT_RESTRICTED
        (τ_2+τ_3)/2 ≤ R < τ_3 → HIGH_RISK_TOOLS_DISABLED
        τ_3 ≤ R < (τ_3+τ_4)/2 → DELEGATION_PROHIBITED
        (τ_3+τ_4)/2 ≤ R < τ_4 → READ_ONLY
        τ_4 ≤ R < 2*τ_4   → NETWORK_ISOLATED
        R ≥ 2*τ_4         → CREDENTIALS_REVOKED
    """

    def __init__(self, thresholds: ContainmentThresholds | None = None) -> None:
        self.t = thresholds or ContainmentThresholds()
        self._current: dict[AgentID, ContainmentLevel] = {}

    # --------------------------------------------------------------
    # Pure mapping
    # --------------------------------------------------------------
    def level_for(self, risk: float) -> ContainmentLevel:
        t = self.t
        if risk < t.tau_1:
            return ContainmentLevel.NORMAL
        if risk < t.tau_2:
            return ContainmentLevel.INCREASED_MONITORING
        if risk < (t.tau_2 + t.tau_3) / 2:
            return ContainmentLevel.OUTPUT_RESTRICTED
        if risk < t.tau_3:
            return ContainmentLevel.HIGH_RISK_TOOLS_DISABLED
        if risk < (t.tau_3 + t.tau_4) / 2:
            return ContainmentLevel.DELEGATION_PROHIBITED
        if risk < t.tau_4:
            return ContainmentLevel.READ_ONLY
        if risk < 2 * t.tau_4:
            return ContainmentLevel.NETWORK_ISOLATED
        return ContainmentLevel.CREDENTIALS_REVOKED

    # --------------------------------------------------------------
    # Stateful API used by the runtime
    # --------------------------------------------------------------
    def evaluate(self, agent: AgentID, risk: float) -> ContainmentLevel:
        """Return the new containment level *and* persist it.

        The level is monotone (we never automatically lower containment
        — manual recovery is required after isolation, per the paper's
        intent).
        """

        new = self.level_for(risk)
        old = self._current.get(agent, ContainmentLevel.NORMAL)
        if int(new) > int(old):
            self._current[agent] = new
            return new
        return old

    def current(self, agent: AgentID) -> ContainmentLevel:
        return self._current.get(agent, ContainmentLevel.NORMAL)

    def manual_reset(self, agent: AgentID) -> None:
        """Operator-driven recovery from elevated containment."""

        self._current.pop(agent, None)


def restrict_scopes(scopes: list[str], level: ContainmentLevel) -> list[str]:
    """Return a filtered scope list for the given containment level.

    Implements `Scopes_i^{t+1} = Scopes_i^t \\ HighRiskScopes` (paper §III-H).
    The "high risk" tag is encoded as a `*.high_risk.*` substring in the scope
    name; deployments can adapt the predicate to their own taxonomy.
    """

    if level == ContainmentLevel.NORMAL:
        return list(scopes)
    if level == ContainmentLevel.INCREASED_MONITORING:
        return list(scopes)  # no scope change, just more logging
    if level == ContainmentLevel.OUTPUT_RESTRICTED:
        return [s for s in scopes if not s.startswith("output.broadcast")]
    if level == ContainmentLevel.HIGH_RISK_TOOLS_DISABLED:
        return [s for s in scopes if "high_risk" not in s]
    if level == ContainmentLevel.DELEGATION_PROHIBITED:
        return [s for s in scopes if "high_risk" not in s and not s.startswith("delegate.")]
    if level == ContainmentLevel.READ_ONLY:
        return [s for s in scopes if s.endswith(".read")]
    if level == ContainmentLevel.NETWORK_ISOLATED:
        return []
    return []  # CREDENTIALS_REVOKED
