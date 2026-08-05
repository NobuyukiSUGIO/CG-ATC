"""Policy evaluator (paper §III-E + §III-G).

Translates a `Policy` document into runtime decisions:

    * `issue_capability(...)` — ask the configured `PolicyAuthority` to
      mint a capability whose scopes are the intersection of the role's
      `may_exercise` set and the requested scopes; rejects if empty.
    * `is_acceptable(...)`  — receiver-side check: does the audience role
      permit accepting an action with the given scope?
    * `containment_for(...)` — pull the per-role `ContainmentThresholds`.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass

from ..capability import Constraints, PolicyAuthority, SignedCapability
from ..containment.scope_reducer import ContainmentThresholds
from ..containment.threshold_authz import HighRiskAction
from ..core.exceptions import CapabilityScopeError
from ..core.types import AgentID, TaskID
from .policy_dsl import Policy, RolePolicy


@dataclass
class PolicyEvaluator:
    """Resolves runtime questions against a parsed `Policy`."""

    policy: Policy
    authority: PolicyAuthority

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def role(self, role_name: str) -> RolePolicy:
        if role_name not in self.policy.roles:
            raise KeyError(f"unknown role: {role_name}")
        return self.policy.roles[role_name]

    @staticmethod
    def _matches(requested: str, allow: tuple[str, ...]) -> bool:
        return any(fnmatch.fnmatchcase(requested, pat) for pat in allow)

    # ------------------------------------------------------------------
    # Exercise side (sender role)
    # ------------------------------------------------------------------
    def intersect_exercise(self, role_name: str, requested_scopes: list[str]) -> list[str]:
        role = self.role(role_name)
        return [s for s in requested_scopes if self._matches(s, role.may_exercise)]

    def issue_capability(
        self,
        *,
        sender_role: str,
        subject: AgentID,
        audience: AgentID,
        task_id: TaskID,
        requested_scopes: list[str],
        constraints_override: Constraints | None = None,
    ) -> SignedCapability:
        granted = self.intersect_exercise(sender_role, requested_scopes)
        if not granted:
            raise CapabilityScopeError("no intersecting scope for this role")
        role = self.role(sender_role)
        return self.authority.issue(
            subject=subject, audience=audience, task_id=task_id,
            scopes=granted,
            constraints=constraints_override or role.constraints,
        )

    # ------------------------------------------------------------------
    # Accept side (receiver role)
    # ------------------------------------------------------------------
    def is_acceptable(self, audience_role: str, scope: str) -> bool:
        return self._matches(scope, self.role(audience_role).may_accept)

    # ------------------------------------------------------------------
    # Containment + high-risk lookup
    # ------------------------------------------------------------------
    def containment_for(self, role_name: str) -> ContainmentThresholds:
        return self.role(role_name).containment

    def is_high_risk(self, role_name: str, action: HighRiskAction) -> bool:
        return action in self.role(role_name).high_risk_actions
