"""Policy DSL parser (paper §III-E + §III-H).

A policy document declares, per agent role:

    * which scopes that role may EXERCISE (subject side)
    * which scopes that role may ACCEPT  (audience side)
    * default constraints attached to capabilities issued for that role
    * containment-threshold overrides (per role)
    * which actions count as "high risk" (per role) — feeds the
      `HighRiskAuthorizer`

Rationale for a separate DSL: CLAUDE.md §3.2 lists `cgatc/policy/` as
its own subpackage so deployments can express policy declaratively
(YAML/JSON), version it, and hash it for `policyHash_i` (paper §III-C)
without touching code.

Example YAML:

    version: 1
    roles:
      analyst:
        may_exercise: ["tools.search.*", "data.public.*"]
        may_accept:   ["tools.report.write"]
        constraints:
          max_output_size: 16384
          allowed_external_tools: ["search-1", "search-2"]
          delegation_permitted: false
        high_risk_actions: ["financial_operation"]
        containment:
          tau_1: 1.0
          tau_2: 2.5
          tau_3: 5.0
          tau_4: 10.0
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Mapping

from ..capability.token import Constraints
from ..containment.scope_reducer import ContainmentThresholds
from ..containment.threshold_authz import HighRiskAction
from ..crypto.primitives import H


@dataclass(frozen=True)
class RolePolicy:
    """Resolved per-role policy."""

    name: str
    may_exercise: tuple[str, ...] = ()
    may_accept: tuple[str, ...] = ()
    constraints: Constraints = field(default_factory=Constraints)
    high_risk_actions: tuple[HighRiskAction, ...] = ()
    containment: ContainmentThresholds = field(default_factory=ContainmentThresholds)


@dataclass(frozen=True)
class Policy:
    """Top-level policy document."""

    version: int
    roles: Mapping[str, RolePolicy]

    # ---- canonicalisation -------------------------------------------------
    def encode_canonical(self) -> bytes:
        """Stable JSON serialisation suitable for hashing.

        Used to derive `PolicyHash_i` (paper §III-C).  Two structurally-
        identical YAML files produce the same `policy_hash`.
        """

        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False).encode()

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "roles": {
                name: {
                    "may_exercise": list(rp.may_exercise),
                    "may_accept": list(rp.may_accept),
                    "constraints": rp.constraints.model_dump(),
                    "high_risk_actions": [a.value for a in rp.high_risk_actions],
                    "containment": {
                        "tau_1": rp.containment.tau_1,
                        "tau_2": rp.containment.tau_2,
                        "tau_3": rp.containment.tau_3,
                        "tau_4": rp.containment.tau_4,
                    },
                }
                for name, rp in self.roles.items()
            },
        }

    def hash(self) -> bytes:
        """policyHash_i = H(canonical(policy))."""

        return H(self.encode_canonical())


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------
def load_policy(doc: Mapping[str, Any]) -> Policy:
    """Parse an in-memory dict into a `Policy`.

    Accepts the structure from a YAML/JSON file already loaded by the
    caller; we deliberately do NOT depend on PyYAML here so the DSL
    can be exercised from pure Python tests.
    """

    if "version" not in doc:
        raise ValueError("policy missing 'version' field")
    if "roles" not in doc or not isinstance(doc["roles"], Mapping):
        raise ValueError("policy missing or malformed 'roles' field")

    roles: dict[str, RolePolicy] = {}
    for name, raw in doc["roles"].items():
        if not isinstance(raw, Mapping):
            raise ValueError(f"role {name!r} must be a mapping")
        constraints_raw = dict(raw.get("constraints", {}) or {})
        containment_raw = dict(raw.get("containment", {}) or {})
        actions_raw = list(raw.get("high_risk_actions", []) or [])
        try:
            actions = tuple(HighRiskAction(a) for a in actions_raw)
        except ValueError as exc:
            raise ValueError(f"role {name!r}: unknown high-risk action") from exc

        roles[name] = RolePolicy(
            name=name,
            may_exercise=tuple(raw.get("may_exercise", []) or []),
            may_accept=tuple(raw.get("may_accept", []) or []),
            constraints=Constraints(**constraints_raw),
            high_risk_actions=actions,
            containment=ContainmentThresholds(
                tau_1=float(containment_raw.get("tau_1", ContainmentThresholds().tau_1)),
                tau_2=float(containment_raw.get("tau_2", ContainmentThresholds().tau_2)),
                tau_3=float(containment_raw.get("tau_3", ContainmentThresholds().tau_3)),
                tau_4=float(containment_raw.get("tau_4", ContainmentThresholds().tau_4)),
            ),
        )

    return Policy(version=int(doc["version"]), roles=roles)


def load_policy_yaml(text: str) -> Policy:
    """Parse a YAML string.  Requires PyYAML."""

    import yaml  # local import; PyYAML is an optional run-time dep

    data = yaml.safe_load(text)
    if not isinstance(data, Mapping):
        raise ValueError("YAML root must be a mapping")
    return load_policy(data)
