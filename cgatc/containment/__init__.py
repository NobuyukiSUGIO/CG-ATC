"""CG-ATC containment layer (paper §III-H)."""

from .impact_radius import ImpactGraph, radius_for_level
from .scope_reducer import (
    ContainmentThresholds,
    ScopeReducer,
    restrict_scopes,
)
from .threshold_authz import (
    ActionDescriptor,
    HighRiskAction,
    HighRiskAuthorizer,
)

__all__ = [
    "ActionDescriptor",
    "ContainmentThresholds",
    "HighRiskAction",
    "HighRiskAuthorizer",
    "ImpactGraph",
    "ScopeReducer",
    "radius_for_level",
    "restrict_scopes",
]
