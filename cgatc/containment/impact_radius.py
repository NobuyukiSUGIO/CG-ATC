"""Impact radius (paper §III-H).

    Impact(A_i, t) = { A_j | A_i ⤳ A_j within r signed message hops }

We track an in-memory directed multigraph of *signed* messages, where
each edge `A_i → A_j` is added when `A_i` sends an envelope that
`A_j` accepted (post-verification).  `impact_set(agent, r)` returns the
set of agents reachable within `r` hops.
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass

from ..core.constants import (
    DEFAULT_MAX_RADIUS,
    ISOLATED_MAX_RADIUS,
    SUSPICIOUS_MAX_RADIUS,
)
from ..core.types import AgentID, ContainmentLevel


@dataclass(frozen=True)
class _Edge:
    src: AgentID
    dst: AgentID


class ImpactGraph:
    """Adjacency-list view of recent signed messages."""

    def __init__(self) -> None:
        self._adj: dict[AgentID, set[AgentID]] = defaultdict(set)

    # --------------------------------------------------------------
    # Mutations
    # --------------------------------------------------------------
    def record_send(self, src: AgentID, dst: AgentID) -> None:
        self._adj[src].add(dst)

    def reset(self, agent: AgentID) -> None:
        self._adj[agent].clear()

    # --------------------------------------------------------------
    # Queries
    # --------------------------------------------------------------
    def impact_set(self, agent: AgentID, max_radius: int) -> set[AgentID]:
        """BFS up to `max_radius` hops from `agent` (excluding `agent`)."""

        if max_radius <= 0:
            return set()
        seen: set[AgentID] = set()
        frontier: deque[tuple[AgentID, int]] = deque([(agent, 0)])
        while frontier:
            node, depth = frontier.popleft()
            if depth >= max_radius:
                continue
            for nxt in self._adj.get(node, ()):
                if nxt in seen or nxt == agent:
                    continue
                seen.add(nxt)
                frontier.append((nxt, depth + 1))
        return seen


def radius_for_level(level: ContainmentLevel) -> int:
    """Map a `ContainmentLevel` to a max propagation radius `r`."""

    if level >= ContainmentLevel.NETWORK_ISOLATED:
        return ISOLATED_MAX_RADIUS
    if level >= ContainmentLevel.DELEGATION_PROHIBITED:
        return SUSPICIOUS_MAX_RADIUS
    return DEFAULT_MAX_RADIUS
