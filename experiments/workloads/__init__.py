"""Reusable workload generators (CLAUDE.md §6.3).

All generators take a fixed `seed` and produce a list of
`baselines.Delivery` objects so every baseline sees the same input.
"""

from .benign import benign_workload
from .adversarial import (
    adversarial_collusion_workload,
    adversarial_replay_workload,
    adversarial_worm_workload,
)

__all__ = [
    "adversarial_collusion_workload",
    "adversarial_replay_workload",
    "adversarial_worm_workload",
    "benign_workload",
]
