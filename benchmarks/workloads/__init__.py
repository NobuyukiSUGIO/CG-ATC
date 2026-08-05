"""Adaptive attack workloads (spec §1).

Each workload constructs a deterministic stream of fully-baked
:class:`benchmarks.Message` instances from ``(seed, num_agents,
num_messages)``.  Per-baseline cryptographic artefacts are pre-computed by
:mod:`benchmarks.materialize`, so a single Message stream feeds every
baseline.
"""
from __future__ import annotations

from typing import Callable

from ..interfaces import Workload
from .benign_broadcast import BenignBroadcastWorkload
from .delayed_replay import DelayedReplayWorkload
from .memory_poisoning_delayed import MemoryPoisoningDelayedWorkload
from .multihop_indirect_prompt_injection import MultihopIndirectPromptInjectionWorkload
from .paraphrased_worm import ParaphrasedWormWorkload
from .semantic_collusion import SemanticCollusionWorkload
from .semantic_replay import SemanticReplayWorkload
from .valid_capability_harmful_semantics import ValidCapabilityHarmfulSemanticsWorkload

_FACTORIES: dict[str, Callable[[], Workload]] = {
    "paraphrased_worm": ParaphrasedWormWorkload,
    "delayed_replay": DelayedReplayWorkload,
    "semantic_replay": SemanticReplayWorkload,
    "benign_broadcast": BenignBroadcastWorkload,
    "multihop_indirect_prompt_injection": MultihopIndirectPromptInjectionWorkload,
    "memory_poisoning_delayed": MemoryPoisoningDelayedWorkload,
    "semantic_collusion": SemanticCollusionWorkload,
    "valid_capability_harmful_semantics": ValidCapabilityHarmfulSemanticsWorkload,
}


def make_workload(name: str, **kwargs: object) -> Workload:
    if name not in _FACTORIES:
        raise ValueError(f"unknown workload: {name!r}; known={sorted(_FACTORIES)}")
    factory = _FACTORIES[name]
    return factory(**kwargs)  # type: ignore[call-arg]


def list_workloads() -> list[str]:
    return list(_FACTORIES)


__all__ = [
    "BenignBroadcastWorkload",
    "DelayedReplayWorkload",
    "MemoryPoisoningDelayedWorkload",
    "MultihopIndirectPromptInjectionWorkload",
    "ParaphrasedWormWorkload",
    "SemanticCollusionWorkload",
    "SemanticReplayWorkload",
    "ValidCapabilityHarmfulSemanticsWorkload",
    "list_workloads",
    "make_workload",
]
