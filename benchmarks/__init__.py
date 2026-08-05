"""Adaptive attack and stronger-baseline benchmark suite.

Implements the contract specified in
``docs/spec_additional_experiments_and_baselines.pdf`` ("CG-ATC: additional
experiments and additional baselines -- implementation specification").
The package is intentionally separate from :mod:`cgatc.baselines` so that the
existing 5-baseline harness keeps working unchanged while this benchmark
exposes the spec's :class:`Message` / :class:`Receiver` / :class:`Workload`
interface.
"""
from .interfaces import Decision, Message, Metrics, Receiver, Workload

__all__ = ["Decision", "Message", "Metrics", "Receiver", "Workload"]
