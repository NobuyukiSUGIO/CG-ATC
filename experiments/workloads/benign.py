"""Benign workload generator.

Produces N "delegation chain" deliveries where every message is a
distinct, well-formed request from one of `n_senders` peers.
"""

from __future__ import annotations

import random

from cgatc.baselines import Delivery


def benign_workload(*, seed: int, n_messages: int = 200, n_senders: int = 10) -> list[Delivery]:
    """Each sender appears at least once when `n_messages >= n_senders`.

    The first `n_senders` deliveries cycle through every sender so the
    receiver actually sees all of them; the rest are uniformly random.
    """

    rng = random.Random(seed)
    out: list[Delivery] = []
    for i in range(n_messages):
        if i < n_senders:
            idx = i  # ensure every sender is exercised at least once
        else:
            idx = rng.randrange(n_senders)
        sender = f"agent-{idx}"
        payload = f"benign-task-{i:05d}-{rng.random():.6f}".encode()
        out.append(Delivery(
            sender=sender, payload=payload,
            metadata={"action_scope": "tools.read"},
            is_attack=False,
        ))
    return out
