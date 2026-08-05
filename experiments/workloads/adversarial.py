"""Adversarial workload generators.

Three flavours exercised by `compare_baselines.py`:

  * `adversarial_replay_workload`   — single attacker re-sends one envelope
  * `adversarial_worm_workload`     — single attacker fans the same payload
                                       to many recipients (worm-like)
  * `adversarial_collusion_workload`— two colluding agents reinforce each
                                       other's claims into a third agent
"""

from __future__ import annotations

import random

from cgatc.baselines import Delivery


def adversarial_replay_workload(*, seed: int, n_messages: int = 100) -> list[Delivery]:
    rng = random.Random(seed)
    sender = "alice"
    benign_payload = f"task-{rng.random():.6f}".encode()
    out: list[Delivery] = []
    # First copy is legitimate, subsequent N-1 are replays of the same payload.
    for i in range(n_messages):
        is_attack = i > 0
        out.append(Delivery(
            sender=sender, payload=benign_payload,
            metadata={"action_scope": "tools.read",
                      "is_replay": is_attack},
            is_attack=is_attack,
        ))
    return out


def adversarial_worm_workload(
    *, seed: int, n_messages: int = 200,
    n_infected: int = 20, n_benign_senders: int = 10,
) -> list[Delivery]:
    rng = random.Random(seed)
    payload = b"infect:propagate-everywhere"
    out: list[Delivery] = []
    for i in range(n_messages):
        # 50% of the traffic is the worm payload from various senders;
        # the rest is benign.
        if i % 2 == 0:
            out.append(Delivery(
                sender=f"infected-{rng.randrange(n_infected)}",
                payload=payload,
                metadata={"action_scope": "tools.read"},
                is_attack=True,
            ))
        else:
            out.append(Delivery(
                sender=f"agent-{rng.randrange(n_benign_senders)}",
                payload=f"benign-{i}-{rng.random():.4f}".encode(),
                metadata={"action_scope": "tools.read"},
                is_attack=False,
            ))
    return out


def adversarial_collusion_workload(*, seed: int, n_messages: int = 100) -> list[Delivery]:
    rng = random.Random(seed)
    out: list[Delivery] = []
    claim = b"FALSE_CLAIM_X"
    # Two attackers (mallory, eve) repeatedly endorse the same claim.
    # Real anomaly detectors should pick this up as repeated identical
    # payload from a small set of senders.
    for i in range(n_messages):
        if i % 4 in (0, 1):
            sender = "mallory" if i % 4 == 0 else "eve"
            out.append(Delivery(sender=sender, payload=claim,
                                metadata={"action_scope": "tools.read"},
                                is_attack=True))
        else:
            out.append(Delivery(
                sender=f"agent-{rng.randrange(8)}",
                payload=f"benign-{i}".encode(),
                metadata={"action_scope": "tools.read"},
                is_attack=False,
            ))
    return out
