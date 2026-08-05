"""Delayed replay (spec §1.2).

A previously-valid signed envelope is replayed after the receiver's nonce
cache may have expired.  Six conditions are tested independently:

    same timestamp, expired timestamp, valid-looking timestamp + old seq,
    same prevHash, stale capability token, still-valid capability token

For "same_timestamp" we re-deliver the original envelope verbatim (tests
exact-duplicate replay-guard).  For the other five we build a fresh signed
envelope with the deliberately-conflicting field — CG-ATC's chain /
freshness / capability checks should each individually catch them.
"""
from __future__ import annotations

import copy
import random
import time
from dataclasses import dataclass, replace

from cgatc.capability import Constraints

from ..interfaces import Message
from ..materialize import Crew, MessageBuilder

import time as _time


@dataclass
class DelayedReplayWorkload:
    name: str = "delayed_replay"
    replay_delay_sec: int = 60

    def generate(self, seed: int, num_agents: int, num_messages: int) -> list[Message]:
        rng = random.Random(seed)
        crew = Crew(seed=seed)
        receiver = "delayed_replay_target"
        crew.make(receiver, role="worker")
        sender = "delayed_replay_attacker"
        crew.make(sender, role="worker")
        benign_sender = "delayed_replay_benign"
        crew.make(benign_sender, role="worker")

        builder = MessageBuilder(crew=crew, receiver=receiver)
        # Pre-issue an *already-expired* capability for the stale-cap scenario.
        # We mint with not_before far in the past and a short TTL so expiry
        # < now without making the test wait.
        sm = crew.get(sender)
        rm = crew.get(receiver)
        st = builder._state(sender)
        stale_cap = crew.pa.issue(
            subject=sm.agent_id,
            audience=rm.agent_id,
            task_id=st.task_id,
            scopes=["tools.read"],
            constraints=Constraints(),
            ttl_seconds=10,
            not_before=_time.time() - 1000,  # expiry = now - 990 < now
        )

        out: list[Message] = []

        # 1) Original valid message.
        original = builder.build(
            sender=sender, payload="GET status report v1",
            action="read", scope="tools.read",
            is_attack=False, attack_kind="",
        )
        out.append(original)
        original_seq = original.seq
        original_prev_hash = original.prev_hash
        original_ts = original.timestamp

        # Padding to flush short caches.
        for i in range(min(num_messages // 4, 6)):
            out.append(builder.build(
                sender=sender, payload=f"benign hello #{i}",
                action="read", scope="tools.read",
            ))

        # 1a) Same timestamp — exact duplicate of `original`.
        dup = replace(
            original,
            metadata={**copy.deepcopy(original.metadata),
                      "replay_test_condition": "same_timestamp"},
            is_attack=True, attack_kind="delayed_replay::same_timestamp",
            expected_block=True,
        )
        out.append(dup)

        # 2) Expired timestamp.
        out.append(builder.build(
            sender=sender, payload="GET status report v1 (expired ts)",
            action="read", scope="tools.read",
            timestamp=original_ts - 10_000,
            seq_override=original_seq + 100,
            is_attack=True, attack_kind="delayed_replay::expired_timestamp",
            expected_block=True,
            metadata_extras={"replay_test_condition": "expired_timestamp"},
        ))

        # 3) Valid timestamp but reused old sequence number.
        out.append(builder.build(
            sender=sender, payload="GET status report v1 (old seq)",
            action="read", scope="tools.read",
            seq_override=original_seq,
            is_attack=True, attack_kind="delayed_replay::valid_ts_old_seq",
            expected_block=True,
            metadata_extras={"replay_test_condition": "valid_ts_old_seq"},
        ))

        # 4) Same prevHash (reuses chain head).
        out.append(builder.build(
            sender=sender, payload="GET status report v1 (same prev_hash)",
            action="read", scope="tools.read",
            seq_override=original_seq + 200,
            prev_hash_override=bytes.fromhex(original_prev_hash) if original_prev_hash else None,
            is_attack=True, attack_kind="delayed_replay::same_prev_hash",
            expected_block=True,
            metadata_extras={"replay_test_condition": "same_prev_hash"},
        ))

        # 5) Stale capability token.
        out.append(builder.build(
            sender=sender, payload="GET status report v1 (stale cap)",
            action="read", scope="tools.read",
            capability_override=stale_cap,
            is_attack=True, attack_kind="delayed_replay::stale_capability_token",
            expected_block=True,
            metadata_extras={"replay_test_condition": "stale_capability_token"},
        ))

        # 6) Still-valid capability token but reusing seq (replay-guard catches).
        out.append(builder.build(
            sender=sender, payload="GET status report v1 (still-valid cap, old seq)",
            action="read", scope="tools.read",
            seq_override=original_seq,
            is_attack=True,
            attack_kind="delayed_replay::still_valid_capability_token",
            expected_block=True,
            metadata_extras={"replay_test_condition": "still_valid_capability_token"},
        ))

        # Pad with benign traffic from a clean sender.
        while len(out) < num_messages:
            out.append(builder.build(
                sender=benign_sender,
                payload=f"benign filler #{len(out)} {rng.randint(0, 999)}",
                action="read", scope="tools.read",
            ))

        return out[:num_messages]
