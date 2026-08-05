"""Audit-root committer (paper §III-F).

Periodically takes the agent's current `HashChainLog`, computes the
Merkle root of the events, signs it with the agent's key, and pushes
`(root, Σ_i^t)` to an external store (audit node, ledger, monitor).

The default `InMemoryCommitterSink` simply records each commitment.
Replace it with a writer to your monitoring system in production.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from ..core.types import AgentID, KeyPair, Timestamp, now
from ..crypto.primitives import Sign
from .hashchain import HashChainLog
from .merkle import merkle_root


@dataclass(frozen=True)
class Commitment:
    agent_id: AgentID
    seq_count: int
    root: bytes
    signature: bytes
    timestamp: Timestamp


class CommitterSink(Protocol):
    def record(self, commitment: Commitment) -> None: ...


class InMemoryCommitterSink:
    """Default sink — simply remembers every commitment."""

    def __init__(self) -> None:
        self.commitments: list[Commitment] = []

    def record(self, commitment: Commitment) -> None:
        self.commitments.append(commitment)

    def latest_root(self, agent_id: AgentID) -> bytes | None:
        for c in reversed(self.commitments):
            if c.agent_id == agent_id:
                return c.root
        return None


class AuditCommitter:
    """Drive periodic Merkle commitments for one agent."""

    def __init__(self, agent_id: AgentID, keypair: KeyPair, sink: CommitterSink) -> None:
        self.agent_id = agent_id
        self._keypair = keypair
        self._sink = sink

    def commit(self, log: HashChainLog) -> Commitment:
        leaves = [r.event_bytes() for r in log.records()]
        root = merkle_root(leaves)
        sig = Sign(root, self._keypair)
        c = Commitment(
            agent_id=self.agent_id, seq_count=len(leaves), root=root,
            signature=sig, timestamp=now(),
        )
        self._sink.record(c)
        return c
