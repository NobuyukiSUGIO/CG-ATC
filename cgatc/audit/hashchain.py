"""Per-agent tamper-evident hash-chain audit log (paper §III-F).

    L_i^t = H(L_i^{t-1} ‖ event_i^t ‖ m_i^t ‖ σ_i^t)

`event` is an arbitrary structured payload describing what happened
(message verified, capability rejected, scope reduced, etc.).  `m` is
the canonical bytes of the related A2A envelope when applicable, and
`σ` the corresponding signature; both are optional for events that
have no associated envelope (e.g. internal risk-score updates).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from ..core.constants import GENESIS_PREV_HASH
from ..core.exceptions import AuditTamperingError
from ..core.types import AgentID, now
from ..crypto.primitives import H


@dataclass(frozen=True)
class AuditRecord:
    """One leaf in an agent's audit log."""

    seq: int
    timestamp: float
    event: dict[str, Any]
    envelope_bytes: bytes = b""
    signature_bytes: bytes = b""
    chain_state: bytes = field(default=GENESIS_PREV_HASH)  # L_i^t after appending

    def event_bytes(self) -> bytes:
        return json.dumps(
            self.event, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode()


class HashChainLog:
    """Append-only hash chain for one agent."""

    def __init__(self, agent_id: AgentID) -> None:
        self.agent_id = agent_id
        self._records: list[AuditRecord] = []
        self._head: bytes = GENESIS_PREV_HASH

    # ---- writes -----------------------------------------------------------
    def append(
        self,
        event: dict[str, Any],
        *,
        envelope_bytes: bytes = b"",
        signature_bytes: bytes = b"",
        timestamp: float | None = None,
    ) -> AuditRecord:
        """Append an event and advance L_i^t."""

        ts = timestamp if timestamp is not None else now()
        seq = len(self._records)
        evt_bytes = json.dumps(
            event, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode()
        new_head = H(self._head, evt_bytes, envelope_bytes, signature_bytes)
        rec = AuditRecord(
            seq=seq, timestamp=ts, event=event,
            envelope_bytes=envelope_bytes, signature_bytes=signature_bytes,
            chain_state=new_head,
        )
        self._records.append(rec)
        self._head = new_head
        return rec

    # ---- reads ------------------------------------------------------------
    @property
    def head(self) -> bytes:
        return self._head

    def __len__(self) -> int:
        return len(self._records)

    def records(self) -> list[AuditRecord]:
        return list(self._records)

    # ---- verification -----------------------------------------------------
    def verify(self) -> None:
        """Recompute the chain from genesis and compare to stored heads.

        Raises `AuditTamperingError` on the first divergence.

        This is the local check.  The external committer also publishes
        Merkle roots (see `merkle.MerkleAuditTree`) so a third-party can
        catch the case where the agent rewrote *both* the records and the
        chain.
        """

        recomputed = GENESIS_PREV_HASH
        for rec in self._records:
            evt_bytes = rec.event_bytes()
            recomputed = H(recomputed, evt_bytes, rec.envelope_bytes, rec.signature_bytes)
            if recomputed != rec.chain_state:
                raise AuditTamperingError("audit log integrity violation")
        if recomputed != self._head:
            raise AuditTamperingError("audit log integrity violation")
