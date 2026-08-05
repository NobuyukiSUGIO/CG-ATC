"""Replay guard (paper §III-D).

Tracks (session, sender, seq) and rejects duplicates.  This complements
`SessionChainTracker`; the chain tracker enforces *strict monotonicity*,
the replay guard enforces *no exact duplicates within an entire session*
including out-of-order seq values that would otherwise satisfy "less
than head" silently.
"""

from __future__ import annotations

from ..core.exceptions import ReplayError
from ..core.types import AgentID, SessionID
from .envelope import SignedEnvelope


class ReplayGuard:
    """Per-(session, sender) seq set + observed-digest set."""

    def __init__(self) -> None:
        self._seen_seq: dict[tuple[SessionID, AgentID], set[int]] = {}
        self._seen_digests: set[bytes] = set()

    def check_and_record(self, signed: SignedEnvelope) -> None:
        env = signed.envelope
        key = (env.session_id, env.sender_id)
        seq_set = self._seen_seq.setdefault(key, set())
        if env.seq in seq_set:
            raise ReplayError("invalid envelope")
        digest = env.digest()
        if digest in self._seen_digests:
            raise ReplayError("invalid envelope")
        seq_set.add(env.seq)
        self._seen_digests.add(digest)
