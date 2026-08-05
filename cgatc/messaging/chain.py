"""prevHash chain bookkeeping (paper §III-D).

Each session maintains, per (session, sender) pair, the digest of the
previous in-session message from that sender.  The receiver checks that
each incoming envelope's `prev_hash` equals what the receiver remembers
as the chain head.

This implementation keeps state in memory.  A production deployment
would back it with a durable store; the protocol is unchanged.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..core.constants import GENESIS_PREV_HASH
from ..core.exceptions import ChainError
from ..core.types import AgentID, SessionID
from .envelope import SignedEnvelope


@dataclass
class _ChainState:
    last_hash: bytes = GENESIS_PREV_HASH
    last_seq: int = -1


class SessionChainTracker:
    """Track per-(session, sender) chain state."""

    def __init__(self) -> None:
        self._state: dict[tuple[SessionID, AgentID], _ChainState] = {}

    # ---- queries -----------------------------------------------------------
    def head(self, session: SessionID, sender: AgentID) -> bytes:
        return self._state.get((session, sender), _ChainState()).last_hash

    def seq(self, session: SessionID, sender: AgentID) -> int:
        return self._state.get((session, sender), _ChainState()).last_seq

    # ---- mutations ---------------------------------------------------------
    def accept(self, signed: SignedEnvelope) -> None:
        """Validate and advance the chain state for a freshly-verified envelope.

        Pre-condition: `verify_envelope(signed, ...)` has already returned
        successfully (signature and payload hash are good).  This function
        enforces the *chain* invariants:

          * `seq` is strictly increasing per (session, sender);
          * `prev_hash` equals the receiver's recorded last digest.

        On success the chain head and seq are updated atomically.

        Raises `ChainError` (or `SequenceError`) on failure.
        """

        from ..core.exceptions import SequenceError  # local import to avoid cycle

        env = signed.envelope
        key = (env.session_id, env.sender_id)
        state = self._state.setdefault(key, _ChainState())

        if env.seq <= state.last_seq:
            raise SequenceError("invalid envelope")
        if env.prev_hash != state.last_hash:
            raise ChainError("invalid envelope")

        # Accept: advance head to H(m) and bump seq.
        state.last_hash = env.digest()
        state.last_seq = env.seq

    # ---- introspection (for audit log generation) --------------------------
    def snapshot(self) -> dict[tuple[SessionID, AgentID], tuple[int, bytes]]:
        return {k: (v.last_seq, v.last_hash) for k, v in self._state.items()}
