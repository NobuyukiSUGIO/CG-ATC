"""CG-ATC signed message envelopes and per-session chain (paper §III-D)."""

from .chain import SessionChainTracker
from .envelope import (
    Envelope,
    SignedEnvelope,
    build_envelope,
    encode_envelope_header,
    sign_envelope,
    verify_envelope,
)
from .replay_guard import ReplayGuard

__all__ = [
    "Envelope",
    "ReplayGuard",
    "SessionChainTracker",
    "SignedEnvelope",
    "build_envelope",
    "encode_envelope_header",
    "sign_envelope",
    "verify_envelope",
]
