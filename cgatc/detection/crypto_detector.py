"""Cryptographic detection (paper §III-G).

Maps the ten enumerated rejection conditions of §III-G to numeric
contributions to the *cryptographic violation score* `C_i^t` used by
`risk_score.RiskScoreUpdater`.

Each detection function returns a `Violation` describing *which* rule
triggered (used by audit logs) and a numeric weight in `[0, 1]`.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from ..core.exceptions import (
    CapabilityAudienceError,
    CapabilityError,
    CapabilityExpiredError,
    CapabilityScopeError,
    ChainError,
    EnvelopeError,
    HashMismatchError,
    IdentityError,
    ReplayError,
    SequenceError,
    SignatureVerificationError,
)


class CryptoViolationKind(str, Enum):
    """The 10 conditions enumerated in paper §III-G."""

    INVALID_SIGNATURE = "invalid_signature"
    EXPIRED_OR_FORGED_CAPABILITY = "expired_or_forged_capability"
    NONCE_REUSE = "nonce_reuse"
    INCONSISTENT_SEQUENCE = "inconsistent_sequence"
    INVALID_AGENT_CARD = "invalid_agent_card"
    FAILED_ENV_ATTESTATION = "failed_env_attestation"
    PAYLOAD_HASH_MISMATCH = "payload_hash_mismatch"
    INCONSISTENT_LOG_ROOT = "inconsistent_log_root"
    INVALID_MERKLE_PROOF = "invalid_merkle_proof"
    UNAUTHORIZED_DELEGATION = "unauthorized_delegation"


@dataclass(frozen=True)
class Violation:
    """One detected cryptographic violation."""

    kind: CryptoViolationKind
    severity: float  # contribution to C_i^t in [0, 1]


# ---------------------------------------------------------------------------
# Mapping from concrete exception types to violation kinds.
# ---------------------------------------------------------------------------
_EXCEPTION_MAP: dict[type[BaseException], tuple[CryptoViolationKind, float]] = {
    SignatureVerificationError: (CryptoViolationKind.INVALID_SIGNATURE, 1.0),
    HashMismatchError: (CryptoViolationKind.PAYLOAD_HASH_MISMATCH, 1.0),
    SequenceError: (CryptoViolationKind.INCONSISTENT_SEQUENCE, 0.7),
    ChainError: (CryptoViolationKind.INCONSISTENT_SEQUENCE, 0.8),
    ReplayError: (CryptoViolationKind.NONCE_REUSE, 0.9),
    CapabilityExpiredError: (CryptoViolationKind.EXPIRED_OR_FORGED_CAPABILITY, 0.8),
    CapabilityScopeError: (CryptoViolationKind.UNAUTHORIZED_DELEGATION, 0.8),
    CapabilityAudienceError: (CryptoViolationKind.EXPIRED_OR_FORGED_CAPABILITY, 0.9),
    CapabilityError: (CryptoViolationKind.EXPIRED_OR_FORGED_CAPABILITY, 0.7),
    EnvelopeError: (CryptoViolationKind.INVALID_AGENT_CARD, 0.5),
    IdentityError: (CryptoViolationKind.INVALID_AGENT_CARD, 1.0),
}


def classify_exception(exc: BaseException) -> Violation | None:
    """Translate an exception raised during verification into a `Violation`.

    Returns `None` if the exception is not one of the recognised
    cryptographic-detection cases — callers should treat such failures
    as bugs rather than malicious behaviour.
    """

    for exc_type, (kind, severity) in _EXCEPTION_MAP.items():
        if isinstance(exc, exc_type):
            return Violation(kind=kind, severity=severity)
    return None


def violation(kind: CryptoViolationKind, severity: float = 1.0) -> Violation:
    """Convenience factory for hand-rolled violations (e.g. from log audits)."""

    if not 0.0 <= severity <= 1.0:
        raise ValueError("severity must be in [0, 1]")
    return Violation(kind=kind, severity=severity)
