"""Domain-specific exception hierarchy for CG-ATC.

All exceptions intentionally avoid leaking detail that would help an adversary
distinguish *which* validation failed (Sugio 2026, §III-G; CLAUDE.md §4.5):
detailed messages should only appear in audit logs, not in messages returned to
peers.
"""

from __future__ import annotations


class CGATCError(Exception):
    """Base class for all CG-ATC errors."""


# -- cryptographic verification ---------------------------------------------
class CryptoError(CGATCError):
    """Generic cryptographic failure."""


class SignatureVerificationError(CryptoError):
    """A signature failed to verify."""


class HashMismatchError(CryptoError):
    """A computed hash did not match an expected value."""


# -- identity / agent card --------------------------------------------------
class IdentityError(CGATCError):
    """Generic agent-identity failure."""


class AgentCardVerificationError(IdentityError):
    """Agent Card signature, expiry, or attestation failed verification."""


class EnvironmentAttestationError(IdentityError):
    """Execution-environment attestation could not be verified."""


# -- messaging --------------------------------------------------------------
class EnvelopeError(CGATCError):
    """Generic message-envelope failure."""


class StaleTimestampError(EnvelopeError):
    """Message timestamp is outside the configured freshness window."""


class SequenceError(EnvelopeError):
    """seq number is non-monotonic, duplicated, or out of range."""


class ChainError(EnvelopeError):
    """prevHash is inconsistent with the receiver's expected chain head."""


class ReplayError(EnvelopeError):
    """A previously seen nonce / (sender, seq) pair was observed."""


# -- capability -------------------------------------------------------------
class CapabilityError(CGATCError):
    """Generic capability-token failure."""


class CapabilityScopeError(CapabilityError):
    """Requested action is outside the granted capability scope."""


class CapabilityExpiredError(CapabilityError):
    """Capability token has expired."""


class CapabilityAudienceError(CapabilityError):
    """Capability token is not bound to the presenting audience."""


# -- audit -----------------------------------------------------------------
class AuditError(CGATCError):
    """Generic audit-log failure."""


class AuditTamperingError(AuditError):
    """A previously committed log root no longer matches recomputed state."""


# -- containment / threshold authz ----------------------------------------
class ContainmentError(CGATCError):
    """Generic containment-layer failure."""


class ThresholdNotMetError(ContainmentError):
    """Fewer than k signature shares were supplied for a high-risk action."""
