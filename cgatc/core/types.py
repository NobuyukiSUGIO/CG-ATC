"""Domain value-objects for CG-ATC (Sugio 2026, §III-A).

All identifiers are opaque, immutable byte sequences.  Raw `bytes` MUST NOT
be passed around outside this module — use the `AgentID`, `TaskID`,
`SessionID`, `Nonce` wrappers.  This honours the CLAUDE.md §4.3 rule
"AgentID is a value object — do not pass raw bytes around".
"""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import NewType


# ---------------------------------------------------------------------------
# Opaque-bytes wrappers
# ---------------------------------------------------------------------------
class _OpaqueBytes:
    """Common base for thin immutable byte wrappers used as IDs."""

    __slots__ = ("_b",)

    # Declared for the type-checker only: the slot is populated via
    # object.__setattr__ (below) because __setattr__ is blocked.  A bare
    # annotation creates no class attribute, so __slots__ stays intact.
    _b: bytes

    def __init__(self, raw: bytes) -> None:
        if not isinstance(raw, (bytes, bytearray, memoryview)):
            raise TypeError(f"{type(self).__name__} requires bytes, got {type(raw).__name__}")
        object.__setattr__(self, "_b", bytes(raw))

    @property
    def raw(self) -> bytes:
        return self._b

    # -- equality / hashing -------------------------------------------------
    def __eq__(self, other: object) -> bool:
        return isinstance(other, type(self)) and self._b == other._b

    def __hash__(self) -> int:
        return hash((type(self).__name__, self._b))

    # -- representation -----------------------------------------------------
    def __repr__(self) -> str:
        return f"{type(self).__name__}({self._b.hex()[:16]}…)"

    def __str__(self) -> str:
        return self.hex()

    def hex(self) -> str:
        return self._b.hex()

    def __setattr__(self, key: str, value: object) -> None:
        raise AttributeError(f"{type(self).__name__} is immutable")


class AgentID(_OpaqueBytes):
    """ID_i = H(pk_i ‖ modelHash_i ‖ policyHash_i ‖ envHash_i)  (paper §III-C)."""


class TaskID(_OpaqueBytes):
    """taskID inside an A2A session (paper §III-D)."""

    @classmethod
    def random(cls) -> "TaskID":
        return cls(secrets.token_bytes(16))


class SessionID(_OpaqueBytes):
    """sessionID for an A2A session (paper §III-D)."""

    @classmethod
    def random(cls) -> "SessionID":
        return cls(secrets.token_bytes(16))


class CapabilityID(_OpaqueBytes):
    """capID identifying a capability token (paper §III-E)."""

    @classmethod
    def random(cls) -> "CapabilityID":
        return cls(secrets.token_bytes(16))


class Nonce(_OpaqueBytes):
    """Random nonce, e.g. inside a capability token or session handshake."""

    @classmethod
    def random(cls, n: int = 16) -> "Nonce":
        return cls(secrets.token_bytes(n))


# ---------------------------------------------------------------------------
# Time
# ---------------------------------------------------------------------------
Timestamp = NewType("Timestamp", float)


def now() -> Timestamp:
    """Wall-clock seconds since the Unix epoch (UTC)."""

    return Timestamp(time.time())


# ---------------------------------------------------------------------------
# Message types & containment levels
# ---------------------------------------------------------------------------
class MessageType(str, Enum):
    """Types of A2A envelopes that CG-ATC distinguishes."""

    HANDSHAKE = "handshake"
    REQUEST = "request"
    RESPONSE = "response"
    DELEGATION = "delegation"
    AUDIT_COMMIT = "audit_commit"
    REVOCATION = "revocation"


class ContainmentLevel(int, Enum):
    """Seven-stage gradual containment ladder (paper §III-H-1, items 1-7)."""

    NORMAL = 0
    INCREASED_MONITORING = 1
    OUTPUT_RESTRICTED = 2
    HIGH_RISK_TOOLS_DISABLED = 3
    DELEGATION_PROHIBITED = 4
    READ_ONLY = 5
    NETWORK_ISOLATED = 6
    CREDENTIALS_REVOKED = 7


# ---------------------------------------------------------------------------
# Secret-bytes wrapper (CLAUDE.md §4.6)
# ---------------------------------------------------------------------------
class SecretBytes:
    """Wrapper that hides the underlying bytes from `repr`, `str`, and logs.

    The CLAUDE.md §4.6 rule forbids leaking secret-key material into log
    output, tracebacks, or repr().  Use this wrapper for any private-key or
    long-lived shared-secret value held in process memory.
    """

    __slots__ = ("_b",)

    # Type-checker-only declaration; see the note on _OpaqueBytes._b.
    _b: bytes

    def __init__(self, raw: bytes) -> None:
        if not isinstance(raw, (bytes, bytearray, memoryview)):
            raise TypeError("SecretBytes requires bytes")
        object.__setattr__(self, "_b", bytes(raw))

    def expose(self) -> bytes:
        """Return the raw bytes.  CALLER is responsible for not leaking it."""

        return self._b

    def __len__(self) -> int:
        return len(self._b)

    def __eq__(self, other: object) -> bool:
        # constant-time compare to avoid trivial timing side-channels
        if not isinstance(other, SecretBytes):
            return NotImplemented
        return secrets.compare_digest(self._b, other._b)

    def __hash__(self) -> int:  # do NOT include the secret in the hash
        return id(self)

    def __repr__(self) -> str:
        return f"SecretBytes(len={len(self._b)})"

    def __str__(self) -> str:  # noqa: DUN001
        return repr(self)

    def __setattr__(self, key: str, value: object) -> None:
        raise AttributeError("SecretBytes is immutable")


# ---------------------------------------------------------------------------
# Key pair container (public part is exposable, secret part is wrapped)
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class KeyPair:
    """Ed25519 key pair handle.

    `public_key` is plain bytes (safe to log); `secret_key` is a SecretBytes
    wrapper.  The signing primitives in `cgatc.crypto.primitives` accept this
    container directly.
    """

    public_key: bytes
    secret_key: SecretBytes = field(repr=False)
