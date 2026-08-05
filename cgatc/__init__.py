"""Cryptographically Grounded Agent Trust and Containment (CG-ATC).

Reference implementation of Sugio (2026), §III.

Top-level convenience re-exports keep `from cgatc import ...` ergonomic
for examples and tests.  For full structure see `docs/paper_mapping.md`.
"""

from .core import (
    AgentID,
    CapabilityID,
    ContainmentLevel,
    KeyPair,
    MessageType,
    Nonce,
    SecretBytes,
    SessionID,
    TaskID,
)

__all__ = [
    "AgentID",
    "CapabilityID",
    "ContainmentLevel",
    "KeyPair",
    "MessageType",
    "Nonce",
    "SecretBytes",
    "SessionID",
    "TaskID",
]

__version__ = "0.1.0"
