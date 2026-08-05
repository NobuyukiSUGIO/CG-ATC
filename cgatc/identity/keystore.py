"""In-process key store (development).

For production, replace with a KMS / HSM-backed implementation that
implements the same `KeyStore` protocol.  The interface is intentionally
narrow so the swap is mechanical.

CLAUDE.md §4.2: "in production, factor this out behind an interface that
assumes KMS / HSM integration".
"""

from __future__ import annotations

from typing import Protocol

from ..core.types import AgentID, KeyPair, SecretBytes
from ..crypto.primitives import generate_keypair


class KeyStore(Protocol):
    """Interface every key backend must implement."""

    def create(self, agent_id: AgentID) -> KeyPair: ...
    def get(self, agent_id: AgentID) -> KeyPair: ...
    def public_key(self, agent_id: AgentID) -> bytes: ...
    def has(self, agent_id: AgentID) -> bool: ...


class InMemoryKeyStore:
    """Dev/test backend that holds keys only in process memory."""

    def __init__(self) -> None:
        self._store: dict[AgentID, KeyPair] = {}

    def create(self, agent_id: AgentID) -> KeyPair:
        kp = generate_keypair()
        self._store[agent_id] = kp
        return kp

    def insert(self, agent_id: AgentID, kp: KeyPair) -> None:
        self._store[agent_id] = kp

    def get(self, agent_id: AgentID) -> KeyPair:
        return self._store[agent_id]

    def public_key(self, agent_id: AgentID) -> bytes:
        return self._store[agent_id].public_key

    def has(self, agent_id: AgentID) -> bool:
        return agent_id in self._store

    def secret(self, agent_id: AgentID) -> SecretBytes:
        return self._store[agent_id].secret_key
