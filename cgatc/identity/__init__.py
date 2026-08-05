"""CG-ATC identity layer (paper §III-C)."""

from .agent_card import (
    Card,
    SignedCard,
    build_card,
    compute_agent_id,
    compute_model_hash,
    compute_policy_hash,
    sign_card,
    verify_card,
)
from .attestation import (
    EnvAttest,
    collect_local_env_attest,
    compute_env_hash,
    register_verifier,
    verify_env_attest,
)
from .keystore import InMemoryKeyStore, KeyStore

__all__ = [
    "Card",
    "EnvAttest",
    "InMemoryKeyStore",
    "KeyStore",
    "SignedCard",
    "build_card",
    "collect_local_env_attest",
    "compute_agent_id",
    "compute_env_hash",
    "compute_model_hash",
    "compute_policy_hash",
    "register_verifier",
    "sign_card",
    "verify_card",
    "verify_env_attest",
]
