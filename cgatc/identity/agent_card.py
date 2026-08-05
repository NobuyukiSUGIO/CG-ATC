"""Cryptographic Agent Identity & Verifiable Agent Card (paper §III-C).

Implements:

    ID_i  = H(pk_i ‖ modelHash_i ‖ policyHash_i ‖ envHash_i)         (Eq. III-C)
    Card_i = (ID_i, pk_i, Skills_i, Scopes_i, Auth_i,
              PolicyHash_i, EnvAttest_i, Expiry_i)
    σ_i   = Sign_{sk_i}(H(Card_i))

`Card.encode_canonical()` deterministically serialises the Card so that
`H(Card_i)` is well-defined and reproducible across hosts and Python
versions.  Pydantic v2 is used for the data model so the same object can
be (de)serialised from JSON over A2A.
"""

from __future__ import annotations

import json
import time
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from ..core.constants import HASH_SIZE
from ..core.exceptions import (
    AgentCardVerificationError,
    EnvironmentAttestationError,
)
from ..core.types import AgentID, KeyPair, now
from ..crypto.primitives import H, Sign, Verify
from .attestation import EnvAttest, compute_env_hash, verify_env_attest


# ---------------------------------------------------------------------------
# ID computation (Eq. III-C)
# ---------------------------------------------------------------------------
def compute_agent_id(
    pk: bytes,
    model_hash: bytes,
    policy_hash: bytes,
    env_hash: bytes,
) -> AgentID:
    """ID_i = H(pk_i ‖ modelHash_i ‖ policyHash_i ‖ envHash_i).

    Reference: Sugio 2026, §III-C "Cryptographic Agent Identity".

    All inputs must be bytes; the function defends only against type
    confusion — caller is responsible for using a consistent hash size
    (we recommend 32-byte SHA-256 outputs for `model_hash`, `policy_hash`,
    `env_hash`).
    """

    if len(pk) != 32:
        raise ValueError("Ed25519 public key must be exactly 32 bytes")
    for name, value in (
        ("model_hash", model_hash),
        ("policy_hash", policy_hash),
        ("env_hash", env_hash),
    ):
        if len(value) != HASH_SIZE:
            raise ValueError(f"{name} must be {HASH_SIZE} bytes (got {len(value)})")
    return AgentID(H(pk, model_hash, policy_hash, env_hash))


def compute_model_hash(model_descriptor: str | bytes) -> bytes:
    """`modelHash_i = H(model_descriptor)` — placeholder for a stable model id."""

    if isinstance(model_descriptor, str):
        model_descriptor = model_descriptor.encode()
    return H(model_descriptor)


def compute_policy_hash(policy_doc: str | bytes | dict[str, Any]) -> bytes:
    """`policyHash_i = H(canonical(policy))`."""

    if isinstance(policy_doc, dict):
        policy_doc = json.dumps(policy_doc, sort_keys=True, separators=(",", ":")).encode()
    elif isinstance(policy_doc, str):
        policy_doc = policy_doc.encode()
    return H(policy_doc)


# ---------------------------------------------------------------------------
# Card data model
# ---------------------------------------------------------------------------
class Card(BaseModel):
    """Verifiable Agent Card (paper §III-C, Eq. for `Card_i`).

    Note on `model_hash_hex`: the paper defines
        Card_i = (ID_i, pk_i, Skills_i, Scopes_i, Auth_i,
                  PolicyHash_i, EnvAttest_i, Expiry_i)
    and treats `modelHash_i` as a value the verifier knows out-of-band when
    recomputing `ID_i`.  We additionally bind `modelHash_i` into the signed
    Card so that any receiver can locally verify
        ID_i = H(pk ‖ modelHash ‖ policyHash ‖ envHash)
    without an external lookup.  See docs/open_questions.md.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True, frozen=True)

    agent_id_hex: str = Field(..., description="ID_i, hex-encoded")
    public_key_hex: str = Field(..., description="pk_i, hex-encoded (32 bytes)")
    model_hash_hex: str = Field(..., description="modelHash_i, hex-encoded (extension)")
    skills: list[str] = Field(default_factory=list)
    scopes: list[str] = Field(default_factory=list)
    auth: dict[str, str] = Field(
        default_factory=dict, description="Authentication requirements (Auth_i)."
    )
    policy_hash_hex: str = Field(..., description="PolicyHash_i, hex-encoded")
    env_attest: dict[str, Any] = Field(
        ..., description="EnvAttest_i serialised as a dict"
    )
    expiry: float = Field(..., description="Expiry_i: Unix seconds")
    not_before: float = Field(default_factory=lambda: time.time())
    issuer: str | None = Field(default=None, description="Optional issuing authority")

    # Convenience accessors --------------------------------------------------
    @property
    def agent_id(self) -> AgentID:
        return AgentID(bytes.fromhex(self.agent_id_hex))

    @property
    def public_key(self) -> bytes:
        return bytes.fromhex(self.public_key_hex)

    @property
    def policy_hash(self) -> bytes:
        return bytes.fromhex(self.policy_hash_hex)

    @property
    def model_hash(self) -> bytes:
        return bytes.fromhex(self.model_hash_hex)

    @property
    def env_attest_obj(self) -> EnvAttest:
        return EnvAttest(
            kind=str(self.env_attest.get("kind", "local")),
            claims=dict(self.env_attest.get("claims", {})),
            evidence=bytes.fromhex(str(self.env_attest.get("evidence", ""))),
        )

    # Canonical encoding for hashing/signing ---------------------------------
    def encode_canonical(self) -> bytes:
        """Stable byte serialisation of the Card.

        Used as input to `H(Card_i)`.  The order of keys is fixed by
        `sort_keys=True`; lists keep their declared order (intentional —
        skills order is part of the agent's self-description).
        """

        return json.dumps(
            self.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode()


class SignedCard(BaseModel):
    """`Card` together with its issuer signature."""

    model_config = ConfigDict(frozen=True)

    card: Card
    signature_hex: str = Field(..., description="σ_i = Sign_{sk_i}(H(Card_i))")

    @property
    def signature(self) -> bytes:
        return bytes.fromhex(self.signature_hex)

    def to_json(self) -> str:
        return self.model_dump_json()

    @classmethod
    def from_json(cls, raw: str | bytes) -> "SignedCard":
        return cls.model_validate_json(raw)


# ---------------------------------------------------------------------------
# Build / sign / verify
# ---------------------------------------------------------------------------
def build_card(
    *,
    keypair: KeyPair,
    model_hash: bytes,
    policy_hash: bytes,
    env_attest: EnvAttest,
    skills: list[str] | None = None,
    scopes: list[str] | None = None,
    auth: dict[str, str] | None = None,
    expiry: float,
    issuer: str | None = None,
) -> Card:
    """Compute ID_i and assemble a `Card`."""

    env_hash = compute_env_hash(env_attest)
    agent_id = compute_agent_id(keypair.public_key, model_hash, policy_hash, env_hash)
    return Card(
        agent_id_hex=agent_id.hex(),
        public_key_hex=keypair.public_key.hex(),
        model_hash_hex=model_hash.hex(),
        skills=list(skills or []),
        scopes=list(scopes or []),
        auth=dict(auth or {}),
        policy_hash_hex=policy_hash.hex(),
        env_attest={
            "kind": env_attest.kind,
            "claims": dict(env_attest.claims),
            "evidence": env_attest.evidence.hex(),
        },
        expiry=expiry,
        issuer=issuer,
    )


def sign_card(card: Card, keypair: KeyPair) -> SignedCard:
    """σ_i = Sign_{sk_i}(H(Card_i))."""

    digest = H(card.encode_canonical())
    sig = Sign(digest, keypair)
    return SignedCard(card=card, signature_hex=sig.hex())


def verify_card(
    signed: SignedCard,
    *,
    expected_model_hash: bytes | None = None,
    now_ts: float | None = None,
    require_attestation: bool = True,
) -> None:
    """Verify a `SignedCard` end-to-end (paper §III-C, "before initiating
    A2A communication ...").

    Checks performed, in order:
        1. Card is well-formed and the public key length is right.
        2. Signature σ_i is valid under pk_i for H(Card_i).
        3. The recomputed ID_i matches the one declared in the card.
        4. Expiry is in the future and not_before is in the past.
        5. (optional) Model hash equals an externally pinned value.
        6. (optional) Environment attestation verifies against env_hash.

    Raises `AgentCardVerificationError` (or `EnvironmentAttestationError`
    for attestation failures) on the first failure.  Does not log which
    individual check failed (CLAUDE.md §4.5).
    """

    card = signed.card
    if len(card.public_key) != 32:
        raise AgentCardVerificationError("invalid agent card")

    # 2. signature
    digest = H(card.encode_canonical())
    if not Verify(digest, signed.signature, card.public_key):
        raise AgentCardVerificationError("invalid agent card")

    # 3. ID consistency: ID_i must equal H(pk ‖ modelHash ‖ policyHash ‖ envHash).
    env_hash = compute_env_hash(card.env_attest_obj)
    recomputed = compute_agent_id(
        card.public_key, card.model_hash, card.policy_hash, env_hash,
    )
    if recomputed != card.agent_id:
        raise AgentCardVerificationError("invalid agent card")
    # Optional out-of-band pin on the model hash.
    if expected_model_hash is not None and expected_model_hash != card.model_hash:
        raise AgentCardVerificationError("invalid agent card")

    # 4. validity period
    ts = now_ts if now_ts is not None else now()
    if ts >= card.expiry:
        raise AgentCardVerificationError("invalid agent card")
    if ts < card.not_before - 60:  # tolerate 60 s clock skew
        raise AgentCardVerificationError("invalid agent card")

    # 5. attestation
    if require_attestation:
        try:
            verify_env_attest(card.env_attest_obj, env_hash)
        except EnvironmentAttestationError:
            raise


