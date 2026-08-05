"""Capability tokens (paper §III-E).

    cap_{i,j,t} = (issuer, subject=A_i, audience=A_j, taskID, scopes,
                   constraints, expiry, nonce)
    σ_PA       = Sign_{sk_PA}(H(cap_{i,j,t}))

A receiver accepts a task request only if the corresponding capability
token is **valid, unexpired, audience-bound, and compatible with the
requested action** (paper §III-E).
"""

from __future__ import annotations

import json
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from ..core.types import AgentID, CapabilityID, Nonce, TaskID
from ..crypto.primitives import H


class Constraints(BaseModel):
    """Bounds enumerated in paper §III-E."""

    model_config = ConfigDict(frozen=True)

    max_tool_invocations: int | None = None
    max_output_size: int | None = None  # bytes
    allowed_external_tools: list[str] = Field(default_factory=list)
    permitted_data_labels: list[str] = Field(default_factory=list)
    delegation_permitted: bool = False
    human_approval_required: bool = False
    risk_score_max: float | None = None
    impact_radius_max: int | None = None


class Capability(BaseModel):
    """Unsigned capability tuple."""

    model_config = ConfigDict(frozen=True)

    cap_id_hex: str
    issuer: str  # Policy Authority identifier
    subject_hex: str  # A_i — the subject who may exercise this capability
    audience_hex: str  # A_j — the resource/agent that must accept it
    task_id_hex: str
    scopes: list[str] = Field(default_factory=list)
    constraints: Constraints = Field(default_factory=Constraints)
    expiry: float
    not_before: float
    nonce_hex: str

    # ---- accessors ---------------------------------------------------------
    @property
    def cap_id(self) -> CapabilityID:
        return CapabilityID(bytes.fromhex(self.cap_id_hex))

    @property
    def subject(self) -> AgentID:
        return AgentID(bytes.fromhex(self.subject_hex))

    @property
    def audience(self) -> AgentID:
        return AgentID(bytes.fromhex(self.audience_hex))

    @property
    def task_id(self) -> TaskID:
        return TaskID(bytes.fromhex(self.task_id_hex))

    @property
    def nonce(self) -> Nonce:
        return Nonce(bytes.fromhex(self.nonce_hex))

    # ---- canonical encoding ------------------------------------------------
    def encode_canonical(self) -> bytes:
        return json.dumps(
            self.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode()

    def digest(self) -> bytes:
        return H(self.encode_canonical())


class SignedCapability(BaseModel):
    model_config = ConfigDict(frozen=True)

    capability: Capability
    issuer_pubkey_hex: str
    signature_hex: str

    @property
    def signature(self) -> bytes:
        return bytes.fromhex(self.signature_hex)

    @property
    def issuer_pubkey(self) -> bytes:
        return bytes.fromhex(self.issuer_pubkey_hex)

    def to_json(self) -> str:
        return self.model_dump_json()

    @classmethod
    def from_json(cls, raw: str | bytes) -> "SignedCapability":
        return cls.model_validate_json(raw)


def constraints_dict(c: Constraints) -> dict[str, Any]:
    return c.model_dump()
