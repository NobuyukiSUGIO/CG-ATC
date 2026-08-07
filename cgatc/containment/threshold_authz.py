"""Threshold-protected high-risk action gate (paper §III-H).

Wraps `crypto.threshold.MultiSigThresholdAuthority` with the policy
enumeration of §III-H:

    * sending external emails
    * invoking external APIs
    * deleting files
    * accessing credentials
    * performing financial operations
    * modifying security policies
    * delegating privileges to other agents

`HighRiskAction` is the canonical taxonomy.  `HighRiskAuthorizer.gate()`
takes an action description plus the supplied threshold signature and
either accepts it or raises `ThresholdNotMetError`.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from ..core.exceptions import ThresholdNotMetError
from ..crypto.threshold import (
    MultiSigThresholdAuthority,
    ThresholdAuthority,
    ThresholdSignature,
)


class HighRiskAction(str, Enum):
    """The seven high-risk actions enumerated in paper §III-H."""

    SEND_EMAIL = "send_email"
    EXTERNAL_API = "external_api"
    DELETE_FILE = "delete_file"
    ACCESS_CREDENTIAL = "access_credential"
    FINANCIAL_OPERATION = "financial_operation"
    MODIFY_POLICY = "modify_policy"
    DELEGATE_PRIVILEGES = "delegate_privileges"


@dataclass(frozen=True)
class ActionDescriptor:
    kind: HighRiskAction
    target: str
    argv: tuple[str, ...] = ()

    def encode(self) -> bytes:
        body = "|".join((self.kind.value, self.target, ",".join(self.argv)))
        return body.encode()


class HighRiskAuthorizer:
    def __init__(self, authority: ThresholdAuthority) -> None:
        self._authority = authority

    @property
    def authority(self) -> ThresholdAuthority:
        return self._authority

    @classmethod
    def with_signers(cls, *, k: int, signer_pubkeys: list[bytes]) -> "HighRiskAuthorizer":
        return cls(MultiSigThresholdAuthority(k=k, signer_pubkeys=signer_pubkeys))

    def gate(self, action: ActionDescriptor, signature: ThresholdSignature) -> None:
        """Default-deny.  Raises `ThresholdNotMetError` if the proof is bad."""

        if signature.action_digest != self._authority_digest(action):
            raise ThresholdNotMetError("threshold signature does not bind this action")
        if not self._authority.verify(signature):
            raise ThresholdNotMetError("threshold signature failed verification")

    def _authority_digest(self, action: ActionDescriptor) -> bytes:
        # Re-derive the digest the authority computes internally.
        return MultiSigThresholdAuthority.action_digest(action.encode())
