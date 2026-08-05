"""Policy Authority (PA) — issues capability tokens (paper §III-E).

The PA holds a long-term Ed25519 key pair.  It mints `SignedCapability`
tokens scoped to a single (subject, audience, task) triple with a short
TTL.  In production the PA would be a separate service; this class is
process-local but uses the same data model so the move is mechanical.
"""

from __future__ import annotations

import time

from ..core.constants import DEFAULT_CAPABILITY_TTL_SECONDS
from ..core.types import AgentID, CapabilityID, KeyPair, Nonce, TaskID
from ..crypto.primitives import Sign, generate_keypair
from .token import Capability, Constraints, SignedCapability


class PolicyAuthority:
    """Issues short-lived capability tokens."""

    def __init__(self, *, issuer_id: str = "PA", keypair: KeyPair | None = None) -> None:
        self.issuer_id = issuer_id
        self._keypair = keypair or generate_keypair()

    @property
    def public_key(self) -> bytes:
        return self._keypair.public_key

    def issue(
        self,
        *,
        subject: AgentID,
        audience: AgentID,
        task_id: TaskID,
        scopes: list[str],
        constraints: Constraints | None = None,
        ttl_seconds: int = DEFAULT_CAPABILITY_TTL_SECONDS,
        not_before: float | None = None,
    ) -> SignedCapability:
        """Mint a `SignedCapability`.

        Reference: Sugio 2026, §III-E "For each task, a Policy Authority PA
        issues a short-lived capability token."
        """

        nb = not_before if not_before is not None else time.time()
        cap = Capability(
            cap_id_hex=CapabilityID.random().hex(),
            issuer=self.issuer_id,
            subject_hex=subject.hex(),
            audience_hex=audience.hex(),
            task_id_hex=task_id.hex(),
            scopes=list(scopes),
            constraints=constraints or Constraints(),
            expiry=nb + ttl_seconds,
            not_before=nb,
            nonce_hex=Nonce.random().hex(),
        )
        sig = Sign(cap.digest(), self._keypair)
        return SignedCapability(
            capability=cap,
            issuer_pubkey_hex=self._keypair.public_key.hex(),
            signature_hex=sig.hex(),
        )
