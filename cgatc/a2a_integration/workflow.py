"""End-to-end workflow (paper §V-A).

Realises the eleven-step communication workflow listed in the paper:

    1. retrieve the Agent Card of the sender
    2. verify the Agent Card signature
    3. verify certificate chain and expiration time
    4. verify execution environment attestation
    5. establish a secure session key
    6. issue a short-lived capability token
    7. verify the signature of each A2A message
    8. verify the capability token and policy constraints
    9. update the risk score of the sender
   10. reduce capabilities or isolate the sender if the risk score exceeds a threshold
   11. commit audit log roots to an external monitoring service

Steps 1-6 happen during the handshake (`Workflow.handshake`).
Steps 7-10 happen on every message (`Middleware.handle_inbound`).
Step 11 is driven by `Workflow.commit_audit`.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass

from ..audit import AuditCommitter, Commitment, CommitterSink, HashChainLog
from ..capability import Constraints, PolicyAuthority, SignedCapability
from ..core.types import AgentID, KeyPair, SecretBytes, SessionID, TaskID
from ..crypto.kex import (
    derive_session_key,
    generate_x25519_keypair,
)
from ..crypto.primitives import H, aead_encrypt
from ..identity import (
    SignedCard,
    verify_card,
)
from .middleware import Middleware


@dataclass(frozen=True)
class HandshakeResult:
    session_id: SessionID
    session_key: SecretBytes
    capability: SignedCapability
    # Optional ephemeral X25519 public key + salt produced during ECDH; the
    # local side stashes these so it can transmit them to the peer for
    # symmetric key derivation.  Both are None when the legacy random-key
    # path was taken.
    x25519_pubkey: bytes | None = None
    kex_salt: bytes | None = None


class Workflow:
    """Orchestrate the eleven steps of paper §V-A."""

    def __init__(
        self,
        *,
        my_keypair: KeyPair,
        my_agent_id: AgentID,
        policy_authority: PolicyAuthority,
        middleware: Middleware,
        audit_sink: CommitterSink,
    ) -> None:
        self.kp = my_keypair
        self.me = my_agent_id
        self.pa = policy_authority
        self.middleware = middleware
        self._audit_sink = audit_sink
        self._committer = AuditCommitter(my_agent_id, my_keypair, audit_sink)

    # ----------------------------------------------------------------------
    # Steps 1-6 — handshake
    # ----------------------------------------------------------------------
    def handshake(
        self,
        *,
        peer_card: SignedCard,
        task: TaskID,
        scopes: list[str],
        constraints: Constraints | None = None,
        peer_x25519_pubkey: bytes | None = None,
    ) -> HandshakeResult:
        """Verify the peer Card, register their pk, derive a session key,
        and mint a short-lived capability for the peer.

        If `peer_x25519_pubkey` is supplied, the session key is derived
        via X25519 + HKDF-SHA-256 (paper §V-A step 5).  Otherwise we
        fall back to a freshly generated random key for back-compat with
        examples that do not exchange ephemeral DH keys.
        """

        # 1-4. Card verification (signature, expiry, attestation, ID consistency)
        verify_card(peer_card)
        peer_id = peer_card.card.agent_id
        peer_pk = peer_card.card.public_key

        # Register so the middleware can verify subsequent envelopes.
        self.middleware.register_peer(peer_id, peer_pk)

        # 5. Establish session key.
        if peer_x25519_pubkey is not None:
            my_dh_pk, my_dh_sk = generate_x25519_keypair()
            salt = os.urandom(16)
            context = peer_pk + self.kp.public_key  # binds to both identities
            session_key = derive_session_key(
                my_sk=my_dh_sk, peer_pk=peer_x25519_pubkey,
                salt=salt, context=context,
            )
            session_id = SessionID(
                H(b"sess-ecdh", peer_pk, self.kp.public_key,
                  peer_x25519_pubkey, my_dh_pk, salt)[:16]
            )
            # Stash our ephemeral DH pubkey + salt in the result so the
            # caller can transmit them to the peer if the handshake is
            # symmetric (peer side will independently derive the same key).
            self_dh_pk: bytes | None = my_dh_pk
            kex_salt: bytes | None = salt
        else:
            session_key = SecretBytes(os.urandom(32))
            session_id = SessionID(H(b"sess", peer_pk, self.kp.public_key,
                                     session_key.expose())[:16])
            self_dh_pk = None
            kex_salt = None

        # 6. Issue a short-lived capability token (subject = peer, audience = me).
        cap = self.pa.issue(
            subject=peer_id,
            audience=self.me,
            task_id=task,
            scopes=scopes,
            constraints=constraints,
        )
        return HandshakeResult(
            session_id=session_id, session_key=session_key, capability=cap,
            x25519_pubkey=self_dh_pk, kex_salt=kex_salt,
        )

    # ----------------------------------------------------------------------
    # Step 11 — commit audit root
    # ----------------------------------------------------------------------
    def commit_audit(self, log: HashChainLog | None = None) -> Commitment:
        target = log or self.middleware.log
        return self._committer.commit(target)

    # ----------------------------------------------------------------------
    # Convenience: encrypt a payload with the session key
    # ----------------------------------------------------------------------
    @staticmethod
    def encrypt_payload(session_key: SecretBytes, payload: bytes, aad: bytes = b"") -> bytes:
        return aead_encrypt(session_key, payload, aad)
