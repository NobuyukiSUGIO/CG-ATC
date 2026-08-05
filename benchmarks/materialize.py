"""Deterministic crypto materialisation for adaptive-attack workloads.

A single :class:`Workload` produces a stream of :class:`benchmarks.Message`
instances that is consumed by *all* baselines (CG-ATC, mTLS+nonce,
signed-JWT, OPA/Rego, …).  Each baseline reads a different cryptographic
artefact: signed envelopes, JWT compact strings, plain bearer tokens, etc.
To keep the workloads baseline-agnostic, this module gives every workload
the same constructor toolkit:

* :class:`Crew` — reproducible per-agent keypairs and signed Agent Cards
  derived from the workload seed.
* :class:`MessageBuilder` — assembles :class:`benchmarks.Message` instances
  with all the per-baseline metadata (CG-ATC envelope JSON, JWT, payload
  hash, mTLS metadata, central-audit fields) already filled in, so any
  baseline can pick the field it needs.

Determinism: all keypairs are derived via :func:`_derive_keypair`, which
hashes the workload seed and a label so re-running the same workload with
the same ``seed`` produces byte-identical messages.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from dataclasses import dataclass, field
from typing import Any

from cgatc.capability import Constraints, PolicyAuthority, SignedCapability
from cgatc.capability.token import Capability
from cgatc.core.constants import GENESIS_PREV_HASH
from cgatc.core.types import AgentID, KeyPair, MessageType, Nonce, SecretBytes, SessionID, TaskID
from cgatc.crypto.primitives import H, Sign, Verify, generate_keypair, keypair_from_secret
from cgatc.identity import (
    SignedCard,
    build_card,
    collect_local_env_attest,
    compute_model_hash,
    compute_policy_hash,
    sign_card,
)
from cgatc.messaging import SignedEnvelope, build_envelope, sign_envelope

from .interfaces import Message


# ---------------------------------------------------------------------------
# Determinism helpers
# ---------------------------------------------------------------------------
def _derive_seed(seed: int, *labels: str) -> bytes:
    """Return a deterministic 32-byte seed for a (seed, label*) tuple."""

    h = hashlib.sha256()
    h.update(seed.to_bytes(8, "big", signed=True))
    for label in labels:
        h.update(b"\x00")
        h.update(label.encode())
    return h.digest()


def _derive_keypair(seed: int, label: str) -> KeyPair:
    return keypair_from_secret(_derive_seed(seed, "keypair", label))


def _derive_bytes(seed: int, label: str, n: int = 16) -> bytes:
    return _derive_seed(seed, "bytes", label)[:n]


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


# ---------------------------------------------------------------------------
# Crew: reproducible identities for a workload
# ---------------------------------------------------------------------------
@dataclass
class CrewMember:
    name: str  # symbolic ("agent_3", "A_mal", "coordinator", …)
    keypair: KeyPair
    card: SignedCard
    role: str = "worker"

    @property
    def agent_id(self) -> AgentID:
        return self.card.card.agent_id

    @property
    def public_key(self) -> bytes:
        return self.card.card.public_key


@dataclass
class Crew:
    """A bench of agents + a Policy Authority, all derived from a seed."""

    seed: int
    members: dict[str, CrewMember] = field(default_factory=dict)
    pa: PolicyAuthority = field(init=False)
    pa_pubkey: bytes = field(init=False)

    def __post_init__(self) -> None:
        pa_kp = _derive_keypair(self.seed, "policy_authority")
        self.pa = PolicyAuthority(issuer_id="PA", keypair=pa_kp)
        self.pa_pubkey = self.pa.public_key

    # ----- registration ----------------------------------------------------
    def make(self, name: str, *, role: str = "worker", scopes: list[str] | None = None) -> CrewMember:
        if name in self.members:
            return self.members[name]
        kp = _derive_keypair(self.seed, f"agent::{name}")
        card_obj = build_card(
            keypair=kp,
            model_hash=compute_model_hash(name),
            policy_hash=compute_policy_hash({"name": name, "role": role}),
            env_attest=collect_local_env_attest(),
            scopes=list(scopes or []),
            expiry=time.time() + 3600,
        )
        signed_card = sign_card(card_obj, kp)
        member = CrewMember(name=name, keypair=kp, card=signed_card, role=role)
        self.members[name] = member
        return member

    def get(self, name: str) -> CrewMember:
        return self.members[name]

    def issue_capability(
        self,
        *,
        subject: str,
        audience: str,
        task_id: TaskID,
        scopes: list[str],
        constraints: Constraints | None = None,
        ttl_seconds: int = 600,
    ) -> SignedCapability:
        s = self.get(subject).agent_id
        a = self.get(audience).agent_id
        return self.pa.issue(
            subject=s,
            audience=a,
            task_id=task_id,
            scopes=scopes,
            constraints=constraints,
            ttl_seconds=ttl_seconds,
        )


# ---------------------------------------------------------------------------
# Signed JWT helper (Ed25519 / EdDSA)
# ---------------------------------------------------------------------------
def make_signed_jwt(
    *,
    keypair: KeyPair,
    iss: str,
    aud: str,
    sub: str,
    iat: int,
    exp: int,
    jti: str,
    payload_hash: str,
    scopes: list[str],
    extras: dict[str, Any] | None = None,
) -> str:
    """Mint a compact-serialised EdDSA JWT.

    The JWT carries the same claims listed in spec §2.2:
        iss / aud / sub / iat / exp / jti / payload_hash / scope
    """

    header = {"alg": "EdDSA", "typ": "JWT"}
    body: dict[str, Any] = {
        "iss": iss, "aud": aud, "sub": sub, "iat": iat, "exp": exp,
        "jti": jti, "payload_hash": payload_hash, "scope": scopes,
    }
    if extras:
        body.update(extras)
    h_b64 = _b64url(json.dumps(header, separators=(",", ":")).encode())
    p_b64 = _b64url(json.dumps(body, separators=(",", ":"), sort_keys=True).encode())
    signing_input = f"{h_b64}.{p_b64}".encode()
    sig = Sign(signing_input, keypair)
    return f"{h_b64}.{p_b64}.{_b64url(sig)}"


def parse_and_verify_jwt(token: str, *, expected_pubkey: bytes) -> dict[str, Any] | None:
    """Verify ``token``'s signature; return the parsed claims dict on success."""

    try:
        h_b64, p_b64, s_b64 = token.split(".")
        signing_input = f"{h_b64}.{p_b64}".encode()
        if not Verify(signing_input, _b64url_decode(s_b64), expected_pubkey):
            return None
        return json.loads(_b64url_decode(p_b64))
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Per-message materialisation
# ---------------------------------------------------------------------------
@dataclass
class _SenderState:
    seq: int = 0
    last_digest: bytes = GENESIS_PREV_HASH
    session_id: SessionID = field(default_factory=SessionID.random)
    task_id: TaskID = field(default_factory=TaskID.random)
    capability: SignedCapability | None = None


@dataclass
class MessageBuilder:
    """Stateful builder that fills every per-baseline field of a Message.

    Held per-(crew, receiver) so chain heads / capability tokens / sequence
    counters stay coherent across calls.
    """

    crew: Crew
    receiver: str  # symbolic name in the crew

    _by_sender: dict[str, _SenderState] = field(default_factory=dict)

    def _state(self, sender: str) -> _SenderState:
        st = self._by_sender.get(sender)
        if st is None:
            sid_seed = _derive_bytes(self.crew.seed, f"session::{sender}::{self.receiver}", 16)
            tid_seed = _derive_bytes(self.crew.seed, f"task::{sender}::{self.receiver}", 16)
            st = _SenderState(
                session_id=SessionID(sid_seed),
                task_id=TaskID(tid_seed),
            )
            self._by_sender[sender] = st
        return st

    def issue_capability(
        self,
        *,
        sender: str,
        scopes: list[str],
        constraints: Constraints | None = None,
        ttl_seconds: int = 600,
    ) -> SignedCapability:
        st = self._state(sender)
        cap = self.crew.issue_capability(
            subject=sender, audience=self.receiver,
            task_id=st.task_id, scopes=scopes,
            constraints=constraints, ttl_seconds=ttl_seconds,
        )
        st.capability = cap
        return cap

    def build(
        self,
        *,
        sender: str,
        payload: str,
        timestamp: float | None = None,
        nonce_override: bytes | None = None,
        seq_override: int | None = None,
        prev_hash_override: bytes | None = None,
        signature_override: str | None = None,
        capability_override: SignedCapability | None = None,
        action: str = "request",
        scope: str = "tools.read",
        data_label: str = "public",
        is_attack: bool = False,
        attack_kind: str = "",
        expected_block: bool = False,
        hop_depth: int = 0,
        metadata_extras: dict[str, Any] | None = None,
    ) -> Message:
        """Materialise one fully-baked Message (all baselines covered)."""

        sm = self.crew.get(sender)
        rm = self.crew.get(self.receiver)
        st = self._state(sender)

        seq = seq_override if seq_override is not None else st.seq
        ts = timestamp if timestamp is not None else time.time()
        prev_hash = prev_hash_override if prev_hash_override is not None else st.last_digest
        payload_bytes = payload.encode()
        payload_hash = H(payload_bytes)
        nonce_bytes = nonce_override or _derive_seed(
            self.crew.seed, f"nonce::{sender}::{self.receiver}::{seq}",
        )[:16]

        env = build_envelope(
            session_id=st.session_id,
            task_id=st.task_id,
            seq=seq,
            sender_id=sm.agent_id,
            receiver_id=rm.agent_id,
            msg_type=MessageType.REQUEST,
            payload=payload_bytes,
            prev_hash=prev_hash,
            timestamp=ts,
        )
        signed_env: SignedEnvelope = sign_envelope(env, sm.keypair)
        digest = env.digest()

        if seq_override is None:
            st.seq = seq + 1
        # Only advance chain if the caller didn't override prev_hash (i.e. they
        # are sending a normal in-order message rather than crafting a fork).
        if prev_hash_override is None and seq_override is None:
            st.last_digest = digest

        # Capability token
        cap_obj = capability_override if capability_override is not None else st.capability
        if cap_obj is None:
            cap_obj = self.issue_capability(
                sender=sender, scopes=[scope, "tools.*"],
                constraints=Constraints(),
            )

        # JWT (for baseline_signed_jwt)
        jti_seed = _derive_seed(
            self.crew.seed, f"jti::{sender}::{self.receiver}::{seq}::{nonce_bytes.hex()}",
        )
        jti = jti_seed[:16].hex()
        jwt = make_signed_jwt(
            keypair=sm.keypair,
            iss=sm.agent_id.hex(),
            aud=rm.agent_id.hex(),
            sub=st.task_id.hex(),
            iat=int(ts),
            exp=int(ts) + 300,
            jti=jti,
            payload_hash=payload_hash.hex(),
            scopes=[scope],
        )

        meta: dict[str, Any] = {
            # CG-ATC and capability-bearing baselines
            "envelope_json": signed_env.to_json(),
            "capability_json": cap_obj.to_json(),
            "sender_agent_id_hex": sm.agent_id.hex(),
            "receiver_agent_id_hex": rm.agent_id.hex(),
            "task_id_hex": st.task_id.hex(),
            "session_id_hex": st.session_id.hex(),
            "action_scope": scope,
            "action": action,
            "data_label": data_label,
            "sender_role": sm.role,
            "receiver_role": rm.role,
            "sender_pubkey_hex": sm.public_key.hex(),
            # JWT baseline
            "jwt": jwt,
            "jti": jti,
            # mTLS-style transport authentication identifier
            "tls_client_cn": sm.agent_id.hex(),
        }
        if metadata_extras:
            meta.update(metadata_extras)

        return Message(
            session_id=st.session_id.hex(),
            task_id=st.task_id.hex(),
            seq=seq,
            sender_id=sm.name,
            receiver_id=rm.name,
            payload=payload,
            payload_hash=payload_hash.hex(),
            timestamp=ts,
            nonce=nonce_bytes.hex(),
            capability_token=cap_obj.to_json(),
            prev_hash=prev_hash.hex(),
            signature=signed_env.signature_hex,
            metadata=meta,
            is_attack=is_attack,
            attack_kind=attack_kind,
            expected_block=expected_block,
            hop_depth=hop_depth,
        )


# ---------------------------------------------------------------------------
# Re-exports
# ---------------------------------------------------------------------------
__all__ = [
    "Crew",
    "CrewMember",
    "MessageBuilder",
    "make_signed_jwt",
    "parse_and_verify_jwt",
]
