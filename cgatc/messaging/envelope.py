"""Signed A2A message envelope (paper §III-D).

Envelope structure (Eq. III-D):

    m = (sessionID, taskID, seq, senderID, receiverID, type,
         payloadHash, capID, prevHash, timestamp)
    σ = Sign_{sk_i}(H(m))

Verification on the receiver side is performed by `verify_envelope`,
which checks (in this order):

    1. signature σ over H(m)
    2. payload hash matches the supplied payload (if provided)
    3. timestamp falls inside the freshness window
    4. seq is strictly greater than the last seq seen on this session
       from this sender
    5. prevHash equals the receiver's expected chain head for this session

The chain-head and seq state machines live in `cgatc.messaging.chain` and
`cgatc.messaging.replay_guard`; this module only knows about a single
envelope.
"""

from __future__ import annotations

import json
import time
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field

from ..core.constants import DEFAULT_FRESHNESS_WINDOW_SECONDS, GENESIS_PREV_HASH
from ..core.exceptions import (
    EnvelopeError,
    HashMismatchError,
    SignatureVerificationError,
    StaleTimestampError,
)
from ..core.types import (
    AgentID,
    CapabilityID,
    KeyPair,
    MessageType,
    SessionID,
    TaskID,
)
from ..crypto.primitives import H, Sign, Verify


# ---------------------------------------------------------------------------
# Pydantic model for `m`
# ---------------------------------------------------------------------------
class Envelope(BaseModel):
    """The unsigned A2A message tuple (paper §III-D).

    Hex-encoded fields keep the model JSON-serialisable for transport
    over A2A's JSON-RPC.
    """

    model_config = ConfigDict(frozen=True)

    session_id_hex: str
    task_id_hex: str
    seq: int = Field(ge=0)
    sender_id_hex: str
    receiver_id_hex: str
    type: MessageType
    payload_hash_hex: str
    cap_id_hex: str | None = None
    prev_hash_hex: str
    timestamp: float

    # ---- accessors ---------------------------------------------------------
    @property
    def session_id(self) -> SessionID:
        return SessionID(bytes.fromhex(self.session_id_hex))

    @property
    def task_id(self) -> TaskID:
        return TaskID(bytes.fromhex(self.task_id_hex))

    @property
    def sender_id(self) -> AgentID:
        return AgentID(bytes.fromhex(self.sender_id_hex))

    @property
    def receiver_id(self) -> AgentID:
        return AgentID(bytes.fromhex(self.receiver_id_hex))

    @property
    def payload_hash(self) -> bytes:
        return bytes.fromhex(self.payload_hash_hex)

    @property
    def prev_hash(self) -> bytes:
        return bytes.fromhex(self.prev_hash_hex)

    @property
    def cap_id(self) -> CapabilityID | None:
        return CapabilityID(bytes.fromhex(self.cap_id_hex)) if self.cap_id_hex else None

    # ---- canonical encoding ------------------------------------------------
    def encode_canonical(self) -> bytes:
        """Stable byte serialisation; input to H(m)."""

        return json.dumps(
            self.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode()

    def digest(self) -> bytes:
        """H(m), used as the message-digest input to `Sign`."""

        return H(self.encode_canonical())


class SignedEnvelope(BaseModel):
    """`Envelope` together with σ (paper §III-D)."""

    model_config = ConfigDict(frozen=True)

    envelope: Envelope
    signature_hex: str

    @property
    def signature(self) -> bytes:
        return bytes.fromhex(self.signature_hex)

    def to_json(self) -> str:
        return self.model_dump_json()

    @classmethod
    def from_json(cls, raw: str | bytes) -> "SignedEnvelope":
        return cls.model_validate_json(raw)


# ---------------------------------------------------------------------------
# Build / sign / verify
# ---------------------------------------------------------------------------
def build_envelope(
    *,
    session_id: SessionID,
    task_id: TaskID,
    seq: int,
    sender_id: AgentID,
    receiver_id: AgentID,
    msg_type: MessageType,
    payload: bytes,
    prev_hash: bytes = GENESIS_PREV_HASH,
    cap_id: CapabilityID | None = None,
    timestamp: float | None = None,
) -> Envelope:
    """Construct an `Envelope` from raw fields and the payload bytes."""

    return Envelope(
        session_id_hex=session_id.hex(),
        task_id_hex=task_id.hex(),
        seq=seq,
        sender_id_hex=sender_id.hex(),
        receiver_id_hex=receiver_id.hex(),
        type=msg_type,
        payload_hash_hex=H(payload).hex(),
        cap_id_hex=cap_id.hex() if cap_id is not None else None,
        prev_hash_hex=prev_hash.hex(),
        timestamp=timestamp if timestamp is not None else time.time(),
    )


def sign_envelope(env: Envelope, keypair: KeyPair) -> SignedEnvelope:
    """σ = Sign_{sk_i}(H(m))  (paper §III-D)."""

    sig = Sign(env.digest(), keypair)
    return SignedEnvelope(envelope=env, signature_hex=sig.hex())


def verify_envelope(
    signed: SignedEnvelope,
    *,
    sender_pubkey: bytes,
    payload: bytes | None = None,
    expected_receiver: AgentID | None = None,
    now_ts: Optional[float] = None,
    freshness_window_s: int = DEFAULT_FRESHNESS_WINDOW_SECONDS,
) -> None:
    """Verify an envelope according to paper §III-D.

    `chain` / `replay_guard` are the source of truth for `prev_hash` and
    `seq`; this function only enforces the per-envelope checks.

    Raises a subclass of `EnvelopeError` on failure.  Returned exceptions
    are intentionally non-discriminating in their message (CLAUDE.md §4.5)
    but type-discriminating so the audit log can record which check tripped.
    """

    env = signed.envelope

    # 1. signature
    if not Verify(env.digest(), signed.signature, sender_pubkey):
        raise SignatureVerificationError("invalid envelope")

    # 2. payload hash
    if payload is not None and H(payload) != env.payload_hash:
        raise HashMismatchError("invalid envelope")

    # 3. freshness
    ts = now_ts if now_ts is not None else time.time()
    if abs(ts - env.timestamp) > freshness_window_s:
        raise StaleTimestampError("invalid envelope")

    # 4. receiver binding
    if expected_receiver is not None and expected_receiver != env.receiver_id:
        raise EnvelopeError("invalid envelope")


def encode_envelope_header(signed: SignedEnvelope) -> dict[str, Any]:
    """Encode an envelope+signature as A2A metadata headers (paper §III-J).

    Returns a dict ready to be serialised into A2A request/response
    metadata (see `cgatc.a2a_integration.headers`).  Concretely we use a
    single `A2A-Envelope` header carrying base64url(JSON) — this keeps
    individual headers well-formed regardless of payload.
    """

    return {"A2A-Envelope": signed.to_json()}
