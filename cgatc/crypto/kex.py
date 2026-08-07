"""ECDH key exchange + HKDF for session keys (paper §V-A step 5).

The handshake derives a 32-byte session key as

    shared = X25519(my_sk, peer_pk)
    key    = HKDF-SHA-256(ikm=shared, salt=session_salt,
                          info=b"cgatc-session-v1" ‖ context)

`session_salt` is fresh per handshake (16 random bytes); both sides
must use the same salt.  `context` binds the key to the (initiator,
responder, session_id) triple.

The peer's X25519 public key is delivered in the handshake metadata
alongside the Agent Card; the long-term Ed25519 key in the Card is
NOT used directly for ECDH (mixing the curves' security models is
unnecessary and noisy).
"""

from __future__ import annotations

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from ..core.exceptions import CryptoError
from ..core.types import SecretBytes


def generate_x25519_keypair() -> tuple[bytes, SecretBytes]:
    """Return (public_key_bytes, secret_key_bytes)."""

    sk = X25519PrivateKey.generate()
    pk = sk.public_key().public_bytes_raw()
    return pk, SecretBytes(sk.private_bytes_raw())


def x25519_shared(my_sk: SecretBytes, peer_pk: bytes) -> SecretBytes:
    if len(peer_pk) != 32:
        raise CryptoError("X25519 public key must be 32 bytes")
    sk = X25519PrivateKey.from_private_bytes(my_sk.expose())
    pk = X25519PublicKey.from_public_bytes(peer_pk)
    shared = sk.exchange(pk)
    return SecretBytes(shared)


def hkdf_session_key(
    *,
    shared: SecretBytes,
    salt: bytes,
    info: bytes,
    length: int = 32,
) -> SecretBytes:
    """RFC 5869 HKDF-SHA-256."""

    if length <= 0 or length > 32 * 255:
        raise CryptoError("invalid HKDF output length")
    derived = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    ).derive(shared.expose())
    return SecretBytes(derived)


def derive_session_key(
    *,
    my_sk: SecretBytes,
    peer_pk: bytes,
    salt: bytes,
    context: bytes,
) -> SecretBytes:
    """One-shot helper: ECDH then HKDF.

    The `context` SHOULD include both initiator and responder identities
    plus the session id so that two distinct handshakes between the same
    pair of agents derive distinct keys.
    """

    shared = x25519_shared(my_sk, peer_pk)
    info = b"cgatc-session-v1\x00" + context
    return hkdf_session_key(shared=shared, salt=salt, info=info)
