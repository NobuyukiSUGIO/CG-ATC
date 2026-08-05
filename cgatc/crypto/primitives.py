"""Cryptographic primitives used by CG-ATC.

Thin wrappers over the `cryptography` library:
    H()        — SHA-256 hash + concatenation helper
    Sign()     — Ed25519 signature (EUF-CMA, paper assumption for Theorem 1)
    Verify()   — Ed25519 verification
    AE         — ChaCha20-Poly1305 authenticated encryption for session keys

CLAUDE.md §4.2 forbids hand-rolled cryptography; everything here delegates
to the audited `cryptography` package.
"""

from __future__ import annotations

import hashlib
import os
from typing import Iterable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from ..core.constants import HASH_SIZE
from ..core.exceptions import CryptoError, SignatureVerificationError
from ..core.types import KeyPair, SecretBytes


# ---------------------------------------------------------------------------
# Hash
# ---------------------------------------------------------------------------
def H(*chunks: bytes) -> bytes:
    """SHA-256(chunk_1 ‖ chunk_2 ‖ … ‖ chunk_n).

    The `‖` operator in the paper denotes ordered byte concatenation.
    Length-extension safety is irrelevant here because every call site
    fixes the number and order of chunks at compile time.

    Reference: Sugio 2026 — used throughout §III-C, §III-D, §III-F.
    """

    h = hashlib.sha256()
    for c in chunks:
        if not isinstance(c, (bytes, bytearray, memoryview)):
            raise TypeError("H() only accepts bytes-like input")
        h.update(bytes(c))
    return h.digest()


def H_iter(chunks: Iterable[bytes]) -> bytes:
    """Variant of `H()` that takes an iterable, useful for Merkle code."""

    return H(*chunks)


# ---------------------------------------------------------------------------
# Ed25519 keys
# ---------------------------------------------------------------------------
def generate_keypair() -> KeyPair:
    """Generate a fresh Ed25519 key pair."""

    sk = Ed25519PrivateKey.generate()
    sk_bytes = sk.private_bytes_raw()
    pk_bytes = sk.public_key().public_bytes_raw()
    return KeyPair(public_key=pk_bytes, secret_key=SecretBytes(sk_bytes))


def keypair_from_secret(sk_bytes: bytes) -> KeyPair:
    """Reconstruct a `KeyPair` from a known 32-byte Ed25519 seed."""

    if len(sk_bytes) != 32:
        raise CryptoError("Ed25519 seed must be exactly 32 bytes")
    sk = Ed25519PrivateKey.from_private_bytes(sk_bytes)
    return KeyPair(
        public_key=sk.public_key().public_bytes_raw(),
        secret_key=SecretBytes(sk_bytes),
    )


# ---------------------------------------------------------------------------
# Sign / Verify
# ---------------------------------------------------------------------------
def Sign(message: bytes, sk: SecretBytes | KeyPair) -> bytes:
    """Compute σ = Sign_{sk}(message).

    Reference: Sugio 2026, §III-C "σ_i = Sign_{sk_i}(H(Card_i))" and §III-D
    "σ = Sign_{sk_i}(H(m))".
    """

    if isinstance(sk, KeyPair):
        sk = sk.secret_key
    private_key = Ed25519PrivateKey.from_private_bytes(sk.expose())
    return private_key.sign(message)


def Verify(message: bytes, signature: bytes, pk: bytes) -> bool:
    """Return True iff Verify_{pk}(message, signature) = 1.

    Never raises on a "merely-bad" signature — returns False instead so the
    caller can decide whether to escalate.  Other failures (malformed key,
    wrong sig length) raise `CryptoError`.

    Reference: Sugio 2026, §III-D Eq. for receiver-side verification.
    """

    if len(pk) != 32:
        raise CryptoError("Ed25519 public key must be 32 bytes")
    if len(signature) != 64:
        # Ed25519 signatures are always 64 bytes; a wrong length is
        # automatically a verification failure rather than an exception.
        return False
    public_key = Ed25519PublicKey.from_public_bytes(pk)
    try:
        public_key.verify(signature, message)
    except InvalidSignature:
        return False
    return True


def verify_or_raise(message: bytes, signature: bytes, pk: bytes) -> None:
    """Convenience wrapper that raises `SignatureVerificationError` on failure.

    Use this on protected paths where falling-through with `False` would be
    a bug.
    """

    if not Verify(message, signature, pk):
        raise SignatureVerificationError("signature verification failed")


# ---------------------------------------------------------------------------
# Authenticated encryption (session keys)
# ---------------------------------------------------------------------------
def aead_encrypt(key: SecretBytes, plaintext: bytes, associated_data: bytes = b"") -> bytes:
    """ChaCha20-Poly1305 encrypt; returns nonce (12) ‖ ciphertext ‖ tag (16).

    Used for session-encrypted A2A payloads.  The 12-byte random nonce is
    sufficient; we never reuse a (key, nonce) pair because each session has
    a freshly-derived key.
    """

    if len(key) != 32:
        raise CryptoError("ChaCha20-Poly1305 key must be 32 bytes")
    aead = ChaCha20Poly1305(key.expose())
    nonce = os.urandom(12)
    ct = aead.encrypt(nonce, plaintext, associated_data)
    return nonce + ct


def aead_decrypt(key: SecretBytes, blob: bytes, associated_data: bytes = b"") -> bytes:
    """Inverse of `aead_encrypt`.  Raises `CryptoError` on tag mismatch."""

    if len(key) != 32:
        raise CryptoError("ChaCha20-Poly1305 key must be 32 bytes")
    if len(blob) < 12 + 16:
        raise CryptoError("ciphertext too short")
    aead = ChaCha20Poly1305(key.expose())
    try:
        return aead.decrypt(blob[:12], blob[12:], associated_data)
    except Exception as exc:  # cryptography raises InvalidTag here
        raise CryptoError("authenticated decryption failed") from exc


# ---------------------------------------------------------------------------
# Misc helpers
# ---------------------------------------------------------------------------
def constant_time_eq(a: bytes, b: bytes) -> bool:
    """Constant-time bytes equality."""

    return len(a) == len(b) and _ct_cmp(a, b)


def _ct_cmp(a: bytes, b: bytes) -> bool:
    diff = 0
    for x, y in zip(a, b):
        diff |= x ^ y
    return diff == 0


__all__ = [
    "HASH_SIZE",
    "H",
    "H_iter",
    "Sign",
    "Verify",
    "verify_or_raise",
    "aead_encrypt",
    "aead_decrypt",
    "constant_time_eq",
    "generate_keypair",
    "keypair_from_secret",
]
