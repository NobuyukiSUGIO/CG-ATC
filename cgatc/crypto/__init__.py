"""CG-ATC cryptographic primitives (paper §III)."""

from .primitives import (
    H,
    H_iter,
    Sign,
    Verify,
    aead_decrypt,
    aead_encrypt,
    constant_time_eq,
    generate_keypair,
    keypair_from_secret,
    verify_or_raise,
)
from .kex import (
    derive_session_key,
    generate_x25519_keypair,
    hkdf_session_key,
    x25519_shared,
)
from .threshold import (
    MultiSigThresholdAuthority,
    ThresholdAuthority,
    ThresholdShare,
    ThresholdSignature,
)
from .vrf import select_committee, vrf_eval, vrf_verify

__all__ = [
    "H",
    "H_iter",
    "MultiSigThresholdAuthority",
    "Sign",
    "ThresholdAuthority",
    "ThresholdShare",
    "ThresholdSignature",
    "Verify",
    "aead_decrypt",
    "aead_encrypt",
    "constant_time_eq",
    "derive_session_key",
    "generate_keypair",
    "generate_x25519_keypair",
    "hkdf_session_key",
    "keypair_from_secret",
    "select_committee",
    "verify_or_raise",
    "vrf_eval",
    "vrf_verify",
    "x25519_shared",
]
