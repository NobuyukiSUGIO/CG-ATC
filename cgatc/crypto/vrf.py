"""Pseudo-VRF for committee selection (paper §III-H-3).

    committee_t = VRF_{sk_PA}(taskID ‖ epoch)

A full RFC 9381 ECVRF would be ideal but is heavyweight; for the
reference implementation we approximate the VRF primitive with
"signature-as-hash" (Sign-then-Hash):

    proof = Sign_{sk_PA}(seed)
    output = H("vrf-output", proof)

Properties:

    * **Deterministic** (Ed25519 is deterministic per RFC 8032).
    * **Unforgeable** (anyone can verify `proof` against `pk_PA`; producing
      a fresh `proof` for a new seed requires `sk_PA`).
    * **NOT a true VRF** — the formal pseudo-randomness of `output`
      depends on Ed25519 signatures being modelled as a random oracle.

Replace with a real RFC 9381 VRF in production; the public API
(`vrf_eval`, `vrf_verify`, `select_committee`) is stable.
"""

from __future__ import annotations

import struct

from ..core.types import KeyPair
from .primitives import H, Sign, Verify


def vrf_eval(seed: bytes, kp: KeyPair) -> tuple[bytes, bytes]:
    """Return `(output, proof)`."""

    proof = Sign(H(b"vrf-seed", seed), kp)
    output = H(b"vrf-output", proof)
    return output, proof


def vrf_verify(seed: bytes, output: bytes, proof: bytes, pk: bytes) -> bool:
    if not Verify(H(b"vrf-seed", seed), proof, pk):
        return False
    return H(b"vrf-output", proof) == output


def select_committee(
    seed: bytes,
    kp: KeyPair,
    *,
    n_candidates: int,
    k_committee: int,
) -> tuple[list[int], bytes, bytes]:
    """Deterministically pick `k_committee` indices from `range(n_candidates)`.

    Returns `(indices, output, proof)`.  `indices` is sorted ascending so
    the committee is a *set* even though our shuffle is order-aware.
    """

    if k_committee > n_candidates:
        raise ValueError("k_committee cannot exceed n_candidates")
    output, proof = vrf_eval(seed, kp)

    # Fisher-Yates shuffle driven by H(output ‖ counter).
    indices = list(range(n_candidates))
    for i in range(n_candidates - 1, 0, -1):
        digest = H(output, struct.pack(">I", i))
        j = int.from_bytes(digest[:4], "big") % (i + 1)
        indices[i], indices[j] = indices[j], indices[i]
    return sorted(indices[:k_committee]), output, proof
