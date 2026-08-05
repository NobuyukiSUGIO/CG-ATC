"""k-of-n threshold authorisation (paper §III-H-3).

The paper allows any unforgeable threshold scheme (FROST, BLS, …).  For
the reference implementation we ship a *threshold multi-signature*
proxy: a high-risk action is authorised iff `k` distinct authorised
signers each produced a valid Ed25519 signature over `H(action)`.

This satisfies the security property of Theorem 4 (an adversary that
controls fewer than `k` signers cannot produce a valid `k`-of-`n`
authorisation), but proofs are `k * 64` bytes instead of FROST's 64.

The interface is `ThresholdAuthority`; tests in `tests/security/test_theorem4_*`
are written against the protocol so a FROST backend can swap in.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Protocol

from ..core.exceptions import ThresholdNotMetError
from .primitives import H, Sign, Verify


@dataclass(frozen=True)
class ThresholdShare:
    """One signer's contribution toward a k-of-n authorisation."""

    signer_index: int  # 0 ≤ index < n
    signer_pubkey: bytes  # 32 bytes
    signature: bytes  # 64 bytes


@dataclass(frozen=True)
class ThresholdSignature:
    """Aggregated authorisation: at least `k` distinct shares."""

    k: int
    n: int
    action_digest: bytes
    shares: tuple[ThresholdShare, ...]


class ThresholdAuthority(Protocol):
    """A k-of-n authority over a fixed signer set."""

    @property
    def k(self) -> int: ...

    @property
    def n(self) -> int: ...

    def authorize(self, action: bytes, shares: Iterable[ThresholdShare]) -> ThresholdSignature: ...

    def verify(self, signed: ThresholdSignature) -> bool: ...


class MultiSigThresholdAuthority:
    """Reference implementation backed by Ed25519 multi-signature."""

    def __init__(self, *, k: int, signer_pubkeys: list[bytes]) -> None:
        if k < 1:
            raise ValueError("k must be >= 1")
        if k > len(signer_pubkeys):
            raise ValueError("k cannot exceed the number of signers")
        if any(len(pk) != 32 for pk in signer_pubkeys):
            raise ValueError("each signer pubkey must be 32 bytes")
        self._k = k
        self._signers = list(signer_pubkeys)

    @property
    def k(self) -> int:
        return self._k

    @property
    def n(self) -> int:
        return len(self._signers)

    @staticmethod
    def action_digest(action: bytes) -> bytes:
        """H(action)."""

        return H(action)

    def make_share(self, signer_index: int, secret_key, action: bytes) -> ThresholdShare:  # type: ignore[no-untyped-def]
        from ..core.types import KeyPair, SecretBytes

        if not 0 <= signer_index < self.n:
            raise ValueError("signer index out of range")
        if isinstance(secret_key, KeyPair):
            sk = secret_key.secret_key
        elif isinstance(secret_key, SecretBytes):
            sk = secret_key
        else:
            raise TypeError("secret_key must be KeyPair or SecretBytes")
        sig = Sign(self.action_digest(action), sk)
        return ThresholdShare(
            signer_index=signer_index,
            signer_pubkey=self._signers[signer_index],
            signature=sig,
        )

    def authorize(
        self, action: bytes, shares: Iterable[ThresholdShare]
    ) -> ThresholdSignature:
        digest = self.action_digest(action)
        good: list[ThresholdShare] = []
        seen_signers: set[int] = set()
        for s in shares:
            if s.signer_index in seen_signers:
                continue  # ignore duplicates
            if not 0 <= s.signer_index < self.n:
                continue
            if s.signer_pubkey != self._signers[s.signer_index]:
                continue
            if not Verify(digest, s.signature, s.signer_pubkey):
                continue
            seen_signers.add(s.signer_index)
            good.append(s)
            if len(good) >= self._k:
                break
        if len(good) < self._k:
            raise ThresholdNotMetError(
                f"only {len(good)} valid shares of {self._k} required"
            )
        return ThresholdSignature(
            k=self._k, n=self.n, action_digest=digest, shares=tuple(good)
        )

    def verify(self, signed: ThresholdSignature) -> bool:
        if signed.k != self._k or signed.n != self.n:
            return False
        if len(signed.shares) < self._k:
            return False
        seen: set[int] = set()
        for s in signed.shares:
            if s.signer_index in seen:
                return False
            if not 0 <= s.signer_index < self.n:
                return False
            if s.signer_pubkey != self._signers[s.signer_index]:
                return False
            if not Verify(signed.action_digest, s.signature, s.signer_pubkey):
                return False
            seen.add(s.signer_index)
        return len(seen) >= self._k
