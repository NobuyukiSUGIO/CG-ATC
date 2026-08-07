"""Theorem 4 — Threshold-Protected Critical Action (paper §III-H, §IV-D).

Statement (paraphrased): if the threshold signature scheme is unforgeable
and the adversary compromises fewer than `k` signing parties, then the
adversary cannot authorise a high-risk action requiring a `k`-of-`n`
threshold signature.

Operationalisation:

    For ANY adversary that controls a strict subset of signers of size
    `< k`, *any* `ThresholdSignature` they can produce MUST fail
    `HighRiskAuthorizer.gate(...)`.
"""

from __future__ import annotations

import secrets
import unittest

from cgatc.containment import (
    ActionDescriptor,
    HighRiskAction,
    HighRiskAuthorizer,
)
from cgatc.core.exceptions import ThresholdNotMetError
from cgatc.crypto import generate_keypair
from cgatc.crypto.threshold import (
    MultiSigThresholdAuthority,
    ThresholdShare,
    ThresholdSignature,
)


def _setup(n: int = 7, k: int = 4):  # type: ignore[no-untyped-def]
    signers = [generate_keypair() for _ in range(n)]
    authority = MultiSigThresholdAuthority(
        k=k, signer_pubkeys=[s.public_key for s in signers]
    )
    authz = HighRiskAuthorizer(authority)
    return signers, authority, authz


class TestThresholdProtectedActions(unittest.TestCase):
    def test_any_subset_of_size_lt_k_cannot_authorize(self) -> None:
        signers, authority, authz = _setup(n=7, k=4)
        action = ActionDescriptor(
            kind=HighRiskAction.SEND_EMAIL, target="oncall@example.com"
        )
        for size in range(0, 4):  # k-1 = 3
            for _ in range(20):  # 20 random subsets
                idxs = sorted(secrets.SystemRandom().sample(range(7), size))
                shares = [
                    authority.make_share(i, signers[i], action.encode()) for i in idxs
                ]
                with self.assertRaises(ThresholdNotMetError):
                    signed = authority.authorize(action.encode(), shares)
                    authz.gate(action, signed)

    def test_at_least_k_authorize_succeeds(self) -> None:
        signers, authority, authz = _setup(n=7, k=4)
        action = ActionDescriptor(kind=HighRiskAction.MODIFY_POLICY, target="auth-policy")
        for size in (4, 5, 6, 7):
            idxs = sorted(secrets.SystemRandom().sample(range(7), size))
            shares = [
                authority.make_share(i, signers[i], action.encode()) for i in idxs
            ]
            signed = authority.authorize(action.encode(), shares)
            authz.gate(action, signed)  # must not raise

    def test_signature_does_not_authorize_different_action(self) -> None:
        signers, authority, authz = _setup(n=5, k=2)
        action_a = ActionDescriptor(HighRiskAction.SEND_EMAIL, "boss@example.com")
        action_b = ActionDescriptor(HighRiskAction.SEND_EMAIL, "victim@example.com")
        shares_a = [authority.make_share(i, signers[i], action_a.encode()) for i in (0, 1)]
        signed_a = authority.authorize(action_a.encode(), shares_a)

        # Try to reuse signed_a to authorise action_b: must fail.
        with self.assertRaises(ThresholdNotMetError):
            authz.gate(action_b, signed_a)

    def test_duplicate_shares_not_counted(self) -> None:
        signers, authority, _authz = _setup(n=5, k=3)
        action = ActionDescriptor(HighRiskAction.DELETE_FILE, "/etc/passwd")
        share = authority.make_share(0, signers[0], action.encode())
        with self.assertRaises(ThresholdNotMetError):
            authority.authorize(action.encode(), [share, share, share])

    def test_share_with_mismatched_pubkey_rejected(self) -> None:
        signers, authority, _authz = _setup(n=5, k=2)
        action = ActionDescriptor(HighRiskAction.EXTERNAL_API, "api.bank.com")
        good = authority.make_share(0, signers[0], action.encode())
        bad = ThresholdShare(
            signer_index=1,
            signer_pubkey=signers[2].public_key,  # wrong pk for index 1
            signature=good.signature,
        )
        with self.assertRaises(ThresholdNotMetError):
            authority.authorize(action.encode(), [good, bad])


if __name__ == "__main__":
    unittest.main()
