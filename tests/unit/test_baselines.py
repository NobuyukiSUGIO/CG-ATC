"""Sanity tests for baseline receivers."""

from __future__ import annotations

import unittest

from cgatc.baselines import (
    AnomalyNoCryptoReceiver,
    AuthOnlyReceiver,
    Delivery,
    TLSOAuthReceiver,
    Verdict,
)


class TestAuthOnly(unittest.TestCase):
    def test_known_token_accepted(self) -> None:
        rcv = AuthOnlyReceiver({"alice": "secret-A"})
        msg = Delivery(sender="alice", payload=b"x",
                       metadata={"auth_token": "secret-A"}, is_attack=False)
        self.assertEqual(rcv.deliver(msg).verdict, Verdict.ACCEPT)

    def test_unknown_token_rejected(self) -> None:
        rcv = AuthOnlyReceiver({"alice": "secret-A"})
        msg = Delivery(sender="alice", payload=b"x",
                       metadata={"auth_token": "wrong"}, is_attack=True)
        self.assertEqual(rcv.deliver(msg).verdict, Verdict.REJECT)


class TestTLSOAuth(unittest.TestCase):
    def test_in_scope_accepted(self) -> None:
        rcv = TLSOAuthReceiver(
            bearer_scopes={"tok": ["read"]},
            accept_scopes=["read"],
        )
        msg = Delivery("alice", b"x",
                       {"oauth_bearer": "tok", "action_scope": "read"},
                       is_attack=False)
        self.assertEqual(rcv.deliver(msg).verdict, Verdict.ACCEPT)

    def test_out_of_scope_rejected(self) -> None:
        rcv = TLSOAuthReceiver(
            bearer_scopes={"tok": ["read"]},
            accept_scopes=["read"],
        )
        msg = Delivery("alice", b"x",
                       {"oauth_bearer": "tok", "action_scope": "write"},
                       is_attack=True)
        self.assertEqual(rcv.deliver(msg).verdict, Verdict.REJECT)


class TestAnomalyNoCrypto(unittest.TestCase):
    def test_repeated_payload_flagged(self) -> None:
        rcv = AnomalyNoCryptoReceiver(threshold=0.5)
        # Worm-like: same payload many times.
        for _ in range(20):
            r = rcv.deliver(Delivery("worm", b"infect", {}, is_attack=True))
        self.assertEqual(r.verdict, Verdict.REJECT)

    def test_normal_traffic_passes(self) -> None:
        rcv = AnomalyNoCryptoReceiver(threshold=0.5)
        for i in range(20):
            r = rcv.deliver(
                Delivery("alice", f"unique-{i}".encode(), {}, is_attack=False)
            )
        self.assertEqual(r.verdict, Verdict.ACCEPT)


if __name__ == "__main__":
    unittest.main()
