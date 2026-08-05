"""Unit tests for X25519 + HKDF session-key derivation (paper §III-J step 5)."""

from __future__ import annotations

import unittest

from cgatc.crypto.kex import (
    derive_session_key,
    generate_x25519_keypair,
    hkdf_session_key,
    x25519_shared,
)


class TestECDH(unittest.TestCase):
    def test_keypair_distinct(self) -> None:
        pk1, sk1 = generate_x25519_keypair()
        pk2, sk2 = generate_x25519_keypair()
        self.assertNotEqual(pk1, pk2)
        self.assertEqual(len(pk1), 32)
        self.assertEqual(len(sk1), 32)

    def test_shared_secret_is_symmetric(self) -> None:
        pk_a, sk_a = generate_x25519_keypair()
        pk_b, sk_b = generate_x25519_keypair()
        sec_ab = x25519_shared(sk_a, pk_b)
        sec_ba = x25519_shared(sk_b, pk_a)
        self.assertEqual(sec_ab, sec_ba)

    def test_shared_secret_changes_with_peer(self) -> None:
        pk_a, sk_a = generate_x25519_keypair()
        pk_b, _ = generate_x25519_keypair()
        pk_c, _ = generate_x25519_keypair()
        self.assertNotEqual(x25519_shared(sk_a, pk_b), x25519_shared(sk_a, pk_c))


class TestHKDF(unittest.TestCase):
    def test_distinct_salts_yield_distinct_keys(self) -> None:
        from cgatc.core.types import SecretBytes
        sec = SecretBytes(b"\x42" * 32)
        k1 = hkdf_session_key(shared=sec, salt=b"\x01" * 16, info=b"x")
        k2 = hkdf_session_key(shared=sec, salt=b"\x02" * 16, info=b"x")
        self.assertNotEqual(k1, k2)

    def test_distinct_info_yield_distinct_keys(self) -> None:
        from cgatc.core.types import SecretBytes
        sec = SecretBytes(b"\x42" * 32)
        k1 = hkdf_session_key(shared=sec, salt=b"\x00" * 16, info=b"a")
        k2 = hkdf_session_key(shared=sec, salt=b"\x00" * 16, info=b"b")
        self.assertNotEqual(k1, k2)


class TestDeriveSessionKey(unittest.TestCase):
    def test_two_parties_agree(self) -> None:
        pk_a, sk_a = generate_x25519_keypair()
        pk_b, sk_b = generate_x25519_keypair()
        salt = b"\x07" * 16
        ctx = b"alice|bob|session-1"
        k_a = derive_session_key(my_sk=sk_a, peer_pk=pk_b, salt=salt, context=ctx)
        k_b = derive_session_key(my_sk=sk_b, peer_pk=pk_a, salt=salt, context=ctx)
        self.assertEqual(k_a, k_b)
        self.assertEqual(len(k_a), 32)

    def test_distinct_context_distinct_keys(self) -> None:
        pk_a, sk_a = generate_x25519_keypair()
        pk_b, _ = generate_x25519_keypair()
        salt = b"\x07" * 16
        k1 = derive_session_key(my_sk=sk_a, peer_pk=pk_b, salt=salt, context=b"s1")
        k2 = derive_session_key(my_sk=sk_a, peer_pk=pk_b, salt=salt, context=b"s2")
        self.assertNotEqual(k1, k2)


class TestWorkflowECDHHandshake(unittest.TestCase):
    """Smoke-test that `Workflow.handshake` accepts the ECDH path."""

    def test_handshake_with_ecdh(self) -> None:
        import time
        from cgatc.a2a_integration import Middleware, Workflow
        from cgatc.audit import HashChainLog, InMemoryCommitterSink
        from cgatc.capability import Constraints, Enforcer, PolicyAuthority
        from cgatc.core.types import TaskID
        from cgatc.crypto.primitives import generate_keypair
        from cgatc.identity import (
            build_card,
            collect_local_env_attest,
            compute_model_hash,
            compute_policy_hash,
            sign_card,
        )

        pa = PolicyAuthority()
        kp_a = generate_keypair()
        card_a = build_card(
            keypair=kp_a, model_hash=compute_model_hash("a"),
            policy_hash=compute_policy_hash({"x": 1}),
            env_attest=collect_local_env_attest(),
            scopes=["x"], expiry=time.time() + 3600,
        )
        signed_a = sign_card(card_a, kp_a)

        kp_b = generate_keypair()
        card_b = build_card(
            keypair=kp_b, model_hash=compute_model_hash("b"),
            policy_hash=compute_policy_hash({"x": 1}),
            env_attest=collect_local_env_attest(),
            scopes=["x"], expiry=time.time() + 3600,
        )
        signed_b = sign_card(card_b, kp_b)
        bob_id = signed_b.card.agent_id

        bob_dh_pk, _bob_dh_sk = generate_x25519_keypair()
        mw = Middleware(my_agent_id=bob_id,
                        enforcer=Enforcer(trusted_pa_pubkeys=[pa.public_key]))
        wf = Workflow(my_keypair=kp_b, my_agent_id=bob_id,
                      policy_authority=pa, middleware=mw,
                      audit_sink=InMemoryCommitterSink())
        hs = wf.handshake(peer_card=signed_a, task=TaskID.random(),
                          scopes=["x"], constraints=Constraints(),
                          peer_x25519_pubkey=bob_dh_pk)
        self.assertEqual(len(hs.session_key), 32)
        self.assertIsNotNone(hs.x25519_pubkey)
        self.assertIsNotNone(hs.kex_salt)


if __name__ == "__main__":
    unittest.main()
