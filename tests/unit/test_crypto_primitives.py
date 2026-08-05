"""Unit tests for `cgatc.crypto.primitives`.

Includes Known Answer Tests (KAT) for SHA-256 (NIST short messages) and
Ed25519 (RFC 8032 §7.1 test vector 1) per CLAUDE.md §5.5.
"""

from __future__ import annotations

import unittest

from cgatc.core.exceptions import CryptoError, SignatureVerificationError
from cgatc.core.types import SecretBytes
from cgatc.crypto.primitives import (
    H,
    Sign,
    Verify,
    aead_decrypt,
    aead_encrypt,
    constant_time_eq,
    generate_keypair,
    keypair_from_secret,
    verify_or_raise,
)


class TestSHA256KAT(unittest.TestCase):
    """SHA-256 KAT — NIST Cryptographic Algorithm Validation Program vectors."""

    def test_empty_string(self) -> None:
        # SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        self.assertEqual(
            H().hex(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        )

    def test_abc(self) -> None:
        # SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        self.assertEqual(
            H(b"abc").hex(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        )

    def test_concatenation_equals_serial_hash(self) -> None:
        # H(a, b, c) must equal H of the literal concatenation.
        ref = H(b"abc" + b"def" + b"ghi")
        self.assertEqual(H(b"abc", b"def", b"ghi"), ref)


class TestEd25519KAT(unittest.TestCase):
    """RFC 8032 §7.1 — TEST 1.

    SECRET KEY: 9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60
    PUBLIC KEY: d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a
    MESSAGE   : (empty)
    SIGNATURE : e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555f
                b8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b
    """

    SK = bytes.fromhex(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
    )
    EXPECTED_PK = bytes.fromhex(
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    )
    EXPECTED_SIG = bytes.fromhex(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555f"
        "b8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    )

    def test_keypair_recovery(self) -> None:
        kp = keypair_from_secret(self.SK)
        self.assertEqual(kp.public_key, self.EXPECTED_PK)

    def test_sign_kat(self) -> None:
        kp = keypair_from_secret(self.SK)
        sig = Sign(b"", kp.secret_key)
        self.assertEqual(sig, self.EXPECTED_SIG)

    def test_verify_kat(self) -> None:
        self.assertTrue(Verify(b"", self.EXPECTED_SIG, self.EXPECTED_PK))

    def test_verify_rejects_wrong_message(self) -> None:
        self.assertFalse(Verify(b"x", self.EXPECTED_SIG, self.EXPECTED_PK))

    def test_verify_rejects_bad_signature_length(self) -> None:
        self.assertFalse(Verify(b"", b"\x00" * 63, self.EXPECTED_PK))

    def test_verify_rejects_wrong_pubkey_length(self) -> None:
        with self.assertRaises(CryptoError):
            Verify(b"", self.EXPECTED_SIG, b"\x00" * 31)


class TestSignVerifyRoundTrip(unittest.TestCase):
    def test_random_keys_round_trip(self) -> None:
        kp = generate_keypair()
        msg = b"hello CG-ATC"
        sig = Sign(msg, kp)
        self.assertTrue(Verify(msg, sig, kp.public_key))

    def test_verify_or_raise_raises_on_tamper(self) -> None:
        kp = generate_keypair()
        sig = Sign(b"hello", kp)
        with self.assertRaises(SignatureVerificationError):
            verify_or_raise(b"hello!", sig, kp.public_key)

    def test_verify_or_raise_passes_on_valid(self) -> None:
        kp = generate_keypair()
        sig = Sign(b"hello", kp)
        verify_or_raise(b"hello", sig, kp.public_key)  # must not raise


class TestAEAD(unittest.TestCase):
    def test_encrypt_decrypt_round_trip(self) -> None:
        key = SecretBytes(b"\x01" * 32)
        ct = aead_encrypt(key, b"plaintext", b"context")
        self.assertEqual(aead_decrypt(key, ct, b"context"), b"plaintext")

    def test_decrypt_with_wrong_key_fails(self) -> None:
        ct = aead_encrypt(SecretBytes(b"\x01" * 32), b"x", b"")
        with self.assertRaises(CryptoError):
            aead_decrypt(SecretBytes(b"\x02" * 32), ct, b"")

    def test_decrypt_with_wrong_aad_fails(self) -> None:
        key = SecretBytes(b"\x03" * 32)
        ct = aead_encrypt(key, b"x", b"a")
        with self.assertRaises(CryptoError):
            aead_decrypt(key, ct, b"b")

    def test_decrypt_short_ciphertext_fails(self) -> None:
        with self.assertRaises(CryptoError):
            aead_decrypt(SecretBytes(b"\x04" * 32), b"\x00" * 5, b"")


class TestConstantTimeEq(unittest.TestCase):
    def test_equal(self) -> None:
        self.assertTrue(constant_time_eq(b"abc", b"abc"))

    def test_unequal(self) -> None:
        self.assertFalse(constant_time_eq(b"abc", b"abd"))

    def test_different_length(self) -> None:
        self.assertFalse(constant_time_eq(b"abc", b"abcd"))


class TestSecretBytesDoesNotLeak(unittest.TestCase):
    def test_repr_does_not_contain_secret(self) -> None:
        sb = SecretBytes(b"super-secret-material")
        self.assertNotIn("super-secret-material", repr(sb))
        self.assertNotIn("super-secret-material", str(sb))

    def test_immutable(self) -> None:
        sb = SecretBytes(b"x")
        with self.assertRaises(AttributeError):
            sb._b = b"y"  # type: ignore[misc]


if __name__ == "__main__":
    unittest.main()
