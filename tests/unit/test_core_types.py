"""Unit tests for `cgatc.core.types`."""

from __future__ import annotations

import unittest

from cgatc.core.types import (
    AgentID,
    CapabilityID,
    ContainmentLevel,
    KeyPair,
    Nonce,
    SecretBytes,
    SessionID,
    TaskID,
    now,
)


class TestOpaqueWrappers(unittest.TestCase):
    def test_equality_and_hash(self) -> None:
        a = AgentID(b"\x00" * 32)
        b = AgentID(b"\x00" * 32)
        self.assertEqual(a, b)
        self.assertEqual(hash(a), hash(b))

    def test_distinct_types_not_equal_even_with_same_bytes(self) -> None:
        # AgentID and TaskID share the same byte pattern but must not collide.
        self.assertNotEqual(AgentID(b"x" * 16), TaskID(b"x" * 16))

    def test_immutable(self) -> None:
        a = AgentID(b"\x00")
        with self.assertRaises(AttributeError):
            a._b = b"\x01"  # type: ignore[misc]

    def test_repr_truncates(self) -> None:
        # repr must give a short prefix, never the entire byte string.
        a = AgentID(b"\xab" * 32)
        self.assertIn("…", repr(a))

    def test_random_id_constructors(self) -> None:
        self.assertNotEqual(TaskID.random(), TaskID.random())
        self.assertNotEqual(SessionID.random(), SessionID.random())
        self.assertNotEqual(CapabilityID.random(), CapabilityID.random())
        self.assertNotEqual(Nonce.random(), Nonce.random())

    def test_rejects_non_bytes(self) -> None:
        with self.assertRaises(TypeError):
            AgentID("not bytes")  # type: ignore[arg-type]


class TestNow(unittest.TestCase):
    def test_now_returns_float(self) -> None:
        self.assertIsInstance(now(), float)


class TestSecretBytes(unittest.TestCase):
    def test_repr_hides_content(self) -> None:
        sb = SecretBytes(b"PRIVATE")
        for s in (repr(sb), str(sb)):
            self.assertNotIn("PRIVATE", s)
            self.assertIn("len=7", s)

    def test_constant_time_equality(self) -> None:
        self.assertEqual(SecretBytes(b"abc"), SecretBytes(b"abc"))
        self.assertNotEqual(SecretBytes(b"abc"), SecretBytes(b"abd"))


class TestKeyPair(unittest.TestCase):
    def test_repr_does_not_leak_secret_bytes(self) -> None:
        kp = KeyPair(public_key=b"\x00" * 32, secret_key=SecretBytes(b"S" * 32))
        self.assertNotIn("S" * 32, repr(kp))
        self.assertNotIn(b"S" * 32, repr(kp).encode())


class TestContainmentLevels(unittest.TestCase):
    def test_ordered(self) -> None:
        self.assertLess(ContainmentLevel.NORMAL, ContainmentLevel.READ_ONLY)
        self.assertLess(ContainmentLevel.READ_ONLY, ContainmentLevel.CREDENTIALS_REVOKED)


if __name__ == "__main__":
    unittest.main()
