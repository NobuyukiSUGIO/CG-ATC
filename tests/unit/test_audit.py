"""Unit tests for `cgatc.audit` (paper §III-F)."""

from __future__ import annotations

import unittest

from cgatc.audit import (
    AuditCommitter,
    HashChainLog,
    InMemoryCommitterSink,
    build_proof,
    merkle_root,
    verify_proof,
)
from cgatc.core.types import AgentID
from cgatc.crypto.primitives import generate_keypair


class TestHashChain(unittest.TestCase):
    def test_append_advances_head(self) -> None:
        log = HashChainLog(AgentID(b"\x01" * 32))
        h0 = log.head
        log.append({"e": "msg-verified", "id": 1})
        self.assertNotEqual(log.head, h0)

    def test_verify_accepts_clean_log(self) -> None:
        log = HashChainLog(AgentID(b"\x01" * 32))
        for i in range(5):
            log.append({"e": "x", "i": i})
        log.verify()  # must not raise

    def test_verify_detects_event_mutation(self) -> None:
        from cgatc.core.exceptions import AuditTamperingError

        log = HashChainLog(AgentID(b"\x01" * 32))
        for i in range(5):
            log.append({"e": "x", "i": i})
        # Reach into private state to simulate a malicious in-place edit
        # (in production this would be a disk-level tamper).
        log._records[2].event["i"] = 999  # type: ignore[index]
        with self.assertRaises(AuditTamperingError):
            log.verify()


class TestMerkleProofs(unittest.TestCase):
    def test_root_changes_with_any_leaf_change(self) -> None:
        leaves = [f"x{i}".encode() for i in range(8)]
        r0 = merkle_root(leaves)
        leaves[3] = b"changed"
        r1 = merkle_root(leaves)
        self.assertNotEqual(r0, r1)

    def test_inclusion_proof_round_trip_pow2(self) -> None:
        leaves = [f"x{i}".encode() for i in range(8)]
        root = merkle_root(leaves)
        for i in range(8):
            proof = build_proof(leaves, i)
            self.assertTrue(verify_proof(leaves[i], proof, root))

    def test_inclusion_proof_round_trip_odd(self) -> None:
        leaves = [f"x{i}".encode() for i in range(7)]
        root = merkle_root(leaves)
        for i in range(7):
            proof = build_proof(leaves, i)
            self.assertTrue(verify_proof(leaves[i], proof, root),
                            msg=f"failed at index {i}")

    def test_proof_rejects_wrong_leaf(self) -> None:
        leaves = [f"x{i}".encode() for i in range(8)]
        root = merkle_root(leaves)
        proof = build_proof(leaves, 4)
        self.assertFalse(verify_proof(b"wrong", proof, root))


class TestAuditCommitter(unittest.TestCase):
    def test_commit_signs_root(self) -> None:
        agent_id = AgentID(b"\x09" * 32)
        kp = generate_keypair()
        sink = InMemoryCommitterSink()
        committer = AuditCommitter(agent_id, kp, sink)

        log = HashChainLog(agent_id)
        for i in range(3):
            log.append({"e": "msg", "i": i})
        c = committer.commit(log)

        from cgatc.crypto.primitives import Verify
        self.assertTrue(Verify(c.root, c.signature, kp.public_key))
        self.assertIs(sink.commitments[0], c)


if __name__ == "__main__":
    unittest.main()
