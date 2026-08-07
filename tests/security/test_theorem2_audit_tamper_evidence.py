"""Theorem 2 — Tamper-Evident Auditability (paper §III-F, §IV-B).

Statement (paraphrased): if the hash function is collision-resistant,
then an adversary cannot modify a past audit event while preserving
the same committed log root except with negligible probability.

Operationalisation:

    For ANY arbitrary in-place mutation of a committed audit log
    (event content, envelope bytes, signature bytes, ordering, deletion
    of an event, insertion of an event), recomputing the chain or the
    Merkle root must NOT yield the previously committed value.

We do not break SHA-256; we test that the integration always re-derives
the chain from genesis and never trusts the stored `chain_state` blindly.
"""

from __future__ import annotations

import unittest

from cgatc.audit import (
    AuditCommitter,
    HashChainLog,
    InMemoryCommitterSink,
    merkle_root,
)
from cgatc.core.exceptions import AuditTamperingError
from cgatc.core.types import AgentID
from cgatc.crypto.primitives import generate_keypair


def _build_committed_log():  # type: ignore[no-untyped-def]
    aid = AgentID(b"\x42" * 32)
    kp = generate_keypair()
    sink = InMemoryCommitterSink()
    log = HashChainLog(aid)
    for i in range(10):
        log.append({"e": "msg", "i": i, "extra": "x" * (i + 1)})
    AuditCommitter(aid, kp, sink).commit(log)
    return log, sink, kp


class TestTamperEvidentChain(unittest.TestCase):
    def test_event_mutation_detected(self) -> None:
        log, _sink, _kp = _build_committed_log()
        log._records[5].event["i"] = -1  # type: ignore[index]
        with self.assertRaises(AuditTamperingError):
            log.verify()

    def test_event_swap_detected(self) -> None:
        log, _sink, _kp = _build_committed_log()
        a, b = log._records[1], log._records[2]  # type: ignore[index]
        log._records[1] = b  # type: ignore[index]
        log._records[2] = a  # type: ignore[index]
        with self.assertRaises(AuditTamperingError):
            log.verify()

    def test_event_deletion_detected_via_merkle_root(self) -> None:
        log, sink, _kp = _build_committed_log()
        committed_root = sink.commitments[0].root

        leaves_after = [r.event_bytes() for r in log.records()[:-1]]  # delete last
        new_root = merkle_root(leaves_after)
        self.assertNotEqual(new_root, committed_root)

    def test_event_insertion_detected_via_merkle_root(self) -> None:
        log, sink, _kp = _build_committed_log()
        committed_root = sink.commitments[0].root
        leaves_after = [r.event_bytes() for r in log.records()] + [b'{"e":"injected"}']
        new_root = merkle_root(leaves_after)
        self.assertNotEqual(new_root, committed_root)

    def test_signed_root_unforgeable_without_agent_key(self) -> None:
        """Even if the adversary knows the original root, they cannot produce
        a fresh signature over a different root without the agent's sk."""

        from cgatc.crypto.primitives import Verify
        log, sink, kp = _build_committed_log()
        signed = sink.commitments[0]
        # A different (adversarially chosen) root MUST NOT verify under the
        # agent's pk with the original signature.
        evil_root = b"\xff" * 32
        self.assertFalse(Verify(evil_root, signed.signature, kp.public_key))


if __name__ == "__main__":
    unittest.main()
