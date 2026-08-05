"""Adversarial test: memory poisoning (paper §III-A, §III-G-2).

Memory poisoning injects malicious entries into a long-term store
(vector DB, RAG corpus, conversation memory) so that future inferences
are subverted.

CG-ATC's defence is layered:
  * cryptographic — every memory write is itself an A2A action that
    requires a capability (Theorem 3 bounds what can be written);
  * tamper-evident audit — every write is appended to the agent's
    hash-chain log (Theorem 2 makes silent retroactive edits detectable);
  * behavioural — `BehavioralDetector.observe_memory_write` flags an
    abnormally high write rate (`ABNORMAL_MEMORY_PATTERN`).

This file tests:
  T1. A burst of memory writes from one agent is flagged by the
      behavioural detector.
  T2. Capabilities scoped to read-only memory cannot perform writes.
  T3. Tampering with a previously-committed memory-write audit record
      is detected on `log.verify()`.
"""

from __future__ import annotations

import time
import unittest

from cgatc.audit import HashChainLog
from cgatc.capability import (
    ActionRequest,
    Constraints,
    Enforcer,
    PolicyAuthority,
)
from cgatc.core.exceptions import (
    AuditTamperingError,
    CapabilityScopeError,
)
from cgatc.core.types import AgentID, TaskID
from cgatc.detection import (
    BehavioralAnomalyKind,
    BehavioralDetector,
)


class TestMemoryPoisoning(unittest.TestCase):
    def test_burst_of_writes_flagged(self) -> None:
        """T1: behavioural detector fires on rapid memory-write bursts."""

        det = BehavioralDetector(memory_writes_per_min_threshold=5)
        a = AgentID(b"\x07" * 32)
        # Ten writes within the rolling window.
        anomaly = None
        for i in range(10):
            anomaly = det.observe_memory_write(a, when=float(i) * 0.5)
        self.assertIsNotNone(anomaly)
        assert anomaly is not None
        self.assertEqual(anomaly.kind, BehavioralAnomalyKind.ABNORMAL_MEMORY_PATTERN)

    def test_read_only_capability_cannot_write_memory(self) -> None:
        """T2: capability scoped to `memory.read` cannot authorise `memory.write`."""

        pa = PolicyAuthority()
        enforcer = Enforcer(trusted_pa_pubkeys=[pa.public_key])
        a = AgentID(b"\x01" * 32)
        b = AgentID(b"\x02" * 32)
        task = TaskID.random()
        # Issue a read-only memory cap.
        cap = pa.issue(subject=a, audience=b, task_id=task,
                       scopes=["memory.read"], constraints=Constraints())
        # Attempt a memory write under that cap.
        req = ActionRequest(subject=a, audience=b, task_id=task,
                            scope="memory.write")
        with self.assertRaises(CapabilityScopeError):
            enforcer.check(cap, req)

    def test_audit_tamper_detected(self) -> None:
        """T3: in-place edit of a memory-write audit record fails verify."""

        log = HashChainLog(AgentID(b"\x09" * 32))
        for i in range(5):
            log.append({"type": "memory.write",
                        "key": f"item-{i}",
                        "value_sha256": "abc" + str(i)})
        log.verify()  # clean log passes.

        # Adversary replaces the value of an old write to swap out the
        # known-good content for a poisoned reference.
        log._records[2].event["value_sha256"] = "POISONED"  # type: ignore[index]
        with self.assertRaises(AuditTamperingError):
            log.verify()


if __name__ == "__main__":
    unittest.main()
