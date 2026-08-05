"""Audit tampering experiment (spec §2.3 "Additional evaluation").

For ``baseline_capability_central_audit`` an attacker who compromises the
audit server can ``delete``/``modify``/``reorder``/``insert fake`` events
without trace.  CG-ATC's per-agent hash chain detects all four.

This script runs both side-by-side and writes a CSV summarising
"detected vs. undetected" per tamper kind.

Usage::

    python benchmarks/audit_tampering_experiment.py \\
      --output results/adaptive/audit_tampering.csv
"""
from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cgatc.audit import HashChainLog
from cgatc.core.exceptions import AuditTamperingError
from cgatc.core.types import AgentID

from benchmarks.baselines.capability_central_audit import CentralAuditServer


def _seed_central(srv: CentralAuditServer) -> list[str]:
    ids = []
    for i in range(8):
        ids.append(srv.append({
            "timestamp": 1700000000 + i, "sender_id": "A", "receiver_id": "B",
            "task_id": f"t{i}", "action": "read",
            "capability_id": f"cap{i}", "payload_hash": f"ph{i}",
        }))
    return ids


def _seed_cgatc() -> HashChainLog:
    log = HashChainLog(AgentID(b"\x01" * 32))
    for i in range(8):
        log.append({"type": "inbound.accepted", "i": i})
    return log


def central_detects(kind: str) -> bool:
    """The centralised audit server has no detection — always returns False."""

    srv = CentralAuditServer()
    ids = _seed_central(srv)
    if kind == "delete":
        srv.delete(ids[3])
    elif kind == "modify":
        srv.modify(ids[3], {"action": "write"})
    elif kind == "reorder":
        srv.events[3], srv.events[5] = srv.events[5], srv.events[3]
    elif kind == "insert_fake":
        srv.insert_fake(ids[3], {
            "timestamp": 1700000003, "sender_id": "X", "receiver_id": "B",
            "task_id": "tF", "action": "fake", "capability_id": "capF",
            "payload_hash": "phF",
        })
    return False  # central audit cannot detect post-hoc tampering


def cgatc_detects(kind: str) -> bool:
    """CG-ATC's local hash chain detects every kind of tampering.

    We mutate the in-memory `_records` list (a private attribute) and
    re-run :meth:`HashChainLog.verify`.  In production these mutations
    would correspond to an attacker editing the on-disk store; either
    way, ``verify`` raises :class:`AuditTamperingError`.
    """

    log = _seed_cgatc()
    records = log._records  # type: ignore[attr-defined]

    if kind == "delete":
        records.pop(3)
    elif kind == "modify":
        rec = records[3]
        records[3] = type(rec)(
            seq=rec.seq, timestamp=rec.timestamp,
            event={"type": "tampered", "i": 999},
            envelope_bytes=rec.envelope_bytes,
            signature_bytes=rec.signature_bytes,
            chain_state=rec.chain_state,
        )
    elif kind == "reorder":
        records[3], records[5] = records[5], records[3]
    elif kind == "insert_fake":
        rec = records[3]
        fake = type(rec)(
            seq=rec.seq, timestamp=rec.timestamp,
            event={"type": "fake.inserted"},
            envelope_bytes=b"", signature_bytes=b"",
            chain_state=rec.chain_state,
        )
        records.insert(3, fake)

    try:
        log.verify()
    except AuditTamperingError:
        return True
    return False


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--output", required=True, type=Path)
    args = p.parse_args(argv)

    rows: list[tuple[str, bool, bool]] = []
    for kind in ("delete", "modify", "reorder", "insert_fake"):
        rows.append((kind, cgatc_detects(kind), central_detects(kind)))

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["TamperKind", "CGATCDetects", "CentralAuditDetects"])
        for kind, cg, central in rows:
            w.writerow([kind, "yes" if cg else "no", "yes" if central else "no"])

    for kind, cg, central in rows:
        print(f"  {kind:12s}  CG-ATC={cg}  CentralAudit={central}")
    print(f"\nWrote {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
