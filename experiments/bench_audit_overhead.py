"""Audit overhead benchmark (paper §V).

Measures:
    * append latency to the per-agent hash chain
    * Merkle root construction cost vs. log size
    * Merkle proof size and verification cost
"""

from __future__ import annotations

import json
import os
import platform
import statistics
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from cgatc.audit import HashChainLog, build_proof, merkle_root, verify_proof
from cgatc.core.types import AgentID


def main() -> None:
    log = HashChainLog(AgentID(b"\x09" * 32))
    sizes = [10, 100, 1_000, 10_000]
    rows = []
    for n in sizes:
        # append timing
        t0 = time.perf_counter()
        for i in range(n - len(log)):
            log.append({"e": "x", "i": len(log)})
        append_total = time.perf_counter() - t0
        leaves = [r.event_bytes() for r in log.records()][:n]

        # root construction
        t0 = time.perf_counter()
        root = merkle_root(leaves)
        root_time = time.perf_counter() - t0

        # proof + verify on a random index
        idx = n // 2
        t0 = time.perf_counter()
        proof = build_proof(leaves, idx)
        proof_time = time.perf_counter() - t0

        t0 = time.perf_counter()
        ok = verify_proof(leaves[idx], proof, root)
        verify_time = time.perf_counter() - t0

        proof_bytes = sum(len(s) for s in proof.siblings)
        rows.append({
            "log_size": n,
            "avg_append_us": append_total / n * 1e6,
            "root_construction_ms": root_time * 1e3,
            "proof_build_us": proof_time * 1e6,
            "proof_verify_us": verify_time * 1e6,
            "proof_size_bytes": proof_bytes,
            "verify_ok": ok,
        })
        print(rows[-1])

    out_dir = Path(__file__).resolve().parents[1] / "results" / (
        datetime.now(timezone.utc).strftime("%Y%m%d") + "_audit_bench"
    )
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "audit_bench.json").write_text(json.dumps(rows, indent=2))
    (out_dir / "meta.json").write_text(json.dumps({
        "python": sys.version, "platform": platform.platform(),
        "argv": sys.argv, "cwd": os.getcwd(),
    }, indent=2))
    print(f"\nWrote results to {out_dir}")


if __name__ == "__main__":
    main()
