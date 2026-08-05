"""Crypto-overhead benchmark (paper §III-L).

Measures per-operation latency and throughput for:
    * Ed25519 sign / verify
    * SHA-256
    * full envelope build + sign + verify round-trip
    * full capability issue + verify

Output:
    results/<YYYYMMDD>_crypto_bench/meta.json
    results/<YYYYMMDD>_crypto_bench/crypto_bench.json
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

from cgatc.capability import PolicyAuthority
from cgatc.core.types import MessageType, SessionID, TaskID, AgentID
from cgatc.crypto.primitives import H, Sign, Verify, generate_keypair
from cgatc.messaging import build_envelope, sign_envelope, verify_envelope


def _bench(name: str, fn, n: int = 5000):  # type: ignore[no-untyped-def]
    samples: list[float] = []
    for _ in range(n):
        t0 = time.perf_counter()
        fn()
        samples.append(time.perf_counter() - t0)
    return {
        "op": name,
        "n": n,
        "mean_us": statistics.mean(samples) * 1e6,
        "median_us": statistics.median(samples) * 1e6,
        "p95_us": sorted(samples)[int(n * 0.95)] * 1e6,
        "throughput_per_s": n / sum(samples),
    }


def main() -> None:
    kp = generate_keypair()
    msg = b"x" * 256
    sig = Sign(msg, kp)

    a = AgentID(b"\x01" * 32)
    b = AgentID(b"\x02" * 32)
    pa = PolicyAuthority()
    task = TaskID.random()

    def env_round_trip() -> None:
        env = build_envelope(
            session_id=SessionID.random(), task_id=task, seq=0,
            sender_id=a, receiver_id=b,
            msg_type=MessageType.REQUEST, payload=msg,
        )
        signed = sign_envelope(env, kp)
        verify_envelope(signed, sender_pubkey=kp.public_key, payload=msg)

    def cap_issue_verify() -> None:
        c = pa.issue(subject=a, audience=b, task_id=task, scopes=["x"])
        Verify(c.capability.digest(), c.signature, c.issuer_pubkey)

    results = [
        _bench("sha256_256B", lambda: H(msg)),
        _bench("ed25519_sign_256B", lambda: Sign(msg, kp)),
        _bench("ed25519_verify_256B", lambda: Verify(msg, sig, kp.public_key)),
        _bench("envelope_build_sign_verify", env_round_trip, n=2000),
        _bench("capability_issue_verify", cap_issue_verify, n=2000),
    ]
    for r in results:
        print(f"{r['op']:32s} mean={r['mean_us']:8.1f}us  p95={r['p95_us']:8.1f}us  "
              f"thru={r['throughput_per_s']:8.0f}/s")

    # ---- message-size measurements (paper §III-L "message size") -----------
    sizes = _measure_message_sizes(kp, pa, a, b, task)
    print("\n[ message size, bytes ]")
    for k, v in sizes.items():
        print(f"  {k:40s} {v:6d}")

    # Combine into a single results record and persist.
    full = {"latency": results, "sizes_bytes": sizes}

    out_dir = Path(__file__).resolve().parents[1] / "results" / (
        datetime.now(timezone.utc).strftime("%Y%m%d") + "_crypto_bench"
    )
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "crypto_bench.json").write_text(json.dumps(full, indent=2))
    (out_dir / "meta.json").write_text(json.dumps({
        "python": sys.version, "platform": platform.platform(),
        "argv": sys.argv, "cwd": os.getcwd(),
    }, indent=2))
    print(f"\nWrote results to {out_dir}")


def _measure_message_sizes(kp, pa, a, b, task):  # type: ignore[no-untyped-def]
    """Measure the on-wire bytes added by CG-ATC over a 256-byte payload."""

    from cgatc.a2a_integration import encode
    from cgatc.core.types import MessageType, SessionID

    payload = b"x" * 256
    env = build_envelope(
        session_id=SessionID.random(), task_id=task, seq=0,
        sender_id=a, receiver_id=b,
        msg_type=MessageType.REQUEST, payload=payload,
    )
    signed_env = sign_envelope(env, kp)

    cap = pa.issue(subject=a, audience=b, task_id=task, scopes=["x"])

    headers = encode(
        sender_agent_id_hex=a.hex(),
        signed_envelope=signed_env,
        capability=cap,
    )
    headers_json = json.dumps(headers, separators=(",", ":")).encode()

    return {
        "payload_bytes": len(payload),
        "envelope_canonical_bytes": len(env.encode_canonical()),
        "signed_envelope_json_bytes": len(signed_env.to_json().encode()),
        "capability_canonical_bytes": len(cap.capability.encode_canonical()),
        "signed_capability_json_bytes": len(cap.to_json().encode()),
        "metadata_dict_json_bytes": len(headers_json),
        "overhead_bytes": len(headers_json) - len(payload),
    }


if __name__ == "__main__":
    main()
