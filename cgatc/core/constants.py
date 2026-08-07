"""Numerical / protocol constants for CG-ATC.

Threshold and weight names follow the symbols used in the paper
(Sugio 2026, §III-G, §III-H).
"""

from __future__ import annotations

from typing import Final

# --- hash / signature output sizes -----------------------------------------
HASH_SIZE: Final[int] = 32  # SHA-256 output, octets
ED25519_PUBKEY_SIZE: Final[int] = 32
ED25519_PRIVKEY_SIZE: Final[int] = 32
ED25519_SIG_SIZE: Final[int] = 64

# --- envelope / chain ------------------------------------------------------
DEFAULT_FRESHNESS_WINDOW_SECONDS: Final[int] = 300  # ±5 minutes
GENESIS_PREV_HASH: Final[bytes] = b"\x00" * HASH_SIZE

# --- risk-score weights (§III-G, default values) ---------------------------
DEFAULT_LAMBDA: Final[float] = 0.9   # decay
DEFAULT_ALPHA: Final[float] = 1.0    # cryptographic violation
DEFAULT_BETA: Final[float] = 0.5     # behavioral anomaly
DEFAULT_GAMMA: Final[float] = 0.7    # policy violation
DEFAULT_DELTA: Final[float] = 0.3    # downstream damage

# --- containment thresholds (§III-H) ---------------------------------------
TAU_1: Final[float] = 1.0   # begin scope reduction
TAU_2: Final[float] = 2.5   # restrict outputs / disable high-risk tools
TAU_3: Final[float] = 5.0   # prohibit delegation, switch to read-only
TAU_4: Final[float] = 10.0  # isolate / revoke

# --- impact radius (§III-H) ---------------------------------------------
DEFAULT_MAX_RADIUS: Final[int] = 3
SUSPICIOUS_MAX_RADIUS: Final[int] = 1
ISOLATED_MAX_RADIUS: Final[int] = 0

# --- capability defaults (§III-E) -----------------------------------------
DEFAULT_CAPABILITY_TTL_SECONDS: Final[int] = 600  # 10 min, "short-lived"

# --- A2A metadata header names (§V-A) -----------------------------------
HDR_AGENT_ID: Final[str] = "A2A-Agent-ID"
HDR_SIGNATURE: Final[str] = "A2A-Signature"
HDR_CAPABILITY_TOKEN: Final[str] = "A2A-Capability-Token"
HDR_PREV_HASH: Final[str] = "A2A-Prev-Hash"
HDR_LOG_ROOT: Final[str] = "A2A-Log-Root"
HDR_RISK_LEVEL: Final[str] = "A2A-Risk-Level"
HDR_ENVELOPE: Final[str] = "A2A-Envelope"
