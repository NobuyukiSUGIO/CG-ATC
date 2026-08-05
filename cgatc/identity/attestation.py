"""Execution-environment attestation (paper §III-C, EnvAttest_i).

In production the `envHash` should come from a real measurement source
(TPM PCRs, AMD SEV-SNP attestation, AWS Nitro Enclave attestation, etc.).
For research and CI we provide:

  * `compute_env_hash(...)`: a deterministic hash over container/process
    identity material (image digest, command line, env vars subset).
  * `EnvAttest`: a self-describing attestation envelope that can be
    swapped for a real verifier later.

The `verify_env_attest()` function returns `True` when the supplied
attestation matches the agent's declared `envHash`.  Real platform
verifiers can be plugged in by registering additional verifiers via
`register_verifier()`.
"""

from __future__ import annotations

import json
import os
import platform
import sys
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass, field
from typing import Any

from ..core.exceptions import EnvironmentAttestationError
from ..crypto.primitives import H


@dataclass(frozen=True)
class EnvAttest:
    """A platform-attestation envelope.

    `kind` selects the verifier ("local", "tpm", "sev-snp", ...).  `claims`
    carries a structured set of measurements; `evidence` holds opaque bytes
    that the platform-specific verifier can check.
    """

    kind: str
    claims: dict[str, Any] = field(default_factory=dict)
    evidence: bytes = b""

    def to_canonical_bytes(self) -> bytes:
        """Canonical JSON encoding used as input to `compute_env_hash`."""

        payload = {
            "kind": self.kind,
            "claims": self.claims,
            "evidence_hex": self.evidence.hex(),
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


# ---------------------------------------------------------------------------
# Verifier registry
# ---------------------------------------------------------------------------
Verifier = Callable[[EnvAttest, bytes], bool]
_VERIFIERS: dict[str, Verifier] = {}


def register_verifier(kind: str, fn: Verifier) -> None:
    """Register a platform-specific attestation verifier."""

    _VERIFIERS[kind] = fn


def _verify_local(att: EnvAttest, expected_env_hash: bytes) -> bool:
    """Local 'self-asserted' verifier — only safe in trusted dev/test setups."""

    return compute_env_hash(att) == expected_env_hash


register_verifier("local", _verify_local)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def compute_env_hash(att: EnvAttest) -> bytes:
    """envHash = H(canonical(EnvAttest))  (paper §III-C)."""

    return H(att.to_canonical_bytes())


def collect_local_env_attest(*, image_digest: str | None = None) -> EnvAttest:
    """Build a minimal `EnvAttest` from the current Python process.

    Useful for local examples / tests.  In production, replace this with a
    call to a TEE attestation library.
    """

    claims: dict[str, Any] = {
        "python": sys.version,
        "platform": platform.platform(),
        "image_digest": image_digest or "",
        "argv0": os.path.basename(sys.argv[0]) if sys.argv else "",
    }
    return EnvAttest(kind="local", claims=claims, evidence=b"")


def verify_env_attest(att: EnvAttest, expected_env_hash: bytes) -> None:
    """Raise `EnvironmentAttestationError` if attestation cannot be verified."""

    verifier = _VERIFIERS.get(att.kind)
    if verifier is None:
        raise EnvironmentAttestationError(f"no verifier registered for kind={att.kind!r}")
    if not verifier(att, expected_env_hash):
        # Avoid leaking *which* claim mismatched (CLAUDE.md §4.5).
        raise EnvironmentAttestationError("environment attestation failed")


def attestation_to_dict(att: EnvAttest) -> Mapping[str, Any]:
    return asdict(att) | {"evidence": att.evidence.hex()}
