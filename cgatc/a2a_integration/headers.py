"""A2A metadata-header encoding for CG-ATC (paper §V-A).

The paper proposes the following A2A metadata fields:

    A2A-Agent-ID, A2A-Signature, A2A-Capability-Token,
    A2A-Prev-Hash, A2A-Log-Root, A2A-Risk-Level.

`a2a_sdk.Message` exposes a free-form `metadata: dict[str, Any]` slot
that downstream extensions may use.  We encode every CG-ATC field
*inside that dict* using the canonical header names above; this keeps
us strictly compatible with the A2A SDK and with the Strands `A2AAgent`
wrapper.
"""

from __future__ import annotations

from typing import Any

from ..core.constants import (
    HDR_AGENT_ID,
    HDR_CAPABILITY_TOKEN,
    HDR_ENVELOPE,
    HDR_LOG_ROOT,
    HDR_PREV_HASH,
    HDR_RISK_LEVEL,
    HDR_SIGNATURE,
)
from ..capability.token import SignedCapability
from ..messaging.envelope import SignedEnvelope

if False:  # type-only, avoids circular import at runtime
    from .middleware import Middleware  # noqa: F401


def encode(
    *,
    sender_agent_id_hex: str,
    signed_envelope: SignedEnvelope,
    capability: SignedCapability | None = None,
    log_root_hex: str | None = None,
    risk_level: str | None = None,
    sender_middleware: "Middleware | None" = None,
) -> dict[str, Any]:
    """Build the metadata dict that should be merged into `Message.metadata`.

    If `sender_middleware` is supplied, the optional `A2A-Log-Root` and
    `A2A-Risk-Level` headers are auto-populated from the sender's
    current audit-log head and self-perceived containment level
    (paper §V-A).  Explicit `log_root_hex` / `risk_level` override
    the auto-derived values.
    """

    md: dict[str, Any] = {
        HDR_AGENT_ID: sender_agent_id_hex,
        HDR_SIGNATURE: signed_envelope.signature_hex,
        HDR_PREV_HASH: signed_envelope.envelope.prev_hash_hex,
        HDR_ENVELOPE: signed_envelope.to_json(),
    }
    if capability is not None:
        md[HDR_CAPABILITY_TOKEN] = capability.to_json()

    # Auto-populate Log-Root and Risk-Level from sender state if available.
    if log_root_hex is None and sender_middleware is not None:
        log_root_hex = sender_middleware.log.head.hex()
    if risk_level is None and sender_middleware is not None:
        # Sender's self-perceived containment (always NORMAL for honest
        # senders; informational for downstream verifiers).
        risk_level = sender_middleware.scope.current(sender_middleware.me).name

    if log_root_hex is not None:
        md[HDR_LOG_ROOT] = log_root_hex
    if risk_level is not None:
        md[HDR_RISK_LEVEL] = risk_level
    return md


def decode(metadata: dict[str, Any]) -> dict[str, Any]:
    """Parse a CG-ATC-bearing A2A metadata dict back into typed objects.

    Returns a dict with keys:

        sender_agent_id_hex : str
        signed_envelope     : SignedEnvelope
        capability          : SignedCapability | None
        log_root            : bytes | None
        risk_level          : str | None
    """

    if HDR_ENVELOPE not in metadata:
        raise KeyError(f"missing required CG-ATC header: {HDR_ENVELOPE}")

    out: dict[str, Any] = {
        "sender_agent_id_hex": str(metadata.get(HDR_AGENT_ID, "")),
        "signed_envelope": SignedEnvelope.from_json(str(metadata[HDR_ENVELOPE])),
    }
    cap_raw = metadata.get(HDR_CAPABILITY_TOKEN)
    out["capability"] = SignedCapability.from_json(str(cap_raw)) if cap_raw else None
    log_root_hex = metadata.get(HDR_LOG_ROOT)
    out["log_root"] = bytes.fromhex(str(log_root_hex)) if log_root_hex else None
    out["risk_level"] = str(metadata[HDR_RISK_LEVEL]) if HDR_RISK_LEVEL in metadata else None
    return out
