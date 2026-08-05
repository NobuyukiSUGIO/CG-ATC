"""Adaptive-attack benchmark baselines.

Spec §2 enumerates 5 stronger baselines plus the 4 legacy ones that were
already shipped with CG-ATC.  All of them implement the
:class:`benchmarks.Receiver` Protocol and are constructed by name through
:func:`make_baseline`.
"""
from __future__ import annotations

from typing import Callable

from ..interfaces import Receiver
from ..materialize import Crew
from .anomaly_signed_logs import AnomalySignedLogsReceiver
from .capability_central_audit import CapabilityCentralAuditReceiver
from .cg_atc import CGATCReceiver
from .legacy import (
    AnomalyNoCryptoBenchReceiver,
    AuthOnlyBenchReceiver,
    CapNoAuditBenchReceiver,
    TLSOAuthBenchReceiver,
)
from .mtls_nonce import MTLSNonceReceiver
from .opa_rego import OPARegoReceiver
from .signed_jwt import SignedJWTReceiver

# (name) -> factory(crew) -> Receiver
_FACTORIES: dict[str, Callable[[Crew], Receiver]] = {
    "cg_atc": lambda crew: CGATCReceiver(crew=crew),
    "baseline_mtls_nonce": lambda crew: MTLSNonceReceiver(crew=crew),
    "baseline_signed_jwt": lambda crew: SignedJWTReceiver(crew=crew),
    "baseline_capability_central_audit": lambda crew: CapabilityCentralAuditReceiver(crew=crew),
    "baseline_anomaly_signed_logs": lambda crew: AnomalySignedLogsReceiver(crew=crew),
    "baseline_opa_rego": lambda crew: OPARegoReceiver(crew=crew),
    "auth_only": lambda crew: AuthOnlyBenchReceiver(crew=crew),
    "tls_oauth": lambda crew: TLSOAuthBenchReceiver(crew=crew),
    "cap_no_audit": lambda crew: CapNoAuditBenchReceiver(crew=crew),
    "anomaly_no_crypto": lambda crew: AnomalyNoCryptoBenchReceiver(crew=crew),
}


def make_baseline(name: str, *, crew: Crew) -> Receiver:
    """Construct a baseline receiver by spec name."""

    if name not in _FACTORIES:
        raise ValueError(f"unknown baseline: {name!r}; known={sorted(_FACTORIES)}")
    return _FACTORIES[name](crew)


def list_baselines() -> list[str]:
    return list(_FACTORIES.keys())


__all__ = [
    "AnomalyNoCryptoBenchReceiver",
    "AnomalySignedLogsReceiver",
    "AuthOnlyBenchReceiver",
    "CGATCReceiver",
    "CapNoAuditBenchReceiver",
    "CapabilityCentralAuditReceiver",
    "MTLSNonceReceiver",
    "OPARegoReceiver",
    "SignedJWTReceiver",
    "TLSOAuthBenchReceiver",
    "list_baselines",
    "make_baseline",
]
