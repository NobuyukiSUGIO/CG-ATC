"""Capability enforcement gate (paper §III-E).

A receiver MUST gate every protected action through `Enforcer.check`.
Default is *deny* (CLAUDE.md §4.3 — design principle 4).
"""

from __future__ import annotations

import fnmatch
import time
from dataclasses import dataclass

from ..core.exceptions import (
    CapabilityAudienceError,
    CapabilityError,
    CapabilityExpiredError,
    CapabilityScopeError,
    SignatureVerificationError,
)
from ..core.types import AgentID, TaskID
from ..crypto.primitives import Verify
from .token import SignedCapability


@dataclass(frozen=True)
class ActionRequest:
    """Description of the action a subject is asking the receiver to perform."""

    subject: AgentID
    audience: AgentID  # MUST equal the receiver of the request
    task_id: TaskID
    scope: str  # e.g. "tools.search.read", "data.customer.read"
    estimated_output_size: int | None = None
    invokes_external_tool: str | None = None
    data_label: str | None = None
    is_delegation: bool = False


class Enforcer:
    """Stateless capability checker.

    The enforcer needs to know the trusted PA public key(s).  Capabilities
    signed by an unknown PA are rejected.
    """

    def __init__(self, trusted_pa_pubkeys: list[bytes]) -> None:
        if not trusted_pa_pubkeys:
            raise ValueError("Enforcer requires at least one trusted PA public key")
        self._trusted = list(trusted_pa_pubkeys)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def check(
        self,
        signed: SignedCapability,
        request: ActionRequest,
        *,
        now_ts: float | None = None,
    ) -> None:
        """Default-deny check.

        Raises a subclass of `CapabilityError` (or `SignatureVerificationError`)
        on the first failure.  Returning normally means the action is
        authorised.
        """

        cap = signed.capability
        ts = now_ts if now_ts is not None else time.time()

        # 1. signature must verify under a TRUSTED PA public key.
        if not any(Verify(cap.digest(), signed.signature, pk) for pk in self._trusted):
            raise SignatureVerificationError("invalid capability")

        # 2. expiry / not_before.
        if ts >= cap.expiry:
            raise CapabilityExpiredError("invalid capability")
        if ts < cap.not_before - 60:  # 60s clock skew tolerance
            raise CapabilityExpiredError("invalid capability")

        # 3. subject (presenter) and audience (resource owner) bindings.
        if cap.subject != request.subject:
            raise CapabilityAudienceError("invalid capability")
        if cap.audience != request.audience:
            raise CapabilityAudienceError("invalid capability")

        # 4. task binding.
        if cap.task_id != request.task_id:
            raise CapabilityScopeError("invalid capability")

        # 5. scope match — supports glob patterns ("tools.*").
        if not _scope_matches(request.scope, cap.scopes):
            raise CapabilityScopeError("invalid capability")

        # 6. constraints.
        c = cap.constraints
        if (
            request.estimated_output_size is not None
            and c.max_output_size is not None
            and request.estimated_output_size > c.max_output_size
        ):
            raise CapabilityScopeError("invalid capability")
        if (
            request.invokes_external_tool is not None
            and c.allowed_external_tools
            and request.invokes_external_tool not in c.allowed_external_tools
        ):
            raise CapabilityScopeError("invalid capability")
        if (
            request.data_label is not None
            and c.permitted_data_labels
            and request.data_label not in c.permitted_data_labels
        ):
            raise CapabilityScopeError("invalid capability")
        if request.is_delegation and not c.delegation_permitted:
            raise CapabilityScopeError("invalid capability")

    def is_allowed(self, signed: SignedCapability, request: ActionRequest) -> bool:
        try:
            self.check(signed, request)
            return True
        except CapabilityError:
            return False
        except SignatureVerificationError:
            return False


def _scope_matches(requested: str, allowed: list[str]) -> bool:
    """Glob-style match.  `tools.search.*` matches `tools.search.read`."""

    return any(fnmatch.fnmatchcase(requested, pat) for pat in allowed)
