"""CG-ATC integration with the A2A protocol and Strands Agents (paper §V-A)."""

from .asgi_middleware import CGATCMiddleware
from .headers import decode, encode
from .middleware import Middleware, VerificationResult
from .strands_bridge import CGATCAgent, wrap_strands_agent
from .workflow import HandshakeResult, Workflow

__all__ = [
    "CGATCAgent",
    "CGATCMiddleware",
    "HandshakeResult",
    "Middleware",
    "VerificationResult",
    "Workflow",
    "decode",
    "encode",
    "wrap_strands_agent",
]
