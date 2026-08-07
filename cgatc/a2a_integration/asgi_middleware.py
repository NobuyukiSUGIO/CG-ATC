"""ASGI middleware that runs CG-ATC verification on inbound A2A requests.

This realises the runtime side of paper §V-A: the CG-ATC layer sits
*between* the network and the Strands `A2AServer`, intercepting every
JSON-RPC POST, parsing the embedded A2A `Message`, decoding the
CG-ATC fields from its `metadata` dict, and running the full
verification pipeline (`Middleware.handle_inbound`).

On rejection, a JSON-RPC error response is returned with HTTP 200
(per the JSON-RPC spec) and `error.code = -32001` (custom CG-ATC
rejection); the underlying agent never sees the message.

The middleware does **not** verify GET requests to the well-known
Agent Card endpoint, since that is itself the discovery mechanism for
peer Cards.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Awaitable, Callable, MutableMapping

from .headers import decode
from .middleware import Middleware

ASGIApp = Callable[
    [MutableMapping[str, Any], Callable[[], Awaitable[MutableMapping[str, Any]]],
     Callable[[MutableMapping[str, Any]], Awaitable[None]]],
    Awaitable[None],
]

logger = logging.getLogger(__name__)


class CGATCMiddleware:
    """Pure-ASGI middleware (works under Starlette / FastAPI / Uvicorn)."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        cgatc_middleware: Middleware,
        rpc_url: str = "/",
        action_scope: str = "chat.send",
    ) -> None:
        self.app = app
        self.cg = cgatc_middleware
        self.rpc_url = rpc_url
        self.action_scope = action_scope

    async def __call__(
        self,
        scope: MutableMapping[str, Any],
        receive: Callable[[], Awaitable[MutableMapping[str, Any]]],
        send: Callable[[MutableMapping[str, Any]], Awaitable[None]],
    ) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        # Only intercept JSON-RPC POSTs at the configured rpc_url.
        method = scope.get("method", "GET")
        path = scope.get("path", "/")
        if method != "POST" or path != self.rpc_url:
            await self.app(scope, receive, send)
            return

        body = await _read_body(receive)
        try:
            doc = json.loads(body)
        except Exception:
            await self.app(scope, _replay_body(body), send)
            return

        rpc_id = doc.get("id")
        message = (doc.get("params") or {}).get("message") or {}
        metadata = message.get("metadata") or {}

        if not metadata:
            await _reject(send, rpc_id, "missing_cgatc_metadata")
            return

        try:
            decoded = decode(metadata)
        except KeyError as exc:
            await _reject(send, rpc_id, f"missing_header:{exc.args[0]}")
            return
        except Exception as exc:
            await _reject(send, rpc_id, f"decode_failed:{type(exc).__name__}")
            return

        # Reconstruct the payload bytes from the JSON-RPC parts list.
        payload = _payload_from_message(message)

        result = self.cg.handle_inbound(
            decoded["signed_envelope"],
            payload=payload,
            capability=decoded["capability"],
            action_scope=self.action_scope,
        )
        if not result.accepted:
            await _reject(
                send, rpc_id,
                "cgatc_rejected",
                violations=list(result.violations),
                risk=result.risk,
                containment=result.containment.name,
            )
            return

        # Verified — pass through to the agent.  Replay the buffered body.
        await self.app(scope, _replay_body(body), send)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
async def _read_body(receive: Callable[[], Awaitable[MutableMapping[str, Any]]]) -> bytes:
    """Drain the ASGI receive stream into a single bytes blob."""

    chunks: list[bytes] = []
    while True:
        evt = await receive()
        if evt.get("type") != "http.request":
            continue
        chunks.append(bytes(evt.get("body") or b""))
        if not evt.get("more_body"):
            break
    return b"".join(chunks)


def _replay_body(body: bytes) -> Callable[[], Awaitable[MutableMapping[str, Any]]]:
    sent = False

    async def _recv() -> MutableMapping[str, Any]:
        nonlocal sent
        if sent:
            return {"type": "http.disconnect"}
        sent = True
        return {"type": "http.request", "body": body, "more_body": False}

    return _recv


def _payload_from_message(message: dict[str, Any]) -> bytes:
    """Re-derive the byte payload that was hashed into the envelope.

    The sender hashes `payload` (not the full Message tuple) and stores
    `H(payload)` in the envelope.  By convention we treat the
    concatenation of all text parts as the payload.  Senders that wish
    to bind structured payloads should serialise them and put them in a
    single text part, OR include the canonical bytes in the metadata
    under a documented key.
    """

    if "A2A-Payload-Hex" in (message.get("metadata") or {}):
        return bytes.fromhex(str(message["metadata"]["A2A-Payload-Hex"]))
    parts = message.get("parts") or []
    chunks: list[bytes] = []
    for p in parts:
        if isinstance(p, dict):
            text = p.get("text")
            if text is not None:
                chunks.append(str(text).encode())
    return b"".join(chunks)


async def _reject(
    send: Callable[[MutableMapping[str, Any]], Awaitable[None]],
    rpc_id: Any,
    reason: str,
    *,
    violations: list[str] | None = None,
    risk: float | None = None,
    containment: str | None = None,
) -> None:
    """Emit a JSON-RPC error response (HTTP 200, error.code=-32001)."""

    body = {
        "jsonrpc": "2.0",
        "id": rpc_id,
        "error": {
            "code": -32001,
            "message": reason,
            "data": {
                "violations": violations or [],
                "risk": risk,
                "containment": containment,
            },
        },
    }
    raw = json.dumps(body).encode()
    await send({
        "type": "http.response.start",
        "status": 200,
        "headers": [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(raw)).encode()),
        ],
    })
    await send({"type": "http.response.body", "body": raw, "more_body": False})
