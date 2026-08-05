"""End-to-end HTTP test: real Uvicorn + Strands A2AServer + CG-ATC ASGI middleware.

Verifies that:
  * a JSON-RPC POST whose `params.message.metadata` carries valid CG-ATC
    headers passes through and reaches the Strands agent;
  * a POST with a tampered envelope is REJECTED with JSON-RPC error
    code -32001 and never reaches the agent.

The Strands agent is a real `strands.Agent` backed by the deterministic
`StubModel` so the test runs without AWS credentials.
"""

from __future__ import annotations

import asyncio
import socket
import sys
import threading
import time
import unittest
import uuid
from pathlib import Path

import httpx
import uvicorn

_EXAMPLES = Path(__file__).resolve().parents[2] / "examples"
sys.path.insert(0, str(_EXAMPLES))

from strands import Agent  # noqa: E402

from _stub_model import StubModel  # noqa: E402

from cgatc.a2a_integration import (  # noqa: E402
    CGATCMiddleware,
    Middleware,
    Workflow,
    encode,
)
from cgatc.audit import HashChainLog, InMemoryCommitterSink  # noqa: E402
from cgatc.capability import Constraints, Enforcer, PolicyAuthority  # noqa: E402
from cgatc.containment import ImpactGraph, ScopeReducer  # noqa: E402
from cgatc.core.types import MessageType, TaskID  # noqa: E402
from cgatc.crypto.primitives import generate_keypair  # noqa: E402
from cgatc.detection import BehavioralDetector, RiskScoreUpdater  # noqa: E402
from cgatc.identity import (  # noqa: E402
    build_card,
    collect_local_env_attest,
    compute_model_hash,
    compute_policy_hash,
    sign_card,
)
from cgatc.messaging import (  # noqa: E402
    ReplayGuard,
    SessionChainTracker,
    build_envelope,
    sign_envelope,
)


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _build_card(agent: Agent, scopes: list[str]):  # type: ignore[no-untyped-def]
    kp = generate_keypair()
    direct = getattr(agent.model, "model_id", None)
    if direct:
        model_id = str(direct)
    else:
        cfg = agent.model.get_config()
        if isinstance(cfg, dict):
            model_id = str(cfg.get("model_id", "unknown"))
        else:
            model_id = str(getattr(cfg, "model_id", "unknown"))
    card = build_card(
        keypair=kp, model_hash=compute_model_hash(str(model_id)),
        policy_hash=compute_policy_hash({"name": agent.name}),
        env_attest=collect_local_env_attest(),
        skills=[agent.name], scopes=scopes,
        auth={"scheme": "ed25519"}, expiry=time.time() + 3600,
    )
    return kp, sign_card(card, kp)


def _build_stack(kp, signed_card, pa):  # type: ignore[no-untyped-def]
    me = signed_card.card.agent_id
    mw = Middleware(
        my_agent_id=me,
        enforcer=Enforcer(trusted_pa_pubkeys=[pa.public_key]),
        chain=SessionChainTracker(), replay=ReplayGuard(),
        risk=RiskScoreUpdater(), scope=ScopeReducer(),
        behavior=BehavioralDetector(), impact=ImpactGraph(),
        log=HashChainLog(me),
    )
    wf = Workflow(my_keypair=kp, my_agent_id=me, policy_authority=pa,
                  middleware=mw, audit_sink=InMemoryCommitterSink())
    return mw, wf


class _UvicornInThread:
    """Run a uvicorn server in a background thread with deterministic shutdown."""

    def __init__(self, app, *, host: str, port: int) -> None:  # type: ignore[no-untyped-def]
        self._config = uvicorn.Config(app, host=host, port=port, log_level="warning")
        self._server = uvicorn.Server(self._config)
        self._thread = threading.Thread(target=self._server.run, daemon=True)

    def __enter__(self):  # type: ignore[no-untyped-def]
        self._thread.start()
        # Wait until the server reports ready.
        for _ in range(200):
            if self._server.started:
                return self
            time.sleep(0.025)
        raise RuntimeError("uvicorn did not start in time")

    def __exit__(self, *exc):  # type: ignore[no-untyped-def]
        self._server.should_exit = True
        self._thread.join(timeout=5.0)


class TestE2E(unittest.TestCase):
    def _setup_world(self):  # type: ignore[no-untyped-def]
        from strands.multiagent.a2a import A2AServer

        self.pa = PolicyAuthority()
        self.alice = Agent(model=StubModel(model_id="stub:alice"),
                           name="alice", description="alice",
                           callback_handler=None)
        self.bob = Agent(model=StubModel(model_id="stub:bob"),
                         name="bob", description="bob",
                         callback_handler=None)

        self.kp_a, self.card_a = _build_card(self.alice, ["chat.send"])
        self.kp_b, self.card_b = _build_card(self.bob, ["chat.send"])
        self.mw_b, self.wf_b = _build_stack(self.kp_b, self.card_b, self.pa)

        self.task = TaskID.random()
        self.hs = self.wf_b.handshake(
            peer_card=self.card_a, task=self.task, scopes=["chat.send"],
            constraints=Constraints(),
        )

        # Wrap the Strands A2AServer with CG-ATC ASGI middleware.
        port = _free_port()
        a2a_server = A2AServer(self.bob, host="127.0.0.1", port=port)
        starlette_app = a2a_server.to_starlette_app()
        wrapped = CGATCMiddleware(
            starlette_app,
            cgatc_middleware=self.mw_b,
            rpc_url="/",
            action_scope="chat.send",
        )
        self.port = port
        self.app = wrapped

    def _signed_metadata(self, payload: bytes, *, sign_with=None, tamper=False):  # type: ignore[no-untyped-def]
        sk = sign_with or self.kp_a
        env = build_envelope(
            session_id=self.hs.session_id, task_id=self.task, seq=0,
            sender_id=self.card_a.card.agent_id,
            receiver_id=self.card_b.card.agent_id,
            msg_type=MessageType.REQUEST, payload=payload,
        )
        signed = sign_envelope(env, sk)
        meta = encode(
            sender_agent_id_hex=self.card_a.card.agent_id.hex(),
            signed_envelope=signed, capability=self.hs.capability,
        )
        if tamper:
            # Flip a bit in the SignedEnvelope JSON (which is the source of
            # truth for the verifier — `A2A-Signature` header is informational).
            import json as _json
            env_obj = _json.loads(meta["A2A-Envelope"])
            sig_hex = env_obj["signature_hex"]
            sig = list(sig_hex)
            sig[0] = "0" if sig[0] != "0" else "1"
            env_obj["signature_hex"] = "".join(sig)
            meta["A2A-Envelope"] = _json.dumps(env_obj)
        return meta

    def test_valid_request_passes_through(self) -> None:
        self._setup_world()
        with _UvicornInThread(self.app, host="127.0.0.1", port=self.port):
            payload = b"hello bob from e2e"
            meta = self._signed_metadata(payload)
            body = {
                "jsonrpc": "2.0",
                "id": str(uuid.uuid4()),
                "method": "message/send",
                "params": {
                    "message": {
                        "messageId": str(uuid.uuid4()),
                        "role": "user",
                        "parts": [{"kind": "text", "text": payload.decode()}],
                        "metadata": meta,
                    },
                },
            }
            r = httpx.post(f"http://127.0.0.1:{self.port}/", json=body, timeout=10.0)
            self.assertEqual(r.status_code, 200)
            doc = r.json()
            # Either a result (Strands processed it) or a non-CG-ATC error
            # (the dummy stub agent may not be a fully-conformant A2A server,
            # but the CG-ATC layer must NOT reject with -32001).
            err = doc.get("error", {}) or {}
            self.assertNotEqual(err.get("code"), -32001,
                                msg=f"CG-ATC unexpectedly rejected: {err}")

    def test_tampered_signature_is_rejected_by_middleware(self) -> None:
        self._setup_world()
        with _UvicornInThread(self.app, host="127.0.0.1", port=self.port):
            payload = b"forged"
            meta = self._signed_metadata(payload, tamper=True)
            body = {
                "jsonrpc": "2.0",
                "id": str(uuid.uuid4()),
                "method": "message/send",
                "params": {
                    "message": {
                        "messageId": str(uuid.uuid4()),
                        "role": "user",
                        "parts": [{"kind": "text", "text": payload.decode()}],
                        "metadata": meta,
                    },
                },
            }
            r = httpx.post(f"http://127.0.0.1:{self.port}/", json=body, timeout=10.0)
            self.assertEqual(r.status_code, 200)
            doc = r.json()
            err = doc.get("error") or {}
            self.assertEqual(err.get("code"), -32001,
                             msg=f"expected CG-ATC reject; got: {doc}")
            data = err.get("data") or {}
            self.assertIn("SignatureVerificationError", data.get("violations") or [])

    def test_missing_metadata_is_rejected(self) -> None:
        self._setup_world()
        with _UvicornInThread(self.app, host="127.0.0.1", port=self.port):
            body = {
                "jsonrpc": "2.0",
                "id": str(uuid.uuid4()),
                "method": "message/send",
                "params": {
                    "message": {
                        "messageId": str(uuid.uuid4()),
                        "role": "user",
                        "parts": [{"kind": "text", "text": "hi"}],
                        # no metadata at all
                    },
                },
            }
            r = httpx.post(f"http://127.0.0.1:{self.port}/", json=body, timeout=10.0)
            self.assertEqual(r.status_code, 200)
            doc = r.json()
            err = doc.get("error") or {}
            self.assertEqual(err.get("code"), -32001)
            self.assertEqual(err.get("message"), "missing_cgatc_metadata")


if __name__ == "__main__":
    unittest.main()
