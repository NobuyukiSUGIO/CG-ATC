"""End-to-end Bedrock + CG-ATC over HTTP / JSON-RPC.

Architecture:

    [Alice's Bedrock LLM] --> [Alice signs CG-ATC envelope] --> HTTP POST
        --> [Uvicorn] --> [CGATCMiddleware verifies] --> [Strands A2AServer]
        --> [Bob's Bedrock LLM] --> response (printed by Alice client side)

Bob is the *server*: a real `strands.Agent` (Bedrock-backed) wrapped by
`A2AServer`, with `CGATCMiddleware` injected as the ASGI middleware.
Alice is the *client*: she builds CG-ATC headers locally, posts JSON-RPC
to Bob's HTTP endpoint, and prints what comes back.

Run (after `aws sso login` etc.):
    PYTHONPATH=. python examples/with_bedrock/two_agent_bedrock_http.py
"""

from __future__ import annotations

import asyncio
import os
import socket
import sys
import threading
import time
import uuid
from pathlib import Path

# Make `cgatc` importable.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import httpx
import uvicorn
from strands import Agent
from strands.models.bedrock import BedrockModel
from strands.multiagent.a2a import A2AServer

from cgatc.a2a_integration import (
    CGATCMiddleware,
    Middleware,
    Workflow,
    encode,
)
from cgatc.audit import HashChainLog, InMemoryCommitterSink
from cgatc.capability import Constraints, Enforcer, PolicyAuthority
from cgatc.containment import ImpactGraph, ScopeReducer
from cgatc.core.types import MessageType, TaskID
from cgatc.crypto.primitives import generate_keypair
from cgatc.detection import BehavioralDetector, RiskScoreUpdater
from cgatc.identity import (
    build_card,
    collect_local_env_attest,
    compute_model_hash,
    compute_policy_hash,
    sign_card,
)
from cgatc.messaging import (
    ReplayGuard,
    SessionChainTracker,
    build_envelope,
    sign_envelope,
)


DEFAULT_MODEL = os.environ.get(
    "CGATC_BEDROCK_MODEL",
    "global.amazon.nova-2-lite-v1:0",
)
ALICE_PROMPT = os.environ.get(
    "CGATC_ALICE_PROMPT",
    "Ask Bob the following question, and only the question, "
    "in one short sentence: 'What is the capital of Japan?'",
)
BOB_TASK = os.environ.get(
    "CGATC_BOB_TASK",
    "You are a concise assistant.  Answer the question you receive "
    "in one short sentence.  Do not ask any clarifying questions.",
)


def _model_id_of(agent: Agent) -> str:
    direct = getattr(agent.model, "model_id", None)
    if direct:
        return str(direct)
    cfg = agent.model.get_config()
    if isinstance(cfg, dict):
        return str(cfg.get("model_id", "unknown"))
    return str(getattr(cfg, "model_id", "unknown"))


def _make_card(agent: Agent, scopes: list[str]):  # type: ignore[no-untyped-def]
    kp = generate_keypair()
    card = build_card(
        keypair=kp,
        model_hash=compute_model_hash(_model_id_of(agent)),
        policy_hash=compute_policy_hash(
            {"name": agent.name, "scopes": scopes}
        ),
        env_attest=collect_local_env_attest(image_digest=DEFAULT_MODEL),
        skills=[agent.name], scopes=scopes,
        auth={"scheme": "ed25519"},
        expiry=time.time() + 3600,
    )
    return kp, sign_card(card, kp)


def _make_stack(kp, signed_card, pa):  # type: ignore[no-untyped-def]
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


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class _UvicornInThread:
    def __init__(self, app, *, host: str, port: int) -> None:  # type: ignore[no-untyped-def]
        cfg = uvicorn.Config(app, host=host, port=port, log_level="warning")
        self._server = uvicorn.Server(cfg)
        self._t = threading.Thread(target=self._server.run, daemon=True)

    def __enter__(self):  # type: ignore[no-untyped-def]
        self._t.start()
        for _ in range(200):
            if self._server.started:
                return self
            time.sleep(0.025)
        raise RuntimeError("uvicorn did not start in time")

    def __exit__(self, *exc):  # type: ignore[no-untyped-def]
        self._server.should_exit = True
        self._t.join(timeout=5.0)


async def main() -> None:
    print("=" * 72)
    print("CG-ATC Bedrock + HTTP/JSON-RPC end-to-end demo")
    print(f"  model = {DEFAULT_MODEL}")
    print("=" * 72)

    pa = PolicyAuthority(issuer_id="PA")

    # ---- Bob (server) -----------------------------------------------------
    bob = Agent(
        model=BedrockModel(model_id=DEFAULT_MODEL),
        name="bob",
        description="bob (Bedrock)",
        system_prompt=BOB_TASK,
        callback_handler=None,
    )
    kp_b, card_b = _make_card(bob, ["chat.send"])
    mw_b, wf_b = _make_stack(kp_b, card_b, pa)

    # ---- Alice (client) ---------------------------------------------------
    alice = Agent(
        model=BedrockModel(model_id=DEFAULT_MODEL),
        name="alice",
        description="alice (Bedrock)",
        system_prompt="You are Alice. Be brief.",
        callback_handler=None,
    )
    kp_a, card_a = _make_card(alice, ["chat.send"])
    mw_a, wf_a = _make_stack(kp_a, card_a, pa)
    print(f"  alice_id = {card_a.card.agent_id.hex()[:24]}…")
    print(f"  bob_id   = {card_b.card.agent_id.hex()[:24]}…")

    # ---- Bob's CG-ATC handshake (server side issues capability for Alice)-
    task = TaskID.random()
    hs = wf_b.handshake(
        peer_card=card_a, task=task, scopes=["chat.send"],
        constraints=Constraints(max_output_size=4096),
    )

    # ---- Build Bob's HTTP server with CG-ATC ASGI middleware --------------
    port = _free_port()
    a2a = A2AServer(bob, host="127.0.0.1", port=port)
    asgi_app = CGATCMiddleware(
        a2a.to_starlette_app(),
        cgatc_middleware=mw_b,
        rpc_url="/",
        action_scope="chat.send",
    )

    with _UvicornInThread(asgi_app, host="127.0.0.1", port=port):
        print(f"  bob HTTP listening on http://127.0.0.1:{port}/")

        # ---- Alice generates a question via Bedrock -----------------------
        t0 = time.perf_counter()
        ar = await alice.invoke_async(ALICE_PROMPT)
        question = ar.message["content"][0]["text"]  # type: ignore[index]
        print(f"\n[Alice → Bedrock] ({time.perf_counter()-t0:.2f}s) {question!r}")

        # ---- Alice signs the question into a CG-ATC envelope --------------
        payload = question.encode()
        env = build_envelope(
            session_id=hs.session_id, task_id=task, seq=0,
            sender_id=card_a.card.agent_id, receiver_id=card_b.card.agent_id,
            msg_type=MessageType.REQUEST, payload=payload,
        )
        signed = sign_envelope(env, kp_a)
        meta = encode(
            sender_agent_id_hex=card_a.card.agent_id.hex(),
            signed_envelope=signed,
            capability=hs.capability,
            sender_middleware=mw_a,  # auto-populates Log-Root + Risk-Level
        )
        print(f"[Alice → wire]    headers: {sorted(meta)}")

        # ---- Alice posts JSON-RPC over HTTP -------------------------------
        body = {
            "jsonrpc": "2.0",
            "id": str(uuid.uuid4()),
            "method": "message/send",
            "params": {
                "message": {
                    "messageId": str(uuid.uuid4()),
                    "role": "user",
                    "parts": [{"kind": "text", "text": question}],
                    "metadata": meta,
                },
            },
        }
        t0 = time.perf_counter()
        with httpx.Client(timeout=60.0) as client:
            r = client.post(f"http://127.0.0.1:{port}/", json=body)
        print(f"[HTTP   ← Bob]    status={r.status_code}  "
              f"({time.perf_counter()-t0:.2f}s)")

        doc = r.json()
        if "error" in doc:
            err = doc["error"]
            if err.get("code") == -32001:
                raise SystemExit(f"CG-ATC rejected: {err}")
            else:
                raise SystemExit(f"JSON-RPC error: {err}")

        # ---- Pull Bob's reply text out of the JSON-RPC result -------------
        reply_text = ""
        result = doc.get("result", {})
        for art in result.get("artifacts") or []:
            for part in art.get("parts") or []:
                if part.get("kind") == "text":
                    reply_text += part.get("text", "")
        print(f"[Alice ← reply]   {reply_text.strip()!r}")

    # ---- Audit roots ------------------------------------------------------
    cb = wf_b.commit_audit()
    print(f"\n[ audit ] Bob   root={cb.root.hex()[:16]}…  events={cb.seq_count}")
    mw_b.log.verify()
    print("\nDONE — Bob's audit log verified.\n")


if __name__ == "__main__":
    asyncio.run(main())
