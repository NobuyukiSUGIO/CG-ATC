# CLAUDE.md

This file documents **how the CG-ATC reference implementation in this repository is
built**: how the paper maps onto the code, which conventions the code follows, and
how the claims of the paper are exercised by the test suite.

It describes the code as it stands. Where the implementation deliberately departs
from, or falls short of, what the paper specifies, that is stated here explicitly
rather than written as an aspiration; the detailed interpretation gaps are recorded
in [`docs/open_questions.md`](docs/open_questions.md).

The conventions in §4 are also the rules new contributions are expected to follow.

---

## 1. Project overview

### 1.1 Purpose

This project is the reference implementation of the **CG-ATC** scheme proposed in
**"Cryptographically Grounded Agent Trust and Containment for A2A Multi-Agent
Systems" (Sugio, 2026)**.

CG-ATC (Cryptographically Grounded Agent Trust and Containment) is a zero-trust
security mechanism for LLM-based multi-agent systems running over the
Agent-to-Agent (A2A) protocol.

The implementation is a **research artifact**, not a hardened product. It is built
on the real A2A protocol (`a2a-sdk`), the real Strands agent runtime
(`strands-agents`), and established cryptographic libraries (`cryptography`,
`hashlib`) rather than on mocks — but two primitives are stand-ins for what the
paper assumes (threshold signatures and the VRF; see §4.2 and
`docs/open_questions.md` Q3/Q4), and key management is in-process rather than
KMS/HSM-backed. Treat it as an artifact that reproduces the paper's evaluation,
not as deployable infrastructure.

### 1.2 Central claim (paper §IV)

> CG-ATC does not claim to always prevent malicious agents. Rather, under standard
> cryptographic assumptions it guarantees that impersonation, message tampering,
> unauthorized delegation, and audit falsification are **detectable**, and that the
> damage caused by a compromised agent is **bounded by the scope of the issued
> capabilities and by the impact radius**.

The implementation must always embody this claim in a verifiable form. Do not write
code that merely "looks like it works"; write code for which the **safety games
defined by the game-based formalism of paper §III-I (Games 1-4) hold as the
corresponding Theorems 1-4**.

### 1.3 Assumed threat model (paper §III-A, §III-I)

- Agent set `A = {A_1, ..., A_n}`; the adversary `E` can compromise at most `f`
  agents (`C ⊆ A, |C| ≤ f`).
- The adversary `E` is probabilistic polynomial time (PPT) and can schedule, delay,
  drop, replay, and modify messages on the network.
- However, it cannot break standard cryptographic assumptions (EUF-CMA, AE, hash
  collision resistance, VRF pseudorandomness/verifiability, threshold-signature
  unforgeability); success probability is negligible in the security parameter `λ`.
- Assumed attack vectors (enumerated in §III-A): impersonation, tampering/replay of
  A2A messages, Agent Card forgery, privilege escalation, malicious prompt
  propagation, collusion, shared-memory poisoning, audit-trail tampering, and
  cascading failure via delegated tasks.
- **Cryptography cannot guarantee the semantic truthfulness of outputs.** CG-ATC is
  a combination of cryptographic verification + behavioral detection + policy
  containment.

---

## 2. Mapping between paper sections and implementation modules

The paper has the structure below, and each subsection maps 1:1 to a module as a
rule. When writing code, state the corresponding paper section and **equation
number** explicitly in the docstring.

### 2.1 §III Proposed Scheme — components

| Paper section | Equations | Module | Main responsibility |
|---|---|---|---|
| §III-A System and Threat Model | (1) | `cgatc/core/types.py` | Agent set, task, session, adversary-model type definitions |
| §III-B Design Principles (7 principles) | — | project-wide | Reflected in all code as design-time invariants |
| §III-C Cryptographic Agent Identity & Verifiable Agent Card | (2)-(5) | `cgatc/identity/` | Key pair `(sk_i, pk_i)`, `ID_i`, `Card_i`, signature `σ_i` |
| §III-D Signed A2A Message Format | (6)-(8) | `cgatc/messaging/envelope.py` | Message `m`, signature `σ`, verification `Verify_{pk_i}(H(m), σ) = 1` |
| §III-E Capability Token | (9)-(10) | `cgatc/capability/` | `cap_{i,j,t}`, Policy Authority signature `σ_PA` |
| §III-F Tamper-Evident Audit Log | (11)-(13) | `cgatc/audit/` | `L_i^t`, Merkle root `root_i^t`, signature `Σ_i^t` |
| §III-G-1 Cryptographic Detection | — | `cgatc/detection/crypto_detector.py` | 10 objective verification-failure conditions |
| §III-G-2 Behavioral & Semantic Detection | (14) | `cgatc/detection/behavioral_detector.py` | Risk score `R_i^{t+1} = λ R_i^t + α C + β B + γ P + δ D` |
| §III-H-1 Dynamic Capability Reduction | (15) | `cgatc/containment/scope_reducer.py` | 7-stage graduated containment |
| §III-H-2 Impact Radius Control | (16) | `cgatc/containment/impact_radius.py` | `Impact(A_i, t)`, maximum propagation radius `r` |
| §III-H-3 Threshold Signatures for High-Risk Actions | (17)-(18) | `cgatc/containment/threshold_authz.py` | k-of-n threshold signatures, VRF committee selection |
| §III-K Novelty and Advantages | — | (referenced as design guidance) | Design decisions such as treating the Agent Card as a capability certificate |

### 2.2 §III-I Security Properties — game-based formalization and theorems

Paper §III-I defines four security properties via a **game-based formalism** and proves
four corresponding theorems. `tests/security/` has one file per theorem. The tests
exercise the theorems' properties directly rather than simulating the games —
see §5.2 for exactly what that does and does not establish.

| Paper element | Equations | Implementation file | What is verified |
|---|---|---|---|
| Definition 1 / Theorem 1 / **Game 1: `Exp^{auth}_E(λ)`** | (21)-(26) | `tests/security/test_theorem1_message_authenticity.py` | Under EUF-CMA, messages of uncompromised agents are unforgeable |
| Definition 2 / Theorem 2 / **Game 2: `Exp^{audit}_E(λ)`** | (27)-(31) | `tests/security/test_theorem2_audit_tamper_evidence.py` | Under collision resistance + EUF-CMA, logs inconsistent with a valid execution trace are not accepted |
| Definition 3 / Theorem 3 / **Game 3: `Exp^{cap}_E(λ)`** | (32)-(36) | `tests/security/test_theorem3_capability_bounded_damage.py` | With unforgeable capabilities and enforced verification at every protected resource, `Damage(A_i) ⊆ ∪ Scope(cap)` |
| Definition 4 / Theorem 4 / **Game 4: `Exp^{thr}_E(λ)`** | (37)-(39) | `tests/security/test_theorem4_threshold_protected_actions.py` | Under threshold-signature unforgeability, an adversary with `|C_P| < k` cannot authorize high-risk actions |

Each game is implemented as a **challenger-adversary protocol** (see §5.2).

### 2.3 §III-J / §III-L Implementation and evaluation

| Paper section | Location | Main responsibility |
|---|---|---|
| §III-J Implementation in A2A Environments | `cgatc/a2a_integration/` | 6 A2A extension headers, 11-step workflow |
| §III-L Evaluation Plan | `experiments/` | 6 evaluation axes, 5-baseline comparison |

### 2.4 §IV Conclusion

The completion criterion for the implementation is that §IV's claim (detectability +
bounded damage) is demonstrated as the theorems of §III-I.

### 2.5 How to cite equations

```python
def compute_agent_id(pk: bytes, model_hash: bytes, policy_hash: bytes, env_hash: bytes) -> bytes:
    """Compute agent identity per Sugio 2026, §III-C, Eq. (3):

        ID_i = H(pk_i ‖ modelHash_i ‖ policyHash_i ‖ envHash_i)

    Args:
        pk: Public verification key (pk_i in Eq. (2)).
        model_hash: Hash of model/execution container configuration.
        policy_hash: Hash of policy assigned to the agent.
        env_hash: Runtime environment measurement (e.g., TEE attestation).

    Returns:
        The 32-byte agent identity ID_i.
    """
```

```python
def verify_envelope(m: Envelope, sig: bytes, pk: bytes) -> bool:
    """Verify A2A message signature per Sugio 2026, §III-D, Eq. (8):

        Verify_{pk_i}(H(m), σ) = 1

    This corresponds to the receiver-side check in Game 1 (Exp^{auth}_E(λ)),
    Eq. (24). A return value of False MUST cause the message to be rejected
    by the enforcement layer (see §III-G-1).
    """
```

---

## 3. Architecture and implementation phases

### 3.1 Overall architecture

```
┌──────────────────────────────────────────────────────────────┐
│                    Application Layer (Agents)                 │
│  ┌────────────┐    ┌────────────┐    ┌────────────┐          │
│  │  Agent A   │    │  Agent B   │    │  Agent C   │  ...     │
│  └─────┬──────┘    └─────┬──────┘    └─────┬──────┘          │
└────────┼─────────────────┼─────────────────┼─────────────────┘
         │                 │                 │
┌────────┴─────────────────┴─────────────────┴─────────────────┐
│                       CG-ATC Layer (§III)                     │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────────────┐  │
│  │   Identity   │ │  Messaging   │ │     Capability       │  │
│  │   (§III-C)   │ │   (§III-D)   │ │       (§III-E)       │  │
│  └──────────────┘ └──────────────┘ └──────────────────────┘  │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────────────┐  │
│  │    Audit     │ │  Detection   │ │     Containment      │  │
│  │   (§III-F)   │ │   (§III-G)   │ │       (§III-H)       │  │
│  └──────────────┘ └──────────────┘ └──────────────────────┘  │
└──────────────────────────────────────────────────────────────┘
         │                 │                 │
┌────────┴─────────────────┴─────────────────┴─────────────────┐
│         A2A Protocol Layer (Google A2A) — §III-J              │
│           JSON-RPC over HTTP / Streaming (SSE)                │
└──────────────────────────────────────────────────────────────┘

         ┌─────────────────────────────────────────────┐
         │  Security Property Verification (§III-I)     │
         │  Game-based simulators + property tests      │
         │  Game 1 / Game 2 / Game 3 / Game 4           │
         └─────────────────────────────────────────────┘
```

### 3.2 Directory layout

The tree below is the actual layout of the repository.

```
CG-ATC/
├── CLAUDE.md                         # this file
├── README.md
├── LICENSE                           # Apache-2.0
├── pyproject.toml                    # setuptools; deps + ruff/mypy/pytest config
├── .pre-commit-config.yaml
├── docs/
│   ├── paper_mapping.md              # paper ↔ code mapping (§III-A ... §III-L)
│   ├── threat_model.md               # detailed threat model (§III-A, §III-I)
│   ├── open_questions.md             # interpretation gaps vs. the paper
│   └── spec_additional_experiments_and_baselines.pdf   # adaptive-attack spec (Japanese)
├── cgatc/                            # main package
│   ├── core/
│   │   ├── types.py                  # AgentID, TaskID, SessionID, SecretBytes (§III-A)
│   │   ├── exceptions.py             # CG-ATC-specific exceptions
│   │   └── constants.py              # τ thresholds, λ decay, α/β/γ/δ weights
│   ├── crypto/
│   │   ├── primitives.py             # thin wrappers for H(), Sign(), Verify(), AE
│   │   ├── kex.py                    # X25519 session-key agreement
│   │   ├── threshold.py              # k-of-n threshold authorization (§III-H-3)
│   │   └── vrf.py                    # verifiable-random-function stand-in (§III-H-3, Eq. (18))
│   ├── identity/                     # §III-C
│   │   ├── agent_card.py             # build/sign/verify Card_i (Eq. (4)-(5))
│   │   ├── attestation.py            # envHash, EnvAttest
│   │   └── keystore.py               # key pair (sk_i, pk_i) management (Eq. (2))
│   ├── messaging/                    # §III-D
│   │   ├── envelope.py               # signed envelope (Eq. (6)-(8))
│   │   ├── chain.py                  # prevHash causal-chain verification
│   │   └── replay_guard.py           # nonce/seq management (timestamp freshness)
│   ├── capability/                   # §III-E
│   │   ├── token.py                  # cap_{i,j,t} structure (Eq. (9))
│   │   ├── authority.py              # Policy Authority, σ_PA issuance (Eq. (10))
│   │   └── enforcer.py               # Allow(i, a, cap) enforcement gate (§III-I Eq. (32))
│   ├── audit/                        # §III-F
│   │   ├── hashchain.py              # L_i^t = H(L_i^{t-1} ‖ ...) (Eq. (11))
│   │   ├── merkle.py                 # root_i^t (Eq. (12)) + inclusion proofs
│   │   └── committer.py              # Σ_i^t signature and external commitment (Eq. (13))
│   ├── detection/                    # §III-G
│   │   ├── crypto_detector.py        # cryptographic detection (§III-G-1: 10 conditions)
│   │   ├── behavioral_detector.py    # behavioral detection (§III-G-2)
│   │   └── risk_score.py             # R_i^{t+1} computation (Eq. (14))
│   ├── containment/                  # §III-H
│   │   ├── scope_reducer.py          # dynamic scope reduction (Eq. (15), 7 stages)
│   │   ├── impact_radius.py          # Impact(A_i, t) computation (Eq. (16))
│   │   └── threshold_authz.py        # threshold authorization (Eq. (17)), VRF committee (Eq. (18))
│   ├── a2a_integration/              # §III-J
│   │   ├── headers.py                # the 6 A2A extension headers
│   │   ├── middleware.py             # send/receive extension layer
│   │   ├── asgi_middleware.py        # ASGI hook for FastAPI/uvicorn JSON-RPC servers
│   │   ├── strands_bridge.py         # binding to strands-agents / a2a-sdk
│   │   └── workflow.py               # the 11-step workflow of §III-J
│   ├── policy/
│   │   ├── policy_dsl.py             # DSL parser for policy Π (dict + YAML front-ends)
│   │   └── evaluator.py
│   └── baselines/                    # the 5 baselines of §III-L
│       ├── base.py                   # common pluggable interface
│       ├── auth_only.py
│       ├── tls_oauth.py
│       ├── cap_no_audit.py
│       ├── anomaly_no_crypto.py
│       └── cgatc_full.py
├── tests/                            # 150 tests, all green
│   ├── unit/                         # 113 tests, incl. RFC 8032 KATs
│   ├── integration/                  # 3 tests — A2A workflow, Strands chat
│   ├── security/                     # 18 tests — Theorems 1-4 (see §5.2)
│   │   ├── test_theorem1_message_authenticity.py
│   │   ├── test_theorem2_audit_tamper_evidence.py
│   │   ├── test_theorem3_capability_bounded_damage.py
│   │   └── test_theorem4_threshold_protected_actions.py
│   ├── adversarial/                  # 13 tests — attack scenarios (see §5.3)
│   │   ├── test_impersonation.py
│   │   ├── test_replay.py
│   │   ├── test_collusion.py
│   │   ├── test_memory_poisoning.py
│   │   ├── test_worm_propagation.py
│   │   └── test_contagious_jailbreak.py
│   └── e2e/                          # 3 tests — HTTP JSON-RPC full path
├── experiments/                      # §III-L evaluation scripts (take no arguments)
│   ├── bench_crypto_overhead.py
│   ├── bench_audit_overhead.py
│   ├── eval_detection_perf.py
│   ├── eval_containment_perf.py
│   ├── compare_baselines.py
│   ├── scale_eval.py                 # 10 / 100 / 1000 agents
│   ├── workloads/                    # benign.py, adversarial.py (seeded)
│   └── plotting/                     # CSV → figure, pure functions
├── benchmarks/                       # adaptive-attack suite (8 workloads × 10 baselines)
│   ├── run_adaptive_attacks.py       # one (workload, baseline) combination
│   ├── run_all_adaptive_experiments.sh
│   ├── audit_tampering_experiment.py
│   ├── tables.py                     # Tables A/B/C
│   ├── runner.py, interfaces.py, materialize.py
│   ├── workloads/                    # the 8 adaptive workloads
│   └── baselines/                    # cg_atc + 5 stronger baselines + legacy 4
├── results/                          # committed outputs; each run carries meta.json
└── examples/
    ├── two_agent_handshake.py        # CG-ATC layer only, no LLM
    ├── multi_agent_topology.py
    ├── adversarial_demo.py
    ├── two_agent_chat.py             # real strands.Agent + deterministic stub model
    ├── _stub_model.py
    └── with_bedrock/                 # real strands.Agent + AWS Bedrock
```

Not present, though an earlier revision of this document called for them:
`paper/main.tex` (the manuscript is not distributed here — see §8),
`docs/game_specifications.md`, `experiments/eval_robustness.py` and
`eval_deployability.py` (those two axes are covered by `tests/adversarial/` +
`benchmarks/` and by `tests/e2e/` + `examples/` respectively; see §6.1), and
`tests/security/games/` (see §5.2). `tests/fixtures/kat/` exists but is empty —
the known-answer vectors are inline in the tests (§5.5).

### 3.3 Layering and implementation status

The package was built bottom-up, and the layering is still the reason the modules
depend on each other in the direction they do: nothing in an upper layer is allowed
to reach around a lower one. The table records what each layer contains and how far
it matches the paper.

| Layer | Modules | Paper | Status |
|---|---|---|---|
| 0. Foundations | `core/types.py`, `core/exceptions.py`, `core/constants.py`, `crypto/primitives.py`, `crypto/kex.py` | §III-A | Complete. Ed25519 / SHA-256 / ChaCha20-Poly1305 via `cryptography`; RFC 8032 known-answer tests in `tests/unit/test_crypto_primitives.py` |
| 1. Identity | `identity/{agent_card,attestation,keystore}.py` | §III-C, Eq. (2)-(5) | Complete. `compute_agent_id`, `sign_card`, `verify_card`, expiry checks. Certificate-chain verification is a stub; keys live in process (§4.6) |
| 2. Messaging | `messaging/{envelope,chain,replay_guard}.py` | §III-D, Eq. (6)-(8) | Complete. Signed envelope, `prevHash` chain, `seq` monotonicity, timestamp freshness |
| 3. Capability | `capability/{token,authority,enforcer}.py` | §III-E, Eq. (9)-(10) | Complete. `cap_{i,j,t}`, `σ_PA` issuance, scope/constraint/expiry/audience checks, default-deny `Allow(i, a, cap)` |
| 4. Audit | `audit/{hashchain,merkle,committer}.py` | §III-F, Eq. (11)-(13) | Complete. `L_i^t`, `root_i^t`, inclusion proofs, signed commitment `Σ_i^t`, `verify()` for tamper detection |
| 5. Detection | `detection/{crypto_detector,behavioral_detector,risk_score}.py` | §III-G, Eq. (14) | Complete. 10 cryptographic conditions, behavioral detectors, `R_i^{t+1}`. The aggregation of `B_i^t` is an interpretation — see `open_questions.md` Q2 |
| 6. Containment | `containment/{scope_reducer,impact_radius,threshold_authz}.py`, `crypto/{threshold,vrf}.py` | §III-H, Eq. (15)-(18) | Functionally complete, **two primitives are stand-ins**: the k-of-n scheme is a Schnorr-style multi-signature proxy, not FROST, and the committee VRF is a signature-derived shuffle, not RFC 9381 (Q3/Q4) |
| 7. A2A integration | `a2a_integration/*` | §III-J | Complete. 6 extension headers, 11-step workflow, ASGI middleware, `strands-agents` / `a2a-sdk` binding; exercised by `tests/e2e/` |
| 8. Evaluation | `experiments/`, `benchmarks/`, `baselines/` | §III-L | Complete. See §6; all committed results under `results/` regenerate from a fixed seed |

Parameters `λ, α, β, γ, δ` and the thresholds `τ` are defined in
`cgatc/core/constants.py` and are overridable per-instance at construction time.
`cgatc/detection/risk_score.py` refers to a `examples/configs/risk.yaml` config
file that is not currently shipped; the weights are set programmatically instead.

---

## 4. Coding conventions

### 4.1 Language and toolchain

- Python **3.11 or later** (use type hints and `match`, PEP 695 generics)
- Package management with `uv` or `poetry`
- Formatter: `ruff format`, linter: `ruff check`, types: `mypy --strict`
- All automated via pre-commit

### 4.2 Cryptographic library policy

**No primitive is hand-rolled.** Every cryptographic operation delegates to an
established library:

| Purpose | What the code uses | Assumption in the paper |
|---|---|---|
| Signatures (Ed25519) | `cryptography` | EUF-CMA (§III-A, Theorem 1) |
| Hashing (SHA-256) | `hashlib` (stdlib) | Collision resistance (Theorem 2) |
| AE (ChaCha20-Poly1305) | `cryptography` | Confidentiality + integrity (§III-A) |
| Key agreement (X25519) | `cryptography` | — (`crypto/kex.py`, session keys) |
| Merkle tree | thin in-house over `hashlib` | Reduces to collision resistance (Theorem 2) |
| Threshold signatures | **stand-in**: `k` independent Ed25519 signatures over the same message (`crypto/threshold.py`) | Unforgeability (Theorem 4) |
| VRF | **stand-in**: Ed25519 signature over the seed, shuffle derived from `H(σ)` (`crypto/vrf.py`) | Pseudorandomness + verifiability (§III-A) |

The last two rows are the honest caveat of this artifact. The multi-signature proxy
does satisfy the property Theorem 4 needs — no coalition of `k-1` can authorize —
but it is not FROST, so it has none of FROST's round efficiency or signature
compactness. The VRF stand-in produces an unforgeable, deterministic, publicly
verifiable output, but it is not an RFC 9381 VRF and has no formal VRF proof
structure. Both are isolated behind narrow interfaces so a real FROST / RFC 9381
backend can replace them without touching call sites. See `docs/open_questions.md`
Q3 and Q4.

**Key management**: keys are generated and held in process (`identity/keystore.py`),
wrapped in `SecretBytes`. There is no KMS / HSM integration; the keystore interface
is the seam where one would be added.

### 4.3 Design principles

The 7 principles of paper §III-B translated into coding rules:

1. **No implicit trust** (§III-B-1): explicit verification at the entry point of every
   public function. Comments such as "we trust the caller" are forbidden.
2. **Cryptographic identity** (§III-B-2): AgentID is an immutable value object. Do not
   pass raw `bytes` around.
3. **Signed & causally linked** (§III-B-3): the message-send API has no "send without
   signature" overload. `prevHash` is mandatory.
4. **Capability least privilege** (§III-B-4): privileged access that does not require a
   capability must not exist. Default deny.
5. **Tamper-evident** (§III-B-5): every state change is recorded in the audit log. Do
   not create code paths that skip log writes.
6. **Threshold for high-risk** (§III-B-6): the list of high-risk actions is stated
   explicitly in `cgatc/containment/threshold_authz.py`, and the type system
   prevents executing them with a single signature.
7. **Dynamic containment** (§III-B-7): risk score and scope must be referenceable from
   separate services; do not hard-code them.

### 4.4 Naming conventions

- Match the paper's notation: `prev_hash` (paper `prevHash`), `agent_id` (`ID_i`),
  `risk_score` (`R_i`), `session_id` (`sessionID` or `sid`)
- Function names derived from equations must always carry the corresponding
  **equation number** ((1)-(39)) in the docstring
- Magic constants are collected in `cgatc/core/constants.py`, stating the paper's
  threshold `τ_1`, decay `λ`, and coefficients `α, β, γ, δ`

### 4.5 Error handling

- Cryptographic verification failures raise dedicated exceptions
  (`SignatureVerificationError`, `CapabilityScopeViolation`,
  `AuditChainInconsistency`, etc.)
- Do not swallow security-related failures with `try: ... except Exception: pass`
- Logs record the fact that verification failed, but must not expose information
  useful to an attacker (such as which specific check failed)

### 4.6 Handling of secrets

- Secret keys are never exposed in `__repr__` / `__str__` / log output: they are
  wrapped in `SecretBytes` (`core/types.py`), whose `__repr__` prints only the
  length and whose `__eq__` is constant-time
- No key material is committed. Tests generate ephemeral key pairs at run time, so
  there is no fixture directory to protect; `.gitignore` still excludes
  `tests/fixtures/keys/` and `*.pem` / `*.key` as a guard

---

## 5. Testing policy

### 5.1 Test hierarchy

| Level | Directory | Purpose |
|---|---|---|
| Unit | `tests/unit/` | Behavior of individual functions and classes |
| Integration | `tests/integration/` | Cross-module interaction (e.g. issue → sign → verify → audit) |
| **Security properties** | `tests/security/` | **The four theorems of paper §III-I, one file per theorem (18 tests)** |
| Adversarial scenarios | `tests/adversarial/` | Concrete attack scenarios from §III-A and confirmation of defenses (13 tests) |
| E2E | `tests/e2e/` | Full path over the A2A protocol |

### 5.2 Security-property tests (§III-I, Theorems 1-4)

Paper §III-I formalizes four security properties as challenger-adversary games
(`Exp^{auth}`, `Exp^{audit}`, `Exp^{cap}`, `Exp^{thr}`) and proves Theorems 1-4
against them. `tests/security/` contains one file per theorem, 18 tests in total.

**What the tests actually do — and what they do not.** They are *direct property
tests*, not game simulators. There is no `Challenger` class, no signing oracle, no
corrupt-set bookkeeping, and no `hypothesis` fuzzing. Each file instead fixes the
adversary's capability by construction — the adversary is handed everything except
the honest secret key — and asserts that the enforcement path rejects every attempt.
For example, `test_theorem1_message_authenticity.py` states its operationalisation
directly:

> The adversary may see arbitrary signed envelopes from Alice, pick any payload,
> headers, sequence numbers, but does NOT know Alice's secret key. For ANY
> envelope/signature pair the adversary can produce, `verify_envelope` MUST reject
> it. We do not attempt to *break* Ed25519; we test the integration: that we never
> inadvertently provide an oracle that returns a valid envelope without the secret
> key.

That is the honest scope of all four files. They establish that **CG-ATC's own
enforcement layer contains no bypass** — no code path accepts a forged envelope, a
tampered log, an out-of-scope capability, or a sub-threshold authorization. They do
**not** establish the cryptographic reductions themselves: `Pr[Exp_E(λ) = 1] ≤
negl(λ)` follows from EUF-CMA, collision resistance and threshold unforgeability,
which are assumed, not tested. Breaking Ed25519 is out of scope by construction.

| Theorem | File | Property exercised |
|---|---|---|
| 1 — Message authenticity (§III-D-1) | `test_theorem1_message_authenticity.py` | No envelope verifies under Alice's `pk` without Alice's `sk`; tampering any field invalidates the signature |
| 2 — Tamper-evident auditability (§III-F, §III-I) | `test_theorem2_audit_tamper_evidence.py` | Deleting, modifying, reordering or inserting log entries is detected by the hash chain / Merkle root |
| 3 — Capability-bounded damage (§III-E, §III-I) | `test_theorem3_capability_bounded_damage.py` | A corrupted agent cannot act outside `∪ Scope(cap)`; wrong audience/subject/task/expiry are all denied |
| 4 — Threshold-protected actions (§III-H-3, §III-I) | `test_theorem4_threshold_protected_actions.py` | Fewer than `k` signers cannot authorize a high-risk action |

Building explicit `Challenger` / `Adversary` game simulators, driven by `hypothesis`
over randomized corrupt sets and query budgets, would make the correspondence to
§III-I's formalism literal rather than argued. It remains future work; the current
tests cover the same properties at a coarser granularity.

### 5.3 Adversarial scenario tests

Paper §III-A enumerates nine attack vectors. All nine are covered, but not by nine
dedicated files in `tests/adversarial/`: four are covered where the defending
mechanism lives instead. The table below is the real mapping.

| Attack (§III-A) | Where it is covered | Expected result |
|---|---|---|
| impersonating another agent | `tests/adversarial/test_impersonation.py` | Signature verification fails → rejected |
| modifying or replaying A2A messages | `tests/adversarial/test_replay.py` | Rejected by `replay_guard` (nonce/seq/freshness) |
| colluding with other compromised agents | `tests/adversarial/test_collusion.py` | Contained; high-risk action needs `k` signers (Theorem 4) |
| injecting false information into shared memory | `tests/adversarial/test_memory_poisoning.py` | Behavioral detection + risk-score increase |
| propagating malicious prompts or poisoned contents | `tests/adversarial/test_worm_propagation.py`, `test_contagious_jailbreak.py` | Suppressed by impact radius + scope reduction |
| causing cascading failures through delegated tasks | `tests/adversarial/test_worm_propagation.py`; `experiments/eval_containment_perf.py` | Contained by `impact_radius` + `scope_reducer` |
| publishing a forged or misleading Agent Card | `tests/unit/test_identity.py` | Rejected by Card signature verification |
| requesting tasks beyond authorized privileges | `tests/unit/test_capability.py`, `tests/security/test_theorem3_capability_bounded_damage.py` | Rejected by the enforcer, default-deny (Theorem 3) |
| attempting to erase or modify audit traces | `tests/security/test_theorem2_audit_tamper_evidence.py`, `benchmarks/audit_tampering_experiment.py` | Detected by hash chain / Merkle root (Theorem 2) |

Each test asserts either "the attack does not succeed" or "the attack is always
detected/contained". The adaptive, semantically-varying versions of these attacks —
paraphrased worms, delayed and semantic replay, multi-hop indirect prompt injection
— live in `benchmarks/workloads/` rather than here, because they are measured
(attack success rate, TPR/FPR, propagation depth) rather than asserted; see §6.5.

### 5.4 Coverage

Measured with `PYTHONPATH=. pytest --cov=cgatc --cov-branch`:

**85% overall** (1829 statements, 216 missed; 360 branches, 73 partial).

By area, so the gaps are visible rather than averaged away:

| Area | Coverage | Note |
|---|---|---|
| `capability/` | 93-100% | `authority.py` 100%, `enforcer.py` 93% |
| `audit/` | 80-96% | `committer.py` 80% is the weakest |
| `messaging/` | 91-98% | |
| `identity/` | 59-88% | **`keystore.py` 59%** — persistence paths are unexercised |
| `crypto/` | 75-93% | **`threshold.py` 75%** — the multi-signature stand-in has untested error paths |
| `detection/` | 72-93% | **`behavioral_detector.py` 72%** |
| `containment/` | 86-95% | |
| `a2a_integration/` | 38-100% | **`strands_bridge.py` 38%** — needs a live Strands/Bedrock session |
| `baselines/` | 46-100% | comparison scaffolding, not part of the scheme |

The security-critical paths are not at 100%; `crypto/threshold.py` and
`identity/keystore.py` are the two that most deserve attention, and both are in the
areas §4.2 already flags as stand-in or non-production.

### 5.5 Known-answer tests

Cryptographic primitives carry known-answer tests. Ed25519 is checked against
RFC 8032 §7.1 TEST 1 in `tests/unit/test_crypto_primitives.py`, with the vector
inline in the test rather than in a fixture file. `tests/fixtures/kat/` exists but
is empty; there are currently no NIST CAVP (SHA-256) or RFC 9381 (VRF) vectors —
the latter would not apply anyway, since the VRF is a stand-in (§4.2).

---

## 6. Experiment and evaluation script layout

Evaluation is split across two suites. `experiments/` covers the six axes of
paper §III-L. `benchmarks/` is the later adaptive-attack suite, specified in
`docs/spec_additional_experiments_and_baselines.pdf` and described in §6.5.

### 6.1 Evaluation axes and scripts (§III-L)

Every script in `experiments/` takes **no command-line arguments** — it runs a fixed,
seeded configuration and writes to `results/<YYYYMMDD>_<experiment>/`. Passing
`--help` runs the experiment rather than printing usage.

| Evaluation axis | Script | Output directory |
|---|---|---|
| **Detection performance** (TPR, FPR, latency) | `eval_detection_perf.py` | `results/<date>_detection_perf/` |
| **Containment performance** (affected agents, propagation depth, damage radius) | `eval_containment_perf.py` | `results/<date>_containment_perf/` |
| **Cryptographic overhead** (sign/verify latency, throughput, message size) | `bench_crypto_overhead.py` | `results/<date>_crypto_bench/` |
| **Audit overhead** (append cost, Merkle proof size, verification time) | `bench_audit_overhead.py` | `results/<date>_audit_bench/` |
| **Robustness** (replay, impersonation, collusion, worms, contagious jailbreaks, memory poisoning) | `tests/adversarial/` + `benchmarks/` (§6.5) | pass/fail; per-attack success rate |
| **Practical deployability** (A2A JSON-RPC, HTTP, streaming) | `tests/e2e/test_http_jsonrpc.py` + `examples/` | pass/fail |
| Scale (10 / 100 / 1000 agents) | `scale_eval.py` | `results/<date>_scale_eval/` |

The last two axes have no dedicated `eval_robustness.py` / `eval_deployability.py`
driver: robustness is asserted by the adversarial tests and *measured* by the
adaptive-attack suite, and deployability is demonstrated by the e2e tests and the
runnable examples.

### 6.2 Baseline comparison (§III-L)

The five baselines of §III-L are implemented pluggably under `cgatc/baselines/`
behind the common interface in `base.py`, and compared on an identical workload by
`experiments/compare_baselines.py`:

1. **`auth_only`**: A2A with authentication only
2. **`tls_oauth`**: TLS and OAuth-style bearer-token access control
3. **`cap_no_audit`**: capability control without tamper-evident logging
4. **`anomaly_no_crypto`**: anomaly detection without cryptographic evidence
5. **`cgatc_full`**: the full CG-ATC scheme

The adaptive-attack suite adds five stronger baselines on top of these (§6.5).

### 6.3 Workload generation

`experiments/workloads/` holds the §III-L workloads: `benign.py` (delegation chains,
parallel queries, long-lived sessions) and `adversarial.py` (single attacker,
collusion, worm prompts, memory poisoning). `scale_eval.py` drives them at
10 / 100 / 1000 agents.

Every generator takes a deterministic seed and builds its own `random.Random(seed)`.
This is what makes the committed results reproducible — it is not a lapse in
cryptographic hygiene, and these call sites must not be "fixed" to use `secrets`.

### 6.4 Recording results

- Results are stored under `results/<YYYYMMDD>_<experiment>/`; the adaptive-attack
  runs use `results/adaptive/<YYYYMMDD>_run/`
- Each run writes a `meta.json` recording the random seed, Python version, platform,
  full `argv`, working directory, and run parameters, so a run can be reproduced
  verbatim. Library versions and hardware are not currently captured
- Figure generation is isolated in `experiments/plotting/` as pure CSV → figure
  functions

### 6.5 Adaptive-attack suite (`benchmarks/`)

A second evaluation suite covers attacks that survive naive replay/impersonation
defenses: paraphrased worms, delayed and semantic replay, benign broadcast,
multi-hop indirect prompt injection, delayed memory poisoning, semantic collusion,
and harmful semantics under a valid capability. It evaluates **8 workloads × 10
baselines**, the ten being `cg_atc`, five stronger baselines (`mtls_nonce`,
`signed_jwt`, `capability_central_audit`, `anomaly_signed_logs`, `opa_rego`) and the
four legacy baselines from §6.2.

Reported metrics: attack success rate, TPR, FPR, false containment rate, affected
agents, maximum propagation depth, allowed harmful messages, per-message latency.

```sh
# one combination
PYTHONPATH=. python benchmarks/run_adaptive_attacks.py \
  --workload paraphrased_worm --baseline cg_atc \
  --num-agents 100 --num-messages 1000 --seed 42 --output <path>.json

# all 80 combinations, then the three paper tables
bash benchmarks/run_all_adaptive_experiments.sh
PYTHONPATH=. python -m benchmarks.tables --root <run-dir> --output <run-dir>/tables
```

Unlike `experiments/`, these scripts do take arguments. The headline result is
deliberately qualified: CG-ATC prevents impersonation and low-level replay
cryptographically, policy-blocks unauthorized actions, and bounds propagation — but
for cryptographically valid, semantically harmful behaviour it claims no semantic
correctness. See the README for the full statement.

---

## 7. Working on this code

### 7.1 Orienting a change

1. Identify **which paper section and which equation number ((1)-(39))** the change
   belongs to, and whether a theorem (1-4) depends on it.
2. Respect the layering in §3.3: a change in an upper layer must not reach around a
   lower one. `cgatc/crypto/` depends on nothing in the package; `core/` depends only
   on `crypto/`; and so on upward.
3. Anything touching `capability/`, `audit/`, `messaging/` or `crypto/` changes the
   evidence for a theorem — update `tests/security/` in the same change.

### 7.2 Checklist when adding code

- [ ] Are the paper section and equation number stated in the docstring?
- [ ] If a theorem (1-4) applies, is the relationship documented in the docstring?
- [ ] Was a corresponding security-property test or unit test added?
- [ ] Are cryptographic primitives free of hand-rolled implementations?
- [ ] Is the design such that secrets cannot leak into `__repr__` / logs?
- [ ] Is it default-deny (capability/scope verification)?
- [ ] Does the error path avoid leaking information to an attacker?
- [ ] Does it pass `mypy --strict`?
- [ ] Is `ruff check` error-free?

### 7.3 What not to do

- Adding security specifications not described in the paper "to be helpful" (first
  check consistency with the paper; if the addition is justified, discuss it in a
  separate PR)
- Hand-rolling cryptographic primitives (Ed25519, SHA-256, FROST, VRF, etc.)
- Creating code paths that skip security verification (e.g. `if debug:
  skip_signature_check`)
- Weakening the core logic to make tests pass
- **Removing or narrowing a `tests/security/` test without replacing the evidence it
  provided for its theorem**
- Replacing the seeded `random.Random(seed)` calls in `experiments/workloads/` or
  `benchmarks/workloads/` with `secrets` — they are deterministic on purpose (§6.3),
  and changing them silently invalidates every committed result

### 7.4 When something is unclear

For points where the paper is ambiguous (e.g. the concrete formula for the behavioral
score `B_i^t`, the detailed procedure of `VerifyLog`, the representation format of
policy Π), implement a conservative provisional version and record it in
`docs/open_questions.md` as an "interpretation gap versus the paper". Do not
unilaterally settle on a specification that conflicts with the paper.

The following in particular are not made explicit in the paper:
- The concrete verification steps of `VerifyLog` (referenced by §III-I Game 2, but the
  definition must be inferred from the structure in §III-F)
- Normalization and feature extraction for the behavioral anomaly score `B_i^t`
- The concrete DSL/format of policy Π
- The boundary of the "trusted enforcement layer" mentioned in §III-I (definition of the
  state-transition semantics)

---

## 8. References (main)

From the paper's bibliography, those referenced frequently during implementation:

- **A2A Protocol** [3]: Google, Agent2Agent (A2A) Protocol,
  https://a2a-protocol.org/latest/
- **EUF-CMA**: see a standard cryptography textbook (premise of the threat model in
  §III-A)
- **FROST**: Komlo, Goldberg, "FROST: Flexible Round-Optimized Schnorr Threshold
  Signatures", SAC 2020 (threshold-signature candidate for Eq. (17))
- **VRF (RFC 9381)**: Goldberg et al., "Verifiable Random Functions (VRFs)",
  RFC 9381, 2023 (VRF candidate for Eq. (18))
- **The paper itself** — the single source of truth for the scheme. The manuscript
  source is not distributed in this repository; see `docs/paper_mapping.md` for the
  section ↔ module mapping.

---

*This file describes the implementation as it stands. When the paper is revised
(section structure, equation numbers, theorem statements), update the §2 mapping
tables here first, then `docs/paper_mapping.md`, then the affected docstrings.
Divergences between the paper and the code belong in `docs/open_questions.md`.*
