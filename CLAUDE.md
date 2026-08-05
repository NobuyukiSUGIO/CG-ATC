# CLAUDE.md

This file provides guidance for working in this repository (originally written for
Claude Code, claude.ai/code, but it doubles as the implementation contract for any
contributor).

---

## 1. Project overview

### 1.1 Purpose

This project is the reference implementation of the **CG-ATC** scheme proposed in
**"Cryptographically Grounded Agent Trust and Containment for A2A Multi-Agent
Systems" (Sugio, 2026)**.

CG-ATC (Cryptographically Grounded Agent Trust and Containment) is a zero-trust
security mechanism for LLM-based multi-agent systems running over the
Agent-to-Agent (A2A) protocol. This implementation is not a research PoC: it aims
to be a **production-oriented implementation** integrated with the real A2A
protocol (Google A2A) and real cryptographic libraries (`cryptography`, PyNaCl,
etc.).

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
four corresponding theorems. These are implemented 1:1 in `tests/security/` as
**game simulators + property tests**.

| Paper element | Equations | Implementation file | What is verified |
|---|---|---|---|
| Definition 1 / Theorem 1 / **Game 1: `Exp^{auth}_E(λ)`** | (21)-(26) | `tests/security/test_theorem1_message_authenticity.py` | Under EUF-CMA, messages of uncompromised agents are unforgeable |
| Definition 2 / Theorem 2 / **Game 2: `Exp^{audit}_E(λ)`** | (27)-(31) | `tests/security/test_theorem2_auditability.py` | Under collision resistance + EUF-CMA, logs inconsistent with a valid execution trace are not accepted |
| Definition 3 / Theorem 3 / **Game 3: `Exp^{cap}_E(λ)`** | (32)-(36) | `tests/security/test_theorem3_capability_bounded_damage.py` | With unforgeable capabilities and enforced verification at every protected resource, `Damage(A_i) ⊆ ∪ Scope(cap)` |
| Definition 4 / Theorem 4 / **Game 4: `Exp^{thr}_E(λ)`** | (37)-(39) | `tests/security/test_theorem4_threshold_protected_action.py` | Under threshold-signature unforgeability, an adversary with `|C_P| < k` cannot authorize high-risk actions |

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

```
cg-atc/
├── CLAUDE.md                         # this file
├── README.md
├── pyproject.toml                    # uv or poetry
├── .pre-commit-config.yaml
├── docs/
│   ├── paper_mapping.md              # paper ↔ code mapping (detailed)
│   ├── threat_model.md               # detailed threat model (§III-A, §III-I)
│   └── game_specifications.md        # implementation spec for Games 1-4
├── paper/
│   └── main.tex                      # paper source (for reference)
├── cgatc/                            # main package
│   ├── __init__.py
│   ├── core/
│   │   ├── types.py                  # AgentID, TaskID, SessionID, etc. (§III-A)
│   │   ├── exceptions.py             # CG-ATC-specific exceptions
│   │   └── constants.py
│   ├── crypto/
│   │   ├── primitives.py             # thin wrappers for H(), Sign(), Verify(), AE
│   │   ├── threshold.py              # k-of-n threshold signatures (FROST etc.) (§III-H-3)
│   │   └── vrf.py                    # verifiable random function (§III-H-3, Eq. (18))
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
│   │   ├── headers.py                # A2A-Agent-ID, A2A-Signature, and 4 more headers
│   │   ├── middleware.py             # extension layer over Google A2A
│   │   └── workflow.py               # the 11-step workflow of §III-J
│   ├── policy/
│   │   ├── policy_dsl.py             # DSL parser for policy Π
│   │   └── evaluator.py
│   └── baselines/                    # for the §III-L baseline comparison
│       ├── auth_only.py
│       ├── tls_oauth.py
│       ├── cap_no_audit.py
│       └── anomaly_no_crypto.py
├── tests/
│   ├── unit/
│   ├── integration/
│   ├── security/                     # game-based property tests for §III-I Games 1-4
│   │   ├── games/
│   │   │   ├── challenger.py         # shared challenger infrastructure
│   │   │   ├── adversary.py          # adversary interface
│   │   │   ├── game1_auth.py         # Exp^{auth}_E(λ) simulator
│   │   │   ├── game2_audit.py        # Exp^{audit}_E(λ) simulator
│   │   │   ├── game3_cap.py          # Exp^{cap}_E(λ) simulator
│   │   │   └── game4_thr.py          # Exp^{thr}_E(λ) simulator
│   │   ├── test_theorem1_message_authenticity.py
│   │   ├── test_theorem2_auditability.py
│   │   ├── test_theorem3_capability_bounded_damage.py
│   │   └── test_theorem4_threshold_protected_action.py
│   └── adversarial/                  # concrete scenarios for the 9 attacks of §III-A
│       ├── test_impersonation.py
│       ├── test_replay.py
│       ├── test_forged_card.py
│       ├── test_privilege_escalation.py
│       ├── test_prompt_propagation.py
│       ├── test_collusion.py
│       ├── test_memory_poisoning.py
│       ├── test_audit_tampering.py
│       └── test_cascading_failure.py
├── experiments/                      # §III-L evaluation scripts
│   ├── bench_crypto_overhead.py
│   ├── bench_audit_overhead.py
│   ├── eval_detection_perf.py
│   ├── eval_containment_perf.py
│   ├── eval_robustness.py
│   ├── eval_deployability.py
│   └── compare_baselines.py
└── examples/
    ├── two_agent_handshake.py
    ├── multi_agent_topology.py
    └── adversarial_demo.py
```

### 3.3 Implementation phases

Given the dependencies in the paper, strictly follow a **bottom-up order**. Do not
write code for an upper layer until the lower layers pass their game-based property
tests.

**Phase 0: Foundations** *(starting point)*
- `cgatc/core/types.py`: domain types (AgentID, TaskID, SessionID, Timestamp,
  representation of the adversary model `C ⊆ A`)
- `cgatc/crypto/primitives.py`: thin wrappers for hashing, signatures, and AE
  (Ed25519 recommended, using `cryptography`)
- `tests/security/games/challenger.py` and `adversary.py`: game-simulator
  infrastructure
- Unit tests: must include known-answer tests (KATs)

**Phase 1: Identity and Agent Card (§III-C, Eq. (2)-(5))**
- Key pair generation, `compute_agent_id`, `Card`, `sign_card`, `verify_card`
- `Expiry` validation, certificate-chain verification stub
- Property tests: forged Cards are always rejected, legitimate Cards are always
  accepted

**Phase 2: Message envelope (§III-D, Eq. (6)-(8))**
- Signed envelope, `prevHash` chain, `seq` monotonicity, `timestamp` freshness
- Implement the **Game 1 simulator** in `tests/security/games/game1_auth.py`
- Property test: **Theorem 1 (message authenticity)** —
  `Pr[Exp^{auth}_E(λ) = 1] ≤ negl(λ)`

**Phase 3: Capability tokens (§III-E, Eq. (9)-(10))**
- `cap_{i,j,t}` structure, issuance and signing `σ_PA` by the Policy Authority
- Verification of scope, the 8 constraint kinds, expiry, and audience binding
- Enforcement layer (`Allow(i, a, cap) = 1`, §III-I Eq. (32))
- Implement the **Game 3 simulator** in `tests/security/games/game3_cap.py`
- Property test: **Theorem 3 (capability-bounded damage)** —
  `Damage(A_i) ⊆ ∪ Scope(cap)`

**Phase 4: Audit log (§III-F, Eq. (11)-(13))**
- Hash chain `L_i^t`, Merkle root `root_i^t`, signed commitment `Σ_i^t`
- Implement the `VerifyLog` function (referenced by Game 2)
- Implement the **Game 2 simulator** in `tests/security/games/game2_audit.py`
- Property test: **Theorem 2 (auditability)** — dual protection by tamper detection
  and signature unforgeability

**Phase 5: Detection (§III-G)**
- Cryptographic detection (10 conditions enumerated in §III-G-1)
- Behavioral detection (8 examples in §III-G-2) and risk score `R_i^{t+1}` (Eq. (14))
- Parameters `λ, α, β, γ, δ` and threshold `τ_1` are externalized into a config file

**Phase 6: Containment (§III-H)**
- Dynamic scope reduction (Eq. (15), 7-stage graduated containment)
- Control of the impact radius `r` and computation of `Impact(A_i, t)` (Eq. (16))
- Threshold signatures (FROST etc.) and VRF committee selection (Eq. (17)-(18))
- Implement the **Game 4 simulator** in `tests/security/games/game4_thr.py`
- Property test: **Theorem 4 (threshold-protected critical action)** — an adversary
  with `|C_P| < k` cannot authorize

**Phase 7: A2A integration (§III-J)**
- The 6 A2A extension headers (`A2A-Agent-ID`, `A2A-Signature`,
  `A2A-Capability-Token`, `A2A-Prev-Hash`, `A2A-Log-Root`, `A2A-Risk-Level`)
- Implement the 11-step workflow in `workflow.py`
- Middleware integration with Google A2A's JSON-RPC / SSE
- End-to-end integration tests

**Phase 8: Evaluation (§III-L)**
- The 6 evaluation axes (detection performance, containment performance,
  cryptographic overhead, audit overhead, robustness, deployability)
- Comparison against the 5 baselines (`auth_only`, `tls_oauth`, `cap_no_audit`,
  `anomaly_no_crypto`, `cgatc_full`)

---

## 4. Coding conventions

### 4.1 Language and toolchain

- Python **3.11 or later** (use type hints and `match`, PEP 695 generics)
- Package management with `uv` or `poetry`
- Formatter: `ruff format`, linter: `ruff check`, types: `mypy --strict`
- All automated via pre-commit

### 4.2 Cryptographic library policy

**Hand-rolled cryptography is strictly forbidden.** Use the established libraries
below:

| Purpose | Recommended library | Assumption in the paper |
|---|---|---|
| Signatures (Ed25519) | `cryptography` or `PyNaCl` | EUF-CMA (§III-A, Theorem 1) |
| Hashing (SHA-256/SHA-3) | `hashlib` (stdlib) | Collision resistance (Theorem 2) |
| AE (ChaCha20-Poly1305) | `cryptography` | Confidentiality + integrity (§III-A) |
| Threshold signatures | `frost-ed25519` etc. | Unforgeability (Theorem 4) |
| VRF | RFC 9381-conformant library | Pseudorandomness + verifiability (§III-A) |
| Merkle tree | `pymerkle` or a thin in-house one | Reduces to collision resistance (Theorem 2) |

**Key management**: during development, use the OS keychain or an encrypted file; for
production, factor this out behind an interface that assumes KMS / HSM integration.

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

- Never expose secret keys in `__repr__` / `__str__` / log output (use the
  `SecretBytes` wrapper type)
- Do not hard-code test keys into the repository (`.gitignore` `tests/fixtures/keys/`
  and provide a generation script)

---

## 5. Testing policy

### 5.1 Test hierarchy

| Level | Directory | Purpose |
|---|---|---|
| Unit | `tests/unit/` | Behavior of individual functions and classes |
| Integration | `tests/integration/` | Cross-module interaction (e.g. issue → sign → verify → audit) |
| **Game-based property** | `tests/security/` | **Verification of Games 1-4 and Theorems 1-4 of paper §III-I** |
| Adversarial scenarios | `tests/adversarial/` | Concrete reproduction of the 9 attacks of §III-A and confirmation of defenses |
| E2E | `tests/e2e/` | Full path over the A2A protocol |

### 5.2 Game-based property tests (most important, corresponds to §III-I)

Paper §III-I formalizes Games 1-4 as challenger-adversary protocols. Implement these
faithfully in Python.

#### 5.2.1 Shared challenger-adversary infrastructure

```python
# tests/security/games/challenger.py
class Challenger:
    """Challenger for security games defined in Sugio 2026, §III-I.

    Initializes CG-ATC with security parameter λ, policy Π, and agent set A.
    Provides oracles for the adversary subject to protocol rules.
    """
    def __init__(self, lam: int, policy: Policy, agents: list[AgentID]): ...
    def corrupt(self, agent_ids: set[AgentID]) -> dict[AgentID, SecretKey]: ...
    def signing_oracle(self, agent_id: AgentID, m: Envelope) -> bytes: ...
    # ...

class Adversary(ABC):
    """Adversary interface used in Game 1-4."""
    @abstractmethod
    def attack(self, challenger: Challenger) -> Any: ...
```

#### 5.2.2 Game 1: message authenticity (§III-I Eq. (21)-(26))

```python
# tests/security/games/game1_auth.py
def run_game1(challenger: Challenger, adversary: Adversary) -> bool:
    """Simulate Exp^{auth}_E(λ) per Sugio 2026, §III-I Game 1.

    Adversary wins iff:
      (a) Verify_{pk_i}(H(m*), σ*) = 1   [Eq. (24)]
      (b) senderID* = ID_i for some A_i ∉ C
      (c) m* was never signed by A_i during the experiment
      (d) the system would accept (m*, σ*) as a valid A2A message from A_i
    """
    # ... corrupt set selection, oracle interaction, verification
```

```python
# tests/security/test_theorem1_message_authenticity.py
from hypothesis import given, strategies as st, settings

@given(num_agents=st.integers(min_value=2, max_value=20),
       num_corrupted=st.integers(min_value=0, max_value=5))
@settings(max_examples=200)
def test_theorem1_no_ppt_adversary_wins(num_agents, num_corrupted):
    """Theorem 1 (Sugio 2026, §III-I): Under EUF-CMA security of the underlying
    signature scheme, CG-ATC satisfies message authenticity, i.e.,
        Pr[Exp^{auth}_E(λ) = 1] ≤ negl(λ).

    We approximate the negligible bound by checking that across many
    randomized adversary runs, no PPT-bounded adversary (modeled as a
    fixed-query-budget attacker without access to honest signing keys)
    can produce a winning forgery.
    """
    challenger = Challenger.setup(num_agents=num_agents)
    challenger.corrupt(select_corrupted(num_corrupted))
    adversary = PPTBoundedForgeryAdversary(query_budget=1000)
    assert not run_game1(challenger, adversary)
```

#### 5.2.3 Games 2-4 follow the same challenger-adversary pattern

- **Game 2** (§III-I Eq. (27)-(31)): implementing the `VerifyLog` function is mandatory.
  Confirm that tampered logs are not accepted.
- **Game 3** (§III-I Eq. (32)-(36)): build the assumption that the Policy Authority is
  uncorrupted into the challenger. Confirm that a corrupted agent cannot execute
  protected actions outside `∪ Scope(cap)`.
- **Game 4** (§III-I Eq. (37)-(39)): enforce the adversary constraint `|C_P| < k` on the
  challenger side and confirm that no valid threshold signature can be produced.

**Important**: the adversary in each game is a "simulation of the PPT constraint",
limited by query and computation budgets. Since negligible probability cannot be
demonstrated in practice, we accumulate **negative evidence** (i.e. the adversary
cannot win within its query budget) over many hypothesis trials.

Place at least one property test per game (1-4). **An implementation without a game
simulator and property test corresponding to its theorem is not considered
complete.**

### 5.3 Adversarial scenario tests

Create one test file per attack enumerated in paper §III-A:

| Attack (§III-A) | Test file | Expected result |
|---|---|---|
| impersonating another agent | `test_impersonation.py` | Game 1 violation detected → rejected |
| modifying or replaying A2A messages | `test_replay.py` | Rejected by replay_guard |
| publishing a forged or misleading Agent Card | `test_forged_card.py` | Rejected by Card signature verification |
| requesting tasks beyond authorized privileges | `test_privilege_escalation.py` | Rejected by the enforcer (Theorem 3) |
| propagating malicious prompts or poisoned contents | `test_prompt_propagation.py` | Suppressed by impact_radius |
| colluding with other compromised agents | `test_collusion.py` | Suppressed by threshold signatures (Theorem 4) |
| injecting false information into shared memory | `test_memory_poisoning.py` | Behavioral detection + risk-score increase |
| attempting to erase or modify audit traces | `test_audit_tampering.py` | Detected via Theorem 2 |
| causing cascading failures through delegated tasks | `test_cascading_failure.py` | Contained by impact_radius + scope_reducer |

Each test asserts either "the attack does not succeed" or "the attack is always
detected/contained".

### 5.4 Coverage

- Line: 90% or higher
- Branch: 85% or higher
- Security-critical paths (`crypto/`, `identity/`, `capability/`, `audit/`): target
  100%
- Measure coverage with `pytest --cov=cgatc --cov-branch`

### 5.5 Vector tests

Cryptographic primitives must always include known-answer tests (KATs). Place RFC and
NIST test vectors under `tests/fixtures/kat/` (Ed25519: RFC 8032, SHA-256: NIST CAVP,
VRF: RFC 9381).

---

## 6. Experiment and evaluation script layout

Scripts corresponding to the evaluation axes of paper §III-L live in `experiments/`.

### 6.1 Evaluation axes and scripts (enumerated in §III-L)

| Evaluation axis | Script | Output |
|---|---|---|
| **Detection performance** (TPR, FPR, latency) | `eval_detection_perf.py` | `results/detection_*.csv`, ROC curve |
| **Containment performance** (affected agents, propagation depth, damage radius) | `eval_containment_perf.py` | `results/containment_*.csv`, propagation graph |
| **Cryptographic overhead** (signing/verification latency, throughput, message size) | `bench_crypto_overhead.py` | `results/crypto_bench.json` |
| **Audit overhead** (storage cost, Merkle proof size, log verification time) | `bench_audit_overhead.py` | `results/audit_bench.json` |
| **Robustness** (replay, impersonation, collusion, worm prompts, contagious jailbreaks, memory poisoning) | `eval_robustness.py` (+ `tests/adversarial/`) | Success rate per attack |
| **Practical deployability** (A2A JSON-RPC, HTTP, streaming compatibility) | `eval_deployability.py` + `examples/` | Integration test report |

### 6.2 Baseline comparison (enumerated in §III-L)

Make the 5 baselines switchable via `compare_baselines.py`:

1. **`auth_only`**: A2A with authentication only
2. **`tls_oauth`**: TLS and OAuth-based access control
3. **`cap_no_audit`**: capability control without tamper-evident logging
4. **`anomaly_no_crypto`**: anomaly detection without cryptographic evidence
5. **`cgatc_full`**: the full CG-ATC scheme

Implement each baseline pluggably under `cgatc/baselines/` and compare them on an
identical workload.

### 6.3 Workload generation

Provide the following under `experiments/workloads/`:

- Benign workloads: task-delegation chains, parallel queries, long-lived sessions
- Adversarial workloads: single attacker, collusion (2-3 agents), worm prompts,
  memory poisoning
- Scales: 10 / 100 / 1000 agents

Workloads take a deterministic seed to guarantee reproducibility.

### 6.4 Recording results

- All experiment results are stored under `results/<YYYYMMDD>_<experiment>/`
- Metadata (Python version, library versions, hardware, random seed, CG-ATC commit
  hash) must always be recorded in `meta.json`
- Figure generation is separated into `experiments/plotting/` and written as pure
  functions from CSV → PDF/PNG

---

## 7. Operational instructions

### 7.1 Always confirm before starting work

1. First identify **which paper section, which equation number ((1)-(39)), and which
   game (1-4)** the task corresponds to.
2. Confirm that the lower layers that the relevant phase depends on are complete and
   tested.
3. If a lower layer is incomplete, do not start on the upper layer; implement the
   dependency first.

### 7.2 Checklist when adding code

- [ ] Are the paper section and equation number stated in the docstring?
- [ ] If a game (1-4) or theorem applies, is the relationship documented in the
      docstring?
- [ ] Was a corresponding property test or unit test added?
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
- **Omitting the Game 1-4 simulators or the property tests corresponding to
  Theorems 1-4**
- Deviating from the game definitions of paper §III-I (challenger initialization
  procedure, adversary winning conditions)

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
- **The paper itself**: `paper/main.tex` — the single source of truth for this
  implementation. The manuscript source is not distributed in this repository;
  see `docs/paper_mapping.md` for the section ↔ module mapping.

---

*This file is the single source of truth for the CG-ATC implementation conventions.
When the paper is revised (changes to section structure, equation numbers, or game
definitions), update the §2 mapping tables in this file first.*
