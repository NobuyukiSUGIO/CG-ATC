# Paper ↔ Code mapping

Section numbers refer to the manuscript as of 2026-08-05, whose top-level structure
is: §I Introduction, §II Related Work, §III Proposed Scheme, §IV Security
Properties, §V Evaluation, §VI Discussion and Limitations, §VII Conclusion.

The manuscript has no `\subsubsection`; within a subsection it uses bold or
enumerated paragraphs. References of the form `§III-G-1` therefore do **not** resolve
and must not be reintroduced — cite the subsection and name the paragraph instead.

## §III Proposed Scheme

| Paper section | Module | Notes |
|---|---|---|
| §III-A System and Threat Model | `cgatc/core/types.py` | Domain types: AgentID, TaskID, SessionID, Timestamp |
| §III-B Design Principles | project-wide | 7 enumerated principles; see CLAUDE.md §4.3 |
| §III-C Cryptographic Agent Identity and Agent Card | `cgatc/identity/` | `compute_agent_id`, `Card`, `sign_card`, `verify_card`, attestation stub |
| §III-D Signed A2A Message Envelope | `cgatc/messaging/envelope.py`, `cgatc/messaging/chain.py` | Signed envelope (m, σ), `prevHash` chain, `seq` monotonicity |
| §III-E Capability Tokens | `cgatc/capability/{token,authority,enforcer}.py` | `cap_{i,j,t}`, `PolicyAuthority`, scope/constraint enforcement |
| §III-F Tamper-Evident Audit Log | `cgatc/audit/{hashchain,merkle,committer}.py` | `L_i^t`, Merkle root + inclusion proof, external committer |
| §III-G Detection Mechanism | `cgatc/detection/` | *Cryptographic detection* → `crypto_detector.py`; *Behavioral detection* (`R_i^{t+1}`) → `behavioral_detector.py`, `risk_score.py` |
| §III-H Impact Minimization | `cgatc/containment/` | *Capability reduction* → `scope_reducer.py`; *Impact radius* → `impact_radius.py`; *Threshold authorization* → `threshold_authz.py`, `crypto/{threshold,vrf}.py` |
| §III-I Novelty and Advantages | — | design rationale; no dedicated module |
| §III-J Scope and Non-Goals | — | the semantic boundary the code deliberately does not cross |

## §IV Security Properties

| Paper section | Implementation |
|---|---|
| §IV-A Message Authenticity (Theorem 1) | `tests/security/test_theorem1_message_authenticity.py` |
| §IV-B Auditability (Theorem 2) | `tests/security/test_theorem2_audit_tamper_evidence.py` |
| §IV-C Capability-Bounded Containment (Theorem 3) | `tests/security/test_theorem3_capability_bounded_damage.py` |
| §IV-D Threshold-Protected Critical Action (Theorem 4) | `tests/security/test_theorem4_threshold_protected_actions.py` |
| §IV-E Relationship among Properties | — (argued in prose) |

These are direct property tests, not challenger-adversary game simulators. See
CLAUDE.md §5.2 for exactly what they do and do not establish.

## §V Evaluation

| Paper section | Implementation | Notes |
|---|---|---|
| §V-A Implementation and Methodology | `cgatc/a2a_integration/` | 6 A2A metadata headers, 11-step workflow, ASGI middleware over a Strands `A2AServer` |
| §V-B Cryptographic and Audit Overhead | `experiments/bench_crypto_overhead.py`, `experiments/bench_audit_overhead.py` | sign/verify latency, throughput, message size, Merkle proof cost |
| §V-C Adaptive Attacks and Baselines | `benchmarks/` | 8 workloads × 10 baselines; `experiments/compare_baselines.py` covers the 5 legacy baselines |
| §V-D Layer Responsibility, Scalability, and LLM Integration | `experiments/scale_eval.py`, `benchmarks/tables.py`, `examples/`, `tests/e2e/` | 10/100/1000 agents; end-to-end LLM path |

## §VI–§VII

| Paper section | Implementation | Notes |
|---|---|---|
| §VI-B Forensic Accountability and Semantic Boundary | `benchmarks/workloads/valid_capability_harmful_semantics.py` | the workload that exhibits the boundary empirically |
| §VII Conclusion | — | restates the central claim; see CLAUDE.md §1.2 |
