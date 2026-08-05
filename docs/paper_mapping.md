# Paper ↔ Code mapping

| Paper section | Module | Notes |
|---|---|---|
| §III-A System and Threat Model | `cgatc/core/types.py` | Domain types: AgentID, TaskID, SessionID, Timestamp |
| §III-B Design Principles | project-wide | 7 principles enforced by code review + types |
| §III-C Cryptographic Agent Identity & Verifiable Agent Card | `cgatc/identity/` | `compute_agent_id`, `Card`, `sign_card`, `verify_card`, attestation stub |
| §III-D Signed A2A Message Format | `cgatc/messaging/envelope.py`, `cgatc/messaging/chain.py` | Signed envelope (m, σ), `prevHash` chain, `seq` monotonicity |
| §III-E Capability Token | `cgatc/capability/{token,authority,enforcer}.py` | `cap_{i,j,t}`, `PolicyAuthority`, scope/constraint enforcement |
| §III-F Tamper-Evident Audit Log | `cgatc/audit/{hashchain,merkle,committer}.py` | `L_i^t`, Merkle root + inclusion proof, external committer |
| §III-G Detection | `cgatc/detection/` | crypto detector (10 conditions), behavioral detector (8 anomalies), risk score |
| §III-H Impact Minimization | `cgatc/containment/` | 7-stage scope reducer, impact radius, threshold authz, VRF committee |
| §III-I Security Properties (Theorem 1-4) | `tests/security/` | property-based tests against the four theorems |
| §III-J Implementation in A2A Environments | `cgatc/a2a_integration/` | Strands + a2a-sdk bindings, A2A metadata headers, 11-step workflow |
| §III-L Evaluation Plan | `experiments/` | crypto overhead, audit overhead, detection perf, baselines |
