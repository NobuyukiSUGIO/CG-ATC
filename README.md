# CG-ATC: Cryptographically Grounded Agent Trust and Containment

Reference implementation of the **CG-ATC** scheme proposed in:

> Sugio, "Cryptographically Grounded Agent Trust and Containment for A2A Multi-Agent
> Systems", 2026.

CG-ATC is a zero-trust security mechanism for multi-agent systems based on the
[Agent-to-Agent (A2A) protocol](https://a2a-protocol.org/latest/). It provides:

- Cryptographic agent identities and verifiable Agent Cards (`§III-C`).
- Signed, causally-linked A2A messages (`§III-D`).
- Capability tokens for least-privilege access (`§III-E`).
- Tamper-evident audit logs (`§III-F`).
- Cryptographic + behavioral malicious-agent detection (`§III-G`).
- Dynamic capability reduction, impact-radius control, and threshold authorization
  for high-risk actions (`§III-H`).

This implementation is built on top of [`strands-agents`](https://strandsagents.com/)
and [`a2a-sdk`](https://a2a-protocol.org/latest/) so that an existing Strands agent can
be wrapped with the CG-ATC layer without re-implementing A2A transport or task semantics.

The implementation realizes the four security theorems of the paper as
property-based tests under `tests/security/`.

## Layout

See [`CLAUDE.md`](./CLAUDE.md) for how the paper maps onto the code, the conventions
the code follows, and where the implementation falls short of what the paper
specifies. [`docs/open_questions.md`](docs/open_questions.md) records the detailed
interpretation gaps.

```
cgatc/
  core/            domain types, exceptions, constants
  crypto/          ed25519, sha-256, AE, threshold, vrf
  identity/        agent card and attestation
  messaging/       signed envelope and prevHash chain
  capability/      capability tokens and policy authority
  audit/           hash chain + Merkle root + committer
  detection/       crypto + behavioral detection, risk score
  containment/     scope reduction, impact radius, threshold authz
  a2a_integration/ Strands + A2A bindings (headers, middleware, workflow)
  policy/          policy DSL + evaluator
tests/
  unit/, integration/, security/, adversarial/, e2e/
experiments/       evaluation scripts (§III-L)
examples/          end-to-end demos
```

## Setup

Python 3.11+ is required.

```sh
python -m venv .venv && . .venv/bin/activate
pip install -e ".[test,dev]"
```

> **The virtual environment must stay activated for every command in this README.**
> All commands below — and the `benchmarks/run_all_adaptive_experiments.sh` driver —
> invoke `python` rather than `python3`. On distributions that ship only a `python3`
> binary (Debian/Ubuntu and most CI images), running them without an activated venv
> fails with `python: command not found`. Re-activate with `. .venv/bin/activate` in
> each new shell.

The core CG-ATC layer only needs `cryptography`, `pydantic`, and `PyYAML`. The
`strands-agents` / `a2a-sdk` / `fastapi` / `httpx` dependencies are needed only for
the A2A integration tests (`tests/e2e/`, `tests/integration/test_strands_chat.py`)
and the Bedrock examples.

## Running tests

```sh
# minimal: stdlib unittest discovery (works without installing test extras)
PYTHONPATH=. python -m unittest discover -s tests -v

# with pytest + hypothesis (after `pip install -e .[test]`)
pytest

# core layer only, without the A2A/Strands transport dependencies
pytest --ignore=tests/e2e --ignore=tests/integration/test_strands_chat.py
```

## Examples

```sh
# CG-ATC layer only (no LLM)
PYTHONPATH=. python examples/two_agent_handshake.py
PYTHONPATH=. python examples/multi_agent_topology.py
PYTHONPATH=. python examples/adversarial_demo.py

# Real strands.Agent + deterministic stub LLM (CI-runnable)
PYTHONPATH=. python examples/two_agent_chat.py

# Real strands.Agent + AWS Bedrock (requires credentials & cost)
PYTHONPATH=. python examples/with_bedrock/two_agent_bedrock_chat.py
```

See [`examples/with_bedrock/README.md`](examples/with_bedrock/README.md)
for the AWS prerequisites.

## Adaptive Attack Evaluation

This benchmark suite evaluates CG-ATC against adaptive A2A attack workloads
that are not fully captured by simple replay or impersonation tests. The
goal is to separate what is prevented by cryptographic verification from
what requires capability enforcement, risk scoring, semantic policy
checks, or impact-radius containment.

The suite includes paraphrased worm propagation, delayed replay, semantic
replay, benign broadcast, multi-hop indirect prompt injection, delayed
memory poisoning, semantic collusion without identical payload repetition,
and harmful semantics under valid capabilities.

Each workload is evaluated against CG-ATC and stronger baselines,
including mTLS with nonce replay protection, signed JWT per message,
capability enforcement with centralized audit, anomaly detection with
signed logs, and OPA/Rego-style policy enforcement.

The benchmark reports attack success rate, true-positive rate,
false-positive rate, false containment rate, affected agents, maximum
propagation depth, allowed harmful messages, and per-message latency.

### Running the experiments

```sh
# one combination
PYTHONPATH=. python benchmarks/run_adaptive_attacks.py \
  --workload paraphrased_worm \
  --baseline cg_atc \
  --num-agents 100 --num-messages 1000 --seed 42 \
  --output results/adaptive/paraphrased_worm_cg_atc.json

# every workload × every baseline (10 baselines × 8 workloads)
bash benchmarks/run_all_adaptive_experiments.sh

# audit-tampering side experiment (CG-ATC vs centralised audit)
PYTHONPATH=. python benchmarks/audit_tampering_experiment.py \
  --output results/adaptive/audit_tampering.csv

# generate the three paper tables (Table A/B/C)
PYTHONPATH=. python -m benchmarks.tables \
  --root results/adaptive/<run-dir> \
  --output results/adaptive/<run-dir>/tables
```

### Workloads

| name | spec § |
| --- | --- |
| `paraphrased_worm` | §1.1 |
| `delayed_replay` | §1.2 |
| `semantic_replay` | §1.3 |
| `benign_broadcast` | §1.4 |
| `multihop_indirect_prompt_injection` | §1.5 |
| `memory_poisoning_delayed` | §1.6 |
| `semantic_collusion` | §1.7 |
| `valid_capability_harmful_semantics` | §1.8 |

### Baselines

| name | spec § |
| --- | --- |
| `cg_atc` | full CG-ATC stack |
| `baseline_mtls_nonce` | §2.1 |
| `baseline_signed_jwt` | §2.2 |
| `baseline_capability_central_audit` | §2.3 |
| `baseline_anomaly_signed_logs` | §2.4 |
| `baseline_opa_rego` | §2.5 |
| `auth_only`, `tls_oauth`, `cap_no_audit`, `anomaly_no_crypto` | legacy 4 baselines |

### Specification document and archived results

The spec sections referenced in the tables above
(`§1.1`, `§2.1`, ...) refer to
[`docs/spec_additional_experiments_and_baselines.pdf`](docs/spec_additional_experiments_and_baselines.pdf),
which is written in Japanese. Every behaviour it specifies is also documented in
English in the module docstrings under `benchmarks/`.

Pre-computed outputs of all runs reported in the paper are committed under
`results/`; each run directory carries a `meta.json` with the random seed,
Python version, platform, and exact command line, so the numbers can be
regenerated verbatim.

### Headline finding

CG-ATC cryptographically prevents impersonation and low-level replay,
policy-blocks unauthorized actions, makes multi-hop propagation
forensically reconstructable, and limits downstream damage through
risk-adaptive containment. For semantically harmful but cryptographically
valid behavior, CG-ATC does not claim semantic correctness; instead, it
exposes the need for semantic risk scoring, policy constraints, and
threshold authorization before high-impact actions.

## License

Apache License 2.0 — see [`LICENSE`](./LICENSE).

## Citation

```bibtex
@misc{sugio2026cgatc,
  author = {Sugio, Nobuyuki},
  title  = {Cryptographically Grounded Agent Trust and Containment
            for A2A Multi-Agent Systems},
  year   = {2026}
}
```
