# Threat model

This document operationalises the threat model from paper §III-A and
maps each attack vector to the concrete CG-ATC defence and the test
that proves it works.

## Attacker capabilities

* Up to `f` agents are Byzantine — they may deviate arbitrarily from
  protocol.
* The attacker is a probabilistic polynomial-time adversary; it cannot
  break:
  * EUF-CMA-secure digital signatures (Ed25519),
  * collision-resistant hash functions (SHA-256),
  * authenticated encryption (ChaCha20-Poly1305),
  * verifiable random functions (RFC 9381 / our pseudo-VRF),
  * `k`-of-`n` threshold signature schemes.
* The attacker controls the network: it can drop, reorder, replay, and
  inject messages.
* The attacker may compromise an arbitrary strict subset of the
  threshold-signature signers (size `< k`).
* The Policy Authority's signing key is **not** compromised in the
  baseline model; if it were, capability-bounded damage (Theorem 3)
  no longer holds.
* The attacker cannot replace the agent's environment-attestation
  evidence undetectably (i.e., a real TEE attestation backend is in
  place; the local-mode backend in `cgatc.identity.attestation` is for
  development only).

## Out of scope

* Side-channel attacks against the host (timing, power, EM).
* Attacks against the PA itself (its signing key is part of the trust
  base).
* Semantic correctness of the underlying LLM ("the agent gave a wrong
  answer" — CG-ATC is about authenticity and containment, not truth).

## Attack vectors → defences → tests

| Attack | Defence | Property / test |
|---|---|---|
| Impersonation (forge sender identity) | Signed envelope, verified Agent Card | Theorem 1, `tests/security/test_theorem1_*`, `tests/adversarial/test_impersonation.py` |
| Message tampering | Ed25519 signature over canonical envelope + payload hash | Theorem 1, `test_theorem1_*` |
| Replay | `seq` monotonicity, `prev_hash` chain, `ReplayGuard` | `test_messaging::TestReplayGuard`, `tests/adversarial/test_replay.py` |
| Agent Card forgery | Card signature + ID consistency check + EnvAttest | `test_identity::TestSignAndVerifyCard` |
| Privilege overreach (compromised agent) | Capability-bounded scopes, default-deny enforcer | Theorem 3, `tests/security/test_theorem3_*` |
| Unauthorized delegation | Capability `constraints.delegation_permitted`; PA signature | Theorem 3 |
| Prompt-fanout / worm propagation | Cross-sender payload fingerprint + impact-radius bound | `tests/adversarial/test_worm_propagation.py`; `experiments/eval_containment_perf.py` |
| Collusion / mutual reinforcement | Behavioural detector (`observe_amplification`, `observe_mutual_claim`); cross-sender payload fingerprint | `tests/adversarial/test_collusion.py`; `experiments/compare_baselines.py` |
| Memory / log tampering | Hash-chain audit log + Merkle root + external committer | Theorem 2, `tests/security/test_theorem2_*` |
| High-risk action by single compromised agent | `k`-of-`n` threshold authorisation | Theorem 4, `tests/security/test_theorem4_*` |

## Security boundaries

CG-ATC distinguishes two kinds of trust boundary:

1. **Cryptographic.**  Below this line a defence is reducible to a
   standard hardness assumption (EUF-CMA, collision resistance,
   threshold-sig unforgeability).  These give Theorems 1–4.
2. **Operational.**  Above this line CG-ATC depends on the *receiver*
   running the verification middleware on every inbound message and on
   the *Policy Authority* applying least-privilege scopes when it
   issues capability tokens.  Bypassing either is a deployment defect,
   not a cryptographic weakness; the implementation makes both the
   default and removes the "skip" code paths (CLAUDE.md §4.5).

## Failure-mode policy

* Every cryptographic-verification failure raises a typed exception
  *with a generic message* ("invalid X").  Detail goes to the local
  audit log (which is itself tamper-evident), not to the peer.
* No fallback path silently downgrades any of: signature verification,
  capability enforcement, audit logging.
