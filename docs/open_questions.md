# Open questions / interpretation notes vs. paper

CLAUDE.md §7.4 instructs: when the paper is ambiguous, fall back to the
safer choice and record the divergence here.

## Q1. `modelHash_i` membership in `Card_i` (§III-C)

**Paper.** `Card_i = (ID_i, pk_i, Skills_i, Scopes_i, Auth_i, PolicyHash_i,
EnvAttest_i, Expiry_i)` — `modelHash_i` only appears in the `ID_i` formula
and is implicitly assumed to be available to the verifier.

**Implementation.** We bind `model_hash_hex` into the signed `Card` so
that any receiver can locally check
`ID_i = H(pk_i ‖ modelHash_i ‖ policyHash_i ‖ envHash_i)` without an
external lookup.  This is strictly stronger (every receiver can detect
a model-hash forgery).  No information is lost: callers that *also* want
to pin `modelHash_i` against an external allow-list can pass
`expected_model_hash=` to `verify_card`.

## Q2. Behavioral score `B_i^t` weighting (§III-G)

**Paper.** Lists 8 example anomalies but does not fix per-anomaly
weights or the exact aggregation scheme for `B_i^t`.

**Implementation.** Each detector contributes a score in `[0, 1]`
(saturating).  `B_i^t` is the unweighted sum, clipped to `[0, 5]`.
Weights `α, β, γ, δ, λ` are externalised in
`cgatc/detection/risk_score.py` and `examples/configs/risk.yaml` so
researchers can re-tune them without code changes.

## Q3. Threshold scheme (§III-H, *Threshold authorization*)

**Paper.** Mentions "k-of-n threshold signature" generically (e.g. FROST,
BLS).

**Implementation.** Phase 6 ships a simple Schnorr-style multi-signature
proxy that requires `k` independent Ed25519 signatures over the same
message.  This satisfies the security property of Theorem 4 (no `k-1`
adversary can authorize) but is verbose.  A drop-in FROST backend can
replace it via the `ThresholdAuthority` protocol; tests in
`tests/security/test_theorem4_*` are written against the protocol, not
the implementation, so the swap is mechanical.

## Q4. VRF for committee selection (§III-H, *Threshold authorization*)

**Paper.** `committee_t = VRF_{sk_PA}(taskID ‖ epoch)`.

**Implementation.** We use a hash-to-curve approximation: PA signs the
seed with Ed25519 and the receiver derives a deterministic shuffle from
`H(σ)`.  This is *not* a full RFC 9381 VRF and we mark it as such; the
public output is unforgeable but lacks the formal "VRF proof" structure.
Replacing it with a real RFC 9381 VRF is tracked separately.

## Q5. Section numbering (resolved — recorded so the drift does not recur)

Not an interpretation gap: a documentation defect that took two passes to
fix, kept here because the failure mode is easy to repeat.

**What happened.** The manuscript was restructured during writing. An early
draft put the proposed scheme in §I, the security properties in §II, and the
evaluation in §III. From the 2026-04-27 draft onward the structure became
§I Introduction / §II Related Work / §III Proposed Scheme / §IV Security
Properties / §V Evaluation / §VI Discussion / §VII Conclusion.

The repository tracked neither state cleanly. `docs/paper_mapping.md` had
§III-A..§III-H right but placed the security properties at §III-I, the
implementation at §III-J and the evaluation at §III-L — a numbering no draft
ever used. `CLAUDE.md` was still on the earliest §I/§II/§III scheme. A first
pass renumbered `CLAUDE.md` to agree with `paper_mapping.md`, which
propagated that file's error instead of fixing it, because the manuscript
itself was never consulted.

**Current mapping**, taken from the 2026-08-05 manuscript directly:

| was | is |
|---|---|
| §III-A .. §III-H | unchanged (these were always correct) |
| §III-I (security properties) | **§IV** |
| §III-J (implementation) | **§V-A** |
| §III-K (novelty — an inference, never in any draft) | **§III-I** |
| §III-L (evaluation) | **§V** |
| §IV (conclusion) | **§VII** |
| §III-B-n, §III-D-1, §III-G-n, §III-H-n | parent subsection — see below |

**No `\subsubsection` exists in the manuscript.** Within a subsection it uses
bold paragraphs (`\textbf{Cryptographic detection}`) or an `enumerate` (the
seven design principles). References such as §III-G-1 or §III-H-3 therefore
never resolved to anything; they have been collapsed to §III-G and §III-H,
and the paragraph is named in prose instead.

**Rule.** `docs/paper_mapping.md` is derived from the manuscript, not the
other way round. When the paper is revised, re-derive it by reading the
section headings, then propagate to `CLAUDE.md` and the docstrings. Do not
renumber one document to agree with another.
