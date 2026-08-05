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

## Q3. Threshold scheme (§III-H-3)

**Paper.** Mentions "k-of-n threshold signature" generically (e.g. FROST,
BLS).

**Implementation.** Phase 6 ships a simple Schnorr-style multi-signature
proxy that requires `k` independent Ed25519 signatures over the same
message.  This satisfies the security property of Theorem 4 (no `k-1`
adversary can authorize) but is verbose.  A drop-in FROST backend can
replace it via the `ThresholdAuthority` protocol; tests in
`tests/security/test_theorem4_*` are written against the protocol, not
the implementation, so the swap is mechanical.

## Q4. VRF for committee selection (§III-H-3)

**Paper.** `committee_t = VRF_{sk_PA}(taskID ‖ epoch)`.

**Implementation.** We use a hash-to-curve approximation: PA signs the
seed with Ed25519 and the receiver derives a deterministic shuffle from
`H(σ)`.  This is *not* a full RFC 9381 VRF and we mark it as such; the
public output is unforgeable but lacks the formal "VRF proof" structure.
Replacing it with a real RFC 9381 VRF is tracked separately.
