#!/usr/bin/env bash
# Run every (workload, baseline) pair from the spec §4 list and write
# results to results/adaptive/<YYYYMMDD>_run/<workload>_<baseline>.json.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

NUM_AGENTS="${NUM_AGENTS:-100}"
NUM_MESSAGES="${NUM_MESSAGES:-1000}"
SEED="${SEED:-42}"
OUT_ROOT="${OUT_ROOT:-results/adaptive/$(date -u +%Y%m%d)_run}"

WORKLOADS=(
  paraphrased_worm
  delayed_replay
  semantic_replay
  benign_broadcast
  multihop_indirect_prompt_injection
  memory_poisoning_delayed
  semantic_collusion
  valid_capability_harmful_semantics
)

BASELINES=(
  cg_atc
  baseline_mtls_nonce
  baseline_signed_jwt
  baseline_capability_central_audit
  baseline_anomaly_signed_logs
  baseline_opa_rego
  auth_only
  tls_oauth
  cap_no_audit
  anomaly_no_crypto
)

mkdir -p "$OUT_ROOT"

for wl in "${WORKLOADS[@]}"; do
  for bl in "${BASELINES[@]}"; do
    out="$OUT_ROOT/${wl}__${bl}.json"
    PYTHONPATH="$ROOT" python "$ROOT/benchmarks/run_adaptive_attacks.py" \
      --workload "$wl" \
      --baseline "$bl" \
      --num-agents "$NUM_AGENTS" \
      --num-messages "$NUM_MESSAGES" \
      --seed "$SEED" \
      --output "$out"
  done
done

echo
echo "All experiments written to: $OUT_ROOT"
echo "Generate paper tables with:"
echo "  python -m benchmarks.tables --root '$OUT_ROOT' --output '$OUT_ROOT/tables'"
