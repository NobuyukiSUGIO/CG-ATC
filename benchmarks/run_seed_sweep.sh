#!/usr/bin/env bash
# Repeat the full (workload x baseline) adaptive sweep over several seeds, so the
# seed-dependence claim in the paper (§V-A) can be regenerated.
#
# Writes results/adaptive/<YYYYMMDD>_seed_sweep/seed<NN>/<workload>__<baseline>.json
# Aggregate with:  PYTHONPATH=. python -m benchmarks.seed_stats --root <OUT_ROOT>
#
# The venv must be activated: this script invokes `python`, not `python3`.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

NUM_AGENTS="${NUM_AGENTS:-100}"
NUM_MESSAGES="${NUM_MESSAGES:-1000}"
SEEDS="${SEEDS:-42 43 44 45 46 47 48 49 50 51}"
OUT_ROOT="${OUT_ROOT:-results/adaptive/$(date -u +%Y%m%d)_seed_sweep}"

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

total=0
for seed in $SEEDS; do
  out_dir="$OUT_ROOT/seed$seed"
  mkdir -p "$out_dir"
  for wl in "${WORKLOADS[@]}"; do
    for bl in "${BASELINES[@]}"; do
      PYTHONPATH="$ROOT" python "$ROOT/benchmarks/run_adaptive_attacks.py" \
        --workload "$wl" \
        --baseline "$bl" \
        --num-agents "$NUM_AGENTS" \
        --num-messages "$NUM_MESSAGES" \
        --seed "$seed" \
        --output "$out_dir/${wl}__${bl}.json" > /dev/null
      total=$((total + 1))
    done
  done
  echo "seed $seed done ($total runs so far)"
done

echo
echo "$total runs written to: $OUT_ROOT"
echo "Aggregate with:"
echo "  PYTHONPATH=. python -m benchmarks.seed_stats --root '$OUT_ROOT'"
