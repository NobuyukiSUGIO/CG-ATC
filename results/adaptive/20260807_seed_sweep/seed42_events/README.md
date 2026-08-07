# Layer-responsibility inputs (paper §V-D, Table "Empirical layer responsibility")

`layer_responsibility.csv` is the table in the paper. It is derived from the
per-message decision events of the CG-ATC receiver at `n=100`, `N=1000`, seed 42 —
the same configuration as the seed-42 sweep in the parent directory.

The raw `*.events.json` files are **not committed**: each is ~300 kB, over the
`check-added-large-files` limit in `.pre-commit-config.yaml`. Regenerate them, and
the CSV, with:

```sh
D=results/adaptive/20260807_seed_sweep/seed42_events
for wl in paraphrased_worm delayed_replay semantic_replay benign_broadcast \
          multihop_indirect_prompt_injection memory_poisoning_delayed \
          semantic_collusion valid_capability_harmful_semantics; do
  PYTHONPATH=. python benchmarks/run_adaptive_attacks.py \
    --workload "$wl" --baseline cg_atc \
    --num-agents 100 --num-messages 1000 --seed 42 \
    --save-events --output "$D/${wl}__cg_atc.json"
done

# the unauthorised benign_broadcast variant is a separate row in the paper
PYTHONPATH=. python benchmarks/run_adaptive_attacks.py \
  --workload benign_broadcast --baseline cg_atc \
  --num-agents 100 --num-messages 1000 --seed 42 \
  --broadcast-unauthorized --save-events \
  --output "$D/benign_broadcast_unauth__cg_atc.json"

PYTHONPATH=. python -m benchmarks.layer_stats --root "$D" \
  --csv-out "$D/layer_responsibility.csv"
```

`benchmarks/layer_stats.py` attributes each blocked message to exactly one layer
(crypto → capability → policy → containment, first match wins) and reports any
`blocked_reason` it does not recognise in an `unclassified` column rather than
folding it into a layer. That column is zero for this run.
