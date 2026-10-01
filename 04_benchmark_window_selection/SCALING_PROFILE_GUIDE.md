# Scaling profile guide

Default working directory:

```text
04_benchmark_window_selection
```

All paths below are relative to this directory.

## 1. Purpose

Window selection supports two candidate-mining profiles:

- lightweight smoke/reproduction mode
- larger selection mode for a constructed chain corpus

## 2. Default smoke profile

Current default values in `configs/default_config.json`:

```json
{
  "enable_dense_candidate_mining": true,
  "ranked_candidates_per_stage_per_scenario": 4,
  "dense_scan_stride": 250,
  "max_dense_windows_per_scenario": 800
}
```

This is meant to verify:

- `chain` discovery works
- stage seed construction works
- short-window mining works
- boundary signal classification works
- outputs and validation remain schema-compatible

The number and stage distribution of usable candidates depend on the input
chain corpus and the selection thresholds.

## 3. Larger selection profile

To prepare a larger candidate pool, use a profile such as:

```json
{
  "ranked_candidates_per_stage_per_scenario": 12,
  "dense_scan_stride": 25,
  "max_dense_windows_per_scenario": 12000
}
```

If the corpus is very large, raise `max_dense_windows_per_scenario`
gradually and monitor runtime.

## 4. Stage-quality rule remains the same

Scaling changes how many windows are considered. It should not change
the label semantics:

- `preparation`: request/probing/pre-trigger evidence, no visible
  active processing or observable consequence
- `execution`: active handler/runtime/process/file/network behavior,
  but no safely closed result consequence
- `result`: visible operation-to-effect consequence such as sensitive
  read, response/output flow, data transfer, callback, file/state effect
- `stage_unclosed`: attack-chain related but insufficient or fragmented
  evidence for a safe concrete stage closure

The implementation enforces this through `stage_boundary_gate`.
Score thresholds alone are not enough for `selected`: the
stage-specific gate must also pass.

## 5. Practical recommendation

Use the default config while developing or validating code changes.

Use a copied config for production-scale mining, for example:

```text
configs/production_candidate_pool_config.json
```

Then run:

```bash
python scripts/run_stage_reasoning_window_selection.py \
  --config configs/production_candidate_pool_config.json \
  --output-dir ./window_workdir
```

The handoff file remains:

```text
<work-dir>/annotation_ready_seed.jsonl
```
