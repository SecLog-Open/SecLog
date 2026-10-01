# Full Workflow

This document is the complete end-to-end workflow for
`04_benchmark_window_selection`.

Code directory:

```text
04_benchmark_window_selection
```

All paths below are relative to this directory.

## 1. Goal

Build high-quality stage-reasoning evidence windows from
`../01_dataset_construction/results/**/chain/`, score whether the visible log window can
safely support a stage label, and export the seed material consumed by the
downstream benchmark preparation steps.

## 2. Inputs

Required per scenario:

- `../01_dataset_construction/results/<scenario>/<timestamp>/chain/backbone_chain.v1.json`
- `../01_dataset_construction/results/<scenario>/<timestamp>/chain/behavior_chain_dataset.v2.json`

Auxiliary annotation context:

- `auxiliary_context/vulnerability_facts_seed/normalized/scenario_vulnerability_facts.annotation_context.v0.4.json`
- `auxiliary_context/vulnerability_facts_seed/raw_sources/` (source records
  used by the annotation context)

The normalized file and raw source records provide context for annotation and
review; they are not model-visible stage evidence.

Chain input contract:

- `CHAIN_INPUT_CONTRACT.md`

## 3. Processing stages

### Stage A. Discover chain

Script:

```bash
python scripts/run_stage_reasoning_window_selection.py \
  --output-dir ./window_workdir
```

What it does:

- run an in-memory Python syntax check by default
- scan `../01_dataset_construction/results/**/chain`
- read `backbone_chain.v1.json`
- read `behavior_chain_dataset.v2.json`
- derive stable `scenario_id` from the `results/` path rather than from
  temporary timestamp-only ids
- run build and validation sequentially so the validation manifest always
  matches the current workbench outputs

Output:

- `<work-dir>/chain_inventory.jsonl`

### Stage B. Build scenario stage seed

Logic:

Derive the stage-span seed from local `chain` evidence only.

The derivation uses:

- first / last malicious seq
- preparation-end roles
- result-anchor role
- local post-execution result-like walk
- remaining attack-related gaps mapped to `stage_unclosed`

Output:

- `<work-dir>/scenario_stage_seed.jsonl`

### Stage C. Generate focused candidate windows

For each stage span:

- `preparation`: prefer a late pre-trigger focused slice
- `execution`: prefer an entry-focused slice near the execution start
- `result`: prefer a result-anchor or short post-action slice
- `stage_unclosed`: prefer focused pre-gap or post-gap slices

Optional:

- full-span variant when `allow_full_span_variant=true`

Dense ranked candidate mining:

- when `enable_dense_candidate_mining=true`, the builder also scans
  short visible windows across each `chain` spine
- default dense lengths are `2`, `3`, `5`, `6`, and `7`
- each window is classified by boundary signals rather than by global
  attack progress
- the top ranked candidates per stage and scenario are retained before
  final selected / reserve / rejected splitting

The default config is a lightweight validation profile. For more exhaustive
candidate coverage, increase:

- `ranked_candidates_per_stage_per_scenario`
- `max_dense_windows_per_scenario`

Reduce `dense_scan_stride` to sample windows more densely.

Output:

- `<work-dir>/candidate_windows.jsonl`

### Stage D. Score candidate quality

Each candidate is scored on:

- `stage_feature_score`
- `stage_support_score`
- `log_quality_score`
- `future_annotatability_score`
- `context_length_risk_score`
- `duplicate_risk_score`

Each candidate also gets:

- `stage_support_summary`
- `stage_boundary_rationale`
- `key_evidence_refs`

### Stage E. Split into selected / reserve / rejected

Current default thresholds come from `configs/default_config.json`.

Selected quality is gated twice:

- score thresholds must pass
- `stage_boundary_gate` must pass for the candidate's stage

This prevents a high-scoring but stage-misaligned window from becoming
`selected`; such windows are demoted to `reserve` or `rejected`.

Outputs:

- `<work-dir>/selected_windows.jsonl`
- `<work-dir>/reserve_windows.jsonl`
- `<work-dir>/rejected_windows.jsonl`

### Stage F. Export annotation handoff seed

Output:

- `<work-dir>/annotation_ready_seed.jsonl`

This file is the downstream seed for:

```text
strict-blind
compact evidence
annotation context join
prompt pack build
EWVAA candidate reasoning
Review UI
frozen release export
```

## 4. Extensibility points

The method supports configurable candidate mining over constructed chain
datasets.

Current configurable points in `configs/default_config.json`:

- `allow_full_span_variant`
- `enable_dense_candidate_mining`
- `dense_window_lengths`
- `dense_scan_stride`
- `max_dense_windows_per_scenario`
- `ranked_candidates_per_stage_per_scenario`
- `focused_window_max_edges`
- stage-specific focused window sizes
- `prep_end_roles`
- `result_tier_a_relations`
- `result_tier_b_relations`
- `generic_runtime_relations`
- `request_like_applog_semantic_types`
- `execution_signal_relations`
- `result_signal_relations`
- selection thresholds

Configuration can:

- change result-like relation families
- change applog semantic families treated as request-like support
- change which relations count as execution or result support
- change stage boundary focus sizes
- tighten or relax selected/reserve thresholds
- plug in different stage-window extraction policies without changing
  the downstream handoff contract

## 5. Validation

Run:

```bash
python scripts/run_stage_reasoning_window_selection.py \
  --output-dir ./window_workdir
```

Validator checks:

- required outputs exist
- legal stage vocabulary only
- selected/reserve/rejected counts match the candidate set
- score ranges are valid
- source paths stay relative
- annotation-ready seed is a subset of selected + reserve

If you need the split steps separately, you can still run:

```bash
python scripts/build_stage_reasoning_window_selection.py \
  --output-dir ./window_workdir
python scripts/validate_stage_reasoning_window_selection.py \
  --workbench-dir ./window_workdir
```

## 6. Downstream benchmark

This code unit provides window extraction and stage-candidate selection for
`chain` outputs. The frozen benchmark is available at:

```text
../SecLog-Bench-216
```
