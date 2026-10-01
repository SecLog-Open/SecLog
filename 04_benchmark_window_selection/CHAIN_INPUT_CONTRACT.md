# chain input contract

Default working directory:

```text
04_benchmark_window_selection
```

All paths below are relative to this directory.

## 1. Purpose

This document explains exactly how this workbench reads
`../01_dataset_construction/results/**/chain/` and which fields are treated as authoritative
for stage-window seed construction and visible-evidence scoring.

The goal is to keep the extraction method reproducible and extensible
without forcing later users to rediscover the `chain` schema by trial
and error.

## 2. Required source files per scenario

For each discovered scenario run, the builder expects:

- `../01_dataset_construction/results/<scenario>/<timestamp>/chain/backbone_chain.v1.json`
- `../01_dataset_construction/results/<scenario>/<timestamp>/chain/behavior_chain_dataset.v2.json`

The workbench scans `../01_dataset_construction/results/**/chain/` recursively and ignores
directories that do not contain both files.

## 3. Stable scenario identity

The builder does not trust timestamp-only run ids as the long-term
scenario identity.

It derives:

- `scenario_id` from the relative `results/.../chain` path
- `scenario_slug` from `scenario_id` by normalizing `/`, `:`, and spaces

This allows later handoff artifacts to remain stable even if a scenario
is rebuilt under a different timestamped run directory.

## 4. Fields read from `behavior_chain_dataset.v2.json`

Primary field:

- `spine`

Each `spine` edge is treated as the visible event unit for window
construction. The builder reads:

- `seq`
- `edge_id` if already present
- `relation`
- `subject`
- `object`
- `attrs.malicious`
- `attrs.raw_evt_type`
- `attrs.timestamp`
- `audit_context`
- `multisource_context.applog`
- `multisource_context.traffic`

These fields support:

- slicing windows by `seq`
- counting malicious edges
- relation-family scoring
- modality scoring for audit / applog / traffic
- compact `key_evidence_refs` export

## 5. Fields read from `backbone_chain.v1.json`

The builder reads three areas from the backbone file.

### 5.1 `edge_sequence`

Used to recover `edge_id` when `behavior_chain_dataset.v2.json` spine
does not carry it consistently.

The script builds a `seq -> edge_id` map and injects the missing
`edge_id` back into working edge rows before export.

### 5.2 `chain_summary.expression_clarity`

Used as the first-choice local fallback source for:

- `first_malicious_seq`
- `last_malicious_seq`

If they are missing or invalid, the builder falls back again to
`spine[*].attrs.malicious == true`.

### 5.3 `chain_summary.narrative_roles.annotated_edges`

Used to locate narrative-role anchors such as:

- preparation boundary end
- startup handoff
- entry bridge
- result anchor

The exact role names used for preparation and result logic are
config-driven through:

- `prep_end_roles`
- result-anchor role name currently fixed as `result_anchor`

## 6. Local stage-seed derivation

The builder derives window-level stage-span seeds from `chain` itself.

The algorithm currently uses:

1. first / last malicious seq
2. configured preparation-end roles
3. optional `result_anchor`
4. post-execution result-like relation walk
5. remaining attack-related gaps mapped to `stage_unclosed`

This keeps the method extensible while preserving the benchmark principle:
stage support must come from visible window evidence rather than global
scenario knowledge.

## 7. Focused window extraction

After stage spans are available, the builder creates candidate windows
from those spans.

Window widths are controlled by:

- `focused_window_max_edges`
- `preparation_focus_edges`
- `execution_focus_edges`
- `result_focus_edges`
- `stage_unclosed_focus_edges`

The stage-specific width is capped by `focused_window_max_edges`.

Focus policy:

- `preparation`: late slice near execution boundary
- `execution`: entry slice near execution start
- `result`: short anchor-focused slice
- `stage_unclosed`: boundary or post-gap focused slice

If `allow_full_span_variant=true`, the full stage span is also evaluated
when it differs from the focused window. Its selection status is determined
by the same scores and stage-boundary gate.

## 8. Dense ranked window mining

In addition to focused candidates, the builder generates short windows,
classifies their stage boundaries, and ranks them by visible evidence
quality within each stage and scenario. Dense mining is controlled by:

- `enable_dense_candidate_mining`
- `dense_window_lengths`
- `dense_scan_stride`
- `max_dense_windows_per_scenario`
- `ranked_candidates_per_stage_per_scenario`

The dense pass scans short windows over each `spine`, but it is not an
unbounded full Cartesian expansion. It combines:

- uniform stride sampling
- forced anchors near malicious edges
- forced anchors near execution / result / request relations

Then it classifies windows with visible boundary signals and keeps only
top-ranked windows per stage and scenario.

The default config is a lightweight validation profile. To consider more
candidates from a constructed chain corpus, raise:

- `ranked_candidates_per_stage_per_scenario`
- `max_dense_windows_per_scenario`

and lower `dense_scan_stride` if more exhaustive coverage is needed.
The stage boundary logic does not need to change for that expansion.

The boundary signals are:

- `request_or_payload_visible`
- `active_server_action_visible`
- `generic_outcome_visible`
- `strong_observable_outcome_visible`
- `stage_unclosed_corresponds_to_SU`

The intended label boundaries are:

- `preparation`: request/probing/pre-trigger evidence is visible, but
  active processing and strong outcome evidence are not safely closed
- `execution`: active handler/runtime/process/file/network behavior is
  visible, but strong outcome evidence is not safely closed
- `result`: operation evidence links to a visible consequence such as
  sensitive read, output/response flow, data transfer, or non-log
  file/state effect
- `stage_unclosed`: attack-chain related evidence exists, but the
  retained window is fragmented or insufficient for a safe concrete
  stage closure

Selected-window quality gate:

- every `selected` candidate must pass `stage_boundary_gate`
- the gate is stage-specific and stricter than the score thresholds
- candidates that score well but fail the boundary gate are demoted to
  `reserve` or `rejected`
- validation fails if any `selected` candidate has a failed gate

## 9. Visible-evidence support scoring

The builder scores candidate windows only from fields visible in the
window itself.

Config-driven relation / semantic families include:

- `result_tier_a_relations`
- `result_tier_b_relations`
- `generic_runtime_relations`
- `request_like_applog_semantic_types`
- `execution_signal_relations`
- `result_signal_relations`

Scoring outputs:

- `stage_feature_score`
- `stage_support_score`
- `log_quality_score`
- `future_annotatability_score`
- `context_length_risk_score`
- `duplicate_risk_score`

## 10. Annotation and review handoff

The key downstream handoff file is:

```text
<work-dir>/annotation_ready_seed.jsonl
```

This export contains:

- stable sample seed identity
- candidate stage seed
- window seq range
- evidence-limited rationale
- score summary
- relative source paths

Stage 05 consumes this file for strict blinding, evidence compression,
annotation, EWVAA review, human review, and benchmark export.
