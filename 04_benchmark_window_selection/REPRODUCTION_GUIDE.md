# 04_benchmark_window_selection reproducible workflow

Code directory:

```text
04_benchmark_window_selection
```

All paths below are relative to this directory.

## 1. Purpose

This workflow reads `../01_dataset_construction/results/**/chain/` by default
and produces a stage-reasoning window-selection work directory for the
downstream benchmark steps.

It implements the benchmark construction logic at the window-selection
stage:

```text
chain
-> scenario stage-span seed
-> focused candidate windows
-> visible-evidence stage support scoring
-> selected / reserve / rejected windows
-> handoff seed for later strict-blind + compact + annotation flow
```

The builder reads the source chains and writes generated files to the
selected output directory.

## 2. Inputs

Required:

- `../01_dataset_construction/results/**/chain/backbone_chain.v1.json`
- `../01_dataset_construction/results/**/chain/behavior_chain_dataset.v2.json`

Auxiliary annotation context:

- `auxiliary_context/vulnerability_facts_seed/normalized/scenario_vulnerability_facts.annotation_context.v0.4.json`
- `auxiliary_context/vulnerability_facts_seed/raw_sources/` (complete source
  snapshots used to produce the normalized context)

`scenario_vulnerability_facts.json` contains the structured facts;
`generate_normalized_outputs.py` produces the normalized context from those
facts. The `raw_sources/` directory holds the supporting source records.

## 3. Outputs

The builder writes into the directory selected with `--output-dir`. Use a
user-chosen relative directory such as `./window_workdir` (or provide an
absolute path outside the source data tree).

```text
<work-dir>/
```

Main outputs:

- `<work-dir>/chain_inventory.jsonl`
- `<work-dir>/scenario_stage_seed.jsonl`
- `<work-dir>/candidate_windows.jsonl`
- `<work-dir>/selected_windows.jsonl`
- `<work-dir>/reserve_windows.jsonl`
- `<work-dir>/rejected_windows.jsonl`
- `<work-dir>/annotation_ready_seed.jsonl`
- `<work-dir>/manifest.json`
- `<work-dir>/summary.md`

Downstream handoff contract:

- `HANDOFF_TO_RELEASE_CONTRACT.md`
- `CHAIN_INPUT_CONTRACT.md`

## 4. Candidate-window policy

This workflow does not treat the full chain span as automatically
usable. It creates focused stage candidates from stage spans:

- `preparation`: use the late pre-trigger slice nearest the execution
  boundary
- `execution`: use an entry-focused slice near first malicious /
  semantic-entry behavior
- `result`: use a tail-focused slice near the result anchor or result
  tail
- `stage_unclosed`: use focused pre-gap or post-gap slices from spans
  that remain attack-related but do not safely close a concrete stage

The stage label here is a candidate label for downstream annotation and
evaluation.

When `allow_full_span_variant=true`, full-span candidates are also evaluated
with the same scores and stage-boundary gate as focused candidates.

The extraction and scoring method is config-driven. Relation families,
applog semantic families, focused window sizes, and selection
thresholds are all defined in `configs/default_config.json` rather than
being fixed in the downstream handoff contract.

The stage-span seed is derived from local `chain` evidence only.

## 5. Build

Run:

```bash
python scripts/run_stage_reasoning_window_selection.py \
  --output-dir ./window_workdir
```

Useful options:

```bash
python scripts/run_stage_reasoning_window_selection.py --help
python scripts/run_stage_reasoning_window_selection.py \
  --scenario-limit 4 --output-dir ./window_workdir
```

## 6. Validate

Run:

```bash
python scripts/validate_stage_reasoning_window_selection.py \
  --workbench-dir ./window_workdir
```

The sequential entry runs both build and validation:

```bash
python scripts/run_stage_reasoning_window_selection.py \
  --output-dir ./window_workdir
```

The validator checks:

- workbench files exist
- stage vocabulary is limited to `preparation`, `execution`, `result`,
  `stage_unclosed`
- selected/reserve/rejected counts match the candidate set
- score ranges are valid
- all source paths remain relative

## 7. Handoff to later release stages

`<work-dir>/annotation_ready_seed.jsonl` is the downstream handoff seed.

It is meant to feed later stages such as:

```text
strict-blind masking
compact evidence build
annotation_context join
annotator/reviewer prompt pack
EWVAA candidate reasoning
Review UI human review
benchmark export
```

It is the handoff input for annotation, review, and benchmark export.
