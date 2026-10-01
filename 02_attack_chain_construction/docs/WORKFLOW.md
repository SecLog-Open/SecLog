# Workflow

## Scope

This stage constructs attack chains for dataset export and benchmark window selection.

`raw/ + index/ -> extract -> backbone -> enrich -> dataset`

The outputs are written under each run directory:

- `chain/audit_triples.core.v1.jsonl`
- `chain/backbone_chain.v1.json`
- `chain/behavior_context_edges.v0.jsonl`
- `chain/behavior_chain_dataset.v2.json`
- `chain/behavior_chain_dataset.v2.meta.json`

## Paths

Run the commands from `02_attack_chain_construction/`. The input root is
`../01_dataset_construction/results`; generated status and target files in
the examples use `../work/chain/`, inside the release root. Replace
`<scenario>` and `<timestamp>` with a captured run's directory names.

## Read-Only Scan

```bash
python scripts/scan_chain_status.py \
  --report-path ../work/chain/chain_status_report.json
```

This reads the run directories without changing them and writes the selected
status report. The report lists the presence of raw logs, indexes, and chain
artifacts; it is not a semantic validation of their contents.

## Single-Stage Commands

The input must be a timestamp run directory such as
`../01_dataset_construction/results/<scenario>/<timestamp>`, containing
`raw/sysdig/` and `index/`. Application and traffic context are joined from
the corresponding capture indexes when available.

### 1. Extract

```bash
python results_analysis/pipeline/run_chain_pipeline.py \
  --scenario-dir "../01_dataset_construction/results/<scenario>/<timestamp>" \
  --run-mode adaptive-candidate --only-extract
```

### 2. Backbone

```bash
python results_analysis/pipeline/run_chain_pipeline.py \
  --scenario-dir "../01_dataset_construction/results/<scenario>/<timestamp>" \
  --run-mode adaptive-candidate --only-backbone
```

### 3. Enrich

```bash
python results_analysis/pipeline/enrich_behavior_context_v0.py \
  --scenario-dir "../01_dataset_construction/results/<scenario>/<timestamp>" \
  --backbone-guard-threshold 5000
```

### 4. Dataset

```bash
python results_analysis/pipeline/run_chain_pipeline.py \
  --scenario-dir "../01_dataset_construction/results/<scenario>/<timestamp>" \
  --run-mode adaptive-candidate --only-dataset
```

## Full Single-Run Pipeline

```bash
python results_analysis/pipeline/run_chain_pipeline.py \
  --scenario-dir "../01_dataset_construction/results/<scenario>/<timestamp>" \
  --run-mode adaptive-candidate \
  --backbone-guard-threshold 5000
```

This is the same entry used by the batch chain builders.

The guard skips enrichment when the backbone exceeds the specified edge
count. Such a run is incomplete for stage-03 export. Inspect
`chain/behavior_context_summary.v0.json`; when resources permit, rerun with
an appropriate threshold, or `--backbone-guard-threshold 0` to disable it.

## Batch Build For Missing Chain Runs

```bash
python scripts/build_missing_chain_all_timestamps.py \
  --targets-path ../work/chain/missing_chain_targets.json \
  --report-path ../work/chain/build_missing_chain_report.json
```

This scans all timestamp runs under `../01_dataset_construction/results`,
writes a target list, constructs missing or incomplete chains, and updates
the progress report after each run.

Add these options to the command as needed:

- `--dry-run`: write only the target list, without running construction.
- `--limit 3`: process at most three selected runs.
- `--results-root ../01_dataset_construction/results`: select the input root.
- `--shard-count 3 --shard-index 0`: process one stable shard.
- `--exclude-run "<scenario>/<timestamp>"`: omit a specified run.
- `--targets-file ../work/chain/custom_targets.json`: read a target list with
  a top-level `targets` array and a `run_dir` in each row.

## Low-Memory Stagewise Serial Build

The stagewise builder runs one timestamp at a time and uses separate
extract, backbone, enrich, and dataset processes. Stages with existing
outputs are skipped.

Generate the target list before running the serial builder:

```bash
python scripts/build_missing_chain_all_timestamps.py --dry-run \
  --targets-path ../work/chain/missing_chain_targets.json \
  --report-path ../work/chain/build_missing_chain_report.json

python scripts/build_missing_chain_stagewise_serial.py \
  --targets-file ../work/chain/missing_chain_targets.json \
  --report-path ../work/chain/stagewise_progress.json

python scripts/scan_chain_status.py \
  --report-path ../work/chain/chain_status_report.json
```

## Downstream Export

The resulting chains are consumed by `03_dataset_release_generation`
and `04_benchmark_window_selection`. See
`../03_dataset_release_generation/README.md` for exporting a completed
chain; `--with-release` also requires that sibling stage directory.

