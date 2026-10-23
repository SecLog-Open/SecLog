# Benchmark window selection

Purpose: select evidence windows from stage-02 attack-chain products for later
blind annotation and review.

```bash
cd 04_benchmark_window_selection
python scripts/run_stage_reasoning_window_selection.py \
  --results-root ../01_dataset_construction/results \
  --output-dir ./window_workdir
```

Pass `--output-dir` to choose the generated workbench directory.

The default `results_root` in `configs/default_config.json` resolves to the
sibling path `../01_dataset_construction/results`, matching the output layout
of the public dataset-construction stage. Use `--results-root` when consuming
a separately mounted constructed dataset.

The handoff consumed by stage 05 is:

```text
window_workdir/annotation_ready_seed.jsonl
```

The stage directory name is not hard-coded in the implementation.  Relative
source paths are resolved from this directory, and absolute input/output
paths may be supplied explicitly.

The method assets include the complete vulnerability-facts seed used by the
context checks: both `raw_sources/` snapshots and `normalized/` outputs.

See the [full workflow](FULL_WORKFLOW.md) for inputs, build options,
validation, and the handoff to annotation and review.
