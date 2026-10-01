# Dataset release generation

Purpose: export existing chain products into the documented
`dataset_release_v1` schema. The exporter writes the requested release to the
caller-selected output root.

Run commands from `03_dataset_release_generation/`. Replace `<scenario>`
and `<timestamp>` with a run completed by stage 02. Use a separate output
root for each single-scenario export.

Single-scenario release-only entry:

```bash
python results_analysis/pipeline/build_release_scenario.py \
  --scenario-dir "../01_dataset_construction/results/<scenario>/<timestamp>" \
  --scenario-id "<scenario>" \
  --release-root ../work/dataset_release_single
```

All-scenario release-only entry:

```bash
python results_analysis/pipeline/build_release_all_scenarios.py \
  --results-root ../01_dataset_construction/results \
  --release-root ../work/dataset_release_all
```

The all-scenario entry selects the newest complete timestamp run for each
scenario. Readiness requires a backbone, dataset, dataset metadata, and
completed enrichment. An explicitly completed no-unit enrichment state may
have no context-edge file; a skipped enrichment state is not ready.

The exporter is a pure downstream derivation: it reads `chain/`, writes only
the requested release root, and must not update `raw`, `index`, or `chain`.
Schemas are under `schemas/`; dataset format documentation is under `docs/`.

The output tree contains `manifest.json`, `shared/scenarios/<scenario_slug>/`,
`settings/`, and `schemas/`. The manifest records the successfully exported
scenarios and any errors. Stage-reasoning construction artifacts are also
generated under `benchmarks/stage_reasoning/` when that export succeeds.

`04_benchmark_window_selection/` reads the stage-02 `chain/` products from
the constructed runs; its `--results-root` is not the exported `settings/`
tree. For model evaluation, follow
`05_benchmark_annotation_review_evaluation/` with the frozen
`SecLog-Bench-216/` data.
