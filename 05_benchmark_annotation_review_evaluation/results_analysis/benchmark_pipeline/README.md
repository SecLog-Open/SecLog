# Annotation and review pipeline methods

This package contains the reusable annotation, validation, grounding,
reviewer, repair, and final-candidate export steps used after strict blinding
and compact evidence construction.

Run the preparation command from `05_benchmark_annotation_review_evaluation/`:

```bash
python scripts/run_public_benchmark_pipeline.py \
  --window-seed /path/to/annotation_ready_seed.jsonl \
  --source-base /path/to/04_benchmark_window_selection \
  --work-dir /path/to/benchmark_workdir
```

That entry performs deterministic local preparation only. The modules under
`multiagent/` are explicit AI annotator/reviewer stages. The scripts under `steps/` validate
inputs, build the masked workbench, run an explicitly authorized annotation
trial, audit grounding, judge reasoning quality, and export a reviewed
candidate.

See [AI annotation and review](../../README.md#ai-annotation-and-review) for
the explicit API command and [Review UI workbench preparation](../../review_ui/README.md#workbench-inputs)
for `review_ui/prepare_workbench.py`, which assembles the completed annotation
run and compact evidence into a new human-review workbench.
