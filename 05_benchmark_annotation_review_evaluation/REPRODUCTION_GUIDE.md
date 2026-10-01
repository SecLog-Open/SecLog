# Benchmark annotation, review, and evaluation workflow

This guide describes the benchmark annotation, review, inference, and scoring
workflow.

## End-to-end handoff

```text
<window_workbench>/annotation_ready_seed.jsonl
  -> canonical annotation workspace
  -> strict blinding
  -> compact evidence and annotation context
  -> AI annotator candidate reasoning
  -> AI reviewer, validation, and grounding audit
  -> Review UI workbench preparation
  -> Human Review UI and controlled writeback
  -> frozen SecLog-Bench-216
  -> tested-model inference
  -> local stage and reasoning-quality scoring
```

Run `scripts/run_public_benchmark_pipeline.py` for the deterministic handoff.
It performs no API call. Annotator, reviewer, tested-model inference, and
reasoning-quality assistants are started through explicit API-enabled
commands.

After annotation and AI review, run the following commands from
`05_benchmark_annotation_review_evaluation/`, using your actual input paths:

```bash
python review_ui/prepare_workbench.py \
  --run-dir work/annotation/run \
  --masked-workbench work/benchmark/compact_annotation_workbench \
  --output-dir work/review_workbench
python review_ui/data_loader.py \
  --workbench-dir work/review_workbench \
  --smoke-check
```

The output must be a new directory. The workbench contains a local candidate
copy and starts with all samples `not_reviewed`. Missing AI review findings
remain pending. Follow [review_ui/RUNBOOK.md](review_ui/RUNBOOK.md) for human
review and controlled writeback. Add `--expected-count 216` to preparation
when exactly 216 candidates are required; other annotation sets may use
different counts.

The benchmark is one unified 216-sample dataset with four labels and 54
samples per label. Join every prompt, prediction, label, evidence window, and
reference chain by the contiguous `sample_id`.

Use `scripts/validate_public_benchmark.py` before evaluation. Use
`evaluation/run_benchmark_inference.py`, prediction normalization,
`evaluate_stage_reasoning_predictions.py`, and the scripts documented under
`reasoning_quality_protocol/` for evaluation.
