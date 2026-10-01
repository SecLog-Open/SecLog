# Review UI batch workflow

This workflow prepares reviewed records for `SecLog-Bench-216` after AI
annotation and human review.

## Prepare a workbench

Run the deterministic stage-04 to stage-05 handoff from
`05_benchmark_annotation_review_evaluation/`:

```bash
python scripts/run_public_benchmark_pipeline.py \
  --window-seed /path/to/window_workbench/annotation_ready_seed.jsonl \
  --source-base ../04_benchmark_window_selection \
  --work-dir /path/to/benchmark_workdir
```

This step performs no API calls. It generates canonical, strict-blind, and
compact annotation trees under the selected work directory. Then run
[AI annotation and review](../README.md#ai-annotation-and-review), and prepare
the workbench from the resulting candidates and evidence:

```bash
python review_ui/prepare_workbench.py \
  --run-dir work/annotation/run \
  --masked-workbench work/benchmark/compact_annotation_workbench \
  --output-dir work/review_workbench
python review_ui/data_loader.py \
  --workbench-dir work/review_workbench \
  --smoke-check
```

Use your actual annotation-run and compact-workbench paths. The output
directory must not exist. All samples start as `not_reviewed`, and missing
AI review findings remain pending. Add `--expected-count 216` when exactly
216 candidates are expected. See [Workbench inputs](../review_ui/README.md#workbench-inputs)
for required files.

## Inspect and review

The review implementation is under `review_ui/`. Check its CLI and run the
read-only regression test before enabling any writeback operation:

```bash
python review_ui/batch_review.py --help
python review_ui/regression_check.py \
  --workbench-dir work/review_workbench
```

Review one masked sample at a time. Validate the masked sample identifier,
stage, event keys, four-step chain schema, and evidence references before
accepting a draft. The UI defaults to writeback disabled; any writeback
requires an explicit target and confirmation.
