# Human review runbook

1. Build a compact annotation workbench with
   `scripts/run_public_benchmark_pipeline.py`.
2. Run the annotator and reviewer methods explicitly.
3. Run `review_ui/prepare_workbench.py` with the annotation run, compact
   annotation workbench, and a new output directory as shown below.
4. Run `review_ui/data_loader.py --smoke-check` against the workbench.
5. Open `review_ui/app.py` through Streamlit and inspect every candidate.
6. Save drafts first. Apply controlled writeback only after the displayed diff
   and validation result are accepted.
7. Re-run validation and export a frozen benchmark into a new
   directory, leaving the current `SecLog-Bench-216` unchanged.

Review state is workbench-local. The final 216 labels and reviewed reference
reasoning chains are read from the benchmark data files.

Run the commands from `05_benchmark_annotation_review_evaluation/`, and pass
the prepared directory through `--workbench-dir` for every Review UI command.

```bash
python review_ui/prepare_workbench.py \
  --run-dir work/annotation/run \
  --masked-workbench work/benchmark/compact_annotation_workbench \
  --output-dir work/review_workbench
python review_ui/data_loader.py \
  --workbench-dir work/review_workbench \
  --smoke-check
streamlit run review_ui/app.py --server.port 8771 -- \
  --workbench-dir work/review_workbench
```

Use the actual annotation-run and compact-workbench paths. The output
directory must not exist. Preparation leaves every sample `not_reviewed`;
missing AI review findings remain pending. Add `--expected-count 216` only
when the annotation run is expected to contain exactly 216 candidates.
See [Workbench inputs](README.md#workbench-inputs) for required input files.
