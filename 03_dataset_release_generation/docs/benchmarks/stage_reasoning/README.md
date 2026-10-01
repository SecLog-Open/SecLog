# Stage-reasoning benchmark boundary

This stage exports dataset-side stage labels and evidence artifacts used by
benchmark construction.

The generated output root can contain
`benchmarks/stage_reasoning/data/model_input.jsonl`, `gold.jsonl`, and
`sample_index.jsonl`. These are aligned construction artifacts for the
exported scenarios. Their sample count depends on those scenarios.

The evaluation dataset is the sibling `SecLog-Bench-216/` package. It is one
unified 216-sample unit,
with contiguous IDs from `sample_000001` through `sample_000216` and 54
samples for each of the four stage labels.

Use `04_benchmark_window_selection/` for window selection and
`05_benchmark_annotation_review_evaluation/` for blinding, annotation,
review, inference, and scoring methods.

Model evaluation uses `SecLog-Bench-216/data/prompt_pack.jsonl`; reference labels
and reasoning are consumed by scoring, not supplied to the evaluated model.
