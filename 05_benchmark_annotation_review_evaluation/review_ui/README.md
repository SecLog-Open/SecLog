# Human Review UI

This directory contains the human-review tool used after AI annotation and
reviewer preparation. It reads a review workbench, displays visible evidence,
candidate reasoning, evidence references, validation findings, and diffs, and
stores review drafts and status in that workbench. Approved writeback updates
the annotation candidate file explicitly identified by the candidate index.

It must not modify the public `SecLog-Bench-216` files directly. Freeze a new
benchmark only after review is complete and validation passes.

## Workbench inputs

Run all commands below from `05_benchmark_annotation_review_evaluation/`.
After [AI annotation and review](../README.md#ai-annotation-and-review),
prepare a new workbench using the completed annotation run and its compact
annotation workbench:

```bash
python review_ui/prepare_workbench.py \
  --run-dir work/annotation/run \
  --masked-workbench work/benchmark/compact_annotation_workbench \
  --output-dir work/review_workbench
```

Replace the input paths with the directories from your annotation run. The
output directory must not already exist. Preparation performs no API calls.

Required inputs are:

- `final_candidate_gold.jsonl` in the annotation run;
- `masked_inputs/model_input.masked.jsonl`, `gold.masked.jsonl`, and
  `sample_index.masked.jsonl` in the compact annotation workbench;
- `prompt_packs/reviewer_annotation_prompts.weighted.masked.jsonl` in that
  same workbench;
- `id_maps/sample_id_map.json` when candidate and masked sample IDs differ.
  No map is needed when these IDs already match;
- `id_maps/edge_id_map.json` when candidate and evidence edge IDs differ.
  Maps use an `items` list of objects with `original` and `masked` fields.

Candidates must contain the four reference steps in order. Each evidence
reference contains only `edge_id` and integer `seq`; the pair must identify
an edge in that sample's full evidence after ID mapping. Preparation rejects
missing sample inputs, inconsistent stages, and unusable chain structures.
Missing claims or citations outside the compact view are flagged for review;
full evidence remains available in the UI. Auxiliary context is annotation
context, not evidence for tested-model scoring.

The command creates the candidate index, summary, review diagnostics, loader
configuration, and a local copy of the candidate records and evidence.
The loader configuration and candidate index use workbench-relative paths.
Controlled writeback targets only
the workbench's `final_candidate_gold.jsonl`, leaving the input annotation
run unchanged.

Reviewer, manual-review, and grounding records are used when available.
Missing review findings remain pending; preparation does not certify AI or
human approval. Every candidate starts as `not_reviewed`.

The command accepts any candidate count. Add `--expected-count 216` when
preparing a run that must contain exactly 216 candidates. The published
`SecLog-Bench-216` remains the separate, frozen evaluation dataset.

Review drafts use the four-function reference schema; tested-model outputs
remain free-form and are handled by the separate evaluation pipeline.

## Open the UI

Run the loader smoke check before opening Streamlit:

```bash
python review_ui/data_loader.py \
  --workbench-dir work/review_workbench \
  --smoke-check
```

After the check passes, start the UI with that workbench path:

```bash
streamlit run review_ui/app.py --server.port 8771 -- \
  --workbench-dir work/review_workbench
```

Review status, drafts, diffs, and writeback logs are stored under the selected
workbench. Writeback backups are stored in `.backups/` beside the target
candidate file. See [RUNBOOK.md](RUNBOOK.md) and [ROLLBACK.md](ROLLBACK.md).
