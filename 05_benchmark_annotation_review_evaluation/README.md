# Benchmark annotation, review, and evaluation

Purpose: consume stage-04 windows, construct strict-blind compact prompts,
support AI annotation/reviewer methods and human review, and score predictions.

**Evidence-Guided Risk Review** checks candidate reasoning for evidence risks
and prioritizes human review. The `EWVAA` prefix in script identifiers and
environment variables refers to this annotation and review workflow.

Run the commands below from `05_benchmark_annotation_review_evaluation/`.
Replace `/path/to/...` with the locations selected for your inputs and outputs.

## Deterministic benchmark handoff

The following command performs no API calls:

```bash
python scripts/run_public_benchmark_pipeline.py \
  --window-seed /path/to/window_workbench/annotation_ready_seed.jsonl \
  --source-base /path/to/04_benchmark_window_selection \
  --work-dir /path/to/benchmark_workdir
```

It creates the following directories under the selected work directory:

```text
canonical_benchmark
  -> strict_blind_benchmark
  -> compact_annotation_workbench
```

## AI annotation and review

- `results_analysis/benchmark_pipeline/`: annotation, validator, reviewer,
  grounding, judge, repair, and final-candidate methods;
- `results_analysis/release/`: strict blinding, compact workbench, API trial,
  reasoning-quality judgment, and benchmark-export methods;
- `review_ui/`: human inspection, validation, diff, status, and controlled
  writeback code;
- `reasoning_quality_protocol/`: evidence-bound evaluation protocol.

API execution is not part of the deterministic handoff. Environment-based API
configuration additionally requires `--use-env-api-config`.

After deterministic preparation, run the two-role AI annotation/reviewer
pipeline explicitly:

```bash
python results_analysis/benchmark_pipeline/multiagent/run_multiagent_gold_pipeline_default.py \
  --canonical-benchmark-root /path/to/benchmark_workdir/canonical_benchmark \
  --workbench-dir /path/to/benchmark_workdir/compact_annotation_workbench \
  --output-root /path/to/benchmark_workdir/annotation_runs
```

The wrapper collects separate annotator and reviewer API settings
interactively. `--use-env-api-config` is required before it will read API
configuration from the environment. Validator, grounding-audit, reviewer,
and final-candidate export steps are executed in sequence; a failed gate stops
the later stages.

Prepare the [Review UI workbench](review_ui/README.md) from the completed
annotation run and its compact annotation evidence:

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
directory must not already exist. The command creates a local candidate copy,
evidence, indexes, review diagnostics, and relative-path loader configuration.
Every candidate starts as `not_reviewed`; missing AI findings remain pending.
Add `--expected-count 216` when exactly 216 candidates are expected. Newly
constructed annotation sets may contain other sample counts.

After the loader check passes, follow the
[human review runbook](review_ui/RUNBOOK.md) to inspect candidates and apply
controlled writeback to the workbench-local candidate file.

## Validate and run SecLog-Bench-216

Validate the unified 216-sample dataset first:

```bash
python scripts/validate_public_benchmark.py
```

All samples use one contiguous public ID namespace from `sample_000001`
through `sample_000216`.

Replace `your-model-name` with the model identifier supported by your provider.
Run a no-network inference preflight (real calls require `--call-api`):

```bash
python evaluation/run_benchmark_inference.py \
  --prompt-pack ../SecLog-Bench-216/data/prompt_pack.jsonl \
  --model your-model-name \
  --output /path/to/model_run/raw_responses.jsonl
```

Run the actual API inference after setting the selected key environment
variable. The output path must be outside the release tree:

```bash
export OPENAI_API_KEY="<key>"
python evaluation/run_benchmark_inference.py \
  --prompt-pack ../SecLog-Bench-216/data/prompt_pack.jsonl \
  --model your-model-name \
  --output /path/to/model_run/raw_responses.jsonl \
  --call-api
```

Normalize the run-local responses:

```bash
python evaluation/normalize_stage_reasoning_predictions.py \
  --input /path/to/model_run/raw_responses.jsonl \
  --output /path/to/model_run/predictions.jsonl
```

Prompts request evidence-referenced reasoning with a freely chosen organization;
the reference chain's four-step structure is not required. Normalization also
accepts empty reasoning so unsuccessful responses remain evaluable.
Responses without a parseable
stage are recorded in `invalid_outputs.jsonl` and retained as an invalid-stage
row so the 216-sample join remains complete. Stage evaluation counts invalid
stages as incorrect, while reasoning-quality scoring assigns zero precision
when no verifiable reasoning unit is available.

Score stage prediction and reference/evidence alignment:

```bash
python evaluation/evaluate_stage_reasoning_predictions.py \
  --gold ../SecLog-Bench-216/data/gold_labels.jsonl \
  --reference-chains ../SecLog-Bench-216/data/reference_reasoning_chains.jsonl \
  --model-input ../SecLog-Bench-216/data/evidence_windows.jsonl \
  --sample-index ../SecLog-Bench-216/data/sample_index.jsonl \
  --predictions /path/to/model_run/predictions.jsonl \
  --output-dir /path/to/new_eval_output
```

The evaluator accepts both the canonical construction schema and the
`SecLog-Bench-216` schema.

Its reference-evidence overlap and quadrant fields are diagnostic only. The
formal reasoning-quality values and TT/TF/FT/FF decisions come from the
post-hoc scorer below.

## Post-hoc reasoning quality

Run the commands from this directory. First export reference-only packets:

```bash
python evaluation/prepare_reasoning_quality_inputs.py \
  --reference-only \
  --evidence-windows ../SecLog-Bench-216/data/evidence_windows.jsonl \
  --reference-chains ../SecLog-Bench-216/data/reference_reasoning_chains.jsonl \
  --output-dir /path/to/reasoning_quality_run
```

Use `reasoning_quality_protocol/reference_condition_prompt.md` with each
`reference_condition_packets.jsonl` record to prepare a stage-condition
checklist. Review it against the visible evidence and reference reasoning and
save one object per sample to `/path/to/stage_conditions.jsonl`. Prepare this
checklist independently of model predictions and reuse it for every tested
model. Reference packets and conditions are evaluator inputs, not tested-model
prompts.

Build identity-blinded assistant packets using the shared checklist:

```bash
python evaluation/prepare_reasoning_quality_inputs.py \
  --predictions /path/to/model_run/predictions.jsonl \
  --evidence-windows ../SecLog-Bench-216/data/evidence_windows.jsonl \
  --reference-chains ../SecLog-Bench-216/data/reference_reasoning_chains.jsonl \
  --stage-conditions /path/to/stage_conditions.jsonl \
  --output-dir /path/to/reasoning_quality_run
```

Give the same `assistant_packets.jsonl` records to two independent assistants
with `reasoning_quality_protocol/evidence_bound_evaluation_assistant_prompt.md`.
Save their outputs as `assistant_1.jsonl` and `assistant_2.jsonl`, following
`reasoning_quality_protocol/assistant_output.schema.json`. Each output must
preserve the sample, blind model, reasoning-unit, and condition IDs from its
packet. Use different `assistant_id` values for the two assistants.

```bash
python evaluation/aggregate_reasoning_assistant_checks.py \
  --assistant-packets /path/to/reasoning_quality_run/assistant_packets.jsonl \
  --assistant-checks /path/to/assistant_1.jsonl \
  --assistant-checks /path/to/assistant_2.jsonl \
  --output-dir /path/to/reasoning_quality_run/aggregated
```

An absolute scalar difference greater than `0.30` requires human adjudication.
The aggregator returns exit code `2` while such items remain unresolved.
Inspect `disagreement_report.json`, review the relevant visible evidence, and
save one record per reviewed item:

```json
{"sample_id":"sample_000001","field":"stage_condition:condition_01","value":0.5}
{"sample_id":"sample_000001","reasoning_unit_id":"unit_01","field":"evidence_support_score","value":0.8}
```

The other claim scalar field is `stage_condition_alignment`. Claim values
must be finite numbers in `[0,1]`; condition values must be `0`, `0.5`, or `1`.
Rerun the aggregation command with
`--adjudications /path/to/adjudications.jsonl`. Risk flags remain conservative
OR decisions. The scorer refuses aggregates with unresolved disagreements,
including previews produced with `--allow-unadjudicated`.

Score the completed aggregates:

```bash
python evaluation/score_reasoning_quality.py \
  --gold ../SecLog-Bench-216/data/gold_labels.jsonl \
  --predictions /path/to/model_run/predictions.jsonl \
  --claim-checks /path/to/reasoning_quality_run/aggregated/claim_checks.aggregated.jsonl \
  --closure-checks /path/to/reasoning_quality_run/aggregated/closure_checks.aggregated.jsonl \
  --output-dir /path/to/reasoning_quality_run/scored
```

The scorer computes SCC from the non-optional checklist conditions using
`full = 1.0`, `partial = 0.5`, and `none = 0.0`. The assistant total is an
audit value; fixed local scoring applies the reliability thresholds and risk
gates.
