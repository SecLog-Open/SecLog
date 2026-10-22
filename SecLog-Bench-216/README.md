# SecLog-Bench-216

Public, labeled evaluation benchmark for window-level attack-stage reasoning over strict-blind multi-source evidence.

## Contents

- `data/evidence_windows.jsonl`: 216 compressed multi-source evidence windows visible to a tested model.
- `data/gold_labels.jsonl`: human-confirmed stage labels.
- `data/reference_reasoning_chains.jsonl`: human-confirmed reference reasoning chains and evidence references. The bundled references use four review functions; tested-model reasoning may use its own organization.
- `data/sample_index.jsonl`: ordering, stage, supportability tier, and window metadata.
- `data/prompt_pack.jsonl`: model-facing prompts used for stage prediction.
- `data/dataset_manifest.json`: unified public dataset manifest.
- `manifest.json`: benchmark metadata and data-file hashes used by validation.
- `schemas/`: label, output, and evaluation contracts.

## Label distribution

| Label | Samples |
| --- | ---: |
| preparation | 54 |
| execution | 54 |
| result | 54 |
| stage_unclosed | 54 |
| **Total** | **216** |

`stage_unclosed` denotes attack-related evidence that does not safely support a concrete preparation, execution, or result judgment in the visible window; it is not a benign label.

## Reference reasoning

Each reference chain follows four functions: evidence scope, observable facts, cross-source/behavioral relation, and final stage judgment. Evidence references use the model-visible `edge_id` and `seq` coordinates.

Sample identifiers form a single contiguous namespace from
`sample_000001` through `sample_000216`.
Visible edge identifiers are also sample-local and follow
`<sample_id>_edge_<six-digit-position>` consistently in evidence, prompts,
and reference chains.

## Intended use

Use `data/prompt_pack.jsonl` or construct equivalent prompts from
`data/evidence_windows.jsonl`. Prompts request a stage prediction and
evidence-referenced reasoning. Empty or invalid responses are retained for
evaluation. Join predictions to labels and references only by `sample_id`.
Do not expose labels or reference chains to the tested model during inference.

The matching prompt, normalization, evaluation, and reasoning-quality code is
under `../05_benchmark_annotation_review_evaluation/evaluation/`.  Its
evaluator accepts this public schema directly when `--reference-chains` is
provided.

## License

This benchmark is licensed under [CC BY 4.0](LICENSE).
Copyright (c) 2026 SecLog contributors.
