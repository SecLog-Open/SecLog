# Reasoning-quality protocol

Reasoning quality is evaluated after stage prediction and after the tested
model identity has been replaced with a blind identifier.

1. Export reference-only packets with `prepare_reasoning_quality_inputs.py
   --reference-only`. Use `reference_condition_prompt.md` to prepare and review
   a common stage-condition checklist independently of model predictions.
2. `prepare_reasoning_quality_inputs.py --stage-conditions ...` locally extracts
   reasoning units and builds identity-blinded assistant packets with that checklist.
3. Two independent evidence-bound assistants process the same packets with
   `evidence_bound_evaluation_assistant_prompt.md` and return objects matching
   `assistant_output.schema.json`.
4. `aggregate_reasoning_assistant_checks.py` averages numeric judgments,
   recomputes SCC from key-condition coverage (`full=1`, `partial=0.5`,
   `none=0`), retains risk flags conservatively, and flags absolute
   disagreements greater than `0.30` for human adjudication.
5. `score_reasoning_quality.py` computes SRP, SCC, SRF1, the fixed reliability
   decision, and TT/TF/FT/FF locally.

The fixed reliability thresholds are `SRP >= 0.33`, `SCC >= 0.50`, and
`SRF1 >= 0.45`, with hard failure on a critical evidence error or invalid
evidence reference. Evaluation assistants never assign the final reliability
label; the local scorer applies these thresholds.

See [the evaluation commands](../README.md#post-hoc-reasoning-quality) for packet
preparation, assistant outputs, adjudication records, and scoring. The shared
condition checklist is reused across models. Only aggregates with no unresolved
disagreements are eligible for formal scoring; unresolved preview aggregates
are not.
