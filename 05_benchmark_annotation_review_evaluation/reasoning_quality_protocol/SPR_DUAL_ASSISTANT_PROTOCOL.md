# Reasoning-quality dual-assistant protocol

## Scope

The tested model sees only `prompt_pack.jsonl` or the equivalent visible
evidence window. Labels, reference reasoning, auxiliary annotation context,
and model identity mappings are not model input.

Prepare shared reference conditions from visible evidence and reviewed reference
reasoning using `reference_condition_prompt.md`. Review and freeze them before
assistant scoring, independently of tested predictions; reuse them for all models.

After prediction, the tested model name is replaced by a run-local
`blind_model_id`. Local conservative rules split its explanation into
independently checkable reasoning units. Two independent evidence-bound
assistants receive the same blinded packet, reference chain, criteria, and
output schema.

## Assistant checks

Each reasoning unit is checked for visible-evidence support, citation
validity, contradiction, hidden-evidence dependence, overstatement, and stage
condition alignment. The sample closure check measures whether the explanation
covers the shared reference-grounded conditions and whether it respects
the visible-evidence boundary.

## Local aggregation

Scalar judgments are averaged. An absolute assistant difference greater than
`0.30` on any claim or key-condition item is a human-adjudication item. Risk
flags are aggregated conservatively: a severe unit error, contradiction,
hidden/out-of-window evidence dependence, or invalid evidence reference remains
active if either assistant reports it. Invalid citations also undergo local
visible-evidence validation. Unresolved disagreements block formal scoring.

SCC is recomputed locally from the non-optional checklist conditions using
`full = 1.0`, `partial = 0.5`, and `none = 0.0`. The assistant-provided total
coverage score is retained only as an audit cross-check.

SRP uses the evidence-support and risk rubric for substantive reasoning units.
Its stage-contribution factors are `1.0` for full condition coverage, `0.65`
for partial coverage, and `0.35` for a local fact only. These factors are
distinct from the SCC coverage values. Empty reasoning has SRP zero.

The assistants do not decide final reliability. Local code computes SRP, SCC,
`SRF1 = 2 * SRP * SCC / (SRP + SCC)`, applies the fixed thresholds, and derives
the TT/TF/FT/FF prediction-reasoning quadrant. Model-level SRP and SCC are
sample means; model-level SRF1 is their harmonic mean, not a mean of sample
SRF1 values.

The selected run directory receives the assistant checks and adjudication
records for that evaluation run.
