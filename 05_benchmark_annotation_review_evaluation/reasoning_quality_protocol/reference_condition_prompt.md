# Reference stage conditions

You receive one reference-only packet with a sample ID, visible evidence window,
reviewed stage label, and reviewed reference reasoning. Extract a compact,
auditable checklist of the evidence conditions that justify the reviewed label.
Do not use tested-model predictions or external information.

Identify key observable facts, stage-closure conditions, and missing or negative
evidence boundaries. Each condition must describe a distinct semantic requirement,
not a sentence copied from the reference. Allow alternative evidence-supported
paths, wording, and ordering. Cross-source details that are not essential to stage
closure may be optional. Do not require the model to repeat the reference's four
steps. For `stage_unclosed`, include the visible-evidence limitations that prevent
a stronger stage conclusion.

Return one JSON object:

```json
{
  "sample_id": "sample_000001",
  "stage_conditions": [
    {
      "condition_id": "condition_01",
      "description": "An auditable condition grounded in the supplied window.",
      "importance": "key",
      "evidence_refs": [{"edge_id": "sample_000001_edge_000001", "seq": 10}]
    }
  ]
}
```

Use sample-local unique condition IDs and `importance: key` or `optional`.
Include at least one key condition. Cite only visible evidence; an explicitly
absent-evidence boundary may have an empty reference list. Review the checklist
for grounding, duplicate conditions, and unjustified requirements before use.
Freeze the same checklist for both assistants and all tested models in an
evaluation. Never send it or the reference packet to a tested model.
