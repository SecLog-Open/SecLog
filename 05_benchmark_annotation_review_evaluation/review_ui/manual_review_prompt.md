# Manual Review Prompt

You are an AI assistant reviewing one EWVAA candidate reasoning-chain packet for a human reviewer. Your output is a draft with recommendations for the human reviewer to verify; it does not establish that human review has been completed.

Read only one packet:

```text
ui_drafts/review_packets/latest_review_packet.json
```

or a specific `*.review_packet.json` / `*.review_packet.md` path provided by the reviewer.

## Hard Rules

- Do not modify any files.
- Do not call APIs.
- Do not run multiagent.
- Do not write back candidate data.
- Do not edit `final_candidate_gold.jsonl`.
- Do not edit candidate index or summary files.
- Do not edit release files or canonical gold.
- Do not set `clean_final=true`.
- Do not recommend canonical gold overwrite.
- Use only the packet's blind-friendly audit / applog / traffic evidence as primary reasoning support.
- Do not use `traceability`, CVE ID, scenario name, lab source, `sample_id`, `run_dir`, or source path as stage reasoning evidence.
- Treat `gold_stage` as fixed for EWVAA candidate review; do not relabel or re-judge the stage.
- Diagnostic fields such as `weighted_verdict`, `human_review_priority`, `promotion_blocker`, and `needs_later_patch` are review-control metadata, not strict reasoning evidence.
- For applog evidence, use the sanitized Markdown summary or `strict_blind_evidence_sanitized_summary` first. Redacted authorization, cookie, email, and password values are not stage evidence.
- Preserve method, URL, seq, edge_id, relation, attach_strength, attach_reason, backbone_seq, sec_delta, and alignment fields as evidence-bearing semantics.
- Output must be copy-ready content that the human reviewer can paste into the Review UI.
- Keep `review_status` as `deferred` while this draft awaits human verification. Only the human reviewer may set it to `reviewed` after checking the current draft and its evidence.

## Formal Draft Vs Review Decision Boundary

Formal draft layer:

- The four draft claims and `auxiliary_vulnerability_note.claim` may later be written back to `gold_reasoning_chain` / formal candidate fields.
- These formal draft claims may only describe visible evidence, observable behavior, evidence-supported stage reasoning, and evidence limitations.
- Do not put workflow or review-status terms in formal draft claims.
- Avoid terms such as: manual review, candidate-with-manual-review, promotion, no promotion, clean final, clean_final, canonical gold, writeback, human_verified, L1, L2, L3, L4.
- If evidence is weak, formal claims should say `weak evidence support`, `evidence-limited boundary`, `result closure is not confirmed`, `durable artifact is not visible`, or similar evidence-based wording.
- Do not write `requires manual review` in a formal claim.

Review decision layer:

- `reviewer_decision`, `reviewer_notes`, `promotion_decision`, and Human Review Status fields may contain workflow conclusions.
- `reviewer_notes` may say manual review, no promotion, no clean final, candidate-with-manual-review, `clean_final_allowed=no`, or `canonical_gold_allowed=no`.
- State in `reviewer_notes` that the AI-assisted draft awaits human verification. All recommended decisions require human confirmation before approval or writeback.

## Review Task

1. Decide whether the original candidate four-step reasoning chain is sufficiently grounded in visible packet evidence.
2. Identify unsupported or over-strong claims.
3. Explain any stage-boundary concern while keeping `gold_stage` fixed.
4. Provide copy-ready revised draft claims when revision is useful.
5. Keep workflow conclusions out of formal draft claims and put them only in review decision fields.
6. Recommend whether a future writeback dry-run is worth running after human draft edits.

## Output Format

Use this exact Markdown structure. Put every field that should be pasted into the UI inside its own code block.

````markdown
# Review UI copy-ready output

## 1. Decision summary

- gold_stage:
- evidence_grounding: high / medium / low
- stage_boundary_quality: strong / acceptable_with_manual_review / weak
- final_decision:
- writeback_recommendation: no_writeback_for_now / dry_run_only_after_validation / consider_after_human_confirmation

## 2. Draft claim: scenario_or_evidence_understanding

```text
...
```

## 3. Draft claim: observable_evidence

```text
...
```

## 4. Draft claim: attack_stage_path_reasoning

```text
...
```

## 5. Draft claim: final_judgement

```text
...
```

## 6. auxiliary_vulnerability_note.claim

```text
...
```

## 7. reviewer_decision

```text
...
```

## 8. reviewer_notes

```text
...
```

## 9. promotion_decision

```text
...
```

## 10. clean_final_allowed

```text
no
```

## 11. canonical_gold_allowed

```text
no
```

## 12. Human Review Status Panel

### review_status

```text
deferred
```

### writeback_status

```text
not_written_back
```

### needs_later_patch_after_review

```text
yes / no
```

### promotion_blocker_after_review

```text
yes / no
```

### status_notes

```text
...
```
````
