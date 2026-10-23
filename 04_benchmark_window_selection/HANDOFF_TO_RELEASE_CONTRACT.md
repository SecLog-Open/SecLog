# Handoff To Later Release Stages

This directory does not directly build the frozen release. It hands off
seed material for later strict-blind / compact / annotation / Review UI
work.

Primary handoff file:

```text
<work-dir>/annotation_ready_seed.jsonl
```

Expected downstream use:

1. read selected and reserve windows
2. build strict-blind model-visible packets
3. build compact evidence views
4. join auxiliary context
5. build annotator/reviewer prompt packs
6. run AI annotation and Evidence-Guided Risk Review
7. run Review UI human review
8. export frozen release artefacts

Fields that should be preserved downstream:

- `sample_id_seed`
- `scenario_id`
- `candidate_stage`
- `window.start_seq`
- `window.end_seq`
- `stage_support_summary`
- `stage_boundary_rationale`
- `scores`
- `source_paths`

Fields that should not be turned into model-visible evidence:

- `candidate_stage`
- `scores`
- `selection_status`
- scenario identity or source-location metadata
