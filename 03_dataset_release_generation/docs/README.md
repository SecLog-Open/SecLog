# dataset_release_v1

Three-layer dataset release for attack-stage learning:

1. **Main sample layer** — per-scenario `main_sample.json` and
   `main_sample.meta.json` under `shared/scenarios/`. Only event
   facts and context. No narrative roles, no stage labels.
2. **narrative_roles sidecar** — `narrative_roles.v0.json`.
   Per-edge high-level role annotations derived from backbone
   structure (entry/result anchors, preparation boundaries, ...).
   Every role carries a `confidence_tier` (high/mid/low) and a
   `role_source` describing the rule that produced it.
3. **stage_labels sidecar** — `stage_labels.v0.json`. Authoritative
   stage labels with vocabulary `preparation / execution / result /
   stage_unclosed`. Span-level is canonical; per-edge projection is
   derived.

The generated output root contains three configuration settings under `settings/`:

- `setting_1_real_input/` — pure real input
- `setting_2_anchor_hint/` — setting 1 + entry/result/handoff anchor
  bit features (full `roles[*]` is forbidden)
- `setting_3_multitask/` — setting 1 input + stage primary head +
  narrative_role auxiliary head (high/mid tiers only)

`stage_labels.v0.json` supplies the stage supervision.

These settings define dataset feature and supervision views. Model inference
on `SecLog-Bench-216` uses the prompt pack and protocol documented in
`05_benchmark_annotation_review_evaluation/`.
