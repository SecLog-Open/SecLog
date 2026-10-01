# Setting 3 — multi-task supervision

Input: identical to Setting 1 (no sidecar in the input pipeline).
Primary task: stage classification from `stage_labels.v0.json`.
Auxiliary task: per-edge narrative_role classification; loss
mask excludes low-confidence (`mid_span_representative`) and
unlabelled edges. At test time, drop the auxiliary head and
evaluate exactly as Setting 1.
