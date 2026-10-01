# Setting 2 — anchor-hint augmentation

Input: main_sample (same mask as Setting 1) plus three per-edge
boolean features derived from the narrative_roles sidecar's
`anchors.{entry_anchor, result_anchor, handoff_exec}.edge_id`.
The full `roles[*]` list is not an input feature: role annotations are
supervision and must not be exposed to the stage classifier.

Supervision: identical to Setting 1.
