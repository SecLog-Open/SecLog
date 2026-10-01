# Setting 1 — real input only

Input: `main_sample.json` spine + context. `attrs.malicious` is
masked. No narrative_roles sidecar. Supervision comes from
`stage_labels.v0.json` (edge_stage_projection).

Training and inference read exactly the same field set.
