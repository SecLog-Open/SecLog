# Stage Label Criteria

This workbench uses four labels:

- `preparation`
- `execution`
- `result`
- `stage_unclosed`

These are window-level labels, not global attack-lifecycle labels.

## Core rule

Stage judgement must be based on visible evidence inside the current
candidate window. Do not decide the label from:

- CVE
- scenario name
- run directory
- source path
- external vulnerability knowledge
- final attack success known from outside the window

## Window-level interpretations

### `preparation`

Visible evidence mainly shows:

- preliminary access
- probing
- environment confirmation
- pre-trigger conditions
- attack-related request evidence before server-side processing is
  clearly visible

Boundary:

- if the window only shows request arrival, access, probing, or
  pre-processing evidence, do not advance it to `execution` or `result`

### `execution`

Visible evidence mainly shows:

- attack input being processed by a handler, runtime, or process
- attack-related process, file, network, or runtime behavior

Boundary:

- request arrival alone is not enough
- if the same window already shows a visible consequence, it should be
  checked for `result`

### `result`

Visible evidence mainly shows:

- observable consequence
- returned attack-induced output or sensitive data
- file creation or modification caused by the attack
- persistent state change
- output sending or successful outbound callback/data-carrying effect

Boundary:

- execution behavior alone is not enough
- generic success text, generic response, generic network activity, or
  generic `FILE_WRITE` / `NET_SEND` is not automatically `result`

### `stage_unclosed`

Visible evidence mainly shows:

- attack-related activity still inside the constructed chain
- but the current visible evidence does not safely close
  `preparation`, `execution`, or `result`

Boundary:

- this is not benign
- this is not "unknown"
- this is not a fourth real lifecycle stage
- use it when the window is attack-related but the visible evidence does
  not safely support a concrete stage

## Required rationale fields

Every selected or reserve candidate must include:

```json
{
  "candidate_stage": "...",
  "key_evidence": [
    "2-5 key visible evidence items"
  ],
  "why_this_stage": "...",
  "why_not_previous_stage": "...",
  "why_not_next_stage": "...",
  "boundary_risk": "low|medium|high",
  "notes_for_later_blinding": "...",
  "notes_for_later_annotation": "..."
}
```

