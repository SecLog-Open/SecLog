# Pipeline overview

```text
stage-04 annotation_ready_seed.jsonl
  -> canonical annotation workspace
  -> strict-blind workspace
  -> compact evidence and annotation context
  -> AI annotator candidate reasoning
  -> schema and evidence-reference validation
  -> independent AI reviewer and grounding audit
  -> Review UI workbench preparation
  -> Human Review UI
  -> frozen benchmark
```

The visible log window is the only primary evidence for a concrete stage
judgment. Auxiliary vulnerability context is annotation-only semantic context;
it is never model-facing and never determines a label by itself. Candidate
stage, selection scores, scenario identity, source paths, labels, and reference
reasoning must remain outside prediction prompts.

After AI annotation and review, `review_ui/prepare_workbench.py` creates a
new human-review workbench from the candidate run and compact annotation
evidence. See [workbench preparation](../../../review_ui/README.md#workbench-inputs)
for the input files and command. All candidates start as `not_reviewed`;
missing review findings remain pending.

The published frozen benchmark contains 216 samples and is validated before
evaluation. Workbench preparation supports other candidate counts for new
annotation sets.
