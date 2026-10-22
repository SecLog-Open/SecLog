# Attack-chain construction

Purpose: transform an existing run's `raw/` and `index/` products into a structured
attack chain without changing `raw`.

Pre-generated attack chains: [Zenodo](https://doi.org/10.5281/zenodo.23525715).

Run commands from `02_attack_chain_construction/`. Replace `<scenario>` and
`<timestamp>` with an existing stage-01 run directory.

Single-run entry:

```bash
python results_analysis/pipeline/run_chain_pipeline.py \
  --scenario-dir "../01_dataset_construction/results/<scenario>/<timestamp>" \
  --run-mode adaptive-candidate \
  --backbone-guard-threshold 5000
```

Pipeline:

```text
raw/ + index/
  -> audit_triples.core.v1.jsonl
  -> backbone_chain.v1.json
  -> behavior_context_edges.v0.jsonl
  -> behavior_chain_dataset.v2.json
```

The audit backbone is primary.  `audit_context` and `multisource_context`
attach application/traffic context to that backbone. Outputs are written
under the run's `chain/` directory.

When `--with-release` is supplied, the runner loads the
stage-03 release exporter from the sibling `03_dataset_release_generation/`
unit; pass an explicit `--release-root`, such as
`../work/dataset_release_single`, for an independent output tree.

See [Workflow](docs/WORKFLOW.md) for separate stages, batch execution, and
low-memory execution.
