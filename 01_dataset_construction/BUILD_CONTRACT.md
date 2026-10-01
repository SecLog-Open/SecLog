# Dataset construction contract

## Inputs

Each construction run consumes one directory under `example/` containing a
valid `scene.yml` and all referenced Docker Compose, Dockerfile, service, and
action-driver assets. The `example/` tree is runtime input and must remain
beside `build.sh` and `main.py`.

Host prerequisites are Linux, Bash, Docker Engine with Compose, Poetry, and
the privileged system/network capture tools listed in `README.md`.

## Entry points

The batch entry is:

```bash
bash build.sh
```

A single scenario can be run with:

```bash
BATCH=1 poetry run python main.py --config-path example/python-demo \
  --output-path results/python-demo
```

`build.sh` enumerates the official construction batch. `main.py` loads one
scene, starts its Docker services, performs capture and actions, and then
invokes the analysis/export path.
For a different scenario, replace both `python-demo` paths with its path under
`example/`. `--output-path` selects the parent of the timestamped run directory;
its default is `results`.

## Outputs

The batch and the single-scene command above produce this separated layout:

```text
results/<scenario>/<run-id>/
  raw/
    sysdig/
    tshark/
    applog/
  index/
    unit_index.jsonl
    unit_event_index.jsonl
    capture_manifest.v0.json
    traffic_node_anchor_index.v0.jsonl
    traffic_node_anchor_index_summary.v0.json
    write_event_context_index.v0.jsonl
    edge_applog_context_view.v0.jsonl
    edge_applog_context_summary.v0.json
    applog_model_context.v0.jsonl
    applog_model_context_summary.v0.json
```

The application-log context files require the default replay/context export
settings. `conntrack_nat_index.v0.jsonl` is also written when NAT records are
available. Raw subdirectories and record counts depend on the captured
telemetry; an empty capture is not usable evidence for downstream processing.

Keep `raw/` and `index/` together. The indexes and context files refer to raw
source paths and line numbers. Stage 02 reads these products to construct the
`chain/` directory; the default construction command does not export a chain
dataset inside `index/`.

## Downstream handoff

The constructed run is read-only input to
`../02_attack_chain_construction/`. Stage 02 derives normalized audit triples,
behavior context, backbone chains, and behavior-chain datasets without
modifying the raw/index source run.
