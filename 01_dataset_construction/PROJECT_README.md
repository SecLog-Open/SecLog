# SecLog dataset construction framework

This directory is the public dataset-construction portion of SecLog. It
creates reproducible multi-source security-log runs from Docker scenarios and
exports replayable raw/index artifacts for downstream attack-chain building.

The construction framework collects and correlates:

- Sysdig system-call audit logs;
- Tshark packet-level traffic logs;
- application logs emitted by the scenario services.

Its construction outputs are raw logs, unit and unit-event indexes, capture
metadata, and application/network context files. The downstream attack-chain
stage turns these inputs into structured attack chains with references to
raw source files and line numbers.

## Public entry points

```bash
bash build.sh
BATCH=1 poetry run python main.py --config-path example/python-demo \
  --output-path results/python-demo
```

`build.sh` is the official batch entry. The complete `example/` directory is
required because it contains the Docker Compose definitions, Dockerfiles,
service code, action drivers, and `scene.yml` configurations used by the
builder.

See `README.md` for prerequisites and the shortest reproducible invocation.
See `BUILD_CONTRACT.md` for the stage input/output contract.

## Construction flow

```text
Docker scenario
-> multi-source capture
-> log parsing and alignment
-> provenance graph construction
-> raw/index export
-> stage 02 attack-chain construction
```

The produced run directory is the input to
`../02_attack_chain_construction/`.

## Runtime prerequisites

Reproduction requires Linux, Docker Engine with Compose, Poetry, Sysdig,
Tshark/tcpdump, conntrack, nsenter, and the privileges needed for system and
network capture.
