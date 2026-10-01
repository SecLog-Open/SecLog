#!/usr/bin/env python3
"""Run or dry-run an EWVAA annotation API trial.

Inputs: masked workbench prompt pack.
Outputs: raw responses, masked/unmasked patches, validation/audit reports, and
candidate patched_gold when --execute-api is passed.
Benchmark mutation: never.
API: only with --execute-api.
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path


STAGE_ROOT = Path(__file__).resolve().parents[2]
RUNNER = STAGE_ROOT / "results_analysis/release/run_ewvaa_stage_reasoning_api_trial.py"
DEFAULT_WORKBENCH = Path("workdir/compact_annotation_workbench")
DEFAULT_OUTPUT = Path("workdir/api_trial_masked_workbench")
DEFAULT_GOLD = Path("workdir/canonical_benchmark/data/gold.jsonl")
DEFAULT_MODEL_INPUT = Path("workdir/canonical_benchmark/data/model_input.jsonl")
DEFAULT_SAMPLE_INDEX = Path("workdir/canonical_benchmark/data/sample_index.jsonl")
DEFAULT_VULNERABILITY_FACTS = (
    STAGE_ROOT / "assets/auxiliary_context/scenario_vulnerability_facts.annotation_context.v0.4.json"
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run EWVAA annotation trial from masked workbench.")
    parser.add_argument("--execute-api", action="store_true", help="Explicitly allow live API calls.")
    parser.add_argument("--masked-workbench-dir", type=Path, default=DEFAULT_WORKBENCH)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--gold", type=Path, default=DEFAULT_GOLD)
    parser.add_argument("--model-input", type=Path, default=DEFAULT_MODEL_INPUT)
    parser.add_argument("--sample-index", type=Path, default=DEFAULT_SAMPLE_INDEX)
    parser.add_argument("--vulnerability-facts", type=Path, default=DEFAULT_VULNERABILITY_FACTS)
    parser.add_argument("--limit", type=int, default=10)
    parser.add_argument("--print-only", action="store_true", help="Print the underlying runner command without executing it.")
    args = parser.parse_args()

    cmd = [
        sys.executable,
        str(RUNNER),
        "--masked-workbench-dir",
        str(args.masked_workbench_dir),
        "--use-masked-ids",
        "--output-dir",
        str(args.output_dir),
        "--gold",
        str(args.gold),
        "--model-input",
        str(args.model_input),
        "--sample-index",
        str(args.sample_index),
        "--vulnerability-facts",
        str(args.vulnerability_facts),
        "--limit",
        str(args.limit),
    ]
    if not args.execute_api:
        cmd.append("--dry-run")
    print("+ " + " ".join(cmd))
    if args.print_only:
        print("print-only; underlying annotation trial runner was not executed")
        return 0
    if not args.execute_api:
        print("dry-run only; pass --execute-api to call the configured provider")
    return subprocess.call(cmd)


if __name__ == "__main__":
    raise SystemExit(main())
