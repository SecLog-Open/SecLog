#!/usr/bin/env python3
"""Validate and audit existing EWVAA patches without API calls.

Inputs: unmasked reasoning patch JSONL plus canonical benchmark files.
Outputs: validation and grounding reports in --output-dir when --execute is
passed; otherwise prints the command.
Benchmark mutation: never.
API: never.
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path


STAGE_ROOT = Path(__file__).resolve().parents[2]
RUNNER = STAGE_ROOT / "results_analysis/release/run_ewvaa_stage_reasoning_api_trial.py"
DEFAULT_PATCHES = Path("workdir/annotation_runs/merged_reasoning_patches.unmasked.jsonl")
DEFAULT_OUTPUT = Path("workdir/api_trial_revalidated")


def main() -> int:
    parser = argparse.ArgumentParser(description="Revalidate and audit existing EWVAA patches.")
    parser.add_argument("--execute", action="store_true", help="Actually write validation/audit reports.")
    parser.add_argument("--patches", type=Path, default=DEFAULT_PATCHES)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    cmd = [sys.executable, str(RUNNER), "--revalidate-patches", str(args.patches), "--output-dir", str(args.output_dir)]
    print("+ " + " ".join(cmd))
    if not args.execute:
        print("dry-run only; pass --execute to write a new validation output directory")
        return 0
    return subprocess.call(cmd)


if __name__ == "__main__":
    raise SystemExit(main())
