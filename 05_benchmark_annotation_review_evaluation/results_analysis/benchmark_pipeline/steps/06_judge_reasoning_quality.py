#!/usr/bin/env python3
"""Run or dry-run GPT judge for EWVAA reasoning quality.

Inputs: masked-workbench-derived candidate patches and audit reports.
Outputs: judge inputs, outputs, and summary under --output-dir.
Benchmark mutation: never.
API: only with --execute-api.
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path


STAGE_ROOT = Path(__file__).resolve().parents[2]
JUDGE = STAGE_ROOT / "results_analysis/release/judge_ewvaa_reasoning_quality.py"
DEFAULT_OUTPUT = Path("workdir/reasoning_quality_judge")


def main() -> int:
    parser = argparse.ArgumentParser(description="Judge EWVAA candidate reasoning; dry-run by default.")
    parser.add_argument("--execute-api", action="store_true", help="Explicitly allow live judge API calls.")
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--limit", type=int, default=10)
    parser.add_argument("--print-only", action="store_true", help="Print the underlying judge command without executing it.")
    args = parser.parse_args()

    cmd = [sys.executable, str(JUDGE), "--output-dir", str(args.output_dir), "--limit", str(args.limit)]
    if not args.execute_api:
        cmd.append("--dry-run")
    print("+ " + " ".join(cmd))
    if args.print_only:
        print("print-only; underlying judge runner was not executed")
        return 0
    return subprocess.call(cmd)


if __name__ == "__main__":
    raise SystemExit(main())
