#!/usr/bin/env python3
"""Build or dry-run the EWVAA masked workbench.

Inputs: canonical benchmark files plus annotation_context.v0.4.
Outputs: a new masked workbench directory when --execute is passed.
Benchmark mutation: never.
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path


DEFAULT_OUTPUT = Path("workdir/compact_annotation_workbench")
BUILDER = Path("results_analysis/release/build_ewvaa_masked_workbench.py")


def main() -> int:
    parser = argparse.ArgumentParser(description="Build masked workbench; dry-run by default.")
    parser.add_argument("--execute", action="store_true", help="Actually run the builder.")
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--limit", type=int, default=10)
    args = parser.parse_args()

    cmd = [
        sys.executable,
        str(BUILDER),
        "--split",
        "unified_216",
        "--output-dir",
        str(args.output_dir),
        "--limit",
        str(args.limit),
    ]
    print("+ " + " ".join(cmd))
    if not args.execute:
        print("dry-run only; pass --execute to create the output directory")
        return 0
    return subprocess.call(cmd)


if __name__ == "__main__":
    raise SystemExit(main())
