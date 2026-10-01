#!/usr/bin/env python3
"""Repair selected EWVAA candidates and export candidate patched_gold.

Inputs: judge outputs, existing candidate patches, and canonical benchmark
files. This skeleton is intentionally conservative: it records the intended
candidate export path and does not overwrite benchmark files.
Outputs: candidate repair/export directory when --execute is passed.
Benchmark mutation: never.
API: never unless a future repair worker explicitly adds an API-gated mode.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path


DEFAULT_OUTPUT = Path("workdir/candidate_repair")


def main() -> int:
    parser = argparse.ArgumentParser(description="Prepare candidate repair/export output; dry-run by default.")
    parser.add_argument("--execute", action="store_true", help="Write the candidate repair plan.")
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    plan = {
        "status": "candidate_repair_skeleton",
        "canonical_gold_overwritten": False,
        "patched_gold_is_candidate": True,
        "notes": [
            "Use primary evidence for strict chains.",
            "Keep CVE/context in auxiliary_vulnerability_note only.",
            "Validate forbidden strict-chain terms before exporting any candidate.",
        ],
    }
    if not args.execute:
        print(json.dumps(plan, ensure_ascii=False, indent=2))
        print("dry-run only; pass --execute to write repair_plan.json")
        return 0
    args.output_dir.mkdir(parents=True, exist_ok=True)
    out = args.output_dir / "repair_plan.json"
    out.write_text(json.dumps(plan, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
