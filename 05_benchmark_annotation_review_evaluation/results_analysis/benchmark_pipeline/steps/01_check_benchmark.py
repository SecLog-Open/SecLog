#!/usr/bin/env python3
"""Check canonical stage_reasoning benchmark files.

Inputs: a canonical benchmark workspace with one `data/` unit.
Outputs: a JSON report under --output-dir.
Benchmark mutation: never.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


BENCH = Path("workdir/canonical_benchmark")
FILES = ("model_input.jsonl", "gold.jsonl", "sample_index.jsonl")


def count_jsonl(path: Path) -> int:
    with path.open("r", encoding="utf-8") as fh:
        return sum(1 for line in fh if line.strip())


def main() -> int:
    parser = argparse.ArgumentParser(description="Read-only check of benchmark v2 canonical layout.")
    parser.add_argument("--benchmark-root", type=Path, default=BENCH)
    parser.add_argument("--output-dir", type=Path, default=Path("results_analysis/benchmark_pipeline/runs/check_benchmark"))
    args = parser.parse_args()

    report: dict[str, Any] = {"benchmark_root": str(args.benchmark_root), "dataset": {}, "errors": []}
    manifest = args.benchmark_root / "manifest.json"
    if not manifest.exists():
        report["errors"].append(f"missing:{manifest}")
    else:
        report["manifest"] = json.loads(manifest.read_text(encoding="utf-8"))

    data_root = args.benchmark_root / "data"
    counts = []
    for name in FILES:
        path = data_root / name
        if not path.exists():
            report["errors"].append(f"missing:{path}")
            continue
        n = count_jsonl(path)
        report["dataset"][name] = {"path": str(path), "lines": n}
        counts.append(n)
    if counts and len(set(counts)) != 1:
        report["errors"].append(f"line_count_mismatch:{counts}")

    args.output_dir.mkdir(parents=True, exist_ok=True)
    out = args.output_dir / "benchmark_check_report.json"
    out.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {out}")
    return 1 if report["errors"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
