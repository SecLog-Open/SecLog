#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any


SCRIPT_DIR = Path(__file__).resolve().parent
BUNDLE_ROOT = SCRIPT_DIR.parent
DEFAULT_RESULTS_ROOT = (BUNDLE_ROOT.parent / "01_dataset_construction" / "results").resolve()
DEFAULT_PRIVATE_OUTPUT_ROOT = BUNDLE_ROOT.parents[1] / "seclog_work"
CHAIN_DIR_NAME = "chain"
TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}$")


def rel(path: Path, base: Path) -> str:
    try:
        return str(path.resolve().relative_to(base.resolve())).replace("\\", "/")
    except Exception:
        return str(path.resolve()).replace("\\", "/")


def scan(results_root: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in sorted(results_root.rglob("*")):
        if not path.is_dir() or not TIMESTAMP_RE.fullmatch(path.name):
            continue
        chain_dir = path / CHAIN_DIR_NAME
        rows.append(
            {
                "scenario_rel": rel(path.parent, results_root),
                "timestamp": path.name,
                "run_dir": str(path.resolve()),
                "has_raw": (path / "raw").is_dir(),
                "has_index": (path / "index").is_dir(),
                "has_chain": chain_dir.is_dir(),
                "has_audit_triples_core": (chain_dir / "audit_triples.core.v1.jsonl").is_file(),
                "has_backbone": (chain_dir / "backbone_chain.v1.json").is_file(),
                "has_context_edges": (chain_dir / "behavior_context_edges.v0.jsonl").is_file(),
                "has_dataset": (chain_dir / "behavior_chain_dataset.v2.json").is_file(),
                "has_dataset_meta": (chain_dir / "behavior_chain_dataset.v2.meta.json").is_file(),
            }
        )
    return rows


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Scan raw/index/chain status for all timestamp runs.")
    parser.add_argument("--results-root", type=Path, default=DEFAULT_RESULTS_ROOT)
    parser.add_argument(
        "--report-path",
        type=Path,
        default=DEFAULT_PRIVATE_OUTPUT_ROOT / "chain_status_report.json",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    results_root = args.results_root.resolve()
    rows = scan(results_root)
    write_json(
        args.report_path,
        {
            "results_root": str(results_root),
            "run_count": len(rows),
            "missing_chain_count": sum(1 for row in rows if not row["has_chain"]),
            "rows": rows,
        },
    )
    print(json.dumps({"report_path": str(args.report_path), "run_count": len(rows)}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
