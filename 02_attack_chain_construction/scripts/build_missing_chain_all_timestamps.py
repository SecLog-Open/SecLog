#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any


SCRIPT_DIR = Path(__file__).resolve().parent
BUNDLE_ROOT = SCRIPT_DIR.parent
PIPELINE_ENTRY = BUNDLE_ROOT / "results_analysis" / "pipeline" / "run_chain_pipeline.py"
DEFAULT_RESULTS_ROOT = (BUNDLE_ROOT.parent / "01_dataset_construction" / "results").resolve()
DEFAULT_PRIVATE_OUTPUT_ROOT = BUNDLE_ROOT.parents[1] / "seclog_work"
CHAIN_DIR_NAME = "chain"
TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}$")


def rel(path: Path, base: Path) -> str:
    try:
        return str(path.resolve().relative_to(base.resolve())).replace("\\", "/")
    except Exception:
        return str(path.resolve()).replace("\\", "/")


def find_timestamp_dirs(results_root: Path) -> list[Path]:
    out: list[Path] = []
    for path in results_root.rglob("*"):
        if path.is_dir() and TIMESTAMP_RE.fullmatch(path.name):
            out.append(path)
    return sorted(out, key=lambda item: rel(item, results_root))


def run_ready(path: Path) -> dict[str, Any]:
    return {
        "has_raw": (path / "raw").is_dir(),
        "has_index": (path / "index").is_dir(),
        "has_unit_index": (path / "index" / "unit_index.jsonl").is_file(),
        "has_unit_event_index": (path / "index" / "unit_event_index.jsonl").is_file(),
        "has_capture_manifest": (path / "index" / "capture_manifest.v0.json").is_file(),
        **summarize_chain_state(path),
    }


def summarize_chain_state(run_dir: Path) -> dict[str, bool]:
    chain_dir = run_dir / CHAIN_DIR_NAME
    return {
        "has_chain": chain_dir.is_dir(),
        "has_audit_triples_core": (chain_dir / "audit_triples.core.v1.jsonl").is_file(),
        "has_backbone": (chain_dir / "backbone_chain.v1.json").is_file(),
        "has_context_edges": (chain_dir / "behavior_context_edges.v0.jsonl").is_file(),
        "has_dataset": (chain_dir / "behavior_chain_dataset.v2.json").is_file(),
        "has_dataset_meta": (chain_dir / "behavior_chain_dataset.v2.meta.json").is_file(),
    }


def chain_is_complete(row: dict[str, Any]) -> bool:
    return (
        row["has_chain"]
        and row["has_audit_triples_core"]
        and row["has_backbone"]
        and row["has_context_edges"]
        and row["has_dataset"]
        and row["has_dataset_meta"]
    )


def find_targets(
    results_root: Path,
    include_existing: bool,
    shard_count: int,
    shard_index: int,
    excluded_runs: set[str],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    all_runs = find_timestamp_dirs(results_root)
    for pos, run_dir in enumerate(all_runs):
        if shard_count > 1 and (pos % shard_count) != shard_index:
            continue
        run_rel = f"{rel(run_dir.parent, results_root)}/{run_dir.name}"
        if run_rel in excluded_runs:
            continue
        ready = run_ready(run_dir)
        if not include_existing and chain_is_complete(ready):
            continue
        rows.append(
            {
                "scenario_rel": rel(run_dir.parent, results_root),
                "timestamp": run_dir.name,
                "run_dir": str(run_dir.resolve()),
                "run_rel": run_rel,
                **ready,
            }
        )
    return rows


def invoke_pipeline(
    run_dir: Path,
    backbone_guard_threshold: int,
    run_mode: str,
) -> subprocess.CompletedProcess[str]:
    cmd = [
        sys.executable,
        str(PIPELINE_ENTRY),
        "--scenario-dir",
        str(run_dir),
        "--run-mode",
        run_mode,
        "--backbone-guard-threshold",
        str(backbone_guard_threshold),
    ]
    return subprocess.run(
        cmd,
        cwd=BUNDLE_ROOT,
        text=True,
        capture_output=True,
    )


def summarize_final_state(run_dir: Path) -> dict[str, bool]:
    chain_dir = run_dir / CHAIN_DIR_NAME
    return {
        "chain_exists": chain_dir.is_dir(),
        "audit_triples_core_exists": (chain_dir / "audit_triples.core.v1.jsonl").is_file(),
        "backbone_exists": (chain_dir / "backbone_chain.v1.json").is_file(),
        "enrich_summary_exists": (chain_dir / "behavior_context_summary.v0.json").is_file(),
        "context_edges_exists": (chain_dir / "behavior_context_edges.v0.jsonl").is_file(),
        "dataset_exists": (chain_dir / "behavior_chain_dataset.v2.json").is_file(),
        "dataset_meta_exists": (chain_dir / "behavior_chain_dataset.v2.meta.json").is_file(),
    }


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build chain for every timestamp run missing it."
    )
    parser.add_argument("--results-root", type=Path, default=DEFAULT_RESULTS_ROOT)
    parser.add_argument(
        "--targets-file",
        type=Path,
        default=None,
        help="Optional JSON manifest with a top-level 'targets' array to execute directly.",
    )
    parser.add_argument(
        "--report-path",
        type=Path,
        default=DEFAULT_PRIVATE_OUTPUT_ROOT / "build_missing_chain_report.json",
    )
    parser.add_argument(
        "--targets-path",
        type=Path,
        default=DEFAULT_PRIVATE_OUTPUT_ROOT / "missing_chain_targets.json",
    )
    parser.add_argument("--backbone-guard-threshold", type=int, default=5000)
    parser.add_argument(
        "--run-mode",
        choices=["audit", "adaptive-candidate", "runtime-shell-block-trial"],
        default="adaptive-candidate",
    )
    parser.add_argument(
        "--include-existing",
        action="store_true",
        help="Scan all timestamp runs instead of only those missing or incomplete for chain.",
    )
    parser.add_argument(
        "--shard-count",
        type=int,
        default=1,
        help="Partition timestamp runs into N stable shards for parallel execution.",
    )
    parser.add_argument(
        "--shard-index",
        type=int,
        default=0,
        help="Zero-based shard index to execute when --shard-count is greater than 1.",
    )
    parser.add_argument(
        "--exclude-run",
        action="append",
        default=[],
        help="Exclude a specific run using scenario/timestamp relative form, for example multi-jump/2026-06-27_12-00-56.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Optional cap on number of target runs to execute; 0 means no cap.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Only write the target manifest; do not execute the pipeline.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.shard_count < 1:
        raise SystemExit("--shard-count must be at least 1")
    if args.shard_index < 0 or args.shard_index >= args.shard_count:
        raise SystemExit("--shard-index must be in [0, shard-count)")
    results_root = args.results_root.resolve()
    excluded_runs = {item.strip().replace("\\", "/").rstrip("/") for item in args.exclude_run if item.strip()}
    if args.targets_file is not None:
        payload = json.loads(args.targets_file.read_text(encoding="utf-8"))
        raw_targets = list(payload.get("targets", []))
        targets = []
        for row in raw_targets:
            row = dict(row)
            run_dir = Path(row["run_dir"]).resolve()
            row["run_dir"] = str(run_dir)
            row.setdefault("scenario_rel", rel(run_dir.parent, results_root))
            row.setdefault("timestamp", run_dir.name)
            row.setdefault("run_rel", f"{row['scenario_rel']}/{row['timestamp']}")
            row.update(run_ready(run_dir))
            if excluded_runs and row["run_rel"] in excluded_runs:
                continue
            if not args.include_existing and chain_is_complete(row):
                continue
            targets.append(row)
    else:
        targets = find_targets(
            results_root,
            include_existing=args.include_existing,
            shard_count=args.shard_count,
            shard_index=args.shard_index,
            excluded_runs=excluded_runs,
        )
    write_json(
        args.targets_path,
        {
            "results_root": str(results_root),
            "target_count": len(targets),
            "shard_count": args.shard_count,
            "shard_index": args.shard_index,
            "targets_file": str(args.targets_file) if args.targets_file is not None else None,
            "excluded_runs": sorted(excluded_runs),
            "targets": targets,
        },
    )

    selected = targets
    if args.limit and args.limit > 0:
        selected = targets[: args.limit]

    if args.dry_run:
        print(json.dumps({"target_count": len(selected), "targets_path": str(args.targets_path)}, ensure_ascii=False))
        return 0

    started = time.time()
    runs: list[dict[str, Any]] = []
    status_counter: Counter[str] = Counter()
    rc = 0

    def write_progress_report() -> None:
        report = {
            "bundle_root": str(BUNDLE_ROOT),
            "results_root": str(results_root),
            "selected_target_count": len(selected),
            "target_manifest": str(args.targets_path),
            "run_mode": args.run_mode,
            "backbone_guard_threshold": args.backbone_guard_threshold,
            "shard_count": args.shard_count,
            "shard_index": args.shard_index,
            "targets_file": str(args.targets_file) if args.targets_file is not None else None,
            "excluded_runs": sorted(excluded_runs),
            "elapsed_seconds": round(time.time() - started, 2),
            "status_counts": dict(status_counter),
            "completed_run_count": len(runs),
            "remaining_run_count": max(len(selected) - len(runs), 0),
            "runs": runs,
        }
        write_json(args.report_path, report)

    for idx, row in enumerate(selected, start=1):
        run_dir = Path(row["run_dir"])
        print(f"[build-missing-chain] {idx}/{len(selected)} {rel(run_dir, results_root)}")
        per_start = time.time()
        proc = invoke_pipeline(
            run_dir=run_dir,
            backbone_guard_threshold=args.backbone_guard_threshold,
            run_mode=args.run_mode,
        )
        final_state = summarize_final_state(run_dir)
        if proc.returncode == 0 and final_state["dataset_exists"] and final_state["dataset_meta_exists"]:
            status = "success"
        elif proc.returncode == 2:
            status = "incomplete"
            rc = max(rc, 2)
        else:
            status = "failed"
            rc = 1
        status_counter[status] += 1
        runs.append(
            {
                "scenario_rel": row["scenario_rel"],
                "timestamp": row["timestamp"],
                "run_dir": str(run_dir),
                "elapsed_seconds": round(time.time() - per_start, 2),
                "pipeline_rc": proc.returncode,
                "status": status,
                "final_state": final_state,
                "stdout_tail": proc.stdout[-4000:],
                "stderr_tail": proc.stderr[-4000:],
            }
        )
        write_progress_report()

    write_progress_report()
    print(json.dumps({"report_path": str(args.report_path), "status_counts": dict(status_counter)}, ensure_ascii=False))
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
