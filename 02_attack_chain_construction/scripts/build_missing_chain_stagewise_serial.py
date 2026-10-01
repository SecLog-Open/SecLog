#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any


SCRIPT_DIR = Path(__file__).resolve().parent
BUNDLE_ROOT = SCRIPT_DIR.parent
PIPELINE_ENTRY = BUNDLE_ROOT / "results_analysis" / "pipeline" / "run_chain_pipeline.py"
ENRICH_ENTRY = BUNDLE_ROOT / "results_analysis" / "pipeline" / "enrich_behavior_context_v0.py"
DEFAULT_RESULTS_ROOT = (BUNDLE_ROOT.parent / "01_dataset_construction" / "results").resolve()
DEFAULT_PRIVATE_OUTPUT_ROOT = BUNDLE_ROOT.parents[1] / "seclog_work"
CHAIN_DIR_NAME = "chain"


def rel(path: Path, base: Path) -> str:
    try:
        return str(path.resolve().relative_to(base.resolve())).replace("\\", "/")
    except Exception:
        return str(path.resolve()).replace("\\", "/")


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


def chain_is_complete(state: dict[str, Any]) -> bool:
    return (
        state["has_chain"]
        and state["has_audit_triples_core"]
        and state["has_backbone"]
        and state["has_context_edges"]
        and state["has_dataset"]
        and state["has_dataset_meta"]
    )


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def invoke(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        cwd=BUNDLE_ROOT,
        text=True,
        capture_output=True,
    )


def run_extract(run_dir: Path, run_mode: str, backbone_guard_threshold: int) -> subprocess.CompletedProcess[str]:
    return invoke(
        [
            sys.executable,
            str(PIPELINE_ENTRY),
            "--scenario-dir",
            str(run_dir),
            "--run-mode",
            run_mode,
            "--backbone-guard-threshold",
            str(backbone_guard_threshold),
            "--only-extract",
        ]
    )


def run_backbone(run_dir: Path, run_mode: str, backbone_guard_threshold: int) -> subprocess.CompletedProcess[str]:
    return invoke(
        [
            sys.executable,
            str(PIPELINE_ENTRY),
            "--scenario-dir",
            str(run_dir),
            "--run-mode",
            run_mode,
            "--backbone-guard-threshold",
            str(backbone_guard_threshold),
            "--only-backbone",
        ]
    )


def run_enrich(run_dir: Path, backbone_guard_threshold: int) -> subprocess.CompletedProcess[str]:
    return invoke(
        [
            sys.executable,
            str(ENRICH_ENTRY),
            "--scenario-dir",
            str(run_dir),
            "--backbone-guard-threshold",
            str(backbone_guard_threshold),
        ]
    )


def run_dataset(run_dir: Path, run_mode: str, backbone_guard_threshold: int) -> subprocess.CompletedProcess[str]:
    return invoke(
        [
            sys.executable,
            str(PIPELINE_ENTRY),
            "--scenario-dir",
            str(run_dir),
            "--run-mode",
            run_mode,
            "--backbone-guard-threshold",
            str(backbone_guard_threshold),
            "--only-dataset",
        ]
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Low-memory stagewise serial builder for incomplete chain runs."
    )
    parser.add_argument("--results-root", type=Path, default=DEFAULT_RESULTS_ROOT)
    parser.add_argument(
        "--targets-file",
        type=Path,
        required=True,
        help="JSON manifest with a top-level 'targets' array.",
    )
    parser.add_argument(
        "--report-path",
        type=Path,
        default=DEFAULT_PRIVATE_OUTPUT_ROOT / "build_missing_chain_stagewise_serial_report.json",
    )
    parser.add_argument(
        "--run-mode",
        choices=["audit", "adaptive-candidate", "runtime-shell-block-trial"],
        default="adaptive-candidate",
    )
    parser.add_argument("--backbone-guard-threshold", type=int, default=5000)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    results_root = args.results_root.resolve()
    payload = json.loads(args.targets_file.read_text(encoding="utf-8"))
    selected = list(payload.get("targets", []))
    started = time.time()
    runs: list[dict[str, Any]] = []
    status_counter: Counter[str] = Counter()
    rc = 0

    def write_progress_report() -> None:
        write_json(
            args.report_path,
            {
                "bundle_root": str(BUNDLE_ROOT),
                "results_root": str(results_root),
                "selected_target_count": len(selected),
                "targets_file": str(args.targets_file),
                "run_mode": args.run_mode,
                "backbone_guard_threshold": args.backbone_guard_threshold,
                "elapsed_seconds": round(time.time() - started, 2),
                "status_counts": dict(status_counter),
                "completed_run_count": len(runs),
                "remaining_run_count": max(len(selected) - len(runs), 0),
                "runs": runs,
            },
        )

    for idx, row in enumerate(selected, start=1):
        run_dir = Path(row["run_dir"]).resolve()
        run_rel = row.get("run_rel") or f"{row.get('scenario_rel', rel(run_dir.parent, results_root))}/{row.get('timestamp', run_dir.name)}"
        print(f"[stagewise-serial] {idx}/{len(selected)} {run_rel}")
        per_start = time.time()
        stage_runs: list[dict[str, Any]] = []
        failed = False

        while True:
            state_before = summarize_chain_state(run_dir)
            if chain_is_complete(state_before):
                break

            if not state_before["has_audit_triples_core"]:
                stage_name = "extract"
                proc = run_extract(run_dir, args.run_mode, args.backbone_guard_threshold)
            elif not state_before["has_backbone"]:
                stage_name = "backbone"
                proc = run_backbone(run_dir, args.run_mode, args.backbone_guard_threshold)
            elif not state_before["has_context_edges"]:
                stage_name = "enrich"
                proc = run_enrich(run_dir, args.backbone_guard_threshold)
            else:
                stage_name = "dataset"
                proc = run_dataset(run_dir, args.run_mode, args.backbone_guard_threshold)

            state_after = summarize_chain_state(run_dir)
            stage_ok = False
            if stage_name == "extract":
                stage_ok = proc.returncode == 0 and state_after["has_audit_triples_core"]
            elif stage_name == "backbone":
                stage_ok = proc.returncode == 0 and state_after["has_backbone"]
            elif stage_name == "enrich":
                stage_ok = proc.returncode == 0 and state_after["has_context_edges"]
            elif stage_name == "dataset":
                stage_ok = (
                    state_after["has_dataset"]
                    and state_after["has_dataset_meta"]
                )

            stage_runs.append(
                {
                    "stage": stage_name,
                    "pipeline_rc": proc.returncode,
                    "ok": stage_ok,
                    "state_before": state_before,
                    "state_after": state_after,
                    "stdout_tail": proc.stdout[-4000:],
                    "stderr_tail": proc.stderr[-4000:],
                }
            )
            if not stage_ok:
                failed = True
                break

        final_state = summarize_chain_state(run_dir)
        if not failed and chain_is_complete(final_state):
            status = "success"
        else:
            status = "failed"
            rc = 1
        status_counter[status] += 1
        runs.append(
            {
                "run_rel": run_rel,
                "scenario_rel": row.get("scenario_rel", rel(run_dir.parent, results_root)),
                "timestamp": row.get("timestamp", run_dir.name),
                "run_dir": str(run_dir),
                "elapsed_seconds": round(time.time() - per_start, 2),
                "status": status,
                "final_state": final_state,
                "stage_runs": stage_runs,
            }
        )
        write_progress_report()

    write_progress_report()
    print(json.dumps({"report_path": str(args.report_path), "status_counts": dict(status_counter)}, ensure_ascii=False))
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
