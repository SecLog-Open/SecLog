#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import argparse
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


LEGAL_STAGES = {"preparation", "execution", "result", "stage_unclosed"}


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def rel(path: Path, root: Path) -> str:
    return os.path.relpath(path.resolve(), root.resolve()).replace("\\", "/")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate stage_reasoning_window_selection workbench outputs.")
    parser.add_argument(
        "--workbench-dir",
        default="../../seclog_work/window_selection",
        help="Output directory (default: ../../seclog_work/window_selection).",
    )
    parser.add_argument(
        "--validation-manifest",
        default=None,
        help="Validation output path (default: <workbench-dir>/validation_manifest.json).",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    root = Path(__file__).resolve().parents[1]
    workbench = root / args.workbench_dir
    validation_manifest = (
        Path(args.validation_manifest).resolve()
        if args.validation_manifest
        else workbench / "validation_manifest.json"
    )
    paths = {
        "manifest": workbench / "manifest.json",
        "inventory": workbench / "chain_inventory.jsonl",
        "stage_seed": workbench / "scenario_stage_seed.jsonl",
        "candidate": workbench / "candidate_windows.jsonl",
        "selected": workbench / "selected_windows.jsonl",
        "reserve": workbench / "reserve_windows.jsonl",
        "rejected": workbench / "rejected_windows.jsonl",
        "annotation_ready_seed": workbench / "annotation_ready_seed.jsonl",
        "aux_context": root / "auxiliary_context" / "vulnerability_facts_seed" / "normalized" / "scenario_vulnerability_facts.annotation_context.v0.4.json",
    }
    checks = {f"{name}_exists": path.exists() for name, path in paths.items()}
    if not all(checks.values()):
        out = {
            "validated_at_utc": utc_now(),
            "validation_passed": False,
            "checks": checks,
            "important_paths": {name: rel(path, root) for name, path in paths.items()},
        }
        validation_manifest.parent.mkdir(parents=True, exist_ok=True)
        validation_manifest.write_text(json.dumps(out, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({"validation_passed": False, "missing": [k for k, v in checks.items() if not v]}, ensure_ascii=False, indent=2))
        return 1

    manifest = read_json(paths["manifest"])
    candidate_rows = read_jsonl(paths["candidate"])
    selected_rows = read_jsonl(paths["selected"])
    reserve_rows = read_jsonl(paths["reserve"])
    rejected_rows = read_jsonl(paths["rejected"])
    annotation_ready_rows = read_jsonl(paths["annotation_ready_seed"])

    stage_checks = all(row.get("candidate_stage") in LEGAL_STAGES for row in candidate_rows)
    status_counts = Counter(row.get("selection_status") for row in candidate_rows)
    status_split_checks = (
        len(selected_rows) == status_counts.get("selected", 0)
        and len(reserve_rows) == status_counts.get("reserve", 0)
        and len(rejected_rows) == status_counts.get("rejected", 0)
    )
    score_checks = True
    relative_path_checks = True
    selected_boundary_gate_checks = True
    for row in candidate_rows:
        scores = row.get("scores") or {}
        for key in (
            "stage_feature_score",
            "stage_support_score",
            "log_quality_score",
            "future_annotatability_score",
        ):
            value = int(scores.get(key, -1))
            if value < 0 or value > 5:
                score_checks = False
        for key in ("context_length_risk_score", "duplicate_risk_score"):
            value = int(scores.get(key, -1))
            if value < 0 or value > 5:
                score_checks = False
        for _, src in (row.get("source_paths") or {}).items():
            if src is None:
                continue
            if str(src).startswith("/") or ":/" in str(src) or ":\\" in str(src):
                relative_path_checks = False
        if row.get("selection_status") == "selected" and "stage_boundary_gate" in row:
            if not ((row.get("stage_boundary_gate") or {}).get("passed") is True):
                selected_boundary_gate_checks = False
    annotation_ready_subset_check = set(row["sample_id_seed"] for row in annotation_ready_rows).issubset(
        set(row["sample_id_seed"] for row in selected_rows + reserve_rows)
    )
    manifest_count_checks = (
        int(manifest.get("candidate_count", -1)) == len(candidate_rows)
        and int(manifest.get("selected_count", -1)) == len(selected_rows)
        and int(manifest.get("reserve_count", -1)) == len(reserve_rows)
        and int(manifest.get("rejected_count", -1)) == len(rejected_rows)
    )

    checks.update(
        {
            "legal_stage_vocabulary": stage_checks,
            "status_split_counts_match": status_split_checks,
            "score_ranges_valid": score_checks,
            "relative_source_paths_only": relative_path_checks,
            "selected_stage_boundary_gates_pass": selected_boundary_gate_checks,
            "annotation_ready_subset_valid": annotation_ready_subset_check,
            "manifest_counts_match": manifest_count_checks,
        }
    )

    out = {
        "validated_at_utc": utc_now(),
        "validation_passed": all(checks.values()),
        "checks": checks,
        "counts": {
            "candidate_count": len(candidate_rows),
            "selected_count": len(selected_rows),
            "reserve_count": len(reserve_rows),
            "rejected_count": len(rejected_rows),
            "annotation_ready_seed_count": len(annotation_ready_rows),
        },
        "important_paths": {name: rel(path, root) for name, path in paths.items()},
    }
    validation_manifest.parent.mkdir(parents=True, exist_ok=True)
    validation_manifest.write_text(json.dumps(out, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"validation_passed": out["validation_passed"], "output": str(validation_manifest)}, ensure_ascii=False, indent=2))
    return 0 if out["validation_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
