#!/usr/bin/env python3
"""Step 02: hard-validate annotator patches and run grounding audit."""
from __future__ import annotations

import json

from common import (
    config_path_from_args,
    load_config,
    read_jsonl,
    rel,
    require_active_run,
    utc_now,
    validation_for_patches,
    write_json,
    write_jsonl,
)
from weighted_grounding_audit import blocked_no_input_report, write_audit_outputs


def main() -> int:
    config = load_config(config_path_from_args())
    run_dir = require_active_run(config)
    patches_path = run_dir / "reasoning_patches.unmasked.annotator.jsonl"
    if not patches_path.exists():
        blocked_no_input_report(
            output_dir=run_dir,
            role="annotator",
            report_name="annotator_weighted_grounding_report.json",
            cases_name="annotator_weighted_grounding_cases.jsonl",
            reason=f"missing:{rel(patches_path)}",
            patch_path=patches_path,
        )
        report = {
            "status": "failed",
            "created_at": utc_now(),
            "run_dir": rel(run_dir),
            "errors": [f"missing:{rel(patches_path)}"],
            "api_called": False,
            "benchmark_files_modified": False,
        }
        write_json(run_dir / "annotator_patch_validation_report.json", report)
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return 1

    patch_rows = read_jsonl(patches_path)
    validation_rows, valid_rows, validation_report, grounding_cases, grounding_report = validation_for_patches(
        config, patch_rows, consumer_role="annotator"
    )
    weighted_report = write_audit_outputs(
        config=config,
        patch_rows=valid_rows,
        output_dir=run_dir,
        role="annotator",
        report_name="annotator_weighted_grounding_report.json",
        cases_name="annotator_weighted_grounding_cases.jsonl",
        patch_path=rel(patches_path),
    )
    invalid_rows = [row for row in validation_rows if not row.get("patch_valid")]
    status = "success" if patch_rows and not invalid_rows else "partial" if patch_rows else "failed"
    validation_report.update(
        {
            "status": status,
            "created_at": utc_now(),
            "run_dir": rel(run_dir),
            "inputs": {**validation_report["inputs"], "patches": rel(patches_path)},
            "outputs": {
                "validation_report": rel(run_dir / "annotator_patch_validation_report.json"),
                "grounding_audit_report": rel(run_dir / "annotator_grounding_audit_report.json"),
                "weighted_grounding_report": rel(run_dir / "annotator_weighted_grounding_report.json"),
                "invalid_outputs": rel(run_dir / "annotator_invalid_outputs.jsonl"),
            },
            "weighted_grounding": {
                "status": weighted_report.get("status"),
                "strict_gold_allowed_false": weighted_report.get("counts", {}).get("strict_gold_allowed_false", 0),
                "manual_review_samples": weighted_report.get("counts", {}).get("manual_review_samples", 0),
            },
            "benchmark_files_modified": False,
        }
    )
    write_jsonl(run_dir / "annotator_patch_validation_cases.jsonl", validation_rows)
    write_jsonl(run_dir / "annotator_invalid_outputs.jsonl", invalid_rows)
    write_jsonl(run_dir / "annotator_grounding_audit_cases.jsonl", grounding_cases)
    write_json(run_dir / "annotator_grounding_audit_report.json", grounding_report)
    write_json(run_dir / "annotator_patch_validation_report.json", validation_report)
    print(json.dumps({
        "status": status,
        "run_dir": rel(run_dir),
        "total_patches": len(patch_rows),
        "valid": len(valid_rows),
        "invalid": len(invalid_rows),
        "manual_review_samples": grounding_report.get("counts", {}).get("manual_review_samples", 0),
        "weighted_manual_review_samples": weighted_report.get("counts", {}).get("manual_review_samples", 0),
        "api_called": False,
    }, ensure_ascii=False, indent=2))
    return 0 if patch_rows else 1


if __name__ == "__main__":
    raise SystemExit(main())
