#!/usr/bin/env python3
"""Step 04: merge reviewer revisions and validate final reasoning patches."""
from __future__ import annotations

import json

from common import (
    config_path_from_args,
    is_revision_verdict,
    load_config,
    normalize_verdict,
    read_jsonl,
    rel,
    require_active_run,
    unique_manual_rows,
    utc_now,
    validation_for_patches,
    verdict_distribution,
    write_json,
    write_jsonl,
)
from weighted_grounding_audit import blocked_no_input_report, write_audit_outputs


def by_sample(rows: list[dict]) -> dict[str, dict]:
    return {str(row.get("sample_id")): row for row in rows if row.get("sample_id")}


def main() -> int:
    config = load_config(config_path_from_args())
    run_dir = require_active_run(config)
    annotator_path = run_dir / "reasoning_patches.unmasked.annotator.jsonl"
    judge_path = run_dir / "reviewer_judge_outputs.jsonl"
    revision_path = run_dir / "reviewer_revision_patches.unmasked.jsonl"
    missing = [path for path in (annotator_path, judge_path) if not path.exists()]
    if missing:
        blocked_no_input_report(
            output_dir=run_dir,
            role="reviewer",
            report_name="reviewer_weighted_grounding_report.json",
            cases_name="reviewer_weighted_grounding_cases.jsonl",
            reason=";".join(f"missing:{rel(path)}" for path in missing),
            patch_path=annotator_path,
        )
        report = {
            "status": "failed",
            "created_at": utc_now(),
            "run_dir": rel(run_dir),
            "errors": [f"missing:{rel(path)}" for path in missing],
            "api_called": False,
            "benchmark_files_modified": False,
        }
        write_json(run_dir / "merged_patch_validation_report.json", report)
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return 1

    annotator_rows = read_jsonl(annotator_path)
    judge_rows = read_jsonl(judge_path)
    revision_rows = read_jsonl(revision_path) if revision_path.exists() else []
    judge_by_id = by_sample(judge_rows)
    revision_by_id = by_sample(revision_rows)
    merged_rows: list[dict] = []
    manual_rows: list[dict] = []

    for patch in annotator_rows:
        sample_id = str(patch.get("sample_id", ""))
        judge = judge_by_id.get(sample_id)
        if judge is None:
            manual_rows.append({"sample_id": sample_id, "reason": "missing_reviewer_judgement"})
            merged_rows.append({**patch, "merge_source": "annotator_missing_reviewer"})
            continue
        verdict = normalize_verdict(judge.get("verdict"))
        high_severity = bool(judge.get("high_severity"))
        if high_severity:
            manual_rows.append({"sample_id": sample_id, "reason": "reviewer_high_severity"})
        if verdict in {"major_revision", "reject", "invalid"}:
            manual_rows.append({"sample_id": sample_id, "reason": f"reviewer_verdict_{verdict}"})
        if not is_revision_verdict(verdict):
            merged_rows.append({**patch, "merge_source": "annotator_accept", "reviewer_verdict": verdict})
            continue
        revised = revision_by_id.get(sample_id)
        if revised is None:
            manual_rows.append({"sample_id": sample_id, "reason": "missing_reviewer_revised_patch"})
            merged_rows.append({**patch, "merge_source": "annotator_revision_missing", "reviewer_verdict": verdict})
            continue
        merged_rows.append({**revised, "merge_source": "reviewer_revision", "reviewer_verdict": verdict})

    write_jsonl(run_dir / "merged_reasoning_patches.unmasked.jsonl", merged_rows)
    validation_rows, valid_rows, validation_report, grounding_cases, grounding_report = validation_for_patches(
        config, merged_rows, consumer_role="reviewer"
    )
    weighted_report = write_audit_outputs(
        config=config,
        patch_rows=valid_rows,
        output_dir=run_dir,
        role="reviewer",
        report_name="reviewer_weighted_grounding_report.json",
        cases_name="reviewer_weighted_grounding_cases.jsonl",
        patch_path=rel(run_dir / "merged_reasoning_patches.unmasked.jsonl"),
    )
    invalid_rows = [row for row in validation_rows if not row.get("patch_valid")]
    for row in invalid_rows:
        manual_rows.append({"sample_id": row.get("sample_id"), "reason": "merged_patch_invalid", "errors": row.get("errors")})
    for case in grounding_cases:
        if case.get("manual_review_recommended"):
            manual_rows.append(
                {
                    "sample_id": case.get("sample_id"),
                    "reason": f"grounding_{case.get('overall_grounding')}",
                }
            )
    weighted_cases = read_jsonl(run_dir / "reviewer_weighted_grounding_cases.jsonl")
    for case in weighted_cases:
        if not case.get("strict_gold_allowed") or case.get("verdict") in {"weak", "risky", "invalid"}:
            manual_rows.append(
                {
                    "sample_id": case.get("sample_id"),
                    "reason": f"weighted_grounding_{case.get('verdict')}",
                    "strict_gold_allowed": case.get("strict_gold_allowed"),
                }
            )
    manual_rows = unique_manual_rows(manual_rows)

    validation_report.update(
        {
            "status": "success",
            "created_at": utc_now(),
            "run_dir": rel(run_dir),
            "inputs": {
                **validation_report["inputs"],
                "annotator_patches": rel(annotator_path),
                "reviewer_judge_outputs": rel(judge_path),
                "reviewer_revision_patches": rel(revision_path),
            },
            "outputs": {
                "merged_reasoning_patches": rel(run_dir / "merged_reasoning_patches.unmasked.jsonl"),
                "merged_patch_validation_report": rel(run_dir / "merged_patch_validation_report.json"),
                "merged_grounding_audit_report": rel(run_dir / "merged_grounding_audit_report.json"),
                "reviewer_weighted_grounding_report": rel(run_dir / "reviewer_weighted_grounding_report.json"),
                "merged_invalid_outputs": rel(run_dir / "merged_invalid_outputs.jsonl"),
                "manual_review_required": rel(run_dir / "manual_review_required.jsonl"),
            },
            "weighted_grounding": {
                "status": weighted_report.get("status"),
                "strict_gold_allowed_false": weighted_report.get("counts", {}).get("strict_gold_allowed_false", 0),
                "manual_review_samples": weighted_report.get("counts", {}).get("manual_review_samples", 0),
            },
            "reviewer_verdict_distribution": verdict_distribution(judge_rows),
            "manual_review_required_count": len(manual_rows),
            "high_severity_count": sum(1 for row in judge_rows if row.get("high_severity")),
            "api_called": False,
            "benchmark_files_modified": False,
        }
    )
    write_jsonl(run_dir / "merged_patch_validation_cases.jsonl", validation_rows)
    write_jsonl(run_dir / "merged_invalid_outputs.jsonl", invalid_rows)
    write_jsonl(run_dir / "merged_grounding_audit_cases.jsonl", grounding_cases)
    write_json(run_dir / "merged_grounding_audit_report.json", grounding_report)
    write_jsonl(run_dir / "manual_review_required.jsonl", manual_rows)
    write_json(run_dir / "merged_patch_validation_report.json", validation_report)
    print(json.dumps({
        "status": "success",
        "run_dir": rel(run_dir),
        "merged_patches": len(merged_rows),
        "final_valid": len(valid_rows),
        "final_invalid": len(invalid_rows),
        "manual_review_required": len(manual_rows),
        "weighted_manual_review_samples": weighted_report.get("counts", {}).get("manual_review_samples", 0),
        "api_called": False,
    }, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
