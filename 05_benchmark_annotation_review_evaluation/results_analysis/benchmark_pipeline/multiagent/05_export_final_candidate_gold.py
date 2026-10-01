#!/usr/bin/env python3
"""Step 05: export final candidate gold and human review summary."""
from __future__ import annotations

import json
from collections import Counter

from common import (
    benchmark_paths,
    config_path_from_args,
    configured_sample_ids,
    final_entry_from_chain,
    load_config,
    normalize_verdict,
    read_json,
    read_jsonl,
    rel,
    require_active_run,
    safe_read_jsonl,
    sanitize_candidate_auxiliary_note,
    sanitize_reasoning_chain,
    sample_selection_summary,
    unique_manual_rows,
    utc_now,
    verdict_distribution,
    write_json,
    write_jsonl,
    write_text,
)


def gold_stage(row: dict) -> str:
    return str((row.get("label") or {}).get("stage") or row.get("gold_stage") or "")


def json_short(value: object, max_chars: int = 220) -> str:
    text = json.dumps(value, ensure_ascii=False)
    return text if len(text) <= max_chars else text[: max_chars - 3] + "..."


def run_models(run_dir) -> dict[str, str]:
    annotator_report = read_json(run_dir / "annotator_run_report.json") if (run_dir / "annotator_run_report.json").exists() else {}
    reviewer_report = read_json(run_dir / "reviewer_run_report.json") if (run_dir / "reviewer_run_report.json").exists() else {}
    return {
        "annotator_model": str(annotator_report.get("annotator_model") or ""),
        "reviewer_model": str(reviewer_report.get("reviewer_model") or ""),
    }


def unique_sample_count(rows: list[dict], *, prefix: str | None = None, sample_ids: set[str] | None = None) -> int:
    matched: set[str] = set()
    for row in rows:
        sample_id = str(row.get("sample_id") or "").strip()
        reason = str(row.get("reason") or "")
        if not sample_id:
            continue
        if prefix is not None and not reason.startswith(prefix):
            continue
        if sample_ids is not None and sample_id not in sample_ids:
            continue
        matched.add(sample_id)
    return len(matched)


def latest_weighted_audit_paths(run_dir) -> tuple[object | None, object | None, str]:
    candidates = [
        ("reviewer", run_dir / "reviewer_weighted_grounding_report.json", run_dir / "reviewer_weighted_grounding_cases.jsonl"),
        ("annotator", run_dir / "annotator_weighted_grounding_report.json", run_dir / "annotator_weighted_grounding_cases.jsonl"),
    ]
    for label, report_path, cases_path in candidates:
        if report_path.exists() and cases_path.exists():
            return report_path, cases_path, label
    return None, None, "missing"


def weighted_audit_gate(run_dir) -> dict:
    report_path, cases_path, source = latest_weighted_audit_paths(run_dir)
    if report_path is None or cases_path is None:
        return {
            "status": "missing",
            "source": source,
            "report_path": "",
            "cases_path": "",
            "strict_gold_blocked_sample_ids": [],
            "manual_rows": [{"sample_id": "", "reason": "weighted_grounding_audit_missing"}],
            "candidate_export_allowed": False,
        }
    report = read_json(report_path)
    cases = safe_read_jsonl(cases_path)
    blocked_ids = sorted(
        {
            str(case.get("sample_id"))
            for case in cases
            if case.get("sample_id") and not case.get("strict_gold_allowed")
        }
    )
    risky_ids = sorted(
        {
            str(case.get("sample_id"))
            for case in cases
            if case.get("sample_id") and case.get("verdict") in {"weak", "risky", "invalid"}
        }
    )
    manual_rows = [
        {
            "sample_id": sample_id,
            "reason": "weighted_grounding_strict_gold_not_allowed",
            "weighted_audit_source": source,
        }
        for sample_id in blocked_ids
    ]
    for sample_id in risky_ids:
        if sample_id not in blocked_ids:
            manual_rows.append(
                {
                    "sample_id": sample_id,
                    "reason": "weighted_grounding_manual_review",
                    "weighted_audit_source": source,
                }
            )
    no_input = report.get("status") != "success" or int(report.get("counts", {}).get("cases", 0) or 0) == 0
    if no_input:
        manual_rows.append({"sample_id": "", "reason": f"weighted_grounding_audit_{report.get('status', 'no_input')}"})
    return {
        "status": report.get("status"),
        "source": source,
        "report_path": rel(report_path),
        "cases_path": rel(cases_path),
        "strict_gold_blocked_sample_ids": blocked_ids,
        "manual_rows": manual_rows,
        "candidate_export_allowed": not blocked_ids and not no_input,
        "counts": report.get("counts", {}),
    }


def markdown_summary(
    *,
    config: dict,
    run_dir,
    gold_rows: list[dict],
    final_rows: list[dict],
    patch_by_id: dict[str, dict],
    judge_by_id: dict[str, dict],
    manual_rows: list[dict],
    unpatched_rows: list[dict],
    report: dict,
) -> str:
    models = run_models(run_dir)
    verdict_counts = verdict_distribution(list(judge_by_id.values()))
    modified_ids = sorted(patch_by_id)
    lines: list[str] = [
        "# EWVAA Multi-Agent Human Review Summary",
        "",
        f"Run dir: `{rel(run_dir)}`",
        f"Annotator model: `{models['annotator_model']}`",
        f"Reviewer model: `{models['reviewer_model']}`",
        f"Samples: {len(gold_rows)}",
        f"Final valid / invalid: {report['final_valid']} / {report['final_invalid']}",
        f"Reviewer verdict distribution: `{json.dumps(verdict_counts, ensure_ascii=False)}`",
        "",
        "## Review Counts",
        "",
        f"- patched_sample_manual_review_count: {report['patched_sample_manual_review_count']}",
        f"- weighted_manual_review_count: {report['weighted_manual_review_count']}",
        f"- reviewer_verdict_manual_review_count: {report['reviewer_verdict_manual_review_count']}",
        f"- unpatched_original_gold_retained_count: {report['unpatched_original_gold_retained_count']}",
        "",
        "## Manual Review Required",
        "",
    ]
    if manual_rows:
        for row in manual_rows:
            lines.append(f"- `{row.get('sample_id')}`: {row.get('reason')}")
    else:
        lines.append("- None")
    lines.extend(
        [
            "",
            "## Unpatched Original Gold Retained",
            "",
            f"- Count: {len(unpatched_rows)}",
            f"- Path: `{report['unpatched_original_gold_retained_path']}`",
        ]
    )
    lines.extend(["", "## Modified Sample IDs", ""])
    if modified_ids:
        for sample_id in modified_ids:
            lines.append(f"- `{sample_id}`")
    else:
        lines.append("- None")
    lines.extend(
        [
            "",
            "## Per-Sample Summary",
            "",
            "| sample_id | gold_stage | final_judgement | evidence_refs | reviewer verdict | revision | high severity |",
            "|---|---|---|---|---|---|---|",
        ]
    )
    final_by_id = {row["sample_id"]: row for row in final_rows}
    for gold in gold_rows:
        sample_id = str(gold["sample_id"])
        final = final_by_id.get(sample_id, gold)
        claim, refs = final_entry_from_chain(final.get("gold_reasoning_chain"))
        judge = judge_by_id.get(sample_id, {})
        verdict = normalize_verdict(judge.get("verdict")) if judge else "unpatched"
        patch = patch_by_id.get(sample_id, {})
        revision = "yes" if patch.get("merge_source") == "reviewer_revision" else "no"
        high_severity = "yes" if judge.get("high_severity") else "no"
        lines.append(
            "| `{}` | `{}` | {} | `{}` | `{}` | {} | {} |".format(
                sample_id,
                gold_stage(gold),
                claim.replace("|", "\\|")[:260],
                json_short(refs),
                verdict,
                revision,
                high_severity,
            )
        )
    lines.extend(
        [
            "",
            "## Boundary Statement",
            "",
            "`final_candidate_gold.jsonl` is a candidate final artifact for human review.",
            "Canonical `gold.jsonl` was not overwritten.",
            "Only after human confirmation should this candidate be promoted through a separate formal gold update process.",
        ]
    )
    return "\n".join(lines) + "\n"


def main() -> int:
    config = load_config(config_path_from_args())
    run_dir = require_active_run(config)
    paths = benchmark_paths(config)
    merged_path = run_dir / "merged_reasoning_patches.unmasked.jsonl"
    validation_path = run_dir / "merged_patch_validation_report.json"
    grounding_path = run_dir / "merged_grounding_audit_report.json"
    missing = [path for path in (merged_path, validation_path, grounding_path) if not path.exists()]
    if missing:
        report = {
            "status": "failed",
            "created_at": utc_now(),
            "run_dir": rel(run_dir),
            "errors": [f"missing:{rel(path)}" for path in missing],
            "api_called": False,
            "benchmark_files_modified": False,
        }
        write_json(run_dir / "multiagent_run_report.json", report)
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return 1

    gold_rows = read_jsonl(paths["gold"])
    selected_sample_ids = configured_sample_ids(config)
    if selected_sample_ids:
        gold_by_id = {str(row.get("sample_id")): row for row in gold_rows if row.get("sample_id")}
        missing_selected = [sample_id for sample_id in selected_sample_ids if sample_id not in gold_by_id]
        if missing_selected:
            report = {
                "status": "failed",
                "created_at": utc_now(),
                "run_dir": rel(run_dir),
                "errors": ["selected_sample_id_missing_from_gold:" + sample_id for sample_id in missing_selected],
                "api_called": False,
                "benchmark_files_modified": False,
                **sample_selection_summary(config),
            }
            write_json(run_dir / "multiagent_run_report.json", report)
            print(json.dumps(report, ensure_ascii=False, indent=2))
            return 1
        gold_rows = [gold_by_id[sample_id] for sample_id in selected_sample_ids]
    merged_rows = read_jsonl(merged_path)
    patch_by_id = {str(row.get("sample_id")): row for row in merged_rows if row.get("sample_id")}
    final_rows: list[dict] = []
    for row in gold_rows:
        clean = {key: value for key, value in row.items() if not key.startswith("_")}
        patch = patch_by_id.get(str(clean["sample_id"]))
        if patch:
            clean["gold_reasoning_chain"] = sanitize_reasoning_chain(patch.get("gold_reasoning_chain"))
            clean["auxiliary_vulnerability_note"] = sanitize_candidate_auxiliary_note(
                patch.get("auxiliary_vulnerability_note")
            )
        final_rows.append(clean)

    validation = read_json(validation_path)
    grounding = read_json(grounding_path)
    weighted_gate = weighted_audit_gate(run_dir)
    annotator_report = read_json(run_dir / "annotator_run_report.json") if (run_dir / "annotator_run_report.json").exists() else {}
    annotator_validation = (
        read_json(run_dir / "annotator_patch_validation_report.json")
        if (run_dir / "annotator_patch_validation_report.json").exists()
        else {}
    )
    judge_rows = safe_read_jsonl(run_dir / "reviewer_judge_outputs.jsonl")
    judge_by_id = {str(row.get("sample_id")): row for row in judge_rows if row.get("sample_id")}
    manual_rows = [
        row
        for row in safe_read_jsonl(run_dir / "manual_review_required.jsonl")
        if str(row.get("reason") or "") != "unpatched_original_gold_retained"
    ]
    manual_rows.extend(weighted_gate["manual_rows"])
    unpatched_ids = sorted(str(row["sample_id"]) for row in gold_rows if str(row["sample_id"]) not in patch_by_id)
    manual_rows = unique_manual_rows(manual_rows)
    unpatched_rows = [{"sample_id": sample_id, "reason": "unpatched_original_gold_retained"} for sample_id in unpatched_ids]
    write_jsonl(run_dir / "manual_review_required.jsonl", manual_rows)
    write_jsonl(run_dir / "unpatched_original_gold_retained.jsonl", unpatched_rows)

    verdict_counts = Counter(normalize_verdict(row.get("verdict")) for row in judge_rows)
    final_valid = int(validation.get("counts", {}).get("valid_patches", 0))
    final_invalid = int(validation.get("counts", {}).get("invalid_outputs", 0))
    forbidden_hits = int(validation.get("forbidden_strict_chain_hits", 0))
    cve_only_hits = int(
        validation.get("cve_only_strict_chain_hits")
        or grounding.get("counts", {}).get("cve_only_strict_chain_hits", 0)
        or 0
    )
    high_severity_count = sum(1 for row in judge_rows if row.get("high_severity"))
    final_candidate_rows = len(final_rows)
    total_samples = len(gold_rows)
    patched_samples = len(patch_by_id)
    patched_sample_ids = set(patch_by_id)
    candidate_export_allowed = bool(weighted_gate["candidate_export_allowed"]) and final_invalid == 0
    if candidate_export_allowed:
        write_jsonl(run_dir / "final_candidate_gold.jsonl", final_rows)
    success = (
        final_invalid == 0
        and forbidden_hits == 0
        and cve_only_hits == 0
        and high_severity_count == 0
        and len(manual_rows) == 0
        and final_candidate_rows == total_samples
        and patched_samples == total_samples
        and candidate_export_allowed
    )
    status = "success" if success else "partial"
    models = run_models(run_dir)
    report = {
        "status": status,
        "created_at": utc_now(),
        "dataset": "SecLog-Bench-216",
        "total_samples": total_samples,
        "patched_samples": patched_samples,
        "unpatched_samples": len(unpatched_ids),
        "annotator_model": models["annotator_model"],
        "reviewer_model": models["reviewer_model"],
        "api_called": bool(safe_read_jsonl(run_dir / "raw_annotator_responses.jsonl") or safe_read_jsonl(run_dir / "reviewer_raw_responses.jsonl")),
        "api_key_recorded": False,
        "canonical_gold_overwrite_allowed": False,
        "benchmark_files_modified": False,
        **sample_selection_summary(config, [row.get("sample_id") for row in gold_rows]),
        "annotator_success": int(annotator_report.get("counts", {}).get("patches_unmasked", 0)),
        "annotator_failed": int(annotator_report.get("counts", {}).get("prompts", 0))
        - int(annotator_report.get("counts", {}).get("patches_unmasked", 0)),
        "initial_valid": int(annotator_validation.get("counts", {}).get("valid_patches", 0)),
        "initial_invalid": int(annotator_validation.get("counts", {}).get("invalid_outputs", 0)),
        "reviewer_accept": verdict_counts.get("accept", 0),
        "reviewer_minor_revision": verdict_counts.get("minor_revision", 0),
        "reviewer_major_revision": verdict_counts.get("major_revision", 0),
        "reviewer_reject": verdict_counts.get("reject", 0),
        "final_valid": final_valid,
        "final_invalid": final_invalid,
        "forbidden_strict_chain_hits": forbidden_hits,
        "cve_only_strict_chain_hits": cve_only_hits,
        "high_severity_count": high_severity_count,
        "manual_review_required_count": len(manual_rows),
        "patched_sample_manual_review_count": unique_sample_count(manual_rows, sample_ids=patched_sample_ids),
        "weighted_manual_review_count": unique_sample_count(manual_rows, prefix="weighted_grounding_"),
        "reviewer_verdict_manual_review_count": unique_sample_count(manual_rows, prefix="reviewer_verdict_"),
        "unpatched_original_gold_retained_count": len(unpatched_rows),
        "weighted_grounding": weighted_gate,
        "final_candidate_gold_path": rel(run_dir / "final_candidate_gold.jsonl") if candidate_export_allowed else "",
        "human_review_summary_path": rel(run_dir / "human_review_summary.md"),
        "manual_review_required_path": rel(run_dir / "manual_review_required.jsonl"),
        "unpatched_original_gold_retained_path": rel(run_dir / "unpatched_original_gold_retained.jsonl"),
        "final_candidate_gold_rows": final_candidate_rows if candidate_export_allowed else 0,
        "final_candidate_export_blocked": not candidate_export_allowed,
        "acceptance_conditions": {
            "final_invalid_zero": final_invalid == 0,
            "forbidden_strict_chain_hits_zero": forbidden_hits == 0,
            "cve_only_strict_chain_hits_zero": cve_only_hits == 0,
            "high_severity_zero": high_severity_count == 0,
            "manual_review_required_zero": len(manual_rows) == 0,
            "candidate_rows_equal_canonical": final_candidate_rows == total_samples,
            "patched_samples_equal_total": patched_samples == total_samples,
            "weighted_grounding_candidate_export_allowed": candidate_export_allowed,
            "benchmark_files_modified_false": True,
        },
    }
    write_text(
        run_dir / "human_review_summary.md",
        markdown_summary(
            config=config,
            run_dir=run_dir,
            gold_rows=gold_rows,
            final_rows=final_rows,
            patch_by_id=patch_by_id,
            judge_by_id=judge_by_id,
            manual_rows=manual_rows,
            unpatched_rows=unpatched_rows,
            report=report,
        ),
    )
    write_json(run_dir / "multiagent_run_report.json", report)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
