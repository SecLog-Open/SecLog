"""UI-only human review status tracking for P6.11."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


STATUS_SCHEMA_VERSION = "review_ui_human_review_status_v0.1"
STATUS_EVENT = "human_review_status_update"
STATUS_HISTORY_FILE = "human_review_status.jsonl"
STATUS_LATEST_FILE = "human_review_status.latest.json"
STATUS_META_FILE = "human_review_status.meta.json"
WRITEBACK_LOG_FILE = "writeback_log.jsonl"

REVIEW_STATUS_VALUES = [
    "not_reviewed",
    "reviewed",
    "needs_revision",
    "deferred",
    "rejected_for_clean_final",
]

WRITEBACK_STATUS_VALUES = [
    "not_written_back",
    "dry_run_only",
    "written_back",
    "rollback_required",
    "rolled_back",
]

CLEAN_FINAL_ALLOWED_VALUES = ["no", "yes_after_separate_final_review"]
CANONICAL_GOLD_ALLOWED_VALUES = ["no"]
YES_NO_VALUES = ["yes", "no"]

DEFAULT_REVIEWER_DECISION = "revise_draft_keep_candidate_with_manual_review"
DEFAULT_PROMOTION_DECISION = "no_promotion_keep_L2_human_review_required"

AFTER_REVIEW_STATUS_VALUES = [
    "pending_review",
    "reviewed_and_resolved",
    "reviewed_but_blocked",
    "reviewed_needs_patch",
    "reviewed_pending_writeback_or_check",
]

EFFECTIVE_REVIEW_PRIORITY_VALUES = [
    "resolved",
    "reviewed_still_blocked",
    "needs_followup_patch",
    "reviewed_pending_writeback_or_check",
]


def read_json(path: Path, warnings: list[str] | None = None) -> Any:
    if not path.exists():
        return None
    try:
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError as exc:
        if warnings is not None:
            warnings.append(f"Invalid JSON in {path}: {exc}")
        return None


def read_jsonl(path: Path, warnings: list[str] | None = None) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    rows = []
    with path.open("r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, start=1):
            if not line.strip():
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as exc:
                if warnings is not None:
                    warnings.append(f"Invalid JSONL line {line_no} in {path}: {exc}")
                continue
            if isinstance(obj, dict):
                rows.append(obj)
            elif warnings is not None:
                warnings.append(f"Non-object JSONL line {line_no} in {path}")
    return rows


def write_json(path: Path, obj: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def status_paths(workbench_dir: str | Path) -> dict[str, Path]:
    base = Path(workbench_dir) / "ui_drafts"
    return {
        "dir": base,
        "history": base / STATUS_HISTORY_FILE,
        "latest": base / STATUS_LATEST_FILE,
        "meta": base / STATUS_META_FILE,
        "writeback_log": base / WRITEBACK_LOG_FILE,
    }


def ensure_status_store(workbench_dir: str | Path) -> dict[str, Path]:
    paths = status_paths(workbench_dir)
    paths["dir"].mkdir(parents=True, exist_ok=True)
    if not paths["history"].exists():
        paths["history"].touch()
    if not paths["latest"].exists():
        write_json(paths["latest"], {})
    if not paths["meta"].exists():
        write_json(paths["meta"], _meta_payload(paths, latest_status_count=0))
    return paths


def _meta_payload(
    paths: dict[str, Path],
    *,
    latest_status_count: int,
    latest_updated_at: str | None = None,
) -> dict[str, Any]:
    payload = {
        "status_schema_version": STATUS_SCHEMA_VERSION,
        "scope": "ui_human_review_status_only_not_formal_candidate",
        "history_file": str(paths["history"]),
        "latest_file": str(paths["latest"]),
        "formal_candidate_writeback": False,
        "candidate_index_modified": False,
        "dataset_release_modified": False,
        "canonical_gold_modified": False,
        "clean_final_promotion": False,
        "not_formal_gold": True,
        "latest_status_count": latest_status_count,
    }
    if latest_updated_at:
        payload["latest_updated_at"] = latest_updated_at
    return payload


def load_latest_statuses(
    workbench_dir: str | Path, warnings: list[str] | None = None
) -> dict[str, dict[str, Any]]:
    loaded = read_json(status_paths(workbench_dir)["latest"], warnings)
    return loaded if isinstance(loaded, dict) else {}


def load_writeback_logs_by_sample_id(
    workbench_dir: str | Path, warnings: list[str] | None = None
) -> dict[str, dict[str, Any]]:
    latest: dict[str, dict[str, Any]] = {}
    for event in read_jsonl(status_paths(workbench_dir)["writeback_log"], warnings):
        sample_id = event.get("sample_id")
        if sample_id:
            latest[sample_id] = event
    return latest


def default_status_for_row(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "status_schema_version": STATUS_SCHEMA_VERSION,
        "event": STATUS_EVENT,
        "sample_id": row.get("sample_id", ""),
        "masked_sample_label": row.get("masked_sample_id", ""),
        "gold_stage": row.get("gold_stage", ""),
        "review_status": "not_reviewed",
        "reviewer_decision": "",
        "promotion_decision": "",
        "clean_final_allowed": "no",
        "canonical_gold_allowed": "no",
        "writeback_status": "not_written_back",
        "writeback_log_ref": None,
        "needs_later_patch_after_review": row.get("needs_later_patch", "yes") or "yes",
        "promotion_blocker_after_review": row.get("promotion_blocker", "yes") or "yes",
        "reviewed_at": "",
        "operator": "manual_review_ui",
        "notes": "",
        "not_formal_gold": True,
        "candidate_index_modified": False,
        "dataset_release_modified": False,
        "canonical_gold_modified": False,
        "clean_final_promotion": False,
    }


def derive_after_review_status(row: dict[str, Any], status: dict[str, Any]) -> dict[str, str]:
    review_status = status.get("review_status", "not_reviewed")
    writeback_status = status.get("writeback_status", "not_written_back")
    needs_later_patch_after_review = status.get(
        "needs_later_patch_after_review",
        row.get("needs_later_patch", "yes") or "yes",
    )
    promotion_blocker_after_review = status.get(
        "promotion_blocker_after_review",
        row.get("promotion_blocker", "yes") or "yes",
    )
    original_priority = row.get("human_review_priority", "")

    if review_status != "reviewed":
        effective_review_priority = original_priority
        after_review_status = "pending_review"
    elif (
        writeback_status == "written_back"
        and needs_later_patch_after_review == "no"
        and promotion_blocker_after_review == "no"
    ):
        effective_review_priority = "resolved"
        after_review_status = "reviewed_and_resolved"
    elif (
        needs_later_patch_after_review == "no"
        and promotion_blocker_after_review == "yes"
    ):
        effective_review_priority = "reviewed_still_blocked"
        after_review_status = "reviewed_but_blocked"
    elif needs_later_patch_after_review == "yes":
        effective_review_priority = "needs_followup_patch"
        after_review_status = "reviewed_needs_patch"
    else:
        effective_review_priority = "reviewed_pending_writeback_or_check"
        after_review_status = "reviewed_pending_writeback_or_check"

    return {
        "effective_review_priority": effective_review_priority,
        "after_review_status": after_review_status,
        "review_resolution_status": after_review_status,
    }


def merge_status_for_display(
    row: dict[str, Any],
    latest_status: dict[str, Any] | None,
    writeback_log: dict[str, Any] | None = None,
) -> dict[str, Any]:
    merged = default_status_for_row(row)
    if isinstance(latest_status, dict):
        for key, value in latest_status.items():
            if value is not None:
                merged[key] = value
    if writeback_log:
        merged["has_writeback_log"] = True
        merged["writeback_log_ref"] = merged.get("writeback_log_ref") or {
            "event": writeback_log.get("event"),
            "created_at": writeback_log.get("created_at"),
            "target_final_candidate_gold_path": writeback_log.get(
                "target_final_candidate_gold_path"
            ),
        }
        current_writeback_status = merged.get("writeback_status")
        if current_writeback_status in {
            None,
            "",
            "not_written_back",
            "dry_run_only",
        }:
            merged["writeback_status"] = "written_back"
    else:
        merged["has_writeback_log"] = False
    merged.update(derive_after_review_status(row, merged))
    return merged


def _check_enum(field: str, value: str, allowed: list[str], errors: list[str]) -> None:
    if value not in allowed:
        errors.append(f"{field} must be one of: {', '.join(allowed)}")


def validate_status_record(record: dict[str, Any]) -> list[str]:
    errors = []
    if not record.get("sample_id"):
        errors.append("sample_id is required")
    _check_enum("review_status", record.get("review_status", ""), REVIEW_STATUS_VALUES, errors)
    _check_enum(
        "writeback_status", record.get("writeback_status", ""), WRITEBACK_STATUS_VALUES, errors
    )
    _check_enum(
        "clean_final_allowed",
        record.get("clean_final_allowed", ""),
        CLEAN_FINAL_ALLOWED_VALUES,
        errors,
    )
    _check_enum(
        "canonical_gold_allowed",
        record.get("canonical_gold_allowed", ""),
        CANONICAL_GOLD_ALLOWED_VALUES,
        errors,
    )
    _check_enum(
        "needs_later_patch_after_review",
        record.get("needs_later_patch_after_review", ""),
        YES_NO_VALUES,
        errors,
    )
    _check_enum(
        "promotion_blocker_after_review",
        record.get("promotion_blocker_after_review", ""),
        YES_NO_VALUES,
        errors,
    )
    if record.get("canonical_gold_allowed") != "no":
        errors.append("canonical_gold_allowed must remain no in P6.11")
    for field in [
        "not_formal_gold",
        "candidate_index_modified",
        "dataset_release_modified",
        "canonical_gold_modified",
        "clean_final_promotion",
    ]:
        if field == "not_formal_gold":
            expected = True
        else:
            expected = False
        if record.get(field) is not expected:
            errors.append(f"{field} must be {str(expected).lower()}")
    return errors


def make_status_record(
    *,
    row: dict[str, Any],
    review_status: str,
    reviewer_decision: str = "",
    promotion_decision: str = "",
    clean_final_allowed: str = "no",
    canonical_gold_allowed: str = "no",
    writeback_status: str = "not_written_back",
    writeback_log_ref: Any = None,
    needs_later_patch_after_review: str = "yes",
    promotion_blocker_after_review: str = "yes",
    notes: str = "",
    now_utc: str | None = None,
) -> dict[str, Any]:
    now = now_utc or datetime.now(timezone.utc).isoformat()
    record = {
        "status_schema_version": STATUS_SCHEMA_VERSION,
        "event": STATUS_EVENT,
        "sample_id": row.get("sample_id", ""),
        "masked_sample_label": row.get("masked_sample_id", ""),
        "gold_stage": row.get("gold_stage", ""),
        "review_status": review_status,
        "reviewer_decision": reviewer_decision,
        "promotion_decision": promotion_decision,
        "clean_final_allowed": clean_final_allowed,
        "canonical_gold_allowed": canonical_gold_allowed,
        "writeback_status": writeback_status,
        "writeback_log_ref": writeback_log_ref,
        "needs_later_patch_after_review": needs_later_patch_after_review,
        "promotion_blocker_after_review": promotion_blocker_after_review,
        "reviewed_at": now,
        "operator": "manual_review_ui",
        "notes": notes,
        "not_formal_gold": True,
        "candidate_index_modified": False,
        "dataset_release_modified": False,
        "canonical_gold_modified": False,
        "clean_final_promotion": False,
    }
    errors = validate_status_record(record)
    if errors:
        raise ValueError("; ".join(errors))
    return record


def save_human_review_status(
    workbench_dir: str | Path,
    row: dict[str, Any],
    status_values: dict[str, Any],
) -> dict[str, Any]:
    paths = ensure_status_store(workbench_dir)
    record = make_status_record(row=row, **status_values)
    latest = load_latest_statuses(workbench_dir)
    with paths["history"].open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")
    latest[record["sample_id"]] = record
    write_json(paths["latest"], latest)
    write_json(
        paths["meta"],
        _meta_payload(
            paths,
            latest_status_count=len(latest),
            latest_updated_at=record["reviewed_at"],
        ),
    )
    return {"saved": True, "record": record, "paths": paths}


def _load_candidate_index_row(workbench_dir: Path, sample_id: str) -> dict[str, Any]:
    path = workbench_dir / "ewvaa_candidate_index.multisource_v1_2.jsonl"
    matches = [row for row in read_jsonl(path) if row.get("sample_id") == sample_id]
    if len(matches) != 1:
        raise ValueError(f"candidate index row count for {sample_id}: {len(matches)}")
    row = matches[0]
    return {
        "sample_id": row.get("sample_id", ""),
        "masked_sample_id": row.get("masked_sample_id", ""),
        "gold_stage": row.get("gold_stage", ""),
        "needs_later_patch": row.get("needs_later_patch", "yes"),
        "promotion_blocker": row.get("promotion_blocker", "yes"),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workbench-dir", required=True)
    parser.add_argument("--sample-id", required=True)
    parser.add_argument("--review-status", choices=REVIEW_STATUS_VALUES, required=True)
    parser.add_argument("--reviewer-decision", default=DEFAULT_REVIEWER_DECISION)
    parser.add_argument("--promotion-decision", default=DEFAULT_PROMOTION_DECISION)
    parser.add_argument("--clean-final-allowed", choices=CLEAN_FINAL_ALLOWED_VALUES, default="no")
    parser.add_argument("--canonical-gold-allowed", choices=CANONICAL_GOLD_ALLOWED_VALUES, default="no")
    parser.add_argument("--writeback-status", choices=WRITEBACK_STATUS_VALUES, default="not_written_back")
    parser.add_argument("--needs-later-patch-after-review", choices=YES_NO_VALUES, default="yes")
    parser.add_argument("--promotion-blocker-after-review", choices=YES_NO_VALUES, default="yes")
    parser.add_argument("--notes", default="")
    args = parser.parse_args()

    workbench_path = Path(args.workbench_dir)
    row = _load_candidate_index_row(workbench_path, args.sample_id)
    result = save_human_review_status(
        workbench_path,
        row,
        {
            "review_status": args.review_status,
            "reviewer_decision": args.reviewer_decision,
            "promotion_decision": args.promotion_decision,
            "clean_final_allowed": args.clean_final_allowed,
            "canonical_gold_allowed": args.canonical_gold_allowed,
            "writeback_status": args.writeback_status,
            "needs_later_patch_after_review": args.needs_later_patch_after_review,
            "promotion_blocker_after_review": args.promotion_blocker_after_review,
            "notes": args.notes,
        },
    )
    printable = dict(result)
    printable["paths"] = {key: str(value) for key, value in result["paths"].items()}
    print(json.dumps(printable, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
