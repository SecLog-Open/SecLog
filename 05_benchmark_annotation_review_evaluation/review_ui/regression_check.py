"""Readonly regression checks for the review UI P6 workflow."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

try:
    from data_loader import (
        DEFAULT_WORKBENCH_DIR,
        get_sample_detail,
        load_workbench,
        preview_row_diff,
        smoke_check,
        validate_row_draft,
    )
except ImportError:  # pragma: no cover
    from .data_loader import (
        DEFAULT_WORKBENCH_DIR,
        get_sample_detail,
        load_workbench,
        preview_row_diff,
        smoke_check,
        validate_row_draft,
    )


def run_regression_check(
    workbench_dir: str | Path,
    sample_id: str | None = None,
    *,
    include_writeback_dry_run: bool = False,
) -> dict[str, Any]:
    workbench_path = Path(workbench_dir)
    bundle = load_workbench(workbench_path)
    selected_sample_id = sample_id
    if selected_sample_id is None:
        selected_sample_id = next(iter(bundle.latest_drafts_by_sample_id), None)
    sample_id_requested = sample_id is not None

    result: dict[str, Any] = {
        "workbench_dir": str(workbench_path),
        "readonly": True,
        "smoke_check": smoke_check(workbench_path),
        "latest_draft_loaded_count": len(bundle.latest_drafts_by_sample_id),
        "sample_id": selected_sample_id,
        "draft_dependent_checks_skipped": False,
        "writeback_dry_run_skipped": not include_writeback_dry_run,
        "skip_reason": "",
        "validation": None,
        "diff_preview": None,
        "writeback_dry_run": None,
        "passed": False,
        "errors": [],
    }
    if not selected_sample_id:
        if sample_id_requested:
            result["errors"].append("requested sample_id is empty")
        else:
            result["draft_dependent_checks_skipped"] = True
            result["skip_reason"] = "no latest draft sample_id available"
            result["passed"] = result["smoke_check"].get("passed") is True
        return result

    row = get_sample_detail(bundle, selected_sample_id)
    draft = bundle.latest_drafts_by_sample_id.get(selected_sample_id)
    if row is None or draft is None:
        result["errors"].append(f"sample_id not found in loaded review rows/latest drafts: {selected_sample_id}")
        return result

    validation = validate_row_draft(row, draft)
    diff_preview = preview_row_diff(row, draft)
    result["validation"] = {
        "valid": validation.get("valid"),
        "errors": validation.get("errors", []),
        "warnings": validation.get("warnings", []),
    }
    result["diff_preview"] = {
        "available": diff_preview.get("available"),
        "changed": diff_preview.get("changed"),
        "changed_count": diff_preview.get("changed_count"),
        "preview_only": diff_preview.get("preview_only"),
    }
    if include_writeback_dry_run:
        try:
            from writeback import write_single_sample_draft_to_final_candidate
        except ImportError:  # pragma: no cover
            from .writeback import write_single_sample_draft_to_final_candidate

        writeback_dry_run = write_single_sample_draft_to_final_candidate(
            workbench_dir=str(workbench_path),
            sample_id=selected_sample_id,
            dry_run=True,
            confirm_writeback=False,
        )
        result["writeback_dry_run"] = {
            "ok": writeback_dry_run.get("ok"),
            "dry_run": writeback_dry_run.get("dry_run"),
            "would_write": writeback_dry_run.get("would_write"),
            "changed_fields": writeback_dry_run.get("changed_fields"),
            "changed_line_count": writeback_dry_run.get("changed_line_count"),
            "changed_sample_count": writeback_dry_run.get("changed_sample_count"),
        }
    else:
        result["writeback_dry_run"] = {
            "skipped": True,
            "reason": "disabled_by_default_for_no_writeback_regression_check",
        }
    result["passed"] = (
        result["smoke_check"].get("passed") is True
        and validation.get("valid") is True
        and diff_preview.get("available") is True
        and (
            not include_writeback_dry_run
            or (
                result["writeback_dry_run"].get("ok") is True
                and result["writeback_dry_run"].get("dry_run") is True
            )
        )
    )
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workbench-dir", default=DEFAULT_WORKBENCH_DIR)
    parser.add_argument("--sample-id")
    parser.add_argument("--include-writeback-dry-run", action="store_true")
    args = parser.parse_args()
    result = run_regression_check(
        args.workbench_dir,
        args.sample_id,
        include_writeback_dry_run=args.include_writeback_dry_run,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result.get("passed") else 1


if __name__ == "__main__":
    raise SystemExit(main())
