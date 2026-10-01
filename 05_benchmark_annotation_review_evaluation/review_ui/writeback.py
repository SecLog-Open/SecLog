"""Safety-gated single-sample writeback for review UI drafts."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path, PureWindowsPath
from typing import Any

try:
    from validators import validate_draft
except ImportError:  # pragma: no cover
    from .validators import validate_draft


WRITEBACK_ENABLED = False
DRAFT_LATEST_FILE = "ui_drafts/reasoning_chain_drafts.latest.json"
WRITEBACK_LOG_FILE = "ui_drafts/writeback_log.jsonl"
ALLOWED_FORMAL_FIELDS = ["gold_reasoning_chain", "auxiliary_vulnerability_note"]
LOADER_CONFIG_FILE = "review_ui_loader_config.json"


def resolve_workbench_path(workbench_dir: str | Path, value: str | Path) -> Path:
    """Resolve a relative workbench path without allowing directory escapes."""
    raw = str(value)
    if not raw.strip():
        raise ValueError("workbench path must not be empty")
    path = Path(raw.replace("\\", "/"))
    if path.is_absolute() or PureWindowsPath(raw).drive:
        raise ValueError(f"workbench path must be relative: {value}")
    root = Path(workbench_dir).resolve()
    resolved = (root / path).resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"workbench path escapes its directory: {value}") from exc
    return resolved


def uses_workbench_paths(workbench_dir: str | Path) -> bool:
    config_path = resolve_workbench_path(workbench_dir, LOADER_CONFIG_FILE)
    if not config_path.exists():
        return False
    config = read_json(config_path)
    return isinstance(config, dict) and config.get("path_base") == "workbench"


def _stored_path(workbench_dir: Path, relative_path: str) -> Path:
    if uses_workbench_paths(workbench_dir):
        return resolve_workbench_path(workbench_dir, relative_path)
    return workbench_dir / relative_path


def writeback_disabled(*args, **kwargs):
    """Reject broad or legacy formal candidate writeback attempts."""
    raise RuntimeError(
        "General formal candidate writeback is disabled; use the "
        "single-sample safety-gated function instead."
    )


def save_review_decision(*args, **kwargs):
    """Placeholder for future formal review persistence."""
    return writeback_disabled(*args, **kwargs)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def read_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def read_jsonl_with_raw(path: Path) -> list[tuple[str, dict[str, Any]]]:
    rows = []
    with path.open("r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, start=1):
            if not line.strip():
                continue
            obj = json.loads(line)
            if not isinstance(obj, dict):
                raise ValueError(f"JSONL line {line_no} in {path} is not an object")
            rows.append((line, obj))
    return rows


def write_jsonl_lines(path: Path, lines: list[str]) -> None:
    tmp = path.with_suffix(path.suffix + ".review_ui.tmp")
    with tmp.open("w", encoding="utf-8") as f:
        for line in lines:
            f.write(line)
    tmp.replace(path)


def _candidate_index_path(workbench_dir: Path) -> Path:
    return _stored_path(workbench_dir, "ewvaa_candidate_index.multisource_v1_2.jsonl")


def _latest_drafts_path(workbench_dir: Path) -> Path:
    return _stored_path(workbench_dir, DRAFT_LATEST_FILE)


def _writeback_log_path(workbench_dir: Path) -> Path:
    return _stored_path(workbench_dir, WRITEBACK_LOG_FILE)


def _load_candidate_index_row(workbench_dir: Path, sample_id: str) -> dict[str, Any]:
    path = _candidate_index_path(workbench_dir)
    matches = []
    for _raw, row in read_jsonl_with_raw(path):
        if row.get("sample_id") == sample_id:
            matches.append(row)
    if len(matches) != 1:
        raise ValueError(
            f"candidate index must contain exactly one row for {sample_id}; found {len(matches)}"
        )
    return matches[0]


def _load_latest_draft(workbench_dir: Path, sample_id: str) -> dict[str, Any]:
    path = _latest_drafts_path(workbench_dir)
    if not path.exists():
        raise FileNotFoundError(f"latest draft file not found: {path}")
    latest = read_json(path)
    if not isinstance(latest, dict) or sample_id not in latest:
        raise ValueError(f"sample_id does not exist in latest drafts: {sample_id}")
    draft = latest[sample_id]
    if not isinstance(draft, dict):
        raise ValueError(f"latest draft for {sample_id} is not an object")
    return draft


def _paths_equal(left: str | Path, right: str | Path) -> bool:
    left_path = Path(left)
    right_path = Path(right)
    if str(left_path) == str(right_path):
        return True
    try:
        return left_path.resolve() == right_path.resolve()
    except OSError:
        return False


def _updated_candidate_from_draft(
    original_candidate: dict[str, Any], draft: dict[str, Any]
) -> dict[str, Any]:
    updated = copy.deepcopy(original_candidate)
    updated["gold_reasoning_chain"] = copy.deepcopy(draft["draft_reasoning_chain"])
    updated["auxiliary_vulnerability_note"] = copy.deepcopy(
        draft["draft_auxiliary_vulnerability_note"]
    )
    for forbidden in [
        "reviewer_decision",
        "reviewer_notes",
        "promotion_decision",
        "human_verified",
        "canonical_gold",
    ]:
        updated.pop(forbidden, None)
    return updated


def _changed_fields(original_candidate: dict[str, Any], updated_candidate: dict[str, Any]) -> list[str]:
    return [
        field
        for field in ALLOWED_FORMAL_FIELDS
        if original_candidate.get(field) != updated_candidate.get(field)
    ]


def _validate_formal_update(
    *,
    original_candidate: dict[str, Any],
    updated_candidate: dict[str, Any],
    draft: dict[str, Any],
    index_row: dict[str, Any],
) -> None:
    if updated_candidate.get("sample_id") != original_candidate.get("sample_id"):
        raise ValueError("sample_id changed in formal update")
    if updated_candidate.get("window") != original_candidate.get("window"):
        raise ValueError("window changed in formal update")
    if updated_candidate.get("reasoning_schema_version") != original_candidate.get(
        "reasoning_schema_version"
    ):
        raise ValueError("reasoning_schema_version changed in formal update")
    if updated_candidate.get("candidate_status") != original_candidate.get("candidate_status"):
        raise ValueError("candidate_status changed in formal update")
    original_label = original_candidate.get("label", {})
    updated_label = updated_candidate.get("label", {})
    if updated_label != original_label:
        raise ValueError("label changed in formal update")
    if updated_candidate.get("clean_final") is True:
        raise ValueError("clean_final=true is forbidden")
    if draft.get("canonical_gold_allowed") == "yes":
        raise ValueError("canonical_gold_allowed=yes is forbidden")
    if "human_verified" in updated_candidate:
        raise ValueError("human_verified must not be written")
    if "canonical_gold" in updated_candidate:
        raise ValueError("canonical_gold must not be written")
    changed = set(_changed_fields(original_candidate, updated_candidate))
    full_changed = {
        key
        for key in set(original_candidate) | set(updated_candidate)
        if original_candidate.get(key) != updated_candidate.get(key)
    }
    if not full_changed.issubset(set(ALLOWED_FORMAL_FIELDS)):
        raise ValueError(
            "formal update includes disallowed fields: "
            + ", ".join(sorted(full_changed - set(ALLOWED_FORMAL_FIELDS)))
        )
    if changed and not changed.issubset(set(ALLOWED_FORMAL_FIELDS)):
        raise ValueError("changed fields exceed the review writeback allowlist")
    if index_row.get("sample_id") != original_candidate.get("sample_id"):
        raise ValueError("candidate index sample_id does not match target candidate")


def _backup_token(value: str) -> str:
    token = "".join(ch if ch.isalnum() or ch in {"-", "_"} else "_" for ch in value)
    return token or "unknown_sample"


def _make_backup(target_path: Path, timestamp: str, sample_id: str) -> Path:
    backup_dir = target_path.parent / ".backups"
    backup_dir.mkdir(parents=True, exist_ok=True)
    suffix = target_path.suffix or ".jsonl"
    stem = target_path.stem or "final_candidate_gold"
    sample_token = _backup_token(sample_id)
    backup_path = backup_dir / f"{stem}.backup.{sample_token}.{timestamp}{suffix}"
    counter = 1
    while backup_path.exists():
        backup_path = backup_dir / f"{stem}.backup.{sample_token}.{timestamp}.{counter}{suffix}"
        counter += 1
    shutil.copy2(target_path, backup_path)
    return backup_path


def _append_writeback_log(workbench_dir: Path, event: dict[str, Any]) -> None:
    path = _writeback_log_path(workbench_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(event, ensure_ascii=False, separators=(",", ":")) + "\n")


def write_single_sample_draft_to_final_candidate(
    *,
    workbench_dir: str,
    sample_id: str,
    require_validation: bool = True,
    dry_run: bool = True,
    confirm_writeback: bool = False,
) -> dict[str, Any]:
    """Preview or apply a safety-gated single-sample draft writeback."""
    workbench_path = Path(workbench_dir)
    if not sample_id or not isinstance(sample_id, str):
        raise ValueError("exactly one sample_id string is required")

    index_row = _load_candidate_index_row(workbench_path, sample_id)
    draft = _load_latest_draft(workbench_path, sample_id)
    portable_paths = uses_workbench_paths(workbench_path)
    draft_target = draft.get("source_final_candidate_gold_path", "")
    index_target = index_row.get("candidate_file", "")
    if not draft_target:
        raise ValueError("draft.source_final_candidate_gold_path is empty")
    if not index_target:
        raise ValueError("candidate index candidate_file is empty")
    if portable_paths:
        target_path = resolve_workbench_path(workbench_path, draft_target)
        expected_target_path = resolve_workbench_path(workbench_path, index_target)
        expected_run_dir = index_row.get("run_dir_path") or index_row.get("run_dir") or str(Path(index_target).parent)
        resolve_workbench_path(workbench_path, expected_run_dir)
        resolve_workbench_path(workbench_path, draft.get("source_run_dir", ""))
        target_reference = str(index_target)
    else:
        target_path = Path(draft_target)
        expected_target_path = Path(index_target)
        expected_run_dir = index_row.get("run_dir_path") or str(target_path.parent)
        target_reference = str(target_path)
    if not _paths_equal(target_path, expected_target_path):
        raise ValueError(
            "draft target path does not match candidate index candidate_file: "
            f"{target_path} != {expected_target_path}"
        )
    if not target_path.exists():
        raise FileNotFoundError(f"target final_candidate_gold.jsonl not found: {target_path}")

    rows_with_raw = read_jsonl_with_raw(target_path)
    target_indices = [
        idx for idx, (_raw, row) in enumerate(rows_with_raw) if row.get("sample_id") == sample_id
    ]
    if len(target_indices) != 1:
        raise ValueError(
            f"target JSONL must contain exactly one row for {sample_id}; found {len(target_indices)}"
        )
    target_index = target_indices[0]
    original_candidate = rows_with_raw[target_index][1]
    validation = validate_draft(
        draft,
        original_candidate,
        index_row.get("gold_stage"),
        expected_run_dir,
        str(index_target) if portable_paths else str(expected_target_path),
    )
    if require_validation and not validation["valid"]:
        return {
            "ok": False,
            "dry_run": dry_run,
            "sample_id": sample_id,
            "validation": validation,
            "errors": validation["errors"],
        }

    updated_candidate = _updated_candidate_from_draft(original_candidate, draft)
    _validate_formal_update(
        original_candidate=original_candidate,
        updated_candidate=updated_candidate,
        draft=draft,
        index_row=index_row,
    )
    changed_fields = _changed_fields(original_candidate, updated_candidate)
    projected_rows = [copy.deepcopy(row) for _raw, row in rows_with_raw]
    projected_rows[target_index] = updated_candidate
    original_lines = [raw for raw, _row in rows_with_raw]
    projected_lines = list(original_lines)
    changed_fields = _changed_fields(original_candidate, updated_candidate)
    if changed_fields:
        projected_lines[target_index] = (
            json.dumps(updated_candidate, ensure_ascii=False, separators=(",", ":")) + "\n"
        )
    changed_sample_count = sum(
        1 for idx, (_raw, row) in enumerate(rows_with_raw) if row != projected_rows[idx]
    )
    changed_line_count = sum(
        1 for idx, raw in enumerate(original_lines) if raw != projected_lines[idx]
    )
    other_rows_unchanged = all(
        row == projected_rows[idx]
        for idx, (_raw, row) in enumerate(rows_with_raw)
        if idx != target_index
    )
    if not other_rows_unchanged:
        raise ValueError("non-target rows changed in projected writeback")
    if len(projected_rows) != len(rows_with_raw):
        raise ValueError("projected row count changed")

    before_sha256 = sha256_file(target_path)
    projected_text = "".join(projected_lines)
    projected_after_sha256 = sha256_text(projected_text)
    base_result = {
        "ok": True,
        "event": "single_sample_writeback",
        "dry_run": dry_run,
        "would_write": bool(changed_fields),
        "sample_id": sample_id,
        "gold_stage": index_row.get("gold_stage"),
        "source_run_dir": draft.get("source_run_dir"),
        "target_final_candidate_gold_path": target_reference,
        "draft_schema_version": draft.get("draft_schema_version"),
        "validation_passed": validation["valid"],
        "validation": validation,
        "changed_fields": changed_fields,
        "before_sha256": before_sha256,
        "projected_after_sha256": projected_after_sha256,
        "after_sha256": None,
        "backup_path": None,
        "backup_sha256": None,
        "changed_line_count": changed_line_count,
        "changed_sample_count": changed_sample_count,
        "line_count_before": len(rows_with_raw),
        "line_count_after": len(projected_rows),
        "other_sample_rows_unchanged": other_rows_unchanged,
        "candidate_index_modified": False,
        "dataset_release_modified": False,
        "canonical_gold_modified": False,
        "clean_final_promotion": False,
        "operator": "manual_review_ui",
    }
    if dry_run:
        return base_result
    if not confirm_writeback:
        return {
            **base_result,
            "ok": False,
            "errors": ["confirm_writeback=True is required for real writeback"],
        }
    if not changed_fields:
        return {
            **base_result,
            "ok": False,
            "errors": ["no allowed formal fields differ; real writeback skipped"],
        }

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_%f")
    if portable_paths:
        target_relative = target_path.relative_to(workbench_path.resolve())
        resolve_workbench_path(workbench_path, target_relative.parent / ".backups")
        resolve_workbench_path(workbench_path, target_relative.with_suffix(target_path.suffix + ".review_ui.tmp"))
        _writeback_log_path(workbench_path)
    backup_path = _make_backup(target_path, timestamp, sample_id)
    backup_sha256 = sha256_file(backup_path)
    if backup_sha256 != before_sha256:
        raise ValueError("backup sha256 does not match target before sha256")

    write_jsonl_lines(target_path, projected_lines)
    after_rows = read_jsonl_with_raw(target_path)
    if len(after_rows) != len(rows_with_raw):
        raise ValueError("row count changed after writeback")
    if after_rows[target_index][1].get("sample_id") != sample_id:
        raise ValueError("target sample_id changed after writeback")
    for idx, (_raw, row) in enumerate(rows_with_raw):
        if idx != target_index and after_rows[idx][1] != row:
            raise ValueError("non-target row changed after writeback")
        if idx != target_index and after_rows[idx][0] != rows_with_raw[idx][0]:
            raise ValueError("non-target raw line changed after writeback")
    after_candidate = after_rows[target_index][1]
    post_validation = validate_draft(
        draft,
        after_candidate,
        index_row.get("gold_stage"),
        expected_run_dir,
        str(index_target) if portable_paths else str(expected_target_path),
    )
    if require_validation and not post_validation["valid"]:
        raise ValueError("post-writeback validation failed")
    after_sha256 = sha256_file(target_path)
    event = {
        "event": "single_sample_writeback",
        "sample_id": sample_id,
        "gold_stage": index_row.get("gold_stage"),
        "source_run_dir": draft.get("source_run_dir"),
        "target_final_candidate_gold_path": target_reference,
        "backup_path": str(backup_path),
        "draft_schema_version": draft.get("draft_schema_version"),
        "validation_passed": True,
        "changed_fields": changed_fields,
        "operator": "manual_review_ui",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "before_sha256": before_sha256,
        "after_sha256": after_sha256,
        "candidate_index_modified": False,
        "dataset_release_modified": False,
        "canonical_gold_modified": False,
        "clean_final_promotion": False,
    }
    _append_writeback_log(workbench_path, event)
    return {
        **base_result,
        "dry_run": False,
        "after_sha256": after_sha256,
        "backup_path": str(backup_path),
        "backup_sha256": backup_sha256,
        "post_validation": post_validation,
        "writeback_log_path": str(_writeback_log_path(workbench_path)),
        "writeback_event": event,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workbench-dir", required=True)
    parser.add_argument("--sample-id", required=True)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--confirm-writeback", action="store_true")
    args = parser.parse_args()
    dry_run = True
    if args.write:
        dry_run = False
    elif args.dry_run:
        dry_run = True
    result = write_single_sample_draft_to_final_candidate(
        workbench_dir=args.workbench_dir,
        sample_id=args.sample_id,
        dry_run=dry_run,
        confirm_writeback=args.confirm_writeback,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
