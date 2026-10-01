"""Data loading and UI-only draft persistence for the P6.3 review UI."""

from __future__ import annotations

import argparse
import copy
import json
from datetime import datetime, timezone
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    from validators import (
        EXPECTED_CHAIN_STEPS,
        validate_candidate_record,
        validate_draft,
        validate_draft_errors,
        validate_workbench_bundle,
    )
except ImportError:  # pragma: no cover - package-style import fallback
    from .validators import (
        EXPECTED_CHAIN_STEPS,
        validate_candidate_record,
        validate_draft,
        validate_draft_errors,
        validate_workbench_bundle,
    )

try:
    from diff_utils import build_diff_preview
except ImportError:  # pragma: no cover
    from .diff_utils import build_diff_preview

try:
    from writeback import WRITEBACK_ENABLED, resolve_workbench_path, uses_workbench_paths
except ImportError:  # pragma: no cover
    from .writeback import WRITEBACK_ENABLED, resolve_workbench_path, uses_workbench_paths

try:
    from review_status import (
        load_latest_statuses,
        load_writeback_logs_by_sample_id,
        merge_status_for_display,
    )
except ImportError:  # pragma: no cover
    from .review_status import (
        load_latest_statuses,
        load_writeback_logs_by_sample_id,
        merge_status_for_display,
    )


RELEASE_NAME = "05_benchmark_annotation_review_evaluation"
SCRIPT_DIR = Path(__file__).resolve().parent
RELEASE_PACKAGE_ROOT = SCRIPT_DIR.parents[1]
DEFAULT_WORKBENCH_DIR = "private_review_workbench"
REQUIRED_ROOT_FILES = {
    "candidate_index": "ewvaa_candidate_index.multisource_v1_2.jsonl",
    "summary": "ewvaa_candidate_index.multisource_v1_2.summary.json",
    "p5_35": "reports/p5_35_attack_chain_evidence_fidelity_diagnostic.json",
    "p5_37": "reports/p5_37_promotion_candidate_selection_dry_run.json",
    "p5_38": "reports/p5_38_human_review_sheet.json",
}

BATCH_JSONL_FILES = [
    "final_candidate_gold.jsonl",
    "manual_review_required.jsonl",
    "reviewer_weighted_grounding_cases.jsonl",
]

BATCH_JSON_FILES = ["reviewer_weighted_grounding_report.json"]

PROMPT_EVIDENCE_FILE = "prompt_packs/reviewer_annotation_prompts.weighted.masked.jsonl"
STRICT_BLIND_MODEL_INPUT_FILE = (
    "strict_blind_benchmark/data/model_input.jsonl"
)
STRICT_BLIND_SAMPLE_INDEX_FILE = (
    "strict_blind_benchmark/data/sample_index.jsonl"
)
LOADER_CONFIG_FILE = "review_ui_loader_config.json"
DRAFT_DIR_NAME = "ui_drafts"
DRAFT_HISTORY_FILE = "reasoning_chain_drafts.jsonl"
DRAFT_LATEST_FILE = "reasoning_chain_drafts.latest.json"
DRAFT_META_FILE = "reasoning_chain_drafts.meta.json"
DRAFT_SCHEMA_VERSION = "review_ui_draft_v0.1"
DRAFT_STATUS = "draft_only"


@dataclass
class WorkbenchBundle:
    workbench_dir: Path
    candidate_index: list[dict[str, Any]] = field(default_factory=list)
    summary: dict[str, Any] | None = None
    p5_35: dict[str, Any] | None = None
    p5_37: dict[str, Any] | None = None
    p5_38: dict[str, Any] | None = None
    run_dirs: list[Path] = field(default_factory=list)
    batch_files: dict[str, list[Path]] = field(default_factory=dict)
    final_candidates_by_sample_id: dict[str, dict[str, Any]] = field(default_factory=dict)
    manual_review_by_sample_id: dict[str, dict[str, Any]] = field(default_factory=dict)
    weighted_cases_by_sample_id: dict[str, dict[str, Any]] = field(default_factory=dict)
    weighted_reports: list[dict[str, Any]] = field(default_factory=list)
    prompt_evidence_by_sample_id: dict[str, dict[str, Any]] = field(default_factory=dict)
    strict_blind_input_by_sample_id: dict[str, dict[str, Any]] = field(default_factory=dict)
    strict_blind_sample_index_by_sample_id: dict[str, dict[str, Any]] = field(default_factory=dict)
    resolved_loader_paths: dict[str, str] = field(default_factory=dict)
    latest_drafts_by_sample_id: dict[str, dict[str, Any]] = field(default_factory=dict)
    latest_review_status_by_sample_id: dict[str, dict[str, Any]] = field(default_factory=dict)
    writeback_logs_by_sample_id: dict[str, dict[str, Any]] = field(default_factory=dict)
    review_rows: list[dict[str, Any]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    writeback_enabled: bool = WRITEBACK_ENABLED


def read_json(path: Path, warnings: list[str], optional: bool = False) -> dict[str, Any] | None:
    if not path.exists():
        level = "Optional" if optional else "Required"
        warnings.append(f"{level} file missing: {path}")
        return None
    try:
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError as exc:
        warnings.append(f"Invalid JSON in {path}: {exc}")
        return None


def write_json(path: Path, obj: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def read_jsonl(path: Path, warnings: list[str], optional: bool = False) -> list[dict[str, Any]]:
    if not path.exists():
        level = "Optional" if optional else "Required"
        warnings.append(f"{level} file missing: {path}")
        return []
    rows = []
    with path.open("r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, start=1):
            if not line.strip():
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as exc:
                warnings.append(f"Invalid JSONL line {line_no} in {path}: {exc}")
                continue
            if isinstance(obj, dict):
                rows.append(obj)
            else:
                warnings.append(f"Non-object JSONL line {line_no} in {path}")
    return rows


def discover_run_dirs(workbench_dir: Path) -> list[Path]:
    return sorted(
        p
        for p in workbench_dir.iterdir()
        if p.is_dir() and p.name.startswith("multiagent_api_")
    )


def _index_by_sample_id(rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    indexed = {}
    for row in rows:
        sample_id = row.get("sample_id")
        if sample_id:
            indexed[sample_id] = row
    return indexed


def _release_root_for_workbench(workbench_dir: Path) -> Path | None:
    for candidate in (workbench_dir, *workbench_dir.parents):
        if candidate.name == RELEASE_NAME:
            return candidate
    return None


def _candidate_path_options(workbench_dir: Path, raw_path: Any) -> list[Path]:
    if not raw_path:
        return []
    if uses_workbench_paths(workbench_dir):
        return [resolve_workbench_path(workbench_dir, str(raw_path))]
    path = Path(str(raw_path))
    release_root = _release_root_for_workbench(workbench_dir)
    candidates: list[Path] = []
    if path.is_absolute():
        candidates.append(path)
    else:
        candidates.append(path)
        candidates.append(workbench_dir / path)
        candidates.append(workbench_dir / path.name)
        if release_root is not None:
            candidates.append(release_root / path)
    deduped: list[Path] = []
    seen: set[str] = set()
    for candidate in candidates:
        key = str(candidate)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(candidate)
    return deduped


def _resolve_run_dir_hint(workbench_dir: Path, raw_path: Any) -> Path:
    if uses_workbench_paths(workbench_dir):
        return resolve_workbench_path(workbench_dir, str(raw_path or "."))
    if not raw_path:
        return workbench_dir
    for candidate in _candidate_path_options(workbench_dir, raw_path):
        if candidate.exists():
            return candidate
    return workbench_dir


def _load_candidate_files_from_index(
    workbench_dir: Path,
    candidate_index: list[dict[str, Any]],
    warnings: list[str],
    resolved_loader_paths: dict[str, str] | None = None,
) -> tuple[dict[str, dict[str, Any]], dict[str, Path]]:
    config = _load_loader_config(workbench_dir, warnings)
    records = {}
    sample_to_run_dir = {}
    path_to_rows: dict[Path, list[dict[str, Any]]] = {}
    configured_primary = (
        config.get("formal_candidate_gold")
        or config.get("source_final_candidate_gold")
        or config.get("source_candidate_reasoning")
    )
    primary_path = _resolve_configured_path(
        workbench_dir,
        configured_primary,
        "final_candidate_gold.jsonl",
        warnings=warnings,
        context="formal_candidate_gold",
        allow_fallback=True,
    )
    if resolved_loader_paths is not None:
        resolved_loader_paths["formal_candidate_gold"] = str(primary_path)
    primary_rows = read_jsonl(primary_path, warnings, optional=False)
    primary_records = _index_by_sample_id(primary_rows)
    records.update(primary_records)
    for index_row in candidate_index:
        run_dir_value = index_row.get("run_dir_path") or index_row.get("run_dir")
        sample_id = index_row.get("sample_id")
        if sample_id:
            sample_to_run_dir[sample_id] = _resolve_run_dir_hint(workbench_dir, run_dir_value)
        path_value = index_row.get("candidate_file")
        if not path_value:
            warnings.append(f"Candidate index row missing candidate_file: {index_row.get('sample_id')}")
            continue
        for path in _candidate_path_options(workbench_dir, path_value):
            if path in path_to_rows:
                break
            if path == primary_path:
                path_to_rows[path] = primary_rows
                break
            if path.exists():
                path_to_rows[path] = read_jsonl(path, warnings, optional=False)
                break
    for index_row in candidate_index:
        sample_id = index_row.get("sample_id")
        if not sample_id:
            continue
        if sample_id in records:
            continue
        path_value = index_row.get("candidate_file")
        candidate_rows: list[dict[str, Any]] = []
        for path in _candidate_path_options(workbench_dir, path_value):
            if path in path_to_rows:
                candidate_rows = path_to_rows[path]
                break
        row_index = index_row.get("candidate_row_index")
        candidate = None
        if isinstance(row_index, int) and 0 <= row_index - 1 < len(candidate_rows):
            maybe = candidate_rows[row_index - 1]
            if maybe.get("sample_id") == sample_id:
                candidate = maybe
        if candidate is None:
            candidate = next((row for row in candidate_rows if row.get("sample_id") == sample_id), None)
        if candidate is None:
            warnings.append(f"Unable to resolve final candidate gold for sample_id={sample_id}")
            continue
        records[sample_id] = candidate
    return records, sample_to_run_dir


def _load_batch_files(bundle: WorkbenchBundle) -> None:
    bundle.batch_files = {name: [] for name in BATCH_JSONL_FILES + BATCH_JSON_FILES}
    config = _load_loader_config(bundle.workbench_dir, bundle.warnings)
    diagnostics = config.get("review_diagnostics")
    explicit_diagnostics = config.get("path_base") == "workbench" and isinstance(diagnostics, dict)
    if explicit_diagnostics:
        for key, filename in (
            ("manual_review", "manual_review_required.jsonl"),
            ("weighted_cases", "reviewer_weighted_grounding_cases.jsonl"),
            ("weighted_report", "reviewer_weighted_grounding_report.json"),
        ):
            configured = diagnostics.get(key)
            if configured is None or configured == "":
                continue
            if not isinstance(configured, str):
                bundle.warnings.append(f"Invalid review_diagnostics.{key}: expected a relative path")
                continue
            path = resolve_workbench_path(bundle.workbench_dir, configured)
            bundle.resolved_loader_paths[f"review_diagnostics.{key}"] = str(path)
            if path.is_file():
                bundle.batch_files[filename].append(path)
            else:
                bundle.warnings.append(f"Optional review diagnostic file missing or not a file: {path}")
    for run_dir in (() if explicit_diagnostics else bundle.run_dirs):
        for name in BATCH_JSONL_FILES:
            path = run_dir / name
            if uses_workbench_paths(bundle.workbench_dir):
                path = resolve_workbench_path(bundle.workbench_dir, path.relative_to(bundle.workbench_dir))
            if path.exists():
                bundle.batch_files[name].append(path)
            else:
                bundle.warnings.append(f"Optional batch file missing: {path}")
        for name in BATCH_JSON_FILES:
            path = run_dir / name
            if uses_workbench_paths(bundle.workbench_dir):
                path = resolve_workbench_path(bundle.workbench_dir, path.relative_to(bundle.workbench_dir))
            if path.exists():
                bundle.batch_files[name].append(path)
            else:
                bundle.warnings.append(f"Optional batch file missing: {path}")

    manual_rows = []
    weighted_rows = []
    final_rows = []
    for path in bundle.batch_files.get("manual_review_required.jsonl", []):
        manual_rows.extend(read_jsonl(path, bundle.warnings, optional=True))
    for path in bundle.batch_files.get("reviewer_weighted_grounding_cases.jsonl", []):
        weighted_rows.extend(read_jsonl(path, bundle.warnings, optional=True))
    for path in bundle.batch_files.get("final_candidate_gold.jsonl", []):
        final_rows.extend(read_jsonl(path, bundle.warnings, optional=True))
    for path in bundle.batch_files.get("reviewer_weighted_grounding_report.json", []):
        report = read_json(path, bundle.warnings, optional=True)
        if isinstance(report, dict):
            bundle.weighted_reports.append(report)
        elif report is not None:
            bundle.warnings.append(f"Invalid weighted grounding report: expected a JSON object in {path}")

    bundle.manual_review_by_sample_id = _index_by_sample_id(manual_rows)
    bundle.weighted_cases_by_sample_id = _index_by_sample_id(weighted_rows)
    discovered_candidates = _index_by_sample_id(final_rows)
    for sample_id, record in discovered_candidates.items():
        bundle.final_candidates_by_sample_id.setdefault(sample_id, record)


def _load_prompt_evidence(bundle: WorkbenchBundle) -> None:
    config = _load_loader_config(bundle.workbench_dir, bundle.warnings)
    configured_path = (
        config.get("compact_evidence", {}).get("reviewer_prompt_pack")
        if isinstance(config.get("compact_evidence"), dict)
        else None
    )
    path = _resolve_configured_path(
        bundle.workbench_dir,
        configured_path,
        PROMPT_EVIDENCE_FILE,
        warnings=bundle.warnings,
        context="compact_evidence.reviewer_prompt_pack",
        allow_fallback=not bool(configured_path),
    )
    bundle.resolved_loader_paths["reviewer_prompt_pack"] = str(path)
    rows = read_jsonl(path, bundle.warnings, optional=True)
    masked_to_sample = {
        row.get("masked_sample_id"): row.get("sample_id")
        for row in bundle.candidate_index
        if row.get("masked_sample_id") and row.get("sample_id")
    }
    for row in rows:
        prompt_sample_id = row.get("sample_id")
        real_sample_id = masked_to_sample.get(prompt_sample_id, prompt_sample_id)
        if real_sample_id:
            bundle.prompt_evidence_by_sample_id[real_sample_id] = row


def _load_strict_blind_inputs(bundle: WorkbenchBundle) -> None:
    config = _load_loader_config(bundle.workbench_dir, bundle.warnings)
    strict_config = config.get("strict_blind_evidence", {})
    strict_config = strict_config if isinstance(strict_config, dict) else {}
    configured_model_input = strict_config.get("model_input")
    configured_sample_index = strict_config.get("sample_index")
    model_path = _resolve_configured_path(
        bundle.workbench_dir,
        configured_model_input,
        STRICT_BLIND_MODEL_INPUT_FILE,
        warnings=bundle.warnings,
        context="strict_blind_evidence.model_input",
        allow_fallback=not bool(configured_model_input),
    )
    sample_index_path = _resolve_configured_path(
        bundle.workbench_dir,
        configured_sample_index,
        STRICT_BLIND_SAMPLE_INDEX_FILE,
        warnings=bundle.warnings,
        context="strict_blind_evidence.sample_index",
        allow_fallback=not bool(configured_sample_index),
    )
    bundle.resolved_loader_paths["strict_blind_model_input"] = str(model_path)
    bundle.resolved_loader_paths["strict_blind_sample_index"] = str(sample_index_path)
    masked_to_sample = {
        row.get("masked_sample_id"): row.get("sample_id")
        for row in bundle.candidate_index
        if row.get("masked_sample_id") and row.get("sample_id")
    }
    model_rows = read_jsonl(model_path, bundle.warnings, optional=True)
    for row in model_rows:
        row_sample_id = row.get("sample_id")
        real_sample_id = masked_to_sample.get(row_sample_id, row_sample_id)
        if real_sample_id:
            bundle.strict_blind_input_by_sample_id[real_sample_id] = row
    sample_index_rows = read_jsonl(sample_index_path, bundle.warnings, optional=True)
    for row in sample_index_rows:
        row_sample_id = row.get("sample_id")
        real_sample_id = masked_to_sample.get(row_sample_id, row_sample_id)
        if real_sample_id:
            bundle.strict_blind_sample_index_by_sample_id[real_sample_id] = row


def _load_loader_config(workbench_dir: Path, warnings: list[str]) -> dict[str, Any]:
    path = resolve_workbench_path(workbench_dir, LOADER_CONFIG_FILE)
    if not path.exists():
        return {}
    loaded = read_json(path, warnings, optional=True)
    return loaded if isinstance(loaded, dict) else {}


def _resolve_configured_path(
    workbench_dir: Path,
    configured: Any,
    fallback: str,
    *,
    warnings: list[str] | None = None,
    context: str = "",
    allow_fallback: bool = True,
) -> Path:
    if uses_workbench_paths(workbench_dir):
        path = resolve_workbench_path(workbench_dir, str(configured or fallback))
        if configured and not path.exists() and warnings is not None:
            warnings.append(f"Configured loader path missing for {context or 'configured path'}: {configured}")
        return path
    candidates = []
    release_root = _release_root_for_workbench(workbench_dir)
    if configured:
        configured_path = Path(str(configured))
        candidates.append(configured_path)
        if not configured_path.is_absolute():
            candidates.append(workbench_dir / configured_path)
            if release_root is not None:
                candidates.append(release_root / configured_path)
        for candidate in candidates:
            if candidate.exists():
                return candidate
        if warnings is not None:
            label = context or "configured path"
            warnings.append(
                f"Configured loader path missing for {label}; legacy fallback disabled: {configured}"
            )
        return candidates[0]
    if not allow_fallback:
        missing = Path(str(configured or fallback))
        if warnings is not None:
            label = context or "configured path"
            warnings.append(f"Loader path missing for {label}; fallback disabled: {missing}")
        return missing
    fallback_path = Path(fallback)
    candidates.append(workbench_dir / fallback_path)
    if release_root is not None:
        candidates.append(release_root / fallback_path)
    candidates.append(fallback_path)
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return candidates[0]


def _records_from_report(report: dict[str, Any] | None, key: str) -> dict[str, dict[str, Any]]:
    if not report:
        return {}
    rows = report.get(key, [])
    return _index_by_sample_id(rows if isinstance(rows, list) else [])


def _pick(*values: Any, default: Any = "") -> Any:
    for value in values:
        if value is not None and value != "":
            return value
    return default


def draft_dir(workbench_dir: str | Path) -> Path:
    if uses_workbench_paths(workbench_dir):
        return resolve_workbench_path(workbench_dir, DRAFT_DIR_NAME)
    return Path(workbench_dir) / DRAFT_DIR_NAME


def draft_paths(workbench_dir: str | Path) -> dict[str, Path]:
    base = draft_dir(workbench_dir)
    paths = {
        "dir": base,
        "history": base / DRAFT_HISTORY_FILE,
        "latest": base / DRAFT_LATEST_FILE,
        "meta": base / DRAFT_META_FILE,
        "diff_previews": base / "diff_previews",
    }
    if uses_workbench_paths(workbench_dir):
        root = Path(workbench_dir).resolve()
        return {key: resolve_workbench_path(root, path.relative_to(root)) for key, path in paths.items()}
    return paths


def ensure_draft_store(workbench_dir: str | Path) -> dict[str, Path]:
    paths = draft_paths(workbench_dir)
    paths["dir"].mkdir(parents=True, exist_ok=True)
    if not paths["history"].exists():
        paths["history"].touch()
    if not paths["latest"].exists():
        write_json(paths["latest"], {})
    if not paths["meta"].exists():
        write_json(
            paths["meta"],
            {
                "draft_schema_version": DRAFT_SCHEMA_VERSION,
                "draft_status": DRAFT_STATUS,
                "scope": "ui_drafts_only_not_formal_candidate",
                "formal_candidate_writeback": False,
                "candidate_index_modified": False,
                "dataset_release_v1_modified": False,
                "label_stage_modified": False,
                "canonical_gold_overwritten": False,
                "clean_final_promotion": False,
            },
        )
    return paths


def load_latest_drafts(workbench_dir: str | Path, warnings: list[str] | None = None) -> dict[str, dict[str, Any]]:
    local_warnings = warnings if warnings is not None else []
    path = draft_paths(workbench_dir)["latest"]
    if not path.exists():
        return {}
    loaded = read_json(path, local_warnings, optional=True)
    return loaded if isinstance(loaded, dict) else {}


def _copy_chain_with_fixed_steps(chain: list[dict[str, Any]]) -> list[dict[str, Any]]:
    copied = []
    for idx, step_name in enumerate(EXPECTED_CHAIN_STEPS):
        original_step = chain[idx] if idx < len(chain) and isinstance(chain[idx], dict) else {}
        step = copy.deepcopy(original_step)
        step["step"] = step_name
        step.setdefault("claim", "")
        step.setdefault("evidence_refs", copy.deepcopy(original_step.get("evidence_refs", [])))
        copied.append(step)
    return copied


def make_draft_from_original(
    row: dict[str, Any],
    *,
    existing_values: dict[str, Any] | None = None,
    now_utc: str | None = None,
) -> dict[str, Any]:
    candidate = row.get("candidate", {})
    index_row = row.get("candidate_index", {})
    sheet = row.get("p5_38_review_sheet", {})
    existing_values = existing_values or {}
    now = now_utc or datetime.now(timezone.utc).isoformat()
    source_path = index_row.get("candidate_file", "")
    source_run_dir = row.get("run_dir_path") or str(Path(source_path).parent if source_path else "")
    aux_note = copy.deepcopy(candidate.get("auxiliary_vulnerability_note", {}))
    if not isinstance(aux_note, dict):
        aux_note = {"claim": str(aux_note)}
    aux_note.setdefault("claim", "")
    return {
        "sample_id": row.get("sample_id", ""),
        "gold_stage": row.get("gold_stage", ""),
        "source_run_dir": source_run_dir,
        "source_final_candidate_gold_path": source_path,
        "draft_reasoning_chain": _copy_chain_with_fixed_steps(
            candidate.get("gold_reasoning_chain", [])
            if isinstance(candidate.get("gold_reasoning_chain"), list)
            else []
        ),
        "draft_auxiliary_vulnerability_note": aux_note,
        "reviewer_decision": existing_values.get("reviewer_decision", sheet.get("reviewer_decision", "")),
        "reviewer_notes": existing_values.get("reviewer_notes", sheet.get("reviewer_notes", "")),
        "promotion_decision": existing_values.get("promotion_decision", sheet.get("promotion_decision", "")),
        "clean_final_allowed": "no",
        "canonical_gold_allowed": "no",
        "created_at": now,
        "updated_at": now,
        "draft_schema_version": DRAFT_SCHEMA_VERSION,
        "draft_status": DRAFT_STATUS,
    }


def draft_to_candidate_like(draft: dict[str, Any], original_candidate: dict[str, Any]) -> dict[str, Any]:
    candidate_like = copy.deepcopy(original_candidate)
    candidate_like["gold_reasoning_chain"] = copy.deepcopy(draft.get("draft_reasoning_chain", []))
    candidate_like["auxiliary_vulnerability_note"] = copy.deepcopy(
        draft.get("draft_auxiliary_vulnerability_note", {})
    )
    return candidate_like


def save_draft(workbench_dir: str | Path, row: dict[str, Any], draft: dict[str, Any]) -> dict[str, Any]:
    original_candidate = row.get("candidate", {})
    original_gold_stage = row.get("gold_stage", "")
    errors = validate_draft_errors(
        draft,
        original_candidate,
        original_gold_stage,
        row.get("run_dir_path"),
        row.get("candidate_index", {}).get("candidate_file", ""),
    )
    if errors:
        return {"saved": False, "errors": errors, "paths": draft_paths(workbench_dir)}

    paths = ensure_draft_store(workbench_dir)
    now = datetime.now(timezone.utc).isoformat()
    latest = load_latest_drafts(workbench_dir)
    sample_id = draft["sample_id"]
    previous = latest.get(sample_id)
    to_save = copy.deepcopy(draft)
    to_save["created_at"] = previous.get("created_at", to_save.get("created_at", now)) if previous else to_save.get("created_at", now)
    to_save["updated_at"] = now
    to_save["draft_schema_version"] = DRAFT_SCHEMA_VERSION
    to_save["draft_status"] = DRAFT_STATUS
    to_save["clean_final_allowed"] = "no"
    to_save["canonical_gold_allowed"] = "no"

    with paths["history"].open("a", encoding="utf-8") as f:
        f.write(json.dumps(to_save, ensure_ascii=False) + "\n")
    latest[sample_id] = to_save
    write_json(paths["latest"], latest)
    write_json(
        paths["meta"],
        {
            "draft_schema_version": DRAFT_SCHEMA_VERSION,
            "draft_status": DRAFT_STATUS,
            "latest_updated_at": now,
            "latest_draft_count": len(latest),
            "history_file": str(paths["history"]),
            "latest_file": str(paths["latest"]),
            "formal_candidate_writeback": False,
            "candidate_index_modified": False,
            "dataset_release_v1_modified": False,
            "label_stage_modified": False,
            "canonical_gold_overwritten": False,
            "clean_final_promotion": False,
        },
    )
    return {"saved": True, "errors": [], "paths": paths, "draft": to_save}


def reset_draft_from_original(workbench_dir: str | Path, row: dict[str, Any]) -> dict[str, Any]:
    draft = make_draft_from_original(row)
    return save_draft(workbench_dir, row, draft)


def validate_row_draft(row: dict[str, Any], draft: dict[str, Any] | None = None) -> dict[str, Any]:
    draft_obj = draft if isinstance(draft, dict) else row.get("latest_draft")
    if not isinstance(draft_obj, dict):
        return {
            "sample_id": row.get("sample_id", ""),
            "valid": False,
            "errors": ["No draft exists for this sample"],
            "warnings": [],
            "checks": {},
        }
    return validate_draft(
        draft_obj,
        row.get("candidate", {}),
        row.get("gold_stage", ""),
        row.get("run_dir_path"),
        row.get("candidate_index", {}).get("candidate_file", ""),
    )


def preview_row_diff(row: dict[str, Any], draft: dict[str, Any] | None = None) -> dict[str, Any]:
    draft_obj = draft if isinstance(draft, dict) else row.get("latest_draft")
    if not isinstance(draft_obj, dict):
        return {
            "sample_id": row.get("sample_id", ""),
            "available": False,
            "message": "No draft exists for this sample",
            "changed": False,
            "fields": [],
            "markdown": "No draft exists for this sample.",
        }
    return build_diff_preview(row, draft_obj)


def save_diff_preview(workbench_dir: str | Path, diff_preview: dict[str, Any]) -> dict[str, Path]:
    paths = ensure_draft_store(workbench_dir)
    diff_dir = paths["diff_previews"]
    diff_dir.mkdir(parents=True, exist_ok=True)
    sample_id = diff_preview.get("sample_id", "unknown_sample")
    safe_sample_id = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in sample_id)
    json_path = diff_dir / f"{safe_sample_id}.diff.json"
    md_path = diff_dir / f"{safe_sample_id}.diff.md"
    write_json(json_path, diff_preview)
    md_path.write_text(diff_preview.get("markdown", ""), encoding="utf-8")
    return {"json": json_path, "markdown": md_path}


def _build_review_rows(bundle: WorkbenchBundle, sample_to_run_dir: dict[str, Path]) -> None:
    p35_by_sample = _records_from_report(bundle.p5_35, "sample_diagnostics")
    p37_by_sample = _records_from_report(bundle.p5_37, "sample_dry_run_table")
    p38_by_sample = _records_from_report(bundle.p5_38, "review_sheet")
    portable_paths = uses_workbench_paths(bundle.workbench_dir)
    rows = []
    for index_row in bundle.candidate_index:
        sample_id = index_row.get("sample_id", "")
        candidate = bundle.final_candidates_by_sample_id.get(sample_id, {})
        p35 = p35_by_sample.get(sample_id, {})
        p37 = p37_by_sample.get(sample_id, {})
        p38 = p38_by_sample.get(sample_id, {})
        weighted = bundle.weighted_cases_by_sample_id.get(sample_id, {})
        manual = bundle.manual_review_by_sample_id.get(sample_id, {})
        label = candidate.get("label") if isinstance(candidate.get("label"), dict) else {}
        row = {
            "sample_id": sample_id,
            "masked_sample_id": index_row.get("masked_sample_id", ""),
            "scenario_id": _pick(candidate.get("scenario_id"), index_row.get("scenario_id")),
            "batch_id": _pick(index_row.get("batch_id"), p37.get("batch_id"), p38.get("batch_id")),
            "run_dir": _pick(index_row.get("run_dir"), sample_to_run_dir.get(sample_id)),
            "run_dir_path": (
                str(index_row.get("run_dir_path") or index_row.get("run_dir") or ".")
                if portable_paths else str(sample_to_run_dir.get(sample_id, ""))
            ),
            "gold_stage": _pick(index_row.get("gold_stage"), p37.get("gold_stage"), label.get("stage")),
            "weighted_verdict": _pick(
                p37.get("weighted_verdict"),
                p38.get("weighted_verdict"),
                weighted.get("verdict"),
                index_row.get("weighted_status"),
            ),
            "human_review_priority": _pick(p37.get("human_review_priority"), p38.get("human_review_priority")),
            "original_human_review_priority": _pick(p37.get("human_review_priority"), p38.get("human_review_priority")),
            "dry_run_level": _pick(p37.get("dry_run_level"), p38.get("dry_run_level")),
            "promotion_blocker": _pick(p37.get("promotion_blocker"), p38.get("promotion_blocker")),
            "original_promotion_blocker": _pick(p37.get("promotion_blocker"), p38.get("promotion_blocker")),
            "needs_later_patch": _pick(p37.get("needs_later_patch"), p38.get("needs_later_patch")),
            "original_needs_later_patch": _pick(p37.get("needs_later_patch"), p38.get("needs_later_patch")),
            "recommended_action": _pick(
                p38.get("recommended_next_action"),
                p37.get("recommended_next_action"),
                p35.get("recommended_action"),
            ),
            "generic_template_risk": _pick(p37.get("generic_template_risk"), p38.get("generic_template_risk"), p35.get("generic_template_risk")),
            "candidate": candidate,
            "candidate_index": index_row,
            "p5_35_diagnostic": p35,
            "p5_37_dry_run": p37,
            "p5_38_review_sheet": p38,
            "weighted_case": weighted,
            "manual_review": manual,
            "prompt_evidence": bundle.prompt_evidence_by_sample_id.get(sample_id, {}),
            "strict_blind_input": bundle.strict_blind_input_by_sample_id.get(sample_id, {}),
            "strict_blind_sample_index": bundle.strict_blind_sample_index_by_sample_id.get(sample_id, {}),
            "latest_draft": bundle.latest_drafts_by_sample_id.get(sample_id),
            "human_review_status": merge_status_for_display(
                {
                    "sample_id": sample_id,
                    "masked_sample_id": index_row.get("masked_sample_id", ""),
                    "gold_stage": _pick(index_row.get("gold_stage"), p37.get("gold_stage"), label.get("stage")),
                    "human_review_priority": _pick(p37.get("human_review_priority"), p38.get("human_review_priority")),
                    "needs_later_patch": _pick(p37.get("needs_later_patch"), p38.get("needs_later_patch")),
                    "promotion_blocker": _pick(p37.get("promotion_blocker"), p38.get("promotion_blocker")),
                },
                bundle.latest_review_status_by_sample_id.get(sample_id),
                bundle.writeback_logs_by_sample_id.get(sample_id),
            ),
            "structure_warnings": validate_candidate_record(candidate) if candidate else ["missing candidate record"],
        }
        status = row["human_review_status"]
        row["review_status"] = status.get("review_status", "not_reviewed")
        row["writeback_status"] = status.get("writeback_status", "not_written_back")
        row["needs_later_patch_after_review"] = status.get("needs_later_patch_after_review", "")
        row["promotion_blocker_after_review"] = status.get("promotion_blocker_after_review", "")
        row["effective_review_priority"] = status.get("effective_review_priority", row.get("human_review_priority", ""))
        row["after_review_status"] = status.get("after_review_status", "pending_review")
        row["review_resolution_status"] = status.get("review_resolution_status", row["after_review_status"])
        row["reviewed_at"] = status.get("reviewed_at", "")
        row["has_writeback_log"] = bool(status.get("has_writeback_log"))
        rows.append(row)
    bundle.review_rows = rows


def resolve_workbench_dir(workbench_dir: str | Path | None = DEFAULT_WORKBENCH_DIR) -> Path:
    if workbench_dir is None or str(workbench_dir).strip() == "":
        workbench_path = Path(DEFAULT_WORKBENCH_DIR)
    else:
        workbench_path = Path(workbench_dir)
    if workbench_path == Path(DEFAULT_WORKBENCH_DIR) and not workbench_path.exists():
        raise FileNotFoundError(
            "The private Review UI workbench is missing: "
            f"{DEFAULT_WORKBENCH_DIR}. Pass --workbench-dir explicitly."
        )
    return workbench_path


def load_workbench(workbench_dir: str | Path | None = DEFAULT_WORKBENCH_DIR) -> WorkbenchBundle:
    workbench_path = resolve_workbench_dir(workbench_dir)
    if uses_workbench_paths(workbench_path):
        workbench_path = workbench_path.resolve()
        for relative_path in REQUIRED_ROOT_FILES.values():
            resolve_workbench_path(workbench_path, relative_path)
        for relative_path in (
            "ui_drafts/human_review_status.latest.json",
            "ui_drafts/writeback_log.jsonl",
        ):
            resolve_workbench_path(workbench_path, relative_path)
    bundle = WorkbenchBundle(workbench_dir=workbench_path)
    bundle.candidate_index = read_jsonl(
        workbench_path / REQUIRED_ROOT_FILES["candidate_index"], bundle.warnings, optional=False
    )
    bundle.summary = read_json(workbench_path / REQUIRED_ROOT_FILES["summary"], bundle.warnings, optional=False)
    bundle.p5_35 = read_json(workbench_path / REQUIRED_ROOT_FILES["p5_35"], bundle.warnings, optional=False)
    bundle.p5_37 = read_json(workbench_path / REQUIRED_ROOT_FILES["p5_37"], bundle.warnings, optional=False)
    bundle.p5_38 = read_json(workbench_path / REQUIRED_ROOT_FILES["p5_38"], bundle.warnings, optional=False)
    loader_config = _load_loader_config(workbench_path, bundle.warnings)
    explicit_diagnostics = (
        loader_config.get("path_base") == "workbench"
        and isinstance(loader_config.get("review_diagnostics"), dict)
    )
    bundle.run_dirs = (
        discover_run_dirs(workbench_path)
        if workbench_path.exists() and not explicit_diagnostics else []
    )
    if not bundle.run_dirs and not (workbench_path / "final_candidate_gold.jsonl").exists():
        bundle.warnings.append(f"No batch run_dir discovered under: {workbench_path}")
    resolved_candidates, sample_to_run_dir = _load_candidate_files_from_index(
        workbench_path,
        bundle.candidate_index,
        bundle.warnings,
        bundle.resolved_loader_paths,
    )
    bundle.final_candidates_by_sample_id.update(resolved_candidates)
    _load_batch_files(bundle)
    _load_prompt_evidence(bundle)
    _load_strict_blind_inputs(bundle)
    bundle.latest_drafts_by_sample_id = load_latest_drafts(workbench_path, bundle.warnings)
    bundle.latest_review_status_by_sample_id = load_latest_statuses(workbench_path, bundle.warnings)
    bundle.writeback_logs_by_sample_id = load_writeback_logs_by_sample_id(workbench_path, bundle.warnings)
    _build_review_rows(bundle, sample_to_run_dir)
    bundle.warnings.extend(validate_workbench_bundle(bundle))
    return bundle


def get_sample_detail(bundle: WorkbenchBundle, sample_id: str) -> dict[str, Any] | None:
    return next((row for row in bundle.review_rows if row.get("sample_id") == sample_id), None)


def _summary_expected_sample_count(summary: dict[str, Any] | None) -> int | None:
    if not isinstance(summary, dict):
        return None
    for key in (
        "candidate_count",
        "candidate_index_count",
        "final_candidate_gold_count",
        "candidate_existing",
        "queue_count",
    ):
        value = summary.get(key)
        if isinstance(value, int) and value >= 0:
            return value
    return None


def smoke_check(workbench_dir: str | Path = DEFAULT_WORKBENCH_DIR) -> dict[str, Any]:
    bundle = load_workbench(workbench_dir)
    sample_id_to_run_dir_resolved_count = sum(
        1 for row in bundle.review_rows if row.get("run_dir_path")
    )
    expected_sample_count = _summary_expected_sample_count(bundle.summary)
    if expected_sample_count is None:
        expected_sample_count = len(bundle.candidate_index)
    result = {
        "candidate_count": len(bundle.candidate_index),
        "candidate_index_loaded": bool(bundle.candidate_index),
        "summary_loaded": bundle.summary is not None,
        "p5_35_loaded": bundle.p5_35 is not None,
        "p5_37_loaded": bundle.p5_37 is not None,
        "p5_38_loaded": bundle.p5_38 is not None,
        "final_candidate_gold_loaded_count": len(bundle.final_candidates_by_sample_id),
        "sample_id_to_run_dir_resolved_count": sample_id_to_run_dir_resolved_count,
        "reviewer_prompt_evidence_loaded_count": len(bundle.prompt_evidence_by_sample_id),
        "strict_blind_input_loaded_count": len(bundle.strict_blind_input_by_sample_id),
        "latest_draft_loaded_count": len(bundle.latest_drafts_by_sample_id),
        "latest_review_status_loaded_count": len(bundle.latest_review_status_by_sample_id),
        "writeback_log_sample_count": len(bundle.writeback_logs_by_sample_id),
        "draft_validation_available": True,
        "human_review_status_available": True,
        "diff_preview_available": True,
        "writeback_enabled": bundle.writeback_enabled,
        "resolved_loader_paths": bundle.resolved_loader_paths,
        "warnings": bundle.warnings,
    }
    expected = {
        "candidate_count": expected_sample_count,
        "candidate_index_loaded": True,
        "summary_loaded": True,
        "p5_35_loaded": True,
        "p5_37_loaded": True,
        "p5_38_loaded": True,
        "final_candidate_gold_loaded_count": expected_sample_count,
        "sample_id_to_run_dir_resolved_count": expected_sample_count,
        "writeback_enabled": False,
    }
    failures = []
    for key, expected_value in expected.items():
        if result.get(key) != expected_value:
            failures.append(f"{key}: expected {expected_value!r}, got {result.get(key)!r}")
    if result["reviewer_prompt_evidence_loaded_count"] < 1:
        failures.append("reviewer_prompt_evidence_loaded_count: expected >= 1")
    result["passed"] = not failures
    result["failures"] = failures
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workbench-dir", default=DEFAULT_WORKBENCH_DIR)
    parser.add_argument("--smoke-check", action="store_true")
    args = parser.parse_args()
    if args.smoke_check:
        result = smoke_check(args.workbench_dir)
        for key, value in result.items():
            if key in {"warnings", "failures"}:
                continue
            print(f"{key} = {str(value).lower() if isinstance(value, bool) else value}")
        for warning in result["warnings"]:
            print(f"WARNING: {warning}")
        for failure in result["failures"]:
            print(f"FAIL: {failure}")
        return 0 if result["passed"] else 1
    bundle = load_workbench(args.workbench_dir)
    print(json.dumps({
        "workbench_dir": str(bundle.workbench_dir),
        "review_row_count": len(bundle.review_rows),
        "warnings": bundle.warnings,
        "writeback_enabled": bundle.writeback_enabled,
    }, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
