"""P6.26 batch helper for review UI packet export and guarded draft application."""

from __future__ import annotations

import argparse
import copy
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from batch_review_schema import (
        BATCH_REVIEW_SCHEMA_VERSION,
        build_identity_snapshot,
        validate_batch_review_output,
    )
    from data_loader import (
        DEFAULT_WORKBENCH_DIR,
        get_sample_detail,
        load_workbench,
        make_draft_from_original,
        preview_row_diff,
        save_draft,
        save_diff_preview,
        validate_row_draft,
    )
    from review_packet import build_review_packet, render_packet_markdown, safe_packet_stem, write_json
    from review_status import save_human_review_status
    from writeback import write_single_sample_draft_to_final_candidate
except ImportError:  # pragma: no cover
    from .batch_review_schema import (
        BATCH_REVIEW_SCHEMA_VERSION,
        build_identity_snapshot,
        validate_batch_review_output,
    )
    from .data_loader import (
        DEFAULT_WORKBENCH_DIR,
        get_sample_detail,
        load_workbench,
        make_draft_from_original,
        preview_row_diff,
        save_draft,
        save_diff_preview,
        validate_row_draft,
    )
    from .review_packet import build_review_packet, render_packet_markdown, safe_packet_stem, write_json
    from .review_status import save_human_review_status
    from .writeback import write_single_sample_draft_to_final_candidate


# Review packets and audit reports are run products. Keep the
# default outside the public release tree even when invoked from its root.
DEFAULT_PRIVATE_WORK_ROOT = Path(__file__).resolve().parents[3] / "seclog_work"
REPORT_DIR = DEFAULT_PRIVATE_WORK_ROOT / "review_ui"
PACKET_BATCH_ROOT = "ui_drafts/review_packets"
GPT_OUTPUT_FILE = "batch_review_outputs.jsonl"
GPT_BATCH_INPUT_FILE = "gpt_batch_input.md"
GPT_MARKDOWN_OUTPUT_FILE = "batch_gpt_review_output.md"
PER_SAMPLE_GPT_OUTPUT_FILE = "gpt_review_output.md"
LATEST_PACKET_MD = "latest_review_packet.md"
LATEST_PACKET_JSON = "latest_review_packet.json"
GPT_REVIEW_OUTPUT_PLACEHOLDER = ""
PER_SAMPLE_GPT_OUTPUT_PLACEHOLDER_TEXT = "Paste GPT Review UI copy-ready output here."
UNIFIED_DATASET_NAMESPACE = "seclog_bench_216"
DEFAULT_PRIVATE_SOURCE_FINAL_CANDIDATE_GOLD = "private_review_workbench/final_candidate_gold.jsonl"
PUBLIC_DATASET_NAMESPACES = {
    "seclog_bench_216",
    "window_selection_from_chain",
}
STAGE_BALANCED_PILOT12_MODE = "stage_balanced_pilot12"
DEFAULT_STAGE_BALANCED_STAGES = ("preparation", "execution", "result", "stage_unclosed")
EXPORT_ALL_REMAINING_SELECTION_MODE = "export_all_remaining_sequential_unreviewed"
EXPORT_ALL_REMAINING_EXPORT_ORDER = "sample_id_or_masked_label_ascending"


def _timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")


def _read_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def _read_review_text(path: Path) -> str:
    encodings = ("utf-8", "utf-8-sig", "gb18030", "gbk")
    last_error: UnicodeDecodeError | None = None
    for encoding in encodings:
        try:
            return path.read_text(encoding=encoding)
        except UnicodeDecodeError as exc:
            last_error = exc
    if last_error is not None:
        raise last_error
    return path.read_text(encoding="utf-8")


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows = []
    with path.open("r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, start=1):
            if not line.strip():
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as exc:
                rows.append(
                    {
                        "_batch_line_error": f"Invalid JSONL line {line_no}: {exc}",
                        "_line_no": line_no,
                    }
                )
                continue
            if not isinstance(obj, dict):
                rows.append(
                    {
                        "_batch_line_error": f"JSONL line {line_no} is not an object",
                        "_line_no": line_no,
                    }
                )
                continue
            obj["_line_no"] = line_no
            rows.append(obj)
    return rows


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n")


def _row_label(row: dict[str, Any]) -> str:
    return row.get("masked_sample_id") or row.get("sample_id") or ""


def _load_sample_list(path: str | None) -> set[str] | None:
    if not path:
        return None
    selected = set()
    sample_list_path = Path(path)
    with sample_list_path.open("r", encoding="utf-8") as f:
        for line in f:
            value = line.strip()
            if value and not value.startswith("#"):
                selected.add(value)
    return selected


def _normalize_flag(value: Any) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "y"}


def _workbench_dataset_namespace(workbench_dir: str | Path) -> str:
    workbench_path = Path(workbench_dir)
    for relative_path in ("review_ui_loader_config.json", "review_workbench_manifest.json"):
        path = workbench_path / relative_path
        if not path.exists():
            continue
        try:
            data = _read_json(path)
        except Exception:
            continue
        if isinstance(data, dict) and str(data.get("dataset_namespace", "")).strip():
            return str(data["dataset_namespace"]).strip()
    return ""


def _is_public_workbench(workbench_dir: str | Path) -> bool:
    return _workbench_dataset_namespace(workbench_dir) in PUBLIC_DATASET_NAMESPACES


def _workbench_loader_config(workbench_dir: str | Path) -> dict[str, Any]:
    path = Path(workbench_dir) / "review_ui_loader_config.json"
    if not path.exists():
        return {}
    try:
        data = _read_json(path)
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def _has_signal(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, (list, dict, set, tuple)):
        return bool(value)
    return True


def _source_final_candidate_gold_path(row: dict[str, Any]) -> str:
    candidate_index = row.get("candidate_index", {}) if isinstance(row.get("candidate_index"), dict) else {}
    preferred = candidate_index.get("final_candidate_gold_source")
    if str(preferred or "").strip():
        return str(preferred).strip()
    fallback = candidate_index.get("candidate_file", "")
    return str(fallback or "").strip()


def _row_metadata_ok(row: dict[str, Any]) -> tuple[bool, str]:
    required = {
        "masked_sample_label": _row_label(row),
        "sample_id": row.get("sample_id", ""),
        "gold_stage": row.get("gold_stage", ""),
        "source_final_candidate_gold_path": _source_final_candidate_gold_path(row),
    }
    missing = [key for key, value in required.items() if not str(value or "").strip()]
    if missing:
        return False, f"missing_metadata:{','.join(missing)}"
    return True, ""


def _discover_unfinished_batch_samples(
    workbench_dir: str | Path,
    rows_by_label: dict[str, dict[str, Any]],
    rows_by_sample_id: dict[str, dict[str, Any]],
) -> set[str]:
    root = Path(workbench_dir) / PACKET_BATCH_ROOT
    unfinished: set[str] = set()
    if not root.exists():
        return unfinished
    for manifest_path in root.glob("batch_*/batch_manifest.json"):
        try:
            manifest = _read_json(manifest_path)
        except Exception:
            continue
        if not isinstance(manifest, dict):
            continue
        entries = manifest.get("samples", manifest.get("entries", []))
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            if entry.get("action") == "skipped":
                continue
            label = entry.get("masked_sample_label", "")
            sample_id = entry.get("sample_id", "")
            row = rows_by_label.get(label) or rows_by_sample_id.get(sample_id)
            if not row:
                continue
            if row.get("review_status", "not_reviewed") != "reviewed" or row.get("writeback_status") != "written_back":
                if label:
                    unfinished.add(label)
                if sample_id:
                    unfinished.add(sample_id)
    return unfinished


def _selection_sort_key(row: dict[str, Any]) -> tuple[Any, ...]:
    return (
        0 if _normalize_flag(row.get("promotion_blocker")) else 1,
        0 if _normalize_flag(row.get("needs_later_patch")) else 1,
        0
        if any(
            [
                _has_signal(row.get("reviewer_notes")),
                _has_signal(row.get("manual_review")),
                _has_signal(row.get("structure_warnings")),
            ]
        )
        else 1,
        _row_label(row),
        row.get("sample_id", ""),
    )


def _stage_priority_sort_key(row: dict[str, Any]) -> tuple[Any, ...]:
    effective = str(row.get("effective_review_priority", "") or "").strip().lower()
    original = str(row.get("original_human_review_priority", "") or "").strip().lower()
    priority_rank = {
        "high": 0,
        "medium": 2,
        "low": 3,
    }.get(effective, 4)
    if effective != "high" and original == "high":
        priority_rank = 1
    return (priority_rank, *_selection_sort_key(row))


def _remaining_priority_sort_key(row: dict[str, Any]) -> tuple[Any, ...]:
    effective = str(row.get("effective_review_priority", "") or "").strip().lower()
    priority_rank = {
        "high": 0,
        "medium": 1,
        "low": 2,
    }.get(effective, 3)
    return (priority_rank, *_selection_sort_key(row))


def _stable_sample_sort_key(row: dict[str, Any]) -> tuple[str, str, int]:
    label = _row_label(row)
    sample_id = str(row.get("sample_id", "") or "")
    candidate_index = row.get("candidate_index", {})
    index_value = candidate_index.get("candidate_index", 0) if isinstance(candidate_index, dict) else 0
    return (label or sample_id, sample_id or label, index_value if isinstance(index_value, int) else 0)


def _stage_selection_reason(row: dict[str, Any], stage: str, *, fill: bool = False) -> str:
    effective = str(row.get("effective_review_priority", "") or "").strip().lower()
    original = str(row.get("original_human_review_priority", "") or "").strip().lower()
    if effective == "high":
        priority_reason = "effective_high_priority"
    elif original == "high":
        priority_reason = "original_high_priority_backfill"
    elif effective == "medium":
        priority_reason = "effective_medium_backfill"
    elif effective == "low":
        priority_reason = "effective_low_backfill"
    else:
        priority_reason = "available_priority_backfill"
    prefix = "stage_shortage_cross_stage_fill" if fill else "stage_balanced"
    return f"{prefix}:{stage}:{priority_reason}"


def _candidate_rows_for_guarded_export(
    *,
    bundle: Any,
    sample_list_path: str | None,
    exclude_unfinished_exported_batches: bool,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    sample_list = _load_sample_list(sample_list_path)
    rows_by_label = {_row_label(row): row for row in bundle.review_rows}
    rows_by_sample_id = {row.get("sample_id", ""): row for row in bundle.review_rows if row.get("sample_id")}
    unfinished_samples = (
        _discover_unfinished_batch_samples(
            bundle.workbench_dir,
            rows_by_label=rows_by_label,
            rows_by_sample_id=rows_by_sample_id,
        )
        if exclude_unfinished_exported_batches
        else set()
    )
    candidates: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []

    def add_skip(row: dict[str, Any], reason: str) -> None:
        item = _skip_row(row, reason)
        item["forced_include"] = False
        item["selection_reason"] = ""
        skipped.append(item)

    for row in bundle.review_rows:
        label = _row_label(row)
        sample_id = row.get("sample_id", "")
        if sample_list is not None and label not in sample_list and sample_id not in sample_list:
            continue
        if row.get("review_status", "not_reviewed") == "reviewed":
            add_skip(row, "already_reviewed")
            continue
        if row.get("writeback_status") == "written_back":
            add_skip(row, "already_written_back")
            continue
        if label in unfinished_samples or sample_id in unfinished_samples:
            add_skip(row, "already_exported_in_unfinished_batch")
            continue
        ok, reason = _row_metadata_ok(row)
        if not ok:
            add_skip(row, reason)
            continue
        candidates.append(row)
    return candidates, skipped


def select_stage_balanced_rows_for_export(
    *,
    bundle: Any,
    target_per_stage: int,
    limit: int | None,
    sample_list_path: str | None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, str], dict[str, Any]]:
    candidates, skipped = _candidate_rows_for_guarded_export(
        bundle=bundle,
        sample_list_path=sample_list_path,
        exclude_unfinished_exported_batches=True,
    )
    target_counts = {stage: target_per_stage for stage in DEFAULT_STAGE_BALANCED_STAGES}
    max_count = min(limit if limit is not None else sum(target_counts.values()), sum(target_counts.values()))
    by_stage: dict[str, list[dict[str, Any]]] = {stage: [] for stage in DEFAULT_STAGE_BALANCED_STAGES}
    other_stage_rows: list[dict[str, Any]] = []
    for row in candidates:
        stage = str(row.get("gold_stage", "") or "").strip()
        if stage in by_stage:
            by_stage[stage].append(row)
        else:
            other_stage_rows.append(row)
    for stage in by_stage:
        by_stage[stage] = sorted(by_stage[stage], key=_stage_priority_sort_key)
    other_stage_rows = sorted(other_stage_rows, key=_stage_priority_sort_key)

    selected: list[dict[str, Any]] = []
    reasons: dict[str, str] = {}
    selected_keys: set[str] = set()
    shortages: list[dict[str, Any]] = []

    def add_row(row: dict[str, Any], reason: str) -> bool:
        label = _row_label(row)
        sample_id = row.get("sample_id", "")
        if label in selected_keys or sample_id in selected_keys:
            return False
        if len(selected) >= max_count:
            return False
        selected.append(row)
        selected_keys.update({label, sample_id})
        reasons[label] = reason
        return True

    for stage in DEFAULT_STAGE_BALANCED_STAGES:
        wanted = min(target_counts[stage], max_count - len(selected))
        picked = 0
        for row in by_stage[stage]:
            if picked >= wanted:
                break
            if add_row(row, _stage_selection_reason(row, stage)):
                picked += 1
        if picked < target_counts[stage]:
            shortages.append(
                {
                    "stage_shortage": True,
                    "affected_stage": stage,
                    "available_unreviewed_count": len(by_stage[stage]),
                    "target_count": target_counts[stage],
                    "selected_count": picked,
                }
            )

    if len(selected) < max_count:
        fill_pool = []
        for stage in DEFAULT_STAGE_BALANCED_STAGES:
            fill_pool.extend(by_stage[stage])
        fill_pool.extend(other_stage_rows)
        for row in sorted(fill_pool, key=_stage_priority_sort_key):
            if len(selected) >= max_count:
                break
            stage = str(row.get("gold_stage", "") or "").strip() or "unknown"
            add_row(row, _stage_selection_reason(row, stage, fill=True))

    actual_counts = {stage: 0 for stage in DEFAULT_STAGE_BALANCED_STAGES}
    for row in selected:
        stage = str(row.get("gold_stage", "") or "").strip()
        actual_counts[stage] = actual_counts.get(stage, 0) + 1

    selection_meta = {
        "selection_mode": STAGE_BALANCED_PILOT12_MODE,
        "target_per_stage": target_per_stage,
        "target_stage_counts": target_counts,
        "actual_stage_counts": actual_counts,
        "stage_shortages": shortages,
        "fill_strategy": (
            "shortage stages are filled from remaining eligible not_reviewed/not_written_back rows "
            "sorted by priority and review signals"
        ),
        "exclude_unfinished_exported_batches": True,
    }
    return selected, skipped, reasons, selection_meta


def _manifest_sample(
    *,
    row: dict[str, Any],
    packet: dict[str, Any] | None,
    json_path: Path | None,
    markdown_path: Path | None,
    selection_reason: str,
    forced_include: bool,
    action: str,
    skipped_reason: str = "",
) -> dict[str, Any]:
    identity = build_identity_snapshot(packet=packet or {}, row=row) if packet is not None else {
        "masked_sample_label": _row_label(row),
        "sample_id": row.get("sample_id", ""),
        "gold_stage": row.get("gold_stage", ""),
        "source_final_candidate_gold_path": _source_final_candidate_gold_path(row),
    }
    evidence_alignment = packet.get("evidence_alignment", {}) if isinstance(packet, dict) else {}
    return {
        "masked_sample_label": identity.get("masked_sample_label", _row_label(row)),
        "sample_id": identity.get("sample_id", row.get("sample_id", "")),
        "gold_stage": identity.get("gold_stage", row.get("gold_stage", "")),
        "review_status": row.get("review_status", ""),
        "writeback_status": row.get("writeback_status", ""),
        "human_review_priority": row.get("human_review_priority", ""),
        "effective_review_priority": row.get("effective_review_priority", ""),
        "promotion_blocker": row.get("promotion_blocker", ""),
        "needs_later_patch": row.get("needs_later_patch", ""),
        "selection_reason": selection_reason,
        "forced_include": forced_include,
        "action": action,
        "skipped_reason": skipped_reason,
        "packet_md_path": str(markdown_path) if markdown_path else "",
        "packet_json_path": str(json_path) if json_path else "",
        "gpt_review_output_path": str((json_path.parent / PER_SAMPLE_GPT_OUTPUT_FILE) if json_path else ""),
        "source_final_candidate_gold_path": _source_final_candidate_gold_path(row),
        "sample_dir": str(json_path.parent) if json_path else "",
        "packet_schema_version": packet.get("packet_schema_version") if isinstance(packet, dict) else None,
        "safe_for_gpt_review": evidence_alignment.get("safe_for_gpt_review"),
        "safe_for_writeback": False,
        "cited_ref_count": evidence_alignment.get("cited_ref_count"),
        "cited_refs_visible_in_md_count": evidence_alignment.get("cited_refs_visible_in_md_count"),
        "cited_refs_visible_in_json_count": evidence_alignment.get("cited_refs_visible_in_json_count"),
        "missing_from_md_refs": evidence_alignment.get("missing_from_md_refs"),
        "missing_from_json_refs": evidence_alignment.get("missing_from_json_refs"),
    }


def _legacy_manifest_entry(sample: dict[str, Any]) -> dict[str, Any]:
    return {
        "masked_sample_label": sample.get("masked_sample_label", ""),
        "sample_id": sample.get("sample_id", ""),
        "gold_stage": sample.get("gold_stage", ""),
        "source_final_candidate_gold_path": sample.get("source_final_candidate_gold_path", ""),
        "packet_json": sample.get("packet_json_path", ""),
        "packet_markdown": sample.get("packet_md_path", ""),
        "sample_dir": sample.get("sample_dir", ""),
        "gpt_review_output": sample.get("gpt_review_output_path", ""),
        "packet_schema_version": sample.get("packet_schema_version"),
        "selection_reason": sample.get("selection_reason", ""),
        "forced_include": sample.get("forced_include", False),
        "safe_for_gpt_review": sample.get("safe_for_gpt_review"),
        "safe_for_writeback": sample.get("safe_for_writeback", False),
        "cited_ref_count": sample.get("cited_ref_count"),
        "cited_refs_visible_in_md_count": sample.get("cited_refs_visible_in_md_count"),
        "cited_refs_visible_in_json_count": sample.get("cited_refs_visible_in_json_count"),
    }


def _panel_ref_key(ref: dict[str, Any]) -> tuple[str, str]:
    seq = ref.get("seq") if isinstance(ref, dict) else None
    edge_id = ref.get("edge_id") if isinstance(ref, dict) else None
    return ("" if seq is None else str(seq), str(edge_id or ""))


def _same_ref(left: dict[str, Any], right: dict[str, Any]) -> bool:
    left_seq, left_edge = _panel_ref_key(left)
    right_seq, right_edge = _panel_ref_key(right)
    if left_seq and right_seq and left_edge and right_edge:
        return left_seq == right_seq and left_edge == right_edge
    if left_seq and right_seq:
        return left_seq == right_seq
    if left_edge and right_edge:
        return left_edge == right_edge
    return False


def _panel_cited_refs(packet: dict[str, Any]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str], dict[str, Any]] = {}
    order: list[tuple[str, str]] = []
    chain = packet.get("original_candidate_four_steps", [])
    for step in chain if isinstance(chain, list) else []:
        if not isinstance(step, dict):
            continue
        step_name = step.get("step", "")
        claim = step.get("claim", "")
        for ref in step.get("evidence_refs", []) or []:
            if not isinstance(ref, dict):
                ref = {"ref": ref}
            key = _panel_ref_key(ref)
            if key not in grouped:
                grouped[key] = {
                    "seq": ref.get("seq"),
                    "edge_id": ref.get("edge_id", ""),
                    "steps": [],
                    "claims": [],
                    "ref": copy.deepcopy(ref),
                }
                order.append(key)
            if step_name and step_name not in grouped[key]["steps"]:
                grouped[key]["steps"].append(step_name)
            if claim and claim not in grouped[key]["claims"]:
                grouped[key]["claims"].append(claim)
    if grouped:
        return [grouped[key] for key in order]

    refs = packet.get("evidence_refs", [])
    for ref in refs if isinstance(refs, list) else []:
        if not isinstance(ref, dict):
            continue
        key = _panel_ref_key(ref)
        if key not in grouped:
            grouped[key] = {
                "seq": ref.get("seq"),
                "edge_id": ref.get("edge_id", ""),
                "steps": [],
                "claims": [],
                "ref": copy.deepcopy(ref),
            }
            order.append(key)
        step = ref.get("step", "")
        if step and step not in grouped[key]["steps"]:
            grouped[key]["steps"].append(step)
    return [grouped[key] for key in order]


def _panel_spine(packet: dict[str, Any]) -> list[dict[str, Any]]:
    strict = packet.get("strict_blind_evidence", {})
    spine = strict.get("spine", []) if isinstance(strict, dict) else []
    return spine if isinstance(spine, list) else []


def _find_panel_evidence_item(spine: list[dict[str, Any]], ref: dict[str, Any]) -> dict[str, Any] | None:
    for item in spine:
        if isinstance(item, dict) and _same_ref(ref, item):
            return item
    return None


def _visible_or_note(value: Any) -> Any:
    if value is None or value == "":
        return "not_visible"
    return value


def _panel_redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _panel_redact(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_panel_redact(item) for item in value]
    if not isinstance(value, str):
        return value
    text = re.sub(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b", "<REDACTED_TOKEN>", value)
    text = re.sub(r"(?i)(\bauthorization\b\s*[:=]\s*['\"]?\s*Bearer\s+)([^,'\"\s;}]+)", r"\1<REDACTED_TOKEN>", text)
    text = re.sub(r"(?i)(\bcookie\b\s*[:=]\s*)(['\"])(.*?)(\2)", r"\1\2<REDACTED_COOKIE>\4", text)
    text = re.sub(r"(?i)(\bcookie\b\s*[:=]\s*)([^,;}\s]+)", r"\1<REDACTED_COOKIE>", text)
    text = re.sub(r"(?i)(\btoken=)([^;,'\"\s}]+)", r"\1<REDACTED_TOKEN>", text)
    text = re.sub(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", "<REDACTED_EMAIL>", text)
    text = re.sub(r"(?i)(\b(?:password|passwd|pwd)(?:[_ -]?(?:hash|digest))?\b\s*[:=]\s*['\"]?)([^,'\"\s}\]]+)", r"\1<REDACTED_HASH>", text)
    return re.sub(r"\b[A-Za-z0-9_-]{80,}\b", "<REDACTED_TOKEN>", text)


def _collapse_panel_text(value: Any, max_len: int = 700) -> str:
    text = "" if value is None else str(_panel_redact(value))
    text = re.sub(r"\s+", " ", text).strip()
    if len(text) <= max_len:
        return text
    return text[: max_len - 3].rstrip() + "..."


def _http_fields_from_message(message: str) -> dict[str, str]:
    match = re.search(r'"(?P<method>[A-Z]+)\s+(?P<url>\S+)\s+HTTP/[^"]+"\s+(?P<status>\d{3})\s+(?P<length>\d+|-)', message or "")
    if not match:
        return {}
    return {
        "method": match.group("method"),
        "url": _panel_redact(match.group("url")),
        "status_code": match.group("status"),
        "content_length": match.group("length"),
    }


def _applog_panel_events(item: dict[str, Any]) -> list[dict[str, Any]]:
    multisource = item.get("multisource_context", {}) if isinstance(item, dict) else {}
    applog = multisource.get("applog", []) if isinstance(multisource, dict) else []
    events = []
    for event in applog if isinstance(applog, list) else []:
        if not isinstance(event, dict):
            continue
        message = str(event.get("message", "") or "")
        http = _http_fields_from_message(message)
        attach_basis = event.get("attach_basis", {}) if isinstance(event.get("attach_basis"), dict) else {}
        events.append(
            {
                "timestamp": _visible_or_note(event.get("timestamp")),
                "semantic_type": _visible_or_note(event.get("semantic_type")),
                "method": _visible_or_note(event.get("method") or http.get("method")),
                "url": _visible_or_note(event.get("url") or event.get("endpoint") or http.get("url")),
                "status_code": _visible_or_note(event.get("status") or event.get("status_code") or http.get("status_code")),
                "content_length": _visible_or_note(
                    event.get("content_length")
                    or event.get("content-length")
                    or event.get("contentLength")
                    or http.get("content_length")
                ),
                "attach_strength": _visible_or_note(event.get("attach_strength")),
                "attach_reason": _visible_or_note(event.get("attach_reason")),
                "attach_to_backbone_edge_id": _visible_or_note(event.get("attach_to_backbone_edge_id")),
                "backbone_seq": _visible_or_note(attach_basis.get("backbone_seq")),
                "sanitized_message": _visible_or_note(_collapse_panel_text(message)),
            }
        )
    return events


def _traffic_panel_events(item: dict[str, Any]) -> list[dict[str, Any]]:
    multisource = item.get("multisource_context", {}) if isinstance(item, dict) else {}
    traffic = multisource.get("traffic", []) if isinstance(multisource, dict) else []
    events = []
    for event in traffic if isinstance(traffic, list) else []:
        if not isinstance(event, dict):
            continue
        events.append(
            {
                "semantic_type": _visible_or_note(event.get("semantic_type")),
                "summary_type": _visible_or_note(event.get("summary_type")),
                "src_ip": _visible_or_note(event.get("src_ip") or event.get("src")),
                "src_port": _visible_or_note(event.get("src_port")),
                "dst_ip": _visible_or_note(event.get("dst_ip") or event.get("dst")),
                "dst_port": _visible_or_note(event.get("dst_port")),
                "protocol": _visible_or_note(event.get("l4_proto") or event.get("protocol") or event.get("proto")),
                "flow": _visible_or_note(event.get("normalized_conn_key")),
                "attach_strength": _visible_or_note(event.get("attach_strength")),
                "attach_reason": _visible_or_note(event.get("attach_reason")),
                "attach_to_backbone_edge_id": _visible_or_note(event.get("attach_to_backbone_edge_id")),
            }
        )
    return events


def _audit_context_panel_events(item: dict[str, Any]) -> list[dict[str, Any]]:
    audit_context = item.get("audit_context", []) if isinstance(item, dict) else []
    events = []
    for context in audit_context if isinstance(audit_context, list) else []:
        if not isinstance(context, dict):
            continue
        event = context.get("event", {}) if isinstance(context.get("event"), dict) else {}
        attrs = event.get("attrs", {}) if isinstance(event.get("attrs"), dict) else {}
        events.append(
            {
                "relation": _visible_or_note(event.get("relation")),
                "raw_evt_type": _visible_or_note(attrs.get("raw_evt_type") or event.get("raw_evt_type")),
                "fd_name": _visible_or_note(attrs.get("fd_name") or event.get("fd_name")),
                "subject": _visible_or_note(event.get("subject")),
                "object": _visible_or_note(event.get("object")),
                "attach_strength": _visible_or_note(context.get("attach_strength")),
                "attach_reason": _visible_or_note(context.get("attach_reason")),
                "context_role": _visible_or_note(context.get("context_role")),
            }
        )
    return events


def _looks_like_file_path(value: Any) -> bool:
    text = str(value or "")
    return text.startswith("file:") or text.startswith("/") or ":/" in text


def _panel_path_values(item: dict[str, Any], audit_events: list[dict[str, Any]], applog_events: list[dict[str, Any]]) -> list[str]:
    values: list[str] = []
    attrs = item.get("attrs", {}) if isinstance(item.get("attrs"), dict) else {}
    for value in [item.get("subject"), item.get("object"), attrs.get("fd_name"), attrs.get("proc_exepath")]:
        if _looks_like_file_path(value):
            values.append(str(_panel_redact(value)))
    for event in audit_events:
        for key in ["fd_name", "subject", "object"]:
            value = event.get(key)
            if _looks_like_file_path(value):
                values.append(str(_panel_redact(value)))
    for event in applog_events:
        value = event.get("sanitized_message")
        if _looks_like_file_path(value):
            values.append(str(_panel_redact(value)))
    deduped = []
    for value in values:
        if value and value != "not_visible" and value not in deduped:
            deduped.append(value)
    return deduped


def _panel_connection_object(item: dict[str, Any]) -> str:
    attrs = item.get("attrs", {}) if isinstance(item.get("attrs"), dict) else {}
    for value in [item.get("object"), attrs.get("fd_name"), item.get("subject")]:
        text = str(value or "")
        if text.startswith("conn:") or "->" in text:
            return str(_panel_redact(text))
    return "not_visible"


def _aggregate_visible(events: list[dict[str, Any]], key: str) -> list[Any]:
    values = []
    for event in events:
        value = event.get(key)
        if value is None or value == "" or value == "not_visible":
            continue
        if isinstance(value, (list, dict)):
            value = json.dumps(_panel_redact(value), ensure_ascii=False)
        if value not in values:
            values.append(value)
    return values


def _build_panel_entry(cited: dict[str, Any], item: dict[str, Any] | None) -> dict[str, Any]:
    if item is None:
        return {
            "visible": False,
            "steps": cited.get("steps", []),
            "claims": cited.get("claims", []),
            "seq": cited.get("seq"),
            "edge_id": cited.get("edge_id", ""),
            "source_type": "unknown",
            "source_coverage_note": "candidate-cited ref not found in packet strict_blind_evidence spine",
        }

    attrs = item.get("attrs", {}) if isinstance(item.get("attrs"), dict) else {}
    applog_events = _applog_panel_events(item)
    traffic_events = _traffic_panel_events(item)
    audit_events = _audit_context_panel_events(item)
    attached_sources = ["audit"]
    if applog_events:
        attached_sources.append("applog")
    if traffic_events:
        attached_sources.append("traffic")
    paths = _panel_path_values(item, audit_events, applog_events)
    attach_strengths = _aggregate_visible(audit_events + applog_events + traffic_events, "attach_strength")
    attach_reasons = _aggregate_visible(audit_events + applog_events + traffic_events, "attach_reason")
    return {
        "visible": True,
        "steps": cited.get("steps", []),
        "claims": cited.get("claims", []),
        "seq": _visible_or_note(item.get("seq", cited.get("seq"))),
        "edge_id": _visible_or_note(item.get("edge_id", cited.get("edge_id", ""))),
        "source_type": "audit",
        "attached_source_types": attached_sources,
        "relation": _visible_or_note(item.get("relation")),
        "semantic_type": _visible_or_note(item.get("semantic_type")),
        "subject": _visible_or_note(_panel_redact(item.get("subject"))),
        "process": _visible_or_note(_panel_redact(item.get("subject") or attrs.get("proc_exepath"))),
        "object": _visible_or_note(_panel_redact(item.get("object"))),
        "target": _visible_or_note(_panel_redact(item.get("object"))),
        "raw_evt_type": _visible_or_note(item.get("raw_evt_type") or attrs.get("raw_evt_type")),
        "fd_name": _visible_or_note(_panel_redact(item.get("fd_name") or attrs.get("fd_name"))),
        "file_path": paths or ["not_visible"],
        "connection_object": _panel_connection_object(item),
        "method": _aggregate_visible(applog_events, "method") or ["not_visible"],
        "url_or_endpoint": _aggregate_visible(applog_events, "url") or ["not_visible"],
        "http_status_code": _aggregate_visible(applog_events, "status_code") or ["not_visible"],
        "content_length": _aggregate_visible(applog_events, "content_length") or ["not_visible"],
        "attach_strength": attach_strengths or ["not_visible"],
        "attach_reason": attach_reasons or ["not_visible"],
        "applog_events": applog_events,
        "traffic_events": traffic_events,
        "audit_context_events": audit_events,
        "source_coverage_note": (
            f"backbone audit edge visible; audit_context_count={len(audit_events)}; "
            f"applog_count={len(applog_events)}; traffic_count={len(traffic_events)}"
        ),
    }


def attach_cited_evidence_panel(packet: dict[str, Any]) -> dict[str, Any]:
    cited_refs = _panel_cited_refs(packet)
    spine = _panel_spine(packet)
    panel = []
    for cited in cited_refs:
        item = _find_panel_evidence_item(spine, cited)
        panel.append(_build_panel_entry(cited, item))

    cited_range = [entry.get("seq") for entry in cited_refs if entry.get("seq") is not None]
    displayed_range = [item.get("seq") for item in spine if isinstance(item, dict) and item.get("seq") is not None]
    missing = [
        {"seq": entry.get("seq"), "edge_id": entry.get("edge_id", "")}
        for entry in panel
        if not entry.get("visible")
    ]
    cited_key_set = {_panel_ref_key(ref) for ref in cited_refs}
    displayed_key_set = {_panel_ref_key(item) for item in spine if isinstance(item, dict)}
    overlap = bool(cited_key_set & displayed_key_set)
    alignment = {
        "cited_ref_count": len(cited_refs),
        "cited_ref_mentions_count": sum(len(ref.get("steps", [])) or 1 for ref in cited_refs),
        "cited_refs_visible_in_json_count": len(cited_refs) - len(missing),
        "cited_refs_visible_in_md_count": len(cited_refs) - len(missing),
        "missing_from_json_refs": copy.deepcopy(missing),
        "missing_from_md_refs": copy.deepcopy(missing),
        "seq_range_cited_by_candidate": [min(cited_range), max(cited_range)] if cited_range else [],
        "seq_range_displayed_in_md": [min(displayed_range), max(displayed_range)] if displayed_range else [],
        "seq_namespace_mismatch": bool(cited_refs and spine and not overlap),
        "safe_for_gpt_review": bool(cited_refs) and not missing,
        "panel_rendered": True,
    }
    packet["cited_evidence_panel"] = panel
    packet["evidence_alignment"] = alignment
    packet.setdefault("write_scope", {})["safe_for_writeback"] = False
    return packet


def _md_value(value: Any) -> str:
    if isinstance(value, (list, dict)):
        return json.dumps(_panel_redact(value), ensure_ascii=False)
    return str(_panel_redact(value))


def _render_cited_evidence_panel(packet: dict[str, Any]) -> list[str]:
    alignment = packet.get("evidence_alignment", {})
    panel = packet.get("cited_evidence_panel", [])
    lines = [
        "",
        "## Cited Evidence Panel",
        "",
        "Candidate-cited evidence_refs are rendered first. This panel is the review authority for candidate evidence alignment; the Strict Blind Evidence section below is surrounding context only.",
        "",
    ]
    for key in [
        "cited_ref_count",
        "cited_ref_mentions_count",
        "cited_refs_visible_in_md_count",
        "cited_refs_visible_in_json_count",
        "safe_for_gpt_review",
        "seq_range_cited_by_candidate",
        "seq_range_displayed_in_md",
        "seq_namespace_mismatch",
    ]:
        lines.append(f"- {key}: `{_md_value(alignment.get(key))}`")
    if not panel:
        lines.extend(["", "- no candidate evidence_refs were available"])
        return lines

    for index, entry in enumerate(panel if isinstance(panel, list) else [], start=1):
        lines.extend(["", f"### Cited evidence {index}", ""])
        for key in [
            "visible",
            "steps",
            "seq",
            "edge_id",
            "source_type",
            "attached_source_types",
            "relation",
            "semantic_type",
            "subject",
            "process",
            "object",
            "target",
            "raw_evt_type",
            "fd_name",
            "file_path",
            "connection_object",
            "method",
            "url_or_endpoint",
            "http_status_code",
            "content_length",
            "attach_strength",
            "attach_reason",
            "source_coverage_note",
        ]:
            lines.append(f"- {key}: `{_md_value(entry.get(key, 'not_visible'))}`")
        claims = entry.get("claims", [])
        if claims:
            lines.extend(["", "Candidate claims citing this evidence:"])
            for claim in claims:
                lines.append(f"- {_collapse_panel_text(claim, max_len=450)}")

        lines.extend(["", "#### Applog cited/attached fields", ""])
        applog_events = entry.get("applog_events", [])
        if not applog_events:
            lines.append("- none")
        for event_index, event in enumerate(applog_events if isinstance(applog_events, list) else [], start=1):
            lines.append(f"- applog event {event_index}:")
            for key in [
                "timestamp",
                "semantic_type",
                "method",
                "url",
                "status_code",
                "content_length",
                "attach_strength",
                "attach_reason",
                "attach_to_backbone_edge_id",
                "backbone_seq",
                "sanitized_message",
            ]:
                lines.append(f"  - {key}: `{_md_value(event.get(key, 'not_visible'))}`")

        lines.extend(["", "#### Traffic cited/attached fields", ""])
        traffic_events = entry.get("traffic_events", [])
        if not traffic_events:
            lines.append("- none")
        for event_index, event in enumerate(traffic_events if isinstance(traffic_events, list) else [], start=1):
            lines.append(f"- traffic event {event_index}:")
            for key in [
                "semantic_type",
                "summary_type",
                "src_ip",
                "src_port",
                "dst_ip",
                "dst_port",
                "protocol",
                "flow",
                "attach_strength",
                "attach_reason",
                "attach_to_backbone_edge_id",
            ]:
                lines.append(f"  - {key}: `{_md_value(event.get(key, 'not_visible'))}`")

        lines.extend(["", "#### Audit context cited/attached fields", ""])
        audit_events = entry.get("audit_context_events", [])
        if not audit_events:
            lines.append("- none")
        for event_index, event in enumerate(audit_events if isinstance(audit_events, list) else [], start=1):
            lines.append(f"- audit context event {event_index}:")
            for key in [
                "relation",
                "raw_evt_type",
                "fd_name",
                "subject",
                "object",
                "attach_strength",
                "attach_reason",
                "context_role",
            ]:
                lines.append(f"  - {key}: `{_md_value(event.get(key, 'not_visible'))}`")
    return lines


def render_packet_markdown_for_export(packet: dict[str, Any]) -> str:
    markdown = render_packet_markdown(packet)
    panel = "\n".join(_render_cited_evidence_panel(packet)).rstrip() + "\n"
    marker = "\n## Strict Blind Evidence\n"
    if marker in markdown:
        return markdown.replace(marker, "\n" + panel + marker, 1)
    return markdown.rstrip() + "\n" + panel


def select_rows_for_export(
    *,
    bundle: Any,
    priority: str | None,
    limit: int | None,
    sample_list_path: str | None,
    force_include_samples: list[str],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, str]]:
    sample_list = _load_sample_list(sample_list_path)
    rows_by_label = {_row_label(row): row for row in bundle.review_rows}
    rows_by_sample_id = {row.get("sample_id", ""): row for row in bundle.review_rows if row.get("sample_id")}
    unfinished_samples = _discover_unfinished_batch_samples(
        bundle.workbench_dir,
        rows_by_label=rows_by_label,
        rows_by_sample_id=rows_by_sample_id,
    )

    selected: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    reasons: dict[str, str] = {}
    selected_keys: set[str] = set()

    def add_skip(row: dict[str, Any], reason: str) -> None:
        item = _skip_row(row, reason)
        item["forced_include"] = False
        item["selection_reason"] = ""
        skipped.append(item)

    for sample in force_include_samples:
        row = rows_by_label.get(sample) or rows_by_sample_id.get(sample)
        if row is None:
            skipped.append(
                {
                    "masked_sample_label": sample,
                    "sample_id": sample,
                    "gold_stage": "",
                    "action": "skipped",
                    "fail_reason": "force_include_not_found",
                    "forced_include": True,
                    "selection_reason": "",
                }
            )
            continue
        ok, reason = _row_metadata_ok(row)
        if not ok:
            item = _skip_row(row, reason)
            item["forced_include"] = True
            item["selection_reason"] = ""
            skipped.append(item)
            continue
        if row.get("writeback_status") == "written_back":
            item = _skip_row(row, "force_include_already_written_back")
            item["forced_include"] = True
            item["selection_reason"] = ""
            skipped.append(item)
            continue
        label = _row_label(row)
        sample_id = row.get("sample_id", "")
        selected.append(row)
        selected_keys.update({label, sample_id})
        reasons[label] = "reviewed_but_not_written_back_reaudit"

    if limit is not None and len(selected) >= limit:
        return selected[:limit], skipped, reasons

    candidates = []
    for row in bundle.review_rows:
        label = _row_label(row)
        sample_id = row.get("sample_id", "")
        if sample_list is not None and label not in sample_list and sample_id not in sample_list:
            continue
        if label in selected_keys or sample_id in selected_keys:
            continue
        if row.get("review_status", "not_reviewed") == "reviewed":
            add_skip(row, "already_reviewed")
            continue
        if row.get("writeback_status") == "written_back":
            add_skip(row, "already_written_back")
            continue
        if label in unfinished_samples or sample_id in unfinished_samples:
            add_skip(row, "already_exported_in_unfinished_batch")
            continue
        ok, reason = _row_metadata_ok(row)
        if not ok:
            add_skip(row, reason)
            continue
        candidates.append(row)

    priority_buckets = [
        ("effective_high_priority", lambda row: row.get("effective_review_priority") == priority if priority else True),
        (
            "original_high_priority_backfill",
            lambda row: row.get("effective_review_priority") != priority
            and row.get("original_human_review_priority") == priority
            if priority
            else False,
        ),
        (
            "effective_medium_backfill",
            lambda row: row.get("effective_review_priority") == "medium",
        ),
    ]

    remaining = limit - len(selected) if limit is not None else None
    for reason, predicate in priority_buckets:
        if remaining is not None and remaining <= 0:
            break
        bucket = [row for row in candidates if predicate(row)]
        for row in sorted(bucket, key=_selection_sort_key):
            label = _row_label(row)
            sample_id = row.get("sample_id", "")
            if label in selected_keys or sample_id in selected_keys:
                continue
            selected.append(row)
            selected_keys.update({label, sample_id})
            reasons[label] = reason
            if remaining is not None:
                remaining -= 1
                if remaining <= 0:
                    break
    return selected, skipped, reasons


def select_all_remaining_rows_for_export(
    *,
    bundle: Any,
    limit: int | None,
    sample_list_path: str | None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, str], dict[str, Any]]:
    sample_list = _load_sample_list(sample_list_path)
    rows_by_label = {_row_label(row): row for row in bundle.review_rows}
    rows_by_sample_id = {row.get("sample_id", ""): row for row in bundle.review_rows if row.get("sample_id")}
    unfinished_samples = _discover_unfinished_batch_samples(
        bundle.workbench_dir,
        rows_by_label=rows_by_label,
        rows_by_sample_id=rows_by_sample_id,
    )

    candidates: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    for row in bundle.review_rows:
        label = _row_label(row)
        sample_id = row.get("sample_id", "")
        if sample_list is not None and label not in sample_list and sample_id not in sample_list:
            continue
        if row.get("review_status", "not_reviewed") == "reviewed":
            continue
        if row.get("writeback_status") == "written_back":
            continue
        if label in unfinished_samples or sample_id in unfinished_samples:
            skipped.append(_skip_row(row, "already_exported_in_unfinished_batch"))
            continue
        ok, reason = _row_metadata_ok(row)
        if not ok:
            skipped.append(_skip_row(row, reason))
            continue
        candidates.append(row)

    selected = sorted(candidates, key=_stable_sample_sort_key)
    if limit is not None:
        selected = selected[:limit]
    reasons = {_row_label(row): "all_remaining_selected" for row in selected}
    selection_meta = {
        "selection_mode": EXPORT_ALL_REMAINING_SELECTION_MODE,
        "export_order": EXPORT_ALL_REMAINING_EXPORT_ORDER,
        "detected_remaining_count": len(selected),
        "remaining_candidate_count_before_limit": len(candidates),
        "total_remaining_eligible_before_export": len(candidates),
        "limit_kind": "remaining_count_or_14" if limit is None or limit == len(candidates) else "explicit_limit",
        "priority_filter": "none",
        "priority_filter_used": False,
        "review_status_filter": "review_status != reviewed",
        "writeback_status_filter": "writeback_status != written_back",
        "exclude_unfinished_exported_batches": True,
    }
    return selected, skipped, reasons, selection_meta


def select_rows(
    *,
    bundle: Any,
    select_unreviewed: bool,
    priority: str | None,
    limit: int | None,
    sample_list_path: str | None,
    include_written_back: bool,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    sample_list = _load_sample_list(sample_list_path)
    rows = []
    skipped = []
    for row in bundle.review_rows:
        label = _row_label(row)
        sample_id = row.get("sample_id", "")
        if sample_list is not None and label not in sample_list and sample_id not in sample_list:
            continue
        if select_unreviewed and row.get("review_status", "not_reviewed") == "reviewed":
            skipped.append(_skip_row(row, "already_reviewed"))
            continue
        if not include_written_back and row.get("writeback_status") == "written_back":
            skipped.append(_skip_row(row, "already_written_back"))
            continue
        if priority:
            priorities = {
                row.get("effective_review_priority", ""),
                row.get("original_human_review_priority", ""),
                row.get("human_review_priority", ""),
            }
            if priority not in priorities:
                skipped.append(_skip_row(row, f"priority_mismatch:{priority}"))
                continue
        rows.append(row)
        if limit is not None and len(rows) >= limit:
            break
    return rows, skipped


def _skip_row(row: dict[str, Any], reason: str) -> dict[str, Any]:
    return {
        "masked_sample_label": _row_label(row),
        "sample_id": row.get("sample_id", ""),
        "gold_stage": row.get("gold_stage", ""),
        "review_status": row.get("review_status", ""),
        "writeback_status": row.get("writeback_status", ""),
        "human_review_priority": row.get("human_review_priority", ""),
        "effective_review_priority": row.get("effective_review_priority", ""),
        "promotion_blocker": row.get("promotion_blocker", ""),
        "needs_later_patch": row.get("needs_later_patch", ""),
        "source_final_candidate_gold_path": _source_final_candidate_gold_path(row),
        "action": "skipped",
        "fail_reason": reason,
    }


def export_packets(
    *,
    workbench_dir: str | Path,
    rows: list[dict[str, Any]],
    skipped: list[dict[str, Any]],
    selection_reasons: dict[str, str],
    ts: str,
    batch_id: str | None = None,
    batch_index: int | None = None,
    batch_count: int | None = None,
    batch_size: int | None = None,
    is_final_partial_batch: bool | None = None,
    remaining_eligible_after_this_batch: int | None = None,
    priority: str | None = None,
    selection_mode: str = "priority",
    selection_meta: dict[str, Any] | None = None,
    export_gpt_batch_input: bool = False,
) -> tuple[Path, list[dict[str, Any]]]:
    workbench_path = Path(workbench_dir).resolve()
    dataset_namespace = _workbench_dataset_namespace(workbench_path)
    loader_config = _workbench_loader_config(workbench_path)
    unified_dataset = dataset_namespace == UNIFIED_DATASET_NAMESPACE
    source_final_candidate_gold_path = str(
        loader_config.get("source_final_candidate_gold")
        or (
            DEFAULT_PRIVATE_SOURCE_FINAL_CANDIDATE_GOLD
            if unified_dataset
            else ""
        )
    )
    public_workbench = dataset_namespace in PUBLIC_DATASET_NAMESPACES
    strict_blind_rebuild_required_for_eval = bool(
        loader_config.get(
            "strict_blind_rebuild_required_for_eval",
            unified_dataset or public_workbench,
        )
    )
    resolved_batch_id = batch_id or f"batch_{ts}"
    batch_dir = workbench_path / PACKET_BATCH_ROOT / resolved_batch_id
    batch_dir.mkdir(parents=True, exist_ok=False)
    exported_samples = []
    items = []
    for row in rows:
        packet = build_review_packet(row, workbench_path)
        attach_cited_evidence_panel(packet)
        stem = safe_packet_stem(row)
        sample_dir = batch_dir / stem
        sample_dir.mkdir(parents=True, exist_ok=False)
        json_path = sample_dir / LATEST_PACKET_JSON
        markdown_path = sample_dir / LATEST_PACKET_MD
        write_json(json_path, packet)
        markdown_path.write_text(render_packet_markdown_for_export(packet), encoding="utf-8")
        gpt_output_path = sample_dir / PER_SAMPLE_GPT_OUTPUT_FILE
        gpt_output_path.write_text("", encoding="utf-8")
        sample = _manifest_sample(
            row=row,
            packet=packet,
            json_path=json_path,
            markdown_path=markdown_path,
            selection_reason=selection_reasons.get(_row_label(row), "priority_selected"),
            forced_include=selection_reasons.get(_row_label(row)) == "reviewed_but_not_written_back_reaudit",
            action="packet_exported",
        )
        exported_samples.append(sample)
        items.append(
            {
                **sample,
                "action": "packet_exported",
                "fail_reason": "",
            }
        )
    skipped_samples = []
    for item in skipped:
        row = {
            "masked_sample_id": item.get("masked_sample_label", ""),
            "sample_id": item.get("sample_id", ""),
            "gold_stage": item.get("gold_stage", ""),
            "review_status": item.get("review_status", ""),
            "writeback_status": item.get("writeback_status", ""),
            "human_review_priority": item.get("human_review_priority", ""),
            "effective_review_priority": item.get("effective_review_priority", ""),
            "promotion_blocker": item.get("promotion_blocker", ""),
            "needs_later_patch": item.get("needs_later_patch", ""),
            "candidate_index": {
                "candidate_file": item.get("source_final_candidate_gold_path", ""),
                "final_candidate_gold_source": item.get("source_final_candidate_gold_path", ""),
            },
        }
        skipped_samples.append(
            _manifest_sample(
                row=row,
                packet=None,
                json_path=None,
                markdown_path=None,
                selection_reason=item.get("selection_reason", ""),
                forced_include=bool(item.get("forced_include")),
                action="skipped",
                skipped_reason=item.get("fail_reason", ""),
            )
        )
    selection_meta = selection_meta or {}
    actual_stage_counts = selection_meta.get("actual_stage_counts")
    if not isinstance(actual_stage_counts, dict):
        actual_stage_counts = {}
        for sample in exported_samples:
            stage = str(sample.get("gold_stage", "") or "").strip()
            actual_stage_counts[stage] = actual_stage_counts.get(stage, 0) + 1
    target_stage_counts = selection_meta.get("target_stage_counts", {})
    shortfall_stage = [
        entry.get("affected_stage", "")
        for entry in selection_meta.get("stage_shortages", [])
        if isinstance(entry, dict) and entry.get("affected_stage")
    ]
    stage_balance_target_met = bool(target_stage_counts) and not shortfall_stage
    manifest = {
        "batch_review_schema_version": BATCH_REVIEW_SCHEMA_VERSION,
        "batch_id": resolved_batch_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "workbench_dir": str(workbench_path),
        "batch_dir": str(batch_dir),
        "source_final_candidate_gold_path": source_final_candidate_gold_path,
        "selection_mode": selection_mode,
        "export_order": selection_meta.get("export_order", ""),
        "batch_index": batch_index,
        "batch_count": batch_count,
        "batch_size": batch_size if batch_size is not None else len(rows),
        "is_final_partial_batch": bool(is_final_partial_batch) if is_final_partial_batch is not None else False,
        "remaining_unreviewed_count_after_this_batch": remaining_eligible_after_this_batch,
        "selection_filters": {
            "review_status": selection_meta.get("review_status_filter", "review_status != reviewed"),
            "writeback_status": selection_meta.get("writeback_status_filter", "writeback_status != written_back"),
            "priority_filter": selection_meta.get("priority_filter", priority or "none"),
            "priority_filter_used": bool(selection_meta.get("priority_filter_used", bool(priority))),
            "priority_target": priority,
            "limit": selection_meta.get("limit_kind", len(rows)),
            "forced_include_samples": [sample.get("masked_sample_label", "") for sample in exported_samples if sample.get("forced_include")],
            "include_reviewed_forced_only": True,
            "include_written_back": False,
            "exclude_unfinished_exported_batches": bool(selection_meta.get("exclude_unfinished_exported_batches", True)),
            "target_per_stage": selection_meta.get("target_per_stage"),
        },
        "stage_export_count": actual_stage_counts,
        "stage_balance_target": target_stage_counts,
        "stage_balance_target_met": stage_balance_target_met,
        "shortfall_stage": shortfall_stage,
        "target_stage_counts": selection_meta.get("target_stage_counts", {}),
        "actual_stage_counts": actual_stage_counts,
        "stage_shortages": selection_meta.get("stage_shortages", []),
        "fill_strategy": selection_meta.get("fill_strategy", ""),
        "expected_remaining_count": selection_meta.get("expected_remaining_count"),
        "detected_remaining_count": selection_meta.get("detected_remaining_count", len(exported_samples)),
        "remaining_candidate_count_before_limit": selection_meta.get("remaining_candidate_count_before_limit"),
        "dataset_namespace": dataset_namespace,
        "unified_dataset": unified_dataset,
        "review_workbench_lineage": "P9.30e" if unified_dataset else None,
        "candidate_generation_lineage": "P9.30c" if unified_dataset else None,
        "post_generation_review_status_required": (
            "initial_unreviewed_default" if unified_dataset else None
        ),
        "strict_blind_rebuild_required_for_eval": strict_blind_rebuild_required_for_eval,
        "can_start_model_eval": False if strict_blind_rebuild_required_for_eval else None,
        "forbid_legacy_fallback": public_workbench,
        "legacy_status_inheritance": False if public_workbench else None,
        "p6_p7_status_used": False if public_workbench else None,
        "old_review_state_reuse_detected": False,
        "old_ui_drafts_reused": False,
        "old_human_review_status_reused": False,
        "old_writeback_log_reused": False,
        "old_review_packets_reused": False,
        "current_p9_30e_status_used": True if unified_dataset else None,
        "pre_promotion_status_reused": False if public_workbench else None,
        "all_initial_status_default": all(
            sample.get("review_status") in {"", "not_reviewed"}
            and sample.get("writeback_status") in {"", "not_written_back"}
            for sample in exported_samples
        ),
        "current_initial_review_status": "not_reviewed" if public_workbench else None,
        "current_initial_writeback_status": "not_written_back" if public_workbench else None,
        "packet_identity_rule": "one sample per packet; traceability remains not_for_reasoning",
        "gpt_output_file": str(batch_dir / GPT_OUTPUT_FILE),
        "gpt_batch_input_file": str(batch_dir / GPT_BATCH_INPUT_FILE)
        if export_gpt_batch_input
        else None,
        "gpt_markdown_output_file": str(batch_dir / GPT_MARKDOWN_OUTPUT_FILE),
        "per_sample_gpt_output_glob": str(batch_dir / "*" / PER_SAMPLE_GPT_OUTPUT_FILE),
        "sample_count": len(exported_samples),
        "samples": exported_samples,
        "entries": [_legacy_manifest_entry(sample) for sample in exported_samples],
        "skipped_samples": skipped_samples,
        "selection_skipped": skipped,
        "protected_scope": _protected_scope_confirmation(),
    }
    write_json(batch_dir / "batch_manifest.json", manifest)
    (batch_dir / "README.md").write_text(render_batch_readme(manifest), encoding="utf-8")
    if export_gpt_batch_input:
        gpt_input = render_gpt_batch_input(manifest)
        (batch_dir / GPT_BATCH_INPUT_FILE).write_text(gpt_input, encoding="utf-8")
    return batch_dir, items


def _chunk_rows(rows: list[dict[str, Any]], batch_size: int) -> list[list[dict[str, Any]]]:
    return [rows[index : index + batch_size] for index in range(0, len(rows), batch_size)]


def _total_manifest_skipped_samples(skipped: list[dict[str, Any]]) -> list[dict[str, Any]]:
    samples = []
    for item in skipped:
        if not isinstance(item, dict):
            continue
        samples.append(
            {
                "masked_sample_label": item.get("masked_sample_label", ""),
                "sample_id": item.get("sample_id", ""),
                "gold_stage": item.get("gold_stage", ""),
                "review_status": item.get("review_status", ""),
                "writeback_status": item.get("writeback_status", ""),
                "source_final_candidate_gold_path": item.get("source_final_candidate_gold_path", ""),
                "skipped_reason": item.get("fail_reason", item.get("skipped_reason", "")),
            }
        )
    return samples


def write_export_all_remaining_manifest(
    *,
    workbench_dir: str | Path,
    ts: str,
    batch_size: int,
    selection_meta: dict[str, Any],
    created_batch_dirs: list[Path],
    exported_samples: list[dict[str, Any]],
    skipped: list[dict[str, Any]],
    remaining_eligible_after_export: int,
) -> Path:
    workbench_path = Path(workbench_dir).resolve()
    loader_config = _workbench_loader_config(workbench_path)
    dataset_namespace = _workbench_dataset_namespace(workbench_path)
    unified_dataset = dataset_namespace == UNIFIED_DATASET_NAMESPACE
    source_final_candidate_gold_path = str(
        loader_config.get("source_final_candidate_gold")
        or (
            DEFAULT_PRIVATE_SOURCE_FINAL_CANDIDATE_GOLD
            if unified_dataset
            else ""
        )
    )
    strict_blind_rebuild_required_for_eval = bool(
        loader_config.get("strict_blind_rebuild_required_for_eval", unified_dataset)
    )
    total_remaining = int(
        selection_meta.get(
            "total_remaining_eligible_before_export",
            selection_meta.get("remaining_candidate_count_before_limit", len(exported_samples)),
        )
        or 0
    )
    manifest = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "workbench_dir": str(workbench_path),
        "source_final_candidate_gold_path": source_final_candidate_gold_path,
        "selection_mode": EXPORT_ALL_REMAINING_SELECTION_MODE,
        "export_order": EXPORT_ALL_REMAINING_EXPORT_ORDER,
        "batch_size": batch_size,
        "selection_filters": {
            "review_status": selection_meta.get("review_status_filter", "review_status != reviewed"),
            "writeback_status": selection_meta.get("writeback_status_filter", "writeback_status != written_back"),
            "priority_filter": "none",
            "priority_filter_used": False,
            "exclude_unfinished_exported_batches": True,
        },
        "total_remaining_eligible_before_export": total_remaining,
        "total_exported_sample_count": len(exported_samples),
        "total_skipped_sample_count": len(skipped),
        "created_batch_count": len(created_batch_dirs),
        "created_batch_dirs": [str(path) for path in created_batch_dirs],
        "exported_sample_ids": [sample.get("sample_id", "") for sample in exported_samples],
        "exported_samples": exported_samples,
        "skipped_samples": _total_manifest_skipped_samples(skipped),
        "remaining_eligible_after_export": remaining_eligible_after_export,
        "dataset_namespace": dataset_namespace,
        "unified_dataset": unified_dataset,
        "review_workbench_lineage": "P9.30e" if unified_dataset else None,
        "candidate_generation_lineage": "P9.30c" if unified_dataset else None,
        "strict_blind_rebuild_required_for_eval": strict_blind_rebuild_required_for_eval,
        "can_start_model_eval": False if strict_blind_rebuild_required_for_eval else None,
        "old_review_state_reuse_detected": False,
        "old_ui_drafts_reused": False,
        "old_human_review_status_reused": False,
        "old_writeback_log_reused": False,
        "old_review_packets_reused": False,
        "current_p9_30e_status_used": True if unified_dataset else None,
        "pre_promotion_status_reused": False,
        "current_p9_30e_status_source": str(workbench_path / "ui_drafts"),
        "protected_scope": _protected_scope_confirmation(),
    }
    path = workbench_path / PACKET_BATCH_ROOT / f"export_all_remaining_{ts}_manifest.json"
    write_json(path, manifest)
    return path


def _protected_scope_confirmation() -> dict[str, bool]:
    return {
        "dataset_release_v1_modified": False,
        "canonical_gold_modified": False,
        "label_stage_modified": False,
        "candidate_index_modified": False,
        "candidate_summary_modified": False,
        "evidence_refs_modified": False,
        "clean_final_set_true": False,
        "formal_human_verified_written": False,
        "promotion_fields_modified": False,
        "api_called": False,
        "multiagent_run": False,
        "automatic_promotion": False,
    }


def render_batch_readme(manifest: dict[str, Any]) -> str:
    forced_include_samples = [
        str(sample.get("masked_sample_label", "")).strip()
        for sample in manifest.get("samples", [])
        if isinstance(sample, dict) and sample.get("forced_include")
    ]
    if manifest.get("unified_dataset"):
        title = "# P9.30e Promoted-Compact Per-Sample Review Packet Batch"
    elif manifest.get("selection_mode") == STAGE_BALANCED_PILOT12_MODE:
        title = "# Stage-Balanced Pilot12 Per-Sample Review Packet Batch"
    else:
        title = "# P6.26 Per-Sample Review Packet Batch"
    lines = [
        title,
        "",
        "Each sample directory contains one independent Review UI packet.",
        "",
        "Workflow:",
        "",
        "1. Open one sample directory's `latest_review_packet.md`.",
        "2. Copy that one file to GPT together with the single-sample human reviewer prompt.",
        "3. GPT should return one complete `# Review UI copy-ready output` block for that sample.",
        "4. Paste the full GPT output into that same sample directory as `gpt_review_output.md`.",
        "5. Save all required `gpt_review_output.md` files first, then ask Codex to run per-sample batch writeback later.",
        "",
        "Important reminders:",
        "",
        "- Open one sample directory at a time, such as `<masked_sample_label>/latest_review_packet.md`.",
        "- Do not send multiple sample packets together in one GPT request.",
        "- Do not save sample A's GPT output into sample B's directory.",
        "- Before any future writeback, Codex must still validate masked_sample_label, gold_stage, key seq, relation, process, and object.",
        "- Batch export is not batch writeback.",
        "- Empty `gpt_review_output.md` must be treated as skipped.",
        "- This batch belongs to the unified SecLog-Bench review workbench.",
        "- Do not mix review state from a different workbench or dataset release.",
        "- Do not use P9.25r2g pre-promotion `final_candidate_gold.jsonl` as the writeback source for this batch.",
        "- This task exports all remaining unreviewed / not-written-back samples in stable sample order; no high / medium / low priority filter is used.",
        f"- Each batch contains at most `{manifest.get('batch_size', manifest.get('sample_count', ''))}` samples; the final batch may contain fewer.",
        "- This task does not handle strict-blind rebuild; model eval must not start.",
        "- This batch is a packet export, not a formal review result.",
        "- If `gpt_review_output.md` is empty, later apply must skip it as invalid GPT output.",
        "",
        "Safety boundaries:",
        "",
        "- This export does not parse GPT output, write draft/status, dry-run, or write back formal data.",
        "- No API calls or multiagent runs are performed by this batch tool.",
        "- Failed or incomplete samples are recorded as skipped in `batch_manifest.json`.",
        "",
        "Samples:",
        "",
    ]
    if forced_include_samples:
        lines.insert(
            16,
            "- Force-included re-review samples in this batch: "
            + ", ".join(f"`{label}`" for label in forced_include_samples) + ".",
        )
    for sample in manifest.get("samples", []):
        if not isinstance(sample, dict) or sample.get("action") == "skipped":
            continue
        lines.append(
            f"- `{sample.get('masked_sample_label', '')}/latest_review_packet.md` "
            f"gold_stage=`{sample.get('gold_stage', '')}` "
            f"selection_reason=`{sample.get('selection_reason', '')}`"
        )
    return "\n".join(lines).rstrip() + "\n"


def render_gpt_batch_input(manifest: dict[str, Any]) -> str:
    """Render full independent packets into one GPT chat input markdown."""
    lines = [
        "# EWVAA Review UI Batch Review Input",
        "",
        "You are reviewing multiple independent samples. Treat each sample independently.",
        "Do not mix evidence, seq, process, relation, URL, object, or stage information across samples.",
        "For each sample, output one complete `# Review UI copy-ready output` block.",
        "",
        "Output order must follow the sample order below.",
        "",
        "## GPT Output Requirements",
        "",
        "For each sample, output exactly one block:",
        "",
        "````markdown",
        "# Review UI copy-ready output",
        "",
        "## 0. Packet identity check",
        "",
        "```text",
        "masked_sample_label:",
        "gold_stage:",
        "key_seq:",
        "key_relation:",
        "key_subject_or_process:",
        "key_object_or_target:",
        "```",
        "",
        "## 1. Decision summary",
        "",
        "- gold_stage:",
        "- evidence_grounding: high / medium / low",
        "- stage_boundary_quality: strong / acceptable_with_manual_review / weak",
        "- final_decision:",
        "- writeback_recommendation: no_writeback_for_now / dry_run_only_after_validation / consider_after_human_confirmation",
        "",
        "# Draft Editing Panel",
        "",
        "## 2. Draft claim: scenario_or_evidence_understanding",
        "",
        "```text",
        "...",
        "```",
        "",
        "## 3. Draft claim: observable_evidence",
        "",
        "```text",
        "...",
        "```",
        "",
        "## 4. Draft claim: attack_stage_path_reasoning",
        "",
        "```text",
        "...",
        "```",
        "",
        "## 5. Draft claim: final_judgement",
        "",
        "```text",
        "...",
        "```",
        "",
        "## 6. auxiliary_vulnerability_note.claim",
        "",
        "```text",
        "...",
        "```",
        "",
        "## 7. reviewer_decision",
        "",
        "```text",
        "...",
        "```",
        "",
        "## 8. reviewer_notes",
        "",
        "```text",
        "...",
        "```",
        "",
        "## 9. promotion_decision",
        "",
        "```text",
        "...",
        "```",
        "",
        "## 10. clean_final_allowed",
        "",
        "```text",
        "no",
        "```",
        "",
        "## 11. canonical_gold_allowed",
        "",
        "```text",
        "no",
        "```",
        "",
        "# Human Review Status Panel",
        "",
        "### review_status",
        "",
        "```text",
        "reviewed",
        "```",
        "",
        "### writeback_status",
        "",
        "```text",
        "not_written_back",
        "```",
        "",
        "### needs_later_patch_after_review",
        "",
        "```text",
        "yes / no",
        "```",
        "",
        "### promotion_blocker_after_review",
        "",
        "```text",
        "yes / no",
        "```",
        "",
        "### status_notes",
        "",
        "```text",
        "...",
        "```",
        "",
        "## 16. What to do next in UI",
        "",
        "...",
        "````",
        "",
        "Rules:",
        "",
        "1. Each sample must be output independently.",
        "2. Each output block must include masked_sample_label.",
        "3. Do not reuse evidence across samples.",
        "4. Do not output an aggregate summary instead of per-sample review blocks.",
        "5. If a sample is uncertain, still output that sample block, but use `needs_later_patch_keep_candidate_with_manual_review` for reviewer_decision and explain why in notes.",
        "6. Keep workflow/status terms out of formal draft claims and auxiliary_vulnerability_note.claim.",
        "",
    ]
    for entry in manifest.get("entries", []):
        if not isinstance(entry, dict):
            continue
        markdown_path = Path(entry.get("packet_markdown", ""))
        packet_text = markdown_path.read_text(encoding="utf-8")
        lines.extend(
            [
                "---",
                "",
                "# SAMPLE_BLOCK_START",
                f"masked_sample_label: {entry.get('masked_sample_label', '')}",
                f"gold_stage: {entry.get('gold_stage', '')}",
                f"packet_file: {markdown_path.name}",
                "",
                packet_text.rstrip(),
                "# SAMPLE_BLOCK_END",
                "",
            ]
        )
    return "\n".join(lines).rstrip() + "\n"


def _load_manifest(batch_dir: Path) -> dict[str, Any]:
    manifest_path = batch_dir / "batch_manifest.json"
    if not manifest_path.exists():
        raise FileNotFoundError(f"batch_manifest.json not found: {manifest_path}")
    manifest = _read_json(manifest_path)
    if not isinstance(manifest, dict):
        raise ValueError(f"batch_manifest.json is not an object: {manifest_path}")
    return manifest


def _entry_maps(manifest: dict[str, Any]) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    by_label = {}
    by_sample_id = {}
    entries = manifest.get("entries")
    if not isinstance(entries, list):
        entries = [_legacy_manifest_entry(sample) for sample in manifest.get("samples", [])]
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        label = entry.get("masked_sample_label")
        sample_id = entry.get("sample_id")
        if label:
            by_label[label] = entry
        if sample_id:
            by_sample_id[sample_id] = entry
    return by_label, by_sample_id


def _packet_for_entry(entry: dict[str, Any]) -> dict[str, Any]:
    packet_path = Path(entry.get("packet_json", ""))
    if not packet_path.exists():
        raise FileNotFoundError(f"packet json not found: {packet_path}")
    packet = _read_json(packet_path)
    if not isinstance(packet, dict):
        raise ValueError(f"packet json is not an object: {packet_path}")
    return packet


def _packet_for_entry_from_sample_dir(entry: dict[str, Any]) -> dict[str, Any]:
    label = entry.get("masked_sample_label", "")
    packet_path = Path(entry.get("packet_json", ""))
    if packet_path.name != LATEST_PACKET_JSON:
        packet_path = packet_path.parent / LATEST_PACKET_JSON
    if not packet_path.exists() and label:
        packet_path = Path(entry.get("packet_markdown", "")).parent / LATEST_PACKET_JSON
    if not packet_path.exists():
        return _packet_for_entry(entry)
    packet = _read_json(packet_path)
    if not isinstance(packet, dict):
        raise ValueError(f"packet json is not an object: {packet_path}")
    return packet


def _draft_from_output(
    *,
    row: dict[str, Any],
    output: dict[str, Any],
) -> dict[str, Any]:
    draft = make_draft_from_original(row)
    original_chain = row.get("candidate", {}).get("gold_reasoning_chain", [])
    claims = output.get("draft_claims", [])
    new_chain = []
    for index, original_step in enumerate(original_chain):
        original_step = original_step if isinstance(original_step, dict) else {}
        claim = claims[index] if index < len(claims) and isinstance(claims[index], dict) else {}
        new_chain.append(
            {
                "step": original_step.get("step", claim.get("step", "")),
                "claim": str(claim.get("claim", "")).strip(),
                "evidence_refs": copy.deepcopy(original_step.get("evidence_refs", [])),
            }
        )
    aux = output.get("auxiliary_vulnerability_note", "")
    if isinstance(aux, dict):
        aux_note = copy.deepcopy(aux)
        aux_note["claim"] = str(aux_note.get("claim", "")).strip()
    else:
        aux_note = {"claim": str(aux or "").strip()}
    if "not_for_scoring" in row.get("candidate", {}).get("auxiliary_vulnerability_note", {}):
        aux_note.setdefault(
            "not_for_scoring",
            bool(row["candidate"]["auxiliary_vulnerability_note"].get("not_for_scoring")),
        )
    draft.update(
        {
            "draft_reasoning_chain": new_chain,
            "draft_auxiliary_vulnerability_note": aux_note,
            "reviewer_decision": str(output.get("reviewer_decision", "") or ""),
            "reviewer_notes": str(output.get("notes", "") or ""),
            "promotion_decision": str(output.get("promotion_decision", "") or ""),
            "clean_final_allowed": "no",
            "canonical_gold_allowed": "no",
        }
    )
    return draft


def _status_values_from_output(
    output: dict[str, Any],
    *,
    writeback_status: str = "not_written_back",
    writeback_log_ref: Any = None,
    extra_note: str = "",
) -> dict[str, Any]:
    notes = str(output.get("notes", "") or "")
    if extra_note:
        notes = (notes + "\n" + extra_note).strip()
    return {
        "review_status": output.get("review_status", "reviewed"),
        "reviewer_decision": str(output.get("reviewer_decision", "") or ""),
        "promotion_decision": str(output.get("promotion_decision", "") or ""),
        "clean_final_allowed": "no",
        "canonical_gold_allowed": "no",
        "writeback_status": writeback_status,
        "writeback_log_ref": writeback_log_ref,
        "needs_later_patch_after_review": output.get("needs_later_patch_after_review", "yes"),
        "promotion_blocker_after_review": output.get("promotion_blocker_after_review", "yes"),
        "notes": notes,
    }


def _formal_diff_summary(diff_preview: dict[str, Any]) -> dict[str, Any]:
    changed_formal = []
    for field in diff_preview.get("fields", []):
        name = field.get("field", "")
        if field.get("changed") and (
            name.startswith("gold_reasoning_chain[")
            or name == "auxiliary_vulnerability_note.claim"
        ):
            changed_formal.append(name)
    return {
        "available": diff_preview.get("available"),
        "changed": bool(changed_formal),
        "changed_formal_fields": changed_formal,
        "changed_count": len(changed_formal),
        "preview_only": diff_preview.get("preview_only"),
    }


def _path_matches_any(target: str, candidates: list[str]) -> bool:
    target_path = Path(target)
    for candidate in candidates:
        if not candidate:
            continue
        candidate_path = Path(candidate)
        if str(target_path) == str(candidate_path):
            return True
        try:
            if target_path.resolve() == candidate_path.resolve():
                return True
        except OSError:
            continue
    return False


def _writeback_gate_ok(
    dry_run_result: dict[str, Any],
    entry: dict[str, Any],
    *,
    row: dict[str, Any] | None = None,
    packet: dict[str, Any] | None = None,
) -> tuple[bool, list[str]]:
    errors = []
    if dry_run_result.get("ok") is not True:
        errors.append("dry-run ok is not true")
    if dry_run_result.get("would_write") is not True:
        errors.append("dry-run would_write is not true")
    if dry_run_result.get("changed_sample_count") != 1:
        errors.append("changed_sample_count must be 1")
    if dry_run_result.get("changed_line_count") != 1:
        errors.append("changed_line_count must be 1")
    changed_fields = set(dry_run_result.get("changed_fields", []))
    if not changed_fields.issubset({"gold_reasoning_chain", "auxiliary_vulnerability_note"}):
        errors.append("changed_fields exceeds allowed formal field set")
    if not changed_fields:
        errors.append("changed_fields is empty")
    target = dry_run_result.get("target_final_candidate_gold_path")
    allowed_targets = [entry.get("source_final_candidate_gold_path", "")]
    if isinstance(row, dict):
        candidate_index = row.get("candidate_index", {})
        if isinstance(candidate_index, dict):
            allowed_targets.extend(
                [
                    str(candidate_index.get("candidate_file", "") or ""),
                    str(candidate_index.get("final_candidate_gold_source", "") or ""),
                ]
            )
    if isinstance(packet, dict):
        traceability = packet.get("traceability", {})
        if isinstance(traceability, dict):
            allowed_targets.extend(
                [
                    str(traceability.get("candidate_file", "") or ""),
                    str(traceability.get("source_path", "") or ""),
                ]
            )
    if not _path_matches_any(str(target or ""), allowed_targets):
        errors.append("target_final_candidate_gold_path does not match packet/current candidate targets")
    return not errors, errors


def _status_written_back_noop(
    *,
    workbench_dir: Path,
    row: dict[str, Any],
    output: dict[str, Any],
    reason: str,
) -> dict[str, Any]:
    return save_human_review_status(
        workbench_dir,
        row,
        _status_values_from_output(
            output,
            writeback_status="written_back",
            writeback_log_ref={"event": "strict_noop", "reason": reason},
            extra_note=reason,
        ),
    )


def _markdown_blocks(text: str) -> list[str]:
    pattern = re.compile(
        r"(?m)^# Review UI copy-ready output\s*$"
        r"(.*?)(?=^# Review UI copy-ready output\s*$|\Z)",
        re.DOTALL,
    )
    return [match.group(0).strip() for match in pattern.finditer(text)]


def _section_after_heading(block: str, heading_pattern: str) -> str:
    pattern = re.compile(
        rf"(?im)^{heading_pattern}\s*$"
        r"(.*?)(?=^\#{1,6}\s+|\Z)",
        re.DOTALL,
    )
    match = pattern.search(block)
    return match.group(1).strip() if match else ""


def _first_code_block(text: str) -> str:
    match = re.search(r"```(?:text|json|markdown)?\s*\n(.*?)\n```", text, flags=re.DOTALL)
    if match:
        return match.group(1).strip()
    return text.strip()


def _code_after_heading(block: str, heading_pattern: str) -> str:
    return _first_code_block(_section_after_heading(block, heading_pattern))


def _kv_from_text(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in text.splitlines():
        stripped = line.strip().lstrip("-").strip()
        if ":" not in stripped:
            continue
        key, value = stripped.split(":", 1)
        key = key.strip()
        if key:
            values[key] = value.strip()
    return values


def _normalize_yes_no(value: str, default: str = "yes") -> str:
    lowered = str(value or "").strip().lower()
    if lowered in {"yes", "no"}:
        return lowered
    if lowered.startswith("yes"):
        return "yes"
    if lowered.startswith("no"):
        return "no"
    return default


def _parse_gpt_markdown_block(block: str, line_no: int) -> dict[str, Any]:
    identity_text = _code_after_heading(block, r"\#{2}\s+0\.\s+Packet identity check")
    identity = _kv_from_text(identity_text)
    if not identity:
        header_match = re.search(r"(?im)^masked_sample_label\s*:\s*(.+?)\s*$", block)
        stage_match = re.search(r"(?im)^gold_stage\s*:\s*(.+?)\s*$", block)
        identity = {
            "masked_sample_label": header_match.group(1).strip() if header_match else "",
            "gold_stage": stage_match.group(1).strip() if stage_match else "",
        }
    claims = [
        {
            "step": "scenario_or_evidence_understanding",
            "claim": _code_after_heading(
                block,
                r"\#{2}\s+2\.\s+Draft claim(?:\s+1)?\s*:\s+scenario_or_evidence_understanding",
            ),
        },
        {
            "step": "observable_evidence",
            "claim": _code_after_heading(
                block,
                r"\#{2}\s+3\.\s+Draft claim(?:\s+2)?\s*:\s+observable_evidence",
            ),
        },
        {
            "step": "attack_stage_path_reasoning",
            "claim": _code_after_heading(
                block,
                r"\#{2}\s+4\.\s+Draft claim(?:\s+3)?\s*:\s+attack_stage_path_reasoning",
            ),
        },
        {
            "step": "final_judgement",
            "claim": _code_after_heading(
                block,
                r"\#{2}\s+5\.\s+Draft claim(?:\s+4)?\s*:\s+final_judgement",
            ),
        },
    ]
    notes = _code_after_heading(block, r"\#{2}\s+8\.\s+reviewer_notes")
    status_notes = _code_after_heading(block, r"\#{3}\s+status_notes")
    if status_notes:
        notes = (notes + "\n" + status_notes).strip()

    def first_code(*patterns: str, default: str = "") -> str:
        for pattern in patterns:
            value = _code_after_heading(block, pattern)
            if value:
                return value
        return default

    output = {
        "masked_sample_label": identity.get("masked_sample_label", ""),
        "gold_stage": identity.get("gold_stage", ""),
        "key_seq": identity.get("key_seq", ""),
        "key_relation": identity.get("key_relation", ""),
        "key_subject_or_process": identity.get("key_subject_or_process", ""),
        "key_object_or_target": identity.get("key_object_or_target", ""),
        "draft_claims": claims,
        "auxiliary_vulnerability_note": _code_after_heading(
            block,
            r"\#{2}\s+6\.\s+auxiliary_vulnerability_note\.claim",
        ),
        "review_status": first_code(r"\#{3}\s+review_status", r"\#{2}\s+7\.\s+review_status", default="reviewed")
        or "reviewed",
        "reviewer_decision": first_code(
            r"\#{2}\s+7\.\s+reviewer_decision",
            r"\#{2}\s+8\.\s+reviewer_decision",
        ),
        "promotion_decision": first_code(
            r"\#{2}\s+9\.\s+promotion_decision",
            r"\#{2}\s+9\.\s+promotion_decision",
        ),
        "clean_final_allowed": first_code(
            r"\#{2}\s+10\.\s+clean_final_allowed",
        )
        or "no",
        "canonical_gold_allowed": first_code(
            r"\#{2}\s+11\.\s+canonical_gold_allowed",
        )
        or "no",
        "writeback_status": first_code(r"\#{3}\s+writeback_status", r"\#{2}\s+12\.\s+writeback_status")
        or "not_written_back",
        "needs_later_patch_after_review": _normalize_yes_no(
            first_code(
                r"\#{3}\s+needs_later_patch_after_review",
                r"\#{2}\s+13\.\s+needs_later_patch_after_review",
            ),
            default="yes",
        ),
        "promotion_blocker_after_review": _normalize_yes_no(
            first_code(
                r"\#{3}\s+promotion_blocker_after_review",
                r"\#{2}\s+14\.\s+promotion_blocker_after_review",
            ),
            default="yes",
        ),
        "notes": notes or first_code(r"\#{2}\s+15\.\s+notes"),
        "_line_no": line_no,
        "_source_format": "markdown",
    }
    missing = []
    for field in [
        "masked_sample_label",
        "gold_stage",
        "auxiliary_vulnerability_note",
        "review_status",
        "reviewer_decision",
        "promotion_decision",
        "clean_final_allowed",
        "canonical_gold_allowed",
        "writeback_status",
        "needs_later_patch_after_review",
        "promotion_blocker_after_review",
        "notes",
    ]:
        if not str(output.get(field, "")).strip():
            missing.append(field)
    for index, claim in enumerate(claims, start=1):
        if not claim["claim"].strip():
            missing.append(f"draft_claim_{index}")
    if missing:
        output["_batch_line_error"] = "missing required markdown fields: " + ", ".join(missing)
    return output


def parse_gpt_markdown_output(path: Path) -> list[dict[str, Any]]:
    text = _read_review_text(path)
    blocks = _markdown_blocks(text)
    if not blocks:
        return [
            {
                "_batch_line_error": "no '# Review UI copy-ready output' blocks found",
                "_line_no": 1,
                "_source_format": "markdown",
            }
        ]
    outputs = []
    for block in blocks:
        start = text.find(block)
        line_no = text[:start].count("\n") + 1 if start >= 0 else 1
        outputs.append(_parse_gpt_markdown_block(block, line_no))
    return outputs


def _apply_outputs(
    *,
    workbench_dir: str | Path,
    batch_dir: str | Path,
    output_rows: list[dict[str, Any]],
    write: bool,
    confirm_batch_writeback: bool,
    duplicate_context: str = "batch outputs",
) -> list[dict[str, Any]]:
    workbench_path = Path(workbench_dir)
    batch_path = Path(batch_dir)
    manifest = _load_manifest(batch_path)
    by_label, _by_sample_id = _entry_maps(manifest)
    bundle = load_workbench(workbench_path)
    results = []
    seen_labels = set()
    for output in output_rows:
        label = output.get("masked_sample_label") if isinstance(output, dict) else ""
        base = {
            "masked_sample_label": label or "",
            "sample_id": "",
            "gold_stage": output.get("gold_stage", "") if isinstance(output, dict) else "",
            "action": "failed",
            "fail_reason": "",
            "failed_reason": "",
            "failed_stage": "",
            "draft_save": None,
            "status_save": None,
            "validation": None,
            "formal_diff": None,
            "dry_run": None,
            "writeback": None,
            "backup": None,
            "writeback_log": None,
        }
        if output.get("_batch_line_error"):
            base["fail_reason"] = output["_batch_line_error"]
            base["failed_reason"] = base["fail_reason"]
            base["failed_stage"] = "markdown_parse" if output.get("_source_format") == "markdown" else "jsonl_parse"
            results.append(base)
            continue
        entry = by_label.get(label)
        if not entry:
            base["fail_reason"] = "masked_sample_label not found in batch_manifest"
            base["failed_reason"] = base["fail_reason"]
            base["failed_stage"] = "identity_lookup"
            results.append(base)
            continue
        if label in seen_labels:
            base["fail_reason"] = f"duplicate masked_sample_label in {duplicate_context}"
            base["failed_reason"] = base["fail_reason"]
            base["failed_stage"] = "identity_lookup"
            base["sample_id"] = entry.get("sample_id", "")
            results.append(base)
            continue
        seen_labels.add(label)
        sample_id = entry.get("sample_id", "")
        base["sample_id"] = sample_id
        base["gold_stage"] = entry.get("gold_stage", "")
        try:
            row = get_sample_detail(bundle, sample_id)
            if row is None:
                raise ValueError(f"sample_id not found in current workbench: {sample_id}")
            packet = _packet_for_entry_from_sample_dir(entry)
            gate = validate_batch_review_output(output=output, packet=packet, row=row)
            base["batch_gate"] = gate
            if not gate["valid"]:
                base["fail_reason"] = "; ".join(gate["errors"])
                base["failed_reason"] = base["fail_reason"]
                base["failed_stage"] = "sample_consistency_gate"
                results.append(base)
                continue
            draft = _draft_from_output(row=row, output=output)
            draft_save = save_draft(workbench_path, row, draft)
            base["draft_save"] = _jsonable_save_result(draft_save)
            if not draft_save.get("saved"):
                base["fail_reason"] = "draft save failed: " + "; ".join(draft_save.get("errors", []))
                base["failed_reason"] = base["fail_reason"]
                base["failed_stage"] = "draft_save"
                results.append(base)
                continue
            saved_draft = draft_save["draft"]
            validation = validate_row_draft(row, saved_draft)
            base["validation"] = validation
            if not validation.get("valid"):
                base["fail_reason"] = "validation failed: " + "; ".join(validation.get("errors", []))
                base["failed_reason"] = base["fail_reason"]
                base["failed_stage"] = "validation"
                results.append(base)
                continue
            status_save = save_human_review_status(
                workbench_path,
                row,
                _status_values_from_output(output, writeback_status="not_written_back"),
            )
            base["status_save"] = _jsonable_save_result(status_save)
            diff_preview = preview_row_diff(row, saved_draft)
            save_diff_preview(workbench_path, diff_preview)
            formal_diff = _formal_diff_summary(diff_preview)
            base["formal_diff"] = formal_diff
            dry_run = write_single_sample_draft_to_final_candidate(
                workbench_dir=str(workbench_path),
                sample_id=sample_id,
                dry_run=True,
                confirm_writeback=False,
            )
            base["dry_run"] = dry_run
            if not dry_run.get("ok"):
                base["fail_reason"] = "writeback dry-run failed"
                base["failed_reason"] = base["fail_reason"]
                base["failed_stage"] = "dry_run"
                results.append(base)
                continue
            if dry_run.get("would_write") is False:
                reason = "formal_fields_already_equal"
                noop_status = _status_written_back_noop(
                    workbench_dir=workbench_path,
                    row=row,
                    output=output,
                    reason=reason,
                )
                base["status_save"] = _jsonable_save_result(noop_status)
                base["action"] = "strict_noop"
                base["fail_reason"] = ""
                base["writeback"] = {
                    "ok": True,
                    "strict_noop": True,
                    "formal_fields_equal": True,
                    "real_writeback_executed": False,
                    "reason": reason,
                }
                results.append(base)
                continue
            if not write:
                base["action"] = "dry_run_ok"
                base["fail_reason"] = ""
                results.append(base)
                continue
            if not confirm_batch_writeback:
                base["fail_reason"] = "--confirm-batch-writeback is required with --write"
                base["failed_reason"] = base["fail_reason"]
                base["failed_stage"] = "writeback_confirm"
                results.append(base)
                continue
            writeback_gate_ok, writeback_gate_errors = _writeback_gate_ok(
                dry_run,
                entry,
                row=row,
                packet=packet,
            )
            if not writeback_gate_ok:
                base["fail_reason"] = "; ".join(writeback_gate_errors)
                base["failed_reason"] = base["fail_reason"]
                base["failed_stage"] = "writeback_gate"
                results.append(base)
                continue
            real_write = write_single_sample_draft_to_final_candidate(
                workbench_dir=str(workbench_path),
                sample_id=sample_id,
                dry_run=False,
                confirm_writeback=True,
            )
            base["writeback"] = real_write
            base["backup"] = real_write.get("backup_path")
            base["writeback_log"] = real_write.get("writeback_log_path")
            if not real_write.get("ok"):
                base["fail_reason"] = "real writeback failed"
                base["failed_reason"] = base["fail_reason"]
                base["failed_stage"] = "real_writeback"
                results.append(base)
                continue
            written_status = save_human_review_status(
                workbench_path,
                row,
                _status_values_from_output(
                    output,
                    writeback_status="written_back",
                    writeback_log_ref=real_write.get("writeback_event"),
                ),
            )
            base["status_save"] = _jsonable_save_result(written_status)
            base["action"] = "written_back"
            base["fail_reason"] = ""
            results.append(base)
        except Exception as exc:  # keep batch isolation per sample
            base["fail_reason"] = f"{type(exc).__name__}: {exc}"
            base["failed_reason"] = base["fail_reason"]
            base["failed_stage"] = "exception"
            results.append(base)
    return results


def apply_gpt_jsonl(
    *,
    workbench_dir: str | Path,
    batch_dir: str | Path,
    write: bool,
    confirm_batch_writeback: bool,
) -> list[dict[str, Any]]:
    batch_path = Path(batch_dir)
    outputs_path = batch_path / GPT_OUTPUT_FILE
    if not outputs_path.exists():
        raise FileNotFoundError(f"batch GPT output jsonl not found: {outputs_path}")
    return _apply_outputs(
        workbench_dir=workbench_dir,
        batch_dir=batch_path,
        output_rows=_read_jsonl(outputs_path),
        write=write,
        confirm_batch_writeback=confirm_batch_writeback,
        duplicate_context=GPT_OUTPUT_FILE,
    )


def apply_gpt_markdown(
    *,
    workbench_dir: str | Path,
    batch_dir: str | Path,
    write: bool,
    confirm_batch_writeback: bool,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    batch_path = Path(batch_dir)
    markdown_path = batch_path / GPT_MARKDOWN_OUTPUT_FILE
    if not markdown_path.exists():
        raise FileNotFoundError(f"batch GPT markdown output not found: {markdown_path}")
    outputs = parse_gpt_markdown_output(markdown_path)
    parsed_jsonl_path = batch_path / "batch_gpt_review_output.parsed.jsonl"
    _write_jsonl(parsed_jsonl_path, outputs)
    items = _apply_outputs(
        workbench_dir=workbench_dir,
        batch_dir=batch_path,
        output_rows=outputs,
        write=write,
        confirm_batch_writeback=confirm_batch_writeback,
        duplicate_context=GPT_MARKDOWN_OUTPUT_FILE,
    )
    return items, {
        "gpt_markdown_output_path": str(markdown_path),
        "parsed_gpt_output_count": len(outputs),
        "parsed_gpt_output_jsonl": str(parsed_jsonl_path),
    }


def _entry_sample_dir(entry: dict[str, Any], batch_dir: Path) -> Path:
    value = entry.get("sample_dir")
    if value:
        return Path(value)
    label = entry.get("masked_sample_label", "")
    return batch_dir / label


def _failed_or_skipped_from_entry(
    entry: dict[str, Any],
    *,
    action: str,
    reason: str,
    failed_stage: str = "",
) -> dict[str, Any]:
    return {
        "masked_sample_label": entry.get("masked_sample_label", ""),
        "sample_id": entry.get("sample_id", ""),
        "gold_stage": entry.get("gold_stage", ""),
        "action": action,
        "fail_reason": reason,
        "failed_reason": reason,
        "failed_stage": failed_stage,
        "draft_save": None,
        "status_save": None,
        "validation": None,
        "formal_diff": None,
        "dry_run": None,
        "writeback": None,
        "backup": None,
        "writeback_log": None,
    }


def apply_per_sample_gpt_outputs(
    *,
    workbench_dir: str | Path,
    batch_dir: str | Path,
    write: bool,
    confirm_batch_writeback: bool,
    sample_id: str | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    batch_path = Path(batch_dir)
    manifest = _load_manifest(batch_path)
    manifest_entries = manifest.get("entries")
    if not isinstance(manifest_entries, list):
        manifest_entries = [_legacy_manifest_entry(sample) for sample in manifest.get("samples", [])]
    outputs = []
    pre_items = []
    found_count = 0
    parsed_count = 0
    target_entry_seen = False
    for entry in manifest_entries:
        if not isinstance(entry, dict):
            continue
        if sample_id and entry.get("sample_id") != sample_id:
            continue
        if sample_id:
            target_entry_seen = True
        sample_dir = _entry_sample_dir(entry, batch_path)
        packet_md = sample_dir / LATEST_PACKET_MD
        packet_json = sample_dir / LATEST_PACKET_JSON
        output_path = sample_dir / PER_SAMPLE_GPT_OUTPUT_FILE
        if not packet_md.exists() or not packet_json.exists():
            pre_items.append(
                _failed_or_skipped_from_entry(
                    entry,
                    action="failed",
                    reason="sample packet directory missing latest_review_packet.md/json",
                    failed_stage="packet_load",
                )
            )
            continue
        if not output_path.exists():
            pre_items.append(
                _failed_or_skipped_from_entry(
                    entry,
                    action="skipped",
                    reason="gpt_review_output.md not found",
                    failed_stage="input_scan",
                )
            )
            continue
        found_count += 1
        output_text = _read_review_text(output_path)
        stripped_output = output_text.strip()
        if (
            not stripped_output
            or stripped_output == GPT_REVIEW_OUTPUT_PLACEHOLDER.strip()
            or stripped_output == PER_SAMPLE_GPT_OUTPUT_PLACEHOLDER_TEXT
        ):
            pre_items.append(
                _failed_or_skipped_from_entry(
                    entry,
                    action="skipped",
                    reason="gpt_review_output.md is empty or still contains only the placeholder",
                    failed_stage="input_scan",
                )
            )
            continue
        parsed = parse_gpt_markdown_output(output_path)
        if len(parsed) != 1:
            pre_items.append(
                _failed_or_skipped_from_entry(
                    entry,
                    action="failed",
                    reason=f"expected exactly one Review UI output block, found {len(parsed)}",
                    failed_stage="markdown_parse",
                )
            )
            continue
        parsed_count += 1
        parsed[0]["_source_file"] = str(output_path)
        outputs.append(parsed[0])
    if sample_id and not target_entry_seen:
        pre_items.append(
            {
                "masked_sample_label": sample_id,
                "sample_id": sample_id,
                "gold_stage": "",
                "action": "failed",
                "fail_reason": "sample_id not found in batch_manifest",
                "failed_reason": "sample_id not found in batch_manifest",
                "failed_stage": "input_scan",
                "draft_save": None,
                "status_save": None,
                "validation": None,
                "formal_diff": None,
                "dry_run": None,
                "writeback": None,
                "backup": None,
                "writeback_log": None,
            }
        )

    parsed_jsonl_path = batch_path / "per_sample_gpt_review_outputs.parsed.jsonl"
    _write_jsonl(parsed_jsonl_path, outputs)
    applied_items = _apply_outputs(
        workbench_dir=workbench_dir,
        batch_dir=batch_path,
        output_rows=outputs,
        write=write,
        confirm_batch_writeback=confirm_batch_writeback,
        duplicate_context="per-sample gpt_review_output.md files",
    )
    return pre_items + applied_items, {
        "found_gpt_review_output_count": found_count,
        "parsed_gpt_output_count": parsed_count,
        "parsed_gpt_output_jsonl": str(parsed_jsonl_path),
        "per_sample_gpt_output_glob": str(batch_path / "sample_m_*" / PER_SAMPLE_GPT_OUTPUT_FILE),
        "target_sample_id": sample_id or "",
    }


def _jsonable_save_result(result: dict[str, Any] | None) -> dict[str, Any] | None:
    if result is None:
        return None
    converted = copy.deepcopy(result)
    if isinstance(converted.get("paths"), dict):
        converted["paths"] = {key: str(value) for key, value in converted["paths"].items()}
    return converted


def _summarize_items(items: list[dict[str, Any]]) -> dict[str, int]:
    return {
        "input_sample_count": sum(1 for item in items if item.get("action") != "skipped"),
        "total_record_count": len(items),
        "passed_sample_count": sum(
            1 for item in items if item.get("action") in {"packet_exported", "dry_run_ok", "written_back", "strict_noop"}
        ),
        "skipped_sample_count": sum(1 for item in items if item.get("action") == "skipped"),
        "written_back_count": sum(1 for item in items if item.get("action") == "written_back"),
        "strict_noop_count": sum(1 for item in items if item.get("action") == "strict_noop"),
        "failed_count": sum(1 for item in items if item.get("action") == "failed"),
    }


def _report_prefix_for_mode(mode: str) -> str:
    if "apply_per_sample_gpt_outputs" in mode:
        return "p6_26_per_sample_gpt_batch_writeback"
    return "p6_26_batch_review"


def write_reports(
    *,
    ts: str,
    batch_dir: Path | None,
    mode: str,
    items: list[dict[str, Any]],
    extra: dict[str, Any] | None = None,
) -> dict[str, Path]:
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    summary = _summarize_items(items)
    report = {
        "report": "P6.26 batch review",
        "batch_review_schema_version": BATCH_REVIEW_SCHEMA_VERSION,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "mode": mode,
        "batch_dir": str(batch_dir) if batch_dir else "",
        "gpt_batch_input_path": str(batch_dir / GPT_BATCH_INPUT_FILE)
        if batch_dir and (batch_dir / GPT_BATCH_INPUT_FILE).exists()
        else "",
        "gpt_markdown_output_path": str(batch_dir / GPT_MARKDOWN_OUTPUT_FILE)
        if batch_dir and (batch_dir / GPT_MARKDOWN_OUTPUT_FILE).exists()
        else "",
        "found_gpt_review_output_count": 0,
        **summary,
        "items": items,
        "protected_scope_confirmation": _protected_scope_confirmation(),
    }
    if extra:
        report.update(extra)
    report.setdefault("parsed_gpt_output_count", 0)
    prefix = _report_prefix_for_mode(mode)
    json_path = REPORT_DIR / f"{prefix}_{ts}.json"
    md_path = REPORT_DIR / f"{prefix}_{ts}.md"
    write_json(json_path, report)
    md_path.write_text(_render_report_markdown(report), encoding="utf-8")
    return {"json": json_path, "markdown": md_path}


def _render_report_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# P6.26 Batch Review",
        "",
        f"- mode: `{report.get('mode', '')}`",
        f"- batch_dir: `{report.get('batch_dir', '')}`",
        f"- gpt_batch_input.md: `{report.get('gpt_batch_input_path', '')}`",
        f"- batch_gpt_review_output.md: `{report.get('gpt_markdown_output_path', '')}`",
        f"- input sample count: `{report.get('input_sample_count', 0)}`",
        f"- found gpt_review_output.md count: `{report.get('found_gpt_review_output_count', 0)}`",
        f"- parsed GPT output count: `{report.get('parsed_gpt_output_count', 0)}`",
        f"- total record count: `{report.get('total_record_count', 0)}`",
        f"- passed sample count: `{report.get('passed_sample_count', 0)}`",
        f"- skipped sample count: `{report.get('skipped_sample_count', 0)}`",
        f"- written_back count: `{report.get('written_back_count', 0)}`",
        f"- strict_noop count: `{report.get('strict_noop_count', 0)}`",
        f"- failed count: `{report.get('failed_count', 0)}`",
        "",
        "## Samples",
        "",
        "| masked_sample_label | sample_id | gold_stage | action | fail_reason |",
        "| --- | --- | --- | --- | --- |",
    ]
    for item in report.get("items", []):
        lines.append(
            "| {label} | {sample} | {stage} | {action} | {reason} |".format(
                label=_md_cell(item.get("masked_sample_label", "")),
                sample=_md_cell(item.get("sample_id", "")),
                stage=_md_cell(item.get("gold_stage", "")),
                action=_md_cell(item.get("action", "")),
                reason=_md_cell(item.get("failed_reason", item.get("fail_reason", ""))),
            )
        )
    lines.extend(["", "## Protected Scope", ""])
    for key, value in report.get("protected_scope_confirmation", {}).items():
        lines.append(f"- {key}: `{value}`")
    lines.extend(["", "## Artifacts", ""])
    for item in report.get("items", []):
        if item.get("draft_save") or item.get("validation") or item.get("formal_diff") or item.get("dry_run") or item.get("writeback"):
            lines.extend(
                [
                    f"### {item.get('masked_sample_label', '')}",
                    "",
                    "```json",
                    json.dumps(
                        {
                            "draft_save": item.get("draft_save"),
                            "status_save": item.get("status_save"),
                            "validation": _compact_validation(item.get("validation")),
                            "formal_diff": item.get("formal_diff"),
                            "dry_run": _compact_writeback(item.get("dry_run")),
                            "writeback": _compact_writeback(item.get("writeback")),
                            "backup": item.get("backup"),
                            "writeback_log": item.get("writeback_log"),
                        },
                        ensure_ascii=False,
                        indent=2,
                    ),
                    "```",
                    "",
                ]
            )
    return "\n".join(lines) + "\n"


def _compact_validation(validation: Any) -> Any:
    if not isinstance(validation, dict):
        return validation
    return {
        "valid": validation.get("valid"),
        "errors": validation.get("errors", []),
        "warnings": validation.get("warnings", []),
        "checks": validation.get("checks", {}),
    }


def _compact_writeback(value: Any) -> Any:
    if not isinstance(value, dict):
        return value
    keys = [
        "ok",
        "dry_run",
        "would_write",
        "changed_fields",
        "changed_line_count",
        "changed_sample_count",
        "target_final_candidate_gold_path",
        "backup_path",
        "writeback_log_path",
        "strict_noop",
        "formal_fields_equal",
        "real_writeback_executed",
        "reason",
        "errors",
    ]
    return {key: value.get(key) for key in keys if key in value}


def _md_cell(value: Any) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ").strip()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workbench-dir", default=DEFAULT_WORKBENCH_DIR)
    parser.add_argument("--select-unreviewed", action="store_true")
    parser.add_argument("--select-not-written-back", action="store_true")
    parser.add_argument("--select-all-remaining", action="store_true")
    parser.add_argument("--export-all-remaining", action="store_true")
    parser.add_argument("--expected-remaining-count", type=int)
    parser.add_argument("--priority")
    parser.add_argument("--limit", type=int)
    parser.add_argument("--batch-size", type=int)
    parser.add_argument("--sample-list")
    parser.add_argument("--force-include-sample", action="append", default=[])
    parser.add_argument("--include-reviewed", action="store_true")
    parser.add_argument("--include-written-back", action="store_true")
    parser.add_argument("--export-packets", action="store_true")
    parser.add_argument("--export-gpt-batch-input", action="store_true")
    parser.add_argument("--stage-balanced", action="store_true")
    parser.add_argument("--target-per-stage", type=int, default=3)
    parser.add_argument("--batch-dir")
    parser.add_argument("--apply-gpt-jsonl", action="store_true")
    parser.add_argument("--apply-gpt-markdown", action="store_true")
    parser.add_argument("--apply-per-sample-gpt-outputs", action="store_true")
    parser.add_argument("--sample-id")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--confirm-batch-writeback", action="store_true")
    args = parser.parse_args()

    if args.write and args.dry_run:
        parser.error("--write and --dry-run are mutually exclusive")
    if args.confirm_batch_writeback and not args.write:
        parser.error("--confirm-batch-writeback requires --write")
    if args.write and not args.confirm_batch_writeback:
        parser.error("--write requires --confirm-batch-writeback for batch writeback")
    if args.export_gpt_batch_input and not args.export_packets:
        parser.error("--export-gpt-batch-input requires --export-packets")
    if args.stage_balanced and not args.export_packets:
        parser.error("--stage-balanced requires --export-packets")
    if args.target_per_stage < 1:
        parser.error("--target-per-stage must be >= 1")
    if args.batch_size is not None and args.batch_size < 1:
        parser.error("--batch-size must be >= 1")
    apply_modes = [
        args.apply_gpt_jsonl,
        args.apply_gpt_markdown,
        args.apply_per_sample_gpt_outputs,
    ]
    if sum(1 for enabled in apply_modes if enabled) > 1:
        parser.error(
            "--apply-gpt-jsonl, --apply-gpt-markdown, and "
            "--apply-per-sample-gpt-outputs are mutually exclusive"
        )
    if not args.export_packets and not any(apply_modes):
        parser.error(
            "one of --export-packets, --apply-gpt-jsonl, --apply-gpt-markdown, "
            "or --apply-per-sample-gpt-outputs is required"
        )
    if args.sample_id and not args.apply_per_sample_gpt_outputs:
        parser.error("--sample-id is only supported with --apply-per-sample-gpt-outputs")

    ts = _timestamp()
    all_items: list[dict[str, Any]] = []
    batch_dir: Path | None = Path(args.batch_dir) if args.batch_dir else None
    mode_parts = []

    if args.export_packets:
        bundle = load_workbench(args.workbench_dir)
        if args.include_reviewed or args.include_written_back:
            parser.error("--include-reviewed/--include-written-back are not supported for packet export in this guarded flow")
        selection_mode = "priority"
        selection_meta: dict[str, Any] = {}
        if args.stage_balanced:
            if args.force_include_sample:
                parser.error("--force-include-sample is not supported with --stage-balanced")
            if args.select_all_remaining or args.export_all_remaining:
                parser.error("--select-all-remaining/--export-all-remaining is not supported with --stage-balanced")
            selected, skipped, selection_reasons, selection_meta = select_stage_balanced_rows_for_export(
                bundle=bundle,
                target_per_stage=args.target_per_stage,
                limit=args.limit,
                sample_list_path=args.sample_list,
            )
            selection_mode = STAGE_BALANCED_PILOT12_MODE
        elif args.select_all_remaining or args.export_all_remaining:
            if args.priority:
                parser.error("--priority is not supported with --select-all-remaining/--export-all-remaining")
            if args.force_include_sample:
                parser.error("--force-include-sample is not supported with --select-all-remaining/--export-all-remaining")
            selected, skipped, selection_reasons, selection_meta = select_all_remaining_rows_for_export(
                bundle=bundle,
                limit=args.limit,
                sample_list_path=args.sample_list,
            )
            selection_mode = EXPORT_ALL_REMAINING_SELECTION_MODE if args.export_all_remaining else "all_remaining"
        else:
            selected, skipped, selection_reasons = select_rows_for_export(
                bundle=bundle,
                priority=args.priority,
                limit=args.limit,
                sample_list_path=args.sample_list,
                force_include_samples=args.force_include_sample,
            )
        if args.select_not_written_back:
            selection_meta["writeback_status_filter"] = "writeback_status != written_back"
        if args.select_unreviewed:
            selection_meta["review_status_filter"] = "review_status != reviewed"
        if args.expected_remaining_count is not None:
            selection_meta["expected_remaining_count"] = args.expected_remaining_count
        if any(item.get("forced_include") and item.get("fail_reason") == "force_include_already_written_back" for item in skipped):
            labels = [item.get("masked_sample_label", "") for item in skipped if item.get("forced_include") and item.get("fail_reason") == "force_include_already_written_back"]
            parser.error(f"forced include sample already written_back: {', '.join(labels)}")
        if args.export_all_remaining:
            batch_size = args.batch_size or 20
            chunks = _chunk_rows(selected, batch_size)
            total_remaining = int(
                selection_meta.get(
                    "total_remaining_eligible_before_export",
                    selection_meta.get("remaining_candidate_count_before_limit", len(selected)),
                )
                or 0
            )
            created_batch_dirs: list[Path] = []
            exported_samples_for_manifest: list[dict[str, Any]] = []
            exported_count = 0
            for index, chunk in enumerate(chunks, start=1):
                part_batch_id = f"batch_{ts}_part{index:02d}"
                remaining_after_this_batch = max(total_remaining - exported_count - len(chunk), 0)
                part_dir, exported_items = export_packets(
                    workbench_dir=args.workbench_dir,
                    rows=chunk,
                    skipped=[],
                    selection_reasons=selection_reasons,
                    ts=ts,
                    batch_id=part_batch_id,
                    batch_index=index,
                    batch_count=len(chunks),
                    batch_size=batch_size,
                    is_final_partial_batch=(index == len(chunks) and len(chunk) < batch_size),
                    remaining_eligible_after_this_batch=remaining_after_this_batch,
                    priority=args.priority,
                    selection_mode=EXPORT_ALL_REMAINING_SELECTION_MODE,
                    selection_meta=selection_meta,
                    export_gpt_batch_input=args.export_gpt_batch_input,
                )
                batch_dir = part_dir
                created_batch_dirs.append(part_dir)
                all_items.extend(exported_items)
                exported_samples_for_manifest.extend(exported_items)
                exported_count += len(chunk)
            remaining_after_export = max(total_remaining - exported_count, 0)
            export_all_manifest_path = write_export_all_remaining_manifest(
                workbench_dir=args.workbench_dir,
                ts=ts,
                batch_size=batch_size,
                selection_meta=selection_meta,
                created_batch_dirs=created_batch_dirs,
                exported_samples=exported_samples_for_manifest,
                skipped=skipped,
                remaining_eligible_after_export=remaining_after_export,
            )
            all_items.extend(skipped)
            report_extra = {
                "export_all_remaining_manifest": str(export_all_manifest_path),
                "created_batch_dirs": [str(path) for path in created_batch_dirs],
                "created_batch_count": len(created_batch_dirs),
                "batch_size": batch_size,
                "remaining_eligible_after_export": remaining_after_export,
            }
        else:
            batch_dir, exported_items = export_packets(
                workbench_dir=args.workbench_dir,
                rows=selected,
                skipped=skipped,
                selection_reasons=selection_reasons,
                ts=ts,
                priority=args.priority,
                selection_mode=selection_mode,
                selection_meta=selection_meta,
                export_gpt_batch_input=args.export_gpt_batch_input,
            )
            all_items.extend(exported_items)
            all_items.extend(skipped)
            report_extra = {}
        mode_parts.append("export_packets")
        if args.stage_balanced:
            mode_parts.append(STAGE_BALANCED_PILOT12_MODE)
        if args.export_all_remaining:
            mode_parts.append(EXPORT_ALL_REMAINING_SELECTION_MODE)
        if args.export_gpt_batch_input:
            mode_parts.append("export_gpt_batch_input")

    if args.apply_gpt_jsonl:
        if batch_dir is None:
            parser.error("--batch-dir is required with --apply-gpt-jsonl unless exporting in same run")
        apply_items = apply_gpt_jsonl(
            workbench_dir=args.workbench_dir,
            batch_dir=batch_dir,
            write=args.write,
            confirm_batch_writeback=args.confirm_batch_writeback,
        )
        all_items.extend(apply_items)
        mode_parts.append("apply_gpt_jsonl_write" if args.write else "apply_gpt_jsonl_dry_run")

    report_extra = {
        **(report_extra if "report_extra" in locals() else {}),
        "write_requested": bool(args.write),
        "confirm_batch_writeback": bool(args.confirm_batch_writeback),
    }
    if args.apply_gpt_markdown:
        if batch_dir is None:
            parser.error("--batch-dir is required with --apply-gpt-markdown unless exporting in same run")
        apply_items, markdown_extra = apply_gpt_markdown(
            workbench_dir=args.workbench_dir,
            batch_dir=batch_dir,
            write=args.write,
            confirm_batch_writeback=args.confirm_batch_writeback,
        )
        all_items.extend(apply_items)
        report_extra.update(markdown_extra)
        mode_parts.append("apply_gpt_markdown_write" if args.write else "apply_gpt_markdown_dry_run")

    if args.apply_per_sample_gpt_outputs:
        if batch_dir is None:
            parser.error("--batch-dir is required with --apply-per-sample-gpt-outputs")
        apply_items, per_sample_extra = apply_per_sample_gpt_outputs(
            workbench_dir=args.workbench_dir,
            batch_dir=batch_dir,
            write=args.write,
            confirm_batch_writeback=args.confirm_batch_writeback,
            sample_id=args.sample_id,
        )
        all_items.extend(apply_items)
        report_extra.update(per_sample_extra)
        mode_parts.append(
            "apply_per_sample_gpt_outputs_write"
            if args.write
            else "apply_per_sample_gpt_outputs_dry_run"
        )

    report_paths = write_reports(
        ts=ts,
        batch_dir=batch_dir,
        mode="+".join(mode_parts),
        items=all_items,
        extra=report_extra,
    )
    result = {
        "ok": not any(item.get("action") == "failed" for item in all_items),
        "batch_dir": str(batch_dir) if batch_dir else "",
        "report_json": str(report_paths["json"]),
        "report_markdown": str(report_paths["markdown"]),
        **_summarize_items(all_items),
    }
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

