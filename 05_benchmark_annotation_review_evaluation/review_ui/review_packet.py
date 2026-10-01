"""Blind-friendly review packet export for Codex-assisted manual review."""

from __future__ import annotations

import argparse
import copy
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from data_loader import DEFAULT_WORKBENCH_DIR, get_sample_detail, load_workbench
except ImportError:  # pragma: no cover
    from .data_loader import DEFAULT_WORKBENCH_DIR, get_sample_detail, load_workbench


PACKET_SCHEMA_VERSION = "codex_review_packet.v0.1"
REVIEW_PACKET_DIR = "ui_drafts/review_packets"
REVIEW_CONSTRAINTS = [
    "Use only visible audit / applog / traffic evidence as primary reasoning support.",
    "Do not use CVE ID, scenario name, lab source, sample_id, run_dir, or source path as stage reasoning evidence.",
    "Treat gold_stage as fixed for EWVAA candidate review; do not relabel the stage.",
    "Decide whether the candidate reasoning chain is sufficiently grounded in the evidence.",
    "If evidence is weak, use evidence-limited wording in formal draft claims and place workflow conclusions in review decision fields.",
    "Do not recommend clean_final unless explicitly supported and separately human-approved.",
    "Do not recommend canonical gold overwrite.",
]
FORMAL_DRAFT_REVIEW_DECISION_BOUNDARY = {
    "formal_draft_layer": (
        "The four draft claims are formal reasoning-chain text. They may later be written back to "
        "`gold_reasoning_chain`, so they must only describe visible evidence, observable behavior, "
        "evidence-supported stage reasoning, and evidence limitations."
    ),
    "formal_draft_claim_fields": [
        "gold_reasoning_chain claims",
        "auxiliary_vulnerability_note.claim",
    ],
    "forbidden_formal_draft_terms": [
        "manual review",
        "candidate-with-manual-review",
        "promotion",
        "no promotion",
        "clean final",
        "clean_final",
        "canonical gold",
        "writeback",
        "human_verified",
        "L1",
        "L2",
        "L3",
        "L4",
    ],
    "weak_evidence_wording": [
        "weak evidence support",
        "evidence-limited boundary",
        "result closure is not confirmed",
        "durable artifact is not visible",
    ],
    "review_decision_layer": (
        "Workflow conclusions should appear only in reviewer_notes, promotion_decision, "
        "and Human Review Status fields."
    ),
    "review_decision_fields": [
        "reviewer_decision",
        "reviewer_notes",
        "promotion_decision",
        "human_review_status",
    ],
    "allowed_review_decision_terms": [
        "candidate-with-manual-review",
        "no promotion",
        "clean_final_allowed=no",
        "canonical_gold_allowed=no",
    ],
}
DIAGNOSTIC_FIELDS_NOTICE = (
    "Diagnostic fields such as weighted_verdict, human_review_priority, promotion_blocker, "
    "and needs_later_patch are review-control metadata. They are not evidence and must not "
    "be used as strict reasoning evidence."
)
APPLOG_MARKDOWN_NOTICE = (
    "Markdown displays sanitized applog summaries. Full strict_blind_evidence remains in the "
    "JSON packet for traceability; authorization, cookie, email, and hash-like values are "
    "redacted from Markdown display."
)
RECOMMENDED_REVIEW_QUESTIONS = [
    "Are the four candidate reasoning steps grounded in visible audit / applog / traffic evidence?",
    "Do the cited seq / edge references support the subjects, actions, objects, and temporal links claimed?",
    "Does the chain avoid using CVE IDs, scenario names, lab source, sample_id, run_dir, or source path as reasoning evidence?",
    "Does the chain respect gold_stage as fixed without relabeling the sample?",
    "Are stage-boundary claims too strong for the visible evidence?",
    "Should the human reviewer revise the formal draft wording for evidence grounding?",
    "Do formal draft claims avoid workflow terms while keeping review conclusions in decision fields?",
    "Should any no-promotion or clean-final decision be recorded only in reviewer_notes, promotion_decision, or Human Review Status?",
]
TRACEABILITY_NOTICE = (
    "Traceability fields are for locating the source sample only. They are "
    "not_for_reasoning and must not be used as stage reasoning evidence."
)
JWT_TOKEN_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")
LONG_TOKEN_RE = re.compile(r"\b[A-Za-z0-9_-]{80,}\b")
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
AUTH_BEARER_RE = re.compile(
    r"(?i)(\bauthorization\b\s*[:=]\s*['\"]?\s*Bearer\s+)([^,'\"\s;}]+)"
)
COOKIE_QUOTED_RE = re.compile(r"(?i)(\bcookie\b\s*[:=]\s*)(['\"])(.*?)(\2)")
COOKIE_UNQUOTED_RE = re.compile(r"(?i)(\bcookie\b\s*[:=]\s*)([^,;}\s]+)")
TOKEN_PARAM_RE = re.compile(r"(?i)(\btoken=)([^;,'\"\s}]+)")
PASSWORD_FIELD_RE = re.compile(
    r"(?i)(\b(?:password|passwd|pwd)(?:[_ -]?(?:hash|digest))?\b\s*[:=]\s*['\"]?)([^,'\"\s}\]]+)"
)


def mask_internal_identifiers(value: Any) -> Any:
    """Mask strong priors and internal identifiers in packet review content."""
    if isinstance(value, dict):
        return {k: mask_internal_identifiers(v) for k, v in value.items()}
    if isinstance(value, list):
        return [mask_internal_identifiers(v) for v in value]
    if not isinstance(value, str):
        return value
    text = value
    text = re.sub(
        r"\b[A-Za-z0-9_.-]+__[A-Za-z0-9_.-]+__CVE-\d{4}-\d+__window_\d+_\d+\b",
        "[INTERNAL-SAMPLE-ID-MASKED]",
        text,
        flags=re.IGNORECASE,
    )
    text = re.sub(
        r"\bvulhub[/_][A-Za-z0-9_.-]+[/_]CVE-\d{4}-\d+\b",
        "[SCENARIO-PATH-MASKED]",
        text,
        flags=re.IGNORECASE,
    )
    text = re.sub(r"CVE-\d{4}-\d+", "[CVE-ID-MASKED]", text, flags=re.IGNORECASE)
    text = re.sub(r"\bvulhub\b", "[LAB-SOURCE-MASKED]", text, flags=re.IGNORECASE)
    text = re.sub(r"juice-shop", "[SCENARIO-MASKED]", text, flags=re.IGNORECASE)
    text = re.sub(r"sandworm", "[SCENARIO-MASKED]", text, flags=re.IGNORECASE)
    return text


def safe_packet_stem(row: dict[str, Any]) -> str:
    label = row.get("masked_sample_id") or row.get("sample_id") or "unknown_sample"
    label = str(mask_internal_identifiers(label))
    safe = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in label)
    return safe.strip("._-") or "unknown_sample"


def _copy(value: Any) -> Any:
    return copy.deepcopy(value)


def _redact_sensitive_text(value: Any) -> str:
    text = "" if value is None else str(value)
    text = JWT_TOKEN_RE.sub("<REDACTED_TOKEN>", text)
    text = TOKEN_PARAM_RE.sub(r"\1<REDACTED_TOKEN>", text)
    text = AUTH_BEARER_RE.sub(r"\1<REDACTED_TOKEN>", text)
    text = COOKIE_QUOTED_RE.sub(r"\1\2<REDACTED_COOKIE>\4", text)
    text = COOKIE_UNQUOTED_RE.sub(r"\1<REDACTED_COOKIE>", text)
    text = EMAIL_RE.sub("<REDACTED_EMAIL>", text)
    text = PASSWORD_FIELD_RE.sub(r"\1<REDACTED_HASH>", text)
    text = LONG_TOKEN_RE.sub("<REDACTED_TOKEN>", text)
    return text


def _sanitize_for_markdown_display(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _sanitize_for_markdown_display(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_sanitize_for_markdown_display(v) for v in value]
    if isinstance(value, str):
        return _redact_sensitive_text(value)
    return value


def _extract_message_field(message: str, field_name: str) -> str:
    field_pattern = re.escape(field_name)
    patterns = [
        rf"(?i)(?:^|[\s{{,])['\"]?{field_pattern}['\"]?\s*:\s*['\"]([^'\"]+)['\"]",
        rf"(?i)(?:^|[\s{{,])['\"]?{field_pattern}['\"]?\s*:\s*([^,}}\s]+)",
    ]
    for pattern in patterns:
        match = re.search(pattern, message)
        if match:
            return _redact_sensitive_text(match.group(1).strip())
    return ""


def _collapse_text(text: str, max_len: int = 700) -> str:
    collapsed = re.sub(r"\s+", " ", text).strip()
    if len(collapsed) <= max_len:
        return collapsed
    return collapsed[: max_len - 3].rstrip() + "..."


def _sanitized_applog_message(event: dict[str, Any]) -> str:
    raw_message = str(event.get("message", "") or "")
    method = event.get("method") or _extract_message_field(raw_message, "method")
    url = event.get("url") or _extract_message_field(raw_message, "url")
    host = event.get("host") or _extract_message_field(raw_message, "host")
    content_length = (
        event.get("content_length")
        or event.get("content-length")
        or _extract_message_field(raw_message, "content-length")
        or _extract_message_field(raw_message, "content_length")
        or _extract_message_field(raw_message, "contentLength")
    )

    if method or url:
        headers = []
        if host:
            headers.append(f"host: {host!r}")
        if content_length:
            headers.append(f"'content-length': {str(content_length)!r}")
        if re.search(r"(?i)\bauthorization\b|Bearer\s+", raw_message):
            headers.append("authorization: 'Bearer <REDACTED_TOKEN>'")
        if re.search(r"(?i)\bcookie\b|\btoken=", raw_message):
            headers.append("cookie: '<REDACTED_COOKIE>'")
        if EMAIL_RE.search(raw_message):
            headers.append("email: '<REDACTED_EMAIL>'")
        if PASSWORD_FIELD_RE.search(raw_message):
            headers.append("password_hash: '<REDACTED_HASH>'")
        header_text = ", ".join(headers)
        if header_text:
            header_text = f", headers: {{ {header_text} }}"
        return f"{{ method: {str(method)!r}, url: {str(url)!r}{header_text} }}"

    return _collapse_text(_redact_sensitive_text(raw_message))


def _applog_event_summary(event: dict[str, Any]) -> dict[str, Any]:
    raw_message = str(event.get("message", "") or "")
    attach_basis = event.get("attach_basis", {}) if isinstance(event.get("attach_basis"), dict) else {}
    return {
        "timestamp": event.get("timestamp"),
        "semantic_type": event.get("semantic_type", ""),
        "method": event.get("method") or _extract_message_field(raw_message, "method"),
        "url": event.get("url") or _extract_message_field(raw_message, "url"),
        "host": event.get("host") or _extract_message_field(raw_message, "host"),
        "content_length": (
            event.get("content_length")
            or event.get("content-length")
            or _extract_message_field(raw_message, "content-length")
            or _extract_message_field(raw_message, "content_length")
            or _extract_message_field(raw_message, "contentLength")
        ),
        "attach_strength": event.get("attach_strength", ""),
        "attach_reason": event.get("attach_reason", ""),
        "attach_to_backbone_edge_id": event.get("attach_to_backbone_edge_id", ""),
        "backbone_seq": attach_basis.get("backbone_seq"),
        "sec_delta": attach_basis.get("sec_delta"),
        "thread_aligned": attach_basis.get("thread_aligned"),
        "proc_pid_matched": attach_basis.get("proc_pid_matched"),
        "sanitized_message": _sanitized_applog_message(event),
    }


def _traffic_event_summary(event: dict[str, Any]) -> dict[str, Any]:
    keys = [
        "timestamp",
        "semantic_type",
        "method",
        "url",
        "host",
        "src",
        "dst",
        "src_ip",
        "dst_ip",
        "src_port",
        "dst_port",
        "protocol",
    ]
    return {key: _sanitize_for_markdown_display(event.get(key)) for key in keys if event.get(key) is not None}


def _strict_blind_evidence_sanitized_summary(strict_evidence: dict[str, Any]) -> dict[str, Any]:
    summary = {
        "source": strict_evidence.get("source", ""),
        "available": strict_evidence.get("available", False),
        "window": _copy(strict_evidence.get("window", {})),
        "spine_selection": strict_evidence.get("spine_selection", ""),
        "spine": [],
    }
    spine = strict_evidence.get("spine", []) if isinstance(strict_evidence, dict) else []
    for item in spine if isinstance(spine, list) else []:
        multisource = item.get("multisource_context", {}) if isinstance(item, dict) else {}
        multisource = multisource if isinstance(multisource, dict) else {}
        applog = multisource.get("applog", [])
        traffic = multisource.get("traffic", [])
        applog = applog if isinstance(applog, list) else []
        traffic = traffic if isinstance(traffic, list) else []
        summary["spine"].append(
            {
                "seq": item.get("seq"),
                "edge_id": item.get("edge_id", ""),
                "relation": item.get("relation", ""),
                "subject": item.get("subject", ""),
                "object": item.get("object", ""),
                "audit_context_count": len(item.get("audit_context", []) or []),
                "applog_available": bool(applog),
                "applog_count": len(applog),
                "traffic_available": bool(traffic),
                "traffic_count": len(traffic),
                "applog_events": [_applog_event_summary(event) for event in applog if isinstance(event, dict)],
                "traffic_events": [_traffic_event_summary(event) for event in traffic[:10] if isinstance(event, dict)],
            }
        )
    return summary


def _collect_evidence_refs(candidate: dict[str, Any]) -> list[dict[str, Any]]:
    refs = []
    chain = candidate.get("gold_reasoning_chain", []) if isinstance(candidate, dict) else []
    for step in chain if isinstance(chain, list) else []:
        if not isinstance(step, dict):
            continue
        step_name = step.get("step", "")
        for ref in step.get("evidence_refs", []) or []:
            if isinstance(ref, dict):
                refs.append({"step": step_name, **ref})
            else:
                refs.append({"step": step_name, "ref": ref})
    return refs


def _evidence_ref_keys(ref: dict[str, Any]) -> set[tuple[str, Any]]:
    keys = set()
    if isinstance(ref, dict):
        if ref.get("seq") is not None:
            keys.add(("seq", ref.get("seq")))
        if ref.get("edge_id"):
            keys.add(("edge_id", ref.get("edge_id")))
    return keys


def _filter_spine_by_refs(spine: list[dict[str, Any]], refs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    wanted = set()
    for ref in refs:
        wanted.update(_evidence_ref_keys(ref))
    if not wanted:
        return []
    return [
        item
        for item in spine
        if ("seq", item.get("seq")) in wanted or ("edge_id", item.get("edge_id")) in wanted
    ]


def _classify_spine(spine: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    panels = {"primary": [], "audit": [], "applog": [], "traffic": []}
    for item in spine:
        panels["primary"].append(item)
        if item.get("audit_context"):
            panels["audit"].append(item)
        multisource = item.get("multisource_context", {})
        if isinstance(multisource, dict):
            if multisource.get("applog"):
                panels["applog"].append(item)
            if multisource.get("traffic"):
                panels["traffic"].append(item)
    return panels


def _prompt_spine(prompt_evidence: dict[str, Any]) -> list[dict[str, Any]]:
    prompt_input = prompt_evidence.get("prompt_input", {}) if isinstance(prompt_evidence, dict) else {}
    primary = prompt_input.get("primary_evidence", {}) if isinstance(prompt_input, dict) else {}
    spine = primary.get("spine", []) if isinstance(primary, dict) else []
    return spine if isinstance(spine, list) else []


def _scenario_hint_from_evidence(row: dict[str, Any]) -> str:
    strict_input = row.get("strict_blind_input", {})
    spine = strict_input.get("input", {}).get("spine", []) if isinstance(strict_input, dict) else []
    text = json.dumps(spine[:12], ensure_ascii=False).lower() if spine else ""
    if any(token in text for token in ["http", "api/", "url", "cookie", "authorization"]):
        if any(token in text for token in ["mysql", "postgres", "db", "database"]):
            return "database-backed web service"
        if any(token in text for token in ["admin", "login", "auth"]):
            return "admin interface access"
        return "web application request sequence"
    if any(token in text for token in ["file_write", "file:", "execve", "proc:"]):
        return "server-side process and file activity"
    if any(token in text for token in ["net_accept", "net_connect", "conn:"]):
        return "network-facing service interaction"
    return "general attack-chain evidence window"


def _strict_blind_evidence(row: dict[str, Any], refs: list[dict[str, Any]]) -> dict[str, Any]:
    strict_input = row.get("strict_blind_input", {})
    if isinstance(strict_input, dict) and strict_input:
        spine = strict_input.get("input", {}).get("spine", [])
        spine = spine if isinstance(spine, list) else []
        selected_spine = _filter_spine_by_refs(spine, refs) or spine[:20]
        return {
            "source": "strict_blind_model_input",
            "available": True,
            "strict_blind_sample_id": strict_input.get("sample_id"),
            "strict_blind_scenario_id": strict_input.get("scenario_id"),
            "window": _copy(strict_input.get("window", {})),
            "spine_selection": "candidate_evidence_refs_if_available_else_first_20",
            "spine": _copy(selected_spine),
            "panels": _classify_spine(selected_spine),
        }

    prompt_evidence = row.get("prompt_evidence", {})
    spine = _prompt_spine(prompt_evidence)
    selected_spine = _filter_spine_by_refs(spine, refs) or spine[:20]
    return {
        "source": "reviewer_prompt_evidence_fallback",
        "available": bool(selected_spine),
        "spine_selection": "candidate_evidence_refs_if_available_else_first_20",
        "spine": _copy(selected_spine),
        "panels": _classify_spine(selected_spine),
    }


def _diagnostic_info(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "p5_35_diagnostic": _copy(row.get("p5_35_diagnostic", {})),
        "p5_37_dry_run": _copy(row.get("p5_37_dry_run", {})),
        "p5_38_review_sheet": _copy(row.get("p5_38_review_sheet", {})),
        "manual_review": _copy(row.get("manual_review", {})),
        "weighted_case": _copy(row.get("weighted_case", {})),
        "structure_warnings": _copy(row.get("structure_warnings", [])),
    }


def _draft_for_review(row: dict[str, Any]) -> dict[str, Any]:
    draft = _copy(row.get("latest_draft") or {})
    if not isinstance(draft, dict) or not draft:
        return {}
    for field in ["sample_id", "source_run_dir", "source_final_candidate_gold_path"]:
        if field in draft:
            draft[field] = "[TRACEABILITY-FIELD-AVAILABLE-IN-TRACEABILITY]"
    draft["masked_sample_label"] = row.get("masked_sample_id") or "[INTERNAL-SAMPLE-ID-MASKED]"
    return draft


def _traceability(row: dict[str, Any], workbench_dir: str | Path) -> dict[str, Any]:
    index_row = row.get("candidate_index", {}) if isinstance(row.get("candidate_index"), dict) else {}
    return {
        "not_for_reasoning": True,
        "notice": TRACEABILITY_NOTICE,
        "workbench_dir": str(workbench_dir),
        "internal_sample_id": row.get("sample_id", ""),
        "internal_scenario_id": row.get("scenario_id", ""),
        "run_dir": str(row.get("run_dir", "")),
        "run_dir_path": row.get("run_dir_path", ""),
        "candidate_file": index_row.get("candidate_file", ""),
        "candidate_row_index": index_row.get("candidate_row_index"),
        "source_path": index_row.get("candidate_file", ""),
        "strict_blind_sample_index": _copy(row.get("strict_blind_sample_index", {})),
    }


def _fmt_md(value: Any) -> str:
    if value is None:
        return ""
    return str(value)


def _append_md_kv(lines: list[str], key: str, value: Any, indent: str = "  ") -> None:
    lines.append(f"{indent}- {key}: `{_fmt_md(value)}`")


def _render_strict_blind_evidence_markdown(packet: dict[str, Any]) -> list[str]:
    summary = packet.get("strict_blind_evidence_sanitized_summary", {})
    lines = [
        "",
        "## Strict Blind Evidence",
        "",
        str(packet.get("applog_markdown_notice", APPLOG_MARKDOWN_NOTICE)),
        "",
    ]
    _append_md_kv(lines, "source", summary.get("source", ""), "")
    _append_md_kv(lines, "available", summary.get("available", ""), "")
    _append_md_kv(lines, "spine_selection", summary.get("spine_selection", ""), "")
    if summary.get("window"):
        lines.extend(["", "Window:", ""])
        for key, value in summary.get("window", {}).items():
            _append_md_kv(lines, key, value)

    spine = summary.get("spine", [])
    for index, item in enumerate(spine if isinstance(spine, list) else [], start=1):
        lines.extend(["", f"### Evidence spine item {index}", ""])
        for key in [
            "seq",
            "edge_id",
            "relation",
            "subject",
            "object",
            "audit_context_count",
            "applog_available",
            "applog_count",
            "traffic_available",
            "traffic_count",
        ]:
            _append_md_kv(lines, key, item.get(key), "")

        applog_events = item.get("applog_events", [])
        lines.extend(["", "#### Applog evidence", ""])
        if not applog_events:
            lines.append("- none")
        for event_index, event in enumerate(applog_events if isinstance(applog_events, list) else [], start=1):
            lines.append(f"- applog event {event_index}:")
            for key in [
                "timestamp",
                "semantic_type",
                "method",
                "url",
                "host",
                "content_length",
                "attach_strength",
                "attach_reason",
                "attach_to_backbone_edge_id",
                "backbone_seq",
                "sec_delta",
            ]:
                _append_md_kv(lines, key, event.get(key), "  ")
            alignment = (
                f"thread_aligned={event.get('thread_aligned')}, "
                f"proc_pid_matched={event.get('proc_pid_matched')}"
            )
            _append_md_kv(lines, "alignment", alignment, "  ")
            _append_md_kv(lines, "sanitized_message", event.get("sanitized_message", ""), "  ")

        traffic_events = item.get("traffic_events", [])
        lines.extend(["", "#### Traffic evidence", ""])
        if not traffic_events:
            lines.append("- none")
        for traffic_index, event in enumerate(traffic_events if isinstance(traffic_events, list) else [], start=1):
            lines.append(f"- traffic event {traffic_index}: `{json.dumps(event, ensure_ascii=False)}`")
    return lines


def build_review_packet(row: dict[str, Any], workbench_dir: str | Path) -> dict[str, Any]:
    """Build a blind-friendly review packet without modifying source files."""
    candidate = row.get("candidate", {}) if isinstance(row.get("candidate"), dict) else {}
    refs = _collect_evidence_refs(candidate)
    strict_evidence = _strict_blind_evidence(row, refs)
    review_content = {
        "packet_schema_version": PACKET_SCHEMA_VERSION,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "display_mode": "Blind-friendly review mode",
        "masked_sample_label": row.get("masked_sample_id") or "[INTERNAL-SAMPLE-ID-MASKED]",
        "gold_stage": row.get("gold_stage", ""),
        "weighted_verdict": row.get("weighted_verdict", ""),
        "human_review_priority": row.get("human_review_priority", ""),
        "promotion_blocker": row.get("promotion_blocker", ""),
        "needs_later_patch": row.get("needs_later_patch", ""),
        "scenario_hint": _scenario_hint_from_evidence(row),
        "strict_blind_evidence": strict_evidence,
        "strict_blind_evidence_sanitized_summary": _strict_blind_evidence_sanitized_summary(strict_evidence),
        "applog_markdown_notice": APPLOG_MARKDOWN_NOTICE,
        "evidence_refs": refs,
        "original_candidate_four_steps": _copy(candidate.get("gold_reasoning_chain", [])),
        "auxiliary_vulnerability_note": _copy(candidate.get("auxiliary_vulnerability_note", {})),
        "diagnostic_info": _diagnostic_info(row),
        "current_draft_if_exists": _draft_for_review(row),
        "review_constraints": list(REVIEW_CONSTRAINTS),
        "formal_draft_review_decision_boundary": _copy(FORMAL_DRAFT_REVIEW_DECISION_BOUNDARY),
        "diagnostic_fields_notice": DIAGNOSTIC_FIELDS_NOTICE,
        "recommended_review_questions": list(RECOMMENDED_REVIEW_QUESTIONS),
        "write_scope": {
            "packet_export_only": True,
            "writes_only_to": REVIEW_PACKET_DIR,
            "does_not_update_draft": True,
            "does_not_update_final_candidate_gold": True,
            "does_not_update_candidate_index": True,
            "does_not_update_release_files": True,
            "does_not_update_canonical_gold": True,
            "does_not_promote": True,
        },
    }
    packet = mask_internal_identifiers(review_content)
    packet["traceability"] = _traceability(row, workbench_dir)
    return packet


def packet_paths(workbench_dir: str | Path, row: dict[str, Any]) -> dict[str, Path]:
    out_dir = Path(workbench_dir) / REVIEW_PACKET_DIR
    stem = safe_packet_stem(row)
    return {
        "dir": out_dir,
        "json": out_dir / f"{stem}.review_packet.json",
        "markdown": out_dir / f"{stem}.review_packet.md",
        "latest_json": out_dir / "latest_review_packet.json",
        "latest_markdown": out_dir / "latest_review_packet.md",
    }


def write_json(path: Path, obj: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def render_packet_markdown(packet: dict[str, Any]) -> str:
    """Render the packet as a compact Markdown artifact for manual review."""
    boundary = packet.get("formal_draft_review_decision_boundary", {})
    lines = [
        "# Codex-Assisted Review Packet",
        "",
        f"- packet_schema_version: `{packet.get('packet_schema_version', '')}`",
        f"- created_at: `{packet.get('created_at', '')}`",
        f"- display_mode: `{packet.get('display_mode', '')}`",
        f"- sample: `{packet.get('masked_sample_label', '')}`",
        f"- gold_stage: `{packet.get('gold_stage', '')}`",
        f"- weighted_verdict: `{packet.get('weighted_verdict', '')}`",
        f"- human_review_priority: `{packet.get('human_review_priority', '')}`",
        f"- promotion_blocker: `{packet.get('promotion_blocker', '')}`",
        f"- needs_later_patch: `{packet.get('needs_later_patch', '')}`",
        f"- scenario_hint: `{packet.get('scenario_hint', '')}`",
        "",
        "Traceability is included only in the JSON packet and is marked `not_for_reasoning`.",
        "",
        "## Review Constraints",
        "",
    ]
    lines.extend(f"- {item}" for item in packet.get("review_constraints", []))
    lines.extend(
        [
            "",
            "## Formal draft vs review decision boundary",
            "",
            str(boundary.get("formal_draft_layer", "")),
            "",
            "Formal draft claim fields:",
        ]
    )
    lines.extend(f"- {item}" for item in boundary.get("formal_draft_claim_fields", []))
    lines.extend(
        [
            "",
            "Do not put workflow or review-status terms in the four draft claims. Avoid terms such as:",
        ]
    )
    lines.extend(f"- {item}" for item in boundary.get("forbidden_formal_draft_terms", []))
    lines.extend(["", "If evidence is weak, the four draft claims should use evidence-based wording such as:"])
    lines.extend(f"- {item}" for item in boundary.get("weak_evidence_wording", []))
    lines.extend(
        [
            "",
            str(boundary.get("review_decision_layer", "")),
            "",
            "Review decision fields:",
        ]
    )
    lines.extend(f"- {item}" for item in boundary.get("review_decision_fields", []))
    lines.extend(["", "Review decision layer may use terms such as:"])
    lines.extend(f"- {item}" for item in boundary.get("allowed_review_decision_terms", []))
    lines.extend(["", str(packet.get("diagnostic_fields_notice", ""))])
    lines.extend(["", "## Recommended Review Questions", ""])
    lines.extend(f"- {item}" for item in packet.get("recommended_review_questions", []))
    lines.extend(_render_strict_blind_evidence_markdown(packet))
    sections = [
        ("Evidence Refs", packet.get("evidence_refs", [])),
        ("Original Candidate Four Steps", packet.get("original_candidate_four_steps", [])),
        ("Auxiliary Vulnerability Note", packet.get("auxiliary_vulnerability_note", {})),
        ("Diagnostic Info", packet.get("diagnostic_info", {})),
        ("Current Draft If Exists", packet.get("current_draft_if_exists", {})),
    ]
    for title, value in sections:
        lines.extend(
            [
                "",
                f"## {title}",
                "",
                "```json",
                json.dumps(_sanitize_for_markdown_display(value), ensure_ascii=False, indent=2),
                "```",
            ]
        )
    return "\n".join(lines) + "\n"


def export_review_packet(
    *,
    workbench_dir: str | Path,
    row: dict[str, Any],
    output_latest: bool = True,
) -> dict[str, Any]:
    """Write the current sample review packet under ui_drafts/review_packets."""
    packet = build_review_packet(row, workbench_dir)
    paths = packet_paths(workbench_dir, row)
    paths["dir"].mkdir(parents=True, exist_ok=True)
    markdown = render_packet_markdown(packet)
    write_json(paths["json"], packet)
    paths["markdown"].write_text(markdown, encoding="utf-8")
    if output_latest:
        write_json(paths["latest_json"], packet)
        paths["latest_markdown"].write_text(markdown, encoding="utf-8")
    return {
        "ok": True,
        "packet": packet,
        "paths": {key: str(value) for key, value in paths.items()},
        "output_latest": output_latest,
    }


def export_review_packet_for_sample(
    *,
    workbench_dir: str | Path,
    sample_id: str,
    output_latest: bool = True,
) -> dict[str, Any]:
    bundle = load_workbench(workbench_dir)
    row = get_sample_detail(bundle, sample_id)
    if row is None:
        raise ValueError(f"sample_id not found in workbench: {sample_id}")
    return export_review_packet(
        workbench_dir=workbench_dir,
        row=row,
        output_latest=output_latest,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workbench-dir", default=DEFAULT_WORKBENCH_DIR)
    parser.add_argument("--sample-id", required=True)
    parser.add_argument("--output-latest", action="store_true")
    args = parser.parse_args()
    result = export_review_packet_for_sample(
        workbench_dir=args.workbench_dir,
        sample_id=args.sample_id,
        output_latest=args.output_latest,
    )
    print(json.dumps({k: v for k, v in result.items() if k != "packet"}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
