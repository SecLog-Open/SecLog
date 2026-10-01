"""Streamlit entrypoint for the P6 EWVAA human review UI."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

try:
    import streamlit as st
except ImportError as exc:  # pragma: no cover - runtime environment dependent
    raise SystemExit(
        "Streamlit is required to launch the P6.3 review UI. "
        "Install Streamlit outside this draft-editing prototype, then rerun."
    ) from exc

from data_loader import (
    DEFAULT_WORKBENCH_DIR,
    draft_to_candidate_like,
    load_workbench,
    make_draft_from_original,
    preview_row_diff,
    reset_draft_from_original,
    save_draft,
    save_diff_preview,
    validate_row_draft,
)
from review_packet import export_review_packet
from review_status import (
    CANONICAL_GOLD_ALLOWED_VALUES,
    CLEAN_FINAL_ALLOWED_VALUES,
    DEFAULT_PROMOTION_DECISION,
    DEFAULT_REVIEWER_DECISION,
    REVIEW_STATUS_VALUES,
    WRITEBACK_STATUS_VALUES,
    YES_NO_VALUES,
    save_human_review_status,
)
from writeback import write_single_sample_draft_to_final_candidate


TABLE_COLUMNS = [
    "sample_id",
    "batch_id",
    "gold_stage",
    "weighted_verdict",
    "original_human_review_priority",
    "dry_run_level",
    "original_promotion_blocker",
    "original_needs_later_patch",
    "review_status",
    "writeback_status",
    "needs_later_patch_after_review",
    "promotion_blocker_after_review",
    "effective_review_priority",
    "after_review_status",
    "reviewed_at",
    "recommended_action",
]

FILTER_FIELDS = [
    "batch_id",
    "gold_stage",
    "weighted_verdict",
    "human_review_priority",
    "promotion_blocker",
    "needs_later_patch",
    "generic_template_risk",
]

AFTER_REVIEW_SORT_RANK = {
    "reviewed_needs_patch": 1,
    "reviewed_but_blocked": 2,
    "reviewed_pending_writeback_or_check": 3,
    "pending_review": 4,
    "reviewed_and_resolved": 7,
}

ORIGINAL_PRIORITY_SORT_RANK = {
    "high": 0,
    "medium": 1,
    "low": 2,
}

REVIEW_INFO_FIELDS = [
    "human_review_priority",
    "dry_run_level",
    "promotion_blocker",
    "promotion_blocker_reason",
    "needs_later_patch",
    "data_evidence_grounding",
    "attack_chain_relation_quality",
    "operator_analysis_fidelity",
    "stage_boundary_explanation",
    "generic_template_risk",
    "recommended_next_action",
]

FUTURE_EDIT_FIELDS = [
    "reviewer_decision",
    "reviewer_notes",
    "promotion_decision",
    "clean_final_allowed",
    "canonical_gold_allowed",
]

PRESET_FILTERS = {
    "All samples": {},
    "High-priority review": {"human_review_priority": "high"},
    "Promotion blockers": {"promotion_blocker": "yes"},
    "Needs later patch": {"needs_later_patch": "yes"},
    "Low-risk review candidates": {
        "human_review_priority": "low",
        "promotion_blocker": "no",
    },
}

BLIND_MODE = "Blind-friendly review mode"
TRACE_MODE = "Internal traceability mode"


def mask_internal_identifiers_for_display(value: Any) -> Any:
    """Mask strong internal/scenario identifiers for display only."""
    if isinstance(value, dict):
        return {k: mask_internal_identifiers_for_display(v) for k, v in value.items()}
    if isinstance(value, list):
        return [mask_internal_identifiers_for_display(v) for v in value]
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


def display_value(value: Any, display_mode: str) -> Any:
    if display_mode == BLIND_MODE:
        return mask_internal_identifiers_for_display(value)
    return value


def scenario_hint_from_evidence(row: dict[str, Any]) -> str:
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


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--workbench-dir", default=DEFAULT_WORKBENCH_DIR)
    args, _unknown = parser.parse_known_args()
    return args


@st.cache_data(show_spinner="Loading workbench data...")
def cached_load_workbench(workbench_dir: str):
    return load_workbench(workbench_dir)


def reload_workbench(workbench_dir: str):
    cached_load_workbench.clear()
    return cached_load_workbench(workbench_dir)


SAMPLE_SESSION_PREFIXES = (
    "draft",
    "human_review_status",
    "validation",
    "diff",
    "writeback_preview",
    "review_packet_export",
    "export_review_packet",
)


def clear_sample_session_state(sample_id: str) -> None:
    prefixes = tuple(
        f"{prefix}_{sample_id}"
        for prefix in SAMPLE_SESSION_PREFIXES
    )
    keys_to_delete = [
        key
        for key in list(st.session_state.keys())
        if any(key == prefix or key.startswith(f"{prefix}_") for prefix in prefixes)
    ]
    for key in keys_to_delete:
        del st.session_state[key]


def clear_workbench_reload_session_state(sample_id: str | None = None) -> None:
    if sample_id:
        clear_sample_session_state(sample_id)
        return
    prefixes = tuple(f"{prefix}_" for prefix in SAMPLE_SESSION_PREFIXES)
    for key in list(st.session_state.keys()):
        if key.startswith(prefixes):
            del st.session_state[key]


def reload_workbench_from_disk(workbench_dir: str, sample_id: str | None = None) -> None:
    clear_workbench_reload_session_state(sample_id)
    cached_load_workbench.clear()
    st.rerun()


def reload_sample_from_disk(workbench_dir: str, sample_id: str):
    clear_sample_session_state(sample_id)
    return reload_workbench(workbench_dir)


def stringify(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, indent=2)
    return str(value)


def as_options(rows: list[dict[str, Any]], field: str) -> list[str]:
    values = sorted({str(row.get(field, "")) for row in rows if row.get(field, "") != ""})
    return ["All"] + values


def default_filter_index(options: list[str], preset_value: str | None) -> int:
    if preset_value and preset_value in options:
        return options.index(preset_value)
    return 0


def option_index(options: list[str], current_value: str | None, default: int = 0) -> int:
    if current_value in options:
        return options.index(current_value)
    return default


def apply_filters(
    rows: list[dict[str, Any]],
    filters: dict[str, str],
    sample_search: str,
    *,
    hide_reviewed: bool = False,
    hide_reviewed_resolved: bool = False,
):
    filtered = rows
    if sample_search:
        needle = sample_search.lower()
        filtered = [
            row
            for row in filtered
            if needle in row.get("sample_id", "").lower()
            or needle in row.get("masked_sample_id", "").lower()
        ]
    for field, selected in filters.items():
        if selected != "All":
            filtered = [row for row in filtered if str(row.get(field, "")) == selected]
    if hide_reviewed:
        filtered = [row for row in filtered if row.get("review_status", "not_reviewed") != "reviewed"]
    if hide_reviewed_resolved:
        filtered = [
            row
            for row in filtered
            if row.get("after_review_status", "pending_review") != "reviewed_and_resolved"
        ]
    return filtered


def sort_review_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    def key(row: dict[str, Any]):
        after_status = row.get("after_review_status", "pending_review")
        priority = row.get("original_human_review_priority") or row.get("human_review_priority", "")
        if row.get("review_status", "not_reviewed") != "reviewed":
            status_rank = 0 if priority == "high" else AFTER_REVIEW_SORT_RANK["pending_review"]
            priority_rank = ORIGINAL_PRIORITY_SORT_RANK.get(str(priority), 9)
        else:
            status_rank = AFTER_REVIEW_SORT_RANK.get(str(after_status), 9)
            priority_rank = 9
        return (
            status_rank,
            priority_rank,
            row.get("batch_id", ""),
            row.get("sample_id", ""),
        )

    return sorted(rows, key=key)


def render_metric_row(row: dict[str, Any]) -> None:
    cols = st.columns(6)
    cols[0].metric("Gold Stage", stringify(row.get("gold_stage")))
    cols[1].metric("Weighted", stringify(row.get("weighted_verdict")))
    cols[2].metric("Original Priority", stringify(row.get("original_human_review_priority")))
    cols[3].metric("Effective Priority", stringify(row.get("effective_review_priority")))
    cols[4].metric("After Review", stringify(row.get("after_review_status")))
    cols[5].metric("Writeback", stringify(row.get("writeback_status")))


def render_workflow_guide() -> None:
    st.markdown("### A. Review Workflow Guide")
    st.info(
        "Human review workflow:\n"
        "1. Select: Choose a sample, prioritizing high priority / promotion blocker / needs_later_patch.\n"
        "2. Evidence: Inspect the audit / applog / traffic evidence in the left panel.\n"
        "3. Candidate: Compare against the original candidate four-step reasoning chain in the center panel.\n"
        "4. Draft: Edit only the UI draft in the right panel; do not directly modify the formal candidate.\n"
        "5. Validate & Diff: Run validation and a diff preview after saving the draft.\n"
        "6. Writeback: Use single-sample writeback only when the formal candidate reasoning chain truly needs replacement; default to dry-run."
    )
    st.warning(
        "Blind-friendly mode masks CVE / scenario / lab identifiers in the display layer only. "
        "It does not modify candidate files, drafts, indexes, release files, or canonical gold. "
        "Internal review UI may show sample_id / scenario_id / run_dir / edge_id for traceability. "
        "These identifiers are for human traceability only and must not be used as evidence for stage reasoning. "
        "Formal model evaluation should use strict_blind benchmark inputs."
    )


def table_row_for_display(row: dict[str, Any], display_mode: str) -> dict[str, Any]:
    out = {col: row.get(col, "") for col in TABLE_COLUMNS}
    if display_mode == BLIND_MODE:
        out["sample_id"] = row.get("masked_sample_id") or "[INTERNAL-SAMPLE-ID-MASKED]"
        out["recommended_action"] = mask_internal_identifiers_for_display(out["recommended_action"])
    return out


def sample_label_for_display(row: dict[str, Any], display_mode: str) -> str:
    if display_mode == BLIND_MODE:
        return (
            f"{row.get('masked_sample_id') or '[INTERNAL-SAMPLE-ID-MASKED]'}"
            f" | stage={row.get('gold_stage', '')}"
            f" | priority={row.get('human_review_priority', '')}"
        )
    return row.get("sample_id", "")


def collect_evidence_refs(candidate: dict[str, Any]) -> list[dict[str, Any]]:
    refs = []
    for step in candidate.get("gold_reasoning_chain", []) if isinstance(candidate, dict) else []:
        if not isinstance(step, dict):
            continue
        step_name = step.get("step", "")
        for ref in step.get("evidence_refs", []) or []:
            if isinstance(ref, dict):
                refs.append({"step": step_name, **ref})
            else:
                refs.append({"step": step_name, "ref": ref})
    return refs


def evidence_spine(prompt_evidence: dict[str, Any]) -> list[dict[str, Any]]:
    prompt_input = prompt_evidence.get("prompt_input", {}) if isinstance(prompt_evidence, dict) else {}
    primary = prompt_input.get("primary_evidence", {}) if isinstance(prompt_input, dict) else {}
    spine = primary.get("spine", []) if isinstance(primary, dict) else []
    return spine if isinstance(spine, list) else []


def evidence_ref_keys(ref: dict[str, Any]) -> set[tuple[str, Any]]:
    keys = set()
    if isinstance(ref, dict):
        if ref.get("seq") is not None:
            keys.add(("seq", ref.get("seq")))
        if ref.get("edge_id"):
            keys.add(("edge_id", ref.get("edge_id")))
    return keys


def filter_spine_by_refs(spine: list[dict[str, Any]], refs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    wanted = set()
    for ref in refs:
        wanted.update(evidence_ref_keys(ref))
    if not wanted:
        return []
    matched = []
    for item in spine:
        if ("seq", item.get("seq")) in wanted or ("edge_id", item.get("edge_id")) in wanted:
            matched.append(item)
    return matched


def classify_spine(spine: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
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


def render_json_block(title: str, value: Any, expanded: bool = False) -> None:
    with st.expander(title, expanded=expanded):
        st.json(value if value not in (None, "") else {})


def render_evidence_panel(row: dict[str, Any], display_mode: str) -> None:
    candidate = row.get("candidate", {})
    prompt_evidence = row.get("prompt_evidence", {})
    strict_input = row.get("strict_blind_input", {})
    refs = collect_evidence_refs(candidate)
    if display_mode == BLIND_MODE and strict_input:
        strict_spine = strict_input.get("input", {}).get("spine", [])
        spine = strict_spine if isinstance(strict_spine, list) else []
        matched_spine = filter_spine_by_refs(spine, refs)
        panels = classify_spine(matched_spine or spine[:20])
        evidence_source = "strict_blind model_input evidence"
    else:
        spine = evidence_spine(prompt_evidence)
        matched_spine = filter_spine_by_refs(spine, refs)
        panels = classify_spine(matched_spine or spine[:20])
        evidence_source = "reviewer prompt evidence"

    st.subheader("Evidence Panel")
    st.caption(f"Readonly evidence source: {evidence_source}.")
    if display_mode == BLIND_MODE:
        st.text_input("sample label", "[INTERNAL-SAMPLE-ID-MASKED]", disabled=True)
        st.text_input("scenario_hint", scenario_hint_from_evidence(row), disabled=True)
        st.info("Blind-friendly display masks strong scenario identifiers in the display layer only.")
    else:
        st.text_input("sample_id", row.get("sample_id", ""), disabled=True)
        st.text_input("scenario_id", row.get("scenario_id", ""), disabled=True)
        st.warning("Internal identifiers are for traceability only, not reasoning evidence.")
    st.text_input("gold_stage", row.get("gold_stage", ""), disabled=True)
    st.text_area(
        "window",
        stringify(display_value(candidate.get("window") or row.get("candidate_index", {}).get("window"), display_mode)),
        height=86,
        disabled=True,
    )
    st.dataframe(display_value(refs, display_mode), use_container_width=True, hide_index=True)
    render_json_block("primary evidence", display_value(panels["primary"], display_mode), expanded=True)
    render_json_block("audit evidence", display_value(panels["audit"], display_mode))
    render_json_block("applog evidence", display_value(panels["applog"], display_mode))
    render_json_block("traffic evidence", display_value(panels["traffic"], display_mode))
    with st.expander("Traceability details", expanded=False):
        st.json({
            "sample_id": row.get("sample_id"),
            "masked_sample_id": row.get("masked_sample_id"),
            "scenario_id": row.get("scenario_id"),
            "run_dir_path": row.get("run_dir_path"),
            "candidate_file": row.get("candidate_index", {}).get("candidate_file"),
            "strict_blind_sample_id": strict_input.get("sample_id") if isinstance(strict_input, dict) else None,
        })
    if not prompt_evidence:
        st.warning("No prompt evidence resolved for this sample.")


def render_candidate_panel(row: dict[str, Any], display_mode: str) -> None:
    candidate = row.get("candidate", {})
    weighted = row.get("weighted_case", {})
    manual = row.get("manual_review", {})

    st.subheader("Original Candidate Panel")
    st.caption("Readonly formal candidate. P6.3 edits never modify this source.")
    chain = candidate.get("gold_reasoning_chain", []) if isinstance(candidate, dict) else []
    for step in chain:
        if not isinstance(step, dict):
            continue
        with st.expander(step.get("step", "chain step"), expanded=True):
            st.text_area("claim", display_value(step.get("claim", ""), display_mode), height=150, disabled=True)
            st.dataframe(display_value(step.get("evidence_refs", []) or [], display_mode), use_container_width=True, hide_index=True)

    st.text_area(
        "auxiliary_vulnerability_note",
        stringify(display_value(candidate.get("auxiliary_vulnerability_note", ""), display_mode)),
        height=120,
        disabled=True,
    )
    st.text_input("weighted_verdict", row.get("weighted_verdict", ""), disabled=True)
    st.text_area("manual_review reason", stringify(manual.get("reason", "")), height=80, disabled=True)
    if weighted:
        render_json_block("weighted grounding case", weighted)
    for warning in row.get("structure_warnings", []):
        st.warning(warning)


def render_review_info_panel(row: dict[str, Any]) -> None:
    sheet = row.get("p5_38_review_sheet", {})
    dry_run = row.get("p5_37_dry_run", {})
    diag = row.get("p5_35_diagnostic", {})

    st.subheader("Review Info Panel")
    for field in REVIEW_INFO_FIELDS:
        value = sheet.get(field, dry_run.get(field, diag.get(field, "")))
        st.text_area(field, stringify(value), height=68 if "reason" not in field else 120, disabled=True)

    st.markdown("**Original Review Fields**")
    for field in FUTURE_EDIT_FIELDS:
        value = sheet.get(field, "")
        height = 90 if "notes" in field else 68
        st.text_area(field, stringify(value), height=height, disabled=True)


def render_review_packet_export_panel(row: dict[str, Any], workbench_dir: str) -> None:
    st.subheader("Codex Review Packet Export")
    st.caption("This exports a blind-friendly review packet for Codex-assisted review.")
    st.caption("It writes only to ui_drafts/review_packets/.")
    st.caption(
        "It does not update draft, final_candidate_gold.jsonl, candidate index, "
        "release files, or canonical gold."
    )
    export_key = f"review_packet_export_{row.get('sample_id')}"
    if st.button("Export current sample review packet for Codex", key=f"{export_key}_button"):
        try:
            st.session_state[export_key] = export_review_packet(
                workbench_dir=workbench_dir,
                row=row,
                output_latest=True,
            )
        except Exception as exc:  # pragma: no cover - Streamlit runtime feedback
            st.session_state[export_key] = {"ok": False, "error": str(exc)}

    result = st.session_state.get(export_key)
    if not result:
        return
    if result.get("ok"):
        paths = result.get("paths", {})
        st.success("Review packet exported to ui_drafts/review_packets/ only.")
        st.text_input("latest_review_packet path", paths.get("latest_json", ""), disabled=True)
        st.code("cat review_ui/manual_review_prompt.md", language="bash")
        st.text_area(
            "Suggested Codex instruction",
            "Read ui_drafts/review_packets/latest_review_packet.json, review the current sample in read-only mode, and output the review using the template without modifying any file.",
            height=90,
            disabled=True,
        )
        with st.expander("Exported packet paths", expanded=False):
            st.json(paths)
    else:
        st.error("Review packet export failed.")
        st.write(result.get("error", "unknown error"))


def current_draft_for_row(row: dict[str, Any]) -> dict[str, Any]:
    latest = row.get("latest_draft")
    if isinstance(latest, dict):
        return latest
    return make_draft_from_original(row)


def render_draft_editor(row: dict[str, Any], workbench_dir: str) -> None:
    latest = row.get("latest_draft")
    draft = current_draft_for_row(row)
    prefix = f"draft_{row.get('sample_id')}"

    st.subheader("Draft Editing Panel")
    st.caption("You are editing a human-review draft, not the formal candidate reasoning chain.")
    st.caption("First compare the evidence on the left with the original candidate reasoning chain in the center, then edit the draft below.")
    st.caption("Saving a draft writes only to ui_drafts/ and does not update final_candidate_gold.jsonl.")
    st.caption("For formal writeback, first pass Validation and Diff Preview, then explicitly confirm in the advanced writeback section below.")
    st.info("Current editing target: human-review draft. Saving updates only ui_drafts/ and does not modify the formal candidate.")
    st.warning(
        "Note: the draft editor shows the original editable text and does not automatically save display-layer masked text. Do not use CVEs, scenario names, or lab paths as stage evidence."
    )
    if latest:
        st.success(f"Loaded existing draft updated at {latest.get('updated_at', '')}")
    else:
        st.warning("No saved draft for this sample yet; fields are initialized from original candidate.")

    draft_chain = draft.get("draft_reasoning_chain", [])
    edited_chain = []
    for idx, step in enumerate(draft_chain):
        step_name = step.get("step", "")
        with st.expander(f"Draft claim {idx + 1}: {step_name}", expanded=True):
            claim = st.text_area(
                "claim",
                step.get("claim", ""),
                height=145,
                key=f"{prefix}_claim_{idx}",
            )
            edited_step = dict(step)
            edited_step["claim"] = claim
            edited_chain.append(edited_step)
            st.dataframe(step.get("evidence_refs", []) or [], use_container_width=True, hide_index=True)

    aux_note = draft.get("draft_auxiliary_vulnerability_note", {})
    if not isinstance(aux_note, dict):
        aux_note = {"claim": stringify(aux_note)}
    aux_claim = st.text_area(
        "auxiliary_vulnerability_note.claim",
        aux_note.get("claim", ""),
        height=100,
        key=f"{prefix}_aux_claim",
    )
    edited_aux = dict(aux_note)
    edited_aux["claim"] = aux_claim

    edited_draft = dict(draft)
    edited_draft["draft_reasoning_chain"] = edited_chain
    edited_draft["draft_auxiliary_vulnerability_note"] = edited_aux
    edited_draft["clean_final_allowed"] = "no"
    edited_draft["canonical_gold_allowed"] = "no"
    edited_draft["draft_status"] = "draft_only"

    c1, c2 = st.columns(2)
    with c1:
        if st.button("Save draft for current sample", type="primary", key=f"{prefix}_save"):
            result = save_draft(workbench_dir, row, edited_draft)
            if result["saved"]:
                st.success("Draft saved to ui_drafts only.")
                reload_sample_from_disk(workbench_dir, row.get("sample_id", ""))
                st.rerun()
            else:
                st.error("Draft validation failed.")
                for error in result["errors"]:
                    st.write(f"- {error}")
    with c2:
        if st.button("Reset draft from original candidate", key=f"{prefix}_reset"):
            result = reset_draft_from_original(workbench_dir, row)
            if result["saved"]:
                st.success("Draft reset from original candidate in ui_drafts only.")
                reload_sample_from_disk(workbench_dir, row.get("sample_id", ""))
                st.rerun()
            else:
                st.error("Reset validation failed.")
                for error in result["errors"]:
                    st.write(f"- {error}")

    with st.expander("Draft as candidate-like preview"):
        st.json(draft_to_candidate_like(edited_draft, row.get("candidate", {})))


def render_validation_diff_panel(row: dict[str, Any], workbench_dir: str) -> None:
    st.subheader("Validation & Diff Preview Panel")
    st.caption("Draft-only validation and preview. No formal candidate writeback is performed.")
    draft = row.get("latest_draft")
    if not isinstance(draft, dict):
        st.info("No draft exists for this sample")
        return

    c1, c2, c3 = st.columns(3)
    validation_key = f"validation_{row.get('sample_id')}"
    diff_key = f"diff_{row.get('sample_id')}"
    with c1:
        if st.button("Validate current draft", key=f"{validation_key}_button"):
            st.session_state[validation_key] = validate_row_draft(row, draft)
    with c2:
        if st.button("Show original vs draft diff", key=f"{diff_key}_button"):
            st.session_state[diff_key] = preview_row_diff(row, draft)
    with c3:
        save_preview = st.checkbox("Save diff preview to ui_drafts", key=f"{diff_key}_save")

    validation = st.session_state.get(validation_key)
    if validation:
        if validation.get("valid"):
            st.success("Draft schema valid.")
        else:
            st.error("Draft is not safe for future writeback.")
        if validation.get("errors"):
            with st.expander("Validation errors", expanded=True):
                for error in validation["errors"]:
                    st.write(f"- {error}")
        if validation.get("warnings"):
            with st.expander("Validation warnings", expanded=True):
                for warning in validation["warnings"]:
                    st.write(f"- {warning}")
        render_json_block("Validation checks", validation.get("checks", {}), expanded=True)

    diff_preview = st.session_state.get(diff_key)
    if diff_preview:
        if diff_preview.get("changed"):
            st.warning(f"Draft changes detected: {diff_preview.get('changed_count', 0)} fields changed.")
        else:
            st.success("Draft is unchanged versus original/review baseline.")
        if save_preview:
            paths = save_diff_preview(workbench_dir, diff_preview)
            st.info(f"Diff preview saved to {paths['markdown']} and {paths['json']}")
        st.markdown(diff_preview.get("markdown", ""))
        render_json_block("Diff preview JSON", diff_preview)


def render_human_review_status_panel(row: dict[str, Any], workbench_dir: str) -> None:
    st.subheader("Human Review Status Panel")
    st.caption(
        "This section records the human-review decision and workflow status. It does not modify the formal candidate and does not mean clean final or canonical gold."
    )
    st.caption("Saving here writes only ui_drafts/human_review_status.* and does not modify drafts or candidates.")
    status = row.get("human_review_status", {})
    draft = current_draft_for_row(row)
    prefix = f"human_review_status_{row.get('sample_id')}"

    if status.get("has_writeback_log"):
        st.info("This sample has a writeback log entry.")
    st.text_input(
        "effective_review_priority",
        row.get("effective_review_priority", ""),
        disabled=True,
    )
    st.text_input(
        "after_review_status",
        row.get("after_review_status", ""),
        disabled=True,
    )

    review_status = st.selectbox(
        "review_status",
        REVIEW_STATUS_VALUES,
        index=option_index(REVIEW_STATUS_VALUES, status.get("review_status", "not_reviewed")),
        key=f"{prefix}_review_status",
    )
    reviewer_decision = st.text_input(
        "reviewer_decision",
        status.get("reviewer_decision") or draft.get("reviewer_decision") or DEFAULT_REVIEWER_DECISION,
        key=f"{prefix}_reviewer_decision",
    )
    promotion_decision = st.text_input(
        "promotion_decision",
        status.get("promotion_decision") or draft.get("promotion_decision") or DEFAULT_PROMOTION_DECISION,
        key=f"{prefix}_promotion_decision",
    )
    clean_final_allowed = st.selectbox(
        "clean_final_allowed",
        CLEAN_FINAL_ALLOWED_VALUES,
        index=option_index(CLEAN_FINAL_ALLOWED_VALUES, status.get("clean_final_allowed", "no")),
        key=f"{prefix}_clean_final_allowed",
    )
    canonical_gold_allowed = st.selectbox(
        "canonical_gold_allowed",
        CANONICAL_GOLD_ALLOWED_VALUES,
        index=0,
        key=f"{prefix}_canonical_gold_allowed",
    )
    writeback_status = st.selectbox(
        "writeback_status",
        WRITEBACK_STATUS_VALUES,
        index=option_index(WRITEBACK_STATUS_VALUES, status.get("writeback_status", "not_written_back")),
        key=f"{prefix}_writeback_status",
    )
    needs_later_patch_after_review = st.selectbox(
        "needs_later_patch_after_review",
        YES_NO_VALUES,
        index=option_index(
            YES_NO_VALUES,
            status.get("needs_later_patch_after_review", row.get("needs_later_patch", "yes")),
        ),
        key=f"{prefix}_needs_later_patch_after_review",
    )
    promotion_blocker_after_review = st.selectbox(
        "promotion_blocker_after_review",
        YES_NO_VALUES,
        index=option_index(
            YES_NO_VALUES,
            status.get("promotion_blocker_after_review", row.get("promotion_blocker", "yes")),
        ),
        key=f"{prefix}_promotion_blocker_after_review",
    )
    notes = st.text_area(
        "notes",
        status.get("notes") or draft.get("reviewer_notes", ""),
        height=100,
        key=f"{prefix}_notes",
    )

    st.text_input("latest_reviewed_at", status.get("reviewed_at", ""), disabled=True)
    st.text_input("not_formal_gold", str(status.get("not_formal_gold", True)).lower(), disabled=True)
    if st.button("Save human review status", type="primary", key=f"{prefix}_save"):
        try:
            result = save_human_review_status(
                workbench_dir,
                row,
                {
                    "review_status": review_status,
                    "reviewer_decision": reviewer_decision,
                    "promotion_decision": promotion_decision,
                    "clean_final_allowed": clean_final_allowed,
                    "canonical_gold_allowed": canonical_gold_allowed,
                    "writeback_status": writeback_status,
                    "writeback_log_ref": status.get("writeback_log_ref"),
                    "needs_later_patch_after_review": needs_later_patch_after_review,
                    "promotion_blocker_after_review": promotion_blocker_after_review,
                    "notes": notes,
                },
            )
        except Exception as exc:  # pragma: no cover - Streamlit runtime feedback
            st.error(f"Human review status save failed: {exc}")
            return
        st.success("Human review status saved to ui_drafts only.")
        with st.expander("Saved human review status record", expanded=False):
            st.json(result["record"])
        reload_sample_from_disk(workbench_dir, row.get("sample_id", ""))
        st.rerun()


def render_writeback_preview_panel(row: dict[str, Any], workbench_dir: str) -> None:
    st.subheader("Single-sample Writeback Preview Panel")
    st.caption(
        "P6.4 safety-gated writeback. Only gold_reasoning_chain and "
        "auxiliary_vulnerability_note may be written to one final_candidate_gold.jsonl."
    )
    draft = row.get("latest_draft")
    if not isinstance(draft, dict):
        st.info("No draft exists for this sample")
        return

    sample_id = row.get("sample_id", "")
    target_path = draft.get("source_final_candidate_gold_path", "")
    st.text_input("target final_candidate_gold.jsonl", target_path, disabled=True)
    st.warning(
        "Risk notice: real writeback modifies one run_dir/final_candidate_gold.jsonl. "
        "No candidate index, release, canonical gold, or promotion files are modified."
    )

    preview_key = f"writeback_preview_{sample_id}"
    if st.button("Dry-run single-sample writeback preview", key=f"{preview_key}_dry"):
        st.session_state[preview_key] = write_single_sample_draft_to_final_candidate(
            workbench_dir=workbench_dir,
            sample_id=sample_id,
            dry_run=True,
            confirm_writeback=False,
        )
    preview = st.session_state.get(preview_key)
    if preview:
        if preview.get("ok"):
            st.success("Dry-run preview succeeded. No file was written.")
        else:
            st.error("Dry-run preview failed.")
        render_json_block("Dry-run writeback preview", preview, expanded=True)

    st.markdown("**Real writeback confirmation**")
    understand = st.checkbox(
        "I understand this will modify one final_candidate_gold.jsonl file.",
        key=f"{preview_key}_understand",
    )
    confirm_text = st.text_input(
        f"Type WRITEBACK {sample_id}",
        key=f"{preview_key}_confirm_text",
    )
    can_write = understand and confirm_text == f"WRITEBACK {sample_id}"
    if st.button(
        "Write back current sample draft",
        type="primary",
        disabled=not can_write,
        key=f"{preview_key}_write",
    ):
        result = write_single_sample_draft_to_final_candidate(
            workbench_dir=workbench_dir,
            sample_id=sample_id,
            dry_run=False,
            confirm_writeback=True,
        )
        st.session_state[preview_key] = result
        if result.get("ok"):
            st.success("Single-sample writeback completed.")
            reload_sample_from_disk(workbench_dir, sample_id)
            st.rerun()
        else:
            st.error("Single-sample writeback was blocked.")
        render_json_block("Writeback result", result, expanded=True)


def main() -> None:
    args = parse_args()
    st.set_page_config(
        page_title="P6 EWVAA Review UI",
        layout="wide",
        initial_sidebar_state="expanded",
    )
    st.title("P6 Attack-Chain Reasoning Review UI")
    st.caption(
        "Human review workflow for evidence, original candidate, UI draft, validation, diff preview, "
        "and optional dry-run single-sample writeback."
    )
    render_workflow_guide()

    workbench_dir = str(Path(args.workbench_dir))
    bundle = cached_load_workbench(workbench_dir)
    rows = bundle.review_rows

    with st.sidebar:
        st.header("Workbench")
        st.text_input("workbench_dir", str(bundle.workbench_dir), disabled=True)
        st.text_input("writeback_enabled", str(bundle.writeback_enabled).lower(), disabled=True)
        st.text_input("latest_draft_count", str(len(bundle.latest_drafts_by_sample_id)), disabled=True)
        if st.button("Reload workbench from disk", type="primary"):
            reload_workbench_from_disk(workbench_dir, st.session_state.get("selected_sample_id"))
        st.header("Sample Selection")
        preset = st.selectbox("Preset", list(PRESET_FILTERS), index=0)
        st.caption(
            "Presets: high priority = human_review_priority=high; blockers = promotion_blocker=yes; "
            "later patch = needs_later_patch=yes; low-risk = priority low + no blocker."
        )
        display_mode = st.selectbox(
            "Display mode",
            [BLIND_MODE, TRACE_MODE],
            index=0,
            help="Blind-friendly mode masks strong identifiers in display only; it does not modify files.",
        )
        st.header("Filters")
        sample_search = st.text_input("sample_id search", "")
        preset_defaults = PRESET_FILTERS.get(preset, {})
        filters = {}
        for field in FILTER_FIELDS:
            options = as_options(rows, field)
            filters[field] = st.selectbox(
                field,
                options,
                index=default_filter_index(options, preset_defaults.get(field)),
                key=f"filter_{preset}_{field}",
            )
        st.header("Human Review Status")
        hide_reviewed = st.checkbox("Hide reviewed samples", value=False)
        st.caption(
            "Hide reviewed samples uses UI review_status, not original human_review_priority."
        )
        hide_reviewed_resolved = st.checkbox("Hide reviewed/resolved samples", value=True)
        review_status_filter = st.selectbox(
            "Review status filter",
            as_options(rows, "review_status"),
            index=0,
        )
        writeback_status_filter = st.selectbox(
            "Writeback status filter",
            as_options(rows, "writeback_status"),
            index=0,
        )
        effective_review_priority_filter = st.selectbox(
            "Effective review priority filter",
            as_options(rows, "effective_review_priority"),
            index=0,
        )
        after_review_status_filter = st.selectbox(
            "After-review status filter",
            as_options(rows, "after_review_status"),
            index=0,
        )
        filters["review_status"] = review_status_filter
        filters["writeback_status"] = writeback_status_filter
        filters["effective_review_priority"] = effective_review_priority_filter
        filters["after_review_status"] = after_review_status_filter
        if bundle.warnings:
            with st.expander(f"Warnings ({len(bundle.warnings)})"):
                for warning in bundle.warnings:
                    st.write(warning)

    st.markdown("### B. Sample Selection")
    filtered_rows = apply_filters(
        rows,
        filters,
        sample_search,
        hide_reviewed=hide_reviewed,
        hide_reviewed_resolved=hide_reviewed_resolved,
    )
    filtered_rows = sort_review_rows(filtered_rows)
    st.write(f"Showing {len(filtered_rows)} / {len(rows)} candidates")
    table_rows = [table_row_for_display(row, display_mode) for row in filtered_rows]
    st.dataframe(table_rows, use_container_width=True, hide_index=True)

    if not filtered_rows:
        st.info("No candidates match the current filters.")
        return

    sample_labels = [sample_label_for_display(row, display_mode) for row in filtered_rows]
    selected_label = st.selectbox("Select sample for detail", sample_labels)
    selected_row = filtered_rows[sample_labels.index(selected_label)]
    st.session_state["selected_sample_id"] = selected_row.get("sample_id", "")
    reload_label = f"Reload current sample from disk ({selected_row.get('sample_id', '')})"
    if st.button(reload_label, key=f"reload_sample_{selected_row.get('sample_id', '')}"):
        reload_workbench_from_disk(workbench_dir, selected_row.get("sample_id", ""))
    render_metric_row(selected_row)

    st.markdown("### C. Evidence / Original / Draft")
    left, middle, right = st.columns([1.05, 1.15, 1.2], gap="large")
    with left:
        render_evidence_panel(selected_row, display_mode)
    with middle:
        render_candidate_panel(selected_row, display_mode)
        render_review_info_panel(selected_row)
        render_review_packet_export_panel(selected_row, workbench_dir)
    with right:
        render_draft_editor(selected_row, workbench_dir)
        render_human_review_status_panel(selected_row, workbench_dir)

    st.divider()
    st.markdown("### D. Validation & Diff Preview")
    render_validation_diff_panel(selected_row, workbench_dir)
    st.divider()
    st.markdown("### E. Advanced: Dangerous Single-sample Writeback")
    with st.expander("Advanced / Dangerous / Single-sample Writeback", expanded=False):
        st.caption("Use this only after validation and diff review. Default workflow is dry-run only.")
        render_writeback_preview_panel(selected_row, workbench_dir)


if __name__ == "__main__":
    main()
