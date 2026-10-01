"""Original-vs-draft diff preview helpers for P6.3 review UI drafts."""

from __future__ import annotations

import difflib
from typing import Any


DIFF_FIELDS = [
    "reviewer_decision",
    "reviewer_notes",
    "promotion_decision",
    "clean_final_allowed",
    "canonical_gold_allowed",
]


def _as_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value)


def _unified_diff(original: str, draft: str, fromfile: str, tofile: str) -> str:
    if original == draft:
        return ""
    return "\n".join(
        difflib.unified_diff(
            original.splitlines(),
            draft.splitlines(),
            fromfile=fromfile,
            tofile=tofile,
            lineterm="",
        )
    )


def _field_diff(field: str, original: Any, draft: Any) -> dict[str, Any]:
    original_text = _as_text(original)
    draft_text = _as_text(draft)
    changed = original_text != draft_text
    return {
        "field": field,
        "changed": changed,
        "original": original_text,
        "draft": draft_text,
        "unified_diff": _unified_diff(
            original_text,
            draft_text,
            f"original/{field}",
            f"draft/{field}",
        ),
    }


def _original_review_value(row: dict[str, Any], field: str) -> str:
    sheet = row.get("p5_38_review_sheet", {})
    if isinstance(sheet, dict):
        value = sheet.get(field, "")
        if value is not None:
            return str(value)
    if field in {"clean_final_allowed", "canonical_gold_allowed"}:
        return "no"
    return ""


def build_diff_preview(row: dict[str, Any], draft: dict[str, Any]) -> dict[str, Any]:
    """Build a preview-only original-vs-draft diff for UI display."""
    candidate = row.get("candidate", {}) if isinstance(row, dict) else {}
    original_chain = candidate.get("gold_reasoning_chain", []) if isinstance(candidate, dict) else []
    draft_chain = draft.get("draft_reasoning_chain", []) if isinstance(draft, dict) else []
    fields = []

    for idx in range(4):
        original_step = original_chain[idx] if idx < len(original_chain) and isinstance(original_chain[idx], dict) else {}
        draft_step = draft_chain[idx] if idx < len(draft_chain) and isinstance(draft_chain[idx], dict) else {}
        step_name = draft_step.get("step") or original_step.get("step") or f"step_{idx}"
        fields.append(
            _field_diff(
                f"gold_reasoning_chain[{idx}].claim:{step_name}",
                original_step.get("claim", ""),
                draft_step.get("claim", ""),
            )
        )

    original_aux = candidate.get("auxiliary_vulnerability_note", {}) if isinstance(candidate, dict) else {}
    draft_aux = draft.get("draft_auxiliary_vulnerability_note", {}) if isinstance(draft, dict) else {}
    fields.append(
        _field_diff(
            "auxiliary_vulnerability_note.claim",
            original_aux.get("claim", "") if isinstance(original_aux, dict) else original_aux,
            draft_aux.get("claim", "") if isinstance(draft_aux, dict) else draft_aux,
        )
    )

    for field in DIFF_FIELDS:
        fields.append(_field_diff(field, _original_review_value(row, field), draft.get(field, "")))

    changed_fields = [field for field in fields if field["changed"]]
    markdown = render_diff_markdown(
        sample_id=row.get("sample_id", draft.get("sample_id", "")),
        fields=fields,
    )
    return {
        "sample_id": row.get("sample_id", draft.get("sample_id", "")),
        "available": True,
        "preview_only": True,
        "formal_writeback": False,
        "changed": bool(changed_fields),
        "changed_count": len(changed_fields),
        "unchanged_count": len(fields) - len(changed_fields),
        "fields": fields,
        "markdown": markdown,
    }


def render_diff_markdown(sample_id: str, fields: list[dict[str, Any]]) -> str:
    """Render a readable Markdown diff preview for Streamlit or reports."""
    lines = [
        f"# Draft Diff Preview: {sample_id}",
        "",
        "Preview only. This diff does not write back to formal candidate files.",
        "",
    ]
    for field in fields:
        status = "changed" if field.get("changed") else "unchanged"
        lines.extend(
            [
                f"## {field.get('field', '')}",
                "",
                f"Status: `{status}`",
                "",
                "**Original**",
                "",
                "```text",
                field.get("original", ""),
                "```",
                "",
                "**Draft**",
                "",
                "```text",
                field.get("draft", ""),
                "```",
                "",
            ]
        )
        if field.get("unified_diff"):
            lines.extend(
                [
                    "**Unified Diff**",
                    "",
                    "```diff",
                    field["unified_diff"],
                    "```",
                    "",
                ]
            )
    return "\n".join(lines)
