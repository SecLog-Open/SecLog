"""Schema and gate checks for batch review outputs."""

from __future__ import annotations

import copy
import re
from typing import Any

try:
    from validators import EXPECTED_CHAIN_STEPS
except ImportError:  # pragma: no cover
    from .validators import EXPECTED_CHAIN_STEPS


BATCH_REVIEW_SCHEMA_VERSION = "review_ui_batch_review_v0.1"

FORMAL_FORBIDDEN_TERMS = [
    "manual review",
    "human review",
    "candidate-with-manual-review",
    "promotion",
    "promoted",
    "no promotion",
    "clean final",
    "clean_final",
    "canonical gold",
    "canonical_gold",
    "writeback",
    "human_verified",
    "reviewer decision",
    "reviewer_notes",
    "fixed gold_stage",
    "given gold_stage",
    "under the fixed label",
    "L1",
    "L2",
    "L3",
    "L4",
]

OUTPUT_TOP_LEVEL_FIELDS = {
    "masked_sample_label",
    "gold_stage",
    "key_seq",
    "key_relation",
    "key_subject_or_process",
    "key_object_or_target",
    "draft_claims",
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
}


def _jsonish_values(value: Any) -> list[Any]:
    values = [value]
    if isinstance(value, dict):
        for child in value.values():
            values.extend(_jsonish_values(child))
    elif isinstance(value, list):
        for child in value:
            values.extend(_jsonish_values(child))
    return values


def _candidate_chain(row: dict[str, Any]) -> list[dict[str, Any]]:
    candidate = row.get("candidate", {}) if isinstance(row, dict) else {}
    chain = candidate.get("gold_reasoning_chain", []) if isinstance(candidate, dict) else []
    return chain if isinstance(chain, list) else []


def original_evidence_refs(row: dict[str, Any]) -> list[list[dict[str, Any]]]:
    refs: list[list[dict[str, Any]]] = []
    for step in _candidate_chain(row):
        if isinstance(step, dict) and isinstance(step.get("evidence_refs"), list):
            refs.append(copy.deepcopy(step.get("evidence_refs", [])))
        else:
            refs.append([])
    return refs


def build_identity_snapshot(
    *,
    packet: dict[str, Any],
    row: dict[str, Any],
) -> dict[str, Any]:
    """Capture immutable packet identity and single-sample traceability."""
    traceability = packet.get("traceability", {}) if isinstance(packet, dict) else {}
    index_row = row.get("candidate_index", {}) if isinstance(row, dict) else {}
    return {
        "masked_sample_label": packet.get("masked_sample_label", ""),
        "sample_id": row.get("sample_id", ""),
        "gold_stage": row.get("gold_stage", ""),
        "source_run_dir": row.get("run_dir_path", ""),
        "source_final_candidate_gold_path": index_row.get("candidate_file", ""),
        "packet_traceability_not_for_reasoning": traceability.get("not_for_reasoning") is True,
        "packet_traceability_sample_id": traceability.get("internal_sample_id", ""),
        "packet_traceability_candidate_file": traceability.get("candidate_file", ""),
        "candidate_row_index": index_row.get("candidate_row_index"),
        "evidence_refs_by_step": original_evidence_refs(row),
    }


def _forbidden_hits(text: str) -> list[str]:
    lower = text.lower()
    hits = []
    for term in FORMAL_FORBIDDEN_TERMS:
        if re.fullmatch(r"L[1-4]", term):
            if re.search(rf"(?<![A-Za-z0-9_]){re.escape(term)}(?![A-Za-z0-9_])", text):
                hits.append(term)
            continue
        if term.lower() in lower:
            hits.append(term)
    return hits


def find_forbidden_formal_terms(output: dict[str, Any]) -> list[dict[str, str]]:
    """Return forbidden workflow terms in formal draft fields only."""
    hits = []
    claims = output.get("draft_claims", [])
    if isinstance(claims, list):
        for index, item in enumerate(claims):
            if not isinstance(item, dict):
                continue
            claim = item.get("claim", "")
            if isinstance(claim, str):
                for term in _forbidden_hits(claim):
                    hits.append({"field": f"draft_claims[{index}].claim", "term": term})
    aux = output.get("auxiliary_vulnerability_note", "")
    aux_text = aux.get("claim", "") if isinstance(aux, dict) else aux
    if isinstance(aux_text, str):
        for term in _forbidden_hits(aux_text):
            hits.append({"field": "auxiliary_vulnerability_note", "term": term})
    return hits


def _allowed_evidence_tokens(packet: dict[str, Any]) -> dict[str, set[Any]]:
    allowed: dict[str, set[Any]] = {
        "seq": set(),
        "edge_id": set(),
        "relation": set(),
        "subject": set(),
        "object": set(),
        "process": set(),
    }
    for ref in packet.get("evidence_refs", []) if isinstance(packet, dict) else []:
        if not isinstance(ref, dict):
            continue
        for key in ["seq", "edge_id"]:
            if ref.get(key) not in {None, ""}:
                allowed[key].add(ref.get(key))
    strict = packet.get("strict_blind_evidence", {}) if isinstance(packet, dict) else {}
    spine = strict.get("spine", []) if isinstance(strict, dict) else []
    for item in spine if isinstance(spine, list) else []:
        if not isinstance(item, dict):
            continue
        for key in ["seq", "edge_id", "relation", "subject", "object", "process"]:
            if item.get(key) not in {None, ""}:
                allowed[key].add(item.get(key))
        for ctx in item.get("audit_context", []) or []:
            if not isinstance(ctx, dict):
                continue
            for key in ["process", "subject", "object"]:
                if ctx.get(key) not in {None, ""}:
                    allowed[key].add(ctx.get(key))
    return allowed


def _find_structured_evidence_mixing(
    output: dict[str, Any],
    packet: dict[str, Any],
) -> list[str]:
    allowed = _allowed_evidence_tokens(packet)
    errors = []
    key_aliases = {
        "seq": "seq",
        "edge_id": "edge_id",
        "relation": "relation",
        "process": "process",
        "subject": "subject",
        "object": "object",
    }

    def visit(value: Any, path: str) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                normalized = key_aliases.get(str(key))
                if normalized and child not in {None, ""} and allowed[normalized]:
                    candidates = child if isinstance(child, list) else [child]
                    for candidate in candidates:
                        if isinstance(candidate, dict):
                            continue
                        if candidate not in allowed[normalized]:
                            errors.append(
                                f"{path}.{key} value {candidate!r} is not present in packet evidence"
                            )
                visit(child, f"{path}.{key}")
        elif isinstance(value, list):
            for index, child in enumerate(value):
                visit(child, f"{path}[{index}]")

    visit(output, "output")

    seq_mentions = set()
    text = "\n".join(str(v) for v in _jsonish_values(output) if isinstance(v, str))
    for match in re.finditer(r"(?i)\bseq(?:uence)?\s*[:#=]?\s*(\d+)\b", text):
        seq_mentions.add(int(match.group(1)))
    if allowed["seq"]:
        for seq in sorted(seq_mentions):
            if seq not in allowed["seq"]:
                errors.append(f"text mentions seq {seq}, which is not present in packet evidence")
    return errors


def validate_batch_review_output(
    *,
    output: Any,
    packet: dict[str, Any],
    row: dict[str, Any],
) -> dict[str, Any]:
    errors: list[str] = []
    warnings: list[str] = []
    identity = build_identity_snapshot(packet=packet, row=row)
    if not isinstance(output, dict):
        return {
            "valid": False,
            "errors": ["batch output line is not a JSON object"],
            "warnings": warnings,
            "identity": identity,
            "forbidden_formal_term_hits": [],
        }

    unknown_fields = sorted(set(output) - OUTPUT_TOP_LEVEL_FIELDS)
    if unknown_fields:
        warnings.append("unknown top-level batch output fields ignored: " + ", ".join(unknown_fields))

    if output.get("masked_sample_label") != identity["masked_sample_label"]:
        errors.append("masked_sample_label does not match packet identity")
    if output.get("gold_stage") != identity["gold_stage"]:
        errors.append("gold_stage does not match packet/current candidate")
    if identity["packet_traceability_not_for_reasoning"] is not True:
        errors.append("packet traceability is not marked not_for_reasoning")
    if identity["packet_traceability_sample_id"] != identity["sample_id"]:
        errors.append("packet traceability sample_id does not match current row")
    if identity["packet_traceability_candidate_file"] != identity["source_final_candidate_gold_path"]:
        errors.append("packet traceability candidate file does not match current row")

    claims = output.get("draft_claims")
    if not isinstance(claims, list) or len(claims) != len(EXPECTED_CHAIN_STEPS):
        errors.append("draft_claims must contain exactly four steps")
        claims = []
    actual_steps = [claim.get("step") if isinstance(claim, dict) else None for claim in claims]
    if actual_steps != EXPECTED_CHAIN_STEPS:
        errors.append("draft_claims step names/order must match ewvaa_four_step_v1")
    for index, claim in enumerate(claims):
        if not isinstance(claim, dict):
            errors.append(f"draft_claims[{index}] is not an object")
            continue
        if not isinstance(claim.get("claim"), str) or not claim.get("claim", "").strip():
            errors.append(f"draft_claims[{index}].claim must be non-empty")
        if "evidence_refs" in claim:
            if index >= len(identity["evidence_refs_by_step"]):
                errors.append(f"draft_claims[{index}].evidence_refs is unexpected")
            elif claim.get("evidence_refs") != identity["evidence_refs_by_step"][index]:
                errors.append(f"draft_claims[{index}].evidence_refs changed")

    if output.get("clean_final_allowed", "no") != "no":
        errors.append("clean_final_allowed must be no")
    if output.get("canonical_gold_allowed", "no") != "no":
        errors.append("canonical_gold_allowed must be no")
    if output.get("writeback_status", "not_written_back") != "not_written_back":
        errors.append("writeback_status must be not_written_back in GPT output")

    for field in ["reviewer_decision", "promotion_decision", "notes"]:
        value = output.get(field, "")
        if value is not None and not isinstance(value, str):
            errors.append(f"{field} must be a string")
    for field in ["needs_later_patch_after_review", "promotion_blocker_after_review"]:
        value = output.get(field, "yes")
        if value not in {"yes", "no"}:
            errors.append(f"{field} must be yes or no")
    if output.get("review_status", "reviewed") not in {
        "reviewed",
        "needs_revision",
        "deferred",
        "rejected_for_clean_final",
    }:
        errors.append("review_status is not a supported post-review value")

    forbidden_hits = find_forbidden_formal_terms(output)
    for hit in forbidden_hits:
        errors.append(f"forbidden formal term {hit['term']!r} in {hit['field']}")
    errors.extend(_find_structured_evidence_mixing(output, packet))

    return {
        "valid": not errors,
        "errors": errors,
        "warnings": warnings,
        "identity": identity,
        "forbidden_formal_term_hits": forbidden_hits,
    }
