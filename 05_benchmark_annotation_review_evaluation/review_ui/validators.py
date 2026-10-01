"""Structural checks for P6.3 review UI data and UI-only drafts."""

import os


def _same_source_path(a, b):
    """Separator-insensitive path equality for source path identity checks.

    Cross-platform compatibility only: draft source paths may be produced as
    raw JSONL strings (forward slashes) in one validation context and as
    ``str(Path(...))`` (OS separators) in another. This compares the same
    target location without changing any review/writeback semantics.
    """
    if a is None or b is None:
        return a == b
    a_str = str(a)
    b_str = str(b)
    if not a_str or not b_str:
        return a_str == b_str
    return os.path.normcase(os.path.normpath(a_str)) == os.path.normcase(
        os.path.normpath(b_str)
    )


EXPECTED_CHAIN_STEPS = [
    "scenario_or_evidence_understanding",
    "observable_evidence",
    "attack_stage_path_reasoning",
    "final_judgement",
]

FORBIDDEN_STRICT_TERMS = ["CVE-", "vulhub", "juice-shop", "sandworm"]

ALLOWED_DRAFT_TOP_LEVEL_FIELDS = {
    "sample_id",
    "gold_stage",
    "source_run_dir",
    "source_final_candidate_gold_path",
    "draft_reasoning_chain",
    "draft_auxiliary_vulnerability_note",
    "reviewer_decision",
    "reviewer_notes",
    "promotion_decision",
    "clean_final_allowed",
    "canonical_gold_allowed",
    "created_at",
    "updated_at",
    "draft_schema_version",
    "draft_status",
}

ALLOWED_DRAFT_STEP_FIELDS = {"step", "claim", "evidence_refs"}
ALLOWED_AUXILIARY_NOTE_FIELDS = {"claim", "not_for_scoring"}
DRAFT_SCHEMA_VERSION = "review_ui_draft_v0.1"
DRAFT_STATUS = "draft_only"


def validate_candidate_record(record):
    """Return non-fatal structural warnings for a candidate record."""
    warnings = []
    if not isinstance(record, dict):
        return ["candidate record is not a JSON object"]
    if not record.get("sample_id"):
        warnings.append("missing sample_id")
    chain = record.get("gold_reasoning_chain")
    if not isinstance(chain, list):
        warnings.append("missing gold_reasoning_chain list")
        return warnings
    actual_steps = [step.get("step") for step in chain if isinstance(step, dict)]
    if actual_steps != EXPECTED_CHAIN_STEPS:
        warnings.append(
            "gold_reasoning_chain step order differs from expected EWVAA four-step schema"
        )
    for idx, step in enumerate(chain):
        if not isinstance(step, dict):
            warnings.append(f"chain step {idx} is not an object")
            continue
        if not step.get("claim"):
            warnings.append(f"chain step {idx} missing claim")
        if not isinstance(step.get("evidence_refs", []), list):
            warnings.append(f"chain step {idx} evidence_refs is not a list")
    return warnings


def validate_workbench_bundle(bundle):
    """Return summary-level readonly validation checks for a loaded bundle."""
    warnings = []
    if not bundle.candidate_index:
        warnings.append("candidate index is empty or missing")
    if not bundle.final_candidates_by_sample_id:
        warnings.append("final candidate gold records are empty or missing")
    if not bundle.review_rows:
        warnings.append("review rows are empty")
    if bundle.writeback_enabled:
        warnings.append("writeback is unexpectedly enabled")
    return warnings


def validate_draft(
    draft,
    original_candidate,
    original_gold_stage,
    expected_source_run_dir=None,
    expected_source_final_candidate_gold_path=None,
):
    """Return a structured validation report for a UI-only draft."""
    errors = []
    warnings = []
    checks = {
        "sample_id_unchanged": False,
        "gold_stage_unchanged": False,
        "source_run_dir_unchanged": False,
        "source_final_candidate_gold_path_unchanged": False,
        "fixed_four_step": False,
        "chain_length_is_four": False,
        "step_fields_allowed": False,
        "claims_non_empty": False,
        "evidence_refs_format_valid": False,
        "evidence_refs_unchanged": False,
        "auxiliary_note_fields_allowed": False,
        "draft_status_valid": False,
        "draft_schema_version_valid": False,
        "clean_final_allowed_no": False,
        "canonical_gold_allowed_no": False,
        "clean_final_not_true": False,
        "forbidden_terms_clean": False,
        "top_level_fields_allowed": False,
    }
    sample_id = ""
    if not isinstance(draft, dict):
        return {
            "sample_id": sample_id,
            "valid": False,
            "errors": ["draft is not a JSON object"],
            "warnings": warnings,
            "checks": checks,
        }
    if not isinstance(original_candidate, dict):
        return {
            "sample_id": draft.get("sample_id", ""),
            "valid": False,
            "errors": ["original candidate is not a JSON object"],
            "warnings": warnings,
            "checks": checks,
        }

    sample_id = original_candidate.get("sample_id")
    unknown_top_level = sorted(set(draft) - ALLOWED_DRAFT_TOP_LEVEL_FIELDS)
    checks["top_level_fields_allowed"] = not unknown_top_level
    if unknown_top_level:
        errors.append(
            "unknown top-level draft/formal candidate fields: "
            + ", ".join(unknown_top_level)
        )

    checks["sample_id_unchanged"] = draft.get("sample_id") == sample_id
    if draft.get("sample_id") != sample_id:
        errors.append("sample_id changed")
    checks["gold_stage_unchanged"] = draft.get("gold_stage") == original_gold_stage
    if draft.get("gold_stage") != original_gold_stage:
        errors.append("gold_stage changed")
    if expected_source_run_dir is None:
        checks["source_run_dir_unchanged"] = bool(draft.get("source_run_dir"))
    else:
        checks["source_run_dir_unchanged"] = _same_source_path(
            draft.get("source_run_dir"), expected_source_run_dir
        )
    if not checks["source_run_dir_unchanged"]:
        errors.append("source_run_dir changed")
    if expected_source_final_candidate_gold_path is None:
        checks["source_final_candidate_gold_path_unchanged"] = bool(
            draft.get("source_final_candidate_gold_path")
        )
    else:
        checks["source_final_candidate_gold_path_unchanged"] = _same_source_path(
            draft.get("source_final_candidate_gold_path"),
            expected_source_final_candidate_gold_path,
        )
    if not checks["source_final_candidate_gold_path_unchanged"]:
        errors.append("source_final_candidate_gold_path changed")

    draft_chain = draft.get("draft_reasoning_chain")
    original_chain = original_candidate.get("gold_reasoning_chain")
    checks["chain_length_is_four"] = isinstance(draft_chain, list) and len(draft_chain) == 4
    if not checks["chain_length_is_four"]:
        errors.append("draft_reasoning_chain must contain exactly four steps")
        draft_chain = []
    if not isinstance(original_chain, list) or len(original_chain) != 4:
        errors.append("original candidate chain must contain exactly four steps")
        original_chain = []

    actual_steps = [step.get("step") for step in draft_chain if isinstance(step, dict)]
    checks["fixed_four_step"] = actual_steps == EXPECTED_CHAIN_STEPS
    if not checks["fixed_four_step"]:
        errors.append("draft_reasoning_chain step names/order changed")

    editable_text = []
    step_fields_ok = True
    claims_ok = True
    refs_format_ok = True
    refs_unchanged = True
    for idx, step in enumerate(draft_chain):
        if not isinstance(step, dict):
            errors.append(f"draft step {idx} is not an object")
            step_fields_ok = False
            claims_ok = False
            refs_format_ok = False
            refs_unchanged = False
            continue
        unknown_step_fields = sorted(set(step) - ALLOWED_DRAFT_STEP_FIELDS)
        if unknown_step_fields:
            errors.append(
                f"draft step {idx} has disallowed fields: "
                + ", ".join(unknown_step_fields)
            )
            step_fields_ok = False
        claim = step.get("claim")
        if not isinstance(claim, str) or not claim.strip():
            errors.append(f"draft step {idx} claim must be a non-empty string")
            claims_ok = False
        else:
            editable_text.append(claim)
        refs = step.get("evidence_refs")
        if not isinstance(refs, list):
            errors.append(f"draft step {idx} evidence_refs must be a list")
            refs_format_ok = False
            refs = []
        for ref_idx, ref in enumerate(refs):
            if not isinstance(ref, dict):
                errors.append(f"draft step {idx} evidence_ref {ref_idx} is not an object")
                refs_format_ok = False
                continue
            if set(ref) != {"seq", "edge_id"}:
                errors.append(
                    f"draft step {idx} evidence_ref {ref_idx} must contain only seq and edge_id"
                )
                refs_format_ok = False
            if ref.get("seq") is None or not ref.get("edge_id"):
                errors.append(
                    f"draft step {idx} evidence_ref {ref_idx} requires seq and edge_id"
                )
                refs_format_ok = False
        if idx < len(original_chain):
            original_refs = original_chain[idx].get("evidence_refs", [])
            if step.get("evidence_refs", []) != original_refs:
                errors.append(f"draft step {idx} evidence_refs changed")
                refs_unchanged = False
    checks["step_fields_allowed"] = step_fields_ok
    checks["claims_non_empty"] = claims_ok
    checks["evidence_refs_format_valid"] = refs_format_ok
    checks["evidence_refs_unchanged"] = refs_unchanged

    aux_note = draft.get("draft_auxiliary_vulnerability_note", {})
    aux_fields_ok = True
    if not isinstance(aux_note, dict):
        errors.append("draft_auxiliary_vulnerability_note must be an object")
        aux_fields_ok = False
    else:
        unknown_aux_fields = sorted(set(aux_note) - ALLOWED_AUXILIARY_NOTE_FIELDS)
        if unknown_aux_fields:
            errors.append(
                "draft_auxiliary_vulnerability_note has disallowed fields: "
                + ", ".join(unknown_aux_fields)
            )
            aux_fields_ok = False
        aux_claim = aux_note.get("claim", "")
        if aux_claim:
            if not isinstance(aux_claim, str):
                errors.append("auxiliary_vulnerability_note.claim must be a string")
            else:
                editable_text.append(aux_claim)
        if "not_for_scoring" in aux_note and not isinstance(aux_note["not_for_scoring"], bool):
            errors.append("auxiliary_vulnerability_note.not_for_scoring must be boolean")
            aux_fields_ok = False
    checks["auxiliary_note_fields_allowed"] = aux_fields_ok

    for field in ["reviewer_decision", "reviewer_notes", "promotion_decision"]:
        value = draft.get(field, "")
        if value and not isinstance(value, str):
            errors.append(f"{field} must be a string")
        elif isinstance(value, str):
            editable_text.append(value)

    checks["clean_final_allowed_no"] = draft.get("clean_final_allowed", "no") == "no"
    if not checks["clean_final_allowed_no"]:
        errors.append("clean_final_allowed must remain no in P6.3")
    checks["canonical_gold_allowed_no"] = draft.get("canonical_gold_allowed", "no") == "no"
    if not checks["canonical_gold_allowed_no"]:
        errors.append("canonical_gold_allowed must remain no in P6.3")
    if draft.get("canonical_gold_allowed") == "yes":
        errors.append("canonical_gold_allowed=yes is forbidden in P6.3")
    checks["draft_status_valid"] = draft.get("draft_status") == DRAFT_STATUS
    if not checks["draft_status_valid"]:
        errors.append("draft_status must be draft_only")
    checks["draft_schema_version_valid"] = draft.get("draft_schema_version") == DRAFT_SCHEMA_VERSION
    if not checks["draft_schema_version_valid"]:
        errors.append("draft_schema_version must be review_ui_draft_v0.1")
    checks["clean_final_not_true"] = draft.get("clean_final") is not True
    if draft.get("clean_final") is True:
        errors.append("clean_final must not be set to true")

    haystack = "\n".join(editable_text).lower()
    forbidden_hits = []
    for term in FORBIDDEN_STRICT_TERMS:
        if term.lower() in haystack:
            forbidden_hits.append(term)
    checks["forbidden_terms_clean"] = not forbidden_hits
    for term in forbidden_hits:
        errors.append(f"forbidden strict term found in editable text: {term}")

    if not draft.get("reviewer_notes"):
        warnings.append("reviewer_notes is empty")
    return {
        "sample_id": sample_id or draft.get("sample_id", ""),
        "valid": not errors,
        "errors": errors,
        "warnings": warnings,
        "checks": checks,
    }


def validate_draft_errors(*args, **kwargs):
    """Compatibility helper for callers that need only blocking errors."""
    return validate_draft(*args, **kwargs)["errors"]
