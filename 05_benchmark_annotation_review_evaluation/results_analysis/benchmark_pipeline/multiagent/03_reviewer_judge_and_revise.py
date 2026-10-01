#!/usr/bin/env python3
"""Step 03: reviewer model judges annotator patches and revises when needed."""
from __future__ import annotations

import json
import argparse
from collections import Counter
from pathlib import Path
from typing import Any

from common import (
    blocked_report,
    call_role_model,
    load_benchmark,
    load_config,
    load_validation_cases,
    normalize_verdict,
    print_role_api_usage,
    redact_api_config_for_report,
    read_jsonl,
    rel,
    require_active_run,
    resolve_openai_compatible_api_config,
    role_request_timeout_seconds,
    review_prompt_row,
    safe_read_jsonl,
    sanitize_candidate_auxiliary_note,
    sanitize_reasoning_chain,
    sample_selection_summary,
    utc_now,
    verdict_distribution,
    write_json,
    write_jsonl,
)
from results_analysis.release import run_ewvaa_stage_reasoning_api_trial as ewvaa


def truncate_text(value: Any, limit: int = 500) -> str:
    text = str(value)
    return text if len(text) <= limit else text[: limit - 3] + "..."


def summarize_response_row(row: dict[str, Any]) -> dict[str, Any]:
    response = row.get("response")
    response_keys = sorted(response.keys()) if isinstance(response, dict) else []
    schema_summary = row.get("response_schema_summary")
    if not isinstance(schema_summary, dict):
        schema_summary = {}
    return {
        "sample_id": row.get("sample_id"),
        "gold_stage": row.get("gold_stage"),
        "keys": sorted(row.keys()),
        "has_error": "error" in row,
        "error": truncate_text(row.get("error", "")) if "error" in row else "",
        "provider_error": truncate_text(row.get("provider_error", "")) if row.get("provider_error") else "",
        "traceback_excerpt": truncate_text(row.get("traceback", "")) if row.get("traceback") else "",
        "raw_content_present": bool(row.get("raw_content")),
        "raw_content_preview": truncate_text(row.get("raw_content", "")) if row.get("raw_content") else "",
        "response_keys": response_keys,
        "response_schema_summary": schema_summary,
        "response_excerpt": truncate_text(row.get("response_excerpt", "")) if row.get("response_excerpt") else "",
    }


def prompt_summary(prompt_row: dict[str, Any], *, api_mode: str, model: str, base_url: str, api_key_present: bool) -> dict[str, Any]:
    lengths = ewvaa.prompt_length_summary(prompt_row)
    excerpts = ewvaa.prompt_excerpt_summary(prompt_row, limit=500)
    return {
        "sample_id": str(prompt_row.get("sample_id") or ""),
        "expected_sample_id": str(prompt_row.get("sample_id") or ""),
        "api_mode": api_mode,
        "base_url": base_url,
        "model": model,
        **lengths,
        "has_response_format": api_mode != "responses",
        "max_tokens": 4096,
        "max_output_tokens": 4096 if api_mode == "responses" else None,
        "temperature": 0,
        "store": False,
        "api_key_present": api_key_present,
        "annotator_patch_present": True,
        "prompt_excerpt_head": excerpts["user_excerpt_head"],
        "prompt_excerpt_tail": excerpts["user_excerpt_tail"],
        "system_excerpt_head": excerpts["system_excerpt_head"],
        "system_excerpt_tail": excerpts["system_excerpt_tail"],
    }


def write_progress(run_dir: Path, progress: dict[str, Any]) -> None:
    write_json(run_dir / "reviewer_progress.json", progress)


def write_run_report_snapshot(
    *,
    run_dir: Path,
    api_config: dict[str, Any],
    annotator_patches: list[dict[str, Any]],
    annotator_path: Path,
    config: dict[str, Any],
    judge_rows: list[dict[str, Any]],
    revision_rows: list[dict[str, Any]],
    api_errors: list[dict[str, Any]],
    parse_failures: list[dict[str, Any]],
    calls_made: int,
    status: str,
    current_sample_id: str = "",
) -> dict[str, Any]:
    report = {
        "status": status,
        "created_at": utc_now(),
        "run_dir": rel(run_dir),
        **redact_api_config_for_report(api_config),
        "api_called": bool(calls_made),
        "annotator_api_key_recorded": False,
        "reviewer_api_key_recorded": False,
        "benchmark_files_modified": False,
        "current_sample_id": current_sample_id,
        **sample_selection_summary(config, [row.get("sample_id") for row in annotator_patches]),
        "inputs": {
            "annotator_patches": rel(annotator_path),
            "validation_report": rel(run_dir / "annotator_patch_validation_report.json"),
            "grounding_audit_report": rel(run_dir / "annotator_grounding_audit_report.json"),
            "prompt_pack": config["prompt_pack"],
            "annotation_context": config["annotation_context"],
        },
        "outputs": {
            "reviewer_raw_responses": rel(run_dir / "reviewer_raw_responses.jsonl"),
            "reviewer_judge_outputs": rel(run_dir / "reviewer_judge_outputs.jsonl"),
            "reviewer_revision_patches": rel(run_dir / "reviewer_revision_patches.unmasked.jsonl"),
            "reviewer_run_report": rel(run_dir / "reviewer_run_report.json"),
            "reviewer_progress": rel(run_dir / "reviewer_progress.json"),
            "reviewer_request_diagnosis": rel(run_dir / "reviewer_request_diagnosis.json"),
        },
        "counts": {
            "annotator_patches": len(annotator_patches),
            "reviewer_judgements": len(judge_rows),
            "reviewer_revisions": len(revision_rows),
            "api_errors": len(api_errors),
            "parse_failures": len(parse_failures),
            "calls_made_this_invocation": calls_made,
            "high_severity": sum(1 for row in judge_rows if row.get("high_severity")),
        },
        "verdict_distribution": verdict_distribution(judge_rows),
        "api_errors": api_errors,
        "parse_failures": parse_failures,
    }
    write_json(run_dir / "reviewer_run_report.json", report)
    return report


def flush_outputs(
    *,
    run_dir: Path,
    raw_rows: list[dict[str, Any]],
    judge_rows: list[dict[str, Any]],
    revision_rows: list[dict[str, Any]],
    api_config: dict[str, Any],
    annotator_patches: list[dict[str, Any]],
    annotator_path: Path,
    config: dict[str, Any],
    api_errors: list[dict[str, Any]],
    parse_failures: list[dict[str, Any]],
    calls_made: int,
    status: str,
    current_sample_id: str = "",
) -> dict[str, Any]:
    write_jsonl(run_dir / "reviewer_raw_responses.jsonl", raw_rows)
    write_jsonl(run_dir / "reviewer_judge_outputs.jsonl", judge_rows)
    write_jsonl(run_dir / "reviewer_revision_patches.unmasked.jsonl", revision_rows)
    return write_run_report_snapshot(
        run_dir=run_dir,
        api_config=api_config,
        annotator_patches=annotator_patches,
        annotator_path=annotator_path,
        config=config,
        judge_rows=judge_rows,
        revision_rows=revision_rows,
        api_errors=api_errors,
        parse_failures=parse_failures,
        calls_made=calls_made,
        status=status,
        current_sample_id=current_sample_id,
    )


def _walk_json_candidates(raw_text: str) -> list[dict[str, Any]]:
    decoder = json.JSONDecoder()
    candidates: list[dict[str, Any]] = []
    for idx, char in enumerate(raw_text):
        if char != "{":
            continue
        try:
            parsed, _ = decoder.raw_decode(raw_text[idx:])
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            candidates.append(parsed)
    return candidates


def _extract_response_output_texts(candidate: dict[str, Any]) -> list[str]:
    texts: list[str] = []
    output = candidate.get("output")
    if not isinstance(output, list):
        return texts
    for item in output:
        if not isinstance(item, dict):
            continue
        content = item.get("content")
        if not isinstance(content, list):
            continue
        for block in content:
            if not isinstance(block, dict):
                continue
            text = block.get("text")
            if isinstance(text, str) and text.strip():
                texts.append(text)
    return texts


def _field_alias_value(payload: dict[str, Any], aliases: tuple[str, ...]) -> tuple[Any, str | None]:
    for alias in aliases:
        if alias in payload:
            return payload.get(alias), alias
    queue: list[Any] = [payload]
    while queue:
        current = queue.pop(0)
        if isinstance(current, dict):
            for key, value in current.items():
                if key in aliases:
                    return value, key
                if isinstance(value, (dict, list)):
                    queue.append(value)
        elif isinstance(current, list):
            for item in current:
                if isinstance(item, (dict, list)):
                    queue.append(item)
    return None, None


def parse_reviewer_payload(raw_text: str) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    diagnostics: dict[str, Any] = {
        "raw_parse_mode": "unparsed",
        "top_level_keys": [],
        "candidate_count": 0,
        "response_envelope_detected": False,
    }
    direct = ewvaa.extract_json(raw_text)
    if isinstance(direct, dict):
        diagnostics["candidate_count"] = 1
        diagnostics["top_level_keys"] = sorted(direct.keys())
        if any(key in direct for key in ("sample_id", "verdict", "revised_patch", "revision_patch", "patch")):
            diagnostics["raw_parse_mode"] = "direct_json"
            return direct, diagnostics
        if direct.get("object") == "response":
            diagnostics["response_envelope_detected"] = True
            for text in _extract_response_output_texts(direct):
                nested = ewvaa.extract_json(text)
                if isinstance(nested, dict):
                    diagnostics["raw_parse_mode"] = "response_output_text"
                    diagnostics["top_level_keys"] = sorted(nested.keys())
                    return nested, diagnostics
    candidates = _walk_json_candidates(raw_text)
    diagnostics["candidate_count"] = len(candidates)
    for candidate in candidates:
        if candidate.get("object") == "response":
            diagnostics["response_envelope_detected"] = True
            for text in _extract_response_output_texts(candidate):
                nested = ewvaa.extract_json(text)
                if isinstance(nested, dict):
                    diagnostics["raw_parse_mode"] = "response_output_text_scan"
                    diagnostics["top_level_keys"] = sorted(nested.keys())
                    return nested, diagnostics
        if any(key in candidate for key in ("sample_id", "verdict", "revised_patch", "revision_patch", "patch")):
            diagnostics["raw_parse_mode"] = "candidate_scan"
            diagnostics["top_level_keys"] = sorted(candidate.keys())
            return candidate, diagnostics
    return None, diagnostics


def canonicalize_reviewer_payload(payload: dict[str, Any], expected_sample_id: str) -> tuple[dict[str, Any], list[str], dict[str, Any]]:
    sample_id_value, sample_id_alias = _field_alias_value(payload, ("sample_id", "sample", "sampleId", "id"))
    revised_patch_value, revised_patch_alias = _field_alias_value(
        payload,
        ("revised_patch", "revision_patch", "patch", "corrected_patch"),
    )
    rationale_value, rationale_alias = _field_alias_value(payload, ("rationale", "explanation"))
    issues_value, issues_alias = _field_alias_value(payload, ("issues", "problem_types"))
    verdict_value, _ = _field_alias_value(payload, ("verdict",))
    high_severity_value, _ = _field_alias_value(payload, ("high_severity",))
    overall_score_value, _ = _field_alias_value(payload, ("overall_score",))

    tags: list[str] = []
    if sample_id_alias and sample_id_alias != "sample_id":
        tags.append(f"sample_id_field_alias_used:{sample_id_alias}")
    if revised_patch_alias and revised_patch_alias != "revised_patch":
        tags.append(f"revised_patch_field_alias_used:{revised_patch_alias}")

    sample_id = str(sample_id_value).strip() if sample_id_value is not None else None
    if not sample_id:
        tags.append("sample_id_missing")
    elif sample_id != expected_sample_id:
        tags.append(f"sample_id_mismatch:{sample_id}")

    revised_patch = revised_patch_value if isinstance(revised_patch_value, dict) else None
    verdict = normalize_verdict(verdict_value)
    if verdict == "accept" and revised_patch is None:
        tags.append("accept_without_revision_ok")
    elif verdict in {"minor_revision", "major_revision", "reject", "invalid"} and revised_patch is None:
        tags.append("revised_patch_missing")
        tags.append("verdict_requires_revision_but_missing_patch")

    if isinstance(issues_value, list):
        issues = [str(item) for item in issues_value]
    elif issues_value is None:
        issues = []
    else:
        issues = [str(issues_value)]

    normalized = {
        "sample_id": sample_id,
        "verdict": verdict,
        "overall_score": overall_score_value if overall_score_value is not None else 0.0,
        "problem_types": issues,
        "high_severity": bool(high_severity_value),
        "explanation": "" if rationale_value is None else str(rationale_value),
        "revised_patch": revised_patch,
    }
    alias_info = {
        "sample_id_alias": sample_id_alias,
        "revised_patch_alias": revised_patch_alias,
        "rationale_alias": rationale_alias,
        "issues_alias": issues_alias,
    }
    return normalized, tags, alias_info


def build_schema_contract_diagnosis(run_dir: Path, config: dict[str, Any]) -> dict[str, Any]:
    raw_rows = safe_read_jsonl(run_dir / "reviewer_raw_responses.jsonl")
    judge_rows = safe_read_jsonl(run_dir / "reviewer_judge_outputs.jsonl")
    annotator_rows = safe_read_jsonl(run_dir / "reasoning_patches.unmasked.annotator.jsonl")
    prompt_by_id = load_benchmark(config, consumer_role="reviewer")["prompts_by_id"]
    validation_by_id = load_validation_cases(run_dir / "annotator_patch_validation_cases.jsonl")
    grounding_by_id = load_validation_cases(run_dir / "annotator_grounding_audit_cases.jsonl")

    dry_run_rows: list[dict[str, Any]] = []
    parse_mode_counts: Counter[str] = Counter()
    sample_alias_counts: Counter[str] = Counter()
    revised_alias_counts: Counter[str] = Counter()
    tag_counts: Counter[str] = Counter()
    field_shapes: Counter[str] = Counter()

    annotator_by_id = {str(row.get("sample_id")): row for row in annotator_rows if row.get("sample_id")}
    for raw_row in raw_rows:
        expected_sample_id = str(raw_row.get("sample_id") or "")
        payload, parse_diag = parse_reviewer_payload(str(raw_row.get("raw_content", "")))
        parse_mode_counts.update([str(parse_diag.get("raw_parse_mode", "unparsed"))])
        if payload is None:
            dry_run_rows.append(
                {
                    "expected_sample_id": expected_sample_id,
                    "raw_parse_mode": parse_diag.get("raw_parse_mode"),
                    "tags": ["payload_unparsed"],
                    "payload_keys": [],
                }
            )
            tag_counts.update(["payload_unparsed"])
            continue
        field_shapes.update(["+".join(sorted(payload.keys()))])
        normalized, tags, alias_info = canonicalize_reviewer_payload(payload, expected_sample_id)
        if alias_info.get("sample_id_alias"):
            sample_alias_counts.update([str(alias_info["sample_id_alias"])])
        if alias_info.get("revised_patch_alias"):
            revised_alias_counts.update([str(alias_info["revised_patch_alias"])])
        tag_counts.update(tags)
        dry_run_rows.append(
            {
                "expected_sample_id": expected_sample_id,
                "raw_parse_mode": parse_diag.get("raw_parse_mode"),
                "payload_keys": sorted(payload.keys()),
                "sample_id_from_payload": normalized.get("sample_id"),
                "verdict": normalized.get("verdict"),
                "has_revised_patch": isinstance(normalized.get("revised_patch"), dict),
                "sample_id_alias": alias_info.get("sample_id_alias"),
                "revised_patch_alias": alias_info.get("revised_patch_alias"),
                "tags": tags,
            }
        )

    prompt_before = {
        "expected_sample_id_exposed": True,
        "sample_id_exact_echo_required": False,
        "non_accept_requires_revised_patch": True,
        "accept_allows_null_revised_patch": False,
        "revised_patch_schema_explicit": True,
        "json_only_required": True,
    }
    prompt_after = {
        "expected_sample_id_exposed": True,
        "sample_id_exact_echo_required": True,
        "non_accept_requires_revised_patch": True,
        "accept_allows_null_revised_patch": True,
        "revised_patch_schema_explicit": True,
        "json_only_required": True,
    }
    parser_before = {
        "sample_id_alias_support": False,
        "revised_patch_alias_support": False,
        "response_envelope_support": False,
        "non_accept_missing_patch_high_severity": True,
        "sample_id_mismatch_high_severity": True,
    }
    parser_after = {
        "sample_id_alias_support": True,
        "revised_patch_alias_support": True,
        "response_envelope_support": True,
        "supported_dry_run_categories": [
            "sample_id_missing",
            "revised_patch_missing",
            "revised_patch_field_alias_used:<alias>",
            "verdict_requires_revision_but_missing_patch",
            "accept_without_revision_ok",
        ],
        "dry_run_tag_counts": dict(tag_counts),
    }
    actual_field_examples = dry_run_rows[:5]
    current_judge_problem_counts = Counter()
    for row in judge_rows:
        for issue in row.get("problem_types", []) if isinstance(row.get("problem_types"), list) else []:
            current_judge_problem_counts.update([str(issue)])

    diagnosis = {
        "status": "diagnosed",
        "run_dir": rel(run_dir),
        "files_checked": {
            "reviewer_script": rel(Path(__file__)),
            "reviewer_raw_responses": rel(run_dir / "reviewer_raw_responses.jsonl"),
            "reviewer_judge_outputs": rel(run_dir / "reviewer_judge_outputs.jsonl"),
            "reviewer_run_report": rel(run_dir / "reviewer_run_report.json"),
            "annotator_patches": rel(run_dir / "reasoning_patches.unmasked.annotator.jsonl"),
        },
        "counts": {
            "raw_rows": len(raw_rows),
            "judge_rows": len(judge_rows),
            "annotator_rows": len(annotator_rows),
        },
        "actual_output_field_structure_summary": {
            "parse_mode_counts": dict(parse_mode_counts),
            "payload_key_shapes": dict(field_shapes),
            "sample_id_alias_counts": dict(sample_alias_counts),
            "revised_patch_alias_counts": dict(revised_alias_counts),
            "example_rows": actual_field_examples,
        },
        "current_judge_output_summary": {
            "verdict_distribution": verdict_distribution(judge_rows),
            "problem_type_counts": dict(current_judge_problem_counts),
        },
        "root_cause": {
            "sample_id_became_none": (
                "03 used ewvaa.extract_json directly on reviewer raw_content. In this run the raw text begins with an "
                "error/event wrapper and a provider response envelope, so the parser captured the wrong JSON object "
                "instead of the assistant's JSON payload. parsed.get('sample_id') therefore evaluated to None."
            ),
            "revised_patch_missing": (
                "The same parse path never reached the nested assistant JSON where revised_patch actually exists, "
                "so 03 classified the row as missing_required_revised_patch even though the model output included it."
            ),
            "prompt_vs_parser": "Primary failure is parser extraction. Prompt contract was partially clear before, but it did not emphasize exact sample_id echo, accept/null behavior, or JSON-only constraints strongly enough.",
        },
        "prompt_contract_before_fix": prompt_before,
        "prompt_contract_after_fix": prompt_after,
        "parser_contract_before_fix": parser_before,
        "parser_contract_after_fix": parser_after,
        "reviewer_contract_dry_run": dry_run_rows,
    }

    first_sample = next(iter(annotator_by_id), "")
    if first_sample:
        prompt_preview = review_prompt_row(
            first_sample,
            annotator_by_id[first_sample],
            validation_by_id.get(first_sample),
            grounding_by_id.get(first_sample),
            prompt_by_id.get(first_sample),
        )
        diagnosis["prompt_contract_preview"] = {
            "sample_id": first_sample,
            "system_preview": truncate_text(prompt_preview.get("system", ""), 200),
            "user_preview": truncate_text(prompt_preview.get("user", ""), 800),
        }
    return diagnosis


def write_schema_contract_diagnosis(run_dir: Path, config: dict[str, Any]) -> int:
    diagnosis = build_schema_contract_diagnosis(run_dir, config)
    json_path = run_dir / "reviewer_schema_contract_diagnosis.json"
    md_path = run_dir / "reviewer_schema_contract_diagnosis.md"
    write_json(json_path, diagnosis)

    lines = [
        "# Reviewer Schema Contract Diagnosis",
        "",
        f"Run dir: `{rel(run_dir)}`",
        "",
        "## Actual Reviewer Output Field Summary",
        f"- Raw rows: {diagnosis['counts']['raw_rows']}",
        f"- Parse modes: `{json.dumps(diagnosis['actual_output_field_structure_summary']['parse_mode_counts'], ensure_ascii=False)}`",
        f"- Payload key shapes: `{json.dumps(diagnosis['actual_output_field_structure_summary']['payload_key_shapes'], ensure_ascii=False)}`",
        f"- Sample-id aliases seen: `{json.dumps(diagnosis['actual_output_field_structure_summary']['sample_id_alias_counts'], ensure_ascii=False)}`",
        f"- Revised-patch aliases seen: `{json.dumps(diagnosis['actual_output_field_structure_summary']['revised_patch_alias_counts'], ensure_ascii=False)}`",
        "",
        "## Diagnosis",
        f"- sample_id became None because {diagnosis['root_cause']['sample_id_became_none']}",
        f"- revised_patch looked missing because {diagnosis['root_cause']['revised_patch_missing']}",
        f"- prompt vs parser: {diagnosis['root_cause']['prompt_vs_parser']}",
        "",
        "## Prompt Contract",
        f"- expected sample_id exposed: `{diagnosis['prompt_contract_before_fix']['expected_sample_id_exposed']}`",
        f"- exact sample_id echo explicit before fix: `{diagnosis['prompt_contract_before_fix']['sample_id_exact_echo_required']}`",
        f"- non-accept requires revised_patch: `{diagnosis['prompt_contract_before_fix']['non_accept_requires_revised_patch']}`",
        f"- accept allows null revised_patch: `{diagnosis['prompt_contract_before_fix']['accept_allows_null_revised_patch']}`",
        f"- revised_patch schema explicit: `{diagnosis['prompt_contract_before_fix']['revised_patch_schema_explicit']}`",
        "",
        "## Parser Dry-Run",
        f"- supported categories: `{json.dumps(diagnosis['parser_contract_after_fix']['supported_dry_run_categories'], ensure_ascii=False)}`",
        f"- tag counts: `{json.dumps(diagnosis['parser_contract_after_fix']['dry_run_tag_counts'], ensure_ascii=False)}`",
    ]
    md_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(json.dumps(diagnosis, ensure_ascii=False, indent=2))
    return 0


def diagnose_existing_responses(run_dir: Path) -> int:
    raw_path = run_dir / "reviewer_raw_responses.jsonl"
    diag_json = run_dir / "reviewer_response_diagnosis.json"
    diag_md = run_dir / "reviewer_response_diagnosis.md"
    rows = safe_read_jsonl(raw_path)
    summaries = [summarize_response_row(row) for row in rows]
    error_rows = [row for row in summaries if row.get("has_error")]
    provider_missing_choices = sum(1 for row in summaries if row.get("error") == "provider_response_missing_choices")
    provider_missing_content = sum(1 for row in summaries if row.get("error") == "provider_response_missing_message_content")
    none_subscriptable = sum(1 for row in summaries if "NoneType' object is not subscriptable" in str(row.get("error", "")))
    diagnosis = {
        "status": "diagnosed",
        "run_dir": rel(run_dir),
        "raw_response_path": rel(raw_path),
        "counts": {
            "rows": len(rows),
            "error_rows": len(error_rows),
            "rows_with_raw_content": sum(1 for row in summaries if row.get("raw_content_present")),
            "provider_response_missing_choices": provider_missing_choices,
            "provider_response_missing_message_content": provider_missing_content,
            "none_type_subscriptable_errors": none_subscriptable,
        },
        "root_cause_hypothesis": (
            "reviewer API failures originate before JSON extraction. "
            "The OpenAI-compatible response parser assumes response.choices[0].message.content exists; "
            "for this provider/schema, choices or message content can be missing/None, which triggers a local TypeError "
            "and hides the provider response details."
        ),
        "sample_summaries": summaries[:5],
    }
    write_json(diag_json, diagnosis)
    lines = [
        "# Reviewer Response Diagnosis",
        "",
        f"Run dir: `{rel(run_dir)}`",
        f"Rows inspected: {len(rows)}",
        f"Error rows: {len(error_rows)}",
        f"`provider_response_missing_choices`: {provider_missing_choices}",
        f"`provider_response_missing_message_content`: {provider_missing_content}",
        f"`'NoneType' object is not subscriptable`: {none_subscriptable}",
        "",
        "## Root Cause Hypothesis",
        diagnosis["root_cause_hypothesis"],
        "",
        "## Sample Schema Summaries",
    ]
    for row in summaries[:5]:
        lines.append(f"- `{row.get('sample_id')}` error=`{row.get('error')}` raw_content_present={row.get('raw_content_present')}")
    diag_md.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(json.dumps(diagnosis, ensure_ascii=False, indent=2))
    return 0


def probe_reviewer_provider(config: dict[str, Any], run_dir: Path, probe_api_mode: str | None = None) -> int:
    api_config = resolve_openai_compatible_api_config(config, role="reviewer", use_env_api_config=False)
    if probe_api_mode:
        api_config["reviewer_api_mode"] = probe_api_mode
    probe_path = run_dir / "reviewer_provider_probe.json"
    if api_config.get("blocked"):
        report = {
            "status": "blocked",
            "run_dir": rel(run_dir),
            "role": "reviewer",
            "api_mode": str(api_config.get("reviewer_api_mode") or config.get("reviewer_api_mode") or ""),
            "base_url": str(api_config.get("reviewer_base_url") or ""),
            "model": str(api_config.get("reviewer_model") or ""),
            "api_key_present": bool(api_config.get("reviewer_api_key")),
            "blocked_reason": str(api_config.get("blocked_reason") or "api_config_blocked"),
        }
        write_json(probe_path, report)
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return 1

    prompt = {
        "system": "Return JSON only.",
        "user": "Return {\"ok\": true}.",
    }
    result = call_role_model(config, prompt, "reviewer", api_config)
    report = {
        "status": "success" if "error" not in result else "failed",
        "run_dir": rel(run_dir),
        "role": "reviewer",
        "api_mode": str(api_config.get("reviewer_api_mode") or ""),
        "base_url": str(api_config.get("reviewer_base_url") or ""),
        "model": str(api_config.get("reviewer_model") or ""),
        "api_key_present": bool(api_config.get("reviewer_api_key")),
        "output_text_present": bool(result.get("raw_content")),
        "content_excerpt": truncate_text(result.get("raw_content", ""), 300) if result.get("raw_content") else "",
        "error": truncate_text(result.get("error", "")) if result.get("error") else "",
        "provider_error": truncate_text(result.get("provider_error", "")) if result.get("provider_error") else "",
        "response_schema_summary": result.get("response_schema_summary", {}),
        "response_excerpt": truncate_text(result.get("response_excerpt", ""), 300) if result.get("response_excerpt") else "",
    }
    write_json(probe_path, report)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report["status"] == "success" else 1


def main() -> int:
    parser = argparse.ArgumentParser(description="Review and revise EWVAA annotator patches.")
    parser.add_argument("--config", type=Path, default=None)
    parser.add_argument(
        "--diagnose-existing-responses",
        type=Path,
        default=None,
        help="Read reviewer_raw_responses.jsonl from an existing run dir and write diagnosis files without calling API.",
    )
    parser.add_argument(
        "--probe-reviewer-provider",
        action="store_true",
        help="Run a minimal reviewer provider probe and write reviewer_provider_probe.json.",
    )
    parser.add_argument(
        "--diagnose-schema-contract",
        type=Path,
        default=None,
        help="Diagnose reviewer output schema/prompt contract from an existing run dir without calling API.",
    )
    parser.add_argument(
        "--probe-api-mode",
        choices=("chat_completions", "responses"),
        default=None,
        help="Temporarily override reviewer api_mode for provider probe only.",
    )
    parser.add_argument(
        "--use-env-api-config",
        action="store_true",
        help="Explicitly allow reading OPENAI_* API config. Default is interactive input or EWVAA_RUN_* only.",
    )
    parser.add_argument("--sample-id", type=str, default=None, help="Run reviewer only for one sample_id.")
    parser.add_argument("--max-samples", type=int, default=None, help="Limit number of reviewer samples processed.")
    parser.add_argument("--start-index", type=int, default=0, help="Start offset within the selected reviewer sample list.")
    parser.add_argument(
        "--request-timeout-seconds",
        type=float,
        default=None,
        help="Override reviewer request timeout for this invocation. When omitted, the runtime config default is 900 seconds.",
    )
    parser.add_argument(
        "--diagnose-request-only",
        action="store_true",
        help="Write reviewer_request_diagnosis.json and reviewer_progress.json for the selected sample(s) without calling API.",
    )
    args = parser.parse_args()
    from common import CONFIG_DEFAULT, ROOT

    config_path = args.config or CONFIG_DEFAULT
    config_path = config_path if config_path.is_absolute() else ROOT / config_path
    config = load_config(config_path)
    if args.diagnose_schema_contract is not None:
        run_dir = args.diagnose_schema_contract
        run_dir = run_dir if run_dir.is_absolute() else ROOT / run_dir
        return write_schema_contract_diagnosis(run_dir, config)
    if args.diagnose_existing_responses is not None:
        run_dir = args.diagnose_existing_responses
        run_dir = run_dir if run_dir.is_absolute() else ROOT / run_dir
        return diagnose_existing_responses(run_dir)
    run_dir = require_active_run(config)
    if args.probe_reviewer_provider:
        return probe_reviewer_provider(config, run_dir, args.probe_api_mode)
    annotator_path = run_dir / "reasoning_patches.unmasked.annotator.jsonl"
    if not annotator_path.exists():
        report = {
            "status": "failed",
            "created_at": utc_now(),
            "run_dir": rel(run_dir),
            "errors": [f"missing:{rel(annotator_path)}"],
            "api_called": False,
            "benchmark_files_modified": False,
        }
        write_json(run_dir / "reviewer_run_report.json", report)
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return 1

    api_config = resolve_openai_compatible_api_config(
        config,
        role="reviewer",
        use_env_api_config=args.use_env_api_config,
    )
    if api_config.get("blocked"):
        report = blocked_report(config, run_dir, "reviewer", "reviewer_run_report.json", api_config=api_config)
        print("BLOCKED: " + report["blocked_reason"])
        print(f"run_dir={run_dir}")
        return 1
    print_role_api_usage(api_config, "reviewer")

    annotator_patches = read_jsonl(annotator_path)
    bench = load_benchmark(config, consumer_role="reviewer")
    prompt_by_id = bench["prompts_by_id"]
    validation_by_id = load_validation_cases(run_dir / "annotator_patch_validation_cases.jsonl")
    grounding_by_id = load_validation_cases(run_dir / "annotator_grounding_audit_cases.jsonl")

    existing_raw = safe_read_jsonl(run_dir / "reviewer_raw_responses.jsonl")
    existing_judges = safe_read_jsonl(run_dir / "reviewer_judge_outputs.jsonl")
    existing_revisions = safe_read_jsonl(run_dir / "reviewer_revision_patches.unmasked.jsonl")
    judged_ids = {str(row.get("sample_id")) for row in existing_judges if row.get("sample_id")}

    raw_rows = list(existing_raw)
    judge_rows = list(existing_judges)
    revision_rows = list(existing_revisions)
    api_errors: list[dict] = []
    parse_failures: list[dict] = []
    calls_made = 0
    request_timeout_seconds = role_request_timeout_seconds(config, "reviewer", args.request_timeout_seconds)
    candidate_patches = [patch for patch in annotator_patches if str(patch.get("sample_id", "")) not in judged_ids]
    if args.sample_id:
        candidate_patches = [patch for patch in candidate_patches if str(patch.get("sample_id", "")) == args.sample_id]
    if args.start_index:
        candidate_patches = candidate_patches[args.start_index:]
    if args.max_samples is not None:
        candidate_patches = candidate_patches[: max(0, args.max_samples)]

    initial_progress = {
        "status": "initialized",
        "created_at": utc_now(),
        "updated_at": utc_now(),
        "run_dir": rel(run_dir),
        "api_mode": str(api_config.get("reviewer_api_mode") or ""),
        "request_timeout_seconds": request_timeout_seconds,
        "selected_sample_ids": [str(patch.get("sample_id", "")) for patch in candidate_patches],
        "completed_sample_ids": [],
        "failed_sample_ids": [],
        "calls_made": calls_made,
    }
    write_progress(run_dir, initial_progress)
    flush_outputs(
        run_dir=run_dir,
        raw_rows=raw_rows,
        judge_rows=judge_rows,
        revision_rows=revision_rows,
        api_config=api_config,
        annotator_patches=annotator_patches,
        annotator_path=annotator_path,
        config=config,
        api_errors=api_errors,
        parse_failures=parse_failures,
        calls_made=calls_made,
        status="running" if candidate_patches else "success",
    )

    if args.diagnose_request_only and not candidate_patches:
        print(json.dumps({"status": "no_samples_selected", "run_dir": rel(run_dir)}, ensure_ascii=False, indent=2))
        return 0

    for idx, patch in enumerate(candidate_patches, 1):
        sample_id = str(patch.get("sample_id", ""))
        prompt = review_prompt_row(
            sample_id,
            patch,
            validation_by_id.get(sample_id),
            grounding_by_id.get(sample_id),
            prompt_by_id.get(sample_id),
        )
        diagnosis = prompt_summary(
            prompt,
            api_mode=str(api_config.get("reviewer_api_mode") or ""),
            model=str(api_config.get("reviewer_model") or ""),
            base_url=str(api_config.get("reviewer_base_url") or ""),
            api_key_present=bool(api_config.get("reviewer_api_key")),
        )
        diagnosis["gold_stage"] = patch.get("gold_stage")
        diagnosis["request_timeout_seconds"] = request_timeout_seconds
        write_json(run_dir / "reviewer_request_diagnosis.json", diagnosis)
        progress = {
            "status": "started",
            "created_at": initial_progress["created_at"],
            "updated_at": utc_now(),
            "run_dir": rel(run_dir),
            "api_mode": str(api_config.get("reviewer_api_mode") or ""),
            "request_timeout_seconds": request_timeout_seconds,
            "selected_sample_ids": [str(item.get("sample_id", "")) for item in candidate_patches],
            "completed_sample_ids": [str(row.get("sample_id", "")) for row in judge_rows if row.get("sample_id")],
            "failed_sample_ids": [str(row.get("sample_id", "")) for row in api_errors + parse_failures if row.get("sample_id")],
            "calls_made": calls_made,
            "latest_event": {
                "sample_id": sample_id,
                "status": "started",
                "api_mode": str(api_config.get("reviewer_api_mode") or ""),
                "prompt_summary": {
                    "system_prompt_len": diagnosis["system_prompt_len"],
                    "user_prompt_len": diagnosis["user_prompt_len"],
                    "total_prompt_len": diagnosis["total_prompt_len"],
                },
                "timestamp": utc_now(),
            },
        }
        write_progress(run_dir, progress)
        flush_outputs(
            run_dir=run_dir,
            raw_rows=raw_rows,
            judge_rows=judge_rows,
            revision_rows=revision_rows,
            api_config=api_config,
            annotator_patches=annotator_patches,
            annotator_path=annotator_path,
            config=config,
            api_errors=api_errors,
            parse_failures=parse_failures,
            calls_made=calls_made,
            status="running",
            current_sample_id=sample_id,
        )
        print(f"[03 {idx}/{len(candidate_patches)}] reviewer {sample_id} stage={patch.get('gold_stage')}", flush=True)
        if args.diagnose_request_only:
            continue
        result = call_role_model(
            config,
            prompt,
            "reviewer",
            api_config,
            request_timeout_seconds=request_timeout_seconds,
        )
        calls_made += 1
        raw_rows.append({"sample_id": sample_id, "gold_stage": patch.get("gold_stage"), **result})
        if "error" in result:
            api_errors.append(
                {
                    "sample_id": sample_id,
                    "error": truncate_text(result.get("error", "")),
                    "error_type": str(result.get("error_type") or ""),
                    "api_mode": str(result.get("api_mode") or api_config.get("reviewer_api_mode") or ""),
                    "elapsed_seconds": result.get("elapsed_seconds"),
                    "provider_error": truncate_text(result.get("provider_error", "")) if result.get("provider_error") else "",
                    "traceback_excerpt": truncate_text(result.get("traceback", "")) if result.get("traceback") else "",
                    "response_schema_summary": result.get("response_schema_summary", {}),
                    "response_excerpt": truncate_text(result.get("response_excerpt", "")) if result.get("response_excerpt") else "",
                }
            )
            progress["completed_sample_ids"] = [str(row.get("sample_id", "")) for row in judge_rows if row.get("sample_id")]
            progress["failed_sample_ids"] = [str(row.get("sample_id", "")) for row in api_errors + parse_failures if row.get("sample_id")]
            progress["calls_made"] = calls_made
            progress["updated_at"] = utc_now()
            progress["latest_event"] = {
                "sample_id": sample_id,
                "status": "api_error",
                "error": truncate_text(result.get("error", "")),
                "error_type": str(result.get("error_type") or ""),
                "elapsed_seconds": result.get("elapsed_seconds"),
                "timestamp": utc_now(),
            }
            write_progress(run_dir, progress)
            flush_outputs(
                run_dir=run_dir,
                raw_rows=raw_rows,
                judge_rows=judge_rows,
                revision_rows=revision_rows,
                api_config=api_config,
                annotator_patches=annotator_patches,
                annotator_path=annotator_path,
                config=config,
                api_errors=api_errors,
                parse_failures=parse_failures,
                calls_made=calls_made,
                status="partial" if judge_rows else "failed",
                current_sample_id=sample_id,
            )
            continue
        parsed, parse_diag = parse_reviewer_payload(str(result.get("raw_content", "")))
        if parsed is None:
            parse_failures.append(
                {
                    "sample_id": sample_id,
                    "error": "json_parse_error",
                    "raw_parse_mode": parse_diag.get("raw_parse_mode"),
                }
            )
            progress["completed_sample_ids"] = [str(row.get("sample_id", "")) for row in judge_rows if row.get("sample_id")]
            progress["failed_sample_ids"] = [str(row.get("sample_id", "")) for row in api_errors + parse_failures if row.get("sample_id")]
            progress["calls_made"] = calls_made
            progress["updated_at"] = utc_now()
            progress["latest_event"] = {
                "sample_id": sample_id,
                "status": "parse_failure",
                "raw_parse_mode": parse_diag.get("raw_parse_mode"),
                "timestamp": utc_now(),
            }
            write_progress(run_dir, progress)
            flush_outputs(
                run_dir=run_dir,
                raw_rows=raw_rows,
                judge_rows=judge_rows,
                revision_rows=revision_rows,
                api_config=api_config,
                annotator_patches=annotator_patches,
                annotator_path=annotator_path,
                config=config,
                api_errors=api_errors,
                parse_failures=parse_failures,
                calls_made=calls_made,
                status="partial" if judge_rows else "failed",
                current_sample_id=sample_id,
            )
            continue
        normalized, contract_tags, alias_info = canonicalize_reviewer_payload(parsed, sample_id)
        verdict = str(normalized.get("verdict"))
        problem_types = list(normalized.get("problem_types") or [])
        for tag in contract_tags:
            if tag not in problem_types:
                problem_types.append(tag)
        high_severity = bool(normalized.get("high_severity")) or any(
            tag in {
                "sample_id_missing",
                "revised_patch_missing",
                "verdict_requires_revision_but_missing_patch",
            }
            or tag.startswith("sample_id_mismatch:")
            for tag in problem_types
        )
        revised_patch = normalized.get("revised_patch") if isinstance(normalized.get("revised_patch"), dict) else None
        judge_row = {
            "sample_id": sample_id,
            "verdict": verdict,
            "overall_score": normalized.get("overall_score", 0.0),
            "problem_types": problem_types,
            "high_severity": high_severity,
            "explanation": str(normalized.get("explanation", "")),
            "has_revised_patch": revised_patch is not None,
            "raw_parse_mode": parse_diag.get("raw_parse_mode"),
            "sample_id_alias": alias_info.get("sample_id_alias"),
            "revised_patch_alias": alias_info.get("revised_patch_alias"),
        }
        judge_rows.append(judge_row)
        if revised_patch is not None:
            revision_rows.append(
                {
                    "sample_id": str(revised_patch.get("sample_id") or sample_id),
                    "gold_stage": revised_patch.get("gold_stage") or patch.get("gold_stage"),
                    "gold_reasoning_chain": sanitize_reasoning_chain(revised_patch.get("gold_reasoning_chain")),
                    "auxiliary_vulnerability_note": sanitize_candidate_auxiliary_note(
                        revised_patch.get("auxiliary_vulnerability_note")
                    ),
                    "source": "reviewer",
                    "reviewer_verdict": verdict,
                }
            )
        progress["completed_sample_ids"] = [str(row.get("sample_id", "")) for row in judge_rows if row.get("sample_id")]
        progress["failed_sample_ids"] = [str(row.get("sample_id", "")) for row in api_errors + parse_failures if row.get("sample_id")]
        progress["calls_made"] = calls_made
        progress["updated_at"] = utc_now()
        progress["latest_event"] = {
            "sample_id": sample_id,
            "status": "success",
            "verdict": verdict,
            "has_revised_patch": revised_patch is not None,
            "timestamp": utc_now(),
        }
        write_progress(run_dir, progress)
        flush_outputs(
            run_dir=run_dir,
            raw_rows=raw_rows,
            judge_rows=judge_rows,
            revision_rows=revision_rows,
            api_config=api_config,
            annotator_patches=annotator_patches,
            annotator_path=annotator_path,
            config=config,
            api_errors=api_errors,
            parse_failures=parse_failures,
            calls_made=calls_made,
            status="running",
            current_sample_id=sample_id,
        )

    if args.diagnose_request_only:
        status = "diagnose_only"
    else:
        total_expected = len(existing_judges) + len(candidate_patches)
        status = "success" if len(judge_rows) == total_expected and not api_errors and not parse_failures else "partial" if judge_rows else "failed"
    progress = {
        "status": status,
        "created_at": initial_progress["created_at"],
        "updated_at": utc_now(),
        "run_dir": rel(run_dir),
        "api_mode": str(api_config.get("reviewer_api_mode") or ""),
        "request_timeout_seconds": request_timeout_seconds,
        "selected_sample_ids": [str(patch.get("sample_id", "")) for patch in candidate_patches],
        "completed_sample_ids": [str(row.get("sample_id", "")) for row in judge_rows if row.get("sample_id")],
        "failed_sample_ids": [str(row.get("sample_id", "")) for row in api_errors + parse_failures if row.get("sample_id")],
        "calls_made": calls_made,
        "latest_event": progress.get("latest_event") if 'progress' in locals() else {},
    }
    write_progress(run_dir, progress)
    report = flush_outputs(
        run_dir=run_dir,
        raw_rows=raw_rows,
        judge_rows=judge_rows,
        revision_rows=revision_rows,
        api_config=api_config,
        annotator_patches=annotator_patches,
        annotator_path=annotator_path,
        config=config,
        api_errors=api_errors,
        parse_failures=parse_failures,
        calls_made=calls_made,
        status=status,
    )
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if status in {"success", "partial", "diagnose_only"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
