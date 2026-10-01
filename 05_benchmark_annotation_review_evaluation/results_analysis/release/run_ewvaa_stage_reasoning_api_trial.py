#!/usr/bin/env python3
"""Run an EWVAA stage-reasoning annotation API trial.

Formal runs use the masked workbench, whose auxiliary context is derived from
``scenario_vulnerability_facts.annotation_context.v0.4.json``. The script calls
a selected chat-completion provider only when not in dry-run/revalidation mode,
validates generated gold_reasoning_chain patches, writes candidate patched_gold
outputs, and audits grounding without modifying benchmark inputs.

Strict gold_reasoning_chain claims must be grounded in primary evidence. CVE
and vulnerability context may appear only as auxiliary_vulnerability_note, and
forbidden strict-chain terms are hard invalid. Any patched_gold file produced
here is a candidate artefact and never overwrites canonical gold.jsonl.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import traceback
from collections import Counter
from pathlib import Path
from typing import Any, Iterable

REQUIRED_STEPS = [
    "scenario_or_evidence_understanding",
    "observable_evidence",
    "attack_stage_path_reasoning",
    "final_judgement",
]

FORBIDDEN_STRICT_TERMS: list[tuple[str, re.Pattern[str]]] = [
    ("exploit", re.compile(r"\bexploit(?:ation|ed|ing|s)?\b", re.IGNORECASE)),
    ("post-exploitation", re.compile(r"\bpost[-\s]+exploitation\b", re.IGNORECASE)),
    ("payload", re.compile(r"\bpayloads?\b", re.IGNORECASE)),
    ("RCE", re.compile(r"\bRCE\b|\bremote\s+code\s+execution\b", re.IGNORECASE)),
    ("XXE", re.compile(r"\bXXE\b|\bexternal\s+entity\b", re.IGNORECASE)),
    ("CVE", re.compile(r"\bCVE(?:-\d{4}-\d+)?\b", re.IGNORECASE)),
    ("shell obtained", re.compile(r"\bshell\s+obtained\b", re.IGNORECASE)),
    ("data exfiltration", re.compile(r"\bdata\s+exfiltration\b", re.IGNORECASE)),
    ("privilege escalation", re.compile(r"\bprivilege\s+escalation\b", re.IGNORECASE)),
    ("attacker executed", re.compile(r"\battacker\s+executed\b", re.IGNORECASE)),
    ("remote code execution occurs", re.compile(r"\bremote\s+code\s+execution\s+occurs\b", re.IGNORECASE)),
]

VALIDATION_FORBIDDEN_STRICT_TERMS: list[tuple[str, re.Pattern[str]]] = [
    ("post-exploitation", re.compile(r"\bpost[-\s]+exploitation\b", re.IGNORECASE)),
    ("remote code execution", re.compile(r"\bremote\s+code\s+execution\b", re.IGNORECASE)),
    ("shell obtained", re.compile(r"\bshell\s+obtained\b", re.IGNORECASE)),
    ("data exfiltration", re.compile(r"\bdata\s+exfiltration\b", re.IGNORECASE)),
    ("privilege escalation", re.compile(r"\bprivilege\s+escalation\b", re.IGNORECASE)),
    ("exploitation", re.compile(r"\bexploitation\b", re.IGNORECASE)),
    ("exploited", re.compile(r"\bexploited\b", re.IGNORECASE)),
    ("exploit", re.compile(r"\bexploit(?:s|ing)?\b", re.IGNORECASE)),
    ("payload", re.compile(r"\bpayloads?\b", re.IGNORECASE)),
    ("RCE", re.compile(r"\bRCE\b", re.IGNORECASE)),
    ("CVE", re.compile(r"\bCVE(?:-\d{4}-\d+)?\b", re.IGNORECASE)),
    ("XXE", re.compile(r"\bXXE\b", re.IGNORECASE)),
]

LEAKED_FIELD_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("malicious", re.compile(r'malicious\s*[=:]\s*true', re.IGNORECASE)),
    ("is_attack_related", re.compile(r"is_attack_related", re.IGNORECASE)),
    ("attack_relevance_tier", re.compile(r"attack_relevance_tier", re.IGNORECASE)),
    ("result_anchor", re.compile(r"result_anchor", re.IGNORECASE)),
    ("preparation_boundary", re.compile(r"preparation_boundary", re.IGNORECASE)),
    ("semantic_entry_anchor", re.compile(r"semantic_entry_anchor", re.IGNORECASE)),
    ("prep_rule_used", re.compile(r"prep_rule_used", re.IGNORECASE)),
    ("result_rule_used", re.compile(r"result_rule_used", re.IGNORECASE)),
]

VULNERABILITY_TERMS: list[tuple[str, re.Pattern[str]]] = [
    ("SQL injection", re.compile(r"\bsql\s+injection\b|\bsqli\b", re.IGNORECASE)),
    ("command injection", re.compile(r"\bcommand\s+injection\b", re.IGNORECASE)),
    ("template injection", re.compile(r"\btemplate\s+injection\b", re.IGNORECASE)),
    ("Velocity", re.compile(r"\bvelocity\b|\bv\.template\b", re.IGNORECASE)),
    ("RCE", re.compile(r"\brce\b|remote\s+code\s+execution", re.IGNORECASE)),
    ("path traversal", re.compile(r"\bpath\s+traversal\b|directory\s+traversal", re.IGNORECASE)),
    ("XXE", re.compile(r"\bxxe\b|external\s+entity", re.IGNORECASE)),
    ("deserialization", re.compile(r"\bdeseriali[sz]ation\b|\bdeserialize\b", re.IGNORECASE)),
    ("authentication bypass", re.compile(r"authentication\s+bypass|auth\s+bypass", re.IGNORECASE)),
    ("forgotPassword", re.compile(r"forgotPassword|forgot[_-]?password", re.IGNORECASE)),
    ("CVE", re.compile(r"\bCVE-\d{4}-\d+\b|\bCVE\b", re.IGNORECASE)),
]

STRICT_CHAIN_ENTRY_FIELDS = ("step", "claim", "evidence_refs")
STRICT_EVIDENCE_REF_FIELDS = ("seq", "edge_id")

JsonObj = dict[str, Any]

PRIVATE_WORK_ROOT = Path("workdir")
DEFAULT_MASKED_DRYRUN_OUTPUT_DIR = PRIVATE_WORK_ROOT / "api_trial_masked_workbench_dryrun"
DEFAULT_CANONICAL_BENCHMARK_DIR = PRIVATE_WORK_ROOT / "canonical_benchmark/data"


def read_jsonl(path: Path) -> list[JsonObj]:
    rows: list[JsonObj] = []
    with path.open("r", encoding="utf-8") as fh:
        for line_no, line in enumerate(fh, 1):
            text = line.strip()
            if text:
                row = json.loads(text)
                row["_line_no"] = line_no
                rows.append(row)
    return rows


def write_jsonl(path: Path, rows: Iterable[JsonObj]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with path.open("w", encoding="utf-8") as fh:
        for row in rows:
            clean = {k: v for k, v in row.items() if not k.startswith("_")}
            fh.write(json.dumps(clean, ensure_ascii=False) + "\n")
            count += 1
    return count


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")


def read_id_map(path: Path) -> dict[str, str]:
    obj = json.loads(path.read_text(encoding="utf-8"))
    items = obj.get("items")
    if not isinstance(items, list):
        raise ValueError(f"id map missing items list: {path}")
    mapping: dict[str, str] = {}
    duplicates: list[str] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        masked = item.get("masked")
        original = item.get("original")
        if not isinstance(masked, str) or not isinstance(original, str):
            continue
        if masked in mapping and mapping[masked] != original:
            duplicates.append(masked)
        mapping[masked] = original
    if duplicates:
        raise ValueError(f"id map contains duplicate masked ids with different originals: {path}: {duplicates[:10]}")
    return mapping


def load_id_maps(id_map_dir: Path) -> dict[str, dict[str, str]]:
    return {
        "scenario_id": read_id_map(id_map_dir / "scenario_id_map.json"),
        "sample_id": read_id_map(id_map_dir / "sample_id_map.json"),
        "edge_id": read_id_map(id_map_dir / "edge_id_map.json"),
    }


def reverse_id_maps(id_maps: dict[str, dict[str, str]]) -> dict[str, dict[str, str]]:
    return {
        map_name: {original: masked for masked, original in mapping.items()}
        for map_name, mapping in id_maps.items()
    }


def remap_ids(obj: Any, id_maps: dict[str, dict[str, str]]) -> Any:
    if isinstance(obj, dict):
        remapped: JsonObj = {}
        for key, value in obj.items():
            if key in id_maps and isinstance(value, str):
                remapped[key] = id_maps[key].get(value, value)
            elif key in {"start_edge_id", "end_edge_id", "attach_to_backbone_edge_id"} and isinstance(value, str):
                remapped[key] = id_maps["edge_id"].get(value, value)
            else:
                remapped[key] = remap_ids(value, id_maps)
        return remapped
    if isinstance(obj, list):
        return [remap_ids(item, id_maps) for item in obj]
    return obj


def collect_id_values(obj: Any, field_names: set[str]) -> set[str]:
    values: set[str] = set()
    if isinstance(obj, dict):
        for key, value in obj.items():
            if key in field_names and isinstance(value, str):
                values.add(value)
            values.update(collect_id_values(value, field_names))
    elif isinstance(obj, list):
        for item in obj:
            values.update(collect_id_values(item, field_names))
    return values


def collect_prompt_edge_ids(prompt_row: JsonObj) -> set[str]:
    prompt_input = prompt_row.get("prompt_input")
    if not isinstance(prompt_input, dict):
        prompt_input = extract_user_input(str(prompt_row.get("user", "")))
    ids = collect_id_values(
        {
            "prompt_input": prompt_input,
            "expected_output_schema": prompt_row.get("expected_output_schema"),
            "user": prompt_row.get("user"),
        },
        {"edge_id", "start_edge_id", "end_edge_id", "attach_to_backbone_edge_id"},
    )
    return {edge_id for edge_id in ids if edge_id.startswith("edge_m_")}


def unmask_patch(parsed: JsonObj, id_maps: dict[str, dict[str, str]]) -> tuple[JsonObj, list[str]]:
    errors: list[str] = []
    sample_id = parsed.get("sample_id")
    if isinstance(sample_id, str) and sample_id.startswith("sample_m_"):
        if sample_id not in id_maps["sample_id"]:
            errors.append(f"unknown_masked_sample_id:{sample_id}")
    for edge_id in sorted(collect_id_values(parsed, {"edge_id", "start_edge_id", "end_edge_id", "attach_to_backbone_edge_id"})):
        if edge_id.startswith("edge_m_") and edge_id not in id_maps["edge_id"]:
            errors.append(f"unknown_masked_edge_id:{edge_id}")
    return remap_ids(parsed, id_maps), errors


def extract_json(raw: str) -> JsonObj | None:
    text = raw.strip()
    text = re.sub(r"^```(?:json)?\s*", "", text)
    text = re.sub(r"\s*```$", "", text).strip()
    try:
        obj = json.loads(text)
        return obj if isinstance(obj, dict) else None
    except json.JSONDecodeError:
        pass
    start = text.find("{")
    if start < 0:
        return None
    decoder = json.JSONDecoder()
    try:
        obj, _ = decoder.raw_decode(text[start:])
    except json.JSONDecodeError:
        return None
    return obj if isinstance(obj, dict) else None


def legal_refs_from_gold(gold_row: JsonObj) -> set[tuple[int | None, str | None]]:
    refs: set[tuple[int | None, str | None]] = set()
    for item in ((gold_row.get("label") or {}).get("edge_stage_projection") or []):
        seq = coerce_int(item.get("seq"))
        edge_id = str(item.get("edge_id")) if item.get("edge_id") is not None else None
        refs.add((seq, edge_id))
    return refs


def coerce_int(value: Any) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def validate_chain(chain: Any, legal_refs: set[tuple[int | None, str | None]], gold_stage: str) -> list[str]:
    errors: list[str] = []
    if not isinstance(chain, list):
        return ["gold_reasoning_chain_not_list"]
    steps = [entry.get("step") for entry in chain if isinstance(entry, dict)]
    missing = [step for step in REQUIRED_STEPS if step not in steps]
    extra = [step for step in steps if step not in REQUIRED_STEPS]
    if missing:
        errors.append("missing_steps:" + ",".join(missing))
    if extra:
        errors.append("unknown_steps:" + ",".join(str(step) for step in extra))

    for entry in chain:
        if not isinstance(entry, dict):
            errors.append("chain_entry_not_object")
            continue
        step = entry.get("step")
        claim = entry.get("claim")
        if not isinstance(claim, str) or not claim.strip():
            errors.append(f"missing_claim:{step}")
        refs = entry.get("evidence_refs")
        if not isinstance(refs, list):
            errors.append(f"evidence_refs_not_list:{step}")
            continue
        if step != "final_judgement" and not refs:
            errors.append(f"empty_evidence_refs:{step}")
        if step == "final_judgement":
            if gold_stage not in str(claim).lower():
                errors.append("final_judgement_missing_gold_stage")
            if not refs:
                errors.append("final_judgement_missing_primary_evidence_ref")
        for ref in refs:
            if not isinstance(ref, dict):
                errors.append(f"evidence_ref_not_object:{step}")
                continue
            seq = coerce_int(ref.get("seq"))
            if ref.get("seq") is not None and seq is None:
                errors.append(f"invalid_ref_seq:{step}:{ref.get('seq')}")
                continue
            edge_id = str(ref.get("edge_id")) if ref.get("edge_id") is not None else None
            if (seq, edge_id) not in legal_refs and not any(
                (seq is not None and seq == legal_seq) or (edge_id is not None and edge_id == legal_edge)
                for legal_seq, legal_edge in legal_refs
            ):
                errors.append(f"illegal_evidence_ref:{step}:{seq}:{edge_id}")

    for entry in chain:
        if not isinstance(entry, dict):
            continue
        text = json.dumps(entry, ensure_ascii=False)
        for field_name, pattern in LEAKED_FIELD_PATTERNS:
            if pattern.search(text):
                errors.append(f"leaked_field_in_reasoning:{field_name}:{entry.get('step')}")
    return errors


def sanitize_reasoning_chain(chain: Any) -> Any:
    if not isinstance(chain, list):
        return chain
    sanitized: list[Any] = []
    for entry in chain:
        if not isinstance(entry, dict):
            sanitized.append(entry)
            continue
        clean_entry: JsonObj = {
            key: entry.get(key)
            for key in STRICT_CHAIN_ENTRY_FIELDS
            if key in entry
        }
        refs = entry.get("evidence_refs")
        if isinstance(refs, list):
            clean_refs: list[Any] = []
            for ref in refs:
                if not isinstance(ref, dict):
                    clean_refs.append(ref)
                    continue
                clean_refs.append(
                    {
                        key: ref.get(key)
                        for key in STRICT_EVIDENCE_REF_FIELDS
                        if key in ref
                    }
                )
            clean_entry["evidence_refs"] = clean_refs
        sanitized.append(clean_entry)
    return sanitized


def sanitize_candidate_auxiliary_note(note: Any) -> Any:
    if not isinstance(note, dict):
        return note
    clean: JsonObj = {}
    if "claim" in note:
        clean["claim"] = note.get("claim")
    clean["not_for_scoring"] = True
    return clean


def forbidden_strict_chain_errors(chain: Any) -> list[str]:
    if not isinstance(chain, list):
        return []
    errors: list[str] = []
    for entry in chain:
        if not isinstance(entry, dict):
            continue
        step = str(entry.get("step"))
        claim = entry.get("claim")
        if not isinstance(claim, str):
            continue
        matched_spans: list[tuple[int, int]] = []
        for term, pattern in VALIDATION_FORBIDDEN_STRICT_TERMS:
            for match in pattern.finditer(claim):
                span = match.span()
                if any(span[0] < existing_end and existing_start < span[1] for existing_start, existing_end in matched_spans):
                    continue
                matched_spans.append(span)
                errors.append(f"forbidden_strict_chain_term:{term}:{step}")
                break
    return errors


def auxiliary_note_forbidden_hits(note: Any) -> list[JsonObj]:
    if not isinstance(note, dict):
        return []
    text = json.dumps(note, ensure_ascii=False)
    hits: list[JsonObj] = []
    for term, pattern in VALIDATION_FORBIDDEN_STRICT_TERMS:
        if pattern.search(text):
            hits.append({"term": term})
    return hits


def forbidden_error_terms(errors: Iterable[str]) -> list[str]:
    terms: list[str] = []
    for error in errors:
        if not error.startswith("forbidden_strict_chain_term:"):
            continue
        parts = error.split(":", 2)
        if len(parts) >= 2:
            terms.append(parts[1])
    return terms


def forbidden_invalid_summary(rows: Iterable[JsonObj]) -> JsonObj:
    invalid_rows = [
        row for row in rows
        if any(str(error).startswith("forbidden_strict_chain_term:") for error in row.get("errors", []))
    ]
    term_counter = Counter(
        term
        for row in invalid_rows
        for term in forbidden_error_terms(str(error) for error in row.get("errors", []))
    )
    return {
        "forbidden_strict_chain_invalid_count": len(invalid_rows),
        "forbidden_strict_chain_terms": dict(term_counter),
    }


def validate_patch_note(note: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(note, dict):
        return ["auxiliary_vulnerability_note_not_object"]
    if note.get("not_for_scoring") is not True:
        errors.append("auxiliary_vulnerability_note_not_for_scoring_not_true")
    return errors


def normalize_json_text(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True).lower()


def extract_user_input(prompt_user: str) -> JsonObj | None:
    marker = "## Input"
    schema_marker = "## Required output schema"
    idx = prompt_user.find(marker)
    if idx < 0:
        return None
    start = prompt_user.find("{", idx + len(marker))
    if start < 0:
        return None
    end_limit = prompt_user.find(schema_marker, start)
    snippet = prompt_user[start:] if end_limit < 0 else prompt_user[start:end_limit]
    decoder = json.JSONDecoder()
    try:
        obj, _ = decoder.raw_decode(snippet)
    except json.JSONDecodeError:
        return None
    return obj if isinstance(obj, dict) else None


def iter_possible_edges(obj: Any) -> Iterable[JsonObj]:
    if isinstance(obj, dict):
        if "seq" in obj and "edge_id" in obj:
            yield obj
        for key in ("spine_summary", "spine", "window", "edge_stage_projection", "primary_evidence"):
            value = obj.get(key)
            if isinstance(value, list):
                for item in value:
                    yield from iter_possible_edges(item)
            elif isinstance(value, dict):
                yield from iter_possible_edges(value)
        for key in ("label", "input", "multisource_context", "audit_context"):
            value = obj.get(key)
            if isinstance(value, dict):
                yield from iter_possible_edges(value)
    elif isinstance(obj, list):
        for item in obj:
            yield from iter_possible_edges(item)


def build_ref_texts(*sources: Any) -> dict[tuple[int | None, str | None], str]:
    refs: dict[tuple[int | None, str | None], list[str]] = {}
    for source in sources:
        for edge in iter_possible_edges(source):
            seq = coerce_int(edge.get("seq"))
            edge_id = str(edge.get("edge_id")) if edge.get("edge_id") is not None else None
            text = normalize_json_text(edge)
            for key in ((seq, edge_id), (seq, None), (None, edge_id)):
                refs.setdefault(key, []).append(text)
    return {key: "\n".join(dict.fromkeys(values)) for key, values in refs.items()}


def ref_key(ref: JsonObj) -> tuple[int | None, str | None]:
    return coerce_int(ref.get("seq")), str(ref.get("edge_id")) if ref.get("edge_id") is not None else None


def ref_exists(key: tuple[int | None, str | None], ref_texts: dict[tuple[int | None, str | None], str]) -> bool:
    seq, edge_id = key
    return key in ref_texts or (seq, None) in ref_texts or (None, edge_id) in ref_texts


def combined_ref_text(refs: list[Any], ref_texts: dict[tuple[int | None, str | None], str]) -> str:
    chunks: list[str] = []
    for ref in refs:
        if not isinstance(ref, dict):
            continue
        seq, edge_id = ref_key(ref)
        for key in ((seq, edge_id), (seq, None), (None, edge_id)):
            if key in ref_texts:
                chunks.append(ref_texts[key])
    return "\n".join(dict.fromkeys(chunks))


def extract_terms(text: str, terms: list[tuple[str, re.Pattern[str]]]) -> list[str]:
    return [term for term, pattern in terms if pattern.search(text)]


def audit_grounding(
    patch_rows: list[JsonObj],
    prompts_by_id: dict[str, JsonObj],
    model_by_id: dict[str, JsonObj],
    gold_by_id: dict[str, JsonObj],
    index_by_id: dict[str, JsonObj],
) -> tuple[list[JsonObj], JsonObj]:
    cases: list[JsonObj] = []
    for patch in patch_rows:
        sample_id = str(patch.get("sample_id"))
        prompt_row = prompts_by_id.get(sample_id, {})
        prompt_input = extract_user_input(str(prompt_row.get("user", "")))
        model_row = model_by_id.get(sample_id, {})
        gold_row = gold_by_id.get(sample_id, {})
        index_row = index_by_id.get(sample_id, {})
        stage = str(patch.get("gold_stage") or prompt_row.get("gold_stage") or index_row.get("stage") or (gold_row.get("label") or {}).get("stage") or "unknown")
        scenario_id = str(prompt_row.get("scenario_id") or model_row.get("scenario_id") or gold_row.get("scenario_id") or index_row.get("scenario_id") or "")
        ref_texts = build_ref_texts(prompt_input, model_row, gold_row)
        all_input_text = normalize_json_text({"prompt_input": prompt_input, "model_input": model_row})
        scenario_text = f"{sample_id} {scenario_id}".lower()
        checks: list[JsonObj] = []
        for entry in patch.get("gold_reasoning_chain") if isinstance(patch.get("gold_reasoning_chain"), list) else []:
            if not isinstance(entry, dict):
                continue
            refs = entry.get("evidence_refs") if isinstance(entry.get("evidence_refs"), list) else []
            keys = [ref_key(ref) for ref in refs if isinstance(ref, dict)]
            missing_refs = [key for key in keys if not ref_exists(key, ref_texts)]
            claim = str(entry.get("claim", ""))
            evidence_text = combined_ref_text(refs, ref_texts).lower()
            forbidden_hits = extract_terms(claim, FORBIDDEN_STRICT_TERMS)
            vuln_terms = extract_terms(claim, VULNERABILITY_TERMS)
            cve_only_terms = [
                term for term in vuln_terms
                if term != "CVE" and term.lower() not in all_input_text and term.lower() in scenario_text
            ]
            grounded = not missing_refs and not forbidden_hits and not cve_only_terms
            checks.append({
                "step": entry.get("step"),
                "claim": claim,
                "evidence_refs": refs,
                "grounded_in_input": grounded,
                "possible_hallucination": not grounded,
                "forbidden_hits": forbidden_hits,
                "cve_only_terms_in_strict_chain": cve_only_terms,
                "evidence_text_present": bool(evidence_text),
                "notes": [] if grounded else [
                    *(["missing evidence refs: " + repr(missing_refs)] if missing_refs else []),
                    *(["forbidden terms: " + ", ".join(forbidden_hits)] if forbidden_hits else []),
                    *(["CVE-only strict-chain terms: " + ", ".join(cve_only_terms)] if cve_only_terms else []),
                ],
            })
        hallucinated = sum(1 for check in checks if check["possible_hallucination"])
        if hallucinated >= 2:
            overall = "risky"
        elif hallucinated == 1:
            overall = "weak"
        elif patch.get("patch_valid") is False:
            overall = "invalid"
        else:
            overall = "strong"
        cases.append({
            "sample_id": sample_id,
            "scenario_id": scenario_id,
            "stage": stage,
            "patch_valid": patch.get("patch_valid"),
            "overall_grounding": overall,
            "claim_checks": checks,
            "manual_review_recommended": overall in {"weak", "risky", "invalid"},
        })
    report = {
        "counts": {
            "patch_rows": len(patch_rows),
            "cases": len(cases),
            "by_overall_grounding": dict(Counter(case["overall_grounding"] for case in cases)),
            "forbidden_hits": dict(Counter(hit for case in cases for check in case["claim_checks"] for hit in check["forbidden_hits"])),
            "cve_only_strict_chain_hits": sum(
                1 for case in cases for check in case["claim_checks"] if check["cve_only_terms_in_strict_chain"]
            ),
            "manual_review_samples": sum(1 for case in cases if case["manual_review_recommended"]),
        },
        "manual_review_sample_ids": [case["sample_id"] for case in cases if case["manual_review_recommended"]],
    }
    return cases, report


def build_messages(prompt_row: JsonObj) -> list[JsonObj]:
    messages: list[JsonObj] = []
    system = prompt_row.get("system")
    if isinstance(system, str) and system.strip():
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": str(prompt_row.get("user", ""))})
    return messages


def build_responses_input(prompt_row: JsonObj) -> str:
    messages = build_messages(prompt_row)
    chunks: list[str] = []
    for message in messages:
        role = str(message.get("role", "user")).upper()
        content = str(message.get("content", ""))
        chunks.append(f"{role}:\n{content}")
    return "\n\n".join(chunks)


def prompt_length_summary(prompt_row: JsonObj) -> JsonObj:
    system = str(prompt_row.get("system", "") or "")
    user = str(prompt_row.get("user", "") or "")
    return {
        "system_prompt_len": len(system),
        "user_prompt_len": len(user),
        "total_prompt_len": len(system) + len(user),
    }


def prompt_excerpt_summary(prompt_row: JsonObj, limit: int = 500) -> JsonObj:
    system = str(prompt_row.get("system", "") or "")
    user = str(prompt_row.get("user", "") or "")
    user_head = user[:limit]
    user_tail = user[-limit:] if len(user) > limit else user
    system_head = system[:limit]
    system_tail = system[-limit:] if len(system) > limit else system
    return {
        "system_excerpt_head": system_head,
        "system_excerpt_tail": system_tail,
        "user_excerpt_head": user_head,
        "user_excerpt_tail": user_tail,
    }


def call_anthropic(
    prompt_row: JsonObj,
    *,
    api_key: str,
    model: str,
    max_tokens: int,
    timeout: float,
    max_retries: int,
) -> JsonObj:
    try:
        from anthropic import Anthropic
    except ImportError:
        return {"error": "anthropic package not installed – pip install anthropic"}

    client = Anthropic(api_key=api_key, timeout=timeout)
    messages = build_messages(prompt_row)
    system_parts = [message["content"] for message in messages if message["role"] == "system"]
    user_messages = [message for message in messages if message["role"] != "system"]
    last_exc: Exception | None = None
    for attempt in range(1, max_retries + 2):
        try:
            kwargs: JsonObj = {
                "model": model,
                "max_tokens": max_tokens,
                "messages": user_messages,
            }
            if system_parts:
                kwargs["system"] = "\n\n".join(system_parts)
            if model == "claude-opus-4-7":
                kwargs["thinking"] = {"type": "adaptive"}
                kwargs["output_config"] = {
                    "effort": "high",
                    "format": {"type": "json_object"},
                }
            else:
                kwargs["output_config"] = {"format": {"type": "json_object"}}
            response = client.messages.create(**kwargs)
            raw_content = "".join(
                block.text for block in response.content if getattr(block, "type", None) == "text"
            )
            return {
                "raw_content": raw_content,
                "provider": "anthropic",
                "model": response.model,
                "usage": {
                    "input_tokens": response.usage.input_tokens if response.usage else None,
                    "output_tokens": response.usage.output_tokens if response.usage else None,
                },
                "attempt": attempt,
            }
        except Exception as exc:
            last_exc = exc
            if attempt <= max_retries:
                time.sleep(2 ** attempt)
    return {"error": str(last_exc), "traceback": traceback.format_exc()}


def call_openai_compatible(
    prompt_row: JsonObj,
    *,
    api_key: str,
    base_url: str,
    model: str,
    api_mode: str,
    temperature: float,
    max_tokens: int,
    timeout: float,
    max_retries: int,
) -> JsonObj:
    try:
        from openai import OpenAI
    except ImportError:
        return {"error": "openai package not installed – pip install openai"}

    client = OpenAI(api_key=api_key, base_url=base_url, timeout=timeout)
    messages = build_messages(prompt_row)
    responses_input = build_responses_input(prompt_row)
    prompt_lengths = prompt_length_summary(prompt_row)
    last_exc: Exception | None = None
    last_traceback = ""

    def _response_to_dict(response: Any) -> JsonObj | None:
        if response is None:
            return None
        if isinstance(response, dict):
            return response
        model_dump = getattr(response, "model_dump", None)
        if callable(model_dump):
            try:
                dumped = model_dump()
            except Exception:
                dumped = None
            if isinstance(dumped, dict):
                return dumped
        to_dict = getattr(response, "to_dict", None)
        if callable(to_dict):
            try:
                dumped = to_dict()
            except Exception:
                dumped = None
            if isinstance(dumped, dict):
                return dumped
        return None

    def _truncate(value: Any, limit: int = 500) -> str:
        text = str(value)
        return text if len(text) <= limit else text[: limit - 3] + "..."

    def _safe_getattr(value: Any, name: str, default: Any = None) -> Any:
        try:
            return getattr(value, name, default)
        except Exception:
            return default

    def _is_transient_retryable_exception(exc: Exception) -> bool:
        error_name = exc.__class__.__name__.lower()
        error_text = str(exc).lower()
        joined = f"{error_name} {error_text}"
        transient_terms = (
            "connection error",
            "connect error",
            "apiconnectionerror",
            "api_connection_error",
            "timeout",
            "timed out",
            "readtimeout",
            "connecttimeout",
            "remoteprotocolerror",
            "server disconnected",
            "temporarily unavailable",
            "service unavailable",
            "bad gateway",
            "gateway timeout",
            "rate limit",
            "429",
        )
        return any(term in joined for term in transient_terms)

    def _content_from_message(message: Any) -> str:
        if message is None:
            return ""
        content = getattr(message, "content", None)
        if isinstance(content, str):
            return content
        if isinstance(content, list):
            text_parts: list[str] = []
            for item in content:
                if isinstance(item, str):
                    text_parts.append(item)
                elif isinstance(item, dict):
                    text = item.get("text")
                    if isinstance(text, str):
                        text_parts.append(text)
                else:
                    text = getattr(item, "text", None)
                    if isinstance(text, str):
                        text_parts.append(text)
            if text_parts:
                return "\n".join(text_parts)
        for alt_name in ("reasoning_content", "refusal"):
            alt_value = getattr(message, alt_name, None)
            if isinstance(alt_value, str) and alt_value.strip():
                return alt_value
        tool_calls = getattr(message, "tool_calls", None)
        if tool_calls:
            return json.dumps({"tool_calls_present": True}, ensure_ascii=False)
        return ""

    def _content_from_responses_output(response: Any, response_dict: JsonObj | None) -> str:
        if isinstance(response, str) and response.strip():
            return response
        if isinstance(response_dict, dict):
            output_text = response_dict.get("output_text")
            if isinstance(output_text, str) and output_text.strip():
                return output_text
            if isinstance(response_dict.get("text"), str) and response_dict.get("text", "").strip():
                return str(response_dict.get("text"))
            if isinstance(response_dict.get("content"), str) and response_dict.get("content", "").strip():
                return str(response_dict.get("content"))
        output_text = _safe_getattr(response, "output_text")
        if isinstance(output_text, str) and output_text.strip():
            return output_text

        output = _safe_getattr(response, "output")
        if output is None and isinstance(response_dict, dict):
            output = response_dict.get("output")
        if isinstance(output, list):
            text_parts: list[str] = []
            for item in output:
                item_type = item.get("type") if isinstance(item, dict) else getattr(item, "type", None)
                if item_type == "output_text":
                    text = item.get("text") if isinstance(item, dict) else getattr(item, "text", None)
                    if isinstance(text, str) and text.strip():
                        text_parts.append(text)
                content_items = item.get("content") if isinstance(item, dict) else getattr(item, "content", None)
                if isinstance(content_items, list):
                    for content_item in content_items:
                        content_type = content_item.get("type") if isinstance(content_item, dict) else getattr(content_item, "type", None)
                        text = content_item.get("text") if isinstance(content_item, dict) else getattr(content_item, "text", None)
                        if content_type == "output_text" and isinstance(text, str) and text.strip():
                            text_parts.append(text)
            if text_parts:
                return "\n".join(text_parts)
        return ""

    for attempt in range(1, max_retries + 2):
        started_at = time.monotonic()
        try:
            if api_mode == "responses":
                response = client.responses.create(
                    model=model,
                    input=responses_input,
                    max_output_tokens=max_tokens,
                    timeout=timeout,
                    store=False,
                )
            else:
                response = client.chat.completions.create(
                    model=model,
                    messages=messages,
                    temperature=temperature,
                    max_tokens=max_tokens,
                    response_format={"type": "json_object"},
                    timeout=timeout,
                )
            response_dict = _response_to_dict(response)
            if api_mode == "responses":
                content = _content_from_responses_output(response, response_dict)
                if not content:
                    response_output_text = _safe_getattr(response, "output_text")
                    response_output = _safe_getattr(response, "output")
                    schema_summary = {
                        "response_type": type(response).__name__,
                        "response_keys": sorted(response_dict.keys()) if isinstance(response_dict, dict) else [],
                        "response_is_string": isinstance(response, str),
                        "output_text_present": bool(
                            response_output_text
                            or (response_dict.get("output_text") if isinstance(response_dict, dict) else "")
                        ),
                        "output_type": type(response_output).__name__ if response_output is not None else (
                            type(response_dict.get("output")).__name__ if isinstance(response_dict, dict) and response_dict.get("output") is not None else "NoneType"
                        ),
                    }
                    provider_error = ""
                    if isinstance(response_dict, dict):
                        provider_error = _truncate(response_dict.get("error") or response_dict.get("msg") or "")
                    return {
                        "error": "provider_response_missing_output_text",
                        "provider_error": provider_error,
                        "response_schema_summary": schema_summary,
                        "response_excerpt": _truncate(response_dict if response_dict is not None else response),
                        "attempt": attempt,
                    }
                return {
                    "raw_content": content,
                    "provider": "openai-compatible",
                    "model": getattr(response, "model", None) or (response_dict.get("model") if isinstance(response_dict, dict) else model),
                    "usage": {
                        "prompt_tokens": getattr(getattr(response, "usage", None), "input_tokens", None) if getattr(response, "usage", None) else (
                            (response_dict.get("usage") or {}).get("input_tokens") if isinstance(response_dict, dict) and isinstance(response_dict.get("usage"), dict) else None
                        ),
                        "completion_tokens": getattr(getattr(response, "usage", None), "output_tokens", None) if getattr(response, "usage", None) else (
                            (response_dict.get("usage") or {}).get("output_tokens") if isinstance(response_dict, dict) and isinstance(response_dict.get("usage"), dict) else None
                        ),
                    },
                    "attempt": attempt,
                }
            choices = getattr(response, "choices", None)
            if choices is None and isinstance(response_dict, dict):
                choices = response_dict.get("choices")
            if not choices:
                schema_summary = {
                    "response_type": type(response).__name__,
                    "response_keys": sorted(response_dict.keys()) if isinstance(response_dict, dict) else [],
                    "choices_present": choices is not None,
                    "choices_type": type(choices).__name__ if choices is not None else "NoneType",
                    "has_error": isinstance(response_dict, dict) and ("error" in response_dict),
                    "error_preview": _truncate(response_dict.get("error")) if isinstance(response_dict, dict) else "",
                }
                return {
                    "error": "provider_response_missing_choices",
                    "provider_error": _truncate(response_dict.get("error")) if isinstance(response_dict, dict) else "",
                    "response_schema_summary": schema_summary,
                    "response_excerpt": _truncate(response_dict) if response_dict is not None else "",
                    "attempt": attempt,
                }

            first_choice = choices[0]
            message = getattr(first_choice, "message", None)
            if message is None and isinstance(first_choice, dict):
                message = first_choice.get("message")
            content = _content_from_message(message)
            if not content and isinstance(first_choice, dict):
                msg_dict = first_choice.get("message") if isinstance(first_choice.get("message"), dict) else {}
                for alt_name in ("content", "reasoning_content", "refusal"):
                    alt_value = msg_dict.get(alt_name)
                    if isinstance(alt_value, str) and alt_value.strip():
                        content = alt_value
                        break
            if not content:
                schema_summary = {
                    "response_type": type(response).__name__,
                    "response_keys": sorted(response_dict.keys()) if isinstance(response_dict, dict) else [],
                    "choice_type": type(first_choice).__name__,
                    "message_present": message is not None,
                    "message_type": type(message).__name__ if message is not None else "NoneType",
                    "message_keys": sorted(message.keys()) if isinstance(message, dict) else [],
                }
                return {
                    "error": "provider_response_missing_message_content",
                    "response_schema_summary": schema_summary,
                    "response_excerpt": _truncate(response_dict) if response_dict is not None else "",
                    "attempt": attempt,
                }
            return {
                "raw_content": content,
                "provider": "openai-compatible",
                "model": response.model,
                "usage": {
                    "prompt_tokens": response.usage.prompt_tokens if response.usage else None,
                    "completion_tokens": response.usage.completion_tokens if response.usage else None,
                },
                "attempt": attempt,
            }
        except Exception as exc:
            last_exc = exc
            last_traceback = traceback.format_exc()
            elapsed = round(time.monotonic() - started_at, 3)
            error_name = exc.__class__.__name__
            error_text = str(exc)
            is_timeout = (
                "timeout" in error_name.lower()
                or "timed out" in error_text.lower()
                or "readtimeout" in error_name.lower()
            )
            retryable = _is_transient_retryable_exception(exc)
            if is_timeout and attempt > max_retries:
                return {
                    "error": "request_timeout",
                    "error_type": "request_timeout",
                    "provider_error": error_text,
                    "traceback": last_traceback,
                    "api_mode": api_mode,
                    "sample_id": str(prompt_row.get("sample_id") or ""),
                    "elapsed_seconds": elapsed,
                    "base_url": base_url,
                    "model": model,
                    "prompt_user_len": prompt_lengths["user_prompt_len"],
                    "prompt_system_len": prompt_lengths["system_prompt_len"],
                    "api_key_present": bool(api_key),
                    "attempt": attempt,
                }
            if retryable and attempt <= max_retries:
                time.sleep(2 ** attempt)
                continue
            if is_timeout:
                return {
                    "error": "request_timeout",
                    "error_type": "request_timeout",
                    "provider_error": error_text,
                    "traceback": last_traceback,
                    "api_mode": api_mode,
                    "sample_id": str(prompt_row.get("sample_id") or ""),
                    "elapsed_seconds": elapsed,
                    "base_url": base_url,
                    "model": model,
                    "prompt_user_len": prompt_lengths["user_prompt_len"],
                    "prompt_system_len": prompt_lengths["system_prompt_len"],
                    "api_key_present": bool(api_key),
                    "attempt": attempt,
                }
    return {"error": str(last_exc), "traceback": last_traceback}


def call_provider(
    prompt_row: JsonObj,
    *,
    provider: str,
    api_key: str,
    base_url: str,
    model: str,
    api_mode: str,
    temperature: float,
    max_tokens: int,
    timeout: float,
    max_retries: int,
) -> JsonObj:
    if provider == "anthropic":
        return call_anthropic(
            prompt_row,
            api_key=api_key,
            model=model,
            max_tokens=max_tokens,
            timeout=timeout,
            max_retries=max_retries,
        )
    return call_openai_compatible(
        prompt_row,
        api_key=api_key,
        base_url=base_url,
        model=model,
        api_mode=api_mode,
        temperature=temperature,
        max_tokens=max_tokens,
        timeout=timeout,
        max_retries=max_retries,
    )


def patched_gold_rows(gold_rows: list[JsonObj], valid_patches: dict[str, list[JsonObj]]) -> list[JsonObj]:
    patched: list[JsonObj] = []
    for row in gold_rows:
        clean = {k: v for k, v in row.items() if not k.startswith("_")}
        sample_id = clean["sample_id"]
        if sample_id in valid_patches:
            clean["gold_reasoning_chain"] = sanitize_reasoning_chain(valid_patches[sample_id])
        patched.append(clean)
    return patched


def summarize_chain(chain: Any) -> list[JsonObj] | None:
    if not isinstance(chain, list):
        return None
    return [
        {"step": entry.get("step", "?"), "claim": str(entry.get("claim", ""))[:300]}
        for entry in chain if isinstance(entry, dict)
    ]


def build_readme(provider: str, model: str) -> str:
    return "\n".join([
        "# EWVAA API Trial Balanced 10",
        "",
        "This directory contains a small EWVAA stage-reasoning annotation API trial generated from the balanced 10-prompt dry-run pack.",
        "",
        "Inputs are read-only benchmark/prompt files. The original gold.jsonl, model_input.jsonl, sample_index.jsonl, raw logs, and release structures are not overwritten.",
        "",
        f"Provider: {provider}",
        f"Model: {model}",
        "",
        "Default provider: openai-compatible. Anthropic remains available only when explicitly selected with --provider anthropic.",
        "API credentials are read only from provider environment variables and are not written to this directory.",
        "For the default OpenAI-compatible run on Windows, set OPENAI_API_KEY, OPENAI_BASE_URL, and OPENAI_MODEL in CMD or PowerShell before running.",
        "",
        "Outputs:",
        "- raw_api_responses.jsonl",
        "- reasoning_patches.jsonl",
        "- patched_gold.jsonl",
        "- patch_validation_report.json",
        "- grounding_audit_report.json",
        "- grounding_audit_cases.jsonl",
        "- ewvaa_trial_report.json",
        "- run_config.json",
        "",
    ])


def build_masked_dryrun_readme(report: JsonObj) -> str:
    counts = report.get("counts", {})
    return "\n".join([
        "# EWVAA Masked Workbench Dry-Run",
        "",
        "This directory contains a dry-run unmask validation for masked workbench v1.",
        "",
        "No API calls were made. Benchmark source files were read only and not modified.",
        "",
        f"Masked prompts read: {counts.get('masked_prompt_count')}",
        f"Mapped prompts: {counts.get('mapped_prompt_count')}",
        f"Unmapped sample IDs: {counts.get('unmapped_sample_id_count')}",
        f"Unmapped edge IDs: {counts.get('unmapped_edge_id_count')}",
        f"Canonical edge validation errors: {counts.get('canonical_edge_validation_error_count')}",
        f"Masked prompt metadata leakage findings: {counts.get('masked_prompt_metadata_leakage_count')}",
        "",
        "Outputs:",
        "- unmask_dryrun_report.json",
        "- README.md",
        "",
    ])


def metadata_leakage_patterns() -> list[tuple[str, re.Pattern[str]]]:
    return [
        ("cve_id", re.compile(r"\bCVE-\d{4}-\d+\b", re.IGNORECASE)),
        ("rce_token", re.compile(r"\bRCE\b", re.IGNORECASE)),
        ("xxe_token", re.compile(r"\bXXE\b", re.IGNORECASE)),
        ("vulhub_token", re.compile(r"\bvulhub\b", re.IGNORECASE)),
    ]


def find_masked_prompt_metadata_leakage(
    prompt_row: JsonObj,
    canonical_sample_id: str | None,
    canonical_scenario_id: str | None,
    canonical_edge_ids: set[str],
) -> list[JsonObj]:
    text = json.dumps(prompt_row, ensure_ascii=False)
    findings: list[JsonObj] = []
    for label, value in (
        ("canonical_sample_id", canonical_sample_id),
        ("canonical_scenario_id", canonical_scenario_id),
    ):
        if value and value in text:
            findings.append({"type": label, "value": value})
    for edge_id in sorted(canonical_edge_ids):
        if edge_id and edge_id in text:
            findings.append({"type": "canonical_edge_id", "value": edge_id})
    for name, pattern in metadata_leakage_patterns():
        if pattern.search(text):
            findings.append({"type": name, "value": pattern.pattern})
    return findings


def run_dry_run_unmask(args: argparse.Namespace) -> int:
    if args.masked_workbench_dir is None:
        print("ERROR: --dry-run-unmask requires --masked-workbench-dir", file=sys.stderr)
        return 2

    id_map_dir = args.metadata_id_map_dir or args.masked_workbench_dir / "id_maps"
    masked_prompts_path = args.annotation_prompts or args.masked_workbench_dir / "prompt_packs" / "annotation_prompts.weighted.masked.jsonl"
    output_dir = args.output_dir or DEFAULT_MASKED_DRYRUN_OUTPUT_DIR
    gold_path = args.gold or DEFAULT_CANONICAL_BENCHMARK_DIR / "gold.jsonl"
    model_input_path = args.model_input or DEFAULT_CANONICAL_BENCHMARK_DIR / "model_input.jsonl"
    sample_index_path = args.sample_index or DEFAULT_CANONICAL_BENCHMARK_DIR / "sample_index.jsonl"

    prompts = read_jsonl(masked_prompts_path)[: args.limit]
    id_maps = load_id_maps(id_map_dir)
    gold_rows = read_jsonl(gold_path)
    model_rows = read_jsonl(model_input_path)
    index_rows = read_jsonl(sample_index_path)
    gold_by_id = {row["sample_id"]: row for row in gold_rows}
    model_by_id = {row["sample_id"]: row for row in model_rows}
    index_by_id = {row["sample_id"]: row for row in index_rows}

    unmapped_sample_ids: list[str] = []
    unmapped_edge_ids: set[str] = set()
    missing_canonical_samples: list[str] = []
    prompt_input_parse_failures: list[str] = []
    canonical_edge_validation_errors: list[JsonObj] = []
    masked_prompt_metadata_leakage: list[JsonObj] = []
    mapped_cases: list[JsonObj] = []

    for prompt_row in prompts:
        masked_sample_id = str(prompt_row.get("sample_id", ""))
        masked_scenario_id = str(prompt_row.get("scenario_id", ""))
        prompt_input = prompt_row.get("prompt_input")
        if not isinstance(prompt_input, dict):
            prompt_input = extract_user_input(str(prompt_row.get("user", "")))
        if not isinstance(prompt_input, dict):
            prompt_input_parse_failures.append(masked_sample_id)

        canonical_sample_id = id_maps["sample_id"].get(masked_sample_id)
        canonical_scenario_id = id_maps["scenario_id"].get(masked_scenario_id)
        if canonical_sample_id is None:
            unmapped_sample_ids.append(masked_sample_id)
            continue
        if canonical_sample_id not in gold_by_id or canonical_sample_id not in model_by_id or canonical_sample_id not in index_by_id:
            missing_canonical_samples.append(canonical_sample_id)

        masked_edge_ids = collect_prompt_edge_ids(prompt_row)
        canonical_edge_ids: set[str] = set()
        for masked_edge_id in sorted(masked_edge_ids):
            canonical_edge_id = id_maps["edge_id"].get(masked_edge_id)
            if canonical_edge_id is None:
                unmapped_edge_ids.add(masked_edge_id)
            else:
                canonical_edge_ids.add(canonical_edge_id)

        model_text = normalize_json_text(model_by_id.get(canonical_sample_id, {}).get("input", {}))
        for masked_edge_id, canonical_edge_id in sorted(
            (masked_edge_id, id_maps["edge_id"].get(masked_edge_id))
            for masked_edge_id in masked_edge_ids
        ):
            if canonical_edge_id is None:
                continue
            if canonical_edge_id.lower() not in model_text:
                canonical_edge_validation_errors.append({
                    "masked_sample_id": masked_sample_id,
                    "canonical_sample_id": canonical_sample_id,
                    "masked_edge_id": masked_edge_id,
                    "canonical_edge_id": canonical_edge_id,
                    "error": "canonical_edge_not_found_in_model_input_primary_evidence",
                })

        leakage = find_masked_prompt_metadata_leakage(
            prompt_row,
            canonical_sample_id,
            canonical_scenario_id,
            canonical_edge_ids,
        )
        for finding in leakage:
            masked_prompt_metadata_leakage.append({
                "masked_sample_id": masked_sample_id,
                "canonical_sample_id": canonical_sample_id,
                **finding,
            })

        mapped_cases.append({
            "masked_sample_id": masked_sample_id,
            "canonical_sample_id": canonical_sample_id,
            "masked_scenario_id": masked_scenario_id,
            "canonical_scenario_id": canonical_scenario_id,
            "masked_edge_count": len(masked_edge_ids),
            "canonical_edge_count": len(canonical_edge_ids),
        })

    report: JsonObj = {
        "status": "success",
        "dry_run_unmask": True,
        "api_called": False,
        "inputs": {
            "masked_workbench_dir": str(args.masked_workbench_dir),
            "annotation_prompts": str(masked_prompts_path),
            "metadata_id_map_dir": str(id_map_dir),
            "gold": str(gold_path),
            "model_input": str(model_input_path),
            "sample_index": str(sample_index_path),
        },
        "outputs": {
            "unmask_dryrun_report": str(output_dir / "unmask_dryrun_report.json"),
            "readme": str(output_dir / "README.md"),
        },
        "counts": {
            "masked_prompt_count": len(prompts),
            "mapped_prompt_count": len(mapped_cases),
            "unmapped_sample_id_count": len(unmapped_sample_ids),
            "unmapped_edge_id_count": len(unmapped_edge_ids),
            "canonical_edge_validation_error_count": len(canonical_edge_validation_errors),
            "masked_prompt_metadata_leakage_count": len(masked_prompt_metadata_leakage),
            "prompt_input_parse_failure_count": len(prompt_input_parse_failures),
            "missing_canonical_sample_count": len(missing_canonical_samples),
        },
        "mapped_prompt_count": len(mapped_cases),
        "unmapped_sample_ids": unmapped_sample_ids,
        "unmapped_edge_ids": sorted(unmapped_edge_ids),
        "canonical_edge_validation_errors": canonical_edge_validation_errors,
        "masked_prompt_metadata_leakage": masked_prompt_metadata_leakage,
        "prompt_input_parse_failures": prompt_input_parse_failures,
        "missing_canonical_samples": missing_canonical_samples,
        "mapped_cases": mapped_cases,
        "boundaries": {
            "overwrote_gold": False,
            "modified_model_input": False,
            "modified_benchmark_inputs": False,
            "modified_raw_or_index_or_release_main_structure": False,
            "ran_exploit": False,
            "collected_cve_data_from_network": False,
            "api_called": False,
        },
    }
    if (
        len(prompts) != 10
        or unmapped_sample_ids
        or unmapped_edge_ids
        or canonical_edge_validation_errors
        or masked_prompt_metadata_leakage
        or prompt_input_parse_failures
        or missing_canonical_samples
    ):
        report["status"] = "failed"

    write_json(output_dir / "unmask_dryrun_report.json", report)
    (output_dir / "README.md").write_text(build_masked_dryrun_readme(report), encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report["status"] == "success" else 1


def run_revalidate_patches(args: argparse.Namespace) -> int:
    if args.revalidate_patches is None:
        print("ERROR: --revalidate-patches requires a patch JSONL path", file=sys.stderr)
        return 2
    if args.output_dir is None:
        print("ERROR: --revalidate-patches requires --output-dir", file=sys.stderr)
        return 2

    gold_path = args.gold or DEFAULT_CANONICAL_BENCHMARK_DIR / "gold.jsonl"
    model_input_path = args.model_input or DEFAULT_CANONICAL_BENCHMARK_DIR / "model_input.jsonl"
    sample_index_path = args.sample_index or DEFAULT_CANONICAL_BENCHMARK_DIR / "sample_index.jsonl"

    patch_input_rows = read_jsonl(args.revalidate_patches)[: args.limit]
    gold_rows = read_jsonl(gold_path)
    model_rows = read_jsonl(model_input_path)
    index_rows = read_jsonl(sample_index_path)
    prompt_rows = read_jsonl(args.annotation_prompts)[: args.limit] if args.annotation_prompts else []

    gold_by_id = {row["sample_id"]: row for row in gold_rows}
    model_by_id = {row["sample_id"]: row for row in model_rows}
    index_by_id = {row["sample_id"]: row for row in index_rows}
    prompts_by_id = {row["sample_id"]: row for row in prompt_rows}

    valid_rows: list[JsonObj] = []
    invalid_rows: list[JsonObj] = []
    validation_rows: list[JsonObj] = []
    valid_patches: dict[str, list[JsonObj]] = {}

    for patch in patch_input_rows:
        sample_id = str(patch.get("sample_id"))
        gold_row = gold_by_id.get(sample_id, {})
        gold_stage = str(
            patch.get("gold_stage")
            or (gold_row.get("label") or {}).get("stage")
            or index_by_id.get(sample_id, {}).get("stage")
            or ""
        )
        chain = sanitize_reasoning_chain(patch.get("gold_reasoning_chain"))
        note = patch.get("auxiliary_vulnerability_note")
        clean_note = sanitize_candidate_auxiliary_note(note)
        errors: list[str] = []
        if sample_id not in gold_by_id:
            errors.append("sample_id_missing_from_gold")
        else:
            errors.extend(validate_chain(chain, legal_refs_from_gold(gold_by_id[sample_id]), gold_stage))
        errors.extend(forbidden_strict_chain_errors(chain))
        errors.extend(validate_patch_note(note))
        auxiliary_forbidden_hits = auxiliary_note_forbidden_hits(note)
        patch_entry = {
            "sample_id": sample_id,
            "masked_sample_id": patch.get("masked_sample_id"),
            "gold_stage": gold_stage,
            "gold_reasoning_chain": chain,
            "auxiliary_vulnerability_note": clean_note,
            "auxiliary_forbidden_term_hits": auxiliary_forbidden_hits,
            "patch_valid": not errors,
        }
        validation_rows.append({
            "sample_id": sample_id,
            "masked_sample_id": patch.get("masked_sample_id"),
            "scenario_id": gold_row.get("scenario_id") or index_by_id.get(sample_id, {}).get("scenario_id"),
            "gold_stage": gold_stage,
            "patch_valid": not errors,
            "errors": errors,
            "auxiliary_forbidden_term_hits": auxiliary_forbidden_hits,
            "old_reasoning_chain": summarize_chain(gold_row.get("gold_reasoning_chain")),
            "new_reasoning_chain": summarize_chain(chain),
        })
        if errors:
            invalid_rows.append({**patch_entry, "errors": errors})
        else:
            valid_rows.append(patch_entry)
            valid_patches[sample_id] = chain

    args.output_dir.mkdir(parents=True, exist_ok=True)
    write_jsonl(args.output_dir / "reasoning_patches.revalidated.jsonl", valid_rows)
    write_jsonl(args.output_dir / "invalid_outputs.jsonl", invalid_rows)
    write_jsonl(args.output_dir / "patch_validation_cases.jsonl", validation_rows)
    write_jsonl(args.output_dir / "patched_gold.candidate.jsonl", patched_gold_rows(gold_rows, valid_patches))

    grounding_cases, grounding_report = audit_grounding(valid_rows, prompts_by_id, model_by_id, gold_by_id, index_by_id)
    write_jsonl(args.output_dir / "grounding_audit_cases.jsonl", grounding_cases)
    write_json(args.output_dir / "grounding_audit_report.json", grounding_report)

    forbidden_summary = forbidden_invalid_summary(validation_rows)
    validation_report: JsonObj = {
        "revalidation": True,
        "api_called": False,
        "inputs": {
            "revalidate_patches": str(args.revalidate_patches),
            "gold": str(gold_path),
            "model_input": str(model_input_path),
            "sample_index": str(sample_index_path),
            "annotation_prompts": str(args.annotation_prompts) if args.annotation_prompts else None,
        },
        "outputs": {
            "reasoning_patches_revalidated": str(args.output_dir / "reasoning_patches.revalidated.jsonl"),
            "invalid_outputs": str(args.output_dir / "invalid_outputs.jsonl"),
            "patch_validation_cases": str(args.output_dir / "patch_validation_cases.jsonl"),
            "patched_gold_candidate": str(args.output_dir / "patched_gold.candidate.jsonl"),
            "patch_validation_report": str(args.output_dir / "patch_validation_report.json"),
            "grounding_audit_report": str(args.output_dir / "grounding_audit_report.json"),
        },
        "counts": {
            "total_patches": len(patch_input_rows),
            "valid_patches": len(valid_rows),
            "invalid_outputs": len(invalid_rows),
            "patched_gold_rows": len(gold_rows),
        },
        "invalid_sample_ids": [row["sample_id"] for row in invalid_rows],
        "patched_sample_ids": sorted(valid_patches),
        **forbidden_summary,
        "boundaries": {
            "overwrote_gold": False,
            "modified_model_input": False,
            "modified_benchmark_inputs": False,
            "modified_raw_or_index_or_release_main_structure": False,
            "ran_exploit": False,
            "collected_cve_data_from_network": False,
            "api_called": False,
        },
    }
    write_json(args.output_dir / "patch_validation_report.json", validation_report)

    trial_report = {
        "status": "success" if not invalid_rows else "partial",
        "revalidation": True,
        "api_called": False,
        "counts": validation_report["counts"],
        "forbidden_strict_chain_invalid_count": forbidden_summary["forbidden_strict_chain_invalid_count"],
        "forbidden_strict_chain_terms": forbidden_summary["forbidden_strict_chain_terms"],
        "grounding": grounding_report["counts"],
        "manual_review_sample_ids": grounding_report["manual_review_sample_ids"],
        "boundaries": validation_report["boundaries"],
    }
    write_json(args.output_dir / "ewvaa_revalidation_report.json", trial_report)
    (args.output_dir / "README.md").write_text(
        "\n".join([
            "# EWVAA Masked API Trial Revalidation",
            "",
            "Offline patch revalidation. No API calls were made.",
            "",
            f"Input patches: {args.revalidate_patches}",
            f"Valid patches: {len(valid_rows)}",
            f"Invalid patches: {len(invalid_rows)}",
            f"Forbidden strict-chain invalid patches: {forbidden_summary['forbidden_strict_chain_invalid_count']}",
            "",
        ]),
        encoding="utf-8",
    )
    print(json.dumps(trial_report, ensure_ascii=False, indent=2))
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Run EWVAA stage-reasoning API trial. Formal runs must use "
            "--masked-workbench-dir from ewvaa_workbench_v1 and produce candidate patched_gold only."
        )
    )
    parser.add_argument("--annotation-prompts", type=Path)
    parser.add_argument("--gold", type=Path)
    parser.add_argument("--model-input", type=Path)
    parser.add_argument("--sample-index", type=Path)
    parser.add_argument(
        "--vulnerability-facts",
        type=Path,
        help="Auxiliary facts; formal lineage is annotation_context.v0.4 via the masked workbench.",
    )
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--limit", type=int, default=10)
    parser.add_argument("--provider", choices=("openai-compatible", "anthropic"), default="openai-compatible")
    parser.add_argument("--model", help="Override provider model. Defaults to ANTHROPIC_MODEL or OPENAI_MODEL.")
    parser.add_argument("--temperature", type=float, default=0.0)
    parser.add_argument("--max-tokens", type=int, default=4096)
    parser.add_argument("--max-retries", type=int, default=1)
    parser.add_argument("--timeout", type=float, default=120.0)
    parser.add_argument("--dry-run", action="store_true", help="Build prompts/config only; do not call an API.")
    parser.add_argument("--masked-workbench-dir", type=Path, help="Formal model-facing input root under ewvaa_workbench_v1.")
    parser.add_argument("--use-masked-ids", action="store_true", help="Use masked sample/edge IDs and unmask before validation.")
    parser.add_argument("--metadata-id-map-dir", type=Path)
    parser.add_argument("--dry-run-unmask", action="store_true")
    parser.add_argument("--revalidate-patches", type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.dry_run_unmask:
        return run_dry_run_unmask(args)
    if args.revalidate_patches is not None:
        return run_revalidate_patches(args)

    if args.use_masked_ids and args.masked_workbench_dir is None:
        print("ERROR: --use-masked-ids requires --masked-workbench-dir", file=sys.stderr)
        return 2
    if args.annotation_prompts is None and args.use_masked_ids:
        args.annotation_prompts = args.masked_workbench_dir / "prompt_packs" / "annotation_prompts.weighted.masked.jsonl"
    missing_path_args = [
        name for name in ("annotation_prompts", "gold", "model_input", "sample_index", "vulnerability_facts", "output_dir")
        if getattr(args, name) is None
    ]
    if missing_path_args:
        print("ERROR: missing required path arguments: " + ", ".join("--" + name.replace("_", "-") for name in missing_path_args), file=sys.stderr)
        return 2

    id_maps: dict[str, dict[str, str]] | None = None
    if args.use_masked_ids:
        id_map_dir = args.metadata_id_map_dir or args.masked_workbench_dir / "id_maps"
        id_maps = load_id_maps(id_map_dir)

    prompts = read_jsonl(args.annotation_prompts)[: args.limit]
    gold_rows = read_jsonl(args.gold)
    model_rows = read_jsonl(args.model_input)
    index_rows = read_jsonl(args.sample_index)
    gold_by_id = {row["sample_id"]: row for row in gold_rows}
    model_by_id = {row["sample_id"]: row for row in model_rows}
    index_by_id = {row["sample_id"]: row for row in index_rows}
    prompts_for_audit = [remap_ids(row, id_maps) for row in prompts] if id_maps is not None else prompts
    prompts_by_id = {row["sample_id"]: row for row in prompts_for_audit}
    if args.provider == "openai-compatible":
        model = args.model or os.environ.get("OPENAI_MODEL", "")
        api_key_env = "OPENAI_API_KEY"
        base_url = os.environ.get("OPENAI_BASE_URL", "")
        api_mode = "chat_completions"
    else:
        model = args.model or os.environ.get("ANTHROPIC_MODEL", "claude-opus-4-7")
        api_key_env = "ANTHROPIC_API_KEY"
        base_url = ""
        api_mode = "chat_completions"

    args.output_dir.mkdir(parents=True, exist_ok=True)
    if args.dry_run:
        report = {
            "dry_run": True,
            "would_call_api": False,
            "num_prompts": len(prompts),
            "provider": args.provider,
            "model": model,
            "stage_distribution": dict(Counter(row.get("gold_stage") for row in prompts)),
            "scenario_distribution": dict(Counter(row.get("scenario_id") for row in prompts)),
            "missing_gold": [row.get("sample_id") for row in prompts_for_audit if row.get("sample_id") not in gold_by_id],
            "prompt_input_parse_failures": [
                row.get("sample_id") for row in prompts if extract_user_input(str(row.get("user", ""))) is None
            ],
            "masked_ids": {
                "enabled": bool(args.use_masked_ids),
                "masked_workbench_dir": str(args.masked_workbench_dir) if args.masked_workbench_dir else None,
                "metadata_id_map_dir": str(args.metadata_id_map_dir or args.masked_workbench_dir / "id_maps") if args.use_masked_ids else None,
            },
        }
        write_json(args.output_dir / "ewvaa_trial_report.json", report)
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return 0

    api_key = os.environ.get(api_key_env, "")
    missing_env = []
    if not api_key:
        missing_env.append(api_key_env)
    if args.provider == "openai-compatible" and not base_url:
        missing_env.append("OPENAI_BASE_URL")
    if args.provider == "openai-compatible" and not model:
        missing_env.append("OPENAI_MODEL")
    if missing_env:
        blocked_report = {
            "status": "blocked",
            "blocked_reason": "missing environment variables: " + ",".join(missing_env),
            "api_called": False,
            "provider": args.provider,
            "model": model,
            "dry_run_checks": {
                "num_prompts": len(prompts),
                "missing_gold": [row.get("sample_id") for row in prompts_for_audit if row.get("sample_id") not in gold_by_id],
                "prompt_input_parse_failures": [
                    row.get("sample_id") for row in prompts if extract_user_input(str(row.get("user", ""))) is None
                ],
                "stage_distribution": dict(Counter(row.get("gold_stage") for row in prompts)),
                "scenario_distribution": dict(Counter(row.get("scenario_id") for row in prompts)),
            },
            "outputs_written": {
                "raw_api_responses_jsonl": False,
                "reasoning_patches_jsonl": False,
                "patched_gold_jsonl": False,
                "patch_validation_report_json": False,
                "grounding_audit_report_json": False,
                "readme_md": True,
            },
            "boundaries": {
                "overwrote_gold": False,
                "modified_model_input": False,
                "modified_benchmark_inputs": False,
                "modified_raw_or_index_or_release_main_structure": False,
                "ran_exploit": False,
                "collected_cve_data_from_network": False,
                "api_key_recorded": False,
            },
        }
        write_json(args.output_dir / "ewvaa_trial_report.json", blocked_report)
        (args.output_dir / "README.md").write_text(build_readme(args.provider, model), encoding="utf-8")
        print("ERROR: " + blocked_report["blocked_reason"], file=sys.stderr)
        return 1

    run_config = {
        "annotation_prompts": str(args.annotation_prompts),
        "gold": str(args.gold),
        "model_input": str(args.model_input),
        "sample_index": str(args.sample_index),
        "vulnerability_facts": str(args.vulnerability_facts),
        "output_dir": str(args.output_dir),
        "provider": args.provider,
        "model": model,
        "base_url_set": bool(base_url),
        "api_key_set": bool(api_key),
        "temperature": args.temperature,
        "limit": args.limit,
        "max_tokens": args.max_tokens,
        "max_retries": args.max_retries,
        "timeout": args.timeout,
        "use_masked_ids": bool(args.use_masked_ids),
        "masked_workbench_dir": str(args.masked_workbench_dir) if args.masked_workbench_dir else None,
        "metadata_id_map_dir": str(args.metadata_id_map_dir or args.masked_workbench_dir / "id_maps") if args.use_masked_ids else None,
    }
    write_json(args.output_dir / "run_config.json", run_config)

    raw_api_responses: list[JsonObj] = []
    patch_rows: list[JsonObj] = []
    patch_rows_masked: list[JsonObj] = []
    invalid_rows: list[JsonObj] = []
    validation_rows: list[JsonObj] = []
    valid_patches: dict[str, list[JsonObj]] = {}
    masked_unmask_success = 0
    masked_unmask_failures = 0

    for idx, prompt_row in enumerate(prompts, 1):
        prompt_sample_id = str(prompt_row.get("sample_id"))
        sample_id = id_maps["sample_id"].get(prompt_sample_id, prompt_sample_id) if id_maps is not None else prompt_sample_id
        gold_stage = str(prompt_row.get("gold_stage") or "")
        print(f"[{idx}/{len(prompts)}] Calling {args.provider} for {prompt_sample_id} stage={gold_stage} ...", flush=True)
        result = call_provider(
            prompt_row,
            provider=args.provider,
            api_key=api_key,
            base_url=base_url,
            model=model,
            api_mode=api_mode,
            temperature=args.temperature,
            max_tokens=args.max_tokens,
            timeout=args.timeout,
            max_retries=args.max_retries,
        )
        raw_entry = {"sample_id": prompt_sample_id, "canonical_sample_id": sample_id, "gold_stage": gold_stage, **result}
        raw_api_responses.append(raw_entry)
        if "error" in result:
            errors = ["api_error:" + str(result["error"])[:200]]
            invalid_rows.append({"sample_id": sample_id, "masked_sample_id": prompt_sample_id if id_maps is not None else None, "gold_stage": gold_stage, "errors": errors})
            validation_rows.append({"sample_id": sample_id, "masked_sample_id": prompt_sample_id if id_maps is not None else None, "gold_stage": gold_stage, "patch_valid": False, "errors": errors})
            continue

        parsed = extract_json(str(result.get("raw_content", "")))
        if parsed is None:
            errors = ["json_parse_error"]
            invalid_rows.append({"sample_id": sample_id, "masked_sample_id": prompt_sample_id if id_maps is not None else None, "gold_stage": gold_stage, "errors": errors, "raw_content": str(result.get("raw_content", ""))[:2000]})
            validation_rows.append({"sample_id": sample_id, "masked_sample_id": prompt_sample_id if id_maps is not None else None, "gold_stage": gold_stage, "patch_valid": False, "errors": errors})
            continue

        parsed_sample_id = parsed.get("sample_id", sample_id)
        errors: list[str] = []
        if parsed_sample_id != prompt_sample_id:
            errors.append(f"sample_id_mismatch:{parsed_sample_id}")
        parsed_unmasked = parsed
        if id_maps is not None:
            parsed_unmasked, unmask_errors = unmask_patch(parsed, id_maps)
            errors.extend(unmask_errors)
            if unmask_errors:
                masked_unmask_failures += 1
            else:
                masked_unmask_success += 1
        chain = sanitize_reasoning_chain(parsed_unmasked.get("gold_reasoning_chain"))
        note = parsed_unmasked.get("auxiliary_vulnerability_note")
        clean_note = sanitize_candidate_auxiliary_note(note)
        if sample_id not in gold_by_id:
            errors.append("sample_id_missing_from_gold")
        else:
            errors.extend(validate_chain(chain, legal_refs_from_gold(gold_by_id[sample_id]), gold_stage))
        errors.extend(forbidden_strict_chain_errors(chain))
        errors.extend(validate_patch_note(note))
        auxiliary_forbidden_hits = auxiliary_note_forbidden_hits(note)
        patch_entry_masked = {
            "sample_id": prompt_sample_id,
            "canonical_sample_id": sample_id,
            "gold_stage": gold_stage,
            "gold_reasoning_chain": sanitize_reasoning_chain(parsed.get("gold_reasoning_chain")),
            "auxiliary_vulnerability_note": sanitize_candidate_auxiliary_note(
                parsed.get("auxiliary_vulnerability_note")
            ),
            "patch_valid": not errors,
        }
        patch_entry = {
            "sample_id": sample_id,
            "masked_sample_id": prompt_sample_id if id_maps is not None else None,
            "gold_stage": gold_stage,
            "gold_reasoning_chain": chain,
            "auxiliary_vulnerability_note": clean_note,
            "auxiliary_forbidden_term_hits": auxiliary_forbidden_hits,
            "patch_valid": not errors,
        }
        validation_rows.append({
            "sample_id": sample_id,
            "masked_sample_id": prompt_sample_id if id_maps is not None else None,
            "scenario_id": prompts_by_id.get(sample_id, {}).get("scenario_id", prompt_row.get("scenario_id")),
            "masked_scenario_id": prompt_row.get("scenario_id") if id_maps is not None else None,
            "gold_stage": gold_stage,
            "patch_valid": not errors,
            "errors": errors,
            "auxiliary_forbidden_term_hits": auxiliary_forbidden_hits,
            "old_reasoning_chain": summarize_chain(gold_by_id.get(sample_id, {}).get("gold_reasoning_chain")),
            "new_reasoning_chain": summarize_chain(chain),
        })
        if errors:
            invalid_rows.append({**patch_entry, "errors": errors})
        else:
            patch_rows_masked.append(patch_entry_masked)
            patch_rows.append(patch_entry)
            valid_patches[sample_id] = chain

    write_jsonl(args.output_dir / "raw_api_responses.jsonl", raw_api_responses)
    if id_maps is not None:
        write_jsonl(args.output_dir / "reasoning_patches.masked.jsonl", patch_rows_masked)
        write_jsonl(args.output_dir / "reasoning_patches.unmasked.jsonl", patch_rows)
    write_jsonl(args.output_dir / "reasoning_patches.jsonl", patch_rows)
    write_jsonl(args.output_dir / "invalid_outputs.jsonl", invalid_rows)
    write_jsonl(args.output_dir / "patch_validation_cases.jsonl", validation_rows)
    write_jsonl(args.output_dir / "patched_gold.jsonl", patched_gold_rows(gold_rows, valid_patches))

    grounding_cases, grounding_report = audit_grounding(patch_rows, prompts_by_id, model_by_id, gold_by_id, index_by_id)
    write_jsonl(args.output_dir / "grounding_audit_cases.jsonl", grounding_cases)
    write_json(args.output_dir / "grounding_audit_report.json", grounding_report)

    validation_report = {
        "inputs": {
            "annotation_prompts": str(args.annotation_prompts),
            "gold": str(args.gold),
            "model_input": str(args.model_input),
            "sample_index": str(args.sample_index),
            "vulnerability_facts": str(args.vulnerability_facts),
        },
        "outputs": {
            "raw_api_responses": str(args.output_dir / "raw_api_responses.jsonl"),
            "reasoning_patches": str(args.output_dir / "reasoning_patches.jsonl"),
            "reasoning_patches_masked": str(args.output_dir / "reasoning_patches.masked.jsonl") if id_maps is not None else None,
            "reasoning_patches_unmasked": str(args.output_dir / "reasoning_patches.unmasked.jsonl") if id_maps is not None else None,
            "patched_gold": str(args.output_dir / "patched_gold.jsonl"),
            "patch_validation_report": str(args.output_dir / "patch_validation_report.json"),
            "grounding_audit_report": str(args.output_dir / "grounding_audit_report.json"),
            "ewvaa_trial_report": str(args.output_dir / "ewvaa_trial_report.json"),
        },
        "counts": {
            "total_prompts": len(prompts),
            "api_success": len(raw_api_responses) - sum(1 for row in raw_api_responses if "error" in row),
            "valid_patches": len(patch_rows),
            "invalid_outputs": len(invalid_rows),
            "patched_gold_rows": len(gold_rows),
            "masked_unmask_success": masked_unmask_success,
            "masked_unmask_failures": masked_unmask_failures,
        },
        "masked_ids": {
            "enabled": bool(id_maps is not None),
            "masked_success_count": masked_unmask_success,
            "unmasked_success_count": len(patch_rows),
            "unmask_failure_count": masked_unmask_failures,
        },
        "stage_distribution_valid": dict(Counter(row["gold_stage"] for row in patch_rows)),
        "invalid_sample_ids": [row["sample_id"] for row in invalid_rows],
        "patched_sample_ids": sorted(valid_patches),
    }
    validation_report.update(forbidden_invalid_summary(validation_rows))
    write_json(args.output_dir / "patch_validation_report.json", validation_report)

    trial_report = {
        "status": "success" if len(patch_rows) == len(prompts) else "partial" if patch_rows else "failed",
        "provider": args.provider,
        "model": model,
        "api_key_recorded": False,
        "counts": validation_report["counts"],
        "masked_ids": validation_report["masked_ids"],
        "forbidden_strict_chain_invalid_count": validation_report["forbidden_strict_chain_invalid_count"],
        "forbidden_strict_chain_terms": validation_report["forbidden_strict_chain_terms"],
        "stage_distribution": dict(Counter(row.get("gold_stage") for row in prompts)),
        "scenario_distribution": dict(Counter(row.get("scenario_id") for row in prompts)),
        "grounding": grounding_report["counts"],
        "manual_review_sample_ids": grounding_report["manual_review_sample_ids"],
        "boundaries": {
            "overwrote_gold": False,
            "modified_model_input": False,
            "modified_benchmark_inputs": False,
            "modified_raw_or_index_or_release_main_structure": False,
            "ran_exploit": False,
            "collected_cve_data_from_network": False,
            "api_key_recorded": False,
        },
    }
    write_json(args.output_dir / "ewvaa_trial_report.json", trial_report)

    (args.output_dir / "README.md").write_text(build_readme(args.provider, model), encoding="utf-8")

    print("TRIAL SUMMARY")
    print(json.dumps(trial_report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
