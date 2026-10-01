#!/usr/bin/env python3
"""Weighted grounding audit for EWVAA reasoning patches.

This audit is a local quality gate. It does not call APIs, does not write
candidate gold, and does not modify benchmark inputs.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable

from common import (
    benchmark_paths,
    config_path_from_args,
    load_benchmark,
    load_config,
    read_jsonl,
    rel,
    resolve_path,
    utc_now,
    write_json,
    write_jsonl,
)

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from results_analysis.release import run_ewvaa_stage_reasoning_api_trial as ewvaa  # noqa: E402


JsonObj = dict[str, Any]


@dataclass(frozen=True)
class AuditSettings:
    primary_threshold: float = 0.55
    min_step_score_threshold: float = 0.35
    average_score_threshold: float = 0.55
    penalty_scale: float = 1.0
    weak_step_score_threshold: float = 0.75
    structural_matching: bool = True


SENSITIVITY_PROFILES: dict[str, AuditSettings] = {
    "strict_current_default": AuditSettings(),
    "medium_candidate": AuditSettings(
        primary_threshold=0.45,
        min_step_score_threshold=0.30,
        average_score_threshold=0.50,
        penalty_scale=0.85,
    ),
    "lenient_observation_only": AuditSettings(
        primary_threshold=0.35,
        min_step_score_threshold=0.25,
        average_score_threshold=0.45,
        penalty_scale=0.70,
    ),
}

REVIEW_REASON_CATEGORIES = (
    "low_primary_support",
    "auxiliary_only",
    "missing_primary_refs",
    "weak_text_overlap",
    "forbidden_or_mechanism_claim",
    "final_judgement_not_grounded",
    "evidence_ref_missing_or_unresolved",
)

STOPWORDS = {
    "a",
    "an",
    "and",
    "are",
    "as",
    "at",
    "based",
    "be",
    "because",
    "by",
    "for",
    "from",
    "in",
    "into",
    "is",
    "it",
    "of",
    "on",
    "or",
    "primary",
    "stage",
    "that",
    "the",
    "this",
    "to",
    "using",
    "with",
    "without",
}

HIGH_VALUE_TERMS = {
    "accept",
    "clone",
    "connect",
    "exec",
    "file",
    "fork",
    "http",
    "net",
    "network",
    "open",
    "process",
    "read",
    "recv",
    "request",
    "response",
    "send",
    "write",
}


def tokenize(text: str) -> set[str]:
    return {
        token.lower()
        for token in re.findall(r"[A-Za-z0-9_./:-]{3,}", text)
        if token.lower() not in STOPWORDS
    }


def normalize_text(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True).lower()


def refs_from_step(step: JsonObj) -> list[JsonObj]:
    refs = step.get("evidence_refs")
    return refs if isinstance(refs, list) else []


def ref_key(ref: JsonObj) -> tuple[int | None, str | None]:
    return ewvaa.coerce_int(ref.get("seq")), str(ref.get("edge_id")) if ref.get("edge_id") is not None else None


def iter_primary_edges(value: Any) -> Iterable[JsonObj]:
    yield from ewvaa.iter_possible_edges(value)


def build_primary_ref_texts(*sources: Any) -> dict[tuple[int | None, str | None], str]:
    refs: dict[tuple[int | None, str | None], list[str]] = {}
    for source in sources:
        for edge in iter_primary_edges(source):
            seq = ewvaa.coerce_int(edge.get("seq"))
            edge_id = str(edge.get("edge_id")) if edge.get("edge_id") is not None else None
            text = normalize_text(edge)
            for key in ((seq, edge_id), (seq, None), (None, edge_id)):
                refs.setdefault(key, []).append(text)
    return {key: "\n".join(dict.fromkeys(values)) for key, values in refs.items()}


def ref_exists(key: tuple[int | None, str | None], ref_texts: dict[tuple[int | None, str | None], str]) -> bool:
    seq, edge_id = key
    return key in ref_texts or (seq, None) in ref_texts or (None, edge_id) in ref_texts


def combined_ref_text(refs: list[JsonObj], ref_texts: dict[tuple[int | None, str | None], str]) -> str:
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


def overlap_score(claim: str, evidence_text: str, *, base_when_present: float) -> float:
    if not evidence_text:
        return 0.0
    claim_tokens = tokenize(claim)
    if not claim_tokens:
        return base_when_present
    evidence_tokens = tokenize(evidence_text)
    overlap = claim_tokens & evidence_tokens
    high_value_overlap = overlap & HIGH_VALUE_TERMS
    ratio = len(overlap) / max(1, len(claim_tokens))
    score = base_when_present + 0.55 * ratio + 0.08 * min(3, len(high_value_overlap))
    return max(0.0, min(1.0, score))


def structured_evidence_bonus(
    claim: str,
    evidence_text: str,
    *,
    refs: list[JsonObj],
    missing_refs: list[tuple[int | None, str | None]],
) -> tuple[float, list[str]]:
    if not refs or not evidence_text:
        return 0.0, []
    lower_claim = claim.lower()
    lower_evidence = evidence_text.lower()
    bonus = 0.0
    reasons: list[str] = []
    resolved_ref_count = len([ref for ref in refs if isinstance(ref, dict)]) - len(missing_refs)
    if resolved_ref_count > 0:
        bonus += 0.10
        reasons.append("resolved_evidence_ref")
    if any(isinstance(ref, dict) and ref.get("seq") is not None for ref in refs) and resolved_ref_count > 0:
        bonus += 0.05
        reasons.append("seq_ref_resolved")
    if any(isinstance(ref, dict) and ref.get("edge_id") for ref in refs) and resolved_ref_count > 0:
        bonus += 0.05
        reasons.append("edge_id_ref_resolved")

    fact_groups = {
        "process_fact_match": ("process", "proc", "fork", "exec", "clone"),
        "file_fact_match": ("file", "write", "read", "open"),
        "network_fact_match": ("network", "net", "connect", "send", "recv", "accept", "port"),
        "http_fact_match": ("http", "request", "response", "get", "post", "put"),
        "service_response_fact_match": ("service_response", "response", "status", "200", "500"),
    }
    for reason, terms in fact_groups.items():
        if any(term in lower_claim for term in terms) and any(term in lower_evidence for term in terms):
            bonus += 0.04
            reasons.append(reason)

    behavior_terms = ("exec", "write", "read", "connect", "send", "recv", "accept", "fork", "open")
    matched_behaviors = [term for term in behavior_terms if term in lower_claim and term in lower_evidence]
    if matched_behaviors:
        bonus += min(0.12, 0.04 * len(matched_behaviors))
        reasons.append("behavior_relation_match:" + ",".join(matched_behaviors[:4]))
    return min(0.30, bonus), reasons


NONE_NEGATIVE_MARKERS = (
    "lack",
    "lacks",
    "lacking",
    "no evidence",
    "no stage-specific",
    "does not show",
    "doesn't show",
    "do not show",
    "did not show",
    "not show",
    "does not contain",
    "do not contain",
    "insufficient evidence",
    "insufficient primary evidence",
    "only shows boundary activity",
    "only shows",
    "limited to",
    "without observed",
    "without confirmed",
    "without further",
    "not accompanied by",
    "no command execution",
    "no file write",
    "no output artifact",
    "no post-auth action",
    "no state-changing outcome",
    "no resulting outcome",
)

POSITIVE_OTHER_STAGE_PATTERNS = (
    re.compile(r"\b(?:stage|gold_stage)\s*(?:is|=|:)\s*(?:preparation|execution|result)\b"),
    re.compile(
        r"\b(?:supports|indicates|matches|reflects|confirms|classified\s+as|classification\s+as)"
        r"\s+(?:the\s+)?(?:preparation|execution|result)(?:\s+stage)?\b"
    ),
    re.compile(r"\b(?:preparation|execution|result)\s+stage\s+(?:is\s+)?(?:supported|indicated|matched|confirmed)\b"),
)

NEGATIVE_NONE_STAGE_PATTERNS = (
    re.compile(r"\bnot\s+(?:stage\s+)?none\b"),
    re.compile(r"\bdoes\s+not\s+support\s+(?:stage\s+)?none\b"),
    re.compile(r"\bdo\s+not\s+support\s+(?:stage\s+)?none\b"),
)


def has_positive_none_stage(lower_claim: str) -> bool:
    return bool(
        re.search(r"\bthe\s+stage\s+is\s+none\b", lower_claim)
        or re.search(r"\bsupports?\s+stage\s+none\b", lower_claim)
        or re.search(r"\bsupports?\s+(?:gold_stage\s+)?none\b", lower_claim)
        or re.search(r"\bstage\s+none\b", lower_claim)
        or re.search(r"\bgold_stage\s*(?:is|=|:)?\s*none\b", lower_claim)
        or re.search(r"\bsupported\s+gold_stage\s+is\s+none\b", lower_claim)
    )


def has_none_negative_semantics(lower_claim: str) -> bool:
    return any(marker in lower_claim for marker in NONE_NEGATIVE_MARKERS)


def has_positive_other_stage(lower_claim: str) -> bool:
    return any(pattern.search(lower_claim) for pattern in POSITIVE_OTHER_STAGE_PATTERNS)


def has_negative_none_stage(lower_claim: str) -> bool:
    return any(pattern.search(lower_claim) for pattern in NEGATIVE_NONE_STAGE_PATTERNS)


STAGE_WORDS = ("preparation", "execution", "result", "none")

SCENARIO_SCOPE_MARKERS = (
    "multi-source",
    "evidence window",
    "source coverage",
    "primary",
    "auxiliary",
    "missing",
    "weak",
    "disconnected",
    "evidence condition",
    "evidence limit",
    "stage-relevant evidence condition",
    "visible evidence",
)

OBSERVABLE_FACT_MARKERS = (
    "source-bucketed",
    "source bucket",
    "audit",
    "applog",
    "traffic",
    "directly visible",
    "observable fact",
    "stage-relevant observable facts",
    "evidence_refs",
    "cited",
)

CHAIN_REASONING_MARKERS = (
    "temporal proximity",
    "subject continuity",
    "object consistency",
    "object/target consistency",
    "request chain",
    "process chain",
    "file chain",
    "network chain",
    "adjacent stage",
    "adjacent stages",
)


def has_marker(lower_claim: str, markers: tuple[str, ...]) -> bool:
    return any(marker in lower_claim for marker in markers)


def has_stage_word(lower_claim: str, stage: str) -> bool:
    return bool(stage and re.search(rf"\b{re.escape(stage)}\b", lower_claim))


def has_positive_stage_assertion(lower_claim: str, stage: str) -> bool:
    if not stage:
        return False
    if stage == "none":
        return has_positive_none_stage(lower_claim)
    stage_pattern = re.escape(stage)
    return bool(
        re.search(rf"\b(?:stage|gold_stage)\s*(?:is|=|:)\s*(?:the\s+)?{stage_pattern}\b", lower_claim)
        or re.search(
            rf"\b(?:supports?|indicates|matches|reflects|confirms|classified\s+as|classification\s+as)"
            rf"\s+(?:the\s+)?(?:fixed\s+)?(?:gold_stage\s+)?{stage_pattern}(?:\s+stage)?\b",
            lower_claim,
        )
        or re.search(
            rf"\b{stage_pattern}\s+stage\s+(?:is\s+)?(?:supported|indicated|matched|confirmed)\b",
            lower_claim,
        )
    )


def has_other_stage_assertion(lower_claim: str, gold_stage: str) -> bool:
    return any(
        has_positive_stage_assertion(lower_claim, stage)
        for stage in STAGE_WORDS
        if stage != gold_stage
    )


def stage_coherence_score(step_name: str, claim: str, gold_stage: str) -> float:
    lower = claim.lower()
    stage = gold_stage.lower()
    if not stage:
        return 0.9

    target_asserted = has_positive_stage_assertion(lower, stage) or has_stage_word(lower, stage)
    other_asserted = has_other_stage_assertion(lower, stage)

    if step_name == "final_judgement":
        if other_asserted and not target_asserted:
            return 0.45
        if stage == "none":
            if has_negative_none_stage(lower):
                return 0.45
            if "the stage is none" in lower:
                return 1.0
            if has_positive_none_stage(lower):
                return 0.75
            if has_none_negative_semantics(lower) and not has_positive_other_stage(lower):
                return 0.65
            return 0.25
        if target_asserted:
            return 1.0
        return 0.25

    if stage == "none":
        if has_negative_none_stage(lower):
            return 0.45
        if has_positive_none_stage(lower):
            return 1.0
        if has_none_negative_semantics(lower) and not has_positive_other_stage(lower):
            return 0.9

    if other_asserted and not target_asserted:
        return 0.45

    if step_name == "scenario_or_evidence_understanding":
        if has_marker(lower, SCENARIO_SCOPE_MARKERS):
            return 1.0 if target_asserted else 0.95
        return 1.0 if target_asserted else 0.9

    if step_name == "observable_evidence":
        if has_marker(lower, OBSERVABLE_FACT_MARKERS):
            return 1.0 if target_asserted else 0.95
        return 1.0 if target_asserted else 0.9

    if step_name == "attack_stage_path_reasoning":
        if target_asserted:
            return 1.0
        if has_marker(lower, CHAIN_REASONING_MARKERS):
            return 0.8
        return 0.65

    return 1.0 if target_asserted else 0.9


def detect_schema(patch_rows: list[JsonObj]) -> JsonObj:
    field_counter: Counter[str] = Counter()
    step_fields: Counter[str] = Counter()
    masked = 0
    unmasked = 0
    for row in patch_rows:
        field_counter.update(key for key in row if not key.startswith("_"))
        sample_id = str(row.get("sample_id") or "")
        if sample_id.startswith("sample_m_"):
            masked += 1
        elif sample_id:
            unmasked += 1
        chain = row.get("gold_reasoning_chain")
        if isinstance(chain, list):
            for step in chain:
                if isinstance(step, dict):
                    step_fields.update(step.keys())
    if masked and unmasked:
        id_mode = "mixed"
    elif masked:
        id_mode = "masked"
    elif unmasked:
        id_mode = "unmasked"
    else:
        id_mode = "unknown"
    return {
        "patch_top_level_fields": sorted(field_counter),
        "reasoning_step_fields": sorted(step_fields),
        "chain_field": "gold_reasoning_chain" if "gold_reasoning_chain" in field_counter else "missing",
        "id_mode": id_mode,
        "rows_detected": len(patch_rows),
    }


def canonicalize_patch_ids(patch: JsonObj, sample_id_map: dict[str, str]) -> JsonObj:
    sample_id = patch.get("sample_id")
    if isinstance(sample_id, str) and sample_id.startswith("sample_m_") and sample_id in sample_id_map:
        clean = {key: value for key, value in patch.items() if not key.startswith("_")}
        clean["sample_id"] = sample_id_map[sample_id]
        clean["masked_sample_id"] = sample_id
        return clean
    return {key: value for key, value in patch.items() if not key.startswith("_")}


def load_sample_id_map(config: JsonObj) -> dict[str, str]:
    try:
        return ewvaa.load_id_maps(benchmark_paths(config)["id_map_dir"])["sample_id"]
    except Exception:
        return {}


def auxiliary_text_for(prompt_row: JsonObj) -> str:
    prompt_input = prompt_row.get("prompt_input")
    if not isinstance(prompt_input, dict):
        prompt_input = ewvaa.extract_user_input(str(prompt_row.get("user", ""))) or {}
    return normalize_text(prompt_input.get("auxiliary_vulnerability_context") or {})


def primary_sources_for(prompt_row: JsonObj, model_row: JsonObj, gold_row: JsonObj) -> list[Any]:
    prompt_input = prompt_row.get("prompt_input")
    if not isinstance(prompt_input, dict):
        prompt_input = ewvaa.extract_user_input(str(prompt_row.get("user", ""))) or {}
    return [prompt_input.get("primary_evidence") or prompt_input, model_row.get("input") or model_row, gold_row]


def audit_step(
    *,
    step_index: int,
    step: JsonObj,
    gold_stage: str,
    ref_texts: dict[tuple[int | None, str | None], str],
    all_primary_text: str,
    auxiliary_text: str,
    settings: AuditSettings,
) -> JsonObj:
    step_name = str(step.get("step") or "")
    claim = str(step.get("claim") or "")
    refs = refs_from_step(step)
    keys = [ref_key(ref) for ref in refs if isinstance(ref, dict)]
    missing_refs = [key for key in keys if not ref_exists(key, ref_texts)]
    cited_primary_text = combined_ref_text(refs, ref_texts)
    primary_support = overlap_score(claim, cited_primary_text, base_when_present=0.35)
    structural_bonus = 0.0
    structural_reasons: list[str] = []
    if settings.structural_matching:
        structural_bonus, structural_reasons = structured_evidence_bonus(
            claim,
            cited_primary_text,
            refs=refs,
            missing_refs=missing_refs,
        )
        primary_support = min(1.0, primary_support + structural_bonus)
    if not refs:
        primary_support = 0.0
    auxiliary_support = overlap_score(claim, auxiliary_text, base_when_present=0.05)
    stage_coherence = stage_coherence_score(step_name, claim, gold_stage)
    forbidden_hits = extract_terms(claim, ewvaa.FORBIDDEN_STRICT_TERMS)
    vulnerability_hits = extract_terms(claim, ewvaa.VULNERABILITY_TERMS)
    unsupported_forbidden = [
        term for term in forbidden_hits
        if term.lower() not in all_primary_text and term.lower() not in cited_primary_text
    ]
    unsupported_vulnerability = [
        term for term in vulnerability_hits
        if term.lower() not in all_primary_text and term.lower() not in cited_primary_text
    ]
    declares_auxiliary = (
        str(step.get("source_type") or "").lower() == "auxiliary_vulnerability_context"
        or bool(step.get("uses_vulnerability_context"))
    )
    auxiliary_only = bool(
        declares_auxiliary
        or (primary_support < 0.25 and auxiliary_support >= 0.20)
        or (unsupported_vulnerability and primary_support < 0.45)
    )
    final_without_primary = step_name == "final_judgement" and (not refs or primary_support < 0.25)
    penalty = 0.0
    reasons: list[str] = []
    if not refs:
        penalty += 0.25
        reasons.append("missing_evidence_refs")
    if missing_refs:
        penalty += 0.35
        reasons.append("missing_primary_ref")
    if unsupported_forbidden:
        penalty += 0.25
        reasons.append("unsupported_forbidden_terms:" + ",".join(unsupported_forbidden))
    if unsupported_vulnerability:
        penalty += 0.20
        reasons.append("unsupported_vulnerability_terms:" + ",".join(unsupported_vulnerability))
    if auxiliary_only:
        penalty += 0.45
        reasons.append("auxiliary_only_or_auxiliary_declared")
    if final_without_primary:
        penalty += 0.50
        reasons.append("final_judgement_without_primary_support")
    if stage_coherence < 0.5:
        penalty += 0.15
        reasons.append("low_stage_coherence")
    penalty *= settings.penalty_scale
    weighted_score = max(0.0, min(1.0, 0.75 * primary_support + 0.20 * auxiliary_support + 0.05 * stage_coherence - penalty))
    strict_gold_allowed = not auxiliary_only and not final_without_primary and not missing_refs and not unsupported_forbidden
    if not strict_gold_allowed or weighted_score < settings.min_step_score_threshold:
        verdict = "invalid"
    elif weighted_score < settings.average_score_threshold or auxiliary_only:
        verdict = "risky"
    elif weighted_score < settings.weak_step_score_threshold:
        verdict = "weak"
    else:
        verdict = "strong"
    return {
        "step_index": step_index,
        "step": step_name,
        "claim": claim,
        "evidence_refs": refs,
        "primary_support": round(primary_support, 4),
        "auxiliary_support": round(auxiliary_support, 4),
        "stage_coherence": round(stage_coherence, 4),
        "penalty": round(penalty, 4),
        "weighted_score": round(weighted_score, 4),
        "structural_bonus": round(structural_bonus, 4),
        "structural_match_reasons": structural_reasons,
        "auxiliary_only": auxiliary_only,
        "strict_gold_allowed": strict_gold_allowed,
        "verdict": verdict,
        "reasons": reasons,
        "forbidden_hits": forbidden_hits,
        "vulnerability_hits": vulnerability_hits,
        "missing_refs": [repr(item) for item in missing_refs],
    }


def verdict_for_sample(step_scores: list[JsonObj], patch_valid: Any, settings: AuditSettings) -> str:
    if patch_valid is False or any(step["verdict"] == "invalid" for step in step_scores):
        return "invalid"
    if step_scores:
        average = sum(float(step["weighted_score"]) for step in step_scores) / len(step_scores)
        if average < settings.average_score_threshold:
            return "risky"
    if any(step["verdict"] == "risky" for step in step_scores):
        return "risky"
    if any(step["verdict"] == "weak" for step in step_scores):
        return "weak"
    return "strong"


def audit_patch_rows(
    config: JsonObj,
    patch_rows: list[JsonObj],
    *,
    role: str,
    patch_path: str | None = None,
    settings: AuditSettings | None = None,
) -> tuple[list[JsonObj], JsonObj]:
    settings = settings or AuditSettings()
    schema_detected = detect_schema(patch_rows)
    if not patch_rows:
        report = {
            "status": "no_input",
            "created_at": utc_now(),
            "role": role,
            "schema_version": "weighted_grounding_audit.v1",
            "schema_detected": schema_detected,
            "blocked_reason": "no_patch_rows",
            "api_called": False,
            "benchmark_files_modified": False,
        }
        return [], report

    bench = load_benchmark(config)
    sample_id_map = load_sample_id_map(config)
    cases: list[JsonObj] = []
    for raw_patch in patch_rows:
        patch = canonicalize_patch_ids(raw_patch, sample_id_map)
        sample_id = str(patch.get("sample_id") or "")
        gold_row = bench["gold_by_id"].get(sample_id, {})
        model_row = bench["model_by_id"].get(sample_id, {})
        index_row = bench["index_by_id"].get(sample_id, {})
        prompt_row = bench["prompts_by_id"].get(sample_id, {})
        gold_stage = str(
            patch.get("gold_stage")
            or (gold_row.get("label") or {}).get("stage")
            or index_row.get("stage")
            or ""
        )
        primary_sources = primary_sources_for(prompt_row, model_row, gold_row)
        ref_texts = build_primary_ref_texts(*primary_sources)
        all_primary_text = normalize_text(primary_sources)
        aux_text = auxiliary_text_for(prompt_row)
        chain = patch.get("gold_reasoning_chain")
        step_scores: list[JsonObj] = []
        if isinstance(chain, list):
            for idx, step in enumerate(chain):
                if isinstance(step, dict):
                    step_scores.append(
                        audit_step(
                            step_index=idx,
                            step=step,
                            gold_stage=gold_stage,
                            ref_texts=ref_texts,
                            all_primary_text=all_primary_text,
                            auxiliary_text=aux_text,
                            settings=settings,
                        )
                    )
        strict_allowed = bool(step_scores) and all(step["strict_gold_allowed"] for step in step_scores)
        weighted_scores = [float(step["weighted_score"]) for step in step_scores]
        verdict = verdict_for_sample(step_scores, patch.get("patch_valid"), settings)
        reasons = sorted({reason for step in step_scores for reason in step.get("reasons", [])})
        if not step_scores:
            verdict = "invalid"
            strict_allowed = False
            reasons.append("missing_or_empty_reasoning_chain")
        final_steps = [step for step in step_scores if step.get("step") == "final_judgement"]
        if not final_steps:
            verdict = "invalid"
            strict_allowed = False
            reasons.append("missing_final_judgement")
        elif not final_steps[-1]["strict_gold_allowed"]:
            strict_allowed = False
            reasons.append("final_judgement_not_primary_grounded")
        case = {
            "sample_id": sample_id,
            "masked_sample_id": patch.get("masked_sample_id") or raw_patch.get("sample_id") if str(raw_patch.get("sample_id", "")).startswith("sample_m_") else patch.get("masked_sample_id"),
            "gold_stage": gold_stage,
            "step_count": len(step_scores),
            "average_weighted_score": round(sum(weighted_scores) / len(weighted_scores), 4) if weighted_scores else 0.0,
            "min_step_score": round(min(weighted_scores), 4) if weighted_scores else 0.0,
            "primary_supported_step_count": sum(1 for step in step_scores if step["primary_support"] >= settings.primary_threshold),
            "auxiliary_only_step_count": sum(1 for step in step_scores if step["auxiliary_only"]),
            "invalid_step_count": sum(1 for step in step_scores if step["verdict"] == "invalid"),
            "strict_gold_allowed": strict_allowed,
            "verdict": verdict,
            "reasons": reasons,
            "step_scores": step_scores,
        }
        cases.append(case)

    counts = {
        "patch_rows": len(patch_rows),
        "cases": len(cases),
        "by_verdict": dict(Counter(case["verdict"] for case in cases)),
        "strict_gold_allowed_false": sum(1 for case in cases if not case["strict_gold_allowed"]),
        "auxiliary_only_samples": sum(1 for case in cases if case["auxiliary_only_step_count"] > 0),
        "invalid_samples": sum(1 for case in cases if case["verdict"] == "invalid"),
        "manual_review_samples": sum(1 for case in cases if not case["strict_gold_allowed"] or case["verdict"] in {"weak", "risky", "invalid"}),
    }
    report = {
        "status": "success",
        "created_at": utc_now(),
        "role": role,
        "schema_version": "weighted_grounding_audit.v1",
        "scoring_formula": "weighted_score = 0.75 * primary_support + 0.20 * auxiliary_support + 0.05 * stage_coherence - penalty",
        "settings": asdict(settings),
        "schema_detected": schema_detected,
        "inputs": {
            "patches": patch_path,
            "gold": config.get("gold"),
            "model_input": config.get("model_input"),
            "sample_index": config.get("sample_index"),
            "prompt_pack": config.get("prompt_pack"),
        },
        "counts": counts,
        "strict_gold_blocked_sample_ids": [case["sample_id"] for case in cases if not case["strict_gold_allowed"]],
        "manual_review_sample_ids": [
            case["sample_id"]
            for case in cases
            if not case["strict_gold_allowed"] or case["verdict"] in {"weak", "risky", "invalid"}
        ],
        "api_called": False,
        "benchmark_files_modified": False,
        "canonical_gold_overwrite_allowed": False,
    }
    return cases, report


def write_audit_outputs(
    *,
    config: JsonObj,
    patch_rows: list[JsonObj],
    output_dir: Path,
    role: str,
    report_name: str,
    cases_name: str,
    patch_path: str | None,
    settings: AuditSettings | None = None,
) -> JsonObj:
    cases, report = audit_patch_rows(config, patch_rows, role=role, patch_path=patch_path, settings=settings)
    output_dir.mkdir(parents=True, exist_ok=True)
    write_jsonl(output_dir / cases_name, cases)
    write_json(output_dir / report_name, report)
    return report


def blocked_no_input_report(
    *,
    output_dir: Path,
    role: str,
    report_name: str,
    cases_name: str,
    reason: str,
    patch_path: Path | None = None,
) -> JsonObj:
    report = {
        "status": "no_input",
        "created_at": utc_now(),
        "role": role,
        "schema_version": "weighted_grounding_audit.v1",
        "blocked_reason": reason,
        "inputs": {"patches": rel(patch_path) if patch_path else None},
        "counts": {
            "patch_rows": 0,
            "cases": 0,
            "strict_gold_allowed_false": 0,
            "manual_review_samples": 0,
        },
        "manual_review_sample_ids": [],
        "strict_gold_blocked_sample_ids": [],
        "api_called": False,
        "benchmark_files_modified": False,
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    write_jsonl(output_dir / cases_name, [])
    write_json(output_dir / report_name, report)
    return report


def load_cases(path: Path) -> list[JsonObj]:
    return read_jsonl(path) if path.exists() else []


def classify_step_reasons(step: JsonObj, settings: AuditSettings) -> list[str]:
    reasons: list[str] = []
    if float(step.get("primary_support") or 0.0) < settings.primary_threshold:
        reasons.append("low_primary_support")
    if step.get("auxiliary_only"):
        reasons.append("auxiliary_only")
    step_reasons = [str(item) for item in step.get("reasons") or []]
    if any("missing_primary_ref" in item for item in step_reasons):
        reasons.append("missing_primary_refs")
        reasons.append("evidence_ref_missing_or_unresolved")
    if step.get("evidence_refs") and not step.get("missing_refs") and float(step.get("primary_support") or 0.0) < settings.primary_threshold:
        reasons.append("weak_text_overlap")
    if step.get("forbidden_hits") or step.get("vulnerability_hits") or any("unsupported_forbidden" in item or "unsupported_vulnerability" in item for item in step_reasons):
        reasons.append("forbidden_or_mechanism_claim")
    if step.get("step") == "final_judgement" and not step.get("strict_gold_allowed"):
        reasons.append("final_judgement_not_grounded")
    if not step.get("evidence_refs"):
        reasons.append("evidence_ref_missing_or_unresolved")
    return sorted(set(reasons))


def case_reason_categories(case: JsonObj, settings: AuditSettings) -> list[str]:
    categories: set[str] = set()
    for step in case.get("step_scores") or []:
        if isinstance(step, dict):
            categories.update(classify_step_reasons(step, settings))
    if not categories and case.get("verdict") in {"weak", "risky", "invalid"}:
        categories.add("weak_text_overlap")
    return sorted(categories)


def is_possible_over_conservative(case: JsonObj, settings: AuditSettings) -> bool:
    if not case.get("step_scores"):
        return False
    if not case.get("strict_gold_allowed"):
        return False
    for step in case["step_scores"]:
        if not step.get("evidence_refs") or step.get("missing_refs"):
            return False
        if step.get("auxiliary_only") or step.get("forbidden_hits") or step.get("vulnerability_hits"):
            return False
    return case.get("verdict") in {"weak", "risky", "invalid"} and float(case.get("average_weighted_score") or 0.0) >= 0.35


def is_reasonable_block(case: JsonObj) -> bool:
    if case.get("strict_gold_allowed"):
        return False
    joined = " ".join(str(reason) for reason in case.get("reasons") or [])
    return any(
        token in joined
        for token in (
            "unsupported_forbidden",
            "unsupported_vulnerability",
            "missing_primary_ref",
            "final_judgement_not_primary_grounded",
            "auxiliary_only",
            "missing_evidence_refs",
        )
    )


def manual_review_required(case: JsonObj) -> bool:
    return (not case.get("strict_gold_allowed")) or case.get("verdict") in {"weak", "risky", "invalid"}


def score_distribution(values: list[float]) -> JsonObj:
    bins = {
        "lt_0_25": 0,
        "0_25_to_0_35": 0,
        "0_35_to_0_55": 0,
        "0_55_to_0_75": 0,
        "gte_0_75": 0,
    }
    for value in values:
        if value < 0.25:
            bins["lt_0_25"] += 1
        elif value < 0.35:
            bins["0_25_to_0_35"] += 1
        elif value < 0.55:
            bins["0_35_to_0_55"] += 1
        elif value < 0.75:
            bins["0_55_to_0_75"] += 1
        else:
            bins["gte_0_75"] += 1
    return bins


def summarize_cases(cases: list[JsonObj], settings: AuditSettings) -> JsonObj:
    min_scores = [float(case.get("min_step_score") or 0.0) for case in cases]
    avg_scores = [float(case.get("average_weighted_score") or 0.0) for case in cases]
    category_counter = Counter(reason for case in cases for reason in case_reason_categories(case, settings))
    reason_category_counts = {name: category_counter.get(name, 0) for name in REVIEW_REASON_CATEGORIES}
    for name, count in category_counter.items():
        reason_category_counts.setdefault(name, count)
    return {
        "total_cases": len(cases),
        "by_verdict": dict(Counter(str(case.get("verdict")) for case in cases)),
        "manual_review_count": sum(1 for case in cases if manual_review_required(case)),
        "strict_gold_allowed_false_count": sum(1 for case in cases if not case.get("strict_gold_allowed")),
        "average_score": round(sum(avg_scores) / len(avg_scores), 4) if avg_scores else 0.0,
        "min_score_distribution": score_distribution(min_scores),
        "reason_category_counts": reason_category_counts,
        "possible_over_conservative_count": sum(1 for case in cases if is_possible_over_conservative(case, settings)),
        "reasonable_block_count": sum(1 for case in cases if is_reasonable_block(case)),
    }


def manual_review_rows(cases: list[JsonObj], settings: AuditSettings) -> list[JsonObj]:
    rows: list[JsonObj] = []
    for case in cases:
        categories = case_reason_categories(case, settings)
        rows.append(
            {
                "sample_id": case.get("sample_id"),
                "gold_stage": case.get("gold_stage"),
                "verdict": case.get("verdict"),
                "average_weighted_score": case.get("average_weighted_score"),
                "min_step_score": case.get("min_step_score"),
                "strict_gold_allowed": case.get("strict_gold_allowed"),
                "auxiliary_only_step_count": case.get("auxiliary_only_step_count"),
                "invalid_step_count": case.get("invalid_step_count"),
                "manual_review_required": manual_review_required(case),
                "reason_categories": categories,
                "possible_over_conservative": is_possible_over_conservative(case, settings),
                "reasonable_block": is_reasonable_block(case),
                "blocking_steps": [
                    {
                        "step_index": step.get("step_index"),
                        "step": step.get("step"),
                        "verdict": step.get("verdict"),
                        "strict_gold_allowed": step.get("strict_gold_allowed"),
                        "reasons": step.get("reasons"),
                    }
                    for step in case.get("step_scores") or []
                    if not step.get("strict_gold_allowed") or step.get("verdict") in {"risky", "invalid"}
                ],
            }
        )
    return rows


def profile_changes(base_cases: list[JsonObj], profile_cases: list[JsonObj]) -> JsonObj:
    base_by_id = {case.get("sample_id"): case for case in base_cases}
    profile_by_id = {case.get("sample_id"): case for case in profile_cases}
    blocked_to_allowed = []
    manual_to_pass = []
    verdict_changes = []
    for sample_id, profile_case in profile_by_id.items():
        base_case = base_by_id.get(sample_id)
        if not base_case:
            continue
        if not base_case.get("strict_gold_allowed") and profile_case.get("strict_gold_allowed"):
            blocked_to_allowed.append(sample_id)
        if manual_review_required(base_case) and not manual_review_required(profile_case):
            manual_to_pass.append(sample_id)
        if base_case.get("verdict") != profile_case.get("verdict"):
            verdict_changes.append(
                {
                    "sample_id": sample_id,
                    "from": base_case.get("verdict"),
                    "to": profile_case.get("verdict"),
                    "base_avg": base_case.get("average_weighted_score"),
                    "profile_avg": profile_case.get("average_weighted_score"),
                }
            )
    return {
        "blocked_to_allowed": blocked_to_allowed,
        "manual_review_to_pass": manual_to_pass,
        "verdict_changes": verdict_changes,
    }


def markdown_case_table(rows: list[JsonObj]) -> str:
    lines = [
        "# Strict Gold Blocked Cases",
        "",
        "| sample_id | verdict | avg | min | reasons | blocking steps |",
        "|---|---|---:|---:|---|---|",
    ]
    blocked = [row for row in rows if not row.get("strict_gold_allowed")]
    if not blocked:
        lines.append("| None |  |  |  |  |  |")
    for row in blocked:
        steps = "; ".join(
            f"{step.get('step_index')}:{step.get('step')}:{','.join(step.get('reasons') or [])}"
            for step in row.get("blocking_steps") or []
        )
        lines.append(
            "| `{}` | `{}` | {} | {} | {} | {} |".format(
                row.get("sample_id"),
                row.get("verdict"),
                row.get("average_weighted_score"),
                row.get("min_step_score"),
                ", ".join(row.get("reason_categories") or []),
                steps.replace("|", "\\|")[:500],
            )
        )
    return "\n".join(lines) + "\n"


def markdown_summary(report: JsonObj) -> str:
    default_summary = report["enhanced_default_summary"]
    lines = [
        "# Weighted Grounding Calibration Summary",
        "",
        "This is a local calibration report. It does not call APIs and does not relax strict gold automatically.",
        "",
        "## Enhanced Default",
        "",
        f"- Total cases: {default_summary['total_cases']}",
        f"- Verdicts: `{json.dumps(default_summary['by_verdict'], ensure_ascii=False)}`",
        f"- Manual review count: {default_summary['manual_review_count']}",
        f"- strict_gold_allowed=false: {default_summary['strict_gold_allowed_false_count']}",
        f"- Average score: {default_summary['average_score']}",
        f"- Possible over-conservative cases: {default_summary['possible_over_conservative_count']}",
        f"- Reasonable blocks: {default_summary['reasonable_block_count']}",
        "",
        "## Sensitivity",
        "",
        "| profile | verdicts | manual review | strict false | avg score | blocked->allowed | manual->pass |",
        "|---|---|---:|---:|---:|---|---|",
    ]
    for name, item in report["sensitivity"].items():
        summary = item["summary"]
        changes = item["changes_from_strict_current_default"]
        lines.append(
            "| `{}` | `{}` | {} | {} | {} | {} | {} |".format(
                name,
                json.dumps(summary["by_verdict"], ensure_ascii=False),
                summary["manual_review_count"],
                summary["strict_gold_allowed_false_count"],
                summary["average_score"],
                ", ".join(changes["blocked_to_allowed"]) or "-",
                ", ".join(changes["manual_review_to_pass"]) or "-",
            )
        )
    lines.extend(
        [
            "",
            "## Recommendation",
            "",
            report["recommendation"],
        ]
    )
    return "\n".join(lines) + "\n"


def find_no_input_and_gate_reports(input_dir: Path) -> JsonObj:
    reports: list[JsonObj] = []
    for path in sorted(input_dir.glob("**/*.json")):
        if path.name not in {
            "annotator_weighted_grounding_report.json",
            "reviewer_weighted_grounding_report.json",
            "multiagent_run_report.json",
        }:
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        reports.append(
            {
                "path": rel(path),
                "status": payload.get("status"),
                "blocked_reason": payload.get("blocked_reason"),
                "final_candidate_export_blocked": payload.get("final_candidate_export_blocked"),
                "api_called": payload.get("api_called"),
                "benchmark_files_modified": payload.get("benchmark_files_modified"),
            }
        )
    return {"reports": reports, "count": len(reports)}


def run_calibration_mode(args: argparse.Namespace, config: JsonObj, output_dir: Path) -> int:
    input_dir = args.calibration_input_dir if args.calibration_input_dir else output_dir.parent / "weighted_grounding_dry_run"
    input_dir = input_dir if input_dir.is_absolute() else ROOT / input_dir
    input_report_path = input_dir / "weighted_grounding_report.json"
    input_cases_path = input_dir / "weighted_grounding_cases.jsonl"
    input_report = json.loads(input_report_path.read_text(encoding="utf-8")) if input_report_path.exists() else {}
    input_cases = load_cases(input_cases_path)
    patch_path_text = str(input_report.get("inputs", {}).get("patches") or "")
    patch_path = args.patches if args.patches else (Path(patch_path_text) if patch_path_text else None)
    if patch_path is None:
        report = {
            "status": "no_input",
            "created_at": utc_now(),
            "blocked_reason": "missing_patches_for_sensitivity",
            "input_dir": rel(input_dir),
            "api_called": False,
            "benchmark_files_modified": False,
        }
        output_dir.mkdir(parents=True, exist_ok=True)
        write_json(output_dir / "weighted_grounding_calibration_report.json", report)
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return 1
    patch_path = patch_path if patch_path.is_absolute() else ROOT / patch_path
    if not patch_path.exists():
        report = {
            "status": "no_input",
            "created_at": utc_now(),
            "blocked_reason": f"missing_patches:{rel(patch_path)}",
            "input_dir": rel(input_dir),
            "api_called": False,
            "benchmark_files_modified": False,
        }
        output_dir.mkdir(parents=True, exist_ok=True)
        write_json(output_dir / "weighted_grounding_calibration_report.json", report)
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return 1

    patch_rows = read_jsonl(patch_path)
    enhanced_cases, enhanced_report = audit_patch_rows(
        config,
        patch_rows,
        role=args.role,
        patch_path=rel(patch_path),
        settings=AuditSettings(
            primary_threshold=args.primary_threshold,
            min_step_score_threshold=args.min_step_score_threshold,
            average_score_threshold=args.average_score_threshold,
            penalty_scale=args.penalty_scale,
            structural_matching=True,
        ),
    )
    baseline_cases, _ = audit_patch_rows(
        config,
        patch_rows,
        role=args.role,
        patch_path=rel(patch_path),
        settings=AuditSettings(structural_matching=False),
    )
    sensitivity: dict[str, JsonObj] = {}
    for profile_name, settings in SENSITIVITY_PROFILES.items():
        profile_cases, profile_report = audit_patch_rows(
            config,
            patch_rows,
            role=args.role,
            patch_path=rel(patch_path),
            settings=settings,
        )
        sensitivity[profile_name] = {
            "settings": asdict(settings),
            "summary": summarize_cases(profile_cases, settings),
            "changes_from_strict_current_default": profile_changes(enhanced_cases, profile_cases),
            "report_counts": profile_report.get("counts", {}),
        }

    enhanced_summary = summarize_cases(enhanced_cases, AuditSettings())
    baseline_summary = summarize_cases(baseline_cases, AuditSettings(structural_matching=False))
    table_rows = manual_review_rows(enhanced_cases, AuditSettings())
    over_conservative = [row for row in table_rows if row["possible_over_conservative"]]
    reasonable_blocks = [row for row in table_rows if row["reasonable_block"]]
    report = {
        "status": "success",
        "created_at": utc_now(),
        "schema_version": "weighted_grounding_calibration.v1",
        "input_dir": rel(input_dir),
        "input_report": rel(input_report_path) if input_report_path.exists() else "",
        "input_cases": rel(input_cases_path) if input_cases_path.exists() else "",
        "input_previous_summary": summarize_cases(input_cases, AuditSettings()) if input_cases else {},
        "patches": rel(patch_path),
        "enhanced_default_report": enhanced_report,
        "enhanced_default_summary": enhanced_summary,
        "baseline_without_structural_matching_summary": baseline_summary,
        "enhanced_vs_previous_or_no_structural": {
            "manual_review_count_delta_vs_previous": (
                enhanced_summary["manual_review_count"] - summarize_cases(input_cases, AuditSettings())["manual_review_count"]
                if input_cases else None
            ),
            "strict_false_delta_vs_previous": (
                enhanced_summary["strict_gold_allowed_false_count"] - summarize_cases(input_cases, AuditSettings())["strict_gold_allowed_false_count"]
                if input_cases else None
            ),
            "changes_vs_no_structural": profile_changes(baseline_cases, enhanced_cases),
        },
        "sensitivity": sensitivity,
        "sensitivity_analysis": sensitivity,
        "manual_review_reason_category_counts": enhanced_summary["reason_category_counts"],
        "reason_category_counts": enhanced_summary["reason_category_counts"],
        "strict_gold_blocked_cases": [row for row in table_rows if not row["strict_gold_allowed"]],
        "possible_over_conservative_cases": over_conservative,
        "possible_overconservative_cases": over_conservative,
        "reasonable_block_cases": reasonable_blocks,
        "reasonable_blocks": reasonable_blocks,
        "no_input_and_gate_mock_summary": find_no_input_and_gate_reports(input_dir),
        "recommendation": (
            "Do not adjust default thresholds automatically. The enhanced structural matcher reduces text-overlap dependence, "
            "but all strict_gold_allowed=false samples must remain manual review. Use medium_candidate only for human threshold review."
        ),
        "api_called": False,
        "benchmark_files_modified": False,
        "canonical_gold_overwrite_allowed": False,
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    write_json(output_dir / "weighted_grounding_calibration_report.json", report)
    write_jsonl(output_dir / "manual_review_case_table.jsonl", table_rows)
    write_jsonl(output_dir / "enhanced_weighted_grounding_cases.jsonl", enhanced_cases)
    write_json(output_dir / "enhanced_weighted_grounding_report.json", enhanced_report)
    (output_dir / "strict_gold_blocked_cases.md").write_text(markdown_case_table(table_rows), encoding="utf-8")
    (output_dir / "weighted_grounding_calibration_summary.md").write_text(markdown_summary(report), encoding="utf-8")
    print(json.dumps({
        "status": "success",
        "output_dir": rel(output_dir),
        "enhanced_default_summary": enhanced_summary,
        "baseline_without_structural_matching_summary": baseline_summary,
        "sensitivity_profiles": {key: value["summary"] for key, value in sensitivity.items()},
        "api_called": False,
    }, ensure_ascii=False, indent=2))
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run local weighted grounding audit for EWVAA patches.")
    parser.add_argument("--config", type=Path, default=config_path_from_args([]))
    parser.add_argument("--patches", type=Path, help="Patch JSONL to audit.")
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--role", default="debug", choices=("annotator", "reviewer", "merged", "debug"))
    parser.add_argument("--report-name", default="weighted_grounding_report.json")
    parser.add_argument("--cases-name", default="weighted_grounding_cases.jsonl")
    default_settings = AuditSettings()
    parser.add_argument("--primary-threshold", type=float, default=default_settings.primary_threshold)
    parser.add_argument("--min-step-score-threshold", type=float, default=default_settings.min_step_score_threshold)
    parser.add_argument("--average-score-threshold", type=float, default=default_settings.average_score_threshold)
    parser.add_argument("--penalty-scale", type=float, default=default_settings.penalty_scale)
    parser.add_argument("--calibration-mode", action="store_true")
    parser.add_argument("--calibration-input-dir", type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    config = load_config(args.config if args.config.is_absolute() else ROOT / args.config)
    output_dir = args.output_dir if args.output_dir.is_absolute() else ROOT / args.output_dir
    settings = AuditSettings(
        primary_threshold=args.primary_threshold,
        min_step_score_threshold=args.min_step_score_threshold,
        average_score_threshold=args.average_score_threshold,
        penalty_scale=args.penalty_scale,
    )
    if args.calibration_mode:
        return run_calibration_mode(args, config, output_dir)
    if not args.patches:
        report = blocked_no_input_report(
            output_dir=output_dir,
            role=args.role,
            report_name=args.report_name,
            cases_name=args.cases_name,
            reason="missing_patches_argument",
        )
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return 1
    patch_path = args.patches if args.patches.is_absolute() else ROOT / args.patches
    if not patch_path.exists():
        report = blocked_no_input_report(
            output_dir=output_dir,
            role=args.role,
            report_name=args.report_name,
            cases_name=args.cases_name,
            reason=f"missing_patches:{rel(patch_path)}",
            patch_path=patch_path,
        )
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return 1
    patch_rows = read_jsonl(patch_path)
    report = write_audit_outputs(
        config=config,
        patch_rows=patch_rows,
        output_dir=output_dir,
        role=args.role,
        report_name=args.report_name,
        cases_name=args.cases_name,
        patch_path=rel(patch_path),
        settings=settings,
    )
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report.get("status") == "success" else 1


if __name__ == "__main__":
    raise SystemExit(main())
