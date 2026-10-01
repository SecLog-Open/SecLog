#!/usr/bin/env python3
"""GPT-as-Judge review for EWVAA reasoning quality.

This script is read-only with respect to benchmark inputs and prior trial
outputs. It builds a compact judge input package for exactly the selected
samples, optionally calls an OpenAI-compatible judge model, and writes a
separate review directory with inputs, outputs, summary, and README.

Formal EWVAA judge runs should review masked-workbench-derived candidates,
use annotation_context.v0.4 auxiliary facts, treat forbidden strict-chain terms
as hard invalid, and remember that patched_gold artefacts are candidates that
must not overwrite canonical gold.jsonl.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import traceback
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable


PACKAGE_ROOT = Path(__file__).resolve().parents[3]
PRIVATE_WORK_ROOT = Path("workdir")
DEFAULT_PATCHES = PRIVATE_WORK_ROOT / "annotation_runs/merged_reasoning_patches.unmasked.jsonl"
DEFAULT_PATCHED_GOLD = PRIVATE_WORK_ROOT / "annotation_runs/patched_gold.candidate.jsonl"
DEFAULT_GROUNDING_REPORT = PRIVATE_WORK_ROOT / "annotation_runs/repair_grounding_audit_report.json"
DEFAULT_GROUNDING_CASES = PRIVATE_WORK_ROOT / "annotation_runs/repair_grounding_audit_cases.jsonl"
DEFAULT_MODEL_INPUT = PRIVATE_WORK_ROOT / "canonical_benchmark/data/model_input.jsonl"
DEFAULT_GOLD = PRIVATE_WORK_ROOT / "canonical_benchmark/data/gold.jsonl"
DEFAULT_SAMPLE_INDEX = PRIVATE_WORK_ROOT / "canonical_benchmark/data/sample_index.jsonl"
DEFAULT_VULN_FACTS = (
    PACKAGE_ROOT
    / "05_benchmark_annotation_review_evaluation/assets/auxiliary_context/"
    "scenario_vulnerability_facts.annotation_context.v0.4.json"
)
DEFAULT_OUTPUT_DIR = PRIVATE_WORK_ROOT / "reasoning_quality_judge"

VERDICTS = {"accept", "minor_revision", "major_revision", "reject"}
PROBLEM_TYPES = {
    "ungrounded_claim",
    "weak_evidence_ref",
    "cve_overuse",
    "hallucination",
    "too_template_like",
    "unsafe_wording",
    "stage_mismatch",
    "other",
}
SEVERITIES = {"low", "medium", "high"}
SCORE_KEYS = [
    "stage_alignment",
    "primary_evidence_grounding",
    "evidence_ref_quality",
    "auxiliary_context_use",
    "no_hallucination",
    "specificity",
    "language_safety",
]
RISKY_WORD_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("exploit", re.compile(r"\bexploit(?:ation|ed|ing|s)?\b", re.IGNORECASE)),
    ("payload", re.compile(r"\bpayloads?\b", re.IGNORECASE)),
    ("RCE", re.compile(r"\brce\b|remote\s+code\s+execution", re.IGNORECASE)),
    ("XXE", re.compile(r"\bxxe\b|external\s+entity", re.IGNORECASE)),
    ("shell", re.compile(r"\bshell\b", re.IGNORECASE)),
    ("exfiltration", re.compile(r"\bexfiltrat(?:e|ion|ed)\b", re.IGNORECASE)),
    ("privilege escalation", re.compile(r"\bprivilege\s+escalation\b", re.IGNORECASE)),
]

JsonObj = dict[str, Any]


def read_jsonl(path: Path) -> list[JsonObj]:
    rows: list[JsonObj] = []
    with path.open("r", encoding="utf-8") as fh:
        for line_no, line in enumerate(fh, 1):
            text = line.strip()
            if not text:
                continue
            row = json.loads(text)
            row["_line_no"] = line_no
            rows.append(row)
    return rows


def read_jsonl_filtered(path: Path, sample_ids: set[str]) -> list[JsonObj]:
    if not sample_ids:
        return []
    rows: list[JsonObj] = []
    with path.open("r", encoding="utf-8") as fh:
        for line_no, line in enumerate(fh, 1):
            text = line.strip()
            if not text:
                continue
            row = json.loads(text)
            sample_id = row.get("sample_id")
            if sample_id not in sample_ids:
                continue
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


def build_messages(judge_input: JsonObj) -> list[JsonObj]:
    system = (
        "You are GPT-as-Judge for stage_reasoning gold candidate quality review. "
        "Do not rewrite the reasoning chain. Do not predict the stage. "
        "Evaluate whether the provided qwen-generated gold_reasoning_chain is a good candidate gold explanation for the given gold_stage. "
        "Use primary evidence as the main basis. Vulnerability facts are auxiliary context only. "
        "If a key claim is not supported by the cited seq/edge_id evidence, score it down. "
        "Be strict about hallucination, unsupported exploit wording, CVE-overuse, and weak evidence references. "
        "Return JSON only."
    )
    criteria = {
        "task": "Judge only the quality of the provided gold_reasoning_chain as a candidate gold. Do not propose a replacement chain.",
        "scoring_dimensions": {
            "stage_alignment": "Does the reasoning correctly support the given gold_stage rather than re-predicting it?",
            "primary_evidence_grounding": "Are the strict-chain claims mainly supported by primary evidence?",
            "evidence_ref_quality": "Are evidence_refs specific, valid, and actually used in the final judgement?",
            "auxiliary_context_use": "Are CVE or vulnerability facts used only as background and not as stage evidence?",
            "no_hallucination": "Does the reasoning avoid unseen request bodies, shells, exfiltration, privilege escalation, or unsupported success claims?",
            "specificity": "Is the reasoning concrete and behavior-specific rather than generic template text?",
            "language_safety": "Does the strict chain avoid unsupported exploit/RCE/XXE wording, avoid 'no exploitation' wording for stage_unclosed, and avoid unsupported outcome claims for result?",
        },
        "verdict_policy": {
            "accept": "overall_score >= 4.5 and no high severity problem",
            "minor_revision": "overall_score >= 3.5 and only low/medium problems",
            "major_revision": "overall_score >= 2.5 and there are clear grounding or expression issues",
            "reject": "overall_score < 2.5, or there is hallucination, CVE-only strict reasoning, or stage mismatch",
        },
        "output_schema": {
            "sample_id": "...",
            "gold_stage": "...",
            "scores": {key: "1-5" for key in SCORE_KEYS},
            "overall_score": "1-5 number",
            "verdict": "accept | minor_revision | major_revision | reject",
            "problems": [
                {
                    "type": "ungrounded_claim | weak_evidence_ref | cve_overuse | hallucination | too_template_like | unsafe_wording | stage_mismatch | other",
                    "severity": "low | medium | high",
                    "description": "...",
                }
            ],
            "best_claims": ["..."],
            "revision_suggestion": "...",
        },
    }
    return [
        {"role": "system", "content": system},
        {
            "role": "user",
            "content": json.dumps(
                {
                    "judge_instruction": criteria,
                    "sample_review_input": judge_input,
                },
                ensure_ascii=False,
                indent=2,
            ),
        },
    ]


def call_openai_compatible(
    judge_input: JsonObj,
    *,
    api_key: str,
    base_url: str,
    model: str,
    temperature: float,
    timeout: float,
    max_retries: int,
) -> JsonObj:
    try:
        from openai import OpenAI  # type: ignore
    except ImportError:
        return {"error": "openai package not installed – pip install openai"}

    client = OpenAI(api_key=api_key, base_url=base_url, timeout=timeout)
    messages = build_messages(judge_input)
    last_exc: Exception | None = None
    for attempt in range(1, max_retries + 2):
        try:
            response = client.chat.completions.create(
                model=model,
                messages=messages,
                temperature=temperature,
                response_format={"type": "json_object"},
            )
            content = response.choices[0].message.content or ""
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
            if attempt <= max_retries:
                time.sleep(2**attempt)
    return {"error": str(last_exc), "traceback": traceback.format_exc()}


def coerce_int(value: Any) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def short_text(value: str, limit: int = 240) -> str:
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    return text if len(text) <= limit else text[: limit - 3] + "..."


def summarize_event_context(item: Any) -> JsonObj:
    if not isinstance(item, dict):
        return {"text": short_text(str(item), 120)}
    event = item.get("event")
    if isinstance(event, dict):
        return {
            "relation": event.get("relation"),
            "object": short_text(event.get("object")),
            "event_type": event.get("event_type"),
            "reason": event.get("reason"),
        }
    return {
        "context_role": item.get("context_role"),
        "attach_reason": item.get("attach_reason"),
    }


def summarize_traffic(item: Any) -> JsonObj:
    if not isinstance(item, dict):
        return {"text": short_text(str(item), 120)}
    return {
        "src_ip": item.get("src_ip"),
        "src_port": item.get("src_port"),
        "dst_ip": item.get("dst_ip"),
        "dst_port": item.get("dst_port"),
        "summary_type": item.get("summary_type"),
        "semantic_type": item.get("semantic_type"),
    }


def summarize_applog(item: Any) -> JsonObj:
    if not isinstance(item, dict):
        return {"message": short_text(str(item), 120)}
    return {
        "line_no": item.get("line_no"),
        "semantic_type": item.get("semantic_type"),
        "message": short_text(item.get("message", ""), 240),
    }


def summarize_edge(edge: JsonObj) -> JsonObj:
    multisource = edge.get("multisource_context") if isinstance(edge.get("multisource_context"), dict) else {}
    audit_context = edge.get("audit_context") if isinstance(edge.get("audit_context"), list) else []
    return {
        "seq": coerce_int(edge.get("seq")),
        "edge_id": edge.get("edge_id"),
        "relation": edge.get("relation"),
        "subject": short_text(edge.get("subject")),
        "object": short_text(edge.get("object")),
        "timestamp": (edge.get("attrs") or {}).get("timestamp") or edge.get("timestamp"),
        "raw_evt_type": (edge.get("attrs") or {}).get("raw_evt_type") or edge.get("raw_evt_type"),
        "fd_name": (edge.get("attrs") or {}).get("fd_name") or edge.get("fd_name"),
        "audit_context": [summarize_event_context(item) for item in audit_context[:3]],
        "applog": [summarize_applog(item) for item in (multisource.get("applog") or [])[:3]],
        "traffic": [summarize_traffic(item) for item in (multisource.get("traffic") or [])[:3]],
    }


def find_referenced_edges(spine: list[JsonObj], chain: list[JsonObj]) -> list[JsonObj]:
    by_seq = {coerce_int(edge.get("seq")): edge for edge in spine}
    ordered: list[JsonObj] = []
    seen: set[tuple[int | None, str | None]] = set()
    for step in chain:
        if not isinstance(step, dict):
            continue
        for ref in step.get("evidence_refs") or []:
            if not isinstance(ref, dict):
                continue
            seq = coerce_int(ref.get("seq"))
            edge_id = str(ref.get("edge_id")) if ref.get("edge_id") is not None else None
            key = (seq, edge_id)
            if key in seen:
                continue
            edge = by_seq.get(seq)
            if edge is None:
                continue
            ordered.append(summarize_edge(edge))
            seen.add(key)
    return ordered


def summarize_spine_window(spine: list[JsonObj]) -> JsonObj:
    return {
        "spine_edge_count": len(spine),
        "first_edges": [summarize_edge(edge) for edge in spine[:3]],
        "last_edges": [summarize_edge(edge) for edge in spine[-3:]] if len(spine) > 3 else [],
    }


def load_vulnerability_facts(path: Path) -> dict[str, JsonObj]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    scenarios = raw.get("scenarios")
    if not isinstance(scenarios, list):
        return {}
    result: dict[str, JsonObj] = {}
    for item in scenarios:
        if not isinstance(item, dict):
            continue
        sid = item.get("scenario_id")
        if isinstance(sid, str):
            result[sid] = item
    return result


def prune_vulnerability_facts(facts: JsonObj | None) -> JsonObj:
    facts = facts or {}
    return {
        "scenario_id": facts.get("scenario_id"),
        "scenario_type": facts.get("scenario_type"),
        "cve_ids": facts.get("cve_ids"),
        "safe_annotation_summary": facts.get("safe_annotation_summary"),
        "confirmed_weakness": facts.get("confirmed_weakness"),
        "confirmed_impact": facts.get("confirmed_impact"),
        "affected_component": facts.get("affected_component"),
        "quality_flags": facts.get("quality_flags"),
        "annotation_use_policy": facts.get("annotation_use_policy"),
    }


def risky_terms_in_chain(chain: list[JsonObj]) -> dict[str, list[str]]:
    hits: dict[str, list[str]] = {}
    for step in chain:
        if not isinstance(step, dict):
            continue
        claim = str(step.get("claim", ""))
        found = [name for name, pattern in RISKY_WORD_PATTERNS if pattern.search(claim)]
        if found:
            hits[str(step.get("step", "?"))] = found
    return hits


def build_judge_input(
    patch_row: JsonObj,
    model_row: JsonObj,
    gold_row: JsonObj,
    index_row: JsonObj,
    vuln_facts: JsonObj | None,
    grounding_case: JsonObj | None,
    grounding_report: JsonObj,
    patched_gold_row: JsonObj | None,
) -> JsonObj:
    spine = ((model_row.get("input") or {}).get("spine") or []) if isinstance(model_row, dict) else []
    chain = patch_row.get("gold_reasoning_chain") if isinstance(patch_row.get("gold_reasoning_chain"), list) else []
    sample_id = str(patch_row.get("sample_id") or model_row.get("sample_id") or gold_row.get("sample_id") or "")
    gold_stage = str(
        patch_row.get("gold_stage")
        or ((gold_row.get("label") or {}).get("stage"))
        or index_row.get("stage")
        or ""
    )
    scenario_id = str(
        patch_row.get("scenario_id")
        or model_row.get("scenario_id")
        or gold_row.get("scenario_id")
        or index_row.get("scenario_id")
        or ""
    )
    judge_input = {
        "sample_id": sample_id,
        "scenario_id": scenario_id,
        "gold_stage": gold_stage,
        "window": model_row.get("window") or gold_row.get("window") or index_row.get("window"),
        "primary_evidence_summary": {
            "quoted_edge_pool": find_referenced_edges(spine, chain),
            "spine_window_overview": summarize_spine_window(spine),
        },
        "qwen_candidate_gold_reasoning_chain": chain,
        "auxiliary_vulnerability_note": patch_row.get("auxiliary_vulnerability_note"),
        "prompt_safe_vulnerability_facts": prune_vulnerability_facts(vuln_facts),
        "grounding_audit": {
            "case": grounding_case or {},
            "report_counts": (grounding_report or {}).get("counts", {}),
        },
        "source_checks": {
            "sample_index_line": index_row.get("line_no"),
            "patched_gold_contains_sample": isinstance(patched_gold_row, dict),
            "risky_terms_in_strict_chain": risky_terms_in_chain(chain),
        },
    }
    return judge_input


def validate_judge_output(obj: JsonObj, expected_sample_id: str, expected_stage: str) -> list[str]:
    errors: list[str] = []
    if str(obj.get("sample_id")) != expected_sample_id:
        errors.append(f"sample_id_mismatch:{obj.get('sample_id')}")
    if str(obj.get("gold_stage")) != expected_stage:
        errors.append(f"gold_stage_mismatch:{obj.get('gold_stage')}")
    scores = obj.get("scores")
    if not isinstance(scores, dict):
        errors.append("scores_not_object")
    else:
        for key in SCORE_KEYS:
            value = scores.get(key)
            if not isinstance(value, (int, float)) or not (1 <= float(value) <= 5):
                errors.append(f"invalid_score:{key}:{value}")
    overall = obj.get("overall_score")
    if not isinstance(overall, (int, float)) or not (1 <= float(overall) <= 5):
        errors.append(f"invalid_overall_score:{overall}")
    verdict = obj.get("verdict")
    if verdict not in VERDICTS:
        errors.append(f"invalid_verdict:{verdict}")
    problems = obj.get("problems")
    if not isinstance(problems, list):
        errors.append("problems_not_list")
    else:
        for idx, problem in enumerate(problems):
            if not isinstance(problem, dict):
                errors.append(f"problem_not_object:{idx}")
                continue
            if problem.get("type") not in PROBLEM_TYPES:
                errors.append(f"invalid_problem_type:{idx}:{problem.get('type')}")
            if problem.get("severity") not in SEVERITIES:
                errors.append(f"invalid_problem_severity:{idx}:{problem.get('severity')}")
            if not str(problem.get("description", "")).strip():
                errors.append(f"empty_problem_description:{idx}")
    best_claims = obj.get("best_claims")
    if not isinstance(best_claims, list) or not all(isinstance(item, str) for item in best_claims):
        errors.append("best_claims_not_string_list")
    if not isinstance(obj.get("revision_suggestion"), str):
        errors.append("revision_suggestion_not_string")
    return errors


def average(values: list[float]) -> float:
    return round(sum(values) / len(values), 3) if values else 0.0


def summarize_results(
    outputs: list[JsonObj],
    *,
    total_expected: int,
    judge_model: str,
    status: str,
    api_failures: list[JsonObj],
) -> JsonObj:
    verdict_counter = Counter()
    score_values: dict[str, list[float]] = defaultdict(list)
    overall_values: list[float] = []
    problem_counter = Counter()
    high_samples: list[str] = []
    for row in outputs:
        verdict = row.get("verdict")
        if verdict in VERDICTS:
            verdict_counter[str(verdict)] += 1
        scores = row.get("scores") if isinstance(row.get("scores"), dict) else {}
        for key in SCORE_KEYS:
            value = scores.get(key)
            if isinstance(value, (int, float)):
                score_values[key].append(float(value))
        if isinstance(row.get("overall_score"), (int, float)):
            overall_values.append(float(row["overall_score"]))
        high = False
        for problem in row.get("problems") if isinstance(row.get("problems"), list) else []:
            if isinstance(problem, dict):
                if problem.get("type") in PROBLEM_TYPES:
                    problem_counter[str(problem["type"])] += 1
                if problem.get("severity") == "high":
                    high = True
        if high:
            high_samples.append(str(row.get("sample_id")))

    recommended = (
        "Do not freeze the unified benchmark yet; revise or replace the rejected/high-severity samples first, then rerun the judge."
        if high_samples or verdict_counter.get("reject", 0) > 0
        else "Conditionally suitable for limited A/B expansion after applying the minor/major revisions identified by the judge."
        if verdict_counter.get("major_revision", 0) or verdict_counter.get("minor_revision", 0)
        else "Suitable to advance to the unified benchmark freeze."
    )
    summary = {
        "status": status,
        "judge_model": judge_model,
        "total": total_expected,
        "accept": verdict_counter.get("accept", 0),
        "minor_revision": verdict_counter.get("minor_revision", 0),
        "major_revision": verdict_counter.get("major_revision", 0),
        "reject": verdict_counter.get("reject", 0),
        "average_scores": {
            **{key: average(score_values[key]) for key in SCORE_KEYS},
            "overall_score": average(overall_values),
        },
        "problem_type_counts": dict(problem_counter),
        "high_severity_samples": high_samples,
        "recommended_next_step": recommended,
        "api_failures": api_failures,
        "completed_outputs": len(outputs),
    }
    return summary


def build_readme(summary: JsonObj, run_config: JsonObj) -> str:
    return "\n".join(
        [
            "# EWVAA GPT Judge Review",
            "",
            "This directory contains a standalone GPT-as-Judge quality review for the 10-sample EWVAA v2 qwen3.5-flash reasoning trial.",
            "",
            "Boundaries respected:",
            "- `gold.jsonl` was not modified.",
            "- `model_input.jsonl` was not modified.",
            "- `sample_index.jsonl` was not modified.",
            "- `patched_gold.jsonl` from the qwen trial was not modified.",
            "- The benchmark main structure was not modified.",
            "- No CVE collection, exploit execution, or API key logging was performed.",
            "",
            f"Judge model: {summary.get('judge_model')}",
            f"Status: {summary.get('status')}",
            f"Requested limit: {run_config.get('limit')}",
            f"Temperature: {run_config.get('temperature')}",
            f"OpenAI base URL set: {run_config.get('base_url_set')}",
            f"OpenAI API key set: {run_config.get('api_key_set')}",
            "",
            "Outputs:",
            "- `gpt_judge_inputs.jsonl`: per-sample review packets sent to the judge.",
            "- `gpt_judge_outputs.jsonl`: per-sample judge verdicts.",
            "- `gpt_judge_summary.json`: aggregate counts, averages, high-severity samples, and recommended next step.",
            "- `README.md`: this note.",
            "",
        ]
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Judge masked-workbench EWVAA reasoning quality with GPT-as-Judge."
    )
    parser.add_argument("--reasoning-patches", type=Path, default=DEFAULT_PATCHES)
    parser.add_argument("--patched-gold", type=Path, default=DEFAULT_PATCHED_GOLD)
    parser.add_argument("--grounding-audit-report", type=Path, default=DEFAULT_GROUNDING_REPORT)
    parser.add_argument("--grounding-audit-cases", type=Path, default=DEFAULT_GROUNDING_CASES)
    parser.add_argument("--model-input", type=Path, default=DEFAULT_MODEL_INPUT)
    parser.add_argument("--gold", type=Path, default=DEFAULT_GOLD)
    parser.add_argument("--sample-index", type=Path, default=DEFAULT_SAMPLE_INDEX)
    parser.add_argument("--vulnerability-facts", type=Path, default=DEFAULT_VULN_FACTS)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--limit", type=int, default=10)
    parser.add_argument("--model", help="Override OPENAI_MODEL.")
    parser.add_argument("--temperature", type=float, default=0.0)
    parser.add_argument("--timeout", type=float, default=120.0)
    parser.add_argument("--max-retries", type=int, default=1)
    parser.add_argument("--dry-run", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    patch_rows = read_jsonl(args.reasoning_patches)[: args.limit]
    sample_ids = {
        str(row.get("sample_id"))
        for row in patch_rows
        if isinstance(row, dict) and isinstance(row.get("sample_id"), str)
    }
    patched_gold_rows = read_jsonl_filtered(args.patched_gold, sample_ids)
    grounding_report = json.loads(args.grounding_audit_report.read_text(encoding="utf-8"))
    grounding_cases = {row["sample_id"]: row for row in read_jsonl_filtered(args.grounding_audit_cases, sample_ids)}
    model_by_id = {row["sample_id"]: row for row in read_jsonl_filtered(args.model_input, sample_ids)}
    gold_by_id = {row["sample_id"]: row for row in read_jsonl_filtered(args.gold, sample_ids)}
    index_by_id = {row["sample_id"]: row for row in read_jsonl_filtered(args.sample_index, sample_ids)}
    vuln_by_scenario = load_vulnerability_facts(args.vulnerability_facts)
    patched_gold_by_id = {row["sample_id"]: row for row in patched_gold_rows if isinstance(row.get("sample_id"), str)}

    judge_inputs: list[JsonObj] = []
    missing_inputs: list[str] = []
    for patch_row in patch_rows:
        sample_id = str(patch_row.get("sample_id") or "")
        model_row = model_by_id.get(sample_id)
        gold_row = gold_by_id.get(sample_id)
        index_row = index_by_id.get(sample_id)
        if not isinstance(model_row, dict) or not isinstance(gold_row, dict) or not isinstance(index_row, dict):
            missing_inputs.append(sample_id)
            continue
        scenario_id = str(
            patch_row.get("scenario_id")
            or model_row.get("scenario_id")
            or gold_row.get("scenario_id")
            or index_row.get("scenario_id")
            or ""
        )
        judge_inputs.append(
            build_judge_input(
                patch_row,
                model_row,
                gold_row,
                index_row,
                vuln_by_scenario.get(scenario_id),
                grounding_cases.get(sample_id),
                grounding_report,
                patched_gold_by_id.get(sample_id),
            )
        )

    args.output_dir.mkdir(parents=True, exist_ok=True)
    write_jsonl(args.output_dir / "gpt_judge_inputs.jsonl", judge_inputs)

    model = args.model or os.environ.get("OPENAI_MODEL", "")
    api_key = os.environ.get("OPENAI_API_KEY", "")
    base_url = os.environ.get("OPENAI_BASE_URL", "")
    run_config = {
        "reasoning_patches": str(args.reasoning_patches),
        "patched_gold": str(args.patched_gold),
        "grounding_audit_report": str(args.grounding_audit_report),
        "grounding_audit_cases": str(args.grounding_audit_cases),
        "model_input": str(args.model_input),
        "gold": str(args.gold),
        "sample_index": str(args.sample_index),
        "vulnerability_facts": str(args.vulnerability_facts),
        "output_dir": str(args.output_dir),
        "limit": args.limit,
        "temperature": args.temperature,
        "timeout": args.timeout,
        "max_retries": args.max_retries,
        "model": model,
        "base_url_set": bool(base_url),
        "api_key_set": bool(api_key),
        "missing_inputs": missing_inputs,
    }
    write_json(args.output_dir / "run_config.json", run_config)

    if args.dry_run:
        summary = summarize_results(
            [],
            total_expected=len(judge_inputs),
            judge_model=model or "unset",
            status="dry_run",
            api_failures=[],
        )
        write_jsonl(args.output_dir / "gpt_judge_outputs.jsonl", [])
        write_json(args.output_dir / "gpt_judge_summary.json", summary)
        (args.output_dir / "README.md").write_text(build_readme(summary, run_config), encoding="utf-8")
        print(json.dumps(summary, ensure_ascii=False, indent=2))
        return 0

    missing_env = []
    if not api_key:
        missing_env.append("OPENAI_API_KEY")
    if not base_url:
        missing_env.append("OPENAI_BASE_URL")
    if not model:
        missing_env.append("OPENAI_MODEL")
    if missing_env:
        failures = [
            {
                "type": "blocked",
                "reason": "missing environment variables: " + ",".join(missing_env),
            }
        ]
        summary = summarize_results(
            [],
            total_expected=len(judge_inputs),
            judge_model=model or "unset",
            status="blocked",
            api_failures=failures,
        )
        write_jsonl(args.output_dir / "gpt_judge_outputs.jsonl", [])
        write_json(args.output_dir / "gpt_judge_summary.json", summary)
        (args.output_dir / "README.md").write_text(build_readme(summary, run_config), encoding="utf-8")
        print("ERROR: " + failures[0]["reason"], file=sys.stderr)
        return 1

    outputs: list[JsonObj] = []
    failures: list[JsonObj] = []
    for idx, judge_input in enumerate(judge_inputs, 1):
        sample_id = str(judge_input["sample_id"])
        gold_stage = str(judge_input["gold_stage"])
        print(f"[{idx}/{len(judge_inputs)}] judging {sample_id} stage={gold_stage} ...", flush=True)
        result = call_openai_compatible(
            judge_input,
            api_key=api_key,
            base_url=base_url,
            model=model,
            temperature=args.temperature,
            timeout=args.timeout,
            max_retries=args.max_retries,
        )
        if "error" in result:
            failures.append(
                {
                    "sample_id": sample_id,
                    "error": str(result["error"])[:400],
                    "provider": "openai-compatible",
                }
            )
            continue
        parsed = extract_json(str(result.get("raw_content", "")))
        if parsed is None:
            failures.append(
                {
                    "sample_id": sample_id,
                    "error": "json_parse_error",
                    "provider": "openai-compatible",
                }
            )
            continue
        validation_errors = validate_judge_output(parsed, sample_id, gold_stage)
        if validation_errors:
            failures.append(
                {
                    "sample_id": sample_id,
                    "error": "invalid_judge_output:" + ";".join(validation_errors[:8]),
                    "provider": "openai-compatible",
                }
            )
            continue
        parsed["judge_model"] = result.get("model", model)
        parsed["provider"] = result.get("provider")
        parsed["usage"] = result.get("usage")
        outputs.append(parsed)

    write_jsonl(args.output_dir / "gpt_judge_outputs.jsonl", outputs)
    summary = summarize_results(
        outputs,
        total_expected=len(judge_inputs),
        judge_model=(outputs[0].get("judge_model") if outputs else model),
        status="success" if len(outputs) == len(judge_inputs) else "partial" if outputs else "failed",
        api_failures=failures,
    )
    write_json(args.output_dir / "gpt_judge_summary.json", summary)
    (args.output_dir / "README.md").write_text(build_readme(summary, run_config), encoding="utf-8")

    print("JUDGE SUMMARY")
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
