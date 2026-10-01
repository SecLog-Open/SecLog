#!/usr/bin/env python3
"""Compute public SecLog-Bench reasoning-quality and consistency metrics.

Score normalized model predictions using blinded post-hoc C1/C2 judgments.
"""
from __future__ import annotations

import argparse
import json
import math
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable, Mapping

from prepare_reasoning_quality_inputs import reasoning_units


STAGES = ("preparation", "execution", "result", "stage_unclosed")
SUBSTANTIVE_TYPES = {
    "observable_fact",
    "cross_source_linkage",
    "operation_inference",
    "outcome_inference",
    "boundary_or_missing_evidence",
    "final_stage_judgement",
}
THRESHOLD_SRP = 0.33
THRESHOLD_SCC = 0.50
THRESHOLD_SRF1 = 0.45
COVERAGE_SCORE = {"none": 0.0, "partial": 0.5, "full": 1.0}


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as stream:
        for line_no, line in enumerate(stream, 1):
            if not line.strip():
                continue
            value = json.loads(line)
            if not isinstance(value, dict):
                raise ValueError(f"{path}:{line_no}: expected JSON object")
            rows.append(value)
    return rows


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: Iterable[Mapping[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as stream:
        for row in rows:
            stream.write(json.dumps(dict(row), ensure_ascii=False) + "\n")


def harmonic_mean(a: float, b: float) -> float:
    return 0.0 if a <= 0.0 or b <= 0.0 else 2.0 * a * b / (a + b)


def predicted_stage(row: Mapping[str, Any]) -> str:
    value = str(row.get("normalized_stage") or row.get("predicted_stage") or "").strip().lower()
    return value if value in STAGES else "invalid_stage"


def condition_coverage_score(item: Mapping[str, Any]) -> float:
    value = item.get("coverage_score")
    if "coverage_score" in item:
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or not 0.0 <= value <= 1.0:
            raise ValueError(f"coverage_score must be a finite number in [0,1], got {value!r}")
        return float(value)
    coverage = str(item.get("coverage") or "")
    if coverage not in COVERAGE_SCORE:
        raise ValueError(f"invalid coverage category: {coverage!r}")
    return COVERAGE_SCORE[coverage]


def stage_condition_coverage(row: Mapping[str, Any]) -> float:
    items = row.get("checklist_coverage")
    if not isinstance(items, list) or not items:
        raise ValueError("closure checks require a nonempty reference-condition checklist")
    condition_ids: set[str] = set()
    scores: list[float] = []
    for item in items:
        if not isinstance(item, Mapping):
            raise ValueError("checklist items must be objects")
        condition_id = item.get("condition_id")
        if not isinstance(condition_id, str) or not condition_id or condition_id in condition_ids:
            raise ValueError(f"missing or duplicate condition_id: {condition_id!r}")
        condition_ids.add(condition_id)
        if item.get("importance") not in {"key", "optional"}:
            raise ValueError(f"{condition_id}: importance must be key or optional")
        if "coverage_score" not in item:
            raise ValueError(f"{condition_id}: missing aggregated coverage_score")
        score = condition_coverage_score(item)
        if item["importance"] == "key":
            scores.append(score)
    if not scores:
        raise ValueError("closure checks require at least one key reference condition")
    return sum(scores) / len(scores)


def score_claim(
    row: Mapping[str, Any],
    coverage_index: Mapping[tuple[str, str], float],
    boundary_discipline: str,
) -> tuple[float, dict[str, Any]]:
    support = {
        "fully_supported": 1.0,
        "partially_supported": 0.6,
        "unsupported": 0.0,
        "contradicted": 0.0,
        "unverifiable": 0.0,
    }.get(str(row.get("evidence_support") or "unverifiable"), 0.0)

    validity = str(row.get("evidence_ref_validity") or "missing_refs")
    claim_type = str(row.get("claim_type") or "")
    if validity == "valid":
        ref_weight, ref_mode = 1.0, "valid"
    elif validity == "invalid":
        ref_weight, ref_mode = 0.0, "invalid"
    elif claim_type == "boundary_or_missing_evidence":
        ref_weight, ref_mode = 0.8, "missing_refs_boundary_claim"
    else:
        ref_weight, ref_mode = 0.4, "missing_refs_factual_claim"

    risk_free = 0.0 if str(row.get("evidence_support") or "") == "contradicted" or any(
        bool(row.get(flag))
        for flag in ("critical_evidence_error", "contradiction", "hidden_evidence_use", "out_of_window_evidence")
    ) else 1.0
    overstatement_weight = {"none": 1.0, "minor": 0.85, "major": 0.55}.get(
        str(row.get("overstatement_level") or "none"), 1.0
    )
    coverage = coverage_index.get((str(row["sample_id"]), str(row["reasoning_unit_id"])), -1.0)
    if coverage >= 1.0:
        stage_weight, stage_mode = 1.0, "full_checklist_coverage"
    elif coverage >= 0.5:
        stage_weight, stage_mode = 0.65, "partial_checklist_coverage"
    else:
        stage_weight, stage_mode = 0.35, "local_fact_only"
    boundary_weight = {
        "sound": 1.0,
        "minor_issue": 0.85,
        "severe_boundary_error": 0.65,
    }.get(boundary_discipline, 0.85)
    score = support * ref_weight * risk_free * overstatement_weight * stage_weight * boundary_weight
    return score, {
        "evidence_support_weight": support,
        "reference_mode": ref_mode,
        "reference_weight": ref_weight,
        "risk_free_weight": risk_free,
        "overstatement_weight": overstatement_weight,
        "stage_contribution_mode": stage_mode,
        "stage_contribution_weight": stage_weight,
        "boundary_weight": boundary_weight,
    }


def stage_summary(gold_by_id: Mapping[str, str], pred_by_id: Mapping[str, str]) -> dict[str, Any]:
    per_stage: dict[str, Any] = {}
    f1_values: list[float] = []
    correct = 0
    for stage in STAGES:
        tp = sum(1 for sid, gold in gold_by_id.items() if gold == stage and pred_by_id.get(sid) == stage)
        fp = sum(1 for sid, gold in gold_by_id.items() if gold != stage and pred_by_id.get(sid) == stage)
        fn = sum(1 for sid, gold in gold_by_id.items() if gold == stage and pred_by_id.get(sid) != stage)
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        f1 = harmonic_mean(precision, recall)
        f1_values.append(f1)
        per_stage[stage] = {"support": tp + fn, "precision": precision, "recall": recall, "f1": f1}
        correct += tp
    return {
        "accuracy": correct / len(gold_by_id) if gold_by_id else 0.0,
        "macro_f1": sum(f1_values) / len(f1_values),
        "per_stage": per_stage,
    }


def unique_sample_rows(rows: list[dict[str, Any]], name: str) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for row in rows:
        sid = row.get("sample_id")
        if not isinstance(sid, str) or not sid.strip() or sid in result:
            raise ValueError(f"{name} contains missing or duplicate sample_id: {sid!r}")
        result[sid] = row
    return result


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--gold", type=Path, required=True, help="gold_labels.jsonl")
    parser.add_argument("--predictions", type=Path, required=True, help="normalized predictions JSONL")
    parser.add_argument("--claim-checks", type=Path, required=True, help="blinded C1 claim judgments JSONL")
    parser.add_argument("--closure-checks", type=Path, required=True, help="blinded C2 closure judgments JSONL")
    parser.add_argument("--output-dir", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    gold_rows = read_jsonl(args.gold)
    prediction_rows = read_jsonl(args.predictions)
    c1_rows = read_jsonl(args.claim_checks)
    c2_rows = read_jsonl(args.closure_checks)

    gold_by_id = {sid: str(row["gold_stage"]) for sid, row in unique_sample_rows(gold_rows, "gold").items()}
    if set(gold_by_id.values()) - set(STAGES):
        raise ValueError("gold file contains an unsupported stage")

    prediction_by_id = unique_sample_rows(prediction_rows, "predictions")
    pred_by_id = {sid: predicted_stage(row) for sid, row in prediction_by_id.items()}
    c2_by_id = unique_sample_rows(c2_rows, "closure checks")
    if not gold_by_id or set(gold_by_id) != set(pred_by_id) or set(gold_by_id) != set(c2_by_id):
        raise ValueError("gold, predictions, and closure checks must have identical nonempty sample_id sets")

    expected_units = {
        sid: {unit["reasoning_unit_id"] for unit in reasoning_units(row)}
        for sid, row in prediction_by_id.items()
    }
    all_claims_by_sample: dict[str, list[dict[str, Any]]] = defaultdict(list)
    actual_units: dict[str, set[str]] = defaultdict(set)
    for row in c1_rows:
        sid = row.get("sample_id")
        unit_id = row.get("reasoning_unit_id")
        if not isinstance(sid, str) or sid not in expected_units:
            raise ValueError(f"claim checks contain unknown sample_id: {sid!r}")
        if not isinstance(unit_id, str) or not unit_id.strip() or unit_id in actual_units[sid]:
            raise ValueError(f"{sid}: missing or duplicate claim reasoning_unit_id: {unit_id!r}")
        actual_units[sid].add(unit_id)
        all_claims_by_sample[sid].append(row)
    for sid, unit_ids in expected_units.items():
        if actual_units.get(sid, set()) != unit_ids:
            raise ValueError(f"{sid}: claim units must exactly match prediction reasoning units")

    coverage_index: dict[tuple[str, str], float] = {}
    scc_by_id: dict[str, float] = {}
    for row in c2_rows:
        sid = str(row["sample_id"])
        unresolved = row.get("unresolved_disagreement_count")
        if row.get("scoring_ready") is not True or type(unresolved) is not int or unresolved != 0:
            raise ValueError(f"{sid}: closure checks are not scoring-ready")
        scc_by_id[sid] = stage_condition_coverage(row)
        for item in row["checklist_coverage"]:
            coverage = condition_coverage_score(item)
            covered_units = item.get("covered_by_reasoning_unit_ids", [])
            if not isinstance(covered_units, list) or any(
                not isinstance(unit_id, str) or unit_id not in expected_units[sid]
                for unit_id in covered_units
            ) or len(covered_units) != len(set(covered_units)):
                raise ValueError(f"{sid}: checklist refers to missing or duplicate reasoning units")
            for unit_id in covered_units:
                key = (sid, unit_id)
                coverage_index[key] = max(coverage, coverage_index.get(key, 0.0))

    claims_by_sample: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in c1_rows:
        if row.get("is_substantive_claim") and str(row.get("claim_type")) in SUBSTANTIVE_TYPES:
            claims_by_sample[str(row["sample_id"])].append(row)

    claim_outputs: list[dict[str, Any]] = []
    sample_outputs: list[dict[str, Any]] = []
    for sid, gold_stage in gold_by_id.items():
        c2 = c2_by_id[sid]
        boundary = str(c2.get("boundary_discipline") or "minor_issue")
        claim_scores: list[float] = []
        for row in claims_by_sample[sid]:
            score, parts = score_claim(row, coverage_index, boundary)
            claim_scores.append(score)
            claim_outputs.append({
                "sample_id": sid,
                "reasoning_unit_id": str(row["reasoning_unit_id"]),
                "claim_type": str(row["claim_type"]),
                "claim_score": score,
                **parts,
            })
        srp = sum(claim_scores) / len(claim_scores) if claim_scores else 0.0
        # SCC is recomputed from the key-condition checklist. The assistant's
        # aggregate value is retained in the input for audit but is not used
        # as the formal metric.
        scc = scc_by_id[sid]
        srf1 = harmonic_mean(srp, scc)
        claim_rows_for_sample = all_claims_by_sample[sid]
        critical = bool(c2.get("sample_level_critical_evidence_error")) or any(
            bool(row.get(flag))
            for row in claim_rows_for_sample
            for flag in ("critical_evidence_error", "contradiction", "hidden_evidence_use", "out_of_window_evidence")
        ) or any(str(row.get("evidence_support") or "") == "contradicted" for row in claim_rows_for_sample)
        invalid_ref = bool(c2.get("sample_level_invalid_evidence_refs")) or any(
            str(row.get("evidence_ref_validity")) == "invalid"
            for row in claim_rows_for_sample
        )
        reliable = (
            srp >= THRESHOLD_SRP
            and scc >= THRESHOLD_SCC
            and srf1 >= THRESHOLD_SRF1
            and not critical
            and not invalid_ref
        )
        correct = pred_by_id[sid] == gold_stage
        ttff = "TT" if correct and reliable else "TF" if correct else "FT" if reliable else "FF"
        sample_outputs.append({
            "sample_id": sid,
            "gold_stage": gold_stage,
            "predicted_stage": pred_by_id[sid],
            "stage_correct": correct,
            "substantive_claim_count": len(claim_scores),
            "srp": srp,
            "scc": scc,
            "srf1": srf1,
            "sample_level_critical_evidence_error": critical,
            "sample_level_invalid_evidence_refs": invalid_ref,
            "reasoning_reliable": reliable,
            "ttff": ttff,
        })

    model_srp = sum(row["srp"] for row in sample_outputs) / len(sample_outputs)
    model_scc = sum(row["scc"] for row in sample_outputs) / len(sample_outputs)
    summary = {
        "schema_version": "seclog_bench.public_reasoning_metrics.v1",
        "sample_count": len(sample_outputs),
        "stage_prediction": stage_summary(gold_by_id, pred_by_id),
        "reasoning_quality": {
            "srp": model_srp,
            "scc": model_scc,
            "srf1": harmonic_mean(model_srp, model_scc),
            "threshold_srp": THRESHOLD_SRP,
            "threshold_scc": THRESHOLD_SCC,
            "threshold_srf1": THRESHOLD_SRF1,
        },
        "prediction_reasoning_consistency": dict(Counter(row["ttff"] for row in sample_outputs)),
    }
    write_jsonl(args.output_dir / "reasoning_claim_scores.jsonl", claim_outputs)
    write_jsonl(args.output_dir / "reasoning_metrics_by_sample.jsonl", sample_outputs)
    write_json(args.output_dir / "metrics_summary.json", summary)
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
