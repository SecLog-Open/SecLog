#!/usr/bin/env python3
"""Evaluate predictions for the unified public SecLog-Bench-216 dataset.

This script is a pure downstream evaluator for the frozen public benchmark:

    SecLog-Bench-216/data/
        evidence_windows.jsonl
        gold_labels.jsonl
        sample_index.jsonl
        reference_reasoning_chains.jsonl

It does NOT modify benchmark data. It reads model predictions, aligns them to
`gold.jsonl`, optionally validates evidence refs against `model_input.jsonl`,
and writes evaluation artefacts under `--output-dir`.

Predictions JSONL format (one JSON object per line):

    {
      "sample_id": "...",
      "predicted_stage": "preparation | execution | result | stage_unclosed",
      "reasoning_chain": [
        {
          "step": "optional descriptive step name",
          "claim": "...",
          "evidence_refs": [
            {"seq": 1, "edge_id": "..."}
          ]
        }
      ],
      "confidence": 0.0
    }

Reasoning metrics are computed from evidence-referenced claims. The four-step
reference-chain organization is an optional diagnostic, not a required model
output format. Older prediction formats should be normalized before evaluation.

Required fields:
* `sample_id` (string)
* `predicted_stage` (one of preparation/execution/result/stage_unclosed)

Optional-but-recommended fields:
* `reasoning_chain` (list)
* `confidence` (number in [0, 1])

Outputs:
    <OUTPUT_DIR>/
        metrics_summary.json
        per_sample_results.jsonl
        confusion_matrix.csv
        per_stage_metrics.csv
        per_scenario_metrics.csv
        error_cases.jsonl

No sklearn dependency is used; all metrics are implemented locally.
"""
from __future__ import annotations

import argparse
import csv
import json
import math
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable, Optional

LEGAL_STAGES = ("preparation", "execution", "result", "stage_unclosed")
INVALID_STAGE = "invalid_stage"

# Current EWVAA-style benchmark reasoning protocol.
REQUIRED_REASONING_STEPS = (
    "scenario_or_evidence_understanding",
    "observable_evidence",
    "attack_stage_path_reasoning",
    "final_judgement",
)

MISSING_PREDICTION = "__missing__"

# Human-annotatable failure modes (reserved; not auto-classified)
FAILURE_MODES = (
    "biased_primary_hypothesis",
    "premature_collapse",
    "failed_evidence_constraints",
    "heuristic_adjudication",
    "ineffective_reflection",
    "incompleteness",
    "repetition",
    "interference",
)


# ---------------------------------------------------------------------------
# IO helpers
# ---------------------------------------------------------------------------


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as fh:
        for line_no, line in enumerate(fh, 1):
            s = line.strip()
            if not s:
                continue
            try:
                obj = json.loads(s)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"Invalid JSON in {path} at line {line_no}: {exc}"
                ) from exc
            if not isinstance(obj, dict):
                raise ValueError(
                    f"Expected JSON object in {path} at line {line_no}, got {type(obj).__name__}"
                )
            rows.append(obj)
    return rows


def _write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        json.dump(obj, fh, ensure_ascii=False, indent=2)
        fh.write("\n")


def _write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with path.open("w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, ensure_ascii=False))
            fh.write("\n")
            n += 1
    return n


def _write_csv(path: Path, fieldnames: list[str], rows: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


def _require_unique_sample_ids(rows: list[dict[str, Any]], label: str) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    dupes: list[str] = []
    for idx, row in enumerate(rows, 1):
        sid = row.get("sample_id")
        if not isinstance(sid, str) or not sid:
            raise ValueError(f"{label}: row {idx} missing valid string sample_id")
        if sid in out:
            dupes.append(sid)
            continue
        out[sid] = row
    if dupes:
        preview = dupes[:10]
        raise ValueError(
            f"{label}: duplicated sample_id values detected ({len(dupes)} duplicates), "
            f"examples: {preview}"
        )
    return out


def _validate_prediction_row(row: dict[str, Any], line_no: int, path: Path) -> dict[str, Any]:
    sid = row.get("sample_id")
    if not isinstance(sid, str) or not sid:
        raise ValueError(
            f"{path}: line {line_no}: `sample_id` must be a non-empty string"
        )

    predicted_stage = row.get("predicted_stage")
    if not isinstance(predicted_stage, str) or predicted_stage not in (*LEGAL_STAGES, INVALID_STAGE):
        raise ValueError(
            f"{path}: line {line_no}: `predicted_stage` must be one of {LEGAL_STAGES}, "
            f"got {predicted_stage!r}"
        )

    reasoning_chain = row.get("reasoning_chain", [])
    if reasoning_chain is None:
        reasoning_chain = []
    if not isinstance(reasoning_chain, list):
        raise ValueError(
            f"{path}: line {line_no}: `reasoning_chain` must be a list when present"
        )
    for step_idx, step in enumerate(reasoning_chain, 1):
        if not isinstance(step, dict):
            raise ValueError(
                f"{path}: line {line_no}: reasoning_chain[{step_idx}] must be an object"
            )
        if "step" in step and not isinstance(step.get("step"), str):
            raise ValueError(
                f"{path}: line {line_no}: reasoning_chain[{step_idx}].step must be a string"
            )
        if "claim" in step and not isinstance(step.get("claim"), str):
            raise ValueError(
                f"{path}: line {line_no}: reasoning_chain[{step_idx}].claim must be a string"
            )
        refs = step.get("evidence_refs", [])
        if refs is None:
            refs = []
            step["evidence_refs"] = refs
        if not isinstance(refs, list):
            raise ValueError(
                f"{path}: line {line_no}: reasoning_chain[{step_idx}].evidence_refs must be a list"
            )
        for ref_idx, ref in enumerate(refs, 1):
            if not isinstance(ref, dict):
                raise ValueError(
                    f"{path}: line {line_no}: reasoning_chain[{step_idx}].evidence_refs[{ref_idx}] must be an object"
                )
            seq = ref.get("seq")
            edge_id = ref.get("edge_id")
            if seq is not None and not isinstance(seq, int):
                raise ValueError(
                    f"{path}: line {line_no}: evidence_refs[{ref_idx}].seq must be int or null"
                )
            if edge_id is not None and not isinstance(edge_id, str):
                raise ValueError(
                    f"{path}: line {line_no}: evidence_refs[{ref_idx}].edge_id must be string or null"
                )

    confidence = row.get("confidence")
    if confidence is not None:
        if not isinstance(confidence, (int, float)):
            raise ValueError(
                f"{path}: line {line_no}: `confidence` must be a number in [0, 1] when present"
            )
        if math.isnan(float(confidence)) or float(confidence) < 0.0 or float(confidence) > 1.0:
            raise ValueError(
                f"{path}: line {line_no}: `confidence` must be in [0, 1], got {confidence!r}"
            )

    return {
        "sample_id": sid,
        "predicted_stage": predicted_stage,
        "reasoning_chain": reasoning_chain,
        "confidence": float(confidence) if confidence is not None else None,
    }


def _load_predictions(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as fh:
        for line_no, line in enumerate(fh, 1):
            s = line.strip()
            if not s:
                continue
            try:
                obj = json.loads(s)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"Invalid JSON in predictions file {path} at line {line_no}: {exc}"
                ) from exc
            if not isinstance(obj, dict):
                raise ValueError(
                    f"Predictions file {path} line {line_no}: each row must be a JSON object"
                )
            rows.append(_validate_prediction_row(obj, line_no, path))
    return rows


# ---------------------------------------------------------------------------
# Evidence helpers
# ---------------------------------------------------------------------------


def _gold_stage(gold_row: dict[str, Any]) -> Optional[str]:
    """Accept both canonical ``label.stage`` and public ``gold_stage``."""
    value = (gold_row.get("label") or {}).get("stage") or gold_row.get("gold_stage")
    return value if isinstance(value, str) else None


def _gold_chain(gold_row: dict[str, Any]) -> list[dict[str, Any]]:
    value = gold_row.get("gold_reasoning_chain")
    if value is None:
        value = gold_row.get("reference_reasoning_chain")
    return value if isinstance(value, list) else []


def _model_spine(model_input_row: dict[str, Any]) -> list[dict[str, Any]]:
    value = (model_input_row.get("input") or {}).get("spine")
    if value is None:
        value = model_input_row.get("selected_spine")
    return value if isinstance(value, list) else []


def _build_ref_context(
    gold_row: dict[str, Any],
    sample_index_row: Optional[dict[str, Any]],
    model_input_row: Optional[dict[str, Any]],
) -> dict[str, Any]:
    label = gold_row.get("label") or {}
    edge_proj = label.get("edge_stage_projection") or []
    seq_to_edge_id: dict[int, str] = {}
    edge_id_to_seq: dict[str, int] = {}
    for ep in edge_proj:
        seq = ep.get("seq")
        edge_id = ep.get("edge_id")
        if isinstance(seq, int) and isinstance(edge_id, str):
            seq_to_edge_id[seq] = edge_id
            edge_id_to_seq[edge_id] = seq

    model_seq_to_edge_id: dict[int, str] = {}
    model_edge_id_to_seq: dict[str, int] = {}
    if model_input_row is not None:
        spine = _model_spine(model_input_row)
        for edge in spine:
            seq = edge.get("seq")
            edge_id = edge.get("edge_id")
            if isinstance(seq, int) and isinstance(edge_id, str):
                model_seq_to_edge_id[seq] = edge_id
                model_edge_id_to_seq[edge_id] = seq

    window = gold_row.get("window") or {}
    start_seq = window.get("start_seq")
    end_seq = window.get("end_seq")
    if not isinstance(start_seq, int) or not isinstance(end_seq, int):
        if sample_index_row is not None:
            w = sample_index_row.get("window") or {}
            start_seq = w.get("start_seq")
            end_seq = w.get("end_seq")

    return {
        "seq_to_edge_id": seq_to_edge_id,
        "edge_id_to_seq": edge_id_to_seq,
        "model_seq_to_edge_id": model_seq_to_edge_id,
        "model_edge_id_to_seq": model_edge_id_to_seq,
        "start_seq": start_seq,
        "end_seq": end_seq,
    }


def _canonicalize_ref(ref: dict[str, Any], ctx: dict[str, Any]) -> tuple[Optional[str], bool, list[str]]:
    """Return `(canonical_ref_key, is_valid, errors)` for one evidence ref."""
    seq = ref.get("seq")
    edge_id = ref.get("edge_id")
    errors: list[str] = []

    model_seq_to_edge_id = ctx["model_seq_to_edge_id"]
    model_edge_id_to_seq = ctx["model_edge_id_to_seq"]
    seq_to_edge_id = ctx["seq_to_edge_id"]
    edge_id_to_seq = ctx["edge_id_to_seq"]
    start_seq = ctx["start_seq"]
    end_seq = ctx["end_seq"]

    valid_by_edge_id = False
    valid_by_seq = False

    if isinstance(edge_id, str):
        if edge_id in model_edge_id_to_seq or edge_id in edge_id_to_seq:
            valid_by_edge_id = True
    if isinstance(seq, int):
        if seq in model_seq_to_edge_id or seq in seq_to_edge_id:
            valid_by_seq = True
        elif isinstance(start_seq, int) and isinstance(end_seq, int) and start_seq <= seq <= end_seq:
            valid_by_seq = True

    if not valid_by_edge_id and not valid_by_seq:
        errors.append("evidence_ref_not_alignable")
        return None, False, errors

    # Strongest canonicalization: use actual edge_id if recoverable.
    canon_from_edge = edge_id if valid_by_edge_id and isinstance(edge_id, str) else None
    canon_from_seq = None
    if valid_by_seq and isinstance(seq, int):
        canon_from_seq = model_seq_to_edge_id.get(seq) or seq_to_edge_id.get(seq)
        if canon_from_seq is None:
            canon_from_seq = f"seq::{seq}"

    if canon_from_edge is not None and canon_from_seq is not None and canon_from_edge != canon_from_seq:
        errors.append("evidence_ref_seq_edge_id_mismatch")
        return None, False, errors

    canonical = canon_from_edge or canon_from_seq
    return canonical, True, errors


def _collect_reasoning_refs(
    reasoning_chain: list[dict[str, Any]],
    ctx: dict[str, Any],
) -> dict[str, Any]:
    total_refs = 0
    valid_refs = 0
    canonical_valid_refs: set[str] = set()
    ref_errors: list[str] = []
    present_steps: list[str] = []

    for step in reasoning_chain:
        step_name = step.get("step")
        if isinstance(step_name, str):
            present_steps.append(step_name)
        refs = step.get("evidence_refs", []) or []
        if not isinstance(refs, list):
            continue
        for ref in refs:
            if not isinstance(ref, dict):
                ref_errors.append("non_object_evidence_ref")
                total_refs += 1
                continue
            total_refs += 1
            canonical, is_valid, errors = _canonicalize_ref(ref, ctx)
            if is_valid:
                valid_refs += 1
                if canonical is not None:
                    canonical_valid_refs.add(canonical)
            ref_errors.extend(errors)

    return {
        "present_steps": present_steps,
        "total_refs": total_refs,
        "valid_refs": valid_refs,
        "canonical_valid_refs": canonical_valid_refs,
        "ref_errors": ref_errors,
    }


def _claim_nonempty_rate(reasoning_chain: list[dict[str, Any]]) -> Optional[float]:
    if not reasoning_chain:
        return None
    nonempty = sum(
        1
        for step in reasoning_chain
        if isinstance(step, dict)
        and isinstance(step.get("claim"), str)
        and bool(step["claim"].strip())
    )
    return nonempty / len(reasoning_chain)


def _evidence_ref_presence_rate(reasoning_chain: list[dict[str, Any]]) -> Optional[float]:
    if not reasoning_chain:
        return None
    with_refs = sum(
        1
        for step in reasoning_chain
        if isinstance(step, dict)
        and isinstance(step.get("evidence_refs"), list)
        and len(step.get("evidence_refs") or []) > 0
    )
    return with_refs / len(reasoning_chain)


def _required_steps_present(present_steps: set[str]) -> tuple[bool, float, list[str]]:
    covered_slots = 0
    missing_slot_names: list[str] = []
    for step_name in REQUIRED_REASONING_STEPS:
        if step_name in present_steps:
            covered_slots += 1
        else:
            missing_slot_names.append(step_name)
    coverage = covered_slots / len(REQUIRED_REASONING_STEPS)
    return covered_slots == len(REQUIRED_REASONING_STEPS), coverage, missing_slot_names


def _final_judgement_grounded(
    reasoning_chain: list[dict[str, Any]],
    ctx: dict[str, Any],
) -> Optional[bool]:
    final_steps = [
        step for step in reasoning_chain
        if isinstance(step, dict) and step.get("step") == "final_judgement"
    ]
    if not final_steps:
        return None
    stats = _collect_reasoning_refs(final_steps, ctx)
    return stats["valid_refs"] > 0


# ---------------------------------------------------------------------------
# Metrics helpers
# ---------------------------------------------------------------------------


def _safe_div(num: float, den: float) -> Optional[float]:
    if den == 0:
        return None
    return num / den


def _round_or_none(x: Optional[float], ndigits: int = 4) -> Optional[float]:
    if x is None:
        return None
    return round(float(x), ndigits)


def _compute_stage_metrics(
    gold_rows: list[dict[str, Any]],
    pred_by_id: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    confusion: dict[str, Counter[str]] = {
        gold_stage: Counter() for gold_stage in LEGAL_STAGES
    }
    tp: Counter[str] = Counter()
    fp: Counter[str] = Counter()
    fn: Counter[str] = Counter()
    support: Counter[str] = Counter()
    correct = 0

    for gold_row in gold_rows:
        sid = gold_row["sample_id"]
        gold_stage = _gold_stage(gold_row)
        if gold_stage not in LEGAL_STAGES:
            raise ValueError(f"gold sample {sid} has invalid gold stage {gold_stage!r}")
        support[gold_stage] += 1
        pred_row = pred_by_id.get(sid)
        pred_stage = pred_row["predicted_stage"] if pred_row is not None else MISSING_PREDICTION
        confusion[gold_stage][pred_stage] += 1
        if pred_stage == gold_stage:
            tp[gold_stage] += 1
            correct += 1
        elif pred_stage == MISSING_PREDICTION:
            fn[gold_stage] += 1
        else:
            fp[pred_stage] += 1
            fn[gold_stage] += 1

    per_stage: dict[str, dict[str, Any]] = {}
    f1s: list[float] = []
    for stage in LEGAL_STAGES:
        precision = _safe_div(tp[stage], tp[stage] + fp[stage])
        recall = _safe_div(tp[stage], tp[stage] + fn[stage])
        if precision is None:
            precision = 0.0
        if recall is None:
            recall = 0.0
        f1 = 0.0 if (precision + recall) == 0 else (2 * precision * recall / (precision + recall))
        f1s.append(f1)
        per_stage[stage] = {
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "support": support[stage],
        }

    accuracy = correct / len(gold_rows) if gold_rows else 0.0
    macro_f1 = sum(f1s) / len(LEGAL_STAGES) if LEGAL_STAGES else 0.0
    return {
        "accuracy": round(accuracy, 4),
        "macro_f1": round(macro_f1, 4),
        "per_stage": per_stage,
        "support": dict(support),
        "confusion": confusion,
    }


def _group_rows(rows: list[dict[str, Any]], key_name: str) -> dict[str, list[dict[str, Any]]]:
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        key = row.get(key_name)
        if key is None:
            key = "__null__"
        groups[str(key)].append(row)
    return groups


def _avg(values: list[Optional[float]]) -> Optional[float]:
    xs = [float(v) for v in values if v is not None]
    if not xs:
        return None
    return sum(xs) / len(xs)


def _aggregate_group(rows: list[dict[str, Any]]) -> dict[str, Any]:
    n = len(rows)
    if n == 0:
        return {
            "sample_count": 0,
            "stage_accuracy": None,
            "avg_required_steps_present": None,
            "avg_reasoning_step_coverage": None,
            "avg_claim_nonempty_rate": None,
            "avg_evidence_ref_presence_rate": None,
            "avg_valid_evidence_ref_rate": None,
            "avg_final_judgement_grounded": None,
            "avg_gold_evidence_recall": None,
            "avg_reasoning_evidence_f1": None,
            "quadrants": {},
        }
    correct = sum(1 for r in rows if r.get("stage_correct") is True)
    quadrants = Counter(str(r.get("quadrant")) for r in rows if r.get("quadrant") is not None)
    return {
        "sample_count": n,
        "stage_accuracy": round(correct / n, 4),
        "avg_required_steps_present": _round_or_none(_avg([r.get("required_steps_present") for r in rows])),
        "avg_reasoning_step_coverage": _round_or_none(_avg([r.get("reasoning_step_coverage") for r in rows])),
        "avg_claim_nonempty_rate": _round_or_none(_avg([r.get("claim_nonempty_rate") for r in rows])),
        "avg_evidence_ref_presence_rate": _round_or_none(_avg([r.get("evidence_ref_presence_rate") for r in rows])),
        "avg_valid_evidence_ref_rate": _round_or_none(_avg([r.get("valid_evidence_ref_rate") for r in rows])),
        "avg_final_judgement_grounded": _round_or_none(_avg([r.get("final_judgement_grounded") for r in rows])),
        "avg_gold_evidence_recall": _round_or_none(_avg([r.get("gold_evidence_recall") for r in rows])),
        "avg_reasoning_evidence_f1": _round_or_none(_avg([r.get("reasoning_evidence_f1") for r in rows])),
        "quadrants": dict(quadrants),
    }


# ---------------------------------------------------------------------------
# Main evaluation
# ---------------------------------------------------------------------------


def evaluate(
    gold_path: Path,
    predictions_path: Path,
    output_dir: Path,
    *,
    sample_index_path: Optional[Path] = None,
    model_input_path: Optional[Path] = None,
    reference_chains_path: Optional[Path] = None,
    reasoning_threshold: float = 0.5,
) -> dict[str, Any]:
    gold_rows = _read_jsonl(gold_path)
    pred_rows = _load_predictions(predictions_path)
    sample_index_rows = _read_jsonl(sample_index_path) if sample_index_path else []
    model_input_rows = _read_jsonl(model_input_path) if model_input_path else []
    reference_rows = _read_jsonl(reference_chains_path) if reference_chains_path else []

    if reference_rows:
        reference_by_id = _require_unique_sample_ids(reference_rows, "reference_chains")
        merged_gold_rows: list[dict[str, Any]] = []
        for source_row in gold_rows:
            row = dict(source_row)
            reference_row = reference_by_id.get(row.get("sample_id")) or {}
            if not _gold_chain(row):
                row["reference_reasoning_chain"] = reference_row.get("reference_reasoning_chain") or []
            if _gold_stage(row) is None and isinstance(reference_row.get("gold_stage"), str):
                row["gold_stage"] = reference_row["gold_stage"]
            merged_gold_rows.append(row)
        gold_rows = merged_gold_rows

    gold_by_id = _require_unique_sample_ids(gold_rows, "gold")
    pred_by_id = _require_unique_sample_ids(pred_rows, "predictions")
    index_by_id = _require_unique_sample_ids(sample_index_rows, "sample_index") if sample_index_rows else {}
    model_input_by_id = _require_unique_sample_ids(model_input_rows, "model_input") if model_input_rows else {}

    gold_ids = set(gold_by_id)
    pred_ids = set(pred_by_id)
    missing_ids = sorted(gold_ids - pred_ids)
    extra_ids = sorted(pred_ids - gold_ids)

    # Overall stage metrics use gold domain only.
    stage_metrics = _compute_stage_metrics(gold_rows, pred_by_id)

    per_sample_results: list[dict[str, Any]] = []
    error_cases: list[dict[str, Any]] = []
    quadrant_counts: Counter[str] = Counter()
    quadrant_unavailable = 0

    for gold_row in gold_rows:
        sid = gold_row["sample_id"]
        pred_row = pred_by_id.get(sid)
        index_row = index_by_id.get(sid)
        model_input_row = model_input_by_id.get(sid)
        ctx = _build_ref_context(gold_row, index_row, model_input_row)

        gold_stage = _gold_stage(gold_row)
        predicted_stage = pred_row["predicted_stage"] if pred_row is not None else None
        stage_correct = bool(predicted_stage == gold_stage) if predicted_stage is not None else False
        errors: list[str] = []

        if pred_row is None:
            errors.append("missing_prediction")
            model_chain = []
        else:
            model_chain = pred_row.get("reasoning_chain", []) or []

        gold_chain = _gold_chain(gold_row)

        pred_ref_stats = _collect_reasoning_refs(model_chain, ctx)
        gold_ref_stats = _collect_reasoning_refs(gold_chain, ctx)

        present_steps = set(pred_ref_stats["present_steps"])
        required_steps_present, step_coverage, missing_slot_names = _required_steps_present(present_steps)
        # The reference chain has four organizational steps, but the paper
        # explicitly allows models to organize claims freely. Keep this
        # coverage as an optional diagnostic and do not treat missing steps as
        # an evaluation error.

        claim_nonempty_rate = _claim_nonempty_rate(model_chain)
        evidence_ref_presence_rate = _evidence_ref_presence_rate(model_chain)
        final_judgement_grounded = _final_judgement_grounded(model_chain, ctx)
        if claim_nonempty_rate is not None and claim_nonempty_rate < 1.0:
            errors.append("empty_reasoning_claim")
        if evidence_ref_presence_rate is not None and evidence_ref_presence_rate < 1.0:
            errors.append("reasoning_step_without_evidence_ref")
        if final_judgement_grounded is False:
            errors.append("final_judgement_not_grounded")

        total_refs = pred_ref_stats["total_refs"]
        valid_refs = pred_ref_stats["valid_refs"]
        valid_evidence_ref_rate = None if total_refs == 0 else (valid_refs / total_refs)
        if total_refs == 0:
            errors.append("no_prediction_evidence_refs")
        if pred_ref_stats["ref_errors"]:
            errors.extend(pred_ref_stats["ref_errors"])

        pred_ref_set = pred_ref_stats["canonical_valid_refs"]
        gold_ref_set = gold_ref_stats["canonical_valid_refs"]
        overlap = pred_ref_set & gold_ref_set

        gold_evidence_recall = None
        reasoning_evidence_precision: Optional[float]
        reasoning_evidence_f1: Optional[float]
        reasoning_f1_reason: Optional[str] = None

        if not gold_ref_set and not pred_ref_set:
            reasoning_evidence_precision = None
            gold_evidence_recall = None
            reasoning_evidence_f1 = None
            reasoning_f1_reason = "no_gold_or_prediction_evidence_refs"
        elif not gold_ref_set:
            reasoning_evidence_precision = _safe_div(len(overlap), len(pred_ref_set))
            gold_evidence_recall = None
            reasoning_evidence_f1 = None
            reasoning_f1_reason = "no_gold_evidence_refs"
        else:
            reasoning_evidence_precision = 0.0 if not pred_ref_set else len(overlap) / len(pred_ref_set)
            gold_evidence_recall = len(overlap) / len(gold_ref_set)
            if reasoning_evidence_precision + gold_evidence_recall == 0:
                reasoning_evidence_f1 = 0.0
            else:
                reasoning_evidence_f1 = (
                    2 * reasoning_evidence_precision * gold_evidence_recall /
                    (reasoning_evidence_precision + gold_evidence_recall)
                )

        if reasoning_evidence_f1 is None and reasoning_f1_reason is not None:
            errors.append(f"reasoning_evidence_f1_unavailable:{reasoning_f1_reason}")

        quadrant: Optional[str] = None
        if reasoning_evidence_f1 is None:
            quadrant_unavailable += 1
        else:
            reasoning_good = reasoning_evidence_f1 >= reasoning_threshold
            if stage_correct and reasoning_good:
                quadrant = "TT"
            elif stage_correct and not reasoning_good:
                quadrant = "TF"
            elif (not stage_correct) and reasoning_good:
                quadrant = "FT"
            else:
                quadrant = "FF"
            quadrant_counts[quadrant] += 1

        scenario_id = gold_row.get("scenario_id")
        if index_row is not None:
            scenario_id = index_row.get("scenario_id", scenario_id)

        result_row = {
            "sample_id": sid,
            "scenario_id": scenario_id,
            "gold_stage": gold_stage,
            "predicted_stage": predicted_stage,
            "stage_correct": stage_correct,
            "required_steps_present": required_steps_present,
            "reasoning_step_coverage": round(step_coverage, 4),
            "claim_nonempty_rate": _round_or_none(claim_nonempty_rate),
            "evidence_ref_presence_rate": _round_or_none(evidence_ref_presence_rate),
            "valid_evidence_ref_rate": _round_or_none(valid_evidence_ref_rate),
            "final_judgement_grounded": final_judgement_grounded,
            "gold_evidence_recall": _round_or_none(gold_evidence_recall),
            "reasoning_evidence_f1": _round_or_none(reasoning_evidence_f1),
            "quadrant": quadrant,
            "errors": errors,
            "confidence": pred_row.get("confidence") if pred_row is not None else None,
            "failure_mode": None,
        }
        per_sample_results.append(result_row)

        if errors or (predicted_stage is not None and predicted_stage != gold_stage):
            error_cases.append({
                "error_type": "sample_error" if errors else "stage_incorrect",
                **result_row,
            })

    for sid in missing_ids:
        error_cases.append({
            "error_type": "missing_prediction",
            "sample_id": sid,
            "gold_stage": _gold_stage(gold_by_id[sid]),
            "scenario_id": gold_by_id[sid].get("scenario_id"),
        })
    for sid in extra_ids:
        error_cases.append({
            "error_type": "extra_prediction",
            "sample_id": sid,
            "predicted_stage": pred_by_id[sid].get("predicted_stage"),
        })

    # Aggregates
    mean_reasoning_evidence_f1 = _avg([r.get("reasoning_evidence_f1") for r in per_sample_results])
    reasoning_gap = None if mean_reasoning_evidence_f1 is None else stage_metrics["accuracy"] - mean_reasoning_evidence_f1
    reasoning_gap_reason = None if reasoning_gap is not None else "no_computable_reasoning_evidence_f1"

    by_stage = {
        stage: _aggregate_group(rows)
        for stage, rows in _group_rows(per_sample_results, "gold_stage").items()
    }
    by_scenario = {
        scenario: _aggregate_group(rows)
        for scenario, rows in _group_rows(per_sample_results, "scenario_id").items()
    }
    metrics_summary = {
        "schema_version": "attack_chain_stage_reasoning_eval.v1",
        "inputs": {
            "gold": str(gold_path),
            "predictions": str(predictions_path),
            "sample_index": str(sample_index_path) if sample_index_path else None,
            "model_input": str(model_input_path) if model_input_path else None,
            "reasoning_threshold": reasoning_threshold,
        },
        "alignment": {
            "gold_count": len(gold_rows),
            "prediction_count": len(pred_rows),
            "missing_prediction_count": len(missing_ids),
            "extra_prediction_count": len(extra_ids),
            "missing_prediction_sample_ids": missing_ids,
            "extra_prediction_sample_ids": extra_ids,
        },
        "stage_metrics": {
            "accuracy": stage_metrics["accuracy"],
            "macro_f1": stage_metrics["macro_f1"],
            "per_stage": stage_metrics["per_stage"],
            "support": dict(stage_metrics["support"]),
        },
        "reasoning_metrics": {
            "required_steps": list(REQUIRED_REASONING_STEPS),
            "reasoning_schema_version": "evidence_referenced_claims_v1",
            "avg_required_steps_present": _round_or_none(_avg([r.get("required_steps_present") for r in per_sample_results])),
            "avg_reasoning_step_coverage": _round_or_none(_avg([r.get("reasoning_step_coverage") for r in per_sample_results])),
            "avg_claim_nonempty_rate": _round_or_none(_avg([r.get("claim_nonempty_rate") for r in per_sample_results])),
            "avg_evidence_ref_presence_rate": _round_or_none(_avg([r.get("evidence_ref_presence_rate") for r in per_sample_results])),
            "avg_valid_evidence_ref_rate": _round_or_none(_avg([r.get("valid_evidence_ref_rate") for r in per_sample_results])),
            "avg_final_judgement_grounded": _round_or_none(_avg([r.get("final_judgement_grounded") for r in per_sample_results])),
            "avg_gold_evidence_recall": _round_or_none(_avg([r.get("gold_evidence_recall") for r in per_sample_results])),
            "avg_reasoning_evidence_f1": _round_or_none(mean_reasoning_evidence_f1),
            "reasoning_gap": _round_or_none(reasoning_gap),
            "reasoning_gap_reason": reasoning_gap_reason,
        },
        "quadrants": {
            "metric": "reference_evidence_overlap_diagnostic",
            "note": "This diagnostic is not the paper's SRP/SCC/SRF1 reliability quadrant. Use score_reasoning_quality.py for the formal TT/TF/FT/FF result.",
            "threshold": reasoning_threshold,
            "TT": quadrant_counts["TT"],
            "TF": quadrant_counts["TF"],
            "FT": quadrant_counts["FT"],
            "FF": quadrant_counts["FF"],
            "unavailable": quadrant_unavailable,
            "ratios": {
                "TT": _round_or_none(_safe_div(quadrant_counts["TT"], len(per_sample_results))),
                "TF": _round_or_none(_safe_div(quadrant_counts["TF"], len(per_sample_results))),
                "FT": _round_or_none(_safe_div(quadrant_counts["FT"], len(per_sample_results))),
                "FF": _round_or_none(_safe_div(quadrant_counts["FF"], len(per_sample_results))),
                "unavailable": _round_or_none(_safe_div(quadrant_unavailable, len(per_sample_results))),
            },
        },
        "buckets": {
            "by_stage": by_stage,
            "by_scenario": by_scenario,
        },
    }

    # Write outputs
    output_dir.mkdir(parents=True, exist_ok=True)
    _write_json(output_dir / "metrics_summary.json", metrics_summary)
    _write_jsonl(output_dir / "per_sample_results.jsonl", per_sample_results)
    _write_jsonl(output_dir / "error_cases.jsonl", error_cases)

    # confusion_matrix.csv
    confusion_rows: list[dict[str, Any]] = []
    confusion_fieldnames = ["gold_stage", *LEGAL_STAGES, INVALID_STAGE, MISSING_PREDICTION]
    confusion = stage_metrics["confusion"]
    for gold_stage in LEGAL_STAGES:
        row = {"gold_stage": gold_stage}
        for pred_stage in LEGAL_STAGES:
            row[pred_stage] = confusion[gold_stage][pred_stage]
        row[INVALID_STAGE] = confusion[gold_stage][INVALID_STAGE]
        row[MISSING_PREDICTION] = confusion[gold_stage][MISSING_PREDICTION]
        confusion_rows.append(row)
    _write_csv(output_dir / "confusion_matrix.csv", confusion_fieldnames, confusion_rows)

    # per_stage_metrics.csv
    per_stage_rows = [
        {
            "stage": stage,
            **stage_metrics["per_stage"][stage],
        }
        for stage in LEGAL_STAGES
    ]
    _write_csv(
        output_dir / "per_stage_metrics.csv",
        ["stage", "precision", "recall", "f1", "support"],
        per_stage_rows,
    )

    # per_scenario_metrics.csv
    per_scenario_rows = [
        {"scenario_id": scenario_id, **agg}
        for scenario_id, agg in sorted(by_scenario.items())
    ]
    _write_csv(
        output_dir / "per_scenario_metrics.csv",
            [
                "scenario_id",
                "sample_count",
                "stage_accuracy",
                "avg_required_steps_present",
                "avg_reasoning_step_coverage",
                "avg_claim_nonempty_rate",
                "avg_evidence_ref_presence_rate",
                "avg_valid_evidence_ref_rate",
                "avg_final_judgement_grounded",
                "avg_gold_evidence_recall",
                "avg_reasoning_evidence_f1",
            "quadrants",
        ],
        per_scenario_rows,
    )

    return metrics_summary


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    epilog = """
Examples:
  python evaluation/evaluate_stage_reasoning_predictions.py \
    --gold ../SecLog-Bench-216/data/gold_labels.jsonl \
    --predictions my_predictions.jsonl \
    --sample-index ../SecLog-Bench-216/data/sample_index.jsonl \
    --model-input ../SecLog-Bench-216/data/evidence_windows.jsonl \
    --reference-chains ../SecLog-Bench-216/data/reference_reasoning_chains.jsonl \
    --output-dir stage_eval_output

Predictions JSONL format:
  {"sample_id":"...","predicted_stage":"preparation|execution|result|stage_unclosed",
   "reasoning_chain":[{"step":"scenario_or_evidence_understanding","claim":"...",
                        "evidence_refs":[{"seq":1,"edge_id":"..."}]}],
   "confidence":0.83}
"""
    parser = argparse.ArgumentParser(
        description="Evaluate predictions against the unified public SecLog-Bench-216 gold labels.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=epilog,
    )
    parser.add_argument("--gold", type=Path, required=True, help="Path to benchmark gold.jsonl")
    parser.add_argument("--predictions", type=Path, required=True, help="Path to model predictions.jsonl")
    parser.add_argument(
        "--sample-index",
        type=Path,
        default=None,
        help="Optional sample_index.jsonl for traceability / bucket stats",
    )
    parser.add_argument(
        "--model-input",
        type=Path,
        default=None,
        help="Optional model_input.jsonl for stronger evidence-ref validation against input.spine",
    )
    parser.add_argument(
        "--reference-chains",
        type=Path,
        default=None,
        help="Optional public reference_reasoning_chains.jsonl merged by sample_id.",
    )
    parser.add_argument("--output-dir", type=Path, required=True, help="Directory for evaluation outputs")
    parser.add_argument(
        "--reasoning-threshold",
        type=float,
        default=0.5,
        help="Diagnostic reference-evidence overlap threshold; not formal reasoning reliability (default: 0.5)",
    )
    return parser.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)
    if args.reasoning_threshold < 0.0 or args.reasoning_threshold > 1.0:
        raise SystemExit("--reasoning-threshold must be in [0, 1]")

    summary = evaluate(
        gold_path=args.gold,
        predictions_path=args.predictions,
        sample_index_path=args.sample_index,
        model_input_path=args.model_input,
        reference_chains_path=args.reference_chains,
        output_dir=args.output_dir,
        reasoning_threshold=args.reasoning_threshold,
    )

    print(
        "[stage_reasoning_eval] gold={gold} pred={pred} acc={acc} macro_f1={mf1} "
        "missing={missing} extra={extra} reasoning_f1={rf1}".format(
            gold=summary["alignment"]["gold_count"],
            pred=summary["alignment"]["prediction_count"],
            acc=summary["stage_metrics"]["accuracy"],
            mf1=summary["stage_metrics"]["macro_f1"],
            missing=summary["alignment"]["missing_prediction_count"],
            extra=summary["alignment"]["extra_prediction_count"],
            rf1=summary["reasoning_metrics"]["avg_reasoning_evidence_f1"],
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
