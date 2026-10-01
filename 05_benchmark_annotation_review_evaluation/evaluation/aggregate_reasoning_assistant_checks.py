#!/usr/bin/env python3
"""Aggregate two blinded reasoning-quality assistant runs conservatively."""
from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
from typing import Any, Iterable, Optional

from prepare_reasoning_quality_inputs import validate_conditions


DISAGREEMENT_THRESHOLD = 0.30
SUPPORT_ORDER = {
    "unverifiable": 0,
    "unsupported": 1,
    "contradicted": 1,
    "partially_supported": 2,
    "fully_supported": 3,
}
REF_ORDER = {"invalid": 0, "missing_refs": 1, "valid": 2}
OVERSTATEMENT_ORDER = {"none": 0, "minor": 1, "major": 2}
BOUNDARY_ORDER = {"sound": 0, "minor_issue": 1, "severe_boundary_error": 2}
# The paper defines key-condition coverage as full=1, partial=0.5, none=0.
COVERAGE_SCORE = {"none": 0.0, "partial": 0.5, "full": 1.0}


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as stream:
        for line_no, line in enumerate(stream, 1):
            if not line.strip():
                continue
            value = json.loads(line)
            if not isinstance(value, dict):
                raise ValueError(f"{path}:{line_no}: expected a JSON object")
            rows.append(value)
    return rows


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as stream:
        for row in rows:
            stream.write(json.dumps(row, ensure_ascii=False) + "\n")


def worst(values: list[str], order: dict[str, int], default: str) -> str:
    return max(values or [default], key=lambda value: order.get(value, order[default]))


def support_from_score(score: float, raw_values: list[str]) -> str:
    if "contradicted" in raw_values:
        return "contradicted"
    if score >= 0.85:
        return "fully_supported"
    if score >= 0.40:
        return "partially_supported"
    return "unsupported"


def coverage_score(value: Any) -> float:
    if value not in COVERAGE_SCORE:
        raise ValueError(f"invalid coverage category: {value!r}")
    return COVERAGE_SCORE[value]


def unique_rows(rows: list[dict[str, Any]], key: str) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for row in rows:
        value = row.get(key)
        if not isinstance(value, str) or not value or value in result:
            raise ValueError(f"missing or duplicate {key}: {value!r}")
        result[value] = row
    return result


def numeric_score(value: Any) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or not 0 <= value <= 1:
        raise ValueError(f"expected a finite score in [0,1], got {value!r}")
    return float(value)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--assistant-checks", type=Path, action="append", required=True)
    parser.add_argument("--assistant-packets", type=Path, required=True,
                        help="Prepared packets with the shared reference conditions and expected reasoning units")
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument(
        "--adjudications", type=Path,
        help="Optional JSONL with reviewed disagreement values: sample_id, field, value, and optional reasoning_unit_id.",
    )
    parser.add_argument(
        "--allow-unadjudicated",
        action="store_true",
        help="Return success for preview aggregates; unresolved previews remain ineligible for formal scoring.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if len(args.assistant_checks) != 2:
        raise ValueError("exactly two independent --assistant-checks files are required")
    runs = [read_jsonl(path) for path in args.assistant_checks]
    packets = unique_rows(read_jsonl(args.assistant_packets), "sample_id")
    adjudications: dict[tuple[str, Optional[str], str], float] = {}
    if args.adjudications:
        for item in read_jsonl(args.adjudications):
            sid = str(item.get("sample_id") or "")
            field = str(item.get("field") or "")
            unit_id = item.get("reasoning_unit_id")
            unit_key = str(unit_id) if unit_id is not None else None
            value = item.get("value")
            if not sid or not field:
                raise ValueError("adjudications require sample_id, field, and numeric value in [0,1]")
            key = (sid, unit_key, field)
            if key in adjudications:
                raise ValueError(f"duplicate adjudication: {key}")
            adjudications[key] = numeric_score(value)
    by_run = [unique_rows(rows, "sample_id") for rows in runs]
    if not packets or any(set(run) != set(packets) for run in by_run):
        raise ValueError("assistant runs and packets must contain identical nonempty sample_id sets")
    used_adjudications: set[tuple[str, Optional[str], str]] = set()

    def reviewed_score(sid: str, unit_id: Optional[str], field: str, values: list[float]) -> float:
        key = (sid, unit_id, field)
        value = sum(values) / len(values)
        reviewed = key in adjudications
        if reviewed:
            used_adjudications.add(key)
            value = adjudications[key]
            if field.startswith("stage_condition:") and value not in COVERAGE_SCORE.values():
                raise ValueError("condition adjudication value must be 0, 0.5, or 1")
        if abs(values[0] - values[1]) > DISAGREEMENT_THRESHOLD:
            disagreements.append({
                "sample_id": sid, "reasoning_unit_id": unit_id, "field": field,
                "assistant_values": values, "adjudicated": reviewed,
                "reviewed_value": value if reviewed else None,
            })
        return value

    claim_rows: list[dict[str, Any]] = []
    closure_rows: list[dict[str, Any]] = []
    disagreements: list[dict[str, Any]] = []
    for sid in by_run[0]:
        pair = [run[sid] for run in by_run]
        packet = packets[sid]
        if not all(row.get("assistant_id") for row in pair) or pair[0].get("assistant_id") == pair[1].get("assistant_id"):
            raise ValueError(f"{sid}: assistant_id values must be independent")
        if any(row.get("blind_model_id") != packet.get("blind_model_id") for row in pair):
            raise ValueError(f"{sid}: blind_model_id does not match the packet")
        expected_units = unique_rows(packet["reasoning_units"], "reasoning_unit_id")
        claim_maps = [
            unique_rows(row.get("claim_checks", []), "reasoning_unit_id")
            for row in pair
        ]
        if any(set(mapping) != set(expected_units) for mapping in claim_maps):
            raise ValueError(f"{sid}: assistant claim units must match the packet")
        for unit_id in claim_maps[0]:
            items = [mapping[unit_id] for mapping in claim_maps]
            support_scores = [numeric_score(item["evidence_support_score"]) for item in items]
            alignment_scores = [numeric_score(item["stage_condition_alignment"]) for item in items]
            support_score = reviewed_score(sid, unit_id, "evidence_support_score", support_scores)
            alignment_score = reviewed_score(sid, unit_id, "stage_condition_alignment", alignment_scores)
            reference_validity = worst(
                [str(item.get("evidence_ref_validity") or "missing_refs") for item in items],
                {"valid": 0, "missing_refs": 1, "invalid": 2}, "missing_refs",
            )
            if expected_units[unit_id].get("local_invalid_evidence_refs"):
                reference_validity = "invalid"
            elif not expected_units[unit_id].get("evidence_refs") and reference_validity == "valid":
                reference_validity = "missing_refs"
            claim_rows.append({
                "sample_id": sid,
                "reasoning_unit_id": unit_id,
                "claim_type": str(items[0].get("claim_type") or "operation_inference"),
                "is_substantive_claim": any(bool(item.get("is_substantive_claim", True)) for item in items),
                "evidence_support": support_from_score(
                    support_score, [str(item.get("evidence_support") or "unverifiable") for item in items]
                ),
                "evidence_support_score": support_score,
                "stage_condition_alignment": alignment_score,
                "evidence_ref_validity": reference_validity,
                "critical_evidence_error": any(bool(item.get("critical_evidence_error")) for item in items),
                "contradiction": any(bool(item.get("contradiction")) or item.get("evidence_support") == "contradicted" for item in items),
                "hidden_evidence_use": any(bool(item.get("hidden_evidence_use")) for item in items),
                "out_of_window_evidence": any(bool(item.get("out_of_window_evidence")) for item in items),
                "overstatement_level": worst(
                    [str(item.get("overstatement_level") or "none") for item in items],
                    OVERSTATEMENT_ORDER,
                    "none",
                ),
            })

        closures = [row.get("closure_check") or {} for row in pair]
        assistant_scores = [numeric_score(item["stage_closure_coverage_score"]) for item in closures]

        # Recompute SCC from the per-condition checklist. The assistant's
        # aggregate score is retained for audit only; it is never trusted as
        # the public metric source.
        conditions = unique_rows(validate_conditions(packet, packet["evidence_window"]), "condition_id")
        coverage_maps = [unique_rows(item.get("checklist_coverage", []), "condition_id") for item in closures]
        if any(set(mapping) != set(conditions) for mapping in coverage_maps):
            raise ValueError(f"{sid}: both assistants must cover the exact shared condition checklist")
        merged_claims = {row["reasoning_unit_id"]: row for row in claim_rows if row["sample_id"] == sid}

        condition_scores: list[float] = []
        checklist: list[dict[str, Any]] = []
        for condition_id, condition in conditions.items():
            items = [mapping[condition_id] for mapping in coverage_maps]
            values = [coverage_score(item.get("coverage")) for item in items]
            for item, value in zip(items, values):
                refs = item.get("covered_by_reasoning_unit_ids")
                if not isinstance(refs, list) or any(unit_id not in expected_units for unit_id in refs):
                    raise ValueError(f"{sid}/{condition_id}: coverage references an unknown reasoning unit")
                if value > 0 and not refs:
                    raise ValueError(f"{sid}/{condition_id}: positive coverage requires a reasoning unit")
                if "importance" in item and item["importance"] != condition["importance"]:
                    raise ValueError(f"{sid}/{condition_id}: assistant cannot change condition importance")
            score = reviewed_score(sid, None, f"stage_condition:{condition_id}", values)
            unit_ids = sorted({
                str(unit_id)
                for item in items
                for unit_id in item.get("covered_by_reasoning_unit_ids", []) or []
            })
            # Only supported, risk-free units can establish a closure condition.
            unit_ids = [uid for uid in unit_ids if
                        merged_claims[uid]["evidence_support"] in {"fully_supported", "partially_supported"}
                        and merged_claims[uid]["evidence_ref_validity"] != "invalid"
                        and not any(merged_claims[uid].get(flag) for flag in (
                            "critical_evidence_error", "contradiction", "hidden_evidence_use", "out_of_window_evidence"))]
            if not unit_ids:
                score = 0.0
            if condition["importance"] == "key":
                condition_scores.append(score)
            checklist.append({
                "condition_id": condition_id,
                "importance": condition["importance"],
                "coverage": "full" if score == 1.0 else "partial" if score > 0 else "none",
                "coverage_score": score,
                "covered_by_reasoning_unit_ids": unit_ids,
            })

        stage_closure_coverage_score = sum(condition_scores) / len(condition_scores)
        claim_critical = any(
            bool(row.get(flag))
            for row in claim_rows
            if str(row.get("sample_id")) == sid
            for flag in ("critical_evidence_error", "contradiction", "hidden_evidence_use", "out_of_window_evidence")
        )
        claim_invalid_ref = any(
            str(row.get("sample_id")) == sid and str(row.get("evidence_ref_validity")) == "invalid"
            for row in claim_rows
        )
        closure_rows.append({
            "sample_id": sid,
            "scoring_ready": not any(item["sample_id"] == sid and not item["adjudicated"] for item in disagreements),
            "unresolved_disagreement_count": sum(item["sample_id"] == sid and not item["adjudicated"] for item in disagreements),
            "stage_closure_coverage_score": stage_closure_coverage_score,
            "assistant_stage_closure_coverage_scores": assistant_scores,
            "boundary_discipline": worst(
                [str(item.get("boundary_discipline") or "minor_issue") for item in closures],
                BOUNDARY_ORDER,
                "minor_issue",
            ),
            "sample_level_critical_evidence_error": claim_critical or any(bool(item.get("sample_level_critical_evidence_error")) for item in closures),
            "sample_level_invalid_evidence_refs": claim_invalid_ref or any(bool(item.get("sample_level_invalid_evidence_refs")) for item in closures),
            "checklist_coverage": checklist,
        })

    if set(adjudications) != used_adjudications:
        raise ValueError(f"unknown adjudication targets: {sorted(set(adjudications) - used_adjudications, key=str)}")
    unresolved = sum(not item["adjudicated"] for item in disagreements)
    write_jsonl(args.output_dir / "claim_checks.aggregated.jsonl", claim_rows)
    write_jsonl(args.output_dir / "closure_checks.aggregated.jsonl", closure_rows)
    write_json(args.output_dir / "disagreement_report.json", {
        "threshold_abs": DISAGREEMENT_THRESHOLD,
        "high_disagreement_count": len(disagreements),
        "items": disagreements,
        "adjudicated_count": len(adjudications),
        "unresolved_disagreement_count": unresolved,
        "human_adjudication_required": bool(unresolved),
    })
    print(json.dumps({
        "sample_count": len(closure_rows),
        "claim_count": len(claim_rows),
        "high_disagreement_count": len(disagreements),
        "unresolved_disagreement_count": unresolved,
    }, indent=2))
    return 0 if args.allow_unadjudicated or not unresolved else 2


if __name__ == "__main__":
    raise SystemExit(main())
