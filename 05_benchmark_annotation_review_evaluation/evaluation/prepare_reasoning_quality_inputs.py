#!/usr/bin/env python3
"""Build model-identity-blinded reasoning-quality assistant packets."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Iterable


STEP_TYPES = {
    "scenario_or_evidence_understanding": "observable_fact",
    "observable_evidence": "observable_fact",
    "attack_stage_path_reasoning": "operation_inference",
    "final_judgement": "final_stage_judgement",
}


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


def prediction_stage(row: dict[str, Any]) -> str:
    return str(row.get("normalized_stage") or row.get("predicted_stage") or "")


def unique_rows(rows: list[dict[str, Any]], key: str) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for row in rows:
        value = row.get(key)
        if not isinstance(value, str) or not value or value in result:
            raise ValueError(f"missing or duplicate {key}: {value!r}")
        result[value] = row
    return result


def valid_evidence_ref(ref: Any, evidence: dict[str, Any]) -> bool:
    if not isinstance(ref, dict):
        return False
    spine = (evidence.get("input") or {}).get("spine")
    if spine is None:
        spine = evidence.get("selected_spine", [])
    seq, edge_id = ref.get("seq"), ref.get("edge_id")
    if seq is None and edge_id is None:
        return False
    if seq is not None and (isinstance(seq, bool) or not isinstance(seq, int)):
        return False
    return any(
        (seq is None or edge.get("seq") == seq)
        and (edge_id is None or edge.get("edge_id") == edge_id)
        for edge in spine
    )


def validate_conditions(row: dict[str, Any], evidence: dict[str, Any]) -> list[dict[str, Any]]:
    conditions = row.get("stage_conditions", [])
    unique_rows(conditions, "condition_id")
    if not conditions or not any(item.get("importance") == "key" for item in conditions):
        raise ValueError(f"{row['sample_id']}: at least one key reference condition is required")
    for item in conditions:
        if item.get("importance") not in {"key", "optional"} or not str(item.get("description") or "").strip():
            raise ValueError("conditions require a description and key/optional importance")
        refs = item.get("evidence_refs")
        if not isinstance(refs, list) or any(not valid_evidence_ref(ref, evidence) for ref in refs):
            raise ValueError("condition evidence_refs must refer to visible evidence")
    return conditions


def reasoning_units(row: dict[str, Any]) -> list[dict[str, Any]]:
    units: list[dict[str, Any]] = []
    for index, item in enumerate(row.get("reasoning_chain", []) or [], 1):
        claim = str(item.get("claim") or "").strip()
        if not claim:
            continue
        step = str(item.get("step") or "").strip()
        lowered = claim.lower()
        claim_type = STEP_TYPES.get(step, "operation_inference")
        if any(token in lowered for token in ("not visible", "insufficient", "cannot confirm", "未显示", "不足", "无法确认")):
            claim_type = "boundary_or_missing_evidence"
        units.append({
            "reasoning_unit_id": f"unit_{index:02d}",
            "step": step,
            "claim": claim,
            "claim_type": claim_type,
            "is_substantive_claim": True,
            "evidence_refs": list(item.get("evidence_refs") or []),
        })
    return units


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--predictions", type=Path)
    parser.add_argument("--evidence-windows", type=Path, required=True)
    parser.add_argument("--reference-chains", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--blind-model-id", default="eval_subject_01")
    parser.add_argument("--reference-only", action="store_true",
                        help="Export reference-only packets for preparing a shared condition checklist")
    parser.add_argument("--stage-conditions", type=Path,
                        help="JSONL with sample_id and shared stage_conditions, prepared independently of predictions")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    evidence = read_jsonl(args.evidence_windows)
    references = read_jsonl(args.reference_chains)
    evidence_by_id = unique_rows(evidence, "sample_id")
    reference_by_id = unique_rows(references, "sample_id")
    ids = list(evidence_by_id)
    if not ids or set(ids) != set(reference_by_id):
        raise ValueError("evidence windows and reference chains must have identical nonempty sample_id sets")
    if args.reference_only:
        if args.predictions or args.stage_conditions:
            raise ValueError("reference-only preparation does not accept predictions or conditions")
        write_jsonl(args.output_dir / "reference_condition_packets.jsonl", ({
            "sample_id": sid,
            "gold_stage": reference_by_id[sid]["gold_stage"],
            "evidence_window": evidence_by_id[sid],
            "reference_reasoning_chain": reference_by_id[sid]["reference_reasoning_chain"],
        } for sid in ids))
        print(json.dumps({"sample_count": len(ids)}))
        return 0
    if not args.predictions or not args.stage_conditions:
        raise ValueError("assistant preparation requires --predictions and --stage-conditions")
    pred_by_id = unique_rows(read_jsonl(args.predictions), "sample_id")
    conditions_by_id = unique_rows(read_jsonl(args.stage_conditions), "sample_id")
    if set(ids) != set(pred_by_id) or set(ids) != set(conditions_by_id):
        raise ValueError("predictions and shared conditions must cover every evidence sample exactly once")

    unit_rows: list[dict[str, Any]] = []
    packets: list[dict[str, Any]] = []
    for sid in ids:
        units = reasoning_units(pred_by_id[sid])
        for unit in units:
            unit["local_invalid_evidence_refs"] = any(
                not valid_evidence_ref(ref, evidence_by_id[sid]) for ref in unit["evidence_refs"]
            )
            unit_rows.append({
                "sample_id": sid,
                "blind_model_id": args.blind_model_id,
                **unit,
            })
        packets.append({
            "schema_version": "seclog_bench.reasoning_assistant_packet.v1",
            "sample_id": sid,
            "blind_model_id": args.blind_model_id,
            "predicted_stage": prediction_stage(pred_by_id[sid]),
            "gold_stage": reference_by_id[sid]["gold_stage"],
            "reasoning_units": units,
            "stage_conditions": validate_conditions(conditions_by_id[sid], evidence_by_id[sid]),
            "evidence_window": evidence_by_id[sid],
            "reference_reasoning_chain": reference_by_id[sid].get("reference_reasoning_chain", []),
        })

    write_jsonl(args.output_dir / "reasoning_units.jsonl", unit_rows)
    write_jsonl(args.output_dir / "assistant_packets.jsonl", packets)
    write_json(args.output_dir / "protocol_manifest.json", {
        "schema_version": "seclog_bench.reasoning_quality_preparation.v1",
        "sample_count": len(packets),
        "reasoning_unit_count": len(unit_rows),
        "blind_model_id": args.blind_model_id,
        "tested_model_identity_in_packets": False,
        "assistant_runs_required": 2,
        "assistant_output_contract": "reasoning_quality_protocol/assistant_output.schema.json",
    })
    print(json.dumps({"sample_count": len(packets), "reasoning_unit_count": len(unit_rows)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
