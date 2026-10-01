#!/usr/bin/env python3
"""Build a read-only stratified sample-check plan for SecLog-Bench-216.

This script never calls an API, never runs the EWVAA pipeline, never generates
candidate gold, and never modifies canonical or strict-blind benchmark files.
It only reads benchmark/workbench metadata and writes a seeded sample plan under
an output directory.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter, OrderedDict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DATA_ROOT = Path("workdir/canonical_benchmark/data")
DEFAULT_COMPACT_REPORT = Path("workdir/compact_annotation_workbench/reports/compact_fidelity_report.json")
DEFAULT_OUTPUT_DIR = Path("workdir/stratified_sample_check")
DEFAULT_SEED = 20260428
DEFAULT_SAMPLE_SIZE = 10
HIGH_RISK_MINIMUM = 3
SPINE_LONG_WINDOW_THRESHOLD = 1000
COMPACT_RATIO_HIGH_RISK_THRESHOLD = 0.1
STAGE_QUOTAS = OrderedDict(
    [
        ("stage_unclosed", 4),
        ("execution", 3),
        ("preparation", 1),
        ("result", 2),
    ]
)
STAGE_ORDER = tuple(STAGE_QUOTAS.keys())


@dataclass(frozen=True)
class SampleRecord:
    sample_id: str
    scenario_id: str
    gold_stage: str
    spine_len: int
    compact_spine_ratio: float | None
    high_risk: bool
    high_risk_reasons: tuple[str, ...]
    window_start_seq: int | None
    window_end_seq: int | None


def now_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def rel(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(ROOT))
    except ValueError:
        return str(path)


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, 1):
            text = line.strip()
            if not text:
                continue
            row = json.loads(text)
            if not isinstance(row, dict):
                raise ValueError(f"{rel(path)} line {line_no} is not a JSON object")
            rows.append(row)
    return rows


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")


def stable_rank(seed: int, bucket: str, sample_id: str) -> tuple[str, str]:
    key = f"{seed}|{bucket}|{sample_id}".encode("utf-8")
    return hashlib.sha256(key).hexdigest(), sample_id


def sorted_records(records: list[SampleRecord], seed: int, bucket: str) -> list[SampleRecord]:
    return sorted(records, key=lambda item: stable_rank(seed, bucket, item.sample_id))


def compact_ratio_from_row(row: dict[str, Any]) -> float | None:
    ratio = row.get("compression_ratio")
    if not isinstance(ratio, dict):
        return None
    value = ratio.get("spine")
    if isinstance(value, (int, float)):
        return float(value)
    return None


def load_compact_index(compact_report_path: Path) -> dict[str, dict[str, Any]]:
    doc = read_json(compact_report_path)
    rows = doc.get("sample_fidelity")
    if not isinstance(rows, list):
        raise ValueError(f"{rel(compact_report_path)} missing sample_fidelity list")

    indexed: dict[str, dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        if row.get("consumer_role") != "annotator":
            continue
        sample_id = row.get("original_sample_id")
        if isinstance(sample_id, str):
            indexed[sample_id] = row
    return indexed


def load_records(data_root: Path, compact_report_path: Path) -> tuple[list[SampleRecord], dict[str, Any]]:
    sample_index_path = data_root / "sample_index.jsonl"
    model_input_path = data_root / "model_input.jsonl"
    gold_path = data_root / "gold.jsonl"

    sample_index_rows = read_jsonl(sample_index_path)
    model_input_rows = read_jsonl(model_input_path)
    gold_rows = read_jsonl(gold_path)
    compact_index = load_compact_index(compact_report_path)

    sample_index_map = {row["sample_id"]: row for row in sample_index_rows}
    model_input_map = {row["sample_id"]: row for row in model_input_rows}
    gold_map = {row["sample_id"]: row for row in gold_rows}

    sample_ids = set(sample_index_map)
    if sample_ids != set(model_input_map) or sample_ids != set(gold_map):
        raise ValueError("benchmark sample_id sets are not aligned across sample_index/model_input/gold")

    records: list[SampleRecord] = []
    stage_alignment_errors: list[str] = []
    missing_compact_rows: list[str] = []

    for sample_id in sorted(sample_ids):
        sample_index_row = sample_index_map[sample_id]
        model_input_row = model_input_map[sample_id]
        gold_row = gold_map[sample_id]

        sample_stage = sample_index_row.get("stage")
        gold_label = gold_row.get("label")
        gold_stage = gold_label.get("stage") if isinstance(gold_label, dict) else None
        if sample_stage != gold_stage:
            stage_alignment_errors.append(sample_id)
        if not isinstance(gold_stage, str):
            raise ValueError(f"gold stage missing for {sample_id}")

        input_block = model_input_row.get("input")
        spine = input_block.get("spine") if isinstance(input_block, dict) else None
        if not isinstance(spine, list):
            raise ValueError(f"missing input.spine for {sample_id}")
        spine_len = len(spine)

        compact_row = compact_index.get(sample_id)
        if compact_row is None:
            missing_compact_rows.append(sample_id)
            compact_ratio = None
        else:
            compact_ratio = compact_ratio_from_row(compact_row)

        risk_reasons: list[str] = []
        if spine_len > SPINE_LONG_WINDOW_THRESHOLD:
            risk_reasons.append(f"spine_len>{SPINE_LONG_WINDOW_THRESHOLD}")
        if compact_ratio is not None and compact_ratio < COMPACT_RATIO_HIGH_RISK_THRESHOLD:
            risk_reasons.append(f"compact_ratio<{COMPACT_RATIO_HIGH_RISK_THRESHOLD}")

        window = sample_index_row.get("window")
        window_start = window.get("start_seq") if isinstance(window, dict) else None
        window_end = window.get("end_seq") if isinstance(window, dict) else None

        records.append(
            SampleRecord(
                sample_id=sample_id,
                scenario_id=str(sample_index_row.get("scenario_id")),
                gold_stage=gold_stage,
                spine_len=spine_len,
                compact_spine_ratio=compact_ratio,
                high_risk=bool(risk_reasons),
                high_risk_reasons=tuple(risk_reasons),
                window_start_seq=window_start if isinstance(window_start, int) else None,
                window_end_seq=window_end if isinstance(window_end, int) else None,
            )
        )

    meta = {
        "sample_index_count": len(sample_index_rows),
        "model_input_count": len(model_input_rows),
        "gold_count": len(gold_rows),
        "compact_annotator_count": len(compact_index),
        "stage_alignment_errors": stage_alignment_errors,
        "missing_compact_rows": missing_compact_rows,
    }
    return records, meta


def add_selection(
    selections: list[dict[str, Any]],
    selected_ids: set[str],
    record: SampleRecord,
    selection_reason: str,
) -> None:
    if record.sample_id in selected_ids:
        return
    selections.append(
        {
            "sample_id": record.sample_id,
            "scenario_id": record.scenario_id,
            "gold_stage": record.gold_stage,
            "is_high_risk": record.high_risk,
            "high_risk_reasons": list(record.high_risk_reasons),
            "spine_len": record.spine_len,
            "compact_spine_ratio": record.compact_spine_ratio,
            "window": {
                "start_seq": record.window_start_seq,
                "end_seq": record.window_end_seq,
            },
            "selection_reason": selection_reason,
        }
    )
    selected_ids.add(record.sample_id)


def select_plan(records: list[SampleRecord], seed: int, sample_size: int) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    quota_total = sum(STAGE_QUOTAS.values())
    if sample_size < quota_total:
        raise ValueError(
            f"sample_size={sample_size} is smaller than fixed stage quota total={quota_total}"
        )

    by_stage: dict[str, list[SampleRecord]] = {stage: [] for stage in STAGE_ORDER}
    for record in records:
        if record.gold_stage not in by_stage:
            raise ValueError(f"unexpected stage in benchmark: {record.gold_stage}")
        by_stage[record.gold_stage].append(record)

    selections: list[dict[str, Any]] = []
    selected_ids: set[str] = set()
    remaining_quota = dict(STAGE_QUOTAS)
    fallback_events: list[str] = []

    high_risk_candidates = sorted_records(
        [record for record in records if record.high_risk],
        seed,
        "global-high-risk-minimum",
    )
    for record in high_risk_candidates:
        if sum(1 for item in selections if item["is_high_risk"]) >= HIGH_RISK_MINIMUM:
            break
        if remaining_quota.get(record.gold_stage, 0) <= 0:
            continue
        reason = "reserved high-risk sample to satisfy minimum long-window/compression-risk coverage"
        add_selection(selections, selected_ids, record, reason)
        remaining_quota[record.gold_stage] -= 1

    for stage in STAGE_ORDER:
        need = remaining_quota[stage]
        if need <= 0:
            continue

        stage_remaining = [
            record
            for record in by_stage[stage]
            if record.sample_id not in selected_ids
        ]
        stage_high_risk = sorted_records(
            [record for record in stage_remaining if record.high_risk],
            seed,
            f"{stage}-stage-high-risk-fill",
        )
        stage_standard = sorted_records(
            [record for record in stage_remaining if not record.high_risk],
            seed,
            f"{stage}-stage-standard-fill",
        )

        for record in stage_high_risk:
            if need <= 0:
                break
            add_selection(
                selections,
                selected_ids,
                record,
                "filled stage quota from same-stage high-risk pool",
            )
            need -= 1

        for record in stage_standard:
            if need <= 0:
                break
            add_selection(
                selections,
                selected_ids,
                record,
                "filled stage quota from seeded same-stage remaining pool",
            )
            need -= 1

        remaining_quota[stage] = need
        if need > 0:
            fallback_events.append(
                f"stage {stage} shortfall after same-stage fill: missing {need}"
            )

    current_high_risk = sum(1 for item in selections if item["is_high_risk"])
    if current_high_risk < HIGH_RISK_MINIMUM:
        for stage in STAGE_ORDER:
            if current_high_risk >= HIGH_RISK_MINIMUM:
                break
            selected_non_risk = [
                item
                for item in selections
                if item["gold_stage"] == stage and not item["is_high_risk"]
            ]
            if not selected_non_risk:
                continue
            remaining_stage_high_risk = sorted_records(
                [
                    record
                    for record in by_stage[stage]
                    if record.sample_id not in selected_ids and record.high_risk
                ],
                seed,
                f"{stage}-high-risk-promotion",
            )
            while selected_non_risk and remaining_stage_high_risk and current_high_risk < HIGH_RISK_MINIMUM:
                demote = selected_non_risk.pop(0)
                promote = remaining_stage_high_risk.pop(0)
                selected_ids.remove(demote["sample_id"])
                demote["selection_reason"] = (
                    demote["selection_reason"]
                    + "; replaced during high-risk promotion fallback"
                )
                promote_reason = (
                    "promoted same-stage high-risk sample to recover minimum risk coverage"
                )
                selections = [
                    item for item in selections if item["sample_id"] != demote["sample_id"]
                ]
                add_selection(selections, selected_ids, promote, promote_reason)
                current_high_risk = sum(1 for item in selections if item["is_high_risk"])
                fallback_events.append(
                    f"promoted {promote.sample_id} over {demote['sample_id']} within stage {stage}"
                )

    if len(selections) < sample_size:
        fallback_pool = sorted_records(
            [record for record in records if record.sample_id not in selected_ids],
            seed,
            "global-seeded-fallback",
        )
        for record in fallback_pool:
            if len(selections) >= sample_size:
                break
            add_selection(
                selections,
                selected_ids,
                record,
                "global seeded fallback after stage-specific pool exhaustion",
            )
        if len(selections) > quota_total:
            fallback_events.append(
                "sample_size exceeded fixed stage quota total; appended seeded global fallback samples"
            )

    if len(selections) != sample_size:
        raise ValueError(
            f"selected {len(selections)} samples but expected sample_size={sample_size}"
        )

    ordered_selections = sorted(
        selections,
        key=lambda item: (
            STAGE_ORDER.index(item["gold_stage"]) if item["gold_stage"] in STAGE_ORDER else 999,
            stable_rank(seed, f"final-{item['gold_stage']}", item["sample_id"]),
        ),
    )
    for index, row in enumerate(ordered_selections, 1):
        row["selection_index"] = index

    summary = {
        "stage_quota_targets": dict(STAGE_QUOTAS),
        "high_risk_minimum": HIGH_RISK_MINIMUM,
        "fallback_events": fallback_events,
        "quota_total": quota_total,
    }
    return ordered_selections, summary


def build_markdown(
    plan: dict[str, Any],
    selections: list[dict[str, Any]],
) -> str:
    lines = [
        "# Stratified Stage Reasoning Sample Plan",
        "",
        f"- Generated at: `{plan['generated_at']}`",
        f"- Seed: `{plan['seed']}`",
        f"- Sample size: `{plan['sample_size']}`",
        f"- High-risk minimum: `{plan['rules']['high_risk_minimum']}`",
        f"- High-risk rule: `spine_len > {SPINE_LONG_WINDOW_THRESHOLD} or compact_ratio < {COMPACT_RATIO_HIGH_RISK_THRESHOLD}`",
        "",
        "## Summary",
        "",
        f"- Selected samples: `{plan['summary']['selected_count']}`",
        f"- Stage counts: `{plan['summary']['stage_counts']}`",
        f"- High-risk count: `{plan['summary']['high_risk_count']}`",
        f"- Stage quota satisfied: `{plan['summary']['stage_quota_satisfied']}`",
        f"- Stage quota exact match: `{plan['summary']['stage_quota_exact_match']}`",
        f"- High-risk minimum met: `{plan['summary']['high_risk_minimum_met']}`",
        f"- All sample_ids from SecLog-Bench-216: `{plan['summary']['all_sample_ids_from_benchmark']}`",
        "",
        "## Selections",
        "",
        "| # | sample_id | scenario_id | stage | high_risk | spine_len | compact_ratio | reason |",
        "|---|---|---|---|---:|---:|---:|---|",
    ]
    for row in selections:
        ratio = row["compact_spine_ratio"]
        ratio_text = "null" if ratio is None else f"{ratio:.6f}"
        lines.append(
            "| {idx} | `{sample}` | `{scenario}` | `{stage}` | `{risk}` | `{spine}` | `{ratio}` | {reason} |".format(
                idx=row["selection_index"],
                sample=row["sample_id"],
                scenario=row["scenario_id"],
                stage=row["gold_stage"],
                risk=str(row["is_high_risk"]).lower(),
                spine=row["spine_len"],
                ratio=ratio_text,
                reason=row["selection_reason"],
            )
        )

    fallback_events = plan["selection_notes"]["fallback_events"]
    lines.extend(["", "## Fallback Notes", ""])
    if fallback_events:
        for item in fallback_events:
            lines.append(f"- {item}")
    else:
        lines.append("- None")
    lines.append("")
    return "\n".join(lines)


def build_plan(
    seed: int,
    sample_size: int,
    data_root: Path,
    compact_report_path: Path,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    records, load_meta = load_records(data_root, compact_report_path)
    selections, selection_notes = select_plan(records, seed, sample_size)

    input_sample_ids = {record.sample_id for record in records}
    stage_counts = Counter(row["gold_stage"] for row in selections)
    high_risk_count = sum(1 for row in selections if row["is_high_risk"])
    quota_exact_match = all(stage_counts.get(stage, 0) == quota for stage, quota in STAGE_QUOTAS.items())
    quota_satisfied = all(stage_counts.get(stage, 0) >= quota for stage, quota in STAGE_QUOTAS.items())
    all_from_benchmark = all(row["sample_id"] in input_sample_ids for row in selections)
    unique_sample_ids = len({row["sample_id"] for row in selections}) == len(selections)

    validation_errors: list[str] = []
    if load_meta["stage_alignment_errors"]:
        validation_errors.append("stage alignment errors found between sample_index and gold")
    if len(selections) != sample_size:
        validation_errors.append("selected count does not match requested sample size")
    if not all_from_benchmark:
        validation_errors.append("sample outside canonical benchmark selected")
    if not unique_sample_ids:
        validation_errors.append("duplicate sample_id found in selection")
    if not quota_satisfied:
        validation_errors.append("stage quota minimum requirement failed")
    if high_risk_count < HIGH_RISK_MINIMUM:
        validation_errors.append("high-risk minimum not met")

    plan = {
        "schema_version": "stage_reasoning_stratified_sample_plan.v1",
        "generated_at": now_stamp(),
        "seed": seed,
        "sample_size": sample_size,
        "inputs": {
            "data_root": rel(data_root),
            "sample_index": rel(data_root / "sample_index.jsonl"),
            "model_input": rel(data_root / "model_input.jsonl"),
            "gold": rel(data_root / "gold.jsonl"),
            "compact_report": rel(compact_report_path),
        },
        "rules": {
            "stage_quotas": dict(STAGE_QUOTAS),
            "high_risk_minimum": HIGH_RISK_MINIMUM,
            "high_risk_definition": {
                "spine_len_gt": SPINE_LONG_WINDOW_THRESHOLD,
                "compact_spine_ratio_lt": COMPACT_RATIO_HIGH_RISK_THRESHOLD,
            },
            "fallback_policy": [
                "Prefer same-stage high-risk samples while filling stage quotas.",
                "If a stage is still short, fill from seeded same-stage remaining pool.",
                "If stage pools are exhausted, append seeded global fallback samples from the remaining benchmark rows.",
            ],
        },
        "load_meta": load_meta,
        "selection_notes": selection_notes,
        "summary": {
            "selected_count": len(selections),
            "stage_counts": dict(stage_counts),
            "high_risk_count": high_risk_count,
            "stage_quota_satisfied": quota_satisfied,
            "stage_quota_exact_match": quota_exact_match,
            "high_risk_minimum_met": high_risk_count >= HIGH_RISK_MINIMUM,
            "all_sample_ids_from_benchmark": all_from_benchmark,
            "unique_sample_ids": unique_sample_ids,
            "validation_errors": validation_errors,
        },
        "selections": selections,
    }
    return plan, selections


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--sample-size", type=int, default=DEFAULT_SAMPLE_SIZE)
    parser.add_argument(
        "--output-dir",
        type=Path,
        required=True,
        help=(
            "Required. Provide an explicit output directory."
        ),
    )
    parser.add_argument("--data-root", type=Path, default=DEFAULT_DATA_ROOT)
    parser.add_argument(
        "--compact-report",
        type=Path,
        required=True,
        help=(
            "Required. Pass the intended compact fidelity report explicitly instead of "
            f"falling back to {DEFAULT_COMPACT_REPORT.as_posix()}."
        ),
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    data_root = (ROOT / args.data_root).resolve()
    compact_report_path = (ROOT / args.compact_report).resolve()
    output_dir = (ROOT / args.output_dir).resolve()

    plan, selections = build_plan(
        seed=args.seed,
        sample_size=args.sample_size,
        data_root=data_root,
        compact_report_path=compact_report_path,
    )

    suffix = f"seeded{args.sample_size}"
    json_path = output_dir / f"sample_plan.{suffix}.json"
    jsonl_path = output_dir / f"sample_plan.{suffix}.jsonl"
    md_path = output_dir / f"sample_plan.{suffix}.md"

    write_json(json_path, plan)
    write_jsonl(jsonl_path, selections)
    md_path.parent.mkdir(parents=True, exist_ok=True)
    md_path.write_text(build_markdown(plan, selections) + "\n", encoding="utf-8")

    print(f"wrote {rel(json_path)}")
    print(f"wrote {rel(jsonl_path)}")
    print(f"wrote {rel(md_path)}")
    print(f"selected_count={plan['summary']['selected_count']}")
    print(f"stage_counts={plan['summary']['stage_counts']}")
    print(f"high_risk_count={plan['summary']['high_risk_count']}")
    if plan["summary"]["validation_errors"]:
        print(f"validation_errors={plan['summary']['validation_errors']}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
