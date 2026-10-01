#!/usr/bin/env python3
"""Normalize supported reference-chain layouts to one public schema."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


STEP_ORDER = (
    "scenario_or_evidence_understanding",
    "observable_evidence",
    "attack_stage_path_reasoning",
    "final_judgement",
)
LEGACY_KEYS = {
    "scenario_or_evidence_understanding": "evidence_understanding",
    "observable_evidence": "observable_evidence",
    "attack_stage_path_reasoning": "path_reasoning",
    "final_judgement": "final_judgement",
}


def normalize(row: dict[str, Any]) -> dict[str, Any]:
    if isinstance(row.get("gold_reasoning_chain"), list):
        by_step = {str(item.get("step")): item for item in row["gold_reasoning_chain"]}
    elif isinstance(row.get("reference_reasoning_steps"), dict):
        legacy = row["reference_reasoning_steps"]
        by_step = {
            public_step: {"step": public_step, **legacy[legacy_key]}
            for public_step, legacy_key in LEGACY_KEYS.items()
        }
    else:
        raise ValueError(f"{row.get('sample_id')}: unsupported reference-chain schema")

    chain = []
    for step in STEP_ORDER:
        item = by_step.get(step)
        if not isinstance(item, dict):
            raise ValueError(f"{row.get('sample_id')}: missing step {step}")
        claim = str(item.get("claim") or "").strip()
        refs = item.get("evidence_refs")
        if not claim or not isinstance(refs, list) or not refs:
            raise ValueError(f"{row.get('sample_id')}: invalid step {step}")
        chain.append({"step": step, "claim": claim, "evidence_refs": refs})

    return {
        "sample_id": str(row["sample_id"]),
        "gold_stage": str(row["gold_stage"]),
        "reference_reasoning_chain": chain,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    rows = []
    with args.input.open("r", encoding="utf-8") as stream:
        for line_no, line in enumerate(stream, 1):
            if line.strip():
                value = json.loads(line)
                if not isinstance(value, dict):
                    raise ValueError(f"line {line_no}: expected object")
                rows.append(normalize(value))
    if len(rows) != 216:
        raise ValueError(f"expected 216 reference chains, found {len(rows)}")
    if len({row['sample_id'] for row in rows}) != 216:
        raise ValueError("reference sample_id values are not unique")

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8", newline="\n") as stream:
        for row in rows:
            stream.write(json.dumps(row, ensure_ascii=False) + "\n")
    print(json.dumps({"rows": len(rows), "output": str(args.output)}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
