#!/usr/bin/env python3
"""Apply GPT-generated gold_reasoning_chain patches safely.

Default behavior writes patched_gold.jsonl to a new output directory and never
overwrites the source gold.jsonl. Use --overwrite only when intentionally
replacing the original gold file.
"""
from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any, Iterable


REQUIRED_STEPS = [
    "scenario_or_evidence_understanding",
    "observable_evidence",
    "attack_stage_path_reasoning",
    "final_judgement",
]


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as fh:
        for line_no, line in enumerate(fh, 1):
            s = line.strip()
            if not s:
                continue
            row = json.loads(s)
            row["_line_no"] = line_no
            rows.append(row)
    return rows


def write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with path.open("w", encoding="utf-8") as fh:
        for row in rows:
            clean = {k: v for k, v in row.items() if not k.startswith("_")}
            fh.write(json.dumps(clean, ensure_ascii=False))
            fh.write("\n")
            n += 1
    return n


def validate_chain(chain: Any, legal_refs: set[tuple[int | None, str | None]]) -> list[str]:
    errors: list[str] = []
    if not isinstance(chain, list):
        return ["gold_reasoning_chain_not_list"]
    steps = [entry.get("step") for entry in chain if isinstance(entry, dict)]
    missing = [step for step in REQUIRED_STEPS if step not in steps]
    extra = [step for step in steps if step not in REQUIRED_STEPS]
    if missing:
        errors.append("missing_steps:" + ",".join(missing))
    if extra:
        errors.append("unknown_steps:" + ",".join(str(x) for x in extra))
    for entry in chain:
        if not isinstance(entry, dict):
            errors.append("chain_entry_not_object")
            continue
        step = entry.get("step")
        if not entry.get("claim"):
            errors.append(f"missing_claim:{step}")
        refs = entry.get("evidence_refs")
        if not isinstance(refs, list):
            errors.append(f"evidence_refs_not_list:{step}")
            continue
        if step not in {"final_judgement"} and not refs:
            errors.append(f"empty_evidence_refs:{step}")
        for ref in refs:
            if not isinstance(ref, dict):
                errors.append(f"evidence_ref_not_object:{step}")
                continue
            seq_raw = ref.get("seq")
            edge_id_raw = ref.get("edge_id")
            try:
                seq = int(seq_raw) if seq_raw is not None else None
            except (TypeError, ValueError):
                errors.append(f"invalid_ref_seq:{step}:{seq_raw}")
                continue
            edge_id = str(edge_id_raw) if edge_id_raw is not None else None
            if (seq, edge_id) not in legal_refs and not any(
                (seq is not None and seq == legal_seq) or (edge_id is not None and edge_id == legal_edge)
                for legal_seq, legal_edge in legal_refs
            ):
                errors.append(f"illegal_evidence_ref:{step}:{seq}:{edge_id}")
    return errors


def legal_refs_from_gold(gold_row: dict[str, Any]) -> set[tuple[int | None, str | None]]:
    refs: set[tuple[int | None, str | None]] = set()
    for item in ((gold_row.get("label") or {}).get("edge_stage_projection") or []):
        seq = item.get("seq")
        edge_id = item.get("edge_id")
        try:
            seq = int(seq) if seq is not None else None
        except (TypeError, ValueError):
            seq = None
        refs.add((seq, str(edge_id) if edge_id is not None else None))
    return refs


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Apply stage_reasoning gold_reasoning_chain patch JSONL safely.")
    p.add_argument("--gold", type=Path, required=True, help="Original gold.jsonl")
    p.add_argument("--patch", type=Path, required=True, help="Patch JSONL: sample_id + gold_reasoning_chain")
    p.add_argument("--output-dir", type=Path, required=True, help="Directory for patched_gold.jsonl and summaries")
    p.add_argument("--overwrite", action="store_true", help="Overwrite --gold after validation instead of writing only output-dir/patched_gold.jsonl")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    gold_rows = read_jsonl(args.gold)
    patch_rows = read_jsonl(args.patch)
    gold_by_id = {row["sample_id"]: row for row in gold_rows}

    valid_patches: dict[str, list[dict[str, Any]]] = {}
    invalid_rows: list[dict[str, Any]] = []
    for patch in patch_rows:
        sid = patch.get("sample_id")
        if not isinstance(sid, str) or sid not in gold_by_id:
            invalid_rows.append({"sample_id": sid, "errors": ["sample_id_missing_from_gold"], "patch": patch})
            continue
        chain = patch.get("gold_reasoning_chain")
        errors = validate_chain(chain, legal_refs_from_gold(gold_by_id[sid]))
        if errors:
            invalid_rows.append({"sample_id": sid, "errors": errors, "patch": patch})
            continue
        valid_patches[sid] = chain

    patched_rows: list[dict[str, Any]] = []
    for row in gold_rows:
        clean = {k: v for k, v in row.items() if not k.startswith("_")}
        sid = clean["sample_id"]
        if sid in valid_patches:
            clean["gold_reasoning_chain"] = valid_patches[sid]
        patched_rows.append(clean)

    patched_path = args.gold if args.overwrite else args.output_dir / "patched_gold.jsonl"
    invalid_path = args.output_dir / "invalid_patches.jsonl"
    summary_path = args.output_dir / "patch_summary.json"
    write_jsonl(patched_path, patched_rows)
    write_jsonl(invalid_path, invalid_rows)

    summary = {
        "gold": str(args.gold),
        "patch": str(args.patch),
        "overwrite": bool(args.overwrite),
        "outputs": {
            "patched_gold": str(patched_path),
            "invalid_patches": str(invalid_path),
            "patch_summary": str(summary_path),
        },
        "counts": {
            "gold_rows": len(gold_rows),
            "patch_rows": len(patch_rows),
            "valid_patches": len(valid_patches),
            "invalid_patches": len(invalid_rows),
        },
        "patched_stage_distribution": dict(Counter((row.get("label") or {}).get("stage") for row in patched_rows)),
        "patched_sample_ids": sorted(valid_patches),
    }
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Wrote patched gold to {patched_path}")
    print(f"Wrote {len(invalid_rows)} invalid patches to {invalid_path}")
    print(f"Wrote patch summary to {summary_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
