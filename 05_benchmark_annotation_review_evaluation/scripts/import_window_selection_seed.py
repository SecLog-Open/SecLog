#!/usr/bin/env python3
"""Materialize window-selection candidates as a canonical benchmark workspace.

This is the explicit handoff between ``04_benchmark_window_selection`` and
the blinding/compact/annotation methods in this stage.  It reads only chain
release products and writes a new downstream tree; upstream files are never
modified.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


LEGAL_STAGES = {"preparation", "execution", "result", "stage_unclosed"}
REASONING_PROTOCOL = [
    "scenario_or_evidence_understanding",
    "observable_evidence",
    "attack_stage_path_reasoning",
    "final_judgement",
]


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
                raise ValueError(f"{path}:{line_no}: expected a JSON object")
            rows.append(row)
    return rows


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
            count += 1
    return count


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def resolve_source_path(source_base: Path, value: str) -> Path:
    path = Path(value)
    return path.resolve() if path.is_absolute() else (source_base / path).resolve()


def candidate_source_bases(source_base: Path, seed_path: Path, value: str) -> list[Path]:
    """Return compatible roots for seeds written from different workbench roots.

    Stage 04 stores paths relative to its own release-stage root.  Consumers
    often invoke the importer from a temporary parent or from the repository
    root, so try the requested base first and then the seed's actual stage root
    before failing.  This keeps the handoff path-based without embedding a
    machine-specific absolute path in the seed.
    """
    bases = [source_base.resolve(), seed_path.parent.resolve()]
    for parent in seed_path.parents:
        if parent.name == "04_benchmark_window_selection":
            bases.append(parent.resolve())
            break
    out: list[Path] = []
    seen: set[Path] = set()
    for base in bases:
        if base not in seen:
            seen.add(base)
            out.append(base)
    return out


def task_spec(sample_id: str) -> dict[str, Any]:
    return {
        "task_name": "attack_chain_stage_reasoning",
        "instruction": (
            "Predict exactly one stage from preparation, execution, result, or "
            "stage_unclosed and return a four-step evidence-grounded reasoning chain."
        ),
        "allowed_labels": sorted(LEGAL_STAGES),
        "reasoning_protocol": REASONING_PROTOCOL,
        "output_schema": {
            "task_mode": "stage_prediction",
            "sample_id": sample_id,
            "predicted_stage": "preparation | execution | result | stage_unclosed",
            "reasoning_chain": [
                {"step": step, "claim": "", "evidence_refs": []}
                for step in REASONING_PROTOCOL
            ],
            "confidence": 0.0,
        },
    }


def materialize(row: dict[str, Any], source_bases: list[Path], cache: dict[Path, dict[str, Any]]) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    sample_id = str(row.get("sample_id_seed") or "").strip()
    scenario_id = str(row.get("scenario_id") or "").strip()
    stage = str(row.get("candidate_stage") or "").strip()
    window = row.get("window") or {}
    start_seq = window.get("start_seq")
    end_seq = window.get("end_seq")
    if not sample_id or not scenario_id:
        raise ValueError("window row is missing sample_id_seed or scenario_id")
    if stage not in LEGAL_STAGES:
        raise ValueError(f"{sample_id}: invalid candidate_stage {stage!r}")
    if not isinstance(start_seq, int) or not isinstance(end_seq, int) or start_seq > end_seq:
        raise ValueError(f"{sample_id}: invalid window {window!r}")

    source_value = str((row.get("source_paths") or {}).get("behavior_chain_dataset") or "")
    if not source_value:
        raise ValueError(f"{sample_id}: missing source_paths.behavior_chain_dataset")
    source_path = next(
        (candidate for base in source_bases
         if (candidate := resolve_source_path(base, source_value)).is_file()),
        resolve_source_path(source_bases[0], source_value),
    )
    if source_path not in cache:
        if not source_path.is_file():
            raise FileNotFoundError(f"{sample_id}: behavior dataset not found: {source_path}")
        cache[source_path] = read_json(source_path)
    spine = cache[source_path].get("spine") or []
    visible_spine = [edge for edge in spine if isinstance(edge.get("seq"), int) and start_seq <= edge["seq"] <= end_seq]
    if not visible_spine:
        raise ValueError(f"{sample_id}: no spine edges found in seq window {start_seq}..{end_seq}")

    model_input = {
        "schema_version": "attack_chain_stage_reasoning_input.v1",
        "sample_id": sample_id,
        "scenario_id": scenario_id,
        "window": {"start_seq": start_seq, "end_seq": end_seq},
        "task": task_spec(sample_id),
        "input": {"spine": visible_spine},
    }
    projection = [
        {"seq": edge.get("seq"), "edge_id": edge.get("edge_id"), "stage": stage}
        for edge in visible_spine
        if isinstance(edge.get("seq"), int) and isinstance(edge.get("edge_id"), str)
    ]
    gold = {
        "schema_version": "attack_chain_stage_reasoning_gold.v1",
        "sample_id": sample_id,
        "scenario_id": scenario_id,
        "window": {"start_seq": start_seq, "end_seq": end_seq},
        "label": {
            "stage": stage,
            "stage_span": {"start_seq": start_seq, "end_seq": end_seq},
            "edge_stage_projection": projection,
        },
        "reasoning_schema_version": "ewvaa_four_step_v1",
        "reasoning_source": "pending_annotation_and_human_review",
        "gold_reasoning_chain": [],
    }
    sample_index = {
        "sample_id": sample_id,
        "scenario_id": scenario_id,
        "stage": stage,
        "selection_status": row.get("selection_status"),
        "window": {"start_seq": start_seq, "end_seq": end_seq},
        "source_files": {"behavior_chain_dataset": source_value},
    }
    return model_input, gold, sample_index


def export_unified(output_root: Path, triples: list[tuple[dict[str, Any], dict[str, Any], dict[str, Any]]]) -> dict[str, Any]:
    """Write one canonical dataset unit; selection status is metadata, not a public split."""
    data_dir = output_root / "data"
    model_rows = []
    gold_rows = []
    index_rows = []
    for position, item in enumerate(triples, 1):
        public_id = f"sample_{position:06d}"
        model_row = copy.deepcopy(item[0])
        model_row["sample_id"] = public_id
        task = model_row.get("task")
        if isinstance(task, dict):
            output_schema = task.get("output_schema")
            if isinstance(output_schema, dict):
                output_schema["sample_id"] = public_id
        model_rows.append(model_row)
        gold_row = copy.deepcopy(item[1])
        gold_row["sample_id"] = public_id
        gold_rows.append(gold_row)
        row = copy.deepcopy(item[2])
        row["sample_id"] = public_id
        row["line_no"] = position
        index_rows.append(row)
    paths = {
        "model_input": data_dir / "model_input.jsonl",
        "gold": data_dir / "gold.jsonl",
        "sample_index": data_dir / "sample_index.jsonl",
    }
    write_jsonl(paths["model_input"], model_rows)
    write_jsonl(paths["gold"], gold_rows)
    write_jsonl(paths["sample_index"], index_rows)
    return {
        "sample_count": len(triples),
        "stage_counts": dict(Counter(row[1]["label"]["stage"] for row in triples)),
        "sha256": {name: sha256(path) for name, path in paths.items()},
        "files": {name: str(path.relative_to(output_root)) for name, path in paths.items()},
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Import stage-window candidates into a canonical annotation benchmark tree.")
    parser.add_argument("--seed", type=Path, required=True, help="annotation_ready_seed.jsonl from stage 04")
    parser.add_argument("--source-base", type=Path, default=None, help="Base for relative source_paths (default: parent of the seed workbench)")
    parser.add_argument("--output-dir", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    seed = args.seed.resolve()
    source_base = args.source_base.resolve() if args.source_base else seed.parent.parent.resolve()
    source_bases = candidate_source_bases(source_base, seed, "")
    output = args.output_dir.resolve()
    if output.exists() and any(output.iterdir()):
        raise SystemExit(f"Refusing non-empty output directory: {output}")
    seed_rows = read_jsonl(seed)
    cache: dict[Path, dict[str, Any]] = {}
    triples = [materialize(row, source_bases, cache) for row in seed_rows]
    if not triples:
        raise SystemExit("Seed must contain at least one window row")
    dataset_report = export_unified(output, triples)
    manifest = {
        "schema_version": "stage_reasoning_benchmark_manifest.public_handoff.v2",
        "created_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source_seed": str(seed),
        "source_stage_derivation": "stage_derivation_v0.4.5",
        "source_benchmark_schema": "window_selection_handoff.v1",
        "dataset": dataset_report,
        "sample_count": dataset_report["sample_count"],
        "selection_status_counts": dict(Counter(str(row.get("selection_status") or "") for row in seed_rows)),
        "upstream_modified": False,
        "annotation_status": "pending_ai_annotation_and_human_review",
    }
    write_json(output / "manifest.json", manifest)
    print(json.dumps({"output_dir": str(output), "sample_count": dataset_report["sample_count"]}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
