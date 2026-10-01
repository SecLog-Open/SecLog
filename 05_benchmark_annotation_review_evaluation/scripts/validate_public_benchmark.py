#!/usr/bin/env python3
"""Validate the unified public SecLog-Bench-216 contract."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any


STAGES = ("preparation", "execution", "result", "stage_unclosed")
EXPECTED_IDS = [f"sample_{index:06d}" for index in range(1, 217)]
DATA_FILES = (
    "sample_index.jsonl",
    "evidence_windows.jsonl",
    "gold_labels.jsonl",
    "prompt_pack.jsonl",
    "reference_reasoning_chains.jsonl",
)
FORBIDDEN_PUBLIC_MARKERS = (
    "source_dataset",
    "source_sample_id",
    "masked_sample_label",
    r"\bmerged\d{2,4}_position\b",
    "component_sample_counts",
    "source_release_inputs",
    # Generic patterns catch legacy partition names/counts without encoding
    # any fixed batch vocabulary in the public validator.
    r"\b(?:clean|add)\d{2,4}\b",
    r"\b\d{2,3}\+\d{2,3}\b",
    "ss_edge_",
    "edge_m_",
    "sample" + "_m_",
)


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


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_args() -> argparse.Namespace:
    release_root = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--benchmark-dir",
        type=Path,
        default=release_root / "SecLog-Bench-216",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    benchmark = args.benchmark_dir.resolve()
    data = benchmark / "data"
    manifest_path = data / "dataset_manifest.json"
    if not manifest_path.is_file():
        raise FileNotFoundError(manifest_path)
    release_manifest_path = benchmark / "manifest.json"
    if not release_manifest_path.is_file():
        raise FileNotFoundError(release_manifest_path)
    release_manifest = json.loads(release_manifest_path.read_text(encoding="utf-8"))

    rows_by_name = {name: read_jsonl(data / name) for name in DATA_FILES}
    checks: dict[str, bool] = {}
    checks["all_counts_216"] = all(len(rows) == 216 for rows in rows_by_name.values())
    ids_by_name = {
        name: [str(row.get("sample_id") or "") for row in rows]
        for name, rows in rows_by_name.items()
    }
    checks["ids_contiguous_and_aligned"] = all(ids == EXPECTED_IDS for ids in ids_by_name.values())

    stage_counts = Counter(str(row.get("gold_stage")) for row in rows_by_name["gold_labels.jsonl"])
    checks["stage_distribution_54_each"] = {
        stage: stage_counts.get(stage, 0) for stage in STAGES
    } == {stage: 54 for stage in STAGES}

    index_fields = set(rows_by_name["sample_index.jsonl"][0])
    evidence_fields = set(rows_by_name["evidence_windows.jsonl"][0])
    checks["uniform_sample_index_schema"] = all(set(row) == index_fields for row in rows_by_name["sample_index.jsonl"])
    checks["uniform_evidence_schema"] = all(set(row) == evidence_fields for row in rows_by_name["evidence_windows.jsonl"])
    checks["sample_local_edge_ids"] = all(
        [str(edge.get("edge_id") or "") for edge in row.get("selected_spine", [])]
        == [
            f"{row['sample_id']}_edge_{position:06d}"
            for position, _ in enumerate(row.get("selected_spine", []), 1)
        ]
        for row in rows_by_name["evidence_windows.jsonl"]
    )

    checks["evidence_reference_inventory_matches_spine"] = all(
        [
            (str(ref.get("edge_id") or ""), int(ref.get("seq")))
            for ref in row.get("evidence_refs_inventory", [])
            if ref.get("edge_id") is not None and ref.get("seq") is not None
        ]
        == [
            (str(edge.get("edge_id") or ""), int(edge.get("seq")))
            for edge in row.get("selected_spine", [])
        ]
        for row in rows_by_name["evidence_windows.jsonl"]
    )

    prompt_by_id = {
        str(row["sample_id"]): row for row in rows_by_name["prompt_pack.jsonl"]
    }
    checks["prompt_contains_visible_sample_edges"] = all(
        row["sample_id"] in json.dumps(prompt_by_id[row["sample_id"]], ensure_ascii=False)
        and all(
            str(edge["edge_id"]) in json.dumps(prompt_by_id[row["sample_id"]], ensure_ascii=False)
            for edge in row.get("selected_spine", [])
        )
        for row in rows_by_name["evidence_windows.jsonl"]
    )
    prompt_text = "\n".join(
        json.dumps(row, ensure_ascii=False) for row in rows_by_name["prompt_pack.jsonl"]
    ).lower()
    checks["prompt_has_no_hidden_label_fields"] = not any(
        marker in prompt_text for marker in ("\"malicious\"", "\"is_attack_related\"", "\"gold_stage\"")
    )

    public_text = "\n".join(
        [manifest_path.read_text(encoding="utf-8")]
        + [(data / name).read_text(encoding="utf-8") for name in DATA_FILES]
    ).lower()
    checks["no_historical_partition_markers"] = not any(
        re.search(marker, public_text, flags=re.IGNORECASE)
        for marker in FORBIDDEN_PUBLIC_MARKERS
    )

    evidence_by_id = {
        str(row["sample_id"]): row for row in rows_by_name["evidence_windows.jsonl"]
    }
    reference_ok = True
    for row in rows_by_name["reference_reasoning_chains.jsonl"]:
        sid = str(row["sample_id"])
        allowed = {
            (str(ref.get("edge_id")), int(ref.get("seq")))
            for ref in evidence_by_id[sid].get("evidence_refs_inventory", [])
            if ref.get("edge_id") is not None and ref.get("seq") is not None
        }
        for step in row.get("reference_reasoning_chain", []) or []:
            for ref in step.get("evidence_refs", []) or []:
                key = (str(ref.get("edge_id")), int(ref.get("seq")))
                if key not in allowed:
                    reference_ok = False
    checks["reference_chains_use_visible_refs"] = reference_ok
    checks["manifest_hashes_match"] = all(
        release_manifest.get("files", {}).get(f"data/{name}") == sha256(data / name)
        for name in DATA_FILES
    )
    release_license = str(release_manifest.get("license") or "").strip()
    release_version = str(release_manifest.get("version") or "").strip()
    # A license may be supplied by the publisher separately.  The public
    # benchmark manifest intentionally leaves this optional, so absence is
    # valid while placeholder text is not.
    checks["release_license_valid_or_unset"] = not release_license or (
        "to_be_selected" not in release_license.lower()
    )
    checks["release_version_final"] = bool(release_version) and (
        "candidate" not in release_version.lower()
    )

    result = {
        "schema_version": "seclog_bench.public_validation.v1",
        "benchmark": str(benchmark),
        "checks": checks,
        "validation_passed": all(checks.values()),
        "sample_count": len(rows_by_name["sample_index.jsonl"]),
        "stage_distribution": {stage: stage_counts.get(stage, 0) for stage in STAGES},
    }
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["validation_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
