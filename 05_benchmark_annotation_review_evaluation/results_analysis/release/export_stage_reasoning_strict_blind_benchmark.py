#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any, Iterable


PRIVATE_WORK_ROOT = Path("workdir")
DEFAULT_SOURCE = PRIVATE_WORK_ROOT / "canonical_benchmark"
DEFAULT_OUTPUT = PRIVATE_WORK_ROOT / "strict_blind_benchmark"
MASKED_FIELD_KEYS = {
    "source_file",
    "write_source_file",
    "context_id",
    "event_key",
    "write_event_key",
}
SOURCE_FILE_CONTAINER_KEYS = {"source_files"}
SERVICE_NAME_KEYS = {"service_name"}
SAMPLE_ID_KEYS = {"sample_id", "original_sample_id"}
SCENARIO_ID_KEYS = {"scenario_id", "original_scenario_id"}
PLACEHOLDER_ID_VALUES = {"", "...", "string", "string or null", None}

FORBIDDEN_LEAKAGE_TERMS = [
    "CVE",
    "vulhub",
    "RCE",
    "XXE",
    "cmsms",
    "joomla",
    "gitlist",
    "adminer",
    "solr",
    "geoserver",
    "metabase",
    "ofbiz",
    "pgadmin",
    "juice-shop",
    "multi-jump",
    "sandworm",
]

FORBIDDEN_LEAKAGE_PATTERNS = [
    ("CVE", re.compile(r"\bCVE(?:-\d{4}|\b)", re.IGNORECASE)),
    ("vulhub", re.compile(r"vulhub[A-Za-z0-9_.-]*", re.IGNORECASE)),
    ("RCE", re.compile(r"\bRCE\b", re.IGNORECASE)),
    ("XXE", re.compile(r"\bXXE\b", re.IGNORECASE)),
    ("cmsms", re.compile(r"cmsms[A-Za-z0-9_.-]*", re.IGNORECASE)),
    ("joomla", re.compile(r"joomla[A-Za-z0-9_.-]*", re.IGNORECASE)),
    ("gitlist", re.compile(r"gitlist[A-Za-z0-9_.-]*", re.IGNORECASE)),
    ("adminer", re.compile(r"adminer[A-Za-z0-9_.-]*", re.IGNORECASE)),
    ("solr", re.compile(r"solr[A-Za-z0-9_.-]*", re.IGNORECASE)),
    ("geoserver", re.compile(r"geoserver[A-Za-z0-9_.-]*", re.IGNORECASE)),
    ("metabase", re.compile(r"metabase[A-Za-z0-9_.-]*", re.IGNORECASE)),
    ("ofbiz", re.compile(r"ofbiz[A-Za-z0-9_.-]*", re.IGNORECASE)),
    ("pgadmin", re.compile(r"pgadmin[A-Za-z0-9_.-]*", re.IGNORECASE)),
    ("juice-shop", re.compile(r"juice-shop[A-Za-z0-9_.-]*", re.IGNORECASE)),
    ("multi-jump", re.compile(r"multi-jump[A-Za-z0-9_.-]*", re.IGNORECASE)),
    ("sandworm", re.compile(r"sandworm[A-Za-z0-9_.-]*", re.IGNORECASE)),
]

PRIMARY_EVIDENCE_PRESERVED = [
    "subject",
    "object",
    "relation",
    "message",
    "process/file/network facts",
    "HTTP path",
    "service response",
    "timestamp",
    "seq",
]

PRIMARY_EVIDENCE_POLICY_NOTE = (
    "Primary evidence fields and non-scenario-bearing facts are retained. Exact scenario-bearing "
    "tokens listed in the leakage policy are pseudonymized when they appear inside primary "
    "evidence paths/messages, so model_input remains strict blind."
)

REASONING_PROTOCOL = [
    "scenario_or_evidence_understanding",
    "observable_evidence",
    "attack_stage_path_reasoning",
    "final_judgement",
]
REASONING_SCHEMA_VERSION = "ewvaa_four_step_v1"

VISIBLE_TEXT_REPLACEMENTS = [
    (re.compile(r"\bCVE-\d{4}-\d{4,7}(?:-[A-Za-z0-9_.-]+)?\b", re.IGNORECASE), "public_advisory_m"),
    (re.compile(r"\bCVE\b", re.IGNORECASE), "public_advisory_m"),
    (re.compile(r"vulhub[A-Za-z0-9_.-]*", re.IGNORECASE), "lab_corpus_m"),
    (re.compile(r"\bRCE\b", re.IGNORECASE), "behavior_class_m"),
    (re.compile(r"\bXXE\b", re.IGNORECASE), "parser_class_m"),
    (re.compile(r"cmsms[A-Za-z0-9_.-]*", re.IGNORECASE), "app_family_m"),
    (re.compile(r"joomla[A-Za-z0-9_.-]*", re.IGNORECASE), "app_family_m"),
    (re.compile(r"gitlist[A-Za-z0-9_.-]*", re.IGNORECASE), "app_family_m"),
    (re.compile(r"adminer[A-Za-z0-9_.-]*", re.IGNORECASE), "app_family_m"),
    (re.compile(r"solr[A-Za-z0-9_.-]*", re.IGNORECASE), "app_family_m"),
    (re.compile(r"geoserver[A-Za-z0-9_.-]*", re.IGNORECASE), "app_family_m"),
    (re.compile(r"metabase[A-Za-z0-9_.-]*", re.IGNORECASE), "app_family_m"),
    (re.compile(r"ofbiz[A-Za-z0-9_.-]*", re.IGNORECASE), "app_family_m"),
    (re.compile(r"pgadmin[A-Za-z0-9_.-]*", re.IGNORECASE), "app_family_m"),
    (re.compile(r"juice-shop[A-Za-z0-9_.-]*", re.IGNORECASE), "app_family_m"),
    (re.compile(r"multi-jump[A-Za-z0-9_.-]*", re.IGNORECASE), "scenario_family_m"),
    (re.compile(r"sandworm[A-Za-z0-9_.-]*", re.IGNORECASE), "scenario_family_m"),
]


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n")
            count += 1
    return count


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_hashes(source: Path) -> dict[str, str]:
    files = [
        source / "manifest.json",
        source / "README.md",
        source / "data" / "model_input.jsonl",
        source / "data" / "gold.jsonl",
        source / "data" / "sample_index.jsonl",
    ]
    return {str(path): sha256_file(path) for path in files if path.exists()}


def ordered_unique(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        if value and value not in seen:
            seen.add(value)
            out.append(value)
    return out


def is_placeholder(value: Any) -> bool:
    if value is None:
        return True
    if isinstance(value, str):
        return value.strip() in PLACEHOLDER_ID_VALUES
    return False


def is_edge_key(key: str) -> bool:
    return key == "edge_id" or key.endswith("_edge_id")


def collect_split_values(value: Any, collected: dict[str, list[Any]]) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            key_s = str(key)
            if key_s in SAMPLE_ID_KEYS and isinstance(item, str) and not is_placeholder(item):
                collected["sample"].append(item)
            elif key_s in SCENARIO_ID_KEYS and isinstance(item, str) and not is_placeholder(item):
                collected["scenario"].append(item)
            elif is_edge_key(key_s) and isinstance(item, str) and not is_placeholder(item):
                collected["edge"].append(item)
            elif key_s in MASKED_FIELD_KEYS and not is_placeholder(item):
                collect_metadata_values(key_s, item, collected)
            elif key_s in SOURCE_FILE_CONTAINER_KEYS and not is_placeholder(item):
                collect_metadata_values(key_s, item, collected)
            elif key_s in SERVICE_NAME_KEYS and not is_placeholder(item):
                collect_metadata_values(key_s, item, collected)
            collect_split_values(item, collected)
    elif isinstance(value, list):
        for item in value:
            collect_split_values(item, collected)


def collect_metadata_values(field: str, value: Any, collected: dict[str, list[Any]]) -> None:
    if isinstance(value, str):
        collected["metadata"].append((field, value))
    elif isinstance(value, dict):
        for key, item in value.items():
            collect_metadata_values(f"{field}.{key}", item, collected)
    elif isinstance(value, list):
        for item in value:
            collect_metadata_values(field, item, collected)


def id_map_doc(kind: str, prefix: str, originals: Iterable[str]) -> dict[str, Any]:
    return {
        "schema_version": "stage_reasoning_strict_blind_id_map.v1",
        "kind": kind,
        "items": [
            {"masked": f"{prefix}_m_{idx:06d}", "original": original}
            for idx, original in enumerate(ordered_unique(originals), start=1)
        ],
    }


def metadata_id_map_doc(items: Iterable[tuple[str, str]]) -> dict[str, Any]:
    unique: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for field, original in items:
        if not original or (field, original) in seen:
            continue
        seen.add((field, original))
        unique.append((field, original))
    return {
        "schema_version": "stage_reasoning_strict_blind_metadata_id_map.v1",
        "kind": "metadata",
        "items": [
            {
                "masked": f"{metadata_prefix(field)}_m_{idx:06d}",
                "original": original,
                "field": field,
            }
            for idx, (field, original) in enumerate(unique, start=1)
        ],
    }


def metadata_prefix(field: str) -> str:
    if field.startswith("service_name"):
        return "service_name"
    if field.startswith("source"):
        return "source_file"
    if field.startswith("write_source"):
        return "source_file"
    if field.startswith("context"):
        return "context"
    if field.startswith("write_event"):
        return "event"
    if field.startswith("event"):
        return "event"
    return "metadata"


def lookup(doc: dict[str, Any]) -> dict[str, str]:
    return {item["original"]: item["masked"] for item in doc["items"]}


def metadata_lookup(doc: dict[str, Any]) -> dict[tuple[str, str], str]:
    return {(item["field"], item["original"]): item["masked"] for item in doc["items"]}


class StrictBlindMasker:
    def __init__(
        self,
        scenario_map: dict[str, str],
        sample_map: dict[str, str],
        edge_map: dict[str, str],
        metadata_map: dict[tuple[str, str], str],
    ) -> None:
        self.scenario_map = scenario_map
        self.sample_map = sample_map
        self.edge_map = edge_map
        self.metadata_map = metadata_map

    def metadata_value(self, field: str, value: Any) -> Any:
        if isinstance(value, str):
            return self.metadata_map.get((field, value), value)
        if isinstance(value, dict):
            return {key: self.metadata_value(f"{field}.{key}", item) for key, item in value.items()}
        if isinstance(value, list):
            return [self.metadata_value(field, item) for item in value]
        return value

    def mask(self, value: Any) -> Any:
        if isinstance(value, dict):
            masked: dict[str, Any] = {}
            for key, item in value.items():
                key_s = str(key)
                if key_s in SAMPLE_ID_KEYS and isinstance(item, str):
                    masked[key_s] = self.sample_map.get(item, item)
                elif key_s in SCENARIO_ID_KEYS and isinstance(item, str):
                    masked[key_s] = self.scenario_map.get(item, item)
                elif is_edge_key(key_s) and isinstance(item, str):
                    masked[key_s] = self.edge_map.get(item, item)
                elif key_s in MASKED_FIELD_KEYS:
                    masked[key_s] = self.metadata_value(key_s, item)
                elif key_s in SOURCE_FILE_CONTAINER_KEYS:
                    masked[key_s] = self.metadata_value(key_s, item)
                elif key_s in SERVICE_NAME_KEYS:
                    masked[key_s] = self.metadata_value(key_s, item)
                else:
                    masked[key_s] = self.mask(item)
            return masked
        if isinstance(value, list):
            return [self.mask(item) for item in value]
        return value


def sanitize_model_visible_text(value: Any) -> Any:
    if isinstance(value, str):
        out = value
        for pattern, replacement in VISIBLE_TEXT_REPLACEMENTS:
            out = pattern.sub(replacement, out)
        return out
    if isinstance(value, dict):
        return {key: sanitize_model_visible_text(item) for key, item in value.items()}
    if isinstance(value, list):
        return [sanitize_model_visible_text(item) for item in value]
    return value


MODEL_HIDDEN_KEYS = {
    "label", "gold", "stage", "stage_span", "edge_stage_projection",
    "expected_stage", "target_stage", "answer", "is_high_conf", "high_conf",
    "malicious", "is_malicious", "is_attack_related", "attack_relevance_tier",
    "attack_label_source", "attack_related_level", "attack_related_reason",
    "write_self_malicious", "containing_unit_malicious",
    "attached_backbone_edge_malicious", "prep_rule_used", "result_rule_used",
    "derivation", "compact_view", "stage_inputs", "in_stage", "source_stage",
}


def strip_model_hidden_fields(value: Any) -> Any:
    """Remove supervision/attack-label fields from model-visible input."""
    if isinstance(value, dict):
        return {
            key: strip_model_hidden_fields(item)
            for key, item in value.items()
            if str(key) not in MODEL_HIDDEN_KEYS
        }
    if isinstance(value, list):
        return [strip_model_hidden_fields(item) for item in value]
    return value


def build_maps(rows: list[dict[str, Any]]) -> tuple[dict[str, Any], StrictBlindMasker]:
    collected: dict[str, list[Any]] = {"scenario": [], "sample": [], "edge": [], "metadata": []}
    collect_split_values(rows, collected)
    scenario_doc = id_map_doc("scenario_id", "scenario", collected["scenario"])
    sample_doc = id_map_doc("sample_id", "sample", collected["sample"])
    edge_doc = id_map_doc("edge_id", "edge", collected["edge"])
    metadata_doc = metadata_id_map_doc(collected["metadata"])
    docs = {
        "scenario_id_map.json": scenario_doc,
        "sample_id_map.json": sample_doc,
        "edge_id_map.json": edge_doc,
        "metadata_id_map.json": metadata_doc,
    }
    masker = StrictBlindMasker(
        scenario_map=lookup(scenario_doc),
        sample_map=lookup(sample_doc),
        edge_map=lookup(edge_doc),
        metadata_map=metadata_lookup(metadata_doc),
    )
    return docs, masker


def row_ids(rows: list[dict[str, Any]]) -> list[str]:
    return [str(row.get("sample_id")) for row in rows]


def validate_alignment(model_rows: list[dict[str, Any]], gold_rows: list[dict[str, Any]], index_rows: list[dict[str, Any]]) -> None:
    model_ids = row_ids(model_rows)
    gold_ids = row_ids(gold_rows)
    index_ids = row_ids(index_rows)
    if not (model_ids == gold_ids == index_ids):
        raise SystemExit("model_input/gold/sample_index sample_id alignment failed.")


def forbidden_hits(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    hits: list[dict[str, Any]] = []

    def walk(value: Any, path: tuple[str, ...]) -> None:
        if isinstance(value, str):
            for term, pattern in FORBIDDEN_LEAKAGE_PATTERNS:
                if pattern.search(value):
                    hits.append(
                        {
                            "line_no": line_no,
                            "sample_id": row.get("sample_id"),
                            "path": ".".join(path),
                            "term": term,
                            "text": value[:240],
                        }
                    )
                    break
        elif isinstance(value, dict):
            for key, item in value.items():
                walk(item, path + (str(key),))
        elif isinstance(value, list):
            for idx, item in enumerate(value):
                walk(item, path + (str(idx),))

    for line_no, row in enumerate(rows, start=1):
        walk(row, ())
        if len(hits) >= 200:
            return hits[:200]
    return hits


def count_modalities(rows: list[dict[str, Any]]) -> dict[str, int]:
    counts: Counter[str] = Counter()
    for row in rows:
        for edge in ((row.get("input") or {}).get("spine") or []):
            counts["spine"] += 1
            counts["audit_context"] += len(edge.get("audit_context") or [])
            multi = edge.get("multisource_context") or {}
            counts["applog"] += len(multi.get("applog") or [])
            counts["traffic"] += len(multi.get("traffic") or [])
    return dict(counts)


def count_stages(rows: list[dict[str, Any]]) -> dict[str, int]:
    counts: Counter[str] = Counter()
    for row in rows:
        stage = ((row.get("label") or {}).get("stage")) or ""
        if stage:
            counts[stage] += 1
    return dict(counts)


def split_paths(source: Path, split: str) -> dict[str, Path]:
    # ``data`` is the sole public 216-unit layout.  The split argument is kept
    # for API compatibility.
    base = source / "data"
    return {
        "model_input": base / "model_input.jsonl",
        "gold": base / "gold.jsonl",
        "sample_index": base / "sample_index.jsonl",
    }


def export_split(
    source: Path,
    output: Path,
    split: str,
    expected_count: int | None = None,
    *,
    output_name: str | None = None,
) -> dict[str, Any]:
    paths = split_paths(source, split)
    model_rows = read_jsonl(paths["model_input"])
    gold_rows = read_jsonl(paths["gold"])
    sample_index_rows = read_jsonl(paths["sample_index"])
    expected_count = len(model_rows) if expected_count is None else expected_count
    if len(model_rows) != expected_count:
        raise SystemExit(f"{split} model_input count mismatch: {len(model_rows)} != {expected_count}")
    if len(gold_rows) != expected_count or len(sample_index_rows) != expected_count:
        raise SystemExit(f"{split} gold/sample_index count mismatch.")
    validate_alignment(model_rows, gold_rows, sample_index_rows)

    all_rows = model_rows + gold_rows + sample_index_rows
    map_docs, masker = build_maps(all_rows)
    masked_model_rows = [
        strip_model_hidden_fields(sanitize_model_visible_text(masker.mask(row)))
        for row in model_rows
    ]
    masked_gold_rows = [masker.mask(row) for row in gold_rows]
    masked_sample_index_rows = [masker.mask(row) for row in sample_index_rows]
    validate_alignment(masked_model_rows, masked_gold_rows, masked_sample_index_rows)

    hits = forbidden_hits(masked_model_rows)
    destination = output_name or "data"
    if hits:
        write_json(output / destination / "strict_blind_leakage_failures.json", hits)
        raise SystemExit(f"{split} strict blind leakage check failed; see strict_blind_leakage_failures.json")
    write_json(output / destination / "strict_blind_leakage_failures.json", [])

    split_dir = output / destination
    write_jsonl(split_dir / "model_input.jsonl", masked_model_rows)
    write_jsonl(split_dir / "gold.jsonl", masked_gold_rows)
    write_jsonl(split_dir / "sample_index.jsonl", masked_sample_index_rows)
    for name, doc in map_docs.items():
        write_json(split_dir / "id_maps" / name, doc)

    return {
        "sample_count": len(masked_model_rows),
        "stage_counts": count_stages(gold_rows),
        "source_paths": {key: str(path) for key, path in paths.items()},
        "output_paths": {
            "model_input": str(split_dir / "model_input.jsonl"),
            "gold": str(split_dir / "gold.jsonl"),
            "sample_index": str(split_dir / "sample_index.jsonl"),
            "id_maps": str(split_dir / "id_maps"),
        },
        "id_map_counts": {name: len(doc["items"]) for name, doc in map_docs.items()},
        "raw_modality_counts": count_modalities(model_rows),
        "strict_blind_modality_counts": count_modalities(masked_model_rows),
        "sample_alignment_ok": True,
        "leakage_check": {
            "clean": True,
            "forbidden_terms": FORBIDDEN_LEAKAGE_TERMS,
        },
    }


def write_readme(output: Path, source: Path, source_stage_derivation: str | None) -> None:
    source_stage_note = ""
    if source_stage_derivation:
        source_stage_note = f"\nCurrent canonical stage derivation: `{source_stage_derivation}`.\n"
    readme = f"""# Stage Reasoning Strict Blind Benchmark

This benchmark is derived from the canonical source:

`{source}/`
{source_stage_note}

It rewrites model-visible metadata that can reveal scenario identity while
preserving the single public dataset unit. Use `data/model_input.jsonl` for
model evaluation and the aligned `data/gold.jsonl` for scoring.

The canonical `stage_reasoning` benchmark remains the source of truth and was not modified by the exporter.

## Difference From Canonical

- Top-level `sample_id` and `scenario_id` are masked.
- All `edge_id` and `*_edge_id` values are masked.
- `source_file`, `write_source_file`, `context_id`, `event_key`, `write_event_key`, `source_files`, and `service_name` values are masked.
- Primary evidence fields are preserved: subject, object, relation, message, process/file/network facts, HTTP path, service response, timestamp, and seq.
- Exact scenario-bearing tokens listed in the leakage policy are pseudonymized even inside primary evidence paths/messages when needed for strict blind safety.
- `gold_reasoning_chain` uses the EWVAA-style four-step claim-based schema: `scenario_or_evidence_understanding`, `observable_evidence`, `attack_stage_path_reasoning`, `final_judgement`.
- The four-step reasoning schema is used for reference chains.
- `label.stage` remains the scoring label from the canonical benchmark and is not regenerated by EWVAA or candidate reasoning.

## Evaluation Use

- Model-visible input: `data/model_input.jsonl`
- Scoring labels: `data/gold.jsonl`
- Trace/debug index: `data/sample_index.jsonl`
- Identifier restoration metadata: `data/id_maps/`

Do not include `id_maps/` in model prompts or scoring-side model input.
"""
    (output / "README.md").write_text(readme, encoding="utf-8")


def write_unified_readme(output: Path, source: Path, source_stage_derivation: str | None) -> None:
    source_stage_note = (
        f"\nSource stage derivation: `{source_stage_derivation}`.\n"
        if source_stage_derivation else ""
    )
    readme = f"""# SecLog-Bench-216 strict-blind benchmark

This directory is one unified public 216-sample unit.  It contains no
construction split; all rows are joined by `sample_id` in the same order.
{source_stage_note}
## Files

- `data/model_input.jsonl`: model-visible strict-blind evidence.
- `data/gold.jsonl`: scoring labels and reference fields.
- `data/sample_index.jsonl`: aligned traceability metadata.
- `data/id_maps/`: identifier restoration metadata used by the evaluation
  pipeline; keep it separate from model-visible input.

Scenario, sample, edge, source, and service identifiers are masked in the
model-visible input.  Primary behavioral evidence is retained.  The canonical
source is not modified by this exporter.
"""
    (output / "README.md").write_text(readme, encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Export strict blind stage_reasoning benchmark.")
    parser.add_argument("--source-benchmark", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    source = args.source_benchmark
    output = args.output_dir
    if not source.exists():
        raise SystemExit(f"Source benchmark does not exist: {source}")
    if output.exists() and any(output.iterdir()):
        raise SystemExit(f"Refusing non-empty output directory: {output}")
    output.mkdir(parents=True, exist_ok=True)
    source_manifest_path = source / "manifest.json"
    source_manifest = read_json(source_manifest_path) if source_manifest_path.exists() else {}
    source_stage_derivation = source_manifest.get("source_stage_derivation")

    before_hashes = canonical_hashes(source)
    unified_source_manifest = source_manifest.get("dataset") or {}
    unified_source = (source / "data" / "model_input.jsonl").is_file()
    if unified_source:
        expected_count = int(unified_source_manifest.get("sample_count") or 0) or None
        report = export_split(source, output, "216", expected_count, output_name="data")
        after_hashes = canonical_hashes(source)
        canonical_unchanged = before_hashes == after_hashes
        if not canonical_unchanged:
            raise SystemExit("Canonical benchmark hash check failed after export.")
        manifest = {
            "schema_version": "stage_reasoning_strict_blind_manifest.v2",
            "source_benchmark": str(source),
            "output_benchmark": str(output),
            "source_stage_derivation": source_stage_derivation,
            "dataset": report,
            "sample_count": report["sample_count"],
            "masked_fields": [
                "top-level sample_id", "top-level scenario_id", "all edge_id",
                "source_file", "write_source_file", "context_id", "event_key",
                "write_event_key", "scenario-bearing service_name",
            ],
            "validation": {
                "line_counts_ok": report["sample_count"] == (expected_count or report["sample_count"]),
                "sample_alignment_ok": report["sample_alignment_ok"],
                "leakage_check_ok": report["leakage_check"]["clean"],
                "canonical_hash_check_ok": canonical_unchanged,
                "forbidden_model_input_terms": FORBIDDEN_LEAKAGE_TERMS,
            },
            "canonical_benchmark_was_not_modified": canonical_unchanged,
            "canonical_sha256_before": before_hashes,
            "canonical_sha256_after": after_hashes,
        }
        write_json(output / "manifest.json", manifest)
        write_unified_readme(output, source, source_stage_derivation)
        print(json.dumps({
            "output_dir": str(output),
            "sample_count": report["sample_count"],
            "leakage_check_ok": report["leakage_check"]["clean"],
            "canonical_benchmark_was_not_modified": canonical_unchanged,
        }, ensure_ascii=False))
        return 0

    report = export_split(source, output, "216", None, output_name="data")
    after_hashes = canonical_hashes(source)
    canonical_unchanged = before_hashes == after_hashes
    if not canonical_unchanged:
        raise SystemExit("Canonical benchmark hash check failed after export.")

    manifest = {
        "schema_version": "stage_reasoning_strict_blind_manifest.v2",
        "source_benchmark": str(source),
        "output_benchmark": str(output),
        "source_stage_derivation": source_stage_derivation,
        "source_benchmark_schema": source_manifest.get("source_benchmark_schema"),
        "strict_blind_policy": {
            "purpose": "Prevent scenario and identifier leakage in model-visible stage_reasoning evaluation inputs.",
            "model_visible_file": "data/model_input.jsonl",
            "developer_only_trace_files": ["data/id_maps/*.json"],
            "gold_and_sample_index": "Masked sample/scenario/edge ids are aligned with model_input for scoring and traceability.",
            "primary_evidence_policy": PRIMARY_EVIDENCE_POLICY_NOTE,
            "reasoning_schema_version": REASONING_SCHEMA_VERSION,
            "reasoning_protocol": REASONING_PROTOCOL,
            "formal_task_mode": "stage_prediction",
        },
        "dataset": report,
        "sample_count": report["sample_count"],
        "masked_fields": [
            "top-level sample_id",
            "top-level scenario_id",
            "all edge_id",
            "all *_edge_id",
            "attach_to_backbone_edge_id",
            "source_file",
            "write_source_file",
            "context_id",
            "event_key",
            "write_event_key",
            "scenario-bearing service_name",
        ],
        "preserved_primary_evidence": PRIMARY_EVIDENCE_PRESERVED,
        "preserved_primary_evidence_note": PRIMARY_EVIDENCE_POLICY_NOTE,
        "validation": {
            "line_counts_ok": report["sample_count"] == 216,
            "sample_alignment_ok": report["sample_alignment_ok"],
            "leakage_check_ok": report["leakage_check"]["clean"],
            "canonical_hash_check_ok": canonical_unchanged,
            "forbidden_model_input_terms": FORBIDDEN_LEAKAGE_TERMS,
        },
        "canonical_benchmark_was_not_modified": canonical_unchanged,
        "canonical_sha256_before": before_hashes,
        "canonical_sha256_after": after_hashes,
    }
    write_json(output / "manifest.json", manifest)
    write_readme(output, source, source_stage_derivation)

    print(
        json.dumps(
            {
                "output_dir": str(output),
                "sample_count": manifest["sample_count"],
                "leakage_check_ok": manifest["validation"]["leakage_check_ok"],
                "canonical_benchmark_was_not_modified": canonical_unchanged,
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
