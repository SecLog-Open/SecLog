#!/usr/bin/env python3
"""Check EWVAA run outputs for non-English generated natural-language fields.

This is a post-run validator only. It does not call the EWVAA API and does not
run any multi-agent stage. The check intentionally focuses on model-generated
natural-language fields and avoids treating raw evidence ids, paths, CVE ids,
and quoted raw snippets as language violations.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Iterable


OUTPUT_FILES = (
    ("reasoning_patches.unmasked.annotator.jsonl", "annotator_patches"),
    ("reasoning_patches.masked.annotator.jsonl", "annotator_patches_masked"),
    ("reviewer_judge_outputs.jsonl", "reviewer_judgements"),
    ("reviewer_revision_patches.unmasked.jsonl", "reviewer_revision_patches"),
    ("merged_reasoning_patches.unmasked.jsonl", "merged_reasoning_patches"),
    ("final_candidate_gold.jsonl", "final_candidate_gold"),
    ("final_candidate_gold.manual_reviewed.jsonl", "final_candidate_gold_manual_reviewed"),
)

REVIEWER_TEXT_KEYS = {
    "comment",
    "comments",
    "explanation",
    "judgement",
    "judgment",
    "manual_review_reason",
    "manual_review_reasons",
    "rationale",
    "revision_reason",
    "revision_reasons",
}

FINAL_JUDGEMENT_KEYS = {"final_judgement", "final_judgment"}

NON_ENGLISH_SCRIPT_RE = re.compile(
    "["
    "\u3040-\u30ff"  # Japanese hiragana/katakana
    "\u3400-\u4dbf"
    "\u4e00-\u9fff"
    "\uf900-\ufaff"
    "\uac00-\ud7af"  # Korean hangul
    "\u0400-\u04ff"  # Cyrillic
    "\u0600-\u06ff"  # Arabic
    "\u0900-\u097f"  # Devanagari
    "]"
)

QUOTED_SNIPPET_RE = re.compile(r'"[^"\n]{0,2000}"|\'[^\'\n]{0,2000}\'|`[^`\n]{0,2000}`')
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}(?:-[A-Za-z0-9_.-]+)?\b", re.IGNORECASE)
URL_RE = re.compile(r"https?://\S+")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b")
PATH_RE = re.compile(r"(?:/[A-Za-z0-9._@%+=:,~-]+)+|[A-Za-z]:\\[^\s]+")
EDGE_RE = re.compile(r"\b(?:edge_m_\d{6}|[A-Za-z0-9_.:-]+::[A-Za-z0-9_.:-]+::\d+)\b")
PROC_CONN_RE = re.compile(r"\b(?:proc|conn|file|fd|metadata_ref|source_file)_?[A-Za-z0-9_.:/@%-]*\b")


def read_jsonl(path: Path) -> list[tuple[int, dict[str, Any]]]:
    rows: list[tuple[int, dict[str, Any]]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, 1):
            line = line.strip()
            if not line:
                continue
            rows.append((line_no, json.loads(line)))
    return rows


def iter_strings(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, list):
        for item in value:
            yield from iter_strings(item)
    elif isinstance(value, dict):
        for item in value.values():
            yield from iter_strings(item)


def generated_text_fields(row: dict[str, Any]) -> Iterable[tuple[str, str]]:
    chain = row.get("gold_reasoning_chain")
    if isinstance(chain, list):
        for idx, item in enumerate(chain):
            if not isinstance(item, dict):
                continue
            claim = item.get("claim")
            if isinstance(claim, str):
                step = str(item.get("step") or idx)
                yield f"gold_reasoning_chain[{idx}].claim({step})", claim

    note = row.get("auxiliary_vulnerability_note")
    if isinstance(note, str):
        yield "auxiliary_vulnerability_note", note
    elif isinstance(note, dict):
        for key in ("claim", "comment", "explanation", "note", "reason"):
            value = note.get(key)
            if isinstance(value, str):
                yield f"auxiliary_vulnerability_note.{key}", value

    for key in FINAL_JUDGEMENT_KEYS:
        value = row.get(key)
        if isinstance(value, str):
            yield key, value
        elif isinstance(value, dict):
            for sub_key in ("claim", "explanation", "comment", "reason"):
                sub_value = value.get(sub_key)
                if isinstance(sub_value, str):
                    yield f"{key}.{sub_key}", sub_value

    for key in REVIEWER_TEXT_KEYS:
        if key not in row:
            continue
        for text in iter_strings(row.get(key)):
            yield key, text


def strip_allowed_raw_fragments(text: str) -> str:
    stripped = QUOTED_SNIPPET_RE.sub(" ", text)
    for regex in (CVE_RE, URL_RE, IP_RE, PATH_RE, EDGE_RE, PROC_CONN_RE):
        stripped = regex.sub(" ", stripped)
    return stripped


def is_non_english_generated_text(text: str) -> bool:
    return bool(NON_ENGLISH_SCRIPT_RE.search(strip_allowed_raw_fragments(text)))


def check_run_dir(run_dir: Path, max_examples: int) -> dict[str, Any]:
    checked_files: list[dict[str, Any]] = []
    violations: list[dict[str, Any]] = []
    sample_ids: set[str] = set()
    violation_count = 0

    for filename, kind in OUTPUT_FILES:
        path = run_dir / filename
        file_report = {"path": str(path), "kind": kind, "exists": path.exists(), "rows": 0}
        if not path.exists():
            checked_files.append(file_report)
            continue
        rows = read_jsonl(path)
        file_report["rows"] = len(rows)
        checked_files.append(file_report)
        for line_no, row in rows:
            sample_id = str(row.get("sample_id") or row.get("masked_sample_id") or "")
            for field_path, text in generated_text_fields(row):
                if not is_non_english_generated_text(text):
                    continue
                violation_count += 1
                sample_ids.add(sample_id)
                if len(violations) < max_examples:
                    violations.append(
                        {
                            "file": str(path),
                            "kind": kind,
                            "line": line_no,
                            "sample_id": sample_id,
                            "field": field_path,
                            "snippet": text[:300],
                        }
                    )

    return {
        "run_dir": str(run_dir),
        "checked_files": checked_files,
        "non_english_generated_text_count": violation_count,
        "sample_ids": sorted(sample_ids),
        "violations": violations,
        "notes": [
            "Only model-generated natural-language fields are checked.",
            "Quoted raw snippets, CVE ids, evidence_refs, file paths, process names, network addresses, and edge ids are ignored before script detection.",
            "This lightweight check is strongest for Chinese/Japanese/Korean and other non-Latin scripts; Latin-script non-English prose may require manual review.",
        ],
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Check EWVAA generated output language in an existing run_dir.")
    parser.add_argument("run_dir", type=Path, help="Existing EWVAA multi-agent run directory to inspect.")
    parser.add_argument("--json-out", type=Path, help="Optional path for writing the JSON report.")
    parser.add_argument("--max-examples", type=int, default=200, help="Maximum violation examples to retain.")
    parser.add_argument("--fail-on-non-english", action="store_true", help="Exit with code 1 when violations are found.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not args.run_dir.exists() or not args.run_dir.is_dir():
        raise SystemExit(f"run_dir does not exist or is not a directory: {args.run_dir}")
    report = check_run_dir(args.run_dir, max(1, args.max_examples))
    text = json.dumps(report, ensure_ascii=False, indent=2)
    if args.json_out:
        args.json_out.write_text(text + "\n", encoding="utf-8")
    print(text)
    has_violations = bool(report["sample_ids"])
    return 1 if args.fail_on_non_english and has_violations else 0


if __name__ == "__main__":
    sys.exit(main())
