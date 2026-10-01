#!/usr/bin/env python3
"""Pipeline entrypoint for extracting audit triples from raw sysdig logs.

This wrapper keeps the existing algorithm unchanged and delegates to the
implementation in ``results_analysis/extract_audit_triples_v1_1.py``.
It only standardizes the location, default scenario handling, and CLI usage.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Optional


SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from utils.common import rules_file_path, scenario_chain_dir, scenario_raw_sysdig_dir
from utils.legacy_loader import load_legacy_module


SCENARIO_DIR = SCRIPT_DIR.parents[1] / "results" / "vulhub" / "gitlist" / "CVE-2018-1000533" / "2026-03-21_09-47-27"

RAW_SYSDIG_DIR = scenario_raw_sysdig_dir(SCENARIO_DIR)
CHAIN_DIR = scenario_chain_dir(SCENARIO_DIR)
DEFAULT_OUTPUT_JSONL = CHAIN_DIR / "audit_triples.core.v1.jsonl"
DEFAULT_AUXILIARY_OUTPUT_JSONL = CHAIN_DIR / "audit_triples.auxiliary.v1.jsonl"
DEFAULT_FILTERED_OUTPUT_JSONL = CHAIN_DIR / "audit_triples.filtered.v1.jsonl"
DEFAULT_UNKNOWN_OUTPUT_JSONL = CHAIN_DIR / "audit_triples.unknown.v1.jsonl"
DEFAULT_TIER_MANIFEST_JSON = CHAIN_DIR / "audit_triples_tier_manifest.v1.json"
DEFAULT_RELATION_STATS = CHAIN_DIR / "relation_stats.csv"
DEFAULT_SUMMARY_MD = CHAIN_DIR / "audit_triples_summary.md"
RULES_FILE = rules_file_path()


def _legacy():
    return load_legacy_module(
        __file__,
        "extract_audit_triples_v1_1.py",
        "legacy_extract_audit_triples_v1_1",
    )


def run_for_scenario(
    scenario_dir: Path,
    raw_sysdig_dir: Optional[Path] = None,
    output_jsonl: Optional[Path] = None,
    auxiliary_output_jsonl: Optional[Path] = None,
    filtered_output_jsonl: Optional[Path] = None,
    unknown_output_jsonl: Optional[Path] = None,
    tier_manifest_path: Optional[Path] = None,
    relation_stats_path: Optional[Path] = None,
    summary_md_path: Optional[Path] = None,
    rules_file: Path = RULES_FILE,
) -> int:
    raw_sysdig_dir = raw_sysdig_dir or scenario_raw_sysdig_dir(scenario_dir)
    chain_dir = scenario_chain_dir(scenario_dir)
    output_jsonl = output_jsonl or (chain_dir / "audit_triples.core.v1.jsonl")
    auxiliary_output_jsonl = auxiliary_output_jsonl or (chain_dir / "audit_triples.auxiliary.v1.jsonl")
    filtered_output_jsonl = filtered_output_jsonl or (chain_dir / "audit_triples.filtered.v1.jsonl")
    unknown_output_jsonl = unknown_output_jsonl or (chain_dir / "audit_triples.unknown.v1.jsonl")
    tier_manifest_path = tier_manifest_path or (chain_dir / "audit_triples_tier_manifest.v1.json")
    relation_stats_path = relation_stats_path or (chain_dir / "relation_stats.csv")
    summary_md_path = summary_md_path or (chain_dir / "audit_triples_summary.md")

    legacy = _legacy()
    return legacy.run(
        raw_sysdig_dir=raw_sysdig_dir,
        output_jsonl=output_jsonl,
        auxiliary_output_jsonl=auxiliary_output_jsonl,
        filtered_output_jsonl=filtered_output_jsonl,
        unknown_output_jsonl=unknown_output_jsonl,
        tier_manifest_path=tier_manifest_path,
        relation_stats_path=relation_stats_path,
        summary_md_path=summary_md_path,
        rules_file=rules_file,
    )


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Extract single-scenario audit triples v1",
    )
    parser.add_argument("--scenario-dir", type=Path, default=SCENARIO_DIR)
    parser.add_argument("--raw-sysdig-dir", type=Path, default=RAW_SYSDIG_DIR)
    parser.add_argument("--output-jsonl", type=Path, default=DEFAULT_OUTPUT_JSONL)
    parser.add_argument(
        "--auxiliary-output-jsonl",
        type=Path,
        default=DEFAULT_AUXILIARY_OUTPUT_JSONL,
    )
    parser.add_argument(
        "--filtered-output-jsonl",
        type=Path,
        default=DEFAULT_FILTERED_OUTPUT_JSONL,
    )
    parser.add_argument(
        "--unknown-output-jsonl",
        type=Path,
        default=DEFAULT_UNKNOWN_OUTPUT_JSONL,
    )
    parser.add_argument(
        "--tier-manifest-path",
        type=Path,
        default=DEFAULT_TIER_MANIFEST_JSON,
    )
    parser.add_argument(
        "--relation-stats-path",
        type=Path,
        default=DEFAULT_RELATION_STATS,
    )
    parser.add_argument(
        "--summary-md-path",
        type=Path,
        default=DEFAULT_SUMMARY_MD,
    )
    parser.add_argument("--rules-file", type=Path, default=RULES_FILE)
    return parser.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)
    scenario_dir = args.scenario_dir
    raw_sysdig_dir = args.raw_sysdig_dir
    output_jsonl = args.output_jsonl
    auxiliary_output_jsonl = args.auxiliary_output_jsonl
    filtered_output_jsonl = args.filtered_output_jsonl
    unknown_output_jsonl = args.unknown_output_jsonl
    tier_manifest_path = args.tier_manifest_path
    relation_stats_path = args.relation_stats_path
    summary_md_path = args.summary_md_path

    if scenario_dir != SCENARIO_DIR:
        derived_raw_sysdig_dir = scenario_raw_sysdig_dir(scenario_dir)
        derived_chain_dir = scenario_chain_dir(scenario_dir)

        if raw_sysdig_dir == RAW_SYSDIG_DIR:
            raw_sysdig_dir = derived_raw_sysdig_dir
        if output_jsonl == DEFAULT_OUTPUT_JSONL:
            output_jsonl = derived_chain_dir / "audit_triples.core.v1.jsonl"
        if auxiliary_output_jsonl == DEFAULT_AUXILIARY_OUTPUT_JSONL:
            auxiliary_output_jsonl = derived_chain_dir / "audit_triples.auxiliary.v1.jsonl"
        if filtered_output_jsonl == DEFAULT_FILTERED_OUTPUT_JSONL:
            filtered_output_jsonl = derived_chain_dir / "audit_triples.filtered.v1.jsonl"
        if unknown_output_jsonl == DEFAULT_UNKNOWN_OUTPUT_JSONL:
            unknown_output_jsonl = derived_chain_dir / "audit_triples.unknown.v1.jsonl"
        if tier_manifest_path == DEFAULT_TIER_MANIFEST_JSON:
            tier_manifest_path = derived_chain_dir / "audit_triples_tier_manifest.v1.json"
        if relation_stats_path == DEFAULT_RELATION_STATS:
            relation_stats_path = derived_chain_dir / "relation_stats.csv"
        if summary_md_path == DEFAULT_SUMMARY_MD:
            summary_md_path = derived_chain_dir / "audit_triples_summary.md"

    return run_for_scenario(
        scenario_dir=scenario_dir,
        raw_sysdig_dir=raw_sysdig_dir,
        output_jsonl=output_jsonl,
        auxiliary_output_jsonl=auxiliary_output_jsonl,
        filtered_output_jsonl=filtered_output_jsonl,
        unknown_output_jsonl=unknown_output_jsonl,
        tier_manifest_path=tier_manifest_path,
        relation_stats_path=relation_stats_path,
        summary_md_path=summary_md_path,
        rules_file=args.rules_file,
    )


if __name__ == "__main__":
    raise SystemExit(main())
