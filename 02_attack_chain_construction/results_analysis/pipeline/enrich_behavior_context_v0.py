#!/usr/bin/env python3
"""Pipeline entrypoint for malicious non-core context enrichment."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Optional


SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from utils.common import scenario_chain_dir, scenario_index_dir
from utils.legacy_loader import load_legacy_module


SCENARIO_DIR = SCRIPT_DIR.parents[1] / "results" / "vulhub" / "gitlist" / "CVE-2018-1000533" / "2026-03-21_09-47-27"

CHAIN_DIR = scenario_chain_dir(SCENARIO_DIR)
INDEX_DIR = scenario_index_dir(SCENARIO_DIR)
DEFAULT_BACKBONE = CHAIN_DIR / "backbone_chain.v1.json"
DEFAULT_AUXILIARY = CHAIN_DIR / "audit_triples.auxiliary.v1.jsonl"
DEFAULT_FILTERED = CHAIN_DIR / "audit_triples.filtered.v1.jsonl"
DEFAULT_UNKNOWN = CHAIN_DIR / "audit_triples.unknown.v1.jsonl"
DEFAULT_TIER_MANIFEST = CHAIN_DIR / "audit_triples_tier_manifest.v1.json"
DEFAULT_UNIT_EVENT_INDEX = INDEX_DIR / "unit_event_index.jsonl"
DEFAULT_UNIT_INDEX = INDEX_DIR / "unit_index.jsonl"
DEFAULT_OUTPUT = CHAIN_DIR / "behavior_context_edges.v0.jsonl"
DEFAULT_UNMATCHED_OUTPUT = CHAIN_DIR / "behavior_context_unmatched.v0.jsonl"
DEFAULT_UNMATCHED_REASON_TRACE_OUTPUT = CHAIN_DIR / "unmatched_reason_trace.v0.jsonl"
DEFAULT_SUMMARY_OUTPUT = CHAIN_DIR / "behavior_context_summary.v0.json"
DEFAULT_CANDIDATE_OUTPUT = CHAIN_DIR / "noncore_attach_candidate_index.v0.jsonl"
DEFAULT_ANCHOR_OUTPUT = INDEX_DIR / "event_to_backbone_anchor_index.v0.jsonl"


def _legacy():
    return load_legacy_module(
        __file__,
        "enrich_behavior_context_v0.py",
        "legacy_enrich_behavior_context_v0",
    )


def run_for_scenario(
    scenario_dir: Path,
    backbone_path: Optional[Path] = None,
    auxiliary_path: Optional[Path] = None,
    filtered_path: Optional[Path] = None,
    unknown_path: Optional[Path] = None,
    tier_manifest_path: Optional[Path] = None,
    unit_event_path: Optional[Path] = None,
    unit_index_path: Optional[Path] = None,
    output_path: Optional[Path] = None,
    unmatched_output_path: Optional[Path] = None,
    unmatched_reason_trace_output_path: Optional[Path] = None,
    summary_output_path: Optional[Path] = None,
    candidate_output_path: Optional[Path] = None,
    anchor_output_path: Optional[Path] = None,
    skip_enrich: bool = False,
    backbone_guard_threshold: int = 5000,
) -> int:
    chain_dir = scenario_chain_dir(scenario_dir)
    index_dir = scenario_index_dir(scenario_dir)
    backbone_path = backbone_path or (chain_dir / "backbone_chain.v1.json")
    auxiliary_path = auxiliary_path or (chain_dir / "audit_triples.auxiliary.v1.jsonl")
    filtered_path = filtered_path or (chain_dir / "audit_triples.filtered.v1.jsonl")
    unknown_path = unknown_path or (chain_dir / "audit_triples.unknown.v1.jsonl")
    tier_manifest_path = tier_manifest_path or (chain_dir / "audit_triples_tier_manifest.v1.json")
    unit_event_path = unit_event_path or (index_dir / "unit_event_index.jsonl")
    unit_index_path = unit_index_path or (index_dir / "unit_index.jsonl")
    output_path = output_path or (chain_dir / "behavior_context_edges.v0.jsonl")
    unmatched_output_path = unmatched_output_path or (chain_dir / "behavior_context_unmatched.v0.jsonl")
    unmatched_reason_trace_output_path = unmatched_reason_trace_output_path or (chain_dir / "unmatched_reason_trace.v0.jsonl")
    summary_output_path = summary_output_path or (chain_dir / "behavior_context_summary.v0.json")
    candidate_output_path = candidate_output_path or (chain_dir / "noncore_attach_candidate_index.v0.jsonl")
    anchor_output_path = anchor_output_path or (index_dir / "event_to_backbone_anchor_index.v0.jsonl")

    legacy = _legacy()
    return legacy.run(
        scenario_dir=scenario_dir,
        backbone_path=backbone_path,
        auxiliary_path=auxiliary_path,
        filtered_path=filtered_path,
        unknown_path=unknown_path,
        tier_manifest_path=tier_manifest_path,
        unit_event_path=unit_event_path,
        unit_index_path=unit_index_path,
        output_path=output_path,
        unmatched_output_path=unmatched_output_path,
        unmatched_reason_trace_output_path=unmatched_reason_trace_output_path,
        summary_output_path=summary_output_path,
        candidate_output_path=candidate_output_path,
        anchor_output_path=anchor_output_path,
        skip_enrich=skip_enrich,
        backbone_guard_threshold=backbone_guard_threshold,
    )


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Enrich backbone with malicious non-core context v0")
    parser.add_argument("--scenario-dir", type=Path, default=SCENARIO_DIR)
    parser.add_argument("--backbone", type=Path, default=DEFAULT_BACKBONE)
    parser.add_argument("--auxiliary", type=Path, default=DEFAULT_AUXILIARY)
    parser.add_argument("--filtered", type=Path, default=DEFAULT_FILTERED)
    parser.add_argument("--unknown", type=Path, default=DEFAULT_UNKNOWN)
    parser.add_argument("--tier-manifest", type=Path, default=DEFAULT_TIER_MANIFEST)
    parser.add_argument("--unit-event-index", type=Path, default=DEFAULT_UNIT_EVENT_INDEX)
    parser.add_argument("--unit-index", type=Path, default=DEFAULT_UNIT_INDEX)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--unmatched-output", type=Path, default=DEFAULT_UNMATCHED_OUTPUT)
    parser.add_argument("--unmatched-reason-trace-output", type=Path, default=DEFAULT_UNMATCHED_REASON_TRACE_OUTPUT)
    parser.add_argument("--summary-output", type=Path, default=DEFAULT_SUMMARY_OUTPUT)
    parser.add_argument("--candidate-output", type=Path, default=DEFAULT_CANDIDATE_OUTPUT)
    parser.add_argument("--anchor-output", type=Path, default=DEFAULT_ANCHOR_OUTPUT)
    parser.add_argument("--skip-enrich", action="store_true",
                        help="Skip the entire enrich step (mark run as incomplete; not formal success)")
    parser.add_argument("--backbone-guard-threshold", type=int, default=5000,
                        help="Auto-skip enrich when backbone exceeds this edge count (0=disable)")
    return parser.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)
    scenario_dir = args.scenario_dir
    backbone = args.backbone
    auxiliary = args.auxiliary
    filtered = args.filtered
    unknown = args.unknown
    tier_manifest = args.tier_manifest
    unit_event_index = args.unit_event_index
    unit_index = args.unit_index
    output = args.output
    unmatched_output = args.unmatched_output
    unmatched_reason_trace_output = args.unmatched_reason_trace_output
    summary_output = args.summary_output
    candidate_output = args.candidate_output
    anchor_output = args.anchor_output

    if scenario_dir != SCENARIO_DIR:
        derived_chain_dir = scenario_chain_dir(scenario_dir)
        derived_index_dir = scenario_index_dir(scenario_dir)
        if backbone == DEFAULT_BACKBONE:
            backbone = derived_chain_dir / "backbone_chain.v1.json"
        if auxiliary == DEFAULT_AUXILIARY:
            auxiliary = derived_chain_dir / "audit_triples.auxiliary.v1.jsonl"
        if filtered == DEFAULT_FILTERED:
            filtered = derived_chain_dir / "audit_triples.filtered.v1.jsonl"
        if unknown == DEFAULT_UNKNOWN:
            unknown = derived_chain_dir / "audit_triples.unknown.v1.jsonl"
        if tier_manifest == DEFAULT_TIER_MANIFEST:
            tier_manifest = derived_chain_dir / "audit_triples_tier_manifest.v1.json"
        if unit_event_index == DEFAULT_UNIT_EVENT_INDEX:
            unit_event_index = derived_index_dir / "unit_event_index.jsonl"
        if unit_index == DEFAULT_UNIT_INDEX:
            unit_index = derived_index_dir / "unit_index.jsonl"
        if output == DEFAULT_OUTPUT:
            output = derived_chain_dir / "behavior_context_edges.v0.jsonl"
        if unmatched_output == DEFAULT_UNMATCHED_OUTPUT:
            unmatched_output = derived_chain_dir / "behavior_context_unmatched.v0.jsonl"
        if unmatched_reason_trace_output == DEFAULT_UNMATCHED_REASON_TRACE_OUTPUT:
            unmatched_reason_trace_output = derived_chain_dir / "unmatched_reason_trace.v0.jsonl"
        if summary_output == DEFAULT_SUMMARY_OUTPUT:
            summary_output = derived_chain_dir / "behavior_context_summary.v0.json"
        if candidate_output == DEFAULT_CANDIDATE_OUTPUT:
            candidate_output = derived_chain_dir / "noncore_attach_candidate_index.v0.jsonl"
        if anchor_output == DEFAULT_ANCHOR_OUTPUT:
            anchor_output = derived_index_dir / "event_to_backbone_anchor_index.v0.jsonl"

    return run_for_scenario(
        scenario_dir=scenario_dir,
        backbone_path=backbone,
        auxiliary_path=auxiliary,
        filtered_path=filtered,
        unknown_path=unknown,
        tier_manifest_path=tier_manifest,
        unit_event_path=unit_event_index,
        unit_index_path=unit_index,
        output_path=output,
        unmatched_output_path=unmatched_output,
        unmatched_reason_trace_output_path=unmatched_reason_trace_output,
        summary_output_path=summary_output,
        candidate_output_path=candidate_output,
        anchor_output_path=anchor_output,
        skip_enrich=args.skip_enrich,
        backbone_guard_threshold=args.backbone_guard_threshold,
    )


if __name__ == "__main__":
    raise SystemExit(main())
