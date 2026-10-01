#!/usr/bin/env python3
"""Pipeline entrypoint for building the behavior chain dataset sample."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Optional


SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from utils.common import scenario_chain_dir
from utils.legacy_loader import load_legacy_module


SCENARIO_DIR = SCRIPT_DIR.parents[1] / "results" / "vulhub" / "gitlist" / "CVE-2018-1000533" / "2026-03-21_09-47-27"

CHAIN_DIR = scenario_chain_dir(SCENARIO_DIR)
DEFAULT_BACKBONE = CHAIN_DIR / "backbone_chain.v1.json"
DEFAULT_CONTEXT_EDGES = CHAIN_DIR / "behavior_context_edges.v0.jsonl"
DEFAULT_OUTPUT = CHAIN_DIR / "behavior_chain_dataset.v2.json"
DEFAULT_META_OUTPUT = CHAIN_DIR / "behavior_chain_dataset.v2.meta.json"
DEFAULT_BACKBONE_WARNING_OUTPUT = CHAIN_DIR / "backbone_broad_warning.v0.json"
DEFAULT_NECESSARY_WINDOW = 5


def _legacy():
    return load_legacy_module(
        __file__,
        "build_behavior_chain_instances_v0.py",
        "legacy_build_behavior_chain_instances_v0",
    )


def run_for_scenario(
    scenario_dir: Path,
    backbone_path: Optional[Path] = None,
    context_edges_path: Optional[Path] = None,
    output_path: Optional[Path] = None,
    meta_output_path: Optional[Path] = None,
    backbone_warning_output_path: Optional[Path] = None,
    auxiliary_path: Optional[Path] = None,
    filtered_path: Optional[Path] = None,
    unknown_path: Optional[Path] = None,
    necessary_window: int = DEFAULT_NECESSARY_WINDOW,
    stage_residual_path: Optional[Path] = None,
    refinement_residual_path: Optional[Path] = None,
    edge_applog_context_path: Optional[Path] = None,
    applog_model_context_path: Optional[Path] = None,
) -> int:
    chain_dir = scenario_chain_dir(scenario_dir)
    backbone_path = backbone_path or (chain_dir / "backbone_chain.v1.json")
    context_edges_path = context_edges_path or (chain_dir / "behavior_context_edges.v0.jsonl")
    output_path = output_path or (chain_dir / "behavior_chain_dataset.v2.json")
    meta_output_path = meta_output_path or (chain_dir / "behavior_chain_dataset.v2.meta.json")
    backbone_warning_output_path = backbone_warning_output_path or (chain_dir / "backbone_broad_warning.v0.json")

    tiered_paths: list[tuple[str, Path]] = []
    if auxiliary_path is None:
        cand = chain_dir / "audit_triples.auxiliary.v1.jsonl"
        if cand.exists():
            auxiliary_path = cand
    if filtered_path is None:
        cand = chain_dir / "audit_triples.filtered.v1.jsonl"
        if cand.exists():
            filtered_path = cand
    if unknown_path is None:
        cand = chain_dir / "audit_triples.unknown.v1.jsonl"
        if cand.exists():
            unknown_path = cand

    if auxiliary_path:
        tiered_paths.append(("auxiliary", auxiliary_path))
    if filtered_path:
        tiered_paths.append(("filtered", filtered_path))
    if unknown_path:
        tiered_paths.append(("unknown", unknown_path))

    # Resolve stage_residual path automatically
    if stage_residual_path is None:
        cand = chain_dir / "behavior_context_stage_residual.v0.jsonl"
        if cand.exists():
            stage_residual_path = cand

    if refinement_residual_path is None:
        cand = chain_dir / "backbone_refinement_residual.v0.jsonl"
        if cand.exists():
            refinement_residual_path = cand

    if edge_applog_context_path is None:
        cand = scenario_dir / "index" / "edge_applog_context_view.v0.jsonl"
        if cand.exists():
            edge_applog_context_path = cand

    if applog_model_context_path is None:
        cand = scenario_dir / "index" / "applog_model_context.v0.jsonl"
        if cand.exists():
            applog_model_context_path = cand

    legacy = _legacy()
    return legacy.run(
        backbone_path=backbone_path,
        context_edges_path=context_edges_path,
        output_path=output_path,
        meta_output_path=meta_output_path,
        backbone_warning_output_path=backbone_warning_output_path,
        tiered_paths=tiered_paths or None,
        necessary_window=necessary_window,
        stage_residual_path=stage_residual_path,
        refinement_residual_path=refinement_residual_path,
        edge_applog_context_path=edge_applog_context_path,
        applog_model_context_path=applog_model_context_path,
    )


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Build behavior chain dataset v2")
    p.add_argument("--scenario-dir", type=Path, default=SCENARIO_DIR)
    p.add_argument("--backbone", type=Path, default=DEFAULT_BACKBONE)
    p.add_argument("--context-edges", type=Path, default=DEFAULT_CONTEXT_EDGES)
    p.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    p.add_argument("--meta-output", type=Path, default=DEFAULT_META_OUTPUT)
    p.add_argument("--backbone-warning-output", type=Path, default=DEFAULT_BACKBONE_WARNING_OUTPUT)
    p.add_argument("--auxiliary", type=Path, default=None)
    p.add_argument("--filtered", type=Path, default=None)
    p.add_argument("--unknown", type=Path, default=None)
    p.add_argument("--necessary-context-window", type=int, default=DEFAULT_NECESSARY_WINDOW)
    p.add_argument("--edge-applog-context", type=Path, default=None)
    p.add_argument("--applog-model-context", type=Path, default=None)
    return p.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)
    scenario_dir = args.scenario_dir
    backbone = args.backbone
    context_edges = args.context_edges
    output = args.output
    meta_output = args.meta_output
    backbone_warning_output = args.backbone_warning_output
    auxiliary = args.auxiliary
    filtered = args.filtered
    unknown = args.unknown

    if scenario_dir != SCENARIO_DIR:
        derived = scenario_chain_dir(scenario_dir)
        if backbone == DEFAULT_BACKBONE:
            backbone = derived / "backbone_chain.v1.json"
        if context_edges == DEFAULT_CONTEXT_EDGES:
            context_edges = derived / "behavior_context_edges.v0.jsonl"
        if output == DEFAULT_OUTPUT:
            output = derived / "behavior_chain_dataset.v2.json"
        if meta_output == DEFAULT_META_OUTPUT:
            meta_output = derived / "behavior_chain_dataset.v2.meta.json"
        if backbone_warning_output == DEFAULT_BACKBONE_WARNING_OUTPUT:
            backbone_warning_output = derived / "backbone_broad_warning.v0.json"
        if auxiliary is None:
            cand = derived / "audit_triples.auxiliary.v1.jsonl"
            if cand.exists():
                auxiliary = cand
        if filtered is None:
            cand = derived / "audit_triples.filtered.v1.jsonl"
            if cand.exists():
                filtered = cand
        if unknown is None:
            cand = derived / "audit_triples.unknown.v1.jsonl"
            if cand.exists():
                unknown = cand

    return run_for_scenario(
        scenario_dir=scenario_dir,
        backbone_path=backbone,
        context_edges_path=context_edges,
        output_path=output,
        meta_output_path=meta_output,
        backbone_warning_output_path=backbone_warning_output,
        auxiliary_path=auxiliary,
        filtered_path=filtered,
        unknown_path=unknown,
        necessary_window=args.necessary_context_window,
        edge_applog_context_path=args.edge_applog_context,
        applog_model_context_path=args.applog_model_context,
    )


if __name__ == "__main__":
    raise SystemExit(main())
