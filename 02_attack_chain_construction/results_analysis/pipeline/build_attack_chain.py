#!/usr/bin/env python3
"""Pipeline entrypoint for building attack_subgraph/backbone from core triples."""

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
DEFAULT_TRIPLES_PATH = CHAIN_DIR / "audit_triples.core.v1.jsonl"
DEFAULT_SUBGRAPH_PATH = CHAIN_DIR / "attack_subgraph.v1.json"
DEFAULT_BACKBONE_PATH = CHAIN_DIR / "backbone_chain.v1.json"
DEFAULT_UNIT_EVENT_PATH = INDEX_DIR / "unit_event_index.jsonl"
DEFAULT_UNIT_INDEX_PATH = INDEX_DIR / "unit_index.jsonl"
DEFAULT_BROAD_GATE_RELATIONS = ("NET_RECV", "NET_SEND", "PROCESS_FORK")
DEFAULT_RUNTIME_SHELL_BLOCK_TRIAL_RELATIONS = ("PROCESS_FORK", "NET_ACCEPT")


def _legacy():
    return load_legacy_module(
        __file__,
        "build_attack_chain_v1.py",
        "legacy_build_attack_chain_v1",
    )


def run_for_scenario(
    scenario_dir: Path,
    triples_path: Optional[Path] = None,
    subgraph_path: Optional[Path] = None,
    backbone_path: Optional[Path] = None,
    unit_event_path: Optional[Path] = None,
    unit_index_path: Optional[Path] = None,
    anchors_path: Optional[Path] = None,
    max_hops: int = 1,
    seed_mode: str = "auto",
    strict: bool = True,
    b_fallback_net_pair_required: bool = False,
    b_fallback_net_pair_window_evt: int = 15,
    save_attack_subgraph: bool = False,
    skip_save_attack_subgraph: bool = False,
    backbone_file_devnull_filter: bool = False,
    backbone_file_node_modules_filter: bool = False,
    backbone_file_label_low_info: bool = False,
    backbone_file_label_vendor_composer: bool = False,
    backbone_broad_gate_on_warning: bool = False,
    backbone_broad_gate_relations: str = ",".join(DEFAULT_BROAD_GATE_RELATIONS),
    backbone_broad_gate_window_evt: int = 12,
    backbone_broad_gate_fork_repeat_sparse_experiment: bool = False,
    backbone_broad_gate_fork_repeat_unknown_child_stride: int = 80,
    backbone_broad_gate_fork_parent_cluster_experiment: bool = False,
    backbone_broad_gate_fork_parent_cluster_gap_evt: int = 5000,
    backbone_broad_gate_fork_parent_cluster_min_subject_edges: int = 8,
    backbone_broad_gate_net_accept_repeat_sparse_experiment: bool = False,
    backbone_broad_gate_net_accept_repeat_stride: int = 80,
    backbone_runtime_shell_block_representative_experiment: bool = False,
    backbone_runtime_shell_block_relations: str = ",".join(DEFAULT_RUNTIME_SHELL_BLOCK_TRIAL_RELATIONS),
    backbone_runtime_shell_block_min_block_edges: int = 8,
    backbone_runtime_shell_block_min_overlap_ratio: float = 1.0,
    backbone_runtime_shell_block_net_accept_subject_anchor_trial: bool = False,
    backbone_runtime_shell_block_process_fork_hybrid_gate: bool = False,
    backbone_runtime_shell_block_process_fork_hybrid_min_overlap_ratio: float = 0.45,
    backbone_runtime_shell_block_process_fork_hybrid_min_overlap_edges: int = 6,
    backbone_refinement_planner_mode: bool = False,
    backbone_preparation_shell_trial: bool = False,
) -> int:
    legacy = _legacy()
    return legacy.run_build_attack_chain_v1(
        scenario_dir=scenario_dir,
        triples_path=triples_path,
        subgraph_path=subgraph_path,
        backbone_path=backbone_path,
        unit_event_path=unit_event_path,
        unit_index_path=unit_index_path,
        anchors_path=anchors_path,
        max_hops=max_hops,
        seed_mode=seed_mode,
        strict=strict,
        b_fallback_net_pair_required=b_fallback_net_pair_required,
        b_fallback_net_pair_window_evt=b_fallback_net_pair_window_evt,
        save_attack_subgraph=save_attack_subgraph,
        skip_save_attack_subgraph=skip_save_attack_subgraph,
        backbone_file_devnull_filter=backbone_file_devnull_filter,
        backbone_file_node_modules_filter=backbone_file_node_modules_filter,
        backbone_file_label_low_info=backbone_file_label_low_info,
        backbone_file_label_vendor_composer=backbone_file_label_vendor_composer,
        backbone_broad_gate_on_warning=backbone_broad_gate_on_warning,
        backbone_broad_gate_relations=backbone_broad_gate_relations,
        backbone_broad_gate_window_evt=backbone_broad_gate_window_evt,
        backbone_broad_gate_fork_repeat_sparse_experiment=(
            backbone_broad_gate_fork_repeat_sparse_experiment
        ),
        backbone_broad_gate_fork_repeat_unknown_child_stride=(
            backbone_broad_gate_fork_repeat_unknown_child_stride
        ),
        backbone_broad_gate_fork_parent_cluster_experiment=(
            backbone_broad_gate_fork_parent_cluster_experiment
        ),
        backbone_broad_gate_fork_parent_cluster_gap_evt=(
            backbone_broad_gate_fork_parent_cluster_gap_evt
        ),
        backbone_broad_gate_fork_parent_cluster_min_subject_edges=(
            backbone_broad_gate_fork_parent_cluster_min_subject_edges
        ),
        backbone_broad_gate_net_accept_repeat_sparse_experiment=(
            backbone_broad_gate_net_accept_repeat_sparse_experiment
        ),
        backbone_broad_gate_net_accept_repeat_stride=(
            backbone_broad_gate_net_accept_repeat_stride
        ),
        backbone_runtime_shell_block_representative_experiment=(
            backbone_runtime_shell_block_representative_experiment
        ),
        backbone_runtime_shell_block_relations=backbone_runtime_shell_block_relations,
        backbone_runtime_shell_block_min_block_edges=(
            backbone_runtime_shell_block_min_block_edges
        ),
        backbone_runtime_shell_block_min_overlap_ratio=(
            backbone_runtime_shell_block_min_overlap_ratio
        ),
        backbone_runtime_shell_block_net_accept_subject_anchor_trial=(
            backbone_runtime_shell_block_net_accept_subject_anchor_trial
        ),
        backbone_runtime_shell_block_process_fork_hybrid_gate=(
            backbone_runtime_shell_block_process_fork_hybrid_gate
        ),
        backbone_runtime_shell_block_process_fork_hybrid_min_overlap_ratio=(
            backbone_runtime_shell_block_process_fork_hybrid_min_overlap_ratio
        ),
        backbone_runtime_shell_block_process_fork_hybrid_min_overlap_edges=(
            backbone_runtime_shell_block_process_fork_hybrid_min_overlap_edges
        ),
        backbone_refinement_planner_mode=bool(
            backbone_refinement_planner_mode
        ),
        backbone_preparation_shell_trial=bool(
            backbone_preparation_shell_trial
        ),
    )


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build single-scenario attack chain")
    parser.add_argument("--scenario-dir", type=Path, default=SCENARIO_DIR)
    parser.add_argument("--triples-path", type=Path, default=None)
    parser.add_argument("--subgraph-path", type=Path, default=None)
    parser.add_argument("--backbone-path", type=Path, default=None)
    parser.add_argument("--unit-event-path", type=Path, default=None)
    parser.add_argument("--unit-index-path", type=Path, default=None)
    parser.add_argument("--anchors-path", type=Path, default=None)
    parser.add_argument("--max-hops", type=int, default=1)
    parser.add_argument("--seed-mode", default="auto")
    parser.add_argument("--strict", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--b-fallback-net-pair-required", action="store_true")
    parser.add_argument("--b-fallback-net-pair-window-evt", type=int, default=15)
    parser.add_argument("--save-attack-subgraph", action="store_true")
    parser.add_argument("--skip-save-attack-subgraph", action="store_true")
    parser.add_argument("--backbone-file-devnull-filter", action="store_true")
    parser.add_argument("--backbone-file-node-modules-filter", action="store_true")
    parser.add_argument("--backbone-file-label-low-info", action="store_true")
    parser.add_argument("--backbone-file-label-vendor-composer", action="store_true")
    parser.add_argument("--backbone-broad-gate-on-warning", action="store_true")
    parser.add_argument(
        "--backbone-broad-gate-relations",
        default=",".join(DEFAULT_BROAD_GATE_RELATIONS),
    )
    parser.add_argument("--backbone-broad-gate-window-evt", type=int, default=12)
    parser.add_argument("--backbone-broad-gate-fork-repeat-sparse-experiment", action="store_true")
    parser.add_argument("--backbone-broad-gate-fork-repeat-unknown-child-stride", type=int, default=80)
    parser.add_argument("--backbone-broad-gate-fork-parent-cluster-experiment", action="store_true")
    parser.add_argument("--backbone-broad-gate-fork-parent-cluster-gap-evt", type=int, default=5000)
    parser.add_argument("--backbone-broad-gate-fork-parent-cluster-min-subject-edges", type=int, default=8)
    parser.add_argument("--backbone-broad-gate-net-accept-repeat-sparse-experiment", action="store_true")
    parser.add_argument("--backbone-broad-gate-net-accept-repeat-stride", type=int, default=80)
    parser.add_argument("--backbone-runtime-shell-block-representative-experiment", action="store_true")
    parser.add_argument(
        "--backbone-runtime-shell-block-relations",
        default=",".join(DEFAULT_RUNTIME_SHELL_BLOCK_TRIAL_RELATIONS),
    )
    parser.add_argument("--backbone-runtime-shell-block-min-block-edges", type=int, default=8)
    parser.add_argument("--backbone-runtime-shell-block-min-overlap-ratio", type=float, default=1.0)
    parser.add_argument("--backbone-runtime-shell-block-net-accept-subject-anchor-trial", action="store_true")
    parser.add_argument("--backbone-runtime-shell-block-process-fork-hybrid-gate", action="store_true")
    parser.add_argument("--backbone-runtime-shell-block-process-fork-hybrid-min-overlap-ratio", type=float, default=0.45)
    parser.add_argument("--backbone-runtime-shell-block-process-fork-hybrid-min-overlap-edges", type=int, default=6)
    parser.add_argument("--backbone-refinement-planner-mode", action="store_true")
    parser.add_argument("--backbone-preparation-shell-trial", action="store_true")
    return parser.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)
    return run_for_scenario(
        scenario_dir=args.scenario_dir,
        triples_path=args.triples_path,
        subgraph_path=args.subgraph_path,
        backbone_path=args.backbone_path,
        unit_event_path=args.unit_event_path,
        unit_index_path=args.unit_index_path,
        anchors_path=args.anchors_path,
        max_hops=args.max_hops,
        seed_mode=args.seed_mode,
        strict=args.strict,
        b_fallback_net_pair_required=args.b_fallback_net_pair_required,
        b_fallback_net_pair_window_evt=args.b_fallback_net_pair_window_evt,
        save_attack_subgraph=args.save_attack_subgraph,
        skip_save_attack_subgraph=args.skip_save_attack_subgraph,
        backbone_file_devnull_filter=args.backbone_file_devnull_filter,
        backbone_file_node_modules_filter=args.backbone_file_node_modules_filter,
        backbone_file_label_low_info=args.backbone_file_label_low_info,
        backbone_file_label_vendor_composer=args.backbone_file_label_vendor_composer,
        backbone_broad_gate_on_warning=args.backbone_broad_gate_on_warning,
        backbone_broad_gate_relations=args.backbone_broad_gate_relations,
        backbone_broad_gate_window_evt=args.backbone_broad_gate_window_evt,
        backbone_broad_gate_fork_repeat_sparse_experiment=args.backbone_broad_gate_fork_repeat_sparse_experiment,
        backbone_broad_gate_fork_repeat_unknown_child_stride=args.backbone_broad_gate_fork_repeat_unknown_child_stride,
        backbone_broad_gate_fork_parent_cluster_experiment=args.backbone_broad_gate_fork_parent_cluster_experiment,
        backbone_broad_gate_fork_parent_cluster_gap_evt=args.backbone_broad_gate_fork_parent_cluster_gap_evt,
        backbone_broad_gate_fork_parent_cluster_min_subject_edges=args.backbone_broad_gate_fork_parent_cluster_min_subject_edges,
        backbone_broad_gate_net_accept_repeat_sparse_experiment=args.backbone_broad_gate_net_accept_repeat_sparse_experiment,
        backbone_broad_gate_net_accept_repeat_stride=args.backbone_broad_gate_net_accept_repeat_stride,
        backbone_runtime_shell_block_representative_experiment=args.backbone_runtime_shell_block_representative_experiment,
        backbone_runtime_shell_block_relations=args.backbone_runtime_shell_block_relations,
        backbone_runtime_shell_block_min_block_edges=args.backbone_runtime_shell_block_min_block_edges,
        backbone_runtime_shell_block_min_overlap_ratio=args.backbone_runtime_shell_block_min_overlap_ratio,
        backbone_runtime_shell_block_net_accept_subject_anchor_trial=args.backbone_runtime_shell_block_net_accept_subject_anchor_trial,
        backbone_runtime_shell_block_process_fork_hybrid_gate=args.backbone_runtime_shell_block_process_fork_hybrid_gate,
        backbone_runtime_shell_block_process_fork_hybrid_min_overlap_ratio=args.backbone_runtime_shell_block_process_fork_hybrid_min_overlap_ratio,
        backbone_runtime_shell_block_process_fork_hybrid_min_overlap_edges=args.backbone_runtime_shell_block_process_fork_hybrid_min_overlap_edges,
        backbone_refinement_planner_mode=args.backbone_refinement_planner_mode,
        backbone_preparation_shell_trial=args.backbone_preparation_shell_trial,
    )


if __name__ == "__main__":
    raise SystemExit(main())
