#!/usr/bin/env python3
"""
Batch script for the complete post-processing pipeline (formal main path).

Features:
    1. Scan the latest timestamp directory for every scenario under results/.
    2. Check prerequisites (raw/sysdig and index files).
    3. Run the formal main path sequentially for each eligible scenario:
       extract -> backbone -> enrich -> dataset
    4. Record each step and final status, then write a global summary.

Formal entry point: results_analysis/pipeline/run_chain_pipeline.py
Stage-residual sidecars are not included (build_stage_residual_sidecar_v0.py is not part of the default path).
Do not use --skip-enrich as a success path.

Usage examples:
    # Run the complete pipeline (default results/ root).
    python batch_full_pipeline.py

    # Preview the scenarios without executing anything.
    python batch_full_pipeline.py --dry-run

    # Rerun only scenarios that previously failed.
    python batch_full_pipeline.py --only-failed

    # Specify a custom results root.
    python batch_full_pipeline.py --results-root /path/to/results

    # Specify a log output directory.
    python batch_full_pipeline.py --log-dir /path/to/logs

    # Specify the enrich guard threshold (0 disables automatic skipping).
    python batch_full_pipeline.py --backbone-guard-threshold 0

    # Combined: rerun failures with a high threshold.
    python batch_full_pipeline.py --only-failed --backbone-guard-threshold 8000
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
import traceback
from datetime import datetime
from pathlib import Path

# ---------------------------------------------------------------------------
# Global constants.
# ---------------------------------------------------------------------------
# Directory containing this script (the pipeline/ directory).
SCRIPT_DIR = Path(__file__).resolve().parent
# Project root.
PROJECT_ROOT = SCRIPT_DIR.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from console_observability import (
    banner_box,
    emit_observation,
    final_status_block,
    highest_level_reached,
    progress_line,
    release_slug_for,
    stage_banner,
)
from results_analysis.pipeline.utils.common import CHAIN_DIR_NAME, scenario_chain_dir

try:
    from run_chain_pipeline import _load_release_exporter
except ImportError:  # pragma: no cover - package-style import fallback
    from .run_chain_pipeline import _load_release_exporter

# Default results root.
DEFAULT_RESULTS_ROOT = PROJECT_ROOT.parent / "01_dataset_construction" / "results"
DEFAULT_RESULTS_ROOT_DISPLAY = "../01_dataset_construction/results"
# Default run workspace for generated reports and downstream release data.
DEFAULT_PRIVATE_OUTPUT_ROOT = PROJECT_ROOT.parents[1] / "seclog_work"
# Default dataset_release_v1/ root (used only with --with-release).
DEFAULT_RELEASE_ROOT = DEFAULT_PRIVATE_OUTPUT_ROOT / "dataset_release_v1"
DEFAULT_RELEASE_ROOT_DISPLAY = "../seclog_work/dataset_release_v1"
# Unified pipeline entry script.
PIPELINE_ENTRY = SCRIPT_DIR / "run_chain_pipeline.py"

# Output files for the four stages (used to determine whether each step succeeded).
STAGE_REQUIRED_FILES = {
    "extract": [
        # core is the only required extract artifact.
        # auxiliary / filtered / unknown are non-core tiers;
        # their absence does not mean extract failed (lazy mode writes no file when empty).
        f"{CHAIN_DIR_NAME}/audit_triples.core.v1.jsonl",
    ],
    "backbone": [
        f"{CHAIN_DIR_NAME}/backbone_chain.v1.json",
    ],
    "enrich": [
        f"{CHAIN_DIR_NAME}/behavior_context_edges.v0.jsonl",
        f"{CHAIN_DIR_NAME}/behavior_context_summary.v0.json",
    ],
    "dataset": [
        f"{CHAIN_DIR_NAME}/behavior_chain_dataset.v2.json",
        f"{CHAIN_DIR_NAME}/behavior_chain_dataset.v2.meta.json",
    ],
}

# Files checked as prerequisites.
PREREQUISITE_FILES = [
    "raw/sysdig",
]

FORMAL_SUCCESS_REQUIRED_FILES = [
    (f"{CHAIN_DIR_NAME}/behavior_chain_dataset.v2.json", "dataset file does not exist or is empty"),
    (f"{CHAIN_DIR_NAME}/behavior_chain_dataset.v2.meta.json", "dataset metadata file does not exist or is empty"),
    (f"{CHAIN_DIR_NAME}/behavior_context_edges.v0.jsonl", "enrich output behavior_context_edges.v0.jsonl does not exist or is empty"),
]

TIMESTAMP_DIR_RE = re.compile(r"^\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}$")


# ---------------------------------------------------------------------------
# Scenario discovery: recursively scan all latest timestamp directories.
# ---------------------------------------------------------------------------

def find_latest_timestamp_dirs(root: Path) -> list[tuple[Path, str]]:
    """
    Recursively scan timestamp directories under root and return
    (latest timestamp directory, relative scenario name) for each leaf scenario.

    Results are sorted by relative scenario name for reproducible execution order.

    Example scenario directory structure:
      results/juice-shop/2026-04-09_10-40-58/
      results/vulhub/gitlist/CVE-2018-1000533/2026-03-21_09-47-27/

    For each "leaf scenario directory" (the deepest parent containing timestamp
    directories), select its latest timestamp directory.
    """
    # Find timestamp directories and sort by modification time descending (newest first).
    ts_dirs: list[Path] = []
    for item in root.rglob("*"):
        if item.is_dir() and TIMESTAMP_DIR_RE.fullmatch(item.name):
            ts_dirs.append(item)

    # Sort directory names descending (ISO-formatted strings compare directly; ">" means newer).
    ts_dirs.sort(key=lambda p: p.name, reverse=True)

    # Group by scenario and retain only the newest timestamp directory for each relative name.
    latest_by_scene: dict[str, Path] = {}
    for ts_dir in ts_dirs:
        scene_dir = ts_dir.parent
        rel = str(scene_dir.relative_to(root))
        # The first occurrence is newest because the list is sorted descending.
        if rel not in latest_by_scene:
            latest_by_scene[rel] = ts_dir

    # Return an ordered list sorted alphabetically by relative name.
    sorted_scenes = sorted(latest_by_scene.items(), key=lambda x: x[0])
    return [(ts_dir, rel) for rel, ts_dir in sorted_scenes]


# ---------------------------------------------------------------------------
# Prerequisite checks.
# ---------------------------------------------------------------------------

def check_prerequisites(scene_dir: Path) -> tuple[bool, str]:
    """
    Check whether a scenario directory satisfies basic pipeline prerequisites.
    Return (eligible, skip reason).
    """
    for req in PREREQUISITE_FILES:
        path = scene_dir / req
        if not path.exists():
            return False, f"Required directory/file is missing: {req}"
        if path.is_dir() and req.endswith("/sysdig"):
            # The sysdig directory must contain at least one .log file.
            log_files = list(path.glob("*.log"))
            if not log_files:
                return False, "raw/sysdig/ is empty and contains no .log file"
    return True, ""


def stage_output_exists(scene_dir: Path, stage: str) -> bool:
    """Check that the core output files for a stage exist and are non-empty."""
    if stage == "enrich":
        summary_path = scenario_chain_dir(scene_dir) / "behavior_context_summary.v0.json"
        if not summary_path.exists() or summary_path.stat().st_size == 0:
            return False

        context_edges_path = scenario_chain_dir(scene_dir) / "behavior_context_edges.v0.jsonl"
        if context_edges_path.exists() and context_edges_path.stat().st_size > 0:
            return True

        no_unit_ok, _ = is_no_unit_enrich_completed(scene_dir)
        return no_unit_ok

    for rel_path in STAGE_REQUIRED_FILES[stage]:
        p = scene_dir / rel_path
        if not p.exists() or p.stat().st_size == 0:
            return False
    return True


def _load_enrich_summary(scene_dir: Path) -> dict | None:
    summary_path = scenario_chain_dir(scene_dir) / "behavior_context_summary.v0.json"
    if not summary_path.exists() or summary_path.stat().st_size == 0:
        return None
    try:
        with open(summary_path, encoding="utf-8", errors="replace") as f:
            obj = json.load(f)
            return obj if isinstance(obj, dict) else None
    except Exception:
        return None


def _enrich_skipped_reason(scene_dir: Path) -> str:
    summary = _load_enrich_summary(scene_dir)
    if not summary:
        return ""

    status = str(summary.get("status") or "").strip()
    if status != "skipped":
        return ""

    skip_reason = str(summary.get("skip_reason") or "").strip()
    return skip_reason or "status=skipped"


def is_no_unit_enrich_completed(scene_dir: Path) -> tuple[bool, str]:
    summary = _load_enrich_summary(scene_dir)
    if not summary:
        return False, ""

    status = str(summary.get("status") or "").strip()
    unit_mode = str(summary.get("unit_mode") or "").strip()
    unit_reason = str(summary.get("unit_mode_reason") or "").strip()
    output_state = summary.get("output_state") if isinstance(summary.get("output_state"), dict) else {}
    context_state = str(output_state.get("behavior_context_edges") or "")

    if (
        status == "completed"
        and unit_mode in {"unit-absent", "unit-unavailable"}
        and context_state == "empty_not_written"
    ):
        return True, unit_reason or "no_unit_mode"

    return False, ""


def formal_success_failures(scene_dir: Path) -> list[str]:
    """Return missing key artifacts under the formal success convention."""
    reasons: list[str] = []
    skipped_reason = _enrich_skipped_reason(scene_dir)
    if skipped_reason:
        reasons.append(f"enrich was marked skipped: {skipped_reason}")

    no_unit_ok, _ = is_no_unit_enrich_completed(scene_dir)
    for rel_path, reason in FORMAL_SUCCESS_REQUIRED_FILES:
        if rel_path == f"{CHAIN_DIR_NAME}/behavior_context_edges.v0.jsonl" and no_unit_ok:
            continue
        path = scene_dir / rel_path
        if not path.exists() or path.stat().st_size == 0:
            reasons.append(reason)
    return reasons


def scenario_fully_succeeded(scene_dir: Path) -> tuple[bool, str]:
    """
    Determine whether a scenario has formally succeeded under the current convention.

    Formal success requires all of the following:
      1. behavior_chain_dataset.v2.json exists and is non-empty.
      2. behavior_chain_dataset.v2.meta.json exists and is non-empty.
      3. behavior_context_edges.v0.jsonl exists and is non-empty.
         (enrich must actually complete; guard-skipped and explicit-skip are not success.)

    Return (success, specific reason string).
    """
    reasons = formal_success_failures(scene_dir)
    if not reasons:
        return True, ""
    return False, "; ".join(reasons)


# ---------------------------------------------------------------------------
# Console progress display.
# ---------------------------------------------------------------------------

STAGE_ORDER = ["extract", "backbone", "enrich", "dataset"]

STAGE_LABELS: dict[str, str] = {
    "extract": "EXTRACT",
    "backbone": "BACKBONE",
    "enrich": "ENRICH",
    "dataset": "DATASET",
}

INCOMPLETE_STAGE_STATUSES = {"auto-skipped", "skipped", "incomplete"}

# Stage-entry markers printed by run_chain_pipeline.py.
STAGE_MARKERS: dict[str, str] = {
    "extract": "extract audit triples",
    "backbone": "build attack_subgraph/backbone",
    "enrich": "enrich malicious non-core context",
    "dataset": "build behavior chain dataset",
}


def _emit_stage_row(
    current_stage: str,
    stage_results: dict[str, dict],
    prefix: str = "",
    scenario_index: int | None = None,
    scenario_total: int | None = None,
) -> None:
    """
    Print the status of every stage on one line using this format:

        [1/28] scene_rel | ts_dir
        EXTRACT=OK  BACKBONE=OK  ENRICH=OK  DATASET=OK

    Before each print, use \\r to return to the line start and overwrite the line.
    """
    parts: list[str] = []
    for stage in STAGE_ORDER:
        label = STAGE_LABELS[stage]
        info = stage_results.get(stage, {})
        status = info.get("status", "pending")

        if status == "success":
            tag = f"{label}=OK  "
        elif status == "failed":
            tag = f"{label}=FAIL"
        elif status in INCOMPLETE_STAGE_STATUSES:
            tag = f"{label}=SKIP"
        elif status == "not-run":
            tag = f"{label}=----"
        elif status == "pending":
            tag = f"{label}=...  "
        elif status == "running":
            tag = f"{label}=RUN "
        else:
            tag = f"{label}={status[:4]}  "

        if stage == current_stage and status == "pending":
            # Highlight the currently running stage.
            parts.append(f"\033[1;33m{tag}\033[0m")  # yellow highlight
        else:
            parts.append(tag)

    stage_ratio = 0.0
    if current_stage in STAGE_ORDER:
        stage_ratio = STAGE_ORDER.index(current_stage) / len(STAGE_ORDER)
    terminal_statuses = {
        "success", "failed", "auto-skipped", "skipped", "incomplete", "not-run", "dry-run"
    }
    finished_count = sum(
        1 for s in STAGE_ORDER if stage_results.get(s, {}).get("status") in terminal_statuses
    )
    stage_ratio = max(stage_ratio, finished_count / len(STAGE_ORDER))

    def _bar(ratio: float, width: int = 20) -> str:
        ratio = max(0.0, min(1.0, ratio))
        fill = int(round(ratio * width))
        return "#" * fill + "-" * (width - fill)

    stage_pct = int(round(stage_ratio * 100))
    line = prefix + "  ".join(parts) + f"  | STAGE [{_bar(stage_ratio)}] {stage_pct:>3d}%"

    if scenario_index is not None and scenario_total:
        overall_ratio = (
            (max(0, scenario_index - 1) + stage_ratio) / scenario_total
            if scenario_total > 0
            else 0.0
        )
        overall_pct = int(round(overall_ratio * 100))
        line += f"  TOTAL [{_bar(overall_ratio)}] {overall_pct:>3d}%"

    print(f"\r{line}", end="", flush=True)


def _emit_scenario_summary(
    idx: int,
    total: int,
    scene_rel: str,
    overall_status: str,
    dataset_ok: bool,
    elapsed: float | None,
    error_summary: str,
) -> None:
    """
    Print a one-line summary on a new line when a scenario ends, followed by diagnostics.
    """
    elapsed_str = f"{elapsed:.1f}s" if elapsed is not None else "N/A"

    if overall_status == "success":
        status_tag = f"\033[1;32mOK\033[0m"       # green
        ds_tag = "dataset=OK"
    elif overall_status == "incomplete":
        status_tag = f"\033[1;33mINCOMPLETE\033[0m"  # yellow
        ds_tag = "dataset=OK" if dataset_ok else "dataset=SKIP"
    else:
        status_tag = f"\033[1;31mFAILED\033[0m"   # red
        ds_tag = ""

    print()  # End the line overwritten with \r.
    summary = f"  [{idx}/{total}] {scene_rel}  |  {status_tag}  |  {ds_tag}  |  {elapsed_str}"
    print(summary)
    if error_summary and overall_status != "success":
        print(f"           \033[2;37m{error_summary}\033[0m")  # gray diagnostic text


def _parse_stage_from_line(line: str) -> str | None:
    """Detect the stage entered from a line printed by the pipeline."""
    for stage, marker in STAGE_MARKERS.items():
        if marker in line:
            return stage
    return None


def _load_backbone_warning(scene_dir: Path) -> dict | None:
    path = scenario_chain_dir(scene_dir) / "backbone_broad_warning.v0.json"
    if not path.exists() or path.stat().st_size == 0:
        return None
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            obj = json.load(f)
        return obj if isinstance(obj, dict) else None
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Run one scenario.
# ---------------------------------------------------------------------------

def run_scenario(
    scene_dir: Path,
    scene_rel: str,
    log_file: Path,
    backbone_guard_threshold: int,
    save_attack_subgraph: bool = False,
    backbone_broad_gate_on_warning: bool = False,
    backbone_broad_gate_relations: str = "NET_RECV,NET_SEND,PROCESS_FORK",
    backbone_broad_gate_window_evt: int = 12,
    backbone_runtime_shell_block_representative_experiment: bool = False,
    backbone_runtime_shell_block_relations: str = "PROCESS_FORK,NET_ACCEPT",
    backbone_runtime_shell_block_min_block_edges: int = 8,
    backbone_runtime_shell_block_min_overlap_ratio: float = 1.0,
    backbone_runtime_shell_block_net_accept_subject_anchor_trial: bool = False,
    backbone_runtime_shell_block_process_fork_hybrid_gate: bool = False,
    backbone_runtime_shell_block_process_fork_hybrid_min_overlap_ratio: float = 0.45,
    backbone_runtime_shell_block_process_fork_hybrid_min_overlap_edges: int = 6,
    backbone_runtime_shell_block_process_fork_parent_cluster_trial: bool = False,
    backbone_runtime_shell_block_process_fork_parent_cluster_gap_evt: int = 5000,
    backbone_runtime_shell_block_process_fork_parent_cluster_min_subject_edges: int = 8,
    dry_run: bool = False,
    on_stage_enter: callable | None = None,  # Signature: (stage, stage_results, scenario_index, scenario_total) -> None.
    scenario_index: int | None = None,
    scenario_total: int | None = None,
) -> dict:
    """
    Run the complete pipeline for one scenario (extract -> backbone -> enrich -> dataset).
    Return the execution-result dictionary for that scenario.

    A failed step does not raise; the result records the failure and processing continues with the next scenario.

    Parameters
    ----------
    on_stage_enter
        Callback with the signature
        (stage: str, stage_results: dict[str, dict], scenario_index: int | None, scenario_total: int | None) -> None。
        Called whenever the pipeline enters a new stage to drive the console progress bar.
    """
    stage_results: dict[str, dict] = {}
    for stage in STAGE_ORDER:
        stage_results[stage] = {"status": "pending", "error": ""}

    result = {
        "scene_rel": scene_rel,
        "scene_path": str(scene_dir),
        "pipeline_rc": None,
        "stages": stage_results,
        "dataset_generated": False,
        "dataset_meta_generated": False,
        "enrich_generated": False,
        "overall_status": "pending",
        "skipped": False,
        "skip_reason": "",
        "incomplete_reason": "",
        "elapsed_seconds": None,
        "error_summary": "",
        "wrapper_error": "",
        "backbone_warning_present": False,
        "backbone_warning_codes": [],
        "backbone_warning_metrics": {},
    }

    if dry_run:
        for stage in STAGE_ORDER:
            stage_results[stage]["status"] = "dry-run"
        result["skipped"] = True
        result["skip_reason"] = "dry-run mode"
        return result

    t0 = time.time()
    emit_observation(
        "[batch_full_pipeline][scene]",
        stage="scene",
        substep="start",
        scenario_dir=scene_dir,
        processed=scenario_index,
        total=scenario_total,
        percent=round((scenario_index / scenario_total) * 100.0, 2)
        if scenario_index is not None and scenario_total
        else None,
        raw_sysdig_exists=(scene_dir / "raw" / "sysdig").exists(),
        log_file=log_file,
    )

    # Detect the pipeline stage-entry signal.
    entered_stage: str | None = None

    with open(log_file, "w", encoding="utf-8") as lf:
        lf.write(f"[batch_full_pipeline] Starting scenario: {scene_rel}\n")
        lf.write(f"[batch_full_pipeline] scene_dir: {scene_dir}\n")
        lf.write(f"[batch_full_pipeline] backbone_guard_threshold: {backbone_guard_threshold}\n")
        lf.write(f"[batch_full_pipeline] save_attack_subgraph: {save_attack_subgraph}\n")
        lf.write(f"[batch_full_pipeline] backbone_broad_gate_on_warning: {backbone_broad_gate_on_warning}\n")
        lf.write(f"[batch_full_pipeline] backbone_broad_gate_relations: {backbone_broad_gate_relations}\n")
        lf.write(f"[batch_full_pipeline] backbone_broad_gate_window_evt: {backbone_broad_gate_window_evt}\n")
        lf.write(
            "[batch_full_pipeline] backbone_runtime_shell_block_representative_experiment: "
            f"{backbone_runtime_shell_block_representative_experiment}\n"
        )
        lf.write(
            "[batch_full_pipeline] backbone_runtime_shell_block_relations: "
            f"{backbone_runtime_shell_block_relations}\n"
        )
        lf.write(
            "[batch_full_pipeline] backbone_runtime_shell_block_min_block_edges: "
            f"{backbone_runtime_shell_block_min_block_edges}\n"
        )
        lf.write(
            "[batch_full_pipeline] backbone_runtime_shell_block_min_overlap_ratio: "
            f"{backbone_runtime_shell_block_min_overlap_ratio}\n"
        )
        lf.write(
            "[batch_full_pipeline] backbone_runtime_shell_block_net_accept_subject_anchor_trial: "
            f"{backbone_runtime_shell_block_net_accept_subject_anchor_trial}\n"
        )
        lf.write(
            "[batch_full_pipeline] backbone_runtime_shell_block_process_fork_hybrid_gate: "
            f"{backbone_runtime_shell_block_process_fork_hybrid_gate}\n"
        )
        lf.write(
            "[batch_full_pipeline] backbone_runtime_shell_block_process_fork_hybrid_min_overlap_ratio: "
            f"{backbone_runtime_shell_block_process_fork_hybrid_min_overlap_ratio}\n"
        )
        lf.write(
            "[batch_full_pipeline] backbone_runtime_shell_block_process_fork_hybrid_min_overlap_edges: "
            f"{backbone_runtime_shell_block_process_fork_hybrid_min_overlap_edges}\n"
        )
        lf.write(
            "[batch_full_pipeline] backbone_runtime_shell_block_process_fork_parent_cluster_trial: "
            f"{backbone_runtime_shell_block_process_fork_parent_cluster_trial}\n"
        )
        lf.write(
            "[batch_full_pipeline] backbone_runtime_shell_block_process_fork_parent_cluster_gap_evt: "
            f"{backbone_runtime_shell_block_process_fork_parent_cluster_gap_evt}\n"
        )
        lf.write(
            "[batch_full_pipeline] backbone_runtime_shell_block_process_fork_parent_cluster_min_subject_edges: "
            f"{backbone_runtime_shell_block_process_fork_parent_cluster_min_subject_edges}\n"
        )
        lf.write(f"[batch_full_pipeline] Start time: {datetime.now().astimezone().strftime('%Y-%m-%d %H:%M:%S %Z')}\n")
        lf.write("=" * 80 + "\n")

        cmd = [
            sys.executable,
            str(PIPELINE_ENTRY),
            "--scenario-dir", str(scene_dir),
            "--backbone-guard-threshold", str(backbone_guard_threshold),
        ]
        if save_attack_subgraph:
            cmd.append("--save-attack-subgraph")
        if backbone_broad_gate_on_warning:
            cmd.append("--backbone-broad-gate-on-warning")
            cmd.extend(["--backbone-broad-gate-relations", backbone_broad_gate_relations])
            cmd.extend(["--backbone-broad-gate-window-evt", str(backbone_broad_gate_window_evt)])
        if backbone_runtime_shell_block_representative_experiment:
            cmd.append("--backbone-runtime-shell-block-representative-experiment")
            cmd.extend([
                "--backbone-runtime-shell-block-relations",
                backbone_runtime_shell_block_relations,
            ])
            cmd.extend([
                "--backbone-runtime-shell-block-min-block-edges",
                str(max(2, int(backbone_runtime_shell_block_min_block_edges))),
            ])
            cmd.extend([
                "--backbone-runtime-shell-block-min-overlap-ratio",
                str(max(0.0, min(1.0, float(backbone_runtime_shell_block_min_overlap_ratio)))),
            ])
            if backbone_runtime_shell_block_net_accept_subject_anchor_trial:
                cmd.append(
                    "--backbone-runtime-shell-block-net-accept-subject-anchor-trial"
                )
            if backbone_runtime_shell_block_process_fork_hybrid_gate:
                cmd.append(
                    "--backbone-runtime-shell-block-process-fork-hybrid-gate"
                )
                cmd.extend([
                    "--backbone-runtime-shell-block-process-fork-hybrid-min-overlap-ratio",
                    str(
                        max(
                            0.0,
                            min(
                                1.0,
                                float(
                                    backbone_runtime_shell_block_process_fork_hybrid_min_overlap_ratio
                                ),
                            ),
                        )
                    ),
                ])
                cmd.extend([
                    "--backbone-runtime-shell-block-process-fork-hybrid-min-overlap-edges",
                    str(
                        max(
                            1,
                            int(
                                backbone_runtime_shell_block_process_fork_hybrid_min_overlap_edges
                            ),
                        )
                    ),
                ])
        if backbone_runtime_shell_block_process_fork_parent_cluster_trial:
            cmd.append(
                "--backbone-runtime-shell-block-process-fork-parent-cluster-trial"
            )
            cmd.extend([
                "--backbone-runtime-shell-block-process-fork-parent-cluster-gap-evt",
                str(
                    max(
                        1,
                        int(
                            backbone_runtime_shell_block_process_fork_parent_cluster_gap_evt
                        ),
                    )
                ),
            ])
            cmd.extend([
                "--backbone-runtime-shell-block-process-fork-parent-cluster-min-subject-edges",
                str(
                    max(
                        2,
                        int(
                            backbone_runtime_shell_block_process_fork_parent_cluster_min_subject_edges
                        ),
                    )
                ),
            ])

        lf.write(f"[batch_full_pipeline] Command: {' '.join(cmd)}\n")
        lf.write("=" * 80 + "\n")
        lf.flush()

        wrapper_error = ""

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
            for raw_line in proc.stdout:
                lf.write(raw_line)
                lf.flush()

                # Detect stage-entry signals in real time to drive console progress.
                if on_stage_enter is not None:
                    detected = _parse_stage_from_line(raw_line)
                    if detected is not None and detected != entered_stage:
                        if entered_stage is not None and stage_results[entered_stage]["status"] == "running":
                            stage_results[entered_stage]["status"] = "success"
                        entered_stage = detected
                        stage_results[detected]["status"] = "running"
                        emit_observation(
                            "[batch_full_pipeline][stage]",
                            stage=detected,
                            status="start",
                            scenario_dir=scene_dir,
                            processed=scenario_index,
                            total=scenario_total,
                            percent=round((scenario_index / scenario_total) * 100.0, 2)
                            if scenario_index is not None and scenario_total
                            else None,
                            elapsed=round(time.time() - t0, 2),
                            log_file=log_file,
                        )
                        on_stage_enter(detected, stage_results, scenario_index, scenario_total)

            rc = proc.wait()
        except Exception as e:
            wrapper_error = f"{type(e).__name__}: {e}"
            lf.write(f"[batch_full_pipeline] Failed to start subprocess: {e}\n")
            lf.write(traceback.format_exc())
            rc = 1

        lf.write("=" * 80 + "\n")
        lf.write(f"[batch_full_pipeline] End time: {datetime.now().astimezone().strftime('%Y-%m-%d %H:%M:%S %Z')}\n")
        lf.write(f"[batch_full_pipeline] Pipeline return code: {rc}\n")

    result["pipeline_rc"] = rc
    result["wrapper_error"] = wrapper_error
    result["elapsed_seconds"] = round(time.time() - t0, 1)

    failure_stage: str | None = entered_stage

    # Check each stage's output files to determine whether each step succeeded.
    for stage in STAGE_ORDER:
        if stage_results[stage]["status"] == "running":
            stage_results[stage]["status"] = "pending"  # Not covered by stage validation; reset for checking.
        ok = stage_output_exists(scene_dir, stage)
        stage_results[stage]["status"] = "success" if ok else "failed"
        if not ok:
            missing = [
                rel for rel in STAGE_REQUIRED_FILES[stage]
                if not (scene_dir / rel).exists() or (scene_dir / rel).stat().st_size == 0
            ]
            stage_results[stage]["error"] = f"Output files are missing: {missing}"
            if failure_stage is None:
                failure_stage = stage

    # Additional dataset/enrich fields.
    chain_dir = scenario_chain_dir(scene_dir)
    dataset = chain_dir / "behavior_chain_dataset.v2.json"
    dataset_meta = chain_dir / "behavior_chain_dataset.v2.meta.json"
    context_edges = chain_dir / "behavior_context_edges.v0.jsonl"
    result["dataset_generated"] = dataset.exists() and dataset.stat().st_size > 0
    result["dataset_meta_generated"] = dataset_meta.exists() and dataset_meta.stat().st_size > 0
    result["enrich_generated"] = context_edges.exists() and context_edges.stat().st_size > 0
    backbone_warning = _load_backbone_warning(scene_dir)
    if backbone_warning:
        result["backbone_warning_present"] = bool(backbone_warning.get("warning_present"))
        result["backbone_warning_codes"] = list(backbone_warning.get("warning_codes") or [])
        metrics = backbone_warning.get("metrics") or {}
        result["backbone_warning_metrics"] = {
            key: metrics.get(key)
            for key in (
                "edge_count",
                "malicious_edge_count",
                "malicious_ratio",
                "non_malicious_ratio",
                "backbone_to_subgraph_ratio",
                "context_edge_count",
                "unmatched_count",
            )
        }

    # Mark enrich as incomplete for guard skip, explicit skip, or empty output.
    enrich_summary = scenario_chain_dir(scene_dir) / "behavior_context_summary.v0.json"
    enrich_skip_detected = False
    enrich_skip_reason = ""
    enrich_output_state = ""
    if enrich_summary.exists():
        try:
            with open(enrich_summary, encoding="utf-8", errors="replace") as f:
                summary = json.load(f)
            status = str(summary.get("status") or "")
            skip_reason = str(summary.get("skip_reason") or "")
            output_state = summary.get("output_state") or {}
            if isinstance(output_state, dict):
                enrich_output_state = str(output_state.get("behavior_context_edges") or "")
            if "backbone_guard_threshold_exceeded" in skip_reason:
                enrich_skip_detected = True
                enrich_skip_reason = skip_reason
                stage_results["enrich"]["status"] = "auto-skipped"
                stage_results["enrich"]["error"] = f"backbone_guard_threshold_exceeded: {skip_reason}"
            elif status == "skipped" or skip_reason == "explicit_skip_enrich":
                enrich_skip_detected = True
                enrich_skip_reason = skip_reason or status
                stage_results["enrich"]["status"] = "skipped"
                stage_results["enrich"]["error"] = (
                    f"enrich skipped: {skip_reason or 'status=skipped'}"
                )
        except Exception:
            pass

    incomplete_reason = ""
    if rc == 2:
        if enrich_skip_detected:
            incomplete_reason = f"enrich skipped: {enrich_skip_reason or 'unknown'}"
        elif failure_stage is not None:
            incomplete_reason = f"{failure_stage} incomplete (pipeline_rc=2)"
        else:
            incomplete_reason = "pipeline incomplete (pipeline_rc=2)"
    elif enrich_output_state == "empty_not_written":
        incomplete_reason = "enrich completed but produced no behavior_context_edges output"

    if incomplete_reason:
        result["incomplete_reason"] = incomplete_reason
        if failure_stage is None:
            failure_stage = "enrich"
        stage_results[failure_stage]["status"] = "incomplete"
        if not stage_results[failure_stage]["error"]:
            stage_results[failure_stage]["error"] = incomplete_reason
        failure_index = STAGE_ORDER.index(failure_stage)
        for later_stage in STAGE_ORDER[failure_index + 1:]:
            stage_results[later_stage]["status"] = "not-run"
            stage_results[later_stage]["error"] = f"Prerequisite stage incomplete: {failure_stage}"
    elif rc != 0 and failure_stage is not None:
        failure_index = STAGE_ORDER.index(failure_stage)
        for later_stage in STAGE_ORDER[failure_index + 1:]:
            if stage_results[later_stage]["status"] == "failed":
                stage_results[later_stage]["status"] = "not-run"
                stage_results[later_stage]["error"] = f"Prerequisite stage failed: {failure_stage}"

    # Compute overall_status.
    failed_stages = [s for s, v in stage_results.items() if v["status"] == "failed"]
    formal_success_missing = formal_success_failures(scene_dir)
    formal_success_ok = (rc == 0 and not formal_success_missing)

    if formal_success_ok:
        result["overall_status"] = "success"
        result["error_summary"] = ""
    elif result["incomplete_reason"]:
        result["overall_status"] = "incomplete"
        result["error_summary"] = result["incomplete_reason"]
    else:
        result["overall_status"] = "failed"
        if failed_stages:
            result["error_summary"] = f"Failed stages: {', '.join(failed_stages)}"
        elif result["wrapper_error"]:
            result["error_summary"] = f"Wrapper error: {result['wrapper_error']}"
        elif rc != 0:
            result["error_summary"] = f"pipeline_rc={rc}, but no failed stage was identified (possibly a wrapper error or external interruption)"
        elif formal_success_missing:
            result["error_summary"] = "; ".join(formal_success_missing)
        else:
            result["error_summary"] = "Unknown error (rc=0 and no failed stage identified)"

    emit_observation(
        "[batch_full_pipeline][scene]",
        stage="scene",
        status=result["overall_status"],
        scenario_dir=scene_dir,
        processed=scenario_index,
        total=scenario_total,
        percent=round((scenario_index / scenario_total) * 100.0, 2)
        if scenario_index is not None and scenario_total
        else None,
        elapsed=result["elapsed_seconds"],
        pipeline_rc=rc,
        failure_stage=failure_stage,
        dataset_generated=result["dataset_generated"],
        enrich_generated=result["enrich_generated"],
        log_file=log_file,
        error_summary=result["error_summary"] or None,
    )
    return result


# ---------------------------------------------------------------------------
# Main flow.
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run the complete post-processing pipeline in the formal path (extract->backbone->enrich->dataset).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--results-root",
        type=Path,
        default=DEFAULT_RESULTS_ROOT,
        help=f"results root (default: {DEFAULT_RESULTS_ROOT_DISPLAY})",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Scan and list scenarios without executing the pipeline.",
    )
    parser.add_argument(
        "--only-failed",
        action="store_true",
        help=f"Process only scenarios that previously failed ({CHAIN_DIR_NAME}/behavior_chain_dataset.v2.json is missing or empty).",
    )
    parser.add_argument(
        "--log-dir",
        type=Path,
        default=None,
        help="Log output directory (default: <pipeline>/batch_full_pipeline_logs/).",
    )
    parser.add_argument(
        "--backbone-guard-threshold",
        type=int,
        default=5000,
        help=(
            "Automatic enrich-skip threshold: skip enrich when the backbone edge count exceeds this value "
            "(set to 0 to disable; default 5000)."
        ),
    )
    parser.add_argument(
        "--save-attack-subgraph",
        action="store_true",
        help="Explicitly export attack_subgraph.v1.json (disabled by default).",
    )
    parser.add_argument(
        "--backbone-broad-gate-on-warning",
        action="store_true",
        help="Enable a local backbone gate for scenarios that trigger the broad-backbone warning (disabled by default).",
    )
    parser.add_argument(
        "--backbone-broad-gate-relations",
        type=str,
        default="NET_RECV,NET_SEND,PROCESS_FORK",
        help="Comma-separated relation allowlist for the local gate.",
    )
    parser.add_argument(
        "--backbone-broad-gate-window-evt",
        type=int,
        default=12,
        help="Malicious-neighborhood event window for the local gate.",
    )
    parser.add_argument(
        "--backbone-runtime-shell-block-representative-experiment",
        action="store_true",
        help="Enable the runtime-shell block representative-edge retention trial (PROCESS_FORK/NET_ACCEPT).",
    )
    parser.add_argument(
        "--backbone-runtime-shell-block-relations",
        type=str,
        default="PROCESS_FORK,NET_ACCEPT",
        help="Comma-separated relation allowlist for the runtime-shell block trial.",
    )
    parser.add_argument(
        "--backbone-runtime-shell-block-min-block-edges",
        type=int,
        default=8,
        help="Minimum block-edge count that triggers the runtime-shell block trial.",
    )
    parser.add_argument(
        "--backbone-runtime-shell-block-min-overlap-ratio",
        type=float,
        default=1.0,
        help="Minimum backbone-overlap ratio (0~1) that triggers the runtime-shell block trial.",
    )
    parser.add_argument(
        "--backbone-runtime-shell-block-net-accept-subject-anchor-trial",
        action="store_true",
        help=(
            "Targeted trial A (mongo-express): in the trial view only, aggregate NET_ACCEPT blocks "
            "by subject so one-edge fragments can form a block for the trial; "
            "exported sidecars remain aggregated by subject+connection."
        ),
    )
    parser.add_argument(
        "--backbone-runtime-shell-block-process-fork-hybrid-gate",
        action="store_true",
        help=(
            "Targeted trial B (pgadmin): in the trial view only, apply a combined "
            "ratio and absolute-overlap threshold to PROCESS_FORK target blocks."
        ),
    )
    parser.add_argument(
        "--backbone-runtime-shell-block-process-fork-hybrid-min-overlap-ratio",
        type=float,
        default=0.45,
        help="Targeted trial B: minimum overlap_ratio for the PROCESS_FORK combined threshold.",
    )
    parser.add_argument(
        "--backbone-runtime-shell-block-process-fork-hybrid-min-overlap-edges",
        type=int,
        default=6,
        help="Targeted trial B: minimum overlap_edge_count for the PROCESS_FORK combined threshold.",
    )
    parser.add_argument(
        "--backbone-runtime-shell-block-process-fork-parent-cluster-trial",
        action="store_true",
        help=(
            "Targeted trial C: treat repeated PROCESS_FORK edges under one parent as a runtime-shell "
            "parent-process derivation cluster; retain only representative boundary edges (first/last/optional middle) "
            "and bridge edges where the child later enters malicious_process_nodes. "
            "Effective with --backbone-broad-gate-on-warning."
        ),
    )
    parser.add_argument(
        "--backbone-runtime-shell-block-process-fork-parent-cluster-gap-evt",
        type=int,
        default=5000,
        help="Targeted trial C: evt_num gap threshold for splitting a parent PF stream into clusters (default 5000).",
    )
    parser.add_argument(
        "--backbone-runtime-shell-block-process-fork-parent-cluster-min-subject-edges",
        type=int,
        default=8,
        help=(
            "Targeted trial C: minimum number of repeated PF edges under one parent that triggers representative-edge retention "
            "(default 8)."
        ),
    )
    parser.add_argument(
        "--with-release",
        action="store_true",
        help=(
            "After the batch pipeline completes, also call "
            "results_analysis.release.build_dataset_release_v1 to export each scenario's chain/ "
            "directories from all formally successful scenarios into dataset_release_v1/. "
            "Failed or incomplete scenarios are excluded."
        ),
    )
    parser.add_argument(
        "--release-root",
        type=Path,
        default=DEFAULT_RELEASE_ROOT,
        help=(
            f"release output root (default: {DEFAULT_RELEASE_ROOT_DISPLAY}); used with --with-release."
        ),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    results_root = args.results_root.resolve()
    dry_run = args.dry_run
    only_failed = args.only_failed
    backbone_guard_threshold = args.backbone_guard_threshold
    save_attack_subgraph = args.save_attack_subgraph
    backbone_broad_gate_on_warning = args.backbone_broad_gate_on_warning
    backbone_broad_gate_relations = args.backbone_broad_gate_relations
    backbone_broad_gate_window_evt = max(0, int(args.backbone_broad_gate_window_evt))
    backbone_runtime_shell_block_representative_experiment = (
        args.backbone_runtime_shell_block_representative_experiment
    )
    backbone_runtime_shell_block_relations = args.backbone_runtime_shell_block_relations
    backbone_runtime_shell_block_min_block_edges = max(
        2,
        int(args.backbone_runtime_shell_block_min_block_edges),
    )
    backbone_runtime_shell_block_min_overlap_ratio = max(
        0.0,
        min(1.0, float(args.backbone_runtime_shell_block_min_overlap_ratio)),
    )
    backbone_runtime_shell_block_net_accept_subject_anchor_trial = (
        args.backbone_runtime_shell_block_net_accept_subject_anchor_trial
    )
    backbone_runtime_shell_block_process_fork_hybrid_gate = (
        args.backbone_runtime_shell_block_process_fork_hybrid_gate
    )
    backbone_runtime_shell_block_process_fork_hybrid_min_overlap_ratio = max(
        0.0,
        min(
            1.0,
            float(
                args.backbone_runtime_shell_block_process_fork_hybrid_min_overlap_ratio
            ),
        ),
    )
    backbone_runtime_shell_block_process_fork_hybrid_min_overlap_edges = max(
        1,
        int(
            args.backbone_runtime_shell_block_process_fork_hybrid_min_overlap_edges
        ),
    )
    backbone_runtime_shell_block_process_fork_parent_cluster_trial = (
        args.backbone_runtime_shell_block_process_fork_parent_cluster_trial
    )
    backbone_runtime_shell_block_process_fork_parent_cluster_gap_evt = max(
        1,
        int(
            args.backbone_runtime_shell_block_process_fork_parent_cluster_gap_evt
        ),
    )
    backbone_runtime_shell_block_process_fork_parent_cluster_min_subject_edges = max(
        2,
        int(
            args.backbone_runtime_shell_block_process_fork_parent_cluster_min_subject_edges
        ),
    )

    # Determine the log output directory.
    if args.log_dir:
        log_dir = args.log_dir.resolve()
    else:
        log_dir = DEFAULT_PRIVATE_OUTPUT_ROOT / "batch_full_pipeline_logs"
    log_dir.mkdir(parents=True, exist_ok=True)

    # Global timestamp used in output filenames to avoid overwriting files.
    run_ts = datetime.now().astimezone().strftime("%Y%m%d_%H%M%S")
    summary_json_path = log_dir / f"summary_{run_ts}.json"
    summary_tsv_path = log_dir / f"summary_{run_ts}.tsv"
    progress_json_path = log_dir / f"progress_{run_ts}.json"

    print(f"[batch_full_pipeline] results_root : {results_root}")
    print(f"[batch_full_pipeline] dry_run      : {dry_run}")
    print(f"[batch_full_pipeline] only_failed  : {only_failed}")
    print(f"[batch_full_pipeline] guard_threshold: {backbone_guard_threshold}")
    print(f"[batch_full_pipeline] save_attack_subgraph: {save_attack_subgraph}")
    print(f"[batch_full_pipeline] backbone_broad_gate_on_warning: {backbone_broad_gate_on_warning}")
    print(f"[batch_full_pipeline] backbone_broad_gate_relations: {backbone_broad_gate_relations}")
    print(f"[batch_full_pipeline] backbone_broad_gate_window_evt: {backbone_broad_gate_window_evt}")
    print(
        "[batch_full_pipeline] backbone_runtime_shell_block_representative_experiment: "
        f"{backbone_runtime_shell_block_representative_experiment}"
    )
    print(
        "[batch_full_pipeline] backbone_runtime_shell_block_relations: "
        f"{backbone_runtime_shell_block_relations}"
    )
    print(
        "[batch_full_pipeline] backbone_runtime_shell_block_min_block_edges: "
        f"{backbone_runtime_shell_block_min_block_edges}"
    )
    print(
        "[batch_full_pipeline] backbone_runtime_shell_block_min_overlap_ratio: "
        f"{backbone_runtime_shell_block_min_overlap_ratio}"
    )
    print(
        "[batch_full_pipeline] backbone_runtime_shell_block_net_accept_subject_anchor_trial: "
        f"{backbone_runtime_shell_block_net_accept_subject_anchor_trial}"
    )
    print(
        "[batch_full_pipeline] backbone_runtime_shell_block_process_fork_hybrid_gate: "
        f"{backbone_runtime_shell_block_process_fork_hybrid_gate}"
    )
    print(
        "[batch_full_pipeline] backbone_runtime_shell_block_process_fork_hybrid_min_overlap_ratio: "
        f"{backbone_runtime_shell_block_process_fork_hybrid_min_overlap_ratio}"
    )
    print(
        "[batch_full_pipeline] backbone_runtime_shell_block_process_fork_hybrid_min_overlap_edges: "
        f"{backbone_runtime_shell_block_process_fork_hybrid_min_overlap_edges}"
    )
    print(
        "[batch_full_pipeline] backbone_runtime_shell_block_process_fork_parent_cluster_trial: "
        f"{backbone_runtime_shell_block_process_fork_parent_cluster_trial}"
    )
    print(
        "[batch_full_pipeline] backbone_runtime_shell_block_process_fork_parent_cluster_gap_evt: "
        f"{backbone_runtime_shell_block_process_fork_parent_cluster_gap_evt}"
    )
    print(
        "[batch_full_pipeline] backbone_runtime_shell_block_process_fork_parent_cluster_min_subject_edges: "
        f"{backbone_runtime_shell_block_process_fork_parent_cluster_min_subject_edges}"
    )
    print(f"[batch_full_pipeline] log_dir      : {log_dir}")
    print(f"[batch_full_pipeline] pipeline_entry: {PIPELINE_ENTRY}")
    print()

    # ---- 1. Discover all scenarios ----
    print("[batch_full_pipeline] Scanning scenarios ...")
    all_scenes = find_latest_timestamp_dirs(results_root)
    print(f"[batch_full_pipeline] Found {len(all_scenes)} scenario timestamp directories")

    # ---- 2. Filter by prerequisites ----
    valid_scenes: list[tuple[Path, str]] = []
    skipped_scenes: list[dict] = []

    for ts_dir, rel in all_scenes:
        scene_dir = ts_dir  # ts_dir is the scenario timestamp directory.
        ok, reason = check_prerequisites(scene_dir)
        if not ok:
            skipped_scenes.append({
                "scene_rel": rel,
                "scene_path": str(scene_dir),
                "skip_reason": reason,
            })
            continue

        if only_failed:
            ok, _ = scenario_fully_succeeded(scene_dir)
            if ok:
                skipped_scenes.append({
                    "scene_rel": rel,
                    "scene_path": str(scene_dir),
                    "skip_reason": "only-failed: scenario already succeeded formally (dataset + metadata + enrich exist), skipped",
                })
                continue

        valid_scenes.append((scene_dir, rel))

    print(f"[batch_full_pipeline] Eligible scenarios: {len(valid_scenes)}")
    print(f"[batch_full_pipeline] Skipped for unmet prerequisites: {len(skipped_scenes)}")

    if dry_run:
        print()
        print("=" * 80)
        print("DRY RUN mode: no pipeline is executed; only scenarios are listed")
        print("=" * 80)
        for idx, (scene_dir, rel) in enumerate(valid_scenes, 1):
            print(f"  [{idx}/{len(valid_scenes)}] {rel}")
            print(f"           -> {scene_dir}")
        print()
        print(f"{len(valid_scenes)} scenarios are ready to process")
        return 0

    if not valid_scenes:
        print("[batch_full_pipeline] No scenarios require processing; exiting.")
        _write_outputs(log_dir, run_ts, summary_json_path, summary_tsv_path,
                       progress_json_path, [], skipped_scenes)
        return 0

    # ---- 3. Execute the pipeline per scenario ----
    print()
    banner_box(
        f"[batch][START] scenarios={len(valid_scenes)}",
        [
            f"results_root  : {results_root}",
            f"with_release  : {bool(args.with_release)}",
            f"log_dir       : {log_dir}",
        ],
        status="start",
    )
    print(f"Starting batch execution for {len(valid_scenes)} scenarios (serial, not parallel)")

    # Header: print column labels for subsequent \r overwrites.
    header = "  ".join([f"{STAGE_LABELS[s]}={'':>4}" for s in STAGE_ORDER])
    print(f"  {'':>50}  {header}")
    print(f"  {'Scenario':<50}  {'':>80}")
    print("-" * 130)
    sys.stdout.flush()
    sys.stdout.flush()

    all_results: list[dict] = []
    success_count = 0
    incomplete_count = 0
    failed_count = 0
    batch_started_at = time.time()

    def _on_stage_enter(
        stage: str,
        stage_results: dict[str, dict],
        scenario_index: int | None,
        scenario_total: int | None,
    ) -> None:
        """Update the console progress line whenever the pipeline enters a stage.

        Avoid references to undefined variables inside run_scenario:
        - run_scenario passes the scenario index and total explicitly;
        - when either is missing, fall back to an unnumbered prefix.
        """
        if scenario_index is not None and scenario_total is not None:
            prefix = f"  [{scenario_index}/{scenario_total}] "
        else:
            prefix = "  "
        _emit_stage_row(
            stage,
            stage_results,
            prefix=prefix,
            scenario_index=scenario_index,
            scenario_total=scenario_total,
        )

    for idx, (scene_dir, rel) in enumerate(valid_scenes, 1):
        # Print the scenario header.
        ts_name = scene_dir.name  # Timestamp directory name, e.g. 2026-04-09_10-38-13.
        print()
        progress_line(
            "batch",
            idx,
            len(valid_scenes),
            current=rel,
            extra={"scenarios_total": len(valid_scenes)},
        )
        stage_banner(
            "scenario",
            "start",
            scope="batch",
            scenario=rel,
            processed=idx,
            total=len(valid_scenes),
            emoji=True,
            extra={"timestamp_dir": ts_name},
        )
        print(f"  [{idx}/{len(valid_scenes)}] {rel}")
        print(f"           {ts_name}", end="", flush=True)

        # Initialize stage_results for progress callbacks.
        stage_results: dict[str, dict] = {s: {"status": "pending", "error": ""} for s in STAGE_ORDER}

        # Log file.
        safe_rel = rel.replace("/", "__").replace("\\", "__")
        scene_log = log_dir / f"scene_{safe_rel}__{run_ts}.log"

        try:
            result = run_scenario(
                scene_dir=scene_dir,
                scene_rel=rel,
                log_file=scene_log,
                backbone_guard_threshold=backbone_guard_threshold,
                save_attack_subgraph=save_attack_subgraph,
                backbone_broad_gate_on_warning=backbone_broad_gate_on_warning,
                backbone_broad_gate_relations=backbone_broad_gate_relations,
                backbone_broad_gate_window_evt=backbone_broad_gate_window_evt,
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
                backbone_runtime_shell_block_process_fork_parent_cluster_trial=(
                    backbone_runtime_shell_block_process_fork_parent_cluster_trial
                ),
                backbone_runtime_shell_block_process_fork_parent_cluster_gap_evt=(
                    backbone_runtime_shell_block_process_fork_parent_cluster_gap_evt
                ),
                backbone_runtime_shell_block_process_fork_parent_cluster_min_subject_edges=(
                    backbone_runtime_shell_block_process_fork_parent_cluster_min_subject_edges
                ),
                dry_run=False,
                on_stage_enter=_on_stage_enter,
                scenario_index=idx,
                scenario_total=len(valid_scenes),
            )
        except Exception as e:
            print(f"\n           \033[1;31m[ERROR] Scenario processing failed: {e}\033[0m")
            print(traceback.format_exc())
            result = {
                "scene_rel": rel,
                "scene_path": str(scene_dir),
                "pipeline_rc": -1,
                "stages": {},
                "dataset_generated": False,
                "dataset_meta_generated": False,
                "enrich_generated": False,
                "skipped": False,
                "skip_reason": "",
                "incomplete_reason": "",
                "elapsed_seconds": None,
                "error_summary": f"Scenario processing failed: {e}",
                "overall_status": "failed",
            }
            stage_results = {}

        all_results.append(result)

        overall = result.get("overall_status", "failed")
        if overall == "success":
            success_count += 1
        elif overall == "incomplete":
            incomplete_count += 1
        else:
            failed_count += 1

        # Print the scenario completion summary.
        _emit_scenario_summary(
            idx=idx,
            total=len(valid_scenes),
            scene_rel=rel,
            overall_status=overall,
            dataset_ok=result.get("dataset_generated", False),
            elapsed=result.get("elapsed_seconds"),
            error_summary=result.get("error_summary", ""),
        )

        # Human-readable per-scenario "done" banner with highest level reached.
        # This is a pure summary line; it does not change any on-disk state.
        try:
            release_slug = (
                release_slug_for(scene_dir) if args.with_release else None
            )
            release_root_for_level = (
                args.release_root.resolve() if args.with_release else None
            )
            scn_level = highest_level_reached(
                scene_dir,
                release_root=release_root_for_level,
                release_slug=release_slug,
            )
            result["highest_level"] = scn_level
            status_tag = (
                "ok" if overall == "success"
                else ("incomplete" if overall == "incomplete" else "fail")
            )
            stage_banner(
                "scenario",
                status_tag,
                scope="batch",
                scenario=rel,
                processed=idx,
                total=len(valid_scenes),
                emoji=True,
                extra={
                    "highest_level": scn_level,
                    "elapsed": (
                        f"{result.get('elapsed_seconds', 0):.2f}s"
                        if result.get("elapsed_seconds") is not None
                        else None
                    ),
                },
            )
        except Exception:
            # Banner must never break batch flow.
            pass

        # Write progress after each scenario for restart resilience.
        _write_progress(
            progress_json_path,
            len(valid_scenes),
            success_count,
            incomplete_count,
            failed_count,
            all_results,
        )
        emit_observation(
            "[batch_full_pipeline][progress]",
            stage="scene_loop",
            processed=idx,
            total=len(valid_scenes),
            percent=round((idx / len(valid_scenes)) * 100.0, 2),
            elapsed=round(time.time() - batch_started_at, 2),
            success=success_count,
            incomplete=incomplete_count,
            failed=failed_count,
            scenario_dir=scene_dir,
        )

    # ---- 4. Write summary ----
    print()
    print("=" * 80)
    print("Batch execution complete")
    print(f"  Formal success (dataset + metadata + enrich complete): {success_count}/{len(valid_scenes)}")
    print(f"  Incomplete (extract/enrich incomplete or interrupted by guard/skip): {incomplete_count}/{len(valid_scenes)}")
    print(f"  Failed: {failed_count}/{len(valid_scenes)}")
    print(f"  Skipped for unmet prerequisites: {len(skipped_scenes)} scenarios")
    print("=" * 80)

    # Aggregated highest-level-reached breakdown. Gives a one-line view of
    # "how many scenarios got stuck at raw/index/chain/release" after the
    # batch finishes. Uses on-disk evidence recorded above per scenario.
    level_counts = {"raw": 0, "index": 0, CHAIN_DIR_NAME: 0, "dataset_release_v1": 0, "unknown": 0}
    for r in all_results:
        lvl = r.get("highest_level") or "unknown"
        level_counts[lvl] = level_counts.get(lvl, 0) + 1
    overall_status = (
        "success" if failed_count == 0 and incomplete_count == 0
        else ("incomplete" if failed_count == 0 else "failed")
    )
    final_status_block(
        "batch",
        status=overall_status,
        stage_status={
            "success": str(success_count),
            "incomplete": str(incomplete_count),
            "failed": str(failed_count),
            "skipped_prereq": str(len(skipped_scenes)),
            "total_valid": str(len(valid_scenes)),
        },
        extra={
            "by_level": (
                f"raw={{raw}} index={{index}} {CHAIN_DIR_NAME}={{{CHAIN_DIR_NAME}}} "
                "dataset_release_v1={dataset_release_v1} unknown={unknown}"
            ).format(**level_counts),
            "results_root": str(results_root),
            "log_dir": str(log_dir),
        },
    )

    _write_outputs(log_dir, run_ts, summary_json_path, summary_tsv_path,
                   progress_json_path, all_results, skipped_scenes)

    print()
    print(f"Detailed log directory: {log_dir}")
    print(f"JSON summary : {summary_json_path}")
    print(f"TSV summary  : {summary_tsv_path}")
    print(f"Progress file: {progress_json_path}")

    release_rc = 0
    if args.with_release:
        release_rc = _run_release_export(
            all_results=all_results,
            release_root=args.release_root.resolve(),
            log_dir=log_dir,
            run_ts=run_ts,
        )

    # Return 0 when all stages succeed; return 1 for any failure or release failure.
    if failed_count != 0:
        return 1
    if args.with_release and release_rc != 0:
        return 1
    return 0


# ---------------------------------------------------------------------------
# Batch release export (called only with --with-release).
# ---------------------------------------------------------------------------

def _run_release_export(
    all_results: list[dict],
    release_root: Path,
    log_dir: Path,
    run_ts: str,
) -> int:
    """Export a release after all scenarios finish.

    Only scenario chain directories with overall_status == "success" are
    included; incomplete or failed scenarios are excluded from the release.
    """
    print()
    print("=" * 80)
    print("Starting batch dataset release export ...")
    print("=" * 80)

    success_chain_dirs: list[Path] = []
    for r in all_results:
        if r.get("overall_status") != "success":
            continue
        scene_path = r.get("scene_path") or ""
        if not scene_path:
            continue
        chain_dir = scenario_chain_dir(Path(scene_path))
        if (chain_dir / "behavior_chain_dataset.v2.json").exists():
            success_chain_dirs.append(chain_dir)

    if not success_chain_dirs:
        print("[batch_full_pipeline][release] No successful scenarios to export; skipping release build")
        return 0

    print(
        f"[batch_full_pipeline][release] Number of {CHAIN_DIR_NAME} directories to export: "
        f"{len(success_chain_dirs)}"
    )
    try:
        release_stage = _load_release_exporter()
    except Exception as exc:
        print(f"[batch_full_pipeline][release] Could not import release module: {exc!r}")
        return 1

    try:
        manifest = release_stage.build_release(
            chain_dirs=success_chain_dirs,
            release_root=release_root,
        )
    except Exception as exc:
        print(f"[batch_full_pipeline][release] build_release raised an exception: {exc!r}")
        traceback.print_exc()
        return 1

    errors = manifest.get("errors") or []
    scenario_count = manifest.get("scenario_count") or 0
    print("-" * 80)
    print(
        f"[batch_full_pipeline][release] Completed: scenario_count={scenario_count}, "
        f"errors={len(errors)}, release_root={manifest.get('release_root')}"
    )

    # Write a lightweight release summary in log_dir for batch auditing.
    try:
        release_summary_path = log_dir / f"release_summary_{run_ts}.json"
        with open(release_summary_path, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "release_root": manifest.get("release_root"),
                    "scenario_count": scenario_count,
                    "errors": errors,
                    "scenarios": [
                        {
                            "scenario_id": row.get("scenario_id"),
                            "scenario_slug": row.get("scenario_slug"),
                            "spine_edge_count": row.get("spine_edge_count"),
                        }
                        for row in (manifest.get("scenarios") or [])
                    ],
                },
                f,
                indent=2,
                ensure_ascii=False,
            )
        print(f"[batch_full_pipeline][release] release_summary: {release_summary_path}")
    except Exception as exc:
        print(f"[batch_full_pipeline][release] Could not write release_summary: {exc!r}")

    return 0 if not errors else 1


def _write_progress(
    progress_path: Path,
    total: int,
    success_count: int,
    incomplete_count: int,
    failed_count: int,
    results: list[dict],
) -> None:
    """Write the JSON progress file after each scenario completes."""
    with open(progress_path, "w", encoding="utf-8") as f:
        json.dump({
            "total": total,
            "success": success_count,
            "incomplete": incomplete_count,
            "enrich_skipped": incomplete_count,
            "failed": failed_count,
            "scenarios": results,
            "updated": datetime.now().astimezone().isoformat(),
        }, f, indent=2, ensure_ascii=False)


def _write_outputs(
    log_dir: Path,
    run_ts: str,
    summary_json_path: Path,
    summary_tsv_path: Path,
    progress_json_path: Path,
    results: list[dict],
    skipped: list[dict],
) -> None:
    """Write global summary files (JSON and TSV)."""
    # ---- JSON summary ----
    summary_json = {
        "run_timestamp": run_ts,
        "total_scenes": len(results) + len(skipped),
        "valid_scenes": len(results),
        "skipped_scenes": len(skipped),
        "success": sum(1 for r in results if r.get("overall_status") == "success"),
        "incomplete": sum(1 for r in results if r.get("overall_status") == "incomplete"),
        "enrich_skipped": sum(1 for r in results if r.get("overall_status") == "incomplete"),
        "failed": sum(1 for r in results if r.get("overall_status") == "failed"),
        "scenarios": results,
        "skipped": skipped,
    }
    with open(summary_json_path, "w", encoding="utf-8") as f:
        json.dump(summary_json, f, indent=2, ensure_ascii=False)

    # ---- TSV summary ----
    # Header: scene_rel | pipeline_rc | extract_ok | backbone_ok | enrich_ok |
    #         enrich_status | enrich_generated | dataset_ok | meta_ok |
    #         overall_status | elapsed_s | skipped | skip_reason | error_summary
    tsv_lines = [
        "scene_rel\tpipeline_rc\t"
        "extract_ok\tbackbone_ok\tenrich_ok\t"
        "enrich_status\tenrich_generated\tdataset_ok\tmeta_ok\t"
        "overall_status\tincomplete_reason\telapsed_s\t"
        "backbone_warning_present\tbackbone_warning_codes\tbackbone_warning_malicious_ratio\t"
        "backbone_warning_backbone_to_subgraph_ratio\t"
        "skipped\tskip_reason\terror_summary"
    ]
    for r in results:
        stages = r.get("stages", {})
        warning_metrics = r.get("backbone_warning_metrics") or {}
        tsv_lines.append("\t".join([
            r.get("scene_rel", ""),
            str(r.get("pipeline_rc", "")),
            "1" if stages.get("extract", {}).get("status") == "success" else "0",
            "1" if stages.get("backbone", {}).get("status") == "success" else "0",
            "1" if stages.get("enrich", {}).get("status") == "success" else "0",
            stages.get("enrich", {}).get("status", ""),
            "1" if r.get("enrich_generated") else "0",
            "1" if r.get("dataset_generated") else "0",
            "1" if r.get("dataset_meta_generated") else "0",
            r.get("overall_status", ""),
            r.get("incomplete_reason", ""),
            str(r.get("elapsed_seconds", "")),
            "1" if r.get("backbone_warning_present") else "0",
            ",".join(r.get("backbone_warning_codes") or []),
            str(warning_metrics.get("malicious_ratio", "")),
            str(warning_metrics.get("backbone_to_subgraph_ratio", "")),
            "0",  # not skipped
            r.get("skip_reason", ""),
            r.get("error_summary", ""),
        ]))
    for s in skipped:
        tsv_lines.append("\t".join([
            s.get("scene_rel", ""),
            "",
            "", "", "",
            "", "",
            "0", "0",
            "",  # empty overall_status
            "",
            "",
            "", "", "", "",
            "1",  # skipped
            s.get("skip_reason", ""),
            "",
        ]))

    with open(summary_tsv_path, "w", encoding="utf-8") as f:
        f.write("\n".join(tsv_lines))
        f.write("\n")


if __name__ == "__main__":
    raise SystemExit(main())
