#!/usr/bin/env python3
"""Unified runner for the raw -> behavior-chain post-processing pipeline."""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent.parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))
if str(PROJECT_ROOT) not in sys.path:
    # Keep SCRIPT_DIR first so "from utils.common" resolves pipeline/utils package,
    # not the project-root utils.py module.
    sys.path.append(str(PROJECT_ROOT))

import build_attack_chain as backbone_stage
import build_behavior_chain_instances_v0 as dataset_stage
import enrich_behavior_context_v0 as enrich_stage
import extract_audit_triples_v1_1 as extract_stage
from console_observability import (
    StageTimer,
    artifact_report,
    banner_box,
    failure_classification,
    failure_summary_block,
    final_status_block,
    highest_level_reached,
    path_exists,
    release_slug_for,
    stage_banner,
)
from utils.common import scenario_chain_dir

# Release exporter is imported lazily to avoid a hard dependency on the
# release layer for callers that never use --with-release; see
# _maybe_export_release.
DEFAULT_PRIVATE_OUTPUT_ROOT = PROJECT_ROOT.parents[1] / "seclog_work"
DEFAULT_RELEASE_ROOT = DEFAULT_PRIVATE_OUTPUT_ROOT / "dataset_release_v1"
DEFAULT_RELEASE_ROOT_DISPLAY = "../seclog_work/dataset_release_v1"


def _load_release_exporter() -> Any:
    """Load the release exporter from the public 03 release unit.

    The public release is split into independent units, so this pipeline
    loads the sibling release exporter when it is available. The source-tree
    package remains a fallback for callers that run this file in place.
    """
    public_release_module = (
        Path(__file__).resolve().parents[3]
        / "03_dataset_release_generation"
        / "results_analysis"
        / "release"
        / "build_dataset_release_v1.py"
    )
    if public_release_module.is_file():
        spec = importlib.util.spec_from_file_location(
            "seclog_public_release_build_dataset_release_v1",
            public_release_module,
        )
        if spec is None or spec.loader is None:
            raise ImportError(
                f"cannot create import spec for public release exporter: "
                f"{public_release_module}"
            )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    from results_analysis.release import build_dataset_release_v1

    return build_dataset_release_v1


def _single_release_root_guard_reason(release_root: Path) -> str | None:
    """Reject the shared default release root for single-scenario export.

    Why:
    - `build_dataset_release_v1.build_release()` rewrites `manifest.json`
      for the current invocation but does not clear pre-existing sibling
      scenario directories under `release_root/shared/scenarios/`.
    - In single-scenario mode that can leave a mixed state:
        manifest = one scenario
        on-disk scenario dirs = many old scenarios + this scenario

    Policy:
    - Single-scenario entries must export into an explicit independent
      release root.
    - Batch / all-scenarios entries may continue to use the shared
      default root.
    """
    try:
        resolved = release_root.resolve()
    except Exception:
        resolved = release_root
    if resolved == DEFAULT_RELEASE_ROOT.resolve():
        return (
            "unsafe single-scenario release export blocked: the shared "
            f"default release root ({DEFAULT_RELEASE_ROOT_DISPLAY}) may leave "
            "manifest/scenario-directory mixed state. Re-run with an "
            "explicit independent --release-root."
        )
    return None


SCENARIO_DIR: Path | None = None

BACKBONE_RUN_MODE_AUDIT = "audit"
BACKBONE_RUN_MODE_ADAPTIVE_CANDIDATE = "adaptive-candidate"
BACKBONE_RUN_MODE_RUNTIME_SHELL_BLOCK_TRIAL = "runtime-shell-block-trial"
DEFAULT_BACKBONE_RUN_MODE = BACKBONE_RUN_MODE_ADAPTIVE_CANDIDATE

GREEN_BOLD = "\033[1;32m"
YELLOW_BOLD = "\033[1;33m"
RED_BOLD = "\033[1;31m"
RESET = "\033[0m"


class IncompletePipelineError(RuntimeError):
    """Raised when the pipeline reached a known incomplete-but-nonfatal state."""


@dataclass
class StageObservation:
    name: str
    timer: StageTimer
    last_checkpoint: str


def _check_file_exists_and_nonempty(path: Path, label: str) -> None:
    if not path.exists():
        raise FileNotFoundError(
            f"[run_chain_pipeline] required file missing ({label}): {path}"
        )
    if path.stat().st_size == 0:
        raise ValueError(
            f"[run_chain_pipeline] required file is empty ({label}): {path}"
        )


# Per-stage step index (1..5). Kept at module scope so we get consistent
# "step=<i>/<N>" counters regardless of which entry branch (only_extract /
# only_backbone / only_dataset / full) is active. `_effective_steps` is a
# list of stage names that are actually going to run for the current call,
# and is populated at the top of `run_pipeline`.
_STAGE_STEP_CACHE: dict[str, tuple[int, int]] = {}


def _reset_step_cache(stages: list[str]) -> None:
    _STAGE_STEP_CACHE.clear()
    total = len(stages)
    for idx, stage in enumerate(stages, 1):
        _STAGE_STEP_CACHE[stage] = (idx, total)


def _step_for(stage: str) -> tuple[int | None, int | None]:
    item = _STAGE_STEP_CACHE.get(stage)
    if item is None:
        return None, None
    return item


def _emit_pipeline_progress(stage: str, status: str) -> None:
    step, total = _step_for(stage)
    if step is None or total in (None, 0):
        return
    if status == "start":
        done = max(0, step - 1)
    else:
        done = step
    ratio = max(0.0, min(1.0, done / total))
    width = 20
    fill = int(round(ratio * width))
    bar = "#" * fill + "-" * (width - fill)
    pct = int(round(ratio * 100))
    print(
        f"[run_chain_pipeline][PROGRESS] "
        f"{stage.upper()}={status.upper()} "
        f"({done}/{total}, {pct}%) [{bar}]"
    )


def _scenario_label(scenario_dir: Path) -> str:
    return release_slug_for(scenario_dir) or scenario_dir.name


def _print_step(title: str, scenario_dir: Path) -> None:
    """Compatibility "entering stage" line retained for log parsers."""
    print(f"[run_chain_pipeline] {title}")
    print(f"  scenario_dir={scenario_dir}")


def _print_outputs(*paths: Path) -> None:
    for path in paths:
        print(f"  output={path}")


def _banner_stage_start(stage: str, scenario_dir: Path) -> None:
    step, total = _step_for(stage)
    _emit_pipeline_progress(stage, "start")
    stage_banner(
        stage,
        "start",
        scope="pipeline",
        scenario=_scenario_label(scenario_dir),
        step=step,
        total_steps=total,
    )


def _banner_stage_ok(stage: str, scenario_dir: Path, *, elapsed: float | None = None) -> None:
    step, total = _step_for(stage)
    _emit_pipeline_progress(stage, "ok")
    extra: dict[str, Any] = {}
    if elapsed is not None:
        extra["elapsed"] = f"{elapsed:.2f}s"
    stage_banner(
        stage,
        "ok",
        scope="pipeline",
        scenario=_scenario_label(scenario_dir),
        step=step,
        total_steps=total,
        extra=extra,
    )


def _banner_stage_warn(stage: str, scenario_dir: Path, *, reason: str) -> None:
    step, total = _step_for(stage)
    _emit_pipeline_progress(stage, "warn")
    stage_banner(
        stage,
        "warn",
        scope="pipeline",
        scenario=_scenario_label(scenario_dir),
        step=step,
        total_steps=total,
        extra={"reason": reason},
    )


def _banner_stage_fail(
    stage: str,
    scenario_dir: Path,
    *,
    reason: str,
    missing: list[str] | None = None,
) -> None:
    step, total = _step_for(stage)
    _emit_pipeline_progress(stage, "fail")
    stage_banner(
        stage,
        "fail",
        scope="pipeline",
        scenario=_scenario_label(scenario_dir),
        step=step,
        total_steps=total,
        extra={"reason": reason},
    )
    failure_summary_block(
        "pipeline",
        scenario=_scenario_label(scenario_dir),
        stage=stage,
        reason=reason,
        highest_level=highest_level_reached(scenario_dir),
        missing=missing or [],
    )


def _banner_stage_incomplete(
    stage: str,
    scenario_dir: Path,
    *,
    reason: str,
    missing: list[str] | None = None,
) -> None:
    step, total = _step_for(stage)
    _emit_pipeline_progress(stage, "incomplete")
    stage_banner(
        stage,
        "incomplete",
        scope="pipeline",
        scenario=_scenario_label(scenario_dir),
        step=step,
        total_steps=total,
        extra={"reason": reason, "category": failure_classification(stage, reason)},
    )
    failure_summary_block(
        "pipeline",
        scenario=_scenario_label(scenario_dir),
        stage=stage,
        reason=reason,
        category=failure_classification(stage, reason),
        highest_level=highest_level_reached(scenario_dir),
        missing=missing or [],
    )


def _init_final_state(
    scenario_dir: Path,
    chain_dir: Path,
    *,
    skip_enrich: bool,
) -> dict[str, Any]:
    return {
        "scenario_dir": str(scenario_dir),
        "output_dir": str(chain_dir),
        "failed_stage": "unknown",
        "error": "",
        "incomplete_reason": "",
        "failure_stage_hint": "",
        "enrich_skip_reason": "",
        "skip_enrich_option": bool(skip_enrich),
        "run_scope": "full",
        "stage_status": {
            "extract": "not-run",
            "backbone": "not-run",
            "enrich": "skipped_by_option" if skip_enrich else "not-run",
            "dataset": "not-run",
        },
    }


def _record_failure_state(
    final_state: dict[str, Any],
    stage: str,
    error: str,
    *,
    stage_state: str = "failed",
) -> None:
    stage_status = final_state.get("stage_status")
    if isinstance(stage_status, dict) and stage in stage_status:
        stage_status[stage] = stage_state
    final_state["failed_stage"] = stage or "unknown"
    final_state["failure_stage_hint"] = stage or "unknown"
    final_state["error"] = str(error or "unknown")


def _record_incomplete_state(
    final_state: dict[str, Any],
    reason: str,
    *,
    stage: str | None = None,
    stage_state: str = "incomplete",
    skip_reason: str = "",
) -> None:
    final_state["incomplete_reason"] = str(reason or "")
    if stage:
        final_state["failure_stage_hint"] = stage
        stage_status = final_state.get("stage_status")
        if isinstance(stage_status, dict) and stage in stage_status:
            stage_status[stage] = stage_state
    if skip_reason:
        final_state["enrich_skip_reason"] = skip_reason


def _load_enrich_summary(chain_dir: Path) -> dict[str, Any] | None:
    summary_path = chain_dir / "behavior_context_summary.v0.json"
    if not summary_path.exists() or summary_path.stat().st_size == 0:
        return None
    try:
        with open(summary_path, "r", encoding="utf-8", errors="replace") as fh:
            obj = json.load(fh)
        if isinstance(obj, dict):
            return obj
    except Exception:
        return None
    return None


def _enrich_skipped_reason(chain_dir: Path) -> str:
    summary = _load_enrich_summary(chain_dir)
    if not summary:
        return ""
    status = str(summary.get("status") or "").strip()
    if status != "skipped":
        return ""
    skip_reason = str(summary.get("skip_reason") or "").strip()
    return skip_reason or "status=skipped"


def _is_no_unit_enrich_completed(chain_dir: Path) -> tuple[bool, str]:
    summary = _load_enrich_summary(chain_dir)
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


def _formal_success_failures(chain_dir: Path) -> list[str]:
    reasons: list[str] = []
    skipped_reason = _enrich_skipped_reason(chain_dir)
    if skipped_reason:
        reasons.append(f"enrich was marked as skipped: {skipped_reason}")

    no_unit_ok, _ = _is_no_unit_enrich_completed(chain_dir)
    required_files = [
        (chain_dir / "behavior_chain_dataset.v2.json", "dataset file is missing or empty"),
        (chain_dir / "behavior_chain_dataset.v2.meta.json", "dataset metadata file is missing or empty"),
        (
            chain_dir / "behavior_context_edges.v0.jsonl",
            "enrich output behavior_context_edges.v0.jsonl is missing or empty",
        ),
    ]
    for path, reason in required_files:
        if path.name == "behavior_context_edges.v0.jsonl" and no_unit_ok:
            continue
        if not path.exists() or path.stat().st_size == 0:
            reasons.append(reason)
    return reasons


def _enrich_output_state(chain_dir: Path) -> str:
    summary = _load_enrich_summary(chain_dir)
    if not summary:
        return ""
    output_state = summary.get("output_state") if isinstance(summary.get("output_state"), dict) else {}
    return str(output_state.get("behavior_context_edges") or "")


def _is_full_pipeline_success(final_state: dict[str, Any]) -> bool:
    stage_status = final_state.get("stage_status")
    if not isinstance(stage_status, dict):
        return False

    if str(final_state.get("run_scope") or "") != "full":
        return False

    if stage_status.get("extract") != "success":
        return False
    if stage_status.get("backbone") != "success":
        return False
    if stage_status.get("dataset") != "success":
        return False

    if bool(final_state.get("skip_enrich_option")):
        return stage_status.get("enrich") == "skipped_by_option"
    return stage_status.get("enrich") == "success"


def _final_extras(final_state: dict[str, Any]) -> dict[str, Any]:
    extras: dict[str, Any] = {}
    scenario_dir = final_state.get("scenario_dir")
    if scenario_dir:
        extras["scenario_dir"] = scenario_dir
    output_dir = final_state.get("output_dir")
    if output_dir:
        extras["output_dir"] = output_dir
    release_status = final_state.get("release_export_status")
    if release_status:
        extras["release"] = release_status
        slug = final_state.get("release_scenario_slug")
        if slug:
            extras["release_scenario_slug"] = slug
        rroot = final_state.get("release_root")
        if rroot:
            extras["release_root"] = rroot
    return extras


def _final_highest_level(final_state: dict[str, Any]) -> str:
    scenario_dir = final_state.get("scenario_dir")
    if not scenario_dir:
        return "unknown"
    release_root = final_state.get("release_root")
    slug = final_state.get("release_scenario_slug")
    return highest_level_reached(
        scenario_dir,
        release_root=release_root,
        release_slug=slug,
    )


def _print_final_success_block(final_state: dict[str, Any]) -> None:
    stage_status = final_state.get("stage_status") or {}
    print("RUN_CHAIN_PIPELINE_FINAL_STATUS=SUCCESS")
    final_status_block(
        "pipeline",
        status="success",
        scenario=final_state.get("scenario_dir"),
        highest_level=_final_highest_level(final_state),
        stage_status=dict(stage_status),
        extra=_final_extras(final_state),
    )


def _print_final_failure_block(final_state: dict[str, Any]) -> None:
    stage_status = final_state.get("stage_status") or {}
    print("RUN_CHAIN_PIPELINE_FINAL_STATUS=FAILED")
    extras = _final_extras(final_state)
    if final_state.get("failed_stage"):
        extras["failed_stage"] = final_state.get("failed_stage")
    if final_state.get("error"):
        extras["error"] = final_state.get("error")
    final_status_block(
        "pipeline",
        status="failed",
        scenario=final_state.get("scenario_dir"),
        highest_level=_final_highest_level(final_state),
        stage_status=dict(stage_status),
        extra=extras,
    )


def _print_final_incomplete_block(final_state: dict[str, Any]) -> None:
    stage_status = final_state.get("stage_status") or {}
    print("RUN_CHAIN_PIPELINE_FINAL_STATUS=INCOMPLETE")
    extras = _final_extras(final_state)
    if final_state.get("incomplete_reason"):
        extras["incomplete_reason"] = final_state.get("incomplete_reason")
    final_status_block(
        "pipeline",
        status="incomplete",
        scenario=final_state.get("scenario_dir"),
        highest_level=_final_highest_level(final_state),
        stage_status=dict(stage_status),
        extra=extras,
    )


def _resolve_attack_subgraph_export(
    save_attack_subgraph: bool,
    skip_save_attack_subgraph: bool,
) -> tuple[bool, str]:
    if save_attack_subgraph:
        if skip_save_attack_subgraph:
            return True, "both flags set; --save-attack-subgraph takes precedence"
        return True, "enabled by --save-attack-subgraph"
    if skip_save_attack_subgraph:
        return False, "compatibility flag --skip-save-attack-subgraph (default already no-export)"
    return False, "default policy: in-memory intermediate only"


def _resolve_backbone_refinement_mode(
    run_mode: str,
    *,
    backbone_broad_gate_on_warning: bool,
    backbone_broad_gate_fork_repeat_sparse_experiment: bool,
    backbone_broad_gate_net_accept_repeat_sparse_experiment: bool,
    backbone_runtime_shell_block_representative_experiment: bool,
    backbone_broad_gate_fork_parent_cluster_experiment: bool = False,
) -> tuple[str, bool, bool, bool, bool, bool, bool, str]:
    """Return (mode, gate_on_warning, fork_sparse, net_accept_sparse,
    runtime_shell_trial, fork_parent_cluster, planner_mode, note).

    planner_mode=True means the conditional-triggered planner is invoked
    inside derive_backbone_chain; planner_mode=False means trial flags
    pass through verbatim (used for audit and runtime-shell-block-trial).
    """
    mode = str(run_mode or "").strip().lower()
    if mode == BACKBONE_RUN_MODE_AUDIT:
        return (
            BACKBONE_RUN_MODE_AUDIT,
            False,
            False,
            False,
            False,
            False,
            False,
            "audit mode: warning-only observation, no automatic refinement, planner bypassed",
        )

    if mode == BACKBONE_RUN_MODE_RUNTIME_SHELL_BLOCK_TRIAL:
        return (
            BACKBONE_RUN_MODE_RUNTIME_SHELL_BLOCK_TRIAL,
            True,
            True,
            True,
            True,
            True,
            False,
            (
                "runtime-shell-block-trial mode: force A+B+C on for ablation "
                "study; planner bypassed"
            ),
        )

    if mode != BACKBONE_RUN_MODE_ADAPTIVE_CANDIDATE:
        print(
            "[run_chain_pipeline] WARNING: unknown run mode "
            f"{run_mode}; fallback to {BACKBONE_RUN_MODE_ADAPTIVE_CANDIDATE}"
        )

    # adaptive-candidate: planner_mode=True. The planner inside
    # derive_backbone_chain makes the final A/B/C decision from structural
    # evidence; the umbrella runtime-shell / parent-cluster experiment
    # flags are NOT forced on here - the planner flips them on as needed
    # based on plan decisions. This way, an incoming True on those flags
    # unambiguously reflects user intent (explicit CLI flag) and is
    # correctly recorded as a user override inside the planner.
    return (
        BACKBONE_RUN_MODE_ADAPTIVE_CANDIDATE,
        True,
        True,
        True,
        bool(backbone_runtime_shell_block_representative_experiment),
        bool(backbone_broad_gate_fork_parent_cluster_experiment),
        True,  # planner_mode
        (
            "adaptive-candidate mode: warning-triggered refinement with "
            "conditional planner auto-selecting A / B / C; explicit trial "
            "CLI flags are treated as user overrides"
        ),
    )


def _start_stage(
    stage_name: str,
    scenario_dir: Path,
    *,
    output_path: Path | None = None,
    input_path: Path | None = None,
    core_inputs: dict[str, Any] | None = None,
) -> StageObservation:
    timer = StageTimer(
        stage_name,
        prefix="[run_chain_pipeline][stage]",
        base_fields={
            "scenario_dir": scenario_dir,
            "output_path": output_path,
            "input_path": input_path,
        },
    )
    timer.start(**(core_inputs or {}))
    last_checkpoint = str(input_path or scenario_dir)
    return StageObservation(name=stage_name, timer=timer, last_checkpoint=last_checkpoint)


def _finish_stage(
    observation: StageObservation,
    *,
    status: str = "done",
    outputs: dict[str, Any] | None = None,
    extra: dict[str, Any] | None = None,
) -> None:
    payload: dict[str, Any] = {}
    if outputs:
        payload.update(outputs)
    if extra:
        payload.update(extra)
    observation.timer.done(status=status, **payload)


def _fail_stage(
    observation: StageObservation,
    exc: BaseException | str,
    *,
    failing_step: str,
    extra: dict[str, Any] | None = None,
) -> None:
    payload = {
        "failing_step": failing_step,
        "last_checkpoint": observation.last_checkpoint,
    }
    if extra:
        payload.update(extra)
    observation.timer.fail(exc, **payload)


def _normalize_optional_unit_token(raw: Any) -> str | None:
    if raw is None:
        return None
    text = str(raw).strip()
    if not text or text.lower() == "null":
        return None
    return text


def _inspect_unit_inputs(index_dir: Path) -> tuple[str, str, dict[str, Any]]:
    unit_event_path = index_dir / "unit_event_index.jsonl"
    unit_index_path = index_dir / "unit_index.jsonl"

    diag: dict[str, Any] = {
        "unit_event_exists": unit_event_path.exists(),
        "unit_index_exists": unit_index_path.exists(),
        "unit_event_total_lines": 0,
        "unit_event_nonnull_seen": False,
        "unit_event_invalid_json_lines": 0,
        "unit_index_nonempty": False,
    }

    if not diag["unit_event_exists"] and not diag["unit_index_exists"]:
        return "unit-unavailable", "unit_event_index_missing+unit_index_missing", diag
    if not diag["unit_event_exists"]:
        return "unit-unavailable", "unit_event_index_missing", diag
    if not diag["unit_index_exists"]:
        return "unit-unavailable", "unit_index_missing", diag

    with open(unit_event_path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except Exception:
                diag["unit_event_invalid_json_lines"] += 1
                continue
            diag["unit_event_total_lines"] += 1
            unit_key = _normalize_optional_unit_token(row.get("unit_key"))
            unit_id = _normalize_optional_unit_token(row.get("unit_id"))
            if unit_key is not None or unit_id is not None:
                diag["unit_event_nonnull_seen"] = True
                break

    with open(unit_index_path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if line.strip():
                diag["unit_index_nonempty"] = True
                break

    if int(diag["unit_event_total_lines"]) == 0:
        return "unit-absent", "unit_event_index_empty", diag
    if not bool(diag["unit_event_nonnull_seen"]):
        return "unit-absent", "unit_event_index_all_null", diag
    if not bool(diag["unit_index_nonempty"]):
        return "unit-absent", "unit_index_empty_after_filter", diag

    return "unit-ready", "unit_index_and_event_nonnull_present", diag


def _check_enrich_outputs(
    scenario_dir: Path,
    summary_path: Path,
    context_edges_path: Path,
    anchor_index_path: Path,
) -> None:
    if not summary_path.exists():
        raise FileNotFoundError(
            f"[run_chain_pipeline] enrich summary missing: {summary_path}"
        )

    with open(summary_path, "r", encoding="utf-8", errors="replace") as fh:
        summary = json.load(fh)

    status = str(summary.get("status") or "").strip()
    backbone_edge_count = int(summary.get("backbone_edge_count") or 0)
    unit_mode = str(summary.get("unit_mode") or "")
    unit_mode_reason = str(summary.get("unit_mode_reason") or "")
    output_state = summary.get("output_state") if isinstance(summary.get("output_state"), dict) else {}
    context_output_state = str(output_state.get("behavior_context_edges") or "")
    anchor_output_state = str(output_state.get("event_to_backbone_anchor_index") or "")
    no_unit_mode = unit_mode in {"unit-absent", "unit-unavailable"}
    allow_no_unit_sparse_outputs = (
        status == "completed"
        and no_unit_mode
        and context_output_state == "empty_not_written"
    )

    if status == "skipped":
        skip_reason = str(summary.get("skip_reason") or "")
        # Distinguish a guard skip from an explicit skip and report the cause.
        if "backbone_guard_threshold_exceeded" in skip_reason:
            raise IncompletePipelineError(
                "[run_chain_pipeline] enrich skipped by guard (backbone edges exceed threshold) — "
                "context_edges not produced; this is an expected incomplete state"
            )
        elif skip_reason == "explicit_skip_enrich":
            raise IncompletePipelineError(
                "[run_chain_pipeline] enrich explicitly skipped via --skip-enrich flag — "
                "context_edges not produced; this is an expected incomplete state"
            )
        else:
            raise IncompletePipelineError(
                f"[run_chain_pipeline] enrich status=skipped (reason={skip_reason or 'unknown'}) — "
                "context_edges not produced; this run is INCOMPLETE and NOT formal success"
            )

    if not context_edges_path.exists():
        if allow_no_unit_sparse_outputs:
            print(
                "[run_chain_pipeline] enrich completed in no-unit mode with empty context output; "
                f"unit_mode={unit_mode} reason={unit_mode_reason or 'unknown'}"
            )
            return
        if status == "completed":
            raise IncompletePipelineError(
                "[run_chain_pipeline] enrich completed but produced no behavior_context_edges; "
                "this run is INCOMPLETE and NOT formal success"
            )
        raise FileNotFoundError(
            f"[run_chain_pipeline] enrich context output missing: {context_edges_path}"
        )

    if context_edges_path.stat().st_size == 0:
        if allow_no_unit_sparse_outputs:
            print(
                "[run_chain_pipeline] enrich emitted empty context file in no-unit mode; "
                f"unit_mode={unit_mode} reason={unit_mode_reason or 'unknown'}"
            )
            return
        raise IncompletePipelineError(
            "[run_chain_pipeline] enrich produced an empty behavior_context_edges file; "
            "this run is INCOMPLETE and NOT formal success"
        )

    if not anchor_index_path.exists():
        if allow_no_unit_sparse_outputs and anchor_output_state == "empty_not_written":
            return
        raise FileNotFoundError(
            "[run_chain_pipeline] enrich produced behavior_context_edges but missing "
            f"event_to_backbone_anchor_index: {anchor_index_path}"
        )

    if anchor_index_path.exists() and anchor_index_path.stat().st_size == 0:
        if allow_no_unit_sparse_outputs:
            return
        raise ValueError(
            "[run_chain_pipeline] event_to_backbone_anchor_index is empty: "
            f"{anchor_index_path}"
        )

    print(
        "[run_chain_pipeline] enrich standard outputs ready: "
        f"anchor_index={anchor_index_path.exists()} "
        f"context_edges={context_edges_path.exists()} "
        f"backbone_edge_count={backbone_edge_count}"
    )


def _maybe_export_release(
    scenario_dir: Path,
    chain_dir: Path,
    *,
    release_root: Path,
    final_state: dict[str, Any],
) -> int:
    """Export this scenario into dataset_release_v1/. Returns 0 on success.

    Pure downstream: reads chain/ products, writes the per-scenario
    release tree plus the top-level manifest for this one scenario.
    Never mutates chain/. Called only after the main pipeline has
    reported formal success.
    """
    try:
        release_stage = _load_release_exporter()
    except Exception as exc:  # pragma: no cover - import failure path
        print(
            "[run_chain_pipeline] release export FAILED: "
            f"cannot import release exporter: {exc!r}"
        )
        final_state["release_export_status"] = "import_failed"
        final_state["release_export_error"] = repr(exc)
        return 1

    stage_obs = _start_stage(
        "release",
        scenario_dir,
        output_path=release_root,
        input_path=chain_dir,
        core_inputs={
            "chain_exists": path_exists(chain_dir),
            "dataset_exists": path_exists(chain_dir / "behavior_chain_dataset.v2.json"),
            "backbone_exists": path_exists(chain_dir / "backbone_chain.v1.json"),
            "release_root": str(release_root),
        },
    )
    try:
        manifest = release_stage.build_release(
            chain_dirs=[chain_dir],
            release_root=release_root.resolve(),
        )
    except Exception as exc:
        _fail_stage(
            stage_obs,
            exc,
            failing_step="release_stage.build_release",
        )
        final_state["release_export_status"] = "failed"
        final_state["release_export_error"] = f"{type(exc).__name__}: {exc}"
        print(f"[run_chain_pipeline] release export FAILED: {exc!r}")
        _banner_stage_fail(
            "release",
            scenario_dir,
            reason=f"release_stage.build_release raised {type(exc).__name__}: {exc}",
        )
        return 1

    errors = manifest.get("errors") or []
    scenarios = manifest.get("scenarios") or []
    if errors or not scenarios:
        _fail_stage(
            stage_obs,
            "release exporter reported errors or no scenarios",
            failing_step="release_stage.build_release",
            extra={"errors": errors, "scenario_count": len(scenarios)},
        )
        final_state["release_export_status"] = "failed"
        final_state["release_export_error"] = f"errors={errors}"
        print(
            f"[run_chain_pipeline] release export FAILED: errors={errors}"
        )
        _banner_stage_fail(
            "release",
            scenario_dir,
            reason=(
                "release exporter reported errors or no scenarios; "
                f"errors={errors} scenario_count={len(scenarios)}"
            ),
        )
        return 1

    row = scenarios[0]
    final_state["release_export_status"] = "success"
    final_state["release_scenario_slug"] = row.get("scenario_slug")
    final_state["release_scenario_id"] = row.get("scenario_id")
    final_state["release_root"] = str(release_root.resolve())
    _finish_stage(
        stage_obs,
        outputs={
            "release_root": str(release_root.resolve()),
            "scenario_slug": row.get("scenario_slug"),
            "spine_edge_count": row.get("spine_edge_count"),
        },
    )
    _banner_stage_ok("release", scenario_dir, elapsed=stage_obs.timer.elapsed())
    _release_slug = row.get("scenario_slug") or ""
    _release_root = release_root.resolve()
    _scenario_release_dir = _release_root / "shared" / "scenarios" / _release_slug
    artifact_report(
        "pipeline",
        "release",
        [
            {"path": _scenario_release_dir / "main_sample.json",
             "label": "dataset_release_v1/shared/scenarios/<slug>/main_sample.json"},
            {"path": _scenario_release_dir / "narrative_roles.v0.json",
             "label": "dataset_release_v1/shared/scenarios/<slug>/narrative_roles.v0.json"},
            {"path": _scenario_release_dir / "stage_labels.v0.json",
             "label": "dataset_release_v1/shared/scenarios/<slug>/stage_labels.v0.json"},
        ],
    )
    print(
        "[run_chain_pipeline] release exported: "
        f"scenario_id={row.get('scenario_id')} "
        f"slug={row.get('scenario_slug')} "
        f"spine={row.get('spine_edge_count')} "
        f"root={release_root}"
    )
    return 0


def run_pipeline(
    scenario_dir: Path,
    run_mode: str = DEFAULT_BACKBONE_RUN_MODE,
    skip_enrich: bool = False,
    only_extract: bool = False,
    only_backbone: bool = False,
    only_dataset: bool = False,
    save_attack_subgraph: bool = False,
    skip_save_attack_subgraph: bool = False,
    backbone_file_label_low_info: bool = False,
    backbone_file_label_vendor_composer: bool = False,
    backbone_broad_gate_on_warning: bool = False,
    backbone_broad_gate_relations: str = "NET_RECV,NET_SEND,PROCESS_FORK",
    backbone_broad_gate_window_evt: int = 12,
    backbone_broad_gate_fork_repeat_sparse_experiment: bool = False,
    backbone_broad_gate_fork_repeat_unknown_child_stride: int = 80,
    backbone_broad_gate_net_accept_repeat_sparse_experiment: bool = False,
    backbone_broad_gate_net_accept_repeat_stride: int = 80,
    backbone_runtime_shell_block_representative_experiment: bool = False,
    backbone_runtime_shell_block_relations: str = "PROCESS_FORK,NET_ACCEPT",
    backbone_runtime_shell_block_min_block_edges: int = 8,
    backbone_runtime_shell_block_min_overlap_ratio: float = 1.0,
    backbone_runtime_shell_block_net_accept_subject_anchor_trial: bool = False,
    backbone_runtime_shell_block_process_fork_hybrid_gate: bool = False,
    backbone_runtime_shell_block_process_fork_hybrid_min_overlap_ratio: float = 0.45,
    backbone_runtime_shell_block_process_fork_hybrid_min_overlap_edges: int = 6,
    backbone_broad_gate_fork_parent_cluster_experiment: bool = False,
    backbone_broad_gate_fork_parent_cluster_gap_evt: int = 5000,
    backbone_broad_gate_fork_parent_cluster_min_subject_edges: int = 8,
    backbone_preparation_shell_trial: bool = False,
    backbone_guard_threshold: int = 5000,
    with_release: bool = False,
    release_root: Path | None = None,
    final_state: dict[str, Any] | None = None,
) -> int:
    chain_dir = scenario_chain_dir(scenario_dir)
    if final_state is None:
        final_state = {}
    final_state.clear()
    final_state.update(
        _init_final_state(
            scenario_dir=scenario_dir,
            chain_dir=chain_dir,
            skip_enrich=skip_enrich,
        )
    )
    stage_status = final_state["stage_status"]

    # Compute the list of stages that will actually run for this invocation
    # so that every stage banner can print a stable "step=i/N" counter.
    if only_extract:
        _planned_stages = ["extract"]
    elif only_backbone:
        _planned_stages = ["backbone"]
    elif only_dataset:
        _planned_stages = ["dataset"]
    else:
        _planned_stages = ["extract", "backbone"]
        if not skip_enrich:
            _planned_stages.append("enrich")
        _planned_stages.append("dataset")
        if with_release:
            _planned_stages.append("release")
    _reset_step_cache(_planned_stages)

    banner_box(
        f"[pipeline][START] scenario={_scenario_label(scenario_dir)}",
        [
            f"mode          : single",
            f"stages        : {' -> '.join(_planned_stages)}",
            f"chain_dir     : {chain_dir}",
        ],
        status="start",
    )

    (
        effective_run_mode,
        effective_backbone_broad_gate_on_warning,
        effective_backbone_broad_gate_fork_repeat_sparse_experiment,
        effective_backbone_broad_gate_net_accept_repeat_sparse_experiment,
        effective_backbone_runtime_shell_block_trial,
        effective_backbone_broad_gate_fork_parent_cluster_experiment,
        effective_backbone_refinement_planner_mode,
        mode_note,
    ) = _resolve_backbone_refinement_mode(
        run_mode,
        backbone_broad_gate_on_warning=backbone_broad_gate_on_warning,
        backbone_broad_gate_fork_repeat_sparse_experiment=(
            backbone_broad_gate_fork_repeat_sparse_experiment
        ),
        backbone_broad_gate_net_accept_repeat_sparse_experiment=(
            backbone_broad_gate_net_accept_repeat_sparse_experiment
        ),
        backbone_runtime_shell_block_representative_experiment=(
            backbone_runtime_shell_block_representative_experiment
        ),
        backbone_broad_gate_fork_parent_cluster_experiment=(
            backbone_broad_gate_fork_parent_cluster_experiment
        ),
    )

    print(
        "[run_chain_pipeline] backbone_run_mode="
        f"{effective_run_mode} | {mode_note}"
    )
    print(
        "[run_chain_pipeline] effective_refinement_flags="
        f"gate_on_warning={effective_backbone_broad_gate_on_warning}, "
        f"fork_sparse={effective_backbone_broad_gate_fork_repeat_sparse_experiment}, "
        f"net_accept_sparse={effective_backbone_broad_gate_net_accept_repeat_sparse_experiment}, "
        f"runtime_shell_block_trial={effective_backbone_runtime_shell_block_trial}, "
        f"fork_parent_cluster={effective_backbone_broad_gate_fork_parent_cluster_experiment}, "
        f"planner_mode={effective_backbone_refinement_planner_mode}"
    )

    save_subgraph_output, subgraph_export_reason = _resolve_attack_subgraph_export(
        save_attack_subgraph=save_attack_subgraph,
        skip_save_attack_subgraph=skip_save_attack_subgraph,
    )

    if only_dataset:
        final_state["run_scope"] = "only-dataset"
        _print_step("dataset builder only", scenario_dir)
        _banner_stage_start("dataset", scenario_dir)
        stage_obs = _start_stage(
            "dataset",
            scenario_dir,
            output_path=chain_dir,
            input_path=chain_dir / "behavior_context_edges.v0.jsonl",
            core_inputs={
                "backbone_exists": path_exists(chain_dir / "backbone_chain.v1.json"),
                "context_edges_exists": path_exists(chain_dir / "behavior_context_edges.v0.jsonl"),
            },
        )
        rc = dataset_stage.run_for_scenario(scenario_dir=scenario_dir)
        if rc != 0:
            _record_failure_state(final_state, "dataset", f"dataset rc={rc}")
            _fail_stage(stage_obs, f"dataset rc={rc}", failing_step="dataset_stage.run_for_scenario")
            _banner_stage_fail("dataset", scenario_dir, reason=f"dataset rc={rc}")
            return rc
        stage_status["dataset"] = "success"
        _finish_stage(
            stage_obs,
            outputs={
                "dataset_exists": path_exists(chain_dir / "behavior_chain_dataset.v2.json"),
                "dataset_meta_exists": path_exists(chain_dir / "behavior_chain_dataset.v2.meta.json"),
            },
        )
        _banner_stage_ok("dataset", scenario_dir, elapsed=stage_obs.timer.elapsed())
        artifact_report(
            "pipeline",
            "dataset",
            [
                {"path": chain_dir / "behavior_chain_dataset.v2.json",
                 "label": "behavior_chain_dataset.v2.json"},
                {"path": chain_dir / "behavior_chain_dataset.v2.meta.json",
                 "label": "behavior_chain_dataset.v2.meta.json"},
                {"path": chain_dir / "backbone_broad_warning.v0.json",
                 "label": "backbone_broad_warning.v0.json",
                 "optional": True,
                 "note": "only written when a broad-backbone warning fires"},
            ],
        )
        _print_outputs(
            chain_dir / "behavior_chain_dataset.v2.json",
            chain_dir / "behavior_chain_dataset.v2.meta.json",
            chain_dir / "backbone_broad_warning.v0.json",
        )
        return rc

    if only_backbone:
        final_state["run_scope"] = "only-backbone"
        _print_step("backbone builder only", scenario_dir)
        _banner_stage_start("backbone", scenario_dir)
        stage_obs = _start_stage(
            "backbone",
            scenario_dir,
            output_path=chain_dir,
            input_path=chain_dir / "audit_triples.core.v1.jsonl",
            core_inputs={
                "triples_exists": path_exists(chain_dir / "audit_triples.core.v1.jsonl"),
                "unit_event_index_exists": path_exists(chain_dir.parent / "index" / "unit_event_index.jsonl"),
                "unit_index_exists": path_exists(chain_dir.parent / "index" / "unit_index.jsonl"),
                "run_mode": effective_run_mode,
                "gate_on_warning": effective_backbone_broad_gate_on_warning,
                "fork_sparse": effective_backbone_broad_gate_fork_repeat_sparse_experiment,
                "net_accept_sparse": effective_backbone_broad_gate_net_accept_repeat_sparse_experiment,
                "runtime_shell_block_trial": effective_backbone_runtime_shell_block_trial,
                "fork_parent_cluster": effective_backbone_broad_gate_fork_parent_cluster_experiment,
            },
        )
        rc = backbone_stage.run_for_scenario(
            scenario_dir=scenario_dir,
            save_attack_subgraph=save_attack_subgraph,
            skip_save_attack_subgraph=skip_save_attack_subgraph,
            backbone_file_label_low_info=backbone_file_label_low_info,
            backbone_file_label_vendor_composer=backbone_file_label_vendor_composer,
            backbone_broad_gate_on_warning=effective_backbone_broad_gate_on_warning,
            backbone_broad_gate_relations=backbone_broad_gate_relations,
            backbone_broad_gate_window_evt=backbone_broad_gate_window_evt,
            backbone_broad_gate_fork_repeat_sparse_experiment=(
                effective_backbone_broad_gate_fork_repeat_sparse_experiment
            ),
            backbone_broad_gate_fork_repeat_unknown_child_stride=(
                backbone_broad_gate_fork_repeat_unknown_child_stride
            ),
            backbone_broad_gate_net_accept_repeat_sparse_experiment=(
                effective_backbone_broad_gate_net_accept_repeat_sparse_experiment
            ),
            backbone_broad_gate_net_accept_repeat_stride=(
                backbone_broad_gate_net_accept_repeat_stride
            ),
            backbone_runtime_shell_block_representative_experiment=(
                effective_backbone_runtime_shell_block_trial
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
            backbone_broad_gate_fork_parent_cluster_experiment=(
                effective_backbone_broad_gate_fork_parent_cluster_experiment
            ),
            backbone_broad_gate_fork_parent_cluster_gap_evt=(
                backbone_broad_gate_fork_parent_cluster_gap_evt
            ),
            backbone_broad_gate_fork_parent_cluster_min_subject_edges=(
                backbone_broad_gate_fork_parent_cluster_min_subject_edges
            ),
            backbone_refinement_planner_mode=(
                effective_backbone_refinement_planner_mode
            ),
            backbone_preparation_shell_trial=bool(
                backbone_preparation_shell_trial
            ),
        )
        if rc != 0:
            _record_failure_state(final_state, "backbone", f"backbone rc={rc}")
            _fail_stage(stage_obs, f"backbone rc={rc}", failing_step="backbone_stage.run_for_scenario")
            _banner_stage_fail("backbone", scenario_dir, reason=f"backbone rc={rc}")
            return rc
        # Verify that the backbone artifact exists; only-backbone is a debug mode
        # and should report this state explicitly.
        _check_file_exists_and_nonempty(chain_dir / "backbone_chain.v1.json", "backbone_chain.v1.json")
        stage_status["backbone"] = "success"
        _banner_stage_ok("backbone", scenario_dir, elapsed=stage_obs.timer.elapsed())
        artifact_report(
            "pipeline",
            "backbone",
            [
                {"path": chain_dir / "backbone_chain.v1.json",
                 "label": "backbone_chain.v1.json"},
                {"path": chain_dir / "attack_subgraph.v1.json",
                 "label": "attack_subgraph.v1.json",
                 "optional": not save_subgraph_output,
                 "note": subgraph_export_reason},
            ],
        )
        _finish_stage(
            stage_obs,
            outputs={
                "attack_subgraph_exists": path_exists(chain_dir / "attack_subgraph.v1.json"),
                "backbone_exists": path_exists(chain_dir / "backbone_chain.v1.json"),
            },
            extra={
                "save_attack_subgraph": save_subgraph_output,
                "attack_subgraph_export_reason": subgraph_export_reason,
                "backbone_run_mode": effective_run_mode,
                "backbone_mode_note": mode_note,
                "backbone_gate_on_warning": effective_backbone_broad_gate_on_warning,
                "backbone_fork_sparse": effective_backbone_broad_gate_fork_repeat_sparse_experiment,
                "backbone_net_accept_sparse": (
                    effective_backbone_broad_gate_net_accept_repeat_sparse_experiment
                ),
                "backbone_runtime_shell_block_trial": (
                    effective_backbone_runtime_shell_block_trial
                ),
            },
        )
        if save_subgraph_output:
            print(f"[run_chain_pipeline] attack_subgraph export enabled ({subgraph_export_reason})")
            _print_outputs(
                chain_dir / "attack_subgraph.v1.json",
                chain_dir / "backbone_chain.v1.json",
            )
        else:
            print(
                "[run_chain_pipeline] attack_subgraph built in memory; "
                f"file export disabled ({subgraph_export_reason})"
            )
            _print_outputs(chain_dir / "backbone_chain.v1.json")
        return rc

    _print_step("extract audit triples", scenario_dir)
    _banner_stage_start("extract", scenario_dir)
    extract_obs = _start_stage(
        "extract",
        scenario_dir,
        output_path=chain_dir,
        input_path=scenario_dir / "raw" / "sysdig",
        core_inputs={
            "raw_sysdig_exists": path_exists(scenario_dir / "raw" / "sysdig"),
            "rules_exists": path_exists(extract_stage.RULES_FILE),
        },
    )
    rc = extract_stage.run_for_scenario(scenario_dir=scenario_dir)
    if rc != 0:
        _record_failure_state(final_state, "extract", f"extract rc={rc}")
        _fail_stage(extract_obs, f"extract rc={rc}", failing_step="extract_stage.run_for_scenario")
        _banner_stage_fail(
            "extract",
            scenario_dir,
            reason=f"extract rc={rc}",
            missing=[
                str(scenario_dir / "raw" / "sysdig") + " (required)",
            ] if not (scenario_dir / "raw" / "sysdig").exists() else [],
        )
        return rc
    stage_status["extract"] = "success"
    _finish_stage(
        extract_obs,
        outputs={
            "core_triples_exists": path_exists(chain_dir / "audit_triples.core.v1.jsonl"),
            "tier_manifest_exists": path_exists(chain_dir / "audit_triples_tier_manifest.v1.json"),
        },
    )
    _banner_stage_ok("extract", scenario_dir, elapsed=extract_obs.timer.elapsed())
    artifact_report(
        "pipeline",
        "extract",
        [
            {"path": chain_dir / "audit_triples.core.v1.jsonl",
             "label": "audit_triples.core.v1.jsonl"},
            {"path": chain_dir / "audit_triples.auxiliary.v1.jsonl",
             "label": "audit_triples.auxiliary.v1.jsonl"},
            {"path": chain_dir / "audit_triples.filtered.v1.jsonl",
             "label": "audit_triples.filtered.v1.jsonl"},
            {"path": chain_dir / "audit_triples.unknown.v1.jsonl",
             "label": "audit_triples.unknown.v1.jsonl"},
            {"path": chain_dir / "audit_triples_tier_manifest.v1.json",
             "label": "audit_triples_tier_manifest.v1.json"},
        ],
    )
    _print_outputs(
        chain_dir / "audit_triples.core.v1.jsonl",
        chain_dir / "audit_triples.auxiliary.v1.jsonl",
        chain_dir / "audit_triples.filtered.v1.jsonl",
        chain_dir / "audit_triples.unknown.v1.jsonl",
    )

    if only_extract:
        final_state["run_scope"] = "only-extract"
        return 0

    _print_step("build attack_subgraph/backbone", scenario_dir)
    _banner_stage_start("backbone", scenario_dir)
    backbone_obs = _start_stage(
        "backbone",
        scenario_dir,
        output_path=chain_dir,
        input_path=chain_dir / "audit_triples.core.v1.jsonl",
        core_inputs={
            "triples_exists": path_exists(chain_dir / "audit_triples.core.v1.jsonl"),
            "unit_event_index_exists": path_exists(chain_dir.parent / "index" / "unit_event_index.jsonl"),
            "unit_index_exists": path_exists(chain_dir.parent / "index" / "unit_index.jsonl"),
            "run_mode": effective_run_mode,
            "gate_on_warning": effective_backbone_broad_gate_on_warning,
            "fork_sparse": effective_backbone_broad_gate_fork_repeat_sparse_experiment,
            "net_accept_sparse": effective_backbone_broad_gate_net_accept_repeat_sparse_experiment,
            "runtime_shell_block_trial": effective_backbone_runtime_shell_block_trial,
            "fork_parent_cluster": effective_backbone_broad_gate_fork_parent_cluster_experiment,
        },
    )
    rc = backbone_stage.run_for_scenario(
        scenario_dir=scenario_dir,
        save_attack_subgraph=save_attack_subgraph,
        skip_save_attack_subgraph=skip_save_attack_subgraph,
        backbone_file_label_low_info=backbone_file_label_low_info,
        backbone_file_label_vendor_composer=backbone_file_label_vendor_composer,
        backbone_broad_gate_on_warning=effective_backbone_broad_gate_on_warning,
        backbone_broad_gate_relations=backbone_broad_gate_relations,
        backbone_broad_gate_window_evt=backbone_broad_gate_window_evt,
        backbone_broad_gate_fork_repeat_sparse_experiment=(
            effective_backbone_broad_gate_fork_repeat_sparse_experiment
        ),
        backbone_broad_gate_fork_repeat_unknown_child_stride=(
            backbone_broad_gate_fork_repeat_unknown_child_stride
        ),
        backbone_broad_gate_net_accept_repeat_sparse_experiment=(
            effective_backbone_broad_gate_net_accept_repeat_sparse_experiment
        ),
        backbone_broad_gate_net_accept_repeat_stride=(
            backbone_broad_gate_net_accept_repeat_stride
        ),
        backbone_runtime_shell_block_representative_experiment=(
            effective_backbone_runtime_shell_block_trial
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
        backbone_broad_gate_fork_parent_cluster_experiment=(
            effective_backbone_broad_gate_fork_parent_cluster_experiment
        ),
        backbone_broad_gate_fork_parent_cluster_gap_evt=(
            backbone_broad_gate_fork_parent_cluster_gap_evt
        ),
        backbone_broad_gate_fork_parent_cluster_min_subject_edges=(
            backbone_broad_gate_fork_parent_cluster_min_subject_edges
        ),
        backbone_refinement_planner_mode=(
            effective_backbone_refinement_planner_mode
        ),
        backbone_preparation_shell_trial=bool(
            backbone_preparation_shell_trial
        ),
    )
    if rc != 0:
        _record_failure_state(final_state, "backbone", f"backbone rc={rc}")
        _fail_stage(backbone_obs, f"backbone rc={rc}", failing_step="backbone_stage.run_for_scenario")
        _banner_stage_fail(
            "backbone",
            scenario_dir,
            reason=f"backbone rc={rc}",
            missing=(
                [str(chain_dir / "audit_triples.core.v1.jsonl") + " (required)"]
                if not (chain_dir / "audit_triples.core.v1.jsonl").exists()
                else []
            ),
        )
        return rc
    stage_status["backbone"] = "success"
    unit_mode, unit_reason, unit_diag = _inspect_unit_inputs(chain_dir.parent / "index")
    backbone_obs.last_checkpoint = str(chain_dir / "backbone_chain.v1.json")
    print(
        f"[run_chain_pipeline] unit_mode={unit_mode} reason={unit_reason} diagnostics={unit_diag}"
    )
    _finish_stage(
        backbone_obs,
        outputs={
            "attack_subgraph_exists": path_exists(chain_dir / "attack_subgraph.v1.json"),
            "backbone_exists": path_exists(chain_dir / "backbone_chain.v1.json"),
        },
        extra={
            "unit_mode": unit_mode,
            "save_attack_subgraph": save_subgraph_output,
            "attack_subgraph_export_reason": subgraph_export_reason,
            "backbone_run_mode": effective_run_mode,
            "backbone_mode_note": mode_note,
            "backbone_gate_on_warning": effective_backbone_broad_gate_on_warning,
            "backbone_fork_sparse": effective_backbone_broad_gate_fork_repeat_sparse_experiment,
            "backbone_net_accept_sparse": (
                effective_backbone_broad_gate_net_accept_repeat_sparse_experiment
            ),
            "backbone_runtime_shell_block_trial": (
                effective_backbone_runtime_shell_block_trial
            ),
        },
    )
    _banner_stage_ok("backbone", scenario_dir, elapsed=backbone_obs.timer.elapsed())
    artifact_report(
        "pipeline",
        "backbone",
        [
            {"path": chain_dir / "backbone_chain.v1.json",
             "label": "backbone_chain.v1.json"},
            {"path": chain_dir / "attack_subgraph.v1.json",
             "label": "attack_subgraph.v1.json",
             "optional": not save_subgraph_output,
             "note": subgraph_export_reason},
            {"path": chain_dir / "backbone_broad_warning.v0.json",
             "label": "backbone_broad_warning.v0.json",
             "optional": True,
             "note": "only written when a broad-backbone warning fires"},
        ],
    )
    if save_subgraph_output:
        print(f"[run_chain_pipeline] attack_subgraph export enabled ({subgraph_export_reason})")
        _print_outputs(
            chain_dir / "attack_subgraph.v1.json",
            chain_dir / "backbone_chain.v1.json",
        )
    else:
        print(
            "[run_chain_pipeline] attack_subgraph built in memory; "
            f"file export disabled ({subgraph_export_reason})"
        )
        _print_outputs(chain_dir / "backbone_chain.v1.json")

    if not skip_enrich:
        _print_step("enrich malicious non-core context", scenario_dir)
        _banner_stage_start("enrich", scenario_dir)
        enrich_summary_path = chain_dir / "behavior_context_summary.v0.json"
        context_edges_path = chain_dir / "behavior_context_edges.v0.jsonl"
        anchor_index_path = chain_dir.parent / "index" / "event_to_backbone_anchor_index.v0.jsonl"
        enrich_obs = _start_stage(
            "enrich",
            scenario_dir,
            output_path=chain_dir,
            input_path=chain_dir / "backbone_chain.v1.json",
            core_inputs={
                "backbone_exists": path_exists(chain_dir / "backbone_chain.v1.json"),
                "auxiliary_exists": path_exists(chain_dir / "audit_triples.auxiliary.v1.jsonl"),
                "unit_event_index_exists": path_exists(chain_dir.parent / "index" / "unit_event_index.jsonl"),
            },
        )
        rc = enrich_stage.run_for_scenario(
            scenario_dir=scenario_dir,
            backbone_guard_threshold=backbone_guard_threshold,
        )
        if rc != 0:
            _record_failure_state(final_state, "enrich", f"enrich rc={rc}")
            _fail_stage(enrich_obs, f"enrich rc={rc}", failing_step="enrich_stage.run_for_scenario")
            _banner_stage_fail("enrich", scenario_dir, reason=f"enrich rc={rc}")
            return rc
        try:
            _check_enrich_outputs(
                scenario_dir=scenario_dir,
                summary_path=enrich_summary_path,
                context_edges_path=context_edges_path,
                anchor_index_path=anchor_index_path,
            )
        except IncompletePipelineError as exc:
            _fail_stage(
                enrich_obs,
                exc,
                failing_step="check_enrich_outputs",
                extra={
                    "summary_exists": path_exists(enrich_summary_path),
                    "context_edges_exists": path_exists(context_edges_path),
                    "anchor_index_exists": path_exists(anchor_index_path),
                },
            )
            _record_incomplete_state(
                final_state,
                str(exc),
                stage="enrich",
                stage_state="incomplete",
            )
            _banner_stage_incomplete(
                "enrich",
                scenario_dir,
                reason=str(exc),
                missing=[
                    str(context_edges_path) if not context_edges_path.exists() else None,
                    str(anchor_index_path) if not anchor_index_path.exists() else None,
                ] if not context_edges_path.exists() or not anchor_index_path.exists() else [],
            )
            print(str(exc))
            return 2
        stage_status["enrich"] = "success"
        _finish_stage(
            enrich_obs,
            outputs={
                "summary_exists": path_exists(enrich_summary_path),
                "context_edges_exists": path_exists(context_edges_path),
                "anchor_index_exists": path_exists(anchor_index_path),
            },
        )
        _banner_stage_ok("enrich", scenario_dir, elapsed=enrich_obs.timer.elapsed())
        no_unit_ok, no_unit_reason = _is_no_unit_enrich_completed(chain_dir)
        artifact_report(
            "pipeline",
            "enrich",
            [
                {"path": context_edges_path,
                 "label": "behavior_context_edges.v0.jsonl",
                 "optional": no_unit_ok,
                 "note": (
                     f"empty_not_written in no-unit mode ({no_unit_reason})"
                     if no_unit_ok
                     else None
                 )},
                {"path": enrich_summary_path,
                 "label": "behavior_context_summary.v0.json"},
                {"path": anchor_index_path,
                 "label": "event_to_backbone_anchor_index.v0.jsonl",
                 "optional": no_unit_ok,
                 "note": (
                     f"empty_not_written in no-unit mode ({no_unit_reason})"
                     if no_unit_ok
                     else None
                 )},
                {"path": chain_dir / "behavior_context_unmatched.v0.jsonl",
                 "label": "behavior_context_unmatched.v0.jsonl",
                 "optional": True,
                 "note": "only written when unmatched applog rows exist"},
            ],
        )
        _print_outputs(
            context_edges_path,
            chain_dir / "behavior_context_unmatched.v0.jsonl",
            enrich_summary_path,
            anchor_index_path,
        )
    else:
        print(
            "[run_chain_pipeline] WARNING: enrich explicitly skipped (--skip-enrich) — "
            "this run is INCOMPLETE and will NOT proceed to dataset"
        )
        _record_incomplete_state(
            final_state,
            "enrich skipped by option (--skip-enrich)",
            stage="enrich",
            stage_state="skipped_by_option",
            skip_reason="explicit_skip_enrich",
        )
        _banner_stage_warn(
            "enrich",
            scenario_dir,
            reason="skipped by option (--skip-enrich) — controlled_skip",
        )
        return 2

    _print_step("build behavior chain dataset", scenario_dir)
    _banner_stage_start("dataset", scenario_dir)
    dataset_obs = _start_stage(
        "dataset",
        scenario_dir,
        output_path=chain_dir,
        input_path=chain_dir / "behavior_context_edges.v0.jsonl",
        core_inputs={
            "backbone_exists": path_exists(chain_dir / "backbone_chain.v1.json"),
            "context_edges_exists": path_exists(chain_dir / "behavior_context_edges.v0.jsonl"),
        },
    )
    rc = dataset_stage.run_for_scenario(scenario_dir=scenario_dir)
    if rc != 0:
        _record_failure_state(final_state, "dataset", f"dataset rc={rc}")
        _fail_stage(dataset_obs, f"dataset rc={rc}", failing_step="dataset_stage.run_for_scenario")
        _banner_stage_fail("dataset", scenario_dir, reason=f"dataset rc={rc}")
        return rc
    stage_status["dataset"] = "success"
    _finish_stage(
        dataset_obs,
        outputs={
            "dataset_exists": path_exists(chain_dir / "behavior_chain_dataset.v2.json"),
            "dataset_meta_exists": path_exists(chain_dir / "behavior_chain_dataset.v2.meta.json"),
        },
    )
    _banner_stage_ok("dataset", scenario_dir, elapsed=dataset_obs.timer.elapsed())
    artifact_report(
        "pipeline",
        "dataset",
        [
            {"path": chain_dir / "behavior_chain_dataset.v2.json",
             "label": "behavior_chain_dataset.v2.json"},
            {"path": chain_dir / "behavior_chain_dataset.v2.meta.json",
             "label": "behavior_chain_dataset.v2.meta.json"},
            {"path": chain_dir / "backbone_broad_warning.v0.json",
             "label": "backbone_broad_warning.v0.json",
             "optional": True,
             "note": "only written when a broad-backbone warning fires"},
        ],
    )
    _print_outputs(
        chain_dir / "behavior_chain_dataset.v2.json",
        chain_dir / "behavior_chain_dataset.v2.meta.json",
        chain_dir / "backbone_broad_warning.v0.json",
    )
    final_state["failed_stage"] = "unknown"
    final_state["error"] = ""

    if with_release:
        # run_scope stays "full" so formal-success reporting still applies;
        # release status is tracked independently under release_export_status.
        effective_release_root = Path(release_root) if release_root else DEFAULT_RELEASE_ROOT
        release_root_guard_reason = _single_release_root_guard_reason(
            effective_release_root
        )
        if release_root_guard_reason:
            final_state["release_export_status"] = "blocked_unsafe_shared_root"
            final_state["release_export_error"] = release_root_guard_reason
            final_state["failed_stage"] = "release"
            final_state["error"] = release_root_guard_reason
            final_state["incomplete_reason"] = release_root_guard_reason
            print(
                "[run_chain_pipeline] release export BLOCKED: "
                f"{release_root_guard_reason}"
            )
            _banner_stage_fail(
                "release",
                scenario_dir,
                reason=release_root_guard_reason,
            )
            return 2
        _print_step("export dataset_release_v1", scenario_dir)
        _banner_stage_start("release", scenario_dir)
        rc_release = _maybe_export_release(
            scenario_dir=scenario_dir,
            chain_dir=chain_dir,
            release_root=effective_release_root,
            final_state=final_state,
        )
        if rc_release != 0:
            # Keep pipeline rc success (full chain succeeded) but surface the
            # release-export failure in final_state so main() reports it.
            final_state["failed_stage"] = "release"
            final_state["error"] = (
                final_state.get("release_export_error")
                or "release export failed"
            )
            return rc_release
    return 0


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the raw->behavior-chain post-processing pipeline")
    parser.add_argument(
        "--scenario-dir",
        type=Path,
        default=SCENARIO_DIR,
        help=(
            "Scenario timestamp directory that already contains raw/index "
            "inputs, for example results/<slug>/<timestamp>. "
            "Please pass --scenario-dir <path> explicitly."
        ),
    )
    parser.add_argument(
        "--run-mode",
        type=str,
        choices=[
            BACKBONE_RUN_MODE_AUDIT,
            BACKBONE_RUN_MODE_ADAPTIVE_CANDIDATE,
            BACKBONE_RUN_MODE_RUNTIME_SHELL_BLOCK_TRIAL,
        ],
        default=DEFAULT_BACKBONE_RUN_MODE,
        help=(
            "Backbone mode: audit=warning-only (no refinement), "
            "adaptive-candidate=warning-triggered candidate refinement package, "
            "runtime-shell-block-trial=adaptive package + runtime shell representative trial"
        ),
    )
    parser.add_argument(
        "--audit-mode",
        action="store_true",
        help="Explicit rollback entry: force run-mode=audit",
    )
    parser.add_argument("--skip-enrich", action="store_true")
    parser.add_argument("--only-extract", action="store_true")
    parser.add_argument("--only-backbone", action="store_true")
    parser.add_argument("--only-dataset", action="store_true")
    parser.add_argument(
        "--save-attack-subgraph",
        action="store_true",
        help="Explicitly write attack_subgraph.v1.json (default: disabled)",
    )
    parser.add_argument(
        "--skip-save-attack-subgraph",
        action="store_true",
        help=(
            "Compatibility flag for old callers. Default is already no export; "
            "if --save-attack-subgraph is also set, save takes precedence"
        ),
    )
    parser.add_argument("--backbone-file-label-low-info", action="store_true")
    parser.add_argument("--backbone-file-label-vendor-composer", action="store_true")
    parser.add_argument("--backbone-broad-gate-on-warning", action="store_true")
    parser.add_argument(
        "--backbone-broad-gate-relations",
        type=str,
        default="NET_RECV,NET_SEND,PROCESS_FORK",
    )
    parser.add_argument("--backbone-broad-gate-window-evt", type=int, default=12)
    parser.add_argument(
        "--backbone-broad-gate-fork-repeat-sparse-experiment",
        action="store_true",
        help=(
            "Experiment switch: sparsify repeated "
            "non-malicious unknown-child PROCESS_FORK edges"
        ),
    )
    parser.add_argument(
        "--backbone-broad-gate-fork-repeat-unknown-child-stride",
        type=int,
        default=80,
        help="Sparse stride for repeated unknown-child PROCESS_FORK experiment",
    )
    parser.add_argument(
        "--backbone-broad-gate-net-accept-repeat-sparse-experiment",
        action="store_true",
        help="Experiment switch: sparsify repeated non-malicious NET_ACCEPT edges",
    )
    parser.add_argument(
        "--backbone-broad-gate-net-accept-repeat-stride",
        type=int,
        default=80,
        help="Sparse stride for repeated non-malicious NET_ACCEPT experiment",
    )
    parser.add_argument(
        "--backbone-runtime-shell-block-representative-experiment",
        action="store_true",
        help=(
            "Enable post-backbone runtime shell representative trial "
            "(PROCESS_FORK/NET_ACCEPT by default)"
        ),
    )
    parser.add_argument(
        "--backbone-runtime-shell-block-relations",
        type=str,
        default="PROCESS_FORK,NET_ACCEPT",
        help="Comma-separated relations for runtime shell representative trial",
    )
    parser.add_argument(
        "--backbone-runtime-shell-block-min-block-edges",
        type=int,
        default=8,
        help="Minimum runtime shell block size for representative trial",
    )
    parser.add_argument(
        "--backbone-runtime-shell-block-min-overlap-ratio",
        type=float,
        default=1.0,
        help="Minimum overlap ratio (0~1) to treat runtime block as intrusive",
    )
    parser.add_argument(
        "--backbone-runtime-shell-block-net-accept-subject-anchor-trial",
        action="store_true",
        help=(
            "Directed trial A (mongo-express style): re-aggregate NET_ACCEPT "
            "blocks at subject level in the trial view only so that per-conn "
            "single-edge chunks can form a cohesive trial block. The exported "
            "runtime_shell_block_summary.v0.jsonl sidecar is unchanged."
        ),
    )
    parser.add_argument(
        "--backbone-runtime-shell-block-process-fork-hybrid-gate",
        action="store_true",
        help=(
            "Directed trial B (pgadmin style): enable ratio + absolute "
            "overlap hybrid gate for PROCESS_FORK target blocks in the "
            "trial view only. Uniform min-overlap-ratio remains in effect "
            "for non-PROCESS_FORK relations."
        ),
    )
    parser.add_argument(
        "--backbone-runtime-shell-block-process-fork-hybrid-min-overlap-ratio",
        type=float,
        default=0.45,
        help=(
            "Directed trial B: minimum overlap ratio for PROCESS_FORK hybrid "
            "gate (used only when the hybrid gate is enabled)"
        ),
    )
    parser.add_argument(
        "--backbone-runtime-shell-block-process-fork-hybrid-min-overlap-edges",
        type=int,
        default=6,
        help=(
            "Directed trial B: minimum absolute overlap edge count for "
            "PROCESS_FORK hybrid gate (used only when the hybrid gate is "
            "enabled)"
        ),
    )
    parser.add_argument(
        "--backbone-runtime-shell-block-process-fork-parent-cluster-trial",
        action="store_true",
        help=(
            "Directed trial C: treat repeated PROCESS_FORK bursts from the "
            "same parent process as a runtime-shell cluster and keep only "
            "stage-boundary representative edges (first/last/middle) plus "
            "any PF edge whose forked child later enters the malicious "
            "process set. Auto-enabled in runtime-shell-block-trial run mode; "
            "respects --backbone-broad-gate-on-warning."
        ),
    )
    parser.add_argument(
        "--backbone-runtime-shell-block-process-fork-parent-cluster-gap-evt",
        type=int,
        default=5000,
        help=(
            "Trial C: event-number gap used to split a parent-process PF "
            "stream into clusters (default: 5000)"
        ),
    )
    parser.add_argument(
        "--backbone-runtime-shell-block-process-fork-parent-cluster-min-subject-edges",
        type=int,
        default=8,
        help=(
            "Trial C: minimum repeated PF edges from a single parent before "
            "parent-cluster representative retention activates (default: 8)"
        ),
    )
    parser.add_argument(
        "--backbone-preparation-shell-trial",
        action="store_true",
        help=(
            "Trial D (preparation-phase startup shell): collapse a single "
            "subject's pre-malicious PROCESS_FORK/PROCESS_EXEC burst down "
            "to boundary markers (start/end/entry-bridge/optional mid). "
            "Orthogonal to A/B/C. Opt-in across all run_modes: explicit "
            "user override that always wins over the planner. audit / "
            "adaptive-candidate / runtime-shell-block-trial never force "
            "this flag on during the first-round rollout."
        ),
    )
    parser.add_argument("--backbone-guard-threshold", type=int, default=5000,
                        help="Auto-skip enrich when backbone exceeds this edge count (0=disable)")
    parser.add_argument(
        "--with-release",
        action="store_true",
        help=(
            "After the full pipeline succeeds, also export this scenario into "
            "dataset_release_v1/ via the public stage-03 release exporter. "
            "No-op when the pipeline did not reach dataset stage."
        ),
    )
    parser.add_argument(
        "--release-root",
        type=Path,
        default=DEFAULT_RELEASE_ROOT,
        help=(
            f"Release output root (default: {DEFAULT_RELEASE_ROOT_DISPLAY}). "
            "Only used when --with-release is set. In single-scenario "
            "mode, the shared default root is blocked; pass an explicit "
            "independent release root instead."
        ),
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.scenario_dir is None:
        print("[ERROR] missing required scenario input. Please pass --scenario-dir <path>.")
        return 1
    only_flags = [args.only_extract, args.only_backbone, args.only_dataset]
    if sum(bool(flag) for flag in only_flags) > 1:
        print("[ERROR] only one of --only-extract / --only-backbone / --only-dataset may be set")
        return 1

    effective_run_mode = BACKBONE_RUN_MODE_AUDIT if args.audit_mode else args.run_mode
    final_state = _init_final_state(
        scenario_dir=args.scenario_dir,
        chain_dir=scenario_chain_dir(args.scenario_dir),
        skip_enrich=args.skip_enrich,
    )

    try:
        rc = run_pipeline(
            scenario_dir=args.scenario_dir,
            run_mode=effective_run_mode,
            skip_enrich=args.skip_enrich,
            only_extract=args.only_extract,
            only_backbone=args.only_backbone,
            only_dataset=args.only_dataset,
            save_attack_subgraph=args.save_attack_subgraph,
            skip_save_attack_subgraph=args.skip_save_attack_subgraph,
            backbone_file_label_low_info=args.backbone_file_label_low_info,
            backbone_file_label_vendor_composer=args.backbone_file_label_vendor_composer,
            backbone_broad_gate_on_warning=args.backbone_broad_gate_on_warning,
            backbone_broad_gate_relations=args.backbone_broad_gate_relations,
            backbone_broad_gate_window_evt=max(0, int(args.backbone_broad_gate_window_evt)),
            backbone_broad_gate_fork_repeat_sparse_experiment=(
                args.backbone_broad_gate_fork_repeat_sparse_experiment
            ),
            backbone_broad_gate_fork_repeat_unknown_child_stride=max(
                1,
                int(args.backbone_broad_gate_fork_repeat_unknown_child_stride),
            ),
            backbone_broad_gate_net_accept_repeat_sparse_experiment=(
                args.backbone_broad_gate_net_accept_repeat_sparse_experiment
            ),
            backbone_broad_gate_net_accept_repeat_stride=max(
                1,
                int(args.backbone_broad_gate_net_accept_repeat_stride),
            ),
            backbone_runtime_shell_block_representative_experiment=(
                args.backbone_runtime_shell_block_representative_experiment
            ),
            backbone_runtime_shell_block_relations=args.backbone_runtime_shell_block_relations,
            backbone_runtime_shell_block_min_block_edges=max(
                2,
                int(args.backbone_runtime_shell_block_min_block_edges),
            ),
            backbone_runtime_shell_block_min_overlap_ratio=max(
                0.0,
                min(1.0, float(args.backbone_runtime_shell_block_min_overlap_ratio)),
            ),
            backbone_runtime_shell_block_net_accept_subject_anchor_trial=(
                args.backbone_runtime_shell_block_net_accept_subject_anchor_trial
            ),
            backbone_runtime_shell_block_process_fork_hybrid_gate=(
                args.backbone_runtime_shell_block_process_fork_hybrid_gate
            ),
            backbone_runtime_shell_block_process_fork_hybrid_min_overlap_ratio=max(
                0.0,
                min(
                    1.0,
                    float(
                        args.backbone_runtime_shell_block_process_fork_hybrid_min_overlap_ratio
                    ),
                ),
            ),
            backbone_runtime_shell_block_process_fork_hybrid_min_overlap_edges=max(
                1,
                int(
                    args.backbone_runtime_shell_block_process_fork_hybrid_min_overlap_edges
                ),
            ),
            backbone_broad_gate_fork_parent_cluster_experiment=(
                args.backbone_runtime_shell_block_process_fork_parent_cluster_trial
            ),
            backbone_broad_gate_fork_parent_cluster_gap_evt=max(
                1,
                int(
                    args.backbone_runtime_shell_block_process_fork_parent_cluster_gap_evt
                ),
            ),
            backbone_broad_gate_fork_parent_cluster_min_subject_edges=max(
                2,
                int(
                    args.backbone_runtime_shell_block_process_fork_parent_cluster_min_subject_edges
                ),
            ),
            backbone_preparation_shell_trial=bool(
                getattr(args, "backbone_preparation_shell_trial", False)
            ),
            backbone_guard_threshold=args.backbone_guard_threshold,
            with_release=bool(getattr(args, "with_release", False)),
            release_root=getattr(args, "release_root", None),
            final_state=final_state,
        )
    except Exception as exc:
        if not final_state.get("failed_stage") or final_state.get("failed_stage") == "unknown":
            final_state["failed_stage"] = "unknown"
        final_state["error"] = f"{type(exc).__name__}: {exc}"
        _print_final_failure_block(final_state)
        raise

    chain_dir = scenario_chain_dir(args.scenario_dir)
    formal_success_missing = _formal_success_failures(chain_dir)
    formal_success_ok = (
        rc == 0
        and not formal_success_missing
        and str(final_state.get("run_scope") or "") == "full"
    )

    incomplete_reason = str(final_state.get("incomplete_reason") or "")
    if not incomplete_reason:
        if rc == 2:
            enrich_skip_reason = str(final_state.get("enrich_skip_reason") or "")
            failure_stage_hint = str(final_state.get("failure_stage_hint") or "").strip()
            if enrich_skip_reason:
                incomplete_reason = f"enrich skipped: {enrich_skip_reason or 'unknown'}"
            elif failure_stage_hint:
                incomplete_reason = f"{failure_stage_hint} incomplete (pipeline_rc=2)"
            else:
                incomplete_reason = "pipeline incomplete (pipeline_rc=2)"
        elif _enrich_output_state(chain_dir) == "empty_not_written":
            incomplete_reason = "enrich completed but produced no behavior_context_edges output"
    if incomplete_reason:
        final_state["incomplete_reason"] = incomplete_reason

    if formal_success_ok:
        _print_final_success_block(final_state)
    elif final_state.get("incomplete_reason"):
        _print_final_incomplete_block(final_state)
    else:
        stage_status = final_state.get("stage_status") if isinstance(final_state.get("stage_status"), dict) else {}
        failed_stages = [s for s, st in stage_status.items() if st == "failed"]

        if failed_stages:
            error_summary = f"Failed stages: {', '.join(failed_stages)}"
            if not final_state.get("failed_stage") or final_state.get("failed_stage") == "unknown":
                final_state["failed_stage"] = failed_stages[0]
        elif final_state.get("error"):
            error_summary = str(final_state.get("error"))
        elif rc != 0:
            error_summary = (
                f"pipeline_rc={rc}, but no failed stage was identified (wrapper or external interruption possible)"
            )
        elif formal_success_missing:
            error_summary = "; ".join(formal_success_missing)
        else:
            error_summary = "Unknown error (rc=0 and no failed stage was identified)"

        final_state["error"] = error_summary
        _print_final_failure_block(final_state)

    return rc


if __name__ == "__main__":
    raise SystemExit(main())
