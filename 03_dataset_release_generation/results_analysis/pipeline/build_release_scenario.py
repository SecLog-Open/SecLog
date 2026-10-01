#!/usr/bin/env python3
"""Single-scenario release-only entry: chain -> dataset_release_v1.

Scope and boundary:
1) This script is only for one scenario release export.
2) It does NOT run build/analyze/extract/backbone/enrich/dataset.
3) It reuses the formal release exporter logic from
   results_analysis.release.build_dataset_release_v1.

Use this when a scenario already has a valid chain/ and you only want
to (re)build its dataset_release_v1 output.

Relationship with existing entries:
* run_chain_pipeline.py --with-release: single-scenario full pipeline.
* batch_full_pipeline.py --with-release: batch full pipeline.
* build_release_all_scenarios.py: all-scenarios release-only formal entry.
* THIS FILE: single-scenario release-only formal entry.
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path
from typing import Any


SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from console_observability import (  # noqa: E402
    banner_box,
    failure_summary_block,
    final_status_block,
    highest_level_reached,
    release_slug_for,
    stage_banner,
)
from results_analysis.pipeline.build_release_all_scenarios import (  # noqa: E402
    _formal_success_failures,
)
from results_analysis.pipeline.utils.common import scenario_chain_dir


DEFAULT_RELEASE_ROOT = PROJECT_ROOT.parents[1] / "seclog_work" / "dataset_release_v1"
DEFAULT_RELEASE_ROOT_DISPLAY = "../seclog_work/dataset_release_v1"


def _single_release_root_guard_reason(release_root: Path) -> str | None:
    """Block the shared default release root for single-scenario export."""
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


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description=(
            "Single-scenario release-only formal entry: read an existing "
            "scenario chain/ and export dataset_release_v1."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    target = p.add_mutually_exclusive_group(required=True)
    target.add_argument(
        "--scenario-dir",
        type=Path,
        help=(
            "Scenario timestamp directory that already contains chain/, "
            "for example results/<scene>/<timestamp>."
        ),
    )
    target.add_argument(
        "--chain-dir",
        type=Path,
        help=(
            "Existing chain/ directory to export. Equivalent to passing "
            "its parent as --scenario-dir."
        ),
    )
    p.add_argument(
        "--release-root",
        type=Path,
        default=DEFAULT_RELEASE_ROOT,
        help=(
            f"dataset_release_v1 output root (default: {DEFAULT_RELEASE_ROOT_DISPLAY}). "
            "For single-scenario export, the shared default root is blocked; "
            "pass an explicit independent release root."
        ),
    )
    p.add_argument(
        "--scenario-id",
        default=None,
        help=(
            "Stable scenario id override, for example python-demo or "
            "vulhub/solr/CVE-2019-17558. Recommended when the input path is "
            "outside a directory named results/."
        ),
    )
    return p


def _resolve_target(args: argparse.Namespace) -> tuple[Path, Path]:
    if args.chain_dir is not None:
        chain_dir = args.chain_dir.resolve()
        scenario_dir = chain_dir.parent
    else:
        scenario_dir = args.scenario_dir.resolve()
        chain_dir = scenario_chain_dir(scenario_dir)
    return scenario_dir, chain_dir


def _build_release(chain_dir: Path, release_root: Path, scenario_id: str | None = None) -> dict[str, Any]:
    from results_analysis.release import build_dataset_release_v1 as release_stage

    return release_stage.build_release(
        chain_dirs=[chain_dir],
        release_root=release_root,
        scenario_id_overrides=(
            {str(chain_dir.resolve()): scenario_id} if scenario_id else None
        ),
    )


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    scenario_dir, chain_dir = _resolve_target(args)
    release_root = args.release_root.resolve()
    started_at = time.perf_counter()
    scenario_slug = release_slug_for(scenario_dir)

    banner_box(
        "[single-release][START] mode=single-scenario release-only",
        [
            f"scenario_dir   : {scenario_dir}",
            f"chain_dir      : {chain_dir}",
            f"release_root   : {release_root}",
            "input_scope    : existing chain/formal downstream inputs",
            "boundary       : no build/analyze/full-pipeline rerun",
        ],
        status="start",
    )

    stage_banner(
        "readiness",
        "start",
        scope="single-release",
        scenario=scenario_slug or scenario_dir.name,
        step=1,
        total_steps=2,
    )

    if not scenario_dir.exists() or not scenario_dir.is_dir():
        reason = f"scenario_dir does not exist or is not a directory: {scenario_dir}"
        failure_summary_block(
            "single-release",
            scenario=scenario_slug or scenario_dir.name,
            stage="readiness",
            reason=reason,
            category="missing_input",
            highest_level="unknown",
        )
        final_status_block(
            "single-release",
            status="failed",
            scenario=scenario_slug or scenario_dir.name,
            highest_level="unknown",
            elapsed=time.perf_counter() - started_at,
            extra={
                "scenario_dir": str(scenario_dir),
                "chain_dir": str(chain_dir),
                "release_root": str(release_root),
            },
        )
        return 1

    if chain_dir.name != "chain" or not chain_dir.exists() or not chain_dir.is_dir():
        reason = f"chain directory missing or invalid: {chain_dir}"
        failure_summary_block(
            "single-release",
            scenario=scenario_slug or scenario_dir.name,
            stage="readiness",
            reason=reason,
            category="missing_input",
            highest_level=highest_level_reached(scenario_dir),
        )
        final_status_block(
            "single-release",
            status="incomplete",
            scenario=scenario_slug or scenario_dir.name,
            highest_level=highest_level_reached(scenario_dir),
            elapsed=time.perf_counter() - started_at,
            extra={
                "scenario_dir": str(scenario_dir),
                "chain_dir": str(chain_dir),
                "release_root": str(release_root),
            },
        )
        return 2

    formal_failures = _formal_success_failures(scenario_dir)
    if formal_failures:
        stage_banner(
            "readiness",
            "incomplete",
            scope="single-release",
            scenario=scenario_slug or scenario_dir.name,
            step=1,
            total_steps=2,
            extra={"reason": formal_failures[0]},
        )
        failure_summary_block(
            "single-release",
            scenario=scenario_slug or scenario_dir.name,
            stage="readiness",
            reason=(
                "scenario does not satisfy formal chain readiness for "
                "release export"
            ),
            category="incomplete",
            highest_level=highest_level_reached(scenario_dir),
            missing=formal_failures,
        )
        final_status_block(
            "single-release",
            status="incomplete",
            scenario=scenario_slug or scenario_dir.name,
            highest_level=highest_level_reached(scenario_dir),
            elapsed=time.perf_counter() - started_at,
            stage_status={"readiness": "incomplete", "export": "not-run"},
            extra={
                "scenario_dir": str(scenario_dir),
                "chain_dir": str(chain_dir),
                "release_root": str(release_root),
            },
        )
        return 2

    stage_banner(
        "readiness",
        "ok",
        scope="single-release",
        scenario=scenario_slug or scenario_dir.name,
        step=1,
        total_steps=2,
        extra={"highest_level": highest_level_reached(scenario_dir)},
    )

    release_root_guard_reason = _single_release_root_guard_reason(release_root)
    if release_root_guard_reason:
        stage_banner(
            "release",
            "incomplete",
            scope="single-release",
            scenario=scenario_slug or scenario_dir.name,
            step=2,
            total_steps=2,
            extra={"reason": release_root_guard_reason},
        )
        failure_summary_block(
            "single-release",
            scenario=scenario_slug or scenario_dir.name,
            stage="release",
            reason=release_root_guard_reason,
            category="incomplete",
            highest_level=highest_level_reached(scenario_dir),
        )
        final_status_block(
            "single-release",
            status="incomplete",
            scenario=scenario_slug or scenario_dir.name,
            highest_level=highest_level_reached(scenario_dir),
            elapsed=time.perf_counter() - started_at,
            stage_status={"readiness": "ok", "export": "not-run"},
            extra={
                "scenario_dir": str(scenario_dir),
                "chain_dir": str(chain_dir),
                "release_root": str(release_root),
            },
        )
        return 2

    stage_banner(
        "release",
        "start",
        scope="single-release",
        scenario=scenario_slug or scenario_dir.name,
        step=2,
        total_steps=2,
        extra={"driver": "build_dataset_release_v1.build_release"},
    )

    try:
        manifest = _build_release(
            chain_dir=chain_dir,
            release_root=release_root,
            scenario_id=args.scenario_id,
        )
    except Exception as exc:
        reason = f"release exporter raised {type(exc).__name__}: {exc}"
        failure_summary_block(
            "single-release",
            scenario=scenario_slug or scenario_dir.name,
            stage="release",
            reason=reason,
            highest_level=highest_level_reached(scenario_dir),
        )
        final_status_block(
            "single-release",
            status="failed",
            scenario=scenario_slug or scenario_dir.name,
            highest_level=highest_level_reached(scenario_dir),
            elapsed=time.perf_counter() - started_at,
            stage_status={"readiness": "ok", "export": "failed"},
            extra={
                "scenario_dir": str(scenario_dir),
                "chain_dir": str(chain_dir),
                "release_root": str(release_root),
            },
        )
        return 1

    errors = manifest.get("errors") or []
    scenarios = manifest.get("scenarios") or []
    if errors or not scenarios:
        reason = (
            "release exporter reported errors or no scenarios; "
            f"errors={errors} scenario_count={len(scenarios)}"
        )
        failure_summary_block(
            "single-release",
            scenario=scenario_slug or scenario_dir.name,
            stage="release",
            reason=reason,
            highest_level=highest_level_reached(scenario_dir),
        )
        final_status_block(
            "single-release",
            status="failed",
            scenario=scenario_slug or scenario_dir.name,
            highest_level=highest_level_reached(scenario_dir),
            elapsed=time.perf_counter() - started_at,
            stage_status={"readiness": "ok", "export": "failed"},
            extra={
                "scenario_dir": str(scenario_dir),
                "chain_dir": str(chain_dir),
                "release_root": str(release_root),
            },
        )
        return 1

    row = scenarios[0]
    release_slug = str(row.get("scenario_slug") or scenario_slug or "")
    stage_banner(
        "release",
        "ok",
        scope="single-release",
        scenario=release_slug or scenario_dir.name,
        step=2,
        total_steps=2,
        extra={
            "scenario_id": row.get("scenario_id"),
            "spine_edge_count": row.get("spine_edge_count"),
        },
    )
    final_status_block(
        "single-release",
        status="success",
        scenario=release_slug or scenario_dir.name,
        highest_level=highest_level_reached(
            scenario_dir,
            release_root=release_root,
            release_slug=release_slug,
        ),
        elapsed=time.perf_counter() - started_at,
        stage_status={"readiness": "ok", "export": "ok"},
        extra={
            "scenario_dir": str(scenario_dir),
            "chain_dir": str(chain_dir),
            "release_root": str(release_root),
            "manifest": str(release_root / "manifest.json"),
        },
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
