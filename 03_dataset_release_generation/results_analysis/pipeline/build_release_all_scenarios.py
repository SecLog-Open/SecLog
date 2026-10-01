#!/usr/bin/env python3
"""All-scenarios release-only entry: chain -> dataset_release_v1.

Scope and boundary:
1) This script is only for all-scenarios release export.
2) It does NOT run build/analyze/extract/backbone/enrich/dataset.
3) It reuses the formal release exporter logic from
   results_analysis.release.build_dataset_release_v1.

Use this when you already have scenario timestamp dirs under results/ and
want to (re)build dataset_release_v1 for all scenarios in one command.

Relationship with existing entries:
* run_chain_pipeline.py --with-release: single-scenario full pipeline.
* batch_full_pipeline.py --with-release: batch full pipeline.
* run_full_to_release.py --batch: wrapper for batch full pipeline.
* THIS FILE: all-scenarios release-only formal entry.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any


SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from console_observability import (
    banner_box,
    failure_summary_block,
    final_status_block,
    highest_level_reached,
    progress_line,
    stage_banner,
)
from results_analysis.pipeline.utils.common import CHAIN_DIR_NAME, scenario_chain_dir


DEFAULT_RESULTS_ROOT = PROJECT_ROOT.parent / "01_dataset_construction" / "results"
DEFAULT_RESULTS_ROOT_DISPLAY = "../01_dataset_construction/results"
DEFAULT_RELEASE_ROOT = PROJECT_ROOT.parents[1] / "seclog_work" / "dataset_release_v1"
DEFAULT_RELEASE_ROOT_DISPLAY = "../seclog_work/dataset_release_v1"
TIMESTAMP_DIR_RE = re.compile(r"^\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}$")

PHASE_ORDER = ["scan", "selection", "export"]
PHASE_LABELS = {
    "scan": "SCAN",
    "selection": "SELECT",
    "export": "EXPORT",
}


@dataclass
class ScenarioSnapshot:
    scene_dir: Path
    scene_rel: str
    chain_dir: Path
    formal_failure_reasons: list[str]


def _progress_bar(ratio: float, width: int = 16) -> str:
    ratio = max(0.0, min(1.0, ratio))
    fill = int(round(width * ratio))
    return "#" * fill + "-" * (width - fill)


def _emit_phase_dashboard(
    phase: str,
    scan_done: int,
    scan_total: int,
    export_done: int,
    export_total: int,
) -> None:
    states: dict[str, str] = {}
    for p in PHASE_ORDER:
        if phase == "done":
            states[p] = "OK"
            continue
        if p == "scan":
            if scan_total == 0:
                states[p] = "----"
            elif phase == "scan":
                states[p] = "RUN"
            else:
                states[p] = "OK"
            continue
        if p == "selection":
            if phase == "selection":
                states[p] = "RUN"
            elif phase in {"export", "done"}:
                states[p] = "OK"
            else:
                states[p] = "..."
            continue
        if export_total == 0 and phase in {"scan", "selection"}:
            states[p] = "..."
        elif phase == "export":
            states[p] = "RUN"
        elif phase == "done":
            states[p] = "OK"
        else:
            states[p] = "..."

    if phase == "scan" and scan_total > 0:
        stage_ratio = scan_done / scan_total
        total_ratio = (scan_done / scan_total) / 3.0
    elif phase == "selection":
        stage_ratio = 1.0
        total_ratio = 1.0 / 3.0
    elif phase == "export":
        stage_ratio = (export_done / export_total) if export_total > 0 else 1.0
        total_ratio = (2.0 / 3.0) + (stage_ratio / 3.0)
    else:
        stage_ratio = 1.0
        total_ratio = 1.0

    parts = [f"{PHASE_LABELS[p]}={states[p]:<4}" for p in PHASE_ORDER]
    line = (
        "[all-release][PROGRESS] "
        + "  ".join(parts)
        + f"  | STAGE [{_progress_bar(stage_ratio)}] {int(round(stage_ratio * 100)):>3d}%"
        + f"  TOTAL [{_progress_bar(total_ratio)}] {int(round(total_ratio * 100)):>3d}%"
    )
    print(f"\r{line}", end="", flush=True)


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description=(
            "All-scenarios release-only formal entry: read existing scenario "
            "chain inputs and export dataset_release_v1."
        )
    )
    p.add_argument(
        "--results-root",
        type=Path,
        default=DEFAULT_RESULTS_ROOT,
        help=f"results root to scan latest scenario timestamp dirs (default: {DEFAULT_RESULTS_ROOT_DISPLAY})",
    )
    p.add_argument(
        "--release-root",
        type=Path,
        default=DEFAULT_RELEASE_ROOT,
        help=f"dataset_release_v1 output root (default: {DEFAULT_RELEASE_ROOT_DISPLAY})",
    )
    return p


def _find_latest_timestamp_dirs(root: Path) -> list[tuple[Path, str]]:
    ts_dirs: list[Path] = []
    for item in root.rglob("*"):
        if item.is_dir() and TIMESTAMP_DIR_RE.fullmatch(item.name):
            ts_dirs.append(item)

    ts_dirs.sort(key=lambda p: p.name, reverse=True)

    latest_by_scene: dict[str, Path] = {}
    for ts_dir in ts_dirs:
        scene_dir = ts_dir.parent
        rel = str(scene_dir.relative_to(root))
        if rel not in latest_by_scene:
            latest_by_scene[rel] = ts_dir

    pairs = sorted(latest_by_scene.items(), key=lambda x: x[0])
    return [(ts_dir, rel) for rel, ts_dir in pairs]


def _find_all_timestamp_dirs_grouped(root: Path) -> list[tuple[str, list[Path]]]:
    ts_dirs: list[Path] = []
    for item in root.rglob("*"):
        if item.is_dir() and TIMESTAMP_DIR_RE.fullmatch(item.name):
            ts_dirs.append(item)

    grouped: dict[str, list[Path]] = {}
    for ts_dir in ts_dirs:
        scene_dir = ts_dir.parent
        rel = str(scene_dir.relative_to(root))
        grouped.setdefault(rel, []).append(ts_dir)

    rows: list[tuple[str, list[Path]]] = []
    for rel, dirs in grouped.items():
        dirs.sort(key=lambda p: p.name, reverse=True)
        rows.append((rel, dirs))
    rows.sort(key=lambda x: x[0])
    return rows


def _load_enrich_summary(scene_dir: Path) -> dict[str, Any] | None:
    summary_path = scenario_chain_dir(scene_dir) / "behavior_context_summary.v0.json"
    if not summary_path.exists() or summary_path.stat().st_size == 0:
        return None
    try:
        with open(summary_path, "r", encoding="utf-8", errors="replace") as f:
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
    return str(summary.get("skip_reason") or "").strip() or "status=skipped"


def _is_no_unit_enrich_completed(scene_dir: Path) -> tuple[bool, str]:
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


def _formal_success_failures(scene_dir: Path) -> list[str]:
    reasons: list[str] = []

    skipped_reason = _enrich_skipped_reason(scene_dir)
    if skipped_reason:
        reasons.append(f"enrich marked skipped: {skipped_reason}")

    no_unit_ok, _ = _is_no_unit_enrich_completed(scene_dir)
    required_files = [
        (f"{CHAIN_DIR_NAME}/backbone_chain.v1.json", "missing backbone_chain.v1.json"),
        (f"{CHAIN_DIR_NAME}/behavior_chain_dataset.v2.json", "missing behavior_chain_dataset.v2.json"),
        (f"{CHAIN_DIR_NAME}/behavior_chain_dataset.v2.meta.json", "missing behavior_chain_dataset.v2.meta.json"),
        (f"{CHAIN_DIR_NAME}/behavior_context_edges.v0.jsonl", "missing behavior_context_edges.v0.jsonl"),
    ]
    for rel_path, reason in required_files:
        if rel_path == f"{CHAIN_DIR_NAME}/behavior_context_edges.v0.jsonl" and no_unit_ok:
            continue
        path = scene_dir / rel_path
        if not path.exists() or path.stat().st_size == 0:
            reasons.append(reason)
    return reasons


def _collect_latest_scenarios(results_root: Path) -> list[ScenarioSnapshot]:
    snapshots: list[ScenarioSnapshot] = []
    for rel, ts_dirs in _find_all_timestamp_dirs_grouped(results_root):
        preferred: ScenarioSnapshot | None = None
        latest_fallback: ScenarioSnapshot | None = None
        for ts_dir in ts_dirs:
            chain_dir = scenario_chain_dir(ts_dir)
            snapshot = ScenarioSnapshot(
                scene_dir=ts_dir,
                scene_rel=rel,
                chain_dir=chain_dir,
                formal_failure_reasons=_formal_success_failures(ts_dir),
            )
            if latest_fallback is None:
                latest_fallback = snapshot
            if not snapshot.formal_failure_reasons:
                preferred = snapshot
                break
        if preferred is not None:
            snapshots.append(preferred)
        elif latest_fallback is not None:
            snapshots.append(latest_fallback)
    return snapshots


def _build_release_for_eligible(
    eligible: list[ScenarioSnapshot],
    release_root: Path,
) -> dict[str, Any]:
    from results_analysis.release import build_dataset_release_v1 as release_stage

    return release_stage.build_release(
        chain_dirs=[s.chain_dir for s in eligible],
        release_root=release_root,
    )


def _status_from_counts(not_ready_count: int, export_fail_count: int) -> tuple[str, int]:
    if export_fail_count > 0:
        return "failed", 1
    if not_ready_count > 0:
        return "incomplete", 2
    return "success", 0


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    results_root = args.results_root.resolve()
    release_root = args.release_root.resolve()
    started_at = time.perf_counter()

    banner_box(
        "[all-release][START] mode=all-scenarios release-only",
        [
            f"results_root   : {results_root}",
            f"release_root   : {release_root}",
            f"input_scope    : existing {CHAIN_DIR_NAME}/formal downstream inputs",
            "boundary       : no build/analyze/full-pipeline rerun",
        ],
        status="start",
    )

    if not results_root.exists() or not results_root.is_dir():
        reason = f"results_root does not exist or is not a directory: {results_root}"
        failure_summary_block(
            "all-release",
            scenario=None,
            stage="discover",
            reason=reason,
            category="missing_input",
            highest_level="unknown",
        )
        final_status_block(
            "all-release",
            status="failed",
            highest_level="unknown",
            elapsed=time.perf_counter() - started_at,
            stage_status={
                "discovered": "0",
                "eligible": "0",
                "exported": "0",
                "export_failed": "0",
                "skipped_not_ready": "0",
            },
            extra={"results_root": str(results_root)},
        )
        return 1

    snapshots = _collect_latest_scenarios(results_root)
    total = len(snapshots)
    if total == 0:
        reason = "no timestamp scenarios discovered under results_root"
        failure_summary_block(
            "all-release",
            scenario=None,
            stage="discover",
            reason=reason,
            category="missing_input",
            highest_level="unknown",
        )
        final_status_block(
            "all-release",
            status="incomplete",
            highest_level="unknown",
            elapsed=time.perf_counter() - started_at,
            stage_status={
                "discovered": "0",
                "eligible": "0",
                "exported": "0",
                "export_failed": "0",
                "skipped_not_ready": "0",
            },
            extra={"results_root": str(results_root)},
        )
        return 2

    eligible: list[ScenarioSnapshot] = []
    not_ready: list[ScenarioSnapshot] = []
    _emit_phase_dashboard("scan", 0, total, 0, 0)
    for idx, item in enumerate(snapshots, 1):
        progress_line(
            "all-release.scan",
            idx,
            total,
            current=item.scene_rel,
            extra={"phase": "formal-success-check"},
        )
        if item.formal_failure_reasons:
            not_ready.append(item)
            stage_banner(
                "scenario",
                "incomplete",
                scope="all-release.scan",
                scenario=item.scene_rel,
                processed=idx,
                total=total,
                emoji=True,
                extra={
                    "highest_level": highest_level_reached(item.scene_dir),
                    "reason": item.formal_failure_reasons[0],
                },
            )
        else:
            eligible.append(item)
            stage_banner(
                "scenario",
                "ok",
                scope="all-release.scan",
                scenario=item.scene_rel,
                processed=idx,
                total=total,
                emoji=True,
                extra={"highest_level": highest_level_reached(item.scene_dir)},
            )
        _emit_phase_dashboard("scan", idx, total, 0, 0)

    print()
    _emit_phase_dashboard("selection", total, total, 0, len(eligible))
    print()

    stage_banner(
        "selection",
        "warn" if not_ready else "ok",
        scope="all-release",
        extra={
            "discovered": total,
            "eligible": len(eligible),
            "skipped_not_ready": len(not_ready),
        },
    )

    if not not_ready:
        pass
    else:
        top_reasons = Counter(
            reason
            for row in not_ready
            for reason in row.formal_failure_reasons
        )
        missing = [f"{k} x{v}" for k, v in top_reasons.most_common(5)]
        failure_summary_block(
            "all-release",
            scenario=None,
            stage="selection",
            reason=(
                f"{len(not_ready)} scenarios skipped: they do not satisfy "
                f"formal {CHAIN_DIR_NAME} readiness for release export"
            ),
            category="incomplete",
            highest_level=CHAIN_DIR_NAME,
            missing=missing,
        )

    if not eligible:
        final_status_block(
            "all-release",
            status="incomplete",
            highest_level=CHAIN_DIR_NAME,
            elapsed=time.perf_counter() - started_at,
            stage_status={
                "discovered": str(total),
                "eligible": "0",
                "exported": "0",
                "export_failed": "0",
                "skipped_not_ready": str(len(not_ready)),
            },
            extra={
                "results_root": str(results_root),
                "release_root": str(release_root),
            },
        )
        return 2

    banner_box(
        "[all-release][START] per-scenario release export",
        [
            f"eligible      : {len(eligible)}",
            f"release_root  : {release_root}",
            "driver        : build_dataset_release_v1.build_release",
        ],
        status="start",
    )

    for idx, item in enumerate(eligible, 1):
        progress_line(
            "all-release.queue",
            idx,
            len(eligible),
            current=item.scene_rel,
            extra={"phase": "release-export"},
        )

    stage_banner(
        "release",
        "start",
        scope="all-release",
        processed=0,
        total=len(eligible),
        extra={"mode": "all-scenarios"},
    )
    _emit_phase_dashboard("export", total, total, 0, len(eligible))

    try:
        manifest = _build_release_for_eligible(eligible=eligible, release_root=release_root)
    except Exception as exc:
        failure_summary_block(
            "all-release",
            scenario=None,
            stage="release",
            reason=f"release exporter raised {type(exc).__name__}: {exc}",
            highest_level=CHAIN_DIR_NAME,
        )
        final_status_block(
            "all-release",
            status="failed",
            highest_level=CHAIN_DIR_NAME,
            elapsed=time.perf_counter() - started_at,
            stage_status={
                "discovered": str(total),
                "eligible": str(len(eligible)),
                "exported": "0",
                "export_failed": str(len(eligible)),
                "skipped_not_ready": str(len(not_ready)),
            },
            extra={
                "results_root": str(results_root),
                "release_root": str(release_root),
            },
        )
        return 1

    manifest_rows = manifest.get("scenarios") or []
    manifest_errors = manifest.get("errors") or []
    manifest_path = release_root / "manifest.json"

    slug_by_chain_dir: dict[Path, str] = {}
    for row in manifest_rows:
        try:
            cv1 = Path(str(row.get("source_chain_dir") or row.get("source_chain_v1_dir") or "")).resolve()
        except Exception:
            continue
        slug = str(row.get("scenario_slug") or "")
        if cv1 and slug:
            slug_by_chain_dir[cv1] = slug

    error_by_chain_dir: dict[Path, str] = {}
    for row in manifest_errors:
        try:
            cv1 = Path(str(row.get("chain_dir") or row.get("chain_v1_dir") or "")).resolve()
        except Exception:
            continue
        error_by_chain_dir[cv1] = str(row.get("error") or "release exporter error")

    exported_ok = 0
    exported_fail = 0
    for idx, item in enumerate(eligible, 1):
        cv1 = item.chain_dir.resolve()
        if cv1 in error_by_chain_dir:
            exported_fail += 1
            err = error_by_chain_dir[cv1]
            stage_banner(
                "scenario",
                "fail",
                scope="all-release.build",
                scenario=item.scene_rel,
                processed=idx,
                total=len(eligible),
                emoji=True,
                extra={
                    "highest_level": highest_level_reached(item.scene_dir),
                    "reason": err,
                },
            )
            failure_summary_block(
                "all-release",
                scenario=item.scene_rel,
                stage="release",
                reason=err,
                highest_level=highest_level_reached(item.scene_dir),
            )
            _emit_phase_dashboard("export", total, total, idx, len(eligible))
            continue

        exported_ok += 1
        slug = slug_by_chain_dir.get(cv1)
        level = highest_level_reached(
            item.scene_dir,
            release_root=release_root,
            release_slug=slug,
        )
        stage_banner(
            "scenario",
            "ok",
            scope="all-release.build",
            scenario=item.scene_rel,
            processed=idx,
            total=len(eligible),
            emoji=True,
            extra={
                "highest_level": level,
                "release_slug": slug,
            },
        )
        _emit_phase_dashboard("export", total, total, idx, len(eligible))

    print()
    _emit_phase_dashboard("done", total, total, len(eligible), len(eligible))
    print()

    status, rc = _status_from_counts(
        not_ready_count=len(not_ready),
        export_fail_count=exported_fail,
    )

    stage_banner(
        "release",
        "ok" if status == "success" else ("incomplete" if status == "incomplete" else "fail"),
        scope="all-release",
        extra={
            "exported": exported_ok,
            "export_failed": exported_fail,
            "manifest_errors": len(manifest_errors),
        },
    )

    final_status_block(
        "all-release",
        status=status,
        highest_level=("dataset_release_v1" if exported_ok > 0 and exported_fail == 0 else CHAIN_DIR_NAME),
        elapsed=time.perf_counter() - started_at,
        stage_status={
            "discovered": str(total),
            "eligible": str(len(eligible)),
            "exported": str(exported_ok),
            "export_failed": str(exported_fail),
            "skipped_not_ready": str(len(not_ready)),
        },
        extra={
            "results_root": str(results_root),
            "release_root": str(release_root),
            "manifest": str(manifest_path),
        },
    )
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
