#!/usr/bin/env python3
"""Run the public, non-API benchmark-construction handoff.

The default execution performs only deterministic local steps:

window seed -> canonical workspace -> strict blinding -> compact prompt workbench

It never calls a model API, never overwrites an existing work directory, and
never writes into the upstream chain or window-selection directories.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path


STAGE_ROOT = Path(__file__).resolve().parents[1]
IMPORTER = STAGE_ROOT / "scripts" / "import_window_selection_seed.py"
STRICT_BLIND = STAGE_ROOT / "results_analysis" / "release" / "export_stage_reasoning_strict_blind_benchmark.py"
COMPACT_BUILDER = STAGE_ROOT / "results_analysis" / "release" / "build_ewvaa_masked_workbench.py"
ANNOTATION_CONTEXT = (
    STAGE_ROOT / "assets" / "auxiliary_context" / "scenario_vulnerability_facts.annotation_context.v0.4.json"
)


def run(cmd: list[str]) -> None:
    print("+ " + " ".join(cmd))
    completed = subprocess.run(cmd, check=False)
    if completed.returncode != 0:
        raise SystemExit(completed.returncode)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build a strict-blind compact annotation workbench from stage-04 windows.")
    parser.add_argument("--window-seed", type=Path, required=True)
    parser.add_argument("--source-base", type=Path, default=None)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument(
        "--limit",
        type=int,
        default=216,
        help="Maximum public handoff rows (default: unified SecLog-Bench-216).",
    )
    # The public handoff is one dataset unit.
    parser.add_argument("--skip-compact", action="store_true", help="Stop after strict-blind export.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    work_dir = args.work_dir.resolve()
    if work_dir.exists():
        raise SystemExit(f"Refusing existing work directory: {work_dir}")
    work_dir.mkdir(parents=True)

    canonical = work_dir / "canonical_benchmark"
    strict_blind = work_dir / "strict_blind_benchmark"
    compact = work_dir / "compact_annotation_workbench"

    import_cmd = [
        sys.executable,
        str(IMPORTER),
        "--seed",
        str(args.window_seed.resolve()),
        "--output-dir",
        str(canonical),
    ]
    if args.source_base:
        import_cmd.extend(["--source-base", str(args.source_base.resolve())])
    run(import_cmd)

    run(
        [
            sys.executable,
            str(STRICT_BLIND),
            "--source-benchmark",
            str(canonical),
            "--output-dir",
            str(strict_blind),
        ]
    )

    if not args.skip_compact:
        data_root = canonical / "data"
        strict_data_root = strict_blind / "data"
        quality_summary = work_dir / "optional_stage_label_quality_summary.json"
        quality_summary.write_text(
            json.dumps(
                {
                    "schema_version": "stage_label_quality_summary.optional_public_handoff.v1",
                    "samples": [],
                    "note": "No private quality overrides supplied; use canonical selection status.",
                },
                ensure_ascii=False,
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        cmd = [
            sys.executable,
            str(COMPACT_BUILDER),
            "--model-input",
            str(data_root / "model_input.jsonl"),
            "--gold",
            str(data_root / "gold.jsonl"),
            "--sample-index",
            str(data_root / "sample_index.jsonl"),
            "--canonical-manifest",
            str(canonical / "manifest.json"),
            "--strict-blind-manifest",
            str(strict_blind / "manifest.json"),
            "--strict-blind-sample-id-map",
            str(strict_data_root / "id_maps" / "sample_id_map.json"),
            "--annotation-context",
            str(ANNOTATION_CONTEXT),
            "--stage-label-quality-summary",
            str(quality_summary),
            "--output-dir",
            str(compact),
            "--no-exclude-manual-review",
            "--no-require-vulnerability-context",
            "--no-stratify-by-scenario",
            "--compact-version",
            "v2",
            "--stage-adaptive-budget",
            "--modality-floor",
            "--reviewer-more-evidence",
            "--api-safe-budget",
        ]
        cmd.extend(["--limit", str(args.limit)])
        run(cmd)

    summary = {
        "canonical_benchmark": str(canonical),
        "strict_blind_benchmark": str(strict_blind),
        "compact_annotation_workbench": None if args.skip_compact else str(compact),
        "api_called": False,
        "upstream_modified": False,
        "next_steps": [
            "Run the API annotation method explicitly only when desired.",
            "Open review_ui for human validation and writeback into a private work directory.",
            "Publish only the final reviewed benchmark, never intermediate model outputs.",
        ],
    }
    (work_dir / "pipeline_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(summary, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
