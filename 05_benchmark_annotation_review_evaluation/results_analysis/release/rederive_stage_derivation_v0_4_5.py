#!/usr/bin/env python3
"""Re-derive canonical stage_labels + benchmark with stage_derivation_v0.4.5.

Guardrails
----------
* Reads only from an existing `dataset_release_v1/`.
* Does not touch raw, chain, EWVAA run dirs, or strict blind benchmark.
* Rewrites only `stage_labels.v0.json`, the stage-label schema,
  release manifest stage summary fields, and canonical `benchmarks/stage_reasoning/`.
"""

from __future__ import annotations

import argparse
import importlib.util
import sys
from pathlib import Path
from typing import Optional


def _load_module_from_path(module_name: str, module_path: Path):
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load module from {module_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

try:
    from .build_dataset_release_v1 import (
        REPO_ROOT,
        _build_stage_labels_sidecar,
        _read_json,
        _schema_stage_labels,
        _write_json,
    )
    from .export_stage_reasoning_benchmark import export_benchmark
except ImportError:  # pragma: no cover - direct script execution
    _REPO_ROOT = Path(__file__).resolve().parents[2]
    if str(_REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(_REPO_ROOT))
    _release_unit_root = _REPO_ROOT.parent / "03_dataset_release_generation"
    if str(_release_unit_root) not in sys.path:
        sys.path.insert(0, str(_release_unit_root))
    _dataset_release = _load_module_from_path(
        "seclog_public_stage03_dataset_release",
        _release_unit_root
        / "results_analysis"
        / "release"
        / "build_dataset_release_v1.py",
    )
    _benchmark_export = _load_module_from_path(
        "seclog_public_stage05_benchmark_export",
        Path(__file__).with_name("export_stage_reasoning_benchmark.py"),
    )
    REPO_ROOT = _dataset_release.REPO_ROOT
    _build_stage_labels_sidecar = _dataset_release._build_stage_labels_sidecar
    _read_json = _dataset_release._read_json
    _schema_stage_labels = _dataset_release._schema_stage_labels
    _write_json = _dataset_release._write_json
    export_benchmark = _benchmark_export.export_benchmark


DEFAULT_RELEASE_ROOT = REPO_ROOT / "dataset_release_v1"
DEFAULT_BENCHMARK_ROOT = (
    DEFAULT_RELEASE_ROOT / "benchmarks" / "stage_reasoning"
)


def _refresh_manifest_stage_benchmark(
    manifest: dict,
    bench_manifest: dict,
) -> None:
    dataset_output = bench_manifest["outputs"]["dataset"]
    manifest["stage_reasoning_benchmark"] = {
        "data_dir": dataset_output["data_dir"],
        "model_input": dataset_output["model_input"],
        "gold": dataset_output["gold"],
        "sample_index": dataset_output["sample_index"],
        "sample_count": dataset_output["samples"],
        "stage_counts": bench_manifest["stage_counts"],
    }


def rederive_release_in_place(
    release_root: Path,
    benchmark_root: Path,
) -> dict:
    manifest_path = release_root / "manifest.json"
    if not manifest_path.exists():
        raise FileNotFoundError(
            f"release manifest missing: {manifest_path}"
        )

    manifest = _read_json(manifest_path)
    for row in manifest.get("scenarios") or []:
        paths = row.get("paths") or {}
        main_sample = _read_json(release_root / paths["main_sample"])
        narrative_roles = _read_json(release_root / paths["narrative_roles"])
        stage_labels = _build_stage_labels_sidecar(
            main_sample,
            narrative_roles,
            str(row.get("scenario_id") or ""),
            row.get("chain_id"),
            rule_version="stage_derivation_v0.4.5",
        )
        _write_json(release_root / paths["stage_labels"], stage_labels)
        row["stage_inputs"] = stage_labels["derivation"]["inputs"]
        row["per_stage_edge_counts"] = stage_labels["stats"][
            "per_stage_edge_counts"
        ]

    _write_json(
        release_root / "schemas" / "stage_labels.v0.schema.json",
        _schema_stage_labels(),
    )
    _write_json(manifest_path, manifest)

    bench_manifest = export_benchmark(
        release_root,
        out_dir=benchmark_root,
        emit_evidence_visible=False,
        strict_leakage_check=True,
        no_gold_reasoning=False,
    )
    _refresh_manifest_stage_benchmark(manifest, bench_manifest)
    _write_json(manifest_path, manifest)
    return bench_manifest


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Re-derive canonical dataset_release_v1 stage_labels with "
            "stage_derivation_v0.4.5 and refresh the canonical "
            "stage_reasoning benchmark."
        )
    )
    parser.add_argument(
        "--release-root",
        type=Path,
        default=DEFAULT_RELEASE_ROOT,
        help="Existing canonical dataset_release_v1 root to rewrite.",
    )
    parser.add_argument(
        "--benchmark-root",
        type=Path,
        default=DEFAULT_BENCHMARK_ROOT,
        help="Canonical benchmark output directory to rewrite.",
    )
    return parser.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)
    release_root = args.release_root.resolve()
    benchmark_root = args.benchmark_root.resolve()
    bench_manifest = rederive_release_in_place(
        release_root,
        benchmark_root,
    )
    print(
        "[stage_derivation_v0.4.5] "
        f"release={release_root} "
        f"benchmark={benchmark_root} "
        f"samples={bench_manifest['dataset']['sample_count']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
