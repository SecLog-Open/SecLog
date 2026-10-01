#!/usr/bin/env python3
from __future__ import annotations

import argparse
import subprocess
import sys
import tokenize
from pathlib import Path


def script_path(name: str) -> Path:
    return Path(__file__).resolve().parent / name


def run_step(args: list[str]) -> int:
    completed = subprocess.run(args, check=False)
    return int(completed.returncode)


def validate_python_sources(paths: list[Path]) -> bool:
    """Compile source text in memory without creating ``__pycache__``."""
    for path in paths:
        try:
            with tokenize.open(path) as stream:
                source = stream.read()
            compile(source, str(path), "exec")
        except Exception as exc:
            print(f"Python syntax check failed for {path}: {exc}", file=sys.stderr)
            return False
    return True


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run stage_reasoning_window_selection build + validate sequentially."
    )
    parser.add_argument("--config", default="configs/default_config.json")
    parser.add_argument("--results-root", default=None)
    parser.add_argument(
        "--output-dir",
        default="../../seclog_work/window_selection",
        help="Output directory (default: ../../seclog_work/window_selection).",
    )
    parser.add_argument("--scenario-limit", type=int, default=None)
    parser.add_argument(
        "--skip-py-compile",
        action="store_true",
        help="Skip the local in-memory Python syntax check.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    python = sys.executable

    build_cmd = [python, str(script_path("build_stage_reasoning_window_selection.py")), "--config", args.config]
    if args.results_root:
        build_cmd.extend(["--results-root", args.results_root])
    if args.output_dir:
        build_cmd.extend(["--output-dir", args.output_dir])
    if args.scenario_limit is not None:
        build_cmd.extend(["--scenario-limit", str(args.scenario_limit)])

    validate_cmd = [python, str(script_path("validate_stage_reasoning_window_selection.py"))]
    if args.output_dir:
        validate_cmd.extend(["--workbench-dir", args.output_dir])

    if not args.skip_py_compile:
        sources = [
            script_path("build_stage_reasoning_window_selection.py"),
            script_path("validate_stage_reasoning_window_selection.py"),
            script_path("run_stage_reasoning_window_selection.py"),
        ]
        if not validate_python_sources(sources):
            return 1

    if run_step(build_cmd) != 0:
        return 1
    return run_step(validate_cmd)


if __name__ == "__main__":
    raise SystemExit(main())
