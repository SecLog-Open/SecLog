#!/usr/bin/env python3
"""Run the default EWVAA multi-agent gold pipeline, steps 01 through 05."""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

from common import (
    CONFIG_DEFAULT,
    DEFAULT_WORKBENCH_DIR,
    LEGACY_WORKBENCH_DIR,
    ROOT,
    annotator_resume_state,
    LEGACY_RUN_API_KEY_ENV,
    LEGACY_RUN_BASE_URL_ENV,
    RUN_ANNOTATOR_API_MODE_ENV,
    RUN_ANNOTATOR_API_KEY_ENV,
    RUN_ANNOTATOR_BASE_URL_ENV,
    RUN_ANNOTATOR_MODEL_ENV,
    RUN_API_CONFIG_SOURCE_ENV,
    RUN_REVIEWER_API_MODE_ENV,
    RUN_REVIEWER_API_KEY_ENV,
    RUN_REVIEWER_BASE_URL_ENV,
    RUN_REVIEWER_MODEL_ENV,
    api_config_presence_report,
    api_config_from_openai_env,
    attach_api_modes,
    dump_simple_yaml,
    load_config,
    output_root,
    prompt_openai_compatible_api_config,
    read_json,
    read_sample_id_file,
    read_sample_plan,
    redact_api_config_for_report,
    rel,
    resolve_path,
    sample_selection_summary,
    utc_now,
    write_json,
    write_text,
    write_resolved_config,
)


STEPS = [
    "01_annotator_generate_patches.py",
    "02_validate_annotator_patches.py",
    "03_reviewer_judge_and_revise.py",
    "04_validate_reviewer_patches.py",
    "05_export_final_candidate_gold.py",
]


def build_runtime_config(
    base_config: dict[str, object],
    *,
    limit: int | None,
    canonical_benchmark_root: Path,
    workbench_dir: Path,
    output_root_override: Path,
    sample_id_file: Path | None,
    sample_plan: Path | None,
) -> dict[str, object]:
    config = dict(base_config)
    requested_canonical_root = resolve_path(canonical_benchmark_root)
    requested_workbench = resolve_path(workbench_dir)
    requested_output_root = resolve_path(output_root_override)
    requested_limit = limit if limit is not None else base_config.get("limit")
    selected_sample_ids: list[str] = []
    sample_id_file_path = resolve_path(sample_id_file) if sample_id_file else None
    sample_plan_path = resolve_path(sample_plan) if sample_plan else None
    if sample_id_file_path is not None:
        selected_sample_ids = read_sample_id_file(sample_id_file_path)
        if not selected_sample_ids:
            raise SystemExit(f"No sample_id values found in --sample-id-file: {sample_id_file_path}")
        config["limit"] = None
        config["sample_selection_mode"] = "sample_id_file"
        config["sample_id_file"] = rel(sample_id_file_path)
        config["sample_plan"] = ""
    elif sample_plan_path is not None:
        selected_sample_ids = read_sample_plan(sample_plan_path)
        if not selected_sample_ids:
            raise SystemExit(f"No sample_id values found in --sample-plan: {sample_plan_path}")
        config["limit"] = None
        config["sample_selection_mode"] = "sample_plan"
        config["sample_id_file"] = ""
        config["sample_plan"] = rel(sample_plan_path)
    else:
        config["limit"] = requested_limit
        config["sample_selection_mode"] = "limit" if requested_limit is not None else "all"
        config["sample_id_file"] = ""
        config["sample_plan"] = ""
    config["workbench_dir"] = rel(requested_workbench)
    config["output_root"] = rel(requested_output_root)
    config["canonical_benchmark_root"] = rel(requested_canonical_root)
    data_root = requested_canonical_root / "data"
    config["model_input"] = rel(data_root / "model_input.jsonl")
    config["gold"] = rel(data_root / "gold.jsonl")
    config["sample_index"] = rel(data_root / "sample_index.jsonl")
    config["prompt_pack"] = rel(requested_workbench / "prompt_packs" / "annotation_prompts.weighted.masked.jsonl")
    config["reviewer_prompt_pack"] = rel(
        requested_workbench / "prompt_packs" / "reviewer_annotation_prompts.weighted.masked.jsonl"
    )
    config["id_map_dir"] = rel(requested_workbench / "id_maps")
    config["requested_limit"] = requested_limit
    config["selected_sample_count"] = len(selected_sample_ids)
    config["selected_sample_ids"] = selected_sample_ids
    if selected_sample_ids:
        config["run_name_prefix"] = f"multiagent_api_sampleids{len(selected_sample_ids)}"
    else:
        config["run_name_prefix"] = "multiagent_api" if requested_limit is None else f"multiagent_api_limit{requested_limit}"
    return config


def create_new_run_dir(config: dict[str, object]) -> Path:
    root = output_root(config)
    root.mkdir(parents=True, exist_ok=True)
    prefix = str(config.get("run_name_prefix") or "multiagent_api")
    run_dir = root / f"{prefix}_{utc_now().replace('-', '').replace(':', '').split('.')[0]}Z"
    suffix = 1
    while run_dir.exists():
        run_dir = root / f"{prefix}_{utc_now().replace('-', '').replace(':', '').split('.')[0]}Z_{suffix}"
        suffix += 1
    run_dir.mkdir(parents=True, exist_ok=False)
    return run_dir


def runtime_config_path(run_dir: Path) -> Path:
    return run_dir / "runtime_config.yaml"


def normalize_blocked_reason(api_config: dict[str, object]) -> str:
    reason = str(api_config.get("blocked_reason") or "")
    if reason == "interactive_api_config_required":
        return reason
    return "api_config_missing"


def should_stop_before_step05(run_dir: Path) -> tuple[bool, dict[str, object]]:
    validation_path = run_dir / "merged_patch_validation_report.json"
    weighted_path = run_dir / "reviewer_weighted_grounding_report.json"
    if not validation_path.exists():
        return True, {
            "blocked_reason": "missing_merged_patch_validation_report",
            "final_candidate_export_blocked": True,
            "stopped_at": "04_validate_reviewer_patches.py",
        }
    validation = read_json(validation_path)
    final_invalid = int(validation.get("counts", {}).get("invalid_outputs", 0) or 0)
    if final_invalid > 0:
        return True, {
            "blocked_reason": "merged_patch_validation_invalid_outputs_present",
            "final_candidate_export_blocked": True,
            "stopped_at": "04_validate_reviewer_patches.py",
            "final_invalid": final_invalid,
            "invalid_sample_ids": validation.get("invalid_sample_ids", []),
        }
    if not weighted_path.exists():
        return True, {
            "blocked_reason": "missing_reviewer_weighted_grounding_report",
            "final_candidate_export_blocked": True,
            "stopped_at": "04_validate_reviewer_patches.py",
        }
    weighted = read_json(weighted_path)
    weighted_status = str(weighted.get("status") or "")
    strict_false = int(weighted.get("counts", {}).get("strict_gold_allowed_false", 0) or 0)
    cases = int(weighted.get("counts", {}).get("cases", 0) or 0)
    if weighted_status != "success" or cases == 0:
        return True, {
            "blocked_reason": "reviewer_weighted_grounding_no_input",
            "final_candidate_export_blocked": True,
            "stopped_at": "04_validate_reviewer_patches.py",
            "reviewer_weighted_grounding_status": weighted_status,
            "reviewer_weighted_grounding_cases": cases,
        }
    if strict_false > 0:
        return True, {
            "blocked_reason": "reviewer_weighted_grounding_strict_gold_not_allowed",
            "final_candidate_export_blocked": True,
            "stopped_at": "04_validate_reviewer_patches.py",
            "strict_gold_allowed_false": strict_false,
            "strict_gold_blocked_sample_ids": weighted.get("strict_gold_blocked_sample_ids", []),
        }
    return False, {}


def should_stop_after_step02(run_dir: Path) -> tuple[bool, dict[str, object]]:
    validation_path = run_dir / "annotator_patch_validation_report.json"
    if not validation_path.exists():
        return True, {
            "stop_reason": "annotator_validation_failed",
            "blocked_reason": "missing_annotator_patch_validation_report",
            "stopped_at": "02_validate_annotator_patches.py",
            "step03_skipped": True,
            "step04_skipped": True,
            "step05_skipped": True,
        }
    validation = read_json(validation_path)
    invalid_outputs = int(validation.get("counts", {}).get("invalid_outputs", 0) or 0)
    if invalid_outputs > 0:
        return True, {
            "stop_reason": "annotator_validation_failed",
            "blocked_reason": "annotator_validation_invalid_outputs_present",
            "stopped_at": "02_validate_annotator_patches.py",
            "step03_skipped": True,
            "step04_skipped": True,
            "step05_skipped": True,
            "invalid_outputs": invalid_outputs,
            "invalid_sample_ids": validation.get("invalid_sample_ids", []),
        }
    return False, {}


def should_stop_after_step01(run_dir: Path) -> tuple[bool, dict[str, object]]:
    report_path = run_dir / "annotator_run_report.json"
    if not report_path.exists():
        return True, {
            "stop_reason": "annotator_generation_failed",
            "blocked_reason": "missing_annotator_run_report",
            "stopped_at": "01_annotator_generate_patches.py",
            "step02_skipped": True,
            "step03_skipped": True,
            "step04_skipped": True,
            "step05_skipped": True,
        }
    report = read_json(report_path)
    counts = report.get("counts", {})
    api_errors = int(counts.get("api_errors", 0) or 0)
    parse_failures = int(counts.get("parse_failures", 0) or 0)
    unmask_failures = int(counts.get("unmask_failures", 0) or 0)
    existing_resume_state = report.get("resume_state")
    if isinstance(existing_resume_state, dict):
        resume_state = existing_resume_state
    else:
        selected_sample_ids = report.get("selected_sample_ids", [])
        resume_state = annotator_resume_state(
            selected_sample_ids if isinstance(selected_sample_ids, list) else [],
            [],
            api_errors=report.get("api_errors", []),
            parse_failures=report.get("parse_failures", []),
            unmask_failures=report.get("unmask_failures", []),
        )
    completed_samples = int(counts.get("completed_samples", 0) or 0)
    selected_sample_count = int(report.get("selected_sample_count", 0) or 0)
    if (
        api_errors > 0
        or parse_failures > 0
        or unmask_failures > 0
        or completed_samples != selected_sample_count
    ):
        return True, {
            "stop_reason": "annotator_generation_failed",
            "blocked_reason": "annotator_generation_incomplete_or_error",
            "stopped_at": "01_annotator_generate_patches.py",
            "step02_skipped": True,
            "step03_skipped": True,
            "step04_skipped": True,
            "step05_skipped": True,
            "completed_samples": completed_samples,
            "selected_sample_count": selected_sample_count,
            "api_errors": api_errors,
            "parse_failures": parse_failures,
            "unmask_failures": unmask_failures,
            "resume_state": resume_state,
            "failed_sample_ids": [row.get("sample_id") for row in report.get("api_errors", []) if row.get("sample_id")]
            + [row.get("sample_id") for row in report.get("parse_failures", []) if row.get("sample_id")]
            + [row.get("sample_id") for row in report.get("unmask_failures", []) if row.get("sample_id")],
        }
    return False, {}


def blocked_after_step01_report(config: dict[str, object], run_dir: Path, stop_report: dict[str, object]) -> dict[str, object]:
    return {
        "status": "partial",
        "created_at": utc_now(),
        "run_dir": rel(run_dir),
        "api_called": True,
        "api_key_recorded": False,
        "canonical_gold_overwrite_allowed": False,
        "benchmark_files_modified": False,
        "reviewer_started": False,
        "final_candidate_gold_path": "",
        "final_candidate_gold_rows": 0,
        **sample_selection_summary(config),
        "candidate_export_allowed": False,
        **stop_report,
    }


def blocked_after_step02_report(config: dict[str, object], run_dir: Path, stop_report: dict[str, object]) -> dict[str, object]:
    return {
        "status": "partial",
        "created_at": utc_now(),
        "run_dir": rel(run_dir),
        "api_called": True,
        "api_key_recorded": False,
        "canonical_gold_overwrite_allowed": False,
        "benchmark_files_modified": False,
        "reviewer_started": False,
        "final_candidate_gold_path": "",
        "final_candidate_gold_rows": 0,
        **sample_selection_summary(config),
        "candidate_export_allowed": False,
        **stop_report,
    }


def blocked_step05_report(config: dict[str, object], run_dir: Path, stop_report: dict[str, object]) -> dict[str, object]:
    return {
        "status": "partial",
        "created_at": utc_now(),
        "run_dir": rel(run_dir),
        "api_called": True,
        "api_key_recorded": False,
        "canonical_gold_overwrite_allowed": False,
        "benchmark_files_modified": False,
        "step05_skipped": True,
        "exit_before_step05": True,
        "final_candidate_gold_path": "",
        "final_candidate_gold_rows": 0,
        **sample_selection_summary(config),
        "final_candidate_export_blocked": True,
        "candidate_export_allowed": False,
        **stop_report,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run the public AI annotation and reviewer pipeline. "
        "By default, the wrapper interactively prompts for separate annotator and reviewer API configs. "
        "Both roles default to api_mode=chat_completions.",
        epilog=(
            "Supply the canonical and compact directories created by "
            "scripts/run_public_benchmark_pipeline.py. Keep output-root outside "
            "the distributed release. No API key is written to run reports."
        ),
    )
    parser.add_argument("--config", type=Path, default=CONFIG_DEFAULT)
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help=(
            "Override config limit. Ignored when --sample-id-file or --sample-plan is supplied; "
            "fixed sample selection takes priority."
        ),
    )
    parser.add_argument(
        "--sample-id-file",
        type=Path,
        default=None,
        help="Run only sample_ids listed one per line in PATH. Blank lines and lines beginning with # are ignored. Takes priority over --limit.",
    )
    parser.add_argument(
        "--sample-plan",
        type=Path,
        default=None,
        help="Run sample_ids from a JSON/JSONL sample plan by reading sample_id from selections/rows. Ignored if --sample-id-file is also supplied.",
    )
    parser.add_argument(
        "--canonical-benchmark-root",
        type=Path,
        required=True,
        help="canonical_benchmark directory created by the deterministic public handoff.",
    )
    parser.add_argument(
        "--workbench-dir",
        type=Path,
        required=True,
        help="compact_annotation_workbench created by the deterministic public handoff.",
    )
    parser.add_argument(
        "--output-root",
        type=Path,
        required=True,
        help="Output root; a new independent run directory is created beneath it.",
    )
    parser.add_argument(
        "--use-env-api-config",
        action="store_true",
        help="Explicitly allow reading OPENAI_* API config. By default, interactive input collects separate annotator/reviewer configs.",
    )
    parser.add_argument(
        "--annotator-request-timeout-seconds",
        type=float,
        default=None,
        help=(
            "Override the per-sample annotator timeout passed to 01_annotator_generate_patches.py. "
            "Useful for long-running providers or to enforce a stricter hard timeout. "
            "When omitted, the runtime config default is 900 seconds."
        ),
    )
    args = parser.parse_args()
    config_path = args.config if args.config.is_absolute() else ROOT / args.config
    config = build_runtime_config(
        load_config(config_path),
        limit=args.limit,
        canonical_benchmark_root=args.canonical_benchmark_root,
        workbench_dir=args.workbench_dir,
        output_root_override=args.output_root,
        sample_id_file=args.sample_id_file,
        sample_plan=args.sample_plan,
    )
    run_dir = create_new_run_dir(config)
    config["active_run_dir"] = rel(run_dir)
    runtime_path = runtime_config_path(run_dir)
    write_text(runtime_path, dump_simple_yaml(config) + "\n")
    if args.use_env_api_config:
        api_config = api_config_from_openai_env(config, "both")
    else:
        api_config = prompt_openai_compatible_api_config(require_reviewer=True, allow_same_model=True)
    api_config = attach_api_modes(config, api_config)
    write_resolved_config(run_dir, config, api_config)
    if api_config.get("blocked"):
        reason = normalize_blocked_reason(api_config)
        report = {
            "status": "blocked",
            "created_at": utc_now(),
            "run_dir": rel(run_dir),
            "blocked_reason": reason,
            "missing_env": api_config.get("missing_env", []),
            "api_called": False,
            "no_api_called": True,
            "annotator_api_key_recorded": False,
            "reviewer_api_key_recorded": False,
            "requested_limit": config.get("limit"),
            **sample_selection_summary(config),
            "workbench_dir": str(config.get("workbench_dir") or ""),
            "output_root": str(config.get("output_root") or ""),
            "benchmark_files_modified": False,
            **api_config_presence_report(api_config),
            **redact_api_config_for_report(api_config),
            "api_config": redact_api_config_for_report(api_config),
        }
        write_json(run_dir / "multiagent_run_report.json", report)
        write_json(run_dir / "annotator_run_report.json", {**report, "role": "annotator"})
        if reason == "interactive_api_config_required":
            print(
                "Interactive API config is required by default. "
                "Re-run in a TTY or pass --use-env-api-config explicitly."
            )
        else:
            print("BLOCKED: " + reason)
        print(f"run_dir={rel(run_dir)}")
        return 1

    child_env = os.environ.copy()
    for inherited_name in (
        "OPENAI_API_KEY",
        "OPENAI_BASE_URL",
        "OPENAI_ANNOTATOR_API_KEY",
        "OPENAI_ANNOTATOR_BASE_URL",
        "OPENAI_ANNOTATOR_MODEL",
        "OPENAI_REVIEWER_API_KEY",
        "OPENAI_REVIEWER_BASE_URL",
        "OPENAI_REVIEWER_MODEL",
        "OPENAI_MODEL",
    ):
        child_env.pop(inherited_name, None)
    child_env.update(
        {
            LEGACY_RUN_BASE_URL_ENV: str(api_config.get("annotator_base_url", "")),
            LEGACY_RUN_API_KEY_ENV: str(api_config.get("annotator_api_key", "")),
            RUN_ANNOTATOR_BASE_URL_ENV: str(api_config["annotator_base_url"]),
            RUN_ANNOTATOR_API_KEY_ENV: str(api_config["annotator_api_key"]),
            RUN_ANNOTATOR_MODEL_ENV: str(api_config["annotator_model"]),
            RUN_ANNOTATOR_API_MODE_ENV: str(api_config.get("annotator_api_mode", "chat_completions")),
            RUN_REVIEWER_BASE_URL_ENV: str(api_config["reviewer_base_url"]),
            RUN_REVIEWER_API_KEY_ENV: str(api_config["reviewer_api_key"]),
            RUN_REVIEWER_MODEL_ENV: str(api_config["reviewer_model"]),
            RUN_REVIEWER_API_MODE_ENV: str(api_config.get("reviewer_api_mode", "chat_completions")),
            RUN_API_CONFIG_SOURCE_ENV: str(api_config.get("source", "interactive")),
        }
    )
    step_dir = Path(__file__).resolve().parent

    for step in STEPS:
        cmd = [sys.executable, str(step_dir / step), "--config", str(runtime_path)]
        if step == "01_annotator_generate_patches.py" and args.annotator_request_timeout_seconds is not None:
            cmd.extend(["--request-timeout-seconds", str(args.annotator_request_timeout_seconds)])
        print("+ " + " ".join(cmd), flush=True)
        rc = subprocess.call(cmd, cwd=ROOT, env=child_env)
        if rc != 0:
            print(f"stopped_at={step}")
            print(f"return_code={rc}")
            print(f"run_dir={rel(run_dir)}")
            return rc
        if step == "01_annotator_generate_patches.py":
            should_stop, stop_report = should_stop_after_step01(run_dir)
            if should_stop:
                report = blocked_after_step01_report(config, run_dir, stop_report)
                write_json(run_dir / "multiagent_run_report.json", report)
                print("stopped_at=01_annotator_generate_patches.py")
                print(f"stop_reason={stop_report['stop_reason']}")
                print("reviewer_started=false")
                print("return_code=0")
                print(f"run_dir={rel(run_dir)}")
                return 0
        if step == "02_validate_annotator_patches.py":
            should_stop, stop_report = should_stop_after_step02(run_dir)
            if should_stop:
                report = blocked_after_step02_report(config, run_dir, stop_report)
                write_json(run_dir / "multiagent_run_report.json", report)
                print("stopped_at=02_validate_annotator_patches.py")
                print("stop_reason=annotator_validation_failed")
                print("reviewer_started=false")
                print("return_code=0")
                print(f"run_dir={rel(run_dir)}")
                return 0
        if step == "04_validate_reviewer_patches.py":
            should_stop, stop_report = should_stop_before_step05(run_dir)
            if should_stop:
                report = blocked_step05_report(config, run_dir, stop_report)
                write_json(run_dir / "multiagent_run_report.json", report)
                print("stopped_at=04_validate_reviewer_patches.py")
                print("return_code=0")
                print(f"run_dir={rel(run_dir)}")
                return 0

    report = run_dir / "multiagent_run_report.json"
    print(f"run_dir={rel(run_dir)}")
    print(f"multiagent_run_report={rel(report)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
