#!/usr/bin/env python3
"""Step 01: call the annotator model to generate reasoning patches."""
from __future__ import annotations

import argparse
import json
import multiprocessing as mp
from pathlib import Path
from queue import Empty
from typing import Any

from common import (
    annotator_resume_state,
    benchmark_paths,
    blocked_report,
    call_role_model,
    dedupe_error_rows,
    find_active_run,
    load_config,
    load_prompt_rows,
    print_role_api_usage,
    redact_api_config_for_report,
    rel,
    resolve_openai_compatible_api_config,
    role_request_timeout_seconds,
    safe_read_jsonl,
    sanitize_candidate_auxiliary_note,
    sanitize_reasoning_chain,
    sample_selection_summary,
    unresolved_error_rows,
    utc_now,
    write_json,
    write_jsonl,
    write_resolved_config,
)
from results_analysis.release import run_ewvaa_stage_reasoning_api_trial as ewvaa


def existing_by_key(rows: list[dict], key: str) -> dict[str, dict]:
    return {str(row.get(key, "")): row for row in rows if row.get(key)}


def approximate_token_estimate(text: str) -> int:
    """Cheap heuristic for request-size diagnostics without tokenizer deps."""
    return max(1, (len(text) + 3) // 4)


def top_string_lengths(mapping: dict[str, Any], prefix: str) -> list[tuple[str, int]]:
    pairs: list[tuple[str, int]] = []
    for key, value in mapping.items():
        name = f"{prefix}.{key}"
        if isinstance(value, str):
            pairs.append((name, len(value)))
        elif isinstance(value, list):
            for idx, item in enumerate(value):
                if isinstance(item, str):
                    pairs.append((f"{name}[{idx}]", len(item)))
    return sorted(pairs, key=lambda item: item[1], reverse=True)


def build_request_summary(
    prompt: dict[str, Any],
    canonical_sample_id: str,
    *,
    api_mode: str,
    role: str,
) -> dict[str, Any]:
    system = str(prompt.get("system", "") or "")
    user = str(prompt.get("user", "") or "")
    prompt_input = prompt.get("prompt_input") if isinstance(prompt.get("prompt_input"), dict) else {}
    primary = prompt_input.get("primary_evidence") if isinstance(prompt_input, dict) else {}
    auxiliary = prompt_input.get("auxiliary_vulnerability_context") if isinstance(prompt_input, dict) else {}
    if not isinstance(primary, dict):
        primary = {}
    if not isinstance(auxiliary, dict):
        auxiliary = {}
    messages = ewvaa.build_messages(prompt)
    edge_json_sizes = [
        len(json.dumps(edge, ensure_ascii=False))
        for edge in (primary.get("spine") or [])
        if isinstance(edge, dict)
    ]
    aux_string_lengths = top_string_lengths(auxiliary, "aux")
    return {
        "role": role,
        "api_mode": api_mode,
        "masked_sample_id": str(prompt.get("sample_id", "")),
        "sample_id": canonical_sample_id,
        "scenario_id": str(prompt.get("scenario_id", "")),
        "gold_stage": str(prompt.get("gold_stage", "")),
        "message_count": len(messages),
        "system_chars": len(system),
        "user_chars": len(user),
        "prompt_chars": len(system) + len(user),
        "approx_prompt_tokens": approximate_token_estimate(system) + approximate_token_estimate(user),
        "primary_spine_edge_count": primary.get("spine_edge_count"),
        "primary_spine_items_in_prompt": len(primary.get("spine") or []),
        "primary_spine_truncated": primary.get("spine_truncated"),
        "primary_max_edge_chars": max(edge_json_sizes) if edge_json_sizes else 0,
        "primary_total_edge_chars_in_prompt": sum(edge_json_sizes),
        "auxiliary_context_present": bool(auxiliary),
        "auxiliary_chars": len(json.dumps(auxiliary, ensure_ascii=False)),
        "auxiliary_cve_count": len(auxiliary.get("cve_ids") or []),
        "auxiliary_source_extracts_count": len(auxiliary.get("source_extracts") or []),
        "largest_aux_string_fields": aux_string_lengths[:6],
    }


def summarize_prompt_selection(
    prompts: list[dict[str, Any]],
    id_maps: dict[str, dict[str, str]],
    *,
    sample_id: str | None,
    start_index: int,
    max_samples: int | None,
) -> tuple[list[dict[str, Any]], list[str]]:
    rows: list[dict[str, Any]] = []
    for prompt in prompts:
        masked_sample_id = str(prompt.get("sample_id", "") or "")
        canonical_sample_id = str(id_maps["sample_id"].get(masked_sample_id, masked_sample_id))
        if sample_id and sample_id not in {masked_sample_id, canonical_sample_id}:
            continue
        rows.append(
            {
                "masked_sample_id": masked_sample_id,
                "canonical_sample_id": canonical_sample_id,
                "prompt": prompt,
            }
        )
    if start_index > 1:
        rows = rows[start_index - 1 :]
    if max_samples is not None:
        rows = rows[:max_samples]
    return [row["prompt"] for row in rows], [row["canonical_sample_id"] for row in rows]


def print_request_summaries(
    prompts: list[dict[str, Any]],
    id_maps: dict[str, dict[str, str]],
    *,
    api_mode: str,
    role: str,
) -> None:
    summaries = [
        build_request_summary(
            prompt,
            str(id_maps["sample_id"].get(str(prompt.get("sample_id", "") or ""), str(prompt.get("sample_id", "") or ""))),
            api_mode=api_mode,
            role=role,
        )
        for prompt in prompts
    ]
    payload: dict[str, Any] = {
        "summary_count": len(summaries),
        "summaries": summaries,
    }
    if summaries:
        prompt_sizes = [int(item["prompt_chars"]) for item in summaries]
        payload["aggregate"] = {
            "max_prompt_chars": max(prompt_sizes),
            "min_prompt_chars": min(prompt_sizes),
            "selected_masked_sample_ids": [item["masked_sample_id"] for item in summaries],
        }
    print(json.dumps(payload, ensure_ascii=False, indent=2))


def _call_role_model_worker(
    queue: Any,
    config: dict[str, Any],
    prompt: dict[str, Any],
    role: str,
    api_config: dict[str, Any],
    request_timeout_seconds: float | None,
) -> None:
    try:
        result = call_role_model(
            config,
            prompt,
            role,
            api_config,
            request_timeout_seconds=request_timeout_seconds,
        )
        queue.put({"ok": True, "result": result})
    except BaseException as exc:  # noqa: BLE001
        queue.put(
            {
                "ok": False,
                "error": {
                    "error": "annotator_worker_exception",
                    "error_type": exc.__class__.__name__,
                    "provider_error": str(exc),
                },
            }
        )


def call_role_model_with_hard_timeout(
    config: dict[str, Any],
    prompt: dict[str, Any],
    role: str,
    api_config: dict[str, Any],
    *,
    request_timeout_seconds: float | None,
) -> dict[str, Any]:
    timeout_seconds = float(request_timeout_seconds) if request_timeout_seconds is not None else 0.0
    if timeout_seconds <= 0:
        return call_role_model(
            config,
            prompt,
            role,
            api_config,
            request_timeout_seconds=request_timeout_seconds,
        )
    ctx = mp.get_context("spawn")
    queue: Any = ctx.Queue()
    proc = ctx.Process(
        target=_call_role_model_worker,
        args=(queue, config, prompt, role, api_config, request_timeout_seconds),
        daemon=True,
    )
    proc.start()
    proc.join(timeout_seconds)
    if proc.is_alive():
        proc.terminate()
        proc.join(5)
        if proc.is_alive():
            proc.kill()
            proc.join(5)
        queue.close()
        return {
            "error": "request_timeout_hard",
            "error_type": "request_timeout_hard",
            "provider_error": f"annotator_request_exceeded_hard_timeout:{timeout_seconds:g}s",
            "sample_id": str(prompt.get("sample_id", "")),
            "base_url": str(api_config.get("annotator_base_url", "")),
            "model": str(api_config.get("annotator_model", "")),
            "api_mode": str(api_config.get("annotator_api_mode", "chat_completions") or "chat_completions"),
            "api_key_present": bool(api_config.get("annotator_api_key")),
            "elapsed_seconds": timeout_seconds,
        }
    payload: dict[str, Any] | None = None
    try:
        payload = queue.get_nowait()
    except Empty:
        payload = None
    finally:
        queue.close()
    if isinstance(payload, dict) and payload.get("ok") is True and isinstance(payload.get("result"), dict):
        return payload["result"]
    if isinstance(payload, dict) and payload.get("ok") is False and isinstance(payload.get("error"), dict):
        error = dict(payload["error"])
        error.setdefault("sample_id", str(prompt.get("sample_id", "")))
        error.setdefault("base_url", str(api_config.get("annotator_base_url", "")))
        error.setdefault("model", str(api_config.get("annotator_model", "")))
        error.setdefault("api_mode", str(api_config.get("annotator_api_mode", "chat_completions") or "chat_completions"))
        error.setdefault("api_key_present", bool(api_config.get("annotator_api_key")))
        return error
    return {
        "error": "annotator_worker_no_result",
        "error_type": "annotator_worker_no_result",
        "provider_error": f"annotator worker exited with code {proc.exitcode}",
        "sample_id": str(prompt.get("sample_id", "")),
        "base_url": str(api_config.get("annotator_base_url", "")),
        "model": str(api_config.get("annotator_model", "")),
        "api_mode": str(api_config.get("annotator_api_mode", "chat_completions") or "chat_completions"),
        "api_key_present": bool(api_config.get("annotator_api_key")),
    }


def completed_masked_sample_ids(masked_rows: list[dict], unmasked_rows: list[dict]) -> set[str]:
    masked_ids = {str(row.get("sample_id", "")) for row in masked_rows if row.get("sample_id")}
    unmasked_ids = {str(row.get("masked_sample_id", "")) for row in unmasked_rows if row.get("masked_sample_id")}
    return {sample_id for sample_id in masked_ids & unmasked_ids if sample_id}


def make_counts(
    prompts: list[dict[str, Any]],
    masked_rows: list[dict],
    unmasked_rows: list[dict],
    raw_rows: list[dict],
    *,
    api_errors: list[dict],
    parse_failures: list[dict],
    unmask_failures: list[dict],
    calls_made: int,
    skipped_completed: int,
) -> dict[str, int]:
    completed_ids = completed_masked_sample_ids(masked_rows, unmasked_rows)
    return {
        "prompts": len(prompts),
        "raw_responses": len(raw_rows),
        "patches_masked": len(masked_rows),
        "patches_unmasked": len(unmasked_rows),
        "completed_samples": len(completed_ids),
        "pending_samples": max(0, len(prompts) - len(completed_ids)),
        "api_errors": len(api_errors),
        "parse_failures": len(parse_failures),
        "unmask_failures": len(unmask_failures),
        "calls_made_this_invocation": calls_made,
        "skipped_completed_this_invocation": skipped_completed,
    }


def write_progress(
    run_dir: Path,
    prompts: list[dict[str, Any]],
    masked_rows: list[dict],
    unmasked_rows: list[dict],
    raw_rows: list[dict],
    *,
    api_errors: list[dict],
    parse_failures: list[dict],
    unmask_failures: list[dict],
    calls_made: int,
    skipped_completed: int,
    effective_timeout_seconds: float,
    current_sample: dict[str, Any] | None,
    progress_status: str | None = None,
) -> None:
    completed_ids = completed_masked_sample_ids(masked_rows, unmasked_rows)
    ordered_completed_ids = [
        str(prompt.get("sample_id", ""))
        for prompt in prompts
        if str(prompt.get("sample_id", "")) in completed_ids
    ]
    pending_ids = [
        str(prompt.get("sample_id", ""))
        for prompt in prompts
        if str(prompt.get("sample_id", "")) not in completed_ids
    ]
    progress = {
        "status": progress_status or ("running" if pending_ids else "success"),
        "updated_at": utc_now(),
        "run_dir": rel(run_dir),
        "effective_request_timeout_seconds": effective_timeout_seconds,
        "resume_skip_completed_enabled": True,
        "current_sample": current_sample,
        "counts": make_counts(
            prompts,
            masked_rows,
            unmasked_rows,
            raw_rows,
            api_errors=api_errors,
            parse_failures=parse_failures,
            unmask_failures=unmask_failures,
            calls_made=calls_made,
            skipped_completed=skipped_completed,
        ),
        "completed_masked_sample_ids": ordered_completed_ids,
        "pending_masked_sample_ids": pending_ids,
        "api_errors": api_errors,
        "parse_failures": parse_failures,
        "unmask_failures": unmask_failures,
    }
    write_json(run_dir / "annotator_progress.json", progress)


def build_report(
    config: dict[str, Any],
    run_dir: Path,
    api_config: dict[str, Any],
    prompts: list[dict[str, Any]],
    selected_sample_ids: list[str],
    raw_rows: list[dict],
    masked_rows: list[dict],
    unmasked_rows: list[dict],
    *,
    api_errors: list[dict],
    parse_failures: list[dict],
    unmask_failures: list[dict],
    calls_made: int,
    skipped_completed: int,
    effective_timeout_seconds: float,
    status: str,
) -> dict[str, Any]:
    resume_state = annotator_resume_state(
        selected_sample_ids,
        unmasked_rows,
        api_errors=api_errors,
        parse_failures=parse_failures,
        unmask_failures=unmask_failures,
    )
    return {
        "status": status,
        "created_at": utc_now(),
        "run_dir": rel(run_dir),
        **redact_api_config_for_report(api_config),
        "api_called": bool(calls_made or raw_rows),
        "api_key_recorded": False,
        "benchmark_files_modified": False,
        "effective_request_timeout_seconds": effective_timeout_seconds,
        "resume_skip_completed_enabled": True,
        **sample_selection_summary(config, selected_sample_ids),
        "inputs": {
            "config": config["config_path"],
            "prompt_pack": config["prompt_pack"],
            "workbench_dir": config["workbench_dir"],
        },
        "outputs": {
            "run_config_resolved": rel(run_dir / "run_config.resolved.yaml"),
            "raw_annotator_responses": rel(run_dir / "raw_annotator_responses.jsonl"),
            "reasoning_patches_masked_annotator": rel(run_dir / "reasoning_patches.masked.annotator.jsonl"),
            "reasoning_patches_unmasked_annotator": rel(run_dir / "reasoning_patches.unmasked.annotator.jsonl"),
            "annotator_progress": rel(run_dir / "annotator_progress.json"),
            "annotator_run_report": rel(run_dir / "annotator_run_report.json"),
        },
        "counts": make_counts(
            prompts,
            masked_rows,
            unmasked_rows,
            raw_rows,
            api_errors=api_errors,
            parse_failures=parse_failures,
            unmask_failures=unmask_failures,
            calls_made=calls_made,
            skipped_completed=skipped_completed,
        ),
        "resume_state": resume_state,
        "api_errors": api_errors,
        "parse_failures": parse_failures,
        "unmask_failures": unmask_failures,
    }


def persist_state(
    config: dict[str, Any],
    run_dir: Path,
    api_config: dict[str, Any],
    prompts: list[dict[str, Any]],
    selected_sample_ids: list[str],
    raw_rows: list[dict],
    masked_rows: list[dict],
    unmasked_rows: list[dict],
    *,
    api_errors: list[dict],
    parse_failures: list[dict],
    unmask_failures: list[dict],
    calls_made: int,
    skipped_completed: int,
    effective_timeout_seconds: float,
    current_sample: dict[str, Any] | None,
    report_status: str,
    progress_status: str | None = None,
) -> None:
    write_jsonl(run_dir / "raw_annotator_responses.jsonl", raw_rows)
    write_jsonl(run_dir / "reasoning_patches.masked.annotator.jsonl", masked_rows)
    write_jsonl(run_dir / "reasoning_patches.unmasked.annotator.jsonl", unmasked_rows)
    write_progress(
        run_dir,
        prompts,
        masked_rows,
        unmasked_rows,
        raw_rows,
        api_errors=api_errors,
        parse_failures=parse_failures,
        unmask_failures=unmask_failures,
        calls_made=calls_made,
        skipped_completed=skipped_completed,
        effective_timeout_seconds=effective_timeout_seconds,
        current_sample=current_sample,
        progress_status=progress_status,
    )
    write_json(
        run_dir / "annotator_run_report.json",
        build_report(
            config,
            run_dir,
            api_config,
            prompts,
            selected_sample_ids,
            raw_rows,
            masked_rows,
            unmasked_rows,
            api_errors=api_errors,
            parse_failures=parse_failures,
            unmask_failures=unmask_failures,
            calls_made=calls_made,
            skipped_completed=skipped_completed,
            effective_timeout_seconds=effective_timeout_seconds,
            status=report_status,
        ),
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Generate EWVAA annotator reasoning patches. Existing complete sample_ids in the "
            "active run_dir are skipped automatically so the command can safely resume."
        )
    )
    parser.add_argument("--config", type=Path, default=None)
    parser.add_argument(
        "--use-env-api-config",
        action="store_true",
        help="Explicitly allow reading OPENAI_* API config. Default is interactive input or EWVAA_RUN_* only.",
    )
    parser.add_argument(
        "--request-timeout-seconds",
        type=float,
        default=None,
        help=(
            "Override the per-sample annotator request timeout in seconds. "
            "This value is used for the provider client timeout and the outer hard timeout. "
            "When omitted, the runtime config default is 900 seconds."
        ),
    )
    parser.add_argument(
        "--stop-on-api-error",
        action="store_true",
        help="Stop after the first annotator API error or timeout. Default behavior is to record the error and continue with remaining incomplete samples.",
    )
    parser.add_argument(
        "--sample-id",
        default=None,
        help="Run only one sample_id. Accepts either masked sample_id or canonical sample_id.",
    )
    parser.add_argument(
        "--max-samples",
        type=int,
        default=None,
        help="After filtering and start-index, keep at most N prompts.",
    )
    parser.add_argument(
        "--start-index",
        type=int,
        default=1,
        help="1-based index into the filtered prompt list before API calls.",
    )
    parser.add_argument(
        "--diagnose-request-only",
        action="store_true",
        help="Build the selected request(s) and print request summaries without calling API.",
    )
    parser.add_argument(
        "--dump-request-summary",
        action="store_true",
        help="Print request summary JSON for the selected prompt set before any API call.",
    )
    args = parser.parse_args()
    from common import CONFIG_DEFAULT, ROOT

    if args.max_samples is not None and args.max_samples <= 0:
        raise SystemExit("--max-samples must be greater than 0.")
    if args.start_index <= 0:
        raise SystemExit("--start-index must be 1 or greater.")

    config_path = args.config or CONFIG_DEFAULT
    config_path = config_path if config_path.is_absolute() else ROOT / config_path
    config = load_config(config_path)
    run_dir = find_active_run(config, create=True)
    assert run_dir is not None

    paths = benchmark_paths(config)
    missing_paths = [
        str(path)
        for path in (paths["prompt_pack"], paths["id_map_dir"], paths["gold"], paths["model_input"], paths["sample_index"])
        if not Path(path).exists()
    ]
    if missing_paths:
        report = {
            "status": "failed",
            "created_at": utc_now(),
            "run_dir": rel(run_dir),
            "errors": ["missing_path:" + path for path in missing_paths],
            "api_called": False,
            "benchmark_files_modified": False,
        }
        write_json(run_dir / "annotator_run_report.json", report)
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return 1

    effective_timeout_seconds = role_request_timeout_seconds(config, "annotator", args.request_timeout_seconds)
    prompts_all = load_prompt_rows(config)
    id_maps = ewvaa.load_id_maps(paths["id_map_dir"])
    prompts, selected_sample_ids = summarize_prompt_selection(
        prompts_all,
        id_maps,
        sample_id=args.sample_id,
        start_index=args.start_index,
        max_samples=args.max_samples,
    )
    if not prompts:
        raise SystemExit("No prompts matched the requested --sample-id/--start-index/--max-samples selection.")

    if args.diagnose_request_only or args.dump_request_summary:
        print_request_summaries(
            prompts,
            id_maps,
            api_mode=str(config.get("annotator_api_mode", "chat_completions") or "chat_completions"),
            role="annotator",
        )
        if args.diagnose_request_only:
            return 0

    api_config = resolve_openai_compatible_api_config(
        config,
        role="annotator",
        use_env_api_config=args.use_env_api_config,
    )
    write_resolved_config(run_dir, config, api_config)
    if api_config.get("blocked"):
        report = blocked_report(config, run_dir, "annotator", "annotator_run_report.json", api_config=api_config)
        print("BLOCKED: " + report["blocked_reason"])
        print(f"run_dir={run_dir}")
        return 1
    print_role_api_usage(api_config, "annotator")

    existing_raw = safe_read_jsonl(run_dir / "raw_annotator_responses.jsonl")
    existing_masked = safe_read_jsonl(run_dir / "reasoning_patches.masked.annotator.jsonl")
    existing_unmasked = safe_read_jsonl(run_dir / "reasoning_patches.unmasked.annotator.jsonl")
    existing_report: dict[str, Any] = {}
    report_path = run_dir / "annotator_run_report.json"
    if report_path.exists():
        try:
            existing_report = json.loads(report_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            existing_report = {}
    completed_ids = completed_masked_sample_ids(existing_masked, existing_unmasked)

    raw_rows = list(existing_raw)
    masked_rows = list(existing_masked)
    unmasked_rows = list(existing_unmasked)
    parse_failures: list[dict] = dedupe_error_rows(
        list(existing_report.get("parse_failures", [])) if isinstance(existing_report, dict) else []
    )
    unmask_failures: list[dict] = dedupe_error_rows(
        list(existing_report.get("unmask_failures", [])) if isinstance(existing_report, dict) else []
    )
    api_errors: list[dict] = dedupe_error_rows(
        list(existing_report.get("api_errors", [])) if isinstance(existing_report, dict) else []
    )
    calls_made = 0
    skipped_completed = 0

    initial_resume_state = annotator_resume_state(
        selected_sample_ids,
        unmasked_rows,
        api_errors=api_errors,
        parse_failures=parse_failures,
        unmask_failures=unmask_failures,
    )
    print(
        json.dumps(
            {
                "annotator_resume_state": initial_resume_state,
                "resume_policy": {
                    "skip_completed": True,
                    "retry_targets": "failed_transient_transport + unattempted",
                    "force_overwrite_completed": False,
                },
            },
            ensure_ascii=False,
            indent=2,
        )
    )

    persist_state(
        config,
        run_dir,
        api_config,
        prompts,
        selected_sample_ids,
        raw_rows,
        masked_rows,
        unmasked_rows,
        api_errors=api_errors,
        parse_failures=parse_failures,
        unmask_failures=unmask_failures,
        calls_made=calls_made,
        skipped_completed=skipped_completed,
        effective_timeout_seconds=effective_timeout_seconds,
        current_sample=None,
        report_status="running",
    )

    for idx, prompt in enumerate(prompts, 1):
        masked_sample_id = str(prompt.get("sample_id", ""))
        canonical_sample_id = str(id_maps["sample_id"].get(masked_sample_id, masked_sample_id))
        if masked_sample_id in completed_ids:
            skipped_completed += 1
            continue
        print(f"[01 {idx}/{len(prompts)}] annotator {masked_sample_id} stage={prompt.get('gold_stage')}", flush=True)
        current_sample = {
            "index": idx,
            "total": len(prompts),
            "masked_sample_id": masked_sample_id,
            "sample_id": canonical_sample_id,
            "gold_stage": prompt.get("gold_stage"),
            "phase": "calling_api",
        }
        persist_state(
            config,
            run_dir,
            api_config,
            prompts,
            selected_sample_ids,
            raw_rows,
            masked_rows,
            unmasked_rows,
            api_errors=api_errors,
            parse_failures=parse_failures,
            unmask_failures=unmask_failures,
            calls_made=calls_made,
            skipped_completed=skipped_completed,
            effective_timeout_seconds=effective_timeout_seconds,
            current_sample=current_sample,
            report_status="running",
        )
        result = call_role_model_with_hard_timeout(
            config,
            prompt,
            "annotator",
            api_config,
            request_timeout_seconds=effective_timeout_seconds,
        )
        calls_made += 1
        raw_rows.append(
            {
                "sample_id": masked_sample_id,
                "canonical_sample_id": canonical_sample_id,
                "gold_stage": prompt.get("gold_stage"),
                **result,
            }
        )
        if "error" in result:
            api_errors.append({"sample_id": canonical_sample_id, "error": str(result["error"])[:300]})
            api_errors[:] = dedupe_error_rows(api_errors)
            current_sample = {
                **current_sample,
                "phase": "api_error",
                "result": str(result.get("error", ""))[:300],
            }
            persist_state(
                config,
                run_dir,
                api_config,
                prompts,
                selected_sample_ids,
                raw_rows,
                masked_rows,
                unmasked_rows,
                api_errors=api_errors,
                parse_failures=parse_failures,
                unmask_failures=unmask_failures,
                calls_made=calls_made,
                skipped_completed=skipped_completed,
                effective_timeout_seconds=effective_timeout_seconds,
                current_sample=current_sample,
                report_status="error",
                progress_status="error",
            )
            if args.stop_on_api_error:
                final_status = "partial" if completed_masked_sample_ids(masked_rows, unmasked_rows) else "failed"
                persist_state(
                    config,
                    run_dir,
                    api_config,
                    prompts,
                    selected_sample_ids,
                    raw_rows,
                    masked_rows,
                    unmasked_rows,
                    api_errors=api_errors,
                    parse_failures=parse_failures,
                    unmask_failures=unmask_failures,
                    calls_made=calls_made,
                    skipped_completed=skipped_completed,
                    effective_timeout_seconds=effective_timeout_seconds,
                    current_sample=current_sample,
                    report_status=final_status,
                    progress_status=final_status,
                )
                print(
                    json.dumps(
                        build_report(
                            config,
                            run_dir,
                            api_config,
                            prompts,
                            selected_sample_ids,
                            raw_rows,
                            masked_rows,
                            unmasked_rows,
                            api_errors=api_errors,
                            parse_failures=parse_failures,
                            unmask_failures=unmask_failures,
                            calls_made=calls_made,
                            skipped_completed=skipped_completed,
                            effective_timeout_seconds=effective_timeout_seconds,
                            status=final_status,
                        ),
                        ensure_ascii=False,
                        indent=2,
                    )
                )
                return 1
            continue
        parsed = ewvaa.extract_json(str(result.get("raw_content", "")))
        if parsed is None:
            parse_failures.append({"sample_id": canonical_sample_id, "masked_sample_id": masked_sample_id})
            parse_failures[:] = dedupe_error_rows(parse_failures)
            current_sample = {
                **current_sample,
                "phase": "parse_failure",
                "result": "extract_json_returned_none",
            }
            persist_state(
                config,
                run_dir,
                api_config,
                prompts,
                selected_sample_ids,
                raw_rows,
                masked_rows,
                unmasked_rows,
                api_errors=api_errors,
                parse_failures=parse_failures,
                unmask_failures=unmask_failures,
                calls_made=calls_made,
                skipped_completed=skipped_completed,
                effective_timeout_seconds=effective_timeout_seconds,
                current_sample=current_sample,
                report_status="running",
            )
            continue
        if parsed.get("sample_id") != masked_sample_id:
            parse_failures.append(
                {
                    "sample_id": canonical_sample_id,
                    "masked_sample_id": masked_sample_id,
                    "error": f"sample_id_mismatch:{parsed.get('sample_id')}",
                }
            )
            parse_failures[:] = dedupe_error_rows(parse_failures)
            current_sample = {
                **current_sample,
                "phase": "parse_failure",
                "result": f"sample_id_mismatch:{parsed.get('sample_id')}",
            }
            persist_state(
                config,
                run_dir,
                api_config,
                prompts,
                selected_sample_ids,
                raw_rows,
                masked_rows,
                unmasked_rows,
                api_errors=api_errors,
                parse_failures=parse_failures,
                unmask_failures=unmask_failures,
                calls_made=calls_made,
                skipped_completed=skipped_completed,
                effective_timeout_seconds=effective_timeout_seconds,
                current_sample=current_sample,
                report_status="running",
            )
            continue
        parsed_unmasked, unmask_errors = ewvaa.unmask_patch(parsed, id_maps)
        if unmask_errors:
            unmask_failures.append(
                {"sample_id": canonical_sample_id, "masked_sample_id": masked_sample_id, "errors": unmask_errors}
            )
            unmask_failures[:] = dedupe_error_rows(unmask_failures)
            current_sample = {
                **current_sample,
                "phase": "unmask_failure",
                "result": f"errors:{len(unmask_errors)}",
            }
            persist_state(
                config,
                run_dir,
                api_config,
                prompts,
                selected_sample_ids,
                raw_rows,
                masked_rows,
                unmasked_rows,
                api_errors=api_errors,
                parse_failures=parse_failures,
                unmask_failures=unmask_failures,
                calls_made=calls_made,
                skipped_completed=skipped_completed,
                effective_timeout_seconds=effective_timeout_seconds,
                current_sample=current_sample,
                report_status="running",
            )
            continue
        masked_rows.append(
            {
                "sample_id": masked_sample_id,
                "canonical_sample_id": canonical_sample_id,
                "gold_stage": prompt.get("gold_stage"),
                "gold_reasoning_chain": sanitize_reasoning_chain(parsed.get("gold_reasoning_chain")),
                "auxiliary_vulnerability_note": sanitize_candidate_auxiliary_note(
                    parsed.get("auxiliary_vulnerability_note")
                ),
                "source": "annotator",
            }
        )
        unmasked_rows.append(
            {
                "sample_id": canonical_sample_id,
                "masked_sample_id": masked_sample_id,
                "gold_stage": parsed_unmasked.get("gold_stage") or prompt.get("gold_stage"),
                "gold_reasoning_chain": sanitize_reasoning_chain(parsed_unmasked.get("gold_reasoning_chain")),
                "auxiliary_vulnerability_note": sanitize_candidate_auxiliary_note(
                    parsed_unmasked.get("auxiliary_vulnerability_note")
                ),
                "source": "annotator",
            }
        )
        completed_ids.add(masked_sample_id)
        completed_sample_ids = [
            str(id_maps["sample_id"].get(masked_id, masked_id))
            for masked_id in completed_ids
        ]
        api_errors[:] = unresolved_error_rows(api_errors, completed_sample_ids)
        parse_failures[:] = unresolved_error_rows(parse_failures, completed_sample_ids)
        unmask_failures[:] = unresolved_error_rows(unmask_failures, completed_sample_ids)
        current_sample = {
            **current_sample,
            "phase": "completed",
            "result": "patch_persisted",
        }
        persist_state(
            config,
            run_dir,
            api_config,
            prompts,
            selected_sample_ids,
            raw_rows,
            masked_rows,
            unmasked_rows,
            api_errors=api_errors,
            parse_failures=parse_failures,
            unmask_failures=unmask_failures,
            calls_made=calls_made,
            skipped_completed=skipped_completed,
            effective_timeout_seconds=effective_timeout_seconds,
            current_sample=current_sample,
            report_status="running",
        )

    completed_count = len(completed_masked_sample_ids(masked_rows, unmasked_rows))
    status = "success" if completed_count == len(prompts) else "partial" if unmasked_rows else "failed"
    report = build_report(
        config,
        run_dir,
        api_config,
        prompts,
        selected_sample_ids,
        raw_rows,
        masked_rows,
        unmasked_rows,
        api_errors=api_errors,
        parse_failures=parse_failures,
        unmask_failures=unmask_failures,
        calls_made=calls_made,
        skipped_completed=skipped_completed,
        effective_timeout_seconds=effective_timeout_seconds,
        status=status,
    )
    write_json(
        run_dir / "annotator_progress.json",
        {
            **json.loads((run_dir / "annotator_progress.json").read_text(encoding="utf-8")),
            "status": status,
            "updated_at": utc_now(),
            "current_sample": None,
        },
    )
    write_json(run_dir / "annotator_run_report.json", report)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if unmasked_rows else 1


if __name__ == "__main__":
    raise SystemExit(main())
