"""Shared helpers for the EWVAA multi-agent gold pipeline."""
from __future__ import annotations

import json
import os
import sys
from getpass import getpass
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from results_analysis.release import run_ewvaa_stage_reasoning_api_trial as ewvaa  # noqa: E402


CONFIG_DEFAULT = ROOT / "results_analysis/benchmark_pipeline/configs/public_annotation_review.yaml"
DEFAULT_WORKBENCH_DIR = (
    ROOT
    / "annotation_workdir/compact_annotation_workbench"
)
LEGACY_WORKBENCH_DIR = (
    ROOT
    / "annotation_workdir/compact_annotation_workbench"
)
LEGACY_WORKBENCH_ROOT = ROOT / "historical_workbench_not_distributed"
ALLOW_LEGACY_WORKBENCH_DEFAULTS_ENV = "EWVAA_ALLOW_LEGACY_WORKBENCH_DEFAULTS"
TERMINAL_STATUSES = {"success", "partial", "failed"}
MAX_TOKENS = 4096
LEGACY_RUN_BASE_URL_ENV = "EWVAA_RUN_OPENAI_BASE_URL"
LEGACY_RUN_API_KEY_ENV = "EWVAA_RUN_OPENAI_API_KEY"
RUN_ANNOTATOR_BASE_URL_ENV = "EWVAA_RUN_ANNOTATOR_BASE_URL"
RUN_ANNOTATOR_API_KEY_ENV = "EWVAA_RUN_ANNOTATOR_API_KEY"
RUN_ANNOTATOR_MODEL_ENV = "EWVAA_RUN_ANNOTATOR_MODEL"
RUN_ANNOTATOR_API_MODE_ENV = "EWVAA_RUN_ANNOTATOR_API_MODE"
RUN_REVIEWER_BASE_URL_ENV = "EWVAA_RUN_REVIEWER_BASE_URL"
RUN_REVIEWER_API_KEY_ENV = "EWVAA_RUN_REVIEWER_API_KEY"
RUN_REVIEWER_MODEL_ENV = "EWVAA_RUN_REVIEWER_MODEL"
RUN_REVIEWER_API_MODE_ENV = "EWVAA_RUN_REVIEWER_API_MODE"
RUN_API_CONFIG_SOURCE_ENV = "EWVAA_RUN_API_CONFIG_SOURCE"


JsonObj = dict[str, Any]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def rel(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(ROOT))
    except ValueError:
        return str(path)


def resolve_path(value: str | Path) -> Path:
    raw = str(value)
    if os.name != "nt":
        raw = raw.replace("\\", "/")
    path = Path(raw)
    return path if path.is_absolute() else ROOT / path


def is_legacy_workbench_path(path: Path) -> bool:
    try:
        path.resolve().relative_to(LEGACY_WORKBENCH_ROOT.resolve())
        return True
    except ValueError:
        return False


def guard_legacy_workbench_defaults(
    *,
    config_path: Path,
    workbench_dir: Path,
    output_root: Path,
    allow_legacy_defaults: bool,
) -> None:
    if allow_legacy_defaults:
        return
    legacy_fields = []
    if is_legacy_workbench_path(workbench_dir):
        legacy_fields.append(f"workbench_dir={rel(workbench_dir)}")
    if is_legacy_workbench_path(output_root):
        legacy_fields.append(f"output_root={rel(output_root)}")
    if not legacy_fields:
        return
    raise SystemExit(
        "Legacy workbench defaults are fenced for current public workflows. "
        f"Config {rel(config_path)} still resolves {', '.join(legacy_fields)}. "
        "Set explicit non-legacy paths, or opt into a historical run with "
        "allow_legacy_workbench_defaults: true or "
        f"{ALLOW_LEGACY_WORKBENCH_DEFAULTS_ENV}=1."
    )


def parse_scalar(raw: str) -> Any:
    value = raw.strip()
    if value == "null":
        return None
    if value == "true":
        return True
    if value == "false":
        return False
    if (value.startswith('"') and value.endswith('"')) or (value.startswith("'") and value.endswith("'")):
        return value[1:-1]
    if value.startswith("[") or value.startswith("{"):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            pass
    try:
        if "." in value:
            return float(value)
        return int(value)
    except ValueError:
        return value


def load_simple_yaml(path: Path) -> dict[str, Any]:
    root: dict[str, Any] = {}
    stack: list[tuple[int, dict[str, Any]]] = [(-1, root)]
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            continue
        indent = len(raw_line) - len(raw_line.lstrip(" "))
        line = raw_line.strip()
        if ":" not in line:
            raise ValueError(f"Unsupported YAML line in {path}: {raw_line!r}")
        key, value = line.split(":", 1)
        key = key.strip()
        value = value.strip()
        while stack and indent <= stack[-1][0]:
            stack.pop()
        parent = stack[-1][1]
        if value == "":
            child: dict[str, Any] = {}
            parent[key] = child
            stack.append((indent, child))
        else:
            parent[key] = parse_scalar(value)
    return root


def yaml_scalar(value: Any) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, (int, float)):
        return str(value)
    text = str(value)
    if not text or any(ch in text for ch in ":#\n") or text.lower() in {"true", "false", "null"}:
        return json.dumps(text, ensure_ascii=False)
    return text


def dump_simple_yaml(value: dict[str, Any], indent: int = 0) -> str:
    lines: list[str] = []
    pad = " " * indent
    for key, item in value.items():
        if isinstance(item, dict):
            lines.append(f"{pad}{key}:")
            lines.append(dump_simple_yaml(item, indent + 2))
        elif isinstance(item, list):
            lines.append(f"{pad}{key}: {json.dumps(item, ensure_ascii=False)}")
        else:
            lines.append(f"{pad}{key}: {yaml_scalar(item)}")
    return "\n".join(lines)


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def read_jsonl(path: Path) -> list[JsonObj]:
    rows: list[JsonObj] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, 1):
            text = line.strip()
            if not text:
                continue
            row = json.loads(text)
            if isinstance(row, dict):
                row["_line_no"] = line_no
                rows.append(row)
    return rows


def _dedupe_preserve_order(values: Iterable[Any]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        text = str(value or "").strip()
        if not text or text in seen:
            continue
        seen.add(text)
        result.append(text)
    return result


def read_sample_id_file(path: Path) -> list[str]:
    sample_ids: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        text = line.strip()
        if not text or text.startswith("#"):
            continue
        sample_ids.append(text)
    return _dedupe_preserve_order(sample_ids)


def _walk_sample_ids(value: Any) -> Iterable[str]:
    if isinstance(value, dict):
        sample_id = value.get("sample_id")
        if sample_id is not None:
            yield str(sample_id)
        for item in value.values():
            yield from _walk_sample_ids(item)
    elif isinstance(value, list):
        for item in value:
            yield from _walk_sample_ids(item)


def read_sample_plan(path: Path) -> list[str]:
    suffix = path.suffix.lower()
    if suffix == ".jsonl":
        return _dedupe_preserve_order(row.get("sample_id") for row in read_jsonl(path))
    if suffix == ".json":
        return _dedupe_preserve_order(_walk_sample_ids(read_json(path)))
    return read_sample_id_file(path)


def configured_sample_ids(config: JsonObj) -> list[str]:
    explicit_ids = config.get("selected_sample_ids")
    if isinstance(explicit_ids, list):
        return _dedupe_preserve_order(explicit_ids)
    sample_id_file = str(config.get("sample_id_file") or "").strip()
    if sample_id_file:
        return read_sample_id_file(resolve_path(sample_id_file))
    sample_plan = str(config.get("sample_plan") or "").strip()
    if sample_plan:
        return read_sample_plan(resolve_path(sample_plan))
    return []


def sample_selection_mode(config: JsonObj) -> str:
    if str(config.get("sample_plan") or "").strip():
        return "sample_plan"
    if str(config.get("sample_id_file") or "").strip() or configured_sample_ids(config):
        return "sample_id_file"
    if config.get("limit") is not None:
        return "limit"
    return "all"


def sample_selection_summary(config: JsonObj, selected_ids: Iterable[Any] | None = None) -> JsonObj:
    ids = _dedupe_preserve_order(selected_ids if selected_ids is not None else configured_sample_ids(config))
    return {
        "sample_selection_mode": sample_selection_mode(config),
        "sample_id_file": str(config.get("sample_id_file") or ""),
        "sample_plan": str(config.get("sample_plan") or ""),
        "selected_sample_count": len(ids),
        "selected_sample_ids": ids,
    }


def write_jsonl(path: Path, rows: Iterable[JsonObj]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            clean = {key: value for key, value in row.items() if not key.startswith("_")}
            handle.write(json.dumps(clean, ensure_ascii=False) + "\n")
            count += 1
    return count


def sanitize_reasoning_chain(chain: Any) -> Any:
    return ewvaa.sanitize_reasoning_chain(chain)


def sanitize_candidate_auxiliary_note(note: Any) -> Any:
    if not isinstance(note, dict):
        return note
    clean: JsonObj = {}
    if "claim" in note:
        clean["claim"] = note.get("claim")
    clean["not_for_scoring"] = True
    return clean


def sanitize_candidate_patch(patch: JsonObj) -> JsonObj:
    clean = {key: value for key, value in patch.items() if not key.startswith("_")}
    if "gold_reasoning_chain" in clean:
        clean["gold_reasoning_chain"] = sanitize_reasoning_chain(clean.get("gold_reasoning_chain"))
    if "auxiliary_vulnerability_note" in clean:
        clean["auxiliary_vulnerability_note"] = sanitize_candidate_auxiliary_note(
            clean.get("auxiliary_vulnerability_note")
        )
    return clean


def count_jsonl(path: Path) -> int:
    with path.open("r", encoding="utf-8") as handle:
        return sum(1 for line in handle if line.strip())


def bool_env_present(value: Any) -> bool:
    return bool(str(value or "").strip())


def role_base_url_key(role: str) -> str:
    return "annotator_base_url" if role == "annotator" else "reviewer_base_url"


def role_api_key_key(role: str) -> str:
    return "annotator_api_key" if role == "annotator" else "reviewer_api_key"


def role_model_key(role: str) -> str:
    return "annotator_model" if role == "annotator" else "reviewer_model"


def role_api_mode_key(role: str) -> str:
    return "annotator_api_mode" if role == "annotator" else "reviewer_api_mode"


def role_fallback_flag_key(role: str) -> str:
    return f"{role}_fallback_used"


def role_present_key(role: str) -> str:
    return f"{role}_api_key_present"


def load_config(config_path: Path) -> JsonObj:
    raw = load_simple_yaml(config_path)
    benchmark_root = resolve_path(str(raw["canonical_benchmark_root"]))
    workbench_dir = resolve_path(str(raw["workbench_dir"]))
    output_root = resolve_path(str(raw["output_root"]))
    active_run_dir = resolve_path(str(raw["active_run_dir"])) if raw.get("active_run_dir") else None
    allow_legacy_defaults = bool(raw.get("allow_legacy_workbench_defaults")) or (
        os.environ.get(ALLOW_LEGACY_WORKBENCH_DEFAULTS_ENV, "").strip() == "1"
    )
    guard_legacy_workbench_defaults(
        config_path=config_path,
        workbench_dir=workbench_dir,
        output_root=output_root,
        allow_legacy_defaults=allow_legacy_defaults,
    )
    resolved: JsonObj = {
        **raw,
        "allow_legacy_workbench_defaults": allow_legacy_defaults,
        "config_path": rel(config_path),
        "canonical_benchmark_root": rel(benchmark_root),
        "annotation_context": rel(resolve_path(str(raw["annotation_context"]))),
        "workbench_dir": rel(workbench_dir),
        "output_root": rel(output_root),
        "active_run_dir": rel(active_run_dir) if active_run_dir else "",
        "model_input": rel(benchmark_root / "data" / "model_input.jsonl"),
        "gold": rel(benchmark_root / "data" / "gold.jsonl"),
        "sample_index": rel(benchmark_root / "data" / "sample_index.jsonl"),
        "prompt_pack": rel(workbench_dir / "prompt_packs" / "annotation_prompts.weighted.masked.jsonl"),
        "id_map_dir": rel(workbench_dir / "id_maps"),
    }
    return resolved


def config_path_from_args(argv: list[str] | None = None) -> Path:
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, default=CONFIG_DEFAULT)
    args = parser.parse_args(argv)
    return args.config if args.config.is_absolute() else ROOT / args.config


def env_models(config: JsonObj) -> JsonObj:
    fallback_env = str(config.get("fallback_model_env", "OPENAI_MODEL"))
    annotator_env = str(config.get("annotator_model_env", "OPENAI_ANNOTATOR_MODEL"))
    reviewer_env = str(config.get("reviewer_model_env", "OPENAI_REVIEWER_MODEL"))
    annotator_base_url_env = str(config.get("annotator_base_url_env", "OPENAI_ANNOTATOR_BASE_URL"))
    annotator_api_key_env = str(config.get("annotator_api_key_env", "OPENAI_ANNOTATOR_API_KEY"))
    reviewer_base_url_env = str(config.get("reviewer_base_url_env", "OPENAI_REVIEWER_BASE_URL"))
    reviewer_api_key_env = str(config.get("reviewer_api_key_env", "OPENAI_REVIEWER_API_KEY"))
    annotator_api_mode_env = str(config.get("annotator_api_mode_env", "OPENAI_ANNOTATOR_API_MODE"))
    reviewer_api_mode_env = str(config.get("reviewer_api_mode_env", "OPENAI_REVIEWER_API_MODE"))
    fallback = os.environ.get(fallback_env, "")
    annotator = os.environ.get(annotator_env, "") or fallback
    reviewer = os.environ.get(reviewer_env, "") or fallback
    return {
        "annotator_base_url_env": annotator_base_url_env,
        "annotator_api_key_env": annotator_api_key_env,
        "annotator_model": annotator,
        "reviewer_base_url_env": reviewer_base_url_env,
        "reviewer_api_key_env": reviewer_api_key_env,
        "reviewer_model": reviewer,
        "annotator_api_mode_env": annotator_api_mode_env,
        "reviewer_api_mode_env": reviewer_api_mode_env,
        "fallback_model": fallback,
        "annotator_model_env": annotator_env,
        "reviewer_model_env": reviewer_env,
        "fallback_model_env": fallback_env,
        "annotator_model_set": bool(annotator),
        "reviewer_model_set": bool(reviewer),
    }


def normalize_api_mode(value: Any, default: str) -> str:
    mode = str(value or "").strip().lower()
    if mode in {"chat_completions", "responses"}:
        return mode
    return default


def attach_api_modes(config: JsonObj, api_config: JsonObj) -> JsonObj:
    api_config = dict(api_config)
    api_config["annotator_api_mode"] = normalize_api_mode(
        api_config.get("annotator_api_mode"),
        str(config.get("annotator_api_mode", "chat_completions")),
    )
    api_config["reviewer_api_mode"] = normalize_api_mode(
        api_config.get("reviewer_api_mode"),
        str(config.get("reviewer_api_mode", "chat_completions")),
    )
    return api_config


def _prompt_nonempty(prompt: str) -> str:
    while True:
        try:
            value = input(prompt).strip()
        except EOFError as exc:
            raise RuntimeError("interactive_api_config_required") from exc
        if value:
            return value
        print("Value is required.")


def prompt_openai_compatible_api_config(
    *,
    require_reviewer: bool = True,
    allow_same_model: bool = True,
) -> JsonObj:
    if not sys.stdin.isatty():
        return {
            "provider": "openai-compatible",
            "blocked": True,
            "blocked_reason": "interactive_api_config_required",
            "source": "interactive",
        }
    try:
        annotator_base_url = _prompt_nonempty("Enter annotator OpenAI-compatible base_url: ")
        try:
            annotator_api_key = getpass("Enter annotator api_key: ").strip()
        except EOFError as exc:
            raise RuntimeError("interactive_api_config_required") from exc
        while not annotator_api_key:
            print("API key is required.")
            try:
                annotator_api_key = getpass("Enter annotator api_key: ").strip()
            except EOFError as exc:
                raise RuntimeError("api_config_missing") from exc
        annotator_model = _prompt_nonempty("Enter annotator model: ")
        reviewer_base_url = ""
        reviewer_api_key = ""
        reviewer_model = ""
        if require_reviewer:
            try:
                reviewer_base_url = _prompt_nonempty("Enter reviewer OpenAI-compatible base_url: ")
                reviewer_api_key = getpass("Enter reviewer api_key: ").strip()
            except EOFError as exc:
                raise RuntimeError("interactive_api_config_required") from exc
            while not reviewer_api_key:
                print("API key is required.")
                try:
                    reviewer_api_key = getpass("Enter reviewer api_key: ").strip()
                except EOFError as exc:
                    raise RuntimeError("api_config_missing") from exc
            reviewer_model = _prompt_nonempty("Enter reviewer model: ")
        else:
            reviewer_base_url = annotator_base_url if allow_same_model else ""
            reviewer_api_key = annotator_api_key if allow_same_model else ""
            reviewer_model = annotator_model if allow_same_model else ""
    except RuntimeError as exc:
        return {
            "provider": "openai-compatible",
            "blocked": True,
            "blocked_reason": str(exc) or "interactive_api_config_required",
            "source": "interactive",
        }
    api_config = {
        "provider": "openai-compatible",
        "annotator_base_url": annotator_base_url,
        "annotator_api_key": annotator_api_key,
        "annotator_model": annotator_model,
        "reviewer_base_url": reviewer_base_url,
        "reviewer_api_key": reviewer_api_key,
        "reviewer_model": reviewer_model,
        "same_model_for_both": bool(reviewer_model and annotator_model == reviewer_model),
        "annotator_fallback_used": False,
        "reviewer_fallback_used": False,
        "annotator_api_mode": "chat_completions",
        "reviewer_api_mode": "chat_completions",
        "source": "interactive",
    }
    print_api_config_summary(api_config)
    return api_config


def prompt_role_openai_compatible_api_config(role: str) -> JsonObj:
    if role == "annotator":
        return prompt_openai_compatible_api_config(require_reviewer=False, allow_same_model=True)
    if not sys.stdin.isatty():
        return {
            "provider": "openai-compatible",
            "blocked": True,
            "blocked_reason": "interactive_api_config_required",
            "source": "interactive",
        }
    try:
        base_url = _prompt_nonempty("Enter reviewer OpenAI-compatible base_url: ")
        try:
            api_key = getpass("Enter reviewer api_key: ").strip()
        except EOFError as exc:
            raise RuntimeError("interactive_api_config_required") from exc
        while not api_key:
            print("API key is required.")
            try:
                api_key = getpass("Enter reviewer api_key: ").strip()
            except EOFError as exc:
                raise RuntimeError("api_config_missing") from exc
        reviewer_model = _prompt_nonempty("Enter reviewer model: ")
    except RuntimeError as exc:
        return {
            "provider": "openai-compatible",
            "blocked": True,
            "blocked_reason": str(exc) or "interactive_api_config_required",
            "source": "interactive",
        }
    api_config = {
        "provider": "openai-compatible",
        "annotator_base_url": "",
        "annotator_api_key": "",
        "annotator_model": "",
        "reviewer_base_url": base_url,
        "reviewer_api_key": api_key,
        "reviewer_model": reviewer_model,
        "same_model_for_both": False,
        "annotator_fallback_used": False,
        "reviewer_fallback_used": False,
        "annotator_api_mode": "chat_completions",
        "reviewer_api_mode": "chat_completions",
        "source": "interactive",
    }
    print_api_config_summary(api_config)
    return api_config


def api_config_from_run_env(role: str) -> JsonObj | None:
    values = {
        "annotator_base_url": os.environ.get(RUN_ANNOTATOR_BASE_URL_ENV, "") or os.environ.get(LEGACY_RUN_BASE_URL_ENV, ""),
        "annotator_api_key": os.environ.get(RUN_ANNOTATOR_API_KEY_ENV, "") or os.environ.get(LEGACY_RUN_API_KEY_ENV, ""),
        "annotator_model": os.environ.get(RUN_ANNOTATOR_MODEL_ENV, ""),
        "annotator_api_mode": os.environ.get(RUN_ANNOTATOR_API_MODE_ENV, ""),
        "reviewer_base_url": os.environ.get(RUN_REVIEWER_BASE_URL_ENV, "") or os.environ.get(LEGACY_RUN_BASE_URL_ENV, ""),
        "reviewer_api_key": os.environ.get(RUN_REVIEWER_API_KEY_ENV, "") or os.environ.get(LEGACY_RUN_API_KEY_ENV, ""),
        "reviewer_model": os.environ.get(RUN_REVIEWER_MODEL_ENV, ""),
        "reviewer_api_mode": os.environ.get(RUN_REVIEWER_API_MODE_ENV, ""),
    }
    if not any(values.values()):
        return None
    missing: list[str] = []
    if role in {"annotator", "both"} and not values["annotator_base_url"]:
        missing.append(f"{RUN_ANNOTATOR_BASE_URL_ENV} or {LEGACY_RUN_BASE_URL_ENV}")
    if role in {"annotator", "both"} and not values["annotator_api_key"]:
        missing.append(f"{RUN_ANNOTATOR_API_KEY_ENV} or {LEGACY_RUN_API_KEY_ENV}")
    if role in {"annotator", "both"} and not values["annotator_model"]:
        missing.append(RUN_ANNOTATOR_MODEL_ENV)
    if role in {"reviewer", "both"} and not values["reviewer_base_url"]:
        missing.append(f"{RUN_REVIEWER_BASE_URL_ENV} or {LEGACY_RUN_BASE_URL_ENV}")
    if role in {"reviewer", "both"} and not values["reviewer_api_key"]:
        missing.append(f"{RUN_REVIEWER_API_KEY_ENV} or {LEGACY_RUN_API_KEY_ENV}")
    if role in {"reviewer", "both"} and not values["reviewer_model"]:
        missing.append(RUN_REVIEWER_MODEL_ENV)
    if missing:
        return {
            "provider": "openai-compatible",
            "blocked": True,
            "blocked_reason": "missing temporary EWVAA_RUN_* API config",
            "missing_env": missing,
            "source": "wrapper_env",
        }
    return {
        "provider": "openai-compatible",
        **values,
        "same_model_for_both": bool(values["annotator_model"] and values["annotator_model"] == values["reviewer_model"]),
        "annotator_fallback_used": not bool(os.environ.get(RUN_ANNOTATOR_BASE_URL_ENV, "") or os.environ.get(RUN_ANNOTATOR_API_KEY_ENV, "")),
        "reviewer_fallback_used": not bool(os.environ.get(RUN_REVIEWER_BASE_URL_ENV, "") or os.environ.get(RUN_REVIEWER_API_KEY_ENV, "")),
        "source": os.environ.get(RUN_API_CONFIG_SOURCE_ENV, "interactive"),
    }


def api_config_from_openai_env(config: JsonObj, role: str) -> JsonObj:
    api_key_env = str(config.get("api_key_env", "OPENAI_API_KEY"))
    base_url_env = str(config.get("base_url_env", "OPENAI_BASE_URL"))
    annotator_base_url_env = str(config.get("annotator_base_url_env", "OPENAI_ANNOTATOR_BASE_URL"))
    annotator_api_key_env = str(config.get("annotator_api_key_env", "OPENAI_ANNOTATOR_API_KEY"))
    reviewer_base_url_env = str(config.get("reviewer_base_url_env", "OPENAI_REVIEWER_BASE_URL"))
    reviewer_api_key_env = str(config.get("reviewer_api_key_env", "OPENAI_REVIEWER_API_KEY"))
    annotator_env = str(config.get("annotator_model_env", "OPENAI_ANNOTATOR_MODEL"))
    reviewer_env = str(config.get("reviewer_model_env", "OPENAI_REVIEWER_MODEL"))
    annotator_api_mode_env = str(config.get("annotator_api_mode_env", "OPENAI_ANNOTATOR_API_MODE"))
    reviewer_api_mode_env = str(config.get("reviewer_api_mode_env", "OPENAI_REVIEWER_API_MODE"))
    fallback_env = str(config.get("fallback_model_env", "OPENAI_MODEL"))
    fallback_base_url = os.environ.get(base_url_env, "")
    fallback_api_key = os.environ.get(api_key_env, "")
    fallback_model = os.environ.get(fallback_env, "")
    annotator_base_url = os.environ.get(annotator_base_url_env, "") or fallback_base_url
    annotator_api_key = os.environ.get(annotator_api_key_env, "") or fallback_api_key
    reviewer_base_url = os.environ.get(reviewer_base_url_env, "") or fallback_base_url
    reviewer_api_key = os.environ.get(reviewer_api_key_env, "") or fallback_api_key
    annotator_model = os.environ.get(annotator_env, "") or fallback_model
    reviewer_model = os.environ.get(reviewer_env, "") or fallback_model
    annotator_api_mode = os.environ.get(annotator_api_mode_env, "") or str(config.get("annotator_api_mode", "chat_completions"))
    reviewer_api_mode = os.environ.get(reviewer_api_mode_env, "") or str(config.get("reviewer_api_mode", "chat_completions"))
    missing: list[str] = []
    if role in {"annotator", "both"} and not annotator_base_url:
        missing.append(f"{annotator_base_url_env} or {base_url_env}")
    if role in {"annotator", "both"} and not annotator_api_key:
        missing.append(f"{annotator_api_key_env} or {api_key_env}")
    if role in {"annotator", "both"} and not annotator_model:
        missing.append(f"{annotator_env} or {fallback_env}")
    if role in {"reviewer", "both"} and not reviewer_base_url:
        missing.append(f"{reviewer_base_url_env} or {base_url_env}")
    if role in {"reviewer", "both"} and not reviewer_api_key:
        missing.append(f"{reviewer_api_key_env} or {api_key_env}")
    if role in {"reviewer", "both"} and not reviewer_model:
        missing.append(f"{reviewer_env} or {fallback_env}")
    if missing:
        return {
            "provider": "openai-compatible",
            "blocked": True,
            "blocked_reason": "missing explicit env API config",
            "missing_env": missing,
            "source": "env",
        }
    api_config = {
        "provider": "openai-compatible",
        "annotator_base_url": annotator_base_url,
        "annotator_api_key": annotator_api_key,
        "annotator_model": annotator_model,
        "annotator_api_mode": annotator_api_mode,
        "reviewer_base_url": reviewer_base_url,
        "reviewer_api_key": reviewer_api_key,
        "reviewer_model": reviewer_model,
        "reviewer_api_mode": reviewer_api_mode,
        "same_model_for_both": annotator_model == reviewer_model,
        "annotator_fallback_used": not bool(os.environ.get(annotator_base_url_env, "") and os.environ.get(annotator_api_key_env, "")),
        "reviewer_fallback_used": not bool(os.environ.get(reviewer_base_url_env, "") and os.environ.get(reviewer_api_key_env, "")),
        "source": "env",
    }
    print_api_config_summary(api_config)
    return api_config


def resolve_openai_compatible_api_config(
    config: JsonObj,
    *,
    role: str,
    use_env_api_config: bool = False,
) -> JsonObj:
    run_config = api_config_from_run_env(role)
    if run_config is not None:
        return attach_api_modes(config, run_config)
    if use_env_api_config:
        return attach_api_modes(config, api_config_from_openai_env(config, role))
    return attach_api_modes(config, prompt_role_openai_compatible_api_config(role if role in {"annotator", "reviewer"} else "annotator"))


def redact_api_config_for_report(config: JsonObj | None) -> JsonObj:
    config = config or {}
    return {
        "provider": "openai-compatible",
        "annotator_base_url": str(config.get("annotator_base_url") or ""),
        "annotator_api_key_present": bool(config.get("annotator_api_key")),
        "annotator_api_key_redacted": "***" if config.get("annotator_api_key") else "",
        "annotator_model": str(config.get("annotator_model") or ""),
        "annotator_api_mode": str(config.get("annotator_api_mode") or ""),
        "reviewer_base_url": str(config.get("reviewer_base_url") or ""),
        "reviewer_api_key_present": bool(config.get("reviewer_api_key")),
        "reviewer_api_key_redacted": "***" if config.get("reviewer_api_key") else "",
        "reviewer_model": str(config.get("reviewer_model") or ""),
        "reviewer_api_mode": str(config.get("reviewer_api_mode") or ""),
        "same_model_for_both": bool(config.get("same_model_for_both")),
        "annotator_fallback_used": bool(config.get("annotator_fallback_used")),
        "reviewer_fallback_used": bool(config.get("reviewer_fallback_used")),
        "source": str(config.get("source") or ""),
    }


def api_config_presence_report(config: JsonObj | None) -> JsonObj:
    config = config or {}
    return {
        "api_config_source": str(config.get("source") or ""),
        "annotator_base_url_present": bool_env_present(config.get("annotator_base_url")),
        "annotator_api_key_present": bool_env_present(config.get("annotator_api_key")),
        "annotator_model_present": bool_env_present(config.get("annotator_model")),
        "reviewer_base_url_present": bool_env_present(config.get("reviewer_base_url")),
        "reviewer_api_key_present": bool_env_present(config.get("reviewer_api_key")),
        "reviewer_model_present": bool_env_present(config.get("reviewer_model")),
        "annotator_base_url_missing": not bool_env_present(config.get("annotator_base_url")),
        "annotator_api_key_missing": not bool_env_present(config.get("annotator_api_key")),
        "annotator_model_missing": not bool_env_present(config.get("annotator_model")),
        "reviewer_base_url_missing": not bool_env_present(config.get("reviewer_base_url")),
        "reviewer_api_key_missing": not bool_env_present(config.get("reviewer_api_key")),
        "reviewer_model_missing": not bool_env_present(config.get("reviewer_model")),
    }


def print_api_config_summary(api_config: JsonObj) -> None:
    print("API configuration for this run:")
    print("  provider: openai-compatible")
    print(f"  annotator_base_url: {api_config.get('annotator_base_url', '')}")
    print(f"  annotator_api_key_present: {str(bool(api_config.get('annotator_api_key'))).lower()}")
    if api_config.get("annotator_model"):
        print(f"  annotator_model: {api_config.get('annotator_model')}")
    print(f"  annotator_api_mode: {api_config.get('annotator_api_mode', '')}")
    print(f"  reviewer_base_url: {api_config.get('reviewer_base_url', '')}")
    print(f"  reviewer_api_key_present: {str(bool(api_config.get('reviewer_api_key'))).lower()}")
    if api_config.get("reviewer_model"):
        print(f"  reviewer_model: {api_config.get('reviewer_model')}")
    print(f"  reviewer_api_mode: {api_config.get('reviewer_api_mode', '')}")
    if api_config.get("source"):
        print(f"  source: {api_config.get('source')}")


def print_role_api_usage(api_config: JsonObj, role: str) -> None:
    model = api_config.get(role_model_key(role))
    base_url = api_config.get(role_base_url_key(role))
    api_key = api_config.get(role_api_key_key(role))
    api_mode = api_config.get(role_api_mode_key(role))
    print(f"Using {role} model: {model}")
    print(f"Using {role} OpenAI-compatible base_url: {base_url}")
    print(f"Using {role} api_mode: {api_mode}")
    print(f"{role} api_key configured: {str(bool(api_key)).lower()}")


def write_resolved_config(run_dir: Path, config: JsonObj, api_config: JsonObj | None = None) -> None:
    safe_config = {
        **config,
        "created_at": utc_now(),
        "annotator_api_key_recorded": False,
        "reviewer_api_key_recorded": False,
        "api_config": redact_api_config_for_report(api_config),
    }
    write_text(run_dir / "run_config.resolved.yaml", dump_simple_yaml(safe_config) + "\n")


def output_root(config: JsonObj) -> Path:
    return resolve_path(str(config["output_root"]))


def run_dir_status(run_dir: Path) -> str | None:
    for name in ("multiagent_run_report.json", "annotator_run_report.json", "reviewer_run_report.json"):
        path = run_dir / name
        if path.exists():
            try:
                report = read_json(path)
            except json.JSONDecodeError:
                continue
            status = report.get("status")
            if isinstance(status, str):
                return status
    return None


def find_active_run(config: JsonObj, *, create: bool) -> Path | None:
    active_run_dir = str(config.get("active_run_dir") or "").strip()
    if active_run_dir:
        run_dir = resolve_path(active_run_dir)
        if create:
            run_dir.mkdir(parents=True, exist_ok=True)
        return run_dir if run_dir.exists() else None
    root = output_root(config)
    root.mkdir(parents=True, exist_ok=True)
    prefix = str(config.get("run_name_prefix") or "benchmark")
    candidates = sorted(
        [path for path in root.glob(f"{prefix}_*") if path.is_dir()],
        key=lambda path: (path.stat().st_mtime, path.name),
        reverse=True,
    )
    for candidate in candidates:
        status = run_dir_status(candidate)
        if status not in TERMINAL_STATUSES:
            return candidate
    if not create:
        return None
    run_dir = root / f"{prefix}_{timestamp()}"
    suffix = 1
    while run_dir.exists():
        run_dir = root / f"{prefix}_{timestamp()}_{suffix}"
        suffix += 1
    run_dir.mkdir(parents=True)
    return run_dir


def require_active_run(config: JsonObj) -> Path:
    run_dir = find_active_run(config, create=False)
    if run_dir is None:
        raise SystemExit("No active multi-agent run found. Run 01_annotator_generate_patches.py first.")
    return run_dir


def benchmark_paths(config: JsonObj) -> JsonObj:
    workbench_dir = resolve_path(str(config["workbench_dir"]))
    reviewer_prompt_pack = str(config.get("reviewer_prompt_pack") or "").strip()
    if reviewer_prompt_pack:
        reviewer_prompt_pack_path = resolve_path(reviewer_prompt_pack)
    else:
        reviewer_prompt_pack_path = workbench_dir / "prompt_packs" / "reviewer_annotation_prompts.weighted.masked.jsonl"
    return {
        "gold": resolve_path(str(config["gold"])),
        "model_input": resolve_path(str(config["model_input"])),
        "sample_index": resolve_path(str(config["sample_index"])),
        "prompt_pack": resolve_path(str(config["prompt_pack"])),
        "reviewer_prompt_pack": reviewer_prompt_pack_path,
        "id_map_dir": resolve_path(str(config["id_map_dir"])),
        "annotation_context": resolve_path(str(config["annotation_context"])),
        "workbench_dir": workbench_dir,
    }


ANNOTATOR_GROUNDING_CONTRACT = """## Grounding Contract Addendum

Every gold_reasoning_chain claim must be grounded in cited primary evidence:
- EWVAA is not a stage classifier and does not re-label the stage. gold_stage / label.stage is the existing stage label for this EWVAA construction and must not be relabeled.
- Formal reasoning claims should explain how visible primary evidence supports the stage interpretation; they should not say "fixed gold_stage", "given gold_stage", or "therefore the gold_stage is...".
- Write every generated natural-language field in English, including claim, auxiliary_vulnerability_note.claim, final_judgement explanation, reviewer comments, reviewer judgement, and manual-review or revision reasons if present.
- Do not translate raw evidence snippets, application logs, audit events, traffic summaries, process names, file paths, network names, function names, variable names, CVE identifiers, sample_id, scenario_id, edge_id, or evidence_refs.
- Each claim must name a concrete cited primary fact: process/service, event/action, object/target, and seq or edge_id.
- scenario_or_evidence_understanding must scope the visible multi-source evidence window, available source coverage, primary vs auxiliary evidence role, missing / weak / disconnected evidence conditions, and which visible stage-relevant evidence condition(s) matter for the stage interpretation; do not make a final stage judgement in this step.
- observable_evidence must extract source-bucketed observable facts from audit / behavior-chain, applog, and traffic when present; identify directly visible cited facts and stage-relevant observable facts, do not infer the stage, do not turn traffic-only evidence into result, and do not turn CVE / public advisory into observable fact.
- attack_stage_path_reasoning must link primary facts across sources through temporal proximity, subject continuity, object/target consistency, request chain, process chain, file chain, and network chain before explaining why those links support the exact gold_stage and why adjacent stages are not better supported.
- final_judgement must return to the strongest cited primary evidence and close the evidence-based stage interpretation, not predict a new stage; explain uncertainty and missing evidence when needed.
- For result, identify the concrete outcome/artifact, such as a file write path, state change, output artifact, created object, or other observable result.
- For execution, do not treat NET_ACCEPT, NET_RECV, or PROCESS_FORK alone as sufficient; explain what additional cited fact makes the activity execution rather than ordinary service handling.
- For none, use positive insufficiency wording: the cited primary evidence is insufficient to close preparation, execution, or result.
- For none, do not simply say "no attack"; state the missing observable stage-closing evidence such as no command execution, no file write, no output artifact, no post-auth action, or no state-changing outcome.
- Avoid abstract bridge phrases unless the same sentence anchors them to a cited primary fact: active interaction, runtime interaction, outcome artifact, stage-specific evidence.
- Keep CVE, exploit, payload, RCE, PoC, public vulnerability descriptions, and vulnerability mechanism terms out of strict gold_reasoning_chain; if needed, use only auxiliary_vulnerability_note with not_for_scoring=true.
- Do not write the literal word "payload" in strict gold_reasoning_chain claims; use neutral traffic wording such as "no traffic body/details visible", "no request body details visible", or "no additional traffic content beyond connect/send".
- auxiliary_vulnerability_note must contain only claim and not_for_scoring, and not_for_scoring must be true.
"""


def add_annotator_grounding_contract(row: JsonObj) -> JsonObj:
    user = str(row.get("user") or "")
    if "## Grounding Contract Addendum" in user:
        return row
    updated = dict(row)
    marker = "## Input"
    if marker in user:
        user = user.replace(marker, ANNOTATOR_GROUNDING_CONTRACT + "\n" + marker, 1)
    else:
        user = user.rstrip() + "\n\n" + ANNOTATOR_GROUNDING_CONTRACT
    updated["user"] = user
    return updated


def prompt_pack_path_for_role(config: JsonObj, consumer_role: str) -> Path:
    paths = benchmark_paths(config)
    if consumer_role == "reviewer" and paths["reviewer_prompt_pack"].exists():
        return paths["reviewer_prompt_pack"]
    return paths["prompt_pack"]


def load_prompt_rows(config: JsonObj, consumer_role: str = "annotator") -> list[JsonObj]:
    prompt_path = prompt_pack_path_for_role(config, consumer_role)
    rows = read_jsonl(prompt_path)
    requested_sample_ids = configured_sample_ids(config)
    if not requested_sample_ids and sample_selection_mode(config) in {"sample_id_file", "sample_plan"}:
        raise SystemExit("Fixed sample selection was requested, but no sample_id values were loaded.")
    if requested_sample_ids:
        id_maps = ewvaa.load_id_maps(benchmark_paths(config)["id_map_dir"])
        rows_by_id: dict[str, JsonObj] = {}
        for row in rows:
            masked_sample_id = str(row.get("sample_id") or "")
            canonical_sample_id = str(id_maps["sample_id"].get(masked_sample_id, masked_sample_id))
            rows_by_id.setdefault(masked_sample_id, row)
            rows_by_id.setdefault(canonical_sample_id, row)
        missing = [sample_id for sample_id in requested_sample_ids if sample_id not in rows_by_id]
        if missing:
            raise SystemExit(
                "Requested sample_id(s) were not found in prompt_pack/id_map: "
                + ", ".join(missing[:10])
                + (" ..." if len(missing) > 10 else "")
            )
        rows = [rows_by_id[sample_id] for sample_id in requested_sample_ids]
        if consumer_role == "reviewer":
            return rows
        return [add_annotator_grounding_contract(row) for row in rows]
    limit = config.get("limit")
    if limit is not None:
        rows = rows[: int(limit)]
    if consumer_role == "reviewer":
        return rows
    return [add_annotator_grounding_contract(row) for row in rows]


def load_unmasked_prompt_rows(config: JsonObj, consumer_role: str = "annotator") -> list[JsonObj]:
    paths = benchmark_paths(config)
    rows = load_prompt_rows(config, consumer_role)
    id_maps = ewvaa.load_id_maps(paths["id_map_dir"])
    return [ewvaa.remap_ids(row, id_maps) for row in rows]


def load_benchmark(config: JsonObj, consumer_role: str = "annotator") -> JsonObj:
    paths = benchmark_paths(config)
    gold_rows = read_jsonl(paths["gold"])
    model_rows = read_jsonl(paths["model_input"])
    index_rows = read_jsonl(paths["sample_index"])
    prompts = load_unmasked_prompt_rows(config, consumer_role)
    return {
        "gold_rows": gold_rows,
        "model_rows": model_rows,
        "index_rows": index_rows,
        "prompt_rows": prompts,
        "gold_by_id": {row["sample_id"]: row for row in gold_rows},
        "model_by_id": {row["sample_id"]: row for row in model_rows},
        "index_by_id": {row["sample_id"]: row for row in index_rows},
        "prompts_by_id": {row["sample_id"]: row for row in prompts},
    }


def canonical_stage(gold_row: JsonObj, index_row: JsonObj | None = None) -> str:
    return str((gold_row.get("label") or {}).get("stage") or (index_row or {}).get("stage") or "")


def primary_edge_ids(model_row: JsonObj, gold_row: JsonObj) -> set[str]:
    ids: set[str] = set()
    for source in (model_row.get("input"), gold_row):
        for edge in ewvaa.iter_possible_edges(source):
            edge_id = edge.get("edge_id")
            if isinstance(edge_id, str):
                ids.add(edge_id)
    return ids


def strict_reference_errors(chain: Any, model_row: JsonObj, gold_row: JsonObj) -> list[str]:
    errors: list[str] = []
    edge_ids = primary_edge_ids(model_row, gold_row)
    if not isinstance(chain, list):
        return errors
    for entry in chain:
        if not isinstance(entry, dict):
            continue
        step = str(entry.get("step"))
        refs = entry.get("evidence_refs")
        if not isinstance(refs, list):
            continue
        for ref in refs:
            if not isinstance(ref, dict):
                continue
            if ref.get("seq") is not None and ewvaa.coerce_int(ref.get("seq")) is None:
                errors.append(f"evidence_ref_seq_not_integer:{step}:{ref.get('seq')}")
            edge_id = ref.get("edge_id")
            if not isinstance(edge_id, str) or edge_id not in edge_ids:
                errors.append(f"evidence_ref_edge_id_missing_from_primary:{step}:{edge_id}")
    return errors


def final_judgement(chain: Any) -> JsonObj | None:
    if not isinstance(chain, list):
        return None
    for entry in chain:
        if isinstance(entry, dict) and entry.get("step") == "final_judgement":
            return entry
    return None


def validation_for_patches(
    config: JsonObj,
    patch_rows: list[JsonObj],
    *,
    consumer_role: str = "annotator",
) -> tuple[list[JsonObj], list[JsonObj], JsonObj, list[JsonObj], JsonObj]:
    bench = load_benchmark(config, consumer_role)
    gold_by_id = bench["gold_by_id"]
    model_by_id = bench["model_by_id"]
    index_by_id = bench["index_by_id"]
    prompts_by_id = bench["prompts_by_id"]

    validation_rows: list[JsonObj] = []
    valid_rows: list[JsonObj] = []
    invalid_rows: list[JsonObj] = []
    for patch in patch_rows:
        sample_id = str(patch.get("sample_id", ""))
        gold_row = gold_by_id.get(sample_id, {})
        model_row = model_by_id.get(sample_id, {})
        index_row = index_by_id.get(sample_id, {})
        expected_stage = canonical_stage(gold_row, index_row)
        patch_stage = str(patch.get("gold_stage") or "")
        chain = sanitize_reasoning_chain(patch.get("gold_reasoning_chain"))
        note = patch.get("auxiliary_vulnerability_note")
        clean_patch = sanitize_candidate_patch(patch)
        errors: list[str] = []
        if not sample_id or sample_id not in gold_by_id:
            errors.append("sample_id_missing_from_gold")
        if sample_id in gold_by_id and patch_stage != expected_stage:
            errors.append(f"gold_stage_mismatch:{patch_stage}!={expected_stage}")
        if sample_id in gold_by_id:
            errors.extend(ewvaa.validate_chain(chain, ewvaa.legal_refs_from_gold(gold_row), expected_stage))
            errors.extend(strict_reference_errors(chain, model_row, gold_row))
        errors.extend(ewvaa.forbidden_strict_chain_errors(chain))
        errors.extend(ewvaa.validate_patch_note(note))
        auxiliary_forbidden_hits = ewvaa.auxiliary_note_forbidden_hits(note)
        patch_entry = {
            **clean_patch,
            "gold_stage": expected_stage or patch_stage,
            "patch_valid": not errors,
            "auxiliary_forbidden_term_hits": auxiliary_forbidden_hits,
        }
        validation_row = {
            "sample_id": sample_id,
            "masked_sample_id": patch.get("masked_sample_id"),
            "scenario_id": gold_row.get("scenario_id") or index_row.get("scenario_id"),
            "gold_stage": expected_stage or patch_stage,
            "patch_valid": not errors,
            "errors": errors,
            "auxiliary_forbidden_term_hits": auxiliary_forbidden_hits,
            "old_reasoning_chain": ewvaa.summarize_chain(gold_row.get("gold_reasoning_chain")),
            "new_reasoning_chain": ewvaa.summarize_chain(chain),
        }
        validation_rows.append(validation_row)
        if errors:
            invalid_rows.append({**patch_entry, "errors": errors})
        else:
            valid_rows.append(patch_entry)

    grounding_cases, grounding_report = ewvaa.audit_grounding(
        valid_rows,
        prompts_by_id,
        bench["model_by_id"],
        bench["gold_by_id"],
        bench["index_by_id"],
    )
    forbidden_summary = ewvaa.forbidden_invalid_summary(validation_rows)
    validation_report: JsonObj = {
        "api_called": False,
        "inputs": {
            "gold": config["gold"],
            "model_input": config["model_input"],
            "sample_index": config["sample_index"],
            "prompt_pack": rel(prompt_pack_path_for_role(config, consumer_role)),
        },
        **sample_selection_summary(config, [row.get("sample_id") for row in patch_rows]),
        "counts": {
            "total_patches": len(patch_rows),
            "valid_patches": len(valid_rows),
            "invalid_outputs": len(invalid_rows),
        },
        "invalid_sample_ids": [row["sample_id"] for row in invalid_rows],
        "valid_sample_ids": [row["sample_id"] for row in valid_rows],
        "forbidden_strict_chain_hits": forbidden_summary["forbidden_strict_chain_invalid_count"],
        "forbidden_strict_chain_terms": forbidden_summary["forbidden_strict_chain_terms"],
        "cve_only_strict_chain_hits": grounding_report.get("counts", {}).get("cve_only_strict_chain_hits", 0),
        "benchmark_files_modified": False,
    }
    return validation_rows, valid_rows, validation_report, grounding_cases, grounding_report


def blocked_report(
    config: JsonObj,
    run_dir: Path,
    role: str,
    report_name: str,
    *,
    api_config: JsonObj | None = None,
    reason: str | None = None,
) -> JsonObj:
    api_config = api_config or {}
    report = {
        "status": "blocked",
        "created_at": utc_now(),
        "role": role,
        "run_dir": rel(run_dir),
        "blocked_reason": reason or str(api_config.get("blocked_reason") or "api_config_blocked"),
        "missing_env": api_config.get("missing_env", []),
        "api_called": False,
        "no_api_called": True,
        "annotator_api_key_recorded": False,
        "reviewer_api_key_recorded": False,
        "requested_limit": config.get("limit"),
        **sample_selection_summary(config),
        "workbench_dir": str(config.get("workbench_dir") or ""),
        "output_root": str(config.get("output_root") or ""),
        **redact_api_config_for_report(api_config),
        **api_config_presence_report(api_config),
        "api_config": redact_api_config_for_report(api_config),
        "benchmark_files_modified": False,
    }
    write_json(run_dir / report_name, report)
    return report


def role_request_timeout_seconds(config: JsonObj, role: str, override: float | None = None) -> float:
    if override is not None:
        return float(override)
    role_key = f"{role}_request_timeout_seconds"
    for key in (role_key, "api_request_timeout_seconds", "timeout_seconds"):
        value = config.get(key)
        if value is not None:
            try:
                return float(value)
            except (TypeError, ValueError):
                continue
    return 900.0


def call_role_model(
    config: JsonObj,
    prompt_row: JsonObj,
    role: str,
    api_config: JsonObj,
    *,
    request_timeout_seconds: float | None = None,
) -> JsonObj:
    model = api_config.get(role_model_key(role))
    return ewvaa.call_provider(
        prompt_row,
        provider="openai-compatible",
        api_key=str(api_config.get(role_api_key_key(role), "")),
        base_url=str(api_config.get(role_base_url_key(role), "")),
        model=str(model or ""),
        api_mode=str(api_config.get(role_api_mode_key(role), "chat_completions") or "chat_completions"),
        temperature=float(config.get("temperature", 0) or 0),
        max_tokens=MAX_TOKENS,
        timeout=role_request_timeout_seconds(config, role, request_timeout_seconds),
        max_retries=int(config.get("max_retries", 2) or 0),
    )


def compact_json(value: Any, max_chars: int = 1200) -> str:
    text = json.dumps(value, ensure_ascii=False)
    if len(text) <= max_chars:
        return text
    return text[: max_chars - 3] + "..."


def review_prompt_row(
    sample_id: str,
    annotator_patch: JsonObj,
    validation_case: JsonObj | None,
    grounding_case: JsonObj | None,
    prompt_row: JsonObj | None,
) -> JsonObj:
    prompt_input = (prompt_row or {}).get("prompt_input") if isinstance(prompt_row, dict) else None
    if not isinstance(prompt_input, dict):
        prompt_input = ewvaa.extract_user_input(str((prompt_row or {}).get("user", ""))) or {}
    gold_stage = str(annotator_patch.get("gold_stage") or prompt_input.get("gold_stage") or "")
    user = "\n".join(
        [
            "# EWVAA Reviewer / Reviser",
            "",
            "Audit the annotator reasoning patch and return JSON only.",
            "Return exactly one JSON object with no Markdown, no code fences, and no extra prose.",
            "",
            "Rules:",
            "- You are reviewing an AI-generated EWVAA reasoning-chain patch. You are not re-classifying the stage. The gold_stage / label.stage is fixed for this review target, but formal reasoning claims must read as evidence-based analysis rather than workflow-label justification. Your task is to check whether the annotator patch is grounded in visible primary evidence and, when necessary, minimally revise it so the formal claims are evidence-aligned, stage-boundary-aware, and safe for candidate gold use.",
            "- verdict must be one of accept, minor_revision, major_revision, reject.",
            f"- sample_id must be present and must exactly equal {json.dumps(sample_id, ensure_ascii=False)}.",
            "- EWVAA does not re-label the stage; reviewer cannot change gold_stage.",
            "- EWVAA is not a stage classifier; reviewer cannot change label.stage or turn final_judgement into a new prediction.",
            "- gold_stage is given only for annotation construction, not for benchmark evaluation.",
            f"- gold_stage inside revised_patch must remain {json.dumps(gold_stage, ensure_ascii=False)}.",
            "- Write rationale, issues, revised_patch claims, auxiliary_vulnerability_note.claim, judgement, comments, and revision reasons in English.",
            "- Review the strict reasoning chain and make the smallest necessary revision. If a claim is already accurate and evidence-aligned, preserve its structure and concrete log details. Do not rewrite for style alone.",
            "- The annotator draft is the object being reviewed, not a source of evidence. Do not preserve concrete fields from the draft unless they can be verified against visible primary evidence.",
            "- Do not translate raw evidence snippets, application logs, audit events, traffic summaries, process names, file paths, network names, function names, variable names, CVE identifiers, sample_id, scenario_id, edge_id, or evidence_refs.",
            "- strict gold_reasoning_chain must use primary evidence only.",
            "- Every revised_patch claim must name concrete cited primary evidence: process/service, event/action, object/target, and seq or edge_id.",
            "- Before accepting or revising a claim, check every concrete evidence atom against visible primary evidence: seq, edge_id, relation, process/subject, object/target, connection tuple, IP/port, raw event type, fd_name, file path, service_name, method, URL/endpoint, HTTP status, content-length, sanitized_message, applog semantic_type, attach_strength, attach_reason, traffic flow fields, empty source buckets, and source coverage limits.",
            "- If a URL, endpoint, process, connection tuple, status code, file path, command, artifact, or state-changing outcome is not visible in the evidence, remove it, weaken it, or replace it with the exact visible field.",
            "- scenario_or_evidence_understanding must scope the visible multi-source evidence window, available source coverage, primary vs auxiliary evidence role, missing / weak / disconnected evidence conditions, and which visible stage-relevant evidence condition(s) matter for the stage interpretation; do not make a final stage judgement in this step.",
            "- observable_evidence must extract source-bucketed observable facts from audit / behavior-chain, applog, and traffic when present; identify directly visible cited facts and stage-relevant observable facts, do not infer the stage, do not turn traffic-only evidence into result, and do not turn CVE / public advisory into observable fact.",
            "- attack_stage_path_reasoning must use temporal proximity, subject continuity, object/target consistency, request chain, process chain, file chain, and network chain to connect cited primary facts to the exact gold_stage and explain why adjacent stages are not better supported.",
            "- final_judgement must return to the strongest cited primary evidence, restate that fact, and close the evidence-based stage interpretation while explaining uncertainty and missing evidence when needed.",
            "- Prefer source-bucketed fact extraction before cross-source reasoning: audit facts, application-log facts, and traffic facts should be distinguished. In stage reasoning, consider temporal proximity, subject continuity, process lineage, object/target consistency, request-to-process alignment, file/network chains, and source coverage limitations.",
            "- For none: write positive insufficiency. State what visible facts exist and which stage-closing evidence is absent. Do not merely say \"no evidence.\"",
            "- For preparation: do not overclaim active execution or result closure unless visible evidence supports it.",
            "- For execution: NET_ACCEPT, NET_RECV, NET_SEND, or PROCESS_FORK alone usually shows service handling or process activity, not command execution or exploitation. Require concrete visible support before claiming command execution, post-auth action, file-chain execution, database action, or application-level action.",
            "- For result: require concrete visible outcome support, such as a written artifact, created object, persisted state change, returned data content, confirmed exfiltration, or another visible result artifact. If only weak result-side signals exist, use evidence-limited wording.",
            "- For none, use positive insufficiency wording: the cited primary evidence is insufficient to close preparation, execution, or result.",
            "- For none, do not simply say 'no attack'; state the missing observable stage-closing evidence such as no command execution, no file write, no output artifact, no post-auth action, or no state-changing outcome.",
            "- Rewrite abstract bridge phrases unless the same sentence anchors them to a cited primary fact: active interaction, runtime interaction, outcome artifact, stage-specific evidence.",
            "- Do not write formal claims using workflow-label wording such as \"fixed gold_stage\", \"given gold_stage\", \"under the fixed label\", \"because the gold_stage is...\", or \"therefore the gold_stage is...\". Formal claims should explain how visible evidence supports the stage interpretation, not justify it by saying the label is fixed.",
            "- Do not put workflow or review-status terms inside gold_reasoning_chain[*].claim or auxiliary_vulnerability_note.claim, including manual review, candidate-with-manual-review, promotion, no promotion, clean final, canonical gold, writeback, human_verified, reviewer decision, reviewer notes, L1, L2, L3, or L4. These concepts may appear only in reviewer rationale or issues when needed.",
            "- Auxiliary vulnerability context may help semantic interpretation only. It is not strict evidence, must not substitute for primary logs, and must not by itself support a stage claim. If mentioned, it belongs only in auxiliary_vulnerability_note with not_for_scoring=true.",
            "- CVE, exploit, payload, RCE, PoC, public vulnerability descriptions, and public advisory descriptions must not be used as direct evidence in strict reasoning.",
            "- strict gold_reasoning_chain must not contain forbidden terms such as CVE, payload, RCE, PoC, XXE, exploit, exploitation, or post-exploitation.",
            "- final_judgement must not contain CVE, payload, RCE, PoC, XXE, exploit, exploitation, post-exploitation, public vulnerability descriptions, or other vulnerability terminology.",
            "- If any forbidden term is unavoidable, place it only inside auxiliary_vulnerability_note with not_for_scoring=true and do not repeat it in gold_reasoning_chain or final_judgement.",
            "- Do not copy forbidden terms from edge_id, applog text, scenario metadata, or vulnerability context into the strict chain.",
            "- final_judgement must use only stage vocabulary plus cited primary evidence, not vulnerability or CVE terminology.",
            "- Describe primary evidence in neutral behavioral language even when the raw evidence text contains exploit or payload wording.",
            "- Do not write the literal word 'payload' in strict gold_reasoning_chain claims; use neutral traffic wording such as 'no traffic body/details visible', 'no request body details visible', or 'no additional traffic content beyond connect/send'.",
            "- Do not introduce forbidden strict-chain terms or CVE-only strict-chain claims.",
            "- Do not use outside evidence.",
            "- Do not invent evidence_refs, seq values, or edge_id values.",
            "- Never invent seq, edge_id, relation, process, object, URL, file path, status code, traffic facts, application-log messages, evidence_refs, or stage-closing artifacts. If evidence is absent, state the absence as a boundary.",
            "- Do not rewrite strict reasoning based only on vulnerability background.",
            "- Do not force every sample into the same generic opening sentence. Preserve sample-specific evidence anchors and wording when correct. Claims should retain concrete details such as seq, relation, process, object, endpoint, file path, empty buckets, and source limitations.",
            "- If verdict is accept, revised_patch may be null.",
            "- If verdict is minor_revision, major_revision, or reject, revised_patch is required and must be a complete patch object, not natural-language advice.",
            "- If a revised_patch is required, it must be a complete structured patch object for parser compatibility, but unchanged claims and evidence_refs should be preserved exactly when they are already valid.",
            "- revised_patch must contain sample_id, gold_stage, gold_reasoning_chain, auxiliary_vulnerability_note.",
            "- revised_patch.sample_id must exactly equal the original sample_id.",
            "- Each gold_reasoning_chain step must contain only step, claim, evidence_refs.",
            "- Do not add source_type, uses_vulnerability_context, primary_support, auxiliary_support, stage_coherence, weighted_score, verdict, or reason inside gold_reasoning_chain.",
            "- auxiliary_vulnerability_note must contain only claim and not_for_scoring.",
            "- revised_patch evidence_refs must cite primary evidence.",
            "- revised_patch must not rely only on CVE or vulnerability context.",
            "",
            "## Input",
            json.dumps(
                {
                    "sample_id": sample_id,
                    "gold_stage": gold_stage,
                    "annotator_patch": annotator_patch,
                    "validation_case": validation_case,
                    "grounding_case": grounding_case,
                    "primary_evidence": prompt_input.get("primary_evidence"),
                    "auxiliary_vulnerability_context": prompt_input.get("auxiliary_vulnerability_context"),
                },
                ensure_ascii=False,
                indent=2,
            ),
            "## Output schema",
            json.dumps(
                {
                    "sample_id": sample_id,
                    "verdict": "accept | minor_revision | major_revision | reject",
                    "rationale": "",
                    "issues": [],
                    "revised_patch": None,
                },
                ensure_ascii=False,
                indent=2,
            ),
            "If verdict is not accept, replace revised_patch:null with a full patch object shaped like:",
            json.dumps(
                {
                    "sample_id": sample_id,
                    "gold_stage": gold_stage,
                    "gold_reasoning_chain": [
                        {
                            "step": "scenario_or_evidence_understanding",
                            "claim": "The visible multi-source evidence window has source coverage from primary evidence at seq 1 edge EDGE; missing or weak evidence conditions are stated separately, and the cited facts define the evidence boundary for the stage interpretation without making a final stage judgement.",
                            "evidence_refs": [{"seq": 1, "edge_id": "EDGE"}],
                        },
                        {
                            "step": "observable_evidence",
                            "claim": "By source-bucketed audit/applog/traffic primary evidence, the cited directly visible facts show PROCESS_OR_SERVICE EVENT_OR_ACTION OBJECT_OR_TARGET, and these stage-relevant observable facts remain factual without inferring the final stage.",
                            "evidence_refs": [{"seq": 1, "edge_id": "EDGE"}],
                        },
                        {
                            "step": "attack_stage_path_reasoning",
                            "claim": f"At seq 1 edge EDGE, PROCESS_OR_SERVICE EVENT_OR_ACTION OBJECT_OR_TARGET; temporal proximity, subject continuity, object/target consistency, and request/process/file/network chain links support stage {gold_stage} because STAGE_PREDICATE_GROUNDED_IN_THAT_FACT, while adjacent stages are not better supported.",
                            "evidence_refs": [{"seq": 1, "edge_id": "EDGE"}],
                        },
                        {
                            "step": "final_judgement",
                            "claim": f"At seq 1 edge EDGE, PROCESS_OR_SERVICE EVENT_OR_ACTION OBJECT_OR_TARGET; the visible evidence supports a {gold_stage}-stage interpretation, with any missing stage-closing evidence stated as an evidence boundary.",
                            "evidence_refs": [{"seq": 1, "edge_id": "EDGE"}],
                        },
                    ],
                    "auxiliary_vulnerability_note": {
                        "claim": "",
                        "not_for_scoring": True,
                    },
                },
                ensure_ascii=False,
                indent=2,
            ),
        ]
    )
    return {
        "sample_id": sample_id,
        "gold_stage": gold_stage,
        "system": (
            "You are the reviewer/reviser for EWVAA stage_reasoning gold patches. "
            "Prioritize grounding in primary evidence, conservative corrections, and English-only generated reasoning."
        ),
        "user": user,
    }


def verdict_distribution(rows: list[JsonObj]) -> dict[str, int]:
    return dict(Counter(str(row.get("verdict", "invalid")).strip().lower() for row in rows))


def is_revision_verdict(verdict: str) -> bool:
    return verdict in {"minor_revision", "major_revision", "reject", "invalid"}


def normalize_verdict(value: Any) -> str:
    text = str(value or "").strip().lower().replace(" ", "_")
    if text in {"accept", "minor_revision", "major_revision", "reject"}:
        return text
    return "invalid"


def final_entry_from_chain(chain: Any) -> tuple[str, list[Any]]:
    entry = final_judgement(chain)
    if not entry:
        return "", []
    return str(entry.get("claim", "")), entry.get("evidence_refs") if isinstance(entry.get("evidence_refs"), list) else []


def safe_read_jsonl(path: Path) -> list[JsonObj]:
    return read_jsonl(path) if path.exists() else []


def dedupe_error_rows(rows: Iterable[JsonObj]) -> list[JsonObj]:
    seen: set[tuple[str, str, str]] = set()
    out: list[JsonObj] = []
    for row in rows:
        sample_id = str(row.get("sample_id", "") or "").strip()
        masked_sample_id = str(row.get("masked_sample_id", "") or "").strip()
        error = str(
            row.get("error")
            or row.get("error_type")
            or row.get("provider_error")
            or row.get("errors")
            or ""
        ).strip()
        key = (sample_id, masked_sample_id, error)
        if key in seen:
            continue
        seen.add(key)
        out.append(dict(row))
    return out


def unresolved_error_rows(rows: Iterable[JsonObj], completed_sample_ids: Iterable[Any]) -> list[JsonObj]:
    completed = {str(sample_id or "").strip() for sample_id in completed_sample_ids if str(sample_id or "").strip()}
    return [
        dict(row)
        for row in dedupe_error_rows(rows)
        if str(row.get("sample_id", "") or "").strip() not in completed
    ]


def is_transient_transport_error(row: JsonObj) -> bool:
    haystacks = [
        str(row.get("error", "") or ""),
        str(row.get("error_type", "") or ""),
        str(row.get("provider_error", "") or ""),
    ]
    text = " ".join(part.lower() for part in haystacks if part).strip()
    if not text:
        return False
    transient_terms = (
        "connection error",
        "connect error",
        "api_connection_error",
        "apiconnectionerror",
        "request_timeout",
        "request_timeout_hard",
        "timeout",
        "timed out",
        "readtimeout",
        "read timeout",
        "connecttimeout",
        "connect timeout",
        "rate limit",
        "429",
        "temporarily unavailable",
        "service unavailable",
        "bad gateway",
        "gateway timeout",
        "server disconnected",
        "remoteprotocolerror",
        "protocol error",
        "transport",
        "transient",
    )
    return any(term in text for term in transient_terms)


def annotator_resume_state(
    selected_sample_ids: Iterable[Any],
    completed_rows: Iterable[JsonObj],
    *,
    api_errors: Iterable[JsonObj] | None = None,
    parse_failures: Iterable[JsonObj] | None = None,
    unmask_failures: Iterable[JsonObj] | None = None,
) -> JsonObj:
    selected = _dedupe_preserve_order(selected_sample_ids)
    completed = _dedupe_preserve_order(row.get("sample_id") for row in completed_rows if row.get("sample_id"))
    completed_set = set(completed)
    api_error_rows = dedupe_error_rows(api_errors or [])
    parse_failure_rows = dedupe_error_rows(parse_failures or [])
    unmask_failure_rows = dedupe_error_rows(unmask_failures or [])
    failed = _dedupe_preserve_order(
        row.get("sample_id")
        for row in [*api_error_rows, *parse_failure_rows, *unmask_failure_rows]
        if row.get("sample_id") and str(row.get("sample_id")) not in completed_set
    )
    failed_set = set(failed)
    unattempted = [
        sample_id for sample_id in selected
        if sample_id not in completed_set and sample_id not in failed_set
    ]
    retryable_failed = _dedupe_preserve_order(
        row.get("sample_id")
        for row in api_error_rows
        if row.get("sample_id")
        and str(row.get("sample_id")) not in completed_set
        and is_transient_transport_error(row)
    )
    retry_targets = _dedupe_preserve_order([*retryable_failed, *unattempted])
    nonretryable_failed = [
        sample_id for sample_id in failed
        if sample_id not in set(retryable_failed)
    ]
    return {
        "selected_sample_count": len(selected),
        "selected_sample_ids": selected,
        "completed_sample_ids": completed,
        "failed_sample_ids": failed,
        "retryable_failed_sample_ids": retryable_failed,
        "nonretryable_failed_sample_ids": nonretryable_failed,
        "unattempted_sample_ids": unattempted,
        "retry_target_sample_ids": retry_targets,
        "completed_count": len(completed),
        "failed_count": len(failed),
        "retryable_failed_count": len(retryable_failed),
        "unattempted_count": len(unattempted),
        "retry_target_count": len(retry_targets),
        "can_resume_safely": not nonretryable_failed,
        "allow_step02": (
            len(completed) == len(selected)
            and not failed
            and not parse_failure_rows
            and not unmask_failure_rows
        ),
    }


def load_validation_cases(path: Path) -> dict[str, JsonObj]:
    return {row["sample_id"]: row for row in safe_read_jsonl(path) if row.get("sample_id")}


def unique_manual_rows(rows: Iterable[JsonObj]) -> list[JsonObj]:
    seen: set[tuple[str, str]] = set()
    out: list[JsonObj] = []
    for row in rows:
        sample_id = str(row.get("sample_id", ""))
        reason = str(row.get("reason", "manual_review_required"))
        key = (sample_id, reason)
        if key in seen:
            continue
        seen.add(key)
        out.append(row)
    return out
