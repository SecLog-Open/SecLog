from __future__ import annotations

import os
import sys
import time
from pathlib import Path
from typing import Any, Callable, Iterable, Sequence

try:
    from results_analysis.pipeline.utils.common import CHAIN_DIR_NAME, scenario_chain_dir
except ModuleNotFoundError:
    # The public release keeps dataset construction and attack-chain
    # construction in separate top-level directories.  Console reporting for
    # stage 01 only needs these two stable path helpers, so retain a local
    # fallback instead of requiring stage 02 to be importable.
    CHAIN_DIR_NAME = "chain"

    def scenario_chain_dir(scenario_dir: Path) -> Path:
        chain_dir = scenario_dir / CHAIN_DIR_NAME
        if chain_dir.exists():
            return chain_dir
        legacy_chain_dir = scenario_dir / "chain_v1"
        if legacy_chain_dir.exists():
            return legacy_chain_dir
        return chain_dir

OBSERVED_FIELD_ORDER = (
    "stage",
    "substep",
    "status",
    "failing_step",
    "scenario_dir",
    "output_path",
    "input_path",
    "processed",
    "total",
    "percent",
    "elapsed",
    "memory_mb",
)

# -----------------------------------------------------------------------------
# Human-readable stage / progress helpers
#
# The existing StageTimer / ProgressLogger above emit structured
# `key=value` observation lines that are great for log parsers but noisy
# for human readers who just want to know "which stage am I in, did it
# succeed, what did it produce, and how far am I through the run".
#
# The helpers below are a *thin* convenience layer on top of emit_observation
# that format the same information as short, visually consistent banners
# across build.sh / main.py / analyze.py / run_chain_pipeline.py /
# batch_full_pipeline.py / run_full_to_release.py. They do NOT replace the
# structured lines — both remain emitted side by side so the machine-
# friendly stream is preserved.
# -----------------------------------------------------------------------------

# Stable ordering of pipeline stages used for progress counters and final
# highest-level-reached reports. Kept here so every entry script agrees.
PIPELINE_STAGE_ORDER: tuple[str, ...] = (
    "extract",
    "backbone",
    "enrich",
    "dataset",
    "release",
)

# Human labels used in the progress counter, e.g. "[pipeline][extract][ok] step=1/5"
PIPELINE_STAGE_LABELS: dict[str, str] = {
    "extract": "extract",
    "backbone": "backbone",
    "enrich": "enrich",
    "dataset": "dataset",
    "release": "release",
}

# Status tokens we accept for stage banners. The token decides colour and
# symbol; unknown tokens fall back to plain "info".
#
# The visual vocabulary is kept small on purpose so output reads as a
# professional status line rather than a fruit salad:
#   START      cyan        entry of a stage / wrapper
#   OK         green       stage succeeded
#   DONE       green       final block, everything succeeded
#   SUCCESS    green       explicit positive final status
#   WARN       yellow      non-fatal anomaly (e.g. controlled skip)
#   SKIP       yellow      explicit user / policy skip
#   INCOMPLETE yellow      stage/pipeline left mid-way, see reason
#   FAIL       red         stage failed
#   FAILED     red         final block, at least one failure
#   INFO       dim-white   decorative metadata lines
STATUS_COLORS: dict[str, str] = {
    "start": "\033[1;36m",     # bold cyan
    "ok": "\033[1;32m",        # bold green
    "done": "\033[1;32m",      # bold green
    "success": "\033[1;32m",   # bold green
    "warn": "\033[1;33m",      # bold yellow
    "warning": "\033[1;33m",   # bold yellow
    "skip": "\033[1;33m",      # bold yellow
    "incomplete": "\033[1;33m",  # bold yellow
    "fail": "\033[1;31m",      # bold red
    "failed": "\033[1;31m",    # bold red
    "info": "\033[1;37m",      # bold white
}

# Canonical uppercase label shown inside square brackets. Synonyms collapse
# to the same label so the visual output stays consistent even though
# different call sites use e.g. "done"/"ok"/"success".
STATUS_LABELS: dict[str, str] = {
    "start": "START",
    "ok": "OK",
    "done": "DONE",
    "success": "SUCCESS",
    "warn": "WARN",
    "warning": "WARN",
    "skip": "SKIP",
    "incomplete": "INCOMPLETE",
    "fail": "FAIL",
    "failed": "FAILED",
    "info": "INFO",
}

# Optional emoji prefix for *banners that should visibly stand out*
# (scenario-level rows, final blocks, build-level rows). Per-stage rows
# intentionally do NOT get an emoji — they stay lean so the final block is
# the attention-grabber of the run.
STATUS_EMOJI: dict[str, str] = {
    "start": "🚀",
    "ok": "✅",
    "done": "🎉",
    "success": "🎉",
    "warn": "⚠",
    "warning": "⚠",
    "skip": "⚠",
    "incomplete": "⚠",
    "fail": "❌",
    "failed": "❌",
}
COLOR_RESET = "\033[0m"


def _env_enabled(name: str) -> bool:
    value = os.environ.get(name)
    if value is None:
        return False
    if value.strip().lower() in {"", "0", "false", "no", "off"}:
        return False
    return True


def _status_label(status: str) -> str:
    return STATUS_LABELS.get(status.lower().strip(), status.upper())


def _status_color(status: str) -> str:
    return STATUS_COLORS.get(status.lower().strip(), STATUS_COLORS["info"])


def _status_emoji(status: str) -> str:
    # SECLOG_NO_EMOJI=1 gives strict-text environments (dumb terminals,
    # logging pipelines that mangle UTF-8) a way to suppress emoji while
    # keeping the upper-case status label and colour coding intact.
    if _env_enabled("SECLOG_NO_EMOJI"):
        return ""
    emoji = STATUS_EMOJI.get(status.lower().strip(), "")
    if not emoji:
        return ""
    encoding = getattr(sys.stdout, "encoding", None) or ""
    if encoding.lower() in {"gbk", "cp936", "mbcs"}:
        return ""
    return emoji


def _tty_supports_color() -> bool:
    if _env_enabled("SECLOG_NO_COLOR"):
        return False
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    try:
        return sys.stdout.isatty()
    except Exception:
        return False


def _paint(text: str, color: str | None) -> str:
    if not color or not _tty_supports_color():
        return text
    return f"{color}{text}{COLOR_RESET}"


def current_memory_mb() -> float | None:
    try:
        import psutil  # type: ignore

        return round(psutil.Process(os.getpid()).memory_info().rss / 1024.0 / 1024.0, 1)
    except Exception:
        return None


def path_exists(path: str | Path | None) -> bool | None:
    if path is None:
        return None
    try:
        return Path(path).exists()
    except Exception:
        return None


def _format_value(value: Any) -> str:
    if isinstance(value, float):
        return f"{value:.2f}"
    if isinstance(value, Path):
        return str(value)
    return str(value)


def format_observation(prefix: str = "[obs]", **fields: Any) -> str:
    ordered_keys: list[str] = [key for key in OBSERVED_FIELD_ORDER if fields.get(key) is not None]
    ordered_keys.extend(
        key for key in fields.keys() if key not in OBSERVED_FIELD_ORDER and fields.get(key) is not None
    )
    body = " ".join(f"{key}={_format_value(fields[key])}" for key in ordered_keys)
    return f"{prefix} {body}".rstrip()


def emit_observation(prefix: str = "[obs]", emit_fn: Callable[[str], None] | None = None, **fields: Any) -> str:
    line = format_observation(prefix=prefix, **fields)
    if emit_fn is None:
        print(line, flush=True)
    else:
        emit_fn(line)
    return line


class StageTimer:
    def __init__(
        self,
        stage: str,
        *,
        prefix: str = "[obs]",
        emit_fn: Callable[[str], None] | None = None,
        base_fields: dict[str, Any] | None = None,
    ) -> None:
        self.stage = stage
        self.prefix = prefix
        self.emit_fn = emit_fn
        self.base_fields = dict(base_fields or {})
        self.started_at: float | None = None

    def start(self, **fields: Any) -> None:
        self.started_at = time.perf_counter()
        payload = dict(self.base_fields)
        payload.update(fields)
        payload.setdefault("stage", self.stage)
        payload["status"] = "start"
        payload.setdefault("memory_mb", current_memory_mb())
        emit_observation(self.prefix, self.emit_fn, **payload)

    def done(self, **fields: Any) -> None:
        payload = dict(self.base_fields)
        payload.update(fields)
        payload.setdefault("stage", self.stage)
        payload["status"] = payload.get("status") or "done"
        payload.setdefault("elapsed", self.elapsed())
        payload.setdefault("memory_mb", current_memory_mb())
        emit_observation(self.prefix, self.emit_fn, **payload)

    def fail(self, exc: BaseException | str | None = None, **fields: Any) -> None:
        payload = dict(self.base_fields)
        payload.update(fields)
        payload.setdefault("stage", self.stage)
        payload["status"] = "failed"
        payload.setdefault("elapsed", self.elapsed())
        payload.setdefault("memory_mb", current_memory_mb())
        if exc is not None and "error" not in payload:
            payload["error"] = str(exc)
        emit_observation(self.prefix, self.emit_fn, **payload)

    def elapsed(self) -> float | None:
        if self.started_at is None:
            return None
        return round(time.perf_counter() - self.started_at, 2)


class ProgressLogger:
    def __init__(
        self,
        *,
        stage: str,
        substep: str | None = None,
        total: int | None = None,
        every: int = 0,
        percent_step: float = 10.0,
        min_interval_s: float = 15.0,
        prefix: str = "[progress]",
        emit_fn: Callable[[str], None] | None = None,
        base_fields: dict[str, Any] | None = None,
    ) -> None:
        self.stage = stage
        self.substep = substep
        self.total = total
        self.every = max(0, int(every))
        self.percent_step = max(0.1, float(percent_step))
        self.min_interval_s = max(0.0, float(min_interval_s))
        self.prefix = prefix
        self.emit_fn = emit_fn
        self.base_fields = dict(base_fields or {})
        self.started_at = time.perf_counter()
        self.last_logged_processed = 0
        self.last_logged_at = 0.0
        self.next_percent_threshold = self.percent_step

    def maybe_log(self, processed: int, *, total: int | None = None, force: bool = False, **fields: Any) -> bool:
        current_total = total if total is not None else self.total
        now = time.perf_counter()
        should_log = force or processed <= 1

        percent = None
        if current_total is not None and current_total > 0:
            percent = (processed / current_total) * 100.0
            if percent >= self.next_percent_threshold:
                should_log = True

        if self.every and processed - self.last_logged_processed >= self.every:
            should_log = True
        if self.last_logged_at and now - self.last_logged_at >= self.min_interval_s:
            should_log = True

        if not should_log:
            return False

        payload = dict(self.base_fields)
        payload.update(fields)
        payload.setdefault("stage", self.stage)
        payload.setdefault("substep", self.substep)
        payload["processed"] = processed
        if current_total is not None:
            payload["total"] = current_total
        if percent is not None:
            payload["percent"] = round(percent, 2)
        payload["elapsed"] = round(now - self.started_at, 2)
        payload["memory_mb"] = current_memory_mb()
        emit_observation(self.prefix, self.emit_fn, **payload)

        self.last_logged_processed = processed
        self.last_logged_at = now
        if current_total is not None and current_total > 0:
            processed_percent = (processed / current_total) * 100.0
            while self.next_percent_threshold <= processed_percent:
                self.next_percent_threshold += self.percent_step
        return True


# -----------------------------------------------------------------------------
# Human-readable helpers (banners, progress bars, artifact reports, failure
# summaries, highest-level-reached reports). These are all tiny formatters that
# call `print()` directly; they do not hold any mutable state.
# -----------------------------------------------------------------------------

def render_progress_bar(processed: int, total: int | None, *, width: int = 24) -> str:
    """Return a fixed-width ASCII progress bar such as "[#####....] 50.00%".

    Returns an empty string when total is missing or non-positive so callers
    can simply concatenate.
    """
    if not total or total <= 0 or width <= 0:
        return ""
    ratio = max(0.0, min(1.0, processed / float(total)))
    filled = int(round(ratio * width))
    bar = "#" * filled + "." * (width - filled)
    return f"[{bar}] {ratio * 100.0:6.2f}%"


def stage_banner(
    stage: str,
    status: str,
    *,
    scope: str = "pipeline",
    scenario: str | None = None,
    step: int | None = None,
    total_steps: int | None = None,
    processed: int | None = None,
    total: int | None = None,
    extra: dict[str, Any] | None = None,
    emoji: bool = False,
    emit_fn: Callable[[str], None] | None = None,
) -> str:
    """Print a one-line human-readable stage banner and return the rendered text.

    Examples::

        # regular per-stage rows (emoji=False, default)
        [pipeline][extract][START] step=1/5 scenario=foo
        [pipeline][backbone][OK]   step=2/5 scenario=foo elapsed=8.12s
        [pipeline][enrich][WARN]   step=3/5 scenario=foo reason=...

        # scenario-level rows in the batch loop (emoji=True)
        ✅ [batch][scenario][OK]          2/29 scenario=foo highest_level=dataset_release_v1
        ⚠ [batch][scenario][INCOMPLETE]   3/29 scenario=bar highest_level=chain
        ❌ [batch][scenario][FAIL]        4/29 scenario=baz highest_level=index
    """
    label = _status_label(status)
    color = _status_color(status)
    emoji_prefix = f"{_status_emoji(status)} " if emoji and _status_emoji(status) else ""
    prefix = f"{emoji_prefix}[{scope}][{stage}][{_paint(label, color)}]"

    parts: list[str] = [prefix]
    if step is not None and total_steps:
        parts.append(f"step={step}/{total_steps}")
    if processed is not None and total:
        bar = render_progress_bar(processed, total)
        if bar:
            parts.append(f"{processed}/{total} {bar}")
        else:
            parts.append(f"{processed}/{total}")
    if scenario:
        parts.append(f"scenario={scenario}")
    if extra:
        for key, value in extra.items():
            if value is None:
                continue
            parts.append(f"{key}={value}")

    line = " ".join(parts)
    if emit_fn is None:
        print(line, flush=True)
    else:
        emit_fn(line)
    return line


def banner_box(
    title: str,
    body_lines: Sequence[str] = (),
    *,
    status: str = "info",
    width: int = 80,
    emoji: bool = True,
    emit_fn: Callable[[str], None] | None = None,
) -> None:
    """Draw a loud, colour-coded banner box for FINAL status / FAIL blocks.

    Structure::

        ════════════════════════════════════════════════════════════════════
         <emoji> <title>
        ────────────────────────────────────────────────────────────────────
          body line 1
          body line 2
        ════════════════════════════════════════════════════════════════════

    Heavy rules at the top and bottom are colourised with the status colour
    so the whole block reads as a single visual unit, even when scrolled
    inside noisy log output. Only one emoji is placed on the title line —
    never on the body — so the box keeps a professional feel.
    """
    width = max(20, int(width))
    color = _status_color(status)
    heavy = _paint("═" * width, color)
    soft = _paint("─" * width, color)
    emoji_prefix = (
        f"{_status_emoji(status)} "
        if emoji and _status_emoji(status)
        else ""
    )
    colored_title = _paint(title, color)
    out_lines = [heavy, f" {emoji_prefix}{colored_title}"]
    if body_lines:
        out_lines.append(soft)
        for line in body_lines:
            out_lines.append(f"  {line}")
    out_lines.append(heavy)
    block = "\n".join(out_lines)
    if emit_fn is None:
        print(block, flush=True)
    else:
        emit_fn(block)


def progress_line(
    scope: str,
    processed: int,
    total: int | None,
    *,
    current: str | None = None,
    extra: dict[str, Any] | None = None,
    emit_fn: Callable[[str], None] | None = None,
) -> str:
    """Short uniform progress line, e.g. `[batch][progress] 3/29 (10.34%) current=foo`."""
    bar = render_progress_bar(processed, total)
    pct = ""
    if total:
        pct = f" ({(processed / total) * 100.0:.2f}%)"
    body = f"{processed}/{total if total else '?'}{pct}"
    extras: list[str] = []
    if current:
        extras.append(f"current={current}")
    if extra:
        for key, value in extra.items():
            if value is None:
                continue
            extras.append(f"{key}={value}")
    tail = " ".join(extras)
    bar_seg = f" {bar}" if bar else ""
    line = f"[{scope}][progress] {body}{bar_seg}" + (f" {tail}" if tail else "")
    if emit_fn is None:
        print(line, flush=True)
    else:
        emit_fn(line)
    return line


def _artifact_status_tag(exists: bool, optional: bool, note: str | None) -> str:
    if exists:
        return _paint("OK", STATUS_COLORS["ok"])
    if optional:
        if note:
            return _paint(f"not_exported_by_default ({note})", STATUS_COLORS["info"])
        return _paint("not_exported_by_default", STATUS_COLORS["info"])
    return _paint("MISSING", STATUS_COLORS["fail"])


def artifact_report(
    scope: str,
    stage: str,
    artifacts: Sequence[dict[str, Any]],
    *,
    emit_fn: Callable[[str], None] | None = None,
) -> None:
    """Print a compact key-artifact table under a stage banner.

    Each artifact is a dict: {path: Path, label: str (optional), optional: bool (default False),
    note: str (optional), exists: bool (optional, autodetected from path)}.

    The caller is expected to emit this immediately after the stage's OK /
    FAIL / WARN banner so the list reads as "this stage produced:".
    """
    header = f"[{scope}][{stage}][artifacts]"
    rows: list[str] = []
    for art in artifacts:
        path = art.get("path")
        label = art.get("label") or (Path(path).name if path else "<unnamed>")
        optional = bool(art.get("optional", False))
        note = art.get("note")
        if "exists" in art and art.get("exists") is not None:
            exists = bool(art.get("exists"))
        else:
            exists = bool(path_exists(path)) if path is not None else False
        tag = _artifact_status_tag(exists, optional, note)
        size_hint = ""
        if exists and path is not None:
            try:
                size = Path(path).stat().st_size
                if size >= 0:
                    size_hint = f" ({_human_size(size)})"
            except Exception:
                pass
        rows.append(f"    - {label:<44} {tag}{size_hint}")
    if not rows:
        rows.append("    - (no artifacts declared)")
    line = header + "\n" + "\n".join(rows)
    if emit_fn is None:
        print(line, flush=True)
    else:
        emit_fn(line)


def _human_size(size: int) -> str:
    suffixes = ("B", "KB", "MB", "GB", "TB")
    idx = 0
    value = float(size)
    while value >= 1024.0 and idx < len(suffixes) - 1:
        value /= 1024.0
        idx += 1
    if idx == 0:
        return f"{int(value)}{suffixes[idx]}"
    return f"{value:.1f}{suffixes[idx]}"


# Mapping from a scenario timestamp dir to the highest stable level it has
# reached on disk. The names match what the user asked for exactly:
#   raw < index < chain < dataset_release_v1
LEVEL_ORDER = ("raw", "index", CHAIN_DIR_NAME, "dataset_release_v1")


def highest_level_reached(
    scenario_dir: str | Path,
    *,
    release_root: str | Path | None = None,
    release_slug: str | None = None,
) -> str:
    """Return the highest stable level reached for a scenario timestamp dir.

    Uses on-disk evidence only (does not look at stage_status dicts) so it
    is stable across batch summary aggregation and single-scenario runs.
    Order: raw -> index -> chain -> dataset_release_v1.
    """
    try:
        sdir = Path(scenario_dir)
    except Exception:
        return "unknown"

    if not sdir.exists():
        return "unknown"

    level = "unknown"
    # raw/: build-side provenance dump exists
    raw_dir = sdir / "raw"
    if raw_dir.exists() and any(raw_dir.iterdir()):
        level = "raw"
    # index/: build-side indices exist (we key on unit_event_index.jsonl which
    # is the Mode B required index). If any of the core indices exists we
    # treat the scenario as having reached "index".
    index_dir = sdir / "index"
    if index_dir.exists():
        for candidate in ("unit_event_index.jsonl", "unit_index.jsonl",
                          "write_event_context_index.v0.jsonl"):
            p = index_dir / candidate
            if p.exists() and p.stat().st_size > 0:
                level = "index"
                break
    # chain/: pipeline dataset produced
    chain_dir = scenario_chain_dir(sdir)
    dataset_file = chain_dir / "behavior_chain_dataset.v2.json"
    if dataset_file.exists() and dataset_file.stat().st_size > 0:
        level = CHAIN_DIR_NAME
    # dataset_release_v1/: per-scenario release sample materialised
    if release_root is not None and release_slug:
        try:
            rel_sample = Path(release_root) / "shared" / "scenarios" / release_slug / "main_sample.json"
            if rel_sample.exists() and rel_sample.stat().st_size > 0:
                level = "dataset_release_v1"
        except Exception:
            pass
    return level


def release_slug_for(scenario_dir: str | Path) -> str:
    """Best-effort slug derivation (vendor/name/CVE plus timestamp suffix)."""
    try:
        p = Path(scenario_dir).resolve()
        ts = p.name
        base = p.parent
        # Walk upward until we hit results/ root to build a relative slug.
        parts: list[str] = []
        cursor = base
        while cursor.name and cursor.name != "results":
            parts.append(cursor.name)
            cursor = cursor.parent
            if len(parts) > 8:
                break
        parts.reverse()
        slug_base = "__".join(parts) if parts else base.name
        return f"{slug_base}__{ts}"
    except Exception:
        return ""


def failure_classification(stage: str, reason: str) -> str:
    """Map a (stage, reason) pair to a human-readable failure category.

    Output is one of:
        logic_failure / missing_input / incomplete /
        performance_boundary / controlled_skip / unknown
    """
    text = (reason or "").lower()
    if not text:
        return "unknown"
    # Guard/performance boundaries take precedence over controlled_skip so
    # that e.g. "enrich skipped by guard (backbone_guard_threshold_exceeded)"
    # is reported as a performance_boundary rather than a user-controlled skip.
    if (
        "guard_threshold" in text
        or "too many" in text
        or "oom" in text
        or "killed" in text
        or "memory" in text
    ):
        return "performance_boundary"
    if "skipped" in text or "skip_enrich" in text or "controlled" in text:
        return "controlled_skip"
    if (
        "incomplete" in text
        or "empty" in text
        or "produced no" in text
        or "not written" in text
        or "not_written" in text
    ):
        return "incomplete"
    if (
        "missing" in text
        or "not found" in text
        or "no such" in text
        or "does not exist" in text
    ):
        return "missing_input"
    if "rc=" in text or "failed" in text or "error" in text or "exception" in text:
        return "logic_failure"
    return "unknown"


def failure_summary_block(
    scope: str,
    *,
    scenario: str | None,
    stage: str | None,
    reason: str,
    category: str | None = None,
    highest_level: str | None = None,
    missing: Iterable[str] | None = None,
    emit_fn: Callable[[str], None] | None = None,
) -> None:
    """Print a multi-line, colour-highlighted failure summary.

    Rendered as a red/yellow banner box so the block is clearly distinct
    from regular log output — designed to be printed *before* any Python
    traceback so the operator can see a one-glance summary even when
    scrolled inside a noisy log.
    """
    cat = category or failure_classification(stage or "", reason or "")
    is_incomplete = cat in {"controlled_skip", "incomplete", "performance_boundary"}
    box_status = "incomplete" if is_incomplete else "fail"
    label = "INCOMPLETE" if is_incomplete else "FAIL"
    title = f"[{scope}][{label}] stage={stage or 'unknown'} category={cat}"
    body: list[str] = []
    if scenario:
        body.append(f"scenario      : {scenario}")
    if highest_level:
        body.append(f"highest_level : {highest_level}")
    body.append(f"reason        : {reason or 'unknown'}")
    missing_list = [item for item in (missing or []) if item]
    if missing_list:
        body.append("missing_inputs_or_outputs:")
        for item in missing_list:
            body.append(f"  - {item}")
    banner_box(title, body, status=box_status, emoji=True, emit_fn=emit_fn)


def final_status_block(
    scope: str,
    *,
    status: str,
    scenario: str | None = None,
    highest_level: str | None = None,
    stage_status: dict[str, str] | None = None,
    elapsed: float | None = None,
    extra: dict[str, Any] | None = None,
    emit_fn: Callable[[str], None] | None = None,
) -> None:
    """Print a uniform loud final block shared by single-scenario, batch, and wrapper entries."""
    label = _status_label(status)
    title = f"[{scope}][DONE] status={label}"
    body: list[str] = []
    if scenario:
        body.append(f"scenario      : {scenario}")
    if highest_level:
        body.append(f"highest_level : {highest_level}")
    if stage_status:
        joined = "  ".join(
            f"{k}={v}" for k, v in stage_status.items() if v is not None
        )
        body.append(f"stages        : {joined}")
    if elapsed is not None:
        body.append(f"elapsed       : {elapsed:.2f}s")
    if extra:
        for key, value in extra.items():
            if value is None:
                continue
            body.append(f"{key:<14}: {value}")
    banner_box(title, body, status=status, emoji=True, emit_fn=emit_fn)
