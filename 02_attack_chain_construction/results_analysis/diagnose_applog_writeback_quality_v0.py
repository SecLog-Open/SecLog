#!/usr/bin/env python3
"""
Read-only quality diagnostic for multisource_context.applog.

For each scenario's ``behavior_chain_dataset.v2.json`` we:
  * tally Tier / attach_strength / attach_reason distributions;
  * inspect what weak records look like (source_file, service_name,
    log_style, message shape) so we can decide what to tighten;
  * inspect which medium records already carry stronger evidence that
    the current builder ignores (e.g. ``write_proc_pid`` equal to the
    backbone edge's ``proc_pid``) — these are candidates for
    ``medium_high`` promotion;
  * emit a light semantic-type summary so we know which kinds of
    applog lines actually reach the main sample.

Nothing is modified: a summary JSON is written to
``chain/applog_writeback_quality.v0.json``. Run against as many
scenarios as desired.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Optional

from pipeline.utils.common import scenario_chain_dir


# --- light semantic heuristics (keep intentionally simple / explainable) ---

_ACCESS_LOG_PATTERNS = (
    re.compile(r'"\s*(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|CONNECT)\s+'),
    re.compile(r'\s-\s-\s\[\d{1,2}/\w+/\d{4}'),
)
_SQL_PATTERNS = (
    re.compile(r'\b(?:SELECT|INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM|CREATE\s+TABLE|ALTER\s+TABLE|DROP\s+TABLE)\b', re.IGNORECASE),
    re.compile(r'\bFROM\s+`?[a-zA-Z_][\w.$]+`?', re.IGNORECASE),
)
_ERROR_PATTERNS = (
    re.compile(r'\b(?:ERROR|FATAL|CRITICAL|Exception|Traceback|stacktrace)\b'),
    re.compile(r'\b(?:5\d\d\s)'),
)
_WARN_PATTERNS = (
    re.compile(r'\b(?:WARN|WARNING)\b'),
)
_AUTH_PATTERNS = (
    re.compile(r'\b(?:login|logout|auth|session|sign\s*in|sign\s*out|token|password|credential)\b', re.IGNORECASE),
)
_FILE_OP_PATTERNS = (
    re.compile(r'\b(?:upload|download|writ\w+|read\w+|open\w+|delete\w+|unlink|rename)\b', re.IGNORECASE),
    re.compile(r'/[\w./-]{3,}\.(?:log|txt|php|py|jsp|sh|conf|json|xml|yml|yaml|ini)\b'),
)
_RESPONSE_PATTERNS = (
    re.compile(r'\b(?:2\d\d|3\d\d|4\d\d|5\d\d)\s+\d+(?:\s+|$)'),
    re.compile(r'\b(?:HTTP/\d\.\d"\s+\d{3})'),
)
_STARTUP_PATTERNS = (
    re.compile(r'\b(?:starting|started|initializ\w+|bootstrap|listening on|Ready|bind\s+to)\b', re.IGNORECASE),
)


def _classify_semantic(message: str, log_style: Optional[str], source_file: Optional[str]) -> str:
    msg = message or ""
    lstyle = (log_style or "").lower()
    src = (source_file or "").lower()

    if any(p.search(msg) for p in _ERROR_PATTERNS):
        return "error_exception"
    if any(p.search(msg) for p in _WARN_PATTERNS):
        return "warn_event"

    # Access-log style first (web servers put every request here)
    if lstyle == "access_text" or any(p.search(msg) for p in _ACCESS_LOG_PATTERNS):
        return "request_access"

    if any(p.search(msg) for p in _SQL_PATTERNS):
        return "db_query"

    if any(p.search(msg) for p in _AUTH_PATTERNS):
        return "auth_session"

    if any(p.search(msg) for p in _FILE_OP_PATTERNS):
        return "file_operation"

    if any(p.search(msg) for p in _RESPONSE_PATTERNS):
        return "response_result"

    if any(p.search(msg) for p in _STARTUP_PATTERNS):
        return "startup_runtime"

    return "generic_runtime_log"


def _normalize_message_pattern(msg: str) -> str:
    """Collapse volatile parts of a log line for pattern counting."""
    if not msg:
        return ""
    t = msg
    t = re.sub(r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?', '<ts>', t)
    t = re.sub(r'\d{1,2}/[A-Za-z]+/\d{4}:\d{2}:\d{2}:\d{2}(?:\s[+\-]\d{4})?', '<ts>', t)
    t = re.sub(r'\b\d+(?:\.\d+){3}(?::\d+)?\b', '<ip>', t)
    t = re.sub(r'\b0x[0-9a-fA-F]+\b', '<hex>', t)
    t = re.sub(r'\b\d{4,}\b', '<num>', t)
    t = re.sub(r'"[^"]*"', '"<str>"', t)
    return t.strip()[:200]


def _edge_proc_pid(edge: dict[str, Any]) -> Optional[str]:
    attrs = edge.get("attrs") or {}
    v = attrs.get("proc_pid")
    if v is None:
        return None
    return str(v)


def _analyze_scenario(scenario_dir: Path) -> dict[str, Any]:
    dataset_path = scenario_chain_dir(scenario_dir) / "behavior_chain_dataset.v2.json"
    dataset = json.loads(dataset_path.read_text(encoding="utf-8", errors="replace"))

    spine = dataset.get("spine") or []
    edge_by_id: dict[str, dict[str, Any]] = {}
    for edge in spine:
        eid = str(edge.get("edge_id") or "")
        if eid:
            edge_by_id[eid] = edge

    tier_counter: Counter[str] = Counter()
    strength_counter: Counter[str] = Counter()
    reason_counter: Counter[str] = Counter()
    semantic_counter: Counter[str] = Counter()
    log_style_counter: Counter[str] = Counter()
    source_file_counter: Counter[str] = Counter()

    # Per strength breakdown
    per_strength_pattern: dict[str, Counter[str]] = defaultdict(Counter)
    per_strength_semantic: dict[str, Counter[str]] = defaultdict(Counter)
    per_strength_service: dict[str, Counter[str]] = defaultdict(Counter)
    per_strength_source: dict[str, Counter[str]] = defaultdict(Counter)

    # "could be promoted to medium_high": medium records whose write_proc_pid
    # matches the backbone edge's proc_pid (or contain strong evidence).
    promotion_eligible_proc_pid = 0
    promotion_eligible_total = 0
    medium_total = 0

    # per-edge distribution: how many weak entries per edge (for cap checks)
    per_edge_weak_count: Counter[int] = Counter()
    per_edge_total_count: Counter[int] = Counter()
    edges_with_applog = 0
    total_applog = 0

    for edge in spine:
        eid = str(edge.get("edge_id") or "")
        aps = (edge.get("multisource_context") or {}).get("applog") or []
        if not aps:
            continue
        edges_with_applog += 1
        total_applog += len(aps)

        edge_proc_pid = _edge_proc_pid(edge)
        weak_here = 0
        for ap in aps:
            strength = str(ap.get("attach_strength") or "unknown")
            reason = str(ap.get("attach_reason") or "unknown")
            tier_counter[reason] += 1
            strength_counter[strength] += 1
            reason_counter[reason] += 1

            msg = str(ap.get("message") or "")
            log_style = ap.get("log_style")
            src = ap.get("source_file")
            service = ap.get("service_name")

            semantic = _classify_semantic(msg, log_style, src)
            semantic_counter[semantic] += 1
            per_strength_semantic[strength][semantic] += 1

            if log_style:
                log_style_counter[str(log_style)] += 1
            if src:
                source_file_counter[str(src)] += 1
                per_strength_source[strength][str(src)] += 1
            if service:
                per_strength_service[strength][str(service)] += 1

            per_strength_pattern[strength][_normalize_message_pattern(msg)] += 1

            if strength == "weak":
                weak_here += 1

            if strength == "medium":
                medium_total += 1
                write_pid = ap.get("write_proc_pid")
                if (
                    write_pid is not None
                    and edge_proc_pid is not None
                    and str(write_pid) == str(edge_proc_pid)
                ):
                    promotion_eligible_proc_pid += 1
                    promotion_eligible_total += 1

        per_edge_weak_count[weak_here] += 1
        per_edge_total_count[len(aps)] += 1

    def _top(counter: Counter[str], n: int = 10) -> list[dict[str, Any]]:
        return [{"key": k, "count": c} for k, c in counter.most_common(n)]

    summary = {
        "scenario_dir": str(scenario_dir),
        "dataset_path": str(dataset_path),
        "spine_edges": len(spine),
        "edges_with_applog": edges_with_applog,
        "total_applog_entries": total_applog,
        "tier_distribution": dict(sorted(tier_counter.items(), key=lambda p: -p[1])),
        "strength_distribution": dict(sorted(strength_counter.items(), key=lambda p: -p[1])),
        "semantic_distribution": dict(sorted(semantic_counter.items(), key=lambda p: -p[1])),
        "log_style_distribution": dict(sorted(log_style_counter.items(), key=lambda p: -p[1])),
        "source_file_distribution": dict(sorted(source_file_counter.items(), key=lambda p: -p[1])),
        "weak_top_patterns": _top(per_strength_pattern.get("weak", Counter()), 10),
        "weak_semantic_distribution": dict(per_strength_semantic.get("weak", {})),
        "weak_source_distribution": dict(per_strength_source.get("weak", {})),
        "weak_service_distribution": dict(per_strength_service.get("weak", {})),
        "medium_top_patterns": _top(per_strength_pattern.get("medium", Counter()), 10),
        "medium_semantic_distribution": dict(per_strength_semantic.get("medium", {})),
        "promotion_eligibility": {
            "medium_total": medium_total,
            "medium_promotion_eligible_via_proc_pid": promotion_eligible_proc_pid,
            "medium_promotion_eligible_total": promotion_eligible_total,
        },
        "per_edge_weak_distribution": dict(
            sorted(per_edge_weak_count.items(), key=lambda p: p[0])
        ),
        "per_edge_total_distribution": dict(
            sorted(per_edge_total_count.items(), key=lambda p: p[0])
        ),
    }
    return summary


def main(argv: Optional[list[str]] = None) -> int:
    p = argparse.ArgumentParser(description="Applog writeback quality diagnostic")
    p.add_argument("--scenario-dir", type=Path, action="append", required=True,
                   help="Scenario directory (can pass multiple times)")
    p.add_argument("--summary-output", type=Path, default=None,
                   help="Combined summary json (default: stdout only)")
    args = p.parse_args(argv)

    results: dict[str, Any] = {
        "schema_version": "applog_writeback_quality.v0",
        "scenarios": [],
    }
    for sd in args.scenario_dir:
        summary = _analyze_scenario(sd)
        results["scenarios"].append(summary)

        per_scenario_path = scenario_chain_dir(sd) / "applog_writeback_quality.v0.json"
        per_scenario_path.parent.mkdir(parents=True, exist_ok=True)
        per_scenario_path.write_text(
            json.dumps(summary, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        print(
            f"[applog-quality] scenario={sd.name} "
            f"applog={summary['total_applog_entries']} "
            f"edges_with_applog={summary['edges_with_applog']} "
            f"strength={summary['strength_distribution']}"
        )

    if args.summary_output is not None:
        args.summary_output.parent.mkdir(parents=True, exist_ok=True)
        args.summary_output.write_text(
            json.dumps(results, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
