#!/usr/bin/env python3
"""
Attach malicious non-core records back around backbone edges as context only.

v1 upgrade: same_unit attach now uses family consistency, entity confirmation,
and local distance to produce more interpretable and chain-useful attachments.
This is preparation for future behavior_chain_instances, not a backbone rewrite.

This script does not rewrite backbone or change the default core-only builder
contract. It produces a sidecar context layer that can be inspected separately.
"""

from __future__ import annotations

import argparse
import bisect
import json
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from console_observability import ProgressLogger, emit_observation
from results_analysis.pipeline.utils.common import CHAIN_DIR_NAME


SCENARIO_DIR = ROOT_DIR / "results" / "vulhub" / "gitlist" / "CVE-2018-1000533" / "2026-03-17_02-32-45"
CHAIN_DIR = SCENARIO_DIR / CHAIN_DIR_NAME
INDEX_DIR = SCENARIO_DIR / "index"

DEFAULT_BACKBONE = CHAIN_DIR / "backbone_chain.v1.json"
DEFAULT_AUXILIARY = CHAIN_DIR / "audit_triples.auxiliary.v1.jsonl"
DEFAULT_FILTERED = CHAIN_DIR / "audit_triples.filtered.v1.jsonl"
DEFAULT_UNKNOWN = CHAIN_DIR / "audit_triples.unknown.v1.jsonl"
DEFAULT_TIER_MANIFEST = CHAIN_DIR / "audit_triples_tier_manifest.v1.json"
DEFAULT_UNIT_EVENT_INDEX = INDEX_DIR / "unit_event_index.jsonl"
DEFAULT_UNIT_INDEX = INDEX_DIR / "unit_index.jsonl"
DEFAULT_OUTPUT = CHAIN_DIR / "behavior_context_edges.v0.jsonl"
DEFAULT_UNMATCHED_OUTPUT = CHAIN_DIR / "behavior_context_unmatched.v0.jsonl"
DEFAULT_SUMMARY_OUTPUT = CHAIN_DIR / "behavior_context_summary.v0.json"
DEFAULT_NONCORE_ATTACH_CANDIDATE_OUTPUT = CHAIN_DIR / "noncore_attach_candidate_index.v0.jsonl"
DEFAULT_UNMATCHED_REASON_TRACE_OUTPUT = CHAIN_DIR / "unmatched_reason_trace.v0.jsonl"
DEFAULT_EVENT_TO_BACKBONE_ANCHOR_OUTPUT = INDEX_DIR / "event_to_backbone_anchor_index.v0.jsonl"
NONCORE_ATTACH_CANDIDATE_SCHEMA_VERSION = "noncore_attach_candidate_index.v0"
UNMATCHED_REASON_TRACE_SCHEMA_VERSION = "unmatched_reason_trace.v0"
EVENT_TO_BACKBONE_ANCHOR_SCHEMA_VERSION = "event_to_backbone_anchor_index.v0"

RULE_PRIORITY = {
    "same_evt_num": 4,
    "same_unit": 3,
    "family_consistent": 3,
    "entity_confirmed": 3,
    "time_near": 1,
}
TIME_NEAR_EVT_WINDOW = 8
TIME_NEAR_SEC_WINDOW = 0.25

# --- v1 scoring weights ---
# same_unit is the base prerequisite; family/entity/distance refine within it.
SCORE_SAME_EVT_NUM = 400
SCORE_SAME_UNIT_BASE = 100
SCORE_FAMILY_CONSISTENT = 30
SCORE_ENTITY_CONFIRMED = 40
SCORE_SAME_ENTITY_STANDALONE = 80
SCORE_TIME_NEAR = 10
# local distance bonus: up to 20 points for being very close within the unit.
SCORE_LOCAL_DISTANCE_MAX = 20

# --- weak_inferred scoring (getsockname targeted fallback) ---
# Score is intentionally low: this rule only fires after all reliable rules fail.
SCORE_WEAK_INFERRED_NET = 5

# Time window for getsockname -> NET_* weak_inferred: within 5 seconds.
WEAK_INFERRED_NET_SEC_WINDOW = 5.0

# Number of candidate NET_* edges required to be considered "too ambiguous" to attach.
# If more than this many NET_* edges exist in the same container/temporal window,
# we skip the attachment to avoid false binding.
# Special case: we keep the SINGLE NEAREST candidate even when multiple exist
# in the same timestamp (getsockname fires multiple times for the same connection
# but only the nearest-by-time should attach).
WEAK_INFERRED_NET_MAX_CANDIDATES = 1

BACKBONE_GUARD_THRESHOLD = 5000
BOUNDED_ENRICH_EVT_WINDOW = 8

PREPARATORY_EVT_TYPES = frozenset({
    "access", "stat", "lstat", "getdents", "socket",
})

RESULTING_EVT_TYPES = frozenset({
    "close", "shutdown", "unlink", "rmdir", "exit", "exit_group",
})

NECESSARY_CONTEXT_EVT_TYPES = PREPARATORY_EVT_TYPES | RESULTING_EVT_TYPES
DEFAULT_NECESSARY_CONTEXT_WINDOW = 5

# --- explanatory non-malicious channel (diagnostic-driven, opt-in) ---
# Small, stable, semantic whitelist derived from cross-scenario attach
# eligibility diagnostics (adminer / cmsms / kibana / geoserver):
# keep evt_types whose non-malicious records frequently carry attack
# explanatory signal, while excluding high-volume / low-signal syscalls
# (fstat / stat / lstat / newfstatat / lseek / fcntl / flock / ioctl /
# getsockname / getpeername / getcwd / getrlimit / prlimit). These
# excluded ones are descriptor metadata queries: they multiply the
# audit_context without adding much semantic value beyond what entity
# confirmation already provides via the malicious channel.
EXPLANATORY_EVT_TYPES = frozenset({
    # I/O lifecycle
    "close", "shutdown", "dup", "dup2", "dup3",
    # destructive / rename
    "unlink", "unlinkat", "rmdir", "rename", "renameat", "renameat2",
    # permission / ownership changes
    "chmod", "fchmod", "chown", "fchown", "fchmodat", "fchownat",
    # networking setup
    "socket", "bind", "listen", "accept", "accept4",
    # permission / path probing
    "access", "faccessat", "faccessat2",
    # directory listing / navigation
    "getdents", "getdents64", "chdir", "fchdir",
})

# Minimum attach_strength accepted for the explanatory channel. We do
# not admit "medium_low" (same_unit only, no family/entity match) or
# weaker rungs because the diagnostic showed they make up the bulk of
# volume-inflating noise.
EXPLANATORY_MIN_STRENGTH = frozenset({"strong", "medium_high", "medium"})

# Per-backbone-edge cap for the explanatory channel. Hard ceiling on
# audit_context bloat independent of scenario size.
DEFAULT_EXPLANATORY_PER_EDGE_CAP = 3

_FILE_EVT_TYPES = frozenset({
    "stat", "fstat", "lstat", "newfstatat", "access", "lseek",
    "read", "pread", "readv", "write", "pwrite", "writev",
    "open", "openat", "close", "rename", "unlink", "fcntl",
    "getdents", "getdents64", "chdir", "getcwd", "mkdir", "rmdir",
    "chmod", "chown", "fchmod", "fchown", "truncate", "ftruncate",
})
_NET_EVT_TYPES = frozenset({
    "socket", "bind", "listen", "connect", "accept", "accept4",
    "send", "sendto", "sendmsg", "recv", "recvfrom", "recvmsg",
    "shutdown", "getsockname", "getpeername", "getsockopt", "setsockopt",
    "ioctl",
})
_PROCESS_EVT_TYPES = frozenset({
    "clone", "clone3", "fork", "vfork", "execve", "execveat",
    "exit", "exit_group", "wait4", "waitid",
})


def _infer_family_from_relation(relation: Optional[str]) -> str:
    if relation is None:
        return "UNKNOWN"
    r = str(relation).upper()
    if r.startswith("FILE_"):
        return "FILE"
    if r.startswith("NET_"):
        return "NET"
    if r.startswith("PROCESS_"):
        return "PROCESS"
    return "UNKNOWN"


def _infer_family_from_record(record: dict[str, Any]) -> str:
    relation = record.get("relation")
    if relation is not None:
        family = _infer_family_from_relation(str(relation))
        if family != "UNKNOWN":
            return family

    raw_evt_type = (_attrs(record).get("raw_evt_type") or record.get("event_type") or "").lower()
    if raw_evt_type in _FILE_EVT_TYPES:
        return "FILE"
    if raw_evt_type in _NET_EVT_TYPES:
        return "NET"
    if raw_evt_type in _PROCESS_EVT_TYPES:
        return "PROCESS"

    fd_type = None
    attrs = _attrs(record)
    if attrs.get("fd_type"):
        fd_type = str(attrs["fd_type"]).lower()
    else:
        fd = record.get("fd")
        if isinstance(fd, dict) and fd.get("type"):
            fd_type = str(fd["type"]).lower()
    if fd_type in ("file", "directory", "fifo", "pipe"):
        return "FILE"
    if fd_type in ("ipv4", "ipv6", "ipv6v4", "unix"):
        return "NET"

    fd_name = _record_fd_name(record)
    if fd_name:
        if fd_name.startswith("/") or fd_name.startswith("file:"):
            return "FILE"
        if "->" in fd_name or fd_name.startswith("conn:"):
            return "NET"

    return "UNKNOWN"


def _local_distance_bonus(evt_delta: Optional[int]) -> float:
    if evt_delta is None or evt_delta < 0:
        return 0.0
    if evt_delta == 0:
        return float(SCORE_LOCAL_DISTANCE_MAX)
    if evt_delta <= 4:
        return float(SCORE_LOCAL_DISTANCE_MAX) * 0.75
    if evt_delta <= 16:
        return float(SCORE_LOCAL_DISTANCE_MAX) * 0.5
    if evt_delta <= 64:
        return float(SCORE_LOCAL_DISTANCE_MAX) * 0.25
    return 0.0


def _normalize_optional_unit_id(raw: Any) -> Optional[str]:
    if raw is None:
        return None
    s = str(raw).strip()
    if not s or s.lower() == "null":
        return None
    return s


def _select_preferred_unit_key(row: dict[str, Any]) -> Optional[str]:
    unit_key = _normalize_optional_unit_id(row.get("unit_key"))
    if unit_key is not None:
        return unit_key
    return _normalize_optional_unit_id(row.get("unit_id"))


def _parse_ts(raw: Any) -> Optional[datetime]:
    if raw is None:
        return None
    text = str(raw).strip()
    if not text:
        return None
    if "." in text:
        prefix, frac = text.split(".", 1)
        frac = "".join(ch for ch in frac if ch.isdigit())[:6].ljust(6, "0")
        text = f"{prefix}.{frac}"
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def _read_json(path: Path) -> dict[str, Any]:
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return json.load(fh)


def _iter_jsonl(path: Path):
    # The extractor keeps empty non-core tier files lazy and may omit them.
    # Treat a missing optional tier as an empty stream so a core-only run can
    # still proceed through enrichment and dataset assembly.
    if not path.is_file():
        return
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line_no, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except Exception as exc:
                raise ValueError(f"{path} line {line_no}: invalid json: {exc}") from exc


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    if not rows:
        if path.is_file():
            path.unlink()
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, ensure_ascii=False, separators=(",", ":")))
            fh.write("\n")


def _write_json(path: Path, obj: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, ensure_ascii=False, indent=2)
        fh.write("\n")


def _remove_file_if_exists(path: Path) -> bool:
    if path.is_file():
        path.unlink()
        return True
    return False


def _clear_skipped_enrich_downstream_artifacts(
    scenario_dir: Path,
    output_path: Path,
    unmatched_output_path: Path,
) -> list[str]:
    """
    During a guard or explicit skip, clean only downstream enrich/dataset files
    that are definitely invalid and would pollute the formal success/dataset input.

    Deliberately leave backbone/build/analyze/applog/traffic sidecars untouched.
    """
    chain_dir = scenario_dir / CHAIN_DIR_NAME
    stale_paths = [
        output_path,
        unmatched_output_path,
        chain_dir / "behavior_chain_dataset.v2.json",
        chain_dir / "behavior_chain_dataset.v2.meta.json",
    ]
    removed: list[str] = []
    for path in stale_paths:
        if _remove_file_if_exists(path):
            removed.append(str(path))
    return removed


def _normalize_optional_str(raw: Any) -> Optional[str]:
    if raw is None:
        return None
    value = str(raw).strip()
    if not value or value.lower() == "null":
        return None
    return value


def _record_mode(record: dict[str, Any]) -> str:
    return "structured" if str(record.get("record_mode") or "") == "structured_event" else "triple"


def _attrs(record: dict[str, Any]) -> dict[str, Any]:
    attrs = record.get("attrs")
    return attrs if isinstance(attrs, dict) else {}


def _record_evt_num(record: dict[str, Any]) -> Optional[int]:
    value = _attrs(record).get("evt_num")
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _record_timestamp(record: dict[str, Any]) -> Optional[str]:
    ts = _attrs(record).get("timestamp")
    return str(ts) if ts is not None else None


def _record_raw_evt_type(record: dict[str, Any]) -> Optional[str]:
    value = _attrs(record).get("raw_evt_type") or record.get("event_type")
    return str(value) if value is not None else None


def _record_container(record: dict[str, Any]) -> Optional[str]:
    attrs = _attrs(record)
    value = attrs.get("container_id")
    if value is not None:
        return str(value)
    proc = record.get("proc")
    if isinstance(proc, dict) and proc.get("container_id") is not None:
        return str(proc["container_id"])
    return None


def _record_subject(record: dict[str, Any]) -> Optional[str]:
    value = record.get("subject")
    return str(value) if value is not None else None


def _record_object(record: dict[str, Any]) -> Optional[str]:
    value = record.get("object")
    return str(value) if value is not None else None


def _record_fd_name(record: dict[str, Any]) -> Optional[str]:
    attrs = _attrs(record)
    fd_name = attrs.get("fd_name")
    if fd_name is not None:
        return str(fd_name)
    fd = record.get("fd")
    if isinstance(fd, dict) and fd.get("name") is not None:
        return str(fd["name"])
    return None


def _record_proc_pid(record: dict[str, Any]) -> Optional[str]:
    attrs = _attrs(record)
    value = attrs.get("proc_pid")
    if value is not None:
        return str(value)
    proc = record.get("proc")
    if isinstance(proc, dict) and proc.get("pid") is not None:
        return str(proc["pid"])
    return None


def _record_tier(record: dict[str, Any], fallback: str) -> str:
    tier = _attrs(record).get("tier")
    return str(tier) if tier is not None else fallback


def _normalize_entity_value(raw: Optional[str]) -> Optional[str]:
    if raw is None:
        return None
    value = str(raw).strip()
    if not value:
        return None
    for prefix in ("file:", "conn:", "proc:"):
        if value.startswith(prefix):
            return value[len(prefix):]
    return value


def _record_entity_tokens(record: dict[str, Any]) -> dict[str, str]:
    tokens: dict[str, str] = {}
    obj = _normalize_entity_value(_record_object(record))
    fd_name = _normalize_entity_value(_record_fd_name(record))
    if obj:
        tokens[f"entity:{obj}"] = "object"
    if fd_name:
        tokens[f"entity:{fd_name}"] = "fd_name"
    return tokens


def load_backbone(path: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    raw = _read_json(path)
    edges = raw.get("edge_sequence")
    if not isinstance(edges, list):
        raise ValueError(f"invalid backbone edge_sequence: {path}")
    return edges, raw


def _scenario_id_for_outputs(
    scenario_dir: Path,
    tier_manifest: dict[str, Any],
    backbone_raw: dict[str, Any],
) -> str:
    return str(
        tier_manifest.get("scenario_id")
        or backbone_raw.get("scenario_id")
        or scenario_dir.name
    )


def _unit_id_from_row(unit_row: Optional[dict[str, Any]]) -> Optional[str]:
    if not isinstance(unit_row, dict):
        return None
    return _normalize_optional_str(unit_row.get("unit_id"))


def build_backbone_self_anchor_rows(
    enriched_edges: list[dict[str, Any]],
    scenario_id: str,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for edge in enriched_edges:
        evt_num = edge.get("evt_num")
        if evt_num is None:
            continue
        unit_meta = edge.get("unit_meta") if isinstance(edge.get("unit_meta"), dict) else {}
        rows.append(
            {
                "schema_version": EVENT_TO_BACKBONE_ANCHOR_SCHEMA_VERSION,
                "scenario_id": scenario_id,
                "source_type": "sysdig_backbone_event",
                "source_event_key": f"sysdig:{evt_num}",
                "source_evt_num": evt_num,
                "container_id": edge.get("container_id"),
                "thread_vtid": _normalize_optional_str(unit_meta.get("thread_vtid")),
                "unit_id": _unit_id_from_row(unit_meta),
                "proc_pid": _normalize_optional_str((edge.get("attrs") or {}).get("proc_pid")),
                "fd_name": edge.get("fd_name"),
                "source_timestamp": edge.get("timestamp"),
                "anchor_backbone_edge_id": edge.get("edge_id"),
                "anchor_backbone_seq": edge.get("seq"),
                "anchor_backbone_relation": edge.get("relation"),
                "anchor_backbone_evt_num": evt_num,
                "anchor_rule": "backbone_self_evt",
                "confidence": "strong",
                "delta_evt_num": 0,
                "delta_seconds": 0.0,
            }
        )
    return rows


def build_noncore_anchor_row(
    context: dict[str, Any],
    chosen: dict[str, Any],
    scenario_id: str,
) -> dict[str, Any]:
    unit_row = context.get("unit_row") if isinstance(context.get("unit_row"), dict) else {}
    unit_meta = context.get("unit_meta") if isinstance(context.get("unit_meta"), dict) else {}
    record = context.get("record") if isinstance(context.get("record"), dict) else {}
    edge = chosen["edge"]
    return {
        "schema_version": EVENT_TO_BACKBONE_ANCHOR_SCHEMA_VERSION,
        "scenario_id": scenario_id,
        "source_type": "noncore_audit_event",
        "source_event_key": context["record_id"],
        "source_evt_num": context.get("evt_num"),
        "container_id": context.get("container_id"),
        "thread_vtid": _normalize_optional_str(unit_meta.get("thread_vtid")),
        "unit_id": _unit_id_from_row(unit_row),
        "proc_pid": _record_proc_pid(record),
        "fd_name": context.get("fd_name"),
        "source_timestamp": context.get("timestamp"),
        "anchor_backbone_edge_id": edge.get("edge_id"),
        "anchor_backbone_seq": edge.get("seq"),
        "anchor_backbone_relation": edge.get("relation"),
        "anchor_backbone_evt_num": edge.get("evt_num"),
        "anchor_rule": chosen.get("primary_reason"),
        "confidence": chosen.get("attach_strength"),
        "delta_evt_num": chosen.get("evt_delta"),
        "delta_seconds": chosen.get("sec_delta"),
        "source_tier": context.get("source_tier"),
    }


def _context_thread_vtid(context: dict[str, Any]) -> Optional[str]:
    unit_meta = context.get("unit_meta") if isinstance(context.get("unit_meta"), dict) else {}
    return _normalize_optional_str(unit_meta.get("thread_vtid"))


def _context_unit_id(context: dict[str, Any]) -> Optional[str]:
    unit_row = context.get("unit_row") if isinstance(context.get("unit_row"), dict) else {}
    return _unit_id_from_row(unit_row)


def _context_proc_pid(context: dict[str, Any]) -> Optional[str]:
    record = context.get("record") if isinstance(context.get("record"), dict) else {}
    return _record_proc_pid(record)


def rank_attach_candidates(context: dict[str, Any], indices: dict[str, Any]) -> list[dict[str, Any]]:
    candidates = []
    for edge in collect_candidates(context, indices):
        evaluated = evaluate_candidate(context, edge)
        if evaluated is not None:
            candidates.append(evaluated)
    candidates.sort(
        key=lambda item: (
            -item["score"],
            item["evt_delta"] if item["evt_delta"] is not None else 10**18,
            item["sec_delta"] if item["sec_delta"] is not None else 10**18,
            int(item["edge"]["seq"]),
        )
    )
    return candidates


def build_noncore_candidate_rows(
    context: dict[str, Any],
    ranked_candidates: list[dict[str, Any]],
    scenario_id: str,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    selected_edge_id = None
    if ranked_candidates:
        selected_edge_id = ranked_candidates[0]["edge"].get("edge_id")
    for rank, cand in enumerate(ranked_candidates, 1):
        edge = cand["edge"]
        reasons = cand.get("reasons", [])
        rows.append(
            {
                "schema_version": NONCORE_ATTACH_CANDIDATE_SCHEMA_VERSION,
                "scenario_id": scenario_id,
                "source_record_id": context["record_id"],
                "source_evt_num": context.get("evt_num"),
                "source_tier": context.get("source_tier"),
                "container_id": context.get("container_id"),
                "thread_vtid": _context_thread_vtid(context),
                "unit_id": _context_unit_id(context),
                "proc_pid": _context_proc_pid(context),
                "fd_name": context.get("fd_name"),
                "source_timestamp": context.get("timestamp"),
                "candidate_backbone_edge_id": edge.get("edge_id"),
                "candidate_backbone_seq": edge.get("seq"),
                "candidate_backbone_relation": edge.get("relation"),
                "candidate_backbone_evt_num": edge.get("evt_num"),
                "candidate_rule": cand.get("primary_reason"),
                "candidate_score": cand.get("score"),
                "attach_strength": cand.get("attach_strength"),
                "evt_delta": cand.get("evt_delta"),
                "sec_delta": cand.get("sec_delta"),
                "same_evt_num": "same_evt_num" in reasons,
                "same_unit": "same_unit" in reasons,
                "entity_confirmed": cand.get("entity_confirmed"),
                "family_match": cand.get("family_match"),
                "is_selected": edge.get("edge_id") == selected_edge_id,
                "selection_rank": rank,
            }
        )
    return rows


def load_unit_event_index(path: Path) -> dict[int, dict[str, Any]]:
    evt_index: dict[int, dict[str, Any]] = {}
    for row in _iter_jsonl(path):
        evt_num = row.get("evt_num")
        try:
            evt_num_i = int(evt_num)
        except (TypeError, ValueError):
            continue
        evt_index[evt_num_i] = row
    return evt_index


def load_unit_index(path: Path) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for row in _iter_jsonl(path):
        preferred = _select_preferred_unit_key(row)
        if preferred is not None:
            out[preferred] = row
    return out


def classify_unit_inputs(
    unit_event_path: Path,
    unit_index_path: Path,
    evt_to_unit: dict[int, dict[str, Any]],
    unit_meta: dict[str, dict[str, Any]],
) -> tuple[str, str, dict[str, Any]]:
    evt_exists = unit_event_path.exists()
    idx_exists = unit_index_path.exists()
    evt_total = int(len(evt_to_unit))
    evt_nonnull = int(
        sum(1 for row in evt_to_unit.values() if _select_preferred_unit_key(row) is not None)
    )
    idx_total = int(len(unit_meta))

    diagnostics = {
        "unit_event_index_exists": evt_exists,
        "unit_index_exists": idx_exists,
        "unit_event_total": evt_total,
        "unit_event_nonnull": evt_nonnull,
        "unit_index_total": idx_total,
    }

    if not evt_exists and not idx_exists:
        return "unit-unavailable", "unit_event_index_missing+unit_index_missing", diagnostics
    if not evt_exists:
        return "unit-unavailable", "unit_event_index_missing", diagnostics
    if not idx_exists:
        return "unit-unavailable", "unit_index_missing", diagnostics
    if evt_total == 0:
        return "unit-absent", "unit_event_index_empty", diagnostics
    if evt_nonnull == 0:
        return "unit-absent", "unit_event_index_all_null", diagnostics
    if idx_total == 0:
        return "unit-absent", "unit_index_empty_after_filter", diagnostics
    return "unit-ready", "unit_index_and_event_nonnull_present", diagnostics


def load_malicious_non_core(paths: dict[str, Path]) -> tuple[list[dict[str, Any]], Counter[str], Counter[str]]:
    records: list[dict[str, Any]] = []
    tier_totals: Counter[str] = Counter()
    malicious_totals: Counter[str] = Counter()
    for tier, path in paths.items():
        for row in _iter_jsonl(path):
            tier_totals[tier] += 1
            if not bool(_attrs(row).get("malicious", False)):
                continue
            malicious_totals[tier] += 1
            records.append(row)
    return records, tier_totals, malicious_totals


def load_bounded_adjacent_normal_context(
    paths: dict[str, Path],
    edge_sequence: list[dict[str, Any]],
    window: int = DEFAULT_NECESSARY_CONTEXT_WINDOW,
) -> tuple[list[dict[str, Any]], Counter[str]]:
    """
    Narrow adjacent-normal path reused from dataset-builder semantics:
    only non-malicious tiered records in NECESSARY_CONTEXT_EVT_TYPES,
    within evt_num +/- window of the malicious attack zone, same container.
    """
    malicious_evt_to_edge: dict[int, dict[str, Any]] = {}
    for edge in edge_sequence:
        attrs = edge.get("attrs") or {}
        if not attrs.get("malicious"):
            continue
        evt_num = attrs.get("evt_num")
        try:
            malicious_evt_to_edge[int(evt_num)] = edge
        except (TypeError, ValueError):
            continue

    if not malicious_evt_to_edge:
        return [], Counter()

    sorted_malicious_evts = sorted(malicious_evt_to_edge)
    zone_lo = sorted_malicious_evts[0] - window
    zone_hi = sorted_malicious_evts[-1] + window

    spine_evt_to_edge: dict[int, dict[str, Any]] = dict(malicious_evt_to_edge)
    for edge in edge_sequence:
        evt_num = (edge.get("attrs") or {}).get("evt_num")
        try:
            evt_num_i = int(evt_num)
        except (TypeError, ValueError):
            continue
        if zone_lo <= evt_num_i <= zone_hi and evt_num_i not in spine_evt_to_edge:
            spine_evt_to_edge[evt_num_i] = edge

    sorted_evts = sorted(spine_evt_to_edge)
    lo = sorted_evts[0] - window
    hi = sorted_evts[-1] + window

    rows: list[dict[str, Any]] = []
    stats: Counter[str] = Counter()
    for tier_name, path in paths.items():
        if not path.exists():
            continue
        for record in _iter_jsonl(path):
            attrs = _attrs(record)
            if attrs.get("malicious", False):
                continue

            evt_type = str(record.get("event_type") or attrs.get("raw_evt_type") or "").lower()
            if evt_type not in NECESSARY_CONTEXT_EVT_TYPES:
                continue

            evt_num = attrs.get("evt_num")
            try:
                evt_num_i = int(evt_num)
            except (TypeError, ValueError):
                continue
            if evt_num_i < lo or evt_num_i > hi:
                continue

            idx = bisect.bisect_left(sorted_evts, evt_num_i)
            best_evt: Optional[int] = None
            best_delta = window + 1
            for candidate_idx in (idx - 1, idx):
                if 0 <= candidate_idx < len(sorted_evts):
                    delta = abs(sorted_evts[candidate_idx] - evt_num_i)
                    if delta < best_delta:
                        best_delta = delta
                        best_evt = sorted_evts[candidate_idx]

            if best_evt is None or best_delta > window:
                continue

            edge = spine_evt_to_edge[best_evt]
            spine_cid = (edge.get("attrs") or {}).get("container_id")
            rec_cid = attrs.get("container_id") or (record.get("proc") or {}).get("container_id")
            if spine_cid and rec_cid and str(spine_cid) != str(rec_cid):
                continue

            rows.append({
                "context_id": f"nctx_{tier_name}_{record.get('id', evt_num_i)}",
                "source_tier": tier_name,
                "record_mode": record.get("record_mode", "structured_event"),
                "is_malicious": False,
                "is_necessary_context": True,
                "attach_to_backbone_edge_id": edge.get("edge_id"),
                "attach_reason": ["evt_num_proximity"],
                "attach_strength": "proximity",
                "backbone_ref": {
                    "edge_id": edge.get("edge_id"),
                    "seq": edge.get("seq"),
                    "evt_num": best_evt,
                    "relation": edge.get("relation"),
                    "subject": edge.get("subject"),
                    "object": edge.get("object"),
                },
                "context_record": record,
                "link_features": {
                    "evt_num_delta": best_delta,
                    "same_container": True,
                    "necessary_evt_type": evt_type,
                },
            })
            stats[evt_type] += 1
    return rows, stats


def _best_nonmalicious_candidate(
    context: dict[str, Any],
    indices: dict[str, Any],
) -> Optional[dict[str, Any]]:
    """Evaluate the best attach candidate for a non-malicious record.

    Reuses the same scoring used for malicious records so the two
    channels stay methodologically aligned; returns ``None`` when no
    candidate evaluates, exactly like the malicious ranking.
    """
    ranked: list[dict[str, Any]] = []
    for edge in collect_candidates(context, indices):
        evaluated = evaluate_candidate(context, edge)
        if evaluated is not None:
            ranked.append(evaluated)
    if not ranked:
        return None
    ranked.sort(
        key=lambda item: (
            -item["score"],
            item["evt_delta"] if item["evt_delta"] is not None else 10**18,
            item["sec_delta"] if item["sec_delta"] is not None else 10**18,
            int(item["edge"]["seq"]),
        )
    )
    return ranked[0]


def _is_explanatory_accept(chosen: dict[str, Any]) -> bool:
    """Quality gate for the explanatory non-malicious channel.

    Accept only when:
      1. ``attach_strength`` is at least ``medium``; AND
      2. At least one of {same_evt_num, entity_confirmed, or
         (same_unit AND family_match)} is present.

    The second clause filters out "same_unit only" rungs
    (``medium_low``) that the diagnostic showed produce the bulk of
    volume-inflating noise.
    """
    strength = str(chosen.get("attach_strength") or "")
    if strength not in EXPLANATORY_MIN_STRENGTH:
        return False
    reasons = chosen.get("reasons") or []
    if "same_evt_num" in reasons:
        return True
    if chosen.get("entity_confirmed"):
        return True
    if "same_unit" in reasons and chosen.get("family_match"):
        return True
    return False


def load_explanatory_nonmalicious_context(
    paths: dict[str, Path],
    indices: dict[str, Any],
    evt_to_unit: dict[int, dict[str, Any]],
    unit_meta: dict[str, dict[str, Any]],
    per_edge_cap: int = DEFAULT_EXPLANATORY_PER_EDGE_CAP,
    already_seen_record_ids: Optional[frozenset[str]] = None,
) -> tuple[list[dict[str, Any]], Counter[str], dict[str, Counter]]:
    """Load a small, controlled slice of non-malicious non-core records.

    A record is admitted only when:
      * ``attrs.malicious`` is falsy (we never override the malicious
        channel — this is an additive supplement);
      * its ``raw_evt_type`` / ``event_type`` is in
        ``EXPLANATORY_EVT_TYPES`` — a diagnostic-backed semantic
        whitelist, intentionally narrow to exclude metadata / probe
        syscalls that dominate the volume;
      * it reliably attaches to a backbone edge via the same
        ``collect_candidates`` + ``evaluate_candidate`` pipeline the
        malicious channel uses, passing ``_is_explanatory_accept``;
      * it hasn't already been emitted by the adjacent-normal path
        (``already_seen_record_ids``) — we avoid double-counting.

    Per-backbone-edge cap (``per_edge_cap``) gives a hard ceiling on
    audit_context bloat, sorted by score descending then evt_delta
    ascending. Returns the rows plus statistics suitable for the
    ``behavior_context_summary.v0.json`` output.
    """
    rows: list[dict[str, Any]] = []
    stats: Counter[str] = Counter()
    bucket: dict[str, list[dict[str, Any]]] = defaultdict(list)
    per_tier: Counter[str] = Counter()
    per_strength: Counter[str] = Counter()
    per_evt_type: Counter[str] = Counter()
    per_relation: Counter[str] = Counter()

    if per_edge_cap <= 0:
        return rows, stats, {
            "per_tier": per_tier,
            "per_strength": per_strength,
            "per_evt_type": per_evt_type,
            "per_relation": per_relation,
        }

    seen_ids = already_seen_record_ids or frozenset()

    evaluated_count = 0
    accepted_count = 0

    for tier_name, path in paths.items():
        if not path.exists():
            continue
        for record in _iter_jsonl(path):
            attrs = _attrs(record)
            if attrs.get("malicious", False):
                continue
            evt_type = str(
                record.get("event_type") or attrs.get("raw_evt_type") or ""
            ).lower()
            if evt_type not in EXPLANATORY_EVT_TYPES:
                continue

            record_id = str(record.get("id") or "")
            if record_id and record_id in seen_ids:
                continue

            context = make_context_meta(
                record, evt_to_unit, unit_meta, fallback_tier=tier_name
            )
            evaluated_count += 1
            chosen = _best_nonmalicious_candidate(context, indices)
            if chosen is None:
                continue
            if not _is_explanatory_accept(chosen):
                continue

            edge = chosen["edge"]
            edge_id = str(edge.get("edge_id") or "")
            if not edge_id:
                continue

            row = {
                "context_id": f"exctx_{tier_name}_{record_id or record.get('id', '')}",
                "source_tier": tier_name,
                "record_mode": _record_mode(record),
                "is_malicious": False,
                "is_necessary_context": True,
                "explanatory_channel": True,
                "attach_to_backbone_edge_id": edge_id,
                "attach_reason": list(chosen.get("reasons") or []),
                "attach_strength": chosen.get("attach_strength"),
                "backbone_ref": {
                    "edge_id": edge_id,
                    "seq": edge.get("seq"),
                    "evt_num": edge.get("evt_num"),
                    "relation": edge.get("relation"),
                    "subject": edge.get("subject"),
                    "object": edge.get("object"),
                },
                "context_record": record,
                "link_features": {
                    "same_evt_num": "same_evt_num" in (chosen.get("reasons") or []),
                    "same_unit": "same_unit" in (chosen.get("reasons") or []),
                    "family_match": bool(chosen.get("family_match")),
                    "family_non_core": chosen.get("family_non_core", "UNKNOWN"),
                    "family_backbone": chosen.get("family_backbone", "UNKNOWN"),
                    "entity_confirmed": bool(chosen.get("entity_confirmed")),
                    "entity_type": chosen.get("entity_matches") or [],
                    "time_delta_evt": chosen.get("evt_delta"),
                    "time_delta_sec": chosen.get("sec_delta"),
                    "score": chosen.get("score"),
                    "explanatory_evt_type": evt_type,
                },
            }
            accepted_count += 1
            bucket[edge_id].append(row)

    for edge_id, items in bucket.items():
        items.sort(
            key=lambda r: (
                -(r["link_features"].get("score") or 0.0),
                r["link_features"].get("time_delta_evt")
                if r["link_features"].get("time_delta_evt") is not None
                else 10**18,
                r["link_features"].get("time_delta_sec")
                if r["link_features"].get("time_delta_sec") is not None
                else 10**18,
            )
        )
        kept = items[:per_edge_cap]
        for r in kept:
            rows.append(r)
            lf = r["link_features"]
            stats[lf.get("explanatory_evt_type") or "unknown"] += 1
            per_tier[r["source_tier"]] += 1
            per_strength[r.get("attach_strength") or "unknown"] += 1
            per_evt_type[lf.get("explanatory_evt_type") or "unknown"] += 1
            per_relation[str(r["backbone_ref"].get("relation") or "UNKNOWN")] += 1

    diagnostics = {
        "per_tier": per_tier,
        "per_strength": per_strength,
        "per_evt_type": per_evt_type,
        "per_relation": per_relation,
        "evaluated_count": evaluated_count,
        "accepted_before_cap": accepted_count,
        "emitted_after_cap": len(rows),
        "per_edge_cap": per_edge_cap,
    }
    return rows, stats, diagnostics


def build_backbone_indices(
    edges: list[dict[str, Any]],
    evt_to_unit: dict[int, dict[str, Any]],
    unit_meta: dict[str, dict[str, Any]],
) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]]]:
    enriched_edges: list[dict[str, Any]] = []
    indices = {
        "evt_num": defaultdict(list),
        "unit": defaultdict(list),
        "entity": defaultdict(list),
        "thread": defaultdict(list),
        "evt_sorted_evt_nums": [],
        "evt_sorted_edges": [],
    }
    for edge in edges:
        attrs = edge.get("attrs", {})
        if not isinstance(attrs, dict):
            attrs = {}
        evt_num = attrs.get("evt_num")
        try:
            evt_num_i = int(evt_num)
        except (TypeError, ValueError):
            continue
        unit_row = evt_to_unit.get(evt_num_i, {})
        unit_key = _select_preferred_unit_key(unit_row) if unit_row else None
        meta = unit_meta.get(unit_key) if unit_key is not None else None
        enriched = {
            "edge_id": str(edge.get("edge_id")),
            "seq": edge.get("seq"),
            "relation": edge.get("relation"),
            "family": _infer_family_from_relation(edge.get("relation")),
            "subject": edge.get("subject"),
            "object": edge.get("object"),
            "attrs": attrs,
            "evt_num": evt_num_i,
            "timestamp": str(attrs.get("timestamp")) if attrs.get("timestamp") is not None else None,
            "timestamp_dt": _parse_ts(attrs.get("timestamp")),
            "container_id": str(attrs.get("container_id")) if attrs.get("container_id") is not None else None,
            "fd_name": str(attrs.get("fd_name")) if attrs.get("fd_name") is not None else None,
            "unit_key": unit_key,
            "unit_meta": meta,
        }
        enriched_edges.append(enriched)
        indices["evt_num"][evt_num_i].append(enriched)
        if unit_key is not None:
            indices["unit"][unit_key].append(enriched)
        for token in _record_entity_tokens(edge):
            indices["entity"][token].append(enriched)
        if meta is not None:
            container_id = str(meta.get("container_id")) if meta.get("container_id") is not None else None
            thread_vtid = str(meta.get("thread_vtid")) if meta.get("thread_vtid") is not None else None
            if container_id and thread_vtid:
                indices["thread"][(container_id, thread_vtid)].append(enriched)
    for bucket in ("evt_num", "unit", "entity", "thread"):
        for key in indices[bucket]:
            indices[bucket][key].sort(key=lambda e: (abs(e["evt_num"]), int(e["seq"])))
    evt_sorted_edges = sorted(enriched_edges, key=lambda e: (int(e["evt_num"]), int(e["seq"])))
    indices["evt_sorted_edges"] = evt_sorted_edges
    indices["evt_sorted_evt_nums"] = [int(edge["evt_num"]) for edge in evt_sorted_edges]
    return enriched_edges, indices


def make_context_meta(
    record: dict[str, Any],
    evt_to_unit: dict[int, dict[str, Any]],
    unit_meta: dict[str, dict[str, Any]],
    fallback_tier: str,
) -> dict[str, Any]:
    evt_num = _record_evt_num(record)
    unit_row = evt_to_unit.get(evt_num, {}) if evt_num is not None else {}
    unit_key = _select_preferred_unit_key(unit_row) if unit_row else None
    meta = unit_meta.get(unit_key) if unit_key is not None else None
    return {
        "record": record,
        "record_id": str(record.get("id")),
        "source_tier": _record_tier(record, fallback_tier),
        "record_mode": _record_mode(record),
        "evt_num": evt_num,
        "timestamp": _record_timestamp(record),
        "timestamp_dt": _parse_ts(_record_timestamp(record)),
        "raw_evt_type": _record_raw_evt_type(record),
        "family": _infer_family_from_record(record),
        "subject": _record_subject(record),
        "object": _record_object(record),
        "fd_name": _record_fd_name(record),
        "container_id": _record_container(record),
        "unit_key": unit_key,
        "unit_row": unit_row if unit_row else None,
        "unit_meta": meta,
        "entity_tokens": _record_entity_tokens(record),
    }


def _entity_matches(context: dict[str, Any], edge: dict[str, Any]) -> list[str]:
    matches: list[str] = []
    context_object = _normalize_entity_value(context.get("object"))
    edge_object = _normalize_entity_value(edge.get("object"))
    context_fd_name = _normalize_entity_value(context.get("fd_name"))
    edge_fd_name = _normalize_entity_value(edge.get("fd_name"))
    if context_object and context_object == edge_object:
        matches.append("object")
    if context_fd_name and context_fd_name == edge_fd_name:
        matches.append("fd_name")
    return matches


def _time_delta_sec(context: dict[str, Any], edge: dict[str, Any]) -> Optional[float]:
    c_ts = context.get("timestamp_dt")
    e_ts = edge.get("timestamp_dt")
    if c_ts is None or e_ts is None:
        return None
    return abs((c_ts - e_ts).total_seconds())


def collect_candidates(
    context: dict[str, Any],
    indices: dict[str, Any],
) -> list[dict[str, Any]]:
    candidate_edges: dict[str, dict[str, Any]] = {}
    evt_num = context.get("evt_num")
    if evt_num is not None:
        for edge in indices["evt_num"].get(evt_num, []):
            candidate_edges[edge["edge_id"]] = edge
    unit_key = context.get("unit_key")
    if unit_key is not None:
        for edge in indices["unit"].get(unit_key, []):
            candidate_edges.setdefault(edge["edge_id"], edge)
    for token in context.get("entity_tokens", {}):
        for edge in indices["entity"].get(token, []):
            candidate_edges.setdefault(edge["edge_id"], edge)
    unit_meta = context.get("unit_meta")
    if isinstance(unit_meta, dict):
        container_id = unit_meta.get("container_id")
        thread_vtid = unit_meta.get("thread_vtid")
        if container_id is not None and thread_vtid is not None:
            for edge in indices["thread"].get((str(container_id), str(thread_vtid)), []):
                candidate_edges.setdefault(edge["edge_id"], edge)
    return list(candidate_edges.values())


def collect_bounded_candidates(
    context: dict[str, Any],
    indices: dict[str, Any],
    evt_window: int = BOUNDED_ENRICH_EVT_WINDOW,
) -> list[dict[str, Any]]:
    """
    Guard-mode local candidate collection:
    keep attachment scope very narrow around the source event / unit.
    """
    candidate_edges: dict[str, dict[str, Any]] = {}
    evt_num = context.get("evt_num")
    unit_key = context.get("unit_key")
    container_id = context.get("container_id")

    def _accept(edge: dict[str, Any]) -> bool:
        edge_container = edge.get("container_id")
        if container_id and edge_container and str(edge_container) != str(container_id):
            return False
        if evt_num is not None and edge.get("evt_num") is not None:
            if abs(int(edge["evt_num"]) - int(evt_num)) > evt_window:
                return False
        return True

    if evt_num is not None:
        for edge in indices["evt_num"].get(evt_num, []):
            if _accept(edge):
                candidate_edges[edge["edge_id"]] = edge

        evt_values = indices.get("evt_sorted_evt_nums") or []
        evt_edges = indices.get("evt_sorted_edges") or []
        left = bisect.bisect_left(evt_values, int(evt_num) - evt_window)
        right = bisect.bisect_right(evt_values, int(evt_num) + evt_window)
        for edge in evt_edges[left:right]:
            if _accept(edge):
                candidate_edges.setdefault(edge["edge_id"], edge)

    if unit_key is not None:
        for edge in indices["unit"].get(unit_key, []):
            if _accept(edge):
                candidate_edges.setdefault(edge["edge_id"], edge)

    return list(candidate_edges.values())


def evaluate_candidate(context: dict[str, Any], edge: dict[str, Any]) -> Optional[dict[str, Any]]:
    reasons: list[str] = []
    is_same_evt_num = context.get("evt_num") is not None and context["evt_num"] == edge.get("evt_num")
    is_same_unit = context.get("unit_key") is not None and context["unit_key"] == edge.get("unit_key")

    if is_same_evt_num:
        reasons.append("same_evt_num")
    if is_same_unit:
        reasons.append("same_unit")

    entity_matches = _entity_matches(context, edge)
    entity_confirmed = len(entity_matches) > 0
    if entity_confirmed:
        reasons.append("entity_confirmed")

    context_family = context.get("family", "UNKNOWN")
    edge_family = edge.get("family") or _infer_family_from_relation(edge.get("relation"))
    family_match = context_family != "UNKNOWN" and context_family == edge_family
    if family_match and is_same_unit:
        reasons.append("family_consistent")

    evt_delta = None
    if context.get("evt_num") is not None and edge.get("evt_num") is not None:
        evt_delta = abs(int(context["evt_num"]) - int(edge["evt_num"]))
    sec_delta = _time_delta_sec(context, edge)

    same_container = context.get("container_id") and context.get("container_id") == edge.get("container_id")
    same_thread = False
    if isinstance(context.get("unit_meta"), dict) and isinstance(edge.get("unit_meta"), dict):
        c_thread = context["unit_meta"].get("thread_vtid")
        e_thread = edge["unit_meta"].get("thread_vtid")
        same_thread = c_thread is not None and e_thread is not None and str(c_thread) == str(e_thread)

    if not is_same_evt_num and not is_same_unit and not entity_confirmed:
        if same_container and same_thread:
            if evt_delta is not None and evt_delta <= TIME_NEAR_EVT_WINDOW:
                reasons.append("time_near")
            elif sec_delta is not None and sec_delta <= TIME_NEAR_SEC_WINDOW:
                reasons.append("time_near")

    if not reasons:
        return None

    # --- v1 composite score ---
    score = 0.0
    if is_same_evt_num:
        score += SCORE_SAME_EVT_NUM
    elif is_same_unit:
        score += SCORE_SAME_UNIT_BASE
        if family_match:
            score += SCORE_FAMILY_CONSISTENT
        if entity_confirmed:
            score += SCORE_ENTITY_CONFIRMED
        score += _local_distance_bonus(evt_delta)
    elif entity_confirmed:
        score += SCORE_SAME_ENTITY_STANDALONE
    elif "time_near" in reasons:
        score += SCORE_TIME_NEAR

    primary = max(reasons, key=lambda x: RULE_PRIORITY.get(x, 0))
    if is_same_unit:
        if family_match and entity_confirmed:
            strength = "strong"
        elif entity_confirmed:
            strength = "medium_high"
        elif family_match:
            strength = "medium"
        else:
            strength = "medium_low"
    elif is_same_evt_num:
        strength = "strong"
    elif entity_confirmed:
        strength = "medium"
    else:
        strength = "weak"

    return {
        "edge": edge,
        "reasons": sorted(reasons, key=lambda x: (-RULE_PRIORITY.get(x, 0), x)),
        "primary_reason": primary,
        "attach_strength": strength,
        "evt_delta": evt_delta,
        "sec_delta": sec_delta,
        "entity_matches": entity_matches,
        "family_match": family_match,
        "family_non_core": context_family,
        "family_backbone": edge_family,
        "entity_confirmed": entity_confirmed,
        "score": score,
    }


def _try_weak_inferred_net_attach(
    context: dict[str, Any],
    enriched_edges: list[dict[str, Any]],
) -> Optional[dict[str, Any]]:
    """
    Targeted weak_inferred fallback: attach 'getsockname' / 'getpeername'
    unmatched records to a nearby NET_* backbone edge when all reliable
    rules have failed.

    Conditions:
      - raw_evt_type in {"getsockname", "getpeername"}
      - malicious (already filtered upstream)
      - no reliable attach found (caller guarantees this)
      - candidate NET_* edge exists in the same container
      - candidate is temporally within WEAK_INFERRED_NET_SEC_WINDOW seconds
      - at most WEAK_INFERRED_NET_MAX_CANDIDATES candidates exist
        (if multiple candidates appear in the window, remain unmatched to avoid false binding)

    Returns None if conditions are not met, or a minimal candidate dict suitable
    for make_context_edge() / make_unmatched_record().
    """
    raw_evt = context.get("raw_evt_type", "")
    if raw_evt not in ("getsockname", "getpeername"):
        return None

    container_id = context.get("container_id")
    if not container_id:
        return None

    ctx_ts = context.get("timestamp_dt")
    if ctx_ts is None:
        return None

    candidates: list[dict[str, Any]] = []
    for edge in enriched_edges:
        # Only consider NET_* backbone edges
        if edge.get("family") != "NET":
            continue
        # Must be same container
        if edge.get("container_id") != container_id:
            continue
        edge_ts = edge.get("timestamp_dt")
        if edge_ts is None:
            continue
        sec_delta = abs((ctx_ts - edge_ts).total_seconds())
        if sec_delta > WEAK_INFERRED_NET_SEC_WINDOW:
            continue
        candidates.append({
            "edge": edge,
            "sec_delta": sec_delta,
        })

    if not candidates:
        return None

    # Sort by temporal distance (ascending) then by seq as tiebreaker.
    candidates.sort(key=lambda x: (x["sec_delta"], int(x["edge"]["seq"])))

    # Find the minimum time delta among all candidates in window.
    min_delta = candidates[0]["sec_delta"]

    # Count candidates that share the minimum time delta.
    # - If exactly 1: the nearest edge is unique — safe to attach.
    # - If more than 1 share the minimum delta: ambiguous binding;
    #   no reliable key distinguishes them — remain unmatched.
    #   The "seq smallest" tiebreaker is not a semantic justification
    #   and violates "no reliable key, don't force bind".
    candidates_at_min = [c for c in candidates if c["sec_delta"] == min_delta]

    if len(candidates_at_min) == 1:
        chosen = candidates[0]
    else:
        # len >= 2: multiple edges share the exact same nearest timestamp.
        # We cannot reliably choose among them — remain unmatched.
        return None

    edge = chosen["edge"]
    return {
        "edge": edge,
        "reasons": ["weak_inferred_net"],
        "primary_reason": "weak_inferred_net",
        "attach_strength": "weak_inferred",
        "evt_delta": None,
        "sec_delta": chosen["sec_delta"],
        "entity_matches": [],
        "family_match": True,
        "family_non_core": context.get("family", "UNKNOWN"),
        "family_backbone": "NET",
        "entity_confirmed": False,
        "score": float(SCORE_WEAK_INFERRED_NET),
    }


def _inspect_weak_inferred_net_attach(
    context: dict[str, Any],
    enriched_edges: list[dict[str, Any]],
) -> dict[str, Any]:
    raw_evt = context.get("raw_evt_type", "")
    if raw_evt not in ("getsockname", "getpeername"):
        return {"applicable": False, "reason_code": "weak_inferred_net_not_selected", "candidate_count": 0}

    container_id = context.get("container_id")
    ctx_ts = context.get("timestamp_dt")
    if not container_id or ctx_ts is None:
        return {"applicable": True, "reason_code": "weak_inferred_net_no_candidate", "candidate_count": 0}

    candidates: list[dict[str, Any]] = []
    for edge in enriched_edges:
        if edge.get("family") != "NET":
            continue
        if edge.get("container_id") != container_id:
            continue
        edge_ts = edge.get("timestamp_dt")
        if edge_ts is None:
            continue
        sec_delta = abs((ctx_ts - edge_ts).total_seconds())
        if sec_delta > WEAK_INFERRED_NET_SEC_WINDOW:
            continue
        candidates.append({"edge": edge, "sec_delta": sec_delta})

    if not candidates:
        return {"applicable": True, "reason_code": "weak_inferred_net_no_candidate", "candidate_count": 0}

    candidates.sort(key=lambda x: (x["sec_delta"], int(x["edge"]["seq"])))
    min_delta = candidates[0]["sec_delta"]
    candidates_at_min = [c for c in candidates if c["sec_delta"] == min_delta]
    if len(candidates_at_min) == 1:
        chosen = candidates[0]
        summary = _weak_inferred_best_candidate_summary(chosen)
        return {
            "applicable": True,
            "reason_code": None,
            "candidate_count": len(candidates),
            "best_candidate": chosen,
            "best_candidate_summary": summary,
            "chosen": {
                "edge": chosen["edge"],
                "reasons": ["weak_inferred_net"],
                "primary_reason": "weak_inferred_net",
                "attach_strength": "weak_inferred",
                "evt_delta": None,
                "sec_delta": chosen["sec_delta"],
                "entity_matches": [],
                "family_match": True,
                "family_non_core": context.get("family", "UNKNOWN"),
                "family_backbone": "NET",
                "entity_confirmed": False,
                "score": float(SCORE_WEAK_INFERRED_NET),
            },
        }

    return {
        "applicable": True,
        "reason_code": "weak_inferred_net_ambiguous",
        "candidate_count": len(candidates),
        "best_candidate": candidates[0],
        "best_candidate_summary": _weak_inferred_best_candidate_summary(candidates[0]),
    }


def select_best_attach(context: dict[str, Any], indices: dict[str, Any]) -> Optional[dict[str, Any]]:
    candidates = rank_attach_candidates(context, indices)
    if not candidates:
        return None
    return candidates[0]


def make_context_edge(context: dict[str, Any], chosen: dict[str, Any]) -> dict[str, Any]:
    edge = chosen["edge"]
    return {
        "context_id": f"{context['record_id']}::context",
        "source_tier": context["source_tier"],
        "record_mode": context["record_mode"],
        "is_malicious": True,
        "attach_to_backbone_edge_id": edge["edge_id"],
        "attach_reason": chosen["reasons"],
        "attach_strength": chosen["attach_strength"],
        "backbone_ref": {
            "edge_id": edge["edge_id"],
            "seq": edge["seq"],
            "evt_num": edge["evt_num"],
            "relation": edge["relation"],
            "subject": edge["subject"],
            "object": edge["object"],
        },
        "context_record": context["record"],
        "link_features": {
            "same_evt_num": "same_evt_num" in chosen["reasons"],
            "same_unit": "same_unit" in chosen["reasons"],
            "family_match": chosen.get("family_match", False),
            "family_non_core": chosen.get("family_non_core", "UNKNOWN"),
            "family_backbone": chosen.get("family_backbone", "UNKNOWN"),
            "entity_confirmed": chosen.get("entity_confirmed", False),
            "entity_type": chosen["entity_matches"],
            "time_delta_evt": chosen["evt_delta"],
            "time_delta_sec": chosen["sec_delta"],
            "score": chosen["score"],
        },
    }


def make_unmatched_record(context: dict[str, Any], reason_unmatched: str) -> dict[str, Any]:
    return {
        "source_tier": context["source_tier"],
        "evt_num": context["evt_num"],
        "timestamp": context["timestamp"],
        "raw_evt_type": context["raw_evt_type"],
        "reason_unmatched": reason_unmatched,
        "record_mode": context["record_mode"],
        "original_record": context["record"],
    }


def _weak_inferred_best_candidate_summary(candidate: Optional[dict[str, Any]]) -> dict[str, Any]:
    if not isinstance(candidate, dict):
        return {}
    edge = candidate.get("edge") if isinstance(candidate.get("edge"), dict) else {}
    return {
        "best_candidate_backbone_edge_id": edge.get("edge_id"),
        "best_candidate_backbone_seq": edge.get("seq"),
        "best_candidate_backbone_relation": edge.get("relation"),
        "best_candidate_backbone_evt_num": edge.get("evt_num"),
        "best_candidate_rule": "weak_inferred_net",
        "best_candidate_score": float(SCORE_WEAK_INFERRED_NET),
        "best_candidate_attach_strength": "weak_inferred",
        "best_candidate_evt_delta": None,
        "best_candidate_sec_delta": candidate.get("sec_delta"),
        "same_unit_available": False,
        "entity_match_available": False,
        "family_match_available": True,
    }


def _candidate_summary_fields(candidate: Optional[dict[str, Any]]) -> dict[str, Any]:
    if not isinstance(candidate, dict):
        return {}
    edge = candidate.get("edge") if isinstance(candidate.get("edge"), dict) else {}
    reasons = candidate.get("reasons") if isinstance(candidate.get("reasons"), list) else []
    return {
        "best_candidate_backbone_edge_id": edge.get("edge_id"),
        "best_candidate_backbone_seq": edge.get("seq"),
        "best_candidate_backbone_relation": edge.get("relation"),
        "best_candidate_backbone_evt_num": edge.get("evt_num"),
        "best_candidate_rule": candidate.get("primary_reason"),
        "best_candidate_score": candidate.get("score"),
        "best_candidate_attach_strength": candidate.get("attach_strength"),
        "best_candidate_evt_delta": candidate.get("evt_delta"),
        "best_candidate_sec_delta": candidate.get("sec_delta"),
        "same_unit_available": "same_unit" in reasons,
        "entity_match_available": bool(candidate.get("entity_confirmed")),
        "family_match_available": bool(candidate.get("family_match")),
    }


def build_unmatched_reason_trace_row(
    context: dict[str, Any],
    scenario_id: str,
    unmatched_stage: str,
    unmatched_reason_code: str,
    candidate_count: int,
    evaluated_candidate_count: int,
    reliable_candidate_count: int,
    best_candidate: Optional[dict[str, Any]] = None,
    best_candidate_summary: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    row = {
        "schema_version": UNMATCHED_REASON_TRACE_SCHEMA_VERSION,
        "scenario_id": scenario_id,
        "source_record_id": context["record_id"],
        "source_evt_num": context.get("evt_num"),
        "source_tier": context.get("source_tier"),
        "container_id": context.get("container_id"),
        "thread_vtid": _context_thread_vtid(context),
        "unit_id": _context_unit_id(context),
        "proc_pid": _context_proc_pid(context),
        "fd_name": context.get("fd_name"),
        "source_timestamp": context.get("timestamp"),
        "unmatched_stage": unmatched_stage,
        "unmatched_reason_code": unmatched_reason_code,
        "candidate_count": int(candidate_count),
        "evaluated_candidate_count": int(evaluated_candidate_count),
        "reliable_candidate_count": int(reliable_candidate_count),
    }
    if best_candidate_summary:
        row.update(best_candidate_summary)
    elif best_candidate is not None:
        row.update(_candidate_summary_fields(best_candidate))
    return row


def run(
    scenario_dir: Path,
    backbone_path: Path,
    auxiliary_path: Path,
    filtered_path: Path,
    unknown_path: Path,
    tier_manifest_path: Path,
    unit_event_path: Path,
    unit_index_path: Path,
    output_path: Path,
    unmatched_output_path: Path,
    unmatched_reason_trace_output_path: Path,
    summary_output_path: Path,
    candidate_output_path: Path,
    anchor_output_path: Path,
    skip_enrich: bool = False,
    backbone_guard_threshold: int = BACKBONE_GUARD_THRESHOLD,
) -> int:
    emit_observation(
        "[enrich][stage]",
        stage="enrich_behavior_context_v0",
        status="start",
        scenario_dir=scenario_dir,
        input_path=backbone_path,
        output_path=output_path,
        backbone_exists=backbone_path.exists(),
        auxiliary_exists=auxiliary_path.exists(),
        filtered_exists=filtered_path.exists(),
        unknown_exists=unknown_path.exists(),
    )
    if skip_enrich:
        removed_paths = _clear_skipped_enrich_downstream_artifacts(
            scenario_dir=scenario_dir,
            output_path=output_path,
            unmatched_output_path=unmatched_output_path,
        )
        print("[enrich] explicitly skipped via --skip-enrich")
        if removed_paths:
            print(f"[enrich] removed stale downstream files: {len(removed_paths)}")
            for item in removed_paths:
                print(f"[enrich]   removed={item}")
        _write_json(summary_output_path, {
            "schema_version": "behavior_context_summary.v1",
            "status": "skipped",
            "skip_reason": "explicit_skip_enrich",
        })
        emit_observation(
            "[enrich][stage]",
            stage="enrich_behavior_context_v0",
            status="skipped",
            scenario_dir=scenario_dir,
            failing_step="explicit_skip_enrich",
            output_path=summary_output_path,
        )
        return 0

    backbone_edges, backbone_raw = load_backbone(backbone_path)

    edge_count = len(backbone_edges)
    bounded_enrich = backbone_guard_threshold > 0 and edge_count > backbone_guard_threshold
    if bounded_enrich:
        print(
            f"[enrich] backbone_edge_count={edge_count} exceeds "
            f"guard threshold={backbone_guard_threshold}"
        )
        print("[enrich] switching to bounded enrich mode to preserve the closest context layer")
    evt_to_unit: dict[int, dict[str, Any]] = {}
    unit_meta: dict[str, dict[str, Any]] = {}
    if unit_event_path.exists():
        evt_to_unit = load_unit_event_index(unit_event_path)
    if unit_index_path.exists():
        unit_meta = load_unit_index(unit_index_path)

    unit_mode, unit_mode_reason, unit_diagnostics = classify_unit_inputs(
        unit_event_path=unit_event_path,
        unit_index_path=unit_index_path,
        evt_to_unit=evt_to_unit,
        unit_meta=unit_meta,
    )
    if unit_mode != "unit-ready":
        print(
            "[enrich] no-unit mode activated "
            f"unit_mode={unit_mode} reason={unit_mode_reason}"
        )
    enriched_edges, indices = build_backbone_indices(backbone_edges, evt_to_unit, unit_meta)

    malicious_records, tier_totals, malicious_totals = load_malicious_non_core(
        {
            "auxiliary": auxiliary_path,
            "filtered": filtered_path,
            "unknown": unknown_path,
        }
    )
    adjacent_normal_rows, adjacent_normal_stats = load_bounded_adjacent_normal_context(
        {
            "auxiliary": auxiliary_path,
            "filtered": filtered_path,
            "unknown": unknown_path,
        },
        backbone_raw.get("edge_sequence", []),
        window=DEFAULT_NECESSARY_CONTEXT_WINDOW,
    )

    matched_rows: list[dict[str, Any]] = []
    unmatched_rows: list[dict[str, Any]] = []
    unmatched_reason_rows: list[dict[str, Any]] = []
    candidate_rows: list[dict[str, Any]] = []
    anchor_rows: list[dict[str, Any]] = []
    matched_by_primary: Counter[str] = Counter()
    matched_by_strength: Counter[str] = Counter()
    matched_malicious_by_relation: Counter[str] = Counter()
    matched_malicious_by_evt_type: Counter[str] = Counter()
    matched_adjacent_normal_by_relation: Counter[str] = Counter()
    matched_adjacent_normal_by_evt_type: Counter[str] = Counter()
    weak_inferred_net_total = 0
    same_unit_family_consistent = 0
    same_unit_entity_confirmed = 0
    same_unit_family_and_entity = 0
    same_unit_only = 0
    same_unit_total = 0
    same_unit_family_breakdown: Counter[str] = Counter()
    entity_type_breakdown: Counter[str] = Counter()
    tier_manifest = _read_json(tier_manifest_path) if tier_manifest_path.exists() else {}
    scenario_id = _scenario_id_for_outputs(scenario_dir, tier_manifest, backbone_raw)

    anchor_rows.extend(build_backbone_self_anchor_rows(enriched_edges, scenario_id))
    attach_progress = ProgressLogger(
        stage="enrich_behavior_context_v0",
        substep="attach_noncore_records",
        total=len(malicious_records),
        every=5000,
        percent_step=10.0,
        min_interval_s=15.0,
        prefix="[enrich][progress]",
        base_fields={"scenario_dir": scenario_dir},
    )

    for processed, record in enumerate(malicious_records, 1):
        context = make_context_meta(record, evt_to_unit, unit_meta, fallback_tier="unknown")
        if bounded_enrich:
            collected_candidates = collect_bounded_candidates(
                context,
                indices,
                evt_window=BOUNDED_ENRICH_EVT_WINDOW,
            )
        else:
            collected_candidates = collect_candidates(context, indices)
        ranked_candidates = []
        for edge in collected_candidates:
            evaluated = evaluate_candidate(context, edge)
            if evaluated is not None:
                ranked_candidates.append(evaluated)
        ranked_candidates.sort(
            key=lambda item: (
                -item["score"],
                item["evt_delta"] if item["evt_delta"] is not None else 10**18,
                item["sec_delta"] if item["sec_delta"] is not None else 10**18,
                int(item["edge"]["seq"]),
            )
        )
        candidate_rows.extend(build_noncore_candidate_rows(context, ranked_candidates, scenario_id))
        chosen = ranked_candidates[0] if ranked_candidates else None
        is_weak_inferred = False
        if chosen is None:
            weak_info = (
                {"applicable": False, "candidate_count": 0}
                if bounded_enrich
                else _inspect_weak_inferred_net_attach(context, enriched_edges)
            )
            weak = weak_info.get("chosen")
            if weak is not None:
                chosen = weak
                is_weak_inferred = True
            else:
                unmatched_rows.append(make_unmatched_record(context, "no_reliable_attach"))
                unmatched_stage = "reliable_attach"
                unmatched_reason_code = (
                    "candidate_collected_but_none_reliable"
                    if collected_candidates
                    else "no_candidate_collected"
                )
                best_candidate = ranked_candidates[0] if ranked_candidates else None
                best_candidate_summary = None
                if weak_info.get("applicable"):
                    unmatched_stage = "weak_inferred_fallback"
                    unmatched_reason_code = str(weak_info.get("reason_code") or "no_reliable_attach")
                    best_candidate = weak_info.get("best_candidate")
                    best_candidate_summary = weak_info.get("best_candidate_summary")
                unmatched_reason_rows.append(
                    build_unmatched_reason_trace_row(
                        context=context,
                        scenario_id=scenario_id,
                        unmatched_stage=unmatched_stage,
                        unmatched_reason_code=unmatched_reason_code,
                        candidate_count=len(collected_candidates),
                        evaluated_candidate_count=len(ranked_candidates),
                        reliable_candidate_count=len(ranked_candidates),
                        best_candidate=best_candidate,
                        best_candidate_summary=best_candidate_summary,
                    )
                )
                if processed % 5000 == 0:
                    attach_progress.maybe_log(
                        processed,
                        force=True,
                        matched=len(matched_rows),
                        unmatched=len(unmatched_rows),
                        candidates=len(candidate_rows),
                    )
                continue
        matched_rows.append(make_context_edge(context, chosen))
        anchor_rows.append(build_noncore_anchor_row(context, chosen, scenario_id))
        matched_by_primary[chosen["primary_reason"]] += 1
        matched_by_strength[chosen["attach_strength"]] += 1
        matched_malicious_by_relation[str(chosen["edge"].get("relation") or "UNKNOWN")] += 1
        matched_malicious_by_evt_type[str(context.get("raw_evt_type") or "UNKNOWN").lower()] += 1
        if is_weak_inferred:
            weak_inferred_net_total += 1

        reasons = chosen["reasons"]
        has_unit = "same_unit" in reasons
        has_family = "family_consistent" in reasons
        has_entity = "entity_confirmed" in reasons
        if has_unit:
            same_unit_total += 1
            if has_family:
                same_unit_family_consistent += 1
                same_unit_family_breakdown[chosen.get("family_non_core", "UNKNOWN")] += 1
            if has_entity:
                same_unit_entity_confirmed += 1
            if has_family and has_entity:
                same_unit_family_and_entity += 1
            if not has_family and not has_entity:
                same_unit_only += 1
        for et in chosen.get("entity_matches", []):
            entity_type_breakdown[et] += 1

        if processed % 5000 == 0:
            attach_progress.maybe_log(
                processed,
                force=True,
                matched=len(matched_rows),
                unmatched=len(unmatched_rows),
                candidates=len(candidate_rows),
            )

    attach_progress.maybe_log(
        len(malicious_records),
        force=True,
        matched=len(matched_rows),
        unmatched=len(unmatched_rows),
        candidates=len(candidate_rows),
    )

    for row in adjacent_normal_rows:
        backbone_ref = row.get("backbone_ref") or {}
        link_features = row.get("link_features") or {}
        matched_adjacent_normal_by_relation[str(backbone_ref.get("relation") or "UNKNOWN")] += 1
        matched_adjacent_normal_by_evt_type[
            str(link_features.get("necessary_evt_type") or "UNKNOWN").lower()
        ] += 1

    # ── explanatory non-malicious channel (diagnostic-backed, bounded) ──
    # Additive: runs after malicious + adjacent_normal. Does not change
    # the malicious flow. Dedupes by record_id against adjacent_normal
    # to avoid emitting the same record through two channels.
    already_seen_ids: set[str] = set()
    for row in adjacent_normal_rows:
        rec_id = str((row.get("context_record") or {}).get("id") or "")
        if rec_id:
            already_seen_ids.add(rec_id)

    if bounded_enrich:
        explanatory_rows: list[dict[str, Any]] = []
        explanatory_stats: Counter[str] = Counter()
        explanatory_diagnostics: dict[str, Any] = {
            "per_tier": Counter(),
            "per_strength": Counter(),
            "per_evt_type": Counter(),
            "per_relation": Counter(),
            "evaluated_count": 0,
            "accepted_before_cap": 0,
            "emitted_after_cap": 0,
            "per_edge_cap": DEFAULT_EXPLANATORY_PER_EDGE_CAP,
            "bounded_enrich_skipped": True,
        }
    else:
        explanatory_rows, explanatory_stats, explanatory_diagnostics = (
            load_explanatory_nonmalicious_context(
                {
                    "auxiliary": auxiliary_path,
                    "filtered": filtered_path,
                    "unknown": unknown_path,
                },
                indices,
                evt_to_unit,
                unit_meta,
                per_edge_cap=DEFAULT_EXPLANATORY_PER_EDGE_CAP,
                already_seen_record_ids=frozenset(already_seen_ids),
            )
        )

    output_rows = matched_rows + adjacent_normal_rows + explanatory_rows

    _write_jsonl(output_path, output_rows)
    _write_jsonl(unmatched_output_path, unmatched_rows)
    _write_jsonl(unmatched_reason_trace_output_path, unmatched_reason_rows)
    _write_jsonl(candidate_output_path, candidate_rows)
    _write_jsonl(anchor_output_path, anchor_rows)
    summary = {
        "schema_version": "behavior_context_summary.v1",
        "status": "bounded" if bounded_enrich else "completed",
        "scenario_id": scenario_id,
        "inputs": {
            "backbone": str(backbone_path),
            "auxiliary": str(auxiliary_path),
            "filtered": str(filtered_path),
            "unknown": str(unknown_path),
            "unit_event_index": str(unit_event_path),
            "unit_index": str(unit_index_path),
        },
        "counts": {
            "total_non_core_records": int(sum(tier_totals.values())),
            "total_malicious_non_core": len(malicious_records),
            "matched_malicious_non_core": len(matched_rows),
            "unmatched_malicious_non_core": len(unmatched_rows),
            "matched_adjacent_normal_context": len(adjacent_normal_rows),
            "matched_explanatory_nonmalicious_context": len(explanatory_rows),
            "matched_by_same_evt_num": matched_by_primary.get("same_evt_num", 0),
            "matched_by_same_unit_total": same_unit_total,
            "matched_by_same_unit_family_consistent": same_unit_family_consistent,
            "matched_by_same_unit_entity_confirmed": same_unit_entity_confirmed,
            "matched_by_same_unit_family_and_entity": same_unit_family_and_entity,
            "matched_by_same_unit_only": same_unit_only,
            "matched_by_same_entity": matched_by_primary.get("entity_confirmed", 0),
            "matched_by_time_near": matched_by_primary.get("time_near", 0),
            "matched_by_weak_inferred_net": weak_inferred_net_total,
        },
        "same_unit_family_breakdown": dict(sorted(same_unit_family_breakdown.items())),
        "entity_type_breakdown": dict(sorted(entity_type_breakdown.items())),
        "source_tier_breakdown": {
            "total": dict(sorted(tier_totals.items())),
            "malicious": dict(sorted(malicious_totals.items())),
        },
        "unit_mode": unit_mode,
        "unit_mode_reason": unit_mode_reason,
        "unit_diagnostics": unit_diagnostics,
        "attach_strength_breakdown": dict(sorted(matched_by_strength.items())),
        "matched_malicious_by_backbone_relation": dict(sorted(matched_malicious_by_relation.items())),
        "matched_adjacent_normal_by_backbone_relation": dict(sorted(matched_adjacent_normal_by_relation.items())),
        "matched_malicious_by_evt_type": dict(sorted(matched_malicious_by_evt_type.items())),
        "matched_adjacent_normal_by_evt_type": dict(sorted(matched_adjacent_normal_by_evt_type.items())),
        "notes": {
            "backbone_remains_unchanged": True,
            "default_builder_input_remains_core_only": True,
            "malicious_attach_flow_unchanged": True,
            "bounded_adjacent_normal_context_enabled": True,
            "bounded_enrich_mode": bounded_enrich,
            "v1_same_unit_upgrade": "family_consistency + entity_confirmation + local_distance",
            "weak_inferred_net_fallback": "getsockname|getpeername -> NET_* same_container temporal<5s; only fires when reliable attach fails; single-candidate required",
        },
        "bounded_enrich": bool(bounded_enrich),
        "bounded_reason": "backbone_guard_threshold_exceeded" if bounded_enrich else None,
        "bounded_backbone_edge_count": edge_count if bounded_enrich else None,
        "bounded_guard_threshold": backbone_guard_threshold if bounded_enrich else None,
        "necessary_context": {
            "window": DEFAULT_NECESSARY_CONTEXT_WINDOW,
            "allowed_evt_types": sorted(NECESSARY_CONTEXT_EVT_TYPES),
            "loaded_evt_type_counts": dict(sorted(adjacent_normal_stats.items())),
        },
        "explanatory_nonmalicious_context": {
            "allowed_evt_types": sorted(EXPLANATORY_EVT_TYPES),
            "min_attach_strength": sorted(EXPLANATORY_MIN_STRENGTH),
            "per_edge_cap": DEFAULT_EXPLANATORY_PER_EDGE_CAP,
            "evaluated_count": int(explanatory_diagnostics.get("evaluated_count", 0)),
            "accepted_before_cap": int(explanatory_diagnostics.get("accepted_before_cap", 0)),
            "emitted_after_cap": int(explanatory_diagnostics.get("emitted_after_cap", 0)),
            "per_tier": dict(sorted(explanatory_diagnostics.get("per_tier", Counter()).items())),
            "per_strength": dict(sorted(explanatory_diagnostics.get("per_strength", Counter()).items())),
            "per_evt_type": dict(sorted(explanatory_diagnostics.get("per_evt_type", Counter()).items())),
            "per_backbone_relation": dict(sorted(explanatory_diagnostics.get("per_relation", Counter()).items())),
        },
        "output_state": {
            "behavior_context_edges": "written" if output_rows else "empty_not_written",
            "behavior_context_unmatched": "written" if unmatched_rows else "empty_not_written",
            "noncore_attach_candidate_index": "written" if candidate_rows else "empty_not_written",
            "event_to_backbone_anchor_index": "written" if anchor_rows else "empty_not_written",
        },
        "backbone_edge_count": len(backbone_raw.get("edge_sequence", [])),
    }
    _write_json(summary_output_path, summary)

    print(f"[behavior_context_v1] backbone_edges={len(backbone_edges)}")
    print(f"[behavior_context_v1] malicious_non_core={len(malicious_records)} matched={len(matched_rows)} unmatched={len(unmatched_rows)}")
    print(f"[behavior_context_v1] adjacent_normal_context={len(adjacent_normal_rows)} evt_types={dict(sorted(adjacent_normal_stats.items()))}")
    print(
        "[behavior_context_v1] explanatory_nonmalicious_context "
        f"evaluated={explanatory_diagnostics.get('evaluated_count', 0)} "
        f"accepted_before_cap={explanatory_diagnostics.get('accepted_before_cap', 0)} "
        f"emitted={len(explanatory_rows)} "
        f"evt_types={dict(sorted(explanatory_stats.items()))}"
    )
    if bounded_enrich:
        print(
            "[behavior_context_v1] bounded_enrich active "
            f"guard_threshold={backbone_guard_threshold} local_evt_window={BOUNDED_ENRICH_EVT_WINDOW}"
        )
    print(f"[behavior_context_v1] same_unit_total={same_unit_total} family_consistent={same_unit_family_consistent} entity_confirmed={same_unit_entity_confirmed} family_and_entity={same_unit_family_and_entity} unit_only={same_unit_only}")
    edges_note = "written" if output_rows else "skipped_empty_no_file"
    unmatched_note = "written" if unmatched_rows else "skipped_empty_no_file"
    candidates_note = "written" if candidate_rows else "skipped_empty_no_file"
    anchors_note = "written" if anchor_rows else "skipped_empty_no_file"
    print(
        f"[behavior_context_v1] outputs edges={output_path} ({edges_note}) "
        f"unmatched={unmatched_output_path} ({unmatched_note}) "
        f"candidates={candidate_output_path} ({candidates_note}) "
        f"anchors={anchor_output_path} ({anchors_note}) summary={summary_output_path}"
    )
    emit_observation(
        "[enrich][stage]",
        stage="enrich_behavior_context_v0",
        status="bounded" if bounded_enrich else "done",
        scenario_dir=scenario_dir,
        output_path=output_path,
        matched=len(matched_rows),
        adjacent_normal=len(adjacent_normal_rows),
        unmatched=len(unmatched_rows),
        candidate_rows=len(candidate_rows),
        summary_exists=summary_output_path.exists(),
        context_edges_exists=output_path.exists(),
        anchor_index_exists=anchor_output_path.exists(),
        bounded_enrich=bounded_enrich,
    )
    return 0


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Enrich backbone with malicious non-core context v0")
    parser.add_argument("--scenario-dir", type=Path, default=SCENARIO_DIR)
    parser.add_argument("--backbone", type=Path, default=DEFAULT_BACKBONE)
    parser.add_argument("--auxiliary", type=Path, default=DEFAULT_AUXILIARY)
    parser.add_argument("--filtered", type=Path, default=DEFAULT_FILTERED)
    parser.add_argument("--unknown", type=Path, default=DEFAULT_UNKNOWN)
    parser.add_argument("--tier-manifest", type=Path, default=DEFAULT_TIER_MANIFEST)
    parser.add_argument("--unit-event-index", type=Path, default=DEFAULT_UNIT_EVENT_INDEX)
    parser.add_argument("--unit-index", type=Path, default=DEFAULT_UNIT_INDEX)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--unmatched-output", type=Path, default=DEFAULT_UNMATCHED_OUTPUT)
    parser.add_argument("--unmatched-reason-trace-output", type=Path, default=DEFAULT_UNMATCHED_REASON_TRACE_OUTPUT)
    parser.add_argument("--summary-output", type=Path, default=DEFAULT_SUMMARY_OUTPUT)
    parser.add_argument("--candidate-output", type=Path, default=DEFAULT_NONCORE_ATTACH_CANDIDATE_OUTPUT)
    parser.add_argument("--anchor-output", type=Path, default=DEFAULT_EVENT_TO_BACKBONE_ANCHOR_OUTPUT)
    parser.add_argument("--skip-enrich", action="store_true",
                        help="Skip the entire enrich step (mark run as incomplete; not formal success)")
    parser.add_argument("--backbone-guard-threshold", type=int,
                        default=BACKBONE_GUARD_THRESHOLD,
                        help="Auto-skip enrich when backbone exceeds this edge count (0=disable)")
    return parser.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)

    scenario_dir = args.scenario_dir
    backbone = args.backbone
    auxiliary = args.auxiliary
    filtered = args.filtered
    unknown = args.unknown
    tier_manifest = args.tier_manifest
    unit_event_index = args.unit_event_index
    unit_index = args.unit_index
    output = args.output
    unmatched_output = args.unmatched_output
    unmatched_reason_trace_output = args.unmatched_reason_trace_output
    summary_output = args.summary_output
    candidate_output = args.candidate_output
    anchor_output = args.anchor_output

    if scenario_dir != SCENARIO_DIR:
        derived_chain_dir = scenario_dir / CHAIN_DIR_NAME
        derived_index_dir = scenario_dir / "index"
        if backbone == DEFAULT_BACKBONE:
            backbone = derived_chain_dir / "backbone_chain.v1.json"
        if auxiliary == DEFAULT_AUXILIARY:
            auxiliary = derived_chain_dir / "audit_triples.auxiliary.v1.jsonl"
        if filtered == DEFAULT_FILTERED:
            filtered = derived_chain_dir / "audit_triples.filtered.v1.jsonl"
        if unknown == DEFAULT_UNKNOWN:
            unknown = derived_chain_dir / "audit_triples.unknown.v1.jsonl"
        if tier_manifest == DEFAULT_TIER_MANIFEST:
            tier_manifest = derived_chain_dir / "audit_triples_tier_manifest.v1.json"
        if unit_event_index == DEFAULT_UNIT_EVENT_INDEX:
            unit_event_index = derived_index_dir / "unit_event_index.jsonl"
        if unit_index == DEFAULT_UNIT_INDEX:
            unit_index = derived_index_dir / "unit_index.jsonl"
        if output == DEFAULT_OUTPUT:
            output = derived_chain_dir / "behavior_context_edges.v0.jsonl"
        if unmatched_output == DEFAULT_UNMATCHED_OUTPUT:
            unmatched_output = derived_chain_dir / "behavior_context_unmatched.v0.jsonl"
        if unmatched_reason_trace_output == DEFAULT_UNMATCHED_REASON_TRACE_OUTPUT:
            unmatched_reason_trace_output = derived_chain_dir / "unmatched_reason_trace.v0.jsonl"
        if summary_output == DEFAULT_SUMMARY_OUTPUT:
            summary_output = derived_chain_dir / "behavior_context_summary.v0.json"
        if candidate_output == DEFAULT_NONCORE_ATTACH_CANDIDATE_OUTPUT:
            candidate_output = derived_chain_dir / "noncore_attach_candidate_index.v0.jsonl"
        if anchor_output == DEFAULT_EVENT_TO_BACKBONE_ANCHOR_OUTPUT:
            anchor_output = derived_index_dir / "event_to_backbone_anchor_index.v0.jsonl"

    return run(
        scenario_dir=scenario_dir,
        backbone_path=backbone,
        auxiliary_path=auxiliary,
        filtered_path=filtered,
        unknown_path=unknown,
        tier_manifest_path=tier_manifest,
        unit_event_path=unit_event_index,
        unit_index_path=unit_index,
        output_path=output,
        unmatched_output_path=unmatched_output,
        unmatched_reason_trace_output_path=unmatched_reason_trace_output,
        summary_output_path=summary_output,
        candidate_output_path=candidate_output,
        anchor_output_path=anchor_output,
        skip_enrich=args.skip_enrich,
        backbone_guard_threshold=args.backbone_guard_threshold,
    )


if __name__ == "__main__":
    raise SystemExit(main())
