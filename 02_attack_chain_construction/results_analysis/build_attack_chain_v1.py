#!/usr/bin/env python3
"""
Build single-scenario attack subgraph and backbone chain from canonical audit triples.

Input (default):
  <scenario_dir>/chain/audit_triples.core.v1.jsonl

Outputs:
    <scenario_dir>/chain/backbone_chain.v1.json
    <scenario_dir>/chain/attack_subgraph.v1.json (optional; exported only when explicitly enabled)

Scope constraints (v1):
- Single scenario only.
- Core audit triples only (9 relations).
- No step compression.
- No flow/applog reasoning.
"""

from __future__ import annotations

import argparse
from bisect import bisect_left
import gc
import hashlib
import json
import sys
import time
from collections import Counter, deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from console_observability import ProgressLogger, current_memory_mb
from results_analysis.pipeline.utils.common import CHAIN_DIR_NAME


# ---------------------------------------------------------------------------
# Memory-footprint helpers (additive; do not change any output contract).
#
# The backbone stage on heavy scenarios (e.g. metabase/CVE-2021-41277, 10M+
# triples) has been observed to get SIGKILL'd by the OS due to peak RSS
# exceeding available memory. The hottest contributors are, in order:
#   1. ``list[dict]`` of 10M+ triples with many repeating string fields
#      (subject/object/relation/proc_name/... all have tiny cardinality
#      relative to event count).
#   2. ``dict[int, Optional[str]]`` of 10M+ evt_num -> unit_id where almost
#      every value is None.
#   3. ``dict[str, Optional[str]]`` of 10M+ edge_id -> unit_id where almost
#      every value is None.
#   4. The full-graph adjacency/relation index + original triple list kept
#      alive together while the attack subgraph extraction starts.
#
# The helpers below let the loader intern repeated string values so Python
# only keeps one object per unique token, and let the runner emit explicit
# "before/after release" memory lines so we can judge whether a given
# free() call actually reduced RSS.
# ---------------------------------------------------------------------------

# Fields that repeat heavily across millions of triples. Interning these
# collapses per-string object overhead (~50 bytes each) to a single shared
# object per unique value, which is the single largest win available
# without changing the triple dict schema.
_INTERN_ATTR_KEYS: tuple[str, ...] = (
    "raw_evt_type",
    "evt_category",
    "container_id",
    "proc_name",
    "proc_exepath",
    "fd_type",
)

# ``fd_name`` is interned opportunistically: for process/conn rows it is
# usually short and repeated, so interning helps. For very long file paths
# interning is not worth the lookup cost, so we bound the length.
_FD_NAME_INTERN_MAX_LEN = 120


def _intern_triple_strings(triple: dict[str, Any]) -> None:
    """Intern high-repetition string fields on a triple in place.

    Safe to call on any triple shape: fields that are missing or not
    ``str`` are left untouched, so the resulting dict stays schema-compatible.
    The ``id`` field is intentionally skipped because it is essentially
    unique per triple; interning would add dict lookup cost without saving
    memory.
    """

    subject = triple.get("subject")
    if isinstance(subject, str):
        triple["subject"] = sys.intern(subject)

    obj = triple.get("object")
    if isinstance(obj, str):
        triple["object"] = sys.intern(obj)

    relation = triple.get("relation")
    if isinstance(relation, str):
        triple["relation"] = sys.intern(relation)

    attrs = triple.get("attrs")
    if isinstance(attrs, dict):
        for key in _INTERN_ATTR_KEYS:
            val = attrs.get(key)
            if isinstance(val, str):
                attrs[key] = sys.intern(val)
        fd_name = attrs.get("fd_name")
        if isinstance(fd_name, str) and len(fd_name) <= _FD_NAME_INTERN_MAX_LEN:
            attrs["fd_name"] = sys.intern(fd_name)


def _emit_memory_marker(substep: str, **fields: Any) -> None:
    """Emit a single-line memory observation for before/after cleanup.

    Keeps the same ``[build_attack_chain_v1][progress]`` prefix used by the
    existing ProgressLogger so downstream log parsers continue to work.
    """

    payload: list[str] = [
        "stage=build_attack_chain_v1",
        f"substep={substep}",
    ]
    mem = current_memory_mb()
    if mem is not None:
        payload.append(f"memory_mb={mem}")
    for key, value in fields.items():
        if value is None:
            continue
        payload.append(f"{key}={value}")
    print("[build_attack_chain_v1][progress] " + " ".join(payload), flush=True)


def _drop_and_collect(name: str, *objects: Any) -> None:
    """Delete references to ``objects`` and force a GC cycle.

    Logs RSS before and after to make the effect visible in the batch
    pipeline log. ``objects`` themselves are the caller's references;
    the caller must also ``del`` its own local names for the GC to be
    able to free the memory.
    """

    _emit_memory_marker(f"release_before:{name}", released_objects=len(objects))
    for _ in objects:
        # We intentionally do not mutate caller locals here; the caller is
        # responsible for ``del``'ing its own name bindings. We just make
        # sure the tuple of references we captured is dropped before gc.
        pass
    del objects
    gc.collect()
    _emit_memory_marker(f"release_after:{name}")
from results_analysis.backbone_warning_utils import (
    DEFAULT_BROAD_GATE_RELATIONS,
    compute_backbone_edge_metrics,
    evaluate_backbone_broad_warning,
)


SCHEMA_VERSION = "v1"
# Default single-scenario timestamp directory.
# Update this path to the scenario timestamp folder you want to process.
# SCENARIO_DIR = ROOT_DIR / "results" / "your_scenario" / "your_timestamp"
SCENARIO_DIR = ROOT_DIR / "results" / "vulhub" / "gitlist" / "CVE-2018-1000533" / "2026-03-17_02-32-45"

# Paths are derived from SCENARIO_DIR by default.
CHAIN_DIR = SCENARIO_DIR / CHAIN_DIR_NAME
# NOTE: audit_triples.core.v1.jsonl is pre-generated by extract_audit_triples_v1_1.py.
# This script only consumes triples and does not parse raw sysdig logs.
DEFAULT_TRIPLES_PATH = CHAIN_DIR / "audit_triples.core.v1.jsonl"
DEFAULT_SUBGRAPH_PATH = CHAIN_DIR / "attack_subgraph.v1.json"
DEFAULT_BACKBONE_PATH = CHAIN_DIR / "backbone_chain.v1.json"
DEFAULT_REFINEMENT_RESIDUAL_PATH = CHAIN_DIR / "backbone_refinement_residual.v0.jsonl"
DEFAULT_UNIT_BACKBONE_WINDOW_PATH = CHAIN_DIR / "unit_backbone_window_index.v0.jsonl"
DEFAULT_TRAFFIC_BACKBONE_CANDIDATE_PATH = CHAIN_DIR / "traffic_backbone_candidate_index.v0.jsonl"
DEFAULT_RUNTIME_SHELL_BLOCK_SUMMARY_PATH = CHAIN_DIR / "runtime_shell_block_summary.v0.jsonl"
DEFAULT_ENTRY_CANDIDATE_BLOCK_SUMMARY_PATH = CHAIN_DIR / "entry_candidate_block_summary.v0.jsonl"
UNIT_BACKBONE_WINDOW_SCHEMA_VERSION = "unit_backbone_window_index.v0"
TRAFFIC_BACKBONE_CANDIDATE_SCHEMA_VERSION = "traffic_backbone_candidate_index.v0"
REFINEMENT_RESIDUAL_SCHEMA_VERSION = "backbone_refinement_residual.v0"
RUNTIME_SHELL_BLOCK_SCHEMA_VERSION = "runtime_shell_block_summary.v0"
ENTRY_CANDIDATE_BLOCK_SCHEMA_VERSION = "entry_candidate_block_summary.v0"

CORE_RELATIONS = {
    "FILE_OPEN",
    "FILE_READ",
    "FILE_WRITE",
    "PROCESS_EXEC",
    "PROCESS_FORK",
    "NET_CONNECT",
    "NET_ACCEPT",
    "NET_SEND",
    "NET_RECV",
}
EXPAND_RELATION_ALLOWLIST = {
    "PROCESS_EXEC",
    "PROCESS_FORK",
    "NET_CONNECT",
    "NET_ACCEPT",
    "NET_SEND",
    "NET_RECV",
}
BACKBONE_RELATION_ALLOWLIST = set(EXPAND_RELATION_ALLOWLIST)
FILE_RELATIONS = {"FILE_OPEN", "FILE_READ", "FILE_WRITE"}
SEED_EVT_WINDOW_PADDING = 2000
MIN_ATTR_KEYS = ("raw_evt_type", "evt_num", "timestamp", "malicious")
DEFAULT_UNIT_GATE_CONFIG = {
    "allow_cross_unit_relations": set(EXPAND_RELATION_ALLOWLIST),
    "keep_edges_without_unit": False,
}
DEFAULT_MODE_THRESHOLDS = {
    "a_unit_nonnull_ratio": 0.05,
    "a_seed_with_unit_ratio": 0.60,
    "a_seed_unit_count": 3,
}
DEFAULT_FALLBACK_CONFIG = {
    "hop_limit": 2,
    "time_window_sec": 120,
}
FORK_REPEAT_UNKNOWN_CHILD_TOKEN = ":unknown_child:unknown_exe"
BACKBONE_RESULT_RELATIONS = {
    "FILE_WRITE",
    "NET_SEND",
    "NET_RECV",
    "NET_CONNECT",
    "PROCESS_EXEC",
    "FILE_READ",
}
RUNTIME_SHELL_BLOCK_RELATIONS = {
    "PROCESS_FORK",
    "NET_ACCEPT",
    "NET_RECV",
    "NET_SEND",
}
ENTRY_CANDIDATE_RELATION_PRIORITY = (
    "NET_ACCEPT",
    "NET_RECV",
    "NET_SEND",
    "PROCESS_FORK",
)
DEFAULT_RUNTIME_SHELL_BLOCK_MAX_EVT_GAP = 5000
DEFAULT_ENTRY_CANDIDATE_POST_ATTACK_WINDOW_EVT = 2000
DEFAULT_ENTRY_CANDIDATE_SHELL_THICKNESS_MAX = 12
DEFAULT_ENTRY_CANDIDATE_NEAR_FIRST_MALICIOUS_EVT = 2000
DEFAULT_ENTRY_CANDIDATE_HEAVY_SHELL_THICKNESS_MIN = 24
DEFAULT_RUNTIME_SHELL_BLOCK_TRIAL_RELATIONS = (
    "PROCESS_FORK",
    "NET_ACCEPT",
)
DEFAULT_RUNTIME_SHELL_BLOCK_TRIAL_MIN_BLOCK_EDGES = 8
DEFAULT_RUNTIME_SHELL_BLOCK_TRIAL_MIN_OVERLAP_RATIO = 1.0
# Trial-only knobs for the two narrow directed experiments:
#   A) net_accept_subject_anchor_trial
#      - Only affects the trial view. Re-aggregates NET_ACCEPT blocks at
#        subject level (ignoring conn key) so that mongo-express style
#        single-edge NET_ACCEPT chunks can form a cohesive block and
#        become eligible for the representative trial.
#      - The default runtime_shell_block_summary.v0.jsonl sidecar remains
#        subject+conn anchored; the alternate aggregation lives strictly
#        inside derive_backbone_chain -> trial.
#   B) process_fork_hybrid_gate
#      - Only affects the trial view. For PROCESS_FORK target blocks,
#        replace the uniform overlap_ratio gate with a hybrid gate:
#          overlap_ratio >= hybrid_min_overlap_ratio AND
#          overlap_edge_count >= hybrid_min_overlap_edges.
#      - All other target relations keep the existing uniform gate so
#        only pgadmin-style "size OK, ratio just short of 1.0" clusters
#        get an additional path through the trial.
DEFAULT_RUNTIME_SHELL_BLOCK_NET_ACCEPT_SUBJECT_ANCHOR_TRIAL = False
DEFAULT_RUNTIME_SHELL_BLOCK_PROCESS_FORK_HYBRID_GATE = False
DEFAULT_RUNTIME_SHELL_BLOCK_PROCESS_FORK_HYBRID_MIN_OVERLAP_RATIO = 0.45
DEFAULT_RUNTIME_SHELL_BLOCK_PROCESS_FORK_HYBRID_MIN_OVERLAP_EDGES = 6
SEMANTIC_READY_DENSITY_MIN = 0.55
SEMANTIC_READY_SPAN_RATIO_MIN = 0.08
SEMANTIC_READY_PRE_SHELL_MAX = 0.25
SEMANTIC_READY_POST_SHELL_MAX = 0.35

# ---- Backbone narrative-role vocabulary ------------------------------------
# Purely structural roles attached to retained backbone edges so downstream
# consumers can read the chain as a "preparation -> handoff -> execution ->
# result" story without having to cross-reference summary metadata.
#
# The first five roles are injected by Trial D (preparation_shell_trial) via
# its ``kept_anchor_roles`` list. The last three roles are assigned by a
# final pass over ``edge_sequence`` and are independent of any trial.
# No scenario / product / exe name is consulted. All rules are structural.
BACKBONE_NARRATIVE_ROLE_VOCABULARY = (
    # Preparation-side: injected from Trial D kept_anchor_roles when applied.
    "preparation_boundary_start",
    "preparation_boundary_end",
    "startup_handoff_exec",
    "entry_bridge_pre",
    "mid_span_representative",
    # Execution/result-side: assigned from expression_clarity anchors.
    "semantic_entry_anchor",
    "result_anchor",
    "result_tail_context",
)

# Distance (in seq steps) allowed between result_anchor and a candidate
# result_tail_context edge. Kept small on purpose so the role only captures
# an immediate follow-on effect, not arbitrary post-shell noise.
BACKBONE_NARRATIVE_RESULT_TAIL_SEQ_WINDOW = 3


def _read_json(path: Path) -> Any:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _write_json(path: Path, obj: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, ensure_ascii=False, indent=2)
        fh.write("\n")


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")


def _iter_jsonl(path: Path):
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line_no, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except Exception as exc:
                raise ValueError(f"{path} line {line_no}: invalid json: {exc}") from exc


def infer_node_type(entity_id: str) -> Optional[str]:
    """Node type rule is fixed by prefix, per v1 requirement."""
    if entity_id.startswith("proc:"):
        return "process"
    if entity_id.startswith("file:"):
        return "file"
    if entity_id.startswith("conn:"):
        return "conn"
    return None


def _normalize_min_attrs(attrs: dict[str, Any]) -> dict[str, Any]:
    out = dict(attrs)

    evt_num = out.get("evt_num")
    try:
        out["evt_num"] = int(evt_num)
    except (TypeError, ValueError):
        raise ValueError("attrs.evt_num must be an integer")

    timestamp = out.get("timestamp")
    if timestamp is None or str(timestamp).strip() == "":
        raise ValueError("attrs.timestamp is required")
    out["timestamp"] = str(timestamp)

    if "raw_evt_type" not in out or str(out.get("raw_evt_type")).strip() == "":
        raise ValueError("attrs.raw_evt_type is required")
    out["raw_evt_type"] = str(out["raw_evt_type"])

    malicious = out.get("malicious")
    out["malicious"] = bool(malicious) if malicious is not None else False
    return out


def validate_triple_min_schema(triple: dict[str, Any], allowed_relations: set[str]) -> dict[str, Any]:
    for key in ("id", "subject", "relation", "object", "attrs"):
        if key not in triple:
            raise ValueError(f"missing key: {key}")

    if not isinstance(triple["attrs"], dict):
        raise ValueError("attrs must be an object")

    relation = str(triple["relation"])
    if relation not in allowed_relations:
        raise ValueError(f"relation not allowed: {relation}")

    subject = str(triple["subject"])
    obj = str(triple["object"])
    if infer_node_type(subject) is None:
        raise ValueError(f"invalid subject prefix: {subject}")
    if infer_node_type(obj) is None:
        raise ValueError(f"invalid object prefix: {obj}")

    attrs = _normalize_min_attrs(triple["attrs"])

    out = {
        "id": str(triple["id"]),
        "subject": subject,
        "relation": relation,
        "object": obj,
        "attrs": attrs,
    }
    return out


def load_external_anchors(anchors_path: Optional[Path]) -> list[dict[str, str]]:
    if anchors_path is None:
        return []
    if not anchors_path.exists():
        raise FileNotFoundError(f"anchors file not found: {anchors_path}")

    data = _read_json(anchors_path)
    if isinstance(data, dict):
        anchors = data.get("anchors", [])
    elif isinstance(data, list):
        anchors = data
    else:
        raise ValueError("anchors file must be a list or an object with 'anchors'")

    out: list[dict[str, str]] = []
    for item in anchors:
        if not isinstance(item, dict):
            continue
        anchor_type = str(item.get("type", "")).strip()
        value = str(item.get("value", "")).strip()
        if anchor_type not in {"edge", "node"}:
            continue
        if not value:
            continue
        out.append({"type": anchor_type, "value": value})
    return out


def load_audit_triples(
    triples_path: Path,
    allowed_relations: set[str],
    strict: bool = True,
) -> tuple[list[dict[str, Any]], dict[str, int], list[str]]:
    if not triples_path.exists():
        raise FileNotFoundError(f"triples file not found: {triples_path}")

    triples: list[dict[str, Any]] = []
    warnings: list[str] = []
    stats = {
        "total_lines": 0,
        "valid": 0,
        "invalid": 0,
        "skipped": 0,
    }
    progress = ProgressLogger(
        stage="build_attack_chain_v1",
        substep="load_triples",
        every=100000,
        min_interval_s=15.0,
        prefix="[build_attack_chain_v1][progress]",
        base_fields={"input_path": triples_path},
    )

    with open(triples_path, "r", encoding="utf-8", errors="replace") as fh:
        for line_no, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            stats["total_lines"] += 1
            if stats["total_lines"] % 100000 == 0:
                progress.maybe_log(
                    stats["total_lines"],
                    force=True,
                    valid=stats["valid"],
                    invalid=stats["invalid"],
                )

            try:
                raw = json.loads(line)
                triple = validate_triple_min_schema(raw, allowed_relations)
                # Intern repeated string fields in place before we append.
                # For 10M+ triples this collapses subject/object/relation and
                # several attrs values (proc_name, proc_exepath, container_id,
                # fd_type, ...) down to one object per unique token, which is
                # the single biggest peak-memory win on heavy scenarios.
                _intern_triple_strings(triple)
                triples.append(triple)
                stats["valid"] += 1
            except Exception as exc:
                stats["invalid"] += 1
                stats["skipped"] += 1
                msg = f"line {line_no}: {exc}"
                if strict:
                    raise ValueError(msg) from exc
                else:
                    warnings.append(msg)

    # Always sort loaded triples by evt_num for deterministic downstream behavior.
    triples.sort(key=lambda x: int(x["attrs"]["evt_num"]))
    progress.maybe_log(
        stats["total_lines"],
        force=True,
        valid=stats["valid"],
        invalid=stats["invalid"],
    )
    # After parsing + sorting a very large JSONL we likely have a lot of
    # short-lived float/int/str garbage from json.loads; force a cycle now
    # so the peak recorded by the next phase reflects the steady state of
    # ``triples`` rather than transient parsing fragments.
    gc.collect()
    return triples, stats, warnings


def _normalize_optional_unit_id(raw: Any) -> Optional[str]:
    if raw is None:
        return None
    s = str(raw).strip()
    if not s or s.lower() == "null":
        return None
    return s


def _select_preferred_unit_key(row: dict[str, Any]) -> tuple[Optional[str], Optional[str]]:
    unit_key = _normalize_optional_unit_id(row.get("unit_key"))
    if unit_key is not None:
        return unit_key, "from_unit_key"

    unit_id = _normalize_optional_unit_id(row.get("unit_id"))
    if unit_id is not None:
        return unit_id, "fallback_unit_id"

    return None, None


def load_unit_event_index(path: Path) -> tuple[dict[int, Optional[str]], dict[str, Any], list[str]]:
    if not path.exists():
        stats = {
            "total_lines": 0,
            "valid": 0,
            "invalid": 0,
            "with_evt_num": 0,
            "without_evt_num": 0,
            "null_unit": 0,
            "nonnull_unit": 0,
            "duplicate_evt_num": 0,
            "preferred_key_source": {
                "from_unit_key": 0,
                "fallback_unit_id": 0,
            },
            "source_state": "missing_file",
        }
        warnings = [f"unit_event_index missing: {path}; downgrade to no-unit mode"]
        return {}, stats, warnings

    evt_to_unit: dict[int, Optional[str]] = {}
    warnings: list[str] = []
    stats = {
        "total_lines": 0,
        "valid": 0,
        "invalid": 0,
        "with_evt_num": 0,
        "without_evt_num": 0,
        "null_unit": 0,
        "nonnull_unit": 0,
        "duplicate_evt_num": 0,
        "preferred_key_source": {
            "from_unit_key": 0,
            "fallback_unit_id": 0,
        },
    }
    progress = ProgressLogger(
        stage="build_attack_chain_v1",
        substep="load_unit_event_index",
        every=100000,
        min_interval_s=15.0,
        prefix="[build_attack_chain_v1][progress]",
        base_fields={"input_path": path},
    )

    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line_no, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue

            stats["total_lines"] += 1
            if stats["total_lines"] % 100000 == 0:
                progress.maybe_log(
                    stats["total_lines"],
                    force=True,
                    valid=stats["valid"],
                    nonnull=stats["nonnull_unit"],
                )
            try:
                row = json.loads(line)
            except Exception:
                stats["invalid"] += 1
                warnings.append(f"unit_event_index line {line_no}: invalid json")
                continue

            evt_num_raw = row.get("evt_num")
            try:
                evt_num = int(evt_num_raw)
            except (TypeError, ValueError):
                stats["invalid"] += 1
                stats["without_evt_num"] += 1
                warnings.append(f"unit_event_index line {line_no}: missing/invalid evt_num")
                continue

            stats["valid"] += 1
            stats["with_evt_num"] += 1
            preferred_key, preferred_source = _select_preferred_unit_key(row)
            if preferred_key is None:
                stats["null_unit"] += 1
                # Sparse storage: we only keep ``evt_num -> unit`` entries
                # when the mapped unit is non-null. The vast majority of
                # real-world traces (e.g. metabase/CVE-2021-41277 with
                # 10.6M events but only ~600 non-null units) have this
                # asymmetry, and storing None values for every event costs
                # hundreds of MBs of RSS. Downstream ``evt_to_unit.get(k)``
                # still returns ``None`` for unknown/null keys, so the
                # mapping semantics are preserved.
                if evt_num in evt_to_unit:
                    # Can only happen if we already saw a non-null mapping
                    # for this evt_num on a prior line. Under the original
                    # (dense) semantics the last write wins -- a null line
                    # overwrites the prior non-null. Preserve that by
                    # removing the stored entry so downstream ``.get``
                    # returns None just like before.
                    stats["duplicate_evt_num"] += 1
                    del evt_to_unit[evt_num]
                continue

            stats["nonnull_unit"] += 1
            if preferred_source in stats["preferred_key_source"]:
                stats["preferred_key_source"][preferred_source] += 1

            if evt_num in evt_to_unit:
                stats["duplicate_evt_num"] += 1
            # Intern the unit id: in typical traces only a handful of
            # units repeat across many events, so interning collapses
            # them to one shared string object.
            evt_to_unit[evt_num] = sys.intern(preferred_key)

    progress.maybe_log(
        stats["total_lines"],
        force=True,
        valid=stats["valid"],
        nonnull=stats["nonnull_unit"],
    )
    gc.collect()
    return evt_to_unit, stats, warnings


def load_unit_index(path: Path) -> tuple[dict[str, dict[str, Any]], dict[str, Any], list[str]]:
    if not path.exists():
        stats = {
            "total_lines": 0,
            "valid": 0,
            "invalid": 0,
            "missing_unit_id": 0,
            "duplicate_unit_id": 0,
            "duplicate_preferred_key": 0,
            "preferred_key_source": {
                "from_unit_key": 0,
                "fallback_unit_id": 0,
            },
            "source_state": "missing_file",
        }
        warnings = [f"unit_index missing: {path}; downgrade to no-unit mode"]
        return {}, stats, warnings

    unit_meta: dict[str, dict[str, Any]] = {}
    warnings: list[str] = []
    stats = {
        "total_lines": 0,
        "valid": 0,
        "invalid": 0,
        "missing_unit_id": 0,
        "duplicate_unit_id": 0,
        "duplicate_preferred_key": 0,
        "preferred_key_source": {
            "from_unit_key": 0,
            "fallback_unit_id": 0,
        },
    }
    seen_unit_ids: set[str] = set()
    progress = ProgressLogger(
        stage="build_attack_chain_v1",
        substep="load_unit_index",
        every=100000,
        min_interval_s=15.0,
        prefix="[build_attack_chain_v1][progress]",
        base_fields={"input_path": path},
    )

    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line_no, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue

            stats["total_lines"] += 1
            if stats["total_lines"] % 100000 == 0:
                progress.maybe_log(
                    stats["total_lines"],
                    force=True,
                    valid=stats["valid"],
                    duplicates=stats["duplicate_preferred_key"],
                )
            try:
                row = json.loads(line)
            except Exception:
                stats["invalid"] += 1
                warnings.append(f"unit_index line {line_no}: invalid json")
                continue

            unit_id = _normalize_optional_unit_id(row.get("unit_id"))
            preferred_key, preferred_source = _select_preferred_unit_key(row)

            if unit_id is None:
                stats["missing_unit_id"] += 1

            if preferred_key is None:
                stats["invalid"] += 1
                continue

            stats["valid"] += 1
            if unit_id is not None:
                if unit_id in seen_unit_ids:
                    stats["duplicate_unit_id"] += 1
                seen_unit_ids.add(unit_id)

            if preferred_key in unit_meta:
                stats["duplicate_preferred_key"] += 1

            if preferred_source in stats["preferred_key_source"]:
                stats["preferred_key_source"][preferred_source] += 1

            unit_meta[preferred_key] = row

    progress.maybe_log(
        stats["total_lines"],
        force=True,
        valid=stats["valid"],
        duplicates=stats["duplicate_preferred_key"],
    )
    return unit_meta, stats, warnings


def attach_unit_context_to_triples(
    triples: list[dict[str, Any]],
    evt_to_unit: dict[int, Optional[str]],
) -> tuple[dict[str, Optional[str]], dict[str, int]]:
    # ``edge_to_unit`` is accessed downstream exclusively through ``.get``,
    # so a sparse (non-null only) representation is observably equivalent.
    # For scenarios like metabase/CVE-2021-41277 (10.6M edges, <1k
    # non-null units) this cuts the dict's footprint from several hundred
    # MB down to a few KB, which matters because the dict lives side by
    # side with the full triples list and the full-graph adjacency while
    # the attack subgraph is being extracted.
    edge_to_unit: dict[str, Optional[str]] = {}
    stats = {
        "triples_total": 0,
        "with_evt_num": 0,
        "without_evt_num": 0,
        "evt_hit": 0,
        "evt_miss": 0,
        "unit_null": 0,
        "unit_nonnull": 0,
    }
    progress = ProgressLogger(
        stage="build_attack_chain_v1",
        substep="attach_unit_context",
        total=len(triples),
        every=100000,
        percent_step=10.0,
        min_interval_s=15.0,
        prefix="[build_attack_chain_v1][progress]",
    )

    for processed, triple in enumerate(triples, 1):
        stats["triples_total"] += 1
        attrs = triple.get("attrs", {})

        evt_num = attrs.get("evt_num") if isinstance(attrs, dict) else None
        try:
            evt_num_i = int(evt_num)
            stats["with_evt_num"] += 1
        except (TypeError, ValueError):
            stats["without_evt_num"] += 1
            # Non-mapping edge: leave it out of edge_to_unit entirely
            # (``.get`` returns None for missing keys, which matches the
            # original behaviour of storing an explicit None).
            continue

        # ``evt_to_unit`` is now sparse: it only contains entries for
        # events whose preferred unit is non-null. Therefore "hit" here
        # means "an actual unit was attached", and the non-hit bucket
        # merges the ``evt_miss`` + ``unit_null`` counts.
        unit_id = evt_to_unit.get(evt_num_i)
        if unit_id is not None:
            stats["evt_hit"] += 1
            stats["unit_nonnull"] += 1
            edge_id = str(triple.get("id"))
            edge_to_unit[edge_id] = unit_id
        else:
            # Sparse evt_to_unit cannot distinguish "evt_num absent from
            # the original index" from "evt_num mapped to null unit".
            # Both cases produced unit_id=None under the old code path,
            # so the aggregate behaviour for downstream consumers is
            # unchanged; we classify all of them as unit_null here for
            # the observability logs (evt_miss stays at 0). Callers that
            # depend on the total are unaffected because
            # triples_total = with_evt_num + without_evt_num is
            # preserved exactly.
            stats["unit_null"] += 1

        if processed % 100000 == 0:
            progress.maybe_log(
                processed,
                force=True,
                evt_hit=stats["evt_hit"],
                unit_nonnull=stats["unit_nonnull"],
            )

    progress.maybe_log(
        len(triples),
        force=True,
        evt_hit=stats["evt_hit"],
        unit_nonnull=stats["unit_nonnull"],
    )
    return edge_to_unit, stats


def classify_unit_mode(
    unit_event_stats: dict[str, Any],
    unit_index_stats: dict[str, Any],
) -> tuple[str, str]:
    evt_source_state = str(unit_event_stats.get("source_state") or "present")
    idx_source_state = str(unit_index_stats.get("source_state") or "present")

    if evt_source_state == "missing_file" and idx_source_state == "missing_file":
        return "unit-unavailable", "unit_event_index_missing+unit_index_missing"
    if evt_source_state == "missing_file":
        return "unit-unavailable", "unit_event_index_missing"
    if idx_source_state == "missing_file":
        return "unit-unavailable", "unit_index_missing"

    evt_total = int(unit_event_stats.get("total_lines", 0) or 0)
    evt_nonnull = int(unit_event_stats.get("nonnull_unit", 0) or 0)
    idx_valid = int(unit_index_stats.get("valid", 0) or 0)

    if evt_total == 0:
        return "unit-absent", "unit_event_index_empty"
    if evt_nonnull == 0:
        return "unit-absent", "unit_event_index_all_null"
    if idx_valid == 0:
        return "unit-absent", "unit_index_empty_after_filter"

    return "unit-ready", "unit_index_and_event_nonnull_present"


def derive_seed_unit_set(
    seed_edges: list[str],
    edges_by_id: dict[str, dict[str, Any]],
    edge_to_unit: dict[str, Optional[str]],
) -> tuple[set[str], dict[str, int]]:
    seed_units: set[str] = set()
    stats = {
        "seed_edges_total": len(seed_edges),
        "seed_edges_found": 0,
        "seed_edges_missing": 0,
        "seed_edges_with_unit": 0,
        "seed_edges_without_unit": 0,
        "seed_unit_count": 0,
    }

    for edge_id in seed_edges:
        if edge_id not in edges_by_id:
            stats["seed_edges_missing"] += 1
            continue

        stats["seed_edges_found"] += 1
        unit_id = edge_to_unit.get(edge_id)
        if unit_id is None:
            stats["seed_edges_without_unit"] += 1
            continue

        stats["seed_edges_with_unit"] += 1
        seed_units.add(unit_id)

    stats["seed_unit_count"] = len(seed_units)
    return seed_units, stats


def compute_mode_metrics(
    unit_attach_stats: dict[str, int],
    seed_unit_stats: dict[str, int],
) -> dict[str, Any]:
    triples_total = int(unit_attach_stats.get("triples_total", 0) or 0)
    unit_nonnull = int(unit_attach_stats.get("unit_nonnull", 0) or 0)
    seed_edges_total = int(seed_unit_stats.get("seed_edges_total", 0) or 0)
    seed_edges_with_unit = int(seed_unit_stats.get("seed_edges_with_unit", 0) or 0)
    seed_unit_count = int(seed_unit_stats.get("seed_unit_count", 0) or 0)

    unit_nonnull_ratio = (unit_nonnull / triples_total) if triples_total > 0 else 0.0
    seed_with_unit_ratio = (seed_edges_with_unit / seed_edges_total) if seed_edges_total > 0 else 0.0

    return {
        "triples_total": triples_total,
        "unit_nonnull": unit_nonnull,
        "unit_nonnull_ratio": unit_nonnull_ratio,
        "seed_edges_total": seed_edges_total,
        "seed_edges_with_unit": seed_edges_with_unit,
        "seed_with_unit_ratio": seed_with_unit_ratio,
        "seed_unit_count": seed_unit_count,
    }


def select_builder_mode(
    metrics: dict[str, Any],
    thresholds: Optional[dict[str, float]] = None,
) -> tuple[str, str]:
    cfg = dict(DEFAULT_MODE_THRESHOLDS)
    if thresholds:
        cfg.update(thresholds)

    seed_unit_count = int(metrics.get("seed_unit_count", 0) or 0)
    unit_nonnull_ratio = float(metrics.get("unit_nonnull_ratio", 0.0) or 0.0)
    seed_with_unit_ratio = float(metrics.get("seed_with_unit_ratio", 0.0) or 0.0)

    # Fixed decision order:
    # 1) seed_unit_count == 0 -> C
    # 2) meets all A conditions -> A
    # 3) seed_unit_count >= 1 and unit_nonnull_ratio > 0 -> B
    # 4) otherwise -> C
    if seed_unit_count == 0:
        return "C", "seed_unit_count=0"

    is_mode_a = (
        unit_nonnull_ratio >= float(cfg["a_unit_nonnull_ratio"])
        and seed_with_unit_ratio >= float(cfg["a_seed_with_unit_ratio"])
        and seed_unit_count >= int(cfg["a_seed_unit_count"])
    )
    if is_mode_a:
        return "A", "unit coverage high and seed unit support strong"

    if seed_unit_count >= 1 and unit_nonnull_ratio > 0.0:
        return "B", "unit exists but coverage not high enough for pure unit-aware"

    return "C", "fallback by ordered rule"


def should_expand_edge_by_relation(
    edge: dict[str, Any],
    relation_expand_allowlist: set[str],
    file_relations: set[str],
) -> bool:
    relation = str(edge.get("relation"))
    if relation in file_relations:
        return False
    return relation in relation_expand_allowlist


def should_keep_or_expand_by_unit(
    edge: dict[str, Any],
    edge_to_unit: dict[str, Optional[str]],
    seed_unit_set: set[str],
    unit_gate_config: dict[str, Any],
    relation_can_expand: bool,
    is_seed_edge: bool,
    touches_seed_node: bool,
) -> tuple[bool, bool]:
    attrs = edge.get("attrs", {}) if isinstance(edge.get("attrs"), dict) else {}
    relation = str(edge.get("relation"))
    is_malicious = bool(attrs.get("malicious", False))
    unit_id = edge_to_unit.get(str(edge.get("id")))

    if is_seed_edge or is_malicious:
        return True, relation_can_expand and (relation in unit_gate_config["allow_cross_unit_relations"])

    if not seed_unit_set:
        keep = relation_can_expand or touches_seed_node
        return keep, relation_can_expand

    if unit_id is None:
        keep_without_unit = bool(unit_gate_config.get("keep_edges_without_unit", False))
        keep = keep_without_unit and (relation_can_expand or touches_seed_node)
        return keep, False

    if unit_id in seed_unit_set:
        return True, relation_can_expand

    allow_cross = relation in unit_gate_config["allow_cross_unit_relations"]
    keep = allow_cross and relation_can_expand
    expand = allow_cross and relation_can_expand
    return keep, expand


def _node_attrs_from_id_and_edge(node_id: str, edge: dict[str, Any]) -> dict[str, Any]:
    node_type = infer_node_type(node_id)
    attrs = edge.get("attrs", {})

    if node_type == "process":
        out: dict[str, Any] = {}
        if "proc_pid" in attrs:
            out["proc_pid"] = attrs.get("proc_pid")
        if "proc_exepath" in attrs:
            out["proc_exepath"] = attrs.get("proc_exepath")
        if "container_id" in attrs:
            out["container_id"] = attrs.get("container_id")
        if "proc_name" in attrs:
            out["proc_name"] = attrs.get("proc_name")
        return out

    if node_type == "file":
        return {"path": node_id[len("file:") :]}

    if node_type == "conn":
        return {"fd_name": node_id[len("conn:") :]}

    return {}


def build_triple_graph(triples: list[dict[str, Any]]) -> dict[str, Any]:
    nodes_by_id: dict[str, dict[str, Any]] = {}
    edges_by_id: dict[str, dict[str, Any]] = {}
    adjacency: dict[str, set[str]] = {}
    relation_index: dict[str, list[str]] = {r: [] for r in CORE_RELATIONS}
    progress = ProgressLogger(
        stage="build_attack_chain_v1",
        substep="build_graph",
        total=len(triples),
        every=100000,
        percent_step=10.0,
        min_interval_s=15.0,
        prefix="[build_attack_chain_v1][progress]",
    )

    for processed, edge in enumerate(triples, 1):
        edge_id = edge["id"]
        subject = edge["subject"]
        obj = edge["object"]
        relation = edge["relation"]

        edges_by_id[edge_id] = edge
        relation_index.setdefault(relation, []).append(edge_id)

        for node_id in (subject, obj):
            if node_id not in nodes_by_id:
                node_type = infer_node_type(node_id)
                nodes_by_id[node_id] = {
                    "id": node_id,
                    "type": node_type,
                    "attrs": _node_attrs_from_id_and_edge(node_id, edge),
                }
            adjacency.setdefault(node_id, set()).add(edge_id)

        if processed % 100000 == 0:
            progress.maybe_log(
                processed,
                force=True,
                graph_nodes=len(nodes_by_id),
                graph_edges=len(edges_by_id),
            )

    progress.maybe_log(
        len(triples),
        force=True,
        graph_nodes=len(nodes_by_id),
        graph_edges=len(edges_by_id),
    )

    return {
        "nodes_by_id": nodes_by_id,
        "edges_by_id": edges_by_id,
        "adjacency": adjacency,
        "relation_index": relation_index,
    }


def _filter_graph_by_edge_ids(
    graph_obj: dict[str, Any],
    allowed_edge_ids: set[str],
) -> dict[str, Any]:
    edges_by_id_src = graph_obj["edges_by_id"]
    nodes_by_id_src = graph_obj["nodes_by_id"]

    filtered_edges_by_id: dict[str, dict[str, Any]] = {}
    filtered_node_ids: set[str] = set()
    for edge_id in allowed_edge_ids:
        edge = edges_by_id_src.get(edge_id)
        if edge is None:
            continue
        filtered_edges_by_id[edge_id] = edge
        filtered_node_ids.add(str(edge.get("subject")))
        filtered_node_ids.add(str(edge.get("object")))

    filtered_nodes_by_id = {
        node_id: nodes_by_id_src[node_id]
        for node_id in filtered_node_ids
        if node_id in nodes_by_id_src
    }

    filtered_adjacency: dict[str, set[str]] = {}
    for edge_id, edge in filtered_edges_by_id.items():
        s = str(edge.get("subject"))
        o = str(edge.get("object"))
        filtered_adjacency.setdefault(s, set()).add(edge_id)
        filtered_adjacency.setdefault(o, set()).add(edge_id)

    filtered_relation_index: dict[str, list[str]] = {r: [] for r in CORE_RELATIONS}
    for edge_id, edge in filtered_edges_by_id.items():
        relation = str(edge.get("relation"))
        filtered_relation_index.setdefault(relation, []).append(edge_id)

    return {
        "nodes_by_id": filtered_nodes_by_id,
        "edges_by_id": filtered_edges_by_id,
        "adjacency": filtered_adjacency,
        "relation_index": filtered_relation_index,
    }


def seeds_from_malicious_edges(triples: list[dict[str, Any]]) -> tuple[list[str], list[str]]:
    seed_edges: list[str] = []
    seed_nodes: set[str] = set()

    for edge in triples:
        if bool(edge.get("attrs", {}).get("malicious", False)):
            seed_edges.append(edge["id"])
            seed_nodes.add(edge["subject"])
            seed_nodes.add(edge["object"])

    return sorted(set(seed_edges)), sorted(seed_nodes)


def merge_external_anchors(
    graph_obj: dict[str, Any],
    seed_edges: list[str],
    seed_nodes: list[str],
    external_anchors: list[dict[str, str]],
    warnings: list[str],
) -> tuple[list[str], list[str]]:
    edges = set(seed_edges)
    nodes = set(seed_nodes)

    edges_by_id = graph_obj["edges_by_id"]
    nodes_by_id = graph_obj["nodes_by_id"]

    for anchor in external_anchors:
        anchor_type = anchor["type"]
        value = anchor["value"]

        if anchor_type == "edge":
            if value in edges_by_id:
                edges.add(value)
                nodes.add(edges_by_id[value]["subject"])
                nodes.add(edges_by_id[value]["object"])
            else:
                warnings.append(f"external edge anchor not found: {value}")

        elif anchor_type == "node":
            if value in nodes_by_id:
                nodes.add(value)
            else:
                warnings.append(f"external node anchor not found: {value}")

    return sorted(edges), sorted(nodes)


def identify_seeds(
    graph_obj: dict[str, Any],
    triples: list[dict[str, Any]],
    external_anchors: Optional[list[dict[str, str]]] = None,
    seed_mode: str = "auto",
) -> tuple[dict[str, Any], list[str]]:
    warnings: list[str] = []
    anchors = external_anchors or []

    malicious_seed_edges, malicious_seed_nodes = seeds_from_malicious_edges(triples)

    if seed_mode not in {"auto", "malicious_only", "anchor_only"}:
        warnings.append(f"unknown seed_mode={seed_mode}, fallback to auto")
        seed_mode = "auto"

    if seed_mode == "malicious_only":
        seed_edges = malicious_seed_edges
        seed_nodes = malicious_seed_nodes
        mode = "malicious_attr" if (seed_edges or seed_nodes) else "none"
    elif seed_mode == "anchor_only":
        seed_edges, seed_nodes = merge_external_anchors(
            graph_obj, [], [], anchors, warnings
        )
        mode = "external_anchor" if (seed_edges or seed_nodes) else "none"
    else:
        seed_edges, seed_nodes = merge_external_anchors(
            graph_obj, malicious_seed_edges, malicious_seed_nodes, anchors, warnings
        )
        if not seed_edges and not seed_nodes:
            mode = "none"
        elif anchors and (seed_edges or seed_nodes):
            mode = "mixed"
        else:
            mode = "malicious_attr"

    seeds = {
        "mode": mode,
        "seed_edges": seed_edges,
        "seed_nodes": seed_nodes,
    }
    return seeds, warnings


def _sort_edges_by_evt_num(edges: list[dict[str, Any]]) -> list[dict[str, Any]]:
    # In-place sort to avoid transient duplicated edge lists for large backbones.
    edges.sort(key=lambda e: int(e.get("attrs", {}).get("evt_num")))
    return edges


def _build_graph_summary(edges: list[dict[str, Any]], nodes_count: int) -> dict[str, Any]:
    if not edges:
        return {
            "node_count": nodes_count,
            "edge_count": 0,
            "relation_counts": {},
            "min_evt_num": None,
            "max_evt_num": None,
        }

    relation_counts = Counter(e["relation"] for e in edges)
    evt_nums = [int(e["attrs"]["evt_num"]) for e in edges]

    return {
        "node_count": nodes_count,
        "edge_count": len(edges),
        "relation_counts": dict(sorted(relation_counts.items())),
        "min_evt_num": min(evt_nums),
        "max_evt_num": max(evt_nums),
    }


def _build_subgraph_id(edges: list[dict[str, Any]]) -> str:
    if not edges:
        return "sg_empty"
    evt_nums = [int(e["attrs"]["evt_num"]) for e in edges]
    return f"sg_{min(evt_nums)}_{max(evt_nums)}"


def _parse_timestamp_to_epoch_seconds(value: Any) -> Optional[float]:
    if value is None:
        return None
    s = str(value).strip()
    if not s:
        return None

    try:
        if " " in s:
            base, _, frac = s.partition(".")
            frac6 = (frac[:6]).ljust(6, "0") if frac else "000000"
            dt = datetime.strptime(f"{base}.{frac6}", "%Y-%m-%d %H:%M:%S.%f")
            dt = dt.replace(tzinfo=timezone.utc)
            return dt.timestamp()
        return datetime.fromisoformat(s).timestamp()
    except Exception:
        return None


def _build_seed_time_window_seconds(
    edges_by_id: dict[str, dict[str, Any]],
    seed_edges: list[str],
    padding_sec: int,
) -> tuple[Optional[tuple[float, float]], list[str]]:
    warnings: list[str] = []
    seed_ts: list[float] = []
    for edge_id in seed_edges:
        edge = edges_by_id.get(edge_id)
        if edge is None:
            continue
        ts = _parse_timestamp_to_epoch_seconds(edge.get("attrs", {}).get("timestamp"))
        if ts is not None:
            seed_ts.append(ts)

    if not seed_ts:
        warnings.append("seed timestamps unavailable; local fallback time window disabled")
        return None, warnings

    lo = min(seed_ts) - float(max(0, padding_sec))
    hi = max(seed_ts) + float(max(0, padding_sec))
    return (lo, hi), warnings


def _edge_in_time_window_seconds(
    edge: dict[str, Any],
    time_window: Optional[tuple[float, float]],
) -> bool:
    if time_window is None:
        return True
    ts = _parse_timestamp_to_epoch_seconds(edge.get("attrs", {}).get("timestamp"))
    if ts is None:
        return False
    lo, hi = time_window
    return lo <= ts <= hi


def _prune_edges_by_seed_reachability(
    edges: list[dict[str, Any]],
    seed_nodes: list[str],
) -> list[dict[str, Any]]:
    if not edges:
        return []
    seed_node_set = set(seed_nodes)
    if not seed_node_set:
        return []

    node_adj: dict[str, set[str]] = {}
    edge_ids_by_node_pair: dict[tuple[str, str], list[str]] = {}
    edges_by_id: dict[str, dict[str, Any]] = {}

    for edge in edges:
        edge_id = str(edge.get("id"))
        s = str(edge.get("subject"))
        o = str(edge.get("object"))
        edges_by_id[edge_id] = edge
        node_adj.setdefault(s, set()).add(o)
        node_adj.setdefault(o, set()).add(s)
        pair = (s, o)
        edge_ids_by_node_pair.setdefault(pair, []).append(edge_id)

    reachable_nodes: set[str] = set()
    q: deque[str] = deque(n for n in seed_node_set if n in node_adj)
    while q:
        cur = q.popleft()
        if cur in reachable_nodes:
            continue
        reachable_nodes.add(cur)
        for nxt in node_adj.get(cur, set()):
            if nxt not in reachable_nodes:
                q.append(nxt)

    if not reachable_nodes:
        return []

    kept: list[dict[str, Any]] = []
    for edge in edges:
        s = str(edge.get("subject"))
        o = str(edge.get("object"))
        if s in reachable_nodes and o in reachable_nodes:
            kept.append(edge)
    return kept


def _fallback_expand_local_from_seeds(
    graph_obj: dict[str, Any],
    seed_nodes: list[str],
    seed_edges: list[str],
    max_hops: int,
    time_window_sec: int,
    allowed_edge_ids: Optional[set[str]] = None,
    file_context_retain_mode: str = "wide",
    conservative_file_cap_per_node: int = 6,
    b_fallback_net_pair_required: bool = False,
    b_fallback_net_pair_window_evt: int = 15,
) -> tuple[set[str], set[str], list[str], int]:
    warnings: list[str] = []
    adjacency = graph_obj["adjacency"]
    edges_by_id = graph_obj["edges_by_id"]
    seed_node_set = set(seed_nodes)
    seed_edge_set = set(seed_edges)

    time_window, tw_warnings = _build_seed_time_window_seconds(
        edges_by_id=edges_by_id,
        seed_edges=seed_edges,
        padding_sec=time_window_sec,
    )
    warnings.extend(tw_warnings)

    visited_nodes: set[str] = set(seed_nodes)
    collected_edges: set[str] = set(seed_edges)
    node_depth: dict[str, int] = {str(n): 0 for n in seed_nodes}
    expanded_runtime_nodes: set[str] = set()
    q: deque[tuple[str, int]] = deque((n, 0) for n in seed_nodes)

    while q:
        node_id, depth = q.popleft()
        if depth >= max_hops:
            continue

        for edge_id in adjacency.get(node_id, set()):
            if allowed_edge_ids is not None and edge_id not in allowed_edge_ids:
                continue
            edge = edges_by_id.get(edge_id)
            if edge is None:
                continue

            relation_can_expand = should_expand_edge_by_relation(
                edge=edge,
                relation_expand_allowlist=EXPAND_RELATION_ALLOWLIST,
                file_relations=FILE_RELATIONS,
            )
            if not relation_can_expand:
                # FILE_* can be retained as context later, but never drive expansion.
                continue

            if not _edge_in_time_window_seconds(edge, time_window):
                continue

            collected_edges.add(edge_id)
            for nxt in (edge.get("subject"), edge.get("object")):
                if nxt is None:
                    continue
                if nxt not in visited_nodes:
                    visited_nodes.add(nxt)
                    nxt_str = str(nxt)
                    node_depth[nxt_str] = depth + 1
                    if nxt_str.startswith("proc:") or nxt_str.startswith("conn:"):
                        expanded_runtime_nodes.add(nxt_str)
                    q.append((nxt_str, depth + 1))

    # Context retain pass for FILE_*: keep but do not expand.
    if str(file_context_retain_mode).lower() == "conservative":
        # Conservative mode (used by B fallback only):
        # 1) always keep FILE_* edges that directly touch seed nodes;
        # 2) keep a small capped number of FILE_* edges around near runtime nodes.
        anchor_nodes: set[str] = set(seed_node_set)
        for node_id in expanded_runtime_nodes:
            depth = int(node_depth.get(node_id, max_hops + 1))
            if depth <= 1:
                anchor_nodes.add(node_id)

        per_node_added: dict[str, int] = {}
        cap = max(0, int(conservative_file_cap_per_node))
        for node_id in sorted(anchor_nodes):
            for edge_id in adjacency.get(node_id, set()):
                if allowed_edge_ids is not None and edge_id not in allowed_edge_ids:
                    continue
                edge = edges_by_id.get(edge_id)
                if edge is None:
                    continue
                relation = str(edge.get("relation"))
                if relation not in FILE_RELATIONS and edge_id not in seed_edge_set:
                    continue
                if not _edge_in_time_window_seconds(edge, time_window):
                    continue
                if edge_id in seed_edge_set:
                    collected_edges.add(edge_id)
                    continue
                if node_id in seed_node_set:
                    collected_edges.add(edge_id)
                    continue
                cur = per_node_added.get(node_id, 0)
                if cur >= cap:
                    continue
                collected_edges.add(edge_id)
                per_node_added[node_id] = cur + 1
    else:
        for node_id in list(visited_nodes | seed_node_set):
            for edge_id in adjacency.get(node_id, set()):
                if allowed_edge_ids is not None and edge_id not in allowed_edge_ids:
                    continue
                edge = edges_by_id.get(edge_id)
                if edge is None:
                    continue
                relation = str(edge.get("relation"))
                if relation not in FILE_RELATIONS and edge_id not in seed_edge_set:
                    continue
                if not _edge_in_time_window_seconds(edge, time_window):
                    continue
                collected_edges.add(edge_id)

    if b_fallback_net_pair_required:
        pair_window_evt = max(0, int(b_fallback_net_pair_window_evt))
        net_relations = {"NET_RECV", "NET_SEND"}
        paired_evt_index: dict[str, dict[str, list[int]]] = {}

        for edge_id in collected_edges:
            edge = edges_by_id.get(edge_id)
            if edge is None:
                continue
            relation = str(edge.get("relation"))
            if relation not in net_relations:
                continue
            attrs = edge.get("attrs", {}) if isinstance(edge.get("attrs"), dict) else {}
            fd_name = str(attrs.get("fd_name", "")).strip()
            if not fd_name:
                continue
            try:
                evt_num = int(attrs.get("evt_num"))
            except (TypeError, ValueError):
                continue
            rel_map = paired_evt_index.setdefault(fd_name, {"NET_RECV": [], "NET_SEND": []})
            rel_map[relation].append(evt_num)

        for rel_map in paired_evt_index.values():
            rel_map["NET_RECV"].sort()
            rel_map["NET_SEND"].sort()

        def _has_pair(fd_name: str, relation: str, evt_num: int) -> bool:
            other_relation = "NET_SEND" if relation == "NET_RECV" else "NET_RECV"
            rel_map = paired_evt_index.get(fd_name)
            if not rel_map:
                return False
            candidates = rel_map.get(other_relation, [])
            if not candidates:
                return False
            lo = evt_num - pair_window_evt
            hi = evt_num + pair_window_evt
            idx = bisect_left(candidates, lo)
            return idx < len(candidates) and candidates[idx] <= hi

        filtered_edges: set[str] = set()
        for edge_id in collected_edges:
            edge = edges_by_id.get(edge_id)
            if edge is None:
                continue

            relation = str(edge.get("relation"))
            if relation not in net_relations:
                filtered_edges.add(edge_id)
                continue

            attrs = edge.get("attrs", {}) if isinstance(edge.get("attrs"), dict) else {}

            # Highest-priority safety guard: malicious network edges are always kept.
            if bool(attrs.get("malicious", False)):
                filtered_edges.add(edge_id)
                continue

            if edge_id in seed_edge_set:
                filtered_edges.add(edge_id)
                continue

            fd_name = str(attrs.get("fd_name", "")).strip()
            if not fd_name:
                filtered_edges.add(edge_id)
                continue

            try:
                evt_num = int(attrs.get("evt_num"))
            except (TypeError, ValueError):
                filtered_edges.add(edge_id)
                continue

            if _has_pair(fd_name=fd_name, relation=relation, evt_num=evt_num):
                filtered_edges.add(edge_id)

        collected_edges = filtered_edges

    for edge_id in list(collected_edges):
        edge = edges_by_id.get(edge_id)
        if edge is None:
            continue
        visited_nodes.add(str(edge.get("subject")))
        visited_nodes.add(str(edge.get("object")))

    fallback_edges_kept = len(collected_edges)
    return visited_nodes, collected_edges, warnings, fallback_edges_kept


def bfs_expand_from_seeds(
    graph_obj: dict[str, Any],
    seed_nodes: list[str],
    seed_edges: list[str],
    max_hops: int,
    expand_relation_allowlist: set[str],
    edge_to_unit: dict[str, Optional[str]],
    seed_unit_set: set[str],
    unit_gate_config: dict[str, Any],
) -> tuple[set[str], set[str]]:
    adjacency = graph_obj["adjacency"]
    edges_by_id = graph_obj["edges_by_id"]
    seed_edge_set = set(seed_edges)
    seed_node_set = set(seed_nodes)

    visited_nodes: set[str] = set(seed_nodes)
    collected_edges: set[str] = set(seed_edges)

    q: deque[tuple[str, int]] = deque((n, 0) for n in seed_nodes)
    while q:
        node_id, depth = q.popleft()
        if depth >= max_hops:
            continue

        for edge_id in adjacency.get(node_id, set()):
            edge = edges_by_id[edge_id]

            # Always collect adjacent edges into subgraph candidates.
            collected_edges.add(edge_id)

            relation_can_expand = should_expand_edge_by_relation(
                edge=edge,
                relation_expand_allowlist=expand_relation_allowlist,
                file_relations=FILE_RELATIONS,
            )
            if not relation_can_expand:
                continue

            keep_by_unit, expand_by_unit = should_keep_or_expand_by_unit(
                edge=edge,
                edge_to_unit=edge_to_unit,
                seed_unit_set=seed_unit_set,
                unit_gate_config=unit_gate_config,
                relation_can_expand=relation_can_expand,
                is_seed_edge=(edge_id in seed_edge_set),
                touches_seed_node=(edge.get("subject") in seed_node_set or edge.get("object") in seed_node_set),
            )
            if not (keep_by_unit and expand_by_unit):
                continue

            for nxt in (edge["subject"], edge["object"]):
                if nxt not in visited_nodes:
                    visited_nodes.add(nxt)
                    q.append((nxt, depth + 1))

    # Ensure nodes referenced by collected edges are included.
    for edge_id in list(collected_edges):
        edge = edges_by_id.get(edge_id)
        if edge is None:
            continue
        visited_nodes.add(edge["subject"])
        visited_nodes.add(edge["object"])

    return visited_nodes, collected_edges


def _build_seed_context(
    edges_by_id: dict[str, dict[str, Any]],
    seed_nodes: list[str],
    seed_edges: list[str],
) -> tuple[set[str], set[str], Optional[tuple[int, int]], list[str]]:
    warnings: list[str] = []
    seed_node_set = set(seed_nodes)
    seed_process_set = {nid for nid in seed_node_set if str(nid).startswith("proc:")}

    seed_evt_nums: list[int] = []
    for edge_id in seed_edges:
        edge = edges_by_id.get(edge_id)
        if edge is None:
            continue
        try:
            seed_evt_nums.append(int(edge.get("attrs", {}).get("evt_num")))
        except (TypeError, ValueError):
            continue

    seed_evt_window: Optional[tuple[int, int]] = None
    if seed_evt_nums:
        lo = min(seed_evt_nums) - SEED_EVT_WINDOW_PADDING
        hi = max(seed_evt_nums) + SEED_EVT_WINDOW_PADDING
        seed_evt_window = (lo, hi)
    else:
        warnings.append("seed edges missing evt_num; seed_evt_window disabled")

    return seed_node_set, seed_process_set, seed_evt_window, warnings


def _unit_like_keep_edge(
    edge: dict[str, Any],
    seed_node_set: set[str],
    seed_process_set: set[str],
    seed_evt_window: Optional[tuple[int, int]],
) -> bool:
    subject = edge.get("subject")
    obj = edge.get("object")
    relation = edge.get("relation")
    attrs = edge.get("attrs", {})

    touches_seed_process = (subject in seed_process_set) or (obj in seed_process_set)
    touches_seed_node = (subject in seed_node_set) or (obj in seed_node_set)

    evt_num: Optional[int]
    try:
        evt_num = int(attrs.get("evt_num"))
    except (TypeError, ValueError):
        evt_num = None

    in_seed_window_hi_value = False
    if seed_evt_window is not None and evt_num is not None:
        lo, hi = seed_evt_window
        in_seed_window_hi_value = (lo <= evt_num <= hi) and (relation in EXPAND_RELATION_ALLOWLIST)

    keep = touches_seed_process or touches_seed_node or in_seed_window_hi_value

    # FILE_* strict gate: keep only malicious or directly connected to seed processes.
    if relation in FILE_RELATIONS:
        is_malicious = bool(attrs.get("malicious", False))
        if not is_malicious and not touches_seed_process:
            return False

    return keep


def extract_attack_subgraph_mode_a(
    graph_obj: dict[str, Any],
    seeds: dict[str, Any],
    edge_to_unit: dict[str, Optional[str]],
    seed_unit_set: set[str],
    unit_meta: Optional[dict[str, dict[str, Any]]] = None,
    max_hops: int = 1,
    scenario_id: Optional[str] = None,
) -> tuple[dict[str, Any], list[str]]:
    warnings: list[str] = []
    edges_by_id = graph_obj["edges_by_id"]
    nodes_by_id = graph_obj["nodes_by_id"]

    seed_nodes: list[str] = list(seeds.get("seed_nodes", []))
    seed_edges: list[str] = list(seeds.get("seed_edges", []))
    seed_edge_set = set(seed_edges)
    seed_node_set = set(seed_nodes)
    unit_gate_config = dict(DEFAULT_UNIT_GATE_CONFIG)

    if not seed_nodes and not seed_edges:
        subgraph = {
            "schema_version": SCHEMA_VERSION,
            "subgraph_id": "sg_empty",
            "seeds": seeds,
            "graph_summary": {
                "node_count": 0,
                "edge_count": 0,
                "relation_counts": {},
                "min_evt_num": None,
                "max_evt_num": None,
            },
            "nodes": [],
            "edges": [],
        }
        if scenario_id:
            subgraph["scenario_id"] = scenario_id
        warnings.append("no seeds detected; output empty attack_subgraph")
        return subgraph, warnings

    visited_nodes, collected_edge_ids = bfs_expand_from_seeds(
        graph_obj=graph_obj,
        seed_nodes=seed_nodes,
        seed_edges=seed_edges,
        max_hops=max_hops,
        expand_relation_allowlist=EXPAND_RELATION_ALLOWLIST,
        edge_to_unit=edge_to_unit,
        seed_unit_set=seed_unit_set,
        unit_gate_config=unit_gate_config,
    )

    seed_node_set_ctx, seed_process_set, seed_evt_window, ctx_warnings = _build_seed_context(
        edges_by_id=edges_by_id,
        seed_nodes=seed_nodes,
        seed_edges=seed_edges,
    )
    warnings.extend(ctx_warnings)

    edges: list[dict[str, Any]] = []
    filtered_out = 0
    unit_filtered_out = 0
    relation_expand_blocked = 0
    cross_unit_kept = 0
    cross_unit_kept_malicious = 0
    cross_unit_kept_nonmalicious = 0
    edges_with_unit = 0
    edges_without_unit = 0
    cross_unit_kept_relation_counts: Counter[str] = Counter()
    unit_filtered_relation_counts: Counter[str] = Counter()
    unit_filtered_malicious_relation_counts: Counter[str] = Counter()
    for edge_id in collected_edge_ids:
        edge = edges_by_id.get(edge_id)
        if edge is None:
            warnings.append(f"edge missing from graph index: {edge_id}")
            continue

        relation_can_expand = should_expand_edge_by_relation(
            edge=edge,
            relation_expand_allowlist=EXPAND_RELATION_ALLOWLIST,
            file_relations=FILE_RELATIONS,
        )
        keep_by_relation_context = _unit_like_keep_edge(
            edge=edge,
            seed_node_set=seed_node_set_ctx,
            seed_process_set=seed_process_set,
            seed_evt_window=seed_evt_window,
        )

        keep_by_unit, _ = should_keep_or_expand_by_unit(
            edge=edge,
            edge_to_unit=edge_to_unit,
            seed_unit_set=seed_unit_set,
            unit_gate_config=unit_gate_config,
            relation_can_expand=relation_can_expand,
            is_seed_edge=(edge_id in seed_edge_set),
            touches_seed_node=(edge.get("subject") in seed_node_set or edge.get("object") in seed_node_set),
        )

        unit_id = edge_to_unit.get(edge_id)
        if unit_id is None:
            edges_without_unit += 1
        else:
            edges_with_unit += 1

        relation = str(edge.get("relation"))
        attrs = edge.get("attrs", {}) if isinstance(edge.get("attrs"), dict) else {}
        is_malicious = bool(attrs.get("malicious", False))

        if keep_by_relation_context and keep_by_unit:
            edges.append(edge)

            # Cross-unit kept stats only count edges that are actually kept in final subgraph.
            if unit_id is not None and seed_unit_set and unit_id not in seed_unit_set:
                cross_unit_kept += 1
                cross_unit_kept_relation_counts[relation] += 1
                if is_malicious:
                    cross_unit_kept_malicious += 1
                else:
                    cross_unit_kept_nonmalicious += 1
        else:
            filtered_out += 1
            if keep_by_relation_context and not keep_by_unit:
                unit_filtered_out += 1
                unit_filtered_relation_counts[relation] += 1
                if is_malicious:
                    unit_filtered_malicious_relation_counts[relation] += 1
            if not relation_can_expand and edge.get("relation") not in FILE_RELATIONS:
                relation_expand_blocked += 1

    if filtered_out > 0:
        warnings.append(f"unit-like pruning filtered out {filtered_out} candidate edges")

    try:
        edges = _sort_edges_by_evt_num(edges)
    except Exception as exc:
        warnings.append(f"failed to sort subgraph edges by evt_num: {exc}")
        edges = []
        visited_nodes = set()

    # Rebuild node set from filtered edges and seed nodes for consistent output.
    final_node_ids: set[str] = set(seed_nodes)
    for edge in edges:
        final_node_ids.add(edge["subject"])
        final_node_ids.add(edge["object"])

    nodes = [nodes_by_id[nid] for nid in sorted(final_node_ids) if nid in nodes_by_id]

    kept_edge_ids = {str(e.get("id")) for e in edges}
    seed_edge_keep_total = sum(1 for edge_id in seed_edge_set if edge_id in kept_edge_ids)
    seed_edge_drop_total = len(seed_edge_set) - seed_edge_keep_total
    seed_edge_keep_ratio = (seed_edge_keep_total / len(seed_edge_set)) if seed_edge_set else 0.0

    subgraph = {
        "schema_version": SCHEMA_VERSION,
        "subgraph_id": _build_subgraph_id(edges),
        "seeds": {
            "mode": seeds.get("mode", "malicious_attr"),
            "seed_edges": sorted(set(seed_edges)),
            "seed_nodes": sorted(set(seed_nodes)),
        },
        "graph_summary": {
            **_build_graph_summary(edges, len(nodes)),
            "seed_unit_count": len(seed_unit_set),
            "edges_with_unit": edges_with_unit,
            "edges_without_unit": edges_without_unit,
            "unit_filtered_out": unit_filtered_out,
            "relation_expand_blocked": relation_expand_blocked,
            "cross_unit_kept": cross_unit_kept,
            "cross_unit_kept_relation_counts": dict(sorted(cross_unit_kept_relation_counts.items())),
            "cross_unit_kept_malicious": cross_unit_kept_malicious,
            "cross_unit_kept_nonmalicious": cross_unit_kept_nonmalicious,
            "unit_filtered_relation_counts": dict(sorted(unit_filtered_relation_counts.items())),
            "unit_filtered_malicious_relation_counts": dict(sorted(unit_filtered_malicious_relation_counts.items())),
            "seed_edge_keep_total": seed_edge_keep_total,
            "seed_edge_drop_total": seed_edge_drop_total,
            "seed_edge_keep_ratio": round(seed_edge_keep_ratio, 6),
            "unit_index_count": len(unit_meta or {}),
        },
        "nodes": nodes,
        "edges": edges,
    }
    if scenario_id:
        subgraph["scenario_id"] = scenario_id

    return subgraph, warnings


def extract_attack_subgraph_mode_c(
    graph_obj: dict[str, Any],
    seeds: dict[str, Any],
    max_hops: int,
    scenario_id: Optional[str] = None,
    fallback_time_window_sec: int = 120,
    allowed_edge_ids: Optional[set[str]] = None,
    file_context_retain_mode: str = "wide",
    conservative_file_cap_per_node: int = 6,
    b_fallback_net_pair_required: bool = False,
    b_fallback_net_pair_window_evt: int = 15,
) -> tuple[dict[str, Any], list[str], int]:
    warnings: list[str] = []
    edges_by_id = graph_obj["edges_by_id"]
    nodes_by_id = graph_obj["nodes_by_id"]

    seed_nodes: list[str] = list(seeds.get("seed_nodes", []))
    seed_edges: list[str] = list(seeds.get("seed_edges", []))

    if not seed_nodes and not seed_edges:
        subgraph = {
            "schema_version": SCHEMA_VERSION,
            "subgraph_id": "sg_empty",
            "seeds": seeds,
            "graph_summary": {
                "node_count": 0,
                "edge_count": 0,
                "relation_counts": {},
                "min_evt_num": None,
                "max_evt_num": None,
            },
            "nodes": [],
            "edges": [],
        }
        if scenario_id:
            subgraph["scenario_id"] = scenario_id
        warnings.append("no seeds detected; output empty attack_subgraph")
        return subgraph, warnings, 0

    visited_nodes, collected_edge_ids, fb_warnings, fallback_edges_kept = _fallback_expand_local_from_seeds(
        graph_obj=graph_obj,
        seed_nodes=seed_nodes,
        seed_edges=seed_edges,
        max_hops=max_hops,
        time_window_sec=fallback_time_window_sec,
        allowed_edge_ids=allowed_edge_ids,
        file_context_retain_mode=file_context_retain_mode,
        conservative_file_cap_per_node=conservative_file_cap_per_node,
        b_fallback_net_pair_required=b_fallback_net_pair_required,
        b_fallback_net_pair_window_evt=b_fallback_net_pair_window_evt,
    )
    warnings.extend(fb_warnings)

    candidate_edges: list[dict[str, Any]] = []
    for edge_id in collected_edge_ids:
        edge = edges_by_id.get(edge_id)
        if edge is None:
            continue
        candidate_edges.append(edge)

    pruned_edges = _prune_edges_by_seed_reachability(
        edges=candidate_edges,
        seed_nodes=seed_nodes,
    )

    try:
        edges = _sort_edges_by_evt_num(pruned_edges)
    except Exception as exc:
        warnings.append(f"failed to sort fallback subgraph edges by evt_num: {exc}")
        edges = []
        visited_nodes = set()

    final_node_ids: set[str] = set(seed_nodes)
    for edge in edges:
        final_node_ids.add(edge["subject"])
        final_node_ids.add(edge["object"])

    nodes = [nodes_by_id[nid] for nid in sorted(final_node_ids) if nid in nodes_by_id]

    subgraph = {
        "schema_version": SCHEMA_VERSION,
        "subgraph_id": _build_subgraph_id(edges),
        "seeds": {
            "mode": seeds.get("mode", "malicious_attr"),
            "seed_edges": sorted(set(seed_edges)),
            "seed_nodes": sorted(set(seed_nodes)),
        },
        "graph_summary": {
            **_build_graph_summary(edges, len(nodes)),
        },
        "nodes": nodes,
        "edges": edges,
    }
    if scenario_id:
        subgraph["scenario_id"] = scenario_id

    return subgraph, warnings, fallback_edges_kept


def extract_attack_subgraph_mode_b(
    graph_obj: dict[str, Any],
    seeds: dict[str, Any],
    edge_to_unit: dict[str, Optional[str]],
    seed_unit_set: set[str],
    unit_meta: Optional[dict[str, dict[str, Any]]] = None,
    max_hops: int = 1,
    scenario_id: Optional[str] = None,
    fallback_time_window_sec: int = 120,
    unit_nonnull_ratio: Optional[float] = None,
    b_fallback_net_pair_required: bool = False,
    b_fallback_net_pair_window_evt: int = 15,
) -> tuple[dict[str, Any], list[str]]:
    warnings: list[str] = []
    seed_edges = list(seeds.get("seed_edges", []))
    seed_nodes = list(seeds.get("seed_nodes", []))
    print(
        "[build_attack_chain_v1][mode_b] start "
        f"seed_edges={len(seed_edges)} seed_nodes={len(seed_nodes)} "
        f"seed_units={len(seed_unit_set)} "
        f"unit_nonnull_ratio={round(float(unit_nonnull_ratio or 0.0), 6)}"
    )

    phase_t0 = time.perf_counter()
    all_edge_ids = set(graph_obj["edges_by_id"].keys())

    unit_edge_ids: set[str] = {
        edge_id for edge_id in all_edge_ids if edge_to_unit.get(edge_id) is not None
    }
    fallback_edge_ids: set[str] = all_edge_ids - unit_edge_ids
    print(
        "[build_attack_chain_v1][mode_b] partition "
        f"all_edges={len(all_edge_ids)} unit_edges={len(unit_edge_ids)} "
        f"fallback_edges={len(fallback_edge_ids)}"
    )

    # Channel 1: unit-aware path (reuse existing mode A logic) on unit-attached edges.
    unit_graph_obj = _filter_graph_by_edge_ids(graph_obj, unit_edge_ids)
    unit_subgraph, unit_warnings = extract_attack_subgraph_mode_a(
        graph_obj=unit_graph_obj,
        seeds=seeds,
        edge_to_unit=edge_to_unit,
        seed_unit_set=seed_unit_set,
        unit_meta=unit_meta,
        max_hops=max_hops,
        scenario_id=None,
    )
    warnings.extend(unit_warnings)
    unit_edges = list(unit_subgraph.get("edges", []))
    print(
        "[build_attack_chain_v1][mode_b] unit_channel_done "
        f"kept_edges={len(unit_edges)} elapsed_s={round(time.perf_counter() - phase_t0, 2)}"
    )

    # Channel 2: local fallback path (reuse mode C behavior) on edges without unit_id.
    fallback_subgraph, fallback_warnings, fallback_edges_kept = extract_attack_subgraph_mode_c(
        graph_obj=graph_obj,
        seeds=seeds,
        max_hops=max_hops,
        scenario_id=None,
        fallback_time_window_sec=fallback_time_window_sec,
        allowed_edge_ids=fallback_edge_ids,
        file_context_retain_mode="conservative",
        conservative_file_cap_per_node=6,
        b_fallback_net_pair_required=b_fallback_net_pair_required,
        b_fallback_net_pair_window_evt=b_fallback_net_pair_window_evt,
    )
    warnings.extend(fallback_warnings)
    print(
        "[build_attack_chain_v1][mode_b] fallback_channel_done "
        f"kept_edges={int(fallback_edges_kept)} elapsed_s={round(time.perf_counter() - phase_t0, 2)}"
    )

    fallback_edges = list(fallback_subgraph.get("edges", []))

    merged_by_id: dict[str, dict[str, Any]] = {}
    for edge in unit_edges:
        merged_by_id[str(edge.get("id"))] = edge
    for edge in fallback_edges:
        merged_by_id[str(edge.get("id"))] = edge

    merged_edges = list(merged_by_id.values())
    dedup_dropped = (len(unit_edges) + len(fallback_edges)) - len(merged_edges)
    print(
        "[build_attack_chain_v1][mode_b] merge "
        f"unit_edges={len(unit_edges)} fallback_edges={len(fallback_edges)} "
        f"merged_edges={len(merged_edges)} dedup_dropped={dedup_dropped}"
    )

    seed_nodes: list[str] = list(seeds.get("seed_nodes", []))
    pruned_edges = _prune_edges_by_seed_reachability(
        edges=merged_edges,
        seed_nodes=seed_nodes,
    )

    hybrid_seed_reachable_kept = len(pruned_edges)
    print(
        "[build_attack_chain_v1][mode_b] prune_seed_reachability "
        f"kept_edges={hybrid_seed_reachable_kept}"
    )
    try:
        final_edges = _sort_edges_by_evt_num(pruned_edges)
    except Exception as exc:
        warnings.append(f"failed to sort hybrid subgraph edges by evt_num: {exc}")
        final_edges = []

    final_node_ids: set[str] = set(seed_nodes)
    for edge in final_edges:
        final_node_ids.add(str(edge.get("subject")))
        final_node_ids.add(str(edge.get("object")))

    nodes_by_id = graph_obj["nodes_by_id"]
    nodes = [nodes_by_id[nid] for nid in sorted(final_node_ids) if nid in nodes_by_id]

    subgraph = {
        "schema_version": SCHEMA_VERSION,
        "subgraph_id": _build_subgraph_id(final_edges),
        "seeds": {
            "mode": seeds.get("mode", "malicious_attr"),
            "seed_edges": sorted(set(seeds.get("seed_edges", []))),
            "seed_nodes": sorted(set(seed_nodes)),
        },
        "graph_summary": {
            **_build_graph_summary(final_edges, len(nodes)),
            "hybrid_unit_edges_kept": len(unit_edges),
            "hybrid_fallback_edges_kept": int(fallback_edges_kept),
            "hybrid_merged_edge_count": len(merged_edges),
            "hybrid_seed_reachable_kept": hybrid_seed_reachable_kept,
            "hybrid_dedup_dropped": dedup_dropped,
        },
        "nodes": nodes,
        "edges": final_edges,
    }
    if scenario_id:
        subgraph["scenario_id"] = scenario_id

    print(
        "[build_attack_chain_v1][mode_b] done "
        f"final_edges={len(final_edges)} final_nodes={len(nodes)} "
        f"elapsed_s={round(time.perf_counter() - phase_t0, 2)}"
    )

    return subgraph, warnings


def _augment_graph_summary_with_mode(
    attack_subgraph: dict[str, Any],
    builder_mode: str,
    mode_reason: str,
    mode_metrics: dict[str, Any],
    fallback_hop_limit: Optional[int],
    fallback_time_window_sec: Optional[int],
    fallback_edges_kept: Optional[int],
) -> None:
    summary = attack_subgraph.setdefault("graph_summary", {})
    summary["builder_mode"] = builder_mode
    summary["unit_nonnull_ratio"] = round(float(mode_metrics.get("unit_nonnull_ratio", 0.0)), 6)
    summary["seed_with_unit_ratio"] = round(float(mode_metrics.get("seed_with_unit_ratio", 0.0)), 6)
    summary["mode_reason"] = mode_reason
    summary["fallback_hop_limit"] = fallback_hop_limit
    summary["fallback_time_window_sec"] = fallback_time_window_sec
    if fallback_edges_kept is not None:
        summary["fallback_edges_kept"] = int(fallback_edges_kept)


def extract_attack_subgraph(
    graph_obj: dict[str, Any],
    seeds: dict[str, Any],
    edge_to_unit: dict[str, Optional[str]],
    seed_unit_set: set[str],
    unit_meta: Optional[dict[str, dict[str, Any]]] = None,
    max_hops: int = 1,
    scenario_id: Optional[str] = None,
    builder_mode: str = "A",
    mode_reason: str = "",
    mode_metrics: Optional[dict[str, Any]] = None,
    fallback_time_window_sec: int = 120,
    b_fallback_net_pair_required: bool = False,
    b_fallback_net_pair_window_evt: int = 15,
) -> tuple[dict[str, Any], list[str]]:
    warnings: list[str] = []
    mode = str(builder_mode or "A").upper()
    metrics = mode_metrics or {}

    if mode == "C":
        attack_subgraph, mode_warnings, fallback_edges_kept = extract_attack_subgraph_mode_c(
            graph_obj=graph_obj,
            seeds=seeds,
            max_hops=max_hops,
            scenario_id=scenario_id,
            fallback_time_window_sec=fallback_time_window_sec,
        )
        warnings.extend(mode_warnings)
        _augment_graph_summary_with_mode(
            attack_subgraph=attack_subgraph,
            builder_mode="C",
            mode_reason=mode_reason,
            mode_metrics=metrics,
            fallback_hop_limit=max_hops,
            fallback_time_window_sec=fallback_time_window_sec,
            fallback_edges_kept=fallback_edges_kept,
        )
        return attack_subgraph, warnings

    if mode == "B":
        attack_subgraph, mode_warnings = extract_attack_subgraph_mode_b(
            graph_obj=graph_obj,
            seeds=seeds,
            edge_to_unit=edge_to_unit,
            seed_unit_set=seed_unit_set,
            unit_meta=unit_meta,
            max_hops=max_hops,
            scenario_id=scenario_id,
            fallback_time_window_sec=fallback_time_window_sec,
            unit_nonnull_ratio=float(metrics.get("unit_nonnull_ratio", 0.0)),
            b_fallback_net_pair_required=b_fallback_net_pair_required,
            b_fallback_net_pair_window_evt=b_fallback_net_pair_window_evt,
        )
        warnings.extend(mode_warnings)
        _augment_graph_summary_with_mode(
            attack_subgraph=attack_subgraph,
            builder_mode="B",
            mode_reason=mode_reason,
            mode_metrics=metrics,
            fallback_hop_limit=max_hops,
            fallback_time_window_sec=fallback_time_window_sec,
            fallback_edges_kept=None,
        )
        return attack_subgraph, warnings

    attack_subgraph, mode_warnings = extract_attack_subgraph_mode_a(
        graph_obj=graph_obj,
        seeds=seeds,
        edge_to_unit=edge_to_unit,
        seed_unit_set=seed_unit_set,
        unit_meta=unit_meta,
        max_hops=max_hops,
        scenario_id=scenario_id,
    )
    warnings.extend(mode_warnings)
    _augment_graph_summary_with_mode(
        attack_subgraph=attack_subgraph,
        builder_mode="A",
        mode_reason=mode_reason,
        mode_metrics=metrics,
        fallback_hop_limit=max_hops,
        fallback_time_window_sec=fallback_time_window_sec,
        fallback_edges_kept=None,
    )
    return attack_subgraph, warnings


def _ensure_min_attrs(attrs: dict[str, Any]) -> dict[str, Any]:
    out = dict(attrs)
    for k in MIN_ATTR_KEYS:
        if k not in out:
            if k == "malicious":
                out[k] = False
            else:
                out[k] = None
    return out


def _build_chain_id(sorted_edges: list[dict[str, Any]]) -> str:
    if not sorted_edges:
        return "chain_empty"
    evt_nums = [int(e["attrs"]["evt_num"]) for e in sorted_edges]
    return f"chain_{min(evt_nums)}_{max(evt_nums)}"


def _is_devnull_file_edge(edge: dict[str, Any]) -> bool:
    """Return True if the FILE edge targets /dev/null."""
    obj = str(edge.get("object", ""))
    if obj == "file:/dev/null":
        return True
    fd = str((edge.get("attrs") or {}).get("fd_name", ""))
    return fd == "/dev/null"


def _is_node_modules_file_edge(edge: dict[str, Any]) -> bool:
    """Return True if the FILE edge targets a node_modules path."""
    obj = str(edge.get("object", ""))
    if "/node_modules/" in obj:
        return True
    fd = str((edge.get("attrs") or {}).get("fd_name", ""))
    return "/node_modules/" in fd


def _is_vendor_composer_file_edge(edge: dict[str, Any]) -> bool:
    """Return True if the FILE edge targets a Composer autoload path."""
    obj = str(edge.get("object", ""))
    if "/vendor/composer/" in obj or "/libraries/vendor/composer/" in obj:
        return True
    fd = str((edge.get("attrs") or {}).get("fd_name", ""))
    return "/vendor/composer/" in fd or "/libraries/vendor/composer/" in fd


def _evt_is_near_malicious(
    evt_num: Optional[int],
    malicious_evt_nums: list[int],
    window_evt: int,
) -> bool:
    if evt_num is None or not malicious_evt_nums:
        return False
    idx = bisect_left(malicious_evt_nums, evt_num)
    for pos in (idx - 1, idx):
        if 0 <= pos < len(malicious_evt_nums):
            if abs(malicious_evt_nums[pos] - evt_num) <= window_evt:
                return True
    return False


def _family_anchor_key(relation: str) -> str:
    relation_upper = relation.upper()
    if relation_upper.startswith("NET_"):
        return "NET"
    if relation_upper.startswith("PROCESS_"):
        return "PROCESS"
    if relation_upper.startswith("FILE_"):
        return "FILE"
    return "UNKNOWN"


def _edge_conn_nodes(edge: dict[str, Any]) -> set[str]:
    nodes: set[str] = set()
    for node in (edge.get("subject"), edge.get("object")):
        node_s = str(node or "")
        if node_s.startswith("conn:"):
            nodes.add(node_s)
    return nodes


def _edge_process_nodes(edge: dict[str, Any]) -> set[str]:
    nodes: set[str] = set()
    for node in (edge.get("subject"), edge.get("object")):
        node_s = str(node or "")
        if node_s.startswith("proc:"):
            nodes.add(node_s)
    return nodes


def _normalize_relation_csv_with_default(
    raw: str | None,
    default_values: tuple[str, ...],
) -> tuple[str, ...]:
    if raw is None:
        return tuple(default_values)
    values = [
        item.strip().upper()
        for item in str(raw).split(",")
        if item.strip()
    ]
    return tuple(values or default_values)


def _normalize_relation_csv(raw: str | None) -> tuple[str, ...]:
    return _normalize_relation_csv_with_default(
        raw,
        tuple(DEFAULT_BROAD_GATE_RELATIONS),
    )


def _is_unknown_child_process_fork_edge(edge: dict[str, Any]) -> bool:
    if str(edge.get("relation") or "").upper() != "PROCESS_FORK":
        return False
    obj = str(edge.get("object") or "")
    return FORK_REPEAT_UNKNOWN_CHILD_TOKEN in obj


def _edge_is_malicious(edge: dict[str, Any]) -> bool:
    attrs = edge.get("attrs") or {}
    return bool(attrs.get("malicious", False))


def _edge_evt_num_optional(edge: dict[str, Any]) -> Optional[int]:
    attrs = edge.get("attrs") or {}
    try:
        return int(attrs.get("evt_num"))
    except (TypeError, ValueError):
        return None


def _edge_relation_family(relation: str) -> str:
    rel = str(relation or "").upper()
    if rel.startswith("NET_"):
        return "NET"
    if rel.startswith("PROCESS_"):
        return "PROCESS"
    if rel.startswith("FILE_"):
        return "FILE"
    return "UNKNOWN"


def _pick_candidate_by_position(
    candidates: list[dict[str, Any]],
    *,
    mode: str,
    target_evt: Optional[int] = None,
) -> Optional[dict[str, Any]]:
    if not candidates:
        return None
    if mode == "first":
        return candidates[0]
    if mode == "last":
        return candidates[-1]
    if mode == "middle":
        return candidates[len(candidates) // 2]
    if mode == "quarter":
        return candidates[min(len(candidates) - 1, max(0, (len(candidates) - 1) // 4))]
    if mode == "three_quarter":
        idx = int(round((len(candidates) - 1) * 0.75))
        return candidates[min(len(candidates) - 1, max(0, idx))]
    if target_evt is None:
        return None

    evt_candidates: list[tuple[int, dict[str, Any]]] = []
    for edge in candidates:
        evt_num = _edge_evt_num_optional(edge)
        if evt_num is None:
            continue
        evt_candidates.append((evt_num, edge))
    if not evt_candidates:
        return None

    if mode == "last_before":
        eligible = [item for item in evt_candidates if item[0] < target_evt]
        return eligible[-1][1] if eligible else None
    if mode == "first_after":
        eligible = [item for item in evt_candidates if item[0] > target_evt]
        return eligible[0][1] if eligible else None
    if mode == "nearest":
        return min(evt_candidates, key=lambda item: abs(item[0] - target_evt))[1]
    return None


def _edge_position_sort_key(edge: dict[str, Any]) -> tuple[int, int, str]:
    evt_num = _edge_evt_num_optional(edge)
    evt_key = evt_num if evt_num is not None else (1 << 62)
    try:
        seq_key = int(edge.get("seq") or 0)
    except (TypeError, ValueError):
        seq_key = 0
    return (evt_key, seq_key, str(edge.get("id") or ""))


def _runtime_shell_relation_family(edge: dict[str, Any]) -> Optional[str]:
    relation = str(edge.get("relation") or "").upper()
    if relation == "PROCESS_FORK":
        return "process_fork"
    if relation == "NET_ACCEPT":
        return "net_accept"
    if relation in {"NET_RECV", "NET_SEND"}:
        return "net_io"
    return None


def _edge_primary_process_key(edge: dict[str, Any]) -> Optional[str]:
    subject = str(edge.get("subject") or "")
    if subject.startswith("proc:"):
        return subject
    process_nodes = sorted(_edge_process_nodes(edge))
    return process_nodes[0] if process_nodes else None


def _edge_primary_conn_key(edge: dict[str, Any]) -> Optional[str]:
    conn_nodes = sorted(_edge_conn_nodes(edge))
    if conn_nodes:
        return conn_nodes[0]
    attrs = edge.get("attrs") or {}
    fd_name = str(attrs.get("fd_name") or "").strip()
    if fd_name.startswith("conn:"):
        return fd_name
    return None


def _runtime_shell_anchor_key(
    edge: dict[str, Any],
    edge_to_unit: dict[str, Optional[str]],
) -> Optional[tuple[str, Optional[str], Optional[str], Optional[str]]]:
    family = _runtime_shell_relation_family(edge)
    if family is None:
        return None

    edge_id = str(edge.get("id") or "")
    unit_key = edge_to_unit.get(edge_id)
    subject_key = _edge_primary_process_key(edge)
    conn_key = _edge_primary_conn_key(edge)

    if family == "process_fork":
        if subject_key is None:
            return None
        return (family, unit_key, subject_key, None)

    if family in {"net_accept", "net_io"}:
        if subject_key is None or conn_key is None:
            return None
        return (family, unit_key, subject_key, conn_key)

    return None


def _evt_distance_to_range(
    evt_num: Optional[int],
    start_evt: Optional[int],
    end_evt: Optional[int],
) -> Optional[int]:
    if evt_num is None or start_evt is None or end_evt is None:
        return None
    if start_evt <= evt_num <= end_evt:
        return 0
    if evt_num < start_evt:
        return start_evt - evt_num
    return evt_num - end_evt


def _representative_edge_ids_for_block(
    edges: list[dict[str, Any]],
    *,
    first_malicious_evt: Optional[int],
    last_malicious_evt: Optional[int],
) -> list[str]:
    representative_ids: list[str] = []
    seen: set[str] = set()

    def add(edge: Optional[dict[str, Any]]) -> None:
        if edge is None:
            return
        edge_id = str(edge.get("id") or "")
        if not edge_id or edge_id in seen:
            return
        seen.add(edge_id)
        representative_ids.append(edge_id)

    sorted_edges = sorted(edges, key=_edge_position_sort_key)
    add(_pick_candidate_by_position(sorted_edges, mode="first"))
    if first_malicious_evt is not None:
        add(_pick_candidate_by_position(sorted_edges, mode="nearest", target_evt=first_malicious_evt))
    if last_malicious_evt is not None and last_malicious_evt != first_malicious_evt:
        add(_pick_candidate_by_position(sorted_edges, mode="nearest", target_evt=last_malicious_evt))
    add(_pick_candidate_by_position(sorted_edges, mode="last"))

    return representative_ids[:4]


def _stable_short_digest(parts: list[Any]) -> str:
    raw = "|".join("" if part is None else str(part) for part in parts)
    return hashlib.sha1(raw.encode("utf-8", errors="replace")).hexdigest()[:12]


def _build_runtime_block_id(
    *,
    scenario_id: Optional[str],
    family: str,
    unit_key: Optional[str],
    subject_key: Optional[str],
    conn_key: Optional[str],
    evt_start: Optional[int],
    evt_end: Optional[int],
) -> str:
    digest = _stable_short_digest(
        [
            scenario_id,
            family,
            unit_key,
            subject_key,
            conn_key,
            evt_start,
            evt_end,
        ]
    )
    start_label = evt_start if evt_start is not None else "noevt"
    end_label = evt_end if evt_end is not None else "noevt"
    return (
        f"{scenario_id or 'scenario'}::runtime_shell_block::"
        f"{family}::{digest}::{start_label}-{end_label}"
    )


def _runtime_block_recommended_role(
    *,
    malicious_edge_count: int,
    evt_start: Optional[int],
    evt_end: Optional[int],
    first_malicious_evt: Optional[int],
    last_malicious_evt: Optional[int],
) -> str:
    if malicious_edge_count > 0:
        return "backbone_representative_candidate"
    if (
        evt_start is not None
        and evt_end is not None
        and first_malicious_evt is not None
        and last_malicious_evt is not None
    ):
        if evt_start <= last_malicious_evt and evt_end >= first_malicious_evt:
            return "stage_boundary_hint"
    return "residual_preferred"


def _malicious_evt_bounds(edges: list[dict[str, Any]]) -> tuple[Optional[int], Optional[int]]:
    evt_nums = [
        evt
        for evt in (_edge_evt_num_optional(edge) for edge in edges if _edge_is_malicious(edge))
        if evt is not None
    ]
    if not evt_nums:
        return None, None
    return min(evt_nums), max(evt_nums)


def _split_runtime_shell_blocks(
    edges: list[dict[str, Any]],
    *,
    max_evt_gap: int,
) -> list[list[dict[str, Any]]]:
    if not edges:
        return []

    gap_limit = max(1, int(max_evt_gap))
    blocks: list[list[dict[str, Any]]] = []
    current: list[dict[str, Any]] = []
    prev_evt: Optional[int] = None

    for edge in sorted(edges, key=_edge_position_sort_key):
        evt_num = _edge_evt_num_optional(edge)
        same_window = (
            current
            and evt_num is not None
            and prev_evt is not None
            and (evt_num - prev_evt) <= gap_limit
        )
        if same_window:
            current.append(edge)
        else:
            if current:
                blocks.append(current)
            current = [edge]
        if evt_num is not None:
            prev_evt = evt_num

    if current:
        blocks.append(current)
    return blocks


def build_runtime_shell_block_summary(
    attack_subgraph: dict[str, Any],
    *,
    edge_to_unit: dict[str, Optional[str]],
    scenario_id: Optional[str],
    max_evt_gap: int = DEFAULT_RUNTIME_SHELL_BLOCK_MAX_EVT_GAP,
) -> list[dict[str, Any]]:
    edges = list(attack_subgraph.get("edges") or [])
    first_malicious_evt, last_malicious_evt = _malicious_evt_bounds(edges)

    grouped_edges: dict[tuple[str, Optional[str], Optional[str], Optional[str]], list[dict[str, Any]]] = {}
    for edge in edges:
        relation = str(edge.get("relation") or "").upper()
        if relation not in RUNTIME_SHELL_BLOCK_RELATIONS:
            continue
        anchor_key = _runtime_shell_anchor_key(edge, edge_to_unit)
        if anchor_key is None:
            continue
        grouped_edges.setdefault(anchor_key, []).append(edge)

    rows: list[dict[str, Any]] = []
    for anchor_key in sorted(grouped_edges.keys(), key=lambda k: tuple("" if v is None else str(v) for v in k)):
        family, unit_key, subject_key, conn_key = anchor_key
        for block_edges in _split_runtime_shell_blocks(
            grouped_edges[anchor_key],
            max_evt_gap=max_evt_gap,
        ):
            evt_values = [
                evt
                for evt in (_edge_evt_num_optional(edge) for edge in block_edges)
                if evt is not None
            ]
            evt_start = min(evt_values) if evt_values else None
            evt_end = max(evt_values) if evt_values else None
            relation_counts = Counter(str(edge.get("relation") or "") for edge in block_edges)
            malicious_edge_count = sum(1 for edge in block_edges if _edge_is_malicious(edge))

            row = {
                "schema_version": RUNTIME_SHELL_BLOCK_SCHEMA_VERSION,
                "scenario_id": scenario_id,
                "block_id": _build_runtime_block_id(
                    scenario_id=scenario_id,
                    family=family,
                    unit_key=unit_key,
                    subject_key=subject_key,
                    conn_key=conn_key,
                    evt_start=evt_start,
                    evt_end=evt_end,
                ),
                "block_type_candidate": "runtime_shell_block",
                "evt_start": evt_start,
                "evt_end": evt_end,
                "unit_key": unit_key,
                "subject_key": subject_key,
                "conn_key": conn_key,
                "relation_family_counts": dict(sorted(relation_counts.items())),
                "edge_count": len(block_edges),
                "edge_ids": [
                    str(edge.get("id") or "")
                    for edge in sorted(block_edges, key=_edge_position_sort_key)
                    if str(edge.get("id") or "")
                ],
                "malicious_edge_count": malicious_edge_count,
                "distance_to_first_malicious_evt": _evt_distance_to_range(
                    first_malicious_evt,
                    evt_start,
                    evt_end,
                ),
                "distance_to_last_malicious_evt": _evt_distance_to_range(
                    last_malicious_evt,
                    evt_start,
                    evt_end,
                ),
                "recommended_role": _runtime_block_recommended_role(
                    malicious_edge_count=malicious_edge_count,
                    evt_start=evt_start,
                    evt_end=evt_end,
                    first_malicious_evt=first_malicious_evt,
                    last_malicious_evt=last_malicious_evt,
                ),
                "representative_edge_ids": _representative_edge_ids_for_block(
                    block_edges,
                    first_malicious_evt=first_malicious_evt,
                    last_malicious_evt=last_malicious_evt,
                ),
            }
            rows.append(row)

    rows.sort(
        key=lambda row: (
            row.get("evt_start") if row.get("evt_start") is not None else (1 << 62),
            str(row.get("block_id") or ""),
        )
    )
    return rows


def _build_net_accept_subject_level_trial_blocks(
    attack_subgraph: dict[str, Any],
    *,
    edge_to_unit: dict[str, Optional[str]],
    scenario_id: Optional[str],
    max_evt_gap: int = DEFAULT_RUNTIME_SHELL_BLOCK_MAX_EVT_GAP,
) -> list[dict[str, Any]]:
    """Trial-only: rebuild NET_ACCEPT blocks using (family, unit, subject) anchor.

    The default runtime_shell_block_summary uses (family, unit, subject, conn)
    as the block anchor, which for mongo-express style workloads produces
    almost exclusively single-edge NET_ACCEPT blocks (one per connection).
    This helper re-aggregates NET_ACCEPT edges by subject only so that
    repeated accept activity on the same process can form a cohesive block
    and pass the trial size gate. Intended to feed the trial view only; the
    exported sidecar rows are never replaced.
    """
    edges = list(attack_subgraph.get("edges") or [])
    if not edges:
        return []

    first_malicious_evt, last_malicious_evt = _malicious_evt_bounds(edges)

    grouped_edges: dict[
        tuple[str, Optional[str], Optional[str], Optional[str]],
        list[dict[str, Any]],
    ] = {}
    for edge in edges:
        relation = str(edge.get("relation") or "").upper()
        if relation != "NET_ACCEPT":
            continue
        subject_key = _edge_primary_process_key(edge)
        if subject_key is None:
            continue
        edge_id = str(edge.get("id") or "")
        unit_key = edge_to_unit.get(edge_id)
        anchor_key = ("net_accept", unit_key, subject_key, None)
        grouped_edges.setdefault(anchor_key, []).append(edge)

    rows: list[dict[str, Any]] = []
    for anchor_key in sorted(
        grouped_edges.keys(),
        key=lambda k: tuple("" if v is None else str(v) for v in k),
    ):
        family, unit_key, subject_key, conn_key = anchor_key
        for block_edges in _split_runtime_shell_blocks(
            grouped_edges[anchor_key],
            max_evt_gap=max_evt_gap,
        ):
            evt_values = [
                evt
                for evt in (_edge_evt_num_optional(edge) for edge in block_edges)
                if evt is not None
            ]
            evt_start = min(evt_values) if evt_values else None
            evt_end = max(evt_values) if evt_values else None
            relation_counts = Counter(
                str(edge.get("relation") or "") for edge in block_edges
            )
            malicious_edge_count = sum(
                1 for edge in block_edges if _edge_is_malicious(edge)
            )

            row = {
                "schema_version": RUNTIME_SHELL_BLOCK_SCHEMA_VERSION,
                "scenario_id": scenario_id,
                "block_id": _build_runtime_block_id(
                    scenario_id=scenario_id,
                    family=f"{family}_subject_trial",
                    unit_key=unit_key,
                    subject_key=subject_key,
                    conn_key=conn_key,
                    evt_start=evt_start,
                    evt_end=evt_end,
                ),
                "block_type_candidate": "runtime_shell_block_trial_view",
                "trial_view": "net_accept_subject_anchor",
                "evt_start": evt_start,
                "evt_end": evt_end,
                "unit_key": unit_key,
                "subject_key": subject_key,
                "conn_key": conn_key,
                "relation_family_counts": dict(sorted(relation_counts.items())),
                "edge_count": len(block_edges),
                "edge_ids": [
                    str(edge.get("id") or "")
                    for edge in sorted(block_edges, key=_edge_position_sort_key)
                    if str(edge.get("id") or "")
                ],
                "malicious_edge_count": malicious_edge_count,
                "distance_to_first_malicious_evt": _evt_distance_to_range(
                    first_malicious_evt,
                    evt_start,
                    evt_end,
                ),
                "distance_to_last_malicious_evt": _evt_distance_to_range(
                    last_malicious_evt,
                    evt_start,
                    evt_end,
                ),
                "recommended_role": _runtime_block_recommended_role(
                    malicious_edge_count=malicious_edge_count,
                    evt_start=evt_start,
                    evt_end=evt_end,
                    first_malicious_evt=first_malicious_evt,
                    last_malicious_evt=last_malicious_evt,
                ),
                "representative_edge_ids": _representative_edge_ids_for_block(
                    block_edges,
                    first_malicious_evt=first_malicious_evt,
                    last_malicious_evt=last_malicious_evt,
                ),
            }
            rows.append(row)

    rows.sort(
        key=lambda row: (
            row.get("evt_start") if row.get("evt_start") is not None else (1 << 62),
            str(row.get("block_id") or ""),
        )
    )
    return rows


def _first_present_relation(
    relation_counts: dict[str, Any],
    priority: tuple[str, ...],
) -> Optional[str]:
    for relation in priority:
        if int(relation_counts.get(relation) or 0) > 0:
            return relation
    return None


def _build_runtime_shell_evt_indexes(
    edges: list[dict[str, Any]],
) -> tuple[dict[str, list[int]], dict[str, list[int]]]:
    process_evt_index: dict[str, list[int]] = {}
    conn_evt_index: dict[str, list[int]] = {}
    for edge in edges:
        relation = str(edge.get("relation") or "").upper()
        if relation not in RUNTIME_SHELL_BLOCK_RELATIONS:
            continue
        evt_num = _edge_evt_num_optional(edge)
        if evt_num is None:
            continue
        process_key = _edge_primary_process_key(edge)
        if process_key is not None:
            process_evt_index.setdefault(process_key, []).append(evt_num)
        conn_key = _edge_primary_conn_key(edge)
        if conn_key is not None:
            conn_evt_index.setdefault(conn_key, []).append(evt_num)

    for evt_values in process_evt_index.values():
        evt_values.sort()
    for evt_values in conn_evt_index.values():
        evt_values.sort()
    return process_evt_index, conn_evt_index


def _runtime_shell_edge_count_before_attack(
    *,
    process_evt_index: dict[str, list[int]],
    conn_evt_index: dict[str, list[int]],
    entry_evt_start: Optional[int],
    first_malicious_evt: Optional[int],
    subject_key: Optional[str],
    conn_key: Optional[str],
) -> Optional[int]:
    if entry_evt_start is None or first_malicious_evt is None:
        return None
    if conn_key is not None:
        evt_values = conn_evt_index.get(conn_key, [])
    elif subject_key is not None:
        evt_values = process_evt_index.get(subject_key, [])
    else:
        return None
    if not evt_values:
        return 0
    start_idx = bisect_left(evt_values, entry_evt_start)
    end_idx = bisect_left(evt_values, first_malicious_evt)
    return max(0, end_idx - start_idx)


def _entry_candidate_recommendation_reasons(
    *,
    same_conn_as_malicious: bool,
    same_process_as_malicious: bool,
    distance_to_first: Optional[int],
    shell_thickness: Optional[int],
    near_first_malicious_evt: int,
    shell_thickness_max: int,
    heavy_shell_thickness_min: int,
) -> list[str]:
    reasons: list[str] = []
    if same_conn_as_malicious:
        reasons.append("same_conn_as_first_malicious")
    if distance_to_first == 0:
        reasons.append("overlaps_first_malicious_evt")
    if (
        distance_to_first is not None
        and distance_to_first > 0
        and distance_to_first <= max(0, int(near_first_malicious_evt))
    ):
        reasons.append("near_first_malicious_evt")
    if (
        same_process_as_malicious
        and not same_conn_as_malicious
        and distance_to_first != 0
    ):
        reasons.append("same_process_only")
    if shell_thickness is not None and shell_thickness <= max(0, int(shell_thickness_max)):
        reasons.append("low_shell_thickness")
    if shell_thickness is not None and shell_thickness >= max(0, int(heavy_shell_thickness_min)):
        reasons.append("runtime_shell_heavy_before_candidate")
    return reasons


def _entry_candidate_recommendation_tier(
    *,
    reasons: list[str],
    same_conn_as_malicious: bool,
    same_process_as_malicious: bool,
) -> str:
    reason_set = set(reasons)
    if not same_conn_as_malicious and not same_process_as_malicious:
        return "not_recommended"
    if "runtime_shell_heavy_before_candidate" in reason_set:
        return "context_only"
    if (
        "same_conn_as_first_malicious" in reason_set
        or "overlaps_first_malicious_evt" in reason_set
        or (
            "near_first_malicious_evt" in reason_set
            and "low_shell_thickness" in reason_set
        )
    ):
        return "strong_recommended"
    if "same_process_only" in reason_set or "low_shell_thickness" in reason_set:
        return "weak_recommended"
    return "not_recommended"


def build_entry_candidate_block_summary(
    attack_subgraph: dict[str, Any],
    *,
    runtime_block_rows: list[dict[str, Any]],
    scenario_id: Optional[str],
    post_attack_window_evt: int = DEFAULT_ENTRY_CANDIDATE_POST_ATTACK_WINDOW_EVT,
    shell_thickness_max: int = DEFAULT_ENTRY_CANDIDATE_SHELL_THICKNESS_MAX,
    near_first_malicious_evt: int = DEFAULT_ENTRY_CANDIDATE_NEAR_FIRST_MALICIOUS_EVT,
    heavy_shell_thickness_min: int = DEFAULT_ENTRY_CANDIDATE_HEAVY_SHELL_THICKNESS_MIN,
) -> list[dict[str, Any]]:
    edges = list(attack_subgraph.get("edges") or [])
    first_malicious_evt, _ = _malicious_evt_bounds(edges)
    if first_malicious_evt is None:
        return []

    process_evt_index, conn_evt_index = _build_runtime_shell_evt_indexes(edges)
    malicious_edges = [edge for edge in edges if _edge_is_malicious(edge)]
    malicious_conn_keys = {
        conn_key
        for conn_key in (_edge_primary_conn_key(edge) for edge in malicious_edges)
        if conn_key is not None
    }
    malicious_process_keys = {
        process_key
        for edge in malicious_edges
        for process_key in _edge_process_nodes(edge)
    }

    rows: list[dict[str, Any]] = []
    post_window = max(0, int(post_attack_window_evt))
    thickness_limit = max(0, int(shell_thickness_max))

    for block_row in runtime_block_rows:
        relation_counts = block_row.get("relation_family_counts") or {}
        if not isinstance(relation_counts, dict):
            continue
        entry_relation = _first_present_relation(
            relation_counts,
            ENTRY_CANDIDATE_RELATION_PRIORITY,
        )
        if entry_relation is None:
            continue

        try:
            entry_evt_start = (
                int(block_row["evt_start"])
                if block_row.get("evt_start") is not None
                else None
            )
        except (TypeError, ValueError):
            entry_evt_start = None
        try:
            entry_evt_end = (
                int(block_row["evt_end"])
                if block_row.get("evt_end") is not None
                else None
            )
        except (TypeError, ValueError):
            entry_evt_end = None

        if entry_evt_start is None:
            continue
        if entry_evt_start > first_malicious_evt + post_window:
            continue

        subject_key = block_row.get("subject_key")
        conn_key = block_row.get("conn_key")
        same_conn_as_malicious = bool(conn_key is not None and conn_key in malicious_conn_keys)
        same_process_as_malicious = bool(subject_key is not None and subject_key in malicious_process_keys)
        if not same_conn_as_malicious and not same_process_as_malicious:
            continue

        shell_thickness = _runtime_shell_edge_count_before_attack(
            process_evt_index=process_evt_index,
            conn_evt_index=conn_evt_index,
            entry_evt_start=entry_evt_start,
            first_malicious_evt=first_malicious_evt,
            subject_key=str(subject_key) if subject_key is not None else None,
            conn_key=str(conn_key) if conn_key is not None else None,
        )
        distance_to_first = _evt_distance_to_range(
            first_malicious_evt,
            entry_evt_start,
            entry_evt_end,
        )
        recommendation_reasons = _entry_candidate_recommendation_reasons(
            same_conn_as_malicious=same_conn_as_malicious,
            same_process_as_malicious=same_process_as_malicious,
            distance_to_first=distance_to_first,
            shell_thickness=shell_thickness,
            near_first_malicious_evt=near_first_malicious_evt,
            shell_thickness_max=thickness_limit,
            heavy_shell_thickness_min=heavy_shell_thickness_min,
        )
        recommendation_tier = _entry_candidate_recommendation_tier(
            reasons=recommendation_reasons,
            same_conn_as_malicious=same_conn_as_malicious,
            same_process_as_malicious=same_process_as_malicious,
        )
        recommended = recommendation_tier in {"strong_recommended", "weak_recommended"}
        rep_ids = list(block_row.get("representative_edge_ids") or [])
        representative_entry_edge_id = str(rep_ids[0]) if rep_ids else None

        row = {
            "schema_version": ENTRY_CANDIDATE_BLOCK_SCHEMA_VERSION,
            "scenario_id": scenario_id,
            "entry_candidate_id": (
                f"{scenario_id or 'scenario'}::entry_candidate::"
                f"{_stable_short_digest([block_row.get('block_id'), entry_relation, entry_evt_start])}"
            ),
            "block_id": block_row.get("block_id"),
            "entry_evt_start": entry_evt_start,
            "entry_evt_end": entry_evt_end,
            "entry_relation": entry_relation,
            "same_conn_as_malicious": same_conn_as_malicious,
            "same_process_as_malicious": same_process_as_malicious,
            "distance_to_first_malicious_evt": distance_to_first,
            "shell_thickness_before_attack": shell_thickness,
            "recommended_as_backbone_start": recommended,
            "recommendation_tier": recommendation_tier,
            "recommendation_reasons": recommendation_reasons,
            "representative_entry_edge_id": representative_entry_edge_id,
        }
        rows.append(row)

    rows.sort(
        key=lambda row: (
            {
                "strong_recommended": 0,
                "weak_recommended": 1,
                "context_only": 2,
                "not_recommended": 3,
            }.get(str(row.get("recommendation_tier") or ""), 4),
            row.get("shell_thickness_before_attack")
            if row.get("shell_thickness_before_attack") is not None
            else (1 << 62),
            row.get("entry_evt_start") if row.get("entry_evt_start") is not None else (1 << 62),
            str(row.get("entry_candidate_id") or ""),
        )
    )
    return rows


def _build_semantic_repeat_keep_ids(
    candidates: list[dict[str, Any]],
    *,
    relation_family: str,
    first_malicious_evt: Optional[int],
    last_malicious_evt: Optional[int],
) -> set[str]:
    keep_ids: set[str] = set()
    if not candidates:
        return keep_ids

    relation_family_norm = str(relation_family or "").upper()
    for mode in ("first", "last"):
        edge = _pick_candidate_by_position(candidates, mode=mode)
        if edge is not None:
            keep_ids.add(str(edge.get("id") or ""))

    if relation_family_norm not in {"NET_ACCEPT", "PROCESS_FORK"} and len(candidates) >= 5:
        for mode in ("quarter", "middle", "three_quarter"):
            edge = _pick_candidate_by_position(candidates, mode=mode)
            if edge is not None:
                keep_ids.add(str(edge.get("id") or ""))
    elif len(candidates) <= 3:
        edge = _pick_candidate_by_position(candidates, mode="middle")
        if edge is not None:
            keep_ids.add(str(edge.get("id") or ""))

    if first_malicious_evt is not None:
        for mode in ("nearest",):
            edge = _pick_candidate_by_position(
                candidates,
                mode=mode,
                target_evt=first_malicious_evt,
            )
            if edge is not None:
                keep_ids.add(str(edge.get("id") or ""))

    if last_malicious_evt is not None and last_malicious_evt != first_malicious_evt:
        for mode in ("nearest",):
            edge = _pick_candidate_by_position(
                candidates,
                mode=mode,
                target_evt=last_malicious_evt,
            )
            if edge is not None:
                keep_ids.add(str(edge.get("id") or ""))

    keep_ids.discard("")
    return keep_ids


def _split_parent_fork_clusters(
    candidates: list[dict[str, Any]],
    *,
    max_evt_gap: int,
) -> list[list[dict[str, Any]]]:
    if not candidates:
        return []

    clusters: list[list[dict[str, Any]]] = []
    current_cluster: list[dict[str, Any]] = []
    prev_evt_num: Optional[int] = None
    gap_limit = max(1, int(max_evt_gap))

    for edge in sorted(candidates, key=_edge_position_sort_key):
        evt_num = _edge_evt_num_optional(edge)
        if (
            current_cluster
            and evt_num is not None
            and prev_evt_num is not None
            and (evt_num - prev_evt_num) <= gap_limit
        ):
            current_cluster.append(edge)
        else:
            if current_cluster:
                clusters.append(current_cluster)
            current_cluster = [edge]
        prev_evt_num = evt_num

    if current_cluster:
        clusters.append(current_cluster)
    return clusters


def _build_parent_cluster_representative_keep_ids(
    candidates: list[dict[str, Any]],
    *,
    first_malicious_evt: Optional[int],
    last_malicious_evt: Optional[int],
    malicious_process_nodes: Optional[set[str]] = None,
) -> set[str]:
    keep_ids: set[str] = set()
    if not candidates:
        return keep_ids

    # Boundary preservation: keep cluster start/end so the backbone reflects
    # where runtime fan-out begins and ends, instead of sampling interior burst detail.
    first_edge = _pick_candidate_by_position(candidates, mode="first")
    last_edge = _pick_candidate_by_position(candidates, mode="last")
    for edge in (first_edge, last_edge):
        if edge is not None:
            keep_ids.add(str(edge.get("id") or ""))

    first_evt = _edge_evt_num_optional(first_edge) if first_edge is not None else None
    last_evt = _edge_evt_num_optional(last_edge) if last_edge is not None else None

    cluster_near_first = (
        first_malicious_evt is not None
        and first_evt is not None
        and last_evt is not None
        and first_evt <= first_malicious_evt <= last_evt
    )
    cluster_near_last = (
        last_malicious_evt is not None
        and first_evt is not None
        and last_evt is not None
        and first_evt <= last_malicious_evt <= last_evt
    )

    # Interior anchor: preserve a middle sample only when the cluster itself spans
    # an attack-adjacent window; otherwise boundary points are sufficient.
    if len(candidates) > 2 and (cluster_near_first or cluster_near_last):
        edge = _pick_candidate_by_position(candidates, mode="middle")
        if edge is not None:
            keep_ids.add(str(edge.get("id") or ""))

    # Child-bridge safety net: a PF edge whose forked child process later
    # participates in a malicious PROCESS_* edge is a structural bridge into
    # the attack story; keep it regardless of its position inside the cluster.
    if malicious_process_nodes:
        for edge in candidates:
            if str(edge.get("relation") or "").upper() != "PROCESS_FORK":
                continue
            obj = str(edge.get("object") or "")
            if not obj.startswith("proc:"):
                continue
            if obj in malicious_process_nodes:
                edge_id = str(edge.get("id") or "")
                if edge_id:
                    keep_ids.add(edge_id)

    keep_ids.discard("")
    return keep_ids


def _build_backbone_semantic_readiness(
    expression_clarity: dict[str, Any],
) -> dict[str, Any]:
    entry_anchor_clear = bool(expression_clarity.get("entry_anchor_relation"))
    result_anchor_present = bool(expression_clarity.get("result_anchor_relation"))
    result_anchor_result_like = bool(expression_clarity.get("result_anchor_result_like"))
    span_density = float(expression_clarity.get("malicious_span_malicious_density") or 0.0)
    span_ratio = float(expression_clarity.get("malicious_span_ratio") or 0.0)
    pre_shell_ratio = float(expression_clarity.get("pre_malicious_shell_ratio") or 0.0)
    post_shell_ratio = float(expression_clarity.get("post_malicious_shell_ratio") or 0.0)

    dense_enough = span_density >= SEMANTIC_READY_DENSITY_MIN
    span_present = span_ratio >= SEMANTIC_READY_SPAN_RATIO_MIN
    background_shell_controlled = (
        pre_shell_ratio <= SEMANTIC_READY_PRE_SHELL_MAX
        and post_shell_ratio <= SEMANTIC_READY_POST_SHELL_MAX
    )
    story_self_contained = bool(
        entry_anchor_clear
        and result_anchor_present
        and dense_enough
        and span_present
        and background_shell_controlled
    )

    story_gaps: list[str] = []
    if not entry_anchor_clear:
        story_gaps.append("missing_entry_anchor")
    if not result_anchor_present:
        story_gaps.append("missing_result_anchor")
    if not dense_enough:
        story_gaps.append("malicious_span_too_sparse")
    if not span_present:
        story_gaps.append("malicious_span_too_thin")
    if pre_shell_ratio > SEMANTIC_READY_PRE_SHELL_MAX:
        story_gaps.append("pre_shell_too_thick")
    if post_shell_ratio > SEMANTIC_READY_POST_SHELL_MAX:
        story_gaps.append("post_shell_too_thick")

    return {
        "primary_objective": "attack_semantics_priority",
        "entry_anchor_clear": entry_anchor_clear,
        "result_anchor_present": result_anchor_present,
        "result_anchor_result_like": result_anchor_result_like,
        "malicious_span_dense_enough": dense_enough,
        "malicious_span_present_enough": span_present,
        "background_shell_controlled": background_shell_controlled,
        "backbone_story_self_contained": story_self_contained,
        "runtime_shell_demotion_preferred": not background_shell_controlled,
        "preferred_runtime_shell_lane": "refinement_residual",
        "auxiliary_metrics_only": [
            "warning_present",
            "edge_count",
            "malicious_ratio",
        ],
        "story_gaps": story_gaps,
    }


def _summarize_refinement_stage_hint(
    start_evt_num: Optional[int],
    end_evt_num: Optional[int],
    *,
    first_malicious_evt: Optional[int],
    last_malicious_evt: Optional[int],
) -> str:
    if start_evt_num is None or end_evt_num is None:
        return "runtime_shell_unknown"
    if first_malicious_evt is None or last_malicious_evt is None:
        return "runtime_shell_unknown"
    if end_evt_num < first_malicious_evt:
        return "pre_attack_shell"
    if start_evt_num > last_malicious_evt:
        return "post_attack_shell"
    if start_evt_num <= first_malicious_evt <= end_evt_num:
        return "attack_entry_adjacent_shell"
    if start_evt_num <= last_malicious_evt <= end_evt_num:
        return "attack_result_adjacent_shell"
    return "attack_adjacent_runtime_shell"


def _build_refinement_residual_rows(
    *,
    candidate_groups: dict[str, list[dict[str, Any]]],
    semantic_keep_ids: set[str],
    relation_family: str,
    scenario_id: Optional[str],
    first_malicious_evt: Optional[int],
    last_malicious_evt: Optional[int],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    subject_items = sorted(candidate_groups.items(), key=lambda item: item[0])
    why_retained_base = (
        ["repeat_structure_summary", "request_entry_context"]
        if relation_family == "NET_ACCEPT"
        else ["repeat_structure_summary", "process_fanout_context"]
    )

    for idx, (group_key, edges) in enumerate(subject_items, 1):
        if not edges:
            continue
        subject_node = str((edges[0] or {}).get("subject") or group_key or "")
        edge_ids = [str(edge.get("id") or "") for edge in edges if str(edge.get("id") or "")]
        kept_ids = [edge_id for edge_id in edge_ids if edge_id in semantic_keep_ids]
        dropped_ids = [edge_id for edge_id in edge_ids if edge_id not in semantic_keep_ids]
        if not dropped_ids:
            continue

        evt_values = [evt for evt in (_edge_evt_num_optional(edge) for edge in edges) if evt is not None]
        start_evt_num = min(evt_values) if evt_values else None
        end_evt_num = max(evt_values) if evt_values else None
        stage_hint = _summarize_refinement_stage_hint(
            start_evt_num,
            end_evt_num,
            first_malicious_evt=first_malicious_evt,
            last_malicious_evt=last_malicious_evt,
        )

        representative_edges: list[dict[str, Any]] = []
        representative_keep_ids: set[str] = set()
        for mode in ("first", "middle", "last"):
            rep = _pick_candidate_by_position(edges, mode=mode)
            rep_id = str((rep or {}).get("id") or "")
            if rep is None or not rep_id or rep_id in representative_keep_ids:
                continue
            representative_keep_ids.add(rep_id)
            representative_edges.append(
                {
                    "edge_id": rep_id,
                    "evt_num": _edge_evt_num_optional(rep),
                    "relation": str(rep.get("relation") or ""),
                    "subject": str(rep.get("subject") or ""),
                    "object": str(rep.get("object") or ""),
                    "kept_in_backbone": rep_id in semantic_keep_ids,
                }
            )

        rows.append(
            {
                "schema_version": REFINEMENT_RESIDUAL_SCHEMA_VERSION,
                "residual_id": (
                    f"{scenario_id or 'scenario'}::backbone_refinement::"
                    f"{relation_family.lower()}::{idx}"
                ),
                "source": "backbone_refinement",
                "relation_family": relation_family,
                "window": {
                    "start_evt_num": start_evt_num,
                    "end_evt_num": end_evt_num,
                },
                "anchor_backbone_edge_ids": kept_ids[:8],
                "summary": {
                    "original_count": len(edge_ids),
                    "kept_count": len(kept_ids),
                    "dropped_count": len(dropped_ids),
                    "malicious_count": 0,
                    "non_malicious_count": len(edge_ids),
                },
                "representative_edges": representative_edges,
                "stage_hint": stage_hint,
                "why_retained": why_retained_base + [stage_hint],
                "narrative_role": "runtime_shell_summary",
                "backbone_priority": "residual_preferred",
                "shell_origin_hint": "normal_or_steady_runtime_shell",
                "subject": subject_node,
                "group_key": str(group_key or ""),
            }
        )
    return rows


def _apply_runtime_shell_block_representative_trial(
    sorted_edges: list[dict[str, Any]],
    *,
    scenario_id: Optional[str],
    runtime_block_rows: list[dict[str, Any]],
    enabled: bool,
    target_relations: set[str],
    min_block_edge_count: int,
    min_overlap_ratio: float,
    process_fork_hybrid_gate: bool = False,
    process_fork_hybrid_min_overlap_ratio: float = (
        DEFAULT_RUNTIME_SHELL_BLOCK_PROCESS_FORK_HYBRID_MIN_OVERLAP_RATIO
    ),
    process_fork_hybrid_min_overlap_edges: int = (
        DEFAULT_RUNTIME_SHELL_BLOCK_PROCESS_FORK_HYBRID_MIN_OVERLAP_EDGES
    ),
    net_accept_subject_anchor_trial_view_stats: Optional[dict[str, Any]] = None,
) -> tuple[list[dict[str, Any]], dict[str, Any], list[str], list[dict[str, Any]]]:
    warnings: list[str] = []
    residual_rows: list[dict[str, Any]] = []
    pf_hybrid_ratio = float(
        max(0.0, min(1.0, process_fork_hybrid_min_overlap_ratio))
    )
    pf_hybrid_edges = int(max(1, process_fork_hybrid_min_overlap_edges))
    stats = {
        "requested": bool(enabled),
        "applied": False,
        "reason": "disabled",
        "target_relations": sorted(str(rel).upper() for rel in target_relations),
        "runtime_block_rows_total": int(len(runtime_block_rows)),
        "candidate_blocks_considered": 0,
        "triggered_blocks": 0,
        "min_block_edge_count": int(max(2, min_block_edge_count)),
        "min_overlap_ratio": float(max(0.0, min(1.0, min_overlap_ratio))),
        "dropped_total": 0,
        "dropped_relation_counts": {},
        "residual_row_count": 0,
        "selected_block_ids": [],
        "process_fork_hybrid_gate": {
            "enabled": bool(process_fork_hybrid_gate),
            "min_overlap_ratio": pf_hybrid_ratio,
            "min_overlap_edges": pf_hybrid_edges,
            "candidate_blocks": 0,
            "triggered_blocks": 0,
            "rejected_by_ratio": 0,
            "rejected_by_edges": 0,
        },
        "net_accept_subject_anchor_trial_view": dict(
            net_accept_subject_anchor_trial_view_stats or {"enabled": False}
        ),
    }

    if not enabled:
        return sorted_edges, stats, warnings, residual_rows

    normalized_target_relations = {
        str(relation).upper().strip()
        for relation in target_relations
        if str(relation).strip()
    }
    if not normalized_target_relations:
        stats["reason"] = "empty_target_relations"
        return sorted_edges, stats, warnings, residual_rows
    if not runtime_block_rows:
        stats["reason"] = "no_runtime_block_rows"
        return sorted_edges, stats, warnings, residual_rows

    backbone_edges_by_id = {
        str(edge.get("id") or ""): edge
        for edge in sorted_edges
        if str(edge.get("id") or "")
    }
    if not backbone_edges_by_id:
        stats["reason"] = "empty_backbone"
        return sorted_edges, stats, warnings, residual_rows

    first_malicious_evt, last_malicious_evt = _malicious_evt_bounds(sorted_edges)
    min_block_size = max(2, int(min_block_edge_count))
    min_overlap = max(0.0, min(1.0, float(min_overlap_ratio)))

    drop_edge_ids: set[str] = set()
    dropped_relation_counts: Counter[str] = Counter()
    selected_block_ids: list[str] = []
    candidate_blocks_considered = 0
    triggered_blocks = 0

    for block_row in runtime_block_rows:
        relation_counts = block_row.get("relation_family_counts")
        if not isinstance(relation_counts, dict):
            continue

        targeted_relation = None
        targeted_relation_count = 0
        targeted_edge_count = 0
        for raw_relation, raw_count in relation_counts.items():
            relation = str(raw_relation or "").upper()
            count_i = _safe_int(raw_count) or 0
            if relation not in normalized_target_relations:
                continue
            if count_i > 0:
                targeted_edge_count += count_i
            if count_i > targeted_relation_count:
                targeted_relation_count = count_i
                targeted_relation = relation

        if targeted_relation is None or targeted_edge_count <= 0:
            continue

        member_edge_ids = [
            str(edge_id)
            for edge_id in (block_row.get("edge_ids") or [])
            if str(edge_id or "")
        ]
        if not member_edge_ids:
            continue

        block_edge_count = _safe_int(block_row.get("edge_count")) or len(member_edge_ids)
        if block_edge_count < min_block_size:
            continue

        candidate_blocks_considered += 1

        overlap_edge_ids = [
            edge_id
            for edge_id in member_edge_ids
            if edge_id in backbone_edges_by_id
        ]
        if not overlap_edge_ids:
            continue

        overlap_ratio = (
            len(overlap_edge_ids) / block_edge_count
            if block_edge_count > 0
            else 0.0
        )

        is_process_fork_block = targeted_relation == "PROCESS_FORK"
        use_hybrid_gate_for_block = (
            process_fork_hybrid_gate and is_process_fork_block
        )

        if use_hybrid_gate_for_block:
            pf_hybrid_stats = stats["process_fork_hybrid_gate"]
            pf_hybrid_stats["candidate_blocks"] = int(
                pf_hybrid_stats.get("candidate_blocks") or 0
            ) + 1
            if overlap_ratio < pf_hybrid_ratio:
                pf_hybrid_stats["rejected_by_ratio"] = int(
                    pf_hybrid_stats.get("rejected_by_ratio") or 0
                ) + 1
                continue
            if len(overlap_edge_ids) < pf_hybrid_edges:
                pf_hybrid_stats["rejected_by_edges"] = int(
                    pf_hybrid_stats.get("rejected_by_edges") or 0
                ) + 1
                continue
            pf_hybrid_stats["triggered_blocks"] = int(
                pf_hybrid_stats.get("triggered_blocks") or 0
            ) + 1
        else:
            if overlap_ratio < min_overlap:
                continue

        representative_edge_ids = {
            str(edge_id)
            for edge_id in (block_row.get("representative_edge_ids") or [])
            if str(edge_id or "")
        }

        keep_edge_ids: set[str] = set()
        for edge_id in overlap_edge_ids:
            edge = backbone_edges_by_id.get(edge_id)
            if edge is None:
                continue
            if _edge_is_malicious(edge):
                keep_edge_ids.add(edge_id)
            if edge_id in representative_edge_ids:
                keep_edge_ids.add(edge_id)

        if not keep_edge_ids and overlap_edge_ids:
            keep_edge_ids.add(overlap_edge_ids[0])

        block_drop_ids: list[str] = []
        for edge_id in overlap_edge_ids:
            if edge_id in keep_edge_ids:
                continue
            edge = backbone_edges_by_id.get(edge_id)
            if edge is None:
                continue
            relation = str(edge.get("relation") or "").upper()
            if relation not in normalized_target_relations:
                continue
            if _edge_is_malicious(edge):
                continue
            block_drop_ids.append(edge_id)

        if not block_drop_ids:
            continue

        triggered_blocks += 1
        drop_edge_ids.update(block_drop_ids)
        selected_block_ids.append(str(block_row.get("block_id") or ""))

        kept_edges_sorted = sorted(
            [
                backbone_edges_by_id[edge_id]
                for edge_id in overlap_edge_ids
                if edge_id not in block_drop_ids and edge_id in backbone_edges_by_id
            ],
            key=_edge_position_sort_key,
        )
        dropped_edges_sorted = sorted(
            [
                backbone_edges_by_id[edge_id]
                for edge_id in block_drop_ids
                if edge_id in backbone_edges_by_id
            ],
            key=_edge_position_sort_key,
        )

        for edge in dropped_edges_sorted:
            dropped_relation_counts[str(edge.get("relation") or "").upper()] += 1

        overlap_edges_sorted = sorted(
            [
                backbone_edges_by_id[edge_id]
                for edge_id in overlap_edge_ids
                if edge_id in backbone_edges_by_id
            ],
            key=_edge_position_sort_key,
        )
        overlap_evt_values = [
            evt
            for evt in (_edge_evt_num_optional(edge) for edge in overlap_edges_sorted)
            if evt is not None
        ]
        start_evt_num = _safe_int(block_row.get("evt_start"))
        end_evt_num = _safe_int(block_row.get("evt_end"))
        if start_evt_num is None and overlap_evt_values:
            start_evt_num = min(overlap_evt_values)
        if end_evt_num is None and overlap_evt_values:
            end_evt_num = max(overlap_evt_values)

        stage_hint = _summarize_refinement_stage_hint(
            start_evt_num,
            end_evt_num,
            first_malicious_evt=first_malicious_evt,
            last_malicious_evt=last_malicious_evt,
        )

        representative_edges: list[dict[str, Any]] = []
        for edge in kept_edges_sorted[:8]:
            representative_edges.append(
                {
                    "edge_id": str(edge.get("id") or ""),
                    "evt_num": _edge_evt_num_optional(edge),
                    "relation": str(edge.get("relation") or ""),
                    "subject": str(edge.get("subject") or ""),
                    "object": str(edge.get("object") or ""),
                    "kept_in_backbone": True,
                }
            )

        malicious_overlap_count = sum(1 for edge in overlap_edges_sorted if _edge_is_malicious(edge))
        residual_rows.append(
            {
                "schema_version": REFINEMENT_RESIDUAL_SCHEMA_VERSION,
                "residual_id": (
                    f"{scenario_id or 'scenario'}::runtime_shell_block_trial::"
                    f"{_stable_short_digest([block_row.get('block_id'), targeted_relation, start_evt_num, end_evt_num])}"
                ),
                "source": "backbone_runtime_shell_block_trial",
                "relation_family": targeted_relation,
                "window": {
                    "start_evt_num": start_evt_num,
                    "end_evt_num": end_evt_num,
                },
                "anchor_backbone_edge_ids": [
                    str(edge.get("id") or "")
                    for edge in kept_edges_sorted[:8]
                    if str(edge.get("id") or "")
                ],
                "summary": {
                    "original_count": len(overlap_edge_ids),
                    "kept_count": len(kept_edges_sorted),
                    "dropped_count": len(dropped_edges_sorted),
                    "malicious_count": malicious_overlap_count,
                    "non_malicious_count": len(overlap_edge_ids) - malicious_overlap_count,
                },
                "representative_edges": representative_edges,
                "stage_hint": stage_hint,
                "why_retained": [
                    "runtime_shell_block_representative_trial",
                    f"target_relation={targeted_relation}",
                    stage_hint,
                ],
                "narrative_role": "runtime_shell_summary",
                "backbone_priority": "residual_preferred",
                "shell_origin_hint": "runtime_shell_block_intrusion",
                "subject": str(block_row.get("subject_key") or ""),
                "group_key": str(block_row.get("block_id") or ""),
                "block_overlap_ratio_before": round(overlap_ratio, 6),
                "dropped_edge_ids": [str(edge.get("id") or "") for edge in dropped_edges_sorted],
                "kept_representative_edge_ids": [
                    str(edge.get("id") or "")
                    for edge in kept_edges_sorted
                    if str(edge.get("id") or "")
                ],
            }
        )

    stats["candidate_blocks_considered"] = int(candidate_blocks_considered)
    stats["triggered_blocks"] = int(triggered_blocks)

    if not drop_edge_ids:
        stats["reason"] = "no_matching_intrusive_blocks"
        return sorted_edges, stats, warnings, residual_rows

    if len(drop_edge_ids) >= len(sorted_edges):
        stats["reason"] = "unsafe_full_backbone_drop"
        warnings.append(
            "runtime shell block representative trial aborted: drop set would empty backbone"
        )
        return sorted_edges, stats, warnings, []

    dropped_total = 0
    write_idx = 0
    for read_idx, edge in enumerate(sorted_edges):
        edge_id = str(edge.get("id") or "")
        if edge_id in drop_edge_ids:
            dropped_total += 1
            continue
        if write_idx != read_idx:
            sorted_edges[write_idx] = edge
        write_idx += 1

    if write_idx < len(sorted_edges):
        del sorted_edges[write_idx:]

    if dropped_total <= 0:
        stats["reason"] = "no_effective_drop"
        return sorted_edges, stats, warnings, []

    stats["applied"] = True
    stats["reason"] = "runtime_shell_block_overlap_triggered"
    stats["dropped_total"] = int(dropped_total)
    stats["dropped_relation_counts"] = dict(sorted(dropped_relation_counts.items()))
    stats["residual_row_count"] = int(len(residual_rows))
    stats["selected_block_ids"] = [block_id for block_id in selected_block_ids if block_id][:32]

    warnings.append(
        "runtime shell block representative trial dropped "
        f"{dropped_total} non-malicious edges from targeted runtime shell blocks"
    )
    return sorted_edges, stats, warnings, residual_rows


def _apply_preparation_shell_trial(
    sorted_edges: list[dict[str, Any]],
    *,
    scenario_id: Optional[str],
    enabled: bool,
    planner_trigger_info: Optional[dict[str, Any]],
    first_malicious_evt_num: Optional[int],
    malicious_process_nodes: set[str],
) -> tuple[list[dict[str, Any]], dict[str, Any], list[str], list[dict[str, Any]]]:
    """Trial D executor: collapse preparation-phase startup shell on one
    qualifying subject down to a small set of boundary markers.

    Strictly orthogonal to A/B/C:
      * Only operates on PROCESS_FORK + PROCESS_EXEC edges from the subject
        named in ``planner_trigger_info`` (when trigger=True).
      * Only considers edges with ``evt_num < first_malicious_evt_num``.
      * Only touches edges whose ``object`` (child process) is not in
        ``malicious_process_nodes`` (child-bridge safety net).
      * Retention budget is ``PREPARATION_SHELL_MAX_KEEP``.

    When ``enabled`` is False, returns input unchanged and records
    ``applied=False`` in stats.
    """
    warnings: list[str] = []
    residual_rows: list[dict[str, Any]] = []
    stats: dict[str, Any] = {
        "requested": bool(enabled),
        "applied": False,
        "reason": "disabled",
        "planner_trigger": bool(
            (planner_trigger_info or {}).get("trigger", False)
        ),
        "selected_subject": None,
        "candidate_subjects": int(
            ((planner_trigger_info or {}).get("metrics") or {}).get(
                "candidate_subjects_qualified", 0
            )
        ),
        "candidate_edges": 0,
        "kept_edges": 0,
        "kept_edge_ids": [],
        "collapsed_edges": 0,
        "residual_written": 0,
        "max_keep": int(PREPARATION_SHELL_MAX_KEEP),
        "first_malicious_evt_num": (
            int(first_malicious_evt_num)
            if isinstance(first_malicious_evt_num, int)
            else None
        ),
        # Handoff-EXEC observability (filled in only when D actually runs
        # to completion; kept here so the field set is stable across the
        # disabled / early-exit / success branches).
        "handoff_exec_found": False,
        "handoff_exec_kept": False,
        "handoff_exec_edge_id": None,
        "handoff_exec_evt_num": None,
        "handoff_exec_object": None,
        # Role annotation for each kept anchor. Populated by the
        # retention sequence when D executes. Empty list on the
        # disabled / early-exit branches so the schema is stable.
        "kept_anchor_roles": [],
    }

    if not enabled:
        return sorted_edges, stats, warnings, residual_rows
    if planner_trigger_info is None or not planner_trigger_info.get("trigger"):
        stats["reason"] = "planner_trigger_false"
        return sorted_edges, stats, warnings, residual_rows
    if first_malicious_evt_num is None:
        stats["reason"] = "no_first_malicious_evt_num"
        return sorted_edges, stats, warnings, residual_rows
    try:
        fmal = int(first_malicious_evt_num)
    except (TypeError, ValueError):
        stats["reason"] = "first_malicious_evt_num_not_int"
        return sorted_edges, stats, warnings, residual_rows

    metrics = planner_trigger_info.get("metrics") or {}
    subject = metrics.get("top_subject")
    if not subject:
        stats["reason"] = "no_top_subject"
        return sorted_edges, stats, warnings, residual_rows
    stats["selected_subject"] = str(subject)

    # Collect D-cluster edges belonging to the chosen subject in pre-malicious
    # window, and the first post-malicious edge from the same subject (to
    # infer the "entry-anchor bridge" retention candidate).
    d_cluster: list[dict[str, Any]] = []
    first_post_mal_same_subject: Optional[dict[str, Any]] = None
    first_post_mal_evt: Optional[int] = None

    for edge in sorted_edges:
        relation = str(edge.get("relation") or "").upper()
        subj = _edge_primary_process_key(edge)
        if subj != subject:
            continue
        evt_num = _edge_evt_num_optional(edge)
        if evt_num is None:
            continue
        attrs = edge.get("attrs") or {}
        is_mal = bool(attrs.get("malicious", False))
        if relation in ("PROCESS_FORK", "PROCESS_EXEC") and evt_num < fmal:
            if relation == "PROCESS_FORK":
                obj = str(edge.get("object") or "")
                if obj in malicious_process_nodes:
                    # Child-bridge safety net: never demote an edge whose
                    # child is malicious. Leave it in main backbone.
                    continue
            if is_mal:
                # Defensive: never demote an edge flagged malicious, even if
                # its evt_num sits before the declared first_malicious.
                continue
            d_cluster.append(edge)
        elif evt_num >= fmal:
            if first_post_mal_evt is None or evt_num < first_post_mal_evt:
                first_post_mal_evt = evt_num
                first_post_mal_same_subject = edge

    stats["candidate_edges"] = int(len(d_cluster))
    if not d_cluster:
        stats["reason"] = "no_candidate_edges"
        return sorted_edges, stats, warnings, residual_rows

    # Order by (evt_num, id) so "first/last" are evt-num boundaries.
    d_cluster.sort(
        key=lambda e: (_edge_evt_num_optional(e) or 0, str(e.get("id") or ""))
    )

    # ---- Locate startup-handoff PROCESS_EXEC (if any) -------------------
    # A "handoff EXEC" is the latest (largest evt_num) pre-window
    # PROCESS_EXEC in d_cluster whose target executable is NOT the
    # subject's own exe. Semantically it marks "startup shell hands
    # program control over to the real server process" (e.g. bash → java).
    # Self-re-exec (bash → bash) is excluded because it carries no handoff.
    try:
        subject_self_exe = str(subject).split(":", 3)[3]
    except IndexError:
        subject_self_exe = ""
    handoff_exec_edge: Optional[dict[str, Any]] = None
    for _e in reversed(d_cluster):
        if str(_e.get("relation") or "").upper() != "PROCESS_EXEC":
            continue
        _obj = str(_e.get("object") or "")
        if _obj.startswith("file:"):
            _tgt_path = _obj[len("file:"):]
        elif _obj.startswith("proc:"):
            _parts = _obj.split(":", 3)
            _tgt_path = _parts[3] if len(_parts) >= 4 else ""
        else:
            _tgt_path = _obj
        if subject_self_exe and _tgt_path == subject_self_exe:
            continue
        handoff_exec_edge = _e
        break
    stats["handoff_exec_found"] = handoff_exec_edge is not None
    stats["handoff_exec_edge_id"] = (
        str(handoff_exec_edge.get("id") or "") if handoff_exec_edge else None
    )
    stats["handoff_exec_evt_num"] = (
        _edge_evt_num_optional(handoff_exec_edge) if handoff_exec_edge else None
    )
    stats["handoff_exec_object"] = (
        str(handoff_exec_edge.get("object") or "") if handoff_exec_edge else None
    )
    stats["handoff_exec_kept"] = False  # updated after retention finalises

    # Build retention set with a priority-ordered budget.
    # ``kept_anchor_roles`` records, for each retained edge, the retention
    # rule that caused it to be kept. This exposes the implicit "attack
    # story" role of each kept anchor to downstream consumers (narrative,
    # dataset, analysts) without changing what is retained. The role
    # vocabulary is purely structural -- it comes from D's retention rules
    # and does not depend on scenario_id, exe name, or product stack.
    keep_ids: list[str] = []
    keep_seen: set[str] = set()
    kept_anchor_roles: list[dict[str, Any]] = []

    def _retain(edge: Optional[dict[str, Any]], role: str) -> None:
        if edge is None:
            return
        edge_id = str(edge.get("id") or "")
        if not edge_id or edge_id in keep_seen:
            return
        if len(keep_ids) >= PREPARATION_SHELL_MAX_KEEP:
            return
        keep_seen.add(edge_id)
        keep_ids.append(edge_id)
        kept_anchor_roles.append({
            "edge_id": edge_id,
            "role": role,
            "evt_num": _edge_evt_num_optional(edge),
            "relation": str(edge.get("relation") or ""),
            "object": str(edge.get("object") or ""),
        })

    # 1. cluster start edge ("preparation phase begins")
    _retain(d_cluster[0], "preparation_boundary_start")
    # 2. cluster end edge ("preparation phase ends, closest to first_mal")
    _retain(d_cluster[-1], "preparation_boundary_end")
    # 3. startup-handoff PROCESS_EXEC ("control handed to the server
    #    process"). When present this carries stronger "preparation →
    #    execution" semantics than a generic mid-span PF sample, so it
    #    gets the 3rd budget slot. When absent, falls through to the
    #    entry-anchor bridge plus optional mid-span like before.
    _retain(handoff_exec_edge, "startup_handoff_exec")
    # 4. entry-anchor bridge: pre edge closest to the first post-malicious
    #    same-subject edge (or to first_malicious_evt_num when absent). This
    #    guarantees the backbone keeps the causal link between preparation
    #    and execution phases even when step 2's last edge is not a direct
    #    predecessor of an anchor.
    target_bridge = (
        _edge_evt_num_optional(first_post_mal_same_subject)
        if first_post_mal_same_subject is not None
        else fmal
    )
    if target_bridge is not None:
        bridge = _pick_candidate_by_position(
            d_cluster, mode="last_before", target_evt=target_bridge
        )
        _retain(bridge, "entry_bridge_pre")
    # 5. optional mid-span representative when the cluster spans a very large
    #    evt window (at least 2x the threshold) AND there is still budget.
    #    In practice this slot fills in when entry_bridge_pre deduplicates
    #    against cluster_end (happens whenever the last pre-window edge is
    #    already the immediate predecessor of the first malicious edge),
    #    or when no handoff EXEC squeezed it out.
    if len(keep_ids) < PREPARATION_SHELL_MAX_KEEP and len(d_cluster) >= 3:
        first_evt = _edge_evt_num_optional(d_cluster[0]) or 0
        last_evt = _edge_evt_num_optional(d_cluster[-1]) or 0
        if (last_evt - first_evt) >= (2 * PLANNER_D_MIN_PRE_EVT_SPAN):
            _retain(
                _pick_candidate_by_position(d_cluster, mode="middle"),
                "mid_span_representative",
            )

    stats["kept_anchor_roles"] = kept_anchor_roles

    if handoff_exec_edge is not None:
        stats["handoff_exec_kept"] = (
            str(handoff_exec_edge.get("id") or "") in keep_seen
        )

    keep_set = set(keep_ids)
    dropped_ids: set[str] = set()
    kept_cluster_edges: list[dict[str, Any]] = []
    dropped_cluster_edges: list[dict[str, Any]] = []
    for edge in d_cluster:
        edge_id = str(edge.get("id") or "")
        if edge_id in keep_set:
            kept_cluster_edges.append(edge)
        else:
            dropped_cluster_edges.append(edge)
            if edge_id:
                dropped_ids.add(edge_id)

    if not dropped_ids:
        stats["applied"] = False
        stats["reason"] = "no_effective_drop"
        stats["kept_edges"] = int(len(kept_cluster_edges))
        stats["kept_edge_ids"] = [str(e.get("id") or "") for e in kept_cluster_edges]
        return sorted_edges, stats, warnings, residual_rows

    # Defensive: never drop the only remaining edges in backbone.
    if len(dropped_ids) >= len(sorted_edges):
        stats["applied"] = False
        stats["reason"] = "would_empty_backbone_aborted"
        warnings.append(
            "preparation shell trial aborted: would remove all backbone edges"
        )
        return sorted_edges, stats, warnings, residual_rows

    # In-place removal preserving order.
    write_idx = 0
    for read_idx, edge in enumerate(sorted_edges):
        edge_id = str(edge.get("id") or "")
        if edge_id in dropped_ids:
            continue
        if write_idx != read_idx:
            sorted_edges[write_idx] = edge
        write_idx += 1
    if write_idx < len(sorted_edges):
        del sorted_edges[write_idx:]

    # Build a single residual row describing the collapsed cluster. Schema
    # mirrors _build_refinement_residual_rows so downstream consumers
    # (backbone_refinement_residual exporter) see a familiar shape.
    evt_values = [
        _edge_evt_num_optional(e)
        for e in dropped_cluster_edges
        if _edge_evt_num_optional(e) is not None
    ]
    stage_hint = _summarize_refinement_stage_hint(
        min(evt_values) if evt_values else None,
        max(evt_values) if evt_values else None,
        first_malicious_evt=fmal,
        last_malicious_evt=None,
    )
    representative_edges: list[dict[str, Any]] = []
    rep_seen: set[str] = set()
    for mode in ("first", "middle", "last"):
        rep = _pick_candidate_by_position(dropped_cluster_edges, mode=mode)
        rep_id = str((rep or {}).get("id") or "")
        if rep is None or not rep_id or rep_id in rep_seen:
            continue
        rep_seen.add(rep_id)
        representative_edges.append(
            {
                "edge_id": rep_id,
                "evt_num": _edge_evt_num_optional(rep),
                "relation": str(rep.get("relation") or ""),
                "subject": str(rep.get("subject") or ""),
                "object": str(rep.get("object") or ""),
                "kept_in_backbone": False,
            }
        )

    residual_rows.append(
        {
            "schema_version": REFINEMENT_RESIDUAL_SCHEMA_VERSION,
            "residual_id": (
                f"{scenario_id or 'scenario'}::backbone_refinement::"
                f"preparation_shell::1"
            ),
            "source": "backbone_refinement",
            "relation_family": "PROCESS_FORK",
            "window": {
                "start_evt_num": min(evt_values) if evt_values else None,
                "end_evt_num": max(evt_values) if evt_values else None,
            },
            "anchor_backbone_edge_ids": list(keep_ids),
            "summary": {
                "original_count": int(
                    len(kept_cluster_edges) + len(dropped_cluster_edges)
                ),
                "kept_count": int(len(kept_cluster_edges)),
                "dropped_count": int(len(dropped_cluster_edges)),
                "malicious_count": 0,
                "non_malicious_count": int(
                    len(kept_cluster_edges) + len(dropped_cluster_edges)
                ),
            },
            "representative_edges": representative_edges,
            "stage_hint": stage_hint,
            "why_retained": [
                "preparation_boundary_markers",
                "pre_execution_entry_bridge",
                stage_hint,
            ],
            "narrative_role": "preparation_shell_summary",
            "backbone_priority": "residual_preferred",
            "shell_origin_hint": "pre_malicious_startup_shell",
            "subject": str(subject),
            "group_key": f"preparation_shell::{subject}",
            "refinement_residual_reason": "preparation_shell_trial_collapsed",
            "refinement_residual_trial": "preparation_shell",
        }
    )

    stats["applied"] = True
    stats["reason"] = "preparation_shell_collapsed"
    stats["collapsed_edges"] = int(len(dropped_cluster_edges))
    stats["kept_edges"] = int(len(kept_cluster_edges))
    stats["kept_edge_ids"] = [str(e.get("id") or "") for e in kept_cluster_edges]
    stats["residual_written"] = int(len(residual_rows))
    warnings.append(
        "preparation shell trial collapsed "
        f"{len(dropped_cluster_edges)} pre-malicious edges from subject "
        f"{subject}; kept {len(kept_cluster_edges)} boundary markers"
    )
    return sorted_edges, stats, warnings, residual_rows


def _build_backbone_expression_clarity_summary(
    edge_sequence: list[dict[str, Any]],
) -> dict[str, Any]:
    total_edges = len(edge_sequence)
    malicious_edges = [
        edge for edge in edge_sequence
        if _edge_is_malicious(edge)
    ]
    if not malicious_edges:
        expression = {
            "has_malicious_anchor": False,
            "first_malicious_seq": None,
            "last_malicious_seq": None,
            "first_malicious_evt_num": None,
            "last_malicious_evt_num": None,
            "entry_anchor_relation": None,
            "entry_anchor_family": None,
            "result_anchor_relation": None,
            "result_anchor_family": None,
            "result_anchor_result_like": False,
            "malicious_span_edge_count": 0,
            "malicious_span_ratio": 0.0,
            "malicious_span_malicious_density": 0.0,
            "pre_malicious_shell_edge_count": total_edges,
            "pre_malicious_shell_ratio": 1.0 if total_edges else 0.0,
            "post_malicious_shell_edge_count": 0,
            "post_malicious_shell_ratio": 0.0,
            "result_tail_edge_count": 0,
            "result_tail_ratio": 0.0,
        }
        expression["semantic_readiness"] = _build_backbone_semantic_readiness(expression)
        return expression

    first_edge = malicious_edges[0]
    last_edge = malicious_edges[-1]
    first_seq = int(first_edge.get("seq") or 0)
    last_seq = int(last_edge.get("seq") or 0)
    span_edge_count = max(last_seq - first_seq + 1, 0)
    malicious_span_malicious_density = 0.0
    if span_edge_count > 0:
        malicious_span_malicious_density = round(len(malicious_edges) / span_edge_count, 6)
    pre_shell_count = max(first_seq - 1, 0)
    post_shell_count = max(total_edges - last_seq, 0)
    result_tail_edge_count = max(total_edges - last_seq + 1, 0)

    last_relation = str(last_edge.get("relation") or "").upper()
    expression = {
        "has_malicious_anchor": True,
        "first_malicious_seq": first_seq,
        "last_malicious_seq": last_seq,
        "first_malicious_evt_num": _edge_evt_num_optional(first_edge),
        "last_malicious_evt_num": _edge_evt_num_optional(last_edge),
        "entry_anchor_relation": str(first_edge.get("relation") or ""),
        "entry_anchor_family": _edge_relation_family(str(first_edge.get("relation") or "")),
        "result_anchor_relation": str(last_edge.get("relation") or ""),
        "result_anchor_family": _edge_relation_family(last_relation),
        "result_anchor_result_like": last_relation in BACKBONE_RESULT_RELATIONS,
        "malicious_span_edge_count": span_edge_count,
        "malicious_span_ratio": round(span_edge_count / total_edges, 6) if total_edges else 0.0,
        "malicious_span_malicious_density": malicious_span_malicious_density,
        "pre_malicious_shell_edge_count": pre_shell_count,
        "pre_malicious_shell_ratio": round(pre_shell_count / total_edges, 6) if total_edges else 0.0,
        "post_malicious_shell_edge_count": post_shell_count,
        "post_malicious_shell_ratio": round(post_shell_count / total_edges, 6) if total_edges else 0.0,
        "result_tail_edge_count": result_tail_edge_count,
        "result_tail_ratio": round(result_tail_edge_count / total_edges, 6) if total_edges else 0.0,
    }
    expression["semantic_readiness"] = _build_backbone_semantic_readiness(expression)
    return expression


def _annotate_backbone_narrative_roles(
    edge_sequence: list[dict[str, Any]],
    expression_clarity: dict[str, Any],
    preparation_shell_trial_stats: Optional[dict[str, Any]],
) -> dict[str, Any]:
    """Externalise narrative roles onto retained backbone edges.

    Motivation
    ----------
    Before this pass, preparation-side role information only lives inside
    ``preparation_shell_trial.kept_anchor_roles`` (a stats sub-tree); the
    actual kept edges in ``edge_sequence`` carry no role marker. On the
    result side even this indirection is missing -- ``first_malicious_seq``
    and ``last_malicious_seq`` are only summary coordinates, and the two
    key edges (attack entry and result) are not labelled at all. Reading
    the backbone as "preparation -> handoff -> execution -> result"
    therefore requires cross-referencing several sub-trees.

    This pass attaches a structural ``narrative_role`` on each qualifying
    edge using two sources:

    1. Trial D kept_anchor_roles (preparation side). Copied verbatim so
       the roles D already assigned (preparation_boundary_start / _end,
       startup_handoff_exec, entry_bridge_pre, mid_span_representative)
       become visible on the actual edges, not just in D's stats block.

    2. Structural rules over ``edge_sequence`` (execution / result side):
         - ``semantic_entry_anchor``: the first malicious edge.
         - ``result_anchor``: the last malicious edge.
         - ``result_tail_context``: the first non-malicious edge following
           ``result_anchor`` within ``BACKBONE_NARRATIVE_RESULT_TAIL_SEQ_WINDOW``
           whose relation is in ``BACKBONE_RESULT_RELATIONS`` and whose
           subject matches the result_anchor's subject. This captures an
           immediate follow-on effect of the attack (e.g. subsequent
           write / exec / send by the same actor) without relying on
           malicious flags or scenario knowledge.

    Collision handling
    ------------------
    When a single edge qualifies for more than one role (e.g. the attack
    is a single malicious edge so entry == result), the first-tagged role
    stays as primary, and any additional roles are appended to
    ``narrative_role_alt`` so information is preserved. Tag order is:
    preparation (D) -> result_anchor -> semantic_entry_anchor ->
    result_tail_context. ``result_anchor`` runs before
    ``semantic_entry_anchor`` so that single-malicious-edge cases are
    primarily labelled as the story climax, which matches how narrative
    readers anchor on the attack's result.

    Purity
    ------
    No scenario / product / exe name is ever consulted. All decisions
    are functions of: ``malicious`` attr, ``relation``, ``subject``,
    ``seq``, and D's own kept_anchor_roles output.
    """
    role_log: list[dict[str, Any]] = []
    role_to_seqs: dict[str, list[int]] = {}
    # ``roles_any`` tracks every role that ends up on the backbone either
    # as a primary ``narrative_role`` or inside ``narrative_role_alt``.
    # Summary flags (has_*, story_phase_coverage) are computed from this
    # set so a role preserved only in alt still counts as "present",
    # which is what downstream story-coverage checks actually want to
    # know -- they ask "is this narrative phase covered by some edge?",
    # not "is any edge _primarily_ this role?".
    roles_any: set[str] = set()

    def _tag(edge: dict[str, Any], role: str, *, allow_alt: bool = True) -> None:
        """Assign ``role`` on ``edge``. Collisions fall through to alt list."""
        if role not in BACKBONE_NARRATIVE_ROLE_VOCABULARY:
            return
        current = edge.get("narrative_role")
        if current == role:
            return
        if current:
            if not allow_alt:
                return
            alt = edge.setdefault("narrative_role_alt", [])
            if isinstance(alt, list) and role not in alt:
                alt.append(role)
                roles_any.add(role)
            return
        edge["narrative_role"] = role
        roles_any.add(role)
        role_log.append(
            {
                "seq": int(edge.get("seq") or 0),
                "edge_id": str(edge.get("edge_id") or ""),
                "role": role,
                "relation": str(edge.get("relation") or ""),
                "evt_num": _edge_evt_num_optional(edge),
                "subject": str(edge.get("subject") or ""),
                "object": str(edge.get("object") or ""),
                "malicious": bool((edge.get("attrs") or {}).get("malicious", False)),
            }
        )
        role_to_seqs.setdefault(role, []).append(int(edge.get("seq") or 0))

    # ---- 1. Preparation-side roles: copy from Trial D if it applied ------
    edge_by_id: dict[str, dict[str, Any]] = {
        str(e.get("edge_id") or ""): e for e in edge_sequence
    }
    prep_stats = preparation_shell_trial_stats or {}
    prep_applied = bool(prep_stats.get("applied"))
    prep_roles_mapped = 0
    if prep_applied:
        for anchor in prep_stats.get("kept_anchor_roles") or []:
            if not isinstance(anchor, dict):
                continue
            edge_id = str(anchor.get("edge_id") or "")
            role = str(anchor.get("role") or "")
            if not edge_id or role not in BACKBONE_NARRATIVE_ROLE_VOCABULARY:
                continue
            target = edge_by_id.get(edge_id)
            if target is None:
                continue
            _tag(target, role, allow_alt=False)
            prep_roles_mapped += 1

    # ---- 2. Result / entry anchors from expression_clarity --------------
    first_mal_seq = expression_clarity.get("first_malicious_seq")
    last_mal_seq = expression_clarity.get("last_malicious_seq")

    entry_anchor_edge: Optional[dict[str, Any]] = None
    result_anchor_edge: Optional[dict[str, Any]] = None
    if isinstance(first_mal_seq, int) and 1 <= first_mal_seq <= len(edge_sequence):
        entry_anchor_edge = edge_sequence[first_mal_seq - 1]
    if isinstance(last_mal_seq, int) and 1 <= last_mal_seq <= len(edge_sequence):
        result_anchor_edge = edge_sequence[last_mal_seq - 1]

    # Tag result first so single-malicious-edge scenarios primarily read
    # as "result_anchor" (attack climax); semantic_entry_anchor goes into
    # narrative_role_alt in that degenerate case.
    if result_anchor_edge is not None:
        _tag(result_anchor_edge, "result_anchor")
    if entry_anchor_edge is not None:
        _tag(entry_anchor_edge, "semantic_entry_anchor")

    # ---- 3. result_tail_context -----------------------------------------
    result_tail_edge: Optional[dict[str, Any]] = None
    result_tail_reason = "no_result_anchor"
    if result_anchor_edge is not None:
        anchor_subject = str(result_anchor_edge.get("subject") or "")
        anchor_seq = int(result_anchor_edge.get("seq") or 0)
        limit = anchor_seq + BACKBONE_NARRATIVE_RESULT_TAIL_SEQ_WINDOW
        result_tail_reason = "no_matching_tail_edge_in_window"
        # edge_sequence is 1-based via .get("seq"); index anchor_seq in
        # the 0-based list is the edge immediately after the anchor.
        for edge in edge_sequence[anchor_seq:]:
            seq = int(edge.get("seq") or 0)
            if seq <= anchor_seq:
                continue
            if seq > limit:
                break
            if bool((edge.get("attrs") or {}).get("malicious", False)):
                continue
            rel = str(edge.get("relation") or "").upper()
            if rel not in BACKBONE_RESULT_RELATIONS:
                continue
            if str(edge.get("subject") or "") != anchor_subject:
                continue
            result_tail_edge = edge
            result_tail_reason = "matched"
            break
    if result_tail_edge is not None:
        _tag(result_tail_edge, "result_tail_context")

    role_counts: dict[str, int] = {
        role: len(seqs) for role, seqs in sorted(role_to_seqs.items())
    }

    summary = {
        "vocabulary": list(BACKBONE_NARRATIVE_ROLE_VOCABULARY),
        "result_tail_seq_window": BACKBONE_NARRATIVE_RESULT_TAIL_SEQ_WINDOW,
        "annotated_edge_count": int(len(role_log)),
        "role_counts": role_counts,
        "roles_present": sorted(roles_any),
        "preparation_roles_mapped_from_trial_d": int(prep_roles_mapped),
        "has_semantic_entry_anchor": "semantic_entry_anchor" in roles_any,
        "has_result_anchor": "result_anchor" in roles_any,
        "has_result_tail_context": "result_tail_context" in roles_any,
        "entry_anchor_seq": (
            int(first_mal_seq) if isinstance(first_mal_seq, int) else None
        ),
        "result_anchor_seq": (
            int(last_mal_seq) if isinstance(last_mal_seq, int) else None
        ),
        "result_tail_reason": result_tail_reason,
        # Story-coverage summary: which of the four narrative phases
        # currently have at least one role-tagged representative edge
        # (primary OR alt role).
        "story_phase_coverage": {
            "preparation": prep_applied and prep_roles_mapped > 0,
            "handoff": "startup_handoff_exec" in roles_any,
            "execution_entry": "semantic_entry_anchor" in roles_any,
            "result": "result_anchor" in roles_any,
        },
        "annotated_edges": role_log,
    }
    return summary


# ---------------------------------------------------------------------------
# Conditional-triggered backbone refinement planner (A / B / C)
#
# The planner inspects the candidate edge list (pre-refinement) plus runtime
# malicious-process anchors, detects which structural problems are present,
# and decides whether to auto-enable:
#   A = NET_ACCEPT subject-level anchor trial (fragmented single-edge conns)
#   B = PROCESS_FORK hybrid overlap gate (gray-area big blocks)
#   C = PROCESS_FORK parent-cluster representative trial (wide-span shells
#       that touch the malicious process set)
#
# It is a pure function: no IO, no mutation of inputs. Output is written to
# chain_summary.refinement_plan by derive_backbone_chain.
# ---------------------------------------------------------------------------

# Planner triggering thresholds. Conservative by design: when signals are
# ambiguous, planner keeps the trial OFF and lets users opt in via explicit
# CLI flags (which are recorded as user_overrides and take precedence).
PLANNER_NET_ACCEPT_MIN_TOTAL = 20
PLANNER_NET_ACCEPT_SIZE1_RATIO = 0.60
PLANNER_NET_ACCEPT_SUBJECT_COLLAPSE_X = 3.0

PLANNER_PF_B_MIN_BLOCK_EDGES = (
    DEFAULT_RUNTIME_SHELL_BLOCK_PROCESS_FORK_HYBRID_MIN_OVERLAP_EDGES
)
PLANNER_PF_B_MIN_MAL_FRACTION = 0.05
PLANNER_PF_B_MAX_MAL_FRACTION = 1.0  # strictly less than (pure-malicious skipped)

PLANNER_PF_C_MIN_SUBJECT_NONMAL_EDGES = 8
PLANNER_PF_C_MIN_EVT_SPAN = 5000

# ---- Trial D: preparation-phase startup shell ----
# Trial D targets single-subject PROCESS_FORK/PROCESS_EXEC bursts that happen
# BEFORE first_malicious_evt_num, where NONE of the forked children belong
# to the malicious process set. This is mechanically exclusive with C
# (C: pf_malicious_children >= 1; D: pf_malicious_children == 0) so the
# two trials never contend for the same edges.
PLANNER_D_MIN_PRE_FORK_EDGES = 20
PLANNER_D_MIN_PRE_SHELL_RATIO = 0.5
PLANNER_D_MIN_PRE_EVT_SPAN = 50000
# Subject-level startup-shell discriminator (added to tighten D precision
# after Trial-D smoke observations showed that a pure PROCESS_FORK burst
# by a long-lived server process -- e.g. a JVM doing thread/worker warmup
# -- can otherwise look identical to a genuine startup shell. A real
# startup shell is structurally defined by at least one program handoff
# (execve); requiring pre_exec_edges >= 1 keeps solr-class bash warmups
# and rejects geoserver-class JVM-only fork bursts without introducing
# any name-based or scenario-specific rule.
PLANNER_D_MIN_PRE_EXEC_EDGES = 1
PREPARATION_SHELL_MAX_KEEP = 4
# Adaptive-candidate default rollout for Trial D.
#
# D has converged through: (a) planner trigger narrowing via
# PLANNER_D_MIN_PRE_EXEC_EDGES (geoserver-class pure-PF bursts stably
# excluded); (b) executor upgrade to preserve the startup-handoff
# PROCESS_EXEC as an explicit kept anchor. On the current scenario pool
# solr 4/4 trigger correctly, geoserver 2/2 correctly excluded, and
# mongo/pgadmin/ofbiz/kibana/joomla/adminer/cmsms/gitlist/metabase
# 19 scenarios show no false trigger and no backbone / anchor / attach
# regression. D is now promoted into the default adaptive-candidate
# path.
#
# Opt-out: set this constant to False for regression / A-B diffing.
# The CLI flag --backbone-preparation-shell-trial is still honoured as
# an explicit user override on top of the default.
ADAPTIVE_DEFAULT_INCLUDES_D = True


def _planner_collect_malicious_anchors(
    sorted_edges: list[dict[str, Any]],
) -> tuple[set[str], list[int]]:
    """Scan candidate edges once for malicious-process nodes and evt_nums.

    Mirrors the logic inside _apply_backbone_broad_gate so the planner can
    evaluate C without waiting for the broad gate to run.
    """
    mal_process_nodes: set[str] = set()
    mal_evt_nums: list[int] = []
    for edge in sorted_edges:
        attrs = edge.get("attrs") or {}
        if not bool(attrs.get("malicious", False)):
            continue
        try:
            mal_evt_nums.append(int(attrs.get("evt_num")))
        except Exception:
            pass
        subj = str(edge.get("subject") or "")
        obj = str(edge.get("object") or "")
        if subj.startswith("proc:"):
            mal_process_nodes.add(subj)
        if obj.startswith("proc:"):
            mal_process_nodes.add(obj)
    return mal_process_nodes, sorted(mal_evt_nums)


def _planner_evaluate_net_accept(
    sorted_edges: list[dict[str, Any]],
) -> dict[str, Any]:
    """Compute A-trigger evidence: NET_ACCEPT fragmentation at subject+conn."""
    conn_groups: Counter = Counter()
    subject_groups: set[str] = set()
    total = 0
    for edge in sorted_edges:
        if str(edge.get("relation") or "").upper() != "NET_ACCEPT":
            continue
        if bool((edge.get("attrs") or {}).get("malicious", False)):
            continue
        subj = _edge_primary_process_key(edge)
        if subj is None:
            continue
        total += 1
        conn = _edge_primary_conn_key(edge)
        conn_groups[(subj, conn if conn is not None else "__noconn__")] += 1
        subject_groups.add(subj)

    n_conn_groups = len(conn_groups)
    n_subject_groups = len(subject_groups)
    n_size1 = sum(1 for _, count in conn_groups.items() if count == 1)
    size1_ratio = (n_size1 / n_conn_groups) if n_conn_groups else 0.0
    subject_collapse_x = (
        (n_conn_groups / n_subject_groups) if n_subject_groups else 0.0
    )

    trigger = (
        total >= PLANNER_NET_ACCEPT_MIN_TOTAL
        and size1_ratio >= PLANNER_NET_ACCEPT_SIZE1_RATIO
        and subject_collapse_x >= PLANNER_NET_ACCEPT_SUBJECT_COLLAPSE_X
    )
    reasons: list[str] = []
    if total < PLANNER_NET_ACCEPT_MIN_TOTAL:
        reasons.append(
            f"net_accept_nonmal_total={total} < {PLANNER_NET_ACCEPT_MIN_TOTAL}"
        )
    if size1_ratio < PLANNER_NET_ACCEPT_SIZE1_RATIO:
        reasons.append(
            f"size1_ratio={round(size1_ratio, 4)} < {PLANNER_NET_ACCEPT_SIZE1_RATIO}"
        )
    if subject_collapse_x < PLANNER_NET_ACCEPT_SUBJECT_COLLAPSE_X:
        reasons.append(
            f"subject_collapse_x={round(subject_collapse_x, 4)} < "
            f"{PLANNER_NET_ACCEPT_SUBJECT_COLLAPSE_X}"
        )

    return {
        "trigger": bool(trigger),
        "metrics": {
            "net_accept_nonmal_total": total,
            "conn_groups": n_conn_groups,
            "subject_groups": n_subject_groups,
            "size1_groups": n_size1,
            "size1_ratio": round(size1_ratio, 6),
            "subject_collapse_x": round(subject_collapse_x, 6),
        },
        "thresholds": {
            "min_total": PLANNER_NET_ACCEPT_MIN_TOTAL,
            "size1_ratio": PLANNER_NET_ACCEPT_SIZE1_RATIO,
            "subject_collapse_x": PLANNER_NET_ACCEPT_SUBJECT_COLLAPSE_X,
        },
        "skip_reasons": reasons,
    }


def _planner_evaluate_process_fork(
    sorted_edges: list[dict[str, Any]],
    malicious_process_nodes: set[str],
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Compute B and C trigger evidence from PROCESS_FORK edges.

    Returns (trigger_b_info, trigger_c_info).
    """
    # Per-parent-subject aggregation.
    pf_total: Counter = Counter()
    pf_mal: Counter = Counter()
    pf_nonmal_evt_min: dict[str, int] = {}
    pf_nonmal_evt_max: dict[str, int] = {}
    pf_nonmal_count: Counter = Counter()
    # child-bridge evidence: count PF edges whose OBJECT (child process) is
    # in the malicious process set. This matches Trial C's actual preserve
    # rule. A parent that is itself in malicious_process_nodes but whose
    # PF children are all innocent (e.g. solr startup bash) should NOT
    # trigger C; that is a preparation-phase shell problem, orthogonal to C.
    pf_malicious_children: Counter = Counter()

    for edge in sorted_edges:
        if str(edge.get("relation") or "").upper() != "PROCESS_FORK":
            continue
        subj = _edge_primary_process_key(edge)
        if subj is None:
            continue
        attrs = edge.get("attrs") or {}
        is_mal = bool(attrs.get("malicious", False))
        pf_total[subj] += 1
        if is_mal:
            pf_mal[subj] += 1
        else:
            pf_nonmal_count[subj] += 1
            try:
                evt_num = int(attrs.get("evt_num"))
                if subj not in pf_nonmal_evt_min or evt_num < pf_nonmal_evt_min[subj]:
                    pf_nonmal_evt_min[subj] = evt_num
                if subj not in pf_nonmal_evt_max or evt_num > pf_nonmal_evt_max[subj]:
                    pf_nonmal_evt_max[subj] = evt_num
            except Exception:
                pass
        obj = str(edge.get("object") or "")
        if obj in malicious_process_nodes:
            pf_malicious_children[subj] += 1

    # ---------- B: gray-area big block ----------
    b_candidates: list[dict[str, Any]] = []
    for subj, total in pf_total.items():
        mal = pf_mal[subj]
        if total < PLANNER_PF_B_MIN_BLOCK_EDGES:
            continue
        if mal <= 0:
            continue
        frac = mal / total if total else 0.0
        if frac >= PLANNER_PF_B_MAX_MAL_FRACTION:
            continue
        if frac < PLANNER_PF_B_MIN_MAL_FRACTION:
            continue
        b_candidates.append(
            {
                "subject": subj,
                "pf_total": int(total),
                "pf_mal": int(mal),
                "mal_fraction": round(frac, 6),
            }
        )
    b_trigger = bool(b_candidates)
    b_reasons: list[str] = []
    if not b_trigger:
        if not pf_total:
            b_reasons.append("no_process_fork_edges")
        elif not any(pf_total[s] >= PLANNER_PF_B_MIN_BLOCK_EDGES for s in pf_total):
            b_reasons.append(
                f"no_subject_with_pf_total>={PLANNER_PF_B_MIN_BLOCK_EDGES}"
            )
        elif not any(pf_mal[s] > 0 for s in pf_total):
            b_reasons.append("no_subject_with_malicious_pf_edges")
        else:
            b_reasons.append("no_subject_in_gray_fraction_band")

    # ---------- C: wide-span parent cluster with malicious children ----------
    c_candidates: list[dict[str, Any]] = []
    for subj, nonmal in pf_nonmal_count.items():
        if nonmal < PLANNER_PF_C_MIN_SUBJECT_NONMAL_EDGES:
            continue
        span = (
            pf_nonmal_evt_max.get(subj, 0) - pf_nonmal_evt_min.get(subj, 0)
            if subj in pf_nonmal_evt_max and subj in pf_nonmal_evt_min
            else 0
        )
        if span < PLANNER_PF_C_MIN_EVT_SPAN:
            continue
        mal_children = pf_malicious_children.get(subj, 0)
        if mal_children <= 0:
            continue
        c_candidates.append(
            {
                "subject": subj,
                "pf_nonmal": int(nonmal),
                "evt_span": int(span),
                "malicious_children": int(mal_children),
            }
        )
    c_trigger = bool(c_candidates)
    c_reasons: list[str] = []
    if not c_trigger:
        if not pf_nonmal_count:
            c_reasons.append("no_nonmal_process_fork_edges")
        elif not any(
            pf_nonmal_count[s] >= PLANNER_PF_C_MIN_SUBJECT_NONMAL_EDGES
            for s in pf_nonmal_count
        ):
            c_reasons.append(
                f"no_subject_with_nonmal_pf>={PLANNER_PF_C_MIN_SUBJECT_NONMAL_EDGES}"
            )
        elif not any(
            (
                pf_nonmal_evt_max.get(s, 0) - pf_nonmal_evt_min.get(s, 0)
            )
            >= PLANNER_PF_C_MIN_EVT_SPAN
            for s in pf_nonmal_count
        ):
            c_reasons.append(
                f"no_subject_with_evt_span>={PLANNER_PF_C_MIN_EVT_SPAN}"
            )
        else:
            c_reasons.append("no_parent_with_malicious_children")

    trigger_b_info = {
        "trigger": bool(b_trigger),
        "metrics": {
            "pf_subjects_total": len(pf_total),
            "pf_subjects_gray_area": len(b_candidates),
            "top_candidates": b_candidates[:5],
        },
        "thresholds": {
            "min_block_edges": PLANNER_PF_B_MIN_BLOCK_EDGES,
            "min_mal_fraction": PLANNER_PF_B_MIN_MAL_FRACTION,
            "max_mal_fraction_exclusive": PLANNER_PF_B_MAX_MAL_FRACTION,
        },
        "skip_reasons": b_reasons,
    }
    trigger_c_info = {
        "trigger": bool(c_trigger),
        "metrics": {
            "pf_subjects_nonmal_total": len(pf_nonmal_count),
            "pf_subjects_parent_cluster": len(c_candidates),
            "top_candidates": c_candidates[:5],
        },
        "thresholds": {
            "min_subject_nonmal_edges": PLANNER_PF_C_MIN_SUBJECT_NONMAL_EDGES,
            "min_evt_span": PLANNER_PF_C_MIN_EVT_SPAN,
            "min_malicious_children": 1,
        },
        "skip_reasons": c_reasons,
    }
    return trigger_b_info, trigger_c_info


def _planner_evaluate_preparation_shell(
    sorted_edges: list[dict[str, Any]],
    malicious_process_nodes: set[str],
    first_malicious_evt_num: Optional[int],
) -> dict[str, Any]:
    """Compute D-trigger evidence: per-subject pre-malicious PF/EXEC burst
    whose forked children are all outside ``malicious_process_nodes``.

    Purely structural:
      * When there is no malicious anchor (``first_malicious_evt_num is None``)
        the concept of "pre-malicious" is undefined, so D is short-circuited
        to trigger=False with an explicit skip reason.
      * A subject with ANY malicious PF child is excluded from D (that case
        is handled by Trial C under the child-bridge rule). This keeps D and
        C mechanically exclusive.
    """
    thresholds = {
        "min_pre_fork_edges": PLANNER_D_MIN_PRE_FORK_EDGES,
        "min_pre_exec_edges": PLANNER_D_MIN_PRE_EXEC_EDGES,
        "min_pre_shell_ratio": PLANNER_D_MIN_PRE_SHELL_RATIO,
        "min_pre_evt_span": PLANNER_D_MIN_PRE_EVT_SPAN,
    }
    base: dict[str, Any] = {
        "trigger": False,
        "metrics": {
            "candidate_subjects_total": 0,
            "candidate_subjects_qualified": 0,
            "top_subject": None,
            "top_subject_pre_fork_edges": 0,
            "top_subject_pre_exec_edges": 0,
            "top_subject_pf_malicious_children": 0,
            "top_subject_evt_span": 0,
            "pre_malicious_shell_ratio": 0.0,
            "pre_edge_total": 0,
            "backbone_total": int(len(sorted_edges)),
        },
        "thresholds": thresholds,
        "skip_reasons": [],
    }

    if first_malicious_evt_num is None:
        base["skip_reasons"].append("no_first_malicious_evt_num")
        return base

    try:
        fmal = int(first_malicious_evt_num)
    except (TypeError, ValueError):
        base["skip_reasons"].append("first_malicious_evt_num_not_int")
        return base

    # Per-subject pre-malicious aggregations.
    pre_fork: Counter = Counter()
    pre_exec: Counter = Counter()
    pf_mal_children: Counter = Counter()
    pre_evt_min: dict[str, int] = {}
    pre_evt_max: dict[str, int] = {}
    pre_edge_total = 0

    for edge in sorted_edges:
        relation = str(edge.get("relation") or "").upper()
        if relation not in ("PROCESS_FORK", "PROCESS_EXEC"):
            # Count any pre-malicious edge for ratio purposes.
            evt_num = _edge_evt_num_optional(edge)
            if evt_num is not None and evt_num < fmal:
                pre_edge_total += 1
            continue

        evt_num = _edge_evt_num_optional(edge)
        subj = _edge_primary_process_key(edge)
        if subj is None:
            if evt_num is not None and evt_num < fmal:
                pre_edge_total += 1
            continue

        # Track child-bridge for every PF edge regardless of pre/post window.
        # Having even one malicious child anywhere in the timeline disqualifies
        # the subject for D (it belongs to C).
        if relation == "PROCESS_FORK":
            obj = str(edge.get("object") or "")
            if obj in malicious_process_nodes:
                pf_mal_children[subj] += 1

        if evt_num is not None and evt_num < fmal:
            pre_edge_total += 1
            if relation == "PROCESS_FORK":
                pre_fork[subj] += 1
            else:
                pre_exec[subj] += 1
            if subj not in pre_evt_min or evt_num < pre_evt_min[subj]:
                pre_evt_min[subj] = evt_num
            if subj not in pre_evt_max or evt_num > pre_evt_max[subj]:
                pre_evt_max[subj] = evt_num

    all_subjects = set(pre_fork) | set(pre_exec)
    base["metrics"]["candidate_subjects_total"] = int(len(all_subjects))
    base["metrics"]["pre_edge_total"] = int(pre_edge_total)
    pre_shell_ratio_overall = (
        pre_edge_total / len(sorted_edges) if sorted_edges else 0.0
    )
    base["metrics"]["pre_malicious_shell_ratio"] = round(
        pre_shell_ratio_overall, 6
    )

    qualified: list[dict[str, Any]] = []
    for subj in all_subjects:
        pf_cnt = int(pre_fork.get(subj, 0))
        ex_cnt = int(pre_exec.get(subj, 0))
        mal_children = int(pf_mal_children.get(subj, 0))
        total_cnt = pf_cnt + ex_cnt
        if total_cnt < PLANNER_D_MIN_PRE_FORK_EDGES:
            continue
        if mal_children > 0:
            # Belongs to C. Skip for D.
            continue
        # Startup-shell semantic gate: a genuine startup shell must do at
        # least one program handoff (execve) in the pre-malicious window.
        # Pure PROCESS_FORK bursts with zero PROCESS_EXEC are typically
        # server-process internal clone/thread warmup (JVM, Node cluster,
        # Python multiprocessing, ...) and are outside D's target face.
        if ex_cnt < PLANNER_D_MIN_PRE_EXEC_EDGES:
            continue
        span = (
            int(pre_evt_max.get(subj, 0) - pre_evt_min.get(subj, 0))
            if subj in pre_evt_max and subj in pre_evt_min
            else 0
        )
        ratio_ok = pre_shell_ratio_overall >= PLANNER_D_MIN_PRE_SHELL_RATIO
        span_ok = span >= PLANNER_D_MIN_PRE_EVT_SPAN
        if not (ratio_ok or span_ok):
            continue
        qualified.append(
            {
                "subject": subj,
                "pre_fork_edges": pf_cnt,
                "pre_exec_edges": ex_cnt,
                "pf_malicious_children": mal_children,
                "evt_span": span,
            }
        )

    base["metrics"]["candidate_subjects_qualified"] = int(len(qualified))
    if qualified:
        qualified.sort(
            key=lambda c: (
                c["pre_fork_edges"] + c["pre_exec_edges"],
                c["evt_span"],
            ),
            reverse=True,
        )
        top = qualified[0]
        base["metrics"].update(
            {
                "top_subject": top["subject"],
                "top_subject_pre_fork_edges": top["pre_fork_edges"],
                "top_subject_pre_exec_edges": top["pre_exec_edges"],
                "top_subject_pf_malicious_children": top["pf_malicious_children"],
                "top_subject_evt_span": top["evt_span"],
            }
        )
        base["trigger"] = True
        return base

    # Build informative skip reasons.
    reasons: list[str] = []
    if not all_subjects:
        reasons.append("no_pre_malicious_process_fork_or_exec_edges")
    else:
        # Find the best-performing subject for diagnostics, even if it failed.
        best_subj = None
        best_score = -1
        for subj in all_subjects:
            score = pre_fork.get(subj, 0) + pre_exec.get(subj, 0)
            if score > best_score:
                best_score = score
                best_subj = subj
        if best_subj is not None:
            base["metrics"].update(
                {
                    "top_subject": best_subj,
                    "top_subject_pre_fork_edges": int(pre_fork.get(best_subj, 0)),
                    "top_subject_pre_exec_edges": int(pre_exec.get(best_subj, 0)),
                    "top_subject_pf_malicious_children": int(
                        pf_mal_children.get(best_subj, 0)
                    ),
                    "top_subject_evt_span": int(
                        pre_evt_max.get(best_subj, 0) - pre_evt_min.get(best_subj, 0)
                    ) if (
                        best_subj in pre_evt_max and best_subj in pre_evt_min
                    ) else 0,
                }
            )
        any_bridge = any(pf_mal_children.get(s, 0) > 0 for s in all_subjects)
        any_volume = any(
            (pre_fork.get(s, 0) + pre_exec.get(s, 0))
            >= PLANNER_D_MIN_PRE_FORK_EDGES
            for s in all_subjects
        )
        # Volume-eligible subjects that are not ceded to C (no malicious
        # child). Used below to diagnose the new pre_exec startup-shell
        # gate and the shell_ratio / evt_span fallback.
        volume_and_not_ceded = [
            s for s in all_subjects
            if pf_mal_children.get(s, 0) == 0
            and (pre_fork.get(s, 0) + pre_exec.get(s, 0))
            >= PLANNER_D_MIN_PRE_FORK_EDGES
        ]
        if not any_volume:
            reasons.append(
                f"no_subject_with_pre_fork_exec>={PLANNER_D_MIN_PRE_FORK_EDGES}"
            )
        elif any_bridge and not volume_and_not_ceded:
            reasons.append("all_qualifying_subjects_have_malicious_children_ceded_to_C")
        elif volume_and_not_ceded and not any(
            pre_exec.get(s, 0) >= PLANNER_D_MIN_PRE_EXEC_EDGES
            for s in volume_and_not_ceded
        ):
            # Startup-shell semantic gate: every volume-eligible subject
            # does zero PROCESS_EXEC in the pre-malicious window, so the
            # pre-fork burst is structurally server-process internal
            # clone/thread warmup (e.g. JVM, Node cluster) rather than a
            # genuine startup shell.
            reasons.append(
                f"no_subject_with_pre_exec>={PLANNER_D_MIN_PRE_EXEC_EDGES}"
                "_pure_fork_burst_not_startup_shell"
            )
        else:
            reasons.append("no_subject_satisfies_shell_ratio_or_evt_span")
    base["skip_reasons"] = reasons
    return base


def _plan_backbone_refinement(
    sorted_edges: list[dict[str, Any]],
    *,
    warning_present: bool,
    user_overrides: Optional[dict[str, Optional[bool]]] = None,
    resolved_params: Optional[dict[str, Any]] = None,
    first_malicious_evt_num: Optional[int] = None,
) -> dict[str, Any]:
    """Pure planner: inspects edges, emits BackboneRefinementPlan as dict.

    Contract:
      * Does not modify any input.
      * Does not perform IO.
      * Does not read scenario_id or any name-based signal.
      * ``warning_present`` is recorded in the plan for audit, but does NOT
        gate trigger evaluation. Planner triggers are structural (conservative
        thresholds on edge distributions), so they stand on their own. The
        warning system is a separate cross-scenario heuristic and has known
        false negatives (e.g. NET_ACCEPT dominance alone does not always
        fire the warning).
      * Always returns a plan dict ready for chain_summary serialization.
    """
    overrides = {
        "A": None,
        "B": None,
        "C": None,
        "D": None,
    }
    if user_overrides:
        for k in ("A", "B", "C", "D"):
            if k in user_overrides and user_overrides[k] is not None:
                overrides[k] = bool(user_overrides[k])

    notes: list[str] = []
    if not warning_present:
        notes.append(
            "warning_present=False; planner still evaluates structural "
            "triggers (warning is advisory, not gating)."
        )
    mal_process_nodes, _mal_evt_nums = _planner_collect_malicious_anchors(
        sorted_edges
    )
    a_plan = _planner_evaluate_net_accept(sorted_edges)
    b_plan, c_plan = _planner_evaluate_process_fork(
        sorted_edges, mal_process_nodes
    )
    d_plan = _planner_evaluate_preparation_shell(
        sorted_edges,
        mal_process_nodes,
        first_malicious_evt_num,
    )

    def _resolve(auto: bool, override: Optional[bool]) -> bool:
        if override is None:
            return bool(auto)
        return bool(override)

    enable_a = _resolve(a_plan.get("trigger", False), overrides["A"])
    enable_b = _resolve(b_plan.get("trigger", False), overrides["B"])
    enable_c = _resolve(c_plan.get("trigger", False), overrides["C"])
    enable_d = _resolve(d_plan.get("trigger", False), overrides["D"])
    enable_map = {"A": enable_a, "B": enable_b, "C": enable_c, "D": enable_d}
    auto_map = {
        "A": bool(a_plan.get("trigger", False)),
        "B": bool(b_plan.get("trigger", False)),
        "C": bool(c_plan.get("trigger", False)),
        "D": bool(d_plan.get("trigger", False)),
    }
    for key, override in overrides.items():
        if override is None:
            continue
        notes.append(
            f"user_override: {key}={'on' if override else 'off'} "
            f"(planner_auto={'on' if auto_map[key] else 'off'}, "
            f"final={'on' if enable_map[key] else 'off'})"
        )

    plan: dict[str, Any] = {
        "planner_active": True,
        "warning_present": bool(warning_present),
        "enable_net_accept_subject_anchor": bool(enable_a),
        "enable_process_fork_hybrid_gate": bool(enable_b),
        "enable_process_fork_parent_cluster": bool(enable_c),
        "enable_preparation_shell": bool(enable_d),
        "triggers": {
            "net_accept_subject_anchor": a_plan,
            "process_fork_hybrid_gate": b_plan,
            "process_fork_parent_cluster": c_plan,
            "preparation_shell": d_plan,
        },
        "user_overrides": {
            "net_accept_subject_anchor": overrides["A"],
            "process_fork_hybrid_gate": overrides["B"],
            "process_fork_parent_cluster": overrides["C"],
            "preparation_shell": overrides["D"],
        },
        "resolved_params": dict(resolved_params or {}),
        "notes": notes,
    }
    return plan


def _plan_backbone_refinement_inactive(reason: str) -> dict[str, Any]:
    """Placeholder plan when planner is not invoked (audit or force-all modes)."""
    return {
        "planner_active": False,
        "warning_present": False,
        "enable_net_accept_subject_anchor": False,
        "enable_process_fork_hybrid_gate": False,
        "enable_process_fork_parent_cluster": False,
        "enable_preparation_shell": False,
        "triggers": {},
        "user_overrides": {},
        "resolved_params": {},
        "notes": [reason],
    }


def _apply_backbone_broad_gate(
    sorted_edges: list[dict[str, Any]],
    *,
    scenario_id: Optional[str],
    seed_edge_set: set[str],
    warning_eval: dict[str, Any],
    enabled: bool,
    relation_allowlist: set[str],
    evt_window: int,
    fork_repeat_sparse_experiment: bool = False,
    fork_repeat_unknown_child_stride: int = 80,
    fork_repeat_parent_cluster_experiment: bool = False,
    fork_repeat_parent_cluster_gap_evt: int = 5000,
    fork_repeat_parent_cluster_min_subject_edges: int = 8,
    net_accept_repeat_sparse_experiment: bool = False,
    net_accept_repeat_stride: int = 80,
) -> tuple[list[dict[str, Any]], dict[str, Any], list[str], list[dict[str, Any]]]:
    warnings: list[str] = []
    refinement_residual_rows: list[dict[str, Any]] = []
    stats = {
        "requested": bool(enabled),
        "warning_present": bool(warning_eval.get("warning_present")),
        "applied": False,
        "reason": "disabled",
        "target_relations": sorted(relation_allowlist),
        "evt_window": int(evt_window),
        "filtered_total": 0,
        "filtered_relation_counts": {},
        "fork_repeat_sparse_experiment": {
            "enabled": bool(fork_repeat_sparse_experiment),
            "active": bool(fork_repeat_sparse_experiment),
            "unknown_child_stride": max(1, int(fork_repeat_unknown_child_stride)),
            "parent_cluster_experiment": bool(fork_repeat_parent_cluster_experiment),
            "parent_cluster_gap_evt": max(1, int(fork_repeat_parent_cluster_gap_evt)),
            "parent_cluster_min_subject_edges": max(
                2,
                int(fork_repeat_parent_cluster_min_subject_edges),
            ),
            "filtered_unknown_child_process_fork": 0,
            "kept_sparse_unknown_child_process_fork": 0,
            "filtered_parent_cluster_process_fork": 0,
            "kept_parent_cluster_process_fork": 0,
        },
        "net_accept_repeat_sparse_experiment": {
            "enabled": bool(net_accept_repeat_sparse_experiment),
            "active": bool(net_accept_repeat_sparse_experiment),
            "repeat_stride": max(1, int(net_accept_repeat_stride)),
            "candidate_total": 0,
            "candidate_subject_count": 0,
            "filtered_non_malicious_net_accept": 0,
            "kept_sparse_non_malicious_net_accept": 0,
        },
    }

    if not enabled:
        return sorted_edges, stats, warnings, refinement_residual_rows
    if not warning_eval.get("warning_present"):
        stats["reason"] = "warning_not_triggered"
        return sorted_edges, stats, warnings, refinement_residual_rows
    if not relation_allowlist:
        stats["reason"] = "empty_relation_allowlist"
        return sorted_edges, stats, warnings, refinement_residual_rows

    malicious_evt_nums: list[int] = []
    malicious_net_conn_nodes: set[str] = set()
    malicious_net_fd_names: set[str] = set()
    malicious_process_nodes: set[str] = set()
    for edge in sorted_edges:
        attrs = edge.get("attrs") or {}
        if not bool(attrs.get("malicious", False)):
            continue
        try:
            malicious_evt_nums.append(int(attrs.get("evt_num")))
        except (TypeError, ValueError):
            pass
        relation = str(edge.get("relation") or "").upper()
        if relation.startswith("NET_"):
            malicious_net_conn_nodes.update(_edge_conn_nodes(edge))
            fd_name = str(attrs.get("fd_name") or "").strip()
            if fd_name:
                malicious_net_fd_names.add(fd_name)
        if relation.startswith("PROCESS_"):
            malicious_process_nodes.update(_edge_process_nodes(edge))

    malicious_evt_nums.sort()
    if not malicious_evt_nums:
        stats["reason"] = "no_malicious_evt_anchor"
        return sorted_edges, stats, warnings, refinement_residual_rows
    first_malicious_evt = malicious_evt_nums[0]
    last_malicious_evt = malicious_evt_nums[-1]

    filtered_relation_counts: Counter[str] = Counter()
    fork_repeat_sparse_active = bool(fork_repeat_sparse_experiment)
    fork_repeat_parent_cluster_active = bool(fork_repeat_parent_cluster_experiment)
    fork_repeat_unknown_child_stride = max(1, int(fork_repeat_unknown_child_stride))
    fork_repeat_parent_cluster_gap_evt = max(1, int(fork_repeat_parent_cluster_gap_evt))
    fork_repeat_parent_cluster_min_subject_edges = max(
        2,
        int(fork_repeat_parent_cluster_min_subject_edges),
    )
    fork_repeat_candidate_edges_by_subject: dict[str, list[dict[str, Any]]] = {}
    fork_repeat_candidate_groups: dict[str, list[dict[str, Any]]] = {}
    fork_repeat_parent_cluster_candidate_ids: set[str] = set()
    fork_repeat_semantic_keep_ids: set[str] = set()
    fork_repeat_unknown_child_filtered = 0
    fork_repeat_unknown_child_kept_sparse = 0
    fork_repeat_parent_cluster_filtered = 0
    fork_repeat_parent_cluster_kept = 0

    net_accept_sparse_active = bool(net_accept_repeat_sparse_experiment)
    net_accept_repeat_stride = max(1, int(net_accept_repeat_stride))
    net_accept_candidate_edges_by_subject: dict[str, list[dict[str, Any]]] = {}
    net_accept_semantic_keep_ids: set[str] = set()
    net_accept_sparse_filtered = 0
    net_accept_sparse_kept_sparse = 0
    if net_accept_sparse_active:
        for edge in sorted_edges:
            relation = str(edge.get("relation") or "").upper()
            if relation != "NET_ACCEPT":
                continue
            attrs = edge.get("attrs") or {}
            edge_id = str(edge.get("id") or "")
            if bool(attrs.get("malicious", False)) or edge_id in seed_edge_set:
                continue

            evt_num: Optional[int]
            try:
                evt_num = int(attrs.get("evt_num"))
            except (TypeError, ValueError):
                evt_num = None
            evt_near_malicious = _evt_is_near_malicious(
                evt_num=evt_num,
                malicious_evt_nums=malicious_evt_nums,
                window_evt=evt_window,
            )
            if evt_near_malicious:
                continue

            conn_nodes = _edge_conn_nodes(edge)
            fd_name = str(attrs.get("fd_name") or "").strip()
            conn_overlap = bool(conn_nodes & malicious_net_conn_nodes)
            fd_overlap = bool(fd_name) and fd_name in malicious_net_fd_names
            if conn_overlap or fd_overlap:
                continue

            subject_node = str(edge.get("subject") or "")
            net_accept_candidate_edges_by_subject.setdefault(subject_node, []).append(edge)

        for candidate_edges in net_accept_candidate_edges_by_subject.values():
            net_accept_semantic_keep_ids.update(
                _build_semantic_repeat_keep_ids(
                    candidate_edges,
                    relation_family="NET_ACCEPT",
                    first_malicious_evt=first_malicious_evt,
                    last_malicious_evt=last_malicious_evt,
                )
            )

    stats["net_accept_repeat_sparse_experiment"]["candidate_total"] = int(
        sum(len(items) for items in net_accept_candidate_edges_by_subject.values())
    )
    stats["net_accept_repeat_sparse_experiment"]["candidate_subject_count"] = int(
        len(net_accept_candidate_edges_by_subject)
    )
    stats["net_accept_repeat_sparse_experiment"]["selection_mode"] = (
        "semantic_shell_representative"
    )
    stats["net_accept_repeat_sparse_experiment"]["repeat_stride"] = net_accept_repeat_stride

    if fork_repeat_sparse_active or fork_repeat_parent_cluster_active:
        for edge in sorted_edges:
            relation = str(edge.get("relation") or "").upper()
            if relation != "PROCESS_FORK":
                continue
            attrs = edge.get("attrs") or {}
            edge_id = str(edge.get("id") or "")
            if bool(attrs.get("malicious", False)) or edge_id in seed_edge_set:
                continue
            evt_num = _edge_evt_num_optional(edge)
            evt_near_malicious = _evt_is_near_malicious(
                evt_num=evt_num,
                malicious_evt_nums=malicious_evt_nums,
                window_evt=evt_window,
            )
            if evt_near_malicious:
                continue
            process_nodes = _edge_process_nodes(edge)
            if not bool(process_nodes & malicious_process_nodes):
                continue
            subject_node = str(edge.get("subject") or "")
            fork_repeat_candidate_edges_by_subject.setdefault(subject_node, []).append(edge)

        if fork_repeat_parent_cluster_active:
            for subject_node, candidate_edges in fork_repeat_candidate_edges_by_subject.items():
                if len(candidate_edges) < fork_repeat_parent_cluster_min_subject_edges:
                    continue
                for cluster_idx, cluster_edges in enumerate(
                    _split_parent_fork_clusters(
                        candidate_edges,
                        max_evt_gap=fork_repeat_parent_cluster_gap_evt,
                    ),
                    1,
                ):
                    group_key = f"{subject_node}::cluster_{cluster_idx}"
                    fork_repeat_candidate_groups[group_key] = cluster_edges
                    fork_repeat_parent_cluster_candidate_ids.update(
                        str(edge.get("id") or "")
                        for edge in cluster_edges
                        if str(edge.get("id") or "")
                    )
                    fork_repeat_semantic_keep_ids.update(
                        _build_parent_cluster_representative_keep_ids(
                            cluster_edges,
                            first_malicious_evt=first_malicious_evt,
                            last_malicious_evt=last_malicious_evt,
                            malicious_process_nodes=malicious_process_nodes,
                        )
                    )
            stats["fork_repeat_sparse_experiment"]["candidate_total"] = int(
                sum(len(items) for items in fork_repeat_candidate_groups.values())
            )
            stats["fork_repeat_sparse_experiment"]["candidate_subject_count"] = int(
                len(
                    {
                        str((edges[0] or {}).get("subject") or "")
                        for edges in fork_repeat_candidate_groups.values()
                        if edges
                    }
                )
            )
            stats["fork_repeat_sparse_experiment"]["candidate_cluster_count"] = int(
                len(fork_repeat_candidate_groups)
            )
            stats["fork_repeat_sparse_experiment"]["selection_mode"] = (
                "parent_cluster_boundary"
            )
        elif fork_repeat_sparse_active:
            for subject_node, candidate_edges in fork_repeat_candidate_edges_by_subject.items():
                unknown_child_edges = [
                    edge for edge in candidate_edges
                    if _is_unknown_child_process_fork_edge(edge)
                ]
                if not unknown_child_edges:
                    continue
                fork_repeat_candidate_groups[subject_node] = unknown_child_edges
                fork_repeat_semantic_keep_ids.update(
                    _build_semantic_repeat_keep_ids(
                        unknown_child_edges,
                        relation_family="PROCESS_FORK",
                        first_malicious_evt=first_malicious_evt,
                        last_malicious_evt=last_malicious_evt,
                    )
                )
            stats["fork_repeat_sparse_experiment"]["candidate_total"] = int(
                sum(len(items) for items in fork_repeat_candidate_groups.values())
            )
            stats["fork_repeat_sparse_experiment"]["candidate_subject_count"] = int(
                len(fork_repeat_candidate_groups)
            )
            stats["fork_repeat_sparse_experiment"]["selection_mode"] = (
                "semantic_shell_representative"
            )

    write_idx = 0
    for read_idx, edge in enumerate(sorted_edges):
        attrs = edge.get("attrs") or {}
        relation = str(edge.get("relation") or "").upper()
        edge_id = str(edge.get("id") or "")
        keep = False
        targeted_by_gate = relation in relation_allowlist or (
            net_accept_sparse_active and relation == "NET_ACCEPT"
        )
        if not targeted_by_gate:
            keep = True
        elif bool(attrs.get("malicious", False)) or edge_id in seed_edge_set:
            keep = True
        else:
            evt_num: Optional[int]
            try:
                evt_num = int(attrs.get("evt_num"))
            except (TypeError, ValueError):
                evt_num = None

            evt_near_malicious = _evt_is_near_malicious(
                evt_num=evt_num,
                malicious_evt_nums=malicious_evt_nums,
                window_evt=evt_window,
            )
            keep = evt_near_malicious
            if relation.startswith("NET_"):
                conn_nodes = _edge_conn_nodes(edge)
                fd_name = str(attrs.get("fd_name") or "").strip()
                conn_overlap = bool(conn_nodes & malicious_net_conn_nodes)
                fd_overlap = bool(fd_name) and fd_name in malicious_net_fd_names
                keep = keep or conn_overlap
                keep = keep or fd_overlap
                if (
                    net_accept_sparse_active
                    and relation == "NET_ACCEPT"
                    and (not evt_near_malicious)
                    and (not conn_overlap)
                    and (not fd_overlap)
                ):
                    if edge_id in net_accept_semantic_keep_ids:
                        keep = True
                        net_accept_sparse_kept_sparse += 1
                    else:
                        keep = False
                        net_accept_sparse_filtered += 1
            elif relation.startswith("PROCESS_"):
                process_nodes = _edge_process_nodes(edge)
                keep = keep or bool(process_nodes & malicious_process_nodes)
                if (
                    fork_repeat_parent_cluster_active
                    and keep
                    and edge_id in fork_repeat_parent_cluster_candidate_ids
                ):
                    if edge_id in fork_repeat_semantic_keep_ids:
                        fork_repeat_parent_cluster_kept += 1
                    else:
                        keep = False
                        fork_repeat_parent_cluster_filtered += 1
                elif (
                    fork_repeat_sparse_active
                    and keep
                    and (not evt_near_malicious)
                    and _is_unknown_child_process_fork_edge(edge)
                ):
                    if edge_id in fork_repeat_semantic_keep_ids:
                        fork_repeat_unknown_child_kept_sparse += 1
                    else:
                        keep = False
                        fork_repeat_unknown_child_filtered += 1

        if keep:
            if write_idx != read_idx:
                sorted_edges[write_idx] = edge
            write_idx += 1
        else:
            filtered_relation_counts[relation] += 1

    if write_idx < len(sorted_edges):
        del sorted_edges[write_idx:]

    stats["applied"] = True
    stats["reason"] = "warning_triggered_and_gate_enabled"
    stats["filtered_total"] = int(sum(filtered_relation_counts.values()))
    stats["filtered_relation_counts"] = dict(sorted(filtered_relation_counts.items()))
    stats["fork_repeat_sparse_experiment"]["filtered_unknown_child_process_fork"] = int(
        fork_repeat_unknown_child_filtered
    )
    stats["fork_repeat_sparse_experiment"]["kept_sparse_unknown_child_process_fork"] = int(
        fork_repeat_unknown_child_kept_sparse
    )
    stats["fork_repeat_sparse_experiment"]["filtered_parent_cluster_process_fork"] = int(
        fork_repeat_parent_cluster_filtered
    )
    stats["fork_repeat_sparse_experiment"]["kept_parent_cluster_process_fork"] = int(
        fork_repeat_parent_cluster_kept
    )
    stats["net_accept_repeat_sparse_experiment"]["filtered_non_malicious_net_accept"] = int(
        net_accept_sparse_filtered
    )
    stats["net_accept_repeat_sparse_experiment"]["kept_sparse_non_malicious_net_accept"] = int(
        net_accept_sparse_kept_sparse
    )
    if stats["filtered_total"] > 0:
        warnings.append(
            "backbone broad gate filtered "
            f"{stats['filtered_total']} non-malicious NET/PROCESS edges"
        )
    if fork_repeat_unknown_child_filtered > 0:
        warnings.append(
            "fork repeat sparse experiment filtered "
            f"{fork_repeat_unknown_child_filtered} non-malicious unknown-child PROCESS_FORK edges"
        )
    if fork_repeat_parent_cluster_filtered > 0:
        warnings.append(
            "fork parent-cluster experiment filtered "
            f"{fork_repeat_parent_cluster_filtered} non-malicious PROCESS_FORK edges"
        )
    if net_accept_sparse_filtered > 0:
        warnings.append(
            "net_accept repeat sparse experiment filtered "
            f"{net_accept_sparse_filtered} non-malicious NET_ACCEPT edges"
        )
    refinement_residual_rows.extend(
        _build_refinement_residual_rows(
            candidate_groups=net_accept_candidate_edges_by_subject,
            semantic_keep_ids=net_accept_semantic_keep_ids,
            relation_family="NET_ACCEPT",
            scenario_id=scenario_id,
            first_malicious_evt=first_malicious_evt,
            last_malicious_evt=last_malicious_evt,
        )
    )
    refinement_residual_rows.extend(
        _build_refinement_residual_rows(
            candidate_groups=fork_repeat_candidate_groups,
            semantic_keep_ids=fork_repeat_semantic_keep_ids,
            relation_family="PROCESS_FORK",
            scenario_id=scenario_id,
            first_malicious_evt=first_malicious_evt,
            last_malicious_evt=last_malicious_evt,
        )
    )
    stats["refinement_residual_count"] = len(refinement_residual_rows)
    return sorted_edges, stats, warnings, refinement_residual_rows


def derive_backbone_chain(
    attack_subgraph: dict[str, Any],
    scenario_id: Optional[str] = None,
    edge_to_unit: Optional[dict[str, Optional[str]]] = None,
    backbone_file_devnull_filter: bool = False,
    backbone_file_node_modules_filter: bool = False,
    backbone_file_label_low_info: bool = False,
    backbone_file_label_vendor_composer: bool = False,
    backbone_broad_gate_on_warning: bool = False,
    backbone_broad_gate_relations: Optional[tuple[str, ...]] = None,
    backbone_broad_gate_window_evt: int = 12,
    backbone_broad_gate_fork_repeat_sparse_experiment: bool = False,
    backbone_broad_gate_fork_repeat_unknown_child_stride: int = 80,
    backbone_broad_gate_fork_parent_cluster_experiment: bool = False,
    backbone_broad_gate_fork_parent_cluster_gap_evt: int = 5000,
    backbone_broad_gate_fork_parent_cluster_min_subject_edges: int = 8,
    backbone_broad_gate_net_accept_repeat_sparse_experiment: bool = False,
    backbone_broad_gate_net_accept_repeat_stride: int = 80,
    runtime_shell_block_rows: Optional[list[dict[str, Any]]] = None,
    backbone_runtime_shell_block_representative_experiment: bool = False,
    backbone_runtime_shell_block_relations: Optional[tuple[str, ...]] = None,
    backbone_runtime_shell_block_min_block_edges: int = DEFAULT_RUNTIME_SHELL_BLOCK_TRIAL_MIN_BLOCK_EDGES,
    backbone_runtime_shell_block_min_overlap_ratio: float = DEFAULT_RUNTIME_SHELL_BLOCK_TRIAL_MIN_OVERLAP_RATIO,
    backbone_runtime_shell_block_net_accept_subject_anchor_trial: bool = (
        DEFAULT_RUNTIME_SHELL_BLOCK_NET_ACCEPT_SUBJECT_ANCHOR_TRIAL
    ),
    backbone_runtime_shell_block_process_fork_hybrid_gate: bool = (
        DEFAULT_RUNTIME_SHELL_BLOCK_PROCESS_FORK_HYBRID_GATE
    ),
    backbone_runtime_shell_block_process_fork_hybrid_min_overlap_ratio: float = (
        DEFAULT_RUNTIME_SHELL_BLOCK_PROCESS_FORK_HYBRID_MIN_OVERLAP_RATIO
    ),
    backbone_runtime_shell_block_process_fork_hybrid_min_overlap_edges: int = (
        DEFAULT_RUNTIME_SHELL_BLOCK_PROCESS_FORK_HYBRID_MIN_OVERLAP_EDGES
    ),
    backbone_refinement_planner_mode: bool = False,
    backbone_refinement_planner_user_overrides: Optional[dict[str, Optional[bool]]] = None,
    backbone_preparation_shell_trial: bool = False,
    backbone_disable_preparation_shell_trial: bool = False,
) -> tuple[dict[str, Any], list[str], list[dict[str, Any]]]:
    warnings: list[str] = []
    edges = attack_subgraph.get("edges", [])
    subgraph_id = attack_subgraph.get("subgraph_id", "sg_empty")
    seed_nodes = set(attack_subgraph.get("seeds", {}).get("seed_nodes", []))
    seed_edge_set = set(attack_subgraph.get("seeds", {}).get("seed_edges", []))

    devnull_filtered_total = 0
    devnull_filtered_malicious = 0
    node_modules_filtered_total = 0
    node_modules_filtered_malicious = 0

    if not edges:
        chain = {
            "schema_version": SCHEMA_VERSION,
            "chain_id": "chain_empty",
            "graph_ref": {"subgraph_id": subgraph_id},
            "chain_summary": {
                "edge_count": 0,
                "start_evt_num": None,
                "end_evt_num": None,
            },
            "edge_sequence": [],
        }
        if scenario_id:
            chain["scenario_id"] = scenario_id
        return chain, warnings, []

    candidate_edges: list[dict[str, Any]] = []
    for edge in edges:
        relation = edge.get("relation")
        attrs = edge.get("attrs", {})
        is_malicious = bool(attrs.get("malicious", False))
        touches_seed = (edge.get("subject") in seed_nodes) or (edge.get("object") in seed_nodes)

        if not touches_seed:
            continue

        if relation in BACKBONE_RELATION_ALLOWLIST:
            candidate_edges.append(edge)
            continue

        # FILE_* edges are excluded by default and only retained when malicious.
        if relation in FILE_RELATIONS and is_malicious:
            if backbone_file_devnull_filter and _is_devnull_file_edge(edge):
                devnull_filtered_total += 1
                devnull_filtered_malicious += 1
                continue
            if backbone_file_node_modules_filter and _is_node_modules_file_edge(edge):
                node_modules_filtered_total += 1
                node_modules_filtered_malicious += 1
                continue
            candidate_edges.append(edge)

    if not candidate_edges:
        warnings.append("no candidate edges after backbone filtering; output empty backbone_chain")
        chain = {
            "schema_version": SCHEMA_VERSION,
            "chain_id": "chain_empty",
            "graph_ref": {"subgraph_id": subgraph_id},
            "chain_summary": {
                "edge_count": 0,
                "start_evt_num": None,
                "end_evt_num": None,
            },
            "edge_sequence": [],
        }
        if scenario_id:
            chain["scenario_id"] = scenario_id
        return chain, warnings, []

    try:
        sorted_edges = _sort_edges_by_evt_num(candidate_edges)
    except Exception as exc:
        warnings.append(f"failed to sort backbone edges by evt_num: {exc}")
        chain = {
            "schema_version": SCHEMA_VERSION,
            "chain_id": "chain_empty",
            "graph_ref": {"subgraph_id": subgraph_id},
            "chain_summary": {
                "edge_count": 0,
                "start_evt_num": None,
                "end_evt_num": None,
            },
            "edge_sequence": [],
        }
        if scenario_id:
            chain["scenario_id"] = scenario_id
        warnings.append("attack_subgraph exists but backbone is empty due to sorting failure")
        return chain, warnings, []

    distinct_unit_count_in_backbone = 0
    if edge_to_unit is not None:
        distinct_unit_count_in_backbone = len({
            unit_id
            for edge in sorted_edges
            for unit_id in [edge_to_unit.get(str(edge.get("id")))]
            if unit_id
        })

    baseline_metrics = compute_backbone_edge_metrics(
        sorted_edges,
        source_subgraph_edge_count=len(edges),
        distinct_unit_count_in_backbone=distinct_unit_count_in_backbone,
    )
    broad_warning = evaluate_backbone_broad_warning(
        baseline_metrics,
        scenario_id=scenario_id,
    )
    gate_relations = set(backbone_broad_gate_relations or DEFAULT_BROAD_GATE_RELATIONS)

    # ---- Conditional-triggered refinement planner ------------------------
    # Only runs when the caller explicitly opted into planner mode (typically
    # the adaptive-candidate run_mode). When inactive, the trial enable flags
    # passed into the function take effect verbatim.
    # Pre-compute first_malicious_evt_num from the raw pre-refinement
    # sorted_edges so Trial D's planner has a stable anchor to define the
    # "pre-malicious" window. The later expression_clarity computation uses
    # post-refinement edges and agrees with this value as long as the first
    # malicious edge is never demoted (which it isn't by any of A/B/C/D).
    _pre_first_malicious_evt: Optional[int] = None
    for _e in sorted_edges:
        if bool((_e.get("attrs") or {}).get("malicious", False)):
            _evt = _edge_evt_num_optional(_e)
            if _evt is not None:
                if (
                    _pre_first_malicious_evt is None
                    or _evt < _pre_first_malicious_evt
                ):
                    _pre_first_malicious_evt = _evt

    if backbone_refinement_planner_mode:
        planner_user_overrides = dict(backbone_refinement_planner_user_overrides or {})
        # An explicit user-supplied enable_* flag on the function call counts
        # as an override: it is recorded and it wins over planner decision.
        if backbone_runtime_shell_block_net_accept_subject_anchor_trial:
            planner_user_overrides.setdefault("A", True)
        if backbone_runtime_shell_block_process_fork_hybrid_gate:
            planner_user_overrides.setdefault("B", True)
        if backbone_broad_gate_fork_parent_cluster_experiment:
            planner_user_overrides.setdefault("C", True)
        if backbone_preparation_shell_trial:
            planner_user_overrides.setdefault("D", True)

        refinement_plan = _plan_backbone_refinement(
            sorted_edges,
            warning_present=bool(broad_warning.get("warning_present")),
            user_overrides=planner_user_overrides,
            first_malicious_evt_num=_pre_first_malicious_evt,
            resolved_params={
                "fork_parent_cluster_gap_evt": int(
                    backbone_broad_gate_fork_parent_cluster_gap_evt
                ),
                "fork_parent_cluster_min_subject_edges": int(
                    backbone_broad_gate_fork_parent_cluster_min_subject_edges
                ),
                "runtime_shell_block_min_block_edges": int(
                    backbone_runtime_shell_block_min_block_edges
                ),
                "runtime_shell_block_min_overlap_ratio": float(
                    backbone_runtime_shell_block_min_overlap_ratio
                ),
                "process_fork_hybrid_min_overlap_ratio": float(
                    backbone_runtime_shell_block_process_fork_hybrid_min_overlap_ratio
                ),
                "process_fork_hybrid_min_overlap_edges": int(
                    backbone_runtime_shell_block_process_fork_hybrid_min_overlap_edges
                ),
            },
        )
        # Plan decisions override the incoming enable_* flags so all downstream
        # stages consume a single source of truth.
        planner_enable_a = bool(
            refinement_plan.get("enable_net_accept_subject_anchor")
        )
        planner_enable_b = bool(
            refinement_plan.get("enable_process_fork_hybrid_gate")
        )
        planner_enable_c = bool(
            refinement_plan.get("enable_process_fork_parent_cluster")
        )
        # If plan enables B, the parent trial also needs its relation-specific
        # umbrella experiment flag to be true.
        effective_runtime_shell_representative_experiment = bool(
            backbone_runtime_shell_block_representative_experiment
        )
        if planner_enable_a or planner_enable_b:
            effective_runtime_shell_representative_experiment = True
        backbone_runtime_shell_block_net_accept_subject_anchor_trial = planner_enable_a
        backbone_runtime_shell_block_process_fork_hybrid_gate = planner_enable_b
        backbone_broad_gate_fork_parent_cluster_experiment = planner_enable_c
        backbone_runtime_shell_block_representative_experiment = (
            effective_runtime_shell_representative_experiment
        )
    else:
        refinement_plan = _plan_backbone_refinement_inactive(
            "planner_mode=False; trial flags consumed verbatim"
        )

    sorted_edges, broad_gate_stats, broad_gate_warnings, refinement_residual_rows = _apply_backbone_broad_gate(
        sorted_edges,
        scenario_id=scenario_id,
        seed_edge_set=seed_edge_set,
        warning_eval=broad_warning,
        enabled=backbone_broad_gate_on_warning,
        relation_allowlist=gate_relations,
        evt_window=max(0, int(backbone_broad_gate_window_evt)),
        fork_repeat_sparse_experiment=backbone_broad_gate_fork_repeat_sparse_experiment,
        fork_repeat_unknown_child_stride=max(
            1,
            int(backbone_broad_gate_fork_repeat_unknown_child_stride),
        ),
        fork_repeat_parent_cluster_experiment=(
            backbone_broad_gate_fork_parent_cluster_experiment
        ),
        fork_repeat_parent_cluster_gap_evt=max(
            1,
            int(backbone_broad_gate_fork_parent_cluster_gap_evt),
        ),
        fork_repeat_parent_cluster_min_subject_edges=max(
            2,
            int(backbone_broad_gate_fork_parent_cluster_min_subject_edges),
        ),
        net_accept_repeat_sparse_experiment=(
            backbone_broad_gate_net_accept_repeat_sparse_experiment
        ),
        net_accept_repeat_stride=max(
            1,
            int(backbone_broad_gate_net_accept_repeat_stride),
        ),
    )
    warnings.extend(broad_gate_warnings)

    runtime_shell_trial_relations = set(
        backbone_runtime_shell_block_relations
        or DEFAULT_RUNTIME_SHELL_BLOCK_TRIAL_RELATIONS
    )
    # Trial view A: optionally rebuild NET_ACCEPT blocks at subject-only
    # anchor so single-edge per-conn chunks (mongo-express style) can form
    # a cohesive block in the trial. The exported sidecar is unchanged.
    effective_runtime_block_rows = list(runtime_shell_block_rows or [])
    net_accept_subject_anchor_trial_view_stats: dict[str, Any] = {
        "enabled": bool(
            backbone_runtime_shell_block_net_accept_subject_anchor_trial
        ),
        "activated": False,
        "reason": "disabled",
        "original_net_accept_block_rows": 0,
        "trial_view_net_accept_block_rows": 0,
        "trial_view_net_accept_block_rows_size_ge_min": 0,
    }
    if backbone_runtime_shell_block_net_accept_subject_anchor_trial:
        net_accept_active = (
            backbone_runtime_shell_block_representative_experiment
            and "NET_ACCEPT" in {
                str(rel).upper() for rel in runtime_shell_trial_relations
            }
        )
        if not net_accept_active:
            net_accept_subject_anchor_trial_view_stats["reason"] = (
                "net_accept_not_in_active_trial_relations"
            )
        else:
            original_na_rows = [
                row for row in effective_runtime_block_rows
                if "::net_accept::" in str(row.get("block_id") or "")
            ]
            other_rows = [
                row for row in effective_runtime_block_rows
                if "::net_accept::" not in str(row.get("block_id") or "")
            ]
            trial_view_na_rows = _build_net_accept_subject_level_trial_blocks(
                attack_subgraph,
                edge_to_unit=edge_to_unit or {},
                scenario_id=scenario_id,
            )
            effective_runtime_block_rows = other_rows + trial_view_na_rows
            min_block_edges_effective = max(
                2, int(backbone_runtime_shell_block_min_block_edges)
            )
            net_accept_subject_anchor_trial_view_stats.update(
                {
                    "activated": True,
                    "reason": "net_accept_trial_view_replaced",
                    "original_net_accept_block_rows": int(len(original_na_rows)),
                    "trial_view_net_accept_block_rows": int(
                        len(trial_view_na_rows)
                    ),
                    "trial_view_net_accept_block_rows_size_ge_min": int(
                        sum(
                            1
                            for r in trial_view_na_rows
                            if (r.get("edge_count") or 0)
                            >= min_block_edges_effective
                        )
                    ),
                }
            )
    (
        sorted_edges,
        runtime_shell_trial_stats,
        runtime_shell_trial_warnings,
        runtime_shell_trial_residual_rows,
    ) = _apply_runtime_shell_block_representative_trial(
        sorted_edges,
        scenario_id=scenario_id,
        runtime_block_rows=effective_runtime_block_rows,
        enabled=backbone_runtime_shell_block_representative_experiment,
        target_relations=runtime_shell_trial_relations,
        min_block_edge_count=max(
            2,
            int(backbone_runtime_shell_block_min_block_edges),
        ),
        min_overlap_ratio=max(
            0.0,
            min(1.0, float(backbone_runtime_shell_block_min_overlap_ratio)),
        ),
        process_fork_hybrid_gate=(
            backbone_runtime_shell_block_process_fork_hybrid_gate
        ),
        process_fork_hybrid_min_overlap_ratio=(
            backbone_runtime_shell_block_process_fork_hybrid_min_overlap_ratio
        ),
        process_fork_hybrid_min_overlap_edges=(
            backbone_runtime_shell_block_process_fork_hybrid_min_overlap_edges
        ),
        net_accept_subject_anchor_trial_view_stats=(
            net_accept_subject_anchor_trial_view_stats
        ),
    )
    warnings.extend(runtime_shell_trial_warnings)
    if runtime_shell_trial_residual_rows:
        refinement_residual_rows.extend(runtime_shell_trial_residual_rows)

    # ---- Trial D: preparation-phase startup shell ----------------------
    # Runs strictly after A/B/C. Planner-side evaluation already ran above
    # when planner_mode=True. When planner_mode=False we still want to be
    # able to execute D under explicit user override, so we compute a
    # one-shot trigger inline using the same evaluator.
    _pre_mal_nodes_for_d, _ = _planner_collect_malicious_anchors(sorted_edges)
    _first_mal_evt_for_d = _pre_first_malicious_evt
    if backbone_refinement_planner_mode:
        _d_trigger_info = (
            refinement_plan.get("triggers", {}).get("preparation_shell")
        )
    else:
        _d_trigger_info = _planner_evaluate_preparation_shell(
            sorted_edges,
            _pre_mal_nodes_for_d,
            _first_mal_evt_for_d,
        )
    _planner_structural_trigger_d = bool(
        (_d_trigger_info or {}).get("trigger", False)
    )

    # Execution gating (precedence: disable > explicit enable > default):
    #   * Explicit user-disable flag always wins (hard opt-out).
    #   * Explicit user-enable flag wins over planner decision.
    #   * Otherwise: execute when planner structurally triggers AND the
    #     module-level rollout flag opts D into default activation
    #     (currently ADAPTIVE_DEFAULT_INCLUDES_D=True; D is default-on).
    _user_explicit_d = bool(backbone_preparation_shell_trial)
    _user_disable_d = bool(backbone_disable_preparation_shell_trial)
    if _user_disable_d:
        _d_enabled = False
    elif _user_explicit_d:
        _d_enabled = True
    elif _planner_structural_trigger_d and ADAPTIVE_DEFAULT_INCLUDES_D:
        _d_enabled = True
    else:
        _d_enabled = False

    (
        sorted_edges,
        preparation_shell_trial_stats,
        preparation_shell_trial_warnings,
        preparation_shell_trial_residual_rows,
    ) = _apply_preparation_shell_trial(
        sorted_edges,
        scenario_id=scenario_id,
        enabled=_d_enabled,
        planner_trigger_info=_d_trigger_info,
        first_malicious_evt_num=_first_mal_evt_for_d,
        malicious_process_nodes=_pre_mal_nodes_for_d,
    )
    preparation_shell_trial_stats["planner_structural_trigger"] = bool(
        _planner_structural_trigger_d
    )
    preparation_shell_trial_stats["user_override"] = bool(_user_explicit_d)
    preparation_shell_trial_stats["user_disable"] = bool(_user_disable_d)
    preparation_shell_trial_stats["adaptive_default_includes_d"] = bool(
        ADAPTIVE_DEFAULT_INCLUDES_D
    )
    warnings.extend(preparation_shell_trial_warnings)
    if preparation_shell_trial_residual_rows:
        refinement_residual_rows.extend(preparation_shell_trial_residual_rows)

    final_metrics = compute_backbone_edge_metrics(
        sorted_edges,
        source_subgraph_edge_count=len(edges),
        distinct_unit_count_in_backbone=distinct_unit_count_in_backbone,
    )
    broad_warning = evaluate_backbone_broad_warning(
        final_metrics,
        scenario_id=scenario_id,
    )
    if not sorted_edges:
        warnings.append("no candidate edges remain after optional backbone broad gate")
        chain = {
            "schema_version": SCHEMA_VERSION,
            "chain_id": "chain_empty",
            "graph_ref": {"subgraph_id": subgraph_id},
            "chain_summary": {
                "edge_count": 0,
                "start_evt_num": None,
                "end_evt_num": None,
                "malicious_edge_count": 0,
                "malicious_ratio": 0.0,
                "non_malicious_ratio": 0.0,
                "source_subgraph_edge_count": len(edges),
                "backbone_to_subgraph_ratio": 0.0,
                "top_relations": [],
                "top_non_malicious_relations": [],
                "distinct_unit_count_in_backbone": distinct_unit_count_in_backbone,
                "broad_backbone_warning": broad_warning,
                "broad_backbone_gate": broad_gate_stats,
                "runtime_shell_block_trial": runtime_shell_trial_stats,
                "preparation_shell_trial": preparation_shell_trial_stats,
                "refinement_plan": refinement_plan,
            },
            "edge_sequence": [],
        }
        if scenario_id:
            chain["scenario_id"] = scenario_id
        return chain, warnings, []

    # Reuse the same list storage: transform sorted_edges into final edge_sequence in place.
    for idx, edge in enumerate(sorted_edges, 1):
        out_attrs = _ensure_min_attrs(edge.get("attrs", {}))
        if edge.get("relation") in FILE_RELATIONS:
            if backbone_file_label_low_info:
                if _is_devnull_file_edge(edge):
                    out_attrs["low_info_path"] = "devnull"
                elif _is_node_modules_file_edge(edge):
                    out_attrs["low_info_path"] = "node_modules"
            if "low_info_path" not in out_attrs and backbone_file_label_vendor_composer:
                if _is_vendor_composer_file_edge(edge):
                    out_attrs["low_info_path"] = "vendor_composer"
        sorted_edges[idx - 1] = {
            "seq": idx,
            "edge_id": edge["id"],
            "subject": edge["subject"],
            "relation": edge["relation"],
            "object": edge["object"],
            "attrs": out_attrs,
        }

    edge_sequence: list[dict[str, Any]] = sorted_edges
    expression_clarity = _build_backbone_expression_clarity_summary(edge_sequence)
    semantic_readiness = expression_clarity.get("semantic_readiness") or {}

    # Externalise narrative roles onto retained backbone edges. This is
    # an additive annotation pass: it mutates edges in place by setting
    # ``narrative_role`` / ``narrative_role_alt`` fields, and returns a
    # summary that is recorded on chain_summary so downstream consumers
    # can enumerate role-tagged anchors without walking every edge. D's
    # kept_anchor_roles are copied onto the actual edges here so the
    # preparation-side story phase no longer lives only in a stats tree.
    narrative_roles_summary = _annotate_backbone_narrative_roles(
        edge_sequence,
        expression_clarity,
        preparation_shell_trial_stats,
    )

    evt_nums = [int(e["attrs"]["evt_num"]) for e in sorted_edges]
    chain = {
        "schema_version": SCHEMA_VERSION,
        "chain_id": _build_chain_id(sorted_edges),
        "graph_ref": {"subgraph_id": subgraph_id},
        "chain_summary": {
            "edge_count": len(edge_sequence),
            "start_evt_num": min(evt_nums),
            "end_evt_num": max(evt_nums),
            "relation_counts": final_metrics["relation_counts"],
            "malicious_edge_count": final_metrics["malicious_edge_count"],
            "malicious_ratio": final_metrics["malicious_ratio"],
            "non_malicious_ratio": final_metrics["non_malicious_ratio"],
            "source_subgraph_edge_count": len(edges),
            "backbone_to_subgraph_ratio": final_metrics["backbone_to_subgraph_ratio"],
            "top_relations": final_metrics["top_relations"],
            "top_non_malicious_relations": final_metrics["top_non_malicious_relations"],
            "distinct_unit_count_in_backbone": distinct_unit_count_in_backbone,
            "expression_clarity": expression_clarity,
            "semantic_readiness": semantic_readiness,
            "narrative_roles": narrative_roles_summary,
            "refinement_residual_count": len(refinement_residual_rows),
            "refinement_residual_relation_counts": dict(
                sorted(
                    Counter(
                        str(row.get("relation_family") or "UNKNOWN")
                        for row in refinement_residual_rows
                    ).items()
                )
            ),
            "broad_backbone_warning": broad_warning,
            "broad_backbone_gate": broad_gate_stats,
            "runtime_shell_block_trial": runtime_shell_trial_stats,
            "preparation_shell_trial": preparation_shell_trial_stats,
            "refinement_plan": refinement_plan,
        },
        "edge_sequence": edge_sequence,
    }
    if backbone_file_devnull_filter:
        chain["chain_summary"]["file_devnull_filtered_total"] = devnull_filtered_total
        chain["chain_summary"]["file_devnull_filtered_malicious"] = devnull_filtered_malicious
    if backbone_file_node_modules_filter:
        chain["chain_summary"]["file_node_modules_filtered_total"] = node_modules_filtered_total
        chain["chain_summary"]["file_node_modules_filtered_malicious"] = node_modules_filtered_malicious
    if backbone_file_label_low_info or backbone_file_label_vendor_composer:
        lip_counts = Counter(
            e["attrs"]["low_info_path"]
            for e in edge_sequence
            if "low_info_path" in e.get("attrs", {})
        )
        chain["chain_summary"]["low_info_path_tagged_total"] = sum(lip_counts.values())
        chain["chain_summary"]["low_info_path_counts"] = dict(sorted(lip_counts.items()))
    if scenario_id:
        chain["scenario_id"] = scenario_id
    return chain, warnings, refinement_residual_rows


def resolve_paths(
    scenario_dir: Path,
    triples_path: Optional[Path] = None,
    subgraph_path: Optional[Path] = None,
    backbone_path: Optional[Path] = None,
    unit_event_path: Optional[Path] = None,
    unit_index_path: Optional[Path] = None,
) -> dict[str, Path]:
    chain_dir = scenario_dir / CHAIN_DIR_NAME
    index_dir = scenario_dir / "index"
    triples = triples_path or (chain_dir / "audit_triples.core.v1.jsonl")
    attack_subgraph = subgraph_path or (chain_dir / "attack_subgraph.v1.json")
    backbone_chain = backbone_path or (chain_dir / "backbone_chain.v1.json")
    unit_event_index = unit_event_path or (index_dir / "unit_event_index.jsonl")
    unit_index = unit_index_path or (index_dir / "unit_index.jsonl")
    return {
        "chain_dir": chain_dir,
        "index_dir": index_dir,
        "triples": triples,
        "attack_subgraph": attack_subgraph,
        "backbone_chain": backbone_chain,
        "unit_event_index": unit_event_index,
        "unit_index": unit_index,
    }


def save_attack_subgraph(path: Path, attack_subgraph: dict[str, Any]) -> None:
    edge_count = len(attack_subgraph.get("edges", [])) if isinstance(attack_subgraph, dict) else 0
    print(f"[build_attack_chain_v1] save_attack_subgraph start path={path} edge_count={edge_count}")
    t0 = time.perf_counter()
    _write_json(path, attack_subgraph)
    elapsed = time.perf_counter() - t0
    size_bytes = path.stat().st_size if path.exists() else 0
    print(
        "[build_attack_chain_v1] save_attack_subgraph done "
        f"elapsed_s={round(elapsed, 2)} size_bytes={size_bytes}"
    )
    if edge_count > 1_000_000 or size_bytes > 1_000_000_000:
        print(
            "[build_attack_chain_v1][warning] large_attack_subgraph "
            f"edge_count={edge_count} size_bytes={size_bytes}"
        )


def save_backbone_chain(path: Path, backbone_chain: dict[str, Any]) -> None:
    edge_count = len(backbone_chain.get("edge_sequence", [])) if isinstance(backbone_chain, dict) else 0
    print(f"[build_attack_chain_v1] save_backbone_chain start path={path} edge_count={edge_count}")
    t0 = time.perf_counter()
    _write_json(path, backbone_chain)
    elapsed = time.perf_counter() - t0
    size_bytes = path.stat().st_size if path.exists() else 0
    print(
        "[build_attack_chain_v1] save_backbone_chain done "
        f"elapsed_s={round(elapsed, 2)} size_bytes={size_bytes}"
    )
    if edge_count > 1_000_000 or size_bytes > 1_000_000_000:
        print(
            "[build_attack_chain_v1][warning] large_backbone_chain "
            f"edge_count={edge_count} size_bytes={size_bytes}"
        )


def build_unit_backbone_window_index(
    backbone_chain: dict[str, Any],
    edge_to_unit: dict[str, Optional[str]],
    unit_meta: dict[str, dict[str, Any]],
    scenario_id: Optional[str] = None,
) -> list[dict[str, Any]]:
    grouped: dict[str, dict[str, Any]] = {}

    for edge in backbone_chain.get("edge_sequence", []):
        edge_id = str(edge.get("edge_id"))
        unit_key = edge_to_unit.get(edge_id)
        if unit_key is None:
            continue

        attrs = edge.get("attrs", {}) if isinstance(edge.get("attrs"), dict) else {}
        try:
            seq = int(edge.get("seq"))
            evt_num = int(attrs.get("evt_num"))
        except (TypeError, ValueError):
            continue

        timestamp = attrs.get("timestamp")
        relation = str(edge.get("relation") or "")

        bucket = grouped.get(unit_key)
        if bucket is None:
            bucket = {
                "seq_values": [],
                "evt_values": [],
                "timestamp_values": [],
                "relation_counts": Counter(),
            }
            grouped[unit_key] = bucket

        bucket["seq_values"].append(seq)
        bucket["evt_values"].append(evt_num)
        if timestamp is not None and str(timestamp).strip():
            bucket["timestamp_values"].append(str(timestamp))
        if relation:
            bucket["relation_counts"][relation] += 1

    rows: list[dict[str, Any]] = []
    for unit_key in sorted(grouped.keys()):
        bucket = grouped[unit_key]
        meta = unit_meta.get(unit_key, {})
        seq_values = sorted(bucket["seq_values"])
        evt_values = sorted(bucket["evt_values"])
        timestamp_values = sorted(bucket["timestamp_values"])
        relation_counts = dict(sorted(bucket["relation_counts"].items()))

        row = {
            "schema_version": UNIT_BACKBONE_WINDOW_SCHEMA_VERSION,
            "unit_key": unit_key,
            "backbone_edge_count": len(seq_values),
            "backbone_seq_start": seq_values[0],
            "backbone_seq_end": seq_values[-1],
            "backbone_evt_num_start": evt_values[0],
            "backbone_evt_num_end": evt_values[-1],
            "backbone_relation_counts": relation_counts,
        }
        if timestamp_values:
            row["backbone_time_start"] = timestamp_values[0]
            row["backbone_time_end"] = timestamp_values[-1]
        if scenario_id:
            row["scenario_id"] = scenario_id

        unit_id = _normalize_optional_unit_id(meta.get("unit_id"))
        if unit_id is not None:
            row["unit_id"] = unit_id
        container_id = meta.get("container_id")
        if container_id is not None:
            row["container_id"] = str(container_id)
        thread_vtid = meta.get("thread_vtid")
        if thread_vtid is not None:
            row["thread_vtid"] = str(thread_vtid)
        for src_key, dst_key in (
            ("evt_num_start", "unit_evt_num_start"),
            ("evt_num_end", "unit_evt_num_end"),
            ("time_start", "unit_time_start"),
            ("time_end", "unit_time_end"),
            ("event_count", "unit_event_count"),
        ):
            value = meta.get(src_key)
            if value is not None:
                row[dst_key] = value

        rows.append(row)

    return rows


def export_unit_backbone_window_index(path: Path, rows: list[dict[str, Any]]) -> None:
    if not rows:
        if path.exists():
            path.unlink()
            print(
                "[build_attack_chain_v1] unit_backbone_window_index skipped; "
                f"no unit-attached backbone edges, removed stale file {path}"
            )
        else:
            print(
                "[build_attack_chain_v1] unit_backbone_window_index skipped; "
                "no unit-attached backbone edges"
            )
        return

    _write_jsonl(path, rows)
    print(
        "[build_attack_chain_v1] unit_backbone_window_index exported "
        f"rows={len(rows)} path={path}"
    )


def _safe_int(raw: Any) -> Optional[int]:
    try:
        return int(raw)
    except (TypeError, ValueError):
        return None


def _traffic_conn_key(l4_proto: Optional[str], src_ip: Any, src_port: Any, dst_ip: Any, dst_port: Any) -> Optional[str]:
    proto = str(l4_proto or "").lower().strip()
    if not proto:
        return None
    src_port_i = _safe_int(src_port)
    dst_port_i = _safe_int(dst_port)
    if not src_ip or src_port_i is None or not dst_ip or dst_port_i is None:
        return None
    return f"{proto}|{src_ip}:{src_port_i}|{dst_ip}:{dst_port_i}"


def build_traffic_backbone_candidate_index(
    traffic_anchor_index_path: Path,
    conntrack_nat_index_path: Path,
    scenario_id: Optional[str] = None,
) -> list[dict[str, Any]]:
    traffic_rows = list(_iter_jsonl(traffic_anchor_index_path)) if traffic_anchor_index_path.exists() else []
    conntrack_rows = list(_iter_jsonl(conntrack_nat_index_path)) if conntrack_nat_index_path.exists() else []

    conntrack_exact_map: dict[str, dict[str, Any]] = {}
    conntrack_reply_map: dict[str, dict[str, Any]] = {}
    service_by_container: dict[str, str] = {}
    for row in conntrack_rows:
        normalized_conn_key = row.get("normalized_conn_key")
        if normalized_conn_key:
            conntrack_exact_map.setdefault(str(normalized_conn_key), row)
        reply_key = _traffic_conn_key(
            row.get("transport_proto"),
            row.get("reply_src_ip"),
            row.get("reply_src_port"),
            row.get("reply_dst_ip"),
            row.get("reply_dst_port"),
        )
        if reply_key:
            conntrack_reply_map.setdefault(reply_key, row)
        container_id = row.get("container_id")
        service_name = row.get("service_name")
        if container_id and service_name and str(container_id) not in service_by_container:
            service_by_container[str(container_id)] = str(service_name)

    candidate_rows: list[dict[str, Any]] = []
    for row in traffic_rows:
        record_type = str(row.get("record_type") or "")
        if record_type == "anchor":
            packet_ref = row.get("packet_ref", {}) if isinstance(row.get("packet_ref"), dict) else {}
            packet_feature = row.get("packet_feature", {}) if isinstance(row.get("packet_feature"), dict) else {}
            node_anchor = row.get("node_anchor", {}) if isinstance(row.get("node_anchor"), dict) else {}
            traffic_event_key = packet_ref.get("event_key")
            source_file = packet_ref.get("source_file")
            line_no = packet_ref.get("line_no")
            frame_number = packet_ref.get("frame_number")
            l4_proto = packet_feature.get("l4_proto")
            src_ip = packet_feature.get("src_ip")
            src_port = packet_feature.get("src_port")
            dst_ip = packet_feature.get("dst_ip")
            dst_port = packet_feature.get("dst_port")
            normalized_conn_key = _traffic_conn_key(l4_proto, src_ip, src_port, dst_ip, dst_port)
            conntrack_row = None
            conntrack_match_status = "no_nat_alias"
            nat_alias_used = False
            if normalized_conn_key and normalized_conn_key in conntrack_exact_map:
                conntrack_row = conntrack_exact_map[normalized_conn_key]
                conntrack_match_status = "nat_alias_available"
                nat_alias_used = True
            elif normalized_conn_key and normalized_conn_key in conntrack_reply_map:
                conntrack_row = conntrack_reply_map[normalized_conn_key]
                conntrack_match_status = "nat_alias_available"
                nat_alias_used = True

            container_id = node_anchor.get("container_id")
            service_name = service_by_container.get(str(container_id)) if container_id is not None else None
            candidate_rows.append(
                {
                    "schema_version": TRAFFIC_BACKBONE_CANDIDATE_SCHEMA_VERSION,
                    "scenario_id": scenario_id,
                    "traffic_event_key": traffic_event_key,
                    "source_file": source_file,
                    "line_no": line_no,
                    "frame_number": frame_number,
                    "container_id": container_id,
                    "service_name": service_name,
                    "network_node_id": str(node_anchor.get("graph_node_id")) if node_anchor.get("graph_node_id") is not None else None,
                    "network_node_kind": "network_node",
                    "network_node_source": "traffic_node_anchor_index",
                    "conntrack_match_status": conntrack_match_status,
                    "normalized_conn_key": conntrack_row.get("normalized_conn_key") if conntrack_row else normalized_conn_key,
                    "nat_alias_used": nat_alias_used,
                    "candidate_backbone_edge_id": None,
                    "candidate_backbone_seq": None,
                    "candidate_backbone_relation": None,
                    "candidate_backbone_evt_num": None,
                    "candidate_rule": "node_anchor_with_nat_alias" if nat_alias_used else "node_anchor_only",
                    "candidate_source": "traffic_node_anchor_index+conntrack_nat_index" if nat_alias_used else "traffic_node_anchor_index",
                    "candidate_score": None,
                    "fallback_class": "node_anchor_with_nat_alias" if nat_alias_used else "node_anchor_only",
                    "is_selected": True,
                    "selection_rank": 1,
                }
            )
            continue

        if record_type == "miss_summary":
            pcap_file = row.get("pcap_file")
            miss_code = str(row.get("miss_code") or "unmapped")
            sample_frame_numbers = row.get("sample_frame_numbers", [])
            for frame_number in sample_frame_numbers:
                frame_i = _safe_int(frame_number)
                if frame_i is None:
                    continue
                container_id = None
                if pcap_file and "_" in str(pcap_file):
                    container_id = str(pcap_file).split("_", 1)[0]
                candidate_rows.append(
                    {
                        "schema_version": TRAFFIC_BACKBONE_CANDIDATE_SCHEMA_VERSION,
                        "scenario_id": scenario_id,
                        "traffic_event_key": f"traffic:{pcap_file}:{frame_i}",
                        "source_file": pcap_file,
                        "line_no": None,
                        "frame_number": frame_i,
                        "container_id": container_id,
                        "service_name": service_by_container.get(container_id) if container_id else None,
                        "network_node_id": None,
                        "network_node_kind": None,
                        "network_node_source": None,
                        "conntrack_match_status": "not_applicable",
                        "normalized_conn_key": None,
                        "nat_alias_used": False,
                        "candidate_backbone_edge_id": None,
                        "candidate_backbone_seq": None,
                        "candidate_backbone_relation": None,
                        "candidate_backbone_evt_num": None,
                        "candidate_rule": miss_code,
                        "candidate_source": "traffic_node_anchor_index_miss_summary",
                        "candidate_score": None,
                        "fallback_class": "unmapped",
                        "is_selected": True,
                        "selection_rank": 1,
                    }
                )

    return candidate_rows


def export_traffic_backbone_candidate_index(path: Path, rows: list[dict[str, Any]]) -> None:
    if not rows:
        if path.exists():
            path.unlink()
            print(
                "[build_attack_chain_v1] traffic_backbone_candidate_index skipped; "
                f"no traffic candidate rows, removed stale file {path}"
            )
        else:
            print(
                "[build_attack_chain_v1] traffic_backbone_candidate_index skipped; "
                "no traffic candidate rows"
            )
        return

    _write_jsonl(path, rows)
    print(
        "[build_attack_chain_v1] traffic_backbone_candidate_index exported "
        f"rows={len(rows)} path={path}"
    )


def export_backbone_refinement_residual(path: Path, rows: list[dict[str, Any]]) -> None:
    if not rows:
        if path.exists():
            path.unlink()
            print(
                "[build_attack_chain_v1] backbone_refinement_residual skipped; "
                f"no residual rows, removed stale file {path}"
            )
        else:
            print(
                "[build_attack_chain_v1] backbone_refinement_residual skipped; "
                "no residual rows"
            )
        return

    _write_jsonl(path, rows)
    print(
        "[build_attack_chain_v1] backbone_refinement_residual exported "
        f"rows={len(rows)} path={path}"
    )


def export_runtime_shell_block_summary(path: Path, rows: list[dict[str, Any]]) -> None:
    if not rows:
        if path.exists():
            path.unlink()
            print(
                "[build_attack_chain_v1] runtime_shell_block_summary skipped; "
                f"no block rows, removed stale file {path}"
            )
        else:
            print(
                "[build_attack_chain_v1] runtime_shell_block_summary skipped; "
                "no block rows"
            )
        return

    _write_jsonl(path, rows)
    print(
        "[build_attack_chain_v1] runtime_shell_block_summary exported "
        f"rows={len(rows)} path={path}"
    )


def export_entry_candidate_block_summary(path: Path, rows: list[dict[str, Any]]) -> None:
    if not rows:
        if path.exists():
            path.unlink()
            print(
                "[build_attack_chain_v1] entry_candidate_block_summary skipped; "
                f"no entry candidate rows, removed stale file {path}"
            )
        else:
            print(
                "[build_attack_chain_v1] entry_candidate_block_summary skipped; "
                "no entry candidate rows"
            )
        return

    _write_jsonl(path, rows)
    print(
        "[build_attack_chain_v1] entry_candidate_block_summary exported "
        f"rows={len(rows)} path={path}"
    )


def run_build_attack_chain_v1(
    scenario_dir: Path,
    triples_path: Optional[Path] = None,
    subgraph_path: Optional[Path] = None,
    backbone_path: Optional[Path] = None,
    unit_backbone_window_path: Optional[Path] = None,
    unit_event_path: Optional[Path] = None,
    unit_index_path: Optional[Path] = None,
    anchors_path: Optional[Path] = None,
    max_hops: int = 1,
    seed_mode: str = "auto",
    strict: bool = True,
    b_fallback_net_pair_required: bool = False,
    b_fallback_net_pair_window_evt: int = 15,
    save_attack_subgraph: bool = False,
    skip_save_attack_subgraph: bool = False,
    backbone_file_devnull_filter: bool = False,
    backbone_file_node_modules_filter: bool = False,
    backbone_file_label_low_info: bool = False,
    backbone_file_label_vendor_composer: bool = False,
    backbone_broad_gate_on_warning: bool = False,
    backbone_broad_gate_relations: str | None = None,
    backbone_broad_gate_window_evt: int = 12,
    backbone_broad_gate_fork_repeat_sparse_experiment: bool = False,
    backbone_broad_gate_fork_repeat_unknown_child_stride: int = 80,
    backbone_broad_gate_fork_parent_cluster_experiment: bool = False,
    backbone_broad_gate_fork_parent_cluster_gap_evt: int = 5000,
    backbone_broad_gate_fork_parent_cluster_min_subject_edges: int = 8,
    backbone_broad_gate_net_accept_repeat_sparse_experiment: bool = False,
    backbone_broad_gate_net_accept_repeat_stride: int = 80,
    backbone_runtime_shell_block_representative_experiment: bool = False,
    backbone_runtime_shell_block_relations: str | None = None,
    backbone_runtime_shell_block_min_block_edges: int = DEFAULT_RUNTIME_SHELL_BLOCK_TRIAL_MIN_BLOCK_EDGES,
    backbone_runtime_shell_block_min_overlap_ratio: float = DEFAULT_RUNTIME_SHELL_BLOCK_TRIAL_MIN_OVERLAP_RATIO,
    backbone_runtime_shell_block_net_accept_subject_anchor_trial: bool = (
        DEFAULT_RUNTIME_SHELL_BLOCK_NET_ACCEPT_SUBJECT_ANCHOR_TRIAL
    ),
    backbone_runtime_shell_block_process_fork_hybrid_gate: bool = (
        DEFAULT_RUNTIME_SHELL_BLOCK_PROCESS_FORK_HYBRID_GATE
    ),
    backbone_runtime_shell_block_process_fork_hybrid_min_overlap_ratio: float = (
        DEFAULT_RUNTIME_SHELL_BLOCK_PROCESS_FORK_HYBRID_MIN_OVERLAP_RATIO
    ),
    backbone_runtime_shell_block_process_fork_hybrid_min_overlap_edges: int = (
        DEFAULT_RUNTIME_SHELL_BLOCK_PROCESS_FORK_HYBRID_MIN_OVERLAP_EDGES
    ),
    backbone_refinement_planner_mode: bool = False,
    backbone_refinement_planner_user_overrides: Optional[dict[str, Optional[bool]]] = None,
    backbone_preparation_shell_trial: bool = False,
    backbone_disable_preparation_shell_trial: bool = False,
) -> int:
    run_t0 = time.perf_counter()
    print(f"[build_attack_chain_v1] run start scenario_dir={scenario_dir}")
    paths = resolve_paths(
        scenario_dir=scenario_dir,
        triples_path=triples_path,
        subgraph_path=subgraph_path,
        backbone_path=backbone_path,
        unit_event_path=unit_event_path,
        unit_index_path=unit_index_path,
    )
    warnings: list[str] = []
    save_subgraph_output = bool(save_attack_subgraph)
    if save_attack_subgraph and skip_save_attack_subgraph:
        print(
            "[build_attack_chain_v1][warning] both --save-attack-subgraph and "
            "--skip-save-attack-subgraph were set; --save-attack-subgraph takes precedence"
        )
    unit_backbone_window_out = unit_backbone_window_path or (
        paths["chain_dir"] / "unit_backbone_window_index.v0.jsonl"
    )
    traffic_backbone_candidate_out = paths["chain_dir"] / "traffic_backbone_candidate_index.v0.jsonl"
    refinement_residual_out = paths["chain_dir"] / DEFAULT_REFINEMENT_RESIDUAL_PATH.name
    runtime_shell_block_summary_out = (
        paths["chain_dir"] / DEFAULT_RUNTIME_SHELL_BLOCK_SUMMARY_PATH.name
    )
    entry_candidate_block_summary_out = (
        paths["chain_dir"] / DEFAULT_ENTRY_CANDIDATE_BLOCK_SUMMARY_PATH.name
    )

    phase_t0 = time.perf_counter()
    print("[build_attack_chain_v1] phase load_triples start")
    triples, load_stats, load_warnings = load_audit_triples(
        triples_path=paths["triples"],
        allowed_relations=CORE_RELATIONS,
        strict=strict,
    )
    print(
        "[build_attack_chain_v1] phase load_triples done "
        f"elapsed_s={round(time.perf_counter() - phase_t0, 2)} triples_total={len(triples)}"
    )
    warnings.extend(load_warnings)

    phase_t0 = time.perf_counter()
    print("[build_attack_chain_v1] phase load_unit_event_index start")
    evt_to_unit, unit_event_stats, unit_event_warnings = load_unit_event_index(paths["unit_event_index"])
    print(
        "[build_attack_chain_v1] phase load_unit_event_index done "
        f"elapsed_s={round(time.perf_counter() - phase_t0, 2)} "
        f"lines={unit_event_stats.get('total_lines', 0)} nonnull={unit_event_stats.get('nonnull_unit', 0)}"
    )
    warnings.extend(unit_event_warnings)

    phase_t0 = time.perf_counter()
    print("[build_attack_chain_v1] phase load_unit_index start")
    unit_meta, unit_index_stats, unit_index_warnings = load_unit_index(paths["unit_index"])
    print(
        "[build_attack_chain_v1] phase load_unit_index done "
        f"elapsed_s={round(time.perf_counter() - phase_t0, 2)} "
        f"lines={unit_index_stats.get('total_lines', 0)} valid={unit_index_stats.get('valid', 0)}"
    )
    warnings.extend(unit_index_warnings)

    unit_mode, unit_mode_reason = classify_unit_mode(
        unit_event_stats=unit_event_stats,
        unit_index_stats=unit_index_stats,
    )
    if unit_mode != "unit-ready":
        warnings.append(f"unit_mode={unit_mode} reason={unit_mode_reason}")

    phase_t0 = time.perf_counter()
    print("[build_attack_chain_v1] phase attach_unit_context start")
    edge_to_unit, attach_stats = attach_unit_context_to_triples(
        triples=triples,
        evt_to_unit=evt_to_unit,
    )
    print(
        "[build_attack_chain_v1] phase attach_unit_context done "
        f"elapsed_s={round(time.perf_counter() - phase_t0, 2)} "
        f"triples_total={attach_stats.get('triples_total', 0)} unit_nonnull={attach_stats.get('unit_nonnull', 0)}"
    )

    # evt_to_unit's only consumer is attach_unit_context_to_triples; after
    # that all downstream lookups go through edge_to_unit. Dropping it here
    # frees a dict that, even in sparse form, can still represent a
    # noticeable share of resident memory on heavy scenarios. The
    # before/after markers make the delta visible in the pipeline log.
    _emit_memory_marker(
        "release_before:evt_to_unit",
        evt_to_unit_size=len(evt_to_unit),
    )
    del evt_to_unit
    gc.collect()
    _emit_memory_marker("release_after:evt_to_unit")

    external_anchors = load_external_anchors(anchors_path)

    phase_t0 = time.perf_counter()
    print("[build_attack_chain_v1] phase build_graph start")
    graph_obj = build_triple_graph(triples)
    print(
        "[build_attack_chain_v1] phase build_graph done "
        f"elapsed_s={round(time.perf_counter() - phase_t0, 2)} "
        f"graph_edges={len(graph_obj.get('edges_by_id', {}))} graph_nodes={len(graph_obj.get('nodes_by_id', {}))}"
    )

    phase_t0 = time.perf_counter()
    print("[build_attack_chain_v1] phase identify_seeds start")
    seeds, seed_warnings = identify_seeds(
        graph_obj=graph_obj,
        triples=triples,
        external_anchors=external_anchors,
        seed_mode=seed_mode,
    )
    print(
        "[build_attack_chain_v1] phase identify_seeds done "
        f"elapsed_s={round(time.perf_counter() - phase_t0, 2)} "
        f"seed_edges={len(seeds.get('seed_edges', []))} seed_nodes={len(seeds.get('seed_nodes', []))}"
    )
    warnings.extend(seed_warnings)

    # After seed identification the original ``triples`` list is no longer
    # required. ``graph_obj.edges_by_id`` holds references to the same edge
    # dicts, so dropping the list container does not free the dicts
    # themselves, but it does release the ~N*8 byte Python list slot
    # overhead (~80 MB for 10M edges) and -- more importantly -- removes
    # one of the two strong references to the edge dicts, which lets the
    # next phase (extract_attack_subgraph) free individual edges via
    # graph_obj cleanup below.
    _emit_memory_marker(
        "release_before:triples_list",
        triples_list_size=len(triples),
    )
    del triples
    gc.collect()
    _emit_memory_marker("release_after:triples_list")

    seed_unit_set, seed_unit_stats = derive_seed_unit_set(
        seed_edges=list(seeds.get("seed_edges", [])),
        edges_by_id=graph_obj["edges_by_id"],
        edge_to_unit=edge_to_unit,
    )

    mode_metrics = compute_mode_metrics(
        unit_attach_stats=attach_stats,
        seed_unit_stats=seed_unit_stats,
    )
    builder_mode, mode_reason = select_builder_mode(mode_metrics)
    print(
        "[build_attack_chain_v1] phase mode_selection done "
        f"builder_mode={builder_mode} mode_reason={mode_reason} "
        f"unit_nonnull_ratio={round(float(mode_metrics.get('unit_nonnull_ratio', 0.0)), 6)} "
        f"seed_edges_total={mode_metrics.get('seed_edges_total', 0)} "
        f"seed_unit_count={mode_metrics.get('seed_unit_count', 0)}"
    )

    scenario_id = scenario_dir.name if scenario_dir.name else None
    fallback_hop_limit = max(max_hops, int(DEFAULT_FALLBACK_CONFIG["hop_limit"]))
    fallback_time_window_sec = int(DEFAULT_FALLBACK_CONFIG["time_window_sec"])

    phase_t0 = time.perf_counter()
    print("[build_attack_chain_v1] phase extract_attack_subgraph start")
    attack_subgraph, subgraph_warnings = extract_attack_subgraph(
        graph_obj=graph_obj,
        seeds=seeds,
        edge_to_unit=edge_to_unit,
        seed_unit_set=seed_unit_set,
        unit_meta=unit_meta,
        max_hops=(fallback_hop_limit if builder_mode in {"B", "C"} else max_hops),
        scenario_id=scenario_id,
        builder_mode=builder_mode,
        mode_reason=mode_reason,
        mode_metrics=mode_metrics,
        fallback_time_window_sec=fallback_time_window_sec,
        b_fallback_net_pair_required=b_fallback_net_pair_required,
        b_fallback_net_pair_window_evt=b_fallback_net_pair_window_evt,
    )
    print(
        "[build_attack_chain_v1] phase extract_attack_subgraph done "
        f"elapsed_s={round(time.perf_counter() - phase_t0, 2)} "
        f"edge_count={attack_subgraph.get('graph_summary', {}).get('edge_count', 0)}"
    )
    print("[build_attack_chain_v1] attack_subgraph built in memory for backbone derivation")
    warnings.extend(subgraph_warnings)

    # ``graph_obj`` is the peak-memory anchor of the backbone phase: it owns
    # the full-graph adjacency (set[str] per node, O(edges) entries),
    # relation_index (list[str] per relation, O(edges) entries), and the
    # ``edges_by_id`` dict that keeps all 10M+ edge dicts alive. The only
    # consumer of ``graph_obj`` beyond this point is ``extract_attack_subgraph``
    # itself, which has just returned. The downstream phases
    # (build_runtime_shell_block_summary -> build_entry_candidate_block_summary
    # -> derive_backbone_chain) operate exclusively on ``attack_subgraph``
    # and ``edge_to_unit``. Dropping ``graph_obj`` here releases the
    # full-graph adjacency / relation_index immediately, and allows Python
    # to reclaim every edge dict that was not kept by the extracted
    # subgraph -- typically the vast majority on heavy traces. This is
    # the single most important free() for avoiding OOM kills in the
    # derive_backbone_chain phase.
    _emit_memory_marker(
        "release_before:graph_obj",
        graph_obj_edges=len(graph_obj.get("edges_by_id", {}) or {}),
        graph_obj_nodes=len(graph_obj.get("nodes_by_id", {}) or {}),
        attack_subgraph_edges=len(attack_subgraph.get("edges") or []),
    )
    # Explicitly break internal cycles so the GC does not need a full
    # cycle-collection pass to reclaim these containers.
    try:
        graph_obj.get("adjacency", {}).clear()
        graph_obj.get("relation_index", {}).clear()
        graph_obj.get("edges_by_id", {}).clear()
        graph_obj.get("nodes_by_id", {}).clear()
    except Exception:
        # Defensive: cleanup must never fail the pipeline. If any field
        # is unexpectedly missing we still ``del`` below.
        pass
    del graph_obj
    gc.collect()
    _emit_memory_marker("release_after:graph_obj")

    phase_t0 = time.perf_counter()
    print("[build_attack_chain_v1] phase export_runtime_shell_block_summary start")
    runtime_shell_block_rows = build_runtime_shell_block_summary(
        attack_subgraph=attack_subgraph,
        edge_to_unit=edge_to_unit,
        scenario_id=scenario_id,
    )
    export_runtime_shell_block_summary(runtime_shell_block_summary_out, runtime_shell_block_rows)
    print(
        "[build_attack_chain_v1] phase export_runtime_shell_block_summary done "
        f"elapsed_s={round(time.perf_counter() - phase_t0, 2)} rows={len(runtime_shell_block_rows)}"
    )

    phase_t0 = time.perf_counter()
    print("[build_attack_chain_v1] phase export_entry_candidate_block_summary start")
    entry_candidate_block_rows = build_entry_candidate_block_summary(
        attack_subgraph=attack_subgraph,
        runtime_block_rows=runtime_shell_block_rows,
        scenario_id=scenario_id,
    )
    export_entry_candidate_block_summary(entry_candidate_block_summary_out, entry_candidate_block_rows)
    print(
        "[build_attack_chain_v1] phase export_entry_candidate_block_summary done "
        f"elapsed_s={round(time.perf_counter() - phase_t0, 2)} rows={len(entry_candidate_block_rows)}"
    )

    phase_t0 = time.perf_counter()
    print("[build_attack_chain_v1] phase derive_backbone_chain start")
    backbone_chain, chain_warnings, refinement_residual_rows = derive_backbone_chain(
        attack_subgraph=attack_subgraph,
        scenario_id=scenario_id,
        edge_to_unit=edge_to_unit,
        backbone_file_devnull_filter=backbone_file_devnull_filter,
        backbone_file_node_modules_filter=backbone_file_node_modules_filter,
        backbone_file_label_low_info=backbone_file_label_low_info,
        backbone_file_label_vendor_composer=backbone_file_label_vendor_composer,
        backbone_broad_gate_on_warning=backbone_broad_gate_on_warning,
        backbone_broad_gate_relations=_normalize_relation_csv(backbone_broad_gate_relations),
        backbone_broad_gate_window_evt=backbone_broad_gate_window_evt,
        backbone_broad_gate_fork_repeat_sparse_experiment=backbone_broad_gate_fork_repeat_sparse_experiment,
        backbone_broad_gate_fork_repeat_unknown_child_stride=backbone_broad_gate_fork_repeat_unknown_child_stride,
        backbone_broad_gate_fork_parent_cluster_experiment=(
            backbone_broad_gate_fork_parent_cluster_experiment
        ),
        backbone_broad_gate_fork_parent_cluster_gap_evt=(
            backbone_broad_gate_fork_parent_cluster_gap_evt
        ),
        backbone_broad_gate_fork_parent_cluster_min_subject_edges=(
            backbone_broad_gate_fork_parent_cluster_min_subject_edges
        ),
        backbone_broad_gate_net_accept_repeat_sparse_experiment=(
            backbone_broad_gate_net_accept_repeat_sparse_experiment
        ),
        backbone_broad_gate_net_accept_repeat_stride=backbone_broad_gate_net_accept_repeat_stride,
        runtime_shell_block_rows=runtime_shell_block_rows,
        backbone_runtime_shell_block_representative_experiment=(
            backbone_runtime_shell_block_representative_experiment
        ),
        backbone_runtime_shell_block_relations=_normalize_relation_csv_with_default(
            backbone_runtime_shell_block_relations,
            DEFAULT_RUNTIME_SHELL_BLOCK_TRIAL_RELATIONS,
        ),
        backbone_runtime_shell_block_min_block_edges=max(
            2,
            int(backbone_runtime_shell_block_min_block_edges),
        ),
        backbone_runtime_shell_block_min_overlap_ratio=max(
            0.0,
            min(1.0, float(backbone_runtime_shell_block_min_overlap_ratio)),
        ),
        backbone_runtime_shell_block_net_accept_subject_anchor_trial=(
            backbone_runtime_shell_block_net_accept_subject_anchor_trial
        ),
        backbone_runtime_shell_block_process_fork_hybrid_gate=(
            backbone_runtime_shell_block_process_fork_hybrid_gate
        ),
        backbone_runtime_shell_block_process_fork_hybrid_min_overlap_ratio=max(
            0.0,
            min(
                1.0,
                float(
                    backbone_runtime_shell_block_process_fork_hybrid_min_overlap_ratio
                ),
            ),
        ),
        backbone_runtime_shell_block_process_fork_hybrid_min_overlap_edges=max(
            1,
            int(
                backbone_runtime_shell_block_process_fork_hybrid_min_overlap_edges
            ),
        ),
        backbone_refinement_planner_mode=bool(
            backbone_refinement_planner_mode
        ),
        backbone_refinement_planner_user_overrides=(
            backbone_refinement_planner_user_overrides
        ),
        backbone_preparation_shell_trial=bool(
            backbone_preparation_shell_trial
        ),
        backbone_disable_preparation_shell_trial=bool(
            backbone_disable_preparation_shell_trial
        ),
    )
    refinement_plan_log = (
        backbone_chain.get("chain_summary", {}).get("refinement_plan") or {}
    )
    if refinement_plan_log.get("planner_active"):
        _triggers_log = refinement_plan_log.get("triggers") or {}

        def _raw(name: str) -> Any:
            return bool(
                (_triggers_log.get(name) or {}).get("trigger", False)
            )

        print(
            "[build_attack_chain_v1] refinement_plan auto_decisions "
            f"A={_raw('net_accept_subject_anchor')} "
            f"B={_raw('process_fork_hybrid_gate')} "
            f"C={_raw('process_fork_parent_cluster')} "
            f"D={_raw('preparation_shell')} "
            "(post_override: "
            f"A={refinement_plan_log.get('enable_net_accept_subject_anchor')} "
            f"B={refinement_plan_log.get('enable_process_fork_hybrid_gate')} "
            f"C={refinement_plan_log.get('enable_process_fork_parent_cluster')} "
            f"D={refinement_plan_log.get('enable_preparation_shell')})"
        )
    _prep_stats_log = (
        backbone_chain.get("chain_summary", {}).get("preparation_shell_trial")
        or {}
    )
    if _prep_stats_log:
        print(
            "[build_attack_chain_v1] preparation_shell_trial "
            f"applied={_prep_stats_log.get('applied')} "
            f"reason={_prep_stats_log.get('reason')} "
            f"planner_structural_trigger={_prep_stats_log.get('planner_structural_trigger')} "
            f"user_override={_prep_stats_log.get('user_override')} "
            f"collapsed={_prep_stats_log.get('collapsed_edges')} "
            f"kept={_prep_stats_log.get('kept_edges')}"
        )
    print(
        "[build_attack_chain_v1] phase derive_backbone_chain done "
        f"elapsed_s={round(time.perf_counter() - phase_t0, 2)} "
        f"edge_count={backbone_chain.get('chain_summary', {}).get('edge_count', 0)}"
    )
    warnings.extend(chain_warnings)

    if save_subgraph_output:
        print("[build_attack_chain_v1] attack_subgraph export enabled by --save-attack-subgraph")
        phase_t0 = time.perf_counter()
        print("[build_attack_chain_v1] phase save_attack_subgraph start")
        save_attack_subgraph(paths["attack_subgraph"], attack_subgraph)
        print(
            "[build_attack_chain_v1] phase save_attack_subgraph done "
            f"elapsed_s={round(time.perf_counter() - phase_t0, 2)}"
        )
    else:
        if skip_save_attack_subgraph:
            print(
                "[build_attack_chain_v1] phase save_attack_subgraph skipped by "
                "compatibility flag --skip-save-attack-subgraph; export default is disabled"
            )
        else:
            print(
                "[build_attack_chain_v1] phase save_attack_subgraph skipped by default policy "
                "(memory-only intermediate)"
            )
        print(
            "[build_attack_chain_v1] attack_subgraph built in memory; "
            "file export disabled by default; backbone output will continue"
        )

    phase_t0 = time.perf_counter()
    print("[build_attack_chain_v1] phase save_backbone_chain start")
    save_backbone_chain(paths["backbone_chain"], backbone_chain)
    print(
        "[build_attack_chain_v1] phase save_backbone_chain done "
        f"elapsed_s={round(time.perf_counter() - phase_t0, 2)}"
    )

    phase_t0 = time.perf_counter()
    print("[build_attack_chain_v1] phase export_backbone_refinement_residual start")
    export_backbone_refinement_residual(refinement_residual_out, refinement_residual_rows)
    print(
        "[build_attack_chain_v1] phase export_backbone_refinement_residual done "
        f"elapsed_s={round(time.perf_counter() - phase_t0, 2)} rows={len(refinement_residual_rows)}"
    )

    phase_t0 = time.perf_counter()
    print("[build_attack_chain_v1] phase export_unit_backbone_window_index start")
    unit_backbone_window_rows = build_unit_backbone_window_index(
        backbone_chain=backbone_chain,
        edge_to_unit=edge_to_unit,
        unit_meta=unit_meta,
        scenario_id=scenario_id,
    )
    export_unit_backbone_window_index(unit_backbone_window_out, unit_backbone_window_rows)
    print(
        "[build_attack_chain_v1] phase export_unit_backbone_window_index done "
        f"elapsed_s={round(time.perf_counter() - phase_t0, 2)} rows={len(unit_backbone_window_rows)}"
    )

    phase_t0 = time.perf_counter()
    print("[build_attack_chain_v1] phase export_traffic_backbone_candidate_index start")
    traffic_candidate_rows = build_traffic_backbone_candidate_index(
        traffic_anchor_index_path=paths["index_dir"] / "traffic_node_anchor_index.v0.jsonl",
        conntrack_nat_index_path=paths["index_dir"] / "conntrack_nat_index.v0.jsonl",
        scenario_id=scenario_id,
    )
    export_traffic_backbone_candidate_index(traffic_backbone_candidate_out, traffic_candidate_rows)
    print(
        "[build_attack_chain_v1] phase export_traffic_backbone_candidate_index done "
        f"elapsed_s={round(time.perf_counter() - phase_t0, 2)} rows={len(traffic_candidate_rows)}"
    )

    print("[build_attack_chain_v1] done")
    print(f"  triples_in={paths['triples']}")
    if save_subgraph_output:
        print(f"  attack_subgraph_out={paths['attack_subgraph']}")
    elif skip_save_attack_subgraph:
        print(
            f"  attack_subgraph_out={paths['attack_subgraph']} "
            "(not_written; compatibility flag --skip-save-attack-subgraph)"
        )
    else:
        print(
            f"  attack_subgraph_out={paths['attack_subgraph']} "
            "(not_written; default export disabled)"
        )
    print(f"  backbone_chain_out={paths['backbone_chain']}")
    print(f"  backbone_refinement_residual_out={refinement_residual_out}")
    print(f"  runtime_shell_block_summary_out={runtime_shell_block_summary_out}")
    print(f"  entry_candidate_block_summary_out={entry_candidate_block_summary_out}")
    print(f"  unit_backbone_window_index_out={unit_backbone_window_out}")
    print(f"  traffic_backbone_candidate_index_out={traffic_backbone_candidate_out}")
    print(f"  stats={load_stats}")
    print(f"  unit_event_index={paths['unit_event_index']}")
    print(f"  unit_index={paths['unit_index']}")
    print(f"  unit_mode={unit_mode}")
    print(f"  unit_mode_reason={unit_mode_reason}")
    print(f"  unit_event_stats={unit_event_stats}")
    print(f"  unit_index_stats={unit_index_stats}")
    print(f"  unit_attach_stats={attach_stats}")
    print(f"  seed_unit_stats={seed_unit_stats}")
    print(f"  builder_mode={builder_mode}")
    print(f"  mode_metrics={mode_metrics}")
    print(f"  mode_reason={mode_reason}")
    print(f"  backbone_broad_gate_on_warning={backbone_broad_gate_on_warning}")
    print(
        "  backbone_broad_gate_relations="
        f"{list(_normalize_relation_csv(backbone_broad_gate_relations))}"
    )
    print(f"  backbone_broad_gate_window_evt={backbone_broad_gate_window_evt}")
    print(
        "  backbone_broad_gate_fork_repeat_sparse_experiment="
        f"{backbone_broad_gate_fork_repeat_sparse_experiment}"
    )
    print(
        "  backbone_broad_gate_fork_repeat_unknown_child_stride="
        f"{backbone_broad_gate_fork_repeat_unknown_child_stride}"
    )
    print(
        "  backbone_broad_gate_fork_parent_cluster_experiment="
        f"{backbone_broad_gate_fork_parent_cluster_experiment}"
    )
    print(
        "  backbone_broad_gate_fork_parent_cluster_gap_evt="
        f"{backbone_broad_gate_fork_parent_cluster_gap_evt}"
    )
    print(
        "  backbone_broad_gate_fork_parent_cluster_min_subject_edges="
        f"{backbone_broad_gate_fork_parent_cluster_min_subject_edges}"
    )
    print(
        "  backbone_broad_gate_net_accept_repeat_sparse_experiment="
        f"{backbone_broad_gate_net_accept_repeat_sparse_experiment}"
    )
    print(
        "  backbone_broad_gate_net_accept_repeat_stride="
        f"{backbone_broad_gate_net_accept_repeat_stride}"
    )
    print(
        "  backbone_runtime_shell_block_representative_experiment="
        f"{backbone_runtime_shell_block_representative_experiment}"
    )
    print(
        "  backbone_runtime_shell_block_relations="
        f"{list(_normalize_relation_csv_with_default(backbone_runtime_shell_block_relations, DEFAULT_RUNTIME_SHELL_BLOCK_TRIAL_RELATIONS))}"
    )
    print(
        "  backbone_runtime_shell_block_min_block_edges="
        f"{backbone_runtime_shell_block_min_block_edges}"
    )
    print(
        "  backbone_runtime_shell_block_min_overlap_ratio="
        f"{backbone_runtime_shell_block_min_overlap_ratio}"
    )

    if warnings:
        print("  warnings:")
        for w in warnings:
            print(f"    - {w}")

    print(f"[build_attack_chain_v1] run done elapsed_s={round(time.perf_counter() - run_t0, 2)}")

    return 0


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build single-scenario attack chain v1")
    parser.add_argument(
        "--scenario-dir",
        type=Path,
        default=SCENARIO_DIR,
        help="Override scenario timestamp directory (default: SCENARIO_DIR constant)",
    )
    parser.add_argument(
        "--triples-path",
        type=Path,
        default=None,
        help="Override triples JSONL path (default: <scenario_dir>/chain/audit_triples.core.v1.jsonl)",
    )
    parser.add_argument(
        "--subgraph-path",
        type=Path,
        default=None,
        help="Override attack_subgraph output path (default: <scenario_dir>/chain/attack_subgraph.v1.json)",
    )
    parser.add_argument(
        "--backbone-path",
        type=Path,
        default=None,
        help="Override backbone_chain output path (default: <scenario_dir>/chain/backbone_chain.v1.json)",
    )
    parser.add_argument(
        "--unit-event-path",
        type=Path,
        default=None,
        help="Optional unit_event_index.jsonl path (default: <scenario_dir>/index/unit_event_index.jsonl)",
    )
    parser.add_argument(
        "--unit-index-path",
        type=Path,
        default=None,
        help="Optional unit_index.jsonl path (default: <scenario_dir>/index/unit_index.jsonl)",
    )
    parser.add_argument(
        "--anchors-path",
        type=Path,
        default=None,
        help="Optional external anchors JSON path",
    )
    parser.add_argument(
        "--max-hops",
        type=int,
        default=1,
        help="Seed expansion hops for attack subgraph extraction",
    )
    parser.add_argument(
        "--seed-mode",
        type=str,
        default="auto",
        choices=["auto", "malicious_only", "anchor_only"],
        help="Seed mode",
    )
    parser.add_argument(
        "--non-strict",
        action="store_true",
        help="Skip invalid lines instead of treating validation issues as strict warnings",
    )
    parser.add_argument(
        "--b-fallback-net-pair-required",
        action="store_true",
        help="Enable B-mode fallback NET pairing filter",
    )
    parser.add_argument(
        "--b-fallback-net-pair-window-evt",
        type=int,
        default=15,
        help="Event number window for NET pairing (default: 15)",
    )
    parser.add_argument(
        "--save-attack-subgraph",
        action="store_true",
        help="Explicitly write attack_subgraph.v1.json (default: disabled; memory-only intermediate)",
    )
    parser.add_argument(
        "--skip-save-attack-subgraph",
        action="store_true",
        help=(
            "Compatibility flag: keep accepted for old callers. "
            "Default is already no export; if --save-attack-subgraph is also set, save takes precedence"
        ),
    )
    parser.add_argument(
        "--backbone-file-devnull-filter",
        action="store_true",
        help="Filter FILE edges whose object is /dev/null from backbone (seed edges exempt)",
    )
    parser.add_argument(
        "--backbone-file-node-modules-filter",
        action="store_true",
        help="Filter FILE edges whose object contains node_modules/ from backbone",
    )
    parser.add_argument(
        "--backbone-file-label-low-info",
        action="store_true",
        help="Label low-information FILE edges in backbone (devnull, node_modules) without removing them",
    )
    parser.add_argument(
        "--backbone-file-label-vendor-composer",
        action="store_true",
        help="Label FILE edges targeting vendor/composer autoload paths as low_info_path=vendor_composer",
    )
    parser.add_argument(
        "--backbone-broad-gate-on-warning",
        action="store_true",
        help=(
            "Optionally tighten warned backbone scenes by filtering non-malicious "
            "NET/PROCESS tails; only applies when warning rules are triggered"
        ),
    )
    parser.add_argument(
        "--backbone-broad-gate-relations",
        type=str,
        default=",".join(DEFAULT_BROAD_GATE_RELATIONS),
        help="Comma-separated relation allowlist for optional broad-scene gate",
    )
    parser.add_argument(
        "--backbone-broad-gate-window-evt",
        type=int,
        default=12,
        help="Event-number proximity window for optional broad-scene gate (default: 12)",
    )
    parser.add_argument(
        "--backbone-broad-gate-fork-repeat-sparse-experiment",
        action="store_true",
        help=(
            "Experiment switch: sparsify repeated non-malicious unknown-child PROCESS_FORK "
            "edges after warning-triggered gate checks"
        ),
    )
    parser.add_argument(
        "--backbone-broad-gate-fork-repeat-unknown-child-stride",
        type=int,
        default=80,
        help=(
            "Experiment sparse stride for repeated unknown-child PROCESS_FORK "
            "(default: 80, keep 1 in each N edges per subject process)"
        ),
    )
    parser.add_argument(
        "--backbone-broad-gate-fork-parent-cluster-experiment",
        action="store_true",
        help=(
            "Experiment switch: summarize repeated non-malicious PROCESS_FORK "
            "by parent-process derivation clusters after warning-triggered gate checks"
        ),
    )
    parser.add_argument(
        "--backbone-broad-gate-fork-parent-cluster-gap-evt",
        type=int,
        default=5000,
        help=(
            "Maximum evt_num gap used to split repeated PROCESS_FORK parent clusters "
            "(default: 5000)"
        ),
    )
    parser.add_argument(
        "--backbone-broad-gate-fork-parent-cluster-min-subject-edges",
        type=int,
        default=8,
        help=(
            "Minimum repeated PROCESS_FORK edges for a parent process before "
            "parent-cluster representative retention activates (default: 8)"
        ),
    )
    parser.add_argument(
        "--backbone-broad-gate-net-accept-repeat-sparse-experiment",
        action="store_true",
        help=(
            "Experiment switch: sparsify repeated non-malicious NET_ACCEPT edges "
            "after warning-triggered gate checks"
        ),
    )
    parser.add_argument(
        "--backbone-broad-gate-net-accept-repeat-stride",
        type=int,
        default=80,
        help=(
            "Experiment sparse stride for repeated non-malicious NET_ACCEPT "
            "(default: 80, keep first/last and 1 in each N edges per subject process)"
        ),
    )
    parser.add_argument(
        "--backbone-runtime-shell-block-representative-experiment",
        action="store_true",
        help=(
            "Post-backbone narrow trial: for runtime shell blocks, keep representative "
            "edges only and sink the rest into refinement residual"
        ),
    )
    parser.add_argument(
        "--backbone-runtime-shell-block-relations",
        type=str,
        default=",".join(DEFAULT_RUNTIME_SHELL_BLOCK_TRIAL_RELATIONS),
        help="Comma-separated runtime shell relations for representative trial",
    )
    parser.add_argument(
        "--backbone-runtime-shell-block-min-block-edges",
        type=int,
        default=DEFAULT_RUNTIME_SHELL_BLOCK_TRIAL_MIN_BLOCK_EDGES,
        help="Minimum runtime block edge count to trigger representative trial",
    )
    parser.add_argument(
        "--backbone-runtime-shell-block-min-overlap-ratio",
        type=float,
        default=DEFAULT_RUNTIME_SHELL_BLOCK_TRIAL_MIN_OVERLAP_RATIO,
        help=(
            "Minimum overlap ratio between runtime block and current backbone "
            "before representative trial is applied (0.0~1.0)"
        ),
    )
    parser.add_argument(
        "--backbone-runtime-shell-block-net-accept-subject-anchor-trial",
        action="store_true",
        help=(
            "Directed trial A (mongo-express style): in the trial view only, "
            "re-aggregate NET_ACCEPT blocks by (unit, subject) instead of "
            "(unit, subject, conn) so that single-edge per-conn blocks can "
            "combine into a cohesive trial block. Exported sidecar is "
            "unchanged."
        ),
    )
    parser.add_argument(
        "--backbone-runtime-shell-block-process-fork-hybrid-gate",
        action="store_true",
        help=(
            "Directed trial B (pgadmin style): in the trial view only, "
            "replace the uniform overlap-ratio gate with a hybrid gate "
            "(ratio + absolute overlap edge count) for PROCESS_FORK "
            "target blocks."
        ),
    )
    parser.add_argument(
        "--backbone-runtime-shell-block-process-fork-hybrid-min-overlap-ratio",
        type=float,
        default=DEFAULT_RUNTIME_SHELL_BLOCK_PROCESS_FORK_HYBRID_MIN_OVERLAP_RATIO,
        help=(
            "Hybrid gate: minimum overlap ratio for PROCESS_FORK target "
            "blocks (used only when the hybrid gate trial is enabled)"
        ),
    )
    parser.add_argument(
        "--backbone-runtime-shell-block-process-fork-hybrid-min-overlap-edges",
        type=int,
        default=DEFAULT_RUNTIME_SHELL_BLOCK_PROCESS_FORK_HYBRID_MIN_OVERLAP_EDGES,
        help=(
            "Hybrid gate: minimum absolute overlap edge count for "
            "PROCESS_FORK target blocks (used only when the hybrid gate "
            "trial is enabled)"
        ),
    )
    parser.add_argument(
        "--backbone-refinement-planner-mode",
        action="store_true",
        help=(
            "Enable conditional-triggered refinement planner. When on, the "
            "planner inspects structural evidence in the pre-refinement "
            "edge list and auto-selects A (net_accept_subject_anchor), "
            "B (process_fork_hybrid_gate), C (process_fork_parent_cluster). "
            "Any explicit --backbone-...-trial / experiment flag still wins "
            "as a user override."
        ),
    )
    parser.add_argument(
        "--backbone-preparation-shell-trial",
        action="store_true",
        help=(
            "Force-enable Trial D (preparation-phase startup shell). "
            "Independent from A/B/C. Since ADAPTIVE_DEFAULT_INCLUDES_D "
            "is now True, Trial D already auto-executes when the planner "
            "structurally triggers; this flag is retained as an explicit "
            "user override (useful for isolating D effects in A-B diffs) "
            "and always wins over planner decision."
        ),
    )
    parser.add_argument(
        "--backbone-disable-preparation-shell-trial",
        action="store_true",
        help=(
            "Force-disable Trial D (opt-out). Overrides the default "
            "adaptive-candidate behaviour so D never executes for this "
            "run even if the planner would otherwise trigger. "
            "Intended for regression / A-B diffing against the pre-"
            "default-rollout baseline. Wins over "
            "--backbone-preparation-shell-trial when both are set."
        ),
    )
    return parser.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)
    try:
        return run_build_attack_chain_v1(
            scenario_dir=args.scenario_dir,
            triples_path=args.triples_path,
            subgraph_path=args.subgraph_path,
            backbone_path=args.backbone_path,
            unit_event_path=args.unit_event_path,
            unit_index_path=args.unit_index_path,
            anchors_path=args.anchors_path,
            max_hops=max(0, int(args.max_hops)),
            seed_mode=args.seed_mode,
            strict=not args.non_strict,
            b_fallback_net_pair_required=args.b_fallback_net_pair_required,
            b_fallback_net_pair_window_evt=args.b_fallback_net_pair_window_evt,
            save_attack_subgraph=args.save_attack_subgraph,
            skip_save_attack_subgraph=args.skip_save_attack_subgraph,
            backbone_file_devnull_filter=args.backbone_file_devnull_filter,
            backbone_file_node_modules_filter=args.backbone_file_node_modules_filter,
            backbone_file_label_low_info=args.backbone_file_label_low_info,
            backbone_file_label_vendor_composer=args.backbone_file_label_vendor_composer,
            backbone_broad_gate_on_warning=args.backbone_broad_gate_on_warning,
            backbone_broad_gate_relations=args.backbone_broad_gate_relations,
            backbone_broad_gate_window_evt=max(0, int(args.backbone_broad_gate_window_evt)),
            backbone_broad_gate_fork_repeat_sparse_experiment=(
                args.backbone_broad_gate_fork_repeat_sparse_experiment
            ),
            backbone_broad_gate_fork_repeat_unknown_child_stride=max(
                1,
                int(args.backbone_broad_gate_fork_repeat_unknown_child_stride),
            ),
            backbone_broad_gate_fork_parent_cluster_experiment=(
                args.backbone_broad_gate_fork_parent_cluster_experiment
            ),
            backbone_broad_gate_fork_parent_cluster_gap_evt=max(
                1,
                int(args.backbone_broad_gate_fork_parent_cluster_gap_evt),
            ),
            backbone_broad_gate_fork_parent_cluster_min_subject_edges=max(
                2,
                int(args.backbone_broad_gate_fork_parent_cluster_min_subject_edges),
            ),
            backbone_broad_gate_net_accept_repeat_sparse_experiment=(
                args.backbone_broad_gate_net_accept_repeat_sparse_experiment
            ),
            backbone_broad_gate_net_accept_repeat_stride=max(
                1,
                int(args.backbone_broad_gate_net_accept_repeat_stride),
            ),
            backbone_runtime_shell_block_representative_experiment=(
                args.backbone_runtime_shell_block_representative_experiment
            ),
            backbone_runtime_shell_block_relations=args.backbone_runtime_shell_block_relations,
            backbone_runtime_shell_block_min_block_edges=max(
                2,
                int(args.backbone_runtime_shell_block_min_block_edges),
            ),
            backbone_runtime_shell_block_min_overlap_ratio=max(
                0.0,
                min(1.0, float(args.backbone_runtime_shell_block_min_overlap_ratio)),
            ),
            backbone_runtime_shell_block_net_accept_subject_anchor_trial=(
                args.backbone_runtime_shell_block_net_accept_subject_anchor_trial
            ),
            backbone_runtime_shell_block_process_fork_hybrid_gate=(
                args.backbone_runtime_shell_block_process_fork_hybrid_gate
            ),
            backbone_runtime_shell_block_process_fork_hybrid_min_overlap_ratio=max(
                0.0,
                min(
                    1.0,
                    float(
                        args.backbone_runtime_shell_block_process_fork_hybrid_min_overlap_ratio
                    ),
                ),
            ),
            backbone_runtime_shell_block_process_fork_hybrid_min_overlap_edges=max(
                1,
                int(
                    args.backbone_runtime_shell_block_process_fork_hybrid_min_overlap_edges
                ),
            ),
            backbone_refinement_planner_mode=bool(
                getattr(args, "backbone_refinement_planner_mode", False)
            ),
            backbone_preparation_shell_trial=bool(
                getattr(args, "backbone_preparation_shell_trial", False)
            ),
            backbone_disable_preparation_shell_trial=bool(
                getattr(args, "backbone_disable_preparation_shell_trial", False)
            ),
        )
    except Exception as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
