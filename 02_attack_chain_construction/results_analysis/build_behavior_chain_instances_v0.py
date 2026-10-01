#!/usr/bin/env python3
"""
Assemble backbone spine + positioned audit context into a dataset-ready
chain-level object.

v2 dataset schema changes over v1:
- Two-layer stage_segments driven by attack salience rather than family:
  Layer 1  runtime_setup / attack_relevant / post_action_result
  Layer 2  within attack_relevant, sub-segmented by NET_ACCEPT request
           cycles and labelled by dominant activity.
- Necessary non-malicious context from tiered outputs (access, stat,
  close, …) alongside existing malicious context.
- preparatory_context role for before-position probe/check events.

Engineering / attach metadata -> .meta.json (unchanged contract).

Inputs (all read-only):
  backbone_chain.v1.json
  behavior_context_edges.v0.jsonl
  (optional) audit_triples.{auxiliary,filtered,unknown}.v1.jsonl

Outputs:
  behavior_chain_dataset.v2.json       (main sample)
  behavior_chain_dataset.v2.meta.json  (engineering metadata)
"""

from __future__ import annotations

import argparse
import bisect
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Optional

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from console_observability import ProgressLogger, emit_observation
from results_analysis.backbone_warning_utils import (
    BACKBONE_WARNING_SCHEMA_VERSION,
    compute_backbone_edge_metrics,
    evaluate_backbone_broad_warning,
)
from results_analysis.pipeline.utils.common import CHAIN_DIR_NAME


SCENARIO_DIR = ROOT_DIR / "results" / "vulhub" / "gitlist" / "CVE-2018-1000533" / "2026-03-17_02-32-45"
CHAIN_DIR = SCENARIO_DIR / CHAIN_DIR_NAME

DEFAULT_BACKBONE = CHAIN_DIR / "backbone_chain.v1.json"
DEFAULT_CONTEXT_EDGES = CHAIN_DIR / "behavior_context_edges.v0.jsonl"
DEFAULT_OUTPUT = CHAIN_DIR / "behavior_chain_dataset.v2.json"
DEFAULT_META_OUTPUT = CHAIN_DIR / "behavior_chain_dataset.v2.meta.json"
DEFAULT_BACKBONE_WARNING_OUTPUT = CHAIN_DIR / "backbone_broad_warning.v0.json"
DEFAULT_REFINEMENT_RESIDUAL = CHAIN_DIR / "backbone_refinement_residual.v0.jsonl"

SCHEMA_VERSION = "behavior_chain_dataset.v2"
META_SCHEMA_VERSION = "behavior_chain_dataset.v2.meta"

STRENGTH_ORDER: dict[str, int] = {
    "strong": 0,
    "medium_high": 1,
    "medium": 2,
    "medium_low": 3,
    "weak": 4,
    "proximity": 5,
}

# ── Event-type sets for role / necessary-context classification ──────────

PREPARATORY_EVT_TYPES = frozenset({
    "access", "stat", "lstat", "getdents", "socket",
})

RESULTING_EVT_TYPES = frozenset({
    "close", "shutdown", "unlink", "rmdir", "exit", "exit_group",
})

NECESSARY_CONTEXT_EVT_TYPES = PREPARATORY_EVT_TYPES | RESULTING_EVT_TYPES

# ── Attack salience ──────────────────────────────────────────────────────

HIGH_SALIENCE_RELATIONS = frozenset({
    "PROCESS_EXEC", "FILE_WRITE", "NET_CONNECT", "NET_ACCEPT",
    "NET_SEND", "NET_RECV",
})

DEFAULT_NECESSARY_WINDOW = 5

MIN_SUBSTAGE_LEN = 5

ENTRY_RELATIONS = frozenset({
    "NET_ACCEPT", "NET_RECV", "NET_SEND", "NET_CONNECT",
})

HIGH_EXEC_RELATIONS = frozenset({
    "PROCESS_EXEC",
})


# ─────────────────────────────────────────────────────────────────────────
# IO helpers
# ─────────────────────────────────────────────────────────────────────────

def _read_json(path: Path) -> dict[str, Any]:
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return json.load(fh)


def _iter_jsonl(path: Path):
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if line:
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    pass


def _write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, ensure_ascii=False, indent=2)
        fh.write("\n")


def _count_multisource_context_entries(spine: list[dict[str, Any]]) -> int:
    total = 0
    for edge in spine:
        multisource = edge.get("multisource_context") or {}
        traffic = multisource.get("traffic") or []
        applog = multisource.get("applog") or []
        total += len(traffic) + len(applog)
    return total


def _build_backbone_warning_payload(
    *,
    backbone: dict[str, Any],
    dataset_main: dict[str, Any],
    dataset_meta: dict[str, Any],
    enrich_summary: Optional[dict[str, Any]],
    stage_residual_view: Optional[dict[str, Any]],
) -> dict[str, Any]:
    edge_sequence = backbone.get("edge_sequence") or []
    chain_summary = backbone.get("chain_summary") or {}
    instance_summary = dataset_meta.get("instance_summary") or {}
    enrich_counts = (enrich_summary or {}).get("counts") or {}

    metrics = compute_backbone_edge_metrics(
        edge_sequence,
        source_subgraph_edge_count=chain_summary.get("source_subgraph_edge_count"),
        context_edge_count=instance_summary.get("context_edge_count"),
        unmatched_count=enrich_counts.get("unmatched_malicious_non_core"),
        distinct_unit_count_in_backbone=chain_summary.get("distinct_unit_count_in_backbone"),
        stage_residual_count=(stage_residual_view or {}).get("mapped_residual_count"),
        multisource_context_count=_count_multisource_context_entries(dataset_main.get("spine") or []),
    )
    warning_payload = evaluate_backbone_broad_warning(
        metrics,
        scenario_id=backbone.get("scenario_id"),
    )
    warning_payload["schema_version"] = BACKBONE_WARNING_SCHEMA_VERSION
    warning_payload["generated_by"] = "build_behavior_chain_instances_v0"
    warning_payload["warning_output_scope"] = "single_scenario"
    warning_payload["backbone_gate"] = chain_summary.get("broad_backbone_gate") or {}
    warning_payload["backbone_partial_warning"] = chain_summary.get("broad_backbone_warning") or {}
    warning_payload["expression_clarity"] = dataset_meta.get("expression_clarity") or {}
    warning_payload["refinement_residual_count"] = int(
        ((dataset_meta.get("refinement_residual_view") or {}).get("total_residual_records")) or 0
    )
    return warning_payload


def _top_count_items(
    count_map: dict[str, Any],
    *,
    limit: int = 3,
) -> list[dict[str, Any]]:
    items: list[tuple[str, int]] = []
    for name, raw_value in count_map.items():
        key = str(name or "unknown")
        try:
            value = int(raw_value)
        except (TypeError, ValueError):
            continue
        items.append((key, value))
    items.sort(key=lambda item: (-item[1], item[0]))
    return [
        {
            "name": name,
            "count": count,
        }
        for name, count in items[: max(1, int(limit))]
    ]


def _normalize_anchor(
    anchor: Optional[dict[str, Any]],
    *,
    fallback_relation: Optional[str] = None,
    fallback_family: Optional[str] = None,
    fallback_evt_num: Optional[int] = None,
) -> dict[str, Any]:
    anchor = anchor if isinstance(anchor, dict) else {}
    relation = str(anchor.get("relation") or fallback_relation or "") or None
    family = fallback_family or (str(relation or "").split("_", 1)[0] if relation else None)
    evt_num = anchor.get("evt_num")
    if not isinstance(evt_num, int):
        evt_num = fallback_evt_num if isinstance(fallback_evt_num, int) else None
    return {
        "edge_id": anchor.get("edge_id"),
        "relation": relation,
        "family": family,
        "evt_num": evt_num,
    }


def _build_semantic_narrative_summary(
    *,
    backbone: dict[str, Any],
    dataset_meta: dict[str, Any],
) -> dict[str, Any]:
    expression_clarity = dataset_meta.get("expression_clarity")
    if not isinstance(expression_clarity, dict):
        expression_clarity = {}
    backbone_expr = expression_clarity.get("backbone")
    if not isinstance(backbone_expr, dict):
        backbone_expr = {}
    semantic_readiness = expression_clarity.get("semantic_readiness")
    if not isinstance(semantic_readiness, dict):
        semantic_readiness = {}

    refinement_view = dataset_meta.get("refinement_residual_view")
    if not isinstance(refinement_view, dict):
        refinement_view = {}
    stage_summary = refinement_view.get("stage_summary")
    if not isinstance(stage_summary, dict):
        stage_summary = {}
    attack_entry_shell = stage_summary.get("attack_entry_adjacent_shell")
    if not isinstance(attack_entry_shell, dict):
        attack_entry_shell = {}
    attack_entry_story = attack_entry_shell.get("story_alignment")
    if not isinstance(attack_entry_story, dict):
        attack_entry_story = {}

    backbone_story_alignment = refinement_view.get("backbone_story_alignment")
    if not isinstance(backbone_story_alignment, dict):
        backbone_story_alignment = {}

    chain_summary = backbone.get("chain_summary")
    if not isinstance(chain_summary, dict):
        chain_summary = {}

    entry_anchor = _normalize_anchor(
        backbone_story_alignment.get("entry_anchor"),
        fallback_relation=backbone_expr.get("entry_anchor_relation"),
        fallback_family=backbone_expr.get("entry_anchor_family"),
        fallback_evt_num=backbone_expr.get("first_malicious_evt_num"),
    )
    result_anchor = _normalize_anchor(
        backbone_story_alignment.get("result_anchor"),
        fallback_relation=backbone_expr.get("result_anchor_relation"),
        fallback_family=backbone_expr.get("result_anchor_family"),
        fallback_evt_num=backbone_expr.get("last_malicious_evt_num"),
    )

    stage_shells = sorted(stage_summary.keys())
    relation_family_counts = refinement_view.get("relation_family_counts")
    if not isinstance(relation_family_counts, dict):
        relation_family_counts = {}

    attack_entry_class = str(
        attack_entry_story.get("entry_adjacency_class") or ""
    )
    cluster_narrow_exists = bool(
        attack_entry_shell.get("cluster_level_narrow_candidate_exists")
    )
    cluster_narrow_count = int(
        attack_entry_shell.get("cluster_level_narrow_candidate_count") or 0
    )
    if not attack_entry_shell:
        attack_entry_mode = "no_attack_entry_shell"
    elif attack_entry_class == "wide_span_bridge_shell" and cluster_narrow_exists:
        attack_entry_mode = "stage_wide_with_internal_narrow_candidate"
    elif attack_entry_class == "wide_span_bridge_shell":
        attack_entry_mode = "stage_wide_no_internal_narrow_candidate"
    elif attack_entry_class == "narrow_entry_adjacent_shell":
        attack_entry_mode = "stage_narrow_entry_shell"
    else:
        attack_entry_mode = "attack_entry_shell_unclassified"

    return {
        "schema_version": "semantic_narrative_summary.v0",
        "backbone_mainline": {
            "entry_anchor": entry_anchor,
            "result_anchor": result_anchor,
            "result_anchor_result_like": bool(backbone_expr.get("result_anchor_result_like")),
            "malicious_span_ratio": backbone_expr.get("malicious_span_ratio"),
            "malicious_span_malicious_density": backbone_expr.get("malicious_span_malicious_density"),
            "pre_shell_ratio": backbone_expr.get("pre_malicious_shell_ratio"),
            "post_shell_ratio": backbone_expr.get("post_malicious_shell_ratio"),
        },
        "semantic_readiness": {
            "backbone_story_self_contained": bool(
                semantic_readiness.get("backbone_story_self_contained")
            ),
            "runtime_shell_demotion_preferred": bool(
                semantic_readiness.get("runtime_shell_demotion_preferred")
            ),
            "story_gaps": list(semantic_readiness.get("story_gaps") or [])[:5],
        },
        "residual_shell_overview": {
            "residual_enabled": bool(refinement_view),
            "total_residual_records": int(refinement_view.get("total_residual_records") or 0),
            "stage_shells": stage_shells,
            "dominant_relation_families": _top_count_items(relation_family_counts, limit=3),
            "attack_entry_shell_present": bool(attack_entry_shell),
            "attack_entry_adjacency_class": attack_entry_class or None,
            "attack_entry_mode": attack_entry_mode,
            "attack_entry_cluster_level_narrow_candidate_exists": cluster_narrow_exists,
            "attack_entry_cluster_level_narrow_candidate_count": cluster_narrow_count,
        },
        "references": {
            "expression_clarity_path": "meta.expression_clarity",
            "semantic_readiness_path": "meta.expression_clarity.semantic_readiness",
            "refinement_stage_summary_path": "meta.refinement_residual_view.stage_summary",
            "backbone_expression_path": "backbone.chain_summary.expression_clarity",
            "backbone_chain_id": chain_summary.get("chain_id") or backbone.get("chain_id"),
        },
    }


def _load_enrich_summary(summary_path: Path) -> Optional[dict[str, Any]]:
    if not summary_path.exists() or summary_path.stat().st_size == 0:
        return None
    try:
        with open(summary_path, "r", encoding="utf-8", errors="replace") as fh:
            obj = json.load(fh)
            return obj if isinstance(obj, dict) else None
    except Exception:
        return None


def _classify_controlled_empty_context(
    summary: Optional[dict[str, Any]],
) -> tuple[bool, dict[str, Any]]:
    if not summary:
        return False, {"reason": "summary_missing_or_invalid"}

    status = str(summary.get("status") or "").strip()
    unit_mode = str(summary.get("unit_mode") or "").strip()
    unit_reason = str(summary.get("unit_mode_reason") or "").strip()
    output_state = summary.get("output_state")
    if not isinstance(output_state, dict):
        output_state = {}
    context_state = str(output_state.get("behavior_context_edges") or "").strip()

    is_controlled = (
        status == "completed"
        and unit_mode in {"unit-absent", "unit-unavailable"}
        and context_state == "empty_not_written"
    )
    details = {
        "status": status,
        "unit_mode": unit_mode,
        "unit_mode_reason": unit_reason,
        "behavior_context_edges_state": context_state,
    }
    return is_controlled, details


# ─────────────────────────────────────────────────────────────────────────
# Spine-level helpers
# ─────────────────────────────────────────────────────────────────────────

def _spine_family(relation: Optional[str]) -> str:
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


def _slim_spine_attrs(attrs: dict[str, Any]) -> dict[str, Any]:
    keep = (
        "evt_num", "timestamp", "raw_evt_type", "malicious",
        "container_id", "fd_name",
    )
    return {k: attrs[k] for k in keep if k in attrs}


def _build_backbone_context_dependency_proxy(
    spine: list[dict[str, Any]],
    ctx_by_eid: dict[str, list[dict[str, Any]]],
    backbone_expression_clarity: dict[str, Any],
) -> dict[str, Any]:
    first_seq = backbone_expression_clarity.get("first_malicious_seq")
    last_seq = backbone_expression_clarity.get("last_malicious_seq")
    if not isinstance(first_seq, int) or not isinstance(last_seq, int) or first_seq <= 0 or last_seq <= 0:
        return {
            "malicious_span_edge_count": 0,
            "malicious_span_edges_with_context": 0,
            "malicious_span_edges_without_context": 0,
            "malicious_span_context_edge_count": 0,
            "malicious_span_context_per_edge": 0.0,
            "spine_edges_with_any_context_ratio": 0.0,
        }

    malicious_span_edges = [
        edge for edge in spine
        if first_seq <= int(edge.get("seq") or 0) <= last_seq
    ]
    span_edge_count = len(malicious_span_edges)
    span_edges_with_context = 0
    span_context_edge_count = 0
    total_edges_with_context = 0
    for edge in spine:
        edge_context = edge.get("audit_context") or []
        if edge_context:
            total_edges_with_context += 1
    for edge in malicious_span_edges:
        edge_id = str(edge.get("edge_id") or "")
        attached = ctx_by_eid.get(edge_id) or []
        if attached:
            span_edges_with_context += 1
            span_context_edge_count += len(attached)

    return {
        "malicious_span_edge_count": span_edge_count,
        "malicious_span_edges_with_context": span_edges_with_context,
        "malicious_span_edges_without_context": max(span_edge_count - span_edges_with_context, 0),
        "malicious_span_context_edge_count": span_context_edge_count,
        "malicious_span_context_per_edge": (
            round(span_context_edge_count / span_edge_count, 2)
            if span_edge_count else 0.0
        ),
        "spine_edges_with_any_context_ratio": (
            round(total_edges_with_context / len(spine), 6)
            if spine else 0.0
        ),
    }


def _build_semantic_readiness_assessment(
    backbone_expression_clarity: dict[str, Any],
    backbone_context_dependency: dict[str, Any],
) -> dict[str, Any]:
    backbone_semantic = backbone_expression_clarity.get("semantic_readiness") or {}
    span_edge_count = int(backbone_context_dependency.get("malicious_span_edge_count") or 0)
    span_edges_with_context = int(
        backbone_context_dependency.get("malicious_span_edges_with_context") or 0
    )
    context_dependency_ratio = (
        span_edges_with_context / span_edge_count
        if span_edge_count > 0 else 0.0
    )
    if context_dependency_ratio <= 0.05:
        context_dependency_level = "low"
    elif context_dependency_ratio <= 0.3:
        context_dependency_level = "medium"
    else:
        context_dependency_level = "high"

    backbone_can_stand_alone = bool(
        backbone_semantic.get("backbone_story_self_contained")
        and context_dependency_level in {"low", "medium"}
    )
    story_gaps = list(backbone_semantic.get("story_gaps") or [])
    if context_dependency_level == "high":
        story_gaps.append("context_dependency_high")

    return {
        "primary_objective": "attack_semantics_priority",
        "context_dependency_level": context_dependency_level,
        "context_dependency_ratio": round(context_dependency_ratio, 6),
        "backbone_can_stand_alone_proxy": backbone_can_stand_alone,
        "runtime_shell_lane": "refinement_residual_or_context",
        "auxiliary_metrics_only": list(backbone_semantic.get("auxiliary_metrics_only") or []),
        "story_gaps": story_gaps,
    }


# ─────────────────────────────────────────────────────────────────────────
# Context event extraction
# ─────────────────────────────────────────────────────────────────────────

_EVENT_ATTR_KEEP = (
    "evt_num", "timestamp", "raw_evt_type", "tier", "malicious",
    "container_id", "fd_name", "fd_type", "evt_category", "bytes",
    "direction_hint", "proc_pid", "proc_name", "proc_exepath",
)

_PROC_KEEP = ("container_id", "pid", "name", "exepath")
_FD_KEEP = ("name", "type")


def _extract_event(ctx: dict[str, Any]) -> dict[str, Any]:
    """Build the *event* dict from a raw context-edge record.

    Keeps the original (subject, relation, object, attrs) shape for
    backward compatibility, and additionally preserves proc / fd /
    record_mode / reason fields from the underlying non-core triple so
    the main sample's audit_context carries enough information to
    explain each attached record without reaching into sidecars.
    """
    cr = ctx.get("context_record", {}) or {}
    cr_attrs = cr.get("attrs") or {}

    subject = cr.get("subject")
    relation = cr.get("relation")
    obj = cr.get("object")

    if relation is None:
        relation = cr.get("event_type")
    if obj is None:
        fd = cr.get("fd")
        if isinstance(fd, dict) and fd.get("name"):
            obj = fd["name"]

    event_attrs: dict[str, Any] = {}
    for k in _EVENT_ATTR_KEEP:
        if k in cr_attrs and cr_attrs[k] is not None:
            event_attrs[k] = cr_attrs[k]

    event: dict[str, Any] = {
        "subject": subject,
        "relation": relation,
        "object": obj,
        "attrs": event_attrs,
    }

    record_mode = cr.get("record_mode")
    if record_mode:
        event["record_mode"] = record_mode

    event_type = cr.get("event_type")
    if event_type:
        event["event_type"] = event_type

    reason = cr.get("reason")
    if reason:
        event["reason"] = reason

    proc = cr.get("proc")
    if isinstance(proc, dict):
        slim_proc = {k: proc[k] for k in _PROC_KEEP if proc.get(k) is not None}
        if slim_proc:
            event["proc"] = slim_proc

    fd = cr.get("fd")
    if isinstance(fd, dict):
        slim_fd = {k: fd[k] for k in _FD_KEEP if fd.get(k) is not None}
        if slim_fd:
            event["fd"] = slim_fd

    return event


_LINK_FEATURE_KEEP = (
    "same_evt_num", "same_unit", "family_match", "family_non_core",
    "family_backbone", "entity_confirmed", "entity_type",
    "evt_delta", "time_delta_evt", "time_delta_sec", "score",
    "evt_num_delta", "same_container", "necessary_evt_type",
    "explanatory_evt_type",
)


def _slim_link_features(lf: Any) -> dict[str, Any]:
    """Return a size-bounded subset of link_features for audit_context."""
    if not isinstance(lf, dict):
        return {}
    out: dict[str, Any] = {}
    for k in _LINK_FEATURE_KEEP:
        if k in lf and lf[k] is not None:
            out[k] = lf[k]
    return out


# ─────────────────────────────────────────────────────────────────────────
# Position & context_role
# ─────────────────────────────────────────────────────────────────────────

def _determine_position(
    ctx: dict[str, Any],
    spine_evt_num: Optional[int],
    spine_ts: Optional[str],
) -> str:
    lf = ctx.get("link_features") or {}
    strength = ctx.get("attach_strength", "")

    if strength == "strong":
        return "aligned"
    if lf.get("same_evt_num"):
        return "aligned"
    if lf.get("same_unit") and lf.get("entity_confirmed"):
        return "aligned"

    cr_attrs = (ctx.get("context_record") or {}).get("attrs") or {}
    ctx_evt = cr_attrs.get("evt_num")
    try:
        ctx_evt_i = int(ctx_evt)
    except (TypeError, ValueError):
        ctx_evt_i = None

    if ctx_evt_i is not None and spine_evt_num is not None:
        if ctx_evt_i < spine_evt_num:
            return "before"
        if ctx_evt_i > spine_evt_num:
            return "after"
        return "aligned"

    ctx_ts = str(cr_attrs.get("timestamp", ""))
    spine_ts_str = str(spine_ts or "")
    if ctx_ts and spine_ts_str:
        if ctx_ts < spine_ts_str:
            return "before"
        if ctx_ts > spine_ts_str:
            return "after"

    return "aligned"


def _determine_role(
    position: str,
    ctx: dict[str, Any],
) -> str:
    lf = ctx.get("link_features") or {}
    strength = ctx.get("attach_strength", "")

    if position == "aligned" and strength == "strong":
        return "core_related_context"
    if lf.get("same_evt_num"):
        return "core_related_context"
    if lf.get("same_unit") and lf.get("entity_confirmed"):
        return "core_related_context"

    cr = ctx.get("context_record") or {}
    cr_attrs = cr.get("attrs") or {}
    raw_evt = cr_attrs.get("raw_evt_type", "") or cr.get("event_type", "")
    raw_evt_lower = str(raw_evt).lower()

    if position == "before" and raw_evt_lower in PREPARATORY_EVT_TYPES:
        return "preparatory_context"

    if position == "after" and raw_evt_lower in RESULTING_EVT_TYPES:
        return "resulting_context"

    return "supporting_context"


# ─────────────────────────────────────────────────────────────────────────
# Attack salience (per spine edge)
# ─────────────────────────────────────────────────────────────────────────

def _attack_salience(
    edge: dict[str, Any],
    ctx_count: int = 0,
    has_malicious_ctx: bool = False,
) -> str:
    """Return ``'high'`` / ``'medium'`` / ``'low'``."""
    attrs = edge.get("attrs") or {}
    if attrs.get("malicious"):
        return "high"
    if has_malicious_ctx:
        return "high"
    rel = (edge.get("relation") or "").upper()
    if rel in HIGH_SALIENCE_RELATIONS:
        return "medium"
    if ctx_count > 0:
        return "medium"
    return "low"


# ─────────────────────────────────────────────────────────────────────────
# Two-layer stage segments
# ─────────────────────────────────────────────────────────────────────────

def _classify_attack_segment(
    edges: list[dict[str, Any]],
) -> str:
    """Label an attack-relevant sub-segment by dominant activity."""
    rels: Counter[str] = Counter(
        (e.get("relation") or "").upper() for e in edges
    )

    if rels.get("PROCESS_EXEC", 0) > 0:
        return "Execution"
    if rels.get("NET_CONNECT", 0) > 0 or rels.get("NET_SEND", 0) > 0:
        return "Network Interaction"

    families: Counter[str] = Counter()
    for r, c in rels.items():
        families[_spine_family(r)] += c
    dominant = families.most_common(1)[0][0] if families else "UNKNOWN"

    if rels.get("NET_ACCEPT", 0) > 0:
        return "Request Processing"
    if rels.get("FILE_WRITE", 0) > 0:
        return "File Manipulation"
    if dominant == "FILE":
        return "File Interaction"
    if dominant == "PROCESS":
        return "Process Management"
    return "Request Processing"


def build_stage_segments(
    spine: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Two-layer segmentation driven by attack salience.

    Layer 1 – coarse zones:
      runtime_setup / attack_relevant / post_action_result

    Layer 2 – within attack_relevant, one sub-segment per request cycle
              (bounded by NET_ACCEPT) labelled by dominant activity.
    """
    if not spine:
        return []

    saliences: list[str] = []
    for edge in spine:
        ctx = edge.get("audit_context") or []
        has_mal_ctx = any(
            (c.get("event") or {}).get("attrs", {}).get("malicious")
            for c in ctx
        )
        saliences.append(_attack_salience(edge, len(ctx), has_mal_ctx))

    first_active = next(
        (i for i, s in enumerate(saliences) if s != "low"), -1
    )
    if first_active == -1:
        return [{
            "start_seq": spine[0]["seq"],
            "end_seq": spine[-1]["seq"],
            "label": "runtime_setup",
        }]

    last_active = len(spine) - 1
    for i in range(len(spine) - 1, -1, -1):
        if saliences[i] != "low":
            last_active = i
            break

    segments: list[dict[str, Any]] = []

    # Layer 1: runtime_setup
    if first_active > 0:
        segments.append({
            "start_seq": spine[0]["seq"],
            "end_seq": spine[first_active - 1]["seq"],
            "label": "runtime_setup",
        })

    # Layer 2: attack_relevant sub-segments
    attack_slice = spine[first_active: last_active + 1]

    cycle_indices: list[int] = []
    for i, e in enumerate(attack_slice):
        if (e.get("relation") or "").upper() == "NET_ACCEPT":
            cycle_indices.append(i)

    if not cycle_indices:
        segments.append({
            "start_seq": attack_slice[0]["seq"],
            "end_seq": attack_slice[-1]["seq"],
            "label": _classify_attack_segment(attack_slice),
        })
    else:
        if cycle_indices[0] > 0:
            pre = attack_slice[: cycle_indices[0]]
            segments.append({
                "start_seq": pre[0]["seq"],
                "end_seq": pre[-1]["seq"],
                "label": _classify_attack_segment(pre),
            })
        for ci, start in enumerate(cycle_indices):
            end = (
                cycle_indices[ci + 1]
                if ci + 1 < len(cycle_indices)
                else len(attack_slice)
            )
            cycle = attack_slice[start:end]
            segments.append({
                "start_seq": cycle[0]["seq"],
                "end_seq": cycle[-1]["seq"],
                "label": _classify_attack_segment(cycle),
            })

    # Layer 1: post_action_result
    if last_active < len(spine) - 1:
        segments.append({
            "start_seq": spine[last_active + 1]["seq"],
            "end_seq": spine[-1]["seq"],
            "label": "post_action_result",
        })

    return segments


# ─────────────────────────────────────────────────────────────────────────
# Substage segments (within each attack_relevant request cycle)
# ─────────────────────────────────────────────────────────────────────────

def _edge_is_active(edge: dict[str, Any]) -> bool:
    """True when the edge carries attack-relevant signal."""
    if (edge.get("attrs") or {}).get("malicious"):
        return True
    for c in edge.get("audit_context") or []:
        if (c.get("event") or {}).get("attrs", {}).get("malicious"):
            return True
    return False


def _find_exec_marker(
    edges: list[dict[str, Any]],
    start: int,
    end: int,
    min_loading: int = MIN_SUBSTAGE_LEN,
) -> int:
    """Return index of the first strong exec-marker edge in edges[start..end].

    Exec markers, in priority order:
      1. PROCESS_EXEC — strongest; returned immediately.
      2. First malicious FILE_WRITE to a non-/dev/null target that appears
         after a *sustained* loading region (≥ ``min_loading`` FILE_OPEN /
         FILE_READ edges).  /dev/null writes and non-loading non-write edges
         (e.g. NET_RECV, PROCESS_FORK) are tolerated without resetting the
         loading counter.

    Returns -1 if nothing qualifies.
    """
    for i in range(start, end + 1):
        rel = (edges[i].get("relation") or "").upper()
        if rel == "PROCESS_EXEC":
            return i

    _LOADING = frozenset({"FILE_OPEN", "FILE_READ"})
    loading_run = 0
    for i in range(start, end + 1):
        rel = (edges[i].get("relation") or "").upper()
        if rel in _LOADING:
            loading_run += 1
            continue
        if rel == "FILE_WRITE":
            obj = str(edges[i].get("object") or "")
            if "/dev/null" in obj:
                continue
            if loading_run >= min_loading and (
                (edges[i].get("attrs") or {}).get("malicious")
            ):
                return i
            loading_run = 0
            continue

    return -1


def _find_context_transition(
    edges: list[dict[str, Any]],
    start: int,
    end: int,
    min_len: int,
) -> int:
    """Return index where preparatory_context density drops significantly.

    Uses a two-half comparison: if the first half has substantially higher
    preparatory ratio than the second half, returns the midpoint.
    Returns -1 if context data is absent or no significant transition.
    """
    mid_len = end - start + 1
    if mid_len < min_len * 2:
        return -1

    half = mid_len // 2
    first_prep = first_total = 0
    second_prep = second_total = 0

    for i in range(start, start + half):
        for c in edges[i].get("audit_context") or []:
            first_total += 1
            if c.get("context_role") == "preparatory_context":
                first_prep += 1

    for i in range(start + half, end + 1):
        for c in edges[i].get("audit_context") or []:
            second_total += 1
            if c.get("context_role") == "preparatory_context":
                second_prep += 1

    if first_total < 3 and second_total < 3:
        return -1

    r1 = first_prep / max(first_total, 1)
    r2 = second_prep / max(second_total, 1)

    if r1 - r2 >= 0.15 and r1 >= 0.20:
        boundary = start + half
        if boundary - start >= min_len and end - boundary + 1 >= min_len:
            return boundary

    return -1


def _find_relation_shift(
    edges: list[dict[str, Any]],
    start: int,
    end: int,
    min_len: int,
) -> int:
    """Return index where the relation composition shifts to high-exec content.

    Scans for the first position where a sustained block of high-salience
    relations (FILE_WRITE to non-/dev/null, NET_CONNECT, PROCESS_EXEC)
    begins, after a preceding block of loading/setup relations
    (FILE_OPEN, FILE_READ).
    Returns -1 if no clear shift detected.
    """
    mid_len = end - start + 1
    if mid_len < min_len * 2:
        return -1

    loading_rels = frozenset({"FILE_OPEN", "FILE_READ"})
    action_rels = frozenset({"FILE_WRITE", "NET_CONNECT", "PROCESS_EXEC"})

    loading_run = 0
    for i in range(start, end + 1):
        rel = (edges[i].get("relation") or "").upper()
        if rel in loading_rels:
            loading_run += 1
        elif rel in action_rels and loading_run >= min_len:
            if rel == "FILE_WRITE":
                obj = str(edges[i].get("object") or "")
                if "/dev/null" in obj:
                    continue
            remaining = end - i + 1
            if remaining >= min_len:
                return i
            return -1
        else:
            if rel not in loading_rels:
                loading_run = 0

    return -1


def _split_request_cycle(
    edges: list[dict[str, Any]],
    min_len: int = MIN_SUBSTAGE_LEN,
) -> list[dict[str, Any]]:
    """Split one request-cycle into substages using signal-based detection.

    Algorithm (anchor-first, signal-validated, honest default):

    Layer 1 – Anchors:
      Entry:   forward scan while relation is NET_*
      Cleanup: backward scan while edge is non-active

    Layer 2 – Middle section signal probes (in priority order):
      A. PROCESS_EXEC exec-marker
      B. Malicious FILE_WRITE to non-/dev/null after a loading region
      C. Context role transition (preparatory → core_related density drop)
      D. Relation composition shift (FILE_OPEN/READ → action relations)
      If none fire → entire middle = "Execution / Trigger"

    Layer 3 – Stabilisation:
      Merge segments shorter than *min_len* into their predecessor.
    """
    n = len(edges)
    if n < min_len * 2:
        return [{
            "parent_stage": "attack_relevant",
            "start_seq": edges[0]["seq"],
            "end_seq": edges[-1]["seq"],
            "label": "Execution / Trigger",
            "_short_merges": 0,
            "_split_signal": "too_short",
        }]

    # ── Layer 1: Entry anchor (forward scan) ─────────────────────────────
    entry_end = 0
    for i in range(n):
        rel = (edges[i].get("relation") or "").upper()
        if rel in ENTRY_RELATIONS:
            entry_end = i
        else:
            break
    entry_end = max(entry_end, 0)
    entry_end = min(entry_end, n - min_len - 1)

    # ── Layer 1: Cleanup anchor (backward scan) ──────────────────────────
    cleanup_start = n
    for i in range(n - 1, entry_end + min_len, -1):
        if not _edge_is_active(edges[i]):
            cleanup_start = i
        else:
            break

    if cleanup_start < n and (n - cleanup_start) < min_len:
        cleanup_start = n

    # ── Layer 2: Middle section signal probes ────────────────────────────
    mid_start = entry_end + 1
    mid_end = cleanup_start - 1
    mid_len = mid_end - mid_start + 1

    raw: list[tuple[int, int, str]] = [(0, entry_end, "Request Entry")]
    split_signal = "no_signal"

    if mid_len > 0:
        if mid_len < min_len * 2:
            raw.append((mid_start, mid_end, "Execution / Trigger"))
            split_signal = "too_short_mid"
        else:
            boundary = _find_exec_marker(edges, mid_start, mid_end)
            if boundary >= 0:
                split_signal = "exec_marker"
            else:
                boundary = _find_context_transition(
                    edges, mid_start, mid_end, min_len,
                )
                if boundary >= 0:
                    split_signal = "context_transition"
                else:
                    boundary = _find_relation_shift(
                        edges, mid_start, mid_end, min_len,
                    )
                    if boundary >= 0:
                        split_signal = "relation_shift"

            if boundary >= 0:
                before_len = boundary - mid_start
                after_len = mid_end - boundary + 1
                if before_len >= min_len and after_len >= min_len:
                    raw.append(
                        (mid_start, boundary - 1, "Preparation / Discovery"),
                    )
                    raw.append(
                        (boundary, mid_end, "Execution / Trigger"),
                    )
                else:
                    raw.append((mid_start, mid_end, "Execution / Trigger"))
                    split_signal = "no_signal"
            else:
                raw.append((mid_start, mid_end, "Execution / Trigger"))

    if cleanup_start < n:
        raw.append((cleanup_start, n - 1, "Result / Cleanup"))

    # ── Layer 3: Stabilisation – merge short segments ────────────────────
    merged: list[tuple[int, int, str]] = []
    short_merges = 0
    for start_i, end_i, label in raw:
        seg_len = end_i - start_i + 1
        if seg_len < min_len and merged:
            prev_s, prev_e, prev_l = merged[-1]
            merged[-1] = (prev_s, end_i, prev_l)
            short_merges += 1
        else:
            merged.append((start_i, end_i, label))

    result = [
        {
            "parent_stage": "attack_relevant",
            "start_seq": edges[s]["seq"],
            "end_seq": edges[e]["seq"],
            "label": lbl,
            "_short_merges": short_merges,
            "_split_signal": split_signal,
        }
        for s, e, lbl in merged
    ]
    return result


def build_substage_segments(
    spine: list[dict[str, Any]],
    stage_segments: list[dict[str, Any]],
    min_len: int = MIN_SUBSTAGE_LEN,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Build substage segments inside every attack_relevant stage.

    Returns ``(substages_list, stats_dict)`` where *stats_dict* is intended
    for the meta file.
    """
    seq_to_idx = {e["seq"]: i for i, e in enumerate(spine)}
    substages: list[dict[str, Any]] = []
    merge_count = 0
    label_counter: Counter = Counter()
    signal_counter: Counter = Counter()
    lengths: list[int] = []

    for seg in stage_segments:
        if seg["label"] in ("runtime_setup", "post_action_result"):
            continue

        start_idx = seq_to_idx.get(seg["start_seq"])
        end_idx = seq_to_idx.get(seg["end_seq"])
        if start_idx is None or end_idx is None:
            continue

        cycle_edges = spine[start_idx: end_idx + 1]
        if not cycle_edges:
            continue

        subs = _split_request_cycle(cycle_edges, min_len)

        for sub in subs:
            merge_count += sub.pop("_short_merges", 0)
            signal_counter[sub.pop("_split_signal", "none")] += 1
            substages.append(sub)
            label_counter[sub["label"]] += 1
            seg_len = (
                seq_to_idx[sub["end_seq"]]
                - seq_to_idx[sub["start_seq"]]
                + 1
            )
            lengths.append(seg_len)

    stats = {
        "substage_count": len(substages),
        "min_substage_length": min(lengths) if lengths else 0,
        "max_substage_length": max(lengths) if lengths else 0,
        "label_counts": dict(sorted(label_counter.items())),
        "split_signal_counts": dict(sorted(signal_counter.items())),
        "short_merge_applied": merge_count > 0,
        "merge_count": merge_count,
        "min_len_threshold": min_len,
        "method": "anchor_signal_based",
        "honest_default_policy": (
            "When no signal probe detects a stable boundary within "
            "an attack_relevant cycle, the entire middle section is "
            "kept as a single Execution/Trigger block. This is a "
            "deliberate design choice, not a fallback bug. Cycles "
            "shorter than 2×min_len are classified as too_short and "
            "also receive the coarse-grained representation."
        ),
        "description": (
            "Per request cycle: "
            "Layer 1 (anchors) – Request Entry from NET_* head, "
            "Result/Cleanup from non-active tail. "
            "Layer 2 (signals) – middle section probed for exec-marker "
            "(PROCESS_EXEC, or malicious FILE_WRITE to non-/dev/null "
            "after a sustained FILE_OPEN/READ loading region ≥ min_len), "
            "context-role transition, or relation composition shift. "
            "If no signal fires, entire middle defaults to "
            "Execution/Trigger (honest default). "
            "Layer 3 (stabilisation) – segments shorter than min_len "
            "merged into neighbour."
        ),
        "signal_priority": [
            "exec_marker (PROCESS_EXEC or malicious FILE_WRITE "
            "to non-/dev/null after sustained loading ≥ min_len)",
            "context_transition (preparatory_context density drop "
            "between first/second half)",
            "relation_shift (FILE_OPEN/READ → action relations)",
            "too_short (cycle < 2×min_len, no probes attempted)",
            "no_signal (honest default: probes ran, no boundary found)",
        ],
    }
    return substages, stats


# ─────────────────────────────────────────────────────────────────────────
# Necessary (non-malicious) context loading from tiered outputs
# ─────────────────────────────────────────────────────────────────────────

def _load_necessary_context(
    tiered_paths: list[tuple[str, Path]],
    edge_sequence: list[dict[str, Any]],
    window: int = DEFAULT_NECESSARY_WINDOW,
) -> tuple[dict[str, list[dict[str, Any]]], Counter]:
    """Return ``{edge_id: [ctx_dict, …]}`` and a stats Counter.

    Scans tiered output files for non-malicious records whose raw_evt_type
    is in NECESSARY_CONTEXT_EVT_TYPES and whose evt_num is within ±*window*
    of a backbone edge.  Container-id must also match.
    """
    # Only anchor to malicious spine edges so that necessary context stays
    # inside the attack zone and does not pollute runtime_setup / post_action.
    mal_evt_to_edge: dict[int, dict[str, Any]] = {}
    for edge in edge_sequence:
        attrs = edge.get("attrs") or {}
        if not attrs.get("malicious"):
            continue
        en = attrs.get("evt_num")
        if en is not None:
            mal_evt_to_edge[int(en)] = edge

    if not mal_evt_to_edge:
        return {}, Counter()

    # Also include non-malicious edges that fall within the malicious range
    # so that necessary context can bracket the full attack zone.
    sorted_mal = sorted(mal_evt_to_edge.keys())
    zone_lo = sorted_mal[0] - window
    zone_hi = sorted_mal[-1] + window

    spine_evt_to_edge: dict[int, dict[str, Any]] = dict(mal_evt_to_edge)
    for edge in edge_sequence:
        en = (edge.get("attrs") or {}).get("evt_num")
        if en is not None:
            en_i = int(en)
            if zone_lo <= en_i <= zone_hi and en_i not in spine_evt_to_edge:
                spine_evt_to_edge[en_i] = edge

    sorted_evts = sorted(spine_evt_to_edge.keys())
    lo = sorted_evts[0] - window
    hi = sorted_evts[-1] + window

    by_eid: dict[str, list[dict[str, Any]]] = defaultdict(list)
    stats: Counter = Counter()
    progress = ProgressLogger(
        stage="build_behavior_chain_instances_v0",
        substep="load_necessary_context",
        every=50000,
        min_interval_s=15.0,
        prefix="[chain_dataset_v2][progress]",
    )
    processed = 0

    for tier_name, path in tiered_paths:
        if not path.exists():
            continue
        for rec in _iter_jsonl(path):
            processed += 1
            attrs = rec.get("attrs") or {}
            if attrs.get("malicious", False):
                continue

            evt_type = (
                rec.get("event_type")
                or attrs.get("raw_evt_type", "")
            )
            if str(evt_type).lower() not in NECESSARY_CONTEXT_EVT_TYPES:
                continue

            en = attrs.get("evt_num")
            if en is None:
                continue
            en = int(en)
            if en < lo or en > hi:
                continue

            idx = bisect.bisect_left(sorted_evts, en)
            best_evt: Optional[int] = None
            best_delta = window + 1
            for ci in (idx - 1, idx):
                if 0 <= ci < len(sorted_evts):
                    d = abs(sorted_evts[ci] - en)
                    if d < best_delta:
                        best_delta = d
                        best_evt = sorted_evts[ci]

            if best_evt is None or best_delta > window:
                continue

            edge = spine_evt_to_edge[best_evt]

            spine_cid = (edge.get("attrs") or {}).get("container_id")
            rec_cid = (
                attrs.get("container_id")
                or (rec.get("proc") or {}).get("container_id")
            )
            if spine_cid and rec_cid and spine_cid != rec_cid:
                continue

            eid = edge.get("edge_id")
            by_eid[eid].append({
                "context_id": f"nctx_{tier_name}_{rec.get('id', en)}",
                "source_tier": tier_name,
                "record_mode": rec.get("record_mode", "structured_event"),
                "is_malicious": False,
                "is_necessary_context": True,
                "attach_to_backbone_edge_id": eid,
                "attach_reason": ["evt_num_proximity"],
                "attach_strength": "proximity",
                "context_record": rec,
                "link_features": {
                    "evt_num_delta": best_delta,
                    "same_container": True,
                    "necessary_evt_type": str(evt_type).lower(),
                },
            })
            stats[str(evt_type).lower()] += 1

            if processed % 50000 == 0:
                progress.maybe_log(
                    processed,
                    force=True,
                    matched_edges=len(by_eid),
                    loaded_context=sum(len(v) for v in by_eid.values()),
                )

    progress.maybe_log(
        processed,
        force=True,
        matched_edges=len(by_eid),
        loaded_context=sum(len(v) for v in by_eid.values()),
    )
    return dict(by_eid), stats


# ─────────────────────────────────────────────────────────────────────────
# Meta: per-context attach detail
# ─────────────────────────────────────────────────────────────────────────

def _build_context_meta_entry(ctx: dict[str, Any]) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "context_id": ctx.get("context_id"),
        "attach_to_backbone_edge_id": ctx.get("attach_to_backbone_edge_id"),
        "attach_reason": ctx.get("attach_reason"),
        "attach_strength": ctx.get("attach_strength"),
        "backbone_ref": ctx.get("backbone_ref"),
        "link_features": ctx.get("link_features"),
        "source_tier": ctx.get("source_tier"),
        "record_mode": ctx.get("record_mode"),
    }
    if ctx.get("is_necessary_context"):
        entry["is_necessary_context"] = True
    return entry


# ─────────────────────────────────────────────────────────────────────────
# Stage residual sidecar (meta-layer supplemental view)
# ─────────────────────────────────────────────────────────────────────────

def _load_stage_residual_sidecar(
    sidecar_path: Path,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Read stage_residual sidecar JSONL, return (records, parse_stats).

    Tolerates missing / empty / malformed lines gracefully.
    parse_stats carries counts for meta reporting.
    """
    if not sidecar_path.exists():
        return [], {
            "source_file": str(sidecar_path),
            "enabled": False,
            "total_raw_records": 0,
            "total_loaded": 0,
            "parse_errors": 0,
            "skipped_empty": 0,
        }

    records: list[dict[str, Any]] = []
    parse_errors = 0
    skipped_empty = 0

    with open(sidecar_path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                skipped_empty += 1
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                parse_errors += 1

    stats = {
        "source_file": str(sidecar_path),
        "enabled": True,
        "total_raw_records": len(records),
        "total_loaded": len(records),
        "parse_errors": parse_errors,
        "skipped_empty": skipped_empty,
    }
    return records, stats


def _build_stage_residual_view(
    sidecar_records: list[dict[str, Any]],
    substage_segments: list[dict[str, Any]],
    stage_segments: list[dict[str, Any]],
) -> dict[str, Any]:
    """Organise stage residual records by suggest_target_id (stage/substage label).

    Unmapped records (suggest_target_id is null / "unknown") are placed in
    a dedicated ``unattached`` list.

    The existing stage id system (``substage_segments`` / ``stage_segments``)
    is used as-is — no new id scheme is invented here.
    """
    # Build set of valid suggest_target_ids from the existing stage hierarchy.
    valid_ids: set[str] = set()
    for seg in (substage_segments or []):
        lbl = seg.get("label") or ""
        valid_ids.add(lbl)
    for seg in (stage_segments or []):
        lbl = seg.get("label") or ""
        valid_ids.add(lbl)

    by_stage: dict[str, list[dict[str, Any]]] = {}
    unattached: list[dict[str, Any]] = []

    # Counters for meta statistics
    type_counter: Counter[str] = Counter()
    residual_class_counter: Counter[str] = Counter()
    tier_counter: Counter[str] = Counter()
    mapped_count = 0
    unmapped_count = 0

    for rec in sidecar_records:
        # ── lightweight view construction ───────────────────────────────────
        raw_type = rec.get("raw_evt_type", "")
        orig_ref = rec.get("orig_ref") or {}

        # mapping_evidence is kept intact as-is (already structured in sidecar)
        mapping_evidence = rec.get("mapping_evidence") or {}

        # attach_basis: compact summary of why this residual maps to this stage
        # Use the already-structured mapping_evidence as the basis
        attach_basis: dict[str, Any] = {
            "nearest_seq": mapping_evidence.get("nearest_seq"),
            "delta_seconds": mapping_evidence.get("delta_seconds"),
            "backbone_relation": mapping_evidence.get("backbone_relation"),
            "parent_stage": mapping_evidence.get("parent_stage"),
        }

        # If nearest_seq is not available, add source tier from orig_ref
        if attach_basis["nearest_seq"] is None:
            attach_basis["source_tier"] = orig_ref.get("source_tier")

        # ── attach_reason: clean reason without target_level suffix ────────────
        residual_class = rec.get("residual_class", "")
        residual_subreason = rec.get("residual_subreason", "")
        attach_reason = residual_subreason or "stage_level_environment_probe"
        suggest_level = rec.get("suggest_target_level", "")

        view_entry = {
            "residual_id": rec.get("orig_record_id") or rec.get("id") or "",
            "raw_evt_type": raw_type,
            "evt_num": orig_ref.get("evt_num"),
            "timestamp": rec.get("timestamp", ""),
            "malicious": True,          # all sidecar records are malicious
            "source_tier": orig_ref.get("source_tier", "unknown"),
            "suggest_target_level": suggest_level,
            "suggest_target_id": rec.get("suggest_target_id"),
            "attach_reason": attach_reason,
            "attach_basis": attach_basis,
            "original_record_ref": {
                "id": orig_ref.get("orig_record_id") or rec.get("orig_record_id") or "",
                "scenario_id": rec.get("scenario_id", ""),
                "evt_num": orig_ref.get("evt_num"),
                "source_tier": orig_ref.get("source_tier", "unknown"),
            },
        }

        # ── routing: by_stage vs unattached ─────────────────────────────────
        target_id = rec.get("suggest_target_id") or ""
        if target_id and target_id not in ("unknown", "None", ""):
            if target_id not in by_stage:
                by_stage[target_id] = []
            by_stage[target_id].append(view_entry)
            mapped_count += 1
        else:
            unattached.append(view_entry)
            unmapped_count += 1

        # counters
        if raw_type:
            type_counter[raw_type] += 1
        if residual_class:
            residual_class_counter[residual_class] += 1
        if orig_ref.get("source_tier"):
            tier_counter[orig_ref.get("source_tier")] += 1

    # Sort each stage's residual list by evt_num for stable ordering
    for stage_id in by_stage:
        by_stage[stage_id].sort(key=lambda r: r.get("evt_num") or 0)
    unattached.sort(key=lambda r: r.get("evt_num") or 0)

    return {
        "enabled": True,
        "total_residual_records": len(sidecar_records),
        "mapped_residual_count": mapped_count,
        "unmapped_residual_count": unmapped_count,
        "by_target": by_stage,
        "unattached": unattached,
        "residual_type_counts": dict(sorted(type_counter.items())),
        "residual_class_counts": dict(sorted(residual_class_counter.items())),
        "source_tier_counts": dict(sorted(tier_counter.items())),
    }


def _load_refinement_residual_sidecar(
    sidecar_path: Path,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if not sidecar_path.exists():
        return [], {
            "source_file": str(sidecar_path),
            "enabled": False,
            "total_raw_records": 0,
            "total_loaded": 0,
            "parse_errors": 0,
            "skipped_empty": 0,
        }

    records: list[dict[str, Any]] = []
    parse_errors = 0
    skipped_empty = 0
    with open(sidecar_path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                skipped_empty += 1
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                parse_errors += 1

    return records, {
        "source_file": str(sidecar_path),
        "enabled": True,
        "total_raw_records": len(records),
        "total_loaded": len(records),
        "parse_errors": parse_errors,
        "skipped_empty": skipped_empty,
    }


def _get_backbone_edge_id(edge: dict[str, Any]) -> Optional[str]:
    edge_id = edge.get("edge_id")
    if edge_id in (None, ""):
        edge_id = edge.get("id")
    if edge_id in (None, ""):
        return None
    return str(edge_id)


def _extract_backbone_story_alignment(backbone: dict[str, Any]) -> dict[str, Any]:
    edge_sequence = backbone.get("edge_sequence") or []
    seq_to_edge: dict[int, dict[str, Any]] = {}
    first_malicious_edge: Optional[dict[str, Any]] = None
    last_malicious_edge: Optional[dict[str, Any]] = None
    for edge in edge_sequence:
        if not isinstance(edge, dict):
            continue
        seq = edge.get("seq")
        if isinstance(seq, int) and seq > 0:
            seq_to_edge[seq] = edge
        attrs = edge.get("attrs") or {}
        if bool(attrs.get("malicious", False)):
            if first_malicious_edge is None:
                first_malicious_edge = edge
            last_malicious_edge = edge

    chain_summary = backbone.get("chain_summary") or {}
    expression_clarity = chain_summary.get("expression_clarity") or {}
    first_malicious_seq = expression_clarity.get("first_malicious_seq")
    last_malicious_seq = expression_clarity.get("last_malicious_seq")

    if isinstance(first_malicious_seq, int) and first_malicious_seq > 0:
        first_malicious_edge = seq_to_edge.get(first_malicious_seq, first_malicious_edge)
    if isinstance(last_malicious_seq, int) and last_malicious_seq > 0:
        last_malicious_edge = seq_to_edge.get(last_malicious_seq, last_malicious_edge)

    def _anchor_from_edge(edge: Optional[dict[str, Any]]) -> Optional[dict[str, Any]]:
        if not isinstance(edge, dict):
            return None
        attrs = edge.get("attrs") or {}
        evt_num = attrs.get("evt_num")
        if not isinstance(evt_num, int):
            try:
                evt_num = int(evt_num)
            except (TypeError, ValueError):
                evt_num = None
        seq = edge.get("seq")
        if not isinstance(seq, int):
            try:
                seq = int(seq)
            except (TypeError, ValueError):
                seq = None
        return {
            "edge_id": _get_backbone_edge_id(edge),
            "relation": str(edge.get("relation") or ""),
            "evt_num": evt_num,
            "seq": seq,
        }

    entry_anchor = _anchor_from_edge(first_malicious_edge)
    result_anchor = _anchor_from_edge(last_malicious_edge)
    malicious_span_start = _anchor_from_edge(first_malicious_edge)
    malicious_span_end = _anchor_from_edge(last_malicious_edge)

    span_start_evt = (
        malicious_span_start.get("evt_num")
        if isinstance(malicious_span_start, dict)
        else None
    )
    span_end_evt = (
        malicious_span_end.get("evt_num")
        if isinstance(malicious_span_end, dict)
        else None
    )
    boundary_gap_evt = 200
    if isinstance(span_start_evt, int) and isinstance(span_end_evt, int):
        span_width = max(span_end_evt - span_start_evt, 0)
        boundary_gap_evt = max(200, min(5000, span_width // 10 if span_width > 0 else 200))

    return {
        "entry_anchor": entry_anchor,
        "result_anchor": result_anchor,
        "malicious_span_start": malicious_span_start,
        "malicious_span_end": malicious_span_end,
        "malicious_span_evt_window": {
            "start_evt_num": span_start_evt,
            "end_evt_num": span_end_evt,
        },
        "adjacent_boundary_gap_evt": boundary_gap_evt,
    }


def _window_distance_to_evt(
    *,
    start_evt_num: Optional[int],
    end_evt_num: Optional[int],
    anchor_evt_num: Optional[int],
) -> Optional[int]:
    if not isinstance(start_evt_num, int) or not isinstance(end_evt_num, int):
        return None
    if not isinstance(anchor_evt_num, int):
        return None
    if start_evt_num <= anchor_evt_num <= end_evt_num:
        return 0
    if anchor_evt_num < start_evt_num:
        return start_evt_num - anchor_evt_num
    return anchor_evt_num - end_evt_num


def _stage_window_relative_to_malicious_span(
    *,
    start_evt_num: Optional[int],
    end_evt_num: Optional[int],
    span_start_evt_num: Optional[int],
    span_end_evt_num: Optional[int],
) -> str:
    if not isinstance(start_evt_num, int) or not isinstance(end_evt_num, int):
        return "unknown"
    if not isinstance(span_start_evt_num, int) or not isinstance(span_end_evt_num, int):
        return "unknown"
    if end_evt_num < span_start_evt_num:
        return "before_malicious_span"
    if start_evt_num > span_end_evt_num:
        return "after_malicious_span"
    if start_evt_num <= span_start_evt_num and end_evt_num >= span_end_evt_num:
        return "span_bridge_shell"
    if start_evt_num <= span_start_evt_num <= end_evt_num < span_end_evt_num:
        return "overlaps_span_start_boundary"
    if span_start_evt_num < start_evt_num <= span_end_evt_num <= end_evt_num:
        return "overlaps_span_end_boundary"
    if span_start_evt_num <= start_evt_num and end_evt_num <= span_end_evt_num:
        return "inside_malicious_span"
    return "overlaps_malicious_span"


def _classify_stage_narrative_position(
    *,
    relative_position: str,
    adjacent_to_entry: bool,
    adjacent_to_result: bool,
    adjacent_to_span_start: bool,
    adjacent_to_span_end: bool,
) -> str:
    if relative_position == "before_malicious_span":
        if adjacent_to_entry or adjacent_to_span_start:
            return "entry_prelude_shell"
        return "pre_attack_background_shell"
    if relative_position == "after_malicious_span":
        if adjacent_to_result or adjacent_to_span_end:
            return "result_tail_shell"
        return "post_attack_background_shell"
    if relative_position == "overlaps_span_start_boundary":
        return "entry_adjacent_runtime_shell"
    if relative_position == "overlaps_span_end_boundary":
        return "result_adjacent_runtime_shell"
    if relative_position == "span_bridge_shell":
        return "cross_span_runtime_shell"
    if relative_position == "inside_malicious_span":
        return "in_span_runtime_shell"
    if relative_position == "overlaps_malicious_span":
        return "attack_adjacent_runtime_shell"
    return "unknown_runtime_shell"


def _classify_attack_entry_shell_width(
    *,
    relative_position: str,
    start_evt_num: Optional[int],
    end_evt_num: Optional[int],
    span_start_evt_num: Optional[int],
    span_end_evt_num: Optional[int],
    entry_anchor_distance_evt: Optional[int],
    span_start_distance_evt: Optional[int],
    adjacent_gap_evt: int,
) -> tuple[str, dict[str, Any]]:
    stage_width_evt: Optional[int] = None
    if isinstance(start_evt_num, int) and isinstance(end_evt_num, int):
        stage_width_evt = max(end_evt_num - start_evt_num, 0)

    malicious_span_width_evt: Optional[int] = None
    if isinstance(span_start_evt_num, int) and isinstance(span_end_evt_num, int):
        malicious_span_width_evt = max(span_end_evt_num - span_start_evt_num, 0)

    width_vs_malicious_span_ratio: Optional[float] = None
    if isinstance(stage_width_evt, int) and isinstance(malicious_span_width_evt, int):
        divisor = max(malicious_span_width_evt, 1)
        width_vs_malicious_span_ratio = round(stage_width_evt / divisor, 6)

    near_entry = (
        (isinstance(entry_anchor_distance_evt, int) and entry_anchor_distance_evt <= adjacent_gap_evt)
        or (isinstance(span_start_distance_evt, int) and span_start_distance_evt <= adjacent_gap_evt)
    )
    span_bridge = relative_position == "span_bridge_shell"

    wide_by_ratio = bool(
        span_bridge
        and isinstance(width_vs_malicious_span_ratio, float)
        and width_vs_malicious_span_ratio >= 3.0
    )
    wide_by_absolute_width = bool(
        span_bridge
        and isinstance(stage_width_evt, int)
        and stage_width_evt >= max(adjacent_gap_evt * 10, 20000)
    )

    if wide_by_ratio or wide_by_absolute_width:
        entry_adjacency_class = "wide_span_bridge_shell"
    else:
        # Keep this binary and lightweight: non-wide attack-entry shells
        # are interpreted as narrow adjacency shells.
        entry_adjacency_class = "narrow_entry_adjacent_shell"

    metrics: dict[str, Any] = {
        "stage_window_width_evt": stage_width_evt,
        "malicious_span_width_evt": malicious_span_width_evt,
        "width_vs_malicious_span_ratio": width_vs_malicious_span_ratio,
        "entry_anchor_distance_evt": entry_anchor_distance_evt,
        "malicious_span_start_distance_evt": span_start_distance_evt,
        "span_bridge": span_bridge,
        "near_entry": near_entry,
        "wide_by_ratio": wide_by_ratio,
        "wide_by_absolute_width": wide_by_absolute_width,
    }
    return entry_adjacency_class, metrics


def _window_width_evt(window: dict[str, Any]) -> Optional[int]:
    start_evt_num = window.get("start_evt_num")
    end_evt_num = window.get("end_evt_num")
    if not isinstance(start_evt_num, int) or not isinstance(end_evt_num, int):
        return None
    return max(end_evt_num - start_evt_num, 0)


def _build_attack_entry_cluster_narrow_hint(
    *,
    clusters: list[dict[str, Any]],
    backbone_story_alignment: dict[str, Any],
) -> dict[str, Any]:
    evaluated_clusters = 0
    narrow_candidates: list[dict[str, Any]] = []
    min_cluster_window_width_evt: Optional[int] = None

    for cluster in clusters:
        window = cluster.get("window") if isinstance(cluster.get("window"), dict) else {}
        stage_window = {
            "start_evt_num": window.get("start_evt_num"),
            "end_evt_num": window.get("end_evt_num"),
        }
        width_evt = _window_width_evt(stage_window)
        if width_evt is None:
            continue
        evaluated_clusters += 1
        if min_cluster_window_width_evt is None or width_evt < min_cluster_window_width_evt:
            min_cluster_window_width_evt = width_evt

        cluster_alignment = _build_stage_story_alignment(
            stage_hint="attack_entry_adjacent_shell",
            stage_window=stage_window,
            backbone_story_alignment=backbone_story_alignment,
        )
        entry_adjacency_class = str(
            cluster_alignment.get("entry_adjacency_class") or ""
        )
        if entry_adjacency_class != "narrow_entry_adjacent_shell":
            continue
        narrow_candidates.append(
            {
                "residual_id": cluster.get("residual_id"),
                "relation_family": cluster.get("relation_family"),
                "window": stage_window,
                "window_width_evt": width_evt,
                "entry_adjacency_class": entry_adjacency_class,
            }
        )

    narrow_candidates.sort(
        key=lambda item: (
            item.get("window_width_evt") if isinstance(item.get("window_width_evt"), int) else 10**18,
            str(item.get("residual_id") or ""),
        )
    )

    return {
        "cluster_level_narrow_candidate_exists": bool(narrow_candidates),
        "cluster_level_narrow_candidate_count": len(narrow_candidates),
        "cluster_level_narrow_candidate_examples": narrow_candidates[:3],
        "cluster_level_min_window_width_evt": min_cluster_window_width_evt,
        "cluster_level_evaluated_count": evaluated_clusters,
    }


def _build_stage_story_alignment(
    *,
    stage_hint: str,
    stage_window: dict[str, Optional[int]],
    backbone_story_alignment: dict[str, Any],
) -> dict[str, Any]:
    start_evt_num = stage_window.get("start_evt_num")
    end_evt_num = stage_window.get("end_evt_num")
    entry_anchor = backbone_story_alignment.get("entry_anchor") or {}
    result_anchor = backbone_story_alignment.get("result_anchor") or {}
    span_start_anchor = backbone_story_alignment.get("malicious_span_start") or {}
    span_end_anchor = backbone_story_alignment.get("malicious_span_end") or {}
    span_window = backbone_story_alignment.get("malicious_span_evt_window") or {}
    span_start_evt_num = span_window.get("start_evt_num")
    span_end_evt_num = span_window.get("end_evt_num")
    adjacent_gap_evt = int(backbone_story_alignment.get("adjacent_boundary_gap_evt") or 200)

    anchor_specs = [
        ("entry_anchor", entry_anchor),
        ("result_anchor", result_anchor),
        ("malicious_span_start", span_start_anchor),
        ("malicious_span_end", span_end_anchor),
    ]
    anchor_distances_evt: dict[str, Optional[int]] = {}
    nearest_anchors: list[dict[str, Any]] = []
    for anchor_name, anchor in anchor_specs:
        distance_evt = _window_distance_to_evt(
            start_evt_num=start_evt_num,
            end_evt_num=end_evt_num,
            anchor_evt_num=anchor.get("evt_num"),
        )
        anchor_distances_evt[anchor_name] = distance_evt
        nearest_anchors.append(
            {
                "anchor": anchor_name,
                "edge_id": anchor.get("edge_id"),
                "relation": anchor.get("relation"),
                "evt_num": anchor.get("evt_num"),
                "distance_evt": distance_evt,
            }
        )

    nearest_anchors.sort(
        key=lambda item: (
            item.get("distance_evt") is None,
            item.get("distance_evt") if isinstance(item.get("distance_evt"), int) else 10**18,
            str(item.get("anchor") or ""),
        )
    )
    nearest_anchors = nearest_anchors[:2]

    adjacent_to_entry = (
        isinstance(anchor_distances_evt.get("entry_anchor"), int)
        and int(anchor_distances_evt["entry_anchor"]) <= adjacent_gap_evt
    )
    adjacent_to_result = (
        isinstance(anchor_distances_evt.get("result_anchor"), int)
        and int(anchor_distances_evt["result_anchor"]) <= adjacent_gap_evt
    )
    adjacent_to_span_start = (
        isinstance(anchor_distances_evt.get("malicious_span_start"), int)
        and int(anchor_distances_evt["malicious_span_start"]) <= adjacent_gap_evt
    )
    adjacent_to_span_end = (
        isinstance(anchor_distances_evt.get("malicious_span_end"), int)
        and int(anchor_distances_evt["malicious_span_end"]) <= adjacent_gap_evt
    )

    relative_position = _stage_window_relative_to_malicious_span(
        start_evt_num=start_evt_num,
        end_evt_num=end_evt_num,
        span_start_evt_num=span_start_evt_num,
        span_end_evt_num=span_end_evt_num,
    )
    narrative_position = _classify_stage_narrative_position(
        relative_position=relative_position,
        adjacent_to_entry=adjacent_to_entry,
        adjacent_to_result=adjacent_to_result,
        adjacent_to_span_start=adjacent_to_span_start,
        adjacent_to_span_end=adjacent_to_span_end,
    )

    story_alignment = {
        "stage_hint": stage_hint,
        "stage_window": {
            "start_evt_num": start_evt_num,
            "end_evt_num": end_evt_num,
        },
        "relative_to_malicious_span": relative_position,
        "anchor_distance_evt": anchor_distances_evt,
        "adjacent_boundary_gap_evt": adjacent_gap_evt,
        "adjacent_to_entry_anchor": adjacent_to_entry,
        "adjacent_to_result_anchor": adjacent_to_result,
        "adjacent_to_malicious_span_start": adjacent_to_span_start,
        "adjacent_to_malicious_span_end": adjacent_to_span_end,
        "nearest_anchors": nearest_anchors,
        "narrative_position": narrative_position,
    }
    if stage_hint == "attack_entry_adjacent_shell":
        entry_adjacency_class, entry_adjacency_metrics = _classify_attack_entry_shell_width(
            relative_position=relative_position,
            start_evt_num=start_evt_num,
            end_evt_num=end_evt_num,
            span_start_evt_num=span_start_evt_num,
            span_end_evt_num=span_end_evt_num,
            entry_anchor_distance_evt=anchor_distances_evt.get("entry_anchor"),
            span_start_distance_evt=anchor_distances_evt.get("malicious_span_start"),
            adjacent_gap_evt=adjacent_gap_evt,
        )
        story_alignment["entry_adjacency_class"] = entry_adjacency_class
        story_alignment["entry_adjacency_metrics"] = entry_adjacency_metrics
    return story_alignment


def _build_refinement_residual_view(
    sidecar_records: list[dict[str, Any]],
    sidecar_path: Path,
    scenario_dir: Path,
    backbone: dict[str, Any],
) -> dict[str, Any]:
    by_relation_family: dict[str, list[dict[str, Any]]] = defaultdict(list)
    stage_hint_counter: Counter[str] = Counter()
    relation_family_counter: Counter[str] = Counter()
    narrative_role_counter: Counter[str] = Counter()
    backbone_priority_counter: Counter[str] = Counter()
    shell_origin_hint_counter: Counter[str] = Counter()
    total_dropped_edges = 0

    rel_source_file = str(sidecar_path)
    try:
        rel_source_file = str(sidecar_path.relative_to(scenario_dir))
    except ValueError:
        pass

    backbone_story_alignment = _extract_backbone_story_alignment(backbone)

    stage_summary_map: dict[str, dict[str, Any]] = {}

    for rec in sidecar_records:
        relation_family = str(rec.get("relation_family") or "UNKNOWN")
        stage_hint = str(rec.get("stage_hint") or "unknown")
        summary = rec.get("summary") if isinstance(rec.get("summary"), dict) else {}
        total_dropped_edges += int(summary.get("dropped_count") or 0)
        stage_hint_counter[stage_hint] += 1
        relation_family_counter[relation_family] += 1
        narrative_role = str(rec.get("narrative_role") or "unknown")
        backbone_priority = str(rec.get("backbone_priority") or "unknown")
        shell_origin_hint = str(rec.get("shell_origin_hint") or "unknown")
        narrative_role_counter[narrative_role] += 1
        backbone_priority_counter[backbone_priority] += 1
        shell_origin_hint_counter[shell_origin_hint] += 1

        stage_bucket = stage_summary_map.setdefault(
            stage_hint,
            {
                "cluster_count": 0,
                "original_count_total": 0,
                "kept_count_total": 0,
                "dropped_count_total": 0,
                "relation_family_counts": Counter(),
                "anchor_backbone_edge_ids": set(),
                "why_retained": Counter(),
                "subject_counts": Counter(),
                "representative_clusters": [],
                "representative_edges": [],
                "window_start_evt_num": None,
                "window_end_evt_num": None,
            },
        )
        stage_bucket["cluster_count"] += 1
        stage_bucket["original_count_total"] += int(summary.get("original_count") or 0)
        stage_bucket["kept_count_total"] += int(summary.get("kept_count") or 0)
        stage_bucket["dropped_count_total"] += int(summary.get("dropped_count") or 0)
        stage_bucket["relation_family_counts"][relation_family] += 1
        stage_bucket["subject_counts"][str(rec.get("subject") or "unknown")] += 1
        window = rec.get("window") if isinstance(rec.get("window"), dict) else {}
        start_evt_num = window.get("start_evt_num")
        end_evt_num = window.get("end_evt_num")
        if isinstance(start_evt_num, int):
            prev_start = stage_bucket.get("window_start_evt_num")
            if not isinstance(prev_start, int) or start_evt_num < prev_start:
                stage_bucket["window_start_evt_num"] = start_evt_num
        if isinstance(end_evt_num, int):
            prev_end = stage_bucket.get("window_end_evt_num")
            if not isinstance(prev_end, int) or end_evt_num > prev_end:
                stage_bucket["window_end_evt_num"] = end_evt_num
        stage_bucket["anchor_backbone_edge_ids"].update(
            str(x) for x in (rec.get("anchor_backbone_edge_ids") or []) if str(x)
        )
        for why in rec.get("why_retained") or []:
            stage_bucket["why_retained"][str(why)] += 1
        stage_bucket["representative_clusters"].append(
            {
                "residual_id": rec.get("residual_id"),
                "relation_family": relation_family,
                "window": rec.get("window"),
                "dropped_count": int(summary.get("dropped_count") or 0),
                "kept_count": int(summary.get("kept_count") or 0),
                "anchor_backbone_edge_ids": rec.get("anchor_backbone_edge_ids") or [],
            }
        )
        for edge in rec.get("representative_edges") or []:
            stage_bucket["representative_edges"].append(edge)

        by_relation_family[relation_family].append(
            {
                "residual_id": rec.get("residual_id"),
                "window": rec.get("window"),
                "anchor_backbone_edge_ids": rec.get("anchor_backbone_edge_ids") or [],
                "summary": summary,
                "stage_hint": stage_hint,
                "why_retained": rec.get("why_retained") or [],
                "narrative_role": narrative_role,
                "backbone_priority": backbone_priority,
                "shell_origin_hint": shell_origin_hint,
                "representative_edges": rec.get("representative_edges") or [],
            }
        )

    for relation_family in by_relation_family:
        by_relation_family[relation_family].sort(
            key=lambda item: (
                ((item.get("window") or {}).get("start_evt_num") or 0),
                item.get("residual_id") or "",
            )
        )

    stage_summary: dict[str, dict[str, Any]] = {}
    for stage_hint, bucket in sorted(stage_summary_map.items()):
        bucket["representative_clusters"].sort(
            key=lambda item: (
                -int(item.get("dropped_count") or 0),
                ((item.get("window") or {}).get("start_evt_num") or 0),
                str(item.get("residual_id") or ""),
            )
        )
        seen_edge_ids: set[str] = set()
        representative_edges: list[dict[str, Any]] = []
        for edge in bucket["representative_edges"]:
            edge_id = str(edge.get("edge_id") or "")
            if not edge_id or edge_id in seen_edge_ids:
                continue
            seen_edge_ids.add(edge_id)
            representative_edges.append(edge)
            if len(representative_edges) >= 8:
                break
        stage_window = {
            "start_evt_num": bucket.get("window_start_evt_num"),
            "end_evt_num": bucket.get("window_end_evt_num"),
        }
        story_alignment = _build_stage_story_alignment(
            stage_hint=stage_hint,
            stage_window=stage_window,
            backbone_story_alignment=backbone_story_alignment,
        )
        stage_summary_entry = {
            "cluster_count": int(bucket["cluster_count"]),
            "original_count_total": int(bucket["original_count_total"]),
            "kept_count_total": int(bucket["kept_count_total"]),
            "dropped_count_total": int(bucket["dropped_count_total"]),
            "relation_family_counts": dict(sorted(bucket["relation_family_counts"].items())),
            "anchor_backbone_edge_ids": sorted(bucket["anchor_backbone_edge_ids"])[:24],
            "window": stage_window,
            "story_alignment": story_alignment,
            "why_retained": [k for k, _ in bucket["why_retained"].most_common(8)],
            "subject_summary": bucket["subject_counts"].most_common(5),
            "representative_clusters": bucket["representative_clusters"][:5],
            "representative_edges": representative_edges,
        }
        if stage_hint == "attack_entry_adjacent_shell":
            cluster_narrow_hint = _build_attack_entry_cluster_narrow_hint(
                clusters=bucket["representative_clusters"],
                backbone_story_alignment=backbone_story_alignment,
            )
            stage_summary_entry.update(cluster_narrow_hint)
        stage_summary[stage_hint] = stage_summary_entry

    return {
        "enabled": True,
        "source_file": rel_source_file,
        "total_residual_records": len(sidecar_records),
        "total_dropped_edges": total_dropped_edges,
        "relation_family_counts": dict(sorted(relation_family_counter.items())),
        "stage_hint_counts": dict(sorted(stage_hint_counter.items())),
        "narrative_role_counts": dict(sorted(narrative_role_counter.items())),
        "backbone_priority_counts": dict(sorted(backbone_priority_counter.items())),
        "shell_origin_hint_counts": dict(sorted(shell_origin_hint_counter.items())),
        "backbone_story_alignment": backbone_story_alignment,
        "stage_summary": stage_summary,
        "by_relation_family": dict(sorted(by_relation_family.items())),
    }


# ─────────────────────────────────────────────────────────────────────────
# Edge applog context sidecar (meta-layer supplemental view)
# ─────────────────────────────────────────────────────────────────────────

def _load_edge_applog_context_sidecar(
    sidecar_path: Path,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Read edge_applog_context sidecar JSONL, return (records, parse_stats)."""
    if not sidecar_path.exists():
        return [], {
            "source_file": str(sidecar_path),
            "enabled": False,
            "total_raw_records": 0,
            "total_loaded": 0,
            "parse_errors": 0,
            "skipped_empty": 0,
        }

    records: list[dict[str, Any]] = []
    parse_errors = 0
    skipped_empty = 0

    with open(sidecar_path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                skipped_empty += 1
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                parse_errors += 1

    stats = {
        "source_file": str(sidecar_path),
        "enabled": True,
        "total_raw_records": len(records),
        "total_loaded": len(records),
        "parse_errors": parse_errors,
        "skipped_empty": skipped_empty,
    }
    return records, stats


def _build_edge_applog_context_meta_view(
    sidecar_records: list[dict[str, Any]],
    sidecar_path: Path,
    scenario_dir: Path,
) -> dict[str, Any]:
    """Organise applog edge-level context records by target_id for meta view."""
    by_target: dict[str, list[dict[str, Any]]] = {}
    unattached: list[dict[str, Any]] = []

    target_kind_counter: Counter[str] = Counter()
    attach_reason_counter: Counter[str] = Counter()
    mapped_count = 0
    unmapped_count = 0

    rel_source_file = str(sidecar_path)
    try:
        rel_source_file = str(sidecar_path.relative_to(scenario_dir))
    except ValueError:
        pass

    keep_fields = [
        "context_id",
        "context_type",
        "target_level",
        "target_id",
        "target_kind",
        "target_id_note",
        "event_key",
        "source_file",
        "line_no",
        "matched_evt_num",
        "timestamp",
        "container_id",
        "service_name",
        "attach_reason",
        "attach_strength",
        "attach_basis",
        "raw_ref",
    ]

    for rec in sidecar_records:
        view_entry = {field: rec.get(field) for field in keep_fields}
        target_id = view_entry.get("target_id")
        target_kind = view_entry.get("target_kind") or ""
        attach_reason = view_entry.get("attach_reason") or ""

        if target_kind:
            target_kind_counter[target_kind] += 1
        if attach_reason:
            attach_reason_counter[attach_reason] += 1

        if target_id not in (None, "", "unknown", "None"):
            by_target.setdefault(str(target_id), []).append(view_entry)
            mapped_count += 1
        else:
            unattached.append(view_entry)
            unmapped_count += 1

    for target_id in by_target:
        by_target[target_id].sort(
            key=lambda r: (
                r.get("matched_evt_num") or 0,
                r.get("line_no") or 0,
                r.get("context_id") or "",
            )
        )
    unattached.sort(
        key=lambda r: (
            r.get("matched_evt_num") or 0,
            r.get("line_no") or 0,
            r.get("context_id") or "",
        )
    )

    return {
        "enabled": True,
        "source_file": rel_source_file,
        "total_context_records": len(sidecar_records),
        "mapped_record_count": mapped_count,
        "unmapped_record_count": unmapped_count,
        "target_kind_counts": dict(sorted(target_kind_counter.items())),
        "attach_reason_counts": dict(sorted(attach_reason_counter.items())),
        "by_target": by_target,
        "unattached": unattached,
    }


def _load_applog_model_context_sidecar(
    sidecar_path: Path,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Read applog_model_context sidecar JSONL, return (records, parse_stats)."""
    if not sidecar_path.exists():
        return [], {
            "source_file": str(sidecar_path),
            "enabled": False,
            "total_raw_records": 0,
            "total_loaded": 0,
            "parse_errors": 0,
            "skipped_empty": 0,
        }

    records: list[dict[str, Any]] = []
    parse_errors = 0
    skipped_empty = 0

    with open(sidecar_path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                skipped_empty += 1
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                parse_errors += 1

    stats = {
        "source_file": str(sidecar_path),
        "enabled": True,
        "total_raw_records": len(records),
        "total_loaded": len(records),
        "parse_errors": parse_errors,
        "skipped_empty": skipped_empty,
    }
    return records, stats


def _build_applog_evidence_alignment_lookup(
    sidecar_records: list[dict[str, Any]],
) -> tuple[dict[str, set[str]], dict[str, int]]:
    """Build weak alignment lookup from edge_applog_context sidecar."""
    event_keys: set[str] = set()
    context_ids: set[str] = set()

    total_records = 0
    qualified_records = 0
    missing_attach_evidence_records = 0
    missing_alignment_key_records = 0

    for rec in sidecar_records:
        total_records += 1
        attach_reason = rec.get("attach_reason")
        attach_basis = rec.get("attach_basis")
        has_attach_evidence = bool(attach_reason) and isinstance(attach_basis, dict) and bool(attach_basis)
        if not has_attach_evidence:
            missing_attach_evidence_records += 1
            continue

        has_alignment_key = False
        event_key = rec.get("event_key")
        if event_key not in (None, ""):
            event_keys.add(str(event_key))
            has_alignment_key = True

        context_id = rec.get("context_id")
        if context_id not in (None, ""):
            context_ids.add(str(context_id))
            has_alignment_key = True

        if has_alignment_key:
            qualified_records += 1
        else:
            missing_alignment_key_records += 1

    lookup = {
        "event_keys": event_keys,
        "context_ids": context_ids,
    }
    stats = {
        "total_records": total_records,
        "qualified_records": qualified_records,
        "missing_attach_evidence_records": missing_attach_evidence_records,
        "missing_alignment_key_records": missing_alignment_key_records,
    }
    return lookup, stats


APPLOG_WRITEBACK_PER_EDGE_CAP = 10
APPLOG_WEAK_PER_EDGE_CAP = 2
APPLOG_REQUEST_WINDOW_SEC = 2.0
APPLOG_CONTAINER_WINDOW_SEC = 5.0
# HV-only container window relaxation: error/warn/db/auth lines matter
# enough that we widen the container-time fallback specifically for
# them.  request_access / generic_runtime_log stay at 5s to prevent
# noise inflation.
APPLOG_HV_CONTAINER_WINDOW_SEC = 10.0
# Reserved per-edge slots for HV semantic records so they never lose a
# cap fight against request_access duplicates on the same edge.
APPLOG_HV_RESERVED_PER_EDGE = 2
APPLOG_REQUEST_RELATIONS = frozenset({
    "NET_ACCEPT", "NET_RECV", "NET_CONNECT", "NET_SEND",
})
APPLOG_STRENGTH_ORDER: dict[str, int] = {
    "strong": 0,
    "medium_high": 1,
    "medium": 2,
    "weak": 3,
}

# Semantic types that carry strong attack-explanatory value and deserve
# a promotion when other context agrees. Kept small and stable.
APPLOG_HIGH_VALUE_SEMANTICS = frozenset({
    "error_exception", "warn_event", "db_query", "auth_session",
})

# Semantic classifier regexes (kept light, diagnostic-driven).
_APPLOG_ACCESS_PATTERNS = (
    re.compile(r'"\s*(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|CONNECT)\s+'),
    re.compile(r'\s-\s-\s\[\d{1,2}/\w+/\d{4}'),
)
_APPLOG_SQL_PATTERNS = (
    re.compile(
        r'\b(?:SELECT|INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM|'
        r'CREATE\s+TABLE|ALTER\s+TABLE|DROP\s+TABLE)\b',
        re.IGNORECASE,
    ),
    re.compile(r'\bFROM\s+`?[a-zA-Z_][\w.$]+`?', re.IGNORECASE),
)
_APPLOG_ERROR_PATTERNS = (
    re.compile(r'\b(?:ERROR|FATAL|CRITICAL|Exception|Traceback|stacktrace)\b'),
    re.compile(r'\b(?:5\d\d\s)'),
)
_APPLOG_WARN_PATTERNS = (
    re.compile(r'\b(?:WARN|WARNING)\b'),
)
_APPLOG_AUTH_PATTERNS = (
    re.compile(
        r'\b(?:login|logout|auth|session|sign\s*in|sign\s*out|token|'
        r'password|credential)\b',
        re.IGNORECASE,
    ),
)
_APPLOG_FILE_OP_PATTERNS = (
    re.compile(
        r'\b(?:upload|download|writ\w+|read\w+|open\w+|delete\w+|unlink|'
        r'rename)\b',
        re.IGNORECASE,
    ),
    re.compile(
        r'/[\w./-]{3,}\.(?:log|txt|php|py|jsp|sh|conf|json|xml|yml|yaml|ini)\b'
    ),
)
_APPLOG_RESPONSE_PATTERNS = (
    re.compile(r'\b(?:2\d\d|3\d\d|4\d\d|5\d\d)\s+\d+(?:\s+|$)'),
    re.compile(r'\b(?:HTTP/\d\.\d"\s+\d{3})'),
)
_APPLOG_STARTUP_PATTERNS = (
    re.compile(
        r'\b(?:starting|started|initializ\w+|bootstrap|listening on|'
        r'Ready|bind\s+to|Loading\s+\w+\s+[Ss]ervice|extensions\.\.\.)\b',
        re.IGNORECASE,
    ),
)
_APPLOG_PATTERN_COLLAPSE_TS = re.compile(
    r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?'
)
_APPLOG_PATTERN_COLLAPSE_APACHE_TS = re.compile(
    r'\d{1,2}/[A-Za-z]+/\d{4}:\d{2}:\d{2}:\d{2}(?:\s[+\-]\d{4})?'
)
_APPLOG_PATTERN_COLLAPSE_IP = re.compile(r'\b\d+(?:\.\d+){3}(?::\d+)?\b')
_APPLOG_PATTERN_COLLAPSE_HEX = re.compile(r'\b0x[0-9a-fA-F]+\b')
_APPLOG_PATTERN_COLLAPSE_NUM = re.compile(r'\b\d{4,}\b')
_APPLOG_PATTERN_COLLAPSE_STR = re.compile(r'"[^"]*"')


def _classify_applog_semantic(
    message: str,
    log_style: Optional[str],
    source_file: Optional[str],
) -> str:
    msg = message or ""
    lstyle = (log_style or "").lower()
    if any(p.search(msg) for p in _APPLOG_ERROR_PATTERNS):
        return "error_exception"
    if any(p.search(msg) for p in _APPLOG_WARN_PATTERNS):
        return "warn_event"
    # Access-style takes precedence over generic runtime for webservers.
    if lstyle == "access_text" or any(p.search(msg) for p in _APPLOG_ACCESS_PATTERNS):
        return "request_access"
    if any(p.search(msg) for p in _APPLOG_SQL_PATTERNS):
        return "db_query"
    if any(p.search(msg) for p in _APPLOG_AUTH_PATTERNS):
        return "auth_session"
    if any(p.search(msg) for p in _APPLOG_FILE_OP_PATTERNS):
        return "file_operation"
    if any(p.search(msg) for p in _APPLOG_RESPONSE_PATTERNS):
        return "response_result"
    if any(p.search(msg) for p in _APPLOG_STARTUP_PATTERNS):
        return "startup_runtime"
    return "generic_runtime_log"


def _normalize_applog_pattern(msg: str) -> str:
    if not msg:
        return ""
    t = msg
    t = _APPLOG_PATTERN_COLLAPSE_TS.sub('<ts>', t)
    t = _APPLOG_PATTERN_COLLAPSE_APACHE_TS.sub('<ts>', t)
    t = _APPLOG_PATTERN_COLLAPSE_IP.sub('<ip>', t)
    t = _APPLOG_PATTERN_COLLAPSE_HEX.sub('<hex>', t)
    t = _APPLOG_PATTERN_COLLAPSE_NUM.sub('<num>', t)
    t = _APPLOG_PATTERN_COLLAPSE_STR.sub('"<str>"', t)
    return t.strip()[:200]


def _parse_spine_ts_unix(ts: Any) -> Optional[float]:
    """Parse backbone spine timestamp string to unix float seconds.

    Spine attrs store timestamps as "YYYY-mm-dd HH:MM:SS.ffffff"; applog
    sidecars use unix float. We normalise spine into unix so the two can
    be compared on the same axis.
    """
    if ts is None:
        return None
    if isinstance(ts, (int, float)):
        try:
            return float(ts)
        except (TypeError, ValueError):
            return None
    text = str(ts).strip()
    if not text:
        return None
    from datetime import datetime, timezone
    if "." in text:
        prefix, frac = text.split(".", 1)
        frac = "".join(ch for ch in frac if ch.isdigit())[:6].ljust(6, "0")
        text = f"{prefix}.{frac}"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


def _load_anchor_index_sidecar(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    records: list[dict[str, Any]] = []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return records


def _load_write_event_context_sidecar(path: Optional[Path]) -> list[dict[str, Any]]:
    if path is None or not path.exists():
        return []
    records: list[dict[str, Any]] = []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return records


def _load_unit_event_index(
    path: Optional[Path],
) -> dict[int, dict[str, Any]]:
    """Load ``index/unit_event_index.jsonl`` into evt_num -> row map.

    The sidecar is produced by the unit-event indexer at replay time;
    its coverage was confirmed to be 100% on both applog write events
    and backbone edges across our benchmark scenarios, making
    ``thread_vtid`` the strongest writer-identity signal available
    (stronger than ``write_proc_pid``). Returning an empty mapping when
    the sidecar is missing lets the caller degrade gracefully.
    """
    if path is None or not path.exists():
        return {}
    out: dict[int, dict[str, Any]] = {}
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            try:
                en = int(rec.get("evt_num"))
            except (TypeError, ValueError):
                continue
            out[en] = rec
    return out


def _reattach_applog_to_spine(
    applog_model_records: list[dict[str, Any]],
    edge_applog_context_records: list[dict[str, Any]],
    write_event_context_records: list[dict[str, Any]],
    anchor_index_records: list[dict[str, Any]],
    spine: list[dict[str, Any]],
    evt_to_unit: Optional[dict[int, dict[str, Any]]] = None,
    per_edge_cap: int = APPLOG_WRITEBACK_PER_EDGE_CAP,
) -> tuple[dict[str, list[dict[str, Any]]], dict[str, Any]]:
    """Build a backbone-edge keyed applog writeback map with a proper
    priority cascade that leverages artefacts produced AFTER analyze.py
    finished (event_to_backbone_anchor_index, the final backbone spine,
    write event linkage).

    Priority tiers (strongest first):
      1. ``matched_evt_num`` directly equals a spine edge's ``evt_num``
         → ``strong`` / ``matched_evt_num_direct``;
      2. ``sysdig:{matched_evt_num}`` hits
         ``event_to_backbone_anchor_index.v0.jsonl``
         (written by the enrich stage so it IS available now) →
         ``strong`` / ``matched_write_evt_via_anchor_index``;
      3. same-container request-level proximity: pick the closest
         NET_ACCEPT / NET_RECV / NET_CONNECT / NET_SEND spine edge
         within ±``APPLOG_REQUEST_WINDOW_SEC`` seconds →
         ``medium`` / ``request_scoped_container_time_near``;
      4. same-container nearest-any spine edge within
         ±``APPLOG_CONTAINER_WINDOW_SEC`` seconds →
         ``weak`` / ``container_time_near_fallback``.

    Tier 1+2 replace the previous "requires target_kind==backbone_edge
    from analyze.py" gate which never fires because
    ``export_edge_applog_context_view`` runs before the backbone exists.

    Each accepted record is enriched with:
      * ``message`` (``normalized_message`` fallback ``raw_message``),
      * ``source_file`` / ``line_no`` / ``log_style`` / ``service_name``
        / ``container_id`` / ``timestamp``,
      * ``attach_to_backbone_edge_id`` / ``attach_reason`` /
        ``attach_strength`` / ``attach_basis`` (provenance of the tier),
      * when available, ``write_proc_pid`` / ``write_fd_name`` /
        ``write_source_file`` / ``matched_evt_num`` (from
        ``write_event_context_index.v0.jsonl``).

    Per-backbone-edge cap: sort by (strength, timestamp) and keep the
    top ``per_edge_cap`` records. Bounded to keep the main sample slim.
    """
    evt_to_unit = evt_to_unit or {}

    # Build spine indices
    spine_by_evt: dict[int, dict[str, Any]] = {}
    spine_by_edge_id: dict[str, dict[str, Any]] = {}
    # NOTE: container_to_edges stores (ts, edge). We also keep a
    # sibling ``container_to_ts_list`` of just the timestamps to drive
    # bisect lookups safely — ordinary ``bisect(edges, (lo, {}))``
    # crashes on Python 3 when two edges share a timestamp because the
    # dict fallback comparison is illegal.
    container_to_edges: dict[str, list[tuple[float, dict[str, Any]]]] = defaultdict(list)
    allowed_backbone_edge_ids: set[str] = set()
    # SecLog-style writer identity lookup on the spine:
    # edge_id -> {container_id, thread_vtid, unit_id} from unit_event_index.
    edge_id_to_unit: dict[str, dict[str, Any]] = {}
    for edge in spine:
        attrs = edge.get("attrs") or {}
        try:
            en = int(attrs.get("evt_num"))
        except (TypeError, ValueError):
            en = None
        if en is not None:
            spine_by_evt[en] = edge
        eid = edge.get("edge_id")
        if eid:
            allowed_backbone_edge_ids.add(str(eid))
            spine_by_edge_id[str(eid)] = edge
            if en is not None:
                u = evt_to_unit.get(en) or {}
                edge_id_to_unit[str(eid)] = {
                    "container_id": (
                        u.get("container_id") or attrs.get("container_id")
                    ),
                    "thread_vtid": u.get("thread_vtid"),
                    "unit_id": u.get("unit_id"),
                }
        cid = attrs.get("container_id")
        ts_unix = _parse_spine_ts_unix(attrs.get("timestamp"))
        if cid and ts_unix is not None:
            container_to_edges[str(cid)].append((ts_unix, edge))
    container_to_ts_list: dict[str, list[float]] = {}
    for cid in container_to_edges:
        container_to_edges[cid].sort(key=lambda pair: pair[0])
        container_to_ts_list[cid] = [p[0] for p in container_to_edges[cid]]

    # sysdig:{evt_num} -> backbone_edge_id (from anchor index)
    sysdig_to_edge_id: dict[str, str] = {}
    for rec in anchor_index_records:
        sk = rec.get("source_event_key")
        aeid = rec.get("anchor_backbone_edge_id")
        if not sk or not aeid:
            continue
        if str(aeid) not in allowed_backbone_edge_ids:
            continue
        sysdig_to_edge_id.setdefault(str(sk), str(aeid))

    # write_event_context: applog_event_key -> extra provenance
    write_ctx_by_event_key: dict[str, dict[str, Any]] = {}
    for rec in write_event_context_records:
        k = rec.get("applog_event_key")
        if k:
            write_ctx_by_event_key[str(k)] = rec

    # Join applog_model with edge_applog_context on event_key for extra metadata
    ctx_by_event_key: dict[str, dict[str, Any]] = {}
    for rec in edge_applog_context_records:
        k = rec.get("event_key")
        if k:
            ctx_by_event_key[str(k)] = rec

    def _nearest_edge_in_container(
        cid: str,
        ts_unix: float,
        window_sec: float,
        relation_filter: Optional[frozenset[str]],
        preferred_thread_vtid: Optional[str] = None,
    ) -> tuple[
        Optional[dict[str, Any]],
        Optional[float],
        bool,  # thread_aligned with chosen edge
    ]:
        """Pick a backbone edge for an applog line within a
        container+time window.

        When ``preferred_thread_vtid`` is given, we first restrict to
        edges whose ``thread_vtid`` (from ``unit_event_index``) matches
        — this is SecLog's writer/thread-identity channel and a much
        stronger signal than raw time proximity. Only if no
        thread-aligned candidate exists in the window do we fall back to
        nearest-by-time among relation-filtered candidates.
        """
        edges = container_to_edges.get(cid)
        ts_list = container_to_ts_list.get(cid)
        if not edges or not ts_list:
            return None, None, False
        lo = ts_unix - window_sec
        hi = ts_unix + window_sec
        lo_i = bisect.bisect_left(ts_list, lo)
        hi_i = bisect.bisect_right(ts_list, hi)
        in_window: list[tuple[float, dict[str, Any]]] = []
        for et, edge in edges[lo_i:hi_i]:
            if relation_filter is not None:
                rel = str(edge.get("relation") or "").upper()
                if rel not in relation_filter:
                    continue
            in_window.append((et, edge))
        if not in_window:
            return None, None, False

        if preferred_thread_vtid:
            aligned: list[tuple[float, dict[str, Any]]] = []
            for et, edge in in_window:
                eid = str(edge.get("edge_id") or "")
                u = edge_id_to_unit.get(eid) or {}
                if u.get("thread_vtid") is not None and str(
                    u.get("thread_vtid")
                ) == str(preferred_thread_vtid):
                    aligned.append((et, edge))
            if aligned:
                best = min(aligned, key=lambda p: abs(p[0] - ts_unix))
                return best[1], abs(best[0] - ts_unix), True

        best = min(in_window, key=lambda p: abs(p[0] - ts_unix))
        return best[1], abs(best[0] - ts_unix), False

    by_edge: dict[str, list[dict[str, Any]]] = defaultdict(list)
    strength_counter: Counter[str] = Counter()
    reason_counter: Counter[str] = Counter()
    tier_counter: Counter[str] = Counter()
    total_records = 0
    unmatched_empty_message = 0
    unmatched_no_evt_container = 0
    unmatched_no_target = 0
    dropped_by_cap = 0

    for model_rec in applog_model_records:
        total_records += 1
        event_key = str(model_rec.get("event_key") or "")
        ctx_rec = ctx_by_event_key.get(event_key, {}) if event_key else {}
        wec = write_ctx_by_event_key.get(event_key, {}) if event_key else {}

        matched_evt_num: Optional[int] = None
        for src in (model_rec, ctx_rec, wec):
            raw = src.get("matched_evt_num")
            if raw is not None:
                try:
                    matched_evt_num = int(raw)
                    break
                except (TypeError, ValueError):
                    pass
        # Model context stores target_id like "sysdig:23"; fall back to that.
        if matched_evt_num is None:
            tid = model_rec.get("target_id") or ctx_rec.get("target_id")
            if isinstance(tid, str) and tid.startswith("sysdig:"):
                try:
                    matched_evt_num = int(tid.split(":", 1)[1])
                except (TypeError, ValueError):
                    pass

        ts_unix: Optional[float] = None
        raw_ts = model_rec.get("timestamp") or ctx_rec.get("timestamp") or wec.get("write_timestamp")
        if raw_ts is not None:
            try:
                ts_unix = float(raw_ts)
            except (TypeError, ValueError):
                ts_unix = None

        container_id: Optional[str] = None
        for src, key in (
            (ctx_rec, "container_id"),
            (wec, "write_container_id"),
            (model_rec, "container_id"),
        ):
            val = src.get(key) if isinstance(src, dict) else None
            if val:
                container_id = str(val)
                break

        # SecLog-style writer identity: look up (container, thread_vtid,
        # unit_id) of the write() syscall that produced this applog line.
        # thread_vtid was shown by diagnostics to have 100% coverage on
        # write events and backbone edges across the four benchmark
        # scenarios; unit_id is partial. Both are real structural
        # evidence — they never touch the log ``message``.
        write_unit_info: dict[str, Any] = {}
        if matched_evt_num is not None:
            write_unit_info = evt_to_unit.get(int(matched_evt_num)) or {}
        write_thread_vtid = write_unit_info.get("thread_vtid")
        if write_thread_vtid is not None:
            write_thread_vtid = str(write_thread_vtid)
            if write_thread_vtid.lower() == "null" or write_thread_vtid == "":
                write_thread_vtid = None
        write_unit_id = write_unit_info.get("unit_id")
        if write_unit_id is not None:
            write_unit_id = str(write_unit_id)
            if write_unit_id.lower() == "null" or write_unit_id == "":
                write_unit_id = None
        if container_id is None:
            wu_cid = write_unit_info.get("container_id")
            if wu_cid:
                container_id = str(wu_cid)

        # Classify semantic early so HV-only channels (relaxed time
        # window, reserved cap slot) can activate in the tier cascade
        # below. This never touches ``message`` itself; it's a pure
        # read-only classifier over (message, log_style, source_file).
        pre_message = model_rec.get("normalized_message") or model_rec.get("raw_message") or ""
        pre_message_str = str(pre_message).strip()
        if not pre_message_str:
            unmatched_empty_message += 1
            continue
        pre_source_file = model_rec.get("source_file") or ctx_rec.get("source_file")
        pre_log_style = model_rec.get("log_style")
        pre_semantic_type = _classify_applog_semantic(
            pre_message_str, pre_log_style, pre_source_file
        )
        is_hv_semantic = pre_semantic_type in APPLOG_HIGH_VALUE_SEMANTICS

        target_edge_id: Optional[str] = None
        target_edge: Optional[dict[str, Any]] = None
        target_sec_delta: Optional[float] = None
        target_picked_via_thread_align: bool = False
        attach_reason: Optional[str] = None
        attach_strength: Optional[str] = None
        attach_basis: dict[str, Any] = {}

        # Tier 1: direct evt_num -> spine edge
        if matched_evt_num is not None and matched_evt_num in spine_by_evt:
            edge = spine_by_evt[matched_evt_num]
            target_edge_id = str(edge.get("edge_id") or "")
            if target_edge_id:
                target_edge = edge
                attach_reason = "matched_evt_num_direct"
                attach_strength = "strong"
                attach_basis = {
                    "matched_evt_num": matched_evt_num,
                    "backbone_relation": edge.get("relation"),
                    "backbone_seq": edge.get("seq"),
                }
                tier_counter["tier1_direct_evt_num"] += 1

        # Tier 2: write sysdig:{evt_num} -> anchor_index -> edge
        if target_edge_id is None and matched_evt_num is not None:
            sk = f"sysdig:{matched_evt_num}"
            aeid = sysdig_to_edge_id.get(sk)
            if aeid:
                target_edge_id = aeid
                target_edge = spine_by_edge_id.get(aeid)
                attach_reason = "matched_write_evt_via_anchor_index"
                attach_strength = "strong"
                attach_basis = {
                    "matched_evt_num": matched_evt_num,
                    "anchor_index_source_event_key": sk,
                }
                tier_counter["tier2_anchor_index"] += 1

        # Tier 3: request-scoped proximity (NET_*) in same container.
        # When the writer's thread_vtid is known we prefer a
        # thread-aligned candidate over the nearest-by-time candidate
        # (SecLog: writer/thread identity beats time proximity).
        if (
            target_edge_id is None
            and container_id is not None
            and ts_unix is not None
        ):
            edge, delta, picked_via_thread = _nearest_edge_in_container(
                container_id, ts_unix,
                APPLOG_REQUEST_WINDOW_SEC,
                APPLOG_REQUEST_RELATIONS,
                preferred_thread_vtid=write_thread_vtid,
            )
            if edge is not None:
                target_edge_id = str(edge.get("edge_id") or "")
                if target_edge_id:
                    target_edge = edge
                    target_sec_delta = delta
                    target_picked_via_thread_align = picked_via_thread
                    attach_reason = "request_scoped_container_time_near"
                    attach_strength = "medium"
                    attach_basis = {
                        "container_id": container_id,
                        "sec_delta": round(delta or 0.0, 6),
                        "backbone_relation": edge.get("relation"),
                        "backbone_seq": edge.get("seq"),
                        "window_sec": APPLOG_REQUEST_WINDOW_SEC,
                    }
                    tier_counter["tier3_request_scoped"] += 1

        # Tier 4: container proximity any edge (weak). Same preference:
        # thread-aligned candidates win over nearest-time when present.
        if (
            target_edge_id is None
            and container_id is not None
            and ts_unix is not None
        ):
            edge, delta, picked_via_thread = _nearest_edge_in_container(
                container_id, ts_unix,
                APPLOG_CONTAINER_WINDOW_SEC,
                None,
                preferred_thread_vtid=write_thread_vtid,
            )
            if edge is not None:
                target_edge_id = str(edge.get("edge_id") or "")
                if target_edge_id:
                    target_edge = edge
                    target_sec_delta = delta
                    target_picked_via_thread_align = picked_via_thread
                    attach_reason = "container_time_near_fallback"
                    attach_strength = "weak"
                    attach_basis = {
                        "container_id": container_id,
                        "sec_delta": round(delta or 0.0, 6),
                        "backbone_relation": edge.get("relation"),
                        "backbone_seq": edge.get("seq"),
                        "window_sec": APPLOG_CONTAINER_WINDOW_SEC,
                    }
                    tier_counter["tier4_container_time_near"] += 1

        # Tier 5 (HV-only): when normal 5s container window misses, do
        # one more try with a relaxed 10s window — but only for
        # high-value semantics (error/warn/db/auth). This recovers
        # records like the 03:30:05 geoserver ERROR that sat 5.4s from
        # the nearest NET_ACCEPT. Strength stays "weak" to mark the
        # widened evidence; writer-identity promotion downstream can
        # still lift it if thread/unit/proc aligns.
        if (
            target_edge_id is None
            and is_hv_semantic
            and container_id is not None
            and ts_unix is not None
        ):
            edge, delta, picked_via_thread = _nearest_edge_in_container(
                container_id, ts_unix,
                APPLOG_HV_CONTAINER_WINDOW_SEC,
                None,
                preferred_thread_vtid=write_thread_vtid,
            )
            if edge is not None:
                candidate_eid = str(edge.get("edge_id") or "")
                if candidate_eid:
                    target_edge_id = candidate_eid
                    target_edge = edge
                    target_sec_delta = delta
                    target_picked_via_thread_align = picked_via_thread
                    attach_reason = "hv_container_time_near_relaxed"
                    attach_strength = "weak"
                    attach_basis = {
                        "container_id": container_id,
                        "sec_delta": round(delta or 0.0, 6),
                        "backbone_relation": edge.get("relation"),
                        "backbone_seq": edge.get("seq"),
                        "window_sec": APPLOG_HV_CONTAINER_WINDOW_SEC,
                        "hv_window_relaxation": True,
                    }
                    tier_counter["tier5_hv_relaxed"] += 1

        if target_edge_id is None:
            if ts_unix is None or container_id is None:
                unmatched_no_evt_container += 1
            else:
                unmatched_no_target += 1
            continue

        # Reuse the pre-classified values from the early semantic pass.
        # ``message`` is taken from ``applog_model_context.normalized_message``
        # / ``raw_message`` — both are verbatim applog content produced by
        # replay_index's _extract_model_messages over raw/applog/*.log and
        # never carry attach evidence.
        message_str = pre_message_str
        if not message_str:
            unmatched_empty_message += 1
            continue

        service_name = (
            model_rec.get("service_name")
            or ctx_rec.get("service_name")
            or wec.get("service_name")
        )
        source_file = pre_source_file
        line_no = ctx_rec.get("line_no") or wec.get("line_no")
        log_style = pre_log_style
        write_proc_pid = wec.get("write_proc_pid") if wec else None

        semantic_type = pre_semantic_type

        # ── SecLog-style writer/thread identity alignment ──
        # Evidence is purely structural: we compare the (container,
        # thread_vtid, unit_id, proc_pid) of the write() syscall that
        # produced the applog line against the same fields on the
        # chosen backbone edge, as recorded in ``unit_event_index``.
        # Nothing here ever touches the applog ``message``; these are
        # only used for attach/selection/promotion decisions.
        edge_attrs = (target_edge.get("attrs") or {}) if target_edge else {}
        edge_unit_info = (
            edge_id_to_unit.get(target_edge_id or "") or {}
            if target_edge_id else {}
        )
        edge_thread_vtid = edge_unit_info.get("thread_vtid")
        if edge_thread_vtid is not None:
            edge_thread_vtid = str(edge_thread_vtid)
            if edge_thread_vtid.lower() == "null" or edge_thread_vtid == "":
                edge_thread_vtid = None
        edge_unit_id = edge_unit_info.get("unit_id")
        if edge_unit_id is not None:
            edge_unit_id = str(edge_unit_id)
            if edge_unit_id.lower() == "null" or edge_unit_id == "":
                edge_unit_id = None
        edge_container = (
            edge_unit_info.get("container_id")
            or edge_attrs.get("container_id")
        )
        edge_container = str(edge_container) if edge_container else None

        container_match_ok = (
            container_id is None
            or edge_container is None
            or container_id == edge_container
        )

        unit_aligned = bool(
            write_unit_id
            and edge_unit_id
            and write_unit_id == edge_unit_id
            and container_match_ok
        )
        thread_aligned = bool(
            write_thread_vtid
            and edge_thread_vtid
            and write_thread_vtid == edge_thread_vtid
            and container_match_ok
        )

        proc_aligned = False
        if target_edge is not None and write_proc_pid is not None:
            edge_pid = edge_attrs.get("proc_pid")
            if (
                edge_pid is not None
                and str(edge_pid) == str(write_proc_pid)
                and container_match_ok
            ):
                proc_aligned = True

        semantic_high_value = semantic_type in APPLOG_HIGH_VALUE_SEMANTICS

        promoted_from: Optional[str] = None
        promotion_reasons: list[str] = []

        # Promotion cascade — writer identity first (SecLog precedence):
        # unit_aligned  → strong (strongest; request/task-level match)
        # thread_aligned → weak→medium_high, medium/medium_high→strong
        # proc_aligned   → medium promotion only (weakest of the three)
        # semantic_high_value is an additive promotion when identity is
        # missing, to salvage high-value errors/auth/db records that
        # only have time proximity.
        def _level(s: Optional[str]) -> int:
            return APPLOG_STRENGTH_ORDER.get(s or "", 99)

        def _max_strength(a: str, b: str) -> str:
            return a if _level(a) <= _level(b) else b

        start_strength = attach_strength

        if unit_aligned:
            new_strength = "strong"
            if _level(new_strength) < _level(attach_strength):
                promoted_from = attach_strength
                attach_strength = new_strength
            promotion_reasons.append("writer_unit_aligned")
        elif thread_aligned:
            if attach_strength == "weak":
                promoted_from = "weak"
                attach_strength = "medium_high"
            elif attach_strength in ("medium", "medium_high"):
                if attach_strength != "strong":
                    promoted_from = attach_strength
                    attach_strength = "strong"
            promotion_reasons.append("writer_thread_aligned")
        elif proc_aligned:
            if attach_strength == "weak":
                promoted_from = "weak"
                attach_strength = "medium_high"
                promotion_reasons.append("writer_proc_aligned")
            elif attach_strength == "medium":
                promoted_from = "medium"
                attach_strength = "medium_high"
                promotion_reasons.append("writer_proc_aligned")

        # Semantic high-value promotion only if identity did not already
        # lift the record to (medium_high|strong). This keeps semantic
        # as a fallback boost, not a primary signal.
        if _level(attach_strength) >= _level("medium"):
            if semantic_high_value:
                if (
                    attach_strength == "weak"
                    and target_sec_delta is not None
                    and target_sec_delta <= APPLOG_CONTAINER_WINDOW_SEC
                ):
                    promoted_from = promoted_from or "weak"
                    attach_strength = "medium"
                    promotion_reasons.append("semantic_high_value_from_weak")
                elif (
                    attach_strength == "medium"
                    and target_sec_delta is not None
                    and target_sec_delta <= APPLOG_REQUEST_WINDOW_SEC
                ):
                    promoted_from = promoted_from or "medium"
                    attach_strength = "medium_high"
                    promotion_reasons.append("semantic_high_value_in_request_window")

        # Attach-basis bookkeeping — all evidence here is structural and
        # auditable. Never mixed into ``message``.
        attach_basis["semantic_type"] = semantic_type
        if write_thread_vtid is not None:
            attach_basis["write_thread_vtid"] = write_thread_vtid
        if write_unit_id is not None:
            attach_basis["write_unit_id"] = write_unit_id
        if thread_aligned:
            attach_basis["thread_aligned"] = True
        if unit_aligned:
            attach_basis["unit_aligned"] = True
        if proc_aligned:
            attach_basis["proc_pid_matched"] = True
        if target_picked_via_thread_align:
            attach_basis["target_selected_by_thread_align"] = True
        if promoted_from and promoted_from != attach_strength:
            attach_basis["strength_promoted_from"] = promoted_from
        if promotion_reasons:
            # dedupe while preserving order
            seen_r: set[str] = set()
            unique: list[str] = []
            for r in promotion_reasons:
                if r not in seen_r:
                    seen_r.add(r)
                    unique.append(r)
            attach_basis["promotion_reasons"] = unique

        # Write-gated strong/weak provenance transparency (2026-04-20+):
        # propagate the decision level/reason from applog_model_context into
        # multisource_context.applog[*].attach_basis so downstream consumers
        # can tell why a row is (or isn't) `is_attack_related`. Older sidecars
        # won't have these fields — `.get()` returns None in that case and
        # nothing is written, keeping the dataset shape backwards compatible.
        _ar_level = model_rec.get("attack_related_level")
        _ar_reason = model_rec.get("attack_related_reason")
        if _ar_level in ("strong", "weak", "none"):
            attach_basis["attack_related_level"] = _ar_level
        if isinstance(_ar_reason, str) and _ar_reason:
            attach_basis["attack_related_reason"] = _ar_reason

        _ = _max_strength  # silence unused-tag (kept for future use)
        _ = start_strength

        entry: dict[str, Any] = {
            "context_id": model_rec.get("context_id") or ctx_rec.get("context_id"),
            "event_key": event_key or None,
            "source_file": source_file,
            "line_no": line_no,
            "timestamp": ts_unix,
            "service_name": service_name,
            "container_id": container_id,
            "log_style": log_style,
            "semantic_type": semantic_type,
            "message": message_str,
            "malicious": model_rec.get("malicious"),
            "is_attack_related": model_rec.get("is_attack_related"),
            "attach_to_backbone_edge_id": target_edge_id,
            "attach_reason": attach_reason,
            "attach_strength": attach_strength,
            "attach_basis": attach_basis,
        }
        if matched_evt_num is not None:
            entry["matched_evt_num"] = matched_evt_num
        if wec:
            for key_src, key_dst in (
                ("write_proc_pid", "write_proc_pid"),
                ("write_fd_name", "write_fd_name"),
                ("write_source_file", "write_source_file"),
                ("write_event_key", "write_event_key"),
            ):
                val = wec.get(key_src)
                if val is not None:
                    entry[key_dst] = val
        # Track normalised pattern for weak dedup below.
        entry["_pattern"] = _normalize_applog_pattern(message_str)

        by_edge[target_edge_id].append(entry)
        strength_counter[attach_strength] += 1
        reason_counter[attach_reason] += 1

    # Quality-aware post-processing per backbone edge:
    #   1) drop startup_runtime noise that only got "weak" on time;
    #   2) collapse duplicate weak entries by normalised pattern
    #      (keeps 1 representative, records duplicate_count);
    #   3) cap the number of weak entries per edge — HV semantic
    #      (error/warn/db/auth) is EXEMPT from this cap so errors on a
    #      quiet edge don't lose to access-log noise;
    #   4) apply the global per-edge cap, sorted so HV semantic is a
    #      tie-break winner within each strength level, and with an
    #      explicit HV reserved-slot safeguard.
    dropped_startup_weak = 0
    dropped_weak_duplicates = 0
    dropped_weak_by_cap = 0
    hv_saved_from_weak_cap = 0
    hv_saved_by_reserved_slot = 0
    hv_saved_by_window_relaxation = int(tier_counter.get("tier5_hv_relaxed", 0))

    def _is_hv(rec: dict[str, Any]) -> bool:
        return rec.get("semantic_type") in APPLOG_HIGH_VALUE_SEMANTICS

    for edge_id in list(by_edge.keys()):
        items = by_edge[edge_id]

        # 1) drop startup_runtime noise at weak strength only
        survivors: list[dict[str, Any]] = []
        for r in items:
            if (
                r.get("attach_strength") == "weak"
                and r.get("semantic_type") == "startup_runtime"
            ):
                dropped_startup_weak += 1
                continue
            survivors.append(r)

        # 2) dedup weak entries by normalised pattern inside this edge.
        # HV semantics are never folded: each error/warn/db/auth line
        # is kept as its own record even when the normalised pattern
        # collides with an earlier one.
        weak_seen_pattern: dict[str, dict[str, Any]] = {}
        filtered: list[dict[str, Any]] = []
        for r in survivors:
            if r.get("attach_strength") == "weak" and not _is_hv(r):
                pat = r.get("_pattern") or ""
                if pat in weak_seen_pattern:
                    rep = weak_seen_pattern[pat]
                    rep["duplicate_count"] = int(rep.get("duplicate_count", 1)) + 1
                    dropped_weak_duplicates += 1
                    continue
                r["duplicate_count"] = 1
                weak_seen_pattern[pat] = r
                filtered.append(r)
            else:
                filtered.append(r)

        # 3) cap weak entries per edge — but only on non-HV weaks.
        non_weak = [r for r in filtered if r.get("attach_strength") != "weak"]
        weak_hv = [r for r in filtered if r.get("attach_strength") == "weak" and _is_hv(r)]
        weak_nonhv = [r for r in filtered if r.get("attach_strength") == "weak" and not _is_hv(r)]
        weak_nonhv.sort(
            key=lambda r: (
                (r.get("attach_basis") or {}).get("sec_delta")
                if (r.get("attach_basis") or {}).get("sec_delta") is not None
                else float("inf"),
                r.get("timestamp") if r.get("timestamp") is not None else float("inf"),
                r.get("event_key") or "",
            )
        )
        if len(weak_nonhv) > APPLOG_WEAK_PER_EDGE_CAP:
            dropped_weak_by_cap += len(weak_nonhv) - APPLOG_WEAK_PER_EDGE_CAP
            weak_nonhv = weak_nonhv[:APPLOG_WEAK_PER_EDGE_CAP]
        # HV weaks were kept intact regardless of weak cap.
        if weak_hv:
            hv_saved_from_weak_cap += len(weak_hv)
        filtered = non_weak + weak_hv + weak_nonhv

        # 4) final sort + global per-edge cap. HV semantic gets a
        # tie-break priority (sort secondary = 0 for HV, 1 otherwise)
        # so a cap fight never demotes an error/warn/db/auth line in
        # favour of access-log duplicates at the same strength.
        filtered.sort(
            key=lambda r: (
                APPLOG_STRENGTH_ORDER.get(r.get("attach_strength"), 99),
                0 if _is_hv(r) else 1,
                r.get("timestamp") if r.get("timestamp") is not None else float("inf"),
                r.get("event_key") or "",
            )
        )
        if len(filtered) > per_edge_cap:
            # HV reserved slots: the first APPLOG_HV_RESERVED_PER_EDGE
            # HV records survive even if they would otherwise be pushed
            # out of per_edge_cap. Since HV is the tie-break winner
            # within each strength class, this only actually triggers
            # when a very busy edge has >cap entries of stronger
            # non-HV records + HV records at a weaker class.
            kept_ids: set[int] = set()
            kept: list[dict[str, Any]] = []
            hv_reserved_used = 0
            # first pass: fill slots in priority order, reserving HV.
            for r in filtered:
                if len(kept) < per_edge_cap - APPLOG_HV_RESERVED_PER_EDGE + hv_reserved_used:
                    kept.append(r)
                    kept_ids.add(id(r))
                    if _is_hv(r) and hv_reserved_used < APPLOG_HV_RESERVED_PER_EDGE:
                        hv_reserved_used += 1
                else:
                    break
            # second pass: if reserved slots unused, put HV records there
            if hv_reserved_used < APPLOG_HV_RESERVED_PER_EDGE:
                for r in filtered:
                    if id(r) in kept_ids:
                        continue
                    if not _is_hv(r):
                        continue
                    if len(kept) >= per_edge_cap:
                        break
                    kept.append(r)
                    kept_ids.add(id(r))
                    hv_reserved_used += 1
                    hv_saved_by_reserved_slot += 1
            # fill remaining slots with the next non-reserved items
            if len(kept) < per_edge_cap:
                for r in filtered:
                    if id(r) in kept_ids:
                        continue
                    if len(kept) >= per_edge_cap:
                        break
                    kept.append(r)
                    kept_ids.add(id(r))
            dropped_by_cap += len(filtered) - len(kept)
            filtered = kept

        # Strip internal "_pattern" key; duplicate_count only kept when >1.
        for r in filtered:
            r.pop("_pattern", None)
            if int(r.get("duplicate_count", 1)) <= 1:
                r.pop("duplicate_count", None)

        by_edge[edge_id] = filtered

    mapped_edge_count = len(by_edge)
    emitted_total = sum(len(v) for v in by_edge.values())

    # Recompute final strength distribution after post-processing.
    final_strength_counter: Counter[str] = Counter()
    final_semantic_counter: Counter[str] = Counter()
    final_alignment_counter: Counter[str] = Counter()
    # Write-gated provenance distribution (propagated from applog_model_context
    # via attach_basis.attack_related_level / attack_related_reason).
    final_attack_level_counter: Counter[str] = Counter()
    final_attack_reason_counter: Counter[str] = Counter()
    final_is_attack_related_counter: Counter[str] = Counter()
    hv_emitted = 0
    hv_promoted = 0
    for items in by_edge.values():
        for r in items:
            final_strength_counter[r.get("attach_strength", "unknown")] += 1
            final_semantic_counter[r.get("semantic_type", "unknown")] += 1
            basis = r.get("attach_basis") or {}
            if basis.get("unit_aligned"):
                final_alignment_counter["unit_aligned"] += 1
            if basis.get("thread_aligned"):
                final_alignment_counter["thread_aligned"] += 1
            if basis.get("proc_pid_matched"):
                final_alignment_counter["proc_aligned"] += 1
            if basis.get("target_selected_by_thread_align"):
                final_alignment_counter["target_picked_by_thread_align"] += 1
            if r.get("semantic_type") in APPLOG_HIGH_VALUE_SEMANTICS:
                hv_emitted += 1
                if basis.get("strength_promoted_from"):
                    hv_promoted += 1
            _ar_lv = basis.get("attack_related_level") or "unknown"
            final_attack_level_counter[_ar_lv] += 1
            _ar_rs = basis.get("attack_related_reason") or "unknown"
            final_attack_reason_counter[_ar_rs] += 1
            _iar = r.get("is_attack_related")
            if _iar is True:
                final_is_attack_related_counter["true"] += 1
            elif _iar is False:
                final_is_attack_related_counter["false"] += 1
            else:
                final_is_attack_related_counter["null"] += 1

    stats = {
        "total_records": int(total_records),
        "emitted_total": int(emitted_total),
        "mapped_backbone_target_count": int(mapped_edge_count),
        "unmatched_no_evt_container": int(unmatched_no_evt_container),
        "unmatched_no_target": int(unmatched_no_target),
        "empty_message_records": int(unmatched_empty_message),
        "dropped_by_cap": int(dropped_by_cap),
        "dropped_startup_weak": int(dropped_startup_weak),
        "dropped_weak_duplicates": int(dropped_weak_duplicates),
        "dropped_weak_by_cap": int(dropped_weak_by_cap),
        "per_edge_cap": int(per_edge_cap),
        "per_edge_weak_cap": int(APPLOG_WEAK_PER_EDGE_CAP),
        "request_window_sec": APPLOG_REQUEST_WINDOW_SEC,
        "container_window_sec": APPLOG_CONTAINER_WINDOW_SEC,
        "tier_breakdown": dict(sorted(tier_counter.items())),
        # Pre-postprocess strength snapshot (what tiers alone produced).
        "attach_strength_pre_postprocess": dict(sorted(strength_counter.items())),
        # Final strength snapshot (post semantic promotion / dedup / caps).
        "attach_strength_breakdown": dict(sorted(final_strength_counter.items())),
        "attach_reason_breakdown": dict(sorted(reason_counter.items())),
        "semantic_type_breakdown": dict(sorted(final_semantic_counter.items())),
        "writer_alignment_breakdown": dict(sorted(final_alignment_counter.items())),
        "high_value_semantic_emitted": int(hv_emitted),
        "high_value_semantic_promoted": int(hv_promoted),
        "high_value_semantic_saved_from_weak_cap": int(hv_saved_from_weak_cap),
        "high_value_semantic_saved_by_reserved_slot": int(hv_saved_by_reserved_slot),
        "high_value_semantic_saved_by_window_relaxation": int(hv_saved_by_window_relaxation),
        "hv_container_window_sec": APPLOG_HV_CONTAINER_WINDOW_SEC,
        "hv_reserved_per_edge": APPLOG_HV_RESERVED_PER_EDGE,
        # Write-gated provenance distribution (new in 2026-04-20+):
        "attack_related_level_breakdown": dict(sorted(final_attack_level_counter.items())),
        "attack_related_reason_breakdown": dict(sorted(final_attack_reason_counter.items())),
        "is_attack_related_breakdown": dict(sorted(final_is_attack_related_counter.items())),
    }
    return dict(by_edge), stats


# ─────────────────────────────────────────────────────────────────────────
# Traffic writeback (SecLog-style: 4-tuple + NAT + fd lifecycle)
# ─────────────────────────────────────────────────────────────────────────

TRAFFIC_WRITEBACK_PER_EDGE_CAP = 12
TRAFFIC_REPS_PER_FLOW_CAP = 2
TRAFFIC_LIFECYCLE_SOFT_WINDOW_SEC = 30.0

# ── Traffic malicious / attack-related label patterns ───────────────────
# Strong patterns: pcap file name explicitly marks "this capture is the
# attacker / attack side". Only these set ``malicious=true`` on traffic
# entries. Anything else stays ``malicious=None`` (unknown) unless it
# attaches to a malicious backbone edge (→ ``is_attack_related=True``).
# The patterns are matched case-insensitively against the traffic
# anchor's ``packet_ref.source_file`` / ``pcap_file``.
_TRAFFIC_PCAP_MALICIOUS_TOKENS = (
    "bot-attack", "bot_attack",
    "attacker", "attack-",
    "malicious", "evil-",
    "exploit-",
)

# Map backbone NET_* relations to a coarse semantic_type for the flow.
_TRAFFIC_RELATION_SEMANTIC = {
    "NET_ACCEPT": "inbound_request_flow",
    "NET_CONNECT": "outbound_call_flow",
    "NET_RECV": "inbound_data_flow",
    "NET_SEND": "response_data_flow",
}


_TRAFFIC_FD_NAME_PATTERN = re.compile(
    r"^\s*([^\s:]+):(\d+)\s*->\s*([^\s:]+):(\d+)\s*$"
)


def _traffic_conn_key(
    proto: Any, sip: Any, sport: Any, dip: Any, dport: Any
) -> Optional[str]:
    p = str(proto or "").lower().strip()
    if not p:
        return None
    try:
        sp = int(sport)
        dp = int(dport)
    except (TypeError, ValueError):
        return None
    if not sip or not dip:
        return None
    return f"{p}|{sip}:{sp}|{dip}:{dp}"


def _traffic_parse_fd_name(fd_name: Any) -> Optional[tuple[str, int, str, int]]:
    if not fd_name:
        return None
    m = _TRAFFIC_FD_NAME_PATTERN.match(str(fd_name))
    if m is None:
        return None
    try:
        return (m.group(1), int(m.group(2)), m.group(3), int(m.group(4)))
    except (TypeError, ValueError):
        return None


def _traffic_load_jsonl(path: Optional[Path]) -> list[dict[str, Any]]:
    if path is None or not path.exists():
        return []
    rows: list[dict[str, Any]] = []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return rows


def _build_nat_alias_index(
    conntrack_rows: list[dict[str, Any]],
) -> dict[str, set[str]]:
    """Return conn_key -> set of aliased conn_keys (forward + reverse)."""
    alias: dict[str, set[str]] = defaultdict(set)
    for row in conntrack_rows:
        proto = row.get("transport_proto")
        orig = _traffic_conn_key(
            proto,
            row.get("orig_src_ip"), row.get("orig_src_port"),
            row.get("orig_dst_ip"), row.get("orig_dst_port"),
        )
        orig_rev = _traffic_conn_key(
            proto,
            row.get("orig_dst_ip"), row.get("orig_dst_port"),
            row.get("orig_src_ip"), row.get("orig_src_port"),
        )
        reply = _traffic_conn_key(
            proto,
            row.get("reply_src_ip"), row.get("reply_src_port"),
            row.get("reply_dst_ip"), row.get("reply_dst_port"),
        )
        reply_rev = _traffic_conn_key(
            proto,
            row.get("reply_dst_ip"), row.get("reply_dst_port"),
            row.get("reply_src_ip"), row.get("reply_src_port"),
        )
        keys = {k for k in (orig, orig_rev, reply, reply_rev) if k}
        for k in keys:
            alias[k].update(keys - {k})
    return alias


def _reattach_traffic_to_spine(
    traffic_anchor_records: list[dict[str, Any]],
    traffic_candidate_records: list[dict[str, Any]],
    conntrack_records: list[dict[str, Any]],
    spine: list[dict[str, Any]],
    per_edge_cap: int = TRAFFIC_WRITEBACK_PER_EDGE_CAP,
) -> tuple[dict[str, list[dict[str, Any]]], dict[str, Any]]:
    """SecLog-style traffic → backbone edge attach.

    Strategy (priority order; no pure time-proximity is used as a
    primary channel):

      1. **Four-tuple direct match** — packet's normalized
         ``proto|src:sp|dst:dp`` matches the connection described by a
         backbone NET_* edge's ``fd_name`` (``sip:sport->dip:dport``)
         within the same container. Strong.
      2. **Four-tuple NAT-aliased match** — packet's key doesn't match
         directly, but is aliased via ``conntrack_nat_index`` to a key
         that does match a backbone NET_* edge. Strong.
      3. **Connection lifecycle batch matching** — packet's
         ``node_anchor.graph_node_id`` ties it to the same
         (container, connection) as a backbone NET_* edge we already
         confirmed in (1)/(2); packet gets attached to the backbone
         edge nearest in time on that connection. Medium.
      4. *No* pure "container + time near" fallback here. SecLog's
         core value is the 4-tuple + fd lifecycle binding; widening to
         time-only would dilute the core signal and clash with the
         project guidance of not making time-proximity the primary
         channel.

    Per-backbone-edge cap: keep the ``per_edge_cap`` packets nearest in
    time to the backbone edge (so the emitted records are
    representative of that edge's activity).
    """
    # ── Index backbone NET_* edges by connection key ──
    net_edge_by_conn: dict[str, list[dict[str, Any]]] = defaultdict(list)
    all_net_edges: list[dict[str, Any]] = []
    for edge in spine:
        rel = str(edge.get("relation") or "").upper()
        if not rel.startswith("NET_"):
            continue
        attrs = edge.get("attrs") or {}
        tup = _traffic_parse_fd_name(attrs.get("fd_name"))
        if tup is None:
            continue
        # We default to tcp because backbone fd_name doesn't carry proto;
        # conntrack / traffic anchor carry proto explicitly so mismatches
        # on udp won't join. Backbone NET_* is effectively always tcp in
        # real scenarios; udp audit events are rare here.
        key = _traffic_conn_key("tcp", tup[0], tup[1], tup[2], tup[3])
        if key is None:
            continue
        enriched = {
            "edge": edge,
            "conn_key": key,
            "ts_unix": _parse_spine_ts_unix(attrs.get("timestamp")),
            "relation": rel,
        }
        net_edge_by_conn[key].append(enriched)
        all_net_edges.append(enriched)

    # Sort edges on each connection by evt_num for lifecycle ordering.
    for entries in net_edge_by_conn.values():
        entries.sort(
            key=lambda e: (
                int((e["edge"].get("attrs") or {}).get("evt_num") or 0),
                int(e["edge"].get("seq") or 0),
            )
        )

    # ── NAT alias index (bidirectional) ──
    nat_alias = _build_nat_alias_index(conntrack_records)

    # ── Join anchor + candidate by traffic_event_key for richer ctx ──
    cand_by_event_key: dict[str, dict[str, Any]] = {}
    for row in traffic_candidate_records:
        k = row.get("traffic_event_key")
        if k:
            cand_by_event_key[str(k)] = row

    by_edge: dict[str, list[dict[str, Any]]] = defaultdict(list)
    tier_counter: Counter[str] = Counter()
    strength_counter: Counter[str] = Counter()
    reason_counter: Counter[str] = Counter()
    semantic_counter: Counter[str] = Counter()

    total_records = 0
    anchor_missing_4tuple = 0
    anchor_without_conn_match = 0
    anchor_container_mismatch = 0
    emitted_before_cap = 0
    dropped_by_cap = 0

    for anchor in traffic_anchor_records:
        if str(anchor.get("record_type") or "") != "anchor":
            continue
        total_records += 1
        packet_ref = anchor.get("packet_ref") or {}
        pf = anchor.get("packet_feature") or {}
        na = anchor.get("node_anchor") or {}

        proto = pf.get("l4_proto")
        sip = pf.get("src_ip")
        sport = pf.get("src_port")
        dip = pf.get("dst_ip")
        dport = pf.get("dst_port")
        pkt_conn_key = _traffic_conn_key(proto, sip, sport, dip, dport)
        pkt_conn_key_rev = _traffic_conn_key(proto, dip, dport, sip, sport)
        if pkt_conn_key is None and pkt_conn_key_rev is None:
            anchor_missing_4tuple += 1
            continue

        container_id = na.get("container_id")
        ts_unix: Optional[float] = None
        raw_ts = pf.get("timestamp_epoch")
        if raw_ts is not None:
            try:
                ts_unix = float(raw_ts)
            except (TypeError, ValueError):
                ts_unix = None

        # Expand candidate keys with NAT aliases.
        candidate_keys: set[str] = set()
        for k in (pkt_conn_key, pkt_conn_key_rev):
            if k is not None:
                candidate_keys.add(k)
                candidate_keys.update(nat_alias.get(k, set()))

        # Collect backbone NET_* edges for any of these keys, same container.
        direct_hit_keys: set[str] = set()
        nat_hit_keys: set[str] = set()
        candidate_edge_entries: list[dict[str, Any]] = []
        for k in candidate_keys:
            entries = net_edge_by_conn.get(k, [])
            if not entries:
                continue
            # Direct hit: key equals the raw packet conn_key (no NAT)
            direct_hit = k in {pkt_conn_key, pkt_conn_key_rev}
            if direct_hit:
                direct_hit_keys.add(k)
            else:
                nat_hit_keys.add(k)
            for entry in entries:
                edge_attrs = entry["edge"].get("attrs") or {}
                if container_id and edge_attrs.get("container_id"):
                    if str(edge_attrs.get("container_id")) != str(container_id):
                        continue
                candidate_edge_entries.append(entry)

        if not candidate_edge_entries:
            if candidate_keys and not any(
                net_edge_by_conn.get(k) for k in candidate_keys
            ):
                anchor_without_conn_match += 1
            else:
                anchor_container_mismatch += 1
            continue

        # Attach to the nearest-in-time backbone NET_* edge on this conn.
        def _delta_key(entry: dict[str, Any]) -> float:
            et = entry.get("ts_unix")
            if et is None or ts_unix is None:
                return float("inf")
            return abs(float(et) - float(ts_unix))

        candidate_edge_entries.sort(key=_delta_key)
        chosen_entry = candidate_edge_entries[0]
        chosen_edge = chosen_entry["edge"]
        sec_delta = _delta_key(chosen_entry)
        if sec_delta == float("inf"):
            sec_delta = None

        if direct_hit_keys:
            attach_reason = "four_tuple_direct"
            attach_strength = "strong"
            tier = "tier1_four_tuple_direct"
        elif nat_hit_keys:
            attach_reason = "four_tuple_nat_aliased"
            attach_strength = "strong"
            tier = "tier2_four_tuple_nat"
        else:
            # Shouldn't happen given earlier filter; treat as medium fd-lifecycle.
            attach_reason = "connection_lifecycle_batch"
            attach_strength = "medium"
            tier = "tier3_fd_lifecycle"

        # Soft lifecycle window: packets >30s from any NET_* edge of this
        # connection are unlikely to represent the same activity bucket.
        if (
            sec_delta is not None
            and sec_delta > TRAFFIC_LIFECYCLE_SOFT_WINDOW_SEC
            and attach_strength == "strong"
        ):
            # Demote to medium when the packet is way outside any NET_*
            # edge's temporal vicinity — the fd may have been reused.
            attach_strength = "medium"
            attach_reason = "four_tuple_lifecycle_far"
            tier = "tier3_fd_lifecycle"

        relation = str(chosen_entry.get("relation") or "").upper()
        semantic_type = _TRAFFIC_RELATION_SEMANTIC.get(
            relation, "generic_net_context"
        )

        cand = cand_by_event_key.get(str(packet_ref.get("event_key") or ""))
        normalized_conn_key = None
        nat_alias_used = False
        network_node_id = None
        service_name = na.get("service_name") if isinstance(na, dict) else None
        if cand:
            normalized_conn_key = cand.get("normalized_conn_key")
            nat_alias_used = bool(cand.get("nat_alias_used"))
            network_node_id = cand.get("network_node_id")
            service_name = cand.get("service_name") or service_name

        attach_basis: dict[str, Any] = {
            "normalized_conn_key": normalized_conn_key
                or pkt_conn_key
                or pkt_conn_key_rev,
            "nat_alias_used": nat_alias_used,
            "backbone_relation": chosen_edge.get("relation"),
            "backbone_seq": chosen_edge.get("seq"),
            "sec_delta": (round(sec_delta, 6) if sec_delta is not None else None),
            "network_node_id": network_node_id,
            "fd_num": na.get("fd_num"),
            "proc_vpid": na.get("proc_vpid"),
        }
        if nat_hit_keys and not direct_hit_keys:
            attach_basis["nat_aliased_from"] = sorted(nat_hit_keys)[0]

        # ── Traffic labeling (malicious / is_attack_related) ──
        # Two independent signals, both structural, neither invented.
        # Signal A (strong, → malicious=True):
        #     pcap filename contains a known attack-side token
        #     (bot-attack, attacker, attack-, malicious, evil-, exploit-).
        #     Missing → stays malicious=None (unknown), not False.
        # Signal B (derived, → is_attack_related=True):
        #     the attached backbone edge itself is malicious. This is
        #     honest: being on a malicious-audit edge doesn't prove the
        #     packet is the attack payload, but the packet *is*
        #     attack-related context.
        pcap_label = None
        src_file_lower = str(packet_ref.get("source_file") or "").lower()
        pcap_file_lower = str(packet_ref.get("pcap_file") or "").lower()
        label_candidate = src_file_lower + "|" + pcap_file_lower
        for token in _TRAFFIC_PCAP_MALICIOUS_TOKENS:
            if token in label_candidate:
                pcap_label = token
                break
        pkt_malicious = True if pcap_label is not None else None
        backbone_edge_malicious = bool(
            (chosen_edge.get("attrs") or {}).get("malicious")
        )
        is_attack_related = bool(pkt_malicious) or backbone_edge_malicious

        attack_label_source = None
        if pkt_malicious:
            attack_label_source = f"pcap_filename:{pcap_label}"
        elif backbone_edge_malicious:
            attack_label_source = "attached_backbone_edge_malicious"

        entry_out: dict[str, Any] = {
            "event_key": packet_ref.get("event_key"),
            "source_file": packet_ref.get("source_file"),
            "line_no": packet_ref.get("line_no"),
            "frame_number": packet_ref.get("frame_number"),
            "timestamp": ts_unix,
            "l4_proto": proto,
            "src_ip": sip,
            "src_port": sport,
            "dst_ip": dip,
            "dst_port": dport,
            "normalized_conn_key": normalized_conn_key
                or pkt_conn_key
                or pkt_conn_key_rev,
            "container_id": container_id,
            "service_name": service_name,
            "semantic_type": semantic_type,
            "malicious": pkt_malicious,
            "is_attack_related": is_attack_related,
            "attack_label_source": attack_label_source,
            "attach_to_backbone_edge_id": str(chosen_edge.get("edge_id") or ""),
            "attach_reason": attach_reason,
            "attach_strength": attach_strength,
            "attach_basis": attach_basis,
        }

        by_edge[str(chosen_edge.get("edge_id") or "")].append(entry_out)
        tier_counter[tier] += 1
        strength_counter[attach_strength] += 1
        reason_counter[attach_reason] += 1
        semantic_counter[semantic_type] += 1
        emitted_before_cap += 1

    # ── Flow-summary post-processing ──
    # Replace the raw per-packet per-edge cap with a DEPCOMM-style
    # aggregation: group packets on each backbone edge by
    # ``normalized_conn_key`` and emit one ``flow_summary`` record per
    # flow plus a few representative packets. This preserves the
    # attack-explanatory value of connection-level evidence (packet
    # counts, duration, direction balance, NAT/anchor provenance)
    # without letting a single chatty backbone edge inflate the main
    # sample with dozens of near-duplicate packet rows — the pattern
    # we observed for NET_RECV/NET_SEND edges on long-lived flows.
    #
    # Guarantees:
    #   * Every flow is always represented by one ``flow_summary``.
    #   * Representative packets (up to ``TRAFFIC_REPS_PER_FLOW_CAP``
    #     per flow) are real packet records picked as "first seen" +
    #     "nearest to backbone edge timestamp"; they are never
    #     synthesised.
    #   * Summaries and reps never carry attach evidence in the
    #     payload text — all attach provenance stays in
    #     ``attach_basis``.
    STRENGTH_ORDER = {"strong": 0, "medium": 1, "weak": 2}
    summary_total = 0
    reps_total = 0
    suppressed_packets_total = 0
    reps_dropped_by_cap = 0

    # Backbone edge timestamp lookup for rep-selection.
    edge_ts_by_id: dict[str, Optional[float]] = {}
    for entry in all_net_edges:
        eid = str(entry["edge"].get("edge_id") or "")
        edge_ts_by_id[eid] = entry.get("ts_unix")

    for edge_id in list(by_edge.keys()):
        raw_items = by_edge[edge_id]
        if not raw_items:
            continue
        edge_ts = edge_ts_by_id.get(edge_id)

        # Group packets by normalized_conn_key (fallback: (src_ip, src_port, dst_ip, dst_port))
        by_conn: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for p in raw_items:
            ck = p.get("normalized_conn_key") or (
                f"{p.get('l4_proto')}|{p.get('src_ip')}:{p.get('src_port')}|"
                f"{p.get('dst_ip')}:{p.get('dst_port')}"
            )
            by_conn[str(ck)].append(p)

        flows_built: list[tuple[dict[str, Any], list[dict[str, Any]], int, str]] = []
        for ck, pkts in by_conn.items():
            pkts.sort(
                key=lambda r: (
                    r.get("timestamp")
                    if r.get("timestamp") is not None
                    else float("inf"),
                    r.get("frame_number")
                    if r.get("frame_number") is not None
                    else 0,
                )
            )
            first_ts = pkts[0].get("timestamp")
            last_ts = pkts[-1].get("timestamp")

            # Forward / reverse counts relative to the connection key
            # direction (proto|src:sp|dst:dp).
            fwd_src: Optional[str] = None
            fwd_sp: Optional[int] = None
            try:
                parts = ck.split("|")
                if len(parts) == 3:
                    hp = parts[1].rsplit(":", 1)
                    if len(hp) == 2:
                        fwd_src = hp[0]
                        fwd_sp = int(hp[1])
            except (TypeError, ValueError):
                fwd_src = None
                fwd_sp = None
            fwd_cnt = 0
            rev_cnt = 0
            for p in pkts:
                if (
                    fwd_src is not None
                    and fwd_sp is not None
                    and p.get("src_ip") == fwd_src
                    and p.get("src_port") == fwd_sp
                ):
                    fwd_cnt += 1
                else:
                    rev_cnt += 1

            # Pick up to TRAFFIC_REPS_PER_FLOW_CAP representative real
            # packets: the first-seen + the nearest-to-edge (if
            # distinct). Single-packet flows skip reps (summary already
            # carries all information).
            reps: list[dict[str, Any]] = []
            if len(pkts) >= 2:
                first_rep = pkts[0]
                reps.append(first_rep)
                if edge_ts is not None:
                    def _to_edge_delta(p: dict[str, Any]) -> float:
                        ts = p.get("timestamp")
                        if ts is None:
                            return float("inf")
                        return abs(float(ts) - float(edge_ts))
                    nearest = min(pkts, key=_to_edge_delta)
                    if (
                        nearest.get("event_key")
                        and nearest.get("event_key") != first_rep.get("event_key")
                    ):
                        reps.append(nearest)
                reps = reps[:TRAFFIC_REPS_PER_FLOW_CAP]
            suppressed = len(pkts) - len(reps)

            canon = pkts[0]
            canon_basis = canon.get("attach_basis") or {}
            network_node_ids = sorted({
                (p.get("attach_basis") or {}).get("network_node_id")
                for p in pkts
                if (p.get("attach_basis") or {}).get("network_node_id")
            })
            # ── Roll up malicious / is_attack_related on the flow.
            # malicious=True if ANY packet in the flow has malicious=True
            # (i.e. any packet is from an attack-labeled pcap).
            # is_attack_related=True if any packet is marked as such
            # (either pcap-label or attached backbone malicious).
            # This is a real aggregate: we don't guess.
            flow_malicious_any = any(p.get("malicious") is True for p in pkts)
            flow_attack_related = flow_malicious_any or any(
                p.get("is_attack_related") is True for p in pkts
            )
            # Preserve a diversity signal: how the label was reached.
            label_sources = sorted({
                p.get("attack_label_source") for p in pkts
                if p.get("attack_label_source")
            })

            summary = {
                "summary_type": "flow_summary",
                "normalized_conn_key": ck,
                "l4_proto": canon.get("l4_proto"),
                "src_ip": canon.get("src_ip"),
                "src_port": canon.get("src_port"),
                "dst_ip": canon.get("dst_ip"),
                "dst_port": canon.get("dst_port"),
                "container_id": canon.get("container_id"),
                "service_name": canon.get("service_name"),
                "first_seen_ts": first_ts,
                "last_seen_ts": last_ts,
                "packet_count": len(pkts),
                "direction_counts": {"forward": fwd_cnt, "reverse": rev_cnt},
                "frame_range": [
                    canon.get("frame_number"),
                    pkts[-1].get("frame_number"),
                ],
                "nat_alias_used": bool(canon_basis.get("nat_alias_used")),
                "network_node_ids": network_node_ids,
                "semantic_type": canon.get("semantic_type"),
                # Flow-level labels (aggregated from real packets).
                "malicious": True if flow_malicious_any else None,
                "is_attack_related": flow_attack_related,
                "attack_label_source": label_sources or None,
                "attach_to_backbone_edge_id": canon.get("attach_to_backbone_edge_id"),
                "attach_reason": canon.get("attach_reason"),
                "attach_strength": canon.get("attach_strength"),
                "attach_basis": canon.get("attach_basis"),
                "representative_packet_count": len(reps),
                "suppressed_packet_count": suppressed,
            }
            flows_built.append(
                (summary, reps, len(pkts), canon.get("attach_strength") or "weak")
            )
            suppressed_packets_total += suppressed

        # Sort flows by (strength, -packet_count) so stronger / busier
        # flows win if we have to drop reps to stay under per-edge cap.
        flows_built.sort(
            key=lambda f: (STRENGTH_ORDER.get(f[3], 99), -f[2])
        )

        out: list[dict[str, Any]] = []
        # 1) Always keep every flow_summary — never drop a summary.
        for summary, _reps, _cnt, _str in flows_built:
            out.append(summary)
            summary_total += 1
        # 2) Add representative packets in flow priority order, up to cap.
        for summary, reps, _cnt, _str in flows_built:
            for r in reps:
                if len(out) >= per_edge_cap:
                    reps_dropped_by_cap += 1
                    continue
                rep_entry = dict(r)
                rep_entry["summary_type"] = "representative_packet"
                out.append(rep_entry)
                reps_total += 1

        by_edge[edge_id] = out

    mapped_edge_count = len(by_edge)
    emitted_total = sum(len(v) for v in by_edge.values())
    # Backward-compatible total drop counter (packets not kept as reps).
    dropped_by_cap = suppressed_packets_total + reps_dropped_by_cap

    # Final label roll-up for stats. Only count real entries; flow
    # summaries are counted once, representative packets once each.
    flow_malicious_true = 0
    flow_attack_related_true = 0
    rep_malicious_true = 0
    rep_attack_related_true = 0
    label_source_counter: Counter[str] = Counter()
    for items in by_edge.values():
        for r in items:
            if r.get("summary_type") == "flow_summary":
                if r.get("malicious") is True:
                    flow_malicious_true += 1
                if r.get("is_attack_related") is True:
                    flow_attack_related_true += 1
                for src in (r.get("attack_label_source") or []):
                    label_source_counter[str(src)] += 1
            elif r.get("summary_type") == "representative_packet":
                if r.get("malicious") is True:
                    rep_malicious_true += 1
                if r.get("is_attack_related") is True:
                    rep_attack_related_true += 1
                src = r.get("attack_label_source")
                if src:
                    label_source_counter[str(src)] += 1

    stats = {
        "total_anchor_records": int(total_records),
        "anchor_missing_4tuple": int(anchor_missing_4tuple),
        "anchor_without_conn_match": int(anchor_without_conn_match),
        "anchor_container_mismatch": int(anchor_container_mismatch),
        "emitted_before_cap": int(emitted_before_cap),
        "emitted_total": int(emitted_total),
        "mapped_backbone_target_count": int(mapped_edge_count),
        "dropped_by_cap": int(dropped_by_cap),
        "per_edge_cap": int(per_edge_cap),
        "reps_per_flow_cap": int(TRAFFIC_REPS_PER_FLOW_CAP),
        "tier_breakdown": dict(sorted(tier_counter.items())),
        "attach_strength_breakdown": dict(sorted(strength_counter.items())),
        "attach_reason_breakdown": dict(sorted(reason_counter.items())),
        "semantic_type_breakdown": dict(sorted(semantic_counter.items())),
        "backbone_net_edge_count": int(len(all_net_edges)),
        "backbone_net_connection_count": int(len(net_edge_by_conn)),
        "conntrack_rows_loaded": int(len(conntrack_records)),
        "traffic_candidate_rows_loaded": int(len(traffic_candidate_records)),
        # Flow-summary specific metrics:
        "flow_summary_count": int(summary_total),
        "representative_packet_count": int(reps_total),
        "suppressed_packet_count": int(suppressed_packets_total),
        "reps_dropped_by_cap": int(reps_dropped_by_cap),
        # Labeling metrics:
        "flow_malicious_true": int(flow_malicious_true),
        "flow_is_attack_related_true": int(flow_attack_related_true),
        "rep_malicious_true": int(rep_malicious_true),
        "rep_is_attack_related_true": int(rep_attack_related_true),
        "attack_label_source_counter": dict(sorted(label_source_counter.items())),
    }
    return dict(by_edge), stats


def _build_backbone_applog_map(
    sidecar_records: list[dict[str, Any]],
    allowed_backbone_edge_ids: Optional[set[str]] = None,
    evidence_alignment_lookup: Optional[dict[str, set[str]]] = None,
) -> tuple[dict[str, list[dict[str, Any]]], dict[str, int]]:
    """Build a conservative applog writeback map keyed by backbone edge_id."""
    by_target: dict[str, list[dict[str, Any]]] = defaultdict(list)
    total_records = 0
    direct_backbone_records = 0
    proxy_records = 0
    other_unmapped_records = 0
    unresolved_target_id_records = 0
    empty_message_records = 0
    evidence_unaligned_records = 0

    keep_fields = [
        "context_id",
        "event_key",
        "timestamp",
        "service_name",
        "source_file",
        "log_style",
        "target_id",
        "target_kind",
        "attach_strength",
        "malicious",
        "is_attack_related",
    ]

    for rec in sidecar_records:
        total_records += 1
        target_kind = rec.get("target_kind")
        target_id = rec.get("target_id")

        if target_kind != "backbone_edge" or not target_id:
            if target_kind == "sysdig_event_index_entry":
                proxy_records += 1
            else:
                other_unmapped_records += 1
            continue

        target_id_str = str(target_id)
        if allowed_backbone_edge_ids is not None and target_id_str not in allowed_backbone_edge_ids:
            unresolved_target_id_records += 1
            continue

        if evidence_alignment_lookup is not None:
            aligned = False
            event_key = rec.get("event_key")
            if event_key not in (None, "") and str(event_key) in evidence_alignment_lookup.get("event_keys", set()):
                aligned = True

            context_id = rec.get("context_id")
            if not aligned and context_id not in (None, "") and str(context_id) in evidence_alignment_lookup.get("context_ids", set()):
                aligned = True

            if not aligned:
                evidence_unaligned_records += 1
                continue

        light = {field: rec.get(field) for field in keep_fields}
        message = rec.get("normalized_message") or rec.get("raw_message") or ""
        if not str(message).strip():
            empty_message_records += 1
            continue
        light["message"] = message
        by_target[target_id_str].append(light)
        direct_backbone_records += 1

    for target_id in by_target:
        by_target[target_id].sort(
            key=lambda r: (
                r.get("timestamp") if r.get("timestamp") is not None else float("inf"),
                r.get("event_key") or "",
            )
        )

    stats = {
        "total_records": total_records,
        "direct_backbone_records": direct_backbone_records,
        "proxy_records": proxy_records,
        "other_unmapped_records": other_unmapped_records,
        "unresolved_target_id_records": unresolved_target_id_records,
        "empty_message_records": empty_message_records,
        "evidence_unaligned_records": evidence_unaligned_records,
        "dropped_records_total": total_records - direct_backbone_records,
        "evidence_gate_enabled": 1 if evidence_alignment_lookup is not None else 0,
        "mapped_backbone_target_count": len(by_target),
    }
    return by_target, stats


# ─────────────────────────────────────────────────────────────────────────
# Main build
# ─────────────────────────────────────────────────────────────────────────

def build_dataset(
    backbone: dict[str, Any],
    context_edges: list[dict[str, Any]],
    necessary_ctx_by_eid: Optional[dict[str, list[dict[str, Any]]]] = None,
    necessary_ctx_stats: Optional[Counter] = None,
    necessary_window: int = DEFAULT_NECESSARY_WINDOW,
    stage_residual_view: Optional[dict[str, Any]] = None,
    edge_applog_context_view: Optional[dict[str, Any]] = None,
    applog_by_backbone_edge: Optional[dict[str, list[dict[str, Any]]]] = None,
    traffic_by_backbone_edge: Optional[dict[str, list[dict[str, Any]]]] = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    edge_sequence = backbone["edge_sequence"]
    scenario_id = backbone.get("scenario_id")
    chain_id = backbone.get("chain_id", "chain_unknown")

    ctx_by_eid: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for ctx in context_edges:
        eid = ctx.get("attach_to_backbone_edge_id")
        if eid:
            ctx_by_eid[eid].append(ctx)

    if necessary_ctx_by_eid:
        for eid, items in necessary_ctx_by_eid.items():
            ctx_by_eid[eid].extend(items)

    for items in ctx_by_eid.values():
        items.sort(key=lambda c: (
            STRENGTH_ORDER.get(c.get("attach_strength", "weak"), 99),
            -(c.get("link_features") or {}).get("score", 0.0),
        ))

    spine: list[dict[str, Any]] = []
    meta_context_entries: list[dict[str, Any]] = []

    pos_counter: Counter = Counter()
    role_counter: Counter = Counter()
    tier_counter: Counter = Counter()
    strength_counter: Counter = Counter()
    necessary_evt_type_counter: Counter = Counter()
    necessary_backbone_relation_counter: Counter = Counter()
    total_context = 0
    total_malicious_ctx = 0
    total_necessary_ctx = 0
    edges_with_ctx = 0

    all_evt_nums: list[int] = []
    all_timestamps: list[str] = []
    progress = ProgressLogger(
        stage="build_behavior_chain_instances_v0",
        substep="build_dataset_spine",
        total=len(edge_sequence),
        every=5000,
        percent_step=10.0,
        min_interval_s=15.0,
        prefix="[chain_dataset_v2][progress]",
    )

    for processed, edge in enumerate(edge_sequence, 1):
        attrs = edge.get("attrs") or {}
        spine_evt_num: Optional[int] = None
        try:
            spine_evt_num = int(attrs.get("evt_num"))
        except (TypeError, ValueError):
            pass
        spine_ts = attrs.get("timestamp")

        if spine_evt_num is not None:
            all_evt_nums.append(spine_evt_num)
        if spine_ts:
            all_timestamps.append(str(spine_ts))

        raw_ctxs = ctx_by_eid.get(edge.get("edge_id"), [])
        audit_context: list[dict[str, Any]] = []

        for ctx in raw_ctxs:
            position = _determine_position(ctx, spine_evt_num, spine_ts)
            role = _determine_role(position, ctx)
            event = _extract_event(ctx)

            ctx_entry: dict[str, Any] = {
                "position": position,
                "context_role": role,
                "source_tier": ctx.get("source_tier"),
                "record_mode": ctx.get("record_mode"),
                "attach_to_backbone_edge_id": ctx.get(
                    "attach_to_backbone_edge_id"
                ),
                "attach_reason": ctx.get("attach_reason"),
                "attach_strength": ctx.get("attach_strength"),
                "is_malicious": bool(ctx.get("is_malicious")),
                "event": event,
            }
            if ctx.get("is_necessary_context"):
                ctx_entry["is_necessary_context"] = True
            if ctx.get("explanatory_channel"):
                ctx_entry["explanatory_channel"] = True
            slim_lf = _slim_link_features(ctx.get("link_features"))
            if slim_lf:
                ctx_entry["link_features"] = slim_lf
            audit_context.append(ctx_entry)

            pos_counter[position] += 1
            role_counter[role] += 1
            tier_counter[ctx.get("source_tier", "unknown")] += 1
            strength_counter[ctx.get("attach_strength", "unknown")] += 1
            total_context += 1
            if ctx.get("is_necessary_context"):
                total_necessary_ctx += 1
                raw_evt_type = str((event.get("attrs") or {}).get("raw_evt_type") or "").lower()
                if raw_evt_type:
                    necessary_evt_type_counter[raw_evt_type] += 1
                relation = str(edge.get("relation") or "").upper()
                if relation:
                    necessary_backbone_relation_counter[relation] += 1
            else:
                total_malicious_ctx += 1

            cr_attrs = (ctx.get("context_record") or {}).get("attrs") or {}
            c_en = cr_attrs.get("evt_num")
            try:
                all_evt_nums.append(int(c_en))
            except (TypeError, ValueError):
                pass
            c_ts = cr_attrs.get("timestamp")
            if c_ts is not None:
                all_timestamps.append(str(c_ts))

            meta_context_entries.append(_build_context_meta_entry(ctx))

        if audit_context:
            edges_with_ctx += 1
        if processed % 5000 == 0:
            progress.maybe_log(
                processed,
                force=True,
                context_total=total_context,
                edges_with_context=edges_with_ctx,
            )

        spine.append({
            "seq": edge.get("seq"),
            "subject": edge.get("subject"),
            "relation": edge.get("relation"),
            "object": edge.get("object"),
            "attrs": _slim_spine_attrs(attrs),
            "audit_context": audit_context,
            "multisource_context": {
                "traffic": list(
                    (traffic_by_backbone_edge or {}).get(edge.get("edge_id"), [])
                ),
                "applog": list(
                    (applog_by_backbone_edge or {}).get(edge.get("edge_id"), [])
                ),
            },
        })

    progress.maybe_log(
        len(edge_sequence),
        force=True,
        context_total=total_context,
        edges_with_context=edges_with_ctx,
    )

    stage_segments = build_stage_segments(spine)
    substage_segments, substage_stats = build_substage_segments(
        spine, stage_segments,
    )
    backbone_expression_clarity = (
        (backbone.get("chain_summary") or {}).get("expression_clarity")
        if isinstance(backbone.get("chain_summary"), dict)
        else None
    )
    if not isinstance(backbone_expression_clarity, dict):
        backbone_expression_clarity = {}
    backbone_context_dependency = _build_backbone_context_dependency_proxy(
        spine,
        ctx_by_eid,
        backbone_expression_clarity,
    )
    semantic_readiness = _build_semantic_readiness_assessment(
        backbone_expression_clarity,
        backbone_context_dependency,
    )

    all_timestamps.sort()

    main = {
        "schema_version": SCHEMA_VERSION,
        "scenario_id": scenario_id,
        "chain_id": chain_id,
        "spine": spine,
        "stage_segments": stage_segments,
        "substage_segments": substage_segments,
    }

    meta = {
        "schema_version": META_SCHEMA_VERSION,
        "scenario_id": scenario_id,
        "chain_id": chain_id,
        "backbone_ref": {
            "chain_id": chain_id,
            "scenario_id": scenario_id,
            "backbone_edge_count": backbone.get("chain_summary", {}).get(
                "edge_count", len(edge_sequence)
            ),
        },
        "time_span": {
            "start_evt_num": min(all_evt_nums) if all_evt_nums else None,
            "end_evt_num": max(all_evt_nums) if all_evt_nums else None,
            "start_timestamp": all_timestamps[0] if all_timestamps else None,
            "end_timestamp": all_timestamps[-1] if all_timestamps else None,
        },
        "instance_summary": {
            "spine_edge_count": len(spine),
            "context_edge_count": total_context,
            "malicious_context_count": total_malicious_ctx,
            "necessary_nonmalicious_context_count": total_necessary_ctx,
            "spine_edges_with_context": edges_with_ctx,
            "spine_edges_without_context": len(spine) - edges_with_ctx,
            "average_context_per_attached_edge": (
                round(total_context / edges_with_ctx, 2)
                if edges_with_ctx else 0.0
            ),
            "position_breakdown": dict(sorted(pos_counter.items())),
            "context_role_breakdown": dict(sorted(role_counter.items())),
            "source_tier_breakdown": dict(sorted(tier_counter.items())),
            "attach_strength_breakdown": dict(sorted(strength_counter.items())),
            "necessary_nonmalicious_by_evt_type": dict(sorted(necessary_evt_type_counter.items())),
            "necessary_nonmalicious_by_backbone_relation": dict(sorted(necessary_backbone_relation_counter.items())),
            "stage_segment_count": len(stage_segments),
            "substage_segment_count": len(substage_segments),
            "backbone_context_dependency": backbone_context_dependency,
            "semantic_readiness": semantic_readiness,
        },
        "necessary_context_config": {
            "evt_num_window": necessary_window,
            "allowed_evt_types": sorted(NECESSARY_CONTEXT_EVT_TYPES),
            "loaded_evt_type_counts": (
                dict(sorted(necessary_ctx_stats.items()))
                if necessary_ctx_stats else {}
            ),
        },
        "stage_segmentation_notes": {
            "method": "two_layer_salience_based",
            "layer1": "runtime_setup / attack_relevant / post_action_result",
            "layer2": "within attack_relevant: sub-segmented by NET_ACCEPT "
                      "request cycles, labelled by dominant activity",
            "salience_signals": [
                "malicious spine edge",
                "malicious audit context attached",
                "high-salience relation (PROCESS_EXEC, FILE_WRITE, "
                "NET_CONNECT, NET_ACCEPT, NET_SEND, NET_RECV)",
            ],
        },
        "substage_segmentation_notes": substage_stats,
        "context_attach_details": meta_context_entries,
        "expression_clarity": {
            "backbone": backbone_expression_clarity,
            "backbone_context_dependency": backbone_context_dependency,
            "semantic_readiness": semantic_readiness,
        },
    }

    if stage_residual_view is not None:
        meta["stage_residual_view"] = stage_residual_view

    if edge_applog_context_view is not None:
        meta["edge_applog_context_view"] = edge_applog_context_view

    return main, meta


# ─────────────────────────────────────────────────────────────────────────
# Entry points
# ─────────────────────────────────────────────────────────────────────────

def run(
    backbone_path: Path,
    context_edges_path: Path,
    output_path: Path,
    meta_output_path: Path,
    backbone_warning_output_path: Optional[Path] = None,
    tiered_paths: Optional[list[tuple[str, Path]]] = None,
    necessary_window: int = DEFAULT_NECESSARY_WINDOW,
    stage_residual_path: Optional[Path] = None,
    refinement_residual_path: Optional[Path] = None,
    edge_applog_context_path: Optional[Path] = None,
    applog_model_context_path: Optional[Path] = None,
) -> int:
    emit_observation(
        "[chain_dataset_v2][stage]",
        stage="build_behavior_chain_instances_v0",
        status="start",
        input_path=backbone_path,
        output_path=output_path,
        backbone_exists=backbone_path.exists(),
        context_edges_exists=context_edges_path.exists(),
    )
    backbone = _read_json(backbone_path)
    if not isinstance(backbone.get("edge_sequence"), list):
        raise ValueError(f"invalid backbone: {backbone_path}")
    if backbone_warning_output_path is None:
        backbone_warning_output_path = backbone_path.parent / DEFAULT_BACKBONE_WARNING_OUTPUT.name

    summary_path = context_edges_path.parent / "behavior_context_summary.v0.json"
    context_mode_marker: Optional[dict[str, Any]] = None
    enrich_summary = _load_enrich_summary(summary_path)
    if enrich_summary is not None:
        enrich_status = str(enrich_summary.get("status") or "").strip()
        if enrich_status == "skipped":
            skip_reason = str(enrich_summary.get("skip_reason") or "").strip() or "status=skipped"
            raise ValueError(
                f"behavior_context_summary.v0.json marks enrich as skipped: {skip_reason}; "
                f"refusing to consume potential stale enrich context from {context_edges_path}. "
                f"summary={summary_path}"
            )

    if context_edges_path.exists():
        context_edges = list(_iter_jsonl(context_edges_path))
        if not context_edges:
            raise ValueError(
                f"behavior_context_edges.v0.jsonl exists but contains no valid records: "
                f"{context_edges_path}; dataset requires non-empty enrich context"
            )
    else:
        controlled_empty_ok, controlled_details = _classify_controlled_empty_context(
            enrich_summary
        )
        if controlled_empty_ok:
            context_edges = []
            context_mode_marker = {
                "mode": "no-unit-empty-context",
                "status": "degraded",
                "unit_mode": controlled_details.get("unit_mode"),
                "unit_mode_reason": controlled_details.get("unit_mode_reason"),
                "enrich_summary_path": str(summary_path),
                "behavior_context_edges_path": str(context_edges_path),
                "behavior_context_edges_state": controlled_details.get(
                    "behavior_context_edges_state"
                ),
            }
            print(
                "[chain_dataset_v2] controlled no-unit empty-context mode accepted; "
                f"unit_mode={controlled_details.get('unit_mode')} "
                f"reason={controlled_details.get('unit_mode_reason') or 'no_reason'}"
            )
        else:
            raise FileNotFoundError(
                f"behavior_context_edges.v0.jsonl not found: {context_edges_path}; "
                "dataset requires valid enrich output. controlled fallback requires "
                "summary(status=completed, unit_mode in {unit-absent,unit-unavailable}, "
                "output_state.behavior_context_edges=empty_not_written). "
                f"observed={controlled_details} summary={summary_path}"
            )

    nctx_by_eid: Optional[dict] = None
    nctx_stats: Optional[Counter] = None
    context_edges_already_include_necessary = any(
        bool(ctx.get("is_necessary_context")) for ctx in context_edges
    )
    if tiered_paths:
        if context_edges_already_include_necessary:
            print(
                "[chain_dataset_v2] enrich output already contains necessary context; "
                "skip dataset-side necessary-context injection"
            )
        else:
            nctx_by_eid, nctx_stats = _load_necessary_context(
                tiered_paths, backbone["edge_sequence"],
                window=necessary_window,
            )
            total_nctx = sum(len(v) for v in nctx_by_eid.values())
            print(f"[chain_dataset_v2] necessary context loaded: {total_nctx}")
            if nctx_stats:
                print(f"[chain_dataset_v2] necessary evt_types: {dict(nctx_stats)}")

    # Load stage residual sidecar (meta-layer supplemental view)
    stage_residual_view: Optional[dict[str, Any]] = None
    sidecar_parse_stats: dict[str, Any] = {}
    refinement_residual_view: Optional[dict[str, Any]] = None
    refinement_residual_parse_stats: dict[str, Any] = {}
    stage_segments_for_view = []   # built below after build_stage_segments
    substage_segments_for_view = []  # built below after build_substage_segments
    edge_applog_context_view: Optional[dict[str, Any]] = None
    edge_applog_parse_stats: dict[str, Any] = {}
    edge_applog_records: list[dict[str, Any]] = []
    applog_model_records: list[dict[str, Any]] = []
    applog_model_parse_stats: dict[str, Any] = {}
    applog_by_backbone_edge: Optional[dict[str, list[dict[str, Any]]]] = None
    applog_writeback_stats: dict[str, int] = {}
    evidence_alignment_lookup: Optional[dict[str, set[str]]] = None
    evidence_alignment_stats: dict[str, int] = {}

    allowed_backbone_edge_ids: set[str] = set()
    for edge in backbone.get("edge_sequence", []):
        edge_id = edge.get("edge_id") if isinstance(edge, dict) else None
        if edge_id not in (None, ""):
            allowed_backbone_edge_ids.add(str(edge_id))

    if stage_residual_path is not None:
        raw_records, sidecar_parse_stats = _load_stage_residual_sidecar(stage_residual_path)
        if sidecar_parse_stats.get("enabled"):
            print(f"[chain_dataset_v2] stage_residual loaded: "
                  f"{sidecar_parse_stats['total_loaded']} records "
                  f"from {stage_residual_path.name}")
        else:
            print(f"[chain_dataset_v2] stage_residual sidecar not found "
                  f"(non-fatal): {stage_residual_path.name}")

    if refinement_residual_path is not None:
        refinement_residual_records, refinement_residual_parse_stats = _load_refinement_residual_sidecar(
            refinement_residual_path
        )
        if refinement_residual_parse_stats.get("enabled"):
            scenario_dir = backbone_path.parent.parent
            refinement_residual_view = _build_refinement_residual_view(
                refinement_residual_records,
                refinement_residual_path,
                scenario_dir,
                backbone,
            )
            print(
                "[chain_dataset_v2] refinement_residual loaded: "
                f"{refinement_residual_parse_stats['total_loaded']} records "
                f"from {refinement_residual_path.name}"
            )
        else:
            print(
                "[chain_dataset_v2] refinement_residual sidecar not found "
                f"(non-fatal): {refinement_residual_path.name}"
            )

    if edge_applog_context_path is not None:
        edge_applog_records, edge_applog_parse_stats = _load_edge_applog_context_sidecar(
            edge_applog_context_path
        )
        if edge_applog_parse_stats.get("enabled"):
            evidence_alignment_lookup, evidence_alignment_stats = _build_applog_evidence_alignment_lookup(
                edge_applog_records
            )
            print(f"[chain_dataset_v2] edge_applog_context loaded: "
                  f"{edge_applog_parse_stats['total_loaded']} records "
                  f"from {edge_applog_context_path.name}")
        else:
            print(f"[chain_dataset_v2] edge_applog_context sidecar not found "
                  f"(non-fatal): {edge_applog_context_path.name}")

    if applog_model_context_path is not None:
        applog_model_records, applog_model_parse_stats = _load_applog_model_context_sidecar(
            applog_model_context_path
        )
        if applog_model_parse_stats.get("enabled"):
            print(f"[chain_dataset_v2] applog_model_context loaded: "
                  f"{applog_model_parse_stats['total_loaded']} records "
                  f"from {applog_model_context_path.name}")
            # --- Build-time re-attach pass (replaces the old
            # "target_kind==backbone_edge only" gate). analyze.py's
            # edge_applog_context_view almost always emits
            # target_kind=sysdig_event_index_entry because analyze runs
            # before backbone/enrich exist; we re-evaluate here using
            # the now-available spine + event_to_backbone_anchor_index
            # + write_event_context_index.
            anchor_index_path = (
                applog_model_context_path.parent
                / "event_to_backbone_anchor_index.v0.jsonl"
            )
            anchor_index_records = _load_anchor_index_sidecar(anchor_index_path)
            write_event_context_path = (
                applog_model_context_path.parent
                / "write_event_context_index.v0.jsonl"
            )
            write_event_context_records = _load_write_event_context_sidecar(
                write_event_context_path
            )
            # unit_event_index drives SecLog-style writer/thread
            # identity alignment — loaded here so the builder can join
            # it onto applog writes AND backbone edges.
            unit_event_index_path = (
                applog_model_context_path.parent
                / "unit_event_index.jsonl"
            )
            evt_to_unit_map = _load_unit_event_index(unit_event_index_path)
            applog_by_backbone_edge, applog_writeback_stats = _reattach_applog_to_spine(
                applog_model_records=applog_model_records,
                edge_applog_context_records=edge_applog_records,
                write_event_context_records=write_event_context_records,
                anchor_index_records=anchor_index_records,
                spine=list(backbone.get("edge_sequence") or []),
                evt_to_unit=evt_to_unit_map,
                per_edge_cap=APPLOG_WRITEBACK_PER_EDGE_CAP,
            )
            applog_writeback_stats["sidecar_loaded_count"] = int(
                applog_model_parse_stats["total_loaded"]
            )
            applog_writeback_stats["write_event_context_loaded_count"] = len(
                write_event_context_records
            )
            applog_writeback_stats["anchor_index_loaded_count"] = len(
                anchor_index_records
            )
            applog_writeback_stats["unit_event_index_loaded_count"] = len(
                evt_to_unit_map
            )
        else:
            print(f"[chain_dataset_v2] applog_model_context sidecar not found "
                  f"(non-fatal): {applog_model_context_path.name}")

    # --- SecLog-style traffic re-attach (4-tuple + NAT + fd lifecycle) ---
    # Runs at dataset-build time so it can use the final backbone spine
    # and the analyze-stage traffic sidecars that were previously
    # unused by the builder. The whole pass is optional; if any input
    # is missing we simply emit ``multisource_context.traffic = []``
    # just like before.
    traffic_by_backbone_edge: Optional[dict[str, list[dict[str, Any]]]] = None
    traffic_writeback_stats: dict[str, Any] = {}
    scenario_dir_for_traffic = backbone_path.parent.parent
    traffic_anchor_index_path = (
        scenario_dir_for_traffic / "index" / "traffic_node_anchor_index.v0.jsonl"
    )
    traffic_conntrack_index_path = (
        scenario_dir_for_traffic / "index" / "conntrack_nat_index.v0.jsonl"
    )
    traffic_candidate_index_path = (
        scenario_dir_for_traffic / CHAIN_DIR_NAME / "traffic_backbone_candidate_index.v0.jsonl"
    )
    traffic_anchor_records = _traffic_load_jsonl(traffic_anchor_index_path)
    traffic_conntrack_records = _traffic_load_jsonl(traffic_conntrack_index_path)
    traffic_candidate_records = _traffic_load_jsonl(traffic_candidate_index_path)
    if traffic_anchor_records:
        print(
            f"[chain_dataset_v2] traffic sidecars loaded: "
            f"anchor={len(traffic_anchor_records)} "
            f"conntrack={len(traffic_conntrack_records)} "
            f"candidates={len(traffic_candidate_records)} "
            f"from {traffic_anchor_index_path.name}"
        )
        traffic_by_backbone_edge, traffic_writeback_stats = _reattach_traffic_to_spine(
            traffic_anchor_records=traffic_anchor_records,
            traffic_candidate_records=traffic_candidate_records,
            conntrack_records=traffic_conntrack_records,
            spine=list(backbone.get("edge_sequence") or []),
            per_edge_cap=TRAFFIC_WRITEBACK_PER_EDGE_CAP,
        )
    else:
        print(
            "[chain_dataset_v2] traffic sidecars not available "
            f"(non-fatal): {traffic_anchor_index_path.name}"
        )

    main, meta = build_dataset(
        backbone, context_edges, nctx_by_eid, nctx_stats, necessary_window,
        stage_residual_view,
        edge_applog_context_view,
        applog_by_backbone_edge,
        traffic_by_backbone_edge,
    )

    if context_mode_marker is not None:
        main["context_input_mode"] = context_mode_marker
        meta["context_input_mode"] = context_mode_marker

    # Stage residual view needs the built stage/substage segments as context;
    # build them here using the same logic as inside build_dataset (after spine is built)
    if sidecar_parse_stats.get("enabled"):
        _spine = main["spine"]
        _stage_seg = build_stage_segments(_spine)
        _substage_seg, _ = build_substage_segments(_spine, _stage_seg)
        stage_residual_view = _build_stage_residual_view(
            raw_records, _substage_seg, _stage_seg,
        )
        sidecar_parse_stats["total_residual_records"] = stage_residual_view["total_residual_records"]
        sidecar_parse_stats["attached_target_count"] = len(stage_residual_view.get("by_target", {}))
        sidecar_parse_stats["mapped_residual_count"] = stage_residual_view["mapped_residual_count"]
        sidecar_parse_stats["unmapped_residual_count"] = stage_residual_view["unmapped_residual_count"]
        meta["stage_residual_view"] = stage_residual_view
        print(f"[chain_dataset_v2] stage_residual_view: "
              f"{stage_residual_view['mapped_residual_count']} mapped "
              f"to {len(stage_residual_view.get('by_target', {}))} targets, "
              f"{stage_residual_view['unmapped_residual_count']} unattached")

    if edge_applog_parse_stats.get("enabled"):
        scenario_dir = backbone_path.parent.parent
        edge_applog_context_view = _build_edge_applog_context_meta_view(
            edge_applog_records,
            edge_applog_context_path,
            scenario_dir,
        )
        meta["edge_applog_context_view"] = edge_applog_context_view
        print(f"[chain_dataset_v2] edge_applog_context_view: "
              f"{edge_applog_context_view['mapped_record_count']} mapped "
              f"to {len(edge_applog_context_view.get('by_target', {}))} targets, "
              f"{edge_applog_context_view['unmapped_record_count']} unattached")

    if refinement_residual_view is not None:
        meta["refinement_residual_view"] = refinement_residual_view
        meta["instance_summary"]["refinement_residual_count"] = int(
            refinement_residual_view.get("total_residual_records") or 0
        )
        meta["instance_summary"]["refinement_residual_dropped_edge_count"] = int(
            refinement_residual_view.get("total_dropped_edges") or 0
        )
        meta["instance_summary"]["refinement_residual_relation_family_counts"] = (
            refinement_residual_view.get("relation_family_counts") or {}
        )

    if applog_model_parse_stats.get("enabled"):
        meta["applog_writeback_stats"] = applog_writeback_stats
        if evidence_alignment_stats:
            meta["applog_evidence_alignment_stats"] = evidence_alignment_stats

    if traffic_writeback_stats:
        meta["traffic_writeback_stats"] = traffic_writeback_stats

    meta["semantic_narrative_summary"] = _build_semantic_narrative_summary(
        backbone=backbone,
        dataset_meta=meta,
    )

    backbone_warning_payload = _build_backbone_warning_payload(
        backbone=backbone,
        dataset_main=main,
        dataset_meta=meta,
        enrich_summary=enrich_summary,
        stage_residual_view=meta.get("stage_residual_view"),
    )
    main["backbone_broad_warning"] = {
        "warning_present": backbone_warning_payload.get("warning_present", False),
        "warning_codes": backbone_warning_payload.get("warning_codes", []),
    }
    meta["backbone_broad_warning"] = backbone_warning_payload

    _write_json(output_path, main)
    _write_json(meta_output_path, meta)
    _write_json(backbone_warning_output_path, backbone_warning_payload)

    s = meta["instance_summary"]
    print(f"[chain_dataset_v2] spine={s['spine_edge_count']} "
          f"context={s['context_edge_count']}")
    print(f"[chain_dataset_v2] malicious_ctx={s['malicious_context_count']} "
          f"necessary_ctx={s['necessary_nonmalicious_context_count']}")
    print(f"[chain_dataset_v2] with_ctx={s['spine_edges_with_context']} "
          f"without_ctx={s['spine_edges_without_context']}")
    print(f"[chain_dataset_v2] position={s['position_breakdown']}")
    print(f"[chain_dataset_v2] role={s['context_role_breakdown']}")
    print(f"[chain_dataset_v2] stages={s['stage_segment_count']} "
          f"substages={s['substage_segment_count']}")
    if applog_model_parse_stats.get("enabled"):
        print(
            "[chain_dataset_v2] applog_writeback: "
            f"total={applog_writeback_stats.get('total_records', 0)} "
            f"emitted={applog_writeback_stats.get('emitted_total', 0)} "
            f"spine_targets={applog_writeback_stats.get('mapped_backbone_target_count', 0)} "
            f"tiers={applog_writeback_stats.get('tier_breakdown', {})} "
            f"strengths={applog_writeback_stats.get('attach_strength_breakdown', {})}"
        )
        print(
            "[chain_dataset_v2] applog_writeback_quality: "
            f"semantic={applog_writeback_stats.get('semantic_type_breakdown', {})} "
            f"pre_postprocess_strengths={applog_writeback_stats.get('attach_strength_pre_postprocess', {})} "
            f"alignment={applog_writeback_stats.get('writer_alignment_breakdown', {})}"
        )
        print(
            "[chain_dataset_v2] applog_writeback_hv: "
            f"hv_emitted={applog_writeback_stats.get('high_value_semantic_emitted', 0)} "
            f"hv_promoted={applog_writeback_stats.get('high_value_semantic_promoted', 0)} "
            f"saved_from_weak_cap={applog_writeback_stats.get('high_value_semantic_saved_from_weak_cap', 0)} "
            f"saved_by_reserved_slot={applog_writeback_stats.get('high_value_semantic_saved_by_reserved_slot', 0)} "
            f"saved_by_window_relaxation={applog_writeback_stats.get('high_value_semantic_saved_by_window_relaxation', 0)}"
        )
        print(
            "[chain_dataset_v2] applog_writeback_provenance: "
            f"is_attack_related={applog_writeback_stats.get('is_attack_related_breakdown', {})} "
            f"level={applog_writeback_stats.get('attack_related_level_breakdown', {})} "
            f"reason={applog_writeback_stats.get('attack_related_reason_breakdown', {})}"
        )
        print(
            "[chain_dataset_v2] applog_writeback_dropped: "
            f"empty_message={applog_writeback_stats.get('empty_message_records', 0)} "
            f"no_evt_container={applog_writeback_stats.get('unmatched_no_evt_container', 0)} "
            f"no_target={applog_writeback_stats.get('unmatched_no_target', 0)} "
            f"startup_weak={applog_writeback_stats.get('dropped_startup_weak', 0)} "
            f"weak_dups={applog_writeback_stats.get('dropped_weak_duplicates', 0)} "
            f"weak_cap={applog_writeback_stats.get('dropped_weak_by_cap', 0)} "
            f"total_cap={applog_writeback_stats.get('dropped_by_cap', 0)} "
            f"(per_edge_cap={applog_writeback_stats.get('per_edge_cap', 0)} "
            f"per_edge_weak_cap={applog_writeback_stats.get('per_edge_weak_cap', 0)})"
        )
    if traffic_writeback_stats:
        print(
            "[chain_dataset_v2] traffic_writeback: "
            f"anchors={traffic_writeback_stats.get('total_anchor_records', 0)} "
            f"emitted={traffic_writeback_stats.get('emitted_total', 0)} "
            f"spine_targets={traffic_writeback_stats.get('mapped_backbone_target_count', 0)} "
            f"flows={traffic_writeback_stats.get('flow_summary_count', 0)} "
            f"reps={traffic_writeback_stats.get('representative_packet_count', 0)} "
            f"tiers={traffic_writeback_stats.get('tier_breakdown', {})} "
            f"strengths={traffic_writeback_stats.get('attach_strength_breakdown', {})}"
        )
        print(
            "[chain_dataset_v2] traffic_writeback_semantic: "
            f"{traffic_writeback_stats.get('semantic_type_breakdown', {})} "
            f"backbone_net_edges={traffic_writeback_stats.get('backbone_net_edge_count', 0)} "
            f"backbone_net_connections={traffic_writeback_stats.get('backbone_net_connection_count', 0)}"
        )
        print(
            "[chain_dataset_v2] traffic_writeback_labels: "
            f"flow_malicious={traffic_writeback_stats.get('flow_malicious_true', 0)} "
            f"flow_attack_related={traffic_writeback_stats.get('flow_is_attack_related_true', 0)} "
            f"rep_malicious={traffic_writeback_stats.get('rep_malicious_true', 0)} "
            f"rep_attack_related={traffic_writeback_stats.get('rep_is_attack_related_true', 0)} "
            f"sources={traffic_writeback_stats.get('attack_label_source_counter', {})}"
        )
        print(
            "[chain_dataset_v2] traffic_writeback_dropped: "
            f"no_4tuple={traffic_writeback_stats.get('anchor_missing_4tuple', 0)} "
            f"no_conn_match={traffic_writeback_stats.get('anchor_without_conn_match', 0)} "
            f"container_mismatch={traffic_writeback_stats.get('anchor_container_mismatch', 0)} "
            f"suppressed_packets={traffic_writeback_stats.get('suppressed_packet_count', 0)} "
            f"reps_dropped_by_cap={traffic_writeback_stats.get('reps_dropped_by_cap', 0)} "
            f"(per_edge_cap={traffic_writeback_stats.get('per_edge_cap', 0)} "
            f"reps_per_flow_cap={traffic_writeback_stats.get('reps_per_flow_cap', 0)})"
        )
    print(f"[chain_dataset_v2] main={output_path}")
    print(f"[chain_dataset_v2] meta={meta_output_path}")
    print(
        "[chain_dataset_v2] backbone_broad_warning="
        f"{backbone_warning_output_path} present={backbone_warning_payload.get('warning_present', False)} "
        f"codes={backbone_warning_payload.get('warning_codes', [])}"
    )
    emit_observation(
        "[chain_dataset_v2][stage]",
        stage="build_behavior_chain_instances_v0",
        status="done",
        input_path=backbone_path,
        output_path=output_path,
        backbone_edges=s["spine_edge_count"],
        context_edges=s["context_edge_count"],
        output_exists=output_path.exists(),
        meta_exists=meta_output_path.exists(),
    )
    return 0


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Build behavior chain dataset v2")
    p.add_argument("--scenario-dir", type=Path, default=SCENARIO_DIR)
    p.add_argument("--backbone", type=Path, default=DEFAULT_BACKBONE)
    p.add_argument("--context-edges", type=Path, default=DEFAULT_CONTEXT_EDGES)
    p.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    p.add_argument("--meta-output", type=Path, default=DEFAULT_META_OUTPUT)
    p.add_argument("--backbone-warning-output", type=Path, default=DEFAULT_BACKBONE_WARNING_OUTPUT)
    p.add_argument("--auxiliary", type=Path, default=None,
                   help="audit_triples.auxiliary.v1.jsonl")
    p.add_argument("--filtered", type=Path, default=None,
                   help="audit_triples.filtered.v1.jsonl")
    p.add_argument("--unknown", type=Path, default=None,
                   help="audit_triples.unknown.v1.jsonl")
    p.add_argument("--necessary-context-window", type=int,
                   default=DEFAULT_NECESSARY_WINDOW,
                   help="±evt_num window for necessary context (default 5)")
    p.add_argument("--stage-residual", type=Path, default=None,
                   help="behavior_context_stage_residual.v0.jsonl sidecar path")
    p.add_argument("--refinement-residual", type=Path, default=None,
                   help="backbone_refinement_residual.v0.jsonl sidecar path")
    p.add_argument("--edge-applog-context", type=Path, default=None,
                   help="index/edge_applog_context_view.v0.jsonl sidecar path")
    p.add_argument("--applog-model-context", type=Path, default=None,
                   help="index/applog_model_context.v0.jsonl sidecar path")
    return p.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)

    scenario_dir = args.scenario_dir
    backbone = args.backbone
    context_edges = args.context_edges
    output = args.output
    meta_output = args.meta_output
    backbone_warning_output = args.backbone_warning_output

    if scenario_dir != SCENARIO_DIR:
        derived = scenario_dir / CHAIN_DIR_NAME
        if backbone == DEFAULT_BACKBONE:
            backbone = derived / "backbone_chain.v1.json"
        if context_edges == DEFAULT_CONTEXT_EDGES:
            context_edges = derived / "behavior_context_edges.v0.jsonl"
        if output == DEFAULT_OUTPUT:
            output = derived / "behavior_chain_dataset.v2.json"
        if meta_output == DEFAULT_META_OUTPUT:
            meta_output = derived / "behavior_chain_dataset.v2.meta.json"
        if backbone_warning_output == DEFAULT_BACKBONE_WARNING_OUTPUT:
            backbone_warning_output = derived / "backbone_broad_warning.v0.json"
        if args.auxiliary is None:
            cand = derived / "audit_triples.auxiliary.v1.jsonl"
            if cand.exists():
                args.auxiliary = cand
        if args.filtered is None:
            cand = derived / "audit_triples.filtered.v1.jsonl"
            if cand.exists():
                args.filtered = cand
        if args.unknown is None:
            cand = derived / "audit_triples.unknown.v1.jsonl"
            if cand.exists():
                args.unknown = cand

    tiered_paths: list[tuple[str, Path]] = []
    if args.auxiliary:
        tiered_paths.append(("auxiliary", args.auxiliary))
    if args.filtered:
        tiered_paths.append(("filtered", args.filtered))
    if args.unknown:
        tiered_paths.append(("unknown", args.unknown))

    # Resolve stage_residual path
    stage_residual_path: Optional[Path] = args.stage_residual
    if stage_residual_path is None:
        derived = scenario_dir / CHAIN_DIR_NAME
        cand = derived / "behavior_context_stage_residual.v0.jsonl"
        if cand.exists():
            stage_residual_path = cand

    refinement_residual_path: Optional[Path] = args.refinement_residual
    if refinement_residual_path is None:
        derived = scenario_dir / CHAIN_DIR_NAME
        cand = derived / "backbone_refinement_residual.v0.jsonl"
        if cand.exists():
            refinement_residual_path = cand

    edge_applog_context_path: Optional[Path] = args.edge_applog_context
    if edge_applog_context_path is None:
        cand = scenario_dir / "index" / "edge_applog_context_view.v0.jsonl"
        if cand.exists():
            edge_applog_context_path = cand

    applog_model_context_path: Optional[Path] = args.applog_model_context
    if applog_model_context_path is None:
        cand = scenario_dir / "index" / "applog_model_context.v0.jsonl"
        if cand.exists():
            applog_model_context_path = cand

    return run(
        backbone_path=backbone,
        context_edges_path=context_edges,
        output_path=output,
        meta_output_path=meta_output,
        backbone_warning_output_path=backbone_warning_output,
        tiered_paths=tiered_paths or None,
        necessary_window=args.necessary_context_window,
        stage_residual_path=stage_residual_path,
        refinement_residual_path=refinement_residual_path,
        edge_applog_context_path=edge_applog_context_path,
        applog_model_context_path=applog_model_context_path,
    )


if __name__ == "__main__":
    raise SystemExit(main())
