#!/usr/bin/env python3
"""
Read-only diagnostics for backbone block sidecars.

Inputs per scenario:
  chain/backbone_chain.v1.json
  chain/runtime_shell_block_summary.v0.jsonl
  chain/entry_candidate_block_summary.v0.jsonl

The script never modifies pipeline artifacts. Optional --output-json/--output-md
write standalone diagnostic reports only.
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any, Optional

from pipeline.utils.common import scenario_chain_dir


DEFAULT_TOP_N = 5
SEMANTIC_ENTRY_SKIP_RELATIONS = {"PROCESS_FORK"}
RUNTIME_RELATIONS = {"PROCESS_FORK", "NET_ACCEPT", "NET_RECV", "NET_SEND"}
TIER_ORDER = {
    "strong_recommended": 0,
    "weak_recommended": 1,
    "context_only": 2,
    "not_recommended": 3,
}


def _read_json(path: Path) -> Any:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


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


def _safe_int(value: Any) -> Optional[int]:
    try:
        if value is None:
            return None
        return int(value)
    except (TypeError, ValueError):
        return None


def _edge_evt_num(edge: dict[str, Any]) -> Optional[int]:
    attrs = edge.get("attrs") or {}
    return _safe_int(attrs.get("evt_num"))


def _edge_is_malicious(edge: dict[str, Any]) -> bool:
    attrs = edge.get("attrs") or {}
    return bool(attrs.get("malicious", False))


def _edge_brief(edge: dict[str, Any]) -> dict[str, Any]:
    return {
        "edge_id": edge.get("edge_id") or edge.get("id"),
        "relation": edge.get("relation"),
        "evt_num": _edge_evt_num(edge),
        "malicious": _edge_is_malicious(edge),
    }


def _first_matching_edge(
    edges: list[dict[str, Any]],
    predicate,
) -> Optional[dict[str, Any]]:
    for edge in edges:
        if predicate(edge):
            return edge
    return None


def _derive_semantic_entry_edge(edge_sequence: list[dict[str, Any]]) -> tuple[Optional[dict[str, Any]], str]:
    first_malicious = _first_matching_edge(edge_sequence, _edge_is_malicious)
    if first_malicious is None:
        return None, "no_malicious_edge"

    first_mal_evt = _edge_evt_num(first_malicious)
    if first_mal_evt is None:
        return first_malicious, "first_malicious_without_evt"

    candidates: list[dict[str, Any]] = []
    for edge in edge_sequence:
        evt_num = _edge_evt_num(edge)
        if evt_num is None or evt_num > first_mal_evt:
            continue
        relation = str(edge.get("relation") or "")
        if relation in SEMANTIC_ENTRY_SKIP_RELATIONS:
            continue
        if relation in {"NET_ACCEPT", "NET_RECV", "NET_SEND", "NET_CONNECT", "PROCESS_EXEC"}:
            candidates.append(edge)

    if candidates:
        return candidates[-1], "last_pre_malicious_non_fork_runtime_or_exec_edge"
    return first_malicious, "fallback_first_malicious_edge"


def _dominant_relation(relation_counts: dict[str, Any]) -> Optional[str]:
    if not relation_counts:
        return None
    normalized: list[tuple[int, str]] = []
    for relation, count in relation_counts.items():
        count_i = _safe_int(count) or 0
        normalized.append((count_i, str(relation)))
    if not normalized:
        return None
    count_i, relation = max(normalized, key=lambda item: (item[0], item[1]))
    return relation if count_i > 0 else None


def _scenario_label(scene_dir: Path) -> str:
    parts = scene_dir.parts
    if "results" in parts:
        idx = parts.index("results")
        return "/".join(parts[idx + 1 :])
    return str(scene_dir)


def _top_runtime_blocks(rows: list[dict[str, Any]], top_n: int) -> list[dict[str, Any]]:
    ranked = sorted(
        rows,
        key=lambda row: (
            -int(row.get("edge_count") or 0),
            -int(row.get("malicious_edge_count") or 0),
            row.get("distance_to_first_malicious_evt")
            if row.get("distance_to_first_malicious_evt") is not None
            else (1 << 62),
            str(row.get("block_id") or ""),
        ),
    )
    out: list[dict[str, Any]] = []
    for row in ranked[:top_n]:
        relation_counts = row.get("relation_family_counts") or {}
        out.append(
            {
                "block_id": row.get("block_id"),
                "dominant_relation": _dominant_relation(relation_counts),
                "relation_family_counts": relation_counts,
                "edge_count": row.get("edge_count"),
                "malicious_edge_count": row.get("malicious_edge_count"),
                "recommended_role": row.get("recommended_role"),
                "distance_to_first_malicious_evt": row.get("distance_to_first_malicious_evt"),
                "representative_edge_ids": row.get("representative_edge_ids") or [],
                "backbone_overlap_edge_count": row.get("backbone_overlap_edge_count"),
                "backbone_overlap_ratio": row.get("backbone_overlap_ratio"),
                "backbone_overlap_class": row.get("backbone_overlap_class"),
                "backbone_overlap_edge_ids": row.get("backbone_overlap_edge_ids") or [],
            }
        )
    return out


def _top_entry_candidates(rows: list[dict[str, Any]], top_n: int) -> list[dict[str, Any]]:
    ranked = sorted(
        rows,
        key=lambda row: (
            TIER_ORDER.get(str(row.get("recommendation_tier") or ""), 9),
            row.get("shell_thickness_before_attack")
            if row.get("shell_thickness_before_attack") is not None
            else (1 << 62),
            row.get("distance_to_first_malicious_evt")
            if row.get("distance_to_first_malicious_evt") is not None
            else (1 << 62),
            row.get("entry_evt_start") if row.get("entry_evt_start") is not None else (1 << 62),
            str(row.get("entry_candidate_id") or ""),
        ),
    )
    keys = [
        "entry_candidate_id",
        "block_id",
        "entry_relation",
        "entry_evt_start",
        "distance_to_first_malicious_evt",
        "same_conn_as_malicious",
        "same_process_as_malicious",
        "shell_thickness_before_attack",
        "recommended_as_backbone_start",
        "recommendation_tier",
        "recommendation_reasons",
        "representative_entry_edge_id",
    ]
    return [{key: row.get(key) for key in keys} for row in ranked[:top_n]]


def _augment_runtime_overlap(
    runtime_rows: list[dict[str, Any]],
    backbone_edge_ids: set[str],
) -> list[dict[str, Any]]:
    augmented: list[dict[str, Any]] = []
    for row in runtime_rows:
        member_ids = [str(edge_id) for edge_id in (row.get("edge_ids") or []) if edge_id]
        rep_ids = [str(edge_id) for edge_id in (row.get("representative_edge_ids") or []) if edge_id]
        overlap_source = "edge_ids" if member_ids else "representative_edge_ids"
        comparable_ids = member_ids if member_ids else rep_ids
        overlap_ids = [edge_id for edge_id in comparable_ids if edge_id in backbone_edge_ids]
        edge_count = _safe_int(row.get("edge_count")) or 0
        overlap_count = len(overlap_ids)
        overlap_ratio = round(overlap_count / edge_count, 6) if edge_count > 0 else 0.0
        if overlap_count == 0:
            overlap_class = "no_overlap"
        elif edge_count > 0 and overlap_count >= edge_count:
            overlap_class = "full_block_in_backbone"
        elif overlap_count <= 2:
            overlap_class = "representative_only"
        else:
            overlap_class = "partial_block_in_backbone"
        out = dict(row)
        out["backbone_overlap_edge_count"] = overlap_count
        out["backbone_overlap_ratio"] = overlap_ratio
        out["backbone_overlap_class"] = overlap_class
        out["backbone_overlap_edge_ids"] = overlap_ids
        out["backbone_overlap_source"] = overlap_source
        augmented.append(out)
    return augmented


def diagnose_scene(scene_dir: Path, top_n: int) -> dict[str, Any]:
    chain_dir = scenario_chain_dir(scene_dir)
    backbone_path = chain_dir / "backbone_chain.v1.json"
    runtime_path = chain_dir / "runtime_shell_block_summary.v0.jsonl"
    entry_path = chain_dir / "entry_candidate_block_summary.v0.jsonl"

    missing = [
        str(path)
        for path in (backbone_path, runtime_path, entry_path)
        if not path.exists()
    ]
    if missing:
        return {
            "scenario_dir": str(scene_dir),
            "scenario_label": _scenario_label(scene_dir),
            "status": "missing_inputs",
            "missing_inputs": missing,
        }

    backbone = _read_json(backbone_path)
    edge_sequence = list(backbone.get("edge_sequence") or [])
    backbone_edge_ids = {
        str(edge.get("edge_id") or edge.get("id") or "")
        for edge in edge_sequence
        if str(edge.get("edge_id") or edge.get("id") or "")
    }
    first_edge = edge_sequence[0] if edge_sequence else {}
    first_edge_evt = _edge_evt_num(first_edge)
    first_malicious_edge = _first_matching_edge(edge_sequence, _edge_is_malicious)
    semantic_entry_edge, semantic_entry_rule = _derive_semantic_entry_edge(edge_sequence)
    malicious_evt_values = [
        evt
        for evt in (_edge_evt_num(edge) for edge in edge_sequence if _edge_is_malicious(edge))
        if evt is not None
    ]
    first_malicious_evt = min(malicious_evt_values) if malicious_evt_values else None
    first_to_malicious_delta = (
        first_malicious_evt - first_edge_evt
        if first_malicious_evt is not None and first_edge_evt is not None
        else None
    )

    runtime_rows = list(_iter_jsonl(runtime_path))
    entry_rows = list(_iter_jsonl(entry_path))
    runtime_rows = _augment_runtime_overlap(runtime_rows, backbone_edge_ids)

    runtime_type_counts = Counter(str(row.get("block_type_candidate") or "") for row in runtime_rows)
    runtime_role_counts = Counter(str(row.get("recommended_role") or "") for row in runtime_rows)
    runtime_overlap_class_counts = Counter(
        str(row.get("backbone_overlap_class") or "") for row in runtime_rows
    )
    runtime_relation_presence = Counter()
    for row in runtime_rows:
        counts = row.get("relation_family_counts") or {}
        if isinstance(counts, dict):
            for relation, count in counts.items():
                if (_safe_int(count) or 0) > 0:
                    runtime_relation_presence[str(relation)] += 1

    top_runtime = _top_runtime_blocks(runtime_rows, top_n)
    top_runtime_relations = sorted(
        {
            relation
            for row in top_runtime
            for relation, count in (row.get("relation_family_counts") or {}).items()
            if (_safe_int(count) or 0) > 0
        }
    )

    recommended_entry_rows = [
        row for row in entry_rows if bool(row.get("recommended_as_backbone_start"))
    ]
    tier_counts = Counter(str(row.get("recommendation_tier") or "unknown") for row in entry_rows)
    reason_counts = Counter()
    same_process_only_count = 0
    same_process_only_recommended_count = 0
    for row in entry_rows:
        reasons = [str(reason) for reason in (row.get("recommendation_reasons") or [])]
        reason_counts.update(reasons)
        reason_set = set(reasons)
        if reason_set == {"same_process_only"} or (
            "same_process_only" in reason_set
            and not {
                "same_conn_as_first_malicious",
                "overlaps_first_malicious_evt",
                "near_first_malicious_evt",
            } & reason_set
        ):
            same_process_only_count += 1
            if bool(row.get("recommended_as_backbone_start")):
                same_process_only_recommended_count += 1
    earlier_than_backbone = [
        row
        for row in entry_rows
        if first_edge_evt is not None
        and _safe_int(row.get("entry_evt_start")) is not None
        and int(row.get("entry_evt_start")) < first_edge_evt
    ]
    recommended_before_malicious = [
        row
        for row in recommended_entry_rows
        if first_malicious_evt is not None
        and _safe_int(row.get("entry_evt_start")) is not None
        and int(row.get("entry_evt_start")) <= first_malicious_evt
    ]
    same_conn_count = sum(1 for row in entry_rows if bool(row.get("same_conn_as_malicious")))
    same_process_count = sum(1 for row in entry_rows if bool(row.get("same_process_as_malicious")))
    top_entry = _top_entry_candidates(entry_rows, top_n)

    best_entry = top_entry[0] if top_entry else None
    best_entry_evt = _safe_int((best_entry or {}).get("entry_evt_start"))
    best_entry_distance = _safe_int((best_entry or {}).get("distance_to_first_malicious_evt"))
    best_entry_shell = _safe_int((best_entry or {}).get("shell_thickness_before_attack"))

    thick_pre_shell = bool(
        first_to_malicious_delta is not None
        and first_to_malicious_delta > 1000
        and len(recommended_before_malicious) > 0
    )
    backbone_first_late = bool(
        earlier_than_backbone
        or (
            first_edge_evt is not None
            and first_malicious_evt is not None
            and first_edge_evt > first_malicious_evt
        )
    )
    semantic_entry_buried = bool(
        first_to_malicious_delta is not None
        and first_to_malicious_delta > 1000
        and best_entry_evt is not None
        and first_edge_evt is not None
        and best_entry_evt > first_edge_evt
    )
    better_entry_candidate_exists = bool(
        best_entry is not None
        and bool(best_entry.get("recommended_as_backbone_start"))
        and best_entry_distance is not None
        and (
            best_entry_distance == 0
            or best_entry.get("same_conn_as_malicious")
            or (best_entry_shell is not None and best_entry_shell <= 12)
        )
    )

    return {
        "scenario_dir": str(scene_dir),
        "scenario_label": _scenario_label(scene_dir),
        "status": "ok",
        "inputs": {
            "backbone_chain": str(backbone_path),
            "runtime_shell_block_summary": str(runtime_path),
            "entry_candidate_block_summary": str(entry_path),
        },
        "backbone_first_edge": {
            **_edge_brief(first_edge),
            "first_malicious_evt_num": first_malicious_evt,
            "first_to_malicious_delta": first_to_malicious_delta,
            "edge_count": len(edge_sequence),
        },
        "backbone_entry_edges": {
            "current_backbone_first_edge": _edge_brief(first_edge),
            "current_backbone_first_malicious_edge": (
                _edge_brief(first_malicious_edge) if first_malicious_edge else None
            ),
            "current_backbone_semantic_entry_edge": (
                _edge_brief(semantic_entry_edge) if semantic_entry_edge else None
            ),
            "semantic_entry_rule": semantic_entry_rule,
            "first_to_semantic_entry_delta": (
                _edge_evt_num(semantic_entry_edge) - first_edge_evt
                if semantic_entry_edge is not None
                and _edge_evt_num(semantic_entry_edge) is not None
                and first_edge_evt is not None
                else None
            ),
            "semantic_entry_to_first_malicious_delta": (
                first_malicious_evt - _edge_evt_num(semantic_entry_edge)
                if semantic_entry_edge is not None
                and _edge_evt_num(semantic_entry_edge) is not None
                and first_malicious_evt is not None
                else None
            ),
        },
        "runtime_shell": {
            "total_blocks": len(runtime_rows),
            "block_type_candidate_counts": dict(sorted(runtime_type_counts.items())),
            "recommended_role_counts": dict(sorted(runtime_role_counts.items())),
            "backbone_overlap_class_counts": dict(sorted(runtime_overlap_class_counts.items())),
            "blocks_with_backbone_overlap": sum(
                1 for row in runtime_rows if (_safe_int(row.get("backbone_overlap_edge_count")) or 0) > 0
            ),
            "blocks_full_or_partial_in_backbone": sum(
                1
                for row in runtime_rows
                if row.get("backbone_overlap_class") in {
                    "full_block_in_backbone",
                    "partial_block_in_backbone",
                }
            ),
            "relation_presence_counts": dict(sorted(runtime_relation_presence.items())),
            "top_runtime_relations": top_runtime_relations,
            "top_blocks": top_runtime,
        },
        "entry_candidates": {
            "total_candidates": len(entry_rows),
            "recommended_as_backbone_start_count": len(recommended_entry_rows),
            "recommendation_tier_counts": dict(sorted(tier_counts.items())),
            "recommendation_reason_counts": dict(sorted(reason_counts.items())),
            "same_process_only_count": same_process_only_count,
            "same_process_only_recommended_count": same_process_only_recommended_count,
            "earlier_than_backbone_first_count": len(earlier_than_backbone),
            "recommended_before_first_malicious_count": len(recommended_before_malicious),
            "same_conn_as_malicious_count": same_conn_count,
            "same_process_as_malicious_count": same_process_count,
            "top_candidates": top_entry,
        },
        "comparison": {
            "backbone_first_may_be_late": backbone_first_late,
            "semantic_entry_buried_by_runtime_shell": semantic_entry_buried,
            "thick_pre_attack_shell_visible": thick_pre_shell,
            "better_entry_candidate_exists": better_entry_candidate_exists,
            "entry_candidates_from_runtime_blocks": bool(entry_rows),
            "notes": _comparison_notes(
                first_edge_evt=first_edge_evt,
                first_malicious_evt=first_malicious_evt,
                first_to_malicious_delta=first_to_malicious_delta,
                earlier_count=len(earlier_than_backbone),
                recommended_before_count=len(recommended_before_malicious),
                best_entry=best_entry,
            ),
        },
    }


def _comparison_notes(
    *,
    first_edge_evt: Optional[int],
    first_malicious_evt: Optional[int],
    first_to_malicious_delta: Optional[int],
    earlier_count: int,
    recommended_before_count: int,
    best_entry: Optional[dict[str, Any]],
) -> list[str]:
    notes: list[str] = []
    if earlier_count > 0:
        notes.append("found_entry_candidates_earlier_than_current_backbone_first_edge")
    elif first_edge_evt is not None:
        notes.append("no_entry_candidate_earlier_than_current_backbone_first_edge")
    if first_to_malicious_delta is not None and first_to_malicious_delta > 1000:
        notes.append("large_gap_between_backbone_first_edge_and_first_malicious_evt")
    if recommended_before_count > 0:
        notes.append("recommended_entry_candidates_exist_before_or_at_first_malicious_evt")
    if best_entry and best_entry.get("block_id"):
        notes.append("top_entry_candidate_is_linked_to_runtime_shell_block")
    if first_edge_evt is not None and first_malicious_evt is not None and first_edge_evt < first_malicious_evt:
        notes.append("current_backbone_first_edge_is_early_runtime_context_not_semantic_attack_start")
    return notes


def _format_bool(value: Any) -> str:
    return "yes" if bool(value) else "no"


def render_text(summaries: list[dict[str, Any]]) -> str:
    lines: list[str] = []
    for summary in summaries:
        lines.append(f"## {summary.get('scenario_label')}")
        if summary.get("status") != "ok":
            lines.append(f"status: {summary.get('status')}")
            lines.append(f"missing_inputs: {summary.get('missing_inputs')}")
            lines.append("")
            continue

        first = summary["backbone_first_edge"]
        entry_edges = summary.get("backbone_entry_edges") or {}
        runtime = summary["runtime_shell"]
        entry = summary["entry_candidates"]
        comparison = summary["comparison"]
        lines.append(
            "backbone_first: "
            f"{first.get('relation')}@{first.get('evt_num')} "
            f"first_malicious={first.get('first_malicious_evt_num')} "
            f"delta={first.get('first_to_malicious_delta')} "
            f"edge_count={first.get('edge_count')}"
        )
        semantic = entry_edges.get("current_backbone_semantic_entry_edge") or {}
        first_mal = entry_edges.get("current_backbone_first_malicious_edge") or {}
        lines.append(
            "backbone_entry_edges: "
            f"first={first.get('relation')}@{first.get('evt_num')} "
            f"first_malicious={first_mal.get('relation')}@{first_mal.get('evt_num')} "
            f"semantic={semantic.get('relation')}@{semantic.get('evt_num')} "
            f"semantic_rule={entry_edges.get('semantic_entry_rule')} "
            f"first_to_semantic_delta={entry_edges.get('first_to_semantic_entry_delta')}"
        )
        lines.append(
            "runtime_shell: "
            f"blocks={runtime.get('total_blocks')} "
            f"roles={runtime.get('recommended_role_counts')} "
            f"overlap={runtime.get('backbone_overlap_class_counts')} "
            f"relations={runtime.get('relation_presence_counts')}"
        )
        lines.append(
            "entry_candidates: "
            f"total={entry.get('total_candidates')} "
            f"recommended={entry.get('recommended_as_backbone_start_count')} "
            f"tiers={entry.get('recommendation_tier_counts')} "
            f"same_process_only={entry.get('same_process_only_count')} "
            f"earlier_than_backbone_first={entry.get('earlier_than_backbone_first_count')} "
            f"same_conn={entry.get('same_conn_as_malicious_count')} "
            f"same_process={entry.get('same_process_as_malicious_count')}"
        )
        lines.append(
            "comparison: "
            f"backbone_first_may_be_late={_format_bool(comparison.get('backbone_first_may_be_late'))} "
            f"semantic_entry_buried={_format_bool(comparison.get('semantic_entry_buried_by_runtime_shell'))} "
            f"thick_pre_shell={_format_bool(comparison.get('thick_pre_attack_shell_visible'))} "
            f"better_entry_candidate={_format_bool(comparison.get('better_entry_candidate_exists'))}"
        )
        lines.append("top_runtime_blocks:")
        for block in runtime.get("top_blocks", []):
            lines.append(
                "  - "
                f"{block.get('dominant_relation')} edges={block.get('edge_count')} "
                f"mal={block.get('malicious_edge_count')} role={block.get('recommended_role')} "
                f"dist={block.get('distance_to_first_malicious_evt')} "
                f"overlap={block.get('backbone_overlap_class')}:{block.get('backbone_overlap_edge_count')} "
                f"id={block.get('block_id')} reps={block.get('representative_edge_ids')}"
            )
        lines.append("top_entry_candidates:")
        for candidate in entry.get("top_candidates", []):
            lines.append(
                "  - "
                f"{candidate.get('entry_relation')}@{candidate.get('entry_evt_start')} "
                f"dist={candidate.get('distance_to_first_malicious_evt')} "
                f"shell={candidate.get('shell_thickness_before_attack')} "
                f"same_conn={candidate.get('same_conn_as_malicious')} "
                f"same_proc={candidate.get('same_process_as_malicious')} "
                f"tier={candidate.get('recommendation_tier')} "
                f"reasons={candidate.get('recommendation_reasons')} "
                f"id={candidate.get('entry_candidate_id')} "
                f"rep={candidate.get('representative_entry_edge_id')}"
            )
        lines.append(f"notes: {comparison.get('notes')}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def render_markdown(summaries: list[dict[str, Any]]) -> str:
    lines = ["# Backbone Block Sidecar Diagnostics", ""]
    for summary in summaries:
        lines.append(f"## {summary.get('scenario_label')}")
        if summary.get("status") != "ok":
            lines.append(f"- status: `{summary.get('status')}`")
            lines.append(f"- missing inputs: `{summary.get('missing_inputs')}`")
            lines.append("")
            continue
        first = summary["backbone_first_edge"]
        entry_edges = summary.get("backbone_entry_edges") or {}
        runtime = summary["runtime_shell"]
        entry = summary["entry_candidates"]
        comparison = summary["comparison"]
        semantic = entry_edges.get("current_backbone_semantic_entry_edge") or {}
        lines.extend(
            [
                f"- backbone first: `{first.get('relation')}@{first.get('evt_num')}`",
                f"- semantic entry: `{semantic.get('relation')}@{semantic.get('evt_num')}` via `{entry_edges.get('semantic_entry_rule')}`",
                f"- first malicious evt: `{first.get('first_malicious_evt_num')}`",
                f"- first-to-malicious delta: `{first.get('first_to_malicious_delta')}`",
                f"- runtime blocks: `{runtime.get('total_blocks')}` roles `{runtime.get('recommended_role_counts')}` overlap `{runtime.get('backbone_overlap_class_counts')}`",
                f"- entry candidates: `{entry.get('total_candidates')}` tiers `{entry.get('recommendation_tier_counts')}`",
                f"- comparison: semantic entry buried `{_format_bool(comparison.get('semantic_entry_buried_by_runtime_shell'))}`, better candidate `{_format_bool(comparison.get('better_entry_candidate_exists'))}`",
                "",
                "| top runtime relation | edges | malicious | role | overlap | dist to first malicious |",
                "|---|---:|---:|---|---|---:|",
            ]
        )
        for block in runtime.get("top_blocks", []):
            lines.append(
                f"| `{block.get('dominant_relation')}` | {block.get('edge_count')} | "
                f"{block.get('malicious_edge_count')} | `{block.get('recommended_role')}` | "
                f"`{block.get('backbone_overlap_class')}:{block.get('backbone_overlap_edge_count')}` | "
                f"{block.get('distance_to_first_malicious_evt')} |"
            )
        lines.extend(
            [
                "",
                "| top entry relation | evt | dist | shell | tier | reasons | same conn | same process |",
                "|---|---:|---:|---:|---|---|---|---|",
            ]
        )
        for candidate in entry.get("top_candidates", []):
            lines.append(
                f"| `{candidate.get('entry_relation')}` | {candidate.get('entry_evt_start')} | "
                f"{candidate.get('distance_to_first_malicious_evt')} | "
                f"{candidate.get('shell_thickness_before_attack')} | "
                f"`{candidate.get('recommendation_tier')}` | "
                f"`{candidate.get('recommendation_reasons')}` | "
                f"{candidate.get('same_conn_as_malicious')} | "
                f"{candidate.get('same_process_as_malicious')} |"
            )
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Read-only diagnostics for runtime shell and entry candidate sidecars."
    )
    parser.add_argument(
        "scenario_dirs",
        type=Path,
        nargs="+",
        help="Scenario timestamp directories to diagnose.",
    )
    parser.add_argument("--top-n", type=int, default=DEFAULT_TOP_N)
    parser.add_argument("--output-json", type=Path, default=None)
    parser.add_argument("--output-md", type=Path, default=None)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    top_n = max(1, int(args.top_n))
    summaries = [diagnose_scene(path, top_n=top_n) for path in args.scenario_dirs]
    payload = {
        "schema_version": "backbone_block_sidecar_diagnostics.v0",
        "scene_count": len(summaries),
        "summaries": summaries,
    }

    print(render_text(summaries))

    if args.output_json is not None:
        args.output_json.parent.mkdir(parents=True, exist_ok=True)
        with open(args.output_json, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False, indent=2)
            fh.write("\n")
        print(f"[diagnose] wrote JSON: {args.output_json}")

    if args.output_md is not None:
        args.output_md.parent.mkdir(parents=True, exist_ok=True)
        args.output_md.write_text(render_markdown(summaries), encoding="utf-8")
        print(f"[diagnose] wrote Markdown: {args.output_md}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
