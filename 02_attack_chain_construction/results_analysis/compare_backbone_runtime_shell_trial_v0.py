#!/usr/bin/env python3
"""
Compare baseline vs trial backbone for runtime shell representative trial.

Default file layout per scenario:
  chain/backbone_chain.v1.baseline.json
  chain/backbone_chain.v1.json
  chain/runtime_shell_block_summary.v0.jsonl

Focus:
  - PROCESS_FORK / NET_ACCEPT runtime shell block intrusion
  - representative-only retention after trial
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any, Optional

from pipeline.utils.common import scenario_chain_dir


TARGET_RELATIONS = {"PROCESS_FORK", "NET_ACCEPT"}
SEMANTIC_ENTRY_SKIP_RELATIONS = {"PROCESS_FORK"}
RESULT_ANCHOR_RELATIONS = {
    "FILE_WRITE",
    "NET_SEND",
    "NET_CONNECT",
    "PROCESS_EXEC",
    "FILE_READ",
}

# Hang-back contract audit: at minimum, narrow backbone trials must not
# silently break secondary anchoring / context surfaces. These files are
# the ones called out as the minimum hang-back contract.
HANG_BACK_AUDIT_SPECS: tuple[dict[str, Any], ...] = (
    # (label, relative_path_from_scene_dir, kind)
    # kind="jsonl" -> compare line counts; kind="json" -> compare a few headline keys.
    {
        "label": "behavior_context_edges",
        "relative_path": "chain/behavior_context_edges.v0.jsonl",
        "kind": "jsonl",
    },
    {
        "label": "behavior_context_unmatched",
        "relative_path": "chain/behavior_context_unmatched.v0.jsonl",
        "kind": "jsonl",
    },
    {
        "label": "behavior_context_summary",
        "relative_path": "chain/behavior_context_summary.v0.json",
        "kind": "json",
    },
    {
        "label": "event_to_backbone_anchor_index",
        "relative_path": "index/event_to_backbone_anchor_index.v0.jsonl",
        "kind": "jsonl",
    },
    {
        "label": "edge_applog_context_view",
        "relative_path": "index/edge_applog_context_view.v0.jsonl",
        "kind": "jsonl",
    },
    {
        "label": "edge_applog_context_summary",
        "relative_path": "index/edge_applog_context_summary.v0.json",
        "kind": "json",
    },
)


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


def _edge_id(edge: dict[str, Any]) -> str:
    return str(edge.get("edge_id") or edge.get("id") or "")


def _edge_evt_num(edge: dict[str, Any]) -> Optional[int]:
    attrs = edge.get("attrs") or {}
    return _safe_int(attrs.get("evt_num"))


def _edge_is_malicious(edge: dict[str, Any]) -> bool:
    attrs = edge.get("attrs") or {}
    return bool(attrs.get("malicious", False))


def _edge_brief(edge: Optional[dict[str, Any]]) -> Optional[dict[str, Any]]:
    if not edge:
        return None
    return {
        "edge_id": _edge_id(edge),
        "relation": str(edge.get("relation") or ""),
        "evt_num": _edge_evt_num(edge),
        "malicious": _edge_is_malicious(edge),
    }


def _first_matching_edge(edge_sequence: list[dict[str, Any]], predicate) -> Optional[dict[str, Any]]:
    for edge in edge_sequence:
        if predicate(edge):
            return edge
    return None


def _derive_semantic_entry_edge(edge_sequence: list[dict[str, Any]]) -> Optional[dict[str, Any]]:
    first_malicious = _first_matching_edge(edge_sequence, _edge_is_malicious)
    if first_malicious is None:
        return None

    first_mal_evt = _edge_evt_num(first_malicious)
    if first_mal_evt is None:
        return first_malicious

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
        return candidates[-1]
    return first_malicious


def _result_anchor_edge(edge_sequence: list[dict[str, Any]]) -> Optional[dict[str, Any]]:
    result_like = [
        edge
        for edge in edge_sequence
        if str(edge.get("relation") or "").upper() in RESULT_ANCHOR_RELATIONS
    ]
    if result_like:
        return result_like[-1]
    return edge_sequence[-1] if edge_sequence else None


def _backbone_core_metrics(edge_sequence: list[dict[str, Any]]) -> dict[str, Any]:
    relation_counts = Counter(str(edge.get("relation") or "").upper() for edge in edge_sequence)
    first_edge = edge_sequence[0] if edge_sequence else None
    first_malicious_edge = _first_matching_edge(edge_sequence, _edge_is_malicious)
    semantic_entry_edge = _derive_semantic_entry_edge(edge_sequence)
    result_anchor_edge = _result_anchor_edge(edge_sequence)

    first_evt = _edge_evt_num(first_edge or {})
    first_mal_evt = _edge_evt_num(first_malicious_edge or {})
    semantic_evt = _edge_evt_num(semantic_entry_edge or {})

    pre_shell_thickness_evt = (
        first_mal_evt - first_evt
        if first_evt is not None and first_mal_evt is not None
        else None
    )

    return {
        "edge_count": len(edge_sequence),
        "relation_counts": dict(sorted(relation_counts.items())),
        "target_relation_counts": {
            relation: int(relation_counts.get(relation, 0))
            for relation in sorted(TARGET_RELATIONS)
        },
        "first_edge": _edge_brief(first_edge),
        "first_malicious_edge": _edge_brief(first_malicious_edge),
        "semantic_entry_edge": _edge_brief(semantic_entry_edge),
        "result_anchor_edge": _edge_brief(result_anchor_edge),
        "pre_shell_thickness_evt": pre_shell_thickness_evt,
        "first_evt": first_evt,
        "first_malicious_evt": first_mal_evt,
        "semantic_entry_evt": semantic_evt,
    }


def _dominant_target_relation(relation_counts: dict[str, Any]) -> Optional[str]:
    best_relation = None
    best_count = 0
    for relation_raw, count_raw in relation_counts.items():
        relation = str(relation_raw or "").upper()
        if relation not in TARGET_RELATIONS:
            continue
        count_i = _safe_int(count_raw) or 0
        if count_i > best_count:
            best_count = count_i
            best_relation = relation
    return best_relation


def _block_overlap_info(row: dict[str, Any], backbone_edge_ids: set[str]) -> dict[str, Any]:
    member_ids = [str(edge_id) for edge_id in (row.get("edge_ids") or []) if str(edge_id or "")]
    representative_ids = [
        str(edge_id)
        for edge_id in (row.get("representative_edge_ids") or [])
        if str(edge_id or "")
    ]
    comparable_ids = member_ids if member_ids else representative_ids
    edge_count = _safe_int(row.get("edge_count"))
    if edge_count is None or edge_count <= 0:
        edge_count = len(comparable_ids)
    overlap_ids = [edge_id for edge_id in comparable_ids if edge_id in backbone_edge_ids]
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

    return {
        "edge_count": edge_count,
        "overlap_count": overlap_count,
        "overlap_ratio": overlap_ratio,
        "overlap_class": overlap_class,
        "overlap_ids": overlap_ids,
        "member_ids": comparable_ids,
        "representative_ids": representative_ids,
    }


def _runtime_overlap_counts(
    runtime_rows: list[dict[str, Any]],
    backbone_edge_ids: set[str],
) -> dict[str, int]:
    counts: Counter[str] = Counter()
    for row in runtime_rows:
        relation_counts = row.get("relation_family_counts") or {}
        if not isinstance(relation_counts, dict):
            continue
        if _dominant_target_relation(relation_counts) is None:
            continue
        overlap_info = _block_overlap_info(row, backbone_edge_ids)
        counts[str(overlap_info["overlap_class"])] += 1
    return dict(sorted(counts.items()))


def _baseline_variant_path(path: Path, suffix: str) -> Path:
    suffix = suffix.strip() if suffix else ""
    if not suffix:
        suffix = ".baseline"
    if not suffix.startswith("."):
        suffix = "." + suffix
    # Insert the suffix immediately before the LAST extension so that
    # foo.v0.jsonl becomes foo.v0.baseline.jsonl, matching the
    # convention already used for backbone_chain.v1.baseline.json.
    last_ext = path.suffix
    if last_ext:
        stem = path.name[: -len(last_ext)]
        return path.with_name(f"{stem}{suffix}{last_ext}")
    return path.with_name(f"{path.name}{suffix}")


def _count_jsonl_lines(path: Path) -> Optional[int]:
    if not path.exists():
        return None
    count = 0
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if line.strip():
                    count += 1
        return count
    except OSError:
        return None


def _read_json_safe(path: Path) -> Optional[Any]:
    if not path.exists():
        return None
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def _summary_headline(payload: Any) -> dict[str, Any]:
    """Pick a few headline counters from the top level of a summary JSON.

    We keep this loose on purpose: downstream schemas differ between
    behavior_context_summary and edge_applog_context_summary, but both
    tend to expose *_count / *_total / *_matched / *_unmatched fields we
    can surface without coupling to a specific version.
    """
    if not isinstance(payload, dict):
        return {}
    headline: dict[str, Any] = {}
    for key, value in payload.items():
        if not isinstance(key, str):
            continue
        if not isinstance(value, (int, float)):
            continue
        lowered = key.lower()
        if any(
            token in lowered
            for token in (
                "count",
                "total",
                "matched",
                "unmatched",
                "anchor",
                "edges",
                "candidates",
                "rows",
            )
        ):
            headline[key] = value
    return headline


def _audit_one_file(
    scene_dir: Path,
    spec: dict[str, Any],
    baseline_suffix: str,
) -> dict[str, Any]:
    relative_path = str(spec["relative_path"])
    kind = str(spec["kind"])
    label = str(spec["label"])
    if relative_path.startswith("chain/"):
        trial_path = scenario_chain_dir(scene_dir) / relative_path.split("/", 1)[1]
    else:
        trial_path = scene_dir / relative_path
    baseline_path = _baseline_variant_path(trial_path, baseline_suffix)

    result: dict[str, Any] = {
        "label": label,
        "relative_path": relative_path,
        "baseline_path": str(baseline_path),
        "trial_path": str(trial_path),
        "baseline_exists": baseline_path.exists(),
        "trial_exists": trial_path.exists(),
        "kind": kind,
    }

    if kind == "jsonl":
        trial_lines = _count_jsonl_lines(trial_path)
        baseline_lines = _count_jsonl_lines(baseline_path)
        result["trial_line_count"] = trial_lines
        result["baseline_line_count"] = baseline_lines
        if trial_lines is not None and baseline_lines is not None:
            result["line_count_delta"] = trial_lines - baseline_lines
            if baseline_lines > 0:
                result["line_count_ratio_delta"] = round(
                    (trial_lines - baseline_lines) / baseline_lines, 6
                )
            else:
                result["line_count_ratio_delta"] = None
        else:
            result["line_count_delta"] = None
            result["line_count_ratio_delta"] = None
    elif kind == "json":
        trial_payload = _read_json_safe(trial_path)
        baseline_payload = _read_json_safe(baseline_path)
        result["trial_headline"] = _summary_headline(trial_payload)
        result["baseline_headline"] = _summary_headline(baseline_payload)
        if result["trial_headline"] and result["baseline_headline"]:
            delta: dict[str, Any] = {}
            for key in sorted(set(result["trial_headline"].keys()) | set(result["baseline_headline"].keys())):
                trial_v = result["trial_headline"].get(key)
                baseline_v = result["baseline_headline"].get(key)
                if isinstance(trial_v, (int, float)) and isinstance(baseline_v, (int, float)):
                    delta[key] = trial_v - baseline_v
            result["headline_delta"] = delta
        else:
            result["headline_delta"] = {}
    return result


def _hang_back_audit(
    scene_dir: Path,
    baseline_suffix: str,
) -> dict[str, Any]:
    entries = [
        _audit_one_file(scene_dir, spec, baseline_suffix)
        for spec in HANG_BACK_AUDIT_SPECS
    ]
    any_baseline = any(entry.get("baseline_exists") for entry in entries)
    any_shrink_flagged = False
    for entry in entries:
        delta = entry.get("line_count_delta")
        ratio_delta = entry.get("line_count_ratio_delta")
        if (
            isinstance(delta, int)
            and delta < 0
            and isinstance(ratio_delta, (int, float))
            and ratio_delta <= -0.2
        ):
            any_shrink_flagged = True
            entry["shrink_warning"] = True
        # behavior_context_unmatched growth is a symptom even on its own
        if entry.get("label") == "behavior_context_unmatched":
            if isinstance(delta, int) and delta > 0:
                entry.setdefault("growth_warning", True)

    return {
        "baseline_suffix": baseline_suffix,
        "any_baseline_present": any_baseline,
        "any_shrink_flagged": any_shrink_flagged,
        "entries": entries,
    }


def _scenario_label(scene_dir: Path) -> str:
    parts = scene_dir.parts
    if "results" in parts:
        idx = parts.index("results")
        return "/".join(parts[idx + 1 :])
    return str(scene_dir)


def _block_transition_examples(
    runtime_rows: list[dict[str, Any]],
    baseline_edge_ids: set[str],
    trial_edge_ids: set[str],
    baseline_edges_by_id: dict[str, dict[str, Any]],
    max_examples: int = 2,
) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []

    for row in runtime_rows:
        relation_counts = row.get("relation_family_counts") or {}
        if not isinstance(relation_counts, dict):
            continue
        dominant_relation = _dominant_target_relation(relation_counts)
        if dominant_relation is None:
            continue

        before = _block_overlap_info(row, baseline_edge_ids)
        after = _block_overlap_info(row, trial_edge_ids)

        if before["overlap_class"] != "full_block_in_backbone":
            continue
        if after["overlap_class"] not in {
            "representative_only",
            "partial_block_in_backbone",
            "no_overlap",
        }:
            continue

        removed_ids = [edge_id for edge_id in before["overlap_ids"] if edge_id not in after["overlap_ids"]]
        removed_non_malicious = 0
        removed_malicious = 0
        for edge_id in removed_ids:
            edge = baseline_edges_by_id.get(edge_id)
            if edge is None:
                continue
            if _edge_is_malicious(edge):
                removed_malicious += 1
            else:
                removed_non_malicious += 1

        candidates.append(
            {
                "block_id": row.get("block_id"),
                "dominant_relation": dominant_relation,
                "edge_count": before["edge_count"],
                "before_overlap_class": before["overlap_class"],
                "after_overlap_class": after["overlap_class"],
                "before_overlap_count": before["overlap_count"],
                "after_overlap_count": after["overlap_count"],
                "before_overlap_ratio": before["overlap_ratio"],
                "after_overlap_ratio": after["overlap_ratio"],
                "removed_edge_count": len(removed_ids),
                "removed_non_malicious_count": removed_non_malicious,
                "removed_malicious_count": removed_malicious,
                "kept_representative_edge_ids": [
                    edge_id
                    for edge_id in before["representative_ids"]
                    if edge_id in trial_edge_ids
                ],
                "removed_edge_ids_sample": removed_ids[:8],
            }
        )

    candidates.sort(
        key=lambda item: (
            -int(item.get("edge_count") or 0),
            -int(item.get("removed_edge_count") or 0),
            str(item.get("block_id") or ""),
        )
    )
    return candidates[: max(1, int(max_examples))]


def compare_scene(
    scene_dir: Path,
    baseline_backbone_file: str,
    trial_backbone_file: str,
    runtime_block_file: str,
    examples_per_scene: int,
    hang_back_baseline_suffix: str = ".baseline",
) -> dict[str, Any]:
    chain_dir = scenario_chain_dir(scene_dir)
    baseline_path = chain_dir / baseline_backbone_file
    trial_path = chain_dir / trial_backbone_file
    runtime_path = chain_dir / runtime_block_file

    missing = [
        str(path)
        for path in (baseline_path, trial_path, runtime_path)
        if not path.exists()
    ]
    if missing:
        return {
            "scenario_dir": str(scene_dir),
            "scenario_label": _scenario_label(scene_dir),
            "status": "missing_inputs",
            "missing_inputs": missing,
        }

    baseline_chain = _read_json(baseline_path)
    trial_chain = _read_json(trial_path)
    runtime_rows = list(_iter_jsonl(runtime_path))

    baseline_edges = list(baseline_chain.get("edge_sequence") or [])
    trial_edges = list(trial_chain.get("edge_sequence") or [])

    baseline_metrics = _backbone_core_metrics(baseline_edges)
    trial_metrics = _backbone_core_metrics(trial_edges)

    baseline_edge_ids = {
        _edge_id(edge)
        for edge in baseline_edges
        if _edge_id(edge)
    }
    trial_edge_ids = {
        _edge_id(edge)
        for edge in trial_edges
        if _edge_id(edge)
    }
    baseline_edges_by_id = {
        _edge_id(edge): edge
        for edge in baseline_edges
        if _edge_id(edge)
    }

    before_overlap_counts = _runtime_overlap_counts(runtime_rows, baseline_edge_ids)
    after_overlap_counts = _runtime_overlap_counts(runtime_rows, trial_edge_ids)

    result_before = baseline_metrics.get("result_anchor_edge") or {}
    result_after = trial_metrics.get("result_anchor_edge") or {}
    result_anchor_damage = bool(
        str(result_before.get("relation") or "").upper() in RESULT_ANCHOR_RELATIONS
        and str(result_after.get("relation") or "").upper() not in RESULT_ANCHOR_RELATIONS
    )

    semantic_before_evt = baseline_metrics.get("semantic_entry_evt")
    semantic_after_evt = trial_metrics.get("semantic_entry_evt")
    semantic_entry_damage = bool(
        semantic_before_evt is not None
        and (
            semantic_after_evt is None
            or int(semantic_after_evt) > int(semantic_before_evt)
        )
    )

    examples = _block_transition_examples(
        runtime_rows=runtime_rows,
        baseline_edge_ids=baseline_edge_ids,
        trial_edge_ids=trial_edge_ids,
        baseline_edges_by_id=baseline_edges_by_id,
        max_examples=examples_per_scene,
    )

    hang_back_audit = _hang_back_audit(
        scene_dir=scene_dir,
        baseline_suffix=hang_back_baseline_suffix,
    )

    return {
        "scenario_dir": str(scene_dir),
        "scenario_label": _scenario_label(scene_dir),
        "status": "ok",
        "inputs": {
            "baseline_backbone": str(baseline_path),
            "trial_backbone": str(trial_path),
            "runtime_shell_block_summary": str(runtime_path),
        },
        "metrics": {
            "backbone_edge_count": {
                "before": baseline_metrics["edge_count"],
                "after": trial_metrics["edge_count"],
                "delta": trial_metrics["edge_count"] - baseline_metrics["edge_count"],
            },
            "target_relation_counts": {
                relation: {
                    "before": baseline_metrics["target_relation_counts"].get(relation, 0),
                    "after": trial_metrics["target_relation_counts"].get(relation, 0),
                    "delta": (
                        trial_metrics["target_relation_counts"].get(relation, 0)
                        - baseline_metrics["target_relation_counts"].get(relation, 0)
                    ),
                }
                for relation in sorted(TARGET_RELATIONS)
            },
            "runtime_overlap_class_counts": {
                "before": before_overlap_counts,
                "after": after_overlap_counts,
                "full_block_in_backbone_delta": (
                    int(after_overlap_counts.get("full_block_in_backbone", 0))
                    - int(before_overlap_counts.get("full_block_in_backbone", 0))
                ),
                "representative_only_delta": (
                    int(after_overlap_counts.get("representative_only", 0))
                    - int(before_overlap_counts.get("representative_only", 0))
                ),
            },
            "backbone_entry_edges": {
                "before": {
                    "first_edge": baseline_metrics.get("first_edge"),
                    "semantic_entry_edge": baseline_metrics.get("semantic_entry_edge"),
                    "first_malicious_edge": baseline_metrics.get("first_malicious_edge"),
                },
                "after": {
                    "first_edge": trial_metrics.get("first_edge"),
                    "semantic_entry_edge": trial_metrics.get("semantic_entry_edge"),
                    "first_malicious_edge": trial_metrics.get("first_malicious_edge"),
                },
            },
            "pre_shell_thickness_evt": {
                "before": baseline_metrics.get("pre_shell_thickness_evt"),
                "after": trial_metrics.get("pre_shell_thickness_evt"),
                "delta": (
                    None
                    if baseline_metrics.get("pre_shell_thickness_evt") is None
                    or trial_metrics.get("pre_shell_thickness_evt") is None
                    else trial_metrics.get("pre_shell_thickness_evt") - baseline_metrics.get("pre_shell_thickness_evt")
                ),
            },
            "result_anchor_damage": result_anchor_damage,
            "semantic_entry_damage": semantic_entry_damage,
        },
        "example_block_transitions": examples,
        "hang_back_audit": hang_back_audit,
    }


def render_text(summaries: list[dict[str, Any]]) -> str:
    lines: list[str] = []
    for summary in summaries:
        lines.append(f"## {summary.get('scenario_label')}")
        if summary.get("status") != "ok":
            lines.append(f"status: {summary.get('status')}")
            lines.append(f"missing_inputs: {summary.get('missing_inputs')}")
            lines.append("")
            continue

        metrics = summary.get("metrics") or {}
        edge_count = metrics.get("backbone_edge_count") or {}
        relation_counts = metrics.get("target_relation_counts") or {}
        overlap = metrics.get("runtime_overlap_class_counts") or {}
        pre_shell = metrics.get("pre_shell_thickness_evt") or {}

        lines.append(
            "edge_count: "
            f"before={edge_count.get('before')} after={edge_count.get('after')} delta={edge_count.get('delta')}"
        )
        for relation in sorted(TARGET_RELATIONS):
            item = relation_counts.get(relation) or {}
            lines.append(
                f"{relation}: before={item.get('before')} after={item.get('after')} delta={item.get('delta')}"
            )
        lines.append(
            "runtime_overlap: "
            f"before={overlap.get('before')} after={overlap.get('after')} "
            f"full_block_delta={overlap.get('full_block_in_backbone_delta')} "
            f"representative_only_delta={overlap.get('representative_only_delta')}"
        )

        entry_edges = metrics.get("backbone_entry_edges") or {}
        before = entry_edges.get("before") or {}
        after = entry_edges.get("after") or {}
        lines.append(
            "entry_edges_before: "
            f"first={before.get('first_edge')} semantic={before.get('semantic_entry_edge')} "
            f"first_malicious={before.get('first_malicious_edge')}"
        )
        lines.append(
            "entry_edges_after: "
            f"first={after.get('first_edge')} semantic={after.get('semantic_entry_edge')} "
            f"first_malicious={after.get('first_malicious_edge')}"
        )
        lines.append(
            "pre_shell_thickness_evt: "
            f"before={pre_shell.get('before')} after={pre_shell.get('after')} delta={pre_shell.get('delta')}"
        )
        lines.append(
            "anchor_guard: "
            f"result_anchor_damage={metrics.get('result_anchor_damage')} "
            f"semantic_entry_damage={metrics.get('semantic_entry_damage')}"
        )

        lines.append("example_block_transitions:")
        for item in summary.get("example_block_transitions") or []:
            lines.append(
                "  - "
                f"{item.get('dominant_relation')} block={item.get('block_id')} "
                f"edge_count={item.get('edge_count')} "
                f"before={item.get('before_overlap_class')}:{item.get('before_overlap_count')} "
                f"after={item.get('after_overlap_class')}:{item.get('after_overlap_count')} "
                f"removed_non_mal={item.get('removed_non_malicious_count')} "
                f"removed_mal={item.get('removed_malicious_count')} "
                f"kept_rep={item.get('kept_representative_edge_ids')}"
            )

        hang_back = summary.get("hang_back_audit") or {}
        if hang_back:
            lines.append("hang_back_audit:")
            lines.append(
                "  baseline_suffix="
                f"{hang_back.get('baseline_suffix')} "
                f"any_baseline_present={hang_back.get('any_baseline_present')} "
                f"any_shrink_flagged={hang_back.get('any_shrink_flagged')}"
            )
            for entry in hang_back.get("entries") or []:
                label = entry.get("label")
                kind = entry.get("kind")
                base_exists = entry.get("baseline_exists")
                trial_exists = entry.get("trial_exists")
                if kind == "jsonl":
                    line_parts = [
                        f"  - {label} [{kind}]",
                        f"trial_lines={entry.get('trial_line_count')}",
                        f"baseline_lines={entry.get('baseline_line_count')}",
                        f"delta={entry.get('line_count_delta')}",
                        f"ratio_delta={entry.get('line_count_ratio_delta')}",
                        f"baseline_exists={base_exists}",
                        f"trial_exists={trial_exists}",
                    ]
                    if entry.get("shrink_warning"):
                        line_parts.append("SHRINK_WARNING=true")
                    if entry.get("growth_warning"):
                        line_parts.append("GROWTH_WARNING=true")
                    lines.append(" ".join(line_parts))
                else:
                    line_parts = [
                        f"  - {label} [{kind}]",
                        f"trial={entry.get('trial_headline')}",
                        f"baseline={entry.get('baseline_headline')}",
                        f"delta={entry.get('headline_delta')}",
                        f"baseline_exists={base_exists}",
                        f"trial_exists={trial_exists}",
                    ]
                    lines.append(" ".join(line_parts))
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Compare baseline vs runtime shell representative trial backbone outputs."
    )
    parser.add_argument(
        "scenario_dirs",
        nargs="+",
        type=Path,
        help="Scenario timestamp directories to compare.",
    )
    parser.add_argument(
        "--baseline-backbone-file",
        type=str,
        default="backbone_chain.v1.baseline.json",
        help="Baseline backbone file name under chain/.",
    )
    parser.add_argument(
        "--trial-backbone-file",
        type=str,
        default="backbone_chain.v1.json",
        help="Trial backbone file name under chain/.",
    )
    parser.add_argument(
        "--runtime-block-file",
        type=str,
        default="runtime_shell_block_summary.v0.jsonl",
        help="Runtime shell block sidecar file name under chain/.",
    )
    parser.add_argument(
        "--examples-per-scene",
        type=int,
        default=2,
        help="How many block transition examples to keep per scene.",
    )
    parser.add_argument(
        "--hang-back-baseline-suffix",
        type=str,
        default=".baseline",
        help=(
            "Suffix used to locate baseline variants of hang-back contract "
            "sidecars (behavior_context_*, event_to_backbone_anchor_index, "
            "edge_applog_context_*). Files are expected alongside the "
            "current sidecars at <stem><suffix><ext>."
        ),
    )
    parser.add_argument("--output-json", type=Path, default=None)
    parser.add_argument("--output-md", type=Path, default=None)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    examples_per_scene = max(1, int(args.examples_per_scene))

    summaries = [
        compare_scene(
            scene_dir=scene_dir,
            baseline_backbone_file=args.baseline_backbone_file,
            trial_backbone_file=args.trial_backbone_file,
            runtime_block_file=args.runtime_block_file,
            examples_per_scene=examples_per_scene,
            hang_back_baseline_suffix=args.hang_back_baseline_suffix,
        )
        for scene_dir in args.scenario_dirs
    ]

    payload = {
        "schema_version": "runtime_shell_block_trial_compare.v0",
        "target_relations": sorted(TARGET_RELATIONS),
        "scene_count": len(summaries),
        "summaries": summaries,
    }

    rendered = render_text(summaries)
    print(rendered)

    if args.output_json is not None:
        args.output_json.parent.mkdir(parents=True, exist_ok=True)
        with open(args.output_json, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False, indent=2)
            fh.write("\n")
        print(f"[compare] wrote JSON: {args.output_json}")

    if args.output_md is not None:
        args.output_md.parent.mkdir(parents=True, exist_ok=True)
        args.output_md.write_text(rendered, encoding="utf-8")
        print(f"[compare] wrote Markdown: {args.output_md}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
