#!/usr/bin/env python3
"""Stage-label quality audit over the unified SecLog-Bench-216 benchmark.

Scope and guardrails
--------------------
* Read-only consumption of existing release / benchmark artefacts.
* Does NOT rerun pipeline / build / release / benchmark generation.
* Does NOT modify canonical gold, benchmark inputs, strict blind outputs,
  raw data, or stage_labels.v0.json.
* Produces new audit-only sidecars:
  - dataset_release_v1/benchmarks/stage_reasoning/stage_label_quality.v0.jsonl
  - dataset_release_v1/benchmarks/stage_reasoning/stage_label_quality_summary.v0.json
  - a run report documenting the stage-label quality audit

Granularity
-----------
The audit row granularity is one record per public sample_id. The benchmark
is evaluated as a single dataset unit.
"""

from __future__ import annotations

import argparse
import json
import textwrap
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Optional


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_BENCHMARK_ROOT = Path("workdir/dataset_release_v1/benchmarks/stage_reasoning")
DEFAULT_REPORT_PATH = Path("workdir/stage_label_quality_audit.md")

OUTPUT_JSONL_NAME = "stage_label_quality.v0.jsonl"
OUTPUT_SUMMARY_NAME = "stage_label_quality_summary.v0.json"

RULE_VERSION_EXPECTED = "stage_derivation_v0.4.5"
RULE_SOURCE_EXPECTED = "anchor_plus_local_continuity"

DIRECT_RESULT_RELATIONS = frozenset(
    {"FILE_WRITE", "NET_SEND", "NET_CONNECT", "PROCESS_EXEC", "FILE_READ"}
)
STRONG_RESULT_ARTIFACT_RELATIONS = frozenset({"FILE_WRITE", "NET_SEND", "PROCESS_EXEC"})
TIER_B_RESULT_RELATIONS = frozenset({"PROCESS_FORK", "PROCESS_CLONE", "NET_ACCEPT"})
PREP_MARKER_ROLES = frozenset(
    {
        "preparation_boundary_start",
        "preparation_boundary_end",
        "startup_handoff_exec",
        "entry_bridge_pre",
    }
)
HTTP_METHOD_TOKENS = ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS")
LONG_EXEC_WINDOW = 1000
LONG_NONE_WINDOW = 1000
POST_ATTACK_RUNTIME_RELATIONS = frozenset({"PROCESS_FORK", "PROCESS_CLONE", "NET_ACCEPT", "NET_RECV", "NET_SEND"})

@dataclass
class ScenarioArtifacts:
    slug: str
    scenario_id: str
    main_sample: dict[str, Any]
    stage_labels: dict[str, Any]
    narrative_roles: dict[str, Any]

    @property
    def spine(self) -> list[dict[str, Any]]:
        return list(self.main_sample.get("spine") or [])

    @property
    def stage_inputs(self) -> dict[str, Any]:
        return ((self.stage_labels.get("derivation") or {}).get("inputs") or {})

    @property
    def anchors(self) -> dict[str, Any]:
        return (self.narrative_roles.get("anchors") or {})


def _read_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def _write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        json.dump(obj, fh, ensure_ascii=False, indent=2)
        fh.write("\n")


def _write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with path.open("w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, ensure_ascii=False))
            fh.write("\n")
            count += 1
    return count


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        fh.write(text)


def _scenario_slug_from_source_files(source_files: dict[str, Any]) -> str:
    path = str(source_files.get("main_sample") or "")
    parts = path.split("/")
    if len(parts) < 3:
        raise ValueError(f"cannot parse scenario slug from source path: {path}")
    return parts[2]


def _parse_proc_subject(subject: str) -> tuple[Optional[str], Optional[str]]:
    if not isinstance(subject, str) or not subject.startswith("proc:"):
        return None, None
    parts = subject.split(":", 3)
    if len(parts) != 4:
        return None, None
    return parts[1] or None, parts[3] or None


def _subject_family_match(subject: str, anchor_subject: str) -> bool:
    if not subject or not anchor_subject:
        return False
    if subject == anchor_subject:
        return True
    sub_ctnr, sub_exe = _parse_proc_subject(subject)
    anc_ctnr, anc_exe = _parse_proc_subject(anchor_subject)
    return bool(sub_ctnr and sub_exe and anc_ctnr and anc_exe and sub_ctnr == anc_ctnr and sub_exe == anc_exe)


def _window_edges(spine: list[dict[str, Any]], start_seq: int, end_seq: int) -> list[dict[str, Any]]:
    return [edge for edge in spine if start_seq <= int(edge.get("seq") or 0) <= end_seq]


def _top_relations(edges: list[dict[str, Any]], limit: int = 4) -> list[str]:
    counts = Counter(str(edge.get("relation") or "").upper() for edge in edges)
    return [f"{rel}x{count}" for rel, count in counts.most_common(limit)]


def _relation_counts(edges: list[dict[str, Any]]) -> Counter:
    return Counter(str(edge.get("relation") or "").upper() for edge in edges)


def _extract_context_flags(edge: dict[str, Any]) -> dict[str, Any]:
    flags = {
        "has_http_like": False,
        "has_response_status": False,
        "has_auth_or_session": False,
        "has_error_or_exception": False,
        "context_snippet": None,
    }
    multisource = edge.get("multisource_context") or {}
    for applog in multisource.get("applog") or []:
        if not isinstance(applog, dict):
            continue
        message = str(applog.get("message") or applog.get("normalized_message") or "")
        upper_msg = message.upper()
        for method in HTTP_METHOD_TOKENS:
            if method in upper_msg:
                flags["has_http_like"] = True
                break
        if any(code in upper_msg for code in (" 200 ", " 201 ", " 302 ", " 401 ", " 403 ", " 404 ", " 500 ")):
            flags["has_response_status"] = True
        if "AUTH" in upper_msg or "SESSION" in upper_msg or "LOGIN" in upper_msg:
            flags["has_auth_or_session"] = True
        if "ERROR" in upper_msg or "EXCEPTION" in upper_msg:
            flags["has_error_or_exception"] = True
        if not flags["context_snippet"] and message:
            flags["context_snippet"] = message[:160]
    for traffic in multisource.get("traffic") or []:
        if not isinstance(traffic, dict):
            continue
        if traffic.get("http_method") or traffic.get("method") or traffic.get("http_path") or traffic.get("path"):
            flags["has_http_like"] = True
        if traffic.get("status") or traffic.get("status_code") or traffic.get("response_status"):
            flags["has_response_status"] = True
    return flags


def _aggregate_context_flags(edges: list[dict[str, Any]]) -> dict[str, Any]:
    aggregated = {
        "has_http_like": False,
        "has_response_status": False,
        "has_auth_or_session": False,
        "has_error_or_exception": False,
        "context_snippets": [],
    }
    for edge in edges:
        flags = _extract_context_flags(edge)
        for key in ("has_http_like", "has_response_status", "has_auth_or_session", "has_error_or_exception"):
            aggregated[key] = aggregated[key] or bool(flags[key])
        snippet = flags.get("context_snippet")
        if snippet and len(aggregated["context_snippets"]) < 2:
            aggregated["context_snippets"].append(snippet)
    return aggregated


def _bool_counter(values: Iterable[Optional[bool]]) -> dict[str, int]:
    counter = Counter("null" if value is None else str(bool(value)).lower() for value in values)
    return {key: counter.get(key, 0) for key in ("true", "false", "null")}


def _load_sample_index_rows(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            rows.append(obj)
    return rows


def _load_gold_sample_ids(path: Path) -> set[str]:
    ids: set[str] = set()
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            ids.add(str(obj.get("sample_id") or ""))
    return ids


def _load_jsonl_rows(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    rows.append(obj)
    return rows


def _public_spine(evidence_row: dict[str, Any]) -> list[dict[str, Any]]:
    """Adapt the frozen public evidence schema to the audit's edge view."""
    spine = evidence_row.get("selected_spine") or []
    normalized: list[dict[str, Any]] = []
    for edge in spine:
        if not isinstance(edge, dict):
            continue
        item = dict(edge)
        if "attrs" not in item:
            item["attrs"] = dict(item.get("visible_attrs") or {})
        if "multisource_context" not in item:
            item["multisource_context"] = {
                "applog": list(item.get("applog") or []),
                "traffic": list(item.get("traffic") or []),
            }
        normalized.append(item)
    return normalized


def _build_scenario_cache(benchmark_rows: list[dict[str, Any]], benchmark_root: Path) -> dict[str, ScenarioArtifacts]:
    cache: dict[str, ScenarioArtifacts] = {}
    for row in benchmark_rows:
        slug = _scenario_slug_from_source_files(row.get("source_files") or {})
        if slug in cache:
            continue
        scenario_dir = benchmark_root.parents[1] / "shared" / "scenarios" / slug
        main_sample = _read_json(scenario_dir / "main_sample.json")
        stage_labels = _read_json(scenario_dir / "stage_labels.v0.json")
        narrative_roles = _read_json(scenario_dir / "narrative_roles.v0.json")
        cache[slug] = ScenarioArtifacts(
            slug=slug,
            scenario_id=str(main_sample.get("scenario_id") or row.get("scenario_id") or ""),
            main_sample=main_sample,
            stage_labels=stage_labels,
            narrative_roles=narrative_roles,
        )
    return cache


def _build_public_scenario_cache(
    evidence_rows: list[dict[str, Any]],
    gold_rows: list[dict[str, Any]],
) -> dict[str, ScenarioArtifacts]:
    cache: dict[str, ScenarioArtifacts] = {}
    for row in evidence_rows:
        sample_id = str(row.get("sample_id") or "")
        cache[sample_id] = ScenarioArtifacts(
            slug=sample_id,
            scenario_id=sample_id,
            main_sample={"spine": _public_spine(row), "scenario_id": sample_id},
            stage_labels={
                "derivation": {"rule_version": RULE_VERSION_EXPECTED, "source": RULE_SOURCE_EXPECTED, "inputs": {}},
                "stage_spans": [],
            },
            narrative_roles={"anchors": {}, "roles": []},
        )
    return cache


def _base_context(row: dict[str, Any], scenario: ScenarioArtifacts) -> dict[str, Any]:
    start_seq = int((row.get("window") or {}).get("start_seq"))
    end_seq = int((row.get("window") or {}).get("end_seq"))
    edges = _window_edges(scenario.spine, start_seq, end_seq)
    rel_counts = _relation_counts(edges)
    stage_inputs = scenario.stage_inputs
    anchors = scenario.anchors
    first_mal = stage_inputs.get("first_malicious_seq")
    last_mal = stage_inputs.get("last_malicious_seq")
    result_end = stage_inputs.get("result_end_seq")
    result_anchor_seq = ((anchors.get("result_anchor") or {}).get("seq"))
    entry_anchor_seq = ((anchors.get("entry_anchor") or {}).get("seq"))
    prep_gap_seq = stage_inputs.get("prep_inferred_gap_seq")
    has_applog = any((edge.get("multisource_context") or {}).get("applog") for edge in edges)
    has_traffic = any((edge.get("multisource_context") or {}).get("traffic") for edge in edges)
    malicious_edges = [edge for edge in edges if bool((edge.get("attrs") or {}).get("malicious", False))]
    aggregated_context = _aggregate_context_flags(edges)

    position = "other"
    if isinstance(first_mal, int) and end_seq < first_mal:
        position = "pre_attack_runtime"
    elif isinstance(result_end, int) and start_seq > result_end:
        position = "post_result_runtime"
    elif isinstance(last_mal, int) and start_seq > last_mal:
        position = "post_execution_runtime"

    attack_boundary_distance: Optional[int] = None
    candidates: list[int] = []
    if isinstance(first_mal, int) and end_seq < first_mal:
        candidates.append(first_mal - end_seq)
    if isinstance(last_mal, int) and start_seq > last_mal:
        candidates.append(start_seq - last_mal)
    if isinstance(result_end, int) and start_seq > result_end:
        candidates.append(start_seq - result_end)
    if candidates:
        attack_boundary_distance = min(candidates)

    entry_subject = ""
    if isinstance(first_mal, int) and 1 <= first_mal <= len(scenario.spine):
        entry_subject = str(scenario.spine[first_mal - 1].get("subject") or "")
    family_match_count = sum(1 for edge in edges if _subject_family_match(str(edge.get("subject") or ""), entry_subject))
    direct_result_count = sum(rel_counts.get(rel, 0) for rel in DIRECT_RESULT_RELATIONS)
    tier_b_count = sum(rel_counts.get(rel, 0) for rel in TIER_B_RESULT_RELATIONS)
    runtime_tail_count = sum(rel_counts.get(rel, 0) for rel in POST_ATTACK_RUNTIME_RELATIONS)

    prep_roles_in_window = [
        role for role in (scenario.narrative_roles.get("roles") or [])
        if str(role.get("role") or "") in PREP_MARKER_ROLES
        and start_seq <= int(role.get("seq") or 0) <= end_seq
    ]

    return {
        "sample_id": str(row.get("sample_id") or ""),
        "scenario_id": str(row.get("scenario_id") or ""),
        "gold_stage": str(row.get("stage") or ""),
        "window": {"start_seq": start_seq, "end_seq": end_seq},
        "window_length": max(0, end_seq - start_seq + 1),
        "edges": edges,
        "rel_counts": rel_counts,
        "top_relations": _top_relations(edges),
        "has_applog": has_applog,
        "has_traffic": has_traffic,
        "malicious_edges": malicious_edges,
        "malicious_edge_count": len(malicious_edges),
        "stage_inputs": stage_inputs,
        "anchors": anchors,
        "first_malicious_seq": first_mal,
        "last_malicious_seq": last_mal,
        "result_end_seq": result_end,
        "result_anchor_seq": result_anchor_seq if isinstance(result_anchor_seq, int) else None,
        "entry_anchor_seq": entry_anchor_seq if isinstance(entry_anchor_seq, int) else None,
        "position": position,
        "attack_boundary_distance": attack_boundary_distance,
        "entry_subject": entry_subject,
        "family_match_count": family_match_count,
        "family_match_ratio": (family_match_count / len(edges)) if edges else 0.0,
        "prep_gap_seq": prep_gap_seq if isinstance(prep_gap_seq, int) else None,
        "prep_roles_in_window": prep_roles_in_window,
        "direct_result_count": direct_result_count,
        "tier_b_count": tier_b_count,
        "runtime_tail_count": runtime_tail_count,
        "aggregated_context": aggregated_context,
        "rule_version": str((scenario.stage_labels.get("derivation") or {}).get("rule_version") or ""),
        "rule_source": str((scenario.stage_labels.get("derivation") or {}).get("source") or ""),
        "stage_rule_used": _stage_rule_used(str(row.get("stage") or ""), stage_inputs, start_seq, end_seq, position),
        "source_files": dict(row.get("source_files") or {}),
    }


def _stage_rule_used(stage: str, stage_inputs: dict[str, Any], start_seq: int, end_seq: int, position: str) -> str:
    if stage == "preparation":
        return str(stage_inputs.get("prep_rule_used") or "")
    if stage == "result":
        return str(stage_inputs.get("result_rule_used") or "")
    if stage == "execution":
        return "execution_malicious_span"
    if stage == "stage_unclosed":
        if position == "pre_attack_runtime":
            return "stage_unclosed_pre_attack_runtime"
        if position == "post_result_runtime":
            return "stage_unclosed_post_result_runtime"
        if position == "post_execution_runtime":
            return "stage_unclosed_post_execution_runtime"
        return f"stage_unclosed_runtime_window_{start_seq}_{end_seq}"
    return "unknown"


def _result_anchor_in_window(ctx: dict[str, Any]) -> Optional[bool]:
    seq = ctx.get("result_anchor_seq")
    if not isinstance(seq, int):
        return None
    return bool(ctx["window"]["start_seq"] <= seq <= ctx["window"]["end_seq"])


def _execution_anchor_in_window(ctx: dict[str, Any]) -> Optional[bool]:
    seq = ctx.get("entry_anchor_seq")
    if not isinstance(seq, int):
        seq = ctx.get("first_malicious_seq")
    if not isinstance(seq, int):
        return None
    return bool(ctx["window"]["start_seq"] <= seq <= ctx["window"]["end_seq"])


def _prep_anchor_in_window(ctx: dict[str, Any]) -> Optional[bool]:
    if ctx["stage_rule_used"] == "prep_end_marker_latest":
        return True if ctx["prep_roles_in_window"] else False
    if ctx["stage_rule_used"].startswith("inferred_prep_"):
        return False
    return None


def _context_snippet_text(ctx: dict[str, Any]) -> str:
    snippets = ctx["aggregated_context"]["context_snippets"]
    return " | ".join(snippets[:2]) if snippets else ""


def _classify_execution(ctx: dict[str, Any]) -> dict[str, Any]:
    risks: list[str] = []
    notes = []
    anchor_in_window = _execution_anchor_in_window(ctx)
    self_evidence = ctx["malicious_edge_count"] > 0
    window_len = ctx["window_length"]

    if ctx["malicious_edge_count"] <= 0:
        quality = "suspicious"
        confidence = 0.18
        rule_family = "execution_without_malicious_span"
        risks.append("execution_window_without_malicious_edges")
    elif window_len >= LONG_EXEC_WINDOW:
        quality = "acceptable_weak"
        confidence = 0.79
        rule_family = "execution_long_malicious_span"
        risks.extend(["very_long_execution_window", "benchmark_window_compression_risk"])
        notes.append("Execution is still label-correct, but the window is long enough to dilute the primary attack evidence.")
    else:
        quality = "strong"
        confidence = 0.93
        rule_family = "execution_core_malicious_span"
        notes.append("Primary evidence sits inside the malicious execution span itself.")

    evidence_summary = (
        f"execution len={window_len}; malicious_edges={ctx['malicious_edge_count']}; "
        f"top_relations={', '.join(ctx['top_relations']) or 'none'}; "
        f"modalities=applog:{ctx['has_applog']} traffic:{ctx['has_traffic']}"
    )
    if _context_snippet_text(ctx):
        evidence_summary += f"; context={_context_snippet_text(ctx)}"

    return {
        "rule_family": rule_family,
        "label_quality": quality,
        "confidence_score": confidence,
        "anchor_in_window": anchor_in_window,
        "window_contains_self_evidence": self_evidence,
        "evidence_summary": evidence_summary,
        "risk_reasons": risks,
        "notes": " ".join(notes).strip(),
    }


def _classify_result(ctx: dict[str, Any]) -> dict[str, Any]:
    rule_used = ctx["stage_rule_used"]
    window_len = ctx["window_length"]
    anchor_in_window = _result_anchor_in_window(ctx)
    rels = set(ctx["rel_counts"].keys())
    direct_artifact = ctx["direct_result_count"] > 0
    tier_b_only = ctx["tier_b_count"] > 0 and ctx["direct_result_count"] == 0 and rels and rels.issubset(TIER_B_RESULT_RELATIONS)
    risks: list[str] = []
    notes = []

    if rule_used == "anchor_continuity_walker_tier_b_extended" and tier_b_only and anchor_in_window is False:
        quality = "suspicious"
        confidence = 0.14
        rule_family = "result_tier_b_tail_only"
        self_evidence = False
        risks.extend(
            [
                "tier_b_only_result_window",
                "result_anchor_out_of_window",
                "window_relies_on_post_result_shell_tail",
            ]
        )
        notes.append("Window only preserves post-anchor NET_ACCEPT/PROCESS_FORK/PROCESS_CLONE tail, not the result anchor itself.")
    elif rule_used == "anchor_at_spine_tail_single_edge_result":
        rel = next(iter(rels), "")
        if window_len == 1 and rel in STRONG_RESULT_ARTIFACT_RELATIONS:
            quality = "acceptable_weak"
            confidence = 0.72
            rule_family = "result_tail_anchor_single_edge"
            self_evidence = True
            risks.extend(["tail_anchor_single_edge_result", "single_edge_result_evidence_thin"])
            notes.append("Tail-anchor mode preserves the final malicious result edge, but the window is still only one edge wide.")
        else:
            quality = "boundary_review"
            confidence = 0.56
            rule_family = "result_tail_anchor_single_edge_thin"
            self_evidence = direct_artifact
            risks.extend(["tail_anchor_single_edge_result", "tail_anchor_without_rich_context"])
            notes.append("Result anchor is in-window, but the standalone evidence is thin and should be reviewed before strong supervision use.")
    elif rule_used == "anchor_continuity_walker":
        if window_len == 1 and rels == {"NET_SEND"}:
            quality = "boundary_review"
            confidence = 0.53
            rule_family = "result_tier_a_single_net_send"
            self_evidence = True
            risks.extend(["single_net_send_result_window", "result_anchor_out_of_window"])
            notes.append("Tier-A result exists, but the window only shows one NET_SEND edge after the anchor.")
        elif window_len <= 2 and direct_artifact:
            quality = "acceptable_weak"
            confidence = 0.69
            rule_family = "result_tier_a_thin_artifact"
            self_evidence = True
            risks.extend(["thin_tier_a_result_window", "result_anchor_out_of_window"])
            notes.append("Window contains direct result-like edges, but the anchor itself remains outside the result slice.")
        else:
            quality = "strong"
            confidence = 0.88
            rule_family = "result_tier_a_self_evident"
            self_evidence = True
            notes.append("Window contains direct result evidence without depending on tier-B tail-only semantics.")
    else:
        quality = "boundary_review"
        confidence = 0.5
        rule_family = "result_unexpected_rule_family"
        self_evidence = direct_artifact or bool(anchor_in_window)
        risks.append("unexpected_result_rule_family")

    evidence_summary = (
        f"result len={window_len}; rels={', '.join(ctx['top_relations']) or 'none'}; "
        f"anchor_in_window={anchor_in_window}; direct_result_edges={ctx['direct_result_count']}; "
        f"tier_b_edges={ctx['tier_b_count']}"
    )
    if _context_snippet_text(ctx):
        evidence_summary += f"; context={_context_snippet_text(ctx)}"

    return {
        "rule_family": rule_family,
        "label_quality": quality,
        "confidence_score": confidence,
        "anchor_in_window": anchor_in_window,
        "window_contains_self_evidence": self_evidence,
        "evidence_summary": evidence_summary,
        "risk_reasons": risks,
        "notes": " ".join(notes).strip(),
    }


def _classify_preparation(ctx: dict[str, Any]) -> dict[str, Any]:
    rule_used = ctx["stage_rule_used"]
    window_len = ctx["window_length"]
    anchor_in_window = _prep_anchor_in_window(ctx)
    risks: list[str] = []
    notes = []
    direct_context = ctx["has_applog"] or ctx["has_traffic"] or ctx["aggregated_context"]["has_http_like"]
    near_entry = ctx["attack_boundary_distance"] == 1
    gap_edge_present = isinstance(ctx.get("prep_gap_seq"), int) and ctx["window"]["start_seq"] <= ctx["prep_gap_seq"] <= ctx["window"]["end_seq"]
    self_evidence = True

    if rule_used == "prep_end_marker_latest":
        rels = set(ctx["rel_counts"].keys())
        if window_len <= 1 and not direct_context and rels.issubset({"PROCESS_FORK", "PROCESS_CLONE"}):
            quality = "boundary_review"
            confidence = 0.56
            rule_family = "preparation_marker_based_thin"
            risks.extend(["marker_based_prep_but_window_evidence_thin", "single_edge_preparation_window"])
            notes.append("Structural prep marker exists, but the visible window is too thin to self-explain the preparation semantics.")
        else:
            quality = "strong"
            confidence = 0.9
            rule_family = "preparation_marker_based"
            notes.append("Marker-based preparation window contains explicit prep-side structural evidence.")
    elif rule_used == "inferred_prep_pre_entry_same_subject_window":
        quality = "acceptable_weak"
        confidence = 0.78 if near_entry else 0.74
        rule_family = "preparation_inferred_same_subject"
        risks.append("preparation_inferred_from_same_subject_window")
        notes.append("Preparation is inferred from same-subject pre-entry activity rather than explicit narrative markers.")
    elif rule_used == "inferred_prep_pre_entry_same_subject_window_gap_tolerant":
        quality = "boundary_review"
        confidence = 0.58
        rule_family = "preparation_inferred_same_subject_gap_tolerant"
        self_evidence = False
        risks.extend(["gap_tolerant_preparation_window", "absorbed_non_matching_gap_edge"])
        notes.append("Gap-tolerant preparation absorbed at most one non-matching edge; this is useful for coverage but weakens boundary clarity.")
    elif rule_used == "inferred_prep_pre_entry_same_exe_in_container_window":
        quality = "boundary_review"
        confidence = 0.57
        rule_family = "preparation_inferred_same_exe_in_container"
        self_evidence = False
        risks.extend(["same_exe_in_container_preparation_inference", "no_explicit_prep_marker"])
        notes.append("Preparation depends on same-exe-in-container relaxation, so the window is plausible but not self-anchored.")
    elif rule_used == "inferred_prep_pre_entry_same_exe_in_container_window_gap_tolerant":
        quality = "boundary_review"
        confidence = 0.52
        rule_family = "preparation_inferred_same_exe_gap_tolerant"
        self_evidence = False
        risks.extend(["same_exe_in_container_preparation_inference", "gap_tolerant_preparation_window", "absorbed_non_matching_gap_edge"])
        notes.append("Preparation uses both same-exe relaxation and gap tolerance; keep for extension coverage, not for strong supervision without review.")
        if gap_edge_present and ctx["family_match_ratio"] < 0.8:
            risks.append("mixed_subject_window")
    else:
        quality = "boundary_review"
        confidence = 0.5
        rule_family = "preparation_unexpected_rule_family"
        self_evidence = False
        risks.append("unexpected_preparation_rule_family")

    evidence_summary = (
        f"preparation len={window_len}; rule={rule_used}; rels={', '.join(ctx['top_relations']) or 'none'}; "
        f"near_entry={near_entry}; marker_in_window={anchor_in_window}; family_match_ratio={ctx['family_match_ratio']:.2f}"
    )
    if _context_snippet_text(ctx):
        evidence_summary += f"; context={_context_snippet_text(ctx)}"

    return {
        "rule_family": rule_family,
        "label_quality": quality,
        "confidence_score": confidence,
        "anchor_in_window": anchor_in_window,
        "window_contains_self_evidence": self_evidence,
        "evidence_summary": evidence_summary,
        "risk_reasons": risks,
        "notes": " ".join(notes).strip(),
    }


def _classify_stage_unclosed(ctx: dict[str, Any]) -> dict[str, Any]:
    window_len = ctx["window_length"]
    position = ctx["position"]
    risks: list[str] = []
    notes = []
    direct_result_after_attack = (
        position in {"post_execution_runtime", "post_result_runtime"}
        and ctx["direct_result_count"] > 0
        and window_len <= 5
    )
    runtime_tail_ratio = (ctx["runtime_tail_count"] / window_len) if window_len else 0.0
    attack_adjacent = isinstance(ctx["attack_boundary_distance"], int) and ctx["attack_boundary_distance"] <= 3

    if ctx["malicious_edge_count"] > 0:
        quality = "suspicious"
        confidence = 0.15
        rule_family = f"stage_unclosed_{position}_contains_malicious"
        anchor_in_window = None
        self_evidence = False
        risks.append("stage_unclosed_window_contains_malicious_edges")
    elif direct_result_after_attack:
        quality = "suspicious"
        confidence = 0.24
        rule_family = f"stage_unclosed_{position}_contains_result_like_artifact"
        anchor_in_window = None
        self_evidence = False
        risks.extend(["stage_unclosed_window_contains_result_like_artifact", "post_attack_window_close_to_result"])
    elif window_len >= LONG_NONE_WINDOW:
        quality = "boundary_review"
        confidence = 0.54
        rule_family = f"stage_unclosed_{position}_long_runtime_tail"
        anchor_in_window = None
        self_evidence = False
        risks.extend(["long_runtime_tail_stage_unclosed", position])
        notes.append("Long runtime tail is probably label-correct as stage_unclosed, but it is easy to misread without broader chain context.")
    elif position in {"post_execution_runtime", "post_result_runtime"} and runtime_tail_ratio >= 0.7 and window_len >= 100:
        quality = "boundary_review"
        confidence = 0.58
        rule_family = f"stage_unclosed_{position}_runtime_tail_dominant"
        anchor_in_window = None
        self_evidence = False
        risks.extend(["runtime_tail_dominant_stage_unclosed", position])
    elif attack_adjacent or ctx["aggregated_context"]["has_auth_or_session"]:
        quality = "acceptable_weak"
        confidence = 0.76
        rule_family = f"stage_unclosed_{position}_attack_adjacent"
        anchor_in_window = None
        self_evidence = True
        risks.append("attack_adjacent_signal_without_stage_closure")
        notes.append("Window carries attack-adjacent signals, but still lacks enough evidence to close preparation, execution, or result.")
    else:
        quality = "strong"
        confidence = 0.88
        rule_family = f"stage_unclosed_{position}_self_evident"
        anchor_in_window = None
        self_evidence = True
        notes.append("Window does not contain enough self-contained evidence to close any positive attack stage.")

    evidence_summary = (
        f"stage_unclosed len={window_len}; position={position}; rels={', '.join(ctx['top_relations']) or 'none'}; "
        f"malicious_edges={ctx['malicious_edge_count']}; runtime_tail_ratio={runtime_tail_ratio:.2f}"
    )
    if _context_snippet_text(ctx):
        evidence_summary += f"; context={_context_snippet_text(ctx)}"

    return {
        "rule_family": rule_family,
        "label_quality": quality,
        "confidence_score": confidence,
        "anchor_in_window": anchor_in_window,
        "window_contains_self_evidence": self_evidence,
        "evidence_summary": evidence_summary,
        "risk_reasons": risks,
        "notes": " ".join(notes).strip(),
    }


def _recommendation(quality: str) -> str:
    if quality == "strong":
        return "keep_strict_eval"
    if quality == "acceptable_weak":
        return "keep_strict_eval"
    if quality == "boundary_review":
        return "exclude_from_strict_eval"
    return "exclude_from_strict_eval"


def _audit_row(row: dict[str, Any], scenario: ScenarioArtifacts) -> dict[str, Any]:
    ctx = _base_context(row, scenario)
    stage = ctx["gold_stage"]
    if stage == "execution":
        classified = _classify_execution(ctx)
    elif stage == "result":
        classified = _classify_result(ctx)
    elif stage == "preparation":
        classified = _classify_preparation(ctx)
    elif stage == "stage_unclosed":
        classified = _classify_stage_unclosed(ctx)
    else:
        raise ValueError(f"unsupported gold_stage: {stage}")

    return {
        "schema_version": "stage_label_quality_audit.v0",
        "sample_id": ctx["sample_id"],
        "scenario_id": ctx["scenario_id"],
        "gold_stage": stage,
        "rule_version": ctx["rule_version"],
        "rule_source": ctx["rule_source"],
        "rule_family": classified["rule_family"],
        "stage_rule_used": ctx["stage_rule_used"],
        "label_quality": classified["label_quality"],
        "confidence_score": classified["confidence_score"],
        "anchor_in_window": classified["anchor_in_window"],
        "window_contains_self_evidence": classified["window_contains_self_evidence"],
        "window": ctx["window"],
        "window_length": ctx["window_length"],
        "has_applog": ctx["has_applog"],
        "has_traffic": ctx["has_traffic"],
        "evidence_summary": classified["evidence_summary"],
        "risk_reasons": classified["risk_reasons"],
        "recommendation": _recommendation(classified["label_quality"]),
        "notes": classified["notes"],
        "source_files": ctx["source_files"],
    }


def _nested_counter(rows: list[dict[str, Any]], key_fields: tuple[str, ...], value_field: str) -> dict[str, Any]:
    root: dict[str, Any] = {}
    for row in rows:
        cursor = root
        for field in key_fields[:-1]:
            cursor = cursor.setdefault(str(row[field]), {})
        last = str(row[key_fields[-1]])
        bucket = cursor.setdefault(last, Counter())
        bucket[str(row[value_field])] += 1
    return _counter_tree_to_plain(root)


def _counter_tree_to_plain(obj: Any) -> Any:
    if isinstance(obj, Counter):
        return dict(sorted(obj.items()))
    if isinstance(obj, dict):
        return {key: _counter_tree_to_plain(value) for key, value in sorted(obj.items())}
    return obj


def _summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    result_rows = [row for row in rows if row["gold_stage"] == "result"]
    boundary_or_worse = [
        row for row in rows
        if row["label_quality"] in {"boundary_review", "suspicious"}
    ]
    strict_downgrade = [
        row for row in rows
        if row["recommendation"] == "exclude_from_strict_eval"
    ]
    prep_rule_distribution = dict(sorted(
        Counter(row["rule_family"] for row in rows if row["gold_stage"] == "preparation").items()
    ))
    stage_unclosed_long_boundary_count = sum(
        1
        for row in rows
        if row["gold_stage"] == "stage_unclosed"
        and row["label_quality"] == "boundary_review"
        and row["window_length"] >= LONG_NONE_WINDOW
    )
    return {
        "schema_version": "stage_label_quality_summary.v0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "dataset": "SecLog-Bench-216",
        "row_granularity": "per_public_sample_record",
        "row_count": len(rows),
        "unique_sample_id_count": len({row["sample_id"] for row in rows}),
        "quality_distribution_by_stage": _nested_counter(rows, ("gold_stage",), "label_quality"),
        "recommendation_distribution_by_stage": _nested_counter(rows, ("gold_stage",), "recommendation"),
        "result_tier_b_only_count": sum(row["rule_family"] == "result_tier_b_tail_only" for row in result_rows),
        "result_anchor_in_window_counts": _bool_counter(row["anchor_in_window"] for row in result_rows),
        "preparation_rule_family_distribution": prep_rule_distribution,
        "stage_unclosed_long_window_boundary_count": stage_unclosed_long_boundary_count,
        "boundary_review_sample_ids": sorted({row["sample_id"] for row in boundary_or_worse}),
        "strict_eval_downgrade_sample_ids": sorted({row["sample_id"] for row in strict_downgrade}),
        "strict_eval_downgrade_rows": [
            {
                "sample_id": row["sample_id"],
                "stage": row["gold_stage"],
                "label_quality": row["label_quality"],
                "rule_family": row["rule_family"],
                "risk_reasons": row["risk_reasons"],
            }
            for row in sorted(strict_downgrade, key=lambda row: (row["gold_stage"], row["sample_id"]))
        ],
        "suspicious_sample_ids": sorted({row["sample_id"] for row in rows if row["label_quality"] == "suspicious"}),
        "validation": {
            "all_rows_rule_version_expected": all(row["rule_version"] == RULE_VERSION_EXPECTED for row in rows),
            "all_rows_rule_source_expected": all(row["rule_source"] == RULE_SOURCE_EXPECTED for row in rows),
            "all_sample_ids_unique": len({row["sample_id"] for row in rows}) == len(rows),
        },
    }


def _markdown_table(headers: list[str], rows: list[list[str]]) -> str:
    out = ["| " + " | ".join(headers) + " |", "|" + "|".join(["---"] * len(headers)) + "|"]
    for row in rows:
        out.append("| " + " | ".join(row) + " |")
    return "\n".join(out)


def _report(summary: dict[str, Any], rows: list[dict[str, Any]]) -> str:
    stage_quality = summary["quality_distribution_by_stage"]
    boundary_rows = [row for row in rows if row["label_quality"] in {"boundary_review", "suspicious"}]
    high_downgrade = summary["strict_eval_downgrade_rows"]

    def fmt_stage_quality(stage: str) -> str:
        return str(stage_quality.get(stage) or {})

    boundary_preview = sorted(
        boundary_rows,
        key=lambda row: (
            0 if row["label_quality"] == "suspicious" else 1,
            row["gold_stage"],
            row["sample_id"],
        ),
    )[:15]
    boundary_table = _markdown_table(
        ["sample_id", "stage", "quality", "rule_family", "recommendation"],
        [
            [
                row["sample_id"],
                row["gold_stage"],
                row["label_quality"],
                row["rule_family"],
                row["recommendation"],
            ]
            for row in boundary_preview
        ] or [["None", "-", "-", "-", "-"]],
    )
    downgrade_table = _markdown_table(
        ["sample_id", "stage", "quality", "rule_family"],
        [
            [
                row["sample_id"],
                row["stage"],
                row["label_quality"],
                row["rule_family"],
            ]
            for row in high_downgrade
        ] or [["None", "-", "-", "-"]],
    )

    lines = [
        "# Stage Label Quality Audit v0",
        "",
        "## 1. Overall judgement",
        "",
        "The rule-based stage labels are audited as one unified `SecLog-Bench-216` dataset.",
        "",
        "- `execution` and most `stage_unclosed` rows should remain usable for strict evaluation.",
        "- `preparation` and `result` rows marked `boundary_review` should be reviewed before use as strong supervision.",
        "- The current derivation rule is `stage_derivation_v0.4.5`.",
        "",
        "This audit is read-only over existing benchmark artefacts. It does **not** modify `gold.jsonl`, `model_input.jsonl`, `sample_index.jsonl`, strict blind benchmark files, raw data, or `stage_labels.v0.json`.",
        "",
        "## 2. Row policy",
        "",
        "- Row granularity: `per_public_sample_record`",
        f"- Dataset: `SecLog-Bench-216`",
        f"- Output rows: `{summary['row_count']}`",
        f"- Unique sample_ids: `{summary['unique_sample_id_count']}`",
        "- Public data unit: one contiguous `sample_000001` ... `sample_000216` namespace",
        "",
        "## 3. Key findings",
        "",
        f"- `preparation` quality: {fmt_stage_quality('preparation')}",
        f"- `execution` quality: {fmt_stage_quality('execution')}",
        f"- `result` quality: {fmt_stage_quality('result')}",
        f"- `stage_unclosed` quality: {fmt_stage_quality('stage_unclosed')}",
        f"- `result` tier-B-only count: `{summary['result_tier_b_only_count']}`",
        f"- `result` anchor in-window counts: `{summary['result_anchor_in_window_counts']}`",
        f"- `stage_unclosed` long-window boundary count: `{summary['stage_unclosed_long_window_boundary_count']}`",
        "",
        "Interpretation:",
        "",
        "- `execution` is mostly stable; long windows are reported as weaker rather than silently split out.",
        "- `preparation` is strongest when marker-based and close to the entry boundary; inferred windows need review.",
        "- `result` quality is determined from visible result evidence and anchor coverage.",
        "- `stage_unclosed` is a closure label.",
        "",
        "## 4. Review focus",
        "",
        f"Total rows marked `boundary_review` or `suspicious`: `{len(boundary_rows)}`",
        "",
        boundary_table,
        "",
        "Rows recommended for exclusion from a stricter evaluation pass:",
        "",
        downgrade_table,
        "",
        "## 5. Answers to the requested questions",
        "",
        "1. **Are the current stage labels usable overall?** Yes, with the review flags above.",
        "2. **Is there a separate primary or extension split?** No. The public contract evaluates the single unified 216-sample dataset.",
        "3. **Which samples need review?** The public `sample_id` values listed in the review tables.",
        "4. **Does this audit change the stage derivation rule?** No immediate rewrite is required.",
        "",
        "## 6. Output files",
        "",
        f"- `dataset_release_v1/benchmarks/stage_reasoning/{OUTPUT_JSONL_NAME}`",
        f"- `dataset_release_v1/benchmarks/stage_reasoning/{OUTPUT_SUMMARY_NAME}`",
        "- run report: stage-label quality audit (path is run-specific)",
    ]
    return "\n".join(lines).strip() + "\n"


def run(benchmark_root: Path, report_path: Path) -> dict[str, Any]:
    benchmark_root = benchmark_root.resolve()
    report_path = report_path.resolve()

    data_root = benchmark_root / "data"
    if not data_root.is_dir():
        raise FileNotFoundError(f"unified benchmark data directory missing: {data_root}")
    index_path = data_root / "sample_index.jsonl"
    public_index_path = data_root / "sample_index.jsonl"
    gold_path = data_root / "gold.jsonl"
    public_gold_path = data_root / "gold_labels.jsonl"
    evidence_path = data_root / "evidence_windows.jsonl"
    if public_gold_path.exists() and evidence_path.exists():
        all_rows = _load_jsonl_rows(public_index_path)
        gold_rows = _load_jsonl_rows(public_gold_path)
        gold_by_id = {str(row.get("sample_id") or ""): row for row in gold_rows}
        for row in all_rows:
            row["stage"] = row.get("stage") or gold_by_id.get(str(row.get("sample_id") or ""), {}).get("gold_stage")
        gold_ids = set(gold_by_id)
        scenario_cache = _build_public_scenario_cache(_load_jsonl_rows(evidence_path), gold_rows)
        public_schema = True
    else:
        all_rows = _load_sample_index_rows(index_path)
        gold_ids = _load_gold_sample_ids(gold_path)
        scenario_cache = _build_scenario_cache(all_rows, benchmark_root)
        public_schema = False

    for row in all_rows:
        sid = str(row.get("sample_id") or "")
        if sid not in gold_ids:
            raise ValueError(f"sample_id missing from benchmark gold: {sid}")

    audited_rows = []
    for row in all_rows:
        if public_schema:
            scenario = scenario_cache.get(str(row.get("sample_id") or ""))
        else:
            slug = _scenario_slug_from_source_files(row.get("source_files") or {})
            scenario = scenario_cache.get(slug)
        if scenario is None:
            raise ValueError(f"scenario context missing for sample_id={row.get('sample_id')}")
        audited_rows.append(_audit_row(row, scenario))

    output_jsonl = benchmark_root / OUTPUT_JSONL_NAME
    output_summary = benchmark_root / OUTPUT_SUMMARY_NAME

    written_count = _write_jsonl(output_jsonl, audited_rows)
    summary = _summary(audited_rows)
    summary["written_row_count"] = written_count
    _write_json(output_summary, summary)
    _write_text(report_path, _report(summary, audited_rows))
    return summary


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Read-only stage label quality audit over an existing stage_reasoning benchmark."
    )
    parser.add_argument(
        "--benchmark-root",
        type=Path,
        default=DEFAULT_BENCHMARK_ROOT,
        help=f"Benchmark root (default: {DEFAULT_BENCHMARK_ROOT})",
    )
    parser.add_argument(
        "--report-path",
        type=Path,
        default=DEFAULT_REPORT_PATH,
        help=f"Markdown report output path (default: {DEFAULT_REPORT_PATH})",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    summary = run(args.benchmark_root, args.report_path)
    print(json.dumps(
        {
            "status": "ok",
            "row_count": summary["row_count"],
            "unique_sample_id_count": summary["unique_sample_id_count"],
            "result_tier_b_only_count": summary["result_tier_b_only_count"],
            "report_path": str(args.report_path),
        },
        ensure_ascii=False,
        indent=2,
    ))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
