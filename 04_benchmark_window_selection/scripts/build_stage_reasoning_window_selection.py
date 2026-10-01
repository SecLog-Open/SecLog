#!/usr/bin/env python3
from __future__ import annotations

import argparse
import heapq
import json
import os
import re
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


WINDOW_SELECTION_SCHEMA = "stage_reasoning_window_selection.workbench.v1"
LEGAL_STAGES = ("preparation", "execution", "result", "stage_unclosed")
DEFAULT_RESULT_TIER_A_RELATIONS = frozenset(
    {"FILE_READ", "FILE_WRITE", "NET_CONNECT", "NET_SEND", "PROCESS_EXEC"}
)
DEFAULT_RESULT_TIER_B_RELATIONS = frozenset(
    {"NET_ACCEPT", "PROCESS_CLONE", "PROCESS_FORK"}
)
DEFAULT_PREP_END_ROLES = frozenset(
    {"preparation_boundary_end", "startup_handoff_exec", "entry_bridge_pre"}
)
DEFAULT_GENERIC_RUNTIME_RELATIONS = frozenset(
    {"NET_ACCEPT", "NET_CONNECT", "PROCESS_FORK", "PROCESS_CLONE"}
)
DEFAULT_REQUEST_LIKE_APPLOG_TYPES = frozenset(
    {"request_access", "error_exception", "db_query", "generic_runtime_log"}
)
DEFAULT_EXECUTION_SIGNAL_RELATIONS = frozenset(
    {"PROCESS_EXEC", "FILE_READ", "FILE_WRITE", "NET_CONNECT", "NET_ACCEPT"}
)
DEFAULT_RESULT_SIGNAL_RELATIONS = frozenset({"FILE_WRITE", "NET_SEND", "PROCESS_EXEC"})
EDGE_TEXT_CACHE: dict[tuple[Any, Any], str] = {}
EDGE_FEATURE_CACHE: dict[tuple[Any, Any], dict[str, int]] = {}
PREP_PAT = re.compile(
    r"probe|scan|check|login|auth|config|version|search|select|info|request begun|visitor|session|reach|access|credential|prepar|discover|get ",
    re.IGNORECASE,
)
EXEC_PAT = re.compile(
    r"exec|command|process_fork|clone|write|connect|post |put |delete |update|insert|payload|trigger|file_write|net_connect|net_recv|spawn|launch|runtime|solve",
    re.IGNORECASE,
)
RESULT_PAT = re.compile(
    r"result|success|response|send|content_length|file_write|file_read|state|artifact|delivered|complete|rendering|finished|created|modified|download|exfil|returned",
    re.IGNORECASE,
)
GENERIC_PAT = re.compile(r"accept|fork|status|traffic|close|/dev/null|received a null security object", re.IGNORECASE)


@dataclass
class ScenarioRecord:
    scenario_id: str
    scenario_slug: str
    chain_dir: Path
    behavior_dataset: dict[str, Any]
    backbone_chain: dict[str, Any]


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")
            count += 1
    return count


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def rel(path: Path, root: Path) -> str:
    return os.path.relpath(path.resolve(), root.resolve()).replace("\\", "/")


def released_stage_root(script_path: Path) -> Path:
    """Return this released stage directory, independent of its folder name."""
    return script_path.resolve().parents[1]


def load_config(config_path: Path) -> dict[str, Any]:
    return read_json(config_path)


def config_set(config: dict[str, Any], key: str, default: frozenset[str]) -> frozenset[str]:
    values = config.get(key)
    if not isinstance(values, list):
        return default
    return frozenset(str(value) for value in values)


def scenario_slug_from_id(scenario_id: str) -> str:
    return scenario_id.replace("/", "__").replace(":", "_").replace(" ", "_")


def derive_scenario_id(chain_dir: Path, results_root: Path) -> str:
    rel_parts = list(chain_dir.resolve().relative_to(results_root.resolve()).parts)
    if rel_parts and rel_parts[-1] == "chain":
        rel_parts = rel_parts[:-1]
    if rel_parts and "_" in rel_parts[-1] and "-" in rel_parts[-1]:
        rel_parts = rel_parts[:-1]
    return "/".join(rel_parts)


def discover_chain_dirs(results_root: Path) -> list[Path]:
    return sorted(path for path in results_root.rglob("chain") if path.is_dir())


def load_scenarios(results_root: Path, scenario_limit: int | None) -> list[ScenarioRecord]:
    dirs = discover_chain_dirs(results_root)
    if scenario_limit is not None:
        dirs = dirs[:scenario_limit]
    rows: list[ScenarioRecord] = []
    for chain_dir in dirs:
        behavior_path = chain_dir / "behavior_chain_dataset.v2.json"
        backbone_path = chain_dir / "backbone_chain.v1.json"
        if not behavior_path.exists() or not backbone_path.exists():
            continue
        scenario_id = derive_scenario_id(chain_dir, results_root)
        scenario_slug = scenario_slug_from_id(scenario_id)
        rows.append(
            ScenarioRecord(
                scenario_id=scenario_id,
                scenario_slug=scenario_slug,
                chain_dir=chain_dir,
                behavior_dataset=read_json(behavior_path),
                backbone_chain=read_json(backbone_path),
            )
        )
    return rows


def find_role_seq(backbone: dict[str, Any], role_name: str) -> Optional[int]:
    for row in ((backbone.get("chain_summary") or {}).get("narrative_roles") or {}).get("annotated_edges") or []:
        if row.get("role") == role_name:
            try:
                return int(row.get("seq"))
            except (TypeError, ValueError):
                return None
    return None


def backbone_expression(backbone: dict[str, Any]) -> dict[str, Any]:
    return ((backbone.get("chain_summary") or {}).get("expression_clarity") or {})


def local_stage_seed_from_chain(record: ScenarioRecord, config: dict[str, Any]) -> dict[str, Any]:
    spine = record.behavior_dataset.get("spine") or []
    expr = backbone_expression(record.backbone_chain)
    first_mal = expr.get("first_malicious_seq")
    last_mal = expr.get("last_malicious_seq")
    try:
        first_mal = int(first_mal) if first_mal is not None else None
        last_mal = int(last_mal) if last_mal is not None else None
    except (TypeError, ValueError):
        first_mal = None
        last_mal = None
    if first_mal is None or last_mal is None:
        malicious_seqs = [int(edge.get("seq")) for edge in spine if (edge.get("attrs") or {}).get("malicious") is True]
        if malicious_seqs:
            first_mal = min(malicious_seqs)
            last_mal = max(malicious_seqs)
    prep_end_roles = config_set(config, "prep_end_roles", DEFAULT_PREP_END_ROLES)
    result_tier_a_relations = config_set(config, "result_tier_a_relations", DEFAULT_RESULT_TIER_A_RELATIONS)
    result_tier_b_relations = config_set(config, "result_tier_b_relations", DEFAULT_RESULT_TIER_B_RELATIONS)
    prep_end_candidates = [find_role_seq(record.backbone_chain, role) for role in prep_end_roles]
    prep_end_candidates = [seq for seq in prep_end_candidates if isinstance(seq, int) and first_mal and seq < first_mal]
    prep_start = max(prep_end_candidates) if prep_end_candidates else None
    result_anchor_seq = find_role_seq(record.backbone_chain, "result_anchor")
    stage_spans: list[dict[str, Any]] = []
    if first_mal is None or last_mal is None:
        stage_spans.append({"stage": "stage_unclosed", "start_seq": 1, "end_seq": len(spine), "source": "fallback_no_malicious_anchor"})
    else:
        if prep_start is not None and prep_start > 1:
            stage_spans.append({"stage": "stage_unclosed", "start_seq": 1, "end_seq": prep_start - 1, "source": "pre_attack_runtime"})
        elif first_mal > 1:
            stage_spans.append({"stage": "stage_unclosed", "start_seq": 1, "end_seq": first_mal - 1, "source": "pre_execution_runtime"})
        if prep_start is not None and prep_start < first_mal:
            stage_spans.append({"stage": "preparation", "start_seq": prep_start, "end_seq": first_mal - 1, "source": "prep_boundary_to_entry"})
        if first_mal <= last_mal:
            stage_spans.append({"stage": "execution", "start_seq": first_mal, "end_seq": last_mal, "source": "malicious_span"})
        if result_anchor_seq is not None and last_mal == result_anchor_seq and last_mal == len(spine) and first_mal < last_mal:
            stage_spans[-1] = {"stage": "execution", "start_seq": first_mal, "end_seq": last_mal - 1, "source": "tail_anchor_execution_shrunk"}
            stage_spans.append({"stage": "result", "start_seq": last_mal, "end_seq": last_mal, "source": "tail_anchor_single_edge"})
        else:
            result_edges: list[int] = []
            anchor_subject = None
            if result_anchor_seq and 1 <= result_anchor_seq <= len(spine):
                anchor_subject = (spine[result_anchor_seq - 1] or {}).get("subject")
            for edge in spine[last_mal:]:
                seq = int(edge.get("seq"))
                relation = str(edge.get("relation"))
                if relation in result_tier_a_relations and anchor_subject and edge.get("subject") == anchor_subject:
                    result_edges.append(seq)
                elif result_edges and relation in result_tier_b_relations and edge.get("subject") == anchor_subject:
                    result_edges.append(seq)
                elif result_edges:
                    break
            if result_edges:
                stage_spans.append(
                    {
                        "stage": "result",
                        "start_seq": min(result_edges),
                        "end_seq": max(result_edges),
                        "source": "post_execution_result_like_walk",
                    }
                )
                if max(result_edges) < len(spine):
                    stage_spans.append(
                        {
                            "stage": "stage_unclosed",
                            "start_seq": max(result_edges) + 1,
                            "end_seq": len(spine),
                            "source": "post_result_runtime_tail",
                        }
                    )
            elif last_mal < len(spine):
                stage_spans.append(
                    {
                        "stage": "stage_unclosed",
                        "start_seq": last_mal + 1,
                        "end_seq": len(spine),
                        "source": "post_execution_no_safe_result_closure",
                    }
                )
    return {
        "scenario_id": record.scenario_id,
        "scenario_slug": record.scenario_slug,
        "derivation_source": "chain_local_fallback",
        "first_malicious_seq": first_mal,
        "last_malicious_seq": last_mal,
        "prep_start_seq": prep_start,
        "result_anchor_seq": result_anchor_seq,
        "stage_spans": [row for row in stage_spans if row["end_seq"] >= row["start_seq"]],
    }


def stage_seed_for_record(record: ScenarioRecord, config: dict[str, Any]) -> dict[str, Any]:
    return local_stage_seed_from_chain(record, config)


def edge_modalities(edge: dict[str, Any]) -> dict[str, int]:
    multisource = edge.get("multisource_context") or {}
    return {
        "audit_context": 1 if edge.get("audit_context") else 0,
        "applog": len(multisource.get("applog") or []),
        "traffic": len(multisource.get("traffic") or []),
    }


def edge_text(edge: dict[str, Any]) -> str:
    cache_key = (edge.get("seq"), edge.get("edge_id"))
    if cache_key in EDGE_TEXT_CACHE:
        return EDGE_TEXT_CACHE[cache_key]
    parts = [
        str(edge.get("seq", "")),
        str(edge.get("relation", "")),
        str(edge.get("subject", "")),
        str(edge.get("object", "")),
        json.dumps(edge.get("attrs") or {}, ensure_ascii=False, sort_keys=True),
    ]
    multisource = edge.get("multisource_context") or {}
    for item in (multisource.get("applog") or [])[:6]:
        parts.append(str(item.get("semantic_type", "")))
        parts.append(str(item.get("message", "")))
        parts.append(str(item.get("sanitized_message", "")))
    for item in (multisource.get("traffic") or [])[:4]:
        parts.append(json.dumps(item, ensure_ascii=False, sort_keys=True))
    for item in (edge.get("audit_context") or [])[:4]:
        parts.append(json.dumps(item, ensure_ascii=False, sort_keys=True))
    text = " ".join(parts).lower()
    EDGE_TEXT_CACHE[cache_key] = text
    return text


def text_feature_counts(edges: list[dict[str, Any]]) -> dict[str, int]:
    total = Counter()
    for edge in edges:
        cache_key = (edge.get("seq"), edge.get("edge_id"))
        if cache_key in EDGE_FEATURE_CACHE:
            total.update(EDGE_FEATURE_CACHE[cache_key])
            continue
        text = edge_text(edge)
        multisource = edge.get("multisource_context") or {}
        features = {
            "prep": len(PREP_PAT.findall(text)),
            "exec": len(EXEC_PAT.findall(text)),
            "result": len(RESULT_PAT.findall(text)),
            "generic": len(GENERIC_PAT.findall(text)),
            "attack": 1 if (edge.get("attrs") or {}).get("malicious") is True or "attack_related_level" in text else 0,
            "applog": len(multisource.get("applog") or []),
            "traffic": len(multisource.get("traffic") or []),
            "audit": len(edge.get("audit_context") or []),
        }
        EDGE_FEATURE_CACHE[cache_key] = features
        total.update(features)
    return dict(total)


def boundary_signals(edges: list[dict[str, Any]], config: dict[str, Any]) -> dict[str, bool]:
    relation_counts = Counter(str(edge.get("relation")) for edge in edges)
    text_counts = text_feature_counts(edges)
    text = " ".join(edge_text(edge) for edge in edges)
    result_signal_relations = config_set(config, "result_signal_relations", DEFAULT_RESULT_SIGNAL_RELATIONS)
    execution_signal_relations = config_set(config, "execution_signal_relations", DEFAULT_EXECUTION_SIGNAL_RELATIONS)
    strong_result_relations = {"FILE_READ", "NET_SEND"} | result_signal_relations
    request_or_payload = (
        text_counts.get("prep", 0) > 0
        or any(rel in relation_counts for rel in ("NET_ACCEPT", "NET_RECV"))
        or "inbound_request_flow" in text
        or " method: " in text
        or " url: " in text
    )
    strong_outcome = (
        any(rel in relation_counts for rel in strong_result_relations)
        and not set(relation_counts).issubset({"FILE_WRITE"})
    ) or any(token in text for token in ("content_length", "sensitive", "exfil", "download", "returned", "success"))
    generic_outcome = text_counts.get("generic", 0) > 0 or "/dev/null" in text or "close" in text
    active_action = (
        any(rel in relation_counts for rel in execution_signal_relations)
        or text_counts.get("exec", 0) > 0
    ) and not (set(relation_counts).issubset({"NET_ACCEPT", "NET_RECV", "NET_CONNECT", "PROCESS_FORK", "PROCESS_CLONE"}))
    return {
        "request_or_payload_visible": bool(request_or_payload),
        "active_server_action_visible": bool(active_action),
        "generic_outcome_visible": bool(generic_outcome),
        "strong_observable_outcome_visible": bool(strong_outcome),
        "stage_unclosed_corresponds_to_SU": False,
    }


def classify_dense_stage(edges: list[dict[str, Any]], config: dict[str, Any]) -> Optional[str]:
    counts = text_feature_counts(edges)
    signals = boundary_signals(edges, config)
    attack_related = counts.get("attack", 0) > 0 or signals["request_or_payload_visible"] or signals["active_server_action_visible"]
    if signals["strong_observable_outcome_visible"] and (
        signals["active_server_action_visible"] or signals["request_or_payload_visible"] or counts.get("result", 0) >= 2
    ):
        return "result"
    if signals["active_server_action_visible"]:
        return "execution"
    if signals["request_or_payload_visible"] and not signals["strong_observable_outcome_visible"]:
        return "preparation"
    if attack_related or counts.get("generic", 0) > 0:
        return "stage_unclosed"
    return None


def slice_spine(spine: list[dict[str, Any]], start_seq: int, end_seq: int) -> list[dict[str, Any]]:
    return [edge for edge in spine if start_seq <= int(edge.get("seq", -1)) <= end_seq]


def seq_edge_id_map(backbone_chain: dict[str, Any]) -> dict[int, str]:
    out: dict[int, str] = {}
    for edge in backbone_chain.get("edge_sequence") or []:
        try:
            seq = int(edge.get("seq"))
        except (TypeError, ValueError):
            continue
        edge_id = edge.get("edge_id")
        if isinstance(edge_id, str) and edge_id:
            out[seq] = edge_id
    return out


def enrich_edges_with_edge_id(edges: list[dict[str, Any]], seq_to_edge_id: dict[int, str]) -> list[dict[str, Any]]:
    enriched: list[dict[str, Any]] = []
    for edge in edges:
        cloned = dict(edge)
        try:
            seq = int(cloned.get("seq"))
        except (TypeError, ValueError):
            seq = None
        if not cloned.get("edge_id") and seq is not None and seq in seq_to_edge_id:
            cloned["edge_id"] = seq_to_edge_id[seq]
        enriched.append(cloned)
    return enriched


def focus_window(stage: str, start_seq: int, end_seq: int, config: dict[str, Any], source_note: str) -> tuple[int, int, str]:
    global_cap = max(1, int(config.get("focused_window_max_edges", 8)))
    size_map = {
        "preparation": int(config["preparation_focus_edges"]),
        "execution": int(config["execution_focus_edges"]),
        "result": int(config["result_focus_edges"]),
        "stage_unclosed": int(config["stage_unclosed_focus_edges"]),
    }
    width = max(1, min(size_map[stage], global_cap))
    span_len = end_seq - start_seq + 1
    if span_len <= width:
        return start_seq, end_seq, "full_span"
    if stage == "preparation":
        return max(start_seq, end_seq - width + 1), end_seq, "late_preparation_focus"
    if stage == "execution":
        return start_seq, min(end_seq, start_seq + width - 1), "entry_execution_focus"
    if stage == "result":
        return start_seq, min(end_seq, start_seq + width - 1), "result_anchor_focus"
    if "post" in source_note:
        return start_seq, min(end_seq, start_seq + width - 1), "post_chain_stage_unclosed_focus"
    return max(start_seq, end_seq - width + 1), end_seq, "boundary_stage_unclosed_focus"


def compact_evidence_ref(edge: dict[str, Any]) -> dict[str, Any]:
    attrs = edge.get("attrs") or {}
    return {
        "seq": int(edge.get("seq")),
        "edge_id": edge.get("edge_id"),
        "relation": edge.get("relation"),
        "subject": edge.get("subject"),
        "object": edge.get("object"),
        "raw_evt_type": attrs.get("raw_evt_type"),
        "timestamp": attrs.get("timestamp"),
    }


def summarize_visible_features(edges: list[dict[str, Any]]) -> dict[str, Any]:
    relation_counts = Counter(str(edge.get("relation")) for edge in edges)
    modality_counts = Counter()
    applog_types = Counter()
    for edge in edges:
        modality_counts.update(edge_modalities(edge))
        for row in ((edge.get("multisource_context") or {}).get("applog") or []):
            applog_types[str(row.get("semantic_type") or "unknown")] += 1
    malicious_edge_count = sum(1 for edge in edges if (edge.get("attrs") or {}).get("malicious") is True)
    return {
        "edge_count": len(edges),
        "relation_counts": dict(relation_counts),
        "modality_counts": dict(modality_counts),
        "applog_semantic_counts": dict(applog_types),
        "malicious_edge_count": malicious_edge_count,
    }


def key_evidence_strings(edges: list[dict[str, Any]], limit: int = 5) -> list[str]:
    out: list[str] = []
    for edge in edges[:limit]:
        out.append(
            f"seq {edge.get('seq')} {edge.get('relation')} "
            f"subject={edge.get('subject')} object={edge.get('object')}"
        )
    return out


def compute_scores(
    stage: str,
    source_span: dict[str, Any],
    edges: list[dict[str, Any]],
    features: dict[str, Any],
    config: dict[str, Any],
) -> dict[str, int]:
    edge_count = features["edge_count"]
    relation_counts = Counter(features["relation_counts"])
    modality_counts = features["modality_counts"]
    applog_counts = Counter(features["applog_semantic_counts"])
    result_tier_a_relations = config_set(config, "result_tier_a_relations", DEFAULT_RESULT_TIER_A_RELATIONS)
    result_tier_b_relations = config_set(config, "result_tier_b_relations", DEFAULT_RESULT_TIER_B_RELATIONS)
    generic_runtime_relations = config_set(config, "generic_runtime_relations", DEFAULT_GENERIC_RUNTIME_RELATIONS)
    request_like_applog_types = config_set(
        config, "request_like_applog_semantic_types", DEFAULT_REQUEST_LIKE_APPLOG_TYPES
    )
    execution_signal_relations = config_set(
        config, "execution_signal_relations", DEFAULT_EXECUTION_SIGNAL_RELATIONS
    )
    result_signal_relations = config_set(config, "result_signal_relations", DEFAULT_RESULT_SIGNAL_RELATIONS)
    has_audit = modality_counts.get("audit_context", 0) > 0
    has_applog = modality_counts.get("applog", 0) > 0
    has_traffic = modality_counts.get("traffic", 0) > 0
    result_like_relations = result_tier_a_relations | result_tier_b_relations
    has_result_like_relation = any(rel in result_like_relations for rel in relation_counts)
    has_request_like_log = any(name in applog_counts for name in request_like_applog_types)
    generic_runtime_only = set(relation_counts).issubset(generic_runtime_relations)
    stage_support = 2
    stage_feature = 2
    if stage == "preparation":
        if has_request_like_log:
            stage_support += 1
            stage_feature += 1
        if generic_runtime_only and not has_result_like_relation:
            stage_support += 1
        if "prep" in source_span["source"]:
            stage_feature += 1
        if edge_count <= 6:
            stage_support += 1
    elif stage == "execution":
        if features["malicious_edge_count"] > 0:
            stage_support += 1
            stage_feature += 1
        if any(rel in relation_counts for rel in execution_signal_relations):
            stage_support += 1
            stage_feature += 1
        if has_audit or has_applog:
            stage_support += 1
    elif stage == "result":
        if any(rel in relation_counts for rel in result_signal_relations):
            stage_support += 1
            stage_feature += 1
        if "result" in source_span["source"]:
            stage_support += 1
            stage_feature += 1
        if edge_count <= 6:
            stage_support += 1
    else:
        if "runtime" in source_span["source"] or "no_safe_result" in source_span["source"]:
            stage_support += 1
            stage_feature += 1
        if generic_runtime_only:
            stage_support += 1
        if features["malicious_edge_count"] == 0:
            stage_feature += 1
        if has_audit or has_applog:
            stage_support += 1

    log_quality = 2
    if has_audit:
        log_quality += 1
    if has_applog:
        log_quality += 1
    if has_traffic:
        log_quality += 1
    if edge_count == 0:
        log_quality = 0

    future_annotatability = 2
    if 1 <= edge_count <= 10:
        future_annotatability += 2
    elif edge_count <= 20:
        future_annotatability += 1
    if has_audit or has_applog:
        future_annotatability += 1

    if edge_count <= 8:
        context_length_risk = 1
    elif edge_count <= 20:
        context_length_risk = 2
    elif edge_count <= 50:
        context_length_risk = 3
    else:
        context_length_risk = 5

    duplicate_risk = 1 if edge_count <= 12 else 2 if edge_count <= 20 else 4

    return {
        "stage_feature_score": max(0, min(5, stage_feature)),
        "stage_support_score": max(0, min(5, stage_support)),
        "log_quality_score": max(0, min(5, log_quality)),
        "future_annotatability_score": max(0, min(5, future_annotatability)),
        "context_length_risk_score": context_length_risk,
        "duplicate_risk_score": duplicate_risk,
    }


def boundary_risk_from_scores(scores: dict[str, int]) -> str:
    if scores["stage_feature_score"] >= 4 and scores["stage_support_score"] >= 4:
        return "low"
    if scores["stage_feature_score"] >= 3 and scores["stage_support_score"] >= 3:
        return "medium"
    return "high"


def stage_support_summary(stage: str, source_span: dict[str, Any], features: dict[str, Any]) -> str:
    relations = ", ".join(f"{k}:{v}" for k, v in sorted(features["relation_counts"].items()))
    return (
        f"candidate_stage={stage}; visible_relations={relations}; "
        f"source_span={source_span['source']}; "
        f"edge_count={features['edge_count']}; "
        f"malicious_edge_count={features['malicious_edge_count']}. "
        f"Treat this as window-level support only, not global scenario progress."
    )


def stage_boundary_rationale(
    stage: str,
    source_span: dict[str, Any],
    edges: list[dict[str, Any]],
    scores: dict[str, int],
    config: dict[str, Any],
) -> dict[str, Any]:
    previous_map = {
        "preparation": "stage_unclosed",
        "execution": "preparation",
        "result": "execution",
        "stage_unclosed": "preparation/execution/result",
    }
    next_map = {
        "preparation": "execution",
        "execution": "result",
        "result": "no later concrete stage",
        "stage_unclosed": "no safe concrete stage closure",
    }
    signals = boundary_signals(edges, config)
    signals["stage_unclosed_corresponds_to_SU"] = stage == "stage_unclosed"
    return {
        "candidate_stage": stage,
        "key_evidence": key_evidence_strings(edges, limit=5),
        "boundary_signals": signals,
        "why_this_stage": (
            f"Visible evidence within the current window is most consistent with {stage}. "
            f"The source span came from {source_span['source']} and the score profile is "
            f"{scores['stage_support_score']}/5 stage support with {scores['stage_feature_score']}/5 stage features."
        ),
        "why_not_previous_stage": f"Do not collapse this window to {previous_map[stage]} because the current slice already shows stronger stage-specific cues than that earlier interpretation.",
        "why_not_next_stage": f"Do not advance this window to {next_map[stage]} because the visible evidence in the current slice does not safely close that later boundary.",
        "boundary_risk": boundary_risk_from_scores(scores),
        "notes_for_later_blinding": "Preserve visible seq, edge_id, relation, subject/object, and source-bucketed evidence. Remove scenario/CVE identity later.",
        "notes_for_later_annotation": "Later annotation should re-check visible audit/applog/traffic evidence only and not inherit scenario metadata as stage evidence.",
    }


def dense_window_rank(stage: str, edges: list[dict[str, Any]], config: dict[str, Any]) -> int:
    counts = text_feature_counts(edges)
    signals = boundary_signals(edges, config)
    modalities = summarize_visible_features(edges)["modality_counts"]
    coverage = sum(1 for key in ("audit_context", "applog", "traffic") if modalities.get(key, 0) > 0)
    compact_bonus = max(0, 8 - len(edges))
    base = coverage * 3 + compact_bonus
    if stage == "preparation":
        return base + int(signals["request_or_payload_visible"]) * 8 - int(signals["strong_observable_outcome_visible"]) * 10
    if stage == "execution":
        return base + int(signals["active_server_action_visible"]) * 8 - int(signals["strong_observable_outcome_visible"]) * 5
    if stage == "result":
        return base + int(signals["strong_observable_outcome_visible"]) * 10 + counts.get("result", 0) * 2
    return base + int(not signals["strong_observable_outcome_visible"]) * 4 + counts.get("generic", 0)


def dense_start_indices(spine: list[dict[str, Any]], length: int, config: dict[str, Any]) -> list[int]:
    if len(spine) < length:
        return []
    stride = max(1, int(config.get("dense_scan_stride", 25)))
    max_total = max(1, int(config.get("max_dense_windows_per_scenario", 12000)))
    lengths = [int(value) for value in config.get("dense_window_lengths", [2, 3, 5, 6, 7])]
    max_per_length = max(1, max_total // max(1, len(lengths)))
    important_relations = (
        config_set(config, "execution_signal_relations", DEFAULT_EXECUTION_SIGNAL_RELATIONS)
        | config_set(config, "result_signal_relations", DEFAULT_RESULT_SIGNAL_RELATIONS)
        | {"NET_ACCEPT", "NET_RECV"}
    )
    starts = set(range(0, len(spine) - length + 1, stride))
    offsets = (0, -1, -2, -4, -6)
    for idx, edge in enumerate(spine):
        relation = str(edge.get("relation"))
        attrs = edge.get("attrs") or {}
        if relation not in important_relations and attrs.get("malicious") is not True:
            continue
        for offset in offsets:
            start = idx + offset
            if 0 <= start <= len(spine) - length:
                starts.add(start)
    ordered = sorted(starts)
    if len(ordered) <= max_per_length:
        return ordered
    step = len(ordered) / max_per_length
    return [ordered[int(i * step)] for i in range(max_per_length)]


def build_dense_ranked_windows(record: ScenarioRecord, config: dict[str, Any], root: Path) -> list[dict[str, Any]]:
    if not bool(config.get("enable_dense_candidate_mining")):
        return []
    spine = record.behavior_dataset.get("spine") or []
    if not spine:
        return []
    seq_to_id = seq_edge_id_map(record.backbone_chain)
    enriched_spine = enrich_edges_with_edge_id(spine, seq_to_id)
    lengths = [int(value) for value in config.get("dense_window_lengths", [2, 3, 5, 6, 7])]
    per_stage_limit = int(config.get("ranked_candidates_per_stage_per_scenario", 12))
    ranked: dict[str, list[tuple[int, int, int, int, int, int]]] = {stage: [] for stage in LEGAL_STAGES}
    ordinal = 0
    for length in lengths:
        if length <= 0 or len(enriched_spine) < length:
            continue
        for start_idx in dense_start_indices(enriched_spine, length, config):
            window_edges = enriched_spine[start_idx : start_idx + length]
            stage = classify_dense_stage(window_edges, config)
            if stage is None:
                continue
            start_seq = int(window_edges[0].get("seq"))
            rank = dense_window_rank(stage, window_edges, config)
            ordinal += 1
            item = (rank, -length, -start_seq, ordinal, start_idx, length)
            heap = ranked[stage]
            if len(heap) < per_stage_limit:
                heapq.heappush(heap, item)
            elif item > heap[0]:
                heapq.heapreplace(heap, item)
    rows: list[dict[str, Any]] = []
    for stage, items in ranked.items():
        for rank, neg_length, neg_start_seq, _ordinal, start_idx, length in sorted(items, reverse=True):
            window_edges = enriched_spine[start_idx : start_idx + length]
            start_seq = -neg_start_seq
            end_seq = int(window_edges[-1].get("seq"))
            features = summarize_visible_features(window_edges)
            span = {
                "stage": stage,
                "start_seq": start_seq,
                "end_seq": end_seq,
                "source": f"ranked_{stage}_window",
                "rank_score": rank,
            }
            scores = compute_scores(stage, span, window_edges, features, config)
            rationale = stage_boundary_rationale(stage, span, window_edges, scores, config)
            status, gate = gated_selection_status(stage, window_edges, scores, config)
            rows.append(
                {
                    "schema_version": WINDOW_SELECTION_SCHEMA,
                    "sample_id_seed": f"{record.scenario_slug}__ranked_{stage}_{start_seq}_{end_seq}",
                    "scenario_id": record.scenario_id,
                    "scenario_slug": record.scenario_slug,
                    "candidate_stage": stage,
                    "window": {"start_seq": start_seq, "end_seq": end_seq},
                    "source_span": span,
                    "candidate_rule": "dense_ranked_window",
                    "variant": "dense_ranked",
                    "selection_status": status,
                    "stage_boundary_gate": gate,
                    "stage_support_summary": stage_support_summary(stage, span, features),
                    "stage_boundary_rationale": rationale,
                    "visible_features": features,
                    "scores": scores,
                    "key_evidence_refs": [compact_evidence_ref(edge) for edge in window_edges[:8]],
                    "source_paths": {
                        "chain_dir": rel(record.chain_dir, root),
                        "behavior_chain_dataset": rel(record.chain_dir / "behavior_chain_dataset.v2.json", root),
                        "backbone_chain": rel(record.chain_dir / "backbone_chain.v1.json", root),
                    },
                    "chain_alignment_mode": "dense_ranked_chain_visible_window",
                    "scenario_order_hint": 0,
                }
            )
    return rows


def selection_status(scores: dict[str, int], config: dict[str, Any]) -> str:
    thresholds = config["selection_thresholds"]
    if (
        scores["stage_feature_score"] >= thresholds["stage_feature_score_min"]
        and scores["stage_support_score"] >= thresholds["stage_support_score_min"]
        and scores["log_quality_score"] >= thresholds["log_quality_score_min"]
        and scores["future_annotatability_score"] >= thresholds["future_annotatability_score_min"]
        and scores["context_length_risk_score"] <= thresholds["context_length_risk_score_max"]
        and scores["duplicate_risk_score"] <= thresholds["duplicate_risk_score_max"]
    ):
        return "selected"
    if scores["stage_feature_score"] >= 3 and scores["stage_support_score"] >= 3:
        return "reserve"
    return "rejected"


def stage_boundary_gate(stage: str, edges: list[dict[str, Any]], config: dict[str, Any]) -> tuple[bool, str]:
    signals = boundary_signals(edges, config)
    counts = text_feature_counts(edges)
    modalities = summarize_visible_features(edges)["modality_counts"]
    has_primary_context = any(modalities.get(key, 0) > 0 for key in ("audit_context", "applog", "traffic"))
    if not has_primary_context:
        return False, "missing primary audit/applog/traffic context"
    if stage == "preparation":
        if not signals["request_or_payload_visible"]:
            return False, "preparation requires visible request/probing/pre-trigger evidence"
        if signals["active_server_action_visible"] or signals["strong_observable_outcome_visible"]:
            return False, "preparation cannot include safely closed active processing or result consequence"
        return True, "preparation boundary gate passed"
    if stage == "execution":
        if not signals["active_server_action_visible"]:
            return False, "execution requires visible handler/runtime/process/file/network action"
        if signals["strong_observable_outcome_visible"]:
            return False, "execution cannot include safely closed result consequence"
        return True, "execution boundary gate passed"
    if stage == "result":
        if not signals["strong_observable_outcome_visible"]:
            return False, "result requires a visible observable consequence"
        if not (signals["active_server_action_visible"] or signals["request_or_payload_visible"] or counts.get("result", 0) >= 2):
            return False, "result requires operation-to-effect linkage inside the retained window"
        return True, "result boundary gate passed"
    if stage == "stage_unclosed":
        attack_related = (
            counts.get("attack", 0) > 0
            or signals["request_or_payload_visible"]
            or signals["active_server_action_visible"]
            or counts.get("generic", 0) > 0
        )
        if not attack_related:
            return False, "stage_unclosed requires attack-chain-related visible evidence"
        if signals["strong_observable_outcome_visible"]:
            return False, "stage_unclosed cannot include safely closed result consequence"
        return True, "stage_unclosed boundary gate passed"
    return False, "invalid stage"


def gated_selection_status(stage: str, edges: list[dict[str, Any]], scores: dict[str, int], config: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    status = selection_status(scores, config)
    passed, reason = stage_boundary_gate(stage, edges, config)
    thresholds = config["selection_thresholds"]
    if status == "selected" and bool(thresholds.get("require_stage_boundary_gate_for_selected", True)) and not passed:
        status = "reserve" if scores["stage_feature_score"] >= 3 and scores["stage_support_score"] >= 3 else "rejected"
    return status, {"passed": passed, "reason": reason}


def build_candidate_windows(record: ScenarioRecord, stage_seed: dict[str, Any], config: dict[str, Any], root: Path) -> list[dict[str, Any]]:
    spine = record.behavior_dataset.get("spine") or []
    seq_to_id = seq_edge_id_map(record.backbone_chain)
    rows: list[dict[str, Any]] = []
    for idx, span in enumerate(stage_seed["stage_spans"], start=1):
        stage = span["stage"]
        full_edges = enrich_edges_with_edge_id(slice_spine(spine, span["start_seq"], span["end_seq"]), seq_to_id)
        if not full_edges:
            continue
        focus_start, focus_end, focus_rule = focus_window(stage, span["start_seq"], span["end_seq"], config, span["source"])
        candidate_specs = [
            ("focused", focus_rule, focus_start, focus_end),
        ]
        if bool(config.get("allow_full_span_variant")) and (focus_start, focus_end) != (span["start_seq"], span["end_seq"]):
            candidate_specs.append(("span_full", "full_stage_span", span["start_seq"], span["end_seq"]))
        for variant, candidate_rule, start_seq, end_seq in candidate_specs:
            window_edges = enrich_edges_with_edge_id(slice_spine(spine, start_seq, end_seq), seq_to_id)
            features = summarize_visible_features(window_edges)
            scores = compute_scores(stage, span, window_edges, features, config)
            rationale = stage_boundary_rationale(stage, span, window_edges, scores, config)
            status, gate = gated_selection_status(stage, window_edges, scores, config)
            rows.append(
                {
                    "schema_version": WINDOW_SELECTION_SCHEMA,
                    "sample_id_seed": f"{record.scenario_slug}__window_{start_seq}_{end_seq}",
                    "scenario_id": record.scenario_id,
                    "scenario_slug": record.scenario_slug,
                    "candidate_stage": stage,
                    "window": {"start_seq": start_seq, "end_seq": end_seq},
                    "source_span": span,
                    "candidate_rule": candidate_rule,
                    "variant": variant,
                    "selection_status": status,
                    "stage_boundary_gate": gate,
                    "stage_support_summary": stage_support_summary(stage, span, features),
                    "stage_boundary_rationale": rationale,
                    "visible_features": features,
                    "scores": scores,
                    "key_evidence_refs": [compact_evidence_ref(edge) for edge in window_edges[:8]],
                    "source_paths": {
                        "chain_dir": rel(record.chain_dir, root),
                        "behavior_chain_dataset": rel(record.chain_dir / "behavior_chain_dataset.v2.json", root),
                        "backbone_chain": rel(record.chain_dir / "backbone_chain.v1.json", root),
                    },
                    "chain_alignment_mode": stage_seed["derivation_source"],
                    "scenario_order_hint": idx,
                }
            )
    return rows


def build_summary(candidate_rows: list[dict[str, Any]], output_dir: Path) -> str:
    counts = Counter(row["selection_status"] for row in candidate_rows)
    per_stage = Counter((row["candidate_stage"], row["selection_status"]) for row in candidate_rows)
    result_selected = per_stage.get(("result", "selected"), 0)
    result_reserve = per_stage.get(("result", "reserve"), 0)
    lines = [
        "# stage_reasoning_window_selection summary",
        "",
        f"total_candidates = {len(candidate_rows)}",
        f"selected = {counts.get('selected', 0)}",
        f"reserve = {counts.get('reserve', 0)}",
        f"rejected = {counts.get('rejected', 0)}",
        "",
        "Per-stage status counts:",
        "",
    ]
    for stage in LEGAL_STAGES:
        lines.append(
            f"- {stage}: selected={per_stage.get((stage, 'selected'), 0)} "
            f"reserve={per_stage.get((stage, 'reserve'), 0)} "
            f"rejected={per_stage.get((stage, 'rejected'), 0)}"
        )
    if result_selected == 0 and result_reserve > 0:
        lines.extend(
            [
                "",
                "Note:",
                "- `result` is currently conservative. Reserve windows exist, but the default rules do not yet treat them as safely selected result closures.",
            ]
        )
    lines.extend(
        [
            "",
            "Output files:",
            f"- {output_dir.as_posix()}/chain_inventory.jsonl",
            f"- {output_dir.as_posix()}/scenario_stage_seed.jsonl",
            f"- {output_dir.as_posix()}/candidate_windows.jsonl",
            f"- {output_dir.as_posix()}/selected_windows.jsonl",
            f"- {output_dir.as_posix()}/annotation_ready_seed.jsonl",
        ]
    )
    return "\n".join(lines) + "\n"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build stage_reasoning_window_selection from ../01_dataset_construction/results/**/chain using relative paths.")
    parser.add_argument("--config", default="configs/default_config.json")
    parser.add_argument("--results-root", default=None)
    parser.add_argument("--output-dir", default=None)
    parser.add_argument("--scenario-limit", type=int, default=None)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    workbench_root = released_stage_root(Path(__file__))
    config = load_config(workbench_root / args.config)
    results_root = (workbench_root / (args.results_root or config["results_root"])).resolve()
    output_dir_rel = Path(args.output_dir or config["output_dir"])
    output_dir = workbench_root / output_dir_rel

    scenarios = load_scenarios(results_root, args.scenario_limit)
    inventory_rows: list[dict[str, Any]] = []
    stage_seed_rows: list[dict[str, Any]] = []
    candidate_rows: list[dict[str, Any]] = []

    for record in scenarios:
        inventory_rows.append(
            {
                "scenario_id": record.scenario_id,
                "scenario_slug": record.scenario_slug,
                "chain_dir": rel(record.chain_dir, workbench_root),
                "behavior_chain_dataset": rel(record.chain_dir / "behavior_chain_dataset.v2.json", workbench_root),
                "backbone_chain": rel(record.chain_dir / "backbone_chain.v1.json", workbench_root),
                "stage_seed_source": "chain_local_derivation",
            }
        )
        stage_seed = stage_seed_for_record(record, config)
        stage_seed_rows.append(stage_seed)
        candidate_rows.extend(build_candidate_windows(record, stage_seed, config, workbench_root))
        candidate_rows.extend(build_dense_ranked_windows(record, config, workbench_root))

    deduped_candidate_rows: dict[tuple[str, str, int, int], dict[str, Any]] = {}
    for row in candidate_rows:
        key = (
            str(row["scenario_slug"]),
            str(row["candidate_stage"]),
            int(row["window"]["start_seq"]),
            int(row["window"]["end_seq"]),
        )
        old = deduped_candidate_rows.get(key)
        if old is None or row["scores"]["stage_support_score"] > old["scores"]["stage_support_score"]:
            deduped_candidate_rows[key] = row
    candidate_rows = list(deduped_candidate_rows.values())

    selected_rows = [row for row in candidate_rows if row["selection_status"] == "selected"]
    reserve_rows = [row for row in candidate_rows if row["selection_status"] == "reserve"]
    rejected_rows = [row for row in candidate_rows if row["selection_status"] == "rejected"]
    annotation_ready_seed_rows = [
        {
            "sample_id_seed": row["sample_id_seed"],
            "scenario_id": row["scenario_id"],
            "scenario_slug": row["scenario_slug"],
            "candidate_stage": row["candidate_stage"],
            "window": row["window"],
            "stage_support_summary": row["stage_support_summary"],
            "stage_boundary_rationale": row["stage_boundary_rationale"],
            "scores": row["scores"],
            "source_paths": row["source_paths"],
            "selection_status": row["selection_status"],
        }
        for row in selected_rows + reserve_rows
    ]

    write_jsonl(output_dir / "chain_inventory.jsonl", inventory_rows)
    write_jsonl(output_dir / "scenario_stage_seed.jsonl", stage_seed_rows)
    write_jsonl(output_dir / "candidate_windows.jsonl", candidate_rows)
    write_jsonl(output_dir / "selected_windows.jsonl", selected_rows)
    write_jsonl(output_dir / "reserve_windows.jsonl", reserve_rows)
    write_jsonl(output_dir / "rejected_windows.jsonl", rejected_rows)
    write_jsonl(output_dir / "annotation_ready_seed.jsonl", annotation_ready_seed_rows)
    write_text(output_dir / "summary.md", build_summary(candidate_rows, output_dir_rel))
    write_json(
        output_dir / "manifest.json",
        {
            "schema_version": WINDOW_SELECTION_SCHEMA,
            "created_at_utc": utc_now(),
            "root": ".",
            "results_root": rel(results_root, workbench_root),
            "scenario_count": len(scenarios),
            "candidate_count": len(candidate_rows),
            "selected_count": len(selected_rows),
            "reserve_count": len(reserve_rows),
            "rejected_count": len(rejected_rows),
            "stage_seed_mode": "chain_local_derivation_only",
            "extensible_hooks": {
                "focused_window_max_edges": int(config.get("focused_window_max_edges", 8)),
                "enable_dense_candidate_mining": bool(config.get("enable_dense_candidate_mining")),
                "dense_window_lengths": [int(value) for value in config.get("dense_window_lengths", [2, 3, 5, 6, 7])],
                "dense_scan_stride": int(config.get("dense_scan_stride", 25)),
                "max_dense_windows_per_scenario": int(config.get("max_dense_windows_per_scenario", 12000)),
                "ranked_candidates_per_stage_per_scenario": int(config.get("ranked_candidates_per_stage_per_scenario", 12)),
                "prep_end_roles": sorted(config_set(config, "prep_end_roles", DEFAULT_PREP_END_ROLES)),
                "result_tier_a_relations": sorted(config_set(config, "result_tier_a_relations", DEFAULT_RESULT_TIER_A_RELATIONS)),
                "result_tier_b_relations": sorted(config_set(config, "result_tier_b_relations", DEFAULT_RESULT_TIER_B_RELATIONS)),
                "generic_runtime_relations": sorted(
                    config_set(config, "generic_runtime_relations", DEFAULT_GENERIC_RUNTIME_RELATIONS)
                ),
                "request_like_applog_semantic_types": sorted(
                    config_set(config, "request_like_applog_semantic_types", DEFAULT_REQUEST_LIKE_APPLOG_TYPES)
                ),
                "execution_signal_relations": sorted(
                    config_set(config, "execution_signal_relations", DEFAULT_EXECUTION_SIGNAL_RELATIONS)
                ),
                "result_signal_relations": sorted(
                    config_set(config, "result_signal_relations", DEFAULT_RESULT_SIGNAL_RELATIONS)
                ),
                "allow_full_span_variant": bool(config.get("allow_full_span_variant")),
            },
            "outputs": {
                "inventory": (output_dir_rel / "chain_inventory.jsonl").as_posix(),
                "stage_seed": (output_dir_rel / "scenario_stage_seed.jsonl").as_posix(),
                "candidate_windows": (output_dir_rel / "candidate_windows.jsonl").as_posix(),
                "selected_windows": (output_dir_rel / "selected_windows.jsonl").as_posix(),
                "annotation_ready_seed": (output_dir_rel / "annotation_ready_seed.jsonl").as_posix(),
            },
        },
    )

    print(
        json.dumps(
            {
                "scenario_count": len(scenarios),
                "candidate_count": len(candidate_rows),
                "selected_count": len(selected_rows),
                "output_dir": str(output_dir),
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
