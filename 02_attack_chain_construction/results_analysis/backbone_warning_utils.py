#!/usr/bin/env python3
"""Helpers for backbone breadth metrics and scene-level warnings."""

from __future__ import annotations

from collections import Counter
from typing import Any, Iterable


BACKBONE_WARNING_SCHEMA_VERSION = "backbone_broad_warning.v0"
DEFAULT_TOP_RELATION_LIMIT = 10
DEFAULT_BROAD_GATE_RELATIONS = ("NET_RECV", "NET_SEND", "PROCESS_FORK")


def _safe_ratio(numerator: int, denominator: int) -> float:
    if denominator <= 0:
        return 0.0
    return round(float(numerator) / float(denominator), 6)


def _relation_counter_top(counter: Counter[str], limit: int = DEFAULT_TOP_RELATION_LIMIT) -> list[list[Any]]:
    return [[relation, count] for relation, count in counter.most_common(limit)]


def compute_backbone_edge_metrics(
    edges: Iterable[dict[str, Any]],
    *,
    source_subgraph_edge_count: int | None = None,
    context_edge_count: int | None = None,
    unmatched_count: int | None = None,
    distinct_unit_count_in_backbone: int | None = None,
    stage_residual_count: int | None = None,
    multisource_context_count: int | None = None,
    top_relation_limit: int = DEFAULT_TOP_RELATION_LIMIT,
) -> dict[str, Any]:
    materialized_edges = list(edges)
    relation_counts: Counter[str] = Counter()
    non_malicious_relation_counts: Counter[str] = Counter()
    malicious_edge_count = 0

    for edge in materialized_edges:
        relation = str(edge.get("relation") or "UNKNOWN")
        relation_counts[relation] += 1
        attrs = edge.get("attrs") or {}
        is_malicious = bool(attrs.get("malicious", False))
        if is_malicious:
            malicious_edge_count += 1
        else:
            non_malicious_relation_counts[relation] += 1

    edge_count = len(materialized_edges)
    non_malicious_edge_count = max(edge_count - malicious_edge_count, 0)
    backbone_to_subgraph_ratio = None
    if source_subgraph_edge_count is not None:
        backbone_to_subgraph_ratio = (
            round(edge_count / source_subgraph_edge_count, 6)
            if source_subgraph_edge_count > 0
            else 0.0
        )

    return {
        "edge_count": edge_count,
        "malicious_edge_count": malicious_edge_count,
        "malicious_ratio": _safe_ratio(malicious_edge_count, edge_count),
        "non_malicious_edge_count": non_malicious_edge_count,
        "non_malicious_ratio": _safe_ratio(non_malicious_edge_count, edge_count),
        "backbone_to_subgraph_ratio": backbone_to_subgraph_ratio,
        "context_edge_count": int(context_edge_count or 0),
        "unmatched_count": int(unmatched_count or 0),
        "top_relations": _relation_counter_top(relation_counts, limit=top_relation_limit),
        "top_non_malicious_relations": _relation_counter_top(
            non_malicious_relation_counts,
            limit=top_relation_limit,
        ),
        "distinct_unit_count_in_backbone": int(distinct_unit_count_in_backbone or 0),
        "stage_residual_count": int(stage_residual_count or 0),
        "multisource_context_count": int(multisource_context_count or 0),
        "relation_counts": dict(sorted(relation_counts.items())),
        "non_malicious_relation_counts": dict(sorted(non_malicious_relation_counts.items())),
    }


def evaluate_backbone_broad_warning(
    metrics: dict[str, Any],
    *,
    scenario_id: str | None = None,
) -> dict[str, Any]:
    edge_count = int(metrics.get("edge_count", 0) or 0)
    malicious_ratio = float(metrics.get("malicious_ratio", 0.0) or 0.0)
    backbone_to_subgraph_ratio_raw = metrics.get("backbone_to_subgraph_ratio")
    backbone_to_subgraph_ratio = (
        float(backbone_to_subgraph_ratio_raw)
        if backbone_to_subgraph_ratio_raw is not None
        else None
    )

    warnings: list[dict[str, Any]] = []

    if malicious_ratio < 0.1 and edge_count > 1000:
        warnings.append({
            "code": "low_malicious_ratio_large_backbone",
            "message": "malicious_ratio < 0.1 and edge_count > 1000",
            "observed": {
                "malicious_ratio": round(malicious_ratio, 6),
                "edge_count": edge_count,
            },
        })

    if (
        backbone_to_subgraph_ratio is not None
        and backbone_to_subgraph_ratio > 0.8
        and malicious_ratio < 0.25
    ):
        warnings.append({
            "code": "high_backbone_capture_low_malicious_ratio",
            "message": "backbone_to_subgraph_ratio > 0.8 and malicious_ratio < 0.25",
            "observed": {
                "backbone_to_subgraph_ratio": round(backbone_to_subgraph_ratio, 6),
                "malicious_ratio": round(malicious_ratio, 6),
            },
        })

    top_non_malicious_relations = metrics.get("top_non_malicious_relations") or []
    heavy_non_malicious_relations = [
        relation
        for relation, _count in top_non_malicious_relations[:3]
        if relation in {"NET_RECV", "NET_SEND", "PROCESS_FORK", "NET_ACCEPT", "NET_CONNECT"}
    ]
    if warnings and heavy_non_malicious_relations:
        warnings.append({
            "code": "non_malicious_netproc_dominance_hint",
            "message": "warned scene is top-heavy in non-malicious NET/PROCESS relations",
            "observed": {
                "relations": heavy_non_malicious_relations,
            },
        })

    result = {
        "schema_version": BACKBONE_WARNING_SCHEMA_VERSION,
        "scenario_id": scenario_id,
        "warning_present": bool(warnings),
        "warning_codes": [item["code"] for item in warnings],
        "warnings": warnings,
        "metrics": {
            key: metrics.get(key)
            for key in (
                "edge_count",
                "malicious_edge_count",
                "malicious_ratio",
                "non_malicious_ratio",
                "backbone_to_subgraph_ratio",
                "context_edge_count",
                "unmatched_count",
                "top_relations",
                "top_non_malicious_relations",
                "distinct_unit_count_in_backbone",
                "stage_residual_count",
                "multisource_context_count",
            )
        },
    }
    return result
