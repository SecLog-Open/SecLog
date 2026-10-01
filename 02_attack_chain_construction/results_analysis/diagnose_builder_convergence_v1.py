#!/usr/bin/env python3
"""
TEMPORARY OFFLINE DIAGNOSTICS.
SAFE TO REMOVE AFTER BUILDER TUNING.
DOES NOT AFFECT PRIMARY ARTIFACT CONTRACT.

Offline convergence diagnostics for triple/subgraph/backbone artifacts.
This script is read-only against scenario artifacts and writes independent
sidecar/summary outputs for analysis.
"""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from statistics import mean, median
from typing import Any

from pipeline.utils.common import scenario_chain_dir

DIAGNOSTICS_VERSION = "offline.v1"
INPUT_ARTIFACT_CONTRACT = "raw + index + chain"
SUBGRAPH_OPTIONAL_NOTE = "attack_subgraph.v1.json is an optional diagnostic artifact and may not be written by default."

DEFAULT_SCENARIOS = [
    "python-demo",
    "vulhub/gitlist/CVE-2018-1000533",
    "vulhub/joomla/CVE-2017-8917",
    "vulhub/joomla/CVE-2023-23752",
]


@dataclass
class ScenarioPaths:
    scenario: str
    timestamp_dir: Path
    chain_dir: Path
    index_dir: Path
    triples_path: Path
    subgraph_path: Path
    backbone_path: Path
    unit_event_path: Path
    unit_index_path: Path


def _ratio(a: int, b: int) -> float:
    return float(a) / float(b) if b else 0.0


def _family(relation: str) -> str:
    r = str(relation or "")
    if r.startswith("FILE_"):
        return "FILE"
    if r.startswith("NET_"):
        return "NET"
    if r.startswith("PROCESS_"):
        return "PROCESS"
    return "OTHER"


def _top_k(counter: Counter[str], k: int = 10) -> list[dict[str, Any]]:
    return [{"name": n, "count": int(c)} for n, c in counter.most_common(k)]


def _read_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8", errors="replace") as f:
        return json.load(f)


def _iter_triples(path: Path):
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line_no, line in enumerate(f, 1):
            s = line.strip()
            if not s:
                continue
            try:
                yield json.loads(s)
            except Exception:
                continue


def _load_evt_to_unit(path: Path) -> dict[int, bool]:
    """Map evt_num -> has_unit (True/False)."""
    out: dict[int, bool] = {}
    if not path.exists():
        return out
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            s = line.strip()
            if not s:
                continue
            try:
                row = json.loads(s)
            except Exception:
                continue
            evt_raw = row.get("evt_num")
            try:
                evt = int(evt_raw)
            except Exception:
                continue
            unit_key = row.get("unit_key")
            unit_id = row.get("unit_id")
            has_unit = False
            if unit_key is not None and str(unit_key).strip().lower() not in {"", "null"}:
                has_unit = True
            elif unit_id is not None and str(unit_id).strip().lower() not in {"", "null"}:
                has_unit = True
            out[evt] = has_unit
    return out


def _latest_timestamp_dir(scenario_root: Path) -> Path | None:
    if not scenario_root.exists() or not scenario_root.is_dir():
        return None
    cands = [p for p in scenario_root.iterdir() if p.is_dir() and p.name[:2] == "20"]
    if not cands:
        return None
    cands.sort(key=lambda p: p.name)
    return cands[-1]


def _build_paths(results_root: Path, scenario: str) -> ScenarioPaths | None:
    scenario_root = results_root / scenario
    ts = _latest_timestamp_dir(scenario_root)
    if ts is None:
        return None
    chain = scenario_chain_dir(ts)
    index = ts / "index"
    return ScenarioPaths(
        scenario=scenario,
        timestamp_dir=ts,
        chain_dir=chain,
        index_dir=index,
        triples_path=chain / "audit_triples.core.v1.jsonl",
        subgraph_path=chain / "attack_subgraph.v1.json",
        backbone_path=chain / "backbone_chain.v1.json",
        unit_event_path=index / "unit_event_index.jsonl",
        unit_index_path=index / "unit_index.jsonl",
    )


def _edge_evt_num(edge: dict[str, Any]) -> int | None:
    attrs = edge.get("attrs") if isinstance(edge, dict) else None
    if not isinstance(attrs, dict):
        return None
    raw = attrs.get("evt_num")
    try:
        return int(raw)
    except Exception:
        return None


def _collect_stage_metrics(edges: list[dict[str, Any]], evt_to_unit: dict[int, bool], seed_nodes: set[str]) -> dict[str, Any]:
    fam = Counter[str]()
    rel = Counter[str]()
    with_unit = 0
    without_unit = 0
    touch_seed = 0

    for e in edges:
        relation = str(e.get("relation", ""))
        rel[relation] += 1
        fam[_family(relation)] += 1

        evt = _edge_evt_num(e)
        if evt is not None and evt in evt_to_unit and evt_to_unit[evt]:
            with_unit += 1
        else:
            without_unit += 1

        s = str(e.get("subject", ""))
        o = str(e.get("object", ""))
        if s in seed_nodes or o in seed_nodes:
            touch_seed += 1

    total = len(edges)
    return {
        "edge_count": total,
        "family_counts": {k: int(v) for k, v in sorted(fam.items())},
        "family_ratios": {k: round(_ratio(v, total), 6) for k, v in sorted(fam.items())},
        "relation_top10": _top_k(rel, 10),
        "with_unit": int(with_unit),
        "without_unit": int(without_unit),
        "with_unit_ratio": round(_ratio(with_unit, total), 6),
        "seed_touch_count": int(touch_seed),
        "seed_touch_ratio": round(_ratio(touch_seed, total), 6),
    }


def _textual_summary(
    mode: str,
    funnel: dict[str, Any],
    stage_sub: dict[str, Any],
    stage_back: dict[str, Any],
    subgraph_status: str,
    subgraph_note: str,
) -> str:
    if subgraph_status != "available":
        return f"{subgraph_note} Fell back to the backbone as an approximation for subgraph-stage statistics; subgraph-specific metrics are marked unavailable."

    sub_over_tri = float(funnel.get("subgraph_over_triples", 0.0))
    back_over_sub = float(funnel.get("backbone_over_subgraph", 0.0))

    if sub_over_tri >= 0.7:
        s1 = "Most breadth occurs in the triples->subgraph stage; subgraph expansion has not converged clearly."
    elif back_over_sub >= 0.9:
        s1 = "Most breadth occurs in the subgraph->backbone stage; backbone pruning is insufficient."
    else:
        s1 = "Breadth is concentrated in the intermediate expansion stage; the current funnel shows a present but non-extreme expansion."

    # choose suspicious family/relation by subgraph dominance
    fam_counts = stage_sub.get("family_counts", {})
    suspect_family = "UNKNOWN"
    if fam_counts:
        suspect_family = max(fam_counts.items(), key=lambda kv: kv[1])[0]
    rel_top = stage_sub.get("relation_top10", [])
    suspect_rel = rel_top[0]["name"] if rel_top else "UNKNOWN"
    s2 = f"The most suspicious family is {suspect_family} (representative relation: {suspect_rel})."

    # builder vs unit coverage issue
    with_unit_ratio = float(stage_sub.get("with_unit_ratio", 0.0))
    if with_unit_ratio >= 0.4 and (sub_over_tri >= 0.7 or back_over_sub >= 0.9):
        s3 = "This looks more like a builder-convergence issue than insufficient unit coverage."
    elif with_unit_ratio < 0.1:
        s3 = "There is also a signal of low unit coverage, but the main issue must be judged together with the convergence funnel."
    else:
        s3 = "This points more toward a builder-convergence issue; unit coverage is not the primary bottleneck."

    # Fixed to <=3 sentences.
    return " ".join([s1, s2, s3])


def diagnose_one(paths: ScenarioPaths) -> dict[str, Any]:
    missing = []
    for p in [paths.triples_path, paths.backbone_path, paths.unit_event_path]:
        if not p.exists():
            missing.append(str(p))

    if missing:
        return {
            "scenario": paths.scenario,
            "timestamp_dir": str(paths.timestamp_dir),
            "status": "missing_required_inputs",
            "missing_inputs": missing,
        }

    evt_to_unit = _load_evt_to_unit(paths.unit_event_path)
    unit_index_exists = paths.unit_index_path.exists()

    triples_edges = list(_iter_triples(paths.triples_path))
    backbone = _read_json(paths.backbone_path)

    subgraph: dict[str, Any] = {}
    subgraph_status = "missing_optional"
    subgraph_note = SUBGRAPH_OPTIONAL_NOTE
    subgraph_metrics_source = "backbone_fallback"
    skipped_metrics = [
        "mode.builder_mode",
        "mode.mode_reason",
        "mode.unit_nonnull_ratio",
        "mode.seed_with_unit_ratio",
        "stages.subgraph.seed_touch_ratio",
    ]
    if paths.subgraph_path.exists():
        try:
            loaded = _read_json(paths.subgraph_path)
            if isinstance(loaded, dict):
                subgraph = loaded
                subgraph_status = "available"
                subgraph_note = ""
                subgraph_metrics_source = "subgraph"
                skipped_metrics = []
            else:
                subgraph_status = "unavailable"
                subgraph_note = (
                    f"{SUBGRAPH_OPTIONAL_NOTE} The file exists but has an invalid structure; related metrics are unavailable."
                )
        except Exception as e:
            subgraph_status = "unavailable"
            subgraph_note = (
                f"{SUBGRAPH_OPTIONAL_NOTE} The file could not be read ({e.__class__.__name__}); related metrics are unavailable."
            )

    subgraph_edges = subgraph.get("edges", []) if isinstance(subgraph, dict) else []
    if not isinstance(subgraph_edges, list):
        subgraph_edges = []

    backbone_seq = backbone.get("edge_sequence", []) if isinstance(backbone, dict) else []
    if not isinstance(backbone_seq, list):
        backbone_seq = []

    # Normalize backbone edges into relation/subject/object/attrs shape.
    backbone_edges: list[dict[str, Any]] = []
    for e in backbone_seq:
        if not isinstance(e, dict):
            continue
        backbone_edges.append(
            {
                "relation": e.get("relation"),
                "subject": e.get("subject"),
                "object": e.get("object"),
                "attrs": e.get("attrs") if isinstance(e.get("attrs"), dict) else {},
            }
        )

    seeds = subgraph.get("seeds", {}) if isinstance(subgraph, dict) else {}
    seed_nodes = set(seeds.get("seed_nodes", []) if isinstance(seeds, dict) else [])

    stage_tri = _collect_stage_metrics(triples_edges, evt_to_unit, seed_nodes)
    stage_back = _collect_stage_metrics(backbone_edges, evt_to_unit, seed_nodes)
    stage_sub = _collect_stage_metrics(subgraph_edges, evt_to_unit, seed_nodes)
    if subgraph_status != "available":
        stage_sub = dict(stage_back)

    mode = "UNKNOWN"
    mode_reason = ""
    graph_summary = subgraph.get("graph_summary", {}) if isinstance(subgraph, dict) else {}
    if subgraph_status == "available" and isinstance(graph_summary, dict):
        mode = str(graph_summary.get("builder_mode", "UNKNOWN"))
        mode_reason = str(graph_summary.get("mode_reason", ""))
    else:
        mode = "UNAVAILABLE"
        mode_reason = subgraph_note

    funnel = {
        "triples_edges": int(stage_tri["edge_count"]),
        "subgraph_edges": int(stage_sub["edge_count"]),
        "backbone_edges": int(stage_back["edge_count"]),
        "subgraph_over_triples": round(_ratio(stage_sub["edge_count"], stage_tri["edge_count"]), 6),
        "backbone_over_subgraph": round(_ratio(stage_back["edge_count"], stage_sub["edge_count"]), 6),
        "backbone_over_triples": round(_ratio(stage_back["edge_count"], stage_tri["edge_count"]), 6),
    }

    out = {
        "diagnostics_version": DIAGNOSTICS_VERSION,
        "input_artifact_contract": INPUT_ARTIFACT_CONTRACT,
        "scenario": paths.scenario,
        "timestamp_dir": str(paths.timestamp_dir),
        "status": "ok",
        "mode": {
            "builder_mode": mode,
            "mode_reason": mode_reason,
            "unit_nonnull_ratio": graph_summary.get("unit_nonnull_ratio") if (subgraph_status == "available" and isinstance(graph_summary, dict)) else None,
            "seed_with_unit_ratio": graph_summary.get("seed_with_unit_ratio") if (subgraph_status == "available" and isinstance(graph_summary, dict)) else None,
        },
        "funnel": funnel,
        "stages": {
            "triples": stage_tri,
            "subgraph": stage_sub,
            "backbone": stage_back,
        },
        "unit_index_usage_note": "reserved / not materially used in offline v1 diagnostics",
        "unit_index_exists": bool(unit_index_exists),
        "textual_summary": _textual_summary(mode, funnel, stage_sub, stage_back, subgraph_status, subgraph_note),
        "optional_artifacts": {
            "attack_subgraph": {
                "path": str(paths.subgraph_path),
                "status": subgraph_status,
                "note": subgraph_note,
                "metrics_source": subgraph_metrics_source,
                "skipped_metrics": skipped_metrics,
            }
        },
        "inputs": {
            "triples_path": str(paths.triples_path),
            "subgraph_path": str(paths.subgraph_path),
            "backbone_path": str(paths.backbone_path),
            "unit_event_path": str(paths.unit_event_path),
            "unit_index_path": str(paths.unit_index_path),
        },
        "outputs": {
            "scenario_output": str(paths.chain_dir / "builder_diagnostics.offline.v1.json"),
        },
    }
    return out


def _write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)
        f.write("\n")


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = [
        "scenario",
        "timestamp_dir",
        "subgraph_status",
        "subgraph_note",
        "builder_mode",
        "triples_edges",
        "subgraph_edges",
        "backbone_edges",
        "subgraph_over_triples",
        "backbone_over_subgraph",
        "backbone_over_triples",
        "triples_with_unit_ratio",
        "subgraph_with_unit_ratio",
        "backbone_with_unit_ratio",
        "subgraph_seed_touch_ratio",
        "backbone_seed_touch_ratio",
        "textual_summary",
        "unit_index_usage_note",
    ]
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for r in rows:
            w.writerow(r)


def _group_mode_compare(diags: list[dict[str, Any]]) -> dict[str, Any]:
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for d in diags:
        if d.get("status") != "ok":
            continue
        opt = d.get("optional_artifacts", {}).get("attack_subgraph", {})
        if opt.get("status") != "available":
            continue
        mode = str(d.get("mode", {}).get("builder_mode", "UNKNOWN"))
        groups[mode].append(d)

    out: dict[str, Any] = {}
    for mode, items in groups.items():
        sub_over_tri = [float(x["funnel"]["subgraph_over_triples"]) for x in items]
        back_over_sub = [float(x["funnel"]["backbone_over_subgraph"]) for x in items]
        out[mode] = {
            "scenario_count": len(items),
            "scenarios": [x["scenario"] for x in items],
            "avg_subgraph_over_triples": round(mean(sub_over_tri), 6) if sub_over_tri else 0.0,
            "median_subgraph_over_triples": round(median(sub_over_tri), 6) if sub_over_tri else 0.0,
            "avg_backbone_over_subgraph": round(mean(back_over_sub), 6) if back_over_sub else 0.0,
            "median_backbone_over_subgraph": round(median(back_over_sub), 6) if back_over_sub else 0.0,
        }
    return out


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Offline diagnostics for builder convergence (v1)")
    p.add_argument(
        "--results-root",
        type=Path,
        default=Path("results"),
        help="Root directory containing scenario result trees",
    )
    p.add_argument(
        "--reports-dir",
        type=Path,
        default=Path(__file__).resolve().parents[3] / "seclog_work" / "verification_20260321",
        help="Directory for batch-level summary outputs",
    )
    p.add_argument(
        "--scenarios",
        nargs="*",
        default=DEFAULT_SCENARIOS,
        help="Scenario relative paths under results root",
    )
    return p.parse_args()


def main() -> int:
    args = parse_args()
    results_root = args.results_root.resolve()
    reports_dir = args.reports_dir.resolve()

    diagnostics: list[dict[str, Any]] = []
    table_rows: list[dict[str, Any]] = []

    for scenario in args.scenarios:
        paths = _build_paths(results_root, scenario)
        if paths is None:
            d = {
                "diagnostics_version": DIAGNOSTICS_VERSION,
                "input_artifact_contract": INPUT_ARTIFACT_CONTRACT,
                "scenario": scenario,
                "status": "scenario_not_found_or_no_timestamp",
            }
            diagnostics.append(d)
            continue

        d = diagnose_one(paths)
        diagnostics.append(d)

        # Scenario-level sidecar output.
        scenario_out = paths.chain_dir / "builder_diagnostics.offline.v1.json"
        _write_json(scenario_out, d)

        if d.get("status") == "ok":
            subgraph_meta = d.get("optional_artifacts", {}).get("attack_subgraph", {})
            table_rows.append(
                {
                    "scenario": d["scenario"],
                    "timestamp_dir": d["timestamp_dir"],
                    "subgraph_status": subgraph_meta.get("status", "unknown"),
                    "subgraph_note": subgraph_meta.get("note", ""),
                    "builder_mode": d["mode"].get("builder_mode", "UNKNOWN"),
                    "triples_edges": d["funnel"]["triples_edges"],
                    "subgraph_edges": d["funnel"]["subgraph_edges"],
                    "backbone_edges": d["funnel"]["backbone_edges"],
                    "subgraph_over_triples": d["funnel"]["subgraph_over_triples"],
                    "backbone_over_subgraph": d["funnel"]["backbone_over_subgraph"],
                    "backbone_over_triples": d["funnel"]["backbone_over_triples"],
                    "triples_with_unit_ratio": d["stages"]["triples"]["with_unit_ratio"],
                    "subgraph_with_unit_ratio": d["stages"]["subgraph"]["with_unit_ratio"],
                    "backbone_with_unit_ratio": d["stages"]["backbone"]["with_unit_ratio"],
                    "subgraph_seed_touch_ratio": d["stages"]["subgraph"]["seed_touch_ratio"],
                    "backbone_seed_touch_ratio": d["stages"]["backbone"]["seed_touch_ratio"],
                    "textual_summary": d["textual_summary"],
                    "unit_index_usage_note": d["unit_index_usage_note"],
                }
            )

    summary = {
        "diagnostics_version": DIAGNOSTICS_VERSION,
        "input_artifact_contract": INPUT_ARTIFACT_CONTRACT,
        "scenarios": args.scenarios,
        "results_root": str(results_root),
        "reports_dir": str(reports_dir),
        "mode_group_comparison": _group_mode_compare(diagnostics),
        "per_scenario": diagnostics,
    }

    summary_json = reports_dir / "builder_diagnostics_offline_summary.v1.json"
    table_csv = reports_dir / "builder_diagnostics_offline_table.v1.csv"

    _write_json(summary_json, summary)
    _write_csv(table_csv, table_rows)

    print("[diagnose_builder_convergence_v1] done")
    print(f"  scenarios={len(args.scenarios)}")
    print(f"  summary_json={summary_json}")
    print(f"  table_csv={table_csv}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
