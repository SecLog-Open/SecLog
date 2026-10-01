#!/usr/bin/env python3
"""
Joint diagnostic (read-only) over one scenario's already-built products.

For a given scenario_dir this script answers three questions without
touching any production artefact:

  1. Among applog / traffic records produced by ``analyze``, which ones
     did NOT land in the main sample, and of those which are likely
     high-value (error/exception/db_query/auth_session for applog,
     attack-relevant server connections for traffic)?

  2. Which already-attached records look redundant — same pattern, same
     connection, heavy concentration on a few spine edges — that a
     downstream consumer could drop without information loss?

  3. Does backbone look "locally too narrow" (i.e. high-value strong
     evidence exists but the main sample can't host it because backbone
     did not retain a representative connection / request edge)?

Output: one JSON file per scenario under
``chain/multisource_coverage_diag.v0.json``.  Nothing else is
written.  Use as many ``--scenario-dir`` flags as needed.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from pipeline.utils.common import scenario_chain_dir


# ──────────────────────────────────────────────────────────────────────
# Light semantic classifier (mirrors the builder's rules so we can
# reason about unattached applog categories the same way).
# ──────────────────────────────────────────────────────────────────────

_ACCESS_LOG_PATTERNS = (
    re.compile(r'"\s*(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|CONNECT)\s+'),
    re.compile(r'\s-\s-\s\[\d{1,2}/\w+/\d{4}'),
)
_SQL_PATTERNS = (
    re.compile(r'\b(?:SELECT|INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM|CREATE\s+TABLE|ALTER\s+TABLE|DROP\s+TABLE)\b', re.IGNORECASE),
)
_ERROR_PATTERNS = (
    re.compile(r'\b(?:ERROR|FATAL|CRITICAL|Exception|Traceback|stacktrace)\b'),
    re.compile(r'\b5\d\d\s'),
)
_WARN_PATTERNS = (
    re.compile(r'\b(?:WARN|WARNING)\b'),
)
_AUTH_PATTERNS = (
    re.compile(r'\b(?:login|logout|auth|session|sign\s*in|sign\s*out|token|password|credential)\b', re.IGNORECASE),
)
_FILE_OP_PATTERNS = (
    re.compile(r'\b(?:upload|download|unlink|rename)\b', re.IGNORECASE),
)
_STARTUP_PATTERNS = (
    re.compile(r'\b(?:starting|started|initializ\w+|bootstrap|listening on|Ready|bind\s+to|Loading\s+\w+\s+[Ss]ervice|extensions\.\.\.)\b', re.IGNORECASE),
)


def _classify_semantic(message: str, log_style: Optional[str]) -> str:
    m = message or ""
    lstyle = (log_style or "").lower()
    if any(p.search(m) for p in _ERROR_PATTERNS):
        return "error_exception"
    if any(p.search(m) for p in _WARN_PATTERNS):
        return "warn_event"
    if lstyle == "access_text" or any(p.search(m) for p in _ACCESS_LOG_PATTERNS):
        return "request_access"
    if any(p.search(m) for p in _SQL_PATTERNS):
        return "db_query"
    if any(p.search(m) for p in _AUTH_PATTERNS):
        return "auth_session"
    if any(p.search(m) for p in _FILE_OP_PATTERNS):
        return "file_operation"
    if any(p.search(m) for p in _STARTUP_PATTERNS):
        return "startup_runtime"
    return "generic_runtime_log"


_TS_RE = re.compile(r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?')
_APACHE_TS_RE = re.compile(r'\d{1,2}/[A-Za-z]+/\d{4}:\d{2}:\d{2}:\d{2}(?:\s[+\-]\d{4})?')
_IP_RE = re.compile(r'\b\d+(?:\.\d+){3}(?::\d+)?\b')
_NUM_RE = re.compile(r'\b\d{4,}\b')
_STR_RE = re.compile(r'"[^"]*"')


def _normalize_pattern(msg: str) -> str:
    if not msg:
        return ""
    t = msg
    t = _TS_RE.sub('<ts>', t)
    t = _APACHE_TS_RE.sub('<ts>', t)
    t = _IP_RE.sub('<ip>', t)
    t = _NUM_RE.sub('<num>', t)
    t = _STR_RE.sub('"<str>"', t)
    return t.strip()[:200]


# ──────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────

def _iter_jsonl(path: Path):
    if not path.exists():
        return
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def _parse_spine_ts_unix(ts: Any) -> Optional[float]:
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


def _conn_key(proto: Any, sip: Any, sport: Any, dip: Any, dport: Any) -> Optional[str]:
    p = str(proto or "").lower().strip()
    try:
        sp = int(sport); dp = int(dport)
    except (TypeError, ValueError):
        return None
    if not p or not sip or not dip:
        return None
    return f"{p}|{sip}:{sp}|{dip}:{dp}"


_FD_RE = re.compile(r'^\s*([^\s:]+):(\d+)\s*->\s*([^\s:]+):(\d+)\s*$')


def _parse_fd_name(fd: Any) -> Optional[tuple[str, int, str, int]]:
    if not fd:
        return None
    m = _FD_RE.match(str(fd))
    if not m:
        return None
    try:
        return m.group(1), int(m.group(2)), m.group(3), int(m.group(4))
    except (TypeError, ValueError):
        return None


# ──────────────────────────────────────────────────────────────────────
# Diagnostic core
# ──────────────────────────────────────────────────────────────────────

def diagnose(scenario_dir: Path) -> dict[str, Any]:
    chain_dir = scenario_chain_dir(scenario_dir)
    index_dir = scenario_dir / "index"

    dataset_path = chain_dir / "behavior_chain_dataset.v2.json"
    backbone_path = chain_dir / "backbone_chain.v1.json"

    if not dataset_path.exists() or not backbone_path.exists():
        raise FileNotFoundError(f"missing dataset or backbone under {scenario_dir}")

    dataset = json.loads(dataset_path.read_text(encoding="utf-8", errors="replace"))
    backbone = json.loads(backbone_path.read_text(encoding="utf-8", errors="replace"))

    spine = dataset.get("spine") or []
    backbone_edges = backbone.get("edge_sequence") or []

    # ── applog: attached + model context ──
    applog_model_path = index_dir / "applog_model_context.v0.jsonl"
    write_ctx_path = index_dir / "write_event_context_index.v0.jsonl"
    unit_event_path = index_dir / "unit_event_index.jsonl"

    applog_model_by_key: dict[str, dict[str, Any]] = {}
    for r in _iter_jsonl(applog_model_path):
        k = r.get("event_key")
        if k:
            applog_model_by_key[str(k)] = r
    write_ctx_by_key: dict[str, dict[str, Any]] = {}
    for r in _iter_jsonl(write_ctx_path):
        k = r.get("applog_event_key")
        if k:
            write_ctx_by_key[str(k)] = r
    evt_to_unit: dict[int, dict[str, Any]] = {}
    for r in _iter_jsonl(unit_event_path):
        try:
            en = int(r.get("evt_num"))
        except (TypeError, ValueError):
            continue
        evt_to_unit[en] = r

    # attached applog keys — bucket by each entry's own backbone edge id
    # (main v2 spine entries don't carry edge_id themselves; the writeback
    # is keyed by attach_to_backbone_edge_id on every attached record).
    attached_applog_keys: set[str] = set()
    applog_by_edge: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for e in spine:
        for a in (e.get("multisource_context") or {}).get("applog") or []:
            k = a.get("event_key")
            if k:
                attached_applog_keys.add(str(k))
            target = str(a.get("attach_to_backbone_edge_id") or e.get("edge_id") or "")
            applog_by_edge[target].append(a)

    # ── traffic: anchors + conntrack + attached ──
    traffic_anchor_path = index_dir / "traffic_node_anchor_index.v0.jsonl"
    conntrack_path = index_dir / "conntrack_nat_index.v0.jsonl"

    # Build backbone NET_* conn_key index (assume TCP, as builder does)
    net_edge_by_conn: dict[str, list[dict[str, Any]]] = defaultdict(list)
    backbone_net_conn_keys: set[str] = set()
    backbone_all_evt_nums: set[int] = set()
    backbone_rel_counter: Counter[str] = Counter()
    for edge in backbone_edges:
        attrs = edge.get("attrs") or {}
        try:
            en = int(attrs.get("evt_num"))
        except (TypeError, ValueError):
            en = None
        if en is not None:
            backbone_all_evt_nums.add(en)
        rel = str(edge.get("relation") or "").upper()
        backbone_rel_counter[rel] += 1
        if not rel.startswith("NET_"):
            continue
        tup = _parse_fd_name(attrs.get("fd_name"))
        if not tup:
            continue
        ck = _conn_key("tcp", tup[0], tup[1], tup[2], tup[3])
        if ck:
            net_edge_by_conn[ck].append(edge)
            backbone_net_conn_keys.add(ck)

    conntrack_rows = list(_iter_jsonl(conntrack_path))
    # NAT alias index
    nat_alias: dict[str, set[str]] = defaultdict(set)
    for r in conntrack_rows:
        proto = r.get("transport_proto")
        keys = set()
        for (a, b, c, d) in (
            (r.get("orig_src_ip"), r.get("orig_src_port"),
             r.get("orig_dst_ip"), r.get("orig_dst_port")),
            (r.get("orig_dst_ip"), r.get("orig_dst_port"),
             r.get("orig_src_ip"), r.get("orig_src_port")),
            (r.get("reply_src_ip"), r.get("reply_src_port"),
             r.get("reply_dst_ip"), r.get("reply_dst_port")),
            (r.get("reply_dst_ip"), r.get("reply_dst_port"),
             r.get("reply_src_ip"), r.get("reply_src_port")),
        ):
            ck = _conn_key(proto, a, b, c, d)
            if ck:
                keys.add(ck)
        for ck in keys:
            nat_alias[ck].update(keys - {ck})

    # ── applog unattached scan ──
    applog_semantic_all: Counter[str] = Counter()
    applog_semantic_attached: Counter[str] = Counter()
    applog_semantic_unattached: Counter[str] = Counter()
    applog_unattached_service: Counter[str] = Counter()
    applog_unattached_source_file: Counter[str] = Counter()
    applog_unattached_log_style: Counter[str] = Counter()
    applog_unattached_high_value_samples: list[dict[str, Any]] = []
    applog_unattached_has_writer_identity_high_value = 0

    # Evidence hints for each unattached record (why they likely didn't attach)
    unattached_reason: Counter[str] = Counter()

    for event_key, model_rec in applog_model_by_key.items():
        msg = str(model_rec.get("normalized_message") or model_rec.get("raw_message") or "")
        sem = _classify_semantic(msg, model_rec.get("log_style"))
        applog_semantic_all[sem] += 1
        if event_key in attached_applog_keys:
            applog_semantic_attached[sem] += 1
            continue
        applog_semantic_unattached[sem] += 1
        applog_unattached_service[str(model_rec.get("service_name") or "")] += 1
        applog_unattached_source_file[str(model_rec.get("source_file") or "")] += 1
        applog_unattached_log_style[str(model_rec.get("log_style") or "")] += 1

        # Estimate attach-eligibility: does it have strong writer identity?
        wec = write_ctx_by_key.get(event_key, {})
        matched_evt = wec.get("matched_evt_num")
        try:
            matched_evt_i = int(matched_evt) if matched_evt is not None else None
        except (TypeError, ValueError):
            matched_evt_i = None
        u = evt_to_unit.get(matched_evt_i) if matched_evt_i is not None else None
        has_tvtid = bool(u and u.get("thread_vtid") and str(u.get("thread_vtid")).lower() != "null")
        has_unit = bool(u and u.get("unit_id") and str(u.get("unit_id")).lower() != "null")
        wcid = wec.get("write_container_id") or (u or {}).get("container_id")

        # Reason classification
        if matched_evt_i is not None and matched_evt_i in backbone_all_evt_nums:
            # write evt is in backbone but writeback still missed it → should not happen
            unattached_reason["write_evt_is_backbone_but_missed"] += 1
        elif has_tvtid:
            unattached_reason["writer_thread_known_no_backbone_match"] += 1
        elif wcid:
            unattached_reason["container_known_no_writer_thread"] += 1
        else:
            unattached_reason["no_writer_identity"] += 1

        if sem in {"error_exception", "warn_event", "db_query", "auth_session"}:
            if has_tvtid or has_unit or wec.get("write_proc_pid") is not None:
                applog_unattached_has_writer_identity_high_value += 1
            if len(applog_unattached_high_value_samples) < 15:
                applog_unattached_high_value_samples.append({
                    "event_key": event_key,
                    "semantic_type": sem,
                    "service_name": model_rec.get("service_name"),
                    "source_file": model_rec.get("source_file"),
                    "log_style": model_rec.get("log_style"),
                    "matched_evt_num": matched_evt_i,
                    "has_thread_vtid": has_tvtid,
                    "has_unit_id": has_unit,
                    "write_proc_pid": wec.get("write_proc_pid"),
                    "write_container_id": wcid,
                    "message_head": msg[:160],
                })

    # ── applog redundancy in attached set ──
    applog_edges_total = 0
    applog_emitted_total = 0
    applog_max_per_edge = 0
    applog_weak_total = 0
    applog_weak_dup_rep_total = 0
    applog_strength_counter: Counter[str] = Counter()
    applog_semantic_attached_detail: Counter[str] = Counter()
    applog_top_pattern_per_edge: list[dict[str, Any]] = []
    per_edge_applog_size_hist: Counter[int] = Counter()
    per_edge_pattern_dup: list[dict[str, Any]] = []

    for edge_id, items in applog_by_edge.items():
        if not items:
            continue
        applog_edges_total += 1
        applog_emitted_total += len(items)
        applog_max_per_edge = max(applog_max_per_edge, len(items))
        per_edge_applog_size_hist[len(items)] += 1
        per_edge_patterns: Counter[str] = Counter()
        for a in items:
            st = str(a.get("attach_strength") or "unknown")
            applog_strength_counter[st] += 1
            sem = a.get("semantic_type") or "unknown"
            applog_semantic_attached_detail[sem] += 1
            msg = str(a.get("message") or "")
            pat = _normalize_pattern(msg)
            per_edge_patterns[pat] += 1
            if st == "weak":
                applog_weak_total += 1
                dc = int(a.get("duplicate_count") or 1)
                if dc > 1:
                    applog_weak_dup_rep_total += 1
        if per_edge_patterns:
            top_pat, top_ct = per_edge_patterns.most_common(1)[0]
            if top_ct >= 2 or len(items) >= 5:
                per_edge_pattern_dup.append({
                    "edge_id": edge_id,
                    "entries": len(items),
                    "top_pattern_count": top_ct,
                    "top_pattern": top_pat[:160],
                })

    # ── traffic unattached scan ──
    attached_traffic_keys: set[str] = set()
    traffic_by_edge: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for e in spine:
        for t in (e.get("multisource_context") or {}).get("traffic") or []:
            k = t.get("event_key")
            if k:
                attached_traffic_keys.add(str(k))
            target = str(t.get("attach_to_backbone_edge_id") or e.get("edge_id") or "")
            traffic_by_edge[target].append(t)

    traffic_anchor_total = 0
    traffic_unattached_count = 0
    traffic_unattached_by_conn: dict[str, dict[str, Any]] = defaultdict(
        lambda: {"packet_count": 0, "services": set(), "nat_hit": False,
                 "conn_in_backbone": False, "containers": set()}
    )
    # also conn_key universe seen in traffic
    traffic_conn_universe: set[str] = set()

    for r in _iter_jsonl(traffic_anchor_path):
        if str(r.get("record_type") or "") != "anchor":
            continue
        traffic_anchor_total += 1
        pr = r.get("packet_ref") or {}
        pf = r.get("packet_feature") or {}
        na = r.get("node_anchor") or {}
        ck = _conn_key(
            pf.get("l4_proto"),
            pf.get("src_ip"), pf.get("src_port"),
            pf.get("dst_ip"), pf.get("dst_port"),
        )
        rev = _conn_key(
            pf.get("l4_proto"),
            pf.get("dst_ip"), pf.get("dst_port"),
            pf.get("src_ip"), pf.get("src_port"),
        )
        if ck:
            traffic_conn_universe.add(ck)
        evk = str(pr.get("event_key") or "")
        if evk in attached_traffic_keys:
            continue
        traffic_unattached_count += 1

        keys = {ck, rev} - {None}
        aliased = set()
        for k in list(keys):
            aliased.update(nat_alias.get(k, set()))
        all_keys = keys | aliased
        in_backbone = any(k in backbone_net_conn_keys for k in all_keys)
        primary = ck or rev or "unknown"
        slot = traffic_unattached_by_conn[primary]
        slot["packet_count"] += 1
        if na.get("service_name"):
            slot["services"].add(str(na["service_name"]))
        if na.get("container_id"):
            slot["containers"].add(str(na["container_id"]))
        if aliased:
            slot["nat_hit"] = True
        if in_backbone:
            slot["conn_in_backbone"] = True

    # flatten unattached conn summaries
    traffic_unattached_conns: list[dict[str, Any]] = []
    for ck, slot in traffic_unattached_by_conn.items():
        traffic_unattached_conns.append({
            "conn_key": ck,
            "packet_count": slot["packet_count"],
            "services": sorted(slot["services"]),
            "containers": sorted(slot["containers"]),
            "nat_hit": slot["nat_hit"],
            "already_conn_in_backbone": slot["conn_in_backbone"],
        })
    traffic_unattached_conns.sort(key=lambda d: -d["packet_count"])

    # Rough high-value heuristic: server-side ports (1–1024 or common),
    # container bound, multiple packets.
    def _looks_high_value_conn(conn_key: str) -> bool:
        if not conn_key or conn_key == "unknown":
            return False
        parts = conn_key.split("|")
        if len(parts) < 3:
            return False
        try:
            dp = int(parts[2].split(":")[1])
        except (ValueError, IndexError):
            return False
        if dp in {
            21, 22, 23, 25, 53, 80, 81, 82, 88, 389, 443, 445, 465, 587,
            636, 993, 995, 1433, 1521, 1723, 3000, 3306, 3389, 5000,
            5432, 5601, 5900, 5984, 6379, 7000, 7443, 7474, 7687, 8000,
            8080, 8081, 8088, 8090, 8443, 8500, 8888, 9000, 9042, 9092,
            9200, 9300, 9418, 11211, 27017, 50000,
        }:
            return True
        return False

    traffic_unattached_hv = [
        d for d in traffic_unattached_conns
        if _looks_high_value_conn(d["conn_key"])
    ]

    # Traffic redundancy: per-edge entries & conn repetition
    traffic_edges_total = 0
    traffic_emitted_total = 0
    traffic_max_per_edge = 0
    traffic_same_conn_per_edge: list[dict[str, Any]] = []
    per_edge_conn_dup: Counter[int] = Counter()
    for edge_id, items in traffic_by_edge.items():
        if not items:
            continue
        traffic_edges_total += 1
        traffic_emitted_total += len(items)
        traffic_max_per_edge = max(traffic_max_per_edge, len(items))
        conns = Counter(t.get("normalized_conn_key") for t in items)
        top_ck, top_ct = conns.most_common(1)[0]
        per_edge_conn_dup[top_ct] += 1
        if top_ct >= 2:
            traffic_same_conn_per_edge.append({
                "edge_id": edge_id,
                "entries": len(items),
                "top_conn": top_ck,
                "top_conn_packets": top_ct,
            })
    traffic_same_conn_per_edge.sort(key=lambda d: -d["top_conn_packets"])

    summary = {
        "schema_version": "multisource_coverage_diag.v0",
        "scenario_dir": str(scenario_dir),
        "backbone": {
            "edge_count": len(backbone_edges),
            "relation_counter": dict(backbone_rel_counter),
            "net_connection_count": len(backbone_net_conn_keys),
        },
        "applog": {
            "total_in_model_context": len(applog_model_by_key),
            "attached_count": len(attached_applog_keys),
            "unattached_count": len(applog_model_by_key) - len(attached_applog_keys),
            "semantic_total": dict(applog_semantic_all),
            "semantic_attached": dict(applog_semantic_attached),
            "semantic_unattached": dict(applog_semantic_unattached),
            "unattached_by_service": dict(
                sorted(applog_unattached_service.items(), key=lambda p: -p[1])[:10]
            ),
            "unattached_by_source_file": dict(
                sorted(applog_unattached_source_file.items(), key=lambda p: -p[1])[:10]
            ),
            "unattached_by_log_style": dict(applog_unattached_log_style),
            "unattached_reason_breakdown": dict(unattached_reason),
            "unattached_high_value_with_writer_identity": applog_unattached_has_writer_identity_high_value,
            "unattached_high_value_samples": applog_unattached_high_value_samples,
            "attached_stats": {
                "edges_with_applog": applog_edges_total,
                "emitted_total": applog_emitted_total,
                "max_per_edge": applog_max_per_edge,
                "strength_breakdown": dict(applog_strength_counter),
                "semantic_breakdown": dict(applog_semantic_attached_detail),
                "weak_total": applog_weak_total,
                "weak_representatives_with_duplicates": applog_weak_dup_rep_total,
                "per_edge_size_histogram": dict(per_edge_applog_size_hist),
            },
            "redundancy_observations": {
                "edges_with_dominant_pattern": per_edge_pattern_dup[:10],
            },
        },
        "traffic": {
            "anchor_total": traffic_anchor_total,
            "attached_count": len(attached_traffic_keys),
            "unattached_count": traffic_unattached_count,
            "unique_traffic_connection_count": len(traffic_conn_universe),
            "backbone_net_connection_count": len(backbone_net_conn_keys),
            "unattached_connection_count": len(traffic_unattached_conns),
            "unattached_high_value_connection_count": len(traffic_unattached_hv),
            "top_unattached_connections": traffic_unattached_conns[:15],
            "top_unattached_high_value_connections": traffic_unattached_hv[:15],
            "attached_stats": {
                "edges_with_traffic": traffic_edges_total,
                "emitted_total": traffic_emitted_total,
                "max_per_edge": traffic_max_per_edge,
                "per_edge_top_conn_duplicate_hist": dict(per_edge_conn_dup),
            },
            "redundancy_observations": {
                "edges_with_repeated_same_conn": traffic_same_conn_per_edge[:10],
            },
        },
    }
    return summary


def main(argv: Optional[list[str]] = None) -> int:
    p = argparse.ArgumentParser(
        description="Joint diagnostic of applog/traffic coverage and redundancy"
    )
    p.add_argument("--scenario-dir", type=Path, action="append", required=True)
    args = p.parse_args(argv)
    for sd in args.scenario_dir:
        summary = diagnose(sd)
        out = scenario_chain_dir(sd) / "multisource_coverage_diag.v0.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(
            json.dumps(summary, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        ap = summary["applog"]
        tr = summary["traffic"]
        bb = summary["backbone"]
        print(
            f"[coverage] {sd.name} "
            f"backbone_edges={bb['edge_count']} "
            f"net_conn={bb['net_connection_count']} | "
            f"applog attached={ap['attached_count']}/{ap['total_in_model_context']} "
            f"unattached_hv_with_id={ap['unattached_high_value_with_writer_identity']} | "
            f"traffic attached={tr['attached_count']}/{tr['anchor_total']} "
            f"unattached_conns={tr['unattached_connection_count']} "
            f"hv={tr['unattached_high_value_connection_count']}"
        )
        print(f"[coverage] -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
