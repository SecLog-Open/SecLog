#!/usr/bin/env python3
"""
Read-only post-upgrade observations for two open design questions:

  (P3) Is a finer-grained ``traffic.semantic_type`` classification
       worth turning on? Observe over *real* ``flow_summary``
       records: dst/src port profile, service_name, direction balance,
       local-vs-external profile. Propose rules or recommend keeping
       the current backbone-relation-only mapping.

  (P4) Is there any emitted HV applog record whose ``sec_delta``
       lands in the relaxed 10s HV window but is actually "too far"
       (e.g. >8s) to trust? Summarise the distribution so we can
       decide whether to turn on a soft lower-bound.

No production artefact is written; per-scenario JSON goes to
``chain/post_upgrade_observations.v0.json``.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Optional

from pipeline.utils.common import scenario_chain_dir


# ── helpers ────────────────────────────────────────────────────────────

def _is_ipv4_private(ip: Any) -> bool:
    s = str(ip or "")
    if s.startswith("10.") or s.startswith("192.168.") or s.startswith("127."):
        return True
    if s.startswith("172."):
        try:
            second = int(s.split(".")[1])
            if 16 <= second <= 31:
                return True
        except (ValueError, IndexError):
            return False
    return False


def _is_loopback(ip: Any) -> bool:
    s = str(ip or "")
    return s.startswith("127.") or s == "::1" or s.startswith("::1:")


def _is_container_private(ip: Any) -> bool:
    s = str(ip or "")
    # Docker default bridges use 172.16-31. Our benchmark uses 192.168.123.*
    return s.startswith("172.") or s.startswith("192.168.")


# Common service ports (same set used in prior coverage diag).
_SERVICE_PORT_ROLES = {
    # Web
    80: "http", 443: "https", 8080: "http_alt", 8081: "http_alt",
    8443: "https_alt", 8090: "http_alt", 8888: "http_alt",
    # DB
    3306: "mysql", 5432: "postgres", 6379: "redis", 27017: "mongodb",
    1433: "mssql", 1521: "oracle", 9042: "cassandra",
    # Search / analytics
    9200: "elasticsearch", 9300: "elasticsearch",
    5601: "kibana",
    # Messaging
    9092: "kafka", 5672: "rabbitmq", 61616: "activemq",
    # RCE-oriented / remote
    22: "ssh", 23: "telnet", 21: "ftp", 3389: "rdp",
    # Mail
    25: "smtp", 465: "smtps", 587: "submission", 993: "imaps", 995: "pop3s",
    # Shell-ish
    4444: "shell_backconnect", 1337: "shell_backconnect",
    8000: "http_alt", 5000: "http_alt", 5984: "couchdb",
    11211: "memcached", 2375: "docker_api", 2376: "docker_api_tls",
    50000: "jmx_or_other", 8500: "consul",
}


def _role_of_port(port: Any) -> Optional[str]:
    try:
        return _SERVICE_PORT_ROLES.get(int(port))
    except (TypeError, ValueError):
        return None


def _propose_semantic_type(summary: dict[str, Any]) -> str:
    """Structure-only proposal: what a finer-grained semantic could be.
    Keeps existing backbone-relation-derived label as the coarse base
    and only refines when evidence is structural and unambiguous.
    """
    base = summary.get("semantic_type") or "generic_net_context"
    src = str(summary.get("src_ip") or "")
    dst = str(summary.get("dst_ip") or "")
    dport = summary.get("dst_port")
    sport = summary.get("src_port")
    # Role lookups — only trust when exactly one side is a well-known
    # service port, otherwise stay at the coarse base label.
    d_role = _role_of_port(dport)
    s_role = _role_of_port(sport)
    # Loopback flows (always service-local)
    loop = _is_loopback(src) and _is_loopback(dst)

    # DB request: dst_port is DB; src is internal private
    if d_role in {"mysql", "postgres", "mongodb", "redis", "mssql",
                  "oracle", "elasticsearch", "cassandra"}:
        if base in ("outbound_call_flow", "inbound_data_flow",
                    "response_data_flow", "generic_net_context"):
            return "db_request_flow"
    # Kibana / web admin
    if d_role in {"kibana"} and not loop:
        return "web_admin_flow"
    # Shell back-connect pattern (outbound to known RCE ports)
    if d_role in {"shell_backconnect", "ssh", "rdp", "telnet"}:
        return "callback_flow"
    # Lateral: internal-to-internal non-loopback, no HTTP role but
    # known service port class → keep base but annotate.
    # (Disabled by default — too ambiguous without ground truth.)

    return base


# ── diagnostic core ────────────────────────────────────────────────────

def diagnose(scenario_dir: Path) -> dict[str, Any]:
    dataset_path = scenario_chain_dir(scenario_dir) / "behavior_chain_dataset.v2.json"
    if not dataset_path.exists():
        return {"scenario_dir": str(scenario_dir), "skipped": "no dataset"}
    d = json.loads(dataset_path.read_text(encoding="utf-8", errors="replace"))

    # Traffic observations
    coarse_by_rel: Counter[str] = Counter()
    proposed_counter: Counter[str] = Counter()
    proposed_by_base: dict[str, Counter[str]] = defaultdict(Counter)
    dst_port_role: Counter[str] = Counter()
    src_port_role: Counter[str] = Counter()
    direction_bias: Counter[str] = Counter()
    local_vs_external: Counter[str] = Counter()
    flow_count = rep_count = 0

    # HV applog observations
    hv_total = 0
    hv_by_semantic: Counter[str] = Counter()
    sec_delta_buckets: Counter[str] = Counter()
    hv_over_8s: list[dict[str, Any]] = []
    hv_relaxed_only: list[dict[str, Any]] = []

    def _bucket(delta: Optional[float]) -> str:
        if delta is None:
            return "nil"
        if delta <= 1.0:
            return "<=1s"
        if delta <= 2.0:
            return "<=2s"
        if delta <= 5.0:
            return "<=5s"
        if delta <= 8.0:
            return "<=8s"
        if delta <= 10.0:
            return "<=10s"
        return ">10s"

    for e in d.get("spine") or []:
        msc = e.get("multisource_context") or {}

        # Traffic
        for t in msc.get("traffic") or []:
            st = t.get("summary_type")
            if st == "flow_summary":
                flow_count += 1
                rel = t.get("attach_basis", {}).get("backbone_relation") or ""
                coarse = t.get("semantic_type") or "generic_net_context"
                coarse_by_rel[f"{rel}->{coarse}"] += 1
                proposal = _propose_semantic_type(t)
                proposed_counter[proposal] += 1
                proposed_by_base[coarse][proposal] += 1
                dr = _role_of_port(t.get("dst_port")) or "unknown_port"
                sr = _role_of_port(t.get("src_port")) or "unknown_port"
                dst_port_role[dr] += 1
                src_port_role[sr] += 1
                dc = t.get("direction_counts") or {}
                fwd = int(dc.get("forward") or 0)
                rev = int(dc.get("reverse") or 0)
                total = max(fwd + rev, 1)
                ratio = fwd / total
                if ratio >= 0.9:
                    direction_bias["forward_dominant"] += 1
                elif ratio <= 0.1:
                    direction_bias["reverse_dominant"] += 1
                else:
                    direction_bias["mixed"] += 1
                src_local = _is_loopback(t.get("src_ip")) or _is_container_private(t.get("src_ip"))
                dst_local = _is_loopback(t.get("dst_ip")) or _is_container_private(t.get("dst_ip"))
                if _is_loopback(t.get("src_ip")) and _is_loopback(t.get("dst_ip")):
                    local_vs_external["loopback"] += 1
                elif src_local and dst_local:
                    local_vs_external["container_to_container"] += 1
                elif not src_local and dst_local:
                    local_vs_external["external_to_container"] += 1
                elif src_local and not dst_local:
                    local_vs_external["container_to_external"] += 1
                else:
                    local_vs_external["other"] += 1
            elif st == "representative_packet":
                rep_count += 1

        # HV applog
        for a in msc.get("applog") or []:
            sem = a.get("semantic_type") or ""
            if sem not in ("error_exception", "warn_event",
                           "db_query", "auth_session"):
                continue
            hv_total += 1
            hv_by_semantic[sem] += 1
            basis = a.get("attach_basis") or {}
            sd = basis.get("sec_delta")
            try:
                sd_f = float(sd) if sd is not None else None
            except (TypeError, ValueError):
                sd_f = None
            sec_delta_buckets[_bucket(sd_f)] += 1
            if basis.get("hv_window_relaxation") and len(hv_relaxed_only) < 10:
                hv_relaxed_only.append({
                    "event_key": a.get("event_key"),
                    "semantic_type": sem,
                    "sec_delta": sd_f,
                    "attach_reason": a.get("attach_reason"),
                    "attach_strength": a.get("attach_strength"),
                    "message_head": (a.get("message") or "")[:120],
                })
            if sd_f is not None and sd_f > 8.0 and len(hv_over_8s) < 10:
                hv_over_8s.append({
                    "event_key": a.get("event_key"),
                    "semantic_type": sem,
                    "sec_delta": sd_f,
                    "attach_reason": a.get("attach_reason"),
                    "attach_strength": a.get("attach_strength"),
                    "message_head": (a.get("message") or "")[:120],
                })

    return {
        "schema_version": "post_upgrade_observations.v0",
        "scenario_dir": str(scenario_dir),
        "traffic": {
            "flow_count": flow_count,
            "rep_count": rep_count,
            "coarse_by_relation_pair": dict(sorted(coarse_by_rel.items(), key=lambda p: -p[1])),
            "proposed_semantic_type_counts": dict(sorted(proposed_counter.items(), key=lambda p: -p[1])),
            "proposed_by_coarse_base": {k: dict(v) for k, v in proposed_by_base.items()},
            "dst_port_role": dict(sorted(dst_port_role.items(), key=lambda p: -p[1])),
            "src_port_role": dict(sorted(src_port_role.items(), key=lambda p: -p[1])),
            "direction_bias": dict(sorted(direction_bias.items(), key=lambda p: -p[1])),
            "local_vs_external": dict(sorted(local_vs_external.items(), key=lambda p: -p[1])),
        },
        "applog_hv": {
            "total": hv_total,
            "by_semantic": dict(sorted(hv_by_semantic.items(), key=lambda p: -p[1])),
            "sec_delta_buckets": dict(sec_delta_buckets),
            "samples_hv_window_relaxation": hv_relaxed_only,
            "samples_over_8s": hv_over_8s,
        },
    }


def main(argv: Optional[list[str]] = None) -> int:
    p = argparse.ArgumentParser(description="Post-upgrade observations")
    p.add_argument("--scenario-dir", type=Path, action="append", required=True)
    args = p.parse_args(argv)
    combined: dict[str, Any] = {
        "schema_version": "post_upgrade_observations.v0",
        "scenarios": [],
    }
    for sd in args.scenario_dir:
        s = diagnose(sd)
        combined["scenarios"].append(s)
        out = scenario_chain_dir(sd) / "post_upgrade_observations.v0.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(s, ensure_ascii=False, indent=2) + "\n",
                       encoding="utf-8")
        t = s.get("traffic", {})
        ap = s.get("applog_hv", {})
        print(
            f"[post-obs] {sd.name} "
            f"flows={t.get('flow_count',0)} reps={t.get('rep_count',0)} "
            f"HV_total={ap.get('total',0)} "
            f"sec_delta_buckets={ap.get('sec_delta_buckets',{})}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
