#!/usr/bin/env python3
"""
Extract core audit triples from sysdig JSONL logs using triple_rules_v1_1.json.

Scope constraints:
- Only process sysdig audit logs.
- Only emit core triples.
- Do not redesign rules; strictly follow rule mappings from JSON.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable, Optional

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from console_observability import ProgressLogger, emit_observation
from results_analysis.pipeline.utils.common import CHAIN_DIR_NAME


# Default single-scenario timestamp directory.
# Update this path to the scenario timestamp folder you want to process.
# SCENARIO_DIR = ROOT_DIR / "results" / "your_scenario" / "your_timestamp"
SCENARIO_DIR = ROOT_DIR / "results" / "vulhub" / "gitlist" / "CVE-2018-1000533" / "2026-03-17_02-32-45"

# Paths are derived from SCENARIO_DIR by default.
RAW_SYSDIG_DIR = SCENARIO_DIR / "raw" / "sysdig"
CHAIN_DIR = SCENARIO_DIR / CHAIN_DIR_NAME
DEFAULT_OUTPUT_JSONL = CHAIN_DIR / "audit_triples.core.v1.jsonl"
DEFAULT_AUXILIARY_OUTPUT_JSONL = CHAIN_DIR / "audit_triples.auxiliary.v1.jsonl"
DEFAULT_FILTERED_OUTPUT_JSONL = CHAIN_DIR / "audit_triples.filtered.v1.jsonl"
DEFAULT_UNKNOWN_OUTPUT_JSONL = CHAIN_DIR / "audit_triples.unknown.v1.jsonl"
DEFAULT_TIER_MANIFEST_JSON = CHAIN_DIR / "audit_triples_tier_manifest.v1.json"
DEFAULT_RELATION_STATS = CHAIN_DIR / "relation_stats.csv"
DEFAULT_SUMMARY_MD = CHAIN_DIR / "audit_triples_summary.md"
EXTRACT_INCOMPLETE_RC = 2

# IMPORTANT: verify whether this compatibility path is still active.
RULES_FILE = Path(__file__).resolve().parent / "audit_stats" / "triple_rules_v1_1.json"


try:
    import orjson  # type: ignore

    def _loads(line: str) -> dict[str, Any]:
        return orjson.loads(line)

    def _dumps(obj: dict[str, Any]) -> bytes:
        return orjson.dumps(obj)

except ImportError:
    def _loads(line: str) -> dict[str, Any]:
        return json.loads(line)

    def _dumps(obj: dict[str, Any]) -> bytes:
        return json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


FILELIKE_FD_TYPES = frozenset({"file", "directory", "fifo", "pipe", "blk", "chr"})
NETLIKE_FD_TYPES = frozenset({"ipv4", "ipv6", "ipv6v4", "ip", "unix"})
SPECIAL_FD_PREFIX = (
    "<",
    "anon_inode:",
    "socket:[",
    "pipe:[",
    "eventfd",
)

EPHEMERAL_LOW = 32768
EPHEMERAL_HIGH = 65535
SERVER_COMMON_PORTS = frozenset({20, 21, 22, 23, 25, 53, 80, 110, 123, 143, 389, 443, 445, 3306, 5432, 6379, 8080})

FD_CONN_RE = re.compile(
    r"^(\d{1,3}(?:\.\d{1,3}){3}):(\d+)->(\d{1,3}(?:\.\d{1,3}){3}):(\d+)$"
)


@dataclass(frozen=True)
class ScannedFile:
    path: Path
    scenario: str


class FileScanner:
    """Recursively scan sysdig audit files under one scenario's raw/sysdig directory."""

    _sysdig_segment = re.compile(r"[/\\]raw[/\\]sysdig(?:[/\\]|$)", re.IGNORECASE)
    _timestamp_dir = re.compile(r"^\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}$")
    _candidate_suffixes = {".jsonl", ".log", ".txt"}

    def scan(self, root: Path) -> list[ScannedFile]:
        out: list[ScannedFile] = []
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            if path.suffix.lower() not in self._candidate_suffixes:
                continue
            path_s = str(path)
            if not self._sysdig_segment.search(path_s):
                continue
            out.append(ScannedFile(path=path, scenario=self._extract_scenario(path)))
        out.sort(key=lambda x: str(x.path))
        return out

    @staticmethod
    def _extract_scenario(path: Path) -> str:
        parts = path.parts
        lowered = [p.lower() for p in parts]

        # Prefer directory right before timestamp-like folder, skipping raw/sysdig.
        for i, part in enumerate(parts):
            if not FileScanner._timestamp_dir.match(part):
                continue
            j = i - 1
            while j >= 0 and lowered[j] in {"raw", "sysdig"}:
                j -= 1
            if j >= 0:
                return parts[j]

        # Fallback to previous behavior.
        try:
            idx = lowered.index("sysdig")
            if idx >= 3:
                return parts[idx - 3]
        except ValueError:
            pass
        return "unknown"


class RuleMatcher:
    """Load and match rules from triple_rules_v1_1.json."""

    def __init__(self, rules_file: Path) -> None:
        with open(rules_file, "r", encoding="utf-8") as fh:
            data = json.load(fh)

        self.core_map: dict[str, dict[str, Any]] = {}
        self.aux_map: dict[str, dict[str, Any]] = {}
        self.filtered_map: dict[str, dict[str, Any]] = {}
        self.aux_set: set[str] = set()
        self.filtered_set: set[str] = set()

        for rule in data.get("core_rules", []):
            for raw_evt_type in rule.get("raw_evt_type", []):
                self.core_map[str(raw_evt_type)] = rule

        for rule in data.get("auxiliary_rules", []):
            raw = rule.get("raw_evt_type")
            if isinstance(raw, str):
                self.aux_set.add(raw)
                self.aux_map[raw] = rule
            elif isinstance(raw, list):
                for raw_evt_type in raw:
                    raw_s = str(raw_evt_type)
                    self.aux_set.add(raw_s)
                    self.aux_map[raw_s] = rule

        for rule in data.get("filtered_rules", []):
            raw = rule.get("raw_evt_type")
            if isinstance(raw, str):
                self.filtered_set.add(raw)
                self.filtered_map[raw] = rule
            elif isinstance(raw, list):
                for raw_evt_type in raw:
                    raw_s = str(raw_evt_type)
                    self.filtered_set.add(raw_s)
                    self.filtered_map[raw_s] = rule

    def match_core(self, evt_type: str) -> Optional[dict[str, Any]]:
        return self.core_map.get(evt_type)

    def match_auxiliary(self, evt_type: str) -> Optional[dict[str, Any]]:
        return self.aux_map.get(evt_type)

    def match_filtered(self, evt_type: str) -> Optional[dict[str, Any]]:
        return self.filtered_map.get(evt_type)

    def classify_non_core(self, evt_type: str) -> str:
        if evt_type in self.aux_set:
            return "auxiliary"
        if evt_type in self.filtered_set:
            return "filtered"
        return "unknown"


class IdentityBuilder:
    """Build process/file identities and preserve process key continuity by (container, pid)."""

    def __init__(self) -> None:
        self._stable_exe_by_pid: dict[tuple[str, str], str] = {}

    def process_key(self, evt: dict[str, Any]) -> str:
        cid = str(evt.get("container.id") or "host")
        pid_value = evt.get("proc.pid")
        if pid_value is None:
            pid_value = evt.get("proc.vpid")
        pid = str(pid_value) if pid_value is not None else "unknown_pid"

        exe_now = str(evt.get("proc.exepath") or evt.get("proc.name") or "unknown_exe")
        bucket = (cid, pid)
        if bucket not in self._stable_exe_by_pid:
            self._stable_exe_by_pid[bucket] = exe_now
        exe_stable = self._stable_exe_by_pid[bucket]
        return f"proc:{cid}:{pid}:{exe_stable}"

    @staticmethod
    def process_exec_tail(evt: dict[str, Any]) -> str:
        exe = evt.get("proc.exepath") or evt.get("evt.arg.filename") or evt.get("fd.name") or "unknown_path"
        return f"file:{exe}"

    @staticmethod
    def file_key(evt: dict[str, Any], prefer_evt_filename: bool) -> Optional[str]:
        if prefer_evt_filename:
            path = (
                evt.get("evt.arg.filename")
                or evt.get("fd.name")
                or evt.get("evt.arg.newpath")
                or evt.get("evt.arg.oldpath")
            )
        else:
            path = (
                evt.get("fd.name")
                or evt.get("evt.arg.filename")
                or evt.get("evt.arg.newpath")
                or evt.get("evt.arg.oldpath")
            )

        if not path:
            return "file:unknown_path"

        path_s = str(path)
        if looks_like_conn_name(path_s):
            return None
        if path_s.startswith(SPECIAL_FD_PREFIX):
            return None
        return f"file:{path_s}"

    @staticmethod
    def child_pid(evt: dict[str, Any]) -> str:
        for key in ("evt.arg.pid", "evt.rawres"):
            val = evt.get(key)
            if val is None:
                continue
            try:
                pid = int(val)
            except (TypeError, ValueError):
                continue
            if pid > 0:
                return str(pid)
        return "unknown_child"


class ConnKeyCanonicalizer:
    """Canonicalize conn identity and reuse one key across connect/accept/send/recv."""

    def __init__(self) -> None:
        self._bucket_to_conn_key: dict[tuple[tuple[str, int], tuple[str, int]], str] = {}

    def canonicalize(self, evt: dict[str, Any]) -> tuple[str, Optional[str]]:
        parsed = self._extract_endpoints(evt)
        if parsed is None:
            return "conn:unknown_conn", "unknown"

        ep1, ep2, source = parsed
        bucket = self._unordered_bucket(ep1, ep2)

        if bucket in self._bucket_to_conn_key:
            return self._bucket_to_conn_key[bucket], None

        (src, dst), hint = self._decide_direction(ep1, ep2, source)
        key = f"conn:{src[0]}:{src[1]}->{dst[0]}:{dst[1]}"
        self._bucket_to_conn_key[bucket] = key
        return key, hint

    @staticmethod
    def _unordered_bucket(ep1: tuple[str, int], ep2: tuple[str, int]) -> tuple[tuple[str, int], tuple[str, int]]:
        return tuple(sorted((ep1, ep2), key=lambda x: (x[0], x[1])))  # type: ignore[return-value]

    def _extract_endpoints(
        self, evt: dict[str, Any]
    ) -> Optional[tuple[tuple[str, int], tuple[str, int], str]]:
        cip = evt.get("fd.cip")
        cport = evt.get("fd.cport")
        sip = evt.get("fd.sip")
        sport = evt.get("fd.sport")
        if cip and sip and cport is not None and sport is not None:
            cp = parse_positive_int(cport)
            sp = parse_positive_int(sport)
            if cp is not None and sp is not None:
                return (str(cip), cp), (str(sip), sp), "cip_sip"

        lip = evt.get("fd.lip")
        rip = evt.get("fd.rip")
        if lip and rip and sport is not None and cport is not None:
            sp = parse_positive_int(sport)
            cp = parse_positive_int(cport)
            if sp is not None and cp is not None:
                return (str(lip), sp), (str(rip), cp), "lip_rip"

        fd_name = str(evt.get("fd.name") or "")
        m = FD_CONN_RE.match(fd_name)
        if m:
            ip1, p1, ip2, p2 = m.groups()
            p1i = parse_positive_int(p1)
            p2i = parse_positive_int(p2)
            if p1i is not None and p2i is not None:
                return (ip1, p1i), (ip2, p2i), "fd_name"

        return None

    @staticmethod
    def _decide_direction(
        ep1: tuple[str, int], ep2: tuple[str, int], source: str
    ) -> tuple[tuple[tuple[str, int], tuple[str, int]], Optional[str]]:
        p1 = ep1[1]
        p2 = ep2[1]
        ep1_is_ephemeral = EPHEMERAL_LOW <= p1 <= EPHEMERAL_HIGH
        ep2_is_ephemeral = EPHEMERAL_LOW <= p2 <= EPHEMERAL_HIGH

        if ep1_is_ephemeral and not ep2_is_ephemeral:
            return (ep1, ep2), None
        if ep2_is_ephemeral and not ep1_is_ephemeral:
            return (ep2, ep1), None

        if p1 in SERVER_COMMON_PORTS and p2 not in SERVER_COMMON_PORTS:
            return (ep2, ep1), None
        if p2 in SERVER_COMMON_PORTS and p1 not in SERVER_COMMON_PORTS:
            return (ep1, ep2), None

        if source == "cip_sip":
            return (ep1, ep2), "direction_from_fd_cip_sip"

        return (ep1, ep2), "ambiguous_direction"


class TripleWriter:
    """Write triple JSONL. When ``lazy=True`` (tier side files), open on first write only."""

    def __init__(self, out_jsonl: Path, lazy: bool = False) -> None:
        self._path = out_jsonl
        self._lazy = lazy
        self._fh: Any = None
        if not lazy:
            out_jsonl.parent.mkdir(parents=True, exist_ok=True)
            self._fh = open(out_jsonl, "wb", buffering=1 << 20)
            self._opened = True
        else:
            self._opened = False

    def write(self, triple: dict[str, Any]) -> None:
        if self._fh is None:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._fh = open(self._path, "wb", buffering=1 << 20)
            self._opened = True
        self._fh.write(_dumps(triple))
        self._fh.write(b"\n")

    def close(self) -> None:
        if self._fh is not None:
            self._fh.close()
            self._fh = None
        elif self._lazy and not self._opened and self._path.is_file():
            self._path.unlink()


class StatsCollector:
    def __init__(self) -> None:
        self.total_events = 0
        self.total_triples = 0
        self.core_malicious_triples = 0
        self.files_processed = 0
        self.parse_errors = 0
        self.skipped_no_rule = 0
        self.skipped_auxiliary = 0
        self.skipped_filtered = 0
        self.skipped_invalid_object = 0

        self.relation_counts: Counter[str] = Counter()
        self.raw_evt_type_hit_counts: Counter[str] = Counter()
        self.raw_evt_type_seen_counts: Counter[str] = Counter()
        self.tier_output_counts: Counter[str] = Counter()
        self.tier_output_malicious_counts: Counter[str] = Counter()
        self.tier_output_record_modes: dict[str, set[str]] = defaultdict(set)

    def mark_event_seen(self, evt_type: str) -> None:
        if evt_type:
            self.raw_evt_type_seen_counts[evt_type] += 1

    def mark_triple(self, relation: str, raw_evt_type: str, malicious: bool) -> None:
        self.total_triples += 1
        self.relation_counts[relation] += 1
        self.raw_evt_type_hit_counts[raw_evt_type] += 1
        if malicious:
            self.core_malicious_triples += 1

    def mark_tier_output(self, tier: str, malicious: bool, record_mode: str) -> None:
        self.tier_output_counts[tier] += 1
        if malicious:
            self.tier_output_malicious_counts[tier] += 1
        self.tier_output_record_modes[tier].add(record_mode)


def parse_positive_int(v: Any) -> Optional[int]:
    try:
        iv = int(v)
    except (TypeError, ValueError):
        return None
    return iv if iv >= 0 else None


def looks_like_conn_name(fd_name: str) -> bool:
    return bool(FD_CONN_RE.match(fd_name)) or "->" in fd_name


def fd_is_network(evt: dict[str, Any]) -> bool:
    fd_type = str(evt.get("fd.type") or "").lower().strip()
    fd_name = str(evt.get("fd.name") or "")
    if fd_type in NETLIKE_FD_TYPES:
        return True
    return looks_like_conn_name(fd_name)


def fd_is_file_like(evt: dict[str, Any]) -> bool:
    fd_type = str(evt.get("fd.type") or "").lower().strip()
    fd_name = str(evt.get("fd.name") or "")
    if fd_type in FILELIKE_FD_TYPES:
        return True
    if fd_type in NETLIKE_FD_TYPES:
        return False
    if looks_like_conn_name(fd_name):
        return False
    if fd_name.startswith(SPECIAL_FD_PREFIX):
        return False
    return fd_name.startswith("/")


def make_attrs(evt: dict[str, Any], raw_evt_type: str, direction_hint: Optional[str]) -> dict[str, Any]:
    evt_num = parse_positive_int(evt.get("evt.num"))
    malicious = evt.get("malicious")
    attrs: dict[str, Any] = {
        "raw_evt_type": raw_evt_type,
        "evt_num": evt_num,
        "timestamp": evt.get("evt.datetime") or evt.get("evt.time"),
        "evt_category": evt.get("evt.category"),
        "container_id": evt.get("container.id") or "host",
        "proc_pid": evt.get("proc.pid"),
        "proc_name": evt.get("proc.name"),
        "proc_exepath": evt.get("proc.exepath"),
        "fd_name": evt.get("fd.name"),
        "fd_type": evt.get("fd.type"),
        "malicious": bool(malicious) if malicious is not None else False,
    }
    if direction_hint:
        attrs["direction_hint"] = direction_hint

    rawres = parse_positive_int(evt.get("evt.rawres"))
    if rawres is not None:
        attrs["bytes"] = rawres
    return attrs


def build_record_id(evt: dict[str, Any], source_file: str, scenario: str) -> str:
    evt_num = parse_positive_int(evt.get("evt.num"))
    return f"{scenario}::{Path(source_file).name}::{evt_num if evt_num is not None else 'no_evt_num'}"


def resolve_edge_object(
    evt: dict[str, Any],
    relation: str,
    pattern: str,
    identity: IdentityBuilder,
    conn_canon: ConnKeyCanonicalizer,
    invalid_stats: Optional[StatsCollector] = None,
) -> tuple[Optional[str], Optional[str]]:
    tail: Optional[str] = None
    direction_hint: Optional[str] = None

    if pattern == "process->file":
        if relation in {"FILE_OPEN", "FILE_READ", "FILE_WRITE"}:
            if fd_is_network(evt):
                if invalid_stats is not None:
                    invalid_stats.skipped_invalid_object += 1
                return None, None
            if relation in {"FILE_READ", "FILE_WRITE"} and not fd_is_file_like(evt):
                if invalid_stats is not None:
                    invalid_stats.skipped_invalid_object += 1
                return None, None

        if relation == "PROCESS_EXEC":
            tail = identity.process_exec_tail(evt)
        elif relation == "FILE_OPEN":
            tail = identity.file_key(evt, prefer_evt_filename=True)
        else:
            tail = identity.file_key(evt, prefer_evt_filename=False)

        if tail is None:
            if invalid_stats is not None:
                invalid_stats.skipped_invalid_object += 1
            return None, None

    elif pattern == "process->process":
        cid = str(evt.get("container.id") or "host")
        child_pid = identity.child_pid(evt)
        tail = f"proc:{cid}:{child_pid}:unknown_exe"

    elif pattern == "process->conn":
        if not fd_is_network(evt):
            if invalid_stats is not None:
                invalid_stats.skipped_invalid_object += 1
            return None, None
        tail, direction_hint = conn_canon.canonicalize(evt)

    else:
        if invalid_stats is not None:
            invalid_stats.skipped_invalid_object += 1
        return None, None

    return tail, direction_hint


def make_structured_tier_record(
    evt: dict[str, Any],
    tier: str,
    source_file: str,
    scenario: str,
    identity: IdentityBuilder,
    reason: str,
) -> dict[str, Any]:
    evt_type = str(evt.get("evt.type") or "")
    attrs = make_attrs(evt, evt_type, direction_hint=None)
    attrs["tier"] = tier
    return {
        "id": build_record_id(evt, source_file, scenario),
        "record_mode": "structured_event",
        "subject": identity.process_key(evt),
        "event_type": evt_type,
        "reason": reason,
        "proc": {
            "container_id": evt.get("container.id") or "host",
            "pid": evt.get("proc.pid"),
            "name": evt.get("proc.name"),
            "exepath": evt.get("proc.exepath"),
        },
        "fd": {
            "name": evt.get("fd.name"),
            "type": evt.get("fd.type"),
        },
        "raw_ref": {
            "source_file": Path(source_file).name,
            "scenario": scenario,
        },
        "attrs": attrs,
    }


def build_non_core_record(
    evt: dict[str, Any],
    tier: str,
    matcher: RuleMatcher,
    source_file: str,
    scenario: str,
    identity: IdentityBuilder,
    conn_canon: ConnKeyCanonicalizer,
) -> dict[str, Any]:
    evt_type = str(evt.get("evt.type") or "")
    if tier == "auxiliary":
        rule = matcher.match_auxiliary(evt_type)
        if rule is not None:
            relation = str(rule.get("normalized_relation") or evt_type.upper())
            pattern = str(rule.get("triple_pattern") or "")
            tail, direction_hint = resolve_edge_object(
                evt=evt,
                relation=relation,
                pattern=pattern,
                identity=identity,
                conn_canon=conn_canon,
            )
            if tail is not None:
                attrs = make_attrs(evt, evt_type, direction_hint)
                attrs["tier"] = tier
                return {
                    "id": build_record_id(evt, source_file, scenario),
                    "subject": identity.process_key(evt),
                    "relation": relation,
                    "object": tail,
                    "attrs": attrs,
                }
        return make_structured_tier_record(
            evt=evt,
            tier=tier,
            source_file=source_file,
            scenario=scenario,
            identity=identity,
            reason="auxiliary_rule_no_stable_triple",
        )

    if tier == "filtered":
        filtered_rule = matcher.match_filtered(evt_type)
        reason = str(filtered_rule.get("reason") or "filtered_non_core_event") if filtered_rule else "filtered_non_core_event"
        return make_structured_tier_record(
            evt=evt,
            tier=tier,
            source_file=source_file,
            scenario=scenario,
            identity=identity,
            reason=reason,
        )

    return make_structured_tier_record(
        evt=evt,
        tier=tier,
        source_file=source_file,
        scenario=scenario,
        identity=identity,
        reason="unknown_evt_type_no_rule",
    )


def build_triple(
    evt: dict[str, Any],
    rule: dict[str, Any],
    source_file: str,
    scenario: str,
    identity: IdentityBuilder,
    conn_canon: ConnKeyCanonicalizer,
    stats: StatsCollector,
) -> Optional[dict[str, Any]]:
    evt_type = str(evt.get("evt.type") or "")
    relation = str(rule["normalized_relation"])
    pattern = str(rule["triple_pattern"])

    head = identity.process_key(evt)
    tail, direction_hint = resolve_edge_object(
        evt=evt,
        relation=relation,
        pattern=pattern,
        identity=identity,
        conn_canon=conn_canon,
        invalid_stats=stats,
    )
    if tail is None:
        return None

    attrs = make_attrs(evt, evt_type, direction_hint)
    return {
        "id": build_record_id(evt, source_file, scenario),
        "subject": head,
        "relation": relation,
        "object": tail,
        "attrs": attrs,
    }


def process_file(
    scanned: ScannedFile,
    matcher: RuleMatcher,
    identity: IdentityBuilder,
    conn_canon: ConnKeyCanonicalizer,
    core_writer: TripleWriter,
    tier_writers: dict[str, TripleWriter],
    stats: StatsCollector,
) -> None:
    file_progress = ProgressLogger(
        stage="extract_audit_triples_v1_1",
        substep="sysdig_lines",
        every=100000,
        min_interval_s=15.0,
        prefix="[extract_audit_triples_v1_1][progress]",
        base_fields={
            "scenario_dir": scanned.scenario,
            "input_path": scanned.path,
        },
    )
    file_events = 0
    with open(scanned.path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue

            file_events += 1
            stats.total_events += 1
            if file_events % 100000 == 0:
                file_progress.maybe_log(
                    file_events,
                    force=True,
                    total_events_global=stats.total_events,
                    triples_global=stats.total_triples,
                )
            try:
                evt = _loads(line)
            except Exception:
                stats.parse_errors += 1
                continue

            evt_type = str(evt.get("evt.type") or "")
            stats.mark_event_seen(evt_type)
            rule = matcher.match_core(evt_type)
            if rule is None:
                tier = matcher.classify_non_core(evt_type)
                if tier == "auxiliary":
                    stats.skipped_auxiliary += 1
                elif tier == "filtered":
                    stats.skipped_filtered += 1
                else:
                    stats.skipped_no_rule += 1
                non_core_record = build_non_core_record(
                    evt=evt,
                    tier=tier,
                    matcher=matcher,
                    source_file=str(scanned.path),
                    scenario=scanned.scenario,
                    identity=identity,
                    conn_canon=conn_canon,
                )
                tier_writers[tier].write(non_core_record)
                record_mode = str(non_core_record.get("record_mode") or "triple")
                malicious = bool(non_core_record.get("attrs", {}).get("malicious"))
                stats.mark_tier_output(tier, malicious, record_mode)
                continue

            triple = build_triple(
                evt=evt,
                rule=rule,
                source_file=str(scanned.path),
                scenario=scanned.scenario,
                identity=identity,
                conn_canon=conn_canon,
                stats=stats,
            )
            if triple is None:
                continue

            core_writer.write(triple)
            stats.mark_triple(str(triple["relation"]), evt_type, bool(triple.get("attrs", {}).get("malicious")))

    file_progress.maybe_log(
        file_events,
        force=True,
        total_events_global=stats.total_events,
        triples_global=stats.total_triples,
    )
    stats.files_processed += 1


def write_relation_stats(stats: StatsCollector, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["relation", "count", "pct"])
        total = stats.total_triples
        for relation, count in sorted(stats.relation_counts.items(), key=lambda x: (-x[1], x[0])):
            pct = (count / total * 100.0) if total else 0.0
            w.writerow([relation, count, f"{pct:.2f}%"])


def _manifest_mode_for_tier(stats: StatsCollector, tier: str) -> str:
    if tier == "core":
        return "triple"
    modes = stats.tier_output_record_modes.get(tier, set())
    if not modes:
        return "structured"
    if modes == {"triple"}:
        return "triple"
    if modes == {"structured_event"}:
        return "structured"
    return "triple_or_mixed"


def write_tier_manifest(
    stats: StatsCollector,
    output_path: Path,
    scenario_id: str,
    files: dict[str, Path],
) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    manifest = {
        "schema_version": "audit_triples_tier_manifest.v1",
        "scenario_id": scenario_id,
        "files": {tier: path.name for tier, path in files.items()},
        "counts": {
            "core_total": stats.total_triples,
            "auxiliary_total": stats.tier_output_counts.get("auxiliary", 0),
            "filtered_total": stats.tier_output_counts.get("filtered", 0),
            "unknown_total": stats.tier_output_counts.get("unknown", 0),
            "core_malicious": stats.core_malicious_triples,
            "auxiliary_malicious": stats.tier_output_malicious_counts.get("auxiliary", 0),
            "filtered_malicious": stats.tier_output_malicious_counts.get("filtered", 0),
            "unknown_malicious": stats.tier_output_malicious_counts.get("unknown", 0),
        },
        "record_mode": {
            "core": _manifest_mode_for_tier(stats, "core"),
            "auxiliary": _manifest_mode_for_tier(stats, "auxiliary"),
            "filtered": _manifest_mode_for_tier(stats, "filtered"),
            "unknown": _manifest_mode_for_tier(stats, "unknown"),
        },
        "notes": {
            "builder_default_input": "core_only",
            "tiered_output_purpose": "fidelity_preservation",
        },
    }
    with open(output_path, "wb") as fh:
        fh.write(_dumps(manifest))
        fh.write(b"\n")


def write_summary(stats: StatsCollector, output_path: Path, started_at: datetime) -> None:
    elapsed = (datetime.now() - started_at).total_seconds()
    lines: list[str] = []
    lines.append("# audit_triples_summary")
    lines.append("")
    lines.append(f"- generated_at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("- rules: triple_rules_v1_1.json")
    lines.append("- downstream_default_input: core_only")
    lines.append("- non_core_output: tiered side files for fidelity preservation")
    lines.append(f"- elapsed_seconds: {elapsed:.2f}")
    lines.append("")
    lines.append("## Run Stats")
    lines.append("")
    lines.append("| metric | value |")
    lines.append("|---|---:|")
    lines.append(f"| total_files | {stats.files_processed} |")
    lines.append(f"| total_events | {stats.total_events} |")
    lines.append(f"| extracted_triples_core | {stats.total_triples} |")
    lines.append(f"| core_malicious | {stats.core_malicious_triples} |")
    lines.append(f"| classified_unknown | {stats.skipped_no_rule} |")
    lines.append(f"| classified_auxiliary | {stats.skipped_auxiliary} |")
    lines.append(f"| classified_filtered | {stats.skipped_filtered} |")
    lines.append(f"| written_auxiliary_records | {stats.tier_output_counts.get('auxiliary', 0)} |")
    lines.append(f"| written_filtered_records | {stats.tier_output_counts.get('filtered', 0)} |")
    lines.append(f"| written_unknown_records | {stats.tier_output_counts.get('unknown', 0)} |")
    lines.append(f"| skipped_invalid_object | {stats.skipped_invalid_object} |")
    lines.append(f"| parse_errors | {stats.parse_errors} |")
    lines.append("")

    lines.append("## Relation Counts")
    lines.append("")
    lines.append("| relation | count | pct |")
    lines.append("|---|---:|---:|")
    total = stats.total_triples
    for relation, count in sorted(stats.relation_counts.items(), key=lambda x: (-x[1], x[0])):
        pct = (count / total * 100.0) if total else 0.0
        lines.append(f"| {relation} | {count} | {pct:.2f}% |")
    lines.append("")

    lines.append("## raw evt.type Hit Counts (extracted)")
    lines.append("")
    lines.append("| raw_evt_type | count |")
    lines.append("|---|---:|")
    for evt_type, count in sorted(stats.raw_evt_type_hit_counts.items(), key=lambda x: (-x[1], x[0])):
        lines.append(f"| {evt_type} | {count} |")
    lines.append("")

    lines.append("## raw evt.type Seen Counts (all events)")
    lines.append("")
    lines.append("| raw_evt_type | count |")
    lines.append("|---|---:|")
    for evt_type, count in sorted(stats.raw_evt_type_seen_counts.items(), key=lambda x: (-x[1], x[0])):
        lines.append(f"| {evt_type} | {count} |")
    lines.append("")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


def run(
    raw_sysdig_dir: Path = RAW_SYSDIG_DIR,
    output_jsonl: Path = DEFAULT_OUTPUT_JSONL,
    auxiliary_output_jsonl: Path = DEFAULT_AUXILIARY_OUTPUT_JSONL,
    filtered_output_jsonl: Path = DEFAULT_FILTERED_OUTPUT_JSONL,
    unknown_output_jsonl: Path = DEFAULT_UNKNOWN_OUTPUT_JSONL,
    tier_manifest_path: Path = DEFAULT_TIER_MANIFEST_JSON,
    relation_stats_path: Path = DEFAULT_RELATION_STATS,
    summary_md_path: Path = DEFAULT_SUMMARY_MD,
    rules_file: Path = RULES_FILE,
    write_relation_stats_flag: bool = False,
    write_summary_md: bool = False,
    write_tier_manifest_flag: bool = False,
) -> int:
    started_at = datetime.now()
    output_jsonl.parent.mkdir(parents=True, exist_ok=True)

    matcher = RuleMatcher(rules_file)
    scanner = FileScanner()
    identity = IdentityBuilder()
    conn_canon = ConnKeyCanonicalizer()
    stats = StatsCollector()

    scanned_files = scanner.scan(raw_sysdig_dir)
    core_writer = TripleWriter(output_jsonl)
    tier_writers = {
        "auxiliary": TripleWriter(auxiliary_output_jsonl, lazy=True),
        "filtered": TripleWriter(filtered_output_jsonl, lazy=True),
        "unknown": TripleWriter(unknown_output_jsonl, lazy=True),
    }
    scenario_id = scanned_files[0].scenario if scanned_files else raw_sysdig_dir.parent.parent.name
    failed_files: list[str] = []

    print(f"[extract_audit_triples_v1_1] files={len(scanned_files)}")
    emit_observation(
        "[extract_audit_triples_v1_1][stage]",
        stage="extract_audit_triples_v1_1",
        status="start",
        scenario_dir=scenario_id,
        input_path=raw_sysdig_dir,
        output_path=output_jsonl,
        raw_sysdig_exists=raw_sysdig_dir.exists(),
        files_total=len(scanned_files),
    )
    for idx, scanned in enumerate(scanned_files, 1):
        try:
            emit_observation(
                "[extract_audit_triples_v1_1][stage]",
                stage="extract_audit_triples_v1_1",
                substep="process_file",
                status="start",
                scenario_dir=scanned.scenario,
                input_path=scanned.path,
                processed=idx,
                total=len(scanned_files),
                percent=round((idx / len(scanned_files)) * 100.0, 2) if scanned_files else None,
            )
            process_file(
                scanned=scanned,
                matcher=matcher,
                identity=identity,
                conn_canon=conn_canon,
                core_writer=core_writer,
                tier_writers=tier_writers,
                stats=stats,
            )
            emit_observation(
                "[extract_audit_triples_v1_1][stage]",
                stage="extract_audit_triples_v1_1",
                substep="process_file",
                status="done",
                scenario_dir=scanned.scenario,
                input_path=scanned.path,
                processed=idx,
                total=len(scanned_files),
                percent=round((idx / len(scanned_files)) * 100.0, 2) if scanned_files else None,
                total_events=stats.total_events,
                total_triples=stats.total_triples,
            )
            if idx % 10 == 0 or idx == len(scanned_files):
                print(
                    f"  [{idx}/{len(scanned_files)}] events={stats.total_events} triples={stats.total_triples} "
                    f"skip_invalid={stats.skipped_invalid_object}"
                )
        except Exception as exc:
            failed_files.append(f"{scanned.path}: {exc}")
            emit_observation(
                "[extract_audit_triples_v1_1][stage]",
                stage="extract_audit_triples_v1_1",
                substep="process_file",
                status="failed",
                scenario_dir=scanned.scenario,
                input_path=scanned.path,
                processed=idx,
                total=len(scanned_files),
                percent=round((idx / len(scanned_files)) * 100.0, 2) if scanned_files else None,
                error=exc,
            )
            print(f"[ERROR] {scanned.path}: {exc}", file=sys.stderr)

    core_writer.close()
    for writer in tier_writers.values():
        writer.close()
    if write_relation_stats_flag:
        write_relation_stats(stats, relation_stats_path)
    if write_summary_md:
        write_summary(stats, summary_md_path, started_at)
    if write_tier_manifest_flag:
        manifest_files: dict[str, Path] = {"core": output_jsonl}
        for tier, pth in (
            ("auxiliary", auxiliary_output_jsonl),
            ("filtered", filtered_output_jsonl),
            ("unknown", unknown_output_jsonl),
        ):
            if stats.tier_output_counts.get(tier, 0) > 0:
                manifest_files[tier] = pth
        write_tier_manifest(
            stats=stats,
            output_path=tier_manifest_path,
            scenario_id=scenario_id,
            files=manifest_files,
        )

    elapsed = (datetime.now() - started_at).total_seconds()
    if failed_files:
        emit_observation(
            "[extract_audit_triples_v1_1][stage]",
            stage="extract_audit_triples_v1_1",
            status="failed",
            scenario_dir=scenario_id,
            output_path=output_jsonl,
            files_ok=stats.files_processed,
            files_failed=len(failed_files),
            total_events=stats.total_events,
            total_triples=stats.total_triples,
            elapsed=elapsed,
        )
        print(
            f"[INCOMPLETE] events={stats.total_events} triples={stats.total_triples} "
            f"files_ok={stats.files_processed} files_failed={len(failed_files)} elapsed_s={elapsed:.2f}",
            file=sys.stderr,
        )
        print("[INCOMPLETE] failed files:", file=sys.stderr)
        for item in failed_files:
            print(f"  - {item}", file=sys.stderr)
        return EXTRACT_INCOMPLETE_RC

    emit_observation(
        "[extract_audit_triples_v1_1][stage]",
        stage="extract_audit_triples_v1_1",
        status="done",
        scenario_dir=scenario_id,
        output_path=output_jsonl,
        files_ok=stats.files_processed,
        total_events=stats.total_events,
        total_triples=stats.total_triples,
        elapsed=elapsed,
        core_output_exists=output_jsonl.exists(),
    )
    print(
        f"[DONE] events={stats.total_events} triples={stats.total_triples} "
        f"files={stats.files_processed} elapsed_s={elapsed:.2f}"
    )
    return 0


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Extract single-scenario audit triples v1")
    parser.add_argument(
        "--scenario-dir",
        type=Path,
        default=SCENARIO_DIR,
        help="Override scenario timestamp directory (default: SCENARIO_DIR constant)",
    )
    parser.add_argument(
        "--raw-sysdig-dir",
        type=Path,
        default=RAW_SYSDIG_DIR,
        help="Override raw sysdig input directory (default: RAW_SYSDIG_DIR)",
    )
    parser.add_argument(
        "--output-jsonl",
        type=Path,
        default=DEFAULT_OUTPUT_JSONL,
        help="Override triples JSONL output path (default: DEFAULT_OUTPUT_JSONL)",
    )
    parser.add_argument(
        "--auxiliary-output-jsonl",
        type=Path,
        default=DEFAULT_AUXILIARY_OUTPUT_JSONL,
        help="Override auxiliary JSONL output path (default: DEFAULT_AUXILIARY_OUTPUT_JSONL)",
    )
    parser.add_argument(
        "--filtered-output-jsonl",
        type=Path,
        default=DEFAULT_FILTERED_OUTPUT_JSONL,
        help="Override filtered JSONL output path (default: DEFAULT_FILTERED_OUTPUT_JSONL)",
    )
    parser.add_argument(
        "--unknown-output-jsonl",
        type=Path,
        default=DEFAULT_UNKNOWN_OUTPUT_JSONL,
        help="Override unknown JSONL output path (default: DEFAULT_UNKNOWN_OUTPUT_JSONL)",
    )
    parser.add_argument(
        "--tier-manifest-path",
        type=Path,
        default=DEFAULT_TIER_MANIFEST_JSON,
        help="Override tier manifest JSON path (default: DEFAULT_TIER_MANIFEST_JSON)",
    )
    parser.add_argument(
        "--relation-stats-path",
        type=Path,
        default=DEFAULT_RELATION_STATS,
        help="Override relation stats CSV path (default: DEFAULT_RELATION_STATS)",
    )
    parser.add_argument(
        "--summary-md-path",
        type=Path,
        default=DEFAULT_SUMMARY_MD,
        help="Override summary markdown path (default: DEFAULT_SUMMARY_MD)",
    )
    parser.add_argument(
        "--rules-file",
        type=Path,
        default=RULES_FILE,
        help="Override triple rules JSON path (default: RULES_FILE)",
    )
    return parser.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)

    scenario_dir = args.scenario_dir
    raw_sysdig_dir = args.raw_sysdig_dir
    output_jsonl = args.output_jsonl
    auxiliary_output_jsonl = args.auxiliary_output_jsonl
    filtered_output_jsonl = args.filtered_output_jsonl
    unknown_output_jsonl = args.unknown_output_jsonl
    tier_manifest_path = args.tier_manifest_path
    relation_stats_path = args.relation_stats_path
    summary_md_path = args.summary_md_path

    # If only scenario_dir is overridden, derive scenario-local defaults from it.
    if scenario_dir != SCENARIO_DIR:
        derived_raw_sysdig_dir = scenario_dir / "raw" / "sysdig"
        derived_chain_dir = scenario_dir / CHAIN_DIR_NAME

        if raw_sysdig_dir == RAW_SYSDIG_DIR:
            raw_sysdig_dir = derived_raw_sysdig_dir
        if output_jsonl == DEFAULT_OUTPUT_JSONL:
            output_jsonl = derived_chain_dir / "audit_triples.core.v1.jsonl"
        if auxiliary_output_jsonl == DEFAULT_AUXILIARY_OUTPUT_JSONL:
            auxiliary_output_jsonl = derived_chain_dir / "audit_triples.auxiliary.v1.jsonl"
        if filtered_output_jsonl == DEFAULT_FILTERED_OUTPUT_JSONL:
            filtered_output_jsonl = derived_chain_dir / "audit_triples.filtered.v1.jsonl"
        if unknown_output_jsonl == DEFAULT_UNKNOWN_OUTPUT_JSONL:
            unknown_output_jsonl = derived_chain_dir / "audit_triples.unknown.v1.jsonl"
        if tier_manifest_path == DEFAULT_TIER_MANIFEST_JSON:
            tier_manifest_path = derived_chain_dir / "audit_triples_tier_manifest.v1.json"
        if relation_stats_path == DEFAULT_RELATION_STATS:
            relation_stats_path = derived_chain_dir / "relation_stats.csv"
        if summary_md_path == DEFAULT_SUMMARY_MD:
            summary_md_path = derived_chain_dir / "audit_triples_summary.md"

    return run(
        raw_sysdig_dir=raw_sysdig_dir,
        output_jsonl=output_jsonl,
        auxiliary_output_jsonl=auxiliary_output_jsonl,
        filtered_output_jsonl=filtered_output_jsonl,
        unknown_output_jsonl=unknown_output_jsonl,
        tier_manifest_path=tier_manifest_path,
        relation_stats_path=relation_stats_path,
        summary_md_path=summary_md_path,
        rules_file=args.rules_file,
    )


if __name__ == "__main__":
    raise SystemExit(main())
