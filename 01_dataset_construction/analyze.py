import datetime
import json
import math
import os
import re
from queue import Queue
from typing import Any

import msgpack
from dateutil import tz
from loguru import logger
from tqdm import tqdm

from console_observability import (
    ProgressLogger,
    StageTimer,
    artifact_report,
    highest_level_reached,
    path_exists,
    stage_banner,
)
from load_logs import load_sysdig, load_tshark
from logs import CAPTURED_PATH
from net_trace import ConnInfo, NatInfo, parse_log_file, query_net
from schema import Scene
from sysdig_rules import SysdigProcessor
from sysdig_rules.graph import FileNode, NetworkNode, Node, ProvGraph, UnitNode
from attack_chain import extract_attack_chains, export_attack_chains
from replay_index import build_event_index, build_node_index, export_event_index
from utils import IS_DEBUG, exec_command

CAPTURED_PATH = "/tmp/capture_dir"

is_sysdig_loaded = False
is_tshark_loaded = False

CONNTRACK_NAT_INDEX_SCHEMA_VERSION = "conntrack_nat_index.v0"
CAPTURE_MANIFEST_SCHEMA_VERSION = "capture_manifest.v0"
TRAFFIC_NODE_ANCHOR_SCHEMA_VERSION = "traffic_node_anchor_index.v0"
TRAFFIC_NODE_ANCHOR_SUMMARY_SCHEMA_VERSION = "traffic_node_anchor_index_summary.v0"
TRAFFIC_MISS_TIME_BUCKET_SECONDS = 1.0
TRAFFIC_MISS_SAMPLE_LIMIT = 5
TRAFFIC_MISS_CODES = {
    "missing_timestamp",
    "missing_ip_tuple",
    "missing_l4_port",
    "no_network_node_hit",
    "parser_error",
    "internal_error",
}
APPLOG_PREFIX_PATTERN = re.compile(
    r"^\[(?:SecLog|AutoLabel) (\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2})\.(\d{9}) (\d+)\] "
)


def _env_value(name: str, default: str = "") -> str:
    return os.environ.get(name, default)


def _env_flag(name: str, default: str = "0") -> bool:
    return _env_value(name, default) == "1"


def get_rawtime(time_str: str) -> int:
    # input: datetime string 2024-09-26 00:24:36.129186487
    # output: timestamp in nanoseconds 1727281568219457129

    seconds_str, nanoseconds_str = time_str.split(".")
    dt = datetime.datetime.strptime(seconds_str, "%Y-%m-%d %H:%M:%S")
    timestamp = dt.timestamp()
    total_nanoseconds = int(timestamp * 1e9) + int(nanoseconds_str)
    return total_nanoseconds


def build_provenance_graph(inv_dict: dict[str, str]) -> ProvGraph:
    """
    syscalls: dict[str, dict[str, list[dict]]] = {}
    for event in load_sysdig():
        category = event["evt.category"]
        type = event["evt.type"]
        syscalls.setdefault(category, {})
        syscalls[category].setdefault(type, [])
        syscalls[category][type].append(event)

    breakpoint()
    return ProvGraph()
    """
    import gc
    import psutil
    import os

    sysdig_processor = SysdigProcessor(inv_dict)
    process = psutil.Process(os.getpid())
    progress = ProgressLogger(
        stage="build_provenance_graph",
        substep="sysdig_events",
        every=100000,
        min_interval_s=15.0,
        prefix="[analyze][progress]",
        emit_fn=logger.info,
    )

    event_count = 0
    last_gc_count = 0
    last_memory_check = 0
    
    try:
        for event in load_sysdig():
            sysdig_processor.process(event)
            event_count += 1
            
            # Report progress every 100,000 events.
            if event_count % 100000 == 0:
                graph_nodes = len(sysdig_processor.graph.nodes)
                graph_edges = sum(len(node.out_edges) + len(node.in_edges) for node in sysdig_processor.graph.nodes) // 2
                progress.maybe_log(
                    event_count,
                    force=True,
                    graph_nodes=graph_nodes,
                    graph_edges=graph_edges,
                )
                
                # Collect unreferenced objects every 500,000 events. Graph nodes
                # and their logs remain reachable through sysdig_processor.graph.
                if event_count - last_gc_count >= 500000:
                    gc.collect()
                    last_gc_count = event_count
                    logger.debug(f"Garbage collection performed at {event_count} events")
                
                # Check resident memory every 1,000,000 events.
                if event_count - last_memory_check >= 1000000:
                    memory_mb = process.memory_info().rss / 1024 / 1024
                    if memory_mb > 8000:  # Warn above approximately 8 GB.
                        logger.warning(
                            f"High memory usage detected: {memory_mb:.1f} MB. "
                            f"Consider optimizing or using a machine with more RAM."
                        )
                    last_memory_check = event_count

    except MemoryError:
        memory_info = process.memory_info()
        memory_mb = memory_info.rss / 1024 / 1024
        logger.error(
            f"Out of memory at {event_count} events. "
            f"Memory usage: {memory_mb:.1f} MB. "
            f"Graph has {len(sysdig_processor.graph.nodes)} nodes."
        )
        raise

    progress.maybe_log(
        event_count,
        force=True,
        graph_nodes=len(sysdig_processor.graph.nodes),
        graph_edges=sum(len(node.out_edges) + len(node.in_edges) for node in sysdig_processor.graph.nodes) // 2,
    )
    logger.info(f"Total sysdig events processed: {event_count}")
    graph = sysdig_processor.graph
    final_memory = process.memory_info().rss / 1024 / 1024
    logger.info(
        f"Graph construction completed. "
        f"Final graph: {len(graph.nodes)} nodes, "
        f"Memory: {final_memory:.1f} MB"
    )
    return graph


local_tz = tz.tzlocal()


def _analyze_stage(
    stage: str,
    *,
    scene_name: str,
    output_path: str,
    input_path: str | os.PathLike[str] | None = None,
) -> StageTimer:
    return StageTimer(
        stage,
        prefix="[analyze][stage]",
        emit_fn=logger.info,
        base_fields={
            "scenario_dir": scene_name,
            "output_path": output_path,
            "input_path": input_path,
        },
    )


def parse_app_log_line(log_line: str):
    match = APPLOG_PREFIX_PATTERN.search(log_line)
    if match:
        date_str, time_str, nanoseconds, integer = match.groups()
        datetime_str = f"{date_str} {time_str}"
        datetime_obj = datetime.datetime.strptime(datetime_str, "%Y-%m-%d %H:%M:%S")
        datetime_obj = datetime_obj.replace(tzinfo=datetime.timezone.utc)
        datetime_obj = datetime_obj.astimezone(local_tz)
        tst_seconds = datetime_obj.timestamp()
        tst_nanoseconds = int(tst_seconds * 1_000_000_000) + int(nanoseconds)
        integer_value = int(integer)
        return datetime_obj, tst_nanoseconds, integer_value
    else:
        raise ValueError("Log format does not match expected SecLog/AutoLabel pattern")


def parse_app_log(container_id: str, log_path: str):
    print(f"Relating File: {log_path}")

    print("Pre Scan...")
    need_to_be_mapped = False
    with open(log_path, "r") as f:
        for li, line in tqdm(enumerate(f)):
            try:
                _, __, ___ = parse_app_log_line(line)
            except ValueError:
                continue
            need_to_be_mapped = True
            break

    if not need_to_be_mapped:
        return {}

    app_log_matches = {}

    """
    logs_by_tid = {}

    for event in load_sysdig():
        event_container_id = event["container.id"]
        event_tst = get_rawtime(event["evt.datetime"])
        event_tid = int(event["thread.vtid"])
        event_type = event["evt.type"]
        event_dir = event["evt.dir"]
        fd_name = event["fd.name"]

        if (
            event_container_id != container_id
            or event_type != "write"
            or fd_name == "/dev/null"
        ):
            continue

        logs_by_tid.setdefault(event_tid, [])
        logs_by_tid[event_tid].append(event)

    iters_by_tid = {}
    for key in logs_by_tid:
        try:
            iterator = iter(logs_by_tid[key])
            iters_by_tid[key] = iterator
        except Exception as msg:
            logger.warning(msg)
    """

    iters_by_tid = {}
    fd_by_tid = {}

    with open(log_path, "r") as f:

        previous_val: dict[int, dict | None] = {}

        for li, line in tqdm(enumerate(f)):
            try:
                occur_time, tst, tid = parse_app_log_line(line)
            except ValueError:
                continue

            while True:
                try:
                    if (tid in previous_val) and (previous_val[tid] is not None):
                        event = previous_val[tid]
                        assert event is not None
                    else:
                        try:
                            # event = next(iters_by_tid[tid])
                            if tid not in fd_by_tid:
                                if not os.path.exists(
                                    f"{CAPTURED_PATH}/divided/{container_id}_{tid}.pk"
                                ):
                                    break
                                fd_by_tid[tid] = open(
                                    f"{CAPTURED_PATH}/divided/{container_id}_{tid}.pk",
                                    "rb",
                                )
                                iters_by_tid[tid] = msgpack.Unpacker(
                                    fd_by_tid[tid], raw=False
                                )
                            event: dict = next(iters_by_tid[tid])
                        except Exception as msg:
                            logger.warning(msg)
                            break

                    event_container_id = event["container.id"]
                    event_tst = get_rawtime(event["evt.datetime"])
                    event_tid = int(event["thread.vtid"])
                    event_type = event["evt.type"]
                    event_dir = event["evt.dir"]

                    # breakpoint()

                    if event_tst < tst:
                        previous_val[tid] = None
                        continue

                    # if current event_tst >= tst and event_dir == '>'
                    # there is no write include this event_tst

                    if event_dir == ">":
                        previous_val[tid] = event
                        break

                    # breakpoint()

                    # Identify each application-log row by path and 1-based line.
                    # Keep both write-event -> rows and row-key -> write-event maps.
                    evt_num = event["evt.num"]
                    line_no_1based = li + 1
                    applog_key = f"{log_path}:{line_no_1based}"

                    # A write event can be associated with multiple application-log rows.
                    if evt_num not in app_log_matches:
                        app_log_matches[evt_num] = []
                    app_log_matches[evt_num].append((log_path, line_no_1based, applog_key))
                    
                    # Index each row independently for event-index construction.
                    if "_applog_entries" not in app_log_matches:
                        app_log_matches["_applog_entries"] = {}
                    app_log_matches["_applog_entries"][applog_key] = (log_path, line_no_1based, evt_num)
                    
                    break

                except StopIteration:
                    break

    for key in fd_by_tid:
        fd_by_tid[key].close()

    return app_log_matches


def log_relating(
    graph: ProvGraph,
    scene: Scene,
    service_to_container_id: dict[str, str],
    conntrack_index_output_dir: str | None = None,
    conntrack_scenario_id: str | None = None,
) -> ProvGraph:

    # Relating App Logs

    pre_scan_fds = {}
    for event in load_sysdig():
        event_container_id = event["container.id"]
        event_tid = int(event["thread.vtid"])
        event_type = event["evt.type"]
        fd_name = event["fd.name"]

        if event_type != "write" or fd_name == "/dev/null":
            continue

        if (event_container_id, event_tid) not in pre_scan_fds:
            pre_scan_fds[(event_container_id, event_tid)] = open(
                f"{CAPTURED_PATH}/divided/{event_container_id}_{event_tid}.pk", "wb"
            )

        pre_scan_fds[(event_container_id, event_tid)].write(msgpack.packb(event))

    for key in pre_scan_fds:
        pre_scan_fds[key].close()

    # Match entries have two forms:
    # evt_num -> [(path, line_no, applog_key), ...] for graph association;
    # "_applog_entries" -> {applog_key: (path, line_no, evt_num)} for replay.
    graph.app_log_matches = {}

    for service_name, service in scene.services.items():
        app_log_path = service.get("x-app-log", None)
        if not app_log_path:
            continue
        directory = f"{CAPTURED_PATH}/app_log/{service_name}"
        for root, _, files in os.walk(directory):
            for file in files:
                path = os.path.join(root, file)
                try:
                    graph.app_log_files.add(path)
                    # Parse each file into the shared bidirectional match structure.
                    new_matches = parse_app_log(service_to_container_id[service_name], path)
                    
                    # Merge row-key metadata separately from write-event row lists.
                    for key, value in new_matches.items():
                        if key == "_applog_entries":
                            # Row keys identify one file and line.
                            if "_applog_entries" not in graph.app_log_matches:
                                graph.app_log_matches["_applog_entries"] = {}
                            graph.app_log_matches["_applog_entries"].update(value)
                        else:
                            # Multiple application logs may share a write-event key.
                            if key not in graph.app_log_matches:
                                graph.app_log_matches[key] = []
                            graph.app_log_matches[key].extend(value)
                except Exception as e:
                    logger.exception(e)
                    continue

    # Relating Traffic Logs

    all_nat_info: dict[
        tuple[bool, ConnInfo], list[tuple[NatInfo, datetime.datetime]]
    ] = {}
    conntrack_index_rows: list[dict[str, Any]] = []
    for service_name in scene.services.keys():
        container_id = service_to_container_id[service_name]
        nat_info, nat_export_rows = parse_log_file(container_id)
        for key in nat_info:
            all_nat_info.setdefault(key, [])
            all_nat_info[key] += nat_info[key]

        for nat_record, create_time in nat_export_rows:
            conntrack_index_rows.append(
                {
                    "container_id": container_id,
                    "service_name": service_name,
                    "conntrack_source_file": f"runtime/{container_id}_conntrack.txt",
                    "transport_proto": str(nat_record.transport_proto or "tcp").lower(),
                    "nat_timestamp_epoch": nat_record.timestamp.timestamp(),
                    "nat_timestamp": _format_conntrack_timestamp(nat_record.timestamp),
                    "create_time_epoch": create_time.timestamp(),
                    "create_time": _format_conntrack_timestamp(create_time),
                    "orig_src_ip": nat_record.orig_conn.src,
                    "orig_src_port": nat_record.orig_conn.sport,
                    "orig_dst_ip": nat_record.orig_conn.dst,
                    "orig_dst_port": nat_record.orig_conn.dport,
                    "reply_src_ip": nat_record.repl_conn.src,
                    "reply_src_port": nat_record.repl_conn.sport,
                    "reply_dst_ip": nat_record.repl_conn.dst,
                    "reply_dst_port": nat_record.repl_conn.dport,
                    "normalized_conn_key": _build_normalized_conn_key(
                        nat_record.orig_conn, nat_record.transport_proto
                    ),
                    "raw_line_no": nat_record.raw_line_no,
                }
            )

    for key in all_nat_info.keys():
        all_nat_info[key] = sorted(all_nat_info[key], key=lambda x: x[0].timestamp)

    if conntrack_index_output_dir and conntrack_scenario_id:
        export_conntrack_nat_index(
            conntrack_index_output_dir,
            conntrack_scenario_id,
            conntrack_index_rows,
        )

    for node in graph.nodes:
        if not isinstance(node, NetworkNode):
            continue
        if (
            node.client_ip == "null"
            or node.client_port == 0
            or node.server_ip == "null"
            or node.server_port == 0
        ):
            continue
        conn = ConnInfo(
            src=node.client_ip,
            sport=node.client_port,
            dst=node.server_ip,
            dport=node.server_port,
        )
        conns_server = query_net(
            conn,
            False,
            datetime.datetime.strptime(
                node.create_time.partition(".")[0], "%Y-%m-%d %H:%M:%S"
            ),
            all_nat_info,
        )
        conns_client = query_net(
            conn,
            True,
            datetime.datetime.strptime(
                node.create_time.partition(".")[0], "%Y-%m-%d %H:%M:%S"
            ),
            all_nat_info,
        )

        """
        FIRST_OUT_NODE = Node.ID_MAP[list(Node.ID_MAP[1].out_edges.keys())[0]]
        if isinstance(FIRST_OUT_NODE, NetworkNode) and (
            node.client_port == FIRST_OUT_NODE.client_port
        ):
            breakpoint()
        """
        conns = conns_server.union(conns_client)
        graph.join(node.ID, conns)

    # breakpoint()
    return graph


def get_(x: dict, keys: str):
    for key in keys.split("/"):
        if not key in x:
            return None
        x = x[key]
    return x


def _format_conntrack_timestamp(ts: datetime.datetime | None) -> str | None:
    if ts is None:
        return None
    return ts.isoformat(timespec="microseconds")


def _build_normalized_conn_key(conn: ConnInfo, transport_proto: str) -> str:
    proto = str(transport_proto or "tcp").lower()
    return f"{proto}|{conn.src}:{conn.sport}|{conn.dst}:{conn.dport}"


def export_conntrack_nat_index(
    output_dir: str,
    scenario_id: str,
    rows: list[dict[str, Any]],
) -> str | None:
    os.makedirs(output_dir, exist_ok=True)
    jsonl_path = os.path.join(output_dir, "conntrack_nat_index.v0.jsonl")

    if not rows:
        if os.path.exists(jsonl_path):
            os.remove(jsonl_path)
            logger.info(
                f"Skipping conntrack_nat_index export for {scenario_id}: no NAT rows collected; removed stale file {jsonl_path}"
            )
        else:
            logger.info(
                f"Skipping conntrack_nat_index export for {scenario_id}: no NAT rows collected"
            )
        return None

    with open(jsonl_path, "w", encoding="utf-8") as fh:
        for row in rows:
            rec = {
                "schema_version": CONNTRACK_NAT_INDEX_SCHEMA_VERSION,
                "scenario_id": scenario_id,
                "container_id": row["container_id"],
                "conntrack_source_file": row["conntrack_source_file"],
                "transport_proto": row["transport_proto"],
                "nat_timestamp_epoch": row["nat_timestamp_epoch"],
                "orig_src_ip": row["orig_src_ip"],
                "orig_src_port": row["orig_src_port"],
                "orig_dst_ip": row["orig_dst_ip"],
                "orig_dst_port": row["orig_dst_port"],
                "reply_src_ip": row["reply_src_ip"],
                "reply_src_port": row["reply_src_port"],
                "reply_dst_ip": row["reply_dst_ip"],
                "reply_dst_port": row["reply_dst_port"],
                "normalized_conn_key": row["normalized_conn_key"],
            }

            if row.get("service_name"):
                rec["service_name"] = row["service_name"]
            if row.get("nat_timestamp") is not None:
                rec["nat_timestamp"] = row["nat_timestamp"]
            if row.get("create_time_epoch") is not None:
                rec["create_time_epoch"] = row["create_time_epoch"]
            if row.get("create_time") is not None:
                rec["create_time"] = row["create_time"]
            if row.get("raw_line_no") is not None:
                rec["raw_line_no"] = row["raw_line_no"]

            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")

    logger.info(f"Conntrack NAT index exported: {jsonl_path} ({len(rows)} rows)")
    return jsonl_path


def _file_state(path: str | None) -> dict[str, Any]:
    if not path:
        return {"exists": False, "size_bytes": 0, "is_empty": True}

    exists = os.path.exists(path)
    size_bytes = os.path.getsize(path) if exists else 0
    return {
        "exists": exists,
        "size_bytes": size_bytes,
        "is_empty": size_bytes == 0,
    }


def export_capture_manifest(
    output_dir: str,
    scenario_id: str,
    generated_at: datetime.datetime,
    capture_root: str,
    result_index_dir: str,
    result_base_dir: str,
    service_to_container_id: dict[str, str],
    graph: ProvGraph,
    mode_b_dataset: bool,
) -> str:
    os.makedirs(output_dir, exist_ok=True)
    manifest_path = os.path.join(output_dir, "capture_manifest.v0.json")
    path_prefix = "raw/" if mode_b_dataset else ""

    sysdig_sources: list[dict[str, Any]] = []
    tshark_sources: list[dict[str, Any]] = []
    conntrack_sources: list[dict[str, Any]] = []
    applog_sources: list[dict[str, Any]] = []

    actual_file_paths: dict[str, str] = getattr(graph, "actual_file_paths", {})
    applog_path_map: dict[str, str] = getattr(graph, "applog_path_map", {})
    app_log_files: set[str] = getattr(graph, "app_log_files", set())

    for service_name, container_id in service_to_container_id.items():
        sysdig_relative_path = actual_file_paths.get(
            f"sysdig:{container_id}",
            f"{path_prefix}sysdig/{service_name}.log",
        )
        sysdig_abs_path = os.path.join(result_base_dir, sysdig_relative_path)
        sysdig_rec = {
            "container_id": container_id,
            "service_name": service_name,
            "relative_path": sysdig_relative_path,
        }
        sysdig_rec.update(_file_state(sysdig_abs_path))
        sysdig_sources.append(sysdig_rec)

        conntrack_runtime_file = os.path.join(capture_root, f"{container_id}_conntrack.txt")
        conntrack_rec = {
            "container_id": container_id,
            "service_name": service_name,
            "runtime_file": conntrack_runtime_file,
            "sidecar_relative_path": "index/conntrack_nat_index.v0.jsonl",
        }
        conntrack_rec.update(_file_state(conntrack_runtime_file))
        conntrack_sources.append(conntrack_rec)

        pcap_prefix = f"{container_id}_"
        for runtime_name in sorted(os.listdir(capture_root)) if os.path.isdir(capture_root) else []:
            if not runtime_name.startswith(pcap_prefix) or not runtime_name.endswith(".pcap"):
                continue
            device = runtime_name[len(pcap_prefix) : -len(".pcap")]
            pcap_runtime_file = os.path.join(capture_root, runtime_name)
            relative_path = actual_file_paths.get(
                f"traffic:{runtime_name}.json",
                f"{path_prefix}tshark/{service_name}_{device}.log",
            )
            tshark_rec = {
                "container_id": container_id,
                "service_name": service_name,
                "device": device,
                "pcap_runtime_file": pcap_runtime_file,
                "relative_path": relative_path,
            }
            tshark_rec.update(_file_state(pcap_runtime_file))
            tshark_sources.append(tshark_rec)

    for app_log_file in sorted(app_log_files):
        relative_path = applog_path_map.get(app_log_file)
        relative_path_raw = app_log_file.partition(f"{capture_root}/app_log/")[2]
        service_name = relative_path_raw.split("/", 1)[0] if relative_path_raw else ""
        container_id = service_to_container_id.get(service_name)
        applog_rec = {
            "container_id": container_id,
            "service_name": service_name,
            "runtime_file": app_log_file,
            "relative_path": relative_path,
        }
        applog_rec.update(_file_state(app_log_file))
        applog_sources.append(applog_rec)

    manifest = {
        "schema_version": CAPTURE_MANIFEST_SCHEMA_VERSION,
        "scenario_id": scenario_id,
        "generated_at": generated_at.isoformat(timespec="seconds"),
        "capture_root": capture_root,
        "result_index_dir": result_index_dir,
        "sources": {
            "sysdig": sysdig_sources,
            "tshark": tshark_sources,
            "conntrack": conntrack_sources,
            "applog": applog_sources,
        },
    }

    with open(manifest_path, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, ensure_ascii=False, indent=2)
        fh.write("\n")

    logger.info(f"Capture manifest exported: {manifest_path}")
    return manifest_path


def _safe_int(raw: Any) -> int | None:
    try:
        return int(str(raw))
    except (TypeError, ValueError):
        return None


def _safe_float(raw: Any) -> float | None:
    try:
        return float(str(raw))
    except (TypeError, ValueError):
        return None


def _traffic_bucket_bounds(timestamp_epoch: float | None) -> tuple[float, float]:
    if timestamp_epoch is None:
        return -1.0, -1.0
    bucket_start = math.floor(timestamp_epoch / TRAFFIC_MISS_TIME_BUCKET_SECONDS) * TRAFFIC_MISS_TIME_BUCKET_SECONDS
    bucket_end = bucket_start + TRAFFIC_MISS_TIME_BUCKET_SECONDS
    return float(bucket_start), float(bucket_end)


def _build_network_node_key(node: NetworkNode) -> str:
    return (
        f"cid={node.container_id}|pid={node.pid}|fd={node.fd}|"
        f"cip={node.client_ip}|cport={node.client_port}|"
        f"sip={node.server_ip}|sport={node.server_port}"
    )


def _ensure_traffic_anchor_runtime(graph: ProvGraph) -> None:
    if not hasattr(graph, "traffic_anchor_staging"):
        graph.traffic_anchor_staging = []
    if not hasattr(graph, "traffic_miss_summary"):
        graph.traffic_miss_summary = {}


def _record_traffic_miss(
    graph: ProvGraph,
    pcap_file: str,
    timestamp_epoch: float | None,
    miss_code: str,
    frame_number: int | None,
) -> None:
    _ensure_traffic_anchor_runtime(graph)

    if miss_code not in TRAFFIC_MISS_CODES:
        miss_code = "internal_error"

    bucket_start, bucket_end = _traffic_bucket_bounds(timestamp_epoch)
    key = f"{pcap_file}|{bucket_start}|{bucket_end}|{miss_code}"
    summary_map: dict[str, dict[str, Any]] = graph.traffic_miss_summary

    if key not in summary_map:
        summary_map[key] = {
            "pcap_file": pcap_file,
            "time_bucket_start_epoch": bucket_start,
            "time_bucket_end_epoch": bucket_end,
            "miss_code": miss_code,
            "packet_count": 0,
            "sample_frame_numbers": [],
        }

    rec = summary_map[key]
    rec["packet_count"] += 1
    if frame_number is not None:
        sample_frames = rec["sample_frame_numbers"]
        if len(sample_frames) < TRAFFIC_MISS_SAMPLE_LIMIT and frame_number not in sample_frames:
            sample_frames.append(frame_number)


def export_traffic_node_anchor_index(
    graph: ProvGraph,
    output_dir: str,
    scenario_id: str,
) -> tuple[str, str]:
    os.makedirs(output_dir, exist_ok=True)

    jsonl_path = os.path.join(output_dir, "traffic_node_anchor_index.v0.jsonl")
    summary_path = os.path.join(output_dir, "traffic_node_anchor_index_summary.v0.json")

    anchors: list[dict[str, Any]] = list(getattr(graph, "traffic_anchor_staging", []))
    miss_summary_map: dict[str, dict[str, Any]] = getattr(graph, "traffic_miss_summary", {})
    traffic_file_map: dict[str, str] = getattr(graph, "actual_file_paths", {})
    traffic_line_map: dict[str, int] = getattr(graph, "traffic_line_map", {})

    anchors.sort(key=lambda rec: (rec.get("pcap_file", ""), rec.get("frame_number", -1)))
    miss_rows = sorted(
        miss_summary_map.values(),
        key=lambda rec: (
            rec.get("pcap_file", ""),
            rec.get("time_bucket_start_epoch", -1),
            rec.get("miss_code", ""),
        ),
    )

    anchor_record_count = 0
    match_path_counts = {"forward": 0, "reverse": 0, "none": 0}
    pcap_file_distribution: dict[str, int] = {}
    l4_proto_counts: dict[str, int] = {}
    source_file_covered = 0
    line_no_covered = 0
    miss_code_counts: dict[str, int] = {}
    total_unmatched_packets = 0

    with open(jsonl_path, "w", encoding="utf-8") as fh:
        for staged in anchors:
            pcap_file = str(staged.get("pcap_file", ""))
            frame_number = _safe_int(staged.get("frame_number"))
            if not pcap_file or frame_number is None:
                continue

            source_file = traffic_file_map.get(f"traffic:{pcap_file}")
            line_no = traffic_line_map.get(f"{pcap_file}:{frame_number}")
            event_key = f"traffic:{pcap_file}:{frame_number}"

            match_path = str(staged.get("match_path") or "none")
            if match_path not in match_path_counts:
                match_path = "none"

            l4_proto = str(staged.get("l4_proto") or "")
            if l4_proto:
                l4_proto_counts[l4_proto] = l4_proto_counts.get(l4_proto, 0) + 1

            pcap_file_distribution[pcap_file] = pcap_file_distribution.get(pcap_file, 0) + 1
            match_path_counts[match_path] += 1

            if source_file:
                source_file_covered += 1
            if line_no is not None:
                line_no_covered += 1

            rec = {
                "schema_version": TRAFFIC_NODE_ANCHOR_SCHEMA_VERSION,
                "record_type": "anchor",
                "scenario_id": scenario_id,
                "packet_ref": {
                    "pcap_file": pcap_file,
                    "frame_number": frame_number,
                    "event_key": event_key,
                    "source_file": source_file,
                    "line_no": line_no,
                },
                "packet_feature": {
                    "timestamp_epoch": _safe_float(staged.get("timestamp_epoch")),
                    "l4_proto": l4_proto,
                    "src_ip": staged.get("src_ip"),
                    "src_port": _safe_int(staged.get("src_port")),
                    "dst_ip": staged.get("dst_ip"),
                    "dst_port": _safe_int(staged.get("dst_port")),
                },
                "anchor_result": {
                    "anchor_status": "matched",
                    "match_path": match_path,
                },
                "node_anchor": {
                    "graph_node_id": staged.get("graph_node_id"),
                    "node_key": staged.get("node_key"),
                    "container_id": staged.get("container_id"),
                    "proc_vpid": _safe_int(staged.get("proc_vpid")),
                    "fd_num": _safe_int(staged.get("fd_num")),
                    "client_ip": staged.get("client_ip"),
                    "client_port": _safe_int(staged.get("client_port")),
                    "server_ip": staged.get("server_ip"),
                    "server_port": _safe_int(staged.get("server_port")),
                },
            }
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
            anchor_record_count += 1

        for row in miss_rows:
            packet_count = int(row.get("packet_count", 0))
            miss_code = str(row.get("miss_code") or "internal_error")
            if miss_code not in TRAFFIC_MISS_CODES:
                miss_code = "internal_error"

            miss_code_counts[miss_code] = miss_code_counts.get(miss_code, 0) + packet_count
            total_unmatched_packets += packet_count

            rec = {
                "schema_version": TRAFFIC_NODE_ANCHOR_SCHEMA_VERSION,
                "record_type": "miss_summary",
                "scenario_id": scenario_id,
                "pcap_file": row.get("pcap_file"),
                "time_bucket_start_epoch": row.get("time_bucket_start_epoch"),
                "time_bucket_end_epoch": row.get("time_bucket_end_epoch"),
                "miss_code": miss_code,
                "packet_count": packet_count,
                "sample_frame_numbers": row.get("sample_frame_numbers", []),
            }
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")

    source_ratio = (source_file_covered / anchor_record_count) if anchor_record_count > 0 else 1.0
    line_no_ratio = (line_no_covered / anchor_record_count) if anchor_record_count > 0 else 1.0

    summary = {
        "schema_version": TRAFFIC_NODE_ANCHOR_SUMMARY_SCHEMA_VERSION,
        "scenario_id": scenario_id,
        "anchor_record_count": anchor_record_count,
        "miss_summary_record_count": len(miss_rows),
        "total_matched_packets": anchor_record_count,
        "total_unmatched_packets": total_unmatched_packets,
        "match_path_counts": match_path_counts,
        "pcap_file_distribution": pcap_file_distribution,
        "miss_code_counts": miss_code_counts,
        "source_file_coverage": {
            "covered": source_file_covered,
            "total": anchor_record_count,
            "ratio": source_ratio,
        },
        "line_no_coverage": {
            "covered": line_no_covered,
            "total": anchor_record_count,
            "ratio": line_no_ratio,
        },
        "l4_proto_counts": l4_proto_counts,
    }
    with open(summary_path, "w", encoding="utf-8") as fh:
        json.dump(summary, fh, ensure_ascii=False, indent=2)

    return jsonl_path, summary_path


def anchor_point_locating(graph: ProvGraph) -> ProvGraph:
    _ensure_traffic_anchor_runtime(graph)

    # Traffic Anchor Points
    for pcap_json_file, packet in load_tshark():
        try:
            frame_number = _safe_int(get_(packet, "_source/layers/frame/frame.number"))

            if (IP := get_(packet, "_source/layers/ip")) is None:
                _record_traffic_miss(
                    graph,
                    pcap_file=str(pcap_json_file),
                    timestamp_epoch=_safe_float(get_(packet, "_source/layers/frame/frame.time_epoch")),
                    miss_code="missing_ip_tuple",
                    frame_number=frame_number,
                )
                continue

            srcip = IP.get("ip.src")
            dstip = IP.get("ip.dst")
            if srcip is None or dstip is None:
                _record_traffic_miss(
                    graph,
                    pcap_file=str(pcap_json_file),
                    timestamp_epoch=_safe_float(get_(packet, "_source/layers/frame/frame.time_epoch")),
                    miss_code="missing_ip_tuple",
                    frame_number=frame_number,
                )
                continue

            if (
                timestamp := get_(packet, "_source/layers/frame/frame.time_epoch")
            ) is None:
                _record_traffic_miss(
                    graph,
                    pcap_file=str(pcap_json_file),
                    timestamp_epoch=None,
                    miss_code="missing_timestamp",
                    frame_number=frame_number,
                )
                continue

            timestamp_epoch = _safe_float(timestamp)
            if timestamp_epoch is None:
                _record_traffic_miss(
                    graph,
                    pcap_file=str(pcap_json_file),
                    timestamp_epoch=None,
                    miss_code="missing_timestamp",
                    frame_number=frame_number,
                )
                continue

            timestamp = datetime.datetime.fromtimestamp(timestamp_epoch)

            l4_proto = ""
            srcport: int | None = None
            dstport: int | None = None

            if (TCP := get_(packet, "_source/layers/tcp")) is not None:
                l4_proto = "tcp"
                srcport = _safe_int(TCP.get("tcp.srcport"))
                dstport = _safe_int(TCP.get("tcp.dstport"))

            elif (UDP := get_(packet, "_source/layers/udp")) is not None:
                l4_proto = "udp"
                srcport = _safe_int(UDP.get("udp.srcport"))
                dstport = _safe_int(UDP.get("udp.dstport"))

            else:
                _record_traffic_miss(
                    graph,
                    pcap_file=str(pcap_json_file),
                    timestamp_epoch=timestamp_epoch,
                    miss_code="missing_l4_port",
                    frame_number=frame_number,
                )
                continue

            if srcport is None or dstport is None:
                _record_traffic_miss(
                    graph,
                    pcap_file=str(pcap_json_file),
                    timestamp_epoch=timestamp_epoch,
                    miss_code="missing_l4_port",
                    frame_number=frame_number,
                )
                continue

            flag_str = get_(packet, "_source/layers/ip/ip.flags")
            flag = "0"
            if flag_str is not None:
                try:
                    flag = str((int(str(flag_str), base=16) & 0x80) >> 7)
                except (TypeError, ValueError):
                    flag = "0"

            recorded_packet = packet
            recorded_packet["pcap_file"] = pcap_json_file

            conn = ConnInfo(
                src=str(srcip), sport=int(srcport), dst=str(dstip), dport=int(dstport)
            )
            node = graph.query_by_time(conn, timestamp)
            if node is not None:
                node.logs.append(recorded_packet)
                if flag == "1":
                    node.is_malicious = True
                    # Anchor source observability (paper §Anchor Point
                    # Locating): record that this anchor came from the
                    # traffic-side ip.flags.rb path, not from an audit seed.
                    _anchor_src = getattr(graph, "runtime_diagnostics", {}).get(
                        "anchor_source", None
                    )
                    if isinstance(_anchor_src, dict):
                        _anchor_src["traffic_ip_flags_rb"] = (
                            _anchor_src.get("traffic_ip_flags_rb", 0) + 1
                        )

                graph.traffic_anchor_staging.append(
                    {
                        "pcap_file": str(pcap_json_file),
                        "frame_number": frame_number,
                        "timestamp_epoch": timestamp_epoch,
                        "l4_proto": l4_proto,
                        "src_ip": str(srcip),
                        "src_port": srcport,
                        "dst_ip": str(dstip),
                        "dst_port": dstport,
                        "match_path": "forward",
                        "graph_node_id": node.ID,
                        "node_key": _build_network_node_key(node),
                        "container_id": node.container_id,
                        "proc_vpid": node.pid,
                        "fd_num": node.fd,
                        "client_ip": node.client_ip,
                        "client_port": node.client_port,
                        "server_ip": node.server_ip,
                        "server_port": node.server_port,
                    }
                )
                continue

            # Reverse client and server and search again

            conn = ConnInfo(src=str(dstip), sport=dstport, dst=str(srcip), dport=srcport)
            node = graph.query_by_time(conn, timestamp)
            if node is not None:
                node.logs.append(recorded_packet)
                if flag == "1":
                    node.is_malicious = True
                    _anchor_src = getattr(graph, "runtime_diagnostics", {}).get(
                        "anchor_source", None
                    )
                    if isinstance(_anchor_src, dict):
                        _anchor_src["traffic_ip_flags_rb"] = (
                            _anchor_src.get("traffic_ip_flags_rb", 0) + 1
                        )

                graph.traffic_anchor_staging.append(
                    {
                        "pcap_file": str(pcap_json_file),
                        "frame_number": frame_number,
                        "timestamp_epoch": timestamp_epoch,
                        "l4_proto": l4_proto,
                        "src_ip": str(srcip),
                        "src_port": srcport,
                        "dst_ip": str(dstip),
                        "dst_port": dstport,
                        "match_path": "reverse",
                        "graph_node_id": node.ID,
                        "node_key": _build_network_node_key(node),
                        "container_id": node.container_id,
                        "proc_vpid": node.pid,
                        "fd_num": node.fd,
                        "client_ip": node.client_ip,
                        "client_port": node.client_port,
                        "server_ip": node.server_ip,
                        "server_port": node.server_port,
                    }
                )
                continue

            _record_traffic_miss(
                graph,
                pcap_file=str(pcap_json_file),
                timestamp_epoch=timestamp_epoch,
                miss_code="no_network_node_hit",
                frame_number=frame_number,
            )

        except Exception as e:
            _record_traffic_miss(
                graph,
                pcap_file=str(pcap_json_file),
                timestamp_epoch=_safe_float(get_(packet, "_source/layers/frame/frame.time_epoch")),
                miss_code="internal_error",
                frame_number=_safe_int(get_(packet, "_source/layers/frame/frame.number")),
            )
            logger.exception(e)
            raise

    return graph


def attack_subgraph_extraction(scene: Scene, graph: ProvGraph) -> ProvGraph:
    """
    out_degree: dict[Node, int] = {}
    departure_paths: dict[Node, set[Node]] = {}
    topo_queue: Queue[Node] = Queue()

    def is_network_or_unit(node: Node) -> NetworkNode | UnitNode | None:
        if isinstance(node, NetworkNode) or isinstance(node, UnitNode):
            return node
        return None

    for node in graph.nodes:
        out_degree[node] = len(node.out_edges)
        departure_paths[node] = set()

        if (
            isinstance(node, NetworkNode)
            and graph.merge_set.fa.get(node.ID, None) != node.ID
        ):
            continue

        if out_degree[node] == 0:
            topo_queue.put(node)

    while not topo_queue.empty():
        node = topo_queue.get()

        if (node_ := is_network_or_unit(node)) is not None:
            if not node_.is_malicious:
                continue

            for unique_path_node in departure_paths[node]:
                if (node_ := is_network_or_unit(unique_path_node)) is not None:
                    node_.is_malicious = True

            departure_paths[node] = {node}

        for source_id, edge_list in node.in_edges.items():
            src_node = Node.ID_MAP[source_id]
            out_degree[src_node] -= len(edge_list)
            departure_paths[src_node].update(departure_paths[node])
            if out_degree[src_node] == 0:
                topo_queue.put(src_node)

        if not IS_DEBUG:
            del departure_paths[node]

    return graph
    """

    long_conns: set[tuple[str, int]] = set()
    for node in graph.nodes:
        if isinstance(node, NetworkNode):
            in_edge_set = set(node.in_edges.keys())
            out_edge_set = set(node.out_edges.keys())
            all_edge_set = set()

            for to_node in in_edge_set:
                if graph.nodes[to_node].is_accept:
                    all_edge_set.add(to_node)

            for to_node in out_edge_set:
                if graph.nodes[to_node].is_accept:
                    all_edge_set.add(to_node)

            if (
                len(all_edge_set) > 2
                and f"{node.server_ip}:{node.server_port}" not in scene.attack_conns
            ):
                long_conns.add((node.server_ip, node.server_port))
                # breakpoint()

    if len(long_conns) != 0:
        logger.warning("Long Connections:")
        for conn in long_conns:
            logger.warning(conn)

    visited: set[Node] = set()

    def is_network_or_unit(node: Node) -> NetworkNode | UnitNode | None:
        if isinstance(node, NetworkNode) or isinstance(node, UnitNode):
            return node
        return None

    def dfs(node: NetworkNode | UnitNode, visited: set[Node]):
        visited.add(node)
        # Stop propagation through shared listeners with multiple accepts unless
        # the concrete flow is already an explicit malicious seed. A flow marked
        # by the injected packet flag must retain its label and reach downstream
        # units; unrelated connections on the same listener remain Suspicious.
        if (
            isinstance(node, NetworkNode)
            and (node.server_ip, node.server_port) in long_conns
            and node.is_malicious is not True
        ):
            node.is_malicious = "Suspicious"
            return

        for dst_id, _ in node.out_edges.items():
            dst_node = Node.ID_MAP[dst_id]
            if (
                isinstance(node, NetworkNode)
                and isinstance(dst_node, UnitNode)
                and not dst_node.is_accept
            ):
                continue
            if (
                dst_node not in visited
                and (node_ := is_network_or_unit(dst_node)) is not None
            ):
                if (
                    isinstance(node_, NetworkNode)
                    and (node_.server_ip, node_.server_port) in long_conns
                    and node_.is_malicious is not True
                ):
                    node_.is_malicious = "Suspicious"
                else:
                    node_.is_malicious = True
                    dfs(node_, visited)

    for node in graph.nodes:
        if (node_ := is_network_or_unit(node)) is not None:
            if node_ not in visited and node_.is_malicious is True:
                dfs(node_, visited)

    return graph


# ---------------------------------------------------------------------------
# Write-gated application-log labeling
# ---------------------------------------------------------------------------
# Preparation injects timestamp/thread markers into application logs. Log
# relating uses those markers to match each row to a thread's write syscall.
# Syscall attack flags identify anchor points, and dependency traversal marks
# the attack subgraph. Labels are then assigned through each row's matched write:
#
# * Strong: the write carries a per-event malicious seed, or its owning unit
#   belongs to the attack subgraph. Only these rows receive [*MALICIOUS*].
# * Weak: structural or bounded temporal evidence supports is_attack_related
#   without changing the raw log's malicious label.
#
# Weak evidence is evaluated in this order:
# 1. File-node provenance: the write target is resolved by container and inode.
#    Its first malicious write precedes or equals the matched write, with an
#    event-number distance no greater than _WRITE_LEVEL_WEAK_EVT_WINDOW.
# 2. Path provenance: a malicious write to the application-log path precedes or
#    equals the matched write within the same bounded event-number window.
# 3. Data flow: the owning unit reads a tainted file after its first malicious
#    write. Both the read and the matched application-log write must fall within
#    the bounded forward window. Optional logical-unit refinement rejects
#    mismatched unit IDs; missing IDs remain observable but are not rejected.
# 4. Process lineage: the owning unit is reachable from a malicious unit through
#    a bounded sequence of forward UnitNode-to-UnitNode edges.
# 5. Same-thread proximity: a malicious unit ends strictly before the matched
#    write in the same container/thread and within the event-number window.
#    This heuristic is used only when structural evidence is unavailable.
#
# File boundaries limit unrestricted graph propagation. Forward time bounds
# prevent one malicious write from indefinitely tainting a shared file.
# The 5,000-event bound limits the request-to-log-flush association window.
#
# Output contract:
# * graph.applog_write_level_strong: set[(path, line_no)] for raw log labels.
# * graph.applog_write_level_weak: set[(path, line_no)] for relatedness metadata.
# * graph.applog_write_level_decisions: per-row reasons and supporting evidence.
#
# This stage does not change node malicious flags, syscall fields, or traffic
# labels. Missing application-log declarations or matches produce empty sets.
# Weak evidence must never add [*MALICIOUS*] to raw application logs.
_WRITE_LEVEL_WEAK_EVT_WINDOW = 5000

# Bound forward process-lineage traversal to three UnitNode-to-UnitNode hops.
_WRITE_LEVEL_PROC_LINEAGE_MAX_HOPS = 3


def _collect_applog_path_prefixes_by_container(
    scene: Scene,
    service_to_container_id: dict[str, str],
) -> dict[str, list[str]]:
    """Map each service's declared x-app-log prefix to its container ID."""
    result: dict[str, list[str]] = {}
    for service_name, service in scene.services.items():
        prefix = service.get("x-app-log")
        if not prefix:
            continue
        container_id = service_to_container_id.get(service_name)
        if not container_id:
            continue
        result.setdefault(container_id, []).append(str(prefix))
    return result


def judge_applog_labels_at_write_level(
    scene: Scene,
    graph: ProvGraph,
    service_to_container_id: dict[str, str],
) -> dict[str, int]:
    """Assign application-log labels through their matched write syscalls.

    Read graph.app_log_matches, attack-subgraph unit labels, and the write
    events' per-log malicious seeds before graph.output applies node labels.

    Attach strong/weak (path, line_no) sets and per-row decision records to
    graph. Strong rows may receive raw [*MALICIOUS*] prefixes; weak rows supply
    is_attack_related metadata only. Return diagnostic counts without mutating
    existing node flags or log fields.
    """
    strong: set[tuple[str, int]] = set()
    weak: set[tuple[str, int]] = set()
    decisions: list[dict] = []

    diag = {
        "matched_applog_rows": 0,
        "labeled_strong": 0,
        "labeled_weak": 0,
        "labeled_none": 0,
        "reason_write_self_malicious": 0,
        "reason_containing_unit_malicious": 0,
        "reason_file_node_attack_provenance": 0,
        "reason_file_attack_provenance": 0,
        "reason_read_from_tainted_file": 0,
        "reason_proc_lineage_attack_related": 0,
        "reason_nearby_malicious_unit_same_tid": 0,
        "reason_no_evidence": 0,
        "skipped_no_app_log_matches": 0,
        "skipped_no_applog_declared": 0,
        # Count candidates rejected by forward-time or lineage constraints.
        "file_node_taint_forward_rejected": 0,
        "file_path_taint_forward_rejected": 0,
        "proc_lineage_ancestor_only_rejected": 0,
    }

    app_log_matches = getattr(graph, "app_log_matches", None) or {}
    if not app_log_matches:
        diag["skipped_no_app_log_matches"] = 1
        _attach_write_level_results(graph, strong, weak, decisions)
        return diag

    applog_prefixes = _collect_applog_path_prefixes_by_container(
        scene, service_to_container_id
    )
    if not applog_prefixes:
        diag["skipped_no_applog_declared"] = 1
        _attach_write_level_results(graph, strong, weak, decisions)
        return diag

    # Index event ranges, malicious thread units, and each event's owning unit.
    unit_evt_range: dict[UnitNode, tuple[int, int]] = {}
    malicious_units_by_tid: dict[tuple[str, str], list[tuple[int, int, UnitNode]]] = {}
    evt_to_unit: dict[tuple[str, int], UnitNode] = {}

    for node in graph.nodes:
        if not isinstance(node, UnitNode):
            continue
        nums: list[int] = []
        for log in node.logs:
            val = log.get("evt.num")
            if val is None:
                continue
            try:
                n = int(val)
            except (TypeError, ValueError):
                continue
            nums.append(n)
            evt_to_unit[(str(node.container_id), n)] = node
        if not nums:
            continue
        lo, hi = min(nums), max(nums)
        unit_evt_range[node] = (lo, hi)
        if node.is_malicious is True:
            tid_key = getattr(node, "tid", None) or "null"
            if tid_key != "null":
                malicious_units_by_tid.setdefault(
                    (str(node.container_id), str(tid_key)), []
                ).append((lo, hi, node))

    for tid_key in malicious_units_by_tid:
        malicious_units_by_tid[tid_key].sort(key=lambda t: t[1])  # Sort by last event.

    # Preserve direct access to per-write malicious seeds.
    write_log_by_evt: dict[tuple[str, int], dict] = {}
    for node in graph.nodes:
        if not isinstance(node, UnitNode):
            continue
        for log in node.logs:
            if log.get("evt.type") != "write":
                continue
            val = log.get("evt.num")
            if val is None:
                continue
            try:
                n = int(val)
            except (TypeError, ValueError):
                continue
            write_log_by_evt[(str(node.container_id), n)] = log

    # Record sorted malicious-unit write events by application-log path.
    # Path-based weak evidence must satisfy the bounded forward time window.
    tainted_write_evts_by_path: dict[str, list[int]] = {}
    for evt_num_key, rows in app_log_matches.items():
        if evt_num_key == "_applog_entries":
            continue
        try:
            _en = int(evt_num_key)
        except (TypeError, ValueError):
            continue
        if not isinstance(rows, list):
            continue
        matched_unit: UnitNode | None = None
        for (_cid, _en2), _u in evt_to_unit.items():
            if _en2 == _en:
                matched_unit = _u
                break
        if matched_unit is None or matched_unit.is_malicious is not True:
            continue
        for row in rows:
            try:
                _lp, _, _ = row
            except (TypeError, ValueError):
                continue
            tainted_write_evts_by_path.setdefault(str(_lp), []).append(_en)
    for _p in tainted_write_evts_by_path:
        tainted_write_evts_by_path[_p].sort()

    # Precompute graph-based weak evidence independently of log paths and TIDs:
    # malicious unit IDs; files written by those units and their earliest write
    # event; and bounded forward process-lineage successors.
    malicious_unit_ids: set[int] = set()
    for _n in graph.nodes:
        if isinstance(_n, UnitNode) and _n.is_malicious is True:
            malicious_unit_ids.add(_n.ID)

    tainted_file_ids: set[int] = set()
    tainted_file_first_mal_write_evtnum: dict[int, int] = {}
    for _n in graph.nodes:
        if not isinstance(_n, FileNode):
            continue
        _first_evt: int | None = None
        for _src_id, _edges in _n.in_edges.items():
            if _src_id not in malicious_unit_ids:
                continue
            for _e in _edges:
                _en = _e.log.get("evt.num") if isinstance(_e.log, dict) else None
                try:
                    _en = int(_en) if _en is not None else None
                except (TypeError, ValueError):
                    _en = None
                if _en is None:
                    continue
                if _first_evt is None or _en < _first_evt:
                    _first_evt = _en
        if _first_evt is not None:
            tainted_file_ids.add(_n.ID)
            tainted_file_first_mal_write_evtnum[_n.ID] = _first_evt

    # Traverse only forward UnitNode edges. This also covers unit successors
    # whose paths were not followed through network/accept traversal branches.
    forward_lineage_unit_ids: set[int] = set(malicious_unit_ids)
    _frontier = list(malicious_unit_ids)
    _hop = 0
    while _frontier and _hop < _WRITE_LEVEL_PROC_LINEAGE_MAX_HOPS:
        _next: list[int] = []
        for _uid in _frontier:
            _u = Node.ID_MAP.get(_uid)
            if not isinstance(_u, UnitNode):
                continue
            # Follow the attack-subgraph propagation direction.
            for _nbr_id in _u.out_edges.keys():
                _nbr = Node.ID_MAP.get(_nbr_id)
                if isinstance(_nbr, UnitNode) and _nbr_id not in forward_lineage_unit_ids:
                    forward_lineage_unit_ids.add(_nbr_id)
                    _next.append(_nbr_id)
        _frontier = _next
        _hop += 1

    # Bidirectional lineage is diagnostic only: it counts ancestor-only
    # candidates that cannot satisfy the forward-lineage labeling rule.
    bidirectional_lineage_unit_ids: set[int] = set(malicious_unit_ids)
    _b_frontier = list(malicious_unit_ids)
    _b_hop = 0
    while _b_frontier and _b_hop < _WRITE_LEVEL_PROC_LINEAGE_MAX_HOPS:
        _b_next: list[int] = []
        for _uid in _b_frontier:
            _u = Node.ID_MAP.get(_uid)
            if not isinstance(_u, UnitNode):
                continue
            for _nbr_id in list(_u.out_edges.keys()) + list(_u.in_edges.keys()):
                _nbr = Node.ID_MAP.get(_nbr_id)
                if (
                    isinstance(_nbr, UnitNode)
                    and _nbr_id not in bidirectional_lineage_unit_ids
                ):
                    bidirectional_lineage_unit_ids.add(_nbr_id)
                    _b_next.append(_nbr_id)
        _b_frontier = _b_next
        _b_hop += 1

    # Optional logical-unit refinement restricts data-flow weak evidence to
    # the same execution unit as a malicious unit when both IDs are available.
    # It is disabled by default because cross-request reads can legitimately
    # consume a persisted attacker-written payload. The bounded event window
    # still limits propagation, while match/mismatch/null counts expose
    # shared-file ambiguity without changing labels unless refinement is on.
    malicious_unit_unit_ids: set[str] = set()
    for _n in graph.nodes:
        if isinstance(_n, UnitNode) and _n.is_malicious is True:
            _uid = getattr(_n, "unit_id", None)
            if _uid and str(_uid) != "null":
                malicious_unit_unit_ids.add(str(_uid))

    _data_flow_unit_refine_on = _env_flag("SECLOG_DATAFLOW_UNIT_REFINE")
    diag["data_flow_unit_partition_experiment_on"] = 1 if _data_flow_unit_refine_on else 0
    diag["data_flow_matched_evt_out_of_window_rejected"] = 0
    diag["data_flow_unit_partition_mismatch_rejected"] = 0
    diag["data_flow_unit_partition_mismatch_observed"] = 0
    diag["data_flow_unit_partition_match_observed"] = 0
    diag["data_flow_unit_partition_owning_unit_id_null"] = 0

    # Count distinct reader units per tainted file to expose shared-file fan-out.
    _data_flow_distinct_owners_by_file: dict[int, set[int]] = {}

    # Evaluate each matched application-log row independently.
    for evt_num_key, rows in app_log_matches.items():
        if evt_num_key == "_applog_entries":
            continue
        try:
            evt_num = int(evt_num_key)
        except (TypeError, ValueError):
            continue
        if not isinstance(rows, list):
            continue

        for row in rows:
            try:
                log_path, line_no, _applog_key = row
            except (TypeError, ValueError):
                continue

            diag["matched_applog_rows"] += 1

            # Resolve the matched write's owning unit, container, and thread.
            container_id: str | None = None
            owning_unit: UnitNode | None = None
            write_log: dict | None = None

            for (cid, en), unit in evt_to_unit.items():
                if en == evt_num:
                    container_id = cid
                    owning_unit = unit
                    write_log = write_log_by_evt.get((cid, en))
                    break

            # Strong evidence is either a per-write attack seed or an owning
            # unit that belongs to the extracted attack subgraph.
            write_self_mal = bool(write_log and write_log.get("malicious") is True)
            containing_unit_mal = bool(owning_unit and owning_unit.is_malicious is True)

            # File-node provenance uses (container_id, fd.ino), not path text.
            # Require 0 <= matched_evt - first_malicious_write <= window so a
            # shared file cannot carry unbounded taint from one attack.
            file_node_attack_provenance = False
            file_node_id: int | None = None
            file_node_first_mal_write_evt: int | None = None
            if owning_unit is not None and write_log is not None:
                _ino = write_log.get("fd.ino")
                _cid_for_file = str(getattr(owning_unit, "container_id", container_id) or "")
                if _ino not in (None, "null", "") and _cid_for_file:
                    _fn = graph.node_by_ino.get((_cid_for_file, str(_ino)))
                    if _fn is not None:
                        file_node_id = _fn.ID
                        if _fn.ID in tainted_file_ids:
                            _first_mw = tainted_file_first_mal_write_evtnum.get(_fn.ID)
                            file_node_first_mal_write_evt = _first_mw
                            if _first_mw is not None:
                                _delta = evt_num - _first_mw
                                if 0 <= _delta <= _WRITE_LEVEL_WEAK_EVT_WINDOW:
                                    file_node_attack_provenance = True
                                elif _delta < 0:
                                    diag["file_node_taint_forward_rejected"] += 1
                                else:
                                    # Distinguish expired forward taint from a
                                    # candidate rejected for reverse time order.
                                    diag["file_node_taint_out_of_window_rejected"] = (
                                        diag.get("file_node_taint_out_of_window_rejected", 0) + 1
                                    )

            # Path provenance is a fallback association. A tainted write must
            # be no later than the matched write and within the event window.
            file_provenance_tainted = False
            file_provenance_from_evt: int | None = None
            _tainted_evts = tainted_write_evts_by_path.get(str(log_path))
            if _tainted_evts:
                _had_backward_candidate = False
                for _prev in _tainted_evts:
                    _d = evt_num - _prev
                    if 0 <= _d <= _WRITE_LEVEL_WEAK_EVT_WINDOW:
                        file_provenance_tainted = True
                        file_provenance_from_evt = _prev
                        break
                    if _d > _WRITE_LEVEL_WEAK_EVT_WINDOW:
                        # A later tainted write may be closer to the matched event.
                        continue
                    # Future tainted writes cannot propagate labels backward.
                    _had_backward_candidate = True
                    break
                if (not file_provenance_tainted) and _had_backward_candidate:
                    diag["file_path_taint_forward_rejected"] += 1

            # Data-flow evidence requires a read from a maliciously written
            # file. The read must be strictly after the first malicious write,
            # and both read and matched log-write must be within its forward
            # event window. Optional logical-unit refinement rejects mismatches
            # to limit ambiguous propagation through shared files.
            read_from_tainted = False
            read_from_tainted_file_id: int | None = None
            read_from_tainted_read_evt: int | None = None
            data_flow_unit_partition_match: bool | None = None
            _owning_unit_logical_id = (
                str(owning_unit.unit_id)
                if owning_unit is not None
                and getattr(owning_unit, "unit_id", None) not in (None, "null", "")
                else None
            )
            if owning_unit is not None:
                for _in_src_id, _in_edges in owning_unit.in_edges.items():
                    _src = Node.ID_MAP.get(_in_src_id)
                    if not (isinstance(_src, FileNode) and _src.ID in tainted_file_ids):
                        continue
                    _first_mw = tainted_file_first_mal_write_evtnum.get(_src.ID)
                    if _first_mw is None:
                        continue

                    # The matched log-write must satisfy the same forward window.
                    _matched_delta = evt_num - _first_mw
                    if _matched_delta < 0 or _matched_delta > _WRITE_LEVEL_WEAK_EVT_WINDOW:
                        if _matched_delta > _WRITE_LEVEL_WEAK_EVT_WINDOW:
                            diag["data_flow_matched_evt_out_of_window_rejected"] += 1
                        continue

                    _found_forward_read_evt: int | None = None
                    _had_out_of_window = False
                    for _e in _in_edges:
                        _re = _e.log.get("evt.num") if isinstance(_e.log, dict) else None
                        try:
                            _re = int(_re) if _re is not None else None
                        except (TypeError, ValueError):
                            _re = None
                        if _re is None:
                            continue
                        _rdelta = _re - _first_mw
                        if 0 < _rdelta <= _WRITE_LEVEL_WEAK_EVT_WINDOW:
                            _found_forward_read_evt = _re
                            break
                        if _rdelta > _WRITE_LEVEL_WEAK_EVT_WINDOW:
                            _had_out_of_window = True
                    if _found_forward_read_evt is not None:
                        # Record logical-unit agreement before applying the optional gate.
                        if _owning_unit_logical_id is None:
                            data_flow_unit_partition_match = None
                            diag["data_flow_unit_partition_owning_unit_id_null"] += 1
                        elif _owning_unit_logical_id in malicious_unit_unit_ids:
                            data_flow_unit_partition_match = True
                            diag["data_flow_unit_partition_match_observed"] += 1
                        else:
                            data_flow_unit_partition_match = False
                            diag["data_flow_unit_partition_mismatch_observed"] += 1

                        if (
                            _data_flow_unit_refine_on
                            and data_flow_unit_partition_match is False
                        ):
                            # Reject ambiguous cross-unit evidence when refinement is on.
                            diag["data_flow_unit_partition_mismatch_rejected"] += 1
                            # Another tainted file may provide an accepted match or null ID.
                            continue

                        read_from_tainted = True
                        read_from_tainted_file_id = _src.ID
                        read_from_tainted_read_evt = _found_forward_read_evt
                        # Measure how many distinct units read this tainted file.
                        _data_flow_distinct_owners_by_file.setdefault(
                            _src.ID, set()
                        ).add(owning_unit.ID)
                        break
                    if _had_out_of_window:
                        diag["data_flow_read_out_of_window_rejected"] = (
                            diag.get("data_flow_read_out_of_window_rejected", 0) + 1
                        )

            # Forward-only process lineage must reach the owning unit within
            # the hop bound. Ancestor-only paths contribute diagnostics, not labels.
            proc_lineage_related = False
            if (
                owning_unit is not None
                and owning_unit.ID in forward_lineage_unit_ids
                and owning_unit.ID not in malicious_unit_ids
            ):
                proc_lineage_related = True
            elif (
                owning_unit is not None
                and owning_unit.ID in bidirectional_lineage_unit_ids
                and owning_unit.ID not in forward_lineage_unit_ids
            ):
                diag["proc_lineage_ancestor_only_rejected"] += 1

            # Last-resort weak evidence: a malicious unit on the same
            # container/thread ends strictly before this write within the window.
            # Structural evidence takes priority over this temporal heuristic.
            nearby_mal_unit: UnitNode | None = None
            if owning_unit is not None:
                tid = str(getattr(owning_unit, "tid", None) or "null")
                if container_id and tid != "null":
                    candidates = malicious_units_by_tid.get(
                        (str(container_id), tid), []
                    )
                    for lo, hi, mu in candidates:
                        if mu is owning_unit:
                            continue
                        if hi >= evt_num:
                            continue
                        if evt_num - hi > _WRITE_LEVEL_WEAK_EVT_WINDOW:
                            continue
                        nearby_mal_unit = mu
                        break

            # Apply the evidence hierarchy in strict priority order:
            #     strong(write_self) > strong(containing_unit) >
            #     weak(file_node_attack_provenance) >
            #     weak(file_attack_provenance) >
            #     weak(read_from_tainted_file) >
            #     weak(proc_lineage_attack_related) >
            #     weak(nearby_malicious_unit_same_tid) > none
            key = (str(log_path), int(line_no))

            if write_self_mal or containing_unit_mal:
                strong.add(key)
                diag["labeled_strong"] += 1
                if write_self_mal:
                    reason = "write_self_malicious"
                    diag["reason_write_self_malicious"] += 1
                else:
                    reason = "containing_unit_malicious"
                    diag["reason_containing_unit_malicious"] += 1
            elif file_node_attack_provenance:
                weak.add(key)
                diag["labeled_weak"] += 1
                diag["reason_file_node_attack_provenance"] += 1
                reason = "file_node_attack_provenance"
            elif file_provenance_tainted:
                weak.add(key)
                diag["labeled_weak"] += 1
                diag["reason_file_attack_provenance"] += 1
                reason = "file_attack_provenance"
            elif read_from_tainted:
                weak.add(key)
                diag["labeled_weak"] += 1
                diag["reason_read_from_tainted_file"] += 1
                reason = "read_from_tainted_file"
            elif proc_lineage_related:
                weak.add(key)
                diag["labeled_weak"] += 1
                diag["reason_proc_lineage_attack_related"] += 1
                reason = "proc_lineage_attack_related"
            elif nearby_mal_unit is not None:
                weak.add(key)
                diag["labeled_weak"] += 1
                diag["reason_nearby_malicious_unit_same_tid"] += 1
                reason = "nearby_malicious_unit_same_tid"
            else:
                diag["labeled_none"] += 1
                diag["reason_no_evidence"] += 1
                reason = "no_evidence"

            # Group detailed reasons for downstream relatedness context:
            # anchor (strong); file provenance, data flow, process lineage, or
            # same-thread proximity (weak); None when evidence is absent.
            if reason in ("write_self_malicious", "containing_unit_malicious"):
                attack_related_source = "anchor"
            elif reason in ("file_node_attack_provenance", "file_attack_provenance"):
                attack_related_source = "file_provenance"
            elif reason == "read_from_tainted_file":
                attack_related_source = "data_flow"
            elif reason == "proc_lineage_attack_related":
                attack_related_source = "proc_lineage"
            elif reason == "nearby_malicious_unit_same_tid":
                attack_related_source = "nearby_tid"
            else:
                attack_related_source = None

            # Structural support excludes the same-thread proximity heuristic.
            via_attack_subgraph = bool(
                write_self_mal
                or containing_unit_mal
                or file_node_attack_provenance
                or file_provenance_tainted
                or read_from_tainted
                or proc_lineage_related
            )

            decisions.append({
                "applog_path": str(log_path),
                "line_no": int(line_no),
                "matched_evt_num": int(evt_num),
                "container_id": container_id,
                "thread_vtid": (
                    str(getattr(owning_unit, "tid", None))
                    if owning_unit is not None else None
                ),
                "owning_unit_id": (
                    str(getattr(owning_unit, "unit_id", "null"))
                    if owning_unit is not None else None
                ),
                "write_self_malicious": write_self_mal,
                "containing_unit_malicious": containing_unit_mal,
                "file_node_attack_provenance": file_node_attack_provenance,
                "file_node_id": file_node_id,
                # Together with matched_evt_num, this records the forward-taint bound.
                "file_node_first_mal_write_evt": file_node_first_mal_write_evt,
                "file_attack_provenance": file_provenance_tainted,
                "file_attack_provenance_from_evt": file_provenance_from_evt,
                "read_from_tainted_file": read_from_tainted,
                "read_from_tainted_file_id": read_from_tainted_file_id,
                # Preserve the attacker-write -> reader-unit event-order evidence.
                "read_from_tainted_file_read_evt": read_from_tainted_read_evt,
                # True: same logical unit; False: different units; None: missing ID.
                "data_flow_unit_partition_match": data_flow_unit_partition_match,
                "proc_lineage_attack_related": proc_lineage_related,
                "nearby_malicious_unit_tid": (
                    str(getattr(nearby_mal_unit, "tid", None))
                    if nearby_mal_unit is not None else None
                ),
                # True only when graph/provenance evidence supports the label.
                "via_attack_subgraph": via_attack_subgraph,
                "attack_related_source": attack_related_source,
                "decision": (
                    "malicious_strong" if key in strong
                    else ("attack_related_weak" if key in weak else "none")
                ),
                "reason": reason,
            })

    # Surface the anchor-source counter from SysdigProcessor up to the
    # write-level stage's diag. This is pure observability (paper §Anchor
    # Point Locating coverage report) — lets the pipeline-level stage
    # summary answer "which rule(s) produced the anchor seeds for this
    # scenario" without grep-ing raw/sysdig.
    _anchor_source = getattr(graph, "runtime_diagnostics", {}).get("anchor_source", None)
    if isinstance(_anchor_source, dict):
        for _k, _v in _anchor_source.items():
            diag[f"anchor_source_{_k}"] = _v

    # Separate structurally supported labels from thread-proximity-only labels.
    _via_subgraph = 0
    _via_tid_only = 0
    # Count weak-label contributions per inode, path, and data-flow source file.
    # Concentration on one shared file can indicate excessive dependency fan-out.
    _fanout_fp_inode: dict[int, int] = {}
    _fanout_fp_path: dict[str, int] = {}
    _fanout_data_flow: dict[int, int] = {}
    for _dec in decisions:
        if _dec.get("via_attack_subgraph") is True:
            _via_subgraph += 1
        elif _dec.get("decision") == "attack_related_weak":
            _via_tid_only += 1
        _reason = _dec.get("reason")
        if _reason == "file_node_attack_provenance":
            _fid = _dec.get("file_node_id")
            if _fid is not None:
                _fanout_fp_inode[_fid] = _fanout_fp_inode.get(_fid, 0) + 1
        elif _reason == "file_attack_provenance":
            _pp = _dec.get("applog_path")
            if _pp:
                _fanout_fp_path[_pp] = _fanout_fp_path.get(_pp, 0) + 1
        elif _reason == "read_from_tainted_file":
            _fid = _dec.get("read_from_tainted_file_id")
            if _fid is not None:
                _fanout_data_flow[_fid] = _fanout_data_flow.get(_fid, 0) + 1

    def _top_k(counts_dict, k: int = 5) -> list[tuple]:
        return sorted(counts_dict.items(), key=lambda kv: -kv[1])[:k]

    diag["via_attack_subgraph_count"] = _via_subgraph
    diag["via_tid_only_count"] = _via_tid_only

    # Estimate how often logical-unit refinement would reject observed
    # data-flow candidates without enabling the gate. Missing IDs remain in
    # the denominator and are reported separately from matches/mismatches.
    _m = diag.get("data_flow_unit_partition_match_observed", 0)
    _mm = diag.get("data_flow_unit_partition_mismatch_observed", 0)
    _null = diag.get("data_flow_unit_partition_owning_unit_id_null", 0)
    _denom = _m + _mm + _null
    diag["data_flow_unit_partition_would_demote_pct"] = (
        round(100.0 * _mm / _denom, 2) if _denom > 0 else None
    )
    diag["data_flow_unit_partition_match_pct"] = (
        round(100.0 * _m / _denom, 2) if _denom > 0 else None
    )
    diag["data_flow_unit_partition_null_pct"] = (
        round(100.0 * _null / _denom, 2) if _denom > 0 else None
    )

    diag["fanout_file_node_attack_provenance_unique_files"] = len(_fanout_fp_inode)
    diag["fanout_file_node_attack_provenance_top5"] = [
        {"file_node_id": k, "count": v} for (k, v) in _top_k(_fanout_fp_inode)
    ]
    diag["fanout_file_attack_provenance_unique_paths"] = len(_fanout_fp_path)
    diag["fanout_file_attack_provenance_top5"] = [
        {"applog_path": k, "count": v} for (k, v) in _top_k(_fanout_fp_path)
    ]
    diag["fanout_read_from_tainted_file_unique_files"] = len(_fanout_data_flow)
    diag["fanout_read_from_tainted_file_top5"] = [
        {"file_node_id": k, "count": v} for (k, v) in _top_k(_fanout_data_flow)
    ]
    # Report reader-unit fan-out for the most widely shared tainted files.
    _distinct_owners_top = sorted(
        [(fid, len(s)) for fid, s in _data_flow_distinct_owners_by_file.items()],
        key=lambda kv: -kv[1],
    )[:5]
    diag["data_flow_distinct_owning_units_top5"] = [
        {"file_node_id": fid, "distinct_owning_units": n}
        for (fid, n) in _distinct_owners_top
    ]
    diag["data_flow_max_distinct_owning_units"] = (
        _distinct_owners_top[0][1] if _distinct_owners_top else 0
    )

    # Attach each weak row's source-bucket size as a concentration hint.
    # This is diagnostic metadata only; it does not change decisions or raw logs.
    for _dec in decisions:
        _reason = _dec.get("reason")
        _hint: int | None = None
        if _reason == "file_node_attack_provenance":
            _fid = _dec.get("file_node_id")
            if _fid is not None:
                _hint = _fanout_fp_inode.get(_fid)
        elif _reason == "file_attack_provenance":
            _pp = _dec.get("applog_path")
            if _pp:
                _hint = _fanout_fp_path.get(_pp)
        elif _reason == "read_from_tainted_file":
            _fid = _dec.get("read_from_tainted_file_id")
            if _fid is not None:
                _hint = _fanout_data_flow.get(_fid)
        _dec["fanout_concentration_hint"] = _hint

    _attach_write_level_results(graph, strong, weak, decisions)
    return diag


def _attach_write_level_results(
    graph: ProvGraph,
    strong: set[tuple[str, int]],
    weak: set[tuple[str, int]],
    decisions: list[dict],
) -> None:
    setattr(graph, "applog_write_level_strong", strong)
    setattr(graph, "applog_write_level_weak", weak)
    setattr(graph, "applog_write_level_decisions", decisions)


def analyze_logs(
    scene: Scene,
    service_to_container_id: dict[str, str],
    inv_dict: dict[str, str],
    output_path: str,
    scene_name: str,
    export_attack_chains_flag: bool = True,
    export_replay_index_flag: bool = True,
    chain_mode: str = "unit",
    max_normal_chains: int | None = None,
    normal_sample_ratio: float | None = None,
    mode_b_dataset: bool = True,  # Preserve full raw logs with replay indexes.
    event_index_batch_size: int | None = None,  # Used only by the non-Mode-B event export.
    skip_validation: bool = True,  # Allow bulk generation without replay validation.
    export_applog_sidecars: bool = True,  # Export edge and application-log context.
    export_applog_backbone_candidates: bool = False,  # Optional candidate-context index.
    export_applog_write_level_labels: bool = False,  # Optional per-row labeling evidence.
):
    cur_time = datetime.datetime.now()
    timestamp_suffix = cur_time.strftime("%Y-%m-%d_%H-%M-%S")
    cur_time_str = str(cur_time)
    scenario_id = f"{scene_name}/{timestamp_suffix}"

    if mode_b_dataset:
        timestamp_base = os.path.join(output_path, timestamp_suffix)
        raw_dir = os.path.join(timestamp_base, "raw")
        index_dir = os.path.join(timestamp_base, "index")
    else:
        timestamp_base = os.path.join(output_path, cur_time_str)
        raw_dir = None
        index_dir = timestamp_base

    provenance_stage = _analyze_stage(
        "build_provenance_graph",
        scene_name=scene_name,
        output_path=output_path,
    )
    provenance_stage.start(inv_dict_count=len(inv_dict), services=len(service_to_container_id))
    try:
        graph = build_provenance_graph(inv_dict)
    except Exception as exc:
        provenance_stage.fail(exc, failing_step="build_provenance_graph")
        raise
    provenance_stage.done(graph_nodes=len(graph.nodes), graph_edges=len(graph.edges))

    relate_stage = _analyze_stage(
        "log_relating",
        scene_name=scene_name,
        output_path=output_path,
    )
    relate_stage.start(graph_nodes=len(graph.nodes), app_log_inputs=len(service_to_container_id))
    try:
        graph = log_relating(
            graph,
            scene,
            service_to_container_id,
            conntrack_index_output_dir=index_dir,
            conntrack_scenario_id=scenario_id,
        )
    except Exception as exc:
        relate_stage.fail(exc, failing_step="log_relating")
        raise
    relate_stage.done(app_log_matches=bool(getattr(graph, "app_log_matches", None)))

    anchor_stage = _analyze_stage(
        "anchor_point_locating",
        scene_name=scene_name,
        output_path=output_path,
    )
    anchor_stage.start(graph_edges=len(graph.edges))
    try:
        graph = anchor_point_locating(graph)
    except Exception as exc:
        anchor_stage.fail(exc, failing_step="anchor_point_locating")
        raise
    anchor_stage.done(graph_edges=len(graph.edges))

    subgraph_stage = _analyze_stage(
        "attack_subgraph_extraction",
        scene_name=scene_name,
        output_path=output_path,
    )
    subgraph_stage.start(graph_edges=len(graph.edges))
    try:
        graph = attack_subgraph_extraction(scene, graph)
    except Exception as exc:
        subgraph_stage.fail(exc, failing_step="attack_subgraph_extraction")
        raise
    subgraph_stage.done(graph_edges=len(graph.edges))

    # Backfill application-log labels through the matched write and attack
    # subgraph. Only strong decisions supply raw [*MALICIOUS*] prefixes;
    # weak decisions supply relatedness context without changing raw labels.
    write_level_stage = _analyze_stage(
        "judge_applog_labels_at_write_level",
        scene_name=scene_name,
        output_path=output_path,
    )
    write_level_stage.start(graph_edges=len(graph.edges))
    # The explicit off-switch skips labeling without attaching result
    # attributes or changing graph state; graph.output handles absent results.
    if _env_flag("SECLOG_THIRD_CUT_OFF"):
        write_level_stage.done(
            skipped=1,
            reason="SECLOG_THIRD_CUT_OFF=1",
            matched_applog_rows=0,
            labeled_strong=0,
            labeled_weak=0,
            labeled_none=0,
        )
    else:
        try:
            write_level_diag = judge_applog_labels_at_write_level(
                scene, graph, service_to_container_id
            )
        except Exception as exc:
            write_level_stage.fail(exc, failing_step="judge_applog_labels_at_write_level")
            raise
        write_level_stage.done(**write_level_diag)

    # Mode B stores the dataset under one timestamped run directory.
    if mode_b_dataset:
        # Create {output_path}/{YYYY-MM-DD_HH-MM-SS}/{raw,index}.
        output_stage = _analyze_stage(
            "prepare_output_dirs",
            scene_name=scene_name,
            output_path=output_path,
            input_path=output_path,
        )
        output_stage.start(output_root_exists=path_exists(output_path))
        try:
            os.makedirs(output_path, exist_ok=True)
        except Exception as e:
            output_stage.fail(e, failing_step="os.makedirs_output_root")
            raise
        
        try:
            os.makedirs(raw_dir, exist_ok=True)
            os.makedirs(index_dir, exist_ok=True)
        except Exception as e:
            output_stage.fail(
                e,
                failing_step="os.makedirs_raw_index",
                raw_dir=raw_dir,
                index_dir=index_dir,
            )
            raise
        output_stage.done(raw_dir_exists=path_exists(raw_dir), index_dir_exists=path_exists(index_dir))
        
        # Write captured sources into the run's raw directory.
        graph_output_stage = _analyze_stage(
            "graph_output",
            scene_name=scene_name,
            output_path=raw_dir,
            input_path=output_path,
        )
        graph_output_stage.start(raw_dir_exists=path_exists(raw_dir), graph_nodes=len(graph.nodes))
        try:
            graph.output(service_to_container_id, output_path, cur_time=cur_time, mode_b_raw_dir=raw_dir)
        except Exception as e:
            graph_output_stage.fail(e, failing_step="graph.output", raw_dir=raw_dir)
            raise
        graph_output_stage.done(raw_dir_exists=path_exists(raw_dir))
    else:
        # Non-Mode-B output uses the timestamped graph-output layout.
        os.makedirs(index_dir, exist_ok=True)
        graph.output(service_to_container_id, output_path, cur_time=cur_time)

    traffic_index_output_dir = index_dir if mode_b_dataset else os.path.join(output_path, cur_time_str)
    traffic_scenario_id = scenario_id
    try:
        traffic_stage = _analyze_stage(
            "export_traffic_node_anchor_index",
            scene_name=scene_name,
            output_path=traffic_index_output_dir,
            input_path=raw_dir or output_path,
        )
        traffic_stage.start(traffic_staging_exists=bool(getattr(graph, "traffic_anchor_staging", None)))
        traffic_jsonl, traffic_summary = export_traffic_node_anchor_index(
            graph,
            traffic_index_output_dir,
            traffic_scenario_id,
        )
        traffic_stage.done(
            traffic_jsonl_exists=path_exists(traffic_jsonl),
            traffic_summary_exists=path_exists(traffic_summary),
        )
        # Release staging records after the traffic anchor indexes are exported.
        if hasattr(graph, "traffic_anchor_staging"):
            graph.traffic_anchor_staging.clear()
        if hasattr(graph, "traffic_miss_summary"):
            graph.traffic_miss_summary.clear()
    except Exception as e:
        traffic_stage.fail(e, failing_step="export_traffic_node_anchor_index")
        raise

    build_legacy_attack_chain_path = export_attack_chains_flag and not mode_b_dataset
    build_legacy_node_index = export_replay_index_flag and build_legacy_attack_chain_path

    try:
        manifest_stage = _analyze_stage(
            "export_capture_manifest",
            scene_name=scene_name,
            output_path=index_dir,
            input_path=CAPTURED_PATH,
        )
        manifest_stage.start(capture_root_exists=path_exists(CAPTURED_PATH), index_dir_exists=path_exists(index_dir))
        export_capture_manifest(
            output_dir=index_dir,
            scenario_id=scenario_id,
            generated_at=cur_time,
            capture_root=CAPTURED_PATH,
            result_index_dir=index_dir,
            result_base_dir=timestamp_base,
            service_to_container_id=service_to_container_id,
            graph=graph,
            mode_b_dataset=mode_b_dataset,
        )
        manifest_stage.done(manifest_exists=path_exists(os.path.join(index_dir, "capture_manifest.v0.json")))
    except Exception as e:
        manifest_stage.fail(e, failing_step="export_capture_manifest")
        raise

    if mode_b_dataset and not build_legacy_attack_chain_path:
        released_network_logs = 0
        released_network_nodes = 0
        for node in graph.nodes:
            if not isinstance(node, NetworkNode):
                continue
            if getattr(node, "logs", None):
                released_network_logs += len(node.logs)
                released_network_nodes += 1
                node.logs.clear()
        logger.info(
            "Released NetworkNode.logs for the default Mode B mainline after raw/tshark, "
            "traffic anchor sidecars, and capture_manifest were exported. "
            f"Cleared {released_network_logs} traffic records from {released_network_nodes} network nodes. "
            "This cleanup is skipped for legacy attack_chain paths."
        )

    # Build replay indexes after graph.output records the actual raw-file paths.
    if build_legacy_node_index:
        node_stage = _analyze_stage(
            "build_node_index",
            scene_name=scene_name,
            output_path=index_dir,
        )
        node_stage.start(graph_nodes=len(graph.nodes))
        try:
            node_index = build_node_index(graph)
        except Exception as exc:
            node_stage.fail(exc, failing_step="build_node_index")
            raise
        node_stage.done(node_count=len(node_index))
    else:
        node_index = {}
        if mode_b_dataset:
            logger.info(
                "Skipping legacy build_node_index in default Mode B path; "
                "node_index is no longer needed by the current formal mainline"
            )
    
    event_stage = _analyze_stage(
        "build_event_index",
        scene_name=scene_name,
        output_path=index_dir,
        input_path=raw_dir or output_path,
    )
    event_stage.start(
        graph_edges=len(graph.edges),
        export_replay_index=export_replay_index_flag,
        app_log_matches=bool(getattr(graph, "app_log_matches", None)),
    )
    try:
        event_index = (
            build_event_index(graph, inv_dict, cur_time_str, graph.app_log_matches)
            if export_replay_index_flag
            else []
        )
    except Exception as exc:
        event_stage.fail(exc, failing_step="build_event_index")
        raise
    event_stage.done(event_count=len(event_index))

    chains: list[Any] = []

    if build_legacy_attack_chain_path:
        logger.info("Starting extract_attack_chains...")
        chains = extract_attack_chains(
            graph,
            scene_name=scene_name,
            mode=chain_mode,
            max_normal_chains=max_normal_chains,
            normal_sample_ratio=normal_sample_ratio,
            node_attr_map=node_index,
            app_log_matches=graph.app_log_matches if hasattr(graph, "app_log_matches") else None,
        )
        logger.info(f"Extracted {len(chains)} attack chains")
        
        if mode_b_dataset:
            logger.info(
                "Skipping legacy attack_chains.jsonl export in default Mode B path; "
                "attack chains remain in-memory only for current compatibility/validation steps"
            )
        else:
            # Export chain views under both timestamp and scene directories.
            export_attack_chains(chains, output_path, scene_name, subdir=cur_time_str)
            export_attack_chains(chains, os.path.join(output_path), scene_name, subdir=scene_name)
    elif export_attack_chains_flag and mode_b_dataset:
        logger.info(
            "Skipping legacy extract_attack_chains in default Mode B path; "
            "attack chains are no longer part of the current formal mainline build chain"
        )

    if export_replay_index_flag:
        if mode_b_dataset:
            # Mode B retains event_index in memory for context and validation.
            logger.info(
                "Skipping legacy event_index.jsonl export in default Mode B path; "
                "event_index remains in-memory only for current sidecar/validation steps"
            )

            if export_applog_sidecars:
                logger.info(
                    "Applog helper sidecar exports enabled in current rebuild phase; "
                    "default helper outputs include edge_applog_context / "
                    "applog_model_context"
                )

                # Writer-identity resolution consumes write_event_context_index
                # through build_behavior_chain_instances_v0.
                # Export it with application-log context, independently of the
                # optional applog_backbone_candidate_index diagnostic view.
                logger.info(
                    "Building write_event_context_index as applog writer-identity "
                    "resolution input from event_index applog rows..."
                )
                from replay_index import export_write_event_context_index
                write_ctx_path = export_write_event_context_index(
                    event_index,
                    index_dir,
                    scene_name,
                )
                logger.info(f"Write event context index exported: {write_ctx_path}")

                if export_applog_backbone_candidates:
                    logger.info(
                        "Building applog_backbone_candidate_index from event_index + write_event_context "
                        "(opt-in diagnostic/candidate sidecar)..."
                    )
                    from replay_index import export_applog_backbone_candidate_index
                    applog_candidate_path = export_applog_backbone_candidate_index(
                        event_index,
                        write_ctx_path,
                        index_dir,
                        scene_name,
                    )
                    logger.info(f"Applog backbone candidate index exported: {applog_candidate_path}")
                else:
                    logger.info(
                        "Skipping applog_backbone_candidate_index by default (no downstream consumer in the "
                        "official pipeline or release); enable export_applog_backbone_candidates only when "
                        "the candidate-sidecar diagnostic chain is required."
                    )

                # Link application-log rows to their event-index syscall entries.
                logger.info(f"Building edge_applog_context_view ({len(event_index)} events)...")
                from replay_index import export_edge_applog_context_view
                edge_view_path, edge_summary_path = export_edge_applog_context_view(
                    event_index, index_dir, scene_name
                )
                logger.info(f"Edge applog context view exported: {edge_view_path}")

                # Optional per-row evidence export, with the same strong/weak
                # priority as judge_applog_labels_at_write_level. Decisions also
                # feed relatedness context in memory, so disabling this file
                # does not disable multi-source labeling or change raw text.
                if export_applog_write_level_labels:
                    try:
                        write_level_decisions = getattr(
                            graph, "applog_write_level_decisions", []
                        ) or []
                        if write_level_decisions:
                            os.makedirs(index_dir, exist_ok=True)
                            wl_sidecar_path = os.path.join(
                                index_dir, "applog_write_level_labels.v0.jsonl"
                            )
                            import json as _wl_json
                            with open(wl_sidecar_path, "w", encoding="utf-8") as _wl_fh:
                                for _decision in write_level_decisions:
                                    _wl_fh.write(_wl_json.dumps(_decision, ensure_ascii=False) + "\n")
                            logger.info(
                                "applog_write_level_labels sidecar exported: "
                                f"{wl_sidecar_path} rows={len(write_level_decisions)}"
                            )
                        else:
                            logger.info(
                                "applog_write_level_labels sidecar skipped: "
                                "no decisions produced (likely no app_log_matches or no x-app-log)"
                            )
                    except Exception as _wl_exc:
                        # An optional diagnostic export must not block dataset generation.
                        logger.warning(
                            f"applog_write_level_labels sidecar export failed: {_wl_exc}"
                        )
                else:
                    logger.info(
                        "applog_write_level_labels sidecar skipped by default "
                        "(no pipeline/release consumer; enable --export-applog-write-level-labels to restore "
                        "the write-gated QA sidecar)."
                    )

                # Key in-memory decisions by (raw/applog-relative path, line_no)
                # to match model-context source_file/line_no coordinates.
                # Values retain decision, reason, and supporting provenance.
                write_level_by_rel_path: dict[tuple[str, int], dict] = {}
                try:
                    _path_map = getattr(graph, "applog_path_map", {}) or {}
                    for _decision in getattr(
                        graph, "applog_write_level_decisions", []
                    ) or []:
                        _orig = _decision.get("applog_path")
                        _rel = _path_map.get(_orig)
                        if _rel is None:
                            continue
                        try:
                            _ln = int(_decision.get("line_no"))
                        except (TypeError, ValueError):
                            continue
                        # Pass source category, graph support, and event-order
                        # evidence into the corresponding application-log context row.
                        write_level_by_rel_path[(_rel, _ln)] = {
                            "decision": _decision.get("decision"),
                            "reason": _decision.get("reason"),
                            "attack_related_source": _decision.get("attack_related_source"),
                            "via_attack_subgraph": _decision.get("via_attack_subgraph"),
                            "matched_evt_num": _decision.get("matched_evt_num"),
                            "file_node_id": _decision.get("file_node_id"),
                            "file_node_first_mal_write_evt": _decision.get("file_node_first_mal_write_evt"),
                            "read_from_tainted_file_id": _decision.get("read_from_tainted_file_id"),
                            "read_from_tainted_file_read_evt": _decision.get("read_from_tainted_file_read_evt"),
                            # Preserve the logical-unit agreement diagnostic.
                            "data_flow_unit_partition_match": _decision.get("data_flow_unit_partition_match"),
                            "owning_unit_id": _decision.get("owning_unit_id"),
                            "thread_vtid": _decision.get("thread_vtid"),
                            "fanout_concentration_hint": _decision.get("fanout_concentration_hint"),
                        }
                except Exception as _wlmap_exc:
                    logger.warning(
                        f"Failed to build write_level_by_rel_path map for model context: {_wlmap_exc}"
                    )
                    write_level_by_rel_path = {}

                logger.info("Building applog_model_context from edge_applog_context_view...")
                from replay_index import export_applog_model_context
                model_view_path, model_summary_path = export_applog_model_context(
                    event_index,
                    edge_view_path,
                    index_dir,
                    scene_name,
                    write_level_by_rel_path=write_level_by_rel_path,
                )
                logger.info(f"Applog model context exported: {model_view_path}, {model_summary_path}")
            else:
                logger.info(
                    "Skipping applog enhanced sidecar exports (export_applog_sidecars=False); "
                    "edge_applog_context / applog_model_context will not be written; "
                    "write_event_context_index and applog_backbone_candidate_index remain separately opt-in via "
                    "export_applog_backbone_candidates"
                )

            logger.info(
                "Skipping legacy node_index.json export in default Mode B path; "
                "node_index is retained only for explicit legacy attack-chain paths"
            )
            
            logger.info(
                "Skipping legacy manifests.json export in default Mode B path; "
                "manifests are not part of the current formal mainline"
            )

            # Validate Mode B references against the full raw-log files.
            if not skip_validation:
                from replay_index import verify_event_index_replayability, verify_event_keys_in_chains
                
                # Confirm that indexed raw-file lines exist and are readable.
                logger.info(f"Starting verify_event_index_replayability for {len(event_index)} events...")
                try:
                    verification = verify_event_index_replayability(event_index, raw_dir)
                    logger.info(
                        f"Mode B event_index validation passed: {verification['total_events']} events, "
                        f"all line_no valid and readable"
                    )
                except ValueError as e:
                    logger.error(f"Mode B event_index validation failed: {e}")
                    raise
                
                # Confirm that every chain evidence key resolves in event_index.
                if export_attack_chains_flag and chains:
                    logger.info(f"Starting verify_event_keys_in_chains for {len(chains)} chains...")
                    try:
                        event_keys = {
                            event_key
                            for event_key in (rec.get("event_key") for rec in event_index)
                            if event_key
                        }
                        key_verification = verify_event_keys_in_chains(chains, event_keys, mode_b_strict=True)
                        logger.info(
                            f"Mode B event_key verification passed: "
                            f"{key_verification['found_references']}/{key_verification['total_references']} "
                            f"event_keys found in event_index"
                        )
                    except ValueError as e:
                        logger.error(f"Mode B event_key verification failed: {e}")
                        raise
            else:
                logger.info("Skipping validation steps (skip_validation=True)")
        else:
            # Export to the timestamp directory; replay keys disambiguate
            # event IDs across source types, so conflict counts are not consumed.
            _, event_ids, event_keys, _ = export_event_index(
                event_index, os.path.join(output_path, cur_time_str), batch_size=event_index_batch_size
            )
            # Also export into the persistent scene directory.
            _, _, event_keys_scene, _ = export_event_index(
                event_index, os.path.join(output_path, scene_name), batch_size=event_index_batch_size
            )
        
        # Optional event-ID collision diagnostics; replay uses event_key.
        # if conflict_event_ids:
        #     logger.warning(
        #         f"Found {len(conflict_event_ids)} event_id(s) with cross-source-type conflicts: "
        #         f"{dict(list(conflict_event_ids.items())[:10])}"
        #     )
        #     logger.warning(
        #         "These event_ids appear in multiple source_types. "
        #         "Mode B: When replaying, MUST use event_key (not event_id) for disambiguation."
        #     )

        # Validate chain event IDs when chain export and validation are enabled.
        if export_attack_chains_flag and not skip_validation:
            from replay_index import verify_event_ids_in_chains

            verification = verify_event_ids_in_chains(chains, event_ids)
            logger.info(
                f"Event ID verification: {verification['found_references']}/{verification['total_references']} "
                f"references found in event_index. "
                f"Missing: {verification['missing_references']}"
            )
            if verification["missing_references"] > 0:
                logger.warning(
                    f"Sample missing IDs: {verification['missing_ids_sample']}"
                )

    if mode_b_dataset:
        # Mode B always exports unit and unit-event indexes, independently
        # of the optional chain and event-replay export flags.
        from replay_index import build_unit_event_index, build_unit_index, export_unit_event_index, export_unit_index

        logger.info(
            "Building unit_index for current Mode B mainline "
            "(independent of export_attack_chains_flag and export_replay_index_flag)..."
        )
        unit_index = build_unit_index(graph, chains, inv_dict)
        logger.info(f"Built unit_index: {len(unit_index)} units")
        export_unit_index(unit_index, index_dir)
        logger.info("Unit index exported")

        logger.info(
            "Building unit_event_index for current Mode B mainline "
            "(independent of export_attack_chains_flag and export_replay_index_flag)..."
        )
        unit_event_index = build_unit_event_index(graph)
        logger.info(f"Built unit_event_index: {len(unit_event_index)} events")
        export_unit_event_index(unit_event_index, index_dir)
        logger.info("Unit event index exported")

    # Keep Mode B raw files in place; archive only the non-Mode-B output.
    if not mode_b_dataset:
        cur_time_str = str(cur_time)
        exec_command(
            [
                "tar",
                "czvf",
                f"{output_path}/{cur_time_str}.tar.gz",
                "-C",
                f"{output_path}/{cur_time_str}",
                ".",
            ]
        )
        exec_command(["rm", "-rf", f"{output_path}/{cur_time_str}"])

    # -------------------------------------------------------------------
    # Build/analyze completion summary (human-readable)
    # -------------------------------------------------------------------
    # This block only prints; it does not change any artefact. It makes the
    # console output consistent with the pipeline/release entries so that
    # callers of bash build.sh see exactly which build-side artefacts were
    # produced and which are intentionally not written by the default
    # export policy (2026-04-21 build->release slim-down).
    if mode_b_dataset:
        try:
            scene_timestamp_dir = os.path.join(output_path, timestamp_suffix)
            current_level = highest_level_reached(scene_timestamp_dir)
            stage_banner(
                "analyze",
                "ok",
                scope="build",
                scenario=scene_name,
                extra={
                    "timestamp_dir": timestamp_suffix,
                    "highest_level": current_level,
                },
            )
            artifact_report(
                "build",
                "analyze",
                [
                    {"path": raw_dir, "label": "raw/"},
                    {"path": index_dir, "label": "index/"},
                    {
                        "path": os.path.join(index_dir, "write_event_context_index.v0.jsonl"),
                        "label": "index/write_event_context_index.v0.jsonl",
                    },
                    {
                        "path": os.path.join(index_dir, "unit_event_index.jsonl"),
                        "label": "index/unit_event_index.jsonl",
                    },
                    {
                        "path": os.path.join(index_dir, "unit_index.jsonl"),
                        "label": "index/unit_index.jsonl",
                    },
                    {
                        "path": os.path.join(index_dir, "capture_manifest.v0.json"),
                        "label": "index/capture_manifest.v0.json",
                    },
                    {
                        "path": os.path.join(index_dir, "applog_backbone_candidate_index.v0.jsonl"),
                        "label": "index/applog_backbone_candidate_index.v0.jsonl",
                        "optional": True,
                        "note": "disabled by default; enable via --export-applog-backbone-candidates",
                    },
                    {
                        "path": os.path.join(index_dir, "applog_write_level_labels.v0.jsonl"),
                        "label": "index/applog_write_level_labels.v0.jsonl",
                        "optional": True,
                        "note": "disabled by default; enable via --export-applog-write-level-labels",
                    },
                ],
            )
        except Exception as _summary_exc:
            # Summary printing must never break the build.
            logger.warning(f"build/analyze summary banner failed: {_summary_exc}")


if __name__ == "__main__":
    # analyze_logs()
    pass
