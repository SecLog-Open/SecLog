from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, List, Optional, Sequence, Tuple, Set
from loguru import logger

from console_observability import ProgressLogger, format_observation
from sysdig_rules.graph import Edge, FileNode, NetworkNode, Node, ProvGraph, UnitNode
from attack_chain import _node_label, _node_attrs, _parse_timestamp


WRITE_EVENT_CONTEXT_INDEX_SCHEMA_VERSION = "write_event_context_index.v0"
APPLOG_BACKBONE_CANDIDATE_INDEX_SCHEMA_VERSION = "applog_backbone_candidate_index.v0"
APPLOG_PREFIX_PATTERN = re.compile(
    r"^\[(?:SecLog|AutoLabel) (\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2})\.(\d{9}) (\d+)\] (.*)"
)


def _service_name_from_cid(container_id: str, inv_dict: Dict[str, str]) -> str:
    return inv_dict.get(container_id, container_id)


def _lookup_unit_id(graph: ProvGraph, container_id: Any, evt_num: Any) -> str:
    unit_event_map = getattr(graph, "unit_event_map", None)
    if unit_event_map is None:
        return "null"

    if container_id is None or evt_num is None:
        return "null"

    try:
        evt_num_int = int(evt_num)
    except (TypeError, ValueError):
        return "null"

    return str(unit_event_map.get((str(container_id), evt_num_int), "null"))


def _normalize_optional_unit_id(raw: Any) -> Optional[str]:
    if raw is None:
        return None
    s = str(raw).strip()
    if not s or s.lower() == "null":
        return None
    return s


def _build_unit_key(container_id: Any, thread_vtid: Any, unit_id: Any) -> Optional[str]:
    container_norm = _normalize_optional_unit_id(container_id)
    thread_norm = _normalize_optional_unit_id(thread_vtid)
    unit_norm = _normalize_optional_unit_id(unit_id)
    if container_norm is None or thread_norm is None or unit_norm is None:
        return None
    return f"{container_norm}:{thread_norm}:{unit_norm}"


def build_node_index(graph: ProvGraph) -> Dict[str, Dict[str, Any]]:
    """Index node attributes by node ID for replay and interpretation."""
    node_index: Dict[str, Dict[str, Any]] = {}

    file_path_hint: Dict[int, str] = {}
    proc_cmdline_hint: Dict[int, str] = {}

    for edge in graph.edges:
        log = getattr(edge, "log", {}) or {}
        if isinstance(edge.source, FileNode) or isinstance(edge.target, FileNode):
            path = log.get("fd.name") or log.get("evt.arg.pathname")
            if path:
                if isinstance(edge.source, FileNode):
                    file_path_hint.setdefault(edge.source.ID, path)
                if isinstance(edge.target, FileNode):
                    file_path_hint.setdefault(edge.target.ID, path)
        if isinstance(edge.source, UnitNode) or isinstance(edge.target, UnitNode):
            cmdline = log.get("proc.cmdline") or log.get("proc.exepath")
            if cmdline:
                if isinstance(edge.source, UnitNode):
                    proc_cmdline_hint.setdefault(edge.source.ID, cmdline)
                if isinstance(edge.target, UnitNode):
                    proc_cmdline_hint.setdefault(edge.target.ID, cmdline)

    for node in graph.nodes:
        label = _node_label(node)
        attrs = _node_attrs(node)
        if isinstance(node, FileNode) and node.ID in file_path_hint:
            attrs["path"] = file_path_hint[node.ID]
        if isinstance(node, UnitNode) and node.ID in proc_cmdline_hint:
            attrs["cmdline"] = proc_cmdline_hint[node.ID]
        node_index[label] = attrs

    return node_index


def _generate_raw_from_parsed(log: dict, source_type: str) -> Optional[str]:
    try:
        if source_type == "sysdig":
            evt_type = log.get("evt.type", "unknown")
            proc_name = log.get("proc.name", "unknown")
            pid = log.get("proc.pid", "?")
            fd_name = log.get("fd.name", "")
            datetime_str = log.get("evt.datetime", "")
            raw = f"{datetime_str} {proc_name}({pid}) {evt_type} {fd_name}"
            return raw[:2048]
        elif source_type == "traffic":
            frame = log.get("_source", {}).get("layers", {}).get("frame", {})
            frame_num = frame.get("frame.number", "?")
            ip_layer = log.get("_source", {}).get("layers", {}).get("ip", {})
            src_ip = ip_layer.get("ip.src", "?")
            dst_ip = ip_layer.get("ip.dst", "?")
            raw = f"Frame {frame_num}: {src_ip} -> {dst_ip}"
            return raw[:2048]
    except Exception:
        pass
    return None


def _event_record_from_log(
    log: dict,
    source_type: str,
    source_file: Optional[str],
    line_no: Optional[int] = None,
    byte_offset: Optional[int] = None,
    container_service: Optional[str] = None,
    raw_text: Optional[str] = None,
    inv_dict: Optional[Dict[str, str]] = None,
) -> Optional[Dict[str, Any]]:
    event_id = log.get("evt.num")
    timestamp = None
    container_id = log.get("container.id")
    service = container_service

    if source_type == "traffic":
        frame = log.get("_source", {}).get("layers", {}).get("frame", {})
        event_id = frame.get("frame.number")

        time_epoch = frame.get("frame.time_epoch")
        if time_epoch is not None:
            try:
                timestamp = float(str(time_epoch))
            except Exception:
                timestamp = None

        pcap_file = log.get("pcap_file", "")
        parts = pcap_file.split("_", 1)
        if len(parts) == 2 and parts[0]:
            container_id = parts[0]
            if inv_dict:
                service = _service_name_from_cid(container_id, inv_dict)

    if event_id is None:
        return None

    try:
        event_id = int(event_id)
    except Exception:
        return None

    if raw_text is None:
        raw_text = _generate_raw_from_parsed(log, source_type)

    if timestamp is None and "evt.datetime" in log:
        timestamp = _parse_timestamp(log.get("evt.datetime", ""))

    # Sysdig keys use evt.num; traffic keys include the capture to avoid collisions.
    if source_type == "traffic":
        pcap_file = log.get("pcap_file", "")
        event_key = f"traffic:{pcap_file}:{event_id}"  # Frame numbers are file-local.
    else:
        event_key = f"{source_type}:{event_id}"

    return {
        "event_id": event_id,
        "event_key": event_key,
        "source_type": source_type,
        "source_file": source_file,
        "line_no": line_no,
        "byte_offset": byte_offset,
        "timestamp": timestamp,
        "parsed": log,
        "raw": raw_text,
        "container_id": container_id,
        "service": service,
    }


def build_event_index(
    graph: ProvGraph,
    inv_dict: Dict[str, str],
    cur_time_str: str,
    app_log_matches: Dict[Any, Any],  # evt_num -> matches; _applog_entries -> records.
    minimize_parsed: bool = True,  # Keep essential parsed fields to limit memory use.
    include_traffic_events: bool = False,  # The main chain uses sysdig/applog by default.
) -> List[Dict[str, Any]]:
    from logs import CAPTURED_PATH
    import gc
    import psutil
    import os as os_module

    events: Dict[str, Dict[str, Any]] = {}
    process = psutil.Process(os_module.getpid())

    # Resolve sysdig events through the raw-log line-number map.
    total_edges = len(graph.edges)
    logger.info(
        format_observation(
            "[replay_index][stage]",
            stage="build_event_index",
            substep="sysdig_edges",
            status="start",
            total=total_edges,
        )
    )
    edge_progress = ProgressLogger(
        stage="build_event_index",
        substep="sysdig_edges",
        total=total_edges,
        every=50000,
        percent_step=10.0,
        min_interval_s=15.0,
        prefix="[replay_index][progress]",
        emit_fn=logger.info,
    )
    edge_count = 0
    last_memory_check = 0
    last_gc_count = 0
    
    for edge in graph.edges:
        edge_count += 1
        if edge_count % 50000 == 0:
            edge_progress.maybe_log(
                edge_count,
                force=True,
                events_collected=len(events),
            )
            # Monitor memory while collecting a large event index.
            if edge_count - last_memory_check >= 200000:  # Check every 200,000 edges.
                memory_info = process.memory_info()
                memory_mb = memory_info.rss / 1024 / 1024
                logger.info(f"Memory usage: {memory_mb:.1f} MB, events collected: {len(events)}")
                if memory_mb > 15000:  # Warn above 15,000 MiB of resident memory.
                    logger.warning(
                        f"High memory usage detected: {memory_mb:.1f} MB. "
                        f"Consider using a machine with more RAM or reducing data size."
                    )
                last_memory_check = edge_count
            
            # Collect unreachable objects every 500,000 edges.
            if edge_count - last_gc_count >= 500000:
                gc.collect()
                last_gc_count = edge_count
                logger.debug(f"Garbage collection performed at {edge_count} edges")
        log = getattr(edge, "log", {}) or {}
        if "evt.num" in log:
            container_id = log.get("container.id", "")
            evt_num = log.get("evt.num")
            service = _service_name_from_cid(container_id, inv_dict)
            path_key = f"sysdig:{container_id}"
            source_file = (
                graph.actual_file_paths.get(path_key)
                if hasattr(graph, "actual_file_paths")
                else f"raw/sysdig/{service}.log"
            )
            # Store source paths under the raw/ directory.
            if not source_file.startswith("raw/"):
                source_file = f"raw/{source_file}"
            
            # Look up the exact raw-log line for this container and event.
            line_no = None
            if hasattr(graph, "sysdig_line_map"):
                map_key = f"{container_id}:{evt_num}"
                line_no = graph.sysdig_line_map.get(map_key)
            
            # Every indexed sysdig event must have a replayable line number.
            if line_no is None:
                    raise ValueError(
                        f"Missing line_no for sysdig event: container_id={container_id}, evt_num={evt_num}"
                    )
            
            rec = _event_record_from_log(
                log,
                "sysdig",
                source_file,
                line_no=line_no,
                container_service=service,
                inv_dict=inv_dict,
            )
            if rec:
                # Minimize the parsed payload when requested.
                if minimize_parsed and rec.get("parsed"):
                    # Keep identification and replay fields; discard redundant data.
                    parsed = rec["parsed"]
                    minimal_parsed = {
                        "evt.type": parsed.get("evt.type"),
                        "evt.num": parsed.get("evt.num"),
                        "proc.pid": parsed.get("proc.pid"),
                        "fd.name": parsed.get("fd.name"),
                        "container.id": parsed.get("container.id"),
                        "evt.datetime": parsed.get("evt.datetime"),
                    }
                    rec["parsed"] = minimal_parsed
                    rec["raw"] = None
                events[rec["event_key"]] = rec

    edge_progress.maybe_log(
        edge_count,
        force=True,
        events_collected=len(events),
    )

    # Check memory before collecting traffic events.
    memory_info = process.memory_info()
    memory_mb = memory_info.rss / 1024 / 1024
    logger.info(
        format_observation(
            "[replay_index][stage]",
            stage="build_event_index",
            substep="sysdig_edges",
            status="done",
            total=total_edges,
            processed=edge_count,
            percent=100.0 if total_edges else None,
            memory_mb=round(memory_mb, 1),
            events_collected=len(events),
        )
    )
    if memory_mb > 15000:
        logger.warning(f"High memory usage before traffic processing: {memory_mb:.1f} MB")
    
    if include_traffic_events:
        # Resolve traffic records through their line-number map.
        # graph.output() writes logs only for unmerged root nodes.
        total_nodes = len(graph.nodes)
        logger.info(
            format_observation(
                "[replay_index][stage]",
                stage="build_event_index",
                substep="traffic_nodes",
                status="start",
                total=total_nodes,
            )
        )
        traffic_progress = ProgressLogger(
            stage="build_event_index",
            substep="traffic_nodes",
            total=total_nodes,
            every=10000,
            percent_step=10.0,
            min_interval_s=15.0,
            prefix="[replay_index][progress]",
            emit_fn=logger.info,
        )
        node_count = 0
        for node in graph.nodes:
            node_count += 1
            if node_count % 10000 == 0:
                traffic_progress.maybe_log(
                    node_count,
                    force=True,
                    events_collected=len(events),
                )
            if not isinstance(node, NetworkNode):
                continue
            # Match graph.output() by skipping nodes merged into another root.
            if hasattr(graph, 'merge_set') and graph.merge_set.fa.get(node.ID, None) != node.ID:
                continue
            for log in getattr(node, "logs", []):
                frame = log.get("_source", {}).get("layers", {}).get("frame", {})
                if "frame.number" not in frame:
                    continue
                pcap_file = log.get("pcap_file", "")
                frame_num = frame.get("frame.number")
                path_key = f"traffic:{pcap_file}"
                source_file = (
                    graph.actual_file_paths.get(path_key)
                    if hasattr(graph, "actual_file_paths")
                    else "raw/tshark/unknown.log"
                )
                # Store capture-log paths under raw/.
                if not source_file.startswith("raw/"):
                    source_file = f"raw/{source_file}"
                
                # Locate the frame within its capture file.
                line_no = None
                if hasattr(graph, "traffic_line_map") and pcap_file and frame_num is not None:
                    map_key = f"{pcap_file}:{frame_num}"
                    line_no = graph.traffic_line_map.get(map_key)
                
                # Missing line numbers make traffic evidence unreplayable.
                if line_no is None:
                    raise ValueError(
                        f"Missing line_no for traffic event: pcap_file={pcap_file}, frame_number={frame_num}"
                    )
                
                rec = _event_record_from_log(
                    log,
                    "traffic",
                    source_file,
                    line_no=line_no,
                    inv_dict=inv_dict,
                )
                if rec:
                    # Retain only essential traffic fields in minimized records.
                    if minimize_parsed and rec.get("parsed"):
                        parsed = rec["parsed"]
                        minimal_parsed = {
                            "frame.number": parsed.get("_source", {}).get("layers", {}).get("frame", {}).get("frame.number"),
                            "ip.src": parsed.get("_source", {}).get("layers", {}).get("ip", {}).get("ip.src"),
                            "ip.dst": parsed.get("_source", {}).get("layers", {}).get("ip", {}).get("ip.dst"),
                        }
                        rec["parsed"] = minimal_parsed
                    events[rec["event_key"]] = rec
        traffic_progress.maybe_log(
            node_count,
            force=True,
            events_collected=len(events),
        )
    else:
        logger.info(
            "Skipping traffic event construction in build_event_index for the default mainline path; "
            "retain sysdig/applog records only"
        )

    # Check and reclaim memory before collecting application logs.
    memory_info = process.memory_info()
    memory_mb = memory_info.rss / 1024 / 1024
    logger.info(f"After traffic processing: Memory usage: {memory_mb:.1f} MB, events collected: {len(events)}")
    if memory_mb > 15000:
        logger.warning(f"High memory usage before applog processing: {memory_mb:.1f} MB")
        gc.collect()  # Reclaim unreachable objects under memory pressure.
    
    # Application logs have independent path:line_no keys.
    # _applog_entries maps each key to (path, line_no, matched sysdig evt_num).
    import linecache
    
    applog_entries = app_log_matches.get("_applog_entries", {})
    logger.info(
        format_observation(
            "[replay_index][stage]",
            stage="build_event_index",
            substep="applog_entries",
            status="start",
            total=len(applog_entries),
        )
    )
    applog_progress = ProgressLogger(
        stage="build_event_index",
        substep="applog_entries",
        total=len(applog_entries),
        every=50000,
        percent_step=10.0,
        min_interval_s=15.0,
        prefix="[replay_index][progress]",
        emit_fn=logger.info,
    )
    for applog_count, (applog_key, (path, line_no, evt_num)) in enumerate(applog_entries.items(), 1):
        raw_text = None
        if path and os.path.exists(path):
            try:
                # Request one line through linecache's cached-file interface.
                # Both the stored line number and linecache use one-based indexing.
                line = linecache.getline(path, line_no)
                if line:
                    raw_text = line.rstrip("\n\r")[:4096]
            except Exception:
                pass

        if path and hasattr(graph, "applog_path_map") and path in graph.applog_path_map:
            tar_path = graph.applog_path_map[path]
        else:
            tar_path = f"applog/{os.path.basename(path)}"
        
        # Keep the exported application-log path under raw/.
        if not tar_path.startswith("raw/"):
            tar_path = f"raw/{tar_path}"

        service = None
        if "applog/" in tar_path:
            # Extract the service name from raw/applog/<service>#<log>.
            parts = tar_path.split("applog/", 1)
            if len(parts) == 2:
                service = parts[1].split("#", 1)[0]
        
        # An application log's own key must supply a line number.
        if line_no is None:
            raise ValueError(
                f"Missing line_no for applog event: applog_key={applog_key}, path={path}"
            )

        # Use the application-log key independently of the matched sysdig event.
        # Preserve its one-based line number without an offset.
        event_key = f"applog:{applog_key}"
        events[event_key] = {
            "event_id": applog_key,  # The log's own identifier, not evt_num.
            "event_key": event_key,
            "source_type": "applog",
            "source_file": tar_path,
            "line_no": line_no,  # Already one-based.
            "byte_offset": None,
            "timestamp": None,
            "parsed": None,
            "raw": raw_text,
            "container_id": None,
            "service": service,
            "related_evt_num": evt_num,  # Preserve the sysdig association.
        }
        if applog_count % 50000 == 0:
            applog_progress.maybe_log(
                applog_count,
                force=True,
                events_collected=len(events),
                current_input=path,
            )
    applog_progress.maybe_log(
        len(applog_entries),
        force=True,
        events_collected=len(events),
    )

    # Report memory usage after all event types have been collected.
    memory_info = process.memory_info()
    memory_mb = memory_info.rss / 1024 / 1024
    logger.info(
        format_observation(
            "[replay_index][stage]",
            stage="build_event_index",
            status="done",
            processed=len(events),
            memory_mb=round(memory_mb, 1),
            total_events=len(events),
        )
    )
    
    # Return the records and release the intermediate dictionary.
    result = list(events.values())
    del events  # Drop the dictionary's references explicitly.
    gc.collect()  # Reclaim unreachable objects before returning.
    
    return result


def export_event_index(
    event_index: Sequence[Dict[str, Any]],
    output_dir: str,
    batch_size: Optional[int] = None,
):
    """Write event_index.jsonl and collect identifiers for reference checks.

    Args:
        event_index: Event records to export.
        output_dir: Destination directory.
        batch_size: Explicit write-batch size, or None for automatic selection.
            Automatic mode uses batches of 50,000 above 100,000 events and a
            single batch otherwise.

    Returns:
        (output_path, event_ids, event_keys, conflict_event_ids)
    """
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, "event_index.jsonl")

    event_ids: Set[int] = set()
    event_keys: Set[str] = set()  # Source-qualified keys used by replay references.
    event_id_to_sources: Dict[int, Set[str]] = {}

    total_events = len(event_index)
    
    # Enable bounded write batches automatically above 100,000 events.
    if batch_size is None:
        if total_events > 100000:
            batch_size = 50000
            logger.info(f"Auto-enabling batch mode: {total_events} events, batch_size={batch_size}")
        else:
            batch_size = None
    
    # Split the output only when it exceeds the selected batch size.
    use_batch = batch_size is not None and total_events > batch_size
    
    # Buffer serialized records to reduce write-system-call overhead.
    buffer_size = 1024 * 1024  # 1 MiB write buffer.
    with open(output_path, "w", buffering=buffer_size) as f:
        if use_batch:
            # Bound the temporary serialized payload to one batch.
            logger.info(f"Writing {total_events} events in batches of {batch_size}...")
            for i in range(0, total_events, batch_size):
                batch = event_index[i:i + batch_size]
                batch_num = (i // batch_size) + 1
                total_batches = (total_events + batch_size - 1) // batch_size
                
                # Serialize the current batch before writing it together.
                lines = []
                for rec in batch:
                    eid = rec.get("event_id")
                    st = rec.get("source_type", "unknown")
                    event_key = rec.get("event_key")
                    
                    if eid is not None:
                        event_ids.add(eid)
                        event_id_to_sources.setdefault(eid, set()).add(st)
                    
                    # Retain source-qualified keys for evidence validation.
                    if event_key:
                        event_keys.add(event_key)
                    
                    lines.append(json.dumps(rec, ensure_ascii=False) + "\n")
                f.writelines(lines)
                
                if batch_num % 10 == 0 or batch_num == total_batches:
                    logger.info(f"Written batch {batch_num}/{total_batches} ({i + len(batch)}/{total_events} events)...")
        else:
            # Serialize smaller indexes in a single batch.
            logger.info(f"Writing {total_events} events in single batch...")
            lines = []
            for rec in event_index:
                eid = rec.get("event_id")
                st = rec.get("source_type", "unknown")
                event_key = rec.get("event_key")
                
                if eid is not None:
                    event_ids.add(eid)
                    event_id_to_sources.setdefault(eid, set()).add(st)
                
                # Retain source-qualified keys for evidence validation.
                if event_key:
                    event_keys.add(event_key)
                
                lines.append(json.dumps(rec, ensure_ascii=False) + "\n")
            
            # Write the prepared records together.
            f.writelines(lines)

    conflict_event_ids = {
        eid: sorted(list(sts))
        for eid, sts in event_id_to_sources.items()
        if len(sts) > 1
    }

    return output_path, event_ids, event_keys, conflict_event_ids


def verify_event_ids_in_chains(
    attack_chains: List[Any],
    event_ids: set,
) -> Dict[str, Any]:
    missing_ids = set()
    total_refs = 0
    found_refs = 0

    for chain in attack_chains:
        chain_dict = chain.to_dict() if hasattr(chain, "to_dict") else chain

        for log_id in chain_dict.get("log_ids", []):
            total_refs += 1
            if log_id in event_ids:
                found_refs += 1
            else:
                missing_ids.add(log_id)

        for edge in chain_dict.get("path_edges", []):
            for evt_id in edge.get("evidence_event_ids", []):
                total_refs += 1
                if evt_id in event_ids:
                    found_refs += 1
                else:
                    missing_ids.add(evt_id)

        for edge in chain_dict.get("anomaly_edges", []):
            for evt_id in edge.get("evidence_event_ids", []):
                total_refs += 1
                if evt_id in event_ids:
                    found_refs += 1
                else:
                    missing_ids.add(evt_id)

    return {
        "total_references": total_refs,
        "found_references": found_refs,
        "missing_references": len(missing_ids),
        "missing_ids_sample": list(missing_ids)[:20],
    }


def build_event_key_index(event_index: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """Build an event_key-to-record lookup for indexed evidence replay."""
    index: Dict[str, Dict[str, Any]] = {}
    for rec in event_index:
        event_key = rec.get("event_key")
        if event_key:
            index[event_key] = rec
    return index


def verify_event_keys_in_chains(
    attack_chains: List[Any],
    event_keys: Set[str],
    mode_b_strict: bool = True,
) -> Dict[str, Any]:
    """Check that chain evidence_event_keys resolve in the event index.

    Args:
        attack_chains: Chains whose path and anomaly edges are checked.
        event_keys: All source-qualified keys exported to event_index.jsonl.
        mode_b_strict: Raise ValueError for empty or unresolved evidence keys.

    Returns:
        Reference counts and examples of missing keys and affected chains.

    Raises:
        ValueError: Strict validation encounters missing evidence keys.
    """
    missing_keys: Set[str] = set()
    missing_chains: List[str] = []
    total_refs = 0
    found_refs = 0
    missing_samples: List[Dict[str, Any]] = []

    for chain in attack_chains:
        chain_dict = chain.to_dict() if hasattr(chain, "to_dict") else chain
        chain_id = chain_dict.get("chain_id", "unknown")
        has_missing = False
        
        # Validate evidence references on path edges.
        for edge in chain_dict.get("path_edges", []):
            evidence_keys = edge.get("evidence_event_keys", [])
            if not evidence_keys:
                # Strict replay requires nonempty evidence_event_keys.
                if mode_b_strict:
                    raise ValueError(
                        f"Mode B: chain {chain_id} path_edge {edge.get('edge_id')} "
                        f"missing evidence_event_keys (required, cannot be empty)"
                    )
                has_missing = True
                missing_samples.append({
                    "chain_id": chain_id,
                    "edge_id": edge.get("edge_id", "unknown"),
                    "issue": "missing evidence_event_keys",
                })
                continue
            
            for event_key in evidence_keys:
                total_refs += 1
                if event_key in event_keys:
                    found_refs += 1
                else:
                    missing_keys.add(event_key)
                    if len(missing_samples) < 20:
                        missing_samples.append({
                            "chain_id": chain_id,
                            "edge_id": edge.get("edge_id", "unknown"),
                            "event_key": event_key,
                        })
        
        # Apply the same reference checks to anomaly edges.
        for edge in chain_dict.get("anomaly_edges", []):
            evidence_keys = edge.get("evidence_event_keys", [])
            if not evidence_keys:
                if mode_b_strict:
                    raise ValueError(
                        f"Mode B: chain {chain_id} anomaly_edge {edge.get('edge_id')} "
                        f"missing evidence_event_keys (required, cannot be empty)"
                    )
                has_missing = True
                missing_samples.append({
                    "chain_id": chain_id,
                    "edge_id": edge.get("edge_id", "unknown"),
                    "issue": "missing evidence_event_keys",
                })
                continue
            
            for event_key in evidence_keys:
                total_refs += 1
                if event_key in event_keys:
                    found_refs += 1
                else:
                    missing_keys.add(event_key)
                    has_missing = True
                    if len(missing_samples) < 20:
                        missing_samples.append({
                            "chain_id": chain_id,
                            "edge_id": edge.get("edge_id", "unknown"),
                            "event_key": event_key,
                        })
        
        if has_missing:
            missing_chains.append(str(chain_id))
    
    result = {
        "total_references": total_refs,
        "found_references": found_refs,
        "missing_references": total_refs - found_refs,
        "missing_keys_sample": sorted(list(missing_keys))[:20],
        "missing_chains_sample": missing_chains[:10],
    }
    
    # Strict mode rejects any evidence key absent from the event index.
    if mode_b_strict and missing_keys:
        error_msg = (
            f"Mode B validation FAILED: {len(missing_keys)} event_keys not found in event_index.\n"
            f"  Total references: {total_refs}, Found: {found_refs}, Missing: {len(missing_keys)}\n"
            f"  Sample missing keys: {list(missing_keys)[:10]}\n"
            f"  Affected chains: {missing_chains[:10]}"
        )
        raise ValueError(error_msg)
    
    return result


def export_node_index(node_index: Dict[str, Dict[str, Any]], output_dir: str):
    """Write node attributes to node_index.json."""
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, "node_index.json")
    with open(output_path, "w") as f:
        json.dump(node_index, f, ensure_ascii=False)
    return output_path


def build_unit_index(
    graph: ProvGraph,
    chains: List[Any],
    inv_dict: Dict[str, str],
) -> List[Dict[str, Any]]:
    """Build event windows for each valid execution unit in unit_index.jsonl."""
    _ = chains, inv_dict

    unit_windows: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
    for node in graph.nodes:
        if not isinstance(node, UnitNode):
            continue

        for log in node.logs:
            evt_num = log.get("evt.num")
            container_id = log.get("container.id") or node.container_id
            unit_id = _lookup_unit_id(graph, container_id, evt_num)
            unit_id_norm = _normalize_optional_unit_id(unit_id)
            if evt_num is None or unit_id_norm is None:
                continue

            thread_vtid = log.get("thread.vtid") or node.tid
            container_id_norm = str(container_id)
            thread_vtid_norm = str(thread_vtid)
            unit_key = _build_unit_key(container_id_norm, thread_vtid_norm, unit_id_norm)
            try:
                evt_num_int = int(evt_num)
            except (TypeError, ValueError):
                continue
            evt_datetime = log.get("evt.datetime")
            key = (unit_id_norm, container_id_norm, thread_vtid_norm)

            window = unit_windows.get(key)
            if window is None:
                unit_windows[key] = {
                    "unit_id": unit_id_norm,
                    "unit_key": unit_key,
                    "container_id": container_id_norm,
                    "thread_vtid": thread_vtid_norm,
                    "evt_num_start": evt_num_int,
                    "evt_num_end": evt_num_int,
                    "time_start": evt_datetime,
                    "time_end": evt_datetime,
                    "event_count": 1,
                }
                continue

            if evt_num_int < window["evt_num_start"]:
                window["evt_num_start"] = evt_num_int
            if evt_num_int > window["evt_num_end"]:
                window["evt_num_end"] = evt_num_int
            if evt_datetime is not None:
                if window["time_start"] is None or evt_datetime < window["time_start"]:
                    window["time_start"] = evt_datetime
                if window["time_end"] is None or evt_datetime > window["time_end"]:
                    window["time_end"] = evt_datetime
            window["event_count"] += 1

    unit_index = sorted(
        unit_windows.values(),
        key=lambda rec: (rec["evt_num_start"], rec["container_id"], rec["thread_vtid"], rec["unit_id"]),
    )
    return unit_index


def build_unit_event_index(graph: ProvGraph) -> List[Dict[str, Any]]:
    """Associate raw sysdig events with execution units for unit_event_index.jsonl."""
    records: List[Dict[str, Any]] = []

    for node in graph.nodes:
        if not isinstance(node, UnitNode):
            continue

        for log in node.logs:
            evt_num = log.get("evt.num")
            if evt_num is None:
                continue

            container_id = log.get("container.id") or node.container_id
            unit_id = _lookup_unit_id(graph, container_id, evt_num)
            thread_vtid = log.get("thread.vtid") or node.tid
            container_id_norm = str(container_id)
            thread_vtid_norm = str(thread_vtid)
            unit_key = _build_unit_key(container_id_norm, thread_vtid_norm, unit_id)
            try:
                evt_num_int = int(evt_num)
            except (TypeError, ValueError):
                continue

            records.append(
                {
                    "evt_num": evt_num_int,
                    "unit_id": unit_id,
                    "unit_key": unit_key,
                    "container_id": container_id_norm,
                    "thread_vtid": thread_vtid_norm,
                }
            )

    records.sort(key=lambda rec: rec["evt_num"])
    return records


def export_unit_index(unit_index: List[Dict[str, Any]], output_dir: str):
    """Write execution-unit event windows to unit_index.jsonl."""
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, "unit_index.jsonl")
    with open(output_path, "w") as f:
        for rec in unit_index:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    return output_path


def export_unit_event_index(records: List[Dict[str, Any]], output_dir: str):
    """Write event-to-unit associations to unit_event_index.jsonl."""
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, "unit_event_index.jsonl")
    with open(output_path, "w") as f:
        for rec in records:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    return output_path


def build_manifests(raw_dir: str, config: Dict[str, Any]) -> Dict[str, Any]:
    """Build manifests.json metadata with raw-file paths, sizes, and SHA-256 hashes."""
    import hashlib
    from datetime import datetime
    
    manifests = {
        "version": "1.0",
        "generated_at": datetime.now().isoformat(),
        "config": config,
        "files": [],
    }
    
    # Hash files in larger chunks to reduce read-system-call overhead.
    chunk_size = 64 * 1024  # 64 KiB per read instead of small 4 KiB reads.
    file_count = 0
    for root, dirs, files in os.walk(raw_dir):
        for file in files:
            file_path = os.path.join(root, file)
            rel_path = os.path.relpath(file_path, raw_dir)
            file_size = os.path.getsize(file_path)
            sha256_hash = hashlib.sha256()
            with open(file_path, "rb") as f:
                # Stream each file into the digest without loading it in full.
                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    sha256_hash.update(chunk)
            manifests["files"].append({
                "relative_path": rel_path,
                "size_bytes": file_size,
                "sha256": sha256_hash.hexdigest(),
            })
            file_count += 1
            if file_count % 10 == 0:
                logger.info(f"Processed {file_count} files for manifests...")
    
    return manifests


def export_manifests(manifests: Dict[str, Any], output_dir: str):
    """Write raw-file provenance and checksums to manifests.json."""
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, "manifests.json")
    with open(output_path, "w") as f:
        json.dump(manifests, f, ensure_ascii=False, indent=2)
    return output_path


def export_applog_sidecar_from_event_index(
    event_index: Sequence[Dict[str, Any]],
    output_dir: str,
    scene_name: str,
) -> Tuple[str, str]:
    """Export application-log records with timestamps and container identities.

    Extract records from build_event_index(), parse timestamps from the
    [SecLog {datetime} {tid}] prefix, and resolve container.id through the
    sysdig event identified by related_evt_num.

    Write applog_event_index.v0.jsonl and applog_event_index_summary.v0.json
    in the supplied index directory.
    """
    import datetime as dt_module

    os.makedirs(output_dir, exist_ok=True)
    records = _build_applog_source_rows(event_index, scene_name)

    source_file_dist: Dict[str, int] = {}
    service_dist: Dict[str, int] = {}
    matched_count = 0
    unmatched_count = 0
    ts_values: List[float] = []
    evt_num_values: List[int] = []
    for rec in records:
        related_evt = rec.get("matched_evt_num")
        if related_evt is not None:
            matched_count += 1
            try:
                evt_num_values.append(int(related_evt))
            except (TypeError, ValueError):
                unmatched_count += 1
        else:
            unmatched_count += 1

        ts = rec.get("timestamp")
        if ts is not None:
            try:
                ts_values.append(float(ts))
            except (TypeError, ValueError):
                pass

        source_file = rec.get("source_file", "")
        if source_file:
            source_file_dist[source_file] = source_file_dist.get(source_file, 0) + 1
        svc = rec.get("service_name")
        if svc:
            service_dist[svc] = service_dist.get(svc, 0) + 1

    # Write the application-log sidecar records.
    jsonl_path = os.path.join(output_dir, "applog_event_index.v0.jsonl")
    with open(jsonl_path, "w") as f:
        for rec in records:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")

    # Summarize matched events, timestamps, source files, and services.
    evt_range = {
        "min": min(evt_num_values) if evt_num_values else None,
        "max": max(evt_num_values) if evt_num_values else None,
    }
    ts_range = {
        "min": min(ts_values) if ts_values else None,
        "max": max(ts_values) if ts_values else None,
    }

    summary = {
        "schema_version": "applog_event_index_summary.v0",
        "scenario": scene_name,
        "generated_at": dt_module.datetime.now().isoformat(),
        "total_applog_entries": len(records),
        "matched_evt_num_count": matched_count,
        "unmatched_count": unmatched_count,
        "matched_evt_num_range": evt_range,
        "timestamp_range": ts_range,
        "source_file_distribution": source_file_dist,
        "service_name_distribution": service_dist,
    }
    summary_path = os.path.join(output_dir, "applog_event_index_summary.v0.json")
    with open(summary_path, "w") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)

    return jsonl_path, summary_path


def _build_applog_source_rows(
    event_index: Sequence[Dict[str, Any]],
    scene_name: str,
) -> List[Dict[str, Any]]:
    import datetime as dt_module
    # Build the sysdig evt_num-to-container map once for all application logs.
    cid_by_evt: Dict[int, str] = {}
    for rec in event_index:
        if rec.get("source_type") != "sysdig":
            continue
        ev = rec.get("parsed", {})
        en = ev.get("evt.num")
        cid = ev.get("container.id")
        if en is not None and cid is not None:
            try:
                cid_by_evt[int(en)] = str(cid)
            except (TypeError, ValueError):
                pass

    # Parse the same supported log prefixes as analyze.parse_app_log_line.

    records: List[Dict[str, Any]] = []

    for rec in event_index:
        if rec.get("source_type") != "applog":
            continue

        raw = rec.get("raw", "")
        ts: float | None = None
        m = APPLOG_PREFIX_PATTERN.match(raw)
        if m:
            date_str, time_str, nsecs, _, _ = m.groups()
            dt_str = f"{date_str} {time_str}"
            try:
                dt_obj = dt_module.datetime.strptime(dt_str, "%Y-%m-%d %H:%M:%S")
                ts = dt_obj.timestamp() + int(nsecs) / 1e9
            except (ValueError, OSError):
                pass

        related_evt = rec.get("related_evt_num")
        container_id: str | None = None
        if related_evt is not None:
            try:
                container_id = cid_by_evt.get(int(related_evt))
            except (TypeError, ValueError):
                pass

        source_file = rec.get("source_file", "")
        line_no = rec.get("line_no")
        svc = rec.get("service") or rec.get("service_name")
        applog_key = f"{source_file}:{line_no}"
        event_key = f"applog:{applog_key}"

        records.append({
            "event_key": event_key,
            "source_type": "applog",
            "source_file": source_file,
            "line_no": line_no,
            "matched_evt_num": related_evt,
            "applog_key": applog_key,
            "timestamp": ts,
            "container_id": container_id,
            "service_name": svc,
            "raw_ref": {
                "scenario": scene_name,
                "source_file": source_file,
                "line_no": line_no,
            },
        })

    return records


def export_edge_applog_context_view(
    event_index: Sequence[Dict[str, Any]],
    output_dir: str,
    scene_name: str,
) -> Tuple[str, str]:
    """Attach application logs to an edge-level view of the audit backbone.

    Resolve matched_evt_num through event_to_backbone_anchor_index.v0.jsonl
    first, then a backbone FILE_WRITE edge, then a sysdig event-index entry
    used as a provenance write proxy. Attachments retain strong strength;
    target_kind and attach_reason identify the type of association.

    Write edge_applog_context_view.v0.jsonl and
    edge_applog_context_summary.v0.json in the supplied index directory.
    """
    import datetime as dt_module

    os.makedirs(output_dir, exist_ok=True)

    # Index final backbone anchors by their source_event_key.
    anchor_by_source_event_key: Dict[str, Dict[str, Any]] = {}
    anchor_index_path = os.path.join(output_dir, "event_to_backbone_anchor_index.v0.jsonl")
    if os.path.exists(anchor_index_path):
        try:
            with open(anchor_index_path, "r", encoding="utf-8", errors="replace") as f:
                for line_no, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                    except Exception as exc:
                        logger.warning(
                            f"Skipping invalid anchor row from {anchor_index_path}:{line_no}: {exc}"
                        )
                        continue
                    source_event_key = rec.get("source_event_key")
                    anchor_edge_id = rec.get("anchor_backbone_edge_id")
                    if not source_event_key or not anchor_edge_id:
                        continue
                    anchor_by_source_event_key[str(source_event_key)] = rec
        except Exception as exc:
            logger.warning(f"Failed to load event_to_backbone_anchor_index from {anchor_index_path}: {exc}")

    # Index backbone FILE_WRITE edges by their sysdig event numbers.
    backbone_by_evtnum: Dict[int, Dict[str, Any]] = {}
    backbone_path = os.path.join(os.path.dirname(output_dir), "chain", "backbone_chain.v1.json")
    if os.path.exists(backbone_path):
        try:
            with open(backbone_path, "r") as f:
                backbone_data = json.load(f)
            for edge in backbone_data.get("edge_sequence", []):
                if edge.get("relation") != "FILE_WRITE":
                    continue
                evt_num = edge.get("attrs", {}).get("evt_num")
                if evt_num is None:
                    continue
                try:
                    backbone_by_evtnum[int(evt_num)] = edge
                except (TypeError, ValueError):
                    pass
        except Exception as exc:
            logger.warning(f"Failed to load backbone FILE_WRITE lookup from {backbone_path}: {exc}")

    # Index sysdig records by evt_num.
    # event_index retains the source event number within each source type;
    # a sysdig record's event_id therefore equals its evt_num.
    evti_by_evtnum: Dict[int, Dict[str, Any]] = {}
    for rec in event_index:
        if rec.get("source_type") == "sysdig":
            ev = rec.get("parsed", {})
            en = ev.get("evt.num")
            if en is not None:
                try:
                    evti_by_evtnum[int(en)] = rec
                except (TypeError, ValueError):
                    pass

    records: List[Dict[str, Any]] = []
    source_file_dist: Dict[str, int] = {}
    service_dist: Dict[str, int] = {}
    container_dist: Dict[str, int] = {}
    reason_dist: Dict[str, int] = {}
    strength_dist: Dict[str, int] = {}
    target_kind_dist: Dict[str, int] = {}
    ts_values: List[float] = []
    anchor_index_attach_count = 0
    direct_backbone_attach_count = 0
    sysdig_proxy_attach_count = 0
    unmapped_count = 0

    for rec in event_index:
        if rec.get("source_type") != "applog":
            continue

        raw_ref_sf = rec.get("source_file", "")
        line_no = rec.get("line_no")
        applog_key = f"{raw_ref_sf}:{line_no}"
        context_id = f"applogctx:{scene_name}:{applog_key}"
        event_key = f"applog:{applog_key}"

        # Resolve the associated sysdig event.
        # event_index uses related_evt_num for this association;
        # applog_event_index.v0.jsonl names the same field matched_evt_num.
        related_evt = rec.get("related_evt_num")
        sysdig_target: Dict[str, Any] | None = None
        backbone_target: Dict[str, Any] | None = None
        anchor_target: Dict[str, Any] | None = None
        attach_reason = "matched_evt_num_to_sysdig_event_index_entry"
        attach_strength = "strong"

        if related_evt is not None:
            try:
                related_evt_int = int(related_evt)
                anchor_target = anchor_by_source_event_key.get(f"sysdig:{related_evt_int}")
                backbone_target = backbone_by_evtnum.get(related_evt_int)
                sysdig_target = evti_by_evtnum.get(related_evt_int)
            except (TypeError, ValueError):
                pass

        if anchor_target is not None:
            target_id = anchor_target.get("anchor_backbone_edge_id")
            target_kind = "backbone_edge"
            target_id_note = "resolved by event_to_backbone_anchor_index final anchor lookup"
            attach_reason = "matched_evt_num_to_backbone_anchor_index"
            anchor_index_attach_count += 1
        elif backbone_target is not None:
            target_id = backbone_target.get("edge_id")
            target_kind = "backbone_edge"
            target_id_note = "direct backbone FILE_WRITE attach resolved by matched_evt_num"
            attach_reason = "matched_evt_num_to_backbone_file_write_edge"
            direct_backbone_attach_count += 1
        elif related_evt is not None:
            target_id = f"sysdig:{related_evt}"
            target_kind = "sysdig_event_index_entry"
            target_id_note = "fallback to sysdig event_index entry as provenance write proxy target"
            sysdig_proxy_attach_count += 1
        else:
            target_id = None
            target_kind = "unmapped"
            target_id_note = "matched_evt_num missing; no stable backbone/sysdig target resolved"
            attach_reason = "unmapped"
            unmapped_count += 1

        # Include the matched sysdig record's metadata in attach_basis.
        target_evt_type: str | None = None
        target_source_file: str | None = None
        target_line_no: int | None = None
        # Preserve application-log values; fill absent values from sysdig.
        ts_val = rec.get("timestamp")
        cid_val = rec.get("container_id")
        if sysdig_target is not None:
            target_evt_type = sysdig_target.get("parsed", {}).get("evt.type")
            target_source_file = sysdig_target.get("source_file")
            target_line_no = sysdig_target.get("line_no")
            # Fill an absent application-log timestamp from the sysdig event.
            ei_ts = sysdig_target.get("timestamp")
            if ts_val is None and ei_ts is not None:
                try:
                    ts_val = float(ei_ts)
                except (TypeError, ValueError):
                    pass
            # Fill an absent container identity from the sysdig event.
            if cid_val is None:
                ei_cid = sysdig_target.get("container_id")
                if ei_cid:
                    cid_val = str(ei_cid)
            ei_ts_val = sysdig_target.get("timestamp")
            if ei_ts_val is not None:
                try:
                    ts_values.append(float(ei_ts_val))
                except (TypeError, ValueError):
                    pass

        # Count source and attachment categories for the sidecar summary.
        if raw_ref_sf:
            source_file_dist[raw_ref_sf] = source_file_dist.get(raw_ref_sf, 0) + 1
        svc = rec.get("service") or rec.get("service_name")  # Index and sidecar names.
        if svc:
            service_dist[svc] = service_dist.get(svc, 0) + 1
        if cid_val:
            container_dist[cid_val] = container_dist.get(cid_val, 0) + 1
        reason_dist[attach_reason] = reason_dist.get(attach_reason, 0) + 1
        strength_dist[attach_strength] = strength_dist.get(attach_strength, 0) + 1
        target_kind_dist[target_kind] = target_kind_dist.get(target_kind, 0) + 1

        records.append({
            "context_id": context_id,
            "context_type": "applog_edge_context",
            "target_level": "edge",
            "target_id": target_id,
            "target_kind": target_kind,
            "target_id_note": target_id_note,

            # Carry the application log's identity and source metadata.
            "event_key": event_key,
            "source_file": raw_ref_sf,
            "line_no": line_no,
            "matched_evt_num": related_evt,
            "timestamp": ts_val,
            "container_id": cid_val,
            "service_name": svc,

            # Record how the application log was associated with its target.
            "attach_reason": attach_reason,
            "attach_strength": attach_strength,
            "attach_basis": (
                {
                    "matched_evt_num": related_evt,
                    "anchor_index_source_event_key": anchor_target.get("source_event_key"),
                    "backbone_edge_id": anchor_target.get("anchor_backbone_edge_id"),
                    "backbone_relation": anchor_target.get("anchor_backbone_relation"),
                    "backbone_seq_or_index": anchor_target.get("anchor_backbone_seq"),
                    "anchor_rule": anchor_target.get("anchor_rule"),
                    "anchor_confidence": anchor_target.get("confidence"),
                } if anchor_target is not None else
                {
                    "matched_evt_num": related_evt,
                    "backbone_edge_id": backbone_target.get("edge_id"),
                    "backbone_relation": backbone_target.get("relation"),
                    "backbone_seq_or_index": backbone_target.get("seq"),
                } if backbone_target is not None else
                {
                    "matched_evt_num": related_evt,
                    "event_index_source_file": target_source_file,
                    "event_index_line_no": target_line_no,
                    "sysdig_evt_type": target_evt_type,
                } if sysdig_target is not None else
                {
                    "matched_evt_num": related_evt,
                    "note": "no stable backbone/sysdig target found",
                }
            ),

            # Preserve the raw-log location for replay.
            "raw_ref": {
                "scenario": scene_name,
                "source_file": raw_ref_sf,
                "line_no": line_no,
            },
        })

    # Write the edge-level application-log context records.
    jsonl_path = os.path.join(output_dir, "edge_applog_context_view.v0.jsonl")
    with open(jsonl_path, "w") as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    # Summarize attachment coverage and source distributions.
    ts_range = {
        "min": min(ts_values) if ts_values else None,
        "max": max(ts_values) if ts_values else None,
    }

    summary = {
        "schema_version": "edge_applog_context_summary.v0",
        "scenario": scene_name,
        "generated_at": dt_module.datetime.now().isoformat(),
        "total_applog_entries": len(records),
        "attach_reason_distribution": reason_dist,
        "attach_strength_distribution": strength_dist,
        "target_kind_distribution": target_kind_dist,
        "target_kind_counts": target_kind_dist,
        "anchor_index_attach_count": anchor_index_attach_count,
        "direct_backbone_attach_count": direct_backbone_attach_count,
        "sysdig_proxy_attach_count": sysdig_proxy_attach_count,
        "unmapped_count": unmapped_count,
        "attach_reason_counts": reason_dist,
        "source_file_distribution": source_file_dist,
        "service_name_distribution": service_dist,
        "container_id_distribution": container_dist,
        "timestamp_range": ts_range,
    }
    summary_path = os.path.join(output_dir, "edge_applog_context_summary.v0.json")
    with open(summary_path, "w") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)

    return jsonl_path, summary_path


def export_write_event_context_index(
    event_index: Sequence[Dict[str, Any]],
    output_dir: str,
    scene_name: str,
) -> str:
    """Export one-hop links from applogs to matched writes and optional backbone anchors."""
    os.makedirs(output_dir, exist_ok=True)
    jsonl_path = os.path.join(output_dir, "write_event_context_index.v0.jsonl")

    applog_records = _build_applog_source_rows(event_index, scene_name)
    if not applog_records:
        if os.path.exists(jsonl_path):
            os.remove(jsonl_path)
            logger.info(
                f"Skipping write_event_context_index export for {scene_name}: no applog records; removed stale file {jsonl_path}"
            )
        else:
            logger.info(f"Skipping write_event_context_index export for {scene_name}: no applog records")
        return jsonl_path

    sysdig_by_evtnum: Dict[int, Dict[str, Any]] = {}
    for rec in event_index:
        if rec.get("source_type") != "sysdig":
            continue
        parsed = rec.get("parsed", {}) if isinstance(rec.get("parsed"), dict) else {}
        evt_num = parsed.get("evt.num")
        try:
            evt_num_i = int(evt_num)
        except (TypeError, ValueError):
            continue
        sysdig_by_evtnum[evt_num_i] = rec

    unit_event_by_evt: Dict[int, Dict[str, Any]] = {}
    unit_event_index_path = os.path.join(output_dir, "unit_event_index.jsonl")
    if os.path.exists(unit_event_index_path):
        with open(unit_event_index_path, "r", encoding="utf-8", errors="replace") as f:
            for line_no, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                except Exception as exc:
                    logger.warning(
                        f"Skipping invalid unit_event_index row from {unit_event_index_path}:{line_no}: {exc}"
                    )
                    continue
                evt_num = row.get("evt_num")
                try:
                    unit_event_by_evt[int(evt_num)] = row
                except (TypeError, ValueError):
                    continue

    anchor_by_source_event_key: Dict[str, Dict[str, Any]] = {}
    anchor_index_path = os.path.join(output_dir, "event_to_backbone_anchor_index.v0.jsonl")
    scenario_id: Optional[str] = None
    if os.path.exists(anchor_index_path):
        with open(anchor_index_path, "r", encoding="utf-8", errors="replace") as f:
            for line_no, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                except Exception as exc:
                    logger.warning(
                        f"Skipping invalid anchor row from {anchor_index_path}:{line_no}: {exc}"
                    )
                    continue
                source_event_key = row.get("source_event_key")
                if not source_event_key:
                    continue
                anchor_by_source_event_key[str(source_event_key)] = row
                if scenario_id is None and row.get("scenario_id"):
                    scenario_id = str(row.get("scenario_id"))

    rows: List[Dict[str, Any]] = []
    for rec in applog_records:
        applog_event_key = rec.get("event_key")
        source_file = rec.get("source_file")
        line_no = rec.get("line_no")
        matched_evt_num = rec.get("matched_evt_num")
        row: Dict[str, Any] = {
            "schema_version": WRITE_EVENT_CONTEXT_INDEX_SCHEMA_VERSION,
            "applog_event_key": applog_event_key,
            "source_file": source_file,
            "line_no": line_no,
            "matched_evt_num": matched_evt_num,
            "context_status": "matched_evt_num_missing",
            "context_source": "applog_event_index",
            "has_backbone_anchor": False,
        }
        if scenario_id is not None:
            row["scenario_id"] = scenario_id
        elif scene_name:
            row["scenario_id"] = scene_name
        if rec.get("service_name") is not None:
            row["service_name"] = rec.get("service_name")

        try:
            matched_evt_int = int(matched_evt_num)
        except (TypeError, ValueError):
            rows.append(row)
            continue

        row["write_event_key"] = f"sysdig:{matched_evt_int}"
        sysdig_rec = sysdig_by_evtnum.get(matched_evt_int)
        if sysdig_rec is None:
            row["context_status"] = "write_event_missing"
            row["context_source"] = "applog_event_index"
            rows.append(row)
            continue

        parsed = sysdig_rec.get("parsed", {}) if isinstance(sysdig_rec.get("parsed"), dict) else {}
        row["write_source_file"] = sysdig_rec.get("source_file")
        row["write_line_no"] = sysdig_rec.get("line_no")
        row["write_container_id"] = sysdig_rec.get("container_id")
        row["write_proc_pid"] = (
            parsed.get("proc.pid")
            if parsed.get("proc.pid") is not None
            else None
        )
        row["write_fd_name"] = parsed.get("fd.name")
        row["write_timestamp"] = sysdig_rec.get("timestamp")

        unit_event = unit_event_by_evt.get(matched_evt_int)
        if unit_event is not None:
            if unit_event.get("thread_vtid") is not None:
                row["write_thread_vtid"] = str(unit_event.get("thread_vtid"))
            if unit_event.get("unit_id") is not None:
                row["write_unit_id"] = str(unit_event.get("unit_id"))

        anchor = anchor_by_source_event_key.get(f"sysdig:{matched_evt_int}")
        if anchor is not None:
            row["anchor_backbone_edge_id"] = anchor.get("anchor_backbone_edge_id")
            row["anchor_backbone_seq"] = anchor.get("anchor_backbone_seq")
            row["anchor_backbone_relation"] = anchor.get("anchor_backbone_relation")
            row["anchor_backbone_evt_num"] = anchor.get("anchor_backbone_evt_num")
            row["has_backbone_anchor"] = True
            row["context_status"] = "write_event_and_anchor_resolved"
            row["context_source"] = "applog_event_index+event_index+event_to_backbone_anchor_index"
        else:
            row["context_status"] = "write_event_resolved_no_backbone_anchor"
            row["context_source"] = "applog_event_index+event_index"

        rows.append(row)

    if not rows:
        if os.path.exists(jsonl_path):
            os.remove(jsonl_path)
            logger.info(
                f"Skipping write_event_context_index export for {scene_name}: no rows; removed stale file {jsonl_path}"
            )
        else:
            logger.info(f"Skipping write_event_context_index export for {scene_name}: no rows")
        return jsonl_path

    with open(jsonl_path, "w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
    return jsonl_path


def export_applog_backbone_candidate_index(
    event_index: Sequence[Dict[str, Any]],
    write_event_context_index_path: str,
    output_dir: str,
    scene_name: str,
) -> str:
    """Export the bounded candidate paths explaining application-log attachments.

    Candidate kinds are anchor_index, legacy_file_write, sysdig_proxy, and
    unmapped, describing the available routes to a backbone target.
    """
    chain_dir = os.path.join(os.path.dirname(output_dir), "chain")
    os.makedirs(chain_dir, exist_ok=True)
    jsonl_path = os.path.join(chain_dir, "applog_backbone_candidate_index.v0.jsonl")

    applog_records = _build_applog_source_rows(event_index, scene_name)
    if not applog_records:
        if os.path.exists(jsonl_path):
            os.remove(jsonl_path)
            logger.info(
                f"Skipping applog_backbone_candidate_index export for {scene_name}: no applog records; removed stale file {jsonl_path}"
            )
        else:
            logger.info(f"Skipping applog_backbone_candidate_index export for {scene_name}: no applog records")
        return jsonl_path

    write_context_by_applog_key: Dict[str, Dict[str, Any]] = {}
    if os.path.exists(write_event_context_index_path):
        with open(write_event_context_index_path, "r", encoding="utf-8", errors="replace") as f:
            for line_no, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                except Exception as exc:
                    logger.warning(
                        f"Skipping invalid write_event_context row from {write_event_context_index_path}:{line_no}: {exc}"
                    )
                    continue
                applog_event_key = row.get("applog_event_key")
                if applog_event_key:
                    write_context_by_applog_key[str(applog_event_key)] = row

    anchor_by_source_event_key: Dict[str, Dict[str, Any]] = {}
    anchor_index_path = os.path.join(output_dir, "event_to_backbone_anchor_index.v0.jsonl")
    scenario_id: Optional[str] = None
    if os.path.exists(anchor_index_path):
        with open(anchor_index_path, "r", encoding="utf-8", errors="replace") as f:
            for line_no, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                except Exception as exc:
                    logger.warning(
                        f"Skipping invalid anchor row from {anchor_index_path}:{line_no}: {exc}"
                    )
                    continue
                source_event_key = row.get("source_event_key")
                if not source_event_key:
                    continue
                anchor_by_source_event_key[str(source_event_key)] = row
                if scenario_id is None and row.get("scenario_id"):
                    scenario_id = str(row.get("scenario_id"))

    backbone_by_evtnum: Dict[int, Dict[str, Any]] = {}
    backbone_path = os.path.join(os.path.dirname(output_dir), "chain", "backbone_chain.v1.json")
    if os.path.exists(backbone_path):
        try:
            with open(backbone_path, "r", encoding="utf-8", errors="replace") as f:
                backbone_data = json.load(f)
            for edge in backbone_data.get("edge_sequence", []):
                if edge.get("relation") != "FILE_WRITE":
                    continue
                evt_num = edge.get("attrs", {}).get("evt_num")
                try:
                    backbone_by_evtnum[int(evt_num)] = edge
                except (TypeError, ValueError):
                    continue
        except Exception as exc:
            logger.warning(f"Failed to load backbone FILE_WRITE lookup from {backbone_path}: {exc}")

    sysdig_by_evtnum: Dict[int, Dict[str, Any]] = {}
    for rec in event_index:
        if rec.get("source_type") != "sysdig":
            continue
        parsed = rec.get("parsed", {}) if isinstance(rec.get("parsed"), dict) else {}
        evt_num = parsed.get("evt.num")
        try:
            sysdig_by_evtnum[int(evt_num)] = rec
        except (TypeError, ValueError):
            continue

    rows: List[Dict[str, Any]] = []
    for rec in applog_records:
        applog_event_key = rec.get("event_key")
        matched_evt_num = rec.get("matched_evt_num")
        write_ctx = write_context_by_applog_key.get(str(applog_event_key)) if applog_event_key is not None else None

        base_row: Dict[str, Any] = {
            "schema_version": APPLOG_BACKBONE_CANDIDATE_INDEX_SCHEMA_VERSION,
            "applog_event_key": applog_event_key,
            "source_file": rec.get("source_file"),
            "line_no": rec.get("line_no"),
            "matched_evt_num": matched_evt_num,
            "has_final_anchor": False,
            "scenario_id": scenario_id or scene_name,
        }
        if rec.get("service_name") is not None:
            base_row["service_name"] = rec.get("service_name")
        if isinstance(write_ctx, dict):
            for key in (
                "write_event_key",
                "write_source_file",
                "write_line_no",
                "write_thread_vtid",
                "write_unit_id",
                "write_fd_name",
            ):
                if write_ctx.get(key) is not None:
                    base_row[key] = write_ctx.get(key)

        visible_candidates: List[Dict[str, Any]] = []
        anchor_target = None
        backbone_target = None
        sysdig_target = None
        related_evt_int = None
        try:
            related_evt_int = int(matched_evt_num)
            anchor_target = anchor_by_source_event_key.get(f"sysdig:{related_evt_int}")
            backbone_target = backbone_by_evtnum.get(related_evt_int)
            sysdig_target = sysdig_by_evtnum.get(related_evt_int)
        except (TypeError, ValueError):
            pass

        if anchor_target is not None:
            visible_candidates.append({
                "candidate_backbone_edge_id": anchor_target.get("anchor_backbone_edge_id"),
                "candidate_backbone_seq": anchor_target.get("anchor_backbone_seq"),
                "candidate_backbone_relation": anchor_target.get("anchor_backbone_relation"),
                "candidate_backbone_evt_num": anchor_target.get("anchor_backbone_evt_num"),
                "candidate_rule": "final_anchor_lookup",
                "candidate_score": None,
                "candidate_source": "event_to_backbone_anchor_index",
                "fallback_class": "anchor_index",
                "has_final_anchor": True,
            })
        if backbone_target is not None:
            visible_candidates.append({
                "candidate_backbone_edge_id": backbone_target.get("edge_id"),
                "candidate_backbone_seq": backbone_target.get("seq"),
                "candidate_backbone_relation": backbone_target.get("relation"),
                "candidate_backbone_evt_num": backbone_target.get("attrs", {}).get("evt_num"),
                "candidate_rule": "legacy_file_write_evt_match",
                "candidate_score": None,
                "candidate_source": "backbone_chain_file_write_lookup",
                "fallback_class": "legacy_file_write",
                "has_final_anchor": False,
            })
        if related_evt_int is not None and sysdig_target is not None:
            visible_candidates.append({
                "candidate_rule": "sysdig_proxy_fallback",
                "candidate_score": None,
                "candidate_source": "event_index",
                "fallback_class": "sysdig_proxy",
                "has_final_anchor": False,
            })

        if not visible_candidates:
            row = dict(base_row)
            row.update({
                "candidate_rule": "unmapped",
                "candidate_score": None,
                "candidate_source": "none",
                "fallback_class": "unmapped",
                "has_final_anchor": False,
                "is_selected": True,
                "selection_rank": 1,
            })
            rows.append(row)
            continue

        priority = {
            "anchor_index": 0,
            "legacy_file_write": 1,
            "sysdig_proxy": 2,
            "unmapped": 3,
        }
        visible_candidates.sort(key=lambda item: priority.get(str(item.get("fallback_class")), 99))
        selected_fallback = str(visible_candidates[0].get("fallback_class"))
        for rank, candidate in enumerate(visible_candidates, 1):
            row = dict(base_row)
            row.update(candidate)
            row["is_selected"] = (rank == 1)
            row["selection_rank"] = rank
            row["has_final_anchor"] = bool(candidate.get("has_final_anchor"))
            if selected_fallback == "anchor_index" and row.get("fallback_class") == "legacy_file_write":
                row["is_selected"] = False
            rows.append(row)

    if not rows:
        if os.path.exists(jsonl_path):
            os.remove(jsonl_path)
            logger.info(
                f"Skipping applog_backbone_candidate_index export for {scene_name}: no rows; removed stale file {jsonl_path}"
            )
        else:
            logger.info(f"Skipping applog_backbone_candidate_index export for {scene_name}: no rows")
        return jsonl_path

    with open(jsonl_path, "w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
    return jsonl_path


def _classify_applog_style(source_file: str, raw_line: str) -> str:
    import re

    lower_source = (source_file or "").lower()
    stripped = (raw_line or "").strip()
    if lower_source.endswith(".xml") or lower_source.endswith(".lck"):
        return "config_or_non_event"

    if stripped.startswith("{") and stripped.endswith("}"):
        try:
            obj = json.loads(stripped)
            if isinstance(obj, dict):
                return "json_line"
        except Exception:
            pass

    access_pat = re.compile(
        r'^\S+ \S+ \S+ \[[^\]]+\] "[A-Z]+ [^"]+ HTTP/[0-9.]+" \d{3}(?: \d+|-)?(?: ".*")?(?: ".*")?$'
    )
    if access_pat.match(stripped):
        return "access_text"

    python_pat = re.compile(
        r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3} - .+ - [A-Z]+:"
    )
    if python_pat.match(stripped):
        return "python_log"

    java_pipe_pat = re.compile(
        r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3} \|.+\|[A-Z]\|"
    )
    java_text_pat = re.compile(
        r"^\d{1,2} [A-Z][a-z]{2} \d{2}:\d{2}:\d{2} (?:TRACE|DEBUG|INFO|WARN|ERROR|CONFIG)\s+"
    )
    if java_pipe_pat.match(stripped) or java_text_pat.match(stripped):
        return "java_log"

    return "plain_text"


def _strip_ansi(text: str) -> str:
    import re

    return re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", text or "")


def _collapse_ws(text: str) -> str:
    import re

    return re.sub(r"\s+", " ", (text or "")).strip()


def _read_applog_message_block(raw_path: str, line_no: int, max_lines: int = 12) -> List[str]:
    import linecache

    first_line = linecache.getline(raw_path, int(line_no)).rstrip("\n\r")
    if not first_line:
        return []

    lines = [first_line]
    probe = first_line
    if probe.startswith("[*MALICIOUS*] "):
        probe = probe[len("[*MALICIOUS*] ") :]
    probe_stripped = probe.strip()
    if probe_stripped != "{":
        return lines

    brace_balance = probe.count("{") - probe.count("}")
    next_line_no = int(line_no) + 1
    while len(lines) < max_lines:
        next_line = linecache.getline(raw_path, next_line_no)
        if not next_line:
            break
        next_line = next_line.rstrip("\n\r")
        if not next_line:
            break
        lines.append(next_line)
        brace_balance += next_line.count("{") - next_line.count("}")
        if brace_balance <= 0:
            break
        next_line_no += 1

    return lines


def _extract_model_messages(source_file: str, raw_lines: Sequence[str], log_style: str) -> Tuple[str, str]:
    import re

    raw_message = "\n".join(raw_lines).strip()
    raw_message = _strip_ansi(raw_message)
    raw_message = raw_message.strip()

    normalized_source = raw_message
    if normalized_source.startswith("[*MALICIOUS*] "):
        normalized_source = normalized_source[len("[*MALICIOUS*] ") :]
    line = normalized_source.strip()

    if log_style == "json_line":
        try:
            obj = json.loads(line)
            if isinstance(obj, dict):
                msg = obj.get("message")
                if isinstance(msg, str) and msg.strip():
                    return raw_message, _collapse_ws(_strip_ansi(msg))
        except Exception:
            pass
        return raw_message, _collapse_ws(line)

    if log_style == "python_log":
        normalized = re.sub(
            r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3} - .+? - [A-Z]+:\s*",
            "",
            line,
        )
        return raw_message, _collapse_ws(normalized or line)

    if log_style == "java_log":
        pipe_normalized = re.sub(
            r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3} \|[^|]*\s*\|[^|]*\s*\|[A-Z]\|\s*",
            "",
            line,
        )
        if pipe_normalized != line:
            return raw_message, _collapse_ws(pipe_normalized)
        text_normalized = re.sub(
            r"^\d{1,2} [A-Z][a-z]{2} \d{2}:\d{2}:\d{2} "
            r"(?:TRACE|DEBUG|INFO|WARN|ERROR|CONFIG)\s+[^\s]+\s+-\s+",
            "",
            line,
        )
        return raw_message, _collapse_ws(text_normalized or line)

    if log_style == "plain_text":
        normalized_lines = [ln.strip() for ln in normalized_source.splitlines() if ln.strip()]
        return raw_message, _collapse_ws(" ".join(normalized_lines))

    return raw_message, _collapse_ws(line)


def export_applog_model_context(
    event_index: Sequence[Dict[str, Any]],
    edge_context_view_path: str,
    output_dir: str,
    scene_name: str,
    write_level_by_rel_path: Optional[Dict[Tuple[str, int], Dict[str, Any]]] = None,
) -> Tuple[str, str]:
    """Build a lightweight application-log view from edge context and raw logs.

    Label semantics:
        malicious: True only for the [*MALICIOUS*] raw/applog prefix, reflecting
            strong write-level evidence such as write_self_malicious or
            containing_unit_malicious. Weak evidence never sets this flag.
        is_attack_related: Includes both strong and weak decisions from
            analyze.judge_applog_labels_at_write_level. When no nonempty
            write-level map is supplied, use the matched sysdig write's
            malicious field as a fallback. A weak-only match leaves malicious
            null while setting is_attack_related to True.
        attack_related_level / attack_related_reason: Explain the strength
            and source of the association. Levels are strong, weak, none, or
            null. Reasons include write_self_malicious,
            containing_unit_malicious, file_attack_provenance,
            nearby_malicious_unit_same_tid, sysdig_write_malicious_fallback,
            or null, according to the available evidence.

    Raw applog, sysdig, and tshark files are read without modification.
    Write only applog_model_context.v0.jsonl and
    applog_model_context_summary.v0.json in the supplied index directory.
    """
    import datetime as dt_module
    import linecache

    os.makedirs(output_dir, exist_ok=True)
    scenario_dir = os.path.dirname(output_dir)

    sysdig_by_evtnum: Dict[int, Dict[str, Any]] = {}
    for rec in event_index:
        if rec.get("source_type") != "sysdig":
            continue
        evt_num = rec.get("parsed", {}).get("evt.num")
        if evt_num is None:
            continue
        try:
            sysdig_by_evtnum[int(evt_num)] = {
                "source_file": rec.get("source_file"),
                "line_no": rec.get("line_no"),
            }
        except (TypeError, ValueError):
            pass

    edge_records: List[Dict[str, Any]] = []
    with open(edge_context_view_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            edge_records.append(json.loads(line))

    sysdig_needed: Dict[str, Set[int]] = {}
    for rec in edge_records:
        matched_evt = rec.get("matched_evt_num")
        if matched_evt is None:
            continue
        try:
            sysdig_meta = sysdig_by_evtnum.get(int(matched_evt))
        except (TypeError, ValueError):
            sysdig_meta = None
        if not sysdig_meta:
            continue
        source_file = sysdig_meta.get("source_file")
        line_no = sysdig_meta.get("line_no")
        if source_file and line_no is not None:
            sysdig_needed.setdefault(source_file, set()).add(int(line_no))

    sysdig_malicious_by_line: Dict[Tuple[str, int], Optional[bool]] = {}
    for rel_path, lines in sysdig_needed.items():
        abs_path = os.path.join(scenario_dir, rel_path)
        if not os.path.exists(abs_path):
            continue
        wanted = set(lines)
        with open(abs_path, "r", encoding="utf-8", errors="replace") as f:
            for line_idx, line in enumerate(f, start=1):
                if line_idx not in wanted:
                    continue
                try:
                    sysdig_malicious_by_line[(rel_path, line_idx)] = json.loads(line).get("malicious")
                except json.JSONDecodeError:
                    sysdig_malicious_by_line[(rel_path, line_idx)] = None
                if len([ln for ln in wanted if (rel_path, ln) in sysdig_malicious_by_line]) == len(wanted):
                    break

    records: List[Dict[str, Any]] = []
    log_style_dist: Dict[str, int] = {}
    target_kind_dist: Dict[str, int] = {}
    attach_strength_dist: Dict[str, int] = {}
    source_file_dist: Dict[str, int] = {}
    service_dist: Dict[str, int] = {}
    malicious_dist: Dict[str, int] = {"true": 0, "false": 0, "null": 0}
    attack_related_dist: Dict[str, int] = {"true": 0, "false": 0, "unknown": 0}
    attack_related_level_dist: Dict[str, int] = {"strong": 0, "weak": 0, "none": 0}
    attack_related_reason_dist: Dict[str, int] = {}
    # Separate graph-backed evidence from heuristic associations:
    # attack_related_source distinguishes anchor, file_provenance, data_flow,
    # proc_lineage, nearby_tid, sysdig_fallback, and null sources.
    # via_attack_subgraph counts direct attack-subgraph support;
    # via_tid_only_weak_count tracks weak associations without that support,
    # making reliance on thread-local fallback visible.
    attack_related_source_dist: Dict[str, int] = {}
    via_attack_subgraph_counts: Dict[str, int] = {"true": 0, "false": 0, "unknown": 0}
    via_tid_only_weak_count = 0
    skipped_reason_dist: Dict[str, int] = {}
    skipped_non_event_count = 0
    write_level_map = write_level_by_rel_path or {}
    write_level_available = bool(write_level_map)

    def _mark_skip(reason: str, source_file_value: str) -> None:
        nonlocal skipped_non_event_count
        skipped_non_event_count += 1
        skipped_reason_dist[reason] = skipped_reason_dist.get(reason, 0) + 1
        lower = (source_file_value or "").lower()
        ext = os.path.splitext(lower)[1] or lower.rsplit(".", 1)[-1] or "unknown"
        key = f"{reason}:{ext}"
        skipped_reason_dist[key] = skipped_reason_dist.get(key, 0) + 1

    for rec in edge_records:
        source_file = rec.get("source_file", "")
        line_no = rec.get("line_no")
        if not source_file or line_no is None:
            continue
        lower_source = source_file.lower()
        if lower_source.endswith(".xml") or lower_source.endswith(".lck"):
            _mark_skip("config_or_non_event", source_file)
            continue

        raw_path = os.path.join(scenario_dir, source_file)
        raw_lines = _read_applog_message_block(raw_path, int(line_no))
        if not raw_lines:
            _mark_skip("missing_raw_line", source_file)
            continue

        raw_line = raw_lines[0]
        raw_malicious = raw_line.startswith("[*MALICIOUS*] ")
        classify_line = raw_line[len("[*MALICIOUS*] ") :] if raw_malicious else raw_line

        log_style = _classify_applog_style(source_file, classify_line)
        if log_style == "config_or_non_event":
            _mark_skip("config_or_non_event", source_file)
            continue
        raw_message, normalized_message = _extract_model_messages(source_file, raw_lines, log_style)

        matched_evt = rec.get("matched_evt_num")
        is_attack_related: Optional[bool] = None
        attack_related_level: Optional[str] = None
        attack_related_reason: Optional[str] = None
        attack_related_source: Optional[str] = None
        via_attack_subgraph: Optional[bool] = None
        wl_matched_evt: Optional[int] = None
        wl_file_node_id: Optional[int] = None
        wl_file_node_first_mal_write_evt: Optional[int] = None
        wl_owning_unit_id: Optional[str] = None
        wl_thread_vtid: Optional[str] = None
        wl_fanout_hint: Optional[int] = None
        wl_read_from_tainted_file_id: Optional[int] = None
        wl_read_from_tainted_file_read_evt: Optional[int] = None
        wl_data_flow_unit_partition_match: Optional[bool] = None

        # Prefer write-gated decisions, tolerating invalid source/line metadata
        # as a lookup miss rather than failing the entire export.
        wl_entry: Optional[Dict[str, Any]] = None
        if write_level_available and source_file:
            try:
                _ln = int(line_no)
                wl_entry = write_level_map.get((source_file, _ln))
            except (TypeError, ValueError):
                wl_entry = None
        wl_recognized = False
        if isinstance(wl_entry, dict):
            _decision = wl_entry.get("decision")
            _reason = wl_entry.get("reason")
            _src = wl_entry.get("attack_related_source")
            _via = wl_entry.get("via_attack_subgraph")
            attack_related_source = _src if isinstance(_src, str) else None
            if isinstance(_via, bool):
                via_attack_subgraph = _via
            # Carry traceable write-level evidence for inspecting associations.
            wl_matched_evt = wl_entry.get("matched_evt_num")
            wl_file_node_id = wl_entry.get("file_node_id")
            wl_file_node_first_mal_write_evt = wl_entry.get("file_node_first_mal_write_evt")
            wl_owning_unit_id = wl_entry.get("owning_unit_id")
            wl_thread_vtid = wl_entry.get("thread_vtid")
            wl_fanout_hint = wl_entry.get("fanout_concentration_hint")
            wl_read_from_tainted_file_id = wl_entry.get("read_from_tainted_file_id")
            wl_read_from_tainted_file_read_evt = wl_entry.get("read_from_tainted_file_read_evt")
            wl_data_flow_unit_partition_match = wl_entry.get("data_flow_unit_partition_match")
            if _decision == "malicious_strong":
                is_attack_related = True
                attack_related_level = "strong"
                attack_related_reason = _reason if isinstance(_reason, str) else None
                wl_recognized = True
            elif _decision == "attack_related_weak":
                is_attack_related = True
                attack_related_level = "weak"
                attack_related_reason = _reason if isinstance(_reason, str) else None
                wl_recognized = True
            elif _decision == "none":
                # An explicit no-evidence decision remains negative.
                # A sysdig fallback must not override this write-gated result.
                is_attack_related = False
                attack_related_level = "none"
                attack_related_reason = _reason if isinstance(_reason, str) else None
                wl_recognized = True
            # Unrecognized decisions leave the association unresolved.

        # Fall back to the matched sysdig write's malicious flag only when
        # no nonempty write-level decision map is available. When the map is
        # available, preserve explicit negatives and unresolved lookups rather
        # than replacing them with sysdig-derived decisions.
        if (not write_level_available) and matched_evt is not None:
            try:
                sysdig_meta = sysdig_by_evtnum.get(int(matched_evt))
            except (TypeError, ValueError):
                sysdig_meta = None
            if sysdig_meta:
                key = (sysdig_meta.get("source_file"), int(sysdig_meta.get("line_no")))
                _fallback = sysdig_malicious_by_line.get(key)
                is_attack_related = _fallback
                if _fallback is True:
                    attack_related_level = "strong"
                    attack_related_reason = "sysdig_write_malicious_fallback"
                    attack_related_source = "sysdig_fallback"
                elif _fallback is False:
                    attack_related_level = "none"
                    attack_related_reason = "sysdig_write_malicious_fallback"
                    attack_related_source = "sysdig_fallback"

        records.append({
            "context_id": rec.get("context_id"),
            "event_key": rec.get("event_key"),
            "timestamp": rec.get("timestamp"),
            "service_name": rec.get("service_name"),
            "source_file": source_file,
            "log_style": log_style,
            "raw_message": raw_message,
            "normalized_message": normalized_message,
            "target_id": rec.get("target_id"),
            "target_kind": rec.get("target_kind"),
            "attach_strength": rec.get("attach_strength"),
            "malicious": True if raw_malicious else None,
            "is_attack_related": is_attack_related,
            "attack_related_level": attack_related_level,
            "attack_related_reason": attack_related_reason,
            # Nullable provenance identifies anchor, file_provenance, data_flow,
            # proc_lineage, nearby_tid, and sysdig_fallback sources and whether
            # the association is directly supported by the attack subgraph.
            "attack_related_source": attack_related_source,
            "via_attack_subgraph": via_attack_subgraph,
            "matched_evt_num": wl_matched_evt if wl_matched_evt is not None else matched_evt,
            "file_node_id": wl_file_node_id,
            "file_node_first_mal_write_evt": wl_file_node_first_mal_write_evt,
            "read_from_tainted_file_id": wl_read_from_tainted_file_id,
            "read_from_tainted_file_read_evt": wl_read_from_tainted_file_read_evt,
            # Execution-unit partition evidence for data-flow associations:
            # True: same execution unit, supporting a precise taint link.
            # False: possible dependency expansion across concurrent units.
            # None: no runtime unit ID is available for the owning unit.
            "data_flow_unit_partition_match": wl_data_flow_unit_partition_match,
            "owning_unit_id": wl_owning_unit_id,
            "thread_vtid": wl_thread_vtid,
            "fanout_concentration_hint": wl_fanout_hint,
        })

        log_style_dist[log_style] = log_style_dist.get(log_style, 0) + 1
        target_kind = rec.get("target_kind") or "unknown"
        target_kind_dist[target_kind] = target_kind_dist.get(target_kind, 0) + 1
        attach_strength = rec.get("attach_strength") or "unknown"
        attach_strength_dist[attach_strength] = attach_strength_dist.get(attach_strength, 0) + 1
        source_file_dist[source_file] = source_file_dist.get(source_file, 0) + 1
        service_name = rec.get("service_name")
        if service_name:
            service_dist[service_name] = service_dist.get(service_name, 0) + 1
        if raw_malicious is True:
            malicious_dist["true"] += 1
        else:
            malicious_dist["null"] += 1
        if is_attack_related is True:
            attack_related_dist["true"] += 1
        elif is_attack_related is False:
            attack_related_dist["false"] += 1
        else:
            attack_related_dist["unknown"] += 1

        if attack_related_level in ("strong", "weak", "none"):
            attack_related_level_dist[attack_related_level] += 1
        if attack_related_reason:
            attack_related_reason_dist[attack_related_reason] = (
                attack_related_reason_dist.get(attack_related_reason, 0) + 1
            )
        _source_key = attack_related_source if attack_related_source else "null"
        attack_related_source_dist[_source_key] = (
            attack_related_source_dist.get(_source_key, 0) + 1
        )
        if via_attack_subgraph is True:
            via_attack_subgraph_counts["true"] += 1
        elif via_attack_subgraph is False:
            via_attack_subgraph_counts["false"] += 1
        else:
            via_attack_subgraph_counts["unknown"] += 1
        if attack_related_level == "weak" and via_attack_subgraph is not True:
            via_tid_only_weak_count += 1

    jsonl_path = os.path.join(output_dir, "applog_model_context.v0.jsonl")
    with open(jsonl_path, "w", encoding="utf-8") as f:
        for rec in records:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")

    summary = {
        "schema_version": "applog_model_context_summary.v0",
        "scenario": scene_name,
        "generated_at": dt_module.datetime.now().isoformat(),
        "source_view": os.path.basename(edge_context_view_path),
        "total_context_records": len(edge_records),
        "exported_model_records": len(records),
        "filtered_record_count": skipped_non_event_count,
        "skipped_non_event_count": skipped_non_event_count,
        "filter_reason_counts": skipped_reason_dist,
        "log_style_counts": log_style_dist,
        "target_kind_counts": target_kind_dist,
        "attach_strength_counts": attach_strength_dist,
        "source_file_distribution": source_file_dist,
        "service_name_distribution": service_dist,
        "malicious_counts": malicious_dist,
        "is_attack_related_counts": attack_related_dist,
        "attack_related_level_counts": attack_related_level_dist,
        "attack_related_reason_counts": attack_related_reason_dist,
        # These counts correspond to the write-level labeling diagnostics:
        # via_attack_subgraph_count measures direct graph support, while
        # via_tid_only_count exposes reliance on thread-local weak evidence.
        "attack_related_source_counts": attack_related_source_dist,
        "via_attack_subgraph_counts": via_attack_subgraph_counts,
        "via_tid_only_weak_count": via_tid_only_weak_count,
        "write_level_source_available": write_level_available,
    }
    summary_path = os.path.join(output_dir, "applog_model_context_summary.v0.json")
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)

    return jsonl_path, summary_path


# ====================
# Indexed-evidence replay example
# ====================

def replay_chain_example(
    chain_jsonl_path: str,
    event_index_jsonl_path: str,
    raw_dir: str,
    sample_size: int = 1,
):
    """Sample chain/edge/event-key references and display the original log lines.

    Args:
        chain_jsonl_path: Path to attack_chains.jsonl.
        event_index_jsonl_path: Path to event_index.jsonl.
        raw_dir: Directory containing the raw logs.
        sample_size: Number of chains to sample.
    """
    import random
    
    # Load event records and build the event-key lookup.
    event_index = []
    event_key_index = {}
    with open(event_index_jsonl_path, "r") as f:
        for line in f:
            rec = json.loads(line)
            event_index.append(rec)
            event_key = rec.get("event_key")
            if event_key:
                event_key_index[event_key] = rec
    
    print(f"Loaded {len(event_index)} events, {len(event_key_index)} event_keys")
    
    # Load the attack chains to sample.
    chains = []
    with open(chain_jsonl_path, "r") as f:
        for line in f:
            chains.append(json.loads(line))
    
    print(f"Loaded {len(chains)} chains")
    
    # Sample available chains without exceeding their count.
    if not chains:
        print("No chains to sample")
        return
    
    sampled_chains = random.sample(chains, min(sample_size, len(chains)))
    
    for chain in sampled_chains:
        chain_id = chain.get("chain_id", "unknown")
        print(f"\n{'='*60}")
        print(f"Chain: {chain_id}")
        print(f"{'='*60}")
        
        # Select one path or anomaly edge from the sampled chain.
        all_edges = chain.get("path_edges", []) + chain.get("anomaly_edges", [])
        if not all_edges:
            print("  No edges in this chain")
            continue
        
        edge = random.choice(all_edges)
        edge_id = edge.get("edge_id", "unknown")
        print(f"  Edge: {edge_id}")
        
        # Select one evidence event key from the edge.
        evidence_keys = edge.get("evidence_event_keys", [])
        if not evidence_keys:
            print("  No evidence_event_keys in this edge")
            continue
        
        event_key = random.choice(evidence_keys)
        print(f"  Event Key: {event_key}")
        
        # Resolve the event record associated with the sampled key.
        event_rec = lookup_event(event_key, event_key_index)
        if not event_rec:
            print(f"  ERROR: event_key '{event_key}' not found in event_index")
            continue
        
        source_file = event_rec.get("source_file", "")
        line_no = event_rec.get("line_no")
        source_type = event_rec.get("source_type", "unknown")
        
        print(f"  Source Type: {source_type}")
        print(f"  Source File: {source_file}")
        print(f"  Line No: {line_no}")
        
        # Read the exact source-log line referenced by the event index.
        if source_file and line_no is not None:
            # Remove the optional raw/ prefix before joining with raw_dir.
            rel_path = source_file.replace("raw/", "") if source_file.startswith("raw/") else source_file
            full_path = os.path.join(raw_dir, rel_path)
            
            if not os.path.exists(full_path):
                print(f"  ERROR: file not found: {full_path}")
                continue
            
            try:
                with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()
                    if 1 <= line_no <= len(lines):
                        raw_line = lines[line_no - 1].rstrip("\n\r")
                        print(f"  Raw Log Line ({len(raw_line)} chars):")
                        print(f"    {raw_line[:200]}{'...' if len(raw_line) > 200 else ''}")
                    else:
                        print(f"  ERROR: line_no {line_no} out of range (file has {len(lines)} lines)")
            except Exception as e:
                print(f"  ERROR: failed to read file: {e}")
        else:
            print(f"  ERROR: missing source_file or line_no")


if __name__ == "__main__":
    # Supply chain, event-index, and raw-directory paths explicitly.
    import sys
    
    if len(sys.argv) < 4:
        print("Usage: python replay_index.py <chain_jsonl> <event_index_jsonl> <raw_dir> [sample_size]")
        print("\nExample:")
        print("  python replay_index.py dataset/python-demo/index/attack_chains.jsonl \\")
        print("                        dataset/python-demo/index/event_index.jsonl \\")
        print("                        dataset/python-demo/raw \\")
        print("                        3")
        sys.exit(1)
    
    chain_path = sys.argv[1]
    event_index_path = sys.argv[2]
    raw_dir_path = sys.argv[3]
    sample_size = int(sys.argv[4]) if len(sys.argv) > 4 else 1
    
    replay_chain_example(chain_path, event_index_path, raw_dir_path, sample_size)


# ==================== Indexed-evidence replay helpers ====================

def lookup_event(event_key: str, event_index_path: str) -> Optional[Dict[str, Any]]:
    """Find an event record by its source-qualified key in event_index.jsonl.

    Args:
        event_key: The exported event_key, such as sysdig:<evt_num>.
        event_index_path: Path to event_index.jsonl.

    Returns:
        The matching event record, or None if unavailable.
    """
    try:
        with open(event_index_path, "r", encoding="utf-8") as f:
            for line in f:
                rec = json.loads(line)
                if rec.get("event_key") == event_key:
                    return rec
    except Exception:
        pass
    return None


def replay_event_by_key(event_key: str, event_index_path: str, raw_dir: str) -> Optional[str]:
    """Read the raw log line identified by a source-qualified event key.

    Args:
        event_key: The exported event_key, such as sysdig:<evt_num>.
        event_index_path: Path to event_index.jsonl.
        raw_dir: Directory containing the raw logs.

    Returns:
        The original log text, or None if the record or line is unavailable.
    """
    event_rec = lookup_event(event_key, event_index_path)
    if not event_rec:
        return None
    
    source_file = event_rec.get("source_file", "")
    line_no = event_rec.get("line_no")
    
    if not source_file or line_no is None:
        return None
    
    # Remove the optional raw/ prefix before joining with raw_dir.
    rel_path = source_file.replace("raw/", "") if source_file.startswith("raw/") else source_file
    full_path = os.path.join(raw_dir, rel_path)
    
    if not os.path.exists(full_path):
        return None
    
    try:
        with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
            if 1 <= line_no <= len(lines):
                return lines[line_no - 1].rstrip("\n\r")
    except Exception:
        pass
    
    return None


if __name__ == "__main__":
    """Run a minimal random-sampling test of indexed evidence replay."""
    import sys
    import random
    
    if len(sys.argv) < 4:
        print("Usage: python replay_index.py <dataset_dir> <scene_name> <num_samples>")
        print("Example: python replay_index.py results/dataset python-demo 5")
        sys.exit(1)
    
    dataset_dir = sys.argv[1]
    scene_name = sys.argv[2]
    num_samples = int(sys.argv[3])
    
    index_dir = os.path.join(dataset_dir, scene_name, "index")
    raw_dir = os.path.join(dataset_dir, scene_name, "raw")
    event_index_path = os.path.join(index_dir, "event_index.jsonl")
    attack_chains_path = os.path.join(index_dir, "attack_chains.jsonl")
    
    if not os.path.exists(event_index_path) or not os.path.exists(attack_chains_path):
        print(
            f"Error: Required legacy replay files not found in {index_dir}. "
            "event_index.jsonl and attack_chains.jsonl are no longer generated by the default build path; "
            "this replay entrypoint is debug/compatibility-only."
        )
        sys.exit(1)
    
    # Load the scene's attack chains.
    chains = []
    with open(attack_chains_path, "r") as f:
        for line in f:
            chains.append(json.loads(line))
    
    if not chains:
        print("Error: No chains found")
        sys.exit(1)
    
    # Sample chain, edge, and event-key references for raw-line replay.
    print(f"Testing replay with {num_samples} random samples...")
    for i in range(num_samples):
        chain = random.choice(chains)
        edges = chain.get("path_edges", []) + chain.get("anomaly_edges", [])
        if not edges:
            continue
        
        edge = random.choice(edges)
        evidence_keys = edge.get("evidence_event_keys", [])
        if not evidence_keys:
            print(f"Sample {i+1}: Edge {edge.get('edge_id')} has no evidence_event_keys")
            continue
        
        event_key = random.choice(evidence_keys)
        raw_line = replay_event_by_key(event_key, event_index_path, raw_dir)
        
        if raw_line:
            print(f"Sample {i+1}: Chain {chain.get('chain_id')}, Edge {edge.get('edge_id')}")
            print(f"  Event: {event_key}")
            print(f"  Raw line: {raw_line[:200]}...")
        else:
            print(f"Sample {i+1}: Failed to replay {event_key}")
    
    print("Replay test completed.")


def verify_event_index_replayability(
    event_index: List[Dict[str, Any]],
    raw_dir: str,
) -> Dict[str, Any]:
    """Require every event-index reference to resolve to a readable raw-log line.

    Each source_file must exist under raw_dir, and every line_no must be
    non-null and readable. Sysdig, traffic, and application-log records each
    require 100% non-null line numbers. Missing files or invalid lines raise
    ValueError rather than silently substituting another source.
    """
    # Resolve the caller-supplied raw directory before checking file paths.
    raw_dir = os.path.abspath(raw_dir)
    
    results = {
        "total_events": len(event_index),
        "missing_files": [],
        "missing_line_no": [],
        "line_no_read_errors": [],
        "by_type": {
            "sysdig": {"total": 0, "line_no_null": 0, "read_errors": 0},
            "traffic": {"total": 0, "line_no_null": 0, "read_errors": 0},
            "applog": {"total": 0, "line_no_null": 0, "read_errors": 0},
        },
    }
    
    total_events = len(event_index)
    logger.info(f"Starting verification of {total_events} events...")
    
    # Cache line counts used to diagnose invalid references.
    file_cache: Dict[str, List[str]] = {}
    
    for idx, rec in enumerate(event_index):
        if (idx + 1) % 50000 == 0:
            logger.info(f"Verified {idx + 1}/{total_events} events...")
        
        source_type = rec.get("source_type", "unknown")
        source_file = rec.get("source_file", "")
        line_no = rec.get("line_no")
        event_id = rec.get("event_id")
        
        # Track validation coverage separately for each source type.
        if source_type in results["by_type"]:
            results["by_type"][source_type]["total"] += 1
        
        # Check that the referenced raw file exists.
        if source_file:
            # Remove the optional raw/ prefix before joining with raw_dir.
            rel_path = source_file.replace("raw/", "") if source_file.startswith("raw/") else source_file
            full_path = os.path.join(raw_dir, rel_path)
            if not os.path.exists(full_path):
                # Record the expected path to diagnose missing raw files.
                debug_info = {
                    "event_id": event_id,
                    "source_type": source_type,
                    "source_file": source_file,
                    "rel_path": rel_path,
                    "raw_dir": raw_dir,
                    "expected_path": full_path,
                }
                # Include directory listings only for the first few failures.
                if len(results["missing_files"]) < 3:
                    debug_info.update({
                        "raw_dir_exists": os.path.exists(raw_dir),
                        "raw_dir_contents": os.listdir(raw_dir) if os.path.exists(raw_dir) else None,
                    })
                results["missing_files"].append(debug_info)
        
        # A null line number cannot identify replayable evidence.
        if line_no is None:
            if source_type in results["by_type"]:
                results["by_type"][source_type]["line_no_null"] += 1
            results["missing_line_no"].append({
                "event_id": event_id,
                "source_type": source_type,
                "source_file": source_file,
            })
            continue
        
        # Verify line readability, reusing cached file contents and line counts.
        if source_file:
            rel_path = source_file.replace("raw/", "") if source_file.startswith("raw/") else source_file
            full_path = os.path.join(raw_dir, rel_path)
            if os.path.exists(full_path):
                try:
                    # Retrieve the requested line through linecache's file cache.
                    import linecache
                    line = linecache.getline(full_path, line_no)
                    if not line:  # An empty result can indicate an invalid line number.
                        # Check the file length to identify out-of-range references.
                        if full_path not in file_cache:
                            # Count the file's lines only once.
                            with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                                file_cache[full_path] = len(f.readlines())
                        total_lines = file_cache[full_path]
                        if line_no < 1 or line_no > total_lines:
                            if source_type in results["by_type"]:
                                results["by_type"][source_type]["read_errors"] += 1
                            results["line_no_read_errors"].append({
                                "event_id": event_id,
                                "source_type": source_type,
                                "source_file": source_file,
                                "line_no": line_no,
                                "total_lines": total_lines,
                            })
                except Exception as e:
                    if source_type in results["by_type"]:
                        results["by_type"][source_type]["read_errors"] += 1
                    results["line_no_read_errors"].append({
                        "event_id": event_id,
                        "source_type": source_type,
                        "source_file": source_file,
                        "error": str(e),
                    })
    
    # Any missing file, missing line number, or read error fails strict replay.
    errors = []
    if results["missing_files"]:
        errors.append(f"Missing files: {len(results['missing_files'])}")
    if results["missing_line_no"]:
        errors.append(f"Missing line_no: {len(results['missing_line_no'])}")
    if results["line_no_read_errors"]:
        errors.append(f"Line_no read errors: {len(results['line_no_read_errors'])}")
    
    # Enforce zero null line numbers independently for each source type.
    for st, stats in results["by_type"].items():
        if stats["total"] > 0:
            null_ratio = stats["line_no_null"] / stats["total"]
            if null_ratio > 0:
                errors.append(f"{st} line_no null ratio: {null_ratio:.2%} (must be 0%)")
    
    if errors:
        error_msg = "Mode B validation failed:\n" + "\n".join(f"  - {e}" for e in errors)
        if results["missing_files"]:
            # Include the first few missing-file paths and their diagnostics.
            sample_missing = results["missing_files"][:3]
            error_msg += f"\n  Sample missing files (first 3):"
            for mf in sample_missing:
                error_msg += f"\n    - source_file: {mf.get('source_file')}"
                error_msg += f"\n      expected_path: {mf.get('expected_path')}"
                if 'raw_dir' in mf:
                    error_msg += f"\n      raw_dir: {mf.get('raw_dir')}"
                    error_msg += f"\n      raw_dir_exists: {mf.get('raw_dir_exists')}"
                    if mf.get('raw_dir_contents'):
                        error_msg += f"\n      raw_dir_contents: {mf.get('raw_dir_contents')[:5]}"
        if results["missing_line_no"]:
            error_msg += f"\n  Sample missing line_no: {results['missing_line_no'][:5]}"
        if results["line_no_read_errors"]:
            error_msg += f"\n  Sample read errors: {results['line_no_read_errors'][:5]}"
        raise ValueError(error_msg)
    
    return results
