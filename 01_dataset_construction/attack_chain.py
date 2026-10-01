from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from sysdig_rules.graph import Edge, FileNode, NetworkNode, Node, ProvGraph, UnitNode

# -----------------------------
# Data structures
# -----------------------------

@dataclass
class EdgeInfo:
    """Serializable edge attributes and source-qualified evidence references.

    log_ids stores integer Sysdig evt.num values. evidence_event_ids may
    contain integers or application-log string IDs; evidence_event_keys
    disambiguates sources. evidence_events carries each key, ID, and source.
    malicious is None when the edge label is unknown."""

    edge_id: str
    type: str
    timestamp: float
    log_ids: List[int] = field(default_factory=list)  # Integer Sysdig evt.num values.
    malicious: Optional[bool] = None
    src_node: Optional[str] = None
    dst_node: Optional[str] = None
    src_attrs: Dict[str, Any] = field(default_factory=dict)
    dst_attrs: Dict[str, Any] = field(default_factory=dict)
    evidence_event_ids: List[Any] = field(default_factory=list)  # Numeric Sysdig/traffic IDs or application-log string IDs.
    evidence_event_keys: List[str] = field(default_factory=list)  # Source-qualified keys for replay.
    evidence_events: List[Dict[str, Any]] = field(default_factory=list)  # Structured source, key, and event ID records.
    is_anomaly_edge: int = 0


@dataclass
class AttackChain:
    """Attack or normal behavior sequence represented as a JSONL-ready record.

    Extra metadata belongs in extra_meta. Time fields use seconds as floats."""

    chain_id: str | int
    scenario_name: str
    start_time: float
    end_time: float

    src_host: Optional[str] = None
    src_proc: Optional[str] = None
    src_pid: Optional[int] = None
    src_ip: Optional[str] = None
    src_port: Optional[int] = None

    dst_host: Optional[str] = None
    dst_proc: Optional[str] = None
    dst_pid: Optional[int] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None

    path_nodes: List[str] = field(default_factory=list)
    path_edges: List[EdgeInfo] = field(default_factory=list)

    is_anomaly: int = 0  # 1 when attack nodes or edges are present; otherwise 0.
    anomaly_ratio: float = 0.0
    anomaly_edges: List[EdgeInfo] = field(default_factory=list)
    anomaly_stages: List[Dict[str, Any]] = field(default_factory=list)

    extra_meta: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-serializable dict, including nested edge dataclasses."""

        def edge_to_dict(edge: EdgeInfo) -> Dict[str, Any]:
            data = asdict(edge)
            return data

        data = asdict(self)
        data["path_edges"] = [edge_to_dict(e) for e in self.path_edges]
        data["anomaly_edges"] = [edge_to_dict(e) for e in self.anomaly_edges]
        return data


# -----------------------------
# Chain extraction helpers
# -----------------------------

def _parse_timestamp(ts_str: str) -> float:
    """Parse a nanosecond datetime string into seconds, returning 0.0 on failure."""

    try:
        date_str, nano_str = ts_str.split(".")
        from datetime import datetime

        dt = datetime.strptime(date_str, "%Y-%m-%d %H:%M:%S")
        return dt.timestamp() + int(nano_str) / 1e9
    except Exception:
        return 0.0


def _edge_timestamp(edge: Edge) -> float:
    return _parse_timestamp(edge.time) if isinstance(edge.time, str) else 0.0


def _node_timestamp(node: Node) -> float:
    return _parse_timestamp(node.create_time) if isinstance(node.create_time, str) else 0.0


def _edge_id(edge: Edge, idx: int) -> str:
    return f"{edge.source.ID}->{edge.target.ID}#{idx}"


def _edge_type(edge: Edge) -> str:
    log = getattr(edge, "log", {}) or {}
    evt_type = log.get("evt.type")
    if evt_type:
        return str(evt_type)
    return "edge"


def _edge_log_ids(edge: Edge) -> List[int]:
    """Extract Sysdig evt.num values from the edge log.

    Traffic frame numbers belong to NetworkNode.logs and are collected
    from the endpoints while assembling the chain."""
    log = getattr(edge, "log", {}) or {}
    log_ids: List[int] = []
    if "evt.num" in log:
        evt_num = log["evt.num"]
        try:
            log_ids.append(int(evt_num))
        except (ValueError, TypeError):
            pass
    # Traffic frame numbers are stored on NetworkNode.logs, not edge.log.
    # Collect those records from endpoint nodes when building the chain.
    return log_ids


def _is_edge_malicious(edge: Edge) -> bool:
    # An endpoint's malicious label takes precedence over the edge-log label.
    src_flag = getattr(edge.source, "is_malicious", False)
    dst_flag = getattr(edge.target, "is_malicious", False)
    if src_flag is True or dst_flag is True:
        return True
    if src_flag == "Suspicious" or dst_flag == "Suspicious":
        return True
    log = getattr(edge, "log", {}) or {}
    return log.get("malicious") is True


def _node_label(node: Node) -> str:
    if isinstance(node, UnitNode):
        pid = getattr(node, "pid", None)
        first_evt = getattr(node, "first_evt_num", None)
        if pid is not None and first_evt is not None:
            return f"proc:{node.container_id}:{pid}:{first_evt}"
        return f"proc:{node.container_id}:{node.tid}"
    if isinstance(node, NetworkNode):
        return f"socket:{node.client_ip}:{node.client_port}->{node.server_ip}:{node.server_port}:{node.pid}"
    if isinstance(node, FileNode):
        return f"file:{node.ino}"
    return f"node:{node.ID}"


def _node_attrs(node: Node) -> Dict[str, Any]:
    """Return the node attributes needed for indexing and replay."""

    if isinstance(node, UnitNode):
        return {
            "type": "proc",
            "container_id": node.container_id,
            "tid": node.tid,
            "unit_id": node.unit_id,
            "is_accept": node.is_accept,
        }
    if isinstance(node, NetworkNode):
        return {
            "type": "socket",
            "container_id": node.container_id,
            "pid": node.pid,
            "fd": node.fd,
            "client_ip": node.client_ip,
            "client_port": node.client_port,
            "server_ip": node.server_ip,
            "server_port": node.server_port,
        }
    if isinstance(node, FileNode):
        return {
            "type": "file",
            "container_id": node.container_id,
            "ino": node.ino,
        }
    return {
        "type": "node",
        "container_id": getattr(node, "container_id", None),
    }


def _endpoint_from_node(node: Node) -> Tuple[Optional[str], Optional[str], Optional[int], Optional[str], Optional[int]]:
    """Return (host, process, pid, ip, port) for a node."""

    if isinstance(node, NetworkNode):
        proc = f"pid:{node.pid}"
        return node.container_id, proc, node.pid, node.server_ip or node.client_ip, node.server_port or node.client_port
    if isinstance(node, UnitNode):
        # Use the process ID when it is available on the execution unit.
        pid = getattr(node, "pid", None)
        return node.container_id, f"tid:{node.tid}", pid, None, None
    return None, None, None, None, None


def _infer_dst_endpoint_from_chain(
    edges_sorted: List[Edge],
    nodes_sorted: List[Node],
    fallback_node: Optional[Node]
) -> Tuple[Optional[str], Optional[str], Optional[int], Optional[str], Optional[int]]:
    """Infer (host, process, pid, ip, port) from the chain.

    Prefer the last outbound socket, then an inbound client, then any
    network-node client endpoint; finally use fallback_node."""
    
    # Search backward for the last outbound network edge.
    for edge in reversed(edges_sorted):
        edge_type = _edge_type(edge)
        if edge_type in {"sendto", "connect", "sendmsg"}:
            target = edge.target
            if isinstance(target, NetworkNode):
                # The target socket describes the outbound peer.
                return (
                    target.container_id,
                    f"pid:{target.pid}",
                    target.pid,
                    target.server_ip,  # Outbound destination address.
                    target.server_port
                )
    
    # Use the client endpoint of an inbound edge when available.
    for edge in edges_sorted:
        edge_type = _edge_type(edge)
        if edge_type in {"accept", "accept4", "recvfrom", "recvmsg"}:
            source = edge.source
            if isinstance(source, NetworkNode):
                # The inbound source socket identifies the requesting peer.
                return (
                    source.container_id,
                    f"pid:{source.pid}",
                    source.pid,
                    source.client_ip,   # Inbound client address.
                    source.client_port
                )
    
    # Look for a network-node peer if no network edge supplies one.
    for node in reversed(nodes_sorted):
        if isinstance(node, NetworkNode):
            # Prefer the client endpoint when populated.
            if node.client_ip:
                return (
                    node.container_id,
                    f"pid:{node.pid}",
                    node.pid,
                    node.client_ip,
                    node.client_port
                )
    
    # Fall back to the supplied endpoint node.
    if fallback_node:
        return _endpoint_from_node(fallback_node)
    return None, None, None, None, None


def _collect_chain_edges(
    graph: ProvGraph, node_ids: Set[int]
) -> Tuple[List[Edge], Set[Node]]:
    """Collect edges adjacent to node_ids and their endpoint nodes.

    Traverse each node's incoming and outgoing adjacency lists instead of
    scanning all graph edges. Deduplicate shared edges by object identity."""

    edges: List[Edge] = []
    nodes: Set[Node] = set()
    edge_set: Set[int] = set()  # Track edge objects already included.
    
    # Read adjacent edges directly from each selected node.
    for node_id in node_ids:
        node = Node.ID_MAP.get(node_id)
        if node is None:
            continue
        
        nodes.add(node)
        
        # Collect outgoing edges.
        for target_id, edge_list in node.out_edges.items():
            for edge in edge_list:
                edge_id = id(edge)  # Object identity distinguishes edge instances.
                if edge_id not in edge_set:
                    edge_set.add(edge_id)
                    edges.append(edge)
                    nodes.add(edge.target)
        
        # Collect incoming edges.
        for source_id, edge_list in node.in_edges.items():
            for edge in edge_list:
                edge_id = id(edge)
                if edge_id not in edge_set:
                    edge_set.add(edge_id)
                    edges.append(edge)
                    nodes.add(edge.source)
    
    return edges, nodes


def _connected_components(nodes: Sequence[Node]) -> List[Set[Node]]:
    """Partition the supplied nodes into undirected connected components."""

    adj: Dict[int, Set[int]] = {}
    for node in nodes:
        adj.setdefault(node.ID, set())
        for dst in node.out_edges:
            adj[node.ID].add(dst)
            adj.setdefault(dst, set()).add(node.ID)
        for src in node.in_edges:
            adj[node.ID].add(src)
            adj.setdefault(src, set()).add(node.ID)

    visited: Set[int] = set()
    components: List[Set[Node]] = []

    for node in nodes:
        if node.ID in visited:
            continue
        stack = [node.ID]
        comp_ids: Set[int] = set()
        while stack:
            cur = stack.pop()
            if cur in visited:
                continue
            visited.add(cur)
            comp_ids.add(cur)
            for nei in adj.get(cur, ()):
                if nei not in visited:
                    stack.append(nei)
        components.append({Node.ID_MAP[i] for i in comp_ids})
    return components


def _build_attack_chain(
    chain_id: str | int,
    scenario_name: str,
    nodes: Iterable[Node],
    edges: Iterable[Edge],
    node_attr_map: Dict[str, Dict[str, Any]] | None = None,
    app_log_matches: Dict[Any, Any] | None = None,  # Event-to-application-log matches and independent application-log entries.
) -> AttackChain:
    nodes = list(nodes)
    edges = list(edges)

    # Order nodes and edges chronologically.
    edges_sorted = sorted(edges, key=_edge_timestamp)
    nodes_sorted = sorted(nodes, key=_node_timestamp)

    path_edges: List[EdgeInfo] = []
    anomaly_edges: List[EdgeInfo] = []
    anomaly_stage_events: Dict[int, Set[str]] = {1: set(), 2: set(), 3: set()}

    def extract_file_path(edge_log: Dict[str, Any]) -> Optional[str]:
        """Find the first nonempty, non-null file path.

        Check source/destination path attributes, fd.name attributes, then
        parsed or raw fd.name values in full_logs."""
        if not isinstance(edge_log, dict):
            return None

        # 1) src/dst attrs
        for attrs in (
            edge_log.get("src_attrs", {}) or {},
            edge_log.get("dst_attrs", {}) or {},
        ):
            path = attrs.get("path")
            if path and path != "null":
                return path
            fd_name = attrs.get("fd.name")
            if fd_name and fd_name != "null":
                return fd_name

        # 2) fd.name on edge
        fd_name = edge_log.get("fd.name")
        if fd_name and fd_name != "null":
            return fd_name

        # 3) full_logs
        for lg in edge_log.get("full_logs", []) or []:
            if not isinstance(lg, dict):
                continue
            parsed = lg.get("parsed", {}) or {}
            fd_name_parsed = parsed.get("fd.name")
            if fd_name_parsed and fd_name_parsed != "null":
                return fd_name_parsed
            fd_name_raw = lg.get("fd.name")
            if fd_name_raw and fd_name_raw != "null":
                return fd_name_raw
        return None
    
    def _collect_traffic_events(node: Node) -> List[Dict[str, Any]]:
        """Collect traffic records from NetworkNode.logs.

        Keys use traffic:<pcap_file>:<frame_number> to prevent collisions
        between captures in multi-container scenes."""
        events: List[Dict[str, Any]] = []
        if isinstance(node, NetworkNode):
            for log in getattr(node, "logs", []):
                frame = log.get("_source", {}).get("layers", {}).get("frame", {})
                frame_num = frame.get("frame.number")
                pcap_file = log.get("pcap_file", "")
                if frame_num is not None and pcap_file:
                    try:
                        event_id = int(frame_num)
                        # Include the capture file to disambiguate frame numbers.
                        event_key = f"traffic:{pcap_file}:{event_id}"
                        events.append({
                            "event_key": event_key,
                            "event_id": event_id,
                            "source_type": "traffic",
                            "pcap_file": pcap_file,
                        })
                    except (ValueError, TypeError):
                        pass
        return events
    
    for idx, e in enumerate(edges_sorted):
        info = EdgeInfo(
            edge_id=_edge_id(e, idx),
            type=_edge_type(e),
            timestamp=_edge_timestamp(e),
            log_ids=_edge_log_ids(e),
            malicious=_is_edge_malicious(e),
            src_node=_node_label(e.source),
            dst_node=_node_label(e.target),
        )
        if node_attr_map is not None:
            info.src_attrs = node_attr_map.get(info.src_node, {})
            info.dst_attrs = node_attr_map.get(info.dst_node, {})
        
        # Keep Sysdig, traffic, and application-log evidence source-qualified.
        evidence_events: List[Dict[str, Any]] = []
        
        # Sysdig evidence is identified by the edge log's evt.num.
        log = getattr(e, "log", {}) or {}
        if "evt.num" in log:
            try:
                evt_num = int(log["evt.num"])
                event_key = f"sysdig:{evt_num}"
                evidence_events.append({
                    "event_key": event_key,
                    "event_id": evt_num,
                    "source_type": "sysdig",
                })
            except (ValueError, TypeError):
                pass
        
        # Traffic evidence comes from frame numbers on network endpoints.
        traffic_events_src = _collect_traffic_events(e.source)
        traffic_events_dst = _collect_traffic_events(e.target)
        evidence_events.extend(traffic_events_src)
        evidence_events.extend(traffic_events_dst)
        
        # Attach application-log lines matched to each Sysdig event.
        # Application-log identity uses path and line number independently of evt.num.
        if app_log_matches:
            for evt_num in info.log_ids:
                # Ignore the special application-log entry map.
                if evt_num in app_log_matches and evt_num != "_applog_entries":
                    # Each event maps to (path, line_no, applog_key) tuples.
                    for path, line_no, applog_key in app_log_matches[evt_num]:
                        # Use the independent application-log key.
                        event_key = f"applog:{applog_key}"
                        evidence_events.append({
                            "event_key": event_key,
                            "event_id": applog_key,  # Independent application-log identifier.
                            "source_type": "applog",
                            "line_no": line_no,  # One-based line number for direct replay.
                            "file_path": path,   # Original application-log file path.
                            "related_evt_num": evt_num,  # Retain the associated Sysdig event.
                        })
        
        # Deduplicate by event_key without changing evidence order.
        seen_keys = set()
        unique_events = []
        unique_ids = []
        unique_keys = []
        for evt in evidence_events:
            event_key = evt["event_key"]
            if event_key not in seen_keys:
                seen_keys.add(event_key)
                unique_events.append(evt)
                unique_ids.append(evt["event_id"])
                unique_keys.append(event_key)
        
        # Export both event IDs and source-qualified replay references.
        info.evidence_event_ids = unique_ids  # Event IDs may overlap between sources.
        info.evidence_event_keys = unique_keys  # Unique source-qualified evidence keys.
        info.evidence_events = unique_events  # Structured evidence records.
        
        info.is_anomaly_edge = 1 if info.malicious else 0
        path_edges.append(info)
        if info.malicious:
            anomaly_edges.append(info)
        
        # Aggregate stage cues without changing edge detection labels.
        if log and isinstance(log, dict):
            edge_type = info.type
            file_path = extract_file_path(log)

            # Stage 1: process creation
            if edge_type in {"fork", "vfork", "clone"}:
                anomaly_stage_events[1].update(info.evidence_event_keys)

            # Stage 2: library injection/loading (.so, non-/lib or /usr/lib) via open/read/mmap/pread
            if edge_type in {"open", "read", "mmap", "pread"}:
                if file_path and file_path.endswith(".so") and not (
                    file_path.startswith("/lib") or file_path.startswith("/usr/lib")
                ):
                    anomaly_stage_events[2].update(info.evidence_event_keys)

            # Stage 3: execution/action
            if edge_type in {"exec", "execve", "write", "creat", "rename"}:
                anomaly_stage_events[3].update(info.evidence_event_keys)

    path_nodes = [_node_label(n) for n in nodes_sorted]

    if edges_sorted:
        start_ts = _edge_timestamp(edges_sorted[0])
        end_ts = _edge_timestamp(edges_sorted[-1])
        src_node = edges_sorted[0].source
        dst_node = edges_sorted[-1].target
    else:
        start_ts = _node_timestamp(nodes_sorted[0]) if nodes_sorted else 0.0
        end_ts = _node_timestamp(nodes_sorted[-1]) if nodes_sorted else start_ts
        src_node = nodes_sorted[0] if nodes_sorted else None
        dst_node = nodes_sorted[-1] if nodes_sorted else None

    src_host, src_proc, src_pid, src_ip, src_port = _endpoint_from_node(src_node) if src_node else (None, None, None, None, None)
    # Infer destination details from network activity within the chain.
    dst_host, dst_proc, dst_pid, dst_ip, dst_port = _infer_dst_endpoint_from_chain(
        edges_sorted, nodes_sorted, dst_node
    )

    total_edges = len(path_edges)
    anomaly_ratio = (len(anomaly_edges) / total_edges) if total_edges else 0.0
    is_anomaly = 1 if anomaly_edges else 0

    anomaly_stages: List[Dict[str, Any]] = []
    if is_anomaly:
        stage_defs = {
            1: ("process_creation", "Suspicious process creation or inheritance detected"),
            2: ("library_injection", "Suspicious library loading (non-system .so)"),
            3: ("execution", "Execution or action after potential injection"),
        }
        for stage_no in (1, 2, 3):
            ev_keys = sorted(anomaly_stage_events[stage_no])
            if ev_keys:
                anomaly_stages.append(
                    {
                        "stage": stage_no,
                        "name": stage_defs[stage_no][0],
                        "description": stage_defs[stage_no][1],
                        "evidence_event_keys": ev_keys,
                    }
                )
        if not anomaly_stages:
            # Preserve anomaly evidence in an unclassified stage when no rule matches.
            fallback_keys: List[str] = []
            for ae in anomaly_edges:
                fallback_keys.extend(ae.evidence_event_keys)
            seen_fk = set()
            dedup_fk = []
            for k in fallback_keys:
                if k not in seen_fk:
                    seen_fk.add(k)
                    dedup_fk.append(k)
            if dedup_fk:
                anomaly_stages.append(
                    {
                        "stage": 0,
                        "name": "unclassified",
                        "description": "Anomalous chain without stage-matched evidence",
                        "evidence_event_keys": dedup_fk,
                    }
                )

    return AttackChain(
        chain_id=chain_id,
        scenario_name=scenario_name,
        start_time=start_ts,
        end_time=end_ts,
        src_host=src_host,
        src_proc=src_proc,
        src_pid=src_pid,
        src_ip=src_ip,
        src_port=src_port,
        dst_host=dst_host,
        dst_proc=dst_proc,
        dst_pid=dst_pid,
        dst_ip=dst_ip,
        dst_port=dst_port,
        path_nodes=path_nodes,
        path_edges=path_edges,
        is_anomaly=is_anomaly,
        anomaly_ratio=anomaly_ratio,
        anomaly_edges=anomaly_edges,
        anomaly_stages=anomaly_stages,
        extra_meta={},
    )


def extract_attack_chains(
    graph: ProvGraph,
    scene_name: str,
    mode: str = "unit",
    max_normal_chains: Optional[int] = None,
    normal_sample_ratio: Optional[float] = None,
    node_attr_map: Optional[Dict[str, Dict[str, Any]]] = None,
    app_log_matches: Optional[Dict[Any, Any]] = None,  # Event-to-application-log matches and independent application-log entries.
) -> List[AttackChain]:
    """Extract attack and normal chains from a labeled provenance graph.

    mode="unit" groups execution units by container, thread, and unit ID;
    other modes use connected components. Only normal chains are sampled:
    normal_sample_ratio is applied before the max_normal_chains cap.
    None leaves the corresponding sampling limit unset."""

    chains: List[AttackChain] = []
    from loguru import logger

    # Skip normal-chain retention only when explicitly requested.
    skip_normal = (max_normal_chains is not None and max_normal_chains == 0) and \
                  (normal_sample_ratio is None or normal_sample_ratio == 0)

    if mode == "unit":
        # Group by (container, tid, unit_id), using a null unit for unmarked threads.
        logger.info("Grouping UnitNodes by unit_key...")
        groups: Dict[Tuple[str, str, str], Set[int]] = {}
        unit_node_count = 0
        for node in graph.nodes:
            if isinstance(node, UnitNode):
                unit_node_count += 1
                unit_key = (node.container_id, node.tid, node.unit_id or "null")
                groups.setdefault(unit_key, set()).add(node.ID)
        logger.info(f"Found {len(groups)} unit groups from {unit_node_count} UnitNodes")
        # Include edges and neighboring nodes connected to each execution unit.
        logger.info("Building attack chains from unit groups...")
        
        # Accumulate groups in batches of 1,000 to limit temporary memory.
        batch_size = 1000
        normal_chains_batch: List[AttackChain] = []
        anomaly_chains_batch: List[AttackChain] = []
        
        for idx, (unit_key, node_ids) in enumerate(groups.items()):
            if (idx + 1) % 100 == 0:
                logger.info(f"Processing unit group {idx + 1}/{len(groups)}...")
            edges, related_nodes = _collect_chain_edges(graph, node_ids)
            chain_nodes = {Node.ID_MAP[nid] for nid in node_ids}.union(related_nodes)
            chain = _build_attack_chain(
                chain_id=f"unit-{idx}",
                scenario_name=scene_name,
                nodes=chain_nodes,
                edges=edges,
                node_attr_map=node_attr_map,
                app_log_matches=app_log_matches,
            )
            
            # Classify early so unwanted normal chains are not retained.
            if chain.is_anomaly == 1:
                anomaly_chains_batch.append(chain)
            elif not skip_normal:
                normal_chains_batch.append(chain)
            # Normal chains are discarded when skip_normal is enabled.
            
            # Flush each completed batch to the result list.
            if (idx + 1) % batch_size == 0:
                chains.extend(anomaly_chains_batch)
                if not skip_normal:
                    chains.extend(normal_chains_batch)
                anomaly_chains_batch.clear()
                normal_chains_batch.clear()
                if (idx + 1) % (batch_size * 10) == 0:
                    logger.info(f"Processed {idx + 1} groups, current chains in memory: {len(chains)}")
        
        # Flush the remaining partial batch.
        chains.extend(anomaly_chains_batch)
        if not skip_normal:
            chains.extend(normal_chains_batch)
    else:
        # Build one chain per connected component.
        logger.info("Computing connected components...")
        components = _connected_components(graph.nodes)
        logger.info(f"Found {len(components)} connected components")
        
        # Batch component processing to limit temporary memory.
        batch_size = 1000
        normal_chains_batch: List[AttackChain] = []
        anomaly_chains_batch: List[AttackChain] = []
        
        for idx, comp_nodes in enumerate(components):
            if (idx + 1) % 100 == 0:
                logger.info(f"Processing component {idx + 1}/{len(components)}...")
            comp_edges = []
            for n in comp_nodes:
                for dst, e_list in n.out_edges.items():
                    if Node.ID_MAP[dst] in comp_nodes:
                        comp_edges.extend(e_list)
            chain = _build_attack_chain(
                chain_id=f"cc-{idx}",
                scenario_name=scene_name,
                nodes=comp_nodes,
                edges=comp_edges,
                node_attr_map=node_attr_map,
                app_log_matches=app_log_matches,
            )
            
            # Classify early so unwanted normal chains are not retained.
            if chain.is_anomaly == 1:
                anomaly_chains_batch.append(chain)
            elif not skip_normal:
                normal_chains_batch.append(chain)
            
            # Flush each completed batch to the result list.
            if (idx + 1) % batch_size == 0:
                chains.extend(anomaly_chains_batch)
                if not skip_normal:
                    chains.extend(normal_chains_batch)
                anomaly_chains_batch.clear()
                normal_chains_batch.clear()
                if (idx + 1) % (batch_size * 10) == 0:
                    logger.info(f"Processed {idx + 1} components, current chains in memory: {len(chains)}")
        
        # Flush the remaining partial batch.
        chains.extend(anomaly_chains_batch)
        if not skip_normal:
            chains.extend(normal_chains_batch)

    # Apply optional downsampling to normal chains only.
    # Reuse the early-filtered list when it contains only anomalous chains.
    if skip_normal:
        # No normal chains were retained in this mode.
        anomaly_chains = chains
        normal_chains = []
        logger.info(f"Early filtering enabled: found {len(anomaly_chains)} anomaly chains (normal chains skipped)")
    else:
        logger.info(f"Separating anomaly and normal chains from {len(chains)} total chains...")
        anomaly_chains = [c for c in chains if c.is_anomaly == 1]
        normal_chains = [c for c in chains if c.is_anomaly == 0]
        logger.info(f"Found {len(anomaly_chains)} anomaly chains and {len(normal_chains)} normal chains")

    if normal_sample_ratio is not None:
        try:
            import random

            k = max(1, int(len(normal_chains) * float(normal_sample_ratio)))
            normal_chains = random.sample(normal_chains, k)
        except Exception:
            # Keep all normal chains if sampling fails.
            pass

    if max_normal_chains is not None:
        normal_chains = normal_chains[: max(0, max_normal_chains)]

    return anomaly_chains + normal_chains


def export_attack_chains(
    attack_chains: Sequence[AttackChain],
    output_dir: str,
    scene_name: str,
    subdir: str | None = None,
    batch_size: int | None = None,
) -> str:
    """Write attack and normal chains as JSONL and return the output path.

    An empty subdir writes directly into output_dir; otherwise use the
    requested subdirectory or scene_name. A missing batch_size selects
    batches of 1,000 when more than 1,000 chains are present."""

    import json
    import os
    from loguru import logger

    # An empty subdir means output_dir itself.
    if subdir == "":
        base_dir = output_dir
    elif subdir:
        base_dir = os.path.join(output_dir, subdir)
    else:
        base_dir = os.path.join(output_dir, scene_name)
    os.makedirs(base_dir, exist_ok=True)
    output_path = os.path.join(base_dir, "attack_chains.jsonl")

    total_chains = len(attack_chains)
    
    # Select batches automatically for more than 1,000 chains.
    if batch_size is None:
        if total_chains > 1000:
            batch_size = 1000
            logger.info(f"Auto-enabling batch mode for chains: {total_chains} chains, batch_size={batch_size}")
        else:
            batch_size = None
    
    # Buffer writes to reduce system calls.
    buffer_size = 1024 * 1024  # One MiB output buffer.
    with open(output_path, "w", buffering=buffer_size) as f:
        if batch_size is not None and total_chains > batch_size:
            # Batch serialization bounds temporary memory usage.
            logger.info(f"Writing {total_chains} chains in batches of {batch_size}...")
            lines = []
            for i, chain in enumerate(attack_chains):
                lines.append(json.dumps(chain.to_dict(), ensure_ascii=False) + "\n")
                
                # Flush each batch_size group of serialized chains.
                if (i + 1) % batch_size == 0:
                    f.writelines(lines)
                    lines = []
                    if (i + 1) % (batch_size * 10) == 0:
                        logger.info(f"Written {i + 1}/{total_chains} chains...")
            
            # Flush the remaining serialized lines.
            if lines:
                f.writelines(lines)
        else:
            # Write one chain at a time when batching is disabled.
            for i, chain in enumerate(attack_chains):
                f.write(json.dumps(chain.to_dict(), ensure_ascii=False) + "\n")
                if (i + 1) % 1000 == 0:
                    logger.info(f"Written {i + 1}/{total_chains} chains...")

    return output_path
