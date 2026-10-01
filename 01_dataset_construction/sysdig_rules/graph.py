import json
import os
import re
from datetime import datetime
from io import TextIOWrapper
from typing import Literal

from loguru import logger
from logs import CAPTURED_PATH
from merge_set import MergeSet
from net_trace import ConnInfo

from utils import exec_command


class Node:
    GLOBAL_ID = 0
    ID_MAP: dict[int, "Node"] = {}

    def __init__(self, container_id: str, create_time: str):
        self.ID = Node.GLOBAL_ID
        Node.ID_MAP[self.ID] = self
        Node.GLOBAL_ID += 1
        self.container_id = container_id
        self.create_time = create_time
        self.out_edges: dict[int, list["Edge"]] = {}
        self.in_edges: dict[int, list["Edge"]] = {}


class UnitNode(Node):
    def __init__(self, container_id: str, tid: str, create_time: str):
        Node.__init__(self, container_id, create_time)
        self.is_malicious = False
        self.tid = tid
        self.logs: list[dict] = []
        self.is_accept = False
        self.unit_id: str = "null"


class FileNode(Node):
    def __init__(self, container_id: str, ino: str, create_time: str):
        Node.__init__(self, container_id, create_time)
        self.ino = ino


class NetworkNode(Node):
    def __init__(
        self,
        container_id: str,
        pid: int,
        fd: int,
        client_ip: str,
        client_port: int,
        server_ip: str,
        server_port: int,
        create_time: str,
    ):
        Node.__init__(self, container_id, create_time)
        self.pid = pid
        self.fd = fd
        self.client_ip = client_ip
        self.client_port = client_port
        self.server_ip = server_ip
        self.server_port = server_port
        self.is_malicious: Literal[True, False, "Suspicious"] = False
        self.logs: list[dict] = []


class Edge:
    def __init__(self, source: Node, target: Node, time: str, log: dict):
        self.source = source
        self.target = target
        self.time = time
        self.log = log


class ProvGraph:
    def __init__(self):
        self.type: str = "process"
        # Include the first event number so reused process IDs stay distinct.
        self.node_by_proc_key: dict[tuple[str, str, str], UnitNode] = {}
        # Map each container-local TID to its current process identity.
        self.tid_to_proc_key: dict[tuple[str, str], tuple[str, str, str]] = {}
        self.node_by_ino: dict[tuple[str, str], FileNode] = {}
        self.node_by_cid_pid_fd: dict[tuple[str, int, int], NetworkNode] = {}
        self.nodes: list[Node] = []
        self.edges: list[Edge] = []
        self.merge_set = MergeSet(Node.ID_MAP)

        self.node_by_tid_unit: dict[tuple[str, str, int], UnitNode] = {}

        self.app_log_files: set[str] = set()
        # Event numbers map to (path, line, applog key) tuples for chain linking.
        # The _applog_entries map resolves applog keys for event-index export.
        self.app_log_matches: dict[int | str, list[tuple[str, int, str]] | dict[str, tuple[str, int, int]]] = {}

        # Populate event-index file paths while writing the output logs.
        self.actual_file_paths: dict[str, str] = {}  # {log_key: relative_path}
        self.applog_path_map: dict[str, str] = {}  # {original_path: tar_relative_path}
        
        # Build event-to-line mappings while writing the separate raw logs.
        self.sysdig_line_map: dict[str, int] = {}  # {container_id:evt_num -> line_no (1-based)}
        self.traffic_line_map: dict[str, int] = {}  # {pcap_file:frame_number -> line_no (1-based)}
        
        # Keep one-based raw-log line references for Sysdig and traffic events.
        self.sysdig_line_map: dict[str, int] = {}  # {container_id:evt_num -> line_no (1-based)}
        self.traffic_line_map: dict[str, int] = {}  # {pcap_file:frame_number -> line_no (1-based)}

    def output(
        self,
        service_to_container_id: dict[str, str],
        output_path: str,
        cur_time: datetime | None = None,
        mode_b_raw_dir: str | None = None,  # Base directory for separate raw logs.
    ):
        cur_time = cur_time or datetime.now()
        cur_time_str = str(cur_time)
        
        # Use the explicit raw directory when separate raw/index output is enabled.
        if mode_b_raw_dir:
            sysdig_prefix = os.path.join(mode_b_raw_dir, "sysdig")
            tshark_prefix = os.path.join(mode_b_raw_dir, "tshark")
            applog_prefix = os.path.join(mode_b_raw_dir, "applog")
        else:
            sysdig_prefix = f"{output_path}/{cur_time_str}/sysdig"
            tshark_prefix = f"{output_path}/{cur_time_str}/tshark"
            applog_prefix = f"{output_path}/{cur_time_str}/applog"
        
        os.makedirs(sysdig_prefix, exist_ok=True)
        os.makedirs(tshark_prefix, exist_ok=True)
        os.makedirs(applog_prefix, exist_ok=True)

        malicious_applogs: dict[str, set[int]] = {}

        # Label applog lines through their matched file-write syscalls (TID and time).
        # Strong evidence includes attacker-seeded writes and writes in attack units.
        # Only strong matches receive [*MALICIOUS*]; neighboring weak matches do not.
        # When write-level labels exist, they are the sole source of applog labels.
        # Otherwise, use the containing unit's label as the fallback below.
        # This backfill does not alter Sysdig or traffic labels.
        _has_write_gated = hasattr(self, "applog_write_level_strong")
        _wl_strong: set[tuple[str, int]] = getattr(
            self, "applog_write_level_strong", set()
        ) or set()
        for _wl_path, _wl_line in _wl_strong:
            malicious_applogs.setdefault(_wl_path, set()).add(_wl_line)

        inv_dict = {v: k for k, v in service_to_container_id.items()}

        # Record generated paths for event-index references.
        self.actual_file_paths: dict[str, str] = {}  # {log_key: relative_path}

        fds: dict[str, tuple[TextIOWrapper, list[tuple[int, dict]]]] = {}
        for node in self.nodes:
            if isinstance(node, UnitNode):
                for log in node.logs:
                    log["malicious"] = node.is_malicious
                    # log["unit_id"] = node.unit_id

                    # Use unit-level applog labels only when write-level labels
                    # are unavailable, avoiding duplicate label decisions.
                    evt_num = log["evt.num"]
                    if (
                        not _has_write_gated
                        and evt_num in self.app_log_matches
                        and evt_num != "_applog_entries"
                        and node.is_malicious is True
                    ):
                        for log_path, li, _ in self.app_log_matches[evt_num]:
                            malicious_applogs.setdefault(log_path, set()).add(li)

                    if log["container.id"] in fds:
                        fd = fds[log["container.id"]]
                    else:
                        service_name = inv_dict[log["container.id"]]
                        # Prefix paths with raw/ for separate raw/index output.
                        path_prefix = "raw/" if mode_b_raw_dir else ""
                        actual_path = f"{path_prefix}sysdig/{service_name}.log"
                        fd = (
                            open(f"{sysdig_prefix}/{service_name}.log", "w"),
                            [],
                        )
                        fds[log["container.id"]] = fd
                        # Resolve the container's Sysdig events to this output file.
                        self.actual_file_paths[f"sysdig:{log['container.id']}"] = actual_path
                    # fd.write(json.dumps(log) + "\n")
                    fd[1].append((int(log["evt.num"]), log))
            elif (
                isinstance(node, NetworkNode)
                and self.merge_set.fa.get(node.ID, None) == node.ID
            ):
                for log in node.logs:
                    log["malicious"] = node.is_malicious
                    if log["pcap_file"] in fds:
                        fd = fds[log["pcap_file"]]
                    else:
                        cid, interface = (
                            log["pcap_file"].partition(".json")[0].split("_")
                        )
                        service_name = inv_dict[cid]
                        actual_filename = f"{service_name}_{interface}.log"
                        # Prefix paths with raw/ for separate raw/index output.
                        path_prefix = "raw/" if mode_b_raw_dir else ""
                        actual_path = f"{path_prefix}tshark/{actual_filename}"
                        fd = (
                            open(f"{tshark_prefix}/{actual_filename}", "w"),
                            [],
                        )
                        fds[log["pcap_file"]] = fd
                        # Resolve packets from this capture to the generated log.
                        self.actual_file_paths[f"traffic:{log['pcap_file']}"] = actual_path
                    # fd.write(json.dumps(log) + "\n")
                    fd[1].append(
                        (int(log["_source"]["layers"]["frame"]["frame.number"]), log)
                    )

        # Build line-reference maps in the same order that events are written.
        total_files = len(fds)
        for file_idx, (key, (fd, logs)) in enumerate(fds.items(), 1):
            logger.info(f"Writing log file {file_idx}/{total_files}: {key} ({len(logs)} events)")
            logs.sort(key=lambda x: x[0])
            line_no = 0
            for num, log in logs:
                line_no += 1
                fd.write(json.dumps(log) + "\n")
                
                # Distinguish Sysdig events from captured traffic frames.
                if "container.id" in log and "evt.num" in log:
                    # Map container ID and event number to the written line.
                    container_id = log.get("container.id", "")
                    evt_num = log.get("evt.num")
                    if container_id and evt_num is not None:
                        map_key = f"{container_id}:{evt_num}"
                        self.sysdig_line_map[map_key] = line_no
                elif "pcap_file" in log:
                    # Map capture file and frame number to the written line.
                    pcap_file = log.get("pcap_file", "")
                    frame = log.get("_source", {}).get("layers", {}).get("frame", {})
                    frame_num = frame.get("frame.number")
                    if pcap_file and frame_num is not None:
                        map_key = f"{pcap_file}:{frame_num}"
                        self.traffic_line_map[map_key] = line_no

        # Resolve captured applog paths to their generated output paths.
        self.applog_path_map: dict[str, str] = {}  # {original_path: tar_relative_path}

        for app_log_file in self.app_log_files:
            # Encode path separators without colliding with literal hash signs.
            from urllib.parse import quote
            relative_path_raw = app_log_file.partition(f"{CAPTURED_PATH}/app_log/")[2]
            # Escape literal # before using it to represent a path separator.
            relative_path = relative_path_raw.replace("#", "%23").replace("/", "#")
            # Prefix paths with raw/ for separate raw/index output.
            path_prefix = "raw/" if mode_b_raw_dir else ""
            actual_path = f"{path_prefix}applog/{relative_path}"
            self.applog_path_map[app_log_file] = actual_path
            
            with open(app_log_file, "r") as f:
                with open(f"{applog_prefix}/{relative_path}", "w") as copied_fd:
                    for li, line in enumerate(f, start=1):  # Match one-based applog references.
                        pattern = r"^\[(?:SecLog|AutoLabel) (\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2})\.(\d{9}) (\d+)\] "
                        if match := re.search(pattern, line):
                            line = line[match.end() :]
                        if (
                            app_log_file in malicious_applogs
                            and li in malicious_applogs[app_log_file]
                        ):
                            copied_fd.write(f"[*MALICIOUS*] {line}")
                        else:
                            copied_fd.write(line)

        # The caller in analyze.py handles packaging and cleanup.

    def query_by_id(self, node_id: int) -> int:
        return self.merge_set.query_by_id(node_id)

    def query_by_time(self, conn: ConnInfo, timestamp: datetime) -> NetworkNode | None:
        return self.merge_set.query_by_time(conn, timestamp)

    def join(self, node_id: int, conns: set[tuple[ConnInfo, datetime]]):
        self.merge_set.join(node_id, conns)

    def add_net_node(
        self,
        container_id: str,
        pid: int,
        fd: int,
        client_ip: str,
        client_port: int,
        server_ip: str,
        server_port: int,
        create_time: str,
    ):
        new_node = NetworkNode(
            container_id,
            pid,
            fd,
            client_ip,
            client_port,
            server_ip,
            server_port,
            create_time,
        )
        self.nodes.append(new_node)
        self.node_by_cid_pid_fd[(container_id, pid, fd)] = new_node

    def add_file_node(self, container_id: str, ino: str, create_time: str):
        new_node = FileNode(container_id, ino, create_time)
        self.nodes.append(new_node)
        self.node_by_ino[(container_id, ino)] = new_node

    @staticmethod
    def _build_proc_key(container_id: str, pid: str, first_evt_num: str) -> tuple[str, str, str]:
        return (container_id, pid, first_evt_num)

    def add_process_node(
        self,
        container_id: str,
        pid: str,
        create_time: str,
        first_evt_num: str,
        tid: str | None = None,
    ):
        """Get or create a process node, using its first event to distinguish PID reuse."""
        key = self._build_proc_key(container_id, pid, first_evt_num)
        if key in self.node_by_proc_key:
            node = self.node_by_proc_key[key]
        else:
            node = UnitNode(container_id, tid or "null", create_time)
            node.pid = pid  # Preserve the PID alongside the thread identity.
            node.first_evt_num = first_evt_num
            self.nodes.append(node)
            self.node_by_proc_key[key] = node

        if tid:
            self.tid_to_proc_key[(container_id, tid)] = key
        return node

    def switch_unit(self, container_id: str, tid: str, unit_id: int, create_time: str):
        if (container_id, tid, unit_id) in self.node_by_tid_unit:
            cur_node = self.node_by_tid_unit[(container_id, tid, unit_id)]
            self.tid_to_proc_key[(container_id, tid)] = self._build_proc_key(
                cur_node.container_id, getattr(cur_node, "pid", cur_node.tid), getattr(cur_node, "first_evt_num", create_time)
            )
            cur_node.unit_id = str(unit_id)
        else:
            # Use TID and creation time when PID and event metadata are unavailable.
            proc_key = self._build_proc_key(container_id, tid, create_time)
            cur_node = self.add_process_node(
                container_id=container_id,
                pid=tid,
                create_time=create_time,
                first_evt_num=create_time,
                tid=tid,
            )
            cur_node.unit_id = str(unit_id)
            self.node_by_tid_unit[(container_id, tid, unit_id)] = cur_node

    def get_by_cid_pid_fd(self, container_id: str, pid: int, fd: int) -> NetworkNode:
        return self.node_by_cid_pid_fd[(container_id, pid, fd)]

    def get_by_tid(self, container_id: str, tid: str) -> UnitNode:
        key = self.tid_to_proc_key[(container_id, tid)]
        return self.node_by_proc_key[key]

    def get_by_ino(self, container_id: str, ino: str) -> FileNode:
        return self.node_by_ino[(container_id, ino)]

    def add_edge(self, source: Node, target: Node, time: str, log: dict):
        new_edge = Edge(source, target, time, log)
        self.edges.append(new_edge)
        source.out_edges.setdefault(target.ID, [])
        source.out_edges[target.ID].append(new_edge)

        target.in_edges.setdefault(source.ID, [])
        target.in_edges[source.ID].append(new_edge)
