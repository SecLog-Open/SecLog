import atexit
import json
import os
from typing import Literal

from sysdig_rules.graph import ProvGraph, UnitNode
from sysdig_rules.java import JavaRunnableProcessor
from sysdig_rules.nodejs import NodeJSProcessor
from sysdig_rules.php import PHPRequestProcessor
from sysdig_rules.python_asyncio import FastAPIProcessor

ATK_FLAG_1 = "A#t#k#F#1#"
ATK_FLAG_2 = "A#t#k#F#2#"
ATK_FLAG_3 = "A#t#k#F#3#"
ATK_FLAGS = (ATK_FLAG_1, ATK_FLAG_2, ATK_FLAG_3)


def _env_flag(name: str, default: str = "0") -> bool:
    return os.environ.get(name, default) == "1"


def _str_contains_any_atk_flag(value) -> bool:
    """True if value contains any of the three injected Attack Flag markers.

    Paper §Anchor Point Locating: attack flags are injected by the attack
    scripts / Attack Flag Scanner into payload across several transport
    channels. Each channel historically used a different flag number, but
    there is no behavioural reason to treat them differently at the
    detection site — any flag presence is an anchor. This helper
    generalises the existing single-flag checks to cover all three,
    closing the gap where some payload channels only get flag 1 or 3.
    """
    if not isinstance(value, str) or not value:
        return False
    return any(f in value for f in ATK_FLAGS)


# Behavioural anchor supplement (paper §Anchor Point Locating — rule-based
# supplement). Opt-in via env var. Default OFF so existing baselines are
# byte-equivalent. These rules do NOT consume attack flags; they detect
# generic intrusion behaviours that are suspicious regardless of runtime.
_ANCHOR_BEHAVIORAL_ON = _env_flag("SECLOG_ANCHOR_BEHAVIORAL")

# Generic interpreter / shell program names. These are POSIX-standard names,
# not app-specific. The rule is structural: a program in network-accept
# lineage that execves one of these is a classic post-exploit control
# transfer pattern (webshell / reverse shell / command injection result).
_ANCHOR_INTERPRETER_PROC_NAMES = {
    "sh", "bash", "dash", "ash", "zsh", "ksh", "tcsh", "fish",
    # Dynamic interpreters commonly abused as shells after RCE
    "python", "python2", "python3", "perl", "ruby", "php",
    # Common post-exploit tooling
    "nc", "ncat", "netcat", "socat", "busybox",
}

# Generic executable script extensions delivered to webroots. When written
# by a process inside network-accept lineage this is a classic webshell
# upload pattern; the rule does not depend on the specific app / framework.
_ANCHOR_WEBSHELL_EXTENSIONS = (
    ".php", ".phtml", ".php3", ".php4", ".php5", ".php7", ".phps",
    ".jsp", ".jspx", ".jspf", ".jhtml",
    ".asp", ".aspx", ".ashx", ".asmx",
    ".cfm", ".cgi", ".pl",
)

# Bounded upward BFS cap for "is this unit within network-accept lineage?"
# 8 hops easily covers parent→fork→exec→child chains without exploding.
_ANCHOR_NETWORK_LINEAGE_MAX_HOPS = 8


def _unit_in_network_accept_lineage(unit, max_hops: int = _ANCHOR_NETWORK_LINEAGE_MAX_HOPS) -> bool:
    """Bounded upward BFS over Unit in_edges looking for a NetworkNode source
    or a UnitNode whose is_accept is True.

    Paper §Anchor Point Locating rationale: an attacker's post-exploit
    process is by construction a descendant of the network-facing unit that
    received the attack payload. Restricting behavioural anchors to this
    lineage avoids flagging benign cron / startup processes that also exec
    shells for legitimate admin reasons.
    """
    from sysdig_rules.graph import Node, UnitNode, NetworkNode

    seen: set = {unit.ID}
    frontier = [unit]
    for _ in range(max_hops):
        nxt = []
        for u in frontier:
            if isinstance(u, UnitNode) and getattr(u, "is_accept", False):
                return True
            for src_id in list(u.in_edges.keys()):
                src = Node.ID_MAP.get(src_id)
                if src is None:
                    continue
                if isinstance(src, NetworkNode):
                    return True
                if isinstance(src, UnitNode) and src.ID not in seen:
                    seen.add(src.ID)
                    nxt.append(src)
        if not nxt:
            break
        frontier = nxt
    return False


class SysdigProcessor:
    def __init__(self, inv_dict: dict[str, str]):
        self.graph = ProvGraph()
        self.graph.unit_event_map: dict[tuple[str, int], str] = {}
        self.graph.runtime_hint_by_tid: dict[tuple[str, str], str] = {}
        self.graph.runtime_diagnostics: dict[str, dict[str, int]] = {
            "php_hook": {
                "hook_loaded_count": 0,
                "request_begin_emitted": 0,
                "request_end_emitted": 0,
                "emit_error_count": 0,
            },
            "php_processor": {
                "marker_seen_total": 0,
                "marker_parse_fail": 0,
                "begin_hit": 0,
                "end_hit": 0,
                "unknown_action": 0,
                "request_map_size_peak": 0,
            },
            "java_processor": {
                "marker_seen_total_java": 0,
                "java_begin_hit": 0,
                "java_end_hit": 0,
                "java_create_hit": 0,
                "java_unknown_action": 0,
            },
            "unit_switch": {
                "switch_unit_called": 0,
                "switch_by_runtime_php": 0,
                "switch_by_runtime_java": 0,
                "unit_event_map_nonnull_written": 0,
                "unit_event_map_null_written": 0,
                "unit_event_map_nonnull_written_by_java": 0,
            },
            # Per-rule anchor seed counters (paper §Anchor Point Locating
            # observability). Incremented when a rule raises log["malicious"]
            # to True. Lets QA answer: "why is this unit anchor? which rule
            # fired? how common is each rule per scenario?"
            "anchor_source": {
                "openat_atk_flag": 0,
                "write_evt_buffer_literal": 0,
                "write_arg_data_atk_flag": 0,
                "execve_env_malicious": 0,
                # Supplement rules (SECLOG_ANCHOR_BEHAVIORAL=1 only)
                "execve_shell_in_network_lineage": 0,
                "write_webshell_extension_in_network_lineage": 0,
                # Traffic anchor (set from analyze.anchor_point_locating)
                "traffic_ip_flags_rb": 0,
                # Mechanism counters
                "behavioral_gate_on": 1 if _ANCHOR_BEHAVIORAL_ON else 0,
            },
        }
        self.temp_log: dict[tuple[str, str], dict] = {}
        self.reversed_inv_dict: dict[str, str] = {v: k for k, v in inv_dict.items()}

        self.processors = [
            FastAPIProcessor(self.graph),
            NodeJSProcessor(self.graph),
            PHPRequestProcessor(self.graph),
            JavaRunnableProcessor(self.graph),
        ]

        atexit.register(self._export_runtime_diagnostics)

    def _export_runtime_diagnostics(self) -> None:
        diagnostics = getattr(self.graph, "runtime_diagnostics", None)
        if not isinstance(diagnostics, dict):
            return

        out_dir = "/tmp/capture_dir/diagnostics"
        try:
            os.makedirs(out_dir, exist_ok=True)

            with open(os.path.join(out_dir, "php_hook_diagnostics.json"), "w", encoding="utf-8") as fh:
                json.dump(diagnostics.get("php_hook", {}), fh, ensure_ascii=False, indent=2)
                fh.write("\n")

            with open(os.path.join(out_dir, "php_processor_diagnostics.json"), "w", encoding="utf-8") as fh:
                json.dump(diagnostics.get("php_processor", {}), fh, ensure_ascii=False, indent=2)
                fh.write("\n")

            with open(os.path.join(out_dir, "java_processor_diagnostics.json"), "w", encoding="utf-8") as fh:
                json.dump(diagnostics.get("java_processor", {}), fh, ensure_ascii=False, indent=2)
                fh.write("\n")

            with open(os.path.join(out_dir, "unit_switch_diagnostics.json"), "w", encoding="utf-8") as fh:
                json.dump(diagnostics.get("unit_switch", {}), fh, ensure_ascii=False, indent=2)
                fh.write("\n")
        except Exception:
            # Diagnostics must never break the data pipeline.
            return

    def handle_net(self, log: dict) -> bool:
        if (
            log["evt.type"] == "socket"
            or log["evt.type"] == "accept4"
            or log["evt.type"] == "accept"
        ):
            self.graph.add_net_node(
                log["container.id"],
                log["proc.vpid"],
                log["fd.num"],
                "null",
                0,
                "null",
                0,
                log["evt.datetime"],
            )

        if log["fd.cip"] in self.reversed_inv_dict:
            log["fd.cip"] = self.reversed_inv_dict[log["fd.cip"]]
        if log["fd.sip"] in self.reversed_inv_dict:
            log["fd.sip"] = self.reversed_inv_dict[log["fd.sip"]]

        client_ip = log["fd.cip"]
        client_port = log["fd.cport"]
        server_ip = log["fd.sip"]
        server_port = log["fd.sport"]
        fd = log["fd.num"]

        fd: int | Literal["null"]

        if (
            client_ip != "null"
            and client_port != "null"
            and server_ip != "null"
            and server_port != "null"
            and fd != "null"
        ):
            if (
                log["container.id"],
                log["proc.vpid"],
                fd,
            ) not in self.graph.node_by_cid_pid_fd:
                self.graph.add_net_node(
                    log["container.id"],
                    log["proc.vpid"],
                    fd,
                    client_ip,
                    client_port,
                    server_ip,
                    server_port,
                    log["evt.datetime"],
                )

            net_node = self.graph.get_by_cid_pid_fd(
                log["container.id"],
                log["proc.vpid"],
                fd,
            )
            net_node.client_ip = client_ip
            net_node.client_port = client_port
            net_node.server_ip = server_ip
            net_node.server_port = server_port

        if log["evt.type"] == "accept4" or log["evt.type"] == "accept":
            pid = log.get("proc.pid") or log.get("proc.vpid") or log["thread.vtid"]
            self.graph.add_process_node(
                container_id=log["container.id"],
                pid=str(pid),
                create_time=log["evt.datetime"],
                first_evt_num=str(log.get("evt.num")),
                tid=log["thread.vtid"],
            )
            self.graph.get_by_tid(log["container.id"], log["thread.vtid"]).is_accept = True

            if not (
                client_ip == "null"
                or client_port == "null"
                or server_ip == "null"
                or server_port == "null"
                or fd == "null"
            ):
                self.graph.add_edge(
                    self.graph.get_by_cid_pid_fd(
                        log["container.id"],
                        log["proc.vpid"],
                        fd,
                    ),
                    self.graph.get_by_tid(log["container.id"], log["thread.vtid"]),
                    log["evt.datetime"],
                    log,
                )

        if log["evt.is_io_read"] is True:
            if not (
                client_ip == "null"
                or client_port == "null"
                or server_ip == "null"
                or server_port == "null"
                or fd == "null"
            ):
                self.graph.add_edge(
                    self.graph.get_by_cid_pid_fd(
                        log["container.id"],
                        log["proc.vpid"],
                        fd,
                    ),
                    self.graph.get_by_tid(log["container.id"], log["thread.vtid"]),
                    log["evt.datetime"],
                    log,
                )

        if log["evt.is_io_write"] is True:
            if not (
                client_ip == "null"
                or client_port == "null"
                or server_ip == "null"
                or server_port == "null"
            ):
                self.graph.add_edge(
                    self.graph.get_by_tid(log["container.id"], log["thread.vtid"]),
                    self.graph.get_by_cid_pid_fd(
                        log["container.id"],
                        log["proc.vpid"],
                        fd,
                    ),
                    log["evt.datetime"],
                    log,
                )

        return True

    def handle_file(self, log: dict) -> bool:
        cur_fid = (log["container.id"], log["fd.ino"])

        for processor in self.processors:
            if processor.process(log):
                return True

        # Represent file opens as explicit process-to-file edges.
        if log["evt.type"] in ["open", "openat", "creat"] and log["fd.name"] != "null":
            # Paper §Anchor Point Locating: Attack Flag Scanner may stamp any
            # of the 3 flags into payload; detection should not privilege
            # flag 2. Check all three generically.
            if _str_contains_any_atk_flag(log.get("fd.name")):
                log["malicious"] = True
                log["malicious_seed_rule"] = "openat_atk_flag"
                self.graph.runtime_diagnostics["anchor_source"]["openat_atk_flag"] += 1
            if cur_fid not in self.graph.node_by_ino and log["fd.ino"] != "null":
                self.graph.add_file_node(
                    log["container.id"], log["fd.ino"], log["evt.datetime"]
                )
            if log["fd.ino"] != "null":
                edge_log = dict(log)
                evt_num = edge_log.get("evt.num")
                edge_log["evt.type"] = "open"
                edge_log["evidence_event_keys"] = [f"sysdig:{evt_num}"]
                edge_log["evidence_events"] = [
                    {
                        "event_key": f"sysdig:{evt_num}",
                        "event_id": evt_num,
                        "source_type": "sysdig",
                    }
                ]
                if edge_log.get("fd.name", "").endswith(".so") and not edge_log.get(
                    "fd.name", ""
                ).startswith("/lib"):
                    edge_log["suspicious_core"] = True

                self.graph.add_edge(
                    self.graph.get_by_tid(log["container.id"], log["thread.vtid"]),
                    self.graph.get_by_ino(log["container.id"], log["fd.ino"]),
                    log["evt.datetime"],
                    edge_log,
                )

        if log["evt.type"] == "write":
            if log.get("evt.buffer") == "malicious":
                log["malicious"] = True
                log["malicious_seed_rule"] = "write_evt_buffer_literal"
                self.graph.runtime_diagnostics["anchor_source"]["write_evt_buffer_literal"] += 1
            elif _str_contains_any_atk_flag(str(log.get("evt.arg.data") or "")):
                log["malicious"] = True
                log["malicious_seed_rule"] = "write_arg_data_atk_flag"
                self.graph.runtime_diagnostics["anchor_source"]["write_arg_data_atk_flag"] += 1

            # A6 (SECLOG_ANCHOR_BEHAVIORAL=1): writes of executable-script
            # extensions from a process inside network-accept lineage are a
            # classic webshell-upload pattern. Structural: depends only on
            # graph in-edges + universal extension set, not on app name.
            if _ANCHOR_BEHAVIORAL_ON and log.get("malicious") is not True:
                _fname = str(log.get("fd.name") or "")
                if _fname and any(
                    _fname.lower().endswith(ext) for ext in _ANCHOR_WEBSHELL_EXTENSIONS
                ):
                    _owner = self.graph.get_by_tid(log["container.id"], log["thread.vtid"])
                    if _owner is not None and _unit_in_network_accept_lineage(_owner):
                        log["malicious"] = True
                        log["malicious_seed_rule"] = "write_webshell_extension_in_network_lineage"
                        self.graph.runtime_diagnostics["anchor_source"][
                            "write_webshell_extension_in_network_lineage"
                        ] += 1

        # Connect mapped shared objects to the process that loads them.
        if log["evt.type"] == "mmap":
            fd_name = log.get("fd.name", "")
            fd_ino = log.get("fd.ino")
            if fd_ino and fd_ino != "null":
                if (log["container.id"], fd_ino) not in self.graph.node_by_ino:
                    self.graph.add_file_node(
                        log["container.id"], fd_ino, log["evt.datetime"]
                    )
                edge_log = dict(log)
                evt_num = edge_log.get("evt.num")
                edge_log["evidence_event_keys"] = [f"sysdig:{evt_num}"]
                edge_log["evidence_events"] = [
                    {
                        "event_key": f"sysdig:{evt_num}",
                        "event_id": evt_num,
                        "source_type": "sysdig",
                    }
                ]
                if fd_name.endswith(".so") and not fd_name.startswith("/lib"):
                    edge_log["suspicious_core"] = True
                self.graph.add_edge(
                    self.graph.get_by_tid(log["container.id"], log["thread.vtid"]),
                    self.graph.get_by_ino(log["container.id"], fd_ino),
                    log["evt.datetime"],
                    edge_log,
                )

        if log["evt.is_io_read"] is True:
            if cur_fid not in self.graph.node_by_ino:
                self.graph.add_file_node(
                    log["container.id"], log["fd.ino"], log["evt.datetime"]
                )
            self.graph.add_edge(
                self.graph.get_by_ino(log["container.id"], log["fd.ino"]),
                self.graph.get_by_tid(log["container.id"], log["thread.vtid"]),
                log["evt.datetime"],
                log,
            )

        if log["evt.is_io_write"] is True:
            if cur_fid not in self.graph.node_by_ino:
                self.graph.add_file_node(
                    log["container.id"], log["fd.ino"], log["evt.datetime"]
                )
            self.graph.add_edge(
                self.graph.get_by_tid(log["container.id"], log["thread.vtid"]),
                self.graph.get_by_ino(log["container.id"], log["fd.ino"]),
                log["evt.datetime"],
                log,
            )

        return True

    def handle_process(self, log: dict) -> bool:
        evt_type = log["evt.type"]
        evt_num = log.get("evt.num")
        container_id = log["container.id"]
        tid = log["thread.vtid"]
        pid = log.get("proc.pid") or log.get("proc.vpid") or log.get("thread.tid") or tid

        # Split process identities at exec and connect them with an exec edge.
        if evt_type in ["execve", "execveat"]:
            # Honor the malicious environment marker.
            if log.get("proc.env[malicious]") == "true":
                log["malicious"] = True
                log["malicious_seed_rule"] = "execve_env_malicious"
                self.graph.runtime_diagnostics["anchor_source"]["execve_env_malicious"] += 1

            # A5 (SECLOG_ANCHOR_BEHAVIORAL=1): post-exploit control-flow
            # transfer. A unit in network-accept lineage that execves a
            # shell/interpreter is the classic RCE pattern. Matches the
            # paper's Anchor Point Locating supplement rule spirit:
            # structural (graph lineage) + universal program-name set, no
            # app/CVE dispatch.
            if _ANCHOR_BEHAVIORAL_ON and log.get("malicious") is not True:
                _proc_name = str(log.get("proc.name") or "")
                _argv0 = str(log.get("evt.arg.filename") or "")
                if _argv0:
                    _argv_base = os.path.basename(_argv0).lower()
                else:
                    _argv_base = ""
                _match_name = _proc_name.lower() in _ANCHOR_INTERPRETER_PROC_NAMES
                _match_argv = _argv_base in _ANCHOR_INTERPRETER_PROC_NAMES
                if (_match_name or _match_argv):
                    _owner = self.graph.get_by_tid(container_id, tid)
                    if _owner is not None and _unit_in_network_accept_lineage(_owner):
                        log["malicious"] = True
                        log["malicious_seed_rule"] = "execve_shell_in_network_lineage"
                        self.graph.runtime_diagnostics["anchor_source"][
                            "execve_shell_in_network_lineage"
                        ] += 1

            # Resolve the process identity before exec.
            if (container_id, tid) not in self.graph.tid_to_proc_key:
                # Create the pre-exec node if no TID mapping is available.
                self.graph.add_process_node(
                    container_id=container_id,
                    pid=str(pid),
                    create_time=log["evt.datetime"],
                    first_evt_num=str(evt_num),
                    tid=tid,
                )
            old_proc = self.graph.get_by_tid(container_id, tid)

            # Include the current event number to distinguish the post-exec identity.
            new_proc = self.graph.add_process_node(
                container_id=container_id,
                pid=str(pid),
                create_time=log["evt.datetime"],
                first_evt_num=str(evt_num),
                tid=tid,
            )

            # Connect the pre-exec and post-exec process nodes.
            edge_log = dict(log)
            edge_log["evt.type"] = "exec"
            edge_log["evidence_event_keys"] = [f"sysdig:{evt_num}"]
            edge_log["evidence_events"] = [
                {
                    "event_key": f"sysdig:{evt_num}",
                    "event_id": evt_num,
                    "source_type": "sysdig",
                }
            ]
            self.graph.add_edge(
                old_proc,
                new_proc,
                log["evt.datetime"],
                edge_log,
            )

            return True

        # Represent clone, fork, and vfork as parent-to-child process edges.
        if evt_type in ["clone", "fork", "vfork"]:
            parent_tid = log["thread.vtid"]
            child_tid = log["evt.rawres"]
            parent_pid = log.get("proc.pid") or log.get("proc.vpid") or parent_tid
            child_pid = log.get("evt.arg.res") or log.get("proc.pid") or child_tid
            first_evt_num = str(evt_num)

            if child_tid == "0":
                return True

            child_node = self.graph.add_process_node(
                container_id=log["container.id"],
                pid=str(child_pid),
                create_time=log["evt.datetime"],
                first_evt_num=first_evt_num,
                tid=child_tid,
            )

            self.graph.add_edge(
                self.graph.get_by_tid(log["container.id"], parent_tid),
                child_node,
                log["evt.datetime"],
                log,
            )

        return True

    def add_log_to_node(self, node: UnitNode, log: dict):
        del log["evt.buffer"]
        del log["proc.env[malicious]"]
        del log[">"]
        del log["evt.dir"]

        log_keys = list(log.keys())
        for key in log_keys:
            if isinstance(log[key], str):
                val = log[key]
                val = val.replace(ATK_FLAG_1, "")
                val = val.replace(ATK_FLAG_2, "")
                val = val.replace(ATK_FLAG_3, "")
                log[key] = val
            if log[key] == "null":
                log[key] = None

        if log["malicious"] is True:
            node.is_malicious = True

        container_id = log.get("container.id")
        evt_num = log.get("evt.num")
        if container_id is not None and evt_num is not None:
            try:
                unit_id_val = str(node.unit_id or "null")
                self.graph.unit_event_map[(str(container_id), int(evt_num))] = unit_id_val
                switch_diag = self.graph.runtime_diagnostics.get("unit_switch", {})
                if unit_id_val == "null":
                    switch_diag["unit_event_map_null_written"] = int(switch_diag.get("unit_event_map_null_written", 0)) + 1
                else:
                    switch_diag["unit_event_map_nonnull_written"] = int(switch_diag.get("unit_event_map_nonnull_written", 0)) + 1
                    runtime_hint = getattr(self.graph, "runtime_hint_by_tid", {}).get(
                        (str(container_id), str(log.get("thread.vtid")))
                    )
                    if runtime_hint == "java":
                        switch_diag["unit_event_map_nonnull_written_by_java"] = int(
                            switch_diag.get("unit_event_map_nonnull_written_by_java", 0)
                        ) + 1
            except (TypeError, ValueError):
                pass

        node.logs.append(log)

    def process(self, log: dict):
        container_id = log["container.id"]
        tid = log["thread.vtid"]
        pid = log.get("proc.pid") or log.get("proc.vpid") or log.get("thread.tid") or tid
        first_evt_num = str(log.get("evt.num"))
        cur_tid = (container_id, tid)
        if log["evt.dir"] == ">":
            self.temp_log[cur_tid] = log
            return
        if cur_tid in self.temp_log:
            log[">"] = self.temp_log[cur_tid]
        else:
            log[">"] = {}

        log["malicious"] = False

        # A reused TID with a different PID requires a new process node.
        existing = self.graph.tid_to_proc_key.get(cur_tid)
        need_new_proc = False
        if existing:
            existing_node = self.graph.node_by_proc_key[existing]
            if getattr(existing_node, "pid", None) != str(pid):
                need_new_proc = True

        if (cur_tid not in self.graph.tid_to_proc_key) or need_new_proc:
            self.graph.add_process_node(
                container_id=container_id,
                pid=str(pid),
                create_time=log["evt.datetime"],
                first_evt_num=first_evt_num,
                tid=tid,
            )

        cur_node = self.graph.get_by_tid(container_id, tid)

        if log["evt.category"] == "net":
            res = self.handle_net(log)
        elif log["evt.category"] == "file":
            res = self.handle_file(log)
        elif log["evt.category"] == "process":
            res = self.handle_process(log)
        else:
            return

        if (log["container.id"], log["thread.vtid"]) in self.graph.tid_to_proc_key:
            cur_node = self.graph.get_by_tid(log["container.id"], log["thread.vtid"])

        if res and not log.get("_skip_raw_output", False):
            self.add_log_to_node(cur_node, log)
