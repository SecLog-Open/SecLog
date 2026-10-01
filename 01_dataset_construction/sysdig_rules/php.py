from sysdig_rules.graph import ProvGraph


class PHPRequestProcessor:
    def __init__(self, graph: ProvGraph):
        self.graph = graph
        self.unit_id: int = 0
        self.request_to_unit: dict[tuple[str, str], int] = {}

    def new_unit_id(self) -> int:
        self.unit_id += 1
        return self.unit_id

    def process(self, log: dict) -> bool:
        diagnostics = getattr(self.graph, "runtime_diagnostics", {})
        hook_diag = diagnostics.get("php_hook", {})
        proc_diag = diagnostics.get("php_processor", {})
        switch_diag = diagnostics.get("unit_switch", {})

        if (
            log.get("evt.type") != "write"
            or log.get("fd.name") != "/dev/null"
        ):
            return False

        payload = str(log.get("evt.arg.data") or "")
        if not payload.startswith("furina-php-ins "):
            return False

        proc_diag["marker_seen_total"] = int(proc_diag.get("marker_seen_total", 0)) + 1

        parts = payload.split(" ", 3)
        if len(parts) < 3:
            proc_diag["marker_parse_fail"] = int(proc_diag.get("marker_parse_fail", 0)) + 1
            return False

        action = parts[1]
        request_id = parts[2]
        container_id = log["container.id"]
        tid = log["thread.vtid"]
        request_key = (container_id, request_id)

        # Internal marker events must never be exported into raw/sysdig outputs.
        log["_skip_raw_output"] = True

        if action == "hook_loaded":
            hook_diag["hook_loaded_count"] = int(hook_diag.get("hook_loaded_count", 0)) + 1
            return True

        if action == "emit_error":
            hook_diag["emit_error_count"] = int(hook_diag.get("emit_error_count", 0)) + 1
            return True

        if action == "request_begin":
            hook_diag["request_begin_emitted"] = int(hook_diag.get("request_begin_emitted", 0)) + 1
            proc_diag["begin_hit"] = int(proc_diag.get("begin_hit", 0)) + 1
            cur_node = self.graph.get_by_tid(container_id, tid)
            unit_id = self.request_to_unit.setdefault(request_key, self.new_unit_id())
            self.graph.node_by_tid_unit.setdefault((container_id, tid, unit_id), cur_node)
            self.graph.switch_unit(
                container_id,
                tid,
                unit_id,
                log["evt.datetime"],
            )
            switch_diag["switch_unit_called"] = int(switch_diag.get("switch_unit_called", 0)) + 1
            switch_diag["switch_by_runtime_php"] = int(switch_diag.get("switch_by_runtime_php", 0)) + 1
            proc_diag["request_map_size_peak"] = max(
                int(proc_diag.get("request_map_size_peak", 0)),
                len(self.request_to_unit),
            )
            return True

        if action == "request_end":
            hook_diag["request_end_emitted"] = int(hook_diag.get("request_end_emitted", 0)) + 1
            proc_diag["end_hit"] = int(proc_diag.get("end_hit", 0)) + 1
            self.request_to_unit.pop(request_key, None)
            self.graph.tid_to_proc_key.pop((container_id, tid), None)
            return True

        proc_diag["unknown_action"] = int(proc_diag.get("unknown_action", 0)) + 1
        return False