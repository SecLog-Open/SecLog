from sysdig_rules.graph import ProvGraph


class JavaRunnableProcessor:
    def __init__(self, graph: ProvGraph):
        self.graph = graph
        self.unit_id: int = 0
        self.nodeid_to_unit: dict[int, int] = dict()
        self.handler_to_unit: dict[str, int] = dict()
        self.handler_to_parent_node: dict[str, int] = dict()

        self.handler_stacks: dict[tuple[str, str], list[int]] = dict()

    def new_unit_id(self) -> int:
        self.unit_id += 1
        return self.unit_id

    def process(self, log: dict) -> bool:
        diagnostics = getattr(self.graph, "runtime_diagnostics", {})
        java_diag = diagnostics.get("java_processor", {})
        switch_diag = diagnostics.get("unit_switch", {})

        if (
            log["evt.type"] == "write"
            and log["evt.arg.data"].startswith("JV_")
            and log["fd.name"] == "/dev/null"
        ):
            java_diag["marker_seen_total_java"] = int(
                java_diag.get("marker_seen_total_java", 0)
            ) + 1
            handler_id = str(log["evt.arg.data"].rpartition(" ")[-1])

            if "END" in log["evt.arg.data"]:
                java_diag["java_end_hit"] = int(java_diag.get("java_end_hit", 0)) + 1
                # Remove the TID mapping; process nodes remain keyed by PID.
                if (
                    log["container.id"],
                    log["thread.vtid"],
                ) not in self.handler_stacks or len(
                    self.handler_stacks[(log["container.id"], log["thread.vtid"])]
                ) < 2:
                    self.graph.tid_to_proc_key.pop(
                        (log["container.id"], log["thread.vtid"]), None
                    )
                    self.handler_stacks[(log["container.id"], log["thread.vtid"])] = []
                else:
                    self.handler_stacks[(log["container.id"], log["thread.vtid"])].pop()
                    unit_id = self.handler_stacks[
                        (log["container.id"], log["thread.vtid"])
                    ][-1]
                    self.graph.runtime_hint_by_tid[
                        (str(log["container.id"]), str(log["thread.vtid"]))
                    ] = "java"
                    self.graph.switch_unit(
                        log["container.id"],
                        log["thread.vtid"],
                        unit_id,
                        log["evt.datetime"],
                    )
                    switch_diag["switch_unit_called"] = int(
                        switch_diag.get("switch_unit_called", 0)
                    ) + 1
                    switch_diag["switch_by_runtime_java"] = int(
                        switch_diag.get("switch_by_runtime_java", 0)
                    ) + 1

            else:
                if "CREATE" in log["evt.arg.data"]:
                    java_diag["java_create_hit"] = int(
                        java_diag.get("java_create_hit", 0)
                    ) + 1
                    cur_node = self.graph.get_by_tid(
                        log["container.id"], log["thread.vtid"]
                    )
                    self.nodeid_to_unit.setdefault(cur_node.ID, self.new_unit_id())
                    cur_unit_id = self.nodeid_to_unit[cur_node.ID]

                    self.handler_to_unit[handler_id] = cur_unit_id

                    if (
                        log["container.id"],
                        log["thread.vtid"],
                        cur_unit_id,
                    ) not in self.graph.node_by_tid_unit:
                        self.graph.node_by_tid_unit[
                            (log["container.id"], log["thread.vtid"], cur_unit_id)
                        ] = cur_node

                    self.handler_to_parent_node[handler_id] = cur_node.ID

                if "START" in log["evt.arg.data"]:
                    java_diag["java_begin_hit"] = int(
                        java_diag.get("java_begin_hit", 0)
                    ) + 1
                    if handler_id in self.handler_to_unit:
                        unit_id = self.handler_to_unit[handler_id]
                    else:
                        unit_id = self.new_unit_id()
                        self.handler_to_unit[handler_id] = unit_id
                        self.handler_to_parent_node[handler_id] = -1

                    self.handler_stacks.setdefault(
                        (log["container.id"], log["thread.vtid"]), []
                    ).append(unit_id)

                    self.graph.runtime_hint_by_tid[
                        (str(log["container.id"]), str(log["thread.vtid"]))
                    ] = "java"
                    self.graph.switch_unit(
                        log["container.id"],
                        log["thread.vtid"],
                        self.handler_to_unit[handler_id],
                        log["evt.datetime"],
                    )
                    switch_diag["switch_unit_called"] = int(
                        switch_diag.get("switch_unit_called", 0)
                    ) + 1
                    switch_diag["switch_by_runtime_java"] = int(
                        switch_diag.get("switch_by_runtime_java", 0)
                    ) + 1

                    cur_node = self.graph.get_by_tid(
                        log["container.id"], log["thread.vtid"]
                    )

                    if self.handler_to_parent_node[handler_id] != -1:
                        parent_node = self.graph.nodes[
                            self.handler_to_parent_node[handler_id]
                        ]
                        self.graph.add_edge(
                            parent_node,
                            cur_node,
                            log["evt.datetime"],
                            log,
                        )
                        self.graph.add_edge(
                            cur_node,
                            parent_node,
                            log["evt.datetime"],
                            log,
                        )

                if (
                    "CREATE" not in log["evt.arg.data"]
                    and "START" not in log["evt.arg.data"]
                ):
                    java_diag["java_unknown_action"] = int(
                        java_diag.get("java_unknown_action", 0)
                    ) + 1

            return True
        else:
            return False
