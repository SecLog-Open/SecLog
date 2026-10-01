# Audit Triple Rules v1

This document describes the normalized audit-triple mapping in
`triple_rules_v1.json`. Select this rule set with the extractor's
`--rules-file` option. It maps syscall records to process, file, connection,
and child-process relations. The standard stage-02 pipeline uses
`triple_rules_v1_1.json`.

## Core mapping

| Raw event type | Normalized relation | Triple pattern |
| --- | --- | --- |
| `openat`, `open` | `FILE_OPEN` | process -> file |
| `read` | `FILE_READ` | process -> file |
| `write` | `FILE_WRITE` | process -> file |
| `execve` | `PROCESS_EXEC` | process -> file |
| `clone` | `PROCESS_FORK` | process -> process |
| `connect` | `NET_CONNECT` | process -> connection |
| `accept4` | `NET_ACCEPT` | process -> connection |
| `sendto` | `NET_SEND` | process -> connection |
| `recvfrom` | `NET_RECV` | process -> connection |

The JSON rule file also defines auxiliary and filtered event types. The
extractor writes each category to its corresponding stage-02 chain artifact.

## Entity keys

- Process: `proc:{container_id}:{pid}:{executable}`. Container id, pid, and
  executable use the documented fallback fields when a preferred field is
  absent.
- File: `file:{path}`. The path is selected from the event filename, file
  descriptor name, or rename fields.
- Connection: `conn:{src_ip}:{src_port}->{dst_ip}:{dst_port}`. A connection
  tuple is reused across connect, accept, send, and receive events.
- Child process: `proc:{container_id}:{child_pid}:{executable_or_unknown}`.

## Attributes and outputs

Normalized edges retain the raw event type, event number, timestamp, and
source-specific process, file, descriptor, and connection fields needed to
trace an edge back to its input record. Stage-02 output files are written
under the input run's `chain/` directory.
