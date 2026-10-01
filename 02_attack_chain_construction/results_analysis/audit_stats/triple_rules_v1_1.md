# Audit Triple Rules v1.1

This document describes the normalized audit-triple mapping in
`triple_rules_v1_1.json`. Stage 02 uses these rules to convert syscall records
from the raw Sysdig stream into typed behavior-chain edges.

## Core mapping

| Raw event type | Normalized relation | Triple pattern |
| --- | --- | --- |
| `openat`, `open` | `FILE_OPEN` | process -> file |
| `read`, `pread`, `readv` | `FILE_READ` | process -> file |
| `write`, `pwrite`, `writev` | `FILE_WRITE` | process -> file |
| `execve` | `PROCESS_EXEC` | process -> file |
| `clone`, `clone3`, `fork`, `vfork` | `PROCESS_FORK` | process -> process |
| `connect` | `NET_CONNECT` | process -> connection |
| `accept`, `accept4` | `NET_ACCEPT` | process -> connection |
| `sendto` | `NET_SEND` | process -> connection |
| `recvfrom` | `NET_RECV` | process -> connection |

The JSON rule file additionally lists auxiliary and filtered event types. The
extractor keeps those categories separate so downstream chain construction can
choose the appropriate evidence tier.

## Entity keys

- Process: `proc:{container_id}:{pid}:{executable}`. A missing container ID
  becomes `host`; PID uses `proc.pid`, then `proc.vpid`, then `unknown_pid`;
  executable uses `proc.exepath`, then `proc.name`, then `unknown_exe`.
- File: `file:{path}`. Event filename and descriptor fields are preferred;
  rename paths are used when present.
- Connection: `conn:{src_ip}:{src_port}->{dst_ip}:{dst_port}`. Events sharing
  one unordered four-tuple reuse one canonical directed key. If direction is
  not observable, the first-seen direction is retained with a direction hint.
- Child process: `proc:{container_id}:{child_pid}:{executable_or_unknown}`.
  Child pid comes from the event argument or raw result when available.

## Attributes and outputs

Every normalized edge retains raw event type, event number, timestamp, and the
source process, descriptor, file, or connection fields required for audit
traceability. The stage-02 extractor writes categorized JSONL files and a
per-run relation summary under the input run's `chain/` directory.
