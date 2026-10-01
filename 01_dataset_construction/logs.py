import os
import signal
import subprocess
import threading
import time
from collections import deque
from datetime import datetime
from typing import Any

from rich import print

from schema import Scene
from utils import client

CAPTURED_PATH = "/tmp/capture_dir"
CAPTURED_SYSDIG_PATH = CAPTURED_PATH + "/capture.scap"
SYSDIG_STDOUT_LOG_PATH = "/tmp/sysdig_output.log"
SYSDIG_STDERR_LOG_PATH = "/tmp/sysdig_error.log"
SYSDIG_FAILURE_CONTEXT_PATH = "/tmp/sysdig_failure_context.log"


COLLECTOR_WATCHDOG_INTERVAL_SEC = 1.0
COLLECTOR_STREAM_TAIL_LINES = 80

_collector_lock = threading.Lock()
_collector_entries: list[dict[str, Any]] = []
_collector_failure_message: str | None = None
_collector_watchdog_stop = threading.Event()
_collector_watchdog_thread: threading.Thread | None = None
_collector_kill_signal_sent = False
_capture_directory_prepared = False


def prepare_capture_directory():
    """Prepare capture storage only when a scenario is about to run.

    Importing the CLI must stay side-effect free so ``--help`` and release
    validation do not prompt for deletion or create ``/tmp/capture_dir``.
    """
    global _capture_directory_prepared
    if _capture_directory_prepared:
        return
    if os.path.exists(CAPTURED_PATH):
        if os.environ.get("BATCH", "0") != "0":
            is_overwrite = "y"
        else:
            is_overwrite = input("The capture directory already exists, overwrite? (y/n)")
        if is_overwrite.lower() != "y":
            raise Exception("Capture directory already exists")
        subprocess.run(["sudo", "rm", "-rf", CAPTURED_PATH], check=True)

    os.makedirs(CAPTURED_PATH)
    os.chmod(CAPTURED_PATH, 0o777)
    _capture_directory_prepared = True


def _tail_text_file(path: str, max_lines: int = 20) -> str:
    try:
        tail_lines: deque[str] = deque(maxlen=max_lines)
        with open(path, "r", errors="ignore") as f:
            for line in f:
                tail_lines.append(line)
        return "".join(tail_lines).strip()
    except Exception:
        return ""


def _format_epoch(ts: float | None) -> str:
    if ts is None:
        return "n/a"
    return datetime.fromtimestamp(ts).isoformat(timespec="seconds")


def _start_stream_tail_reader(
    stream,
    sink_path: str,
    tail_cache: deque[str],
    stream_name: str,
) -> threading.Thread:
    def _reader():
        try:
            with open(sink_path, "w", encoding="utf-8", errors="ignore") as sink:
                if stream is None:
                    return
                while True:
                    line = stream.readline()
                    if not line:
                        break
                    tail_cache.append(line.rstrip("\n"))
                    sink.write(line)
                    sink.flush()
        except Exception as e:
            tail_cache.append(f"[{stream_name} reader exception] {e}")
        finally:
            try:
                if stream is not None:
                    stream.close()
            except Exception:
                pass

    t = threading.Thread(target=_reader, name=f"{stream_name}-tail-reader", daemon=True)
    t.start()
    return t


def _write_sysdig_failure_context(entry: dict[str, Any], return_code: int) -> str:
    process = entry.get("process")
    pid = process.pid if isinstance(process, subprocess.Popen) else "n/a"
    start_time = entry.get("start_time")
    end_time = time.time()
    command = entry.get("command")
    if isinstance(command, list):
        command_text = " ".join(str(x) for x in command)
    else:
        command_text = str(command)

    stdout_tail_cache = entry.get("stdout_tail_cache")
    stderr_tail_cache = entry.get("stderr_tail_cache")
    stdout_path = str(entry.get("stdout_path") or SYSDIG_STDOUT_LOG_PATH)
    stderr_path = str(entry.get("stderr_path") or SYSDIG_STDERR_LOG_PATH)

    if isinstance(stdout_tail_cache, deque) and len(stdout_tail_cache) > 0:
        stdout_tail = "\n".join(stdout_tail_cache)
    else:
        stdout_tail = _tail_text_file(stdout_path, COLLECTOR_STREAM_TAIL_LINES)

    if isinstance(stderr_tail_cache, deque) and len(stderr_tail_cache) > 0:
        stderr_tail = "\n".join(stderr_tail_cache)
    else:
        stderr_tail = _tail_text_file(stderr_path, COLLECTOR_STREAM_TAIL_LINES)

    try:
        capture_size = os.path.getsize(CAPTURED_SYSDIG_PATH)
    except Exception:
        capture_size = -1

    lines = [
        "[sysdig_failure_context]",
        f"collector_name={entry.get('name', 'sysdig')}",
        f"pid={pid}",
        f"command={command_text}",
        f"start_time={_format_epoch(start_time if isinstance(start_time, (float, int)) else None)}",
        f"end_time={_format_epoch(end_time)}",
        f"return_code={return_code}",
        f"capture_scap_path={CAPTURED_SYSDIG_PATH}",
        f"capture_scap_size_bytes={capture_size}",
        "scap_last_event_time=unavailable_without_full_scan",
        f"stdout_log_path={stdout_path}",
        f"stderr_log_path={stderr_path}",
        "--- last_stdout_lines ---",
        stdout_tail if stdout_tail else "<empty>",
        "--- last_stderr_lines ---",
        stderr_tail if stderr_tail else "<empty>",
        "",
    ]

    with open(SYSDIG_FAILURE_CONTEXT_PATH, "w", encoding="utf-8", errors="ignore") as f:
        f.write("\n".join(lines))

    return SYSDIG_FAILURE_CONTEXT_PATH


def _register_collector_process(
    name: str,
    process: subprocess.Popen,
    stderr_path: str | None = None,
    stdout_path: str | None = None,
    command: list[str] | None = None,
    start_time: float | None = None,
    stdout_tail_cache: deque[str] | None = None,
    stderr_tail_cache: deque[str] | None = None,
):
    with _collector_lock:
        _collector_entries.append(
            {
                "name": name,
                "process": process,
                "stderr_path": stderr_path,
                "stdout_path": stdout_path,
                "command": command,
                "start_time": start_time,
                "stdout_tail_cache": stdout_tail_cache,
                "stderr_tail_cache": stderr_tail_cache,
            }
        )


def _set_collector_failure(message: str):
    global _collector_failure_message, _collector_kill_signal_sent

    with _collector_lock:
        if _collector_failure_message is None:
            _collector_failure_message = message
            print(f"[Collector Monitor] FAILURE: {message}")

    if not _collector_kill_signal_sent:
        _collector_kill_signal_sent = True
        try:
            os.kill(os.getpid(), signal.SIGTERM)
        except Exception:
            # If signaling fails, explicit checks in scene/main still surface the failure.
            pass


def assert_logging_healthy():
    with _collector_lock:
        failure = _collector_failure_message

    if failure is not None:
        raise RuntimeError(f"Collector health check failed: {failure}")


def _collector_watchdog_loop():
    while not _collector_watchdog_stop.is_set():
        with _collector_lock:
            snapshot = list(_collector_entries)

        for entry in snapshot:
            process: subprocess.Popen = entry["process"]
            name = str(entry["name"])
            return_code = process.poll()
            if return_code is None:
                continue

            stderr_path = entry.get("stderr_path")
            detail = ""
            if isinstance(stderr_path, str) and stderr_path:
                tail = _tail_text_file(stderr_path)
                if tail:
                    detail = f" stderr_tail={tail!r}"

            context_path = ""
            if name == "sysdig":
                try:
                    context_path = _write_sysdig_failure_context(entry, int(return_code))
                except Exception as e:
                    context_path = f"<failed_to_write_context:{e}>"
                detail += f" context={context_path}"

            _set_collector_failure(
                f"collector={name} exited unexpectedly return_code={return_code}.{detail}"
            )
            return

        _collector_watchdog_stop.wait(COLLECTOR_WATCHDOG_INTERVAL_SEC)


def _start_collector_watchdog():
    global _collector_watchdog_thread

    if _collector_watchdog_thread is not None and _collector_watchdog_thread.is_alive():
        return

    _collector_watchdog_stop.clear()
    _collector_watchdog_thread = threading.Thread(
        target=_collector_watchdog_loop,
        name="collector-watchdog",
        daemon=True,
    )
    _collector_watchdog_thread.start()
    print("[Collector Monitor] watchdog started")


def stop_logging_watchdog():
    global _collector_watchdog_thread

    _collector_watchdog_stop.set()
    if _collector_watchdog_thread is not None:
        _collector_watchdog_thread.join(timeout=2.0)
        _collector_watchdog_thread = None
    print("[Collector Monitor] watchdog stopped")


def _reset_logging_state():
    global _collector_entries, _collector_failure_message, _collector_kill_signal_sent
    with _collector_lock:
        _collector_entries = []
        _collector_failure_message = None
        _collector_kill_signal_sent = False


def start_sysdig_log(container_ids: list[str]):
    assert len(container_ids) > 0

    print("[Starting Sysdig Logging]")

    container_id_rule = " or ".join(
        [f"container.id='{container_id[:12]}'" for container_id in container_ids]
    )

    filter_rule = "({})".format(
        " and ".join(
            [
                "(evt.category=net or evt.category=file or evt.category=process)",
                "container.id!='host'",
                "container.id!=''",
                f"({container_id_rule})",
            ]
        )
    )

    sysdig_command = [
        "sudo",
        "sysdig",
        filter_rule,
        "-w",
        CAPTURED_SYSDIG_PATH,
    ]

    print(sysdig_command)

    stdout_tail_cache: deque[str] = deque(maxlen=COLLECTOR_STREAM_TAIL_LINES)
    stderr_tail_cache: deque[str] = deque(maxlen=COLLECTOR_STREAM_TAIL_LINES)
    start_time = time.time()

    sysdig_process = subprocess.Popen(
        sysdig_command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        bufsize=1,
    )

    _start_stream_tail_reader(
        sysdig_process.stdout,
        SYSDIG_STDOUT_LOG_PATH,
        stdout_tail_cache,
        "sysdig-stdout",
    )
    _start_stream_tail_reader(
        sysdig_process.stderr,
        SYSDIG_STDERR_LOG_PATH,
        stderr_tail_cache,
        "sysdig-stderr",
    )

    time.sleep(2)
    if sysdig_process.poll() is not None:
        error_message = _tail_text_file(SYSDIG_STDERR_LOG_PATH, COLLECTOR_STREAM_TAIL_LINES)
        raise RuntimeError(f"Sysdig failed to start: {error_message}")

    _register_collector_process(
        name="sysdig",
        process=sysdig_process,
        stderr_path=SYSDIG_STDERR_LOG_PATH,
        stdout_path=SYSDIG_STDOUT_LOG_PATH,
        command=sysdig_command,
        start_time=start_time,
        stdout_tail_cache=stdout_tail_cache,
        stderr_tail_cache=stderr_tail_cache,
    )
    print(
        f"[Collector Monitor] sysdig started pid={sysdig_process.pid} "
        f"start_time={_format_epoch(start_time)}"
    )


def execute_nsenter_command(pid: int, command: str):
    nsenter_command = [
        "sudo",
        "nsenter",
        "--target",
        str(pid),
        "--net",
        "--",
        "sh",
        "-c",
        command,
    ]
    result = subprocess.run(nsenter_command, capture_output=True, text=True)
    return result.stdout


def list_network_devices(pid: int):
    command = "ip a"
    output = execute_nsenter_command(pid, command)
    return output


def capture_traffic(pid: int, container_id: str):
    devices_output = list_network_devices(pid)
    devices = []
    for line in devices_output.split("\n"):
        if "state UP" in line:
            device = line.split(":")[1].strip().split("@")[0]
            devices.append(device)

    for device in devices:
        pcap_file = f"{container_id}_{device}.pcap"
        tcpdump_command = f"tcpdump -i {device} -w {CAPTURED_PATH}/{pcap_file}"
        full_command = [
            "sudo",
            "nsenter",
            "--target",
            str(pid),
            "--net",
            "--",
            "sh",
            "-c",
            tcpdump_command,
        ]
        print(full_command)
        tcpdump_process = subprocess.Popen(
            full_command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.PIPE,
        )
        _register_collector_process(
            name=f"tcpdump:{container_id}:{device}",
            process=tcpdump_process,
            stderr_path=None,
        )
        print(
            f"[Collector Monitor] tcpdump started container={container_id} device={device} pid={tcpdump_process.pid}"
        )

    conntrack_command = [
        "/bin/bash",
        "./capture_conntrack.sh",
        f"{CAPTURED_PATH}/{container_id}_conntrack.txt",
        str(pid),
    ]
    print(conntrack_command)
    subprocess.Popen(
        conntrack_command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        stdin=subprocess.PIPE,
    )


def start_traffic_log(container_ids: list[str]):
    print("[Starting Traffic Logging]")
    for container_id in container_ids:
        container = client.containers.get(container_id)
        pid: int = container.attrs["State"]["Pid"]
        capture_traffic(pid, container_id[:12])


def start_logging(service_to_container_id: dict[str, str]):
    prepare_capture_directory()
    _reset_logging_state()
    start_sysdig_log(list(service_to_container_id.values()))
    start_traffic_log(list(service_to_container_id.values()))
    _start_collector_watchdog()


def add_app_log(scene: Scene) -> Scene:
    prepare_capture_directory()
    print("[Add App Log]")
    for service_name, service in scene.services.items():
        app_log_path = service.get("x-app-log", None)
        if not app_log_path:
            continue
        service.setdefault("volumes", []).append(
            f"{CAPTURED_PATH}/app_log/{service_name}:{app_log_path}"
        )
    return scene
