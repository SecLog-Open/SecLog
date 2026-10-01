IS_DEBUG = True

import atexit
import os
import socket
import struct
import subprocess
import threading
import time
from datetime import datetime

import docker
from docker.errors import DockerException
from loguru import logger
from rich import print


class _LazyDockerClient:
    """Connect to Docker on first use instead of during module import.

    Keeping the connection lazy lets commands such as ``python main.py
    --help`` and static configuration checks run before a daemon is started,
    while normal scene execution still receives the standard Docker SDK
    client.
    """

    def __init__(self):
        self._client = None

    def _connect(self):
        if self._client is None:
            try:
                self._client = docker.from_env()
            except DockerException as exc:
                raise RuntimeError(
                    "Docker daemon is unavailable. Start Docker on the Linux "
                    "capture host before constructing a SecLog scenario."
                ) from exc
        return self._client

    def __getattr__(self, name):
        return getattr(self._connect(), name)


client = _LazyDockerClient()
_sudo_keepalive_thread = None
_sudo_keepalive_stop = threading.Event()

fields = {
    "proc.name",
    "evt.num",
    "container.id",
    "proc.vpid",
    "thread.vtid",
    "evt.dir",
    "evt.type",
    "fd.name",
    "fd.num",
    "evt.category",
    "fd.cip",
    "fd.cport",
    "fd.sip",
    "fd.sport",
    "fd.is_server",
    "fd.ino",
    "evt.is_io_read",
    "evt.is_io_write",
    "evt.datetime",
    "evt.rawres",
    "proc.cmdline",
    "evt.buffer",
    "proc.env[malicious]",
}


def set_current_workpath(path: str):
    os.environ["CONTEXT_PATH"] = os.path.abspath(path)


def _sudo_keepalive_loop():
    while not _sudo_keepalive_stop.wait(50):
        subprocess.run(
            ["sudo", "-n", "true"],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )


def ensure_sudo_session():
    global _sudo_keepalive_thread

    if os.geteuid() == 0:
        return

    if subprocess.run(
        ["sudo", "-n", "true"],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    ).returncode != 0:
        print("Requesting sudo once for build-related privileged commands...")
        subprocess.run(["sudo", "-v"], check=True)

    if _sudo_keepalive_thread is None or not _sudo_keepalive_thread.is_alive():
        _sudo_keepalive_stop.clear()
        _sudo_keepalive_thread = threading.Thread(
            target=_sudo_keepalive_loop,
            name="sudo-keepalive",
            daemon=True,
        )
        _sudo_keepalive_thread.start()


def stop_sudo_session():
    global _sudo_keepalive_thread

    if _sudo_keepalive_thread is None:
        return

    _sudo_keepalive_stop.set()
    _sudo_keepalive_thread.join(timeout=1)
    _sudo_keepalive_thread = None


atexit.register(stop_sudo_session)


def exec_command(command: list[str], check=True):
    print(f"executing command: {command}")
    try:
        subprocess.run(command, check=check)
    except subprocess.CalledProcessError as e:
        logger.error(f"Error: {e.stderr}")
        raise


def get_current_time() -> str:
    now = datetime.now()
    timestamp = now.strftime("%Y-%m-%d_%H-%M-%S")
    return timestamp


def ip_to_int(ip: str) -> int:
    """Convert an IPv4 address to a 32-bit integer."""
    return struct.unpack("!I", socket.inet_aton(ip))[0]


def int_to_ip(ip_int: int) -> str:
    """Convert a 32-bit integer to an IPv4 address."""
    return socket.inet_ntoa(struct.pack("!I", ip_int))


def invert_ip(ip: str) -> str:
    """Invert an IPv4 address."""
    ip_int = ip_to_int(ip)
    inverted_ip_int = ~ip_int & 0xFFFFFFFF  # Invert bits and ensure it's within 32 bits
    return int_to_ip(inverted_ip_int)
