import ctypes
import os
import signal
import socket
import subprocess
import time
from pathlib import Path

import pytest

EVENT_EXECVE = 1
EVENT_PROCESS_FORK = 6
COMM_LEN = 16
PATH_LEN = 64
MAX_ARGS = 6
ARG_LEN = 32
NET_ADDR_LEN = 64

class ExecEventData(ctypes.Structure):
    _fields_ = [
        ("filename", ctypes.c_char * PATH_LEN),
        ("argc", ctypes.c_uint32),
        ("args", (ctypes.c_char * ARG_LEN) * MAX_ARGS),
    ]


class FileEventData(ctypes.Structure):
    _fields_ = [
        ("filename", ctypes.c_char * PATH_LEN),
    ]


class NetworkEventData(ctypes.Structure):
    _fields_ = [
        ("address", ctypes.c_char * NET_ADDR_LEN),
    ]

class ProcessEventData(ctypes.Structure):
    _fields_ = [
        ("child_pid", ctypes.c_uint32)
    ]


class EventData(ctypes.Union):
    _fields_ = [
        ("exec", ExecEventData),
        ("file", FileEventData),
        ("network", NetworkEventData),
        ("process", ProcessEventData),
    ]


class Event(ctypes.Structure):
    _fields_ = [
        ("timestamp_ns", ctypes.c_uint64),
        ("pid", ctypes.c_uint32),
        ("ppid", ctypes.c_uint32),
        ("uid", ctypes.c_uint32),
        ("event_type", ctypes.c_uint32),
        ("comm", ctypes.c_char * COMM_LEN),
        ("data", EventData),
    ]

EVENT_SIZE = ctypes.sizeof(Event)

def recv_exact(sock, size):
    data = b""

    while len(data) < size:
        chunk = sock.recv(size - len(data))

        if not chunk:
            raise RuntimeError("Socket closed before full event was received")

        data += chunk

    return data


def test_event_size():
    assert EVENT_SIZE == 304


def test_execve_event():
    project_root = Path(__file__).resolve().parents[1]
    build_dir = project_root / "build"
    sentinel_path = build_dir / "sentinel"
    socket_path = "/tmp/sentinel.sock"

    sentinel = subprocess.Popen([str(sentinel_path)], cwd=project_root, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    client = None

    try:
        deadline = time.time() + 3

        while time.time() < deadline:
            if os.path.exists(socket_path):
                break

            if sentinel.poll() is not None:
                stdout, stderr = sentinel.communicate()
                pytest.fail(
                    f"Sentinel exited unexpectedly.\n"
                    f"stdout:\n{stdout}\n"
                    f"stderr:\n{stderr}"
                )

            time.sleep(0.05)

        assert os.path.exists(socket_path)

        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.connect(socket_path)
        client.settimeout(3)

        time.sleep(0.1)

        expected_ppid = os.getpid()

        target = subprocess.Popen(["/usr/bin/true", "sentinel-argv-test"])

        target_pid = target.pid
        target.wait()

        matched_event = None
        deadline = time.time() + 3

        while time.time() < deadline:
            raw = recv_exact(client, EVENT_SIZE)
            event = Event.from_buffer_copy(raw)

            if event.event_type == EVENT_EXECVE and event.pid == target_pid:
                matched_event = event
                break

        assert matched_event is not None, (f"Did not receive execve event for PID {target_pid}")
        assert matched_event.data.exec.argc == 2

        arg0 = bytes(matched_event.data.exec.args[0]).split(b"\0", 1)[0]
        arg1 = bytes(matched_event.data.exec.args[1]).split(b"\0", 1)[0]

        assert arg0 == b"/usr/bin/true"
        assert arg1 == b"sentinel-argv-test"

        assert matched_event.ppid == expected_ppid, (
            f"Expected PPID {expected_ppid}, "
            f"got {matched_event.ppid}"
        )

        assert matched_event.timestamp_ns > 0

    finally:
        if sentinel.poll() is None:
            sentinel.send_signal(signal.SIGINT)

            try:
                sentinel.wait(timeout=3)
            except subprocess.TimeoutExpired:
                sentinel.kill()
                sentinel.wait()

        if client is not None:
            client.close()