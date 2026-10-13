import ctypes
import os
import signal
import socket
import subprocess
import time
from pathlib import Path

import pytest

SYSCALL_EXECVE = 1


class Event(ctypes.Structure):
    _fields_ = [
        ("pid", ctypes.c_uint32),
        ("uid", ctypes.c_uint32),
        ("syscall_type", ctypes.c_uint32),
        ("comm", ctypes.c_char * 16),
        ("filename", ctypes.c_char * 64),
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
    assert EVENT_SIZE == 92


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

        target = subprocess.Popen(["/usr/bin/true"])
        target_pid = target.pid
        target.wait()

        found = False
        deadline = time.time() + 3

        while time.time() < deadline:
            raw = recv_exact(client, EVENT_SIZE)
            event = Event.from_buffer_copy(raw)

            if event.syscall_type == SYSCALL_EXECVE and event.pid == target_pid:
                found = True
                break

        assert found, f"Did not receive execve event for PID {target_pid}"

    finally:
        if client is not None:
            client.close()

        if sentinel.poll() is None:
            sentinel.send_signal(signal.SIGINT)

            try:
                sentinel.wait(timeout=3)
            except subprocess.TimeoutExpired:
                sentinel.kill()
                sentinel.wait()