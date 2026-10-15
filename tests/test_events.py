import os
import signal
import socket
import subprocess
import time
from pathlib import Path
import pytest

from userspace.protocol import (
    Event,
    EVENT_SIZE,
    EVENT_EXECVE,
    EVENT_PROCESS_EXIT,
    EVENT_PROCESS_FORK,
)

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

        

        fork_event = None
        exec_event = None
        exit_event = None

        deadline = time.time() + 3

        while time.time() < deadline:
            raw = recv_exact(client, EVENT_SIZE)
            event = Event.from_buffer_copy(raw)

            if event.event_type == EVENT_PROCESS_FORK and event.pid == expected_ppid and event.data.process.child_pid == target_pid:
                fork_event = event

            elif event.event_type == EVENT_EXECVE and event.pid == target_pid:
                exec_event = event

            elif event.event_type == EVENT_PROCESS_EXIT and event.pid == target_pid:
                exit_event = event

            if fork_event is not None and exec_event is not None and exit_event is not None:
                break
        
        assert fork_event is not None
        assert exit_event is not None
        
        assert exec_event is not None, (f"Did not receive execve event for PID {target_pid}")
        assert exec_event.data.exec.argc == 2

        arg0 = bytes(exec_event.data.exec.args[0]).split(b"\0", 1)[0]
        arg1 = bytes(exec_event.data.exec.args[1]).split(b"\0", 1)[0]

        assert arg0 == b"/usr/bin/true"
        assert arg1 == b"sentinel-argv-test"

        assert exec_event.ppid == expected_ppid, (
            f"Expected PPID {expected_ppid}, "
            f"got {exec_event.ppid}"
        )
        assert exec_event.tid == target_pid
        assert exec_event.timestamp_ns > 0

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