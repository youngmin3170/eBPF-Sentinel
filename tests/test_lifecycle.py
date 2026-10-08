import os
import signal
import subprocess
import time
from pathlib import Path

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
BUILD_DIR = PROJECT_ROOT / "build"

SENTINEL = BUILD_DIR / "sentinel"
SOCKET_PATH = Path("/tmp/sentinel.sock")


def test_sentinel_start_and_shutdown():
    if os.geteuid() != 0:
        pytest.skip("Sentinel lifecycle test requires root privileges")

    process = subprocess.Popen([str(SENTINEL)], cwd=PROJECT_ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    try:
        deadline = time.time() + 3

        while time.time() < deadline:
            if SOCKET_PATH.exists():
                break

            if process.poll() is not None:
                stdout, stderr = process.communicate()
                pytest.fail(
                    f"Sentinel exited unexpectedly.\n"
                    f"stdout:\n{stdout}\n"
                    f"stderr:\n{stderr}"
                )

            time.sleep(0.05)

        assert SOCKET_PATH.exists(), "Sentinel socket was not created"

        process.send_signal(signal.SIGINT)

        return_code = process.wait(timeout=3)

        assert return_code == 0
        assert not SOCKET_PATH.exists(), "Sentinel socket was not removed"

    finally:
        if process.poll() is None:
            process.kill()
            process.wait()