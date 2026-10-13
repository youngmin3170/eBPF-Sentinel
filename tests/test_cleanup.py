import json
import os
import signal
import subprocess
import time
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SENTINEL = PROJECT_ROOT / "build" / "sentinel"
SOCKET_PATH = Path("/tmp/sentinel.sock")


def get_bpf_resources(resource_type):
    result = subprocess.run(["bpftool", "-j", resource_type, "show"], capture_output=True, text=True, check=True)

    return json.loads(result.stdout)

def get_bpf_ids(resource_type):
    resources = get_bpf_resources(resource_type)

    return {resource["id"] for resource in resources}

def test_bpf_resources_are_cleaned_up():
    if os.geteuid() != 0:
        pytest.skip("BPF cleanup test requires root privileges")

    before_progs = get_bpf_ids("prog")
    before_maps = get_bpf_ids("map")
    before_links = get_bpf_ids("link")

    sentinel = subprocess.Popen([str(SENTINEL)], cwd=PROJECT_ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    try:
        deadline = time.time() + 3

        while time.time() < deadline:
            if SOCKET_PATH.exists():
                break

            if sentinel.poll() is not None:
                stdout, stderr = sentinel.communicate()
                pytest.fail(
                    f"Sentinel exited unexpectedly.\n"
                    f"stdout:\n{stdout}\n"
                    f"stderr:\n{stderr}"
                )

            time.sleep(0.05)

        assert SOCKET_PATH.exists()

        during_progs = get_bpf_ids("prog")
        during_maps = get_bpf_ids("map")
        during_links = get_bpf_ids("link")

        new_progs = during_progs - before_progs
        new_maps = during_maps - before_maps
        new_links = during_links - before_links

        assert new_progs, "Sentinel created no BPF programs"
        assert new_maps, "Sentinel created no BPF maps"
        assert new_links, "Sentinel created no BPF links"

        sentinel.send_signal(signal.SIGINT)
        assert sentinel.wait(timeout=3) == 0

        after_progs = get_bpf_ids("prog")
        after_maps = get_bpf_ids("map")
        after_links = get_bpf_ids("link")

        assert new_progs.isdisjoint(after_progs)
        assert new_maps.isdisjoint(after_maps)
        assert new_links.isdisjoint(after_links)

    finally:
        if sentinel.poll() is None:
            sentinel.kill()
            sentinel.wait()