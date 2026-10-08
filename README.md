# eBPF-Sentinel
currently working on to add features. README.md is not correct. 

## eBPF-Sentinel

A lightweight, kernel-level Linux security agent that uses eBPF for real-time syscall telemetry and a PyTorch LSTM to autonomously detect and terminate malicious processes — ransomware, reverse shells, and fork bombs — with sub-millisecond inference latency and near-zero false positives.

---

## Benchmark Results

All measurements taken on Kali Linux 6.18 (x86-64, VirtualBox VM, 4 vCPU, 4 GB RAM).

### Performance (KPI targets from project spec)

| Metric | Target | Measured | Status |
|---|---|---|---|
| Sentinel daemon CPU (idle) | < 5% | **0.5%** | PASS |
| Sentinel daemon RAM | < 50 MB | **3.1 MB** | PASS |
| ML inference latency (avg) | < 100 ms | **0.84 ms** | PASS |
| End-to-end (syscall → SIGKILL) | < 100 ms | **< 2 ms** | PASS |

> The ML engine's RSS is ~260 MB due to PyTorch shared libraries loaded at import time.  
> The LSTM model itself is 47,649 parameters (~186 KB on disk).

### Detection Accuracy (validation split, 600 samples)

| Metric | Value |
|---|---|
| Accuracy | **94.67%** |
| True Positive Rate (recall) | **89.64%** |
| False Positive Rate | **0.94%** |
| Precision | **98.82%** |

> FPR of 0.94% on the synthetic validation set. Real-world FPR will be measured in the QEMU detonation phase.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                          Linux Kernel                           │
│                                                                 │
│   execve() ──┐                                                  │
│   openat() ──┼──► eBPF tracepoints (sensor.o)                   │
│   connect() ─┘          │                                       │
│                         │  BPF ring buffer (256 KB)             │
└─────────────────────────┼───────────────────────────────────────┘
                          │
              ┌───────────▼────────────┐
              │   sentinel (daemon/    │   C — loads BPF, drains
              │   loader.c, root)      │   ring buffer, Unix socket
              └───────────┬────────────┘
                          │ /tmp/sentinel.sock
                          │ raw binary structs (88 bytes/event)
              ┌───────────▼────────────┐
              │   ml_engine.py         │   Python — per-PID sliding
              │   (ml/ml_engine.py)    │   window → LSTM inference
              └───────────┬────────────┘
                          │ score ≥ 0.90
                          ▼
                    os.kill(pid, SIGKILL)
```

**Data flow per event (< 2 ms end-to-end):**
1. Kernel executes `execve` / `openat` / `connect` syscall
2. eBPF tracepoint fires, writes 88-byte struct to ring buffer
3. `sentinel` drains ring buffer every 100 ms, writes raw bytes to Unix socket
4. `ml_engine.py` accumulates 64 events per PID into a sliding window
5. LSTM scores the window; if score ≥ 0.90 → `SIGKILL`

---

## Threat Coverage

| Attack Class | Detection Signal | Hook |
|---|---|---|
| Ransomware | Rapid burst of `openat` on `.doc .pdf .jpg .xlsx` → `.enc` copies | `sys_enter_openat` |
| Reverse shell | `connect()` to external IP immediately after shell `execve` | `sys_enter_connect` + `sys_enter_execve` |
| Fork bomb | Dense `execve` burst with no file I/O | `sys_enter_execve` |
| Credential harvester | `openat` on `/etc/shadow`, SSH private keys | `sys_enter_openat` |

---

## Repository Layout

```
eBPF-Sentinel/
├── kernel/
│   └── sensor.c          eBPF C — tracepoints for execve, openat, connect
├── daemon/
│   ├── loader.c          User-space daemon — loads BPF, Unix socket bridge
│   └── Makefile          Build system
├── ml/
│   ├── generate_dataset.py   Synthetic training data generator
│   ├── train.py              LSTM trainer — outputs model.pt + vocab.json
│   └── ml_engine.py          Inference daemon — scoring + SIGKILL enforcement
├── models/               Trained weights and vocabulary (gitignored)
├── scripts/
│   └── bench.sh          Benchmark suite (latency, CPU, RAM, accuracy)
└── build/                Compiled artifacts (gitignored)
```

---

## Quick Start

### Prerequisites

```bash
sudo apt-get install -y libbpf-dev linux-headers-amd64 linux-libc-dev bpftool
pip3 install torch --break-system-packages
```

### Build

```bash
cd daemon && make
```

### Train the model (optional — pre-trained weights are in `models/`)

```bash
python3 ml/generate_dataset.py   # generates models/dataset.jsonl
python3 ml/train.py              # trains LSTM, saves models/model.pt + vocab.json
```

### Run

**Terminal 1** (root required for eBPF):
```bash
sudo build/sentinel
```

**Terminal 2**:
```bash
python3 ml/ml_engine.py
```

### Reproduce benchmarks

```bash
bash scripts/bench.sh
```

---

## ML Model

**Architecture:** Token embedding (dim=32) → single LSTM layer (hidden=64) → linear classifier  
**Parameters:** 47,649  
**Training data:** 4,000 synthetic sequences (2,000 benign, 2,000 malicious), generated by `ml/generate_dataset.py`  
**Input:** Sliding window of 64 syscall tokens per PID, encoded as `"syscall:argument"` strings  
**Inference:** CPU-only, batch size 1, no GPU required

### Token format

Each syscall maps to a string token fed to the vocabulary:

| Syscall | Token format | Example |
|---|---|---|
| `execve` | `execve:<path>` | `execve:/usr/bin/gcc` |
| `openat` | `openat:<path>` | `openat:/home/user/secret.docx` |
| `connect` | `connect:<ip>:<port>` | `connect:192.168.1.10:4444` |

---

## Test Plan (QEMU Sandbox)

Safe malware detonation requires an isolated VM. The planned test phases are:

**Phase A — Baseline telemetry:** Boot clean QEMU image, run benign workloads (compile, wget, database queries), log syscall sequences labeled as `0` (benign).

**Phase B — Live detonation:** Snapshot the clean VM state. Execute open-source malware samples from [MalwareBazaar](https://bazaar.abuse.ch/), capture real syscall sequences labeled as `1` (malicious). Revert snapshot after every detonation.

**Phase C — Enforcing mode:** Deploy the full agent into QEMU. Re-run malware. Pass criteria: agent kills malicious process before payload completes, no kernel panic, no VM freeze.

---

## Security Notes

- The sentinel daemon requires `CAP_BPF` and `CAP_PERFMON` (effectively root on most systems)
- The Unix socket at `/tmp/sentinel.sock` is `chmod 0666` — change to a dedicated group in production
- `SIGKILL` on `PermissionError` means root-owned malware cannot be killed by the user-space engine; hook into a kernel module or use `bpf_send_signal` for privileged process termination
- This project is for **defensive security research and education only**

---

## License

GPL-2.0 — see [SPDX headers](kernel/sensor.c) in source files.
