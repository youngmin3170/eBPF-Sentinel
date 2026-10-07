"""
ml_engine.py — user-space inference daemon for eBPF-Sentinel.

Reads raw syscall events from sentinel via Unix socket, maintains a
per-PID sliding window of syscall tokens, runs LSTM inference on each
window, and issues SIGKILL when the threat score exceeds the threshold.
"""

import ctypes
import json
import os
import signal
import socket
import time
from collections import defaultdict

import torch
import torch.nn as nn

SOCKET_PATH    = "/tmp/sentinel.sock"
SYSCALL_EXECVE  = 1
SYSCALL_OPENAT  = 2
SYSCALL_CONNECT = 3

MODELS_DIR = os.path.join(os.path.dirname(__file__), "..", "models")
MODEL_FILE = os.path.join(MODELS_DIR, "model.pt")
VOCAB_FILE = os.path.join(MODELS_DIR, "vocab.json")

# Score threshold above which a process is killed.
# 0.90 gives near-zero FPR on the synthetic validation set.
KILL_THRESHOLD = 0.90

# Number of events accumulated per PID before running inference.
# Matches the WINDOW used during training.
WINDOW_SIZE    = 64

# ── C struct mirror ───────────────────────────────────────────────────────────

class Event(ctypes.Structure):
    """Byte-for-byte mirror of struct event in loader.c."""
    _fields_ = [
        ("pid",          ctypes.c_uint32),
        ("uid",          ctypes.c_uint32),
        ("syscall_type", ctypes.c_uint32),
        ("comm",         ctypes.c_char * 16),
        ("filename",     ctypes.c_char * 64),
    ]


EVENT_SIZE = ctypes.sizeof(Event)

# ── LSTM model (must match train.py architecture exactly) ─────────────────────

class ThreatLSTM(nn.Module):
    def __init__(self, vocab_size, embed_dim, hidden_dim):
        super().__init__()
        self.embed = nn.Embedding(vocab_size, embed_dim, padding_idx=0)
        self.lstm  = nn.LSTM(embed_dim, hidden_dim, batch_first=True)
        self.head  = nn.Linear(hidden_dim, 1)

    def forward(self, x):
        emb = self.embed(x)
        _, (h, _) = self.lstm(emb)
        return self.head(h.squeeze(0)).squeeze(1)

# ── model loading ─────────────────────────────────────────────────────────────

def load_model():
    with open(VOCAB_FILE) as f:
        vocab = json.load(f)

    ckpt  = torch.load(MODEL_FILE, map_location="cpu", weights_only=True)
    model = ThreatLSTM(ckpt["vocab_size"], ckpt["embed_dim"], ckpt["hidden_dim"])
    model.load_state_dict(ckpt["model_state"])
    model.eval()
    return model, vocab

# ── inference ─────────────────────────────────────────────────────────────────

def score_sequence(model, vocab, tokens):
    """Return threat probability in [0, 1] for a list of token strings."""
    unk = vocab.get("<UNK>", 1)
    ids = [vocab.get(tok, unk) for tok in tokens[-WINDOW_SIZE:]]
    x   = torch.tensor([ids], dtype=torch.long)   # (1, seq_len)
    with torch.no_grad():
        logit = model(x)
    return torch.sigmoid(logit).item()

# ── socket helpers ────────────────────────────────────────────────────────────

def recvall(sock, n):
    """Read exactly n bytes, blocking until all arrive or the socket closes."""
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf.extend(chunk)
    return bytes(buf)


def connect_to_sentinel():
    user = os.getenv("USER", os.getenv("LOGNAME", str(os.getuid())))
    print(f"[*] ML Engine | user: {user} (UID: {os.getuid()})")
    print(f"[*] Threshold : {KILL_THRESHOLD}  |  Window: {WINDOW_SIZE} events")
    print("[*] Waiting for sentinel daemon...")

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    while True:
        try:
            sock.connect(SOCKET_PATH)
            print("[+] Connected to kernel agent.\n")
            return sock
        except (FileNotFoundError, ConnectionRefusedError):
            time.sleep(1)

# ── main loop ─────────────────────────────────────────────────────────────────

def run(sock, model, vocab):
    # pid → list of token strings (sliding window)
    windows: dict[int, list[str]] = defaultdict(list)
    # pids we have already killed — don't double-kill
    killed: set[int] = set()

    print(f"{'SCORE':>6}  {'ACTION':<8}  {'PID':<6}  {'COMM':<16}  TOKEN")
    print("-" * 72)

    try:
        while True:
            raw = recvall(sock, EVENT_SIZE)
            if raw is None:
                print("\n[!] Sentinel disconnected.")
                break

            ev       = Event.from_buffer_copy(raw)
            comm     = ev.comm.decode("utf-8", "replace").rstrip("\x00")
            filename = ev.filename.decode("utf-8", "replace").rstrip("\x00")
            syscall  = ("execve"  if ev.syscall_type == SYSCALL_EXECVE  else
                        "connect" if ev.syscall_type == SYSCALL_CONNECT else
                        "openat")
            token    = f"{syscall}:{filename}"
            pid      = ev.pid

            if pid in killed:
                continue

            windows[pid].append(token)

            # Only score once we have a full window
            if len(windows[pid]) < WINDOW_SIZE:
                continue

            score = score_sequence(model, vocab, windows[pid])

            if score >= KILL_THRESHOLD:
                action = "KILL"
                try:
                    os.kill(pid, signal.SIGKILL)
                    killed.add(pid)
                except ProcessLookupError:
                    action = "GONE"   # process already exited
                except PermissionError:
                    action = "EPERM"  # can't kill root-owned process
            else:
                action = "ok"

            # Print every scored event (suppress repetitive benign noise in prod
            # by changing the condition to `if score >= KILL_THRESHOLD`)
            print(f"{score:>6.3f}  {action:<8}  {pid:<6}  {comm:<16}  {token[:40]}")

            # Slide the window forward by half its size so we re-score frequently
            windows[pid] = windows[pid][WINDOW_SIZE // 2:]

            # Evict stale PID windows to prevent unbounded memory growth
            if len(windows) > 4096:
                oldest = next(iter(windows))
                del windows[oldest]

    except KeyboardInterrupt:
        print("\n[*] ML Engine shutting down.")
    finally:
        sock.close()


if __name__ == "__main__":
    model, vocab = load_model()
    print(f"[+] Model loaded: {MODEL_FILE}  ({sum(p.numel() for p in model.parameters()):,} params)")
    sock = connect_to_sentinel()
    run(sock, model, vocab)
