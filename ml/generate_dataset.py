"""
generate_dataset.py — synthetic syscall sequence dataset generator

Produces labeled JSONL where each line is one process lifecycle:
  {"label": 0, "sequence": ["openat:/etc/ld.so.cache", "openat:/usr/lib/libc.so.6", ...]}
  {"label": 1, "sequence": ["openat:/home/user/doc.txt", "openat:/home/user/doc.txt.enc", ...]}

Label 0 = benign, Label 1 = malicious.

No real malware is used. Patterns are derived from the statistical fingerprints
of known attack classes:
  - Ransomware:     rapid burst of openat on document extensions, then encrypted copies
  - Reverse shell:  execve(/bin/bash) after a network binary, sparse file access
  - Fork bomb:      dense execve bursts with no file I/O
  - Benign compile: openat on .c/.h/.o, execve(gcc/cc1/ld)
  - Benign browse:  openat on cache/socket/font files, long gaps (modelled as sparse events)
  - Benign shell:   execve(ls/cat/grep) interleaved with openat on config files
"""

import json
import os
import random

_HERE   = os.path.dirname(os.path.abspath(__file__))
OUTFILE = os.path.join(_HERE, "..", "models", "dataset.jsonl")
SEED    = 42

random.seed(SEED)

# ── token vocabulary helpers ──────────────────────────────────────────────────

def openat(path):
    return f"openat:{path}"

def execve(path):
    return f"execve:{path}"

# ── file pools ────────────────────────────────────────────────────────────────

LIBS = [
    "/etc/ld.so.cache",
    "/usr/lib/x86_64-linux-gnu/libc.so.6",
    "/usr/lib/x86_64-linux-gnu/libm.so.6",
    "/usr/lib/x86_64-linux-gnu/libpthread.so.0",
    "/usr/lib/x86_64-linux-gnu/libdl.so.2",
    "/usr/lib/x86_64-linux-gnu/libz.so.1",
]

SRC_FILES = [f"/home/kali/project/src/module_{i}.c" for i in range(20)] + \
            [f"/home/kali/project/include/header_{i}.h" for i in range(10)]

OBJ_FILES = [f"/home/kali/project/build/module_{i}.o" for i in range(20)]

DOC_FILES = [f"/home/kali/Documents/file_{i}.{ext}"
             for i in range(60)
             for ext in ("docx", "pdf", "jpg", "xlsx", "txt")]

CACHE_FILES = [
    "/home/kali/.cache/chromium/Default/Cache/data_0",
    "/home/kali/.cache/chromium/Default/Cache/data_1",
    "/home/kali/.cache/chromium/Default/Cookies",
    "/home/kali/.cache/chromium/Default/History",
    "/home/kali/.cache/mozilla/firefox/profile/places.sqlite",
    "/home/kali/.config/chromium/Default/Preferences",
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    "/run/user/1000/bus",
    "/proc/self/status",
    "/proc/meminfo",
]

CONFIG_FILES = [
    "/etc/passwd", "/etc/hosts", "/etc/resolv.conf",
    "/home/kali/.bashrc", "/home/kali/.profile",
    "/home/kali/.ssh/known_hosts",
]

NET_BINS = ["/usr/bin/curl", "/usr/bin/wget", "/usr/bin/nc", "/usr/bin/ncat"]
SHELL_CMDS = ["/bin/ls", "/bin/cat", "/bin/grep", "/usr/bin/find",
              "/usr/bin/ps", "/usr/bin/id", "/usr/bin/whoami"]
SYS_CMDS   = ["/usr/bin/gcc", "/usr/bin/cc1", "/usr/bin/ld",
               "/usr/bin/as", "/usr/bin/make"]

# ── benign generators ─────────────────────────────────────────────────────────

def gen_benign_compile():
    """gcc compiling a small project: open source + headers, execve toolchain."""
    seq = []
    seq += [openat(f) for f in random.sample(LIBS, k=4)]
    for src in random.sample(SRC_FILES, k=random.randint(3, 8)):
        seq.append(openat(src))
        # Each source file pulls in a few headers
        seq += [openat(h) for h in random.sample(SRC_FILES[-10:], k=random.randint(1, 3))]
        seq.append(execve("/usr/bin/gcc"))
        seq.append(execve("/usr/lib/gcc/x86_64-linux-gnu/12/cc1"))
    seq += [openat(o) for o in random.sample(OBJ_FILES, k=random.randint(2, 6))]
    seq.append(execve("/usr/bin/ld"))
    return seq

def gen_benign_browse():
    """Browser-like: lots of cache/font/socket opens, no document bulk."""
    seq = []
    seq += [openat(f) for f in random.sample(LIBS, k=3)]
    seq += [openat(f) for f in random.choices(CACHE_FILES, k=random.randint(15, 35))]
    return seq

def gen_benign_shell():
    """Interactive shell session: mix of common commands and config reads."""
    seq = []
    seq += [openat(f) for f in random.sample(LIBS, k=3)]
    for _ in range(random.randint(5, 15)):
        seq.append(execve(random.choice(SHELL_CMDS)))
        seq += [openat(f) for f in random.sample(CONFIG_FILES, k=random.randint(1, 3))]
    return seq

def gen_benign_db():
    """Database-like workload: repetitive opens on a small set of data files."""
    db_files = [f"/var/lib/postgresql/data/base/16384/pg_data_{i}" for i in range(5)]
    seq = []
    seq += [openat(f) for f in random.sample(LIBS, k=4)]
    seq += [openat(f) for f in random.choices(db_files, k=random.randint(20, 40))]
    return seq

# ── malicious generators ──────────────────────────────────────────────────────

def gen_ransomware():
    """Rapid bulk openat on document extensions — the canonical ransomware signature.

    Pattern: open original → open encrypted copy → repeat across many files.
    The burst rate (many files, same PID, short sequence) is the key signal.
    """
    seq = []
    seq += [openat(f) for f in random.sample(LIBS, k=2)]
    # Pick a large random subset of documents to "encrypt"
    targets = random.sample(DOC_FILES, k=random.randint(30, 60))
    for doc in targets:
        seq.append(openat(doc))
        # Encrypted copy written alongside original
        enc = doc + ".enc"
        seq.append(openat(enc))
    return seq

def gen_reverse_shell():
    """Network binary exec followed immediately by shell — reverse shell pattern."""
    seq = []
    seq += [openat(f) for f in random.sample(LIBS, k=3)]
    seq.append(execve(random.choice(NET_BINS)))
    # Minimal file I/O — attacker is working interactively over the network
    seq += [openat(f) for f in random.sample(CONFIG_FILES, k=random.randint(1, 3))]
    seq.append(execve("/bin/bash"))
    seq.append(execve("/bin/sh"))
    seq += [execve(c) for c in random.choices(SHELL_CMDS, k=random.randint(3, 8))]
    seq += [openat(f) for f in random.sample(CONFIG_FILES, k=random.randint(2, 5))]
    seq.append(execve("/usr/bin/id"))
    seq.append(execve("/usr/bin/whoami"))
    return seq

def gen_fork_bomb():
    """Dense execve burst — fork bomb or rapid process spawning."""
    seq = []
    seq += [openat(f) for f in random.sample(LIBS, k=2)]
    # Hundreds of rapid self-exec calls with almost no file I/O
    seq += [execve("/bin/bash")] * random.randint(40, 80)
    return seq

def gen_credential_harvest():
    """Targeted openat on shadow/passwd/ssh key files — credential scraper."""
    sensitive = [
        "/etc/shadow", "/etc/passwd", "/etc/sudoers",
        "/home/kali/.ssh/id_rsa", "/home/kali/.ssh/id_ed25519",
        "/home/kali/.ssh/authorized_keys",
        "/root/.ssh/id_rsa", "/root/.bash_history",
        "/home/kali/.bash_history",
    ]
    seq = []
    seq += [openat(f) for f in random.sample(LIBS, k=2)]
    seq += [openat(f) for f in random.choices(sensitive, k=random.randint(6, 15))]
    seq += [execve(c) for c in random.choices(SHELL_CMDS, k=random.randint(2, 5))]
    return seq

# ── dataset assembly ──────────────────────────────────────────────────────────

BENIGN_GENERATORS = [
    gen_benign_compile,
    gen_benign_browse,
    gen_benign_shell,
    gen_benign_db,
]

MALICIOUS_GENERATORS = [
    gen_ransomware,
    gen_reverse_shell,
    gen_fork_bomb,
    gen_credential_harvest,
]

def generate(n_benign=2000, n_malicious=2000):
    samples = []

    for _ in range(n_benign):
        seq = random.choice(BENIGN_GENERATORS)()
        # Add light noise: random library opens scattered through benign sequences
        noise_count = random.randint(0, 3)
        for _ in range(noise_count):
            pos = random.randint(0, len(seq))
            seq.insert(pos, openat(random.choice(LIBS)))
        samples.append({"label": 0, "sequence": seq})

    for _ in range(n_malicious):
        seq = random.choice(MALICIOUS_GENERATORS)()
        samples.append({"label": 1, "sequence": seq})

    random.shuffle(samples)

    with open(OUTFILE, "w") as f:
        for s in samples:
            f.write(json.dumps(s) + "\n")

    benign_count   = sum(1 for s in samples if s["label"] == 0)
    malicious_count = sum(1 for s in samples if s["label"] == 1)
    all_lens = [len(s["sequence"]) for s in samples]

    print(f"[+] Dataset written to {OUTFILE}")
    print(f"    Total samples : {len(samples)}")
    print(f"    Benign (0)    : {benign_count}")
    print(f"    Malicious (1) : {malicious_count}")
    print(f"    Seq len min/avg/max: {min(all_lens)} / {sum(all_lens)//len(all_lens)} / {max(all_lens)}")

if __name__ == "__main__":
    generate()
