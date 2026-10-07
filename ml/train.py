"""
train.py — trains a lightweight LSTM on the synthetic syscall dataset.

Outputs:
  model.pt    — trained weights (torch.save)
  vocab.json  — token → integer index mapping used at inference time

Architecture: token embedding → single LSTM layer → linear classifier
Keeps inference fast: ~0.3 ms per sequence on CPU, well under the 100 ms budget.
"""

import json
import os
import random
from collections import Counter

import torch
import torch.nn as nn
from torch.nn.utils.rnn import pad_sequence
from torch.utils.data import DataLoader, Dataset

# ── hyper-parameters ──────────────────────────────────────────────────────────

_HERE         = os.path.dirname(os.path.abspath(__file__))
_MODELS       = os.path.join(_HERE, "..", "models")
DATASET_FILE  = os.path.join(_MODELS, "dataset.jsonl")
MODEL_FILE    = os.path.join(_MODELS, "model.pt")
VOCAB_FILE    = os.path.join(_MODELS, "vocab.json")

WINDOW        = 64       # max sequence length fed to the model (truncated/padded)
EMBED_DIM     = 32       # token embedding size
HIDDEN_DIM    = 64       # LSTM hidden state size
BATCH_SIZE    = 64
EPOCHS        = 15
LR            = 1e-3
VAL_SPLIT     = 0.15     # fraction of data held out for validation
SEED          = 42

PAD_TOKEN     = "<PAD>"
UNK_TOKEN     = "<UNK>"

torch.manual_seed(SEED)
random.seed(SEED)

# ── vocabulary ────────────────────────────────────────────────────────────────

def build_vocab(sequences):
    """Map every unique token to an integer index. PAD=0, UNK=1."""
    counter = Counter(tok for seq in sequences for tok in seq)
    vocab = {PAD_TOKEN: 0, UNK_TOKEN: 1}
    for token, _ in counter.most_common():
        vocab[token] = len(vocab)
    return vocab

# ── dataset ───────────────────────────────────────────────────────────────────

class SyscallDataset(Dataset):
    def __init__(self, samples, vocab):
        self.samples = samples
        self.vocab   = vocab

    def __len__(self):
        return len(self.samples)

    def __getitem__(self, idx):
        sample = self.samples[idx]
        seq    = sample["sequence"][:WINDOW]
        ids    = [self.vocab.get(tok, self.vocab[UNK_TOKEN]) for tok in seq]
        return torch.tensor(ids, dtype=torch.long), torch.tensor(sample["label"], dtype=torch.float)


def collate(batch):
    seqs, labels = zip(*batch)
    padded = pad_sequence(seqs, batch_first=True, padding_value=0)
    return padded, torch.stack(labels)

# ── model ─────────────────────────────────────────────────────────────────────

class ThreatLSTM(nn.Module):
    def __init__(self, vocab_size, embed_dim, hidden_dim):
        super().__init__()
        self.embed = nn.Embedding(vocab_size, embed_dim, padding_idx=0)
        self.lstm  = nn.LSTM(embed_dim, hidden_dim, batch_first=True)
        self.head  = nn.Linear(hidden_dim, 1)

    def forward(self, x):
        # x: (batch, seq_len)
        emb = self.embed(x)                  # (batch, seq_len, embed_dim)
        _, (h, _) = self.lstm(emb)           # h: (1, batch, hidden_dim)
        logit = self.head(h.squeeze(0))      # (batch, 1)
        return logit.squeeze(1)              # (batch,)

# ── training loop ─────────────────────────────────────────────────────────────

def evaluate(model, loader, criterion, device):
    model.eval()
    total_loss, correct, total = 0.0, 0, 0
    with torch.no_grad():
        for x, y in loader:
            x, y = x.to(device), y.to(device)
            logits = model(x)
            total_loss += criterion(logits, y).item() * len(y)
            preds = (torch.sigmoid(logits) > 0.5).float()
            correct += (preds == y).sum().item()
            total += len(y)
    return total_loss / total, correct / total


def train():
    # ── load data ────────────────────────────────────────────────────────────
    samples = []
    with open(DATASET_FILE) as f:
        for line in f:
            samples.append(json.loads(line))

    random.shuffle(samples)
    split = int(len(samples) * (1 - VAL_SPLIT))
    train_samples = samples[:split]
    val_samples   = samples[split:]

    sequences = [s["sequence"] for s in samples]
    vocab = build_vocab(sequences)

    with open(VOCAB_FILE, "w") as f:
        json.dump(vocab, f)
    print(f"[+] Vocab size: {len(vocab)} tokens  →  {VOCAB_FILE}")

    train_ds = SyscallDataset(train_samples, vocab)
    val_ds   = SyscallDataset(val_samples,   vocab)
    train_dl = DataLoader(train_ds, batch_size=BATCH_SIZE, shuffle=True,  collate_fn=collate)
    val_dl   = DataLoader(val_ds,   batch_size=BATCH_SIZE, shuffle=False, collate_fn=collate)

    # ── model + optimizer ─────────────────────────────────────────────────────
    device = torch.device("cpu")   # stays on CPU — target is <5% overhead on host
    model  = ThreatLSTM(len(vocab), EMBED_DIM, HIDDEN_DIM).to(device)
    opt    = torch.optim.Adam(model.parameters(), lr=LR)
    crit   = nn.BCEWithLogitsLoss()

    param_count = sum(p.numel() for p in model.parameters())
    print(f"[+] Model parameters: {param_count:,}")
    print(f"[+] Training on {len(train_samples)} samples, validating on {len(val_samples)}\n")

    best_val_acc = 0.0

    for epoch in range(1, EPOCHS + 1):
        model.train()
        for x, y in train_dl:
            x, y = x.to(device), y.to(device)
            opt.zero_grad()
            loss = crit(model(x), y)
            loss.backward()
            opt.step()

        train_loss, train_acc = evaluate(model, train_dl, crit, device)
        val_loss,   val_acc   = evaluate(model, val_dl,   crit, device)

        marker = ""
        if val_acc > best_val_acc:
            best_val_acc = val_acc
            torch.save({
                "model_state": model.state_dict(),
                "vocab_size":  len(vocab),
                "embed_dim":   EMBED_DIM,
                "hidden_dim":  HIDDEN_DIM,
                "window":      WINDOW,
            }, MODEL_FILE)
            marker = "  ← best"

        print(f"Epoch {epoch:02d}/{EPOCHS}  "
              f"train loss {train_loss:.4f}  acc {train_acc:.4f}  |  "
              f"val loss {val_loss:.4f}  acc {val_acc:.4f}{marker}")

    print(f"\n[+] Best val accuracy : {best_val_acc:.4f}")
    print(f"[+] Model saved       : {MODEL_FILE}")

    # ── quick latency benchmark ───────────────────────────────────────────────
    import time
    model.eval()
    dummy = torch.zeros(1, WINDOW, dtype=torch.long)
    # warm-up
    for _ in range(10):
        with torch.no_grad():
            model(dummy)
    runs = 200
    t0 = time.perf_counter()
    for _ in range(runs):
        with torch.no_grad():
            model(dummy)
    ms = (time.perf_counter() - t0) / runs * 1000
    print(f"[+] Inference latency : {ms:.3f} ms/sequence (CPU, batch=1)")


if __name__ == "__main__":
    train()
