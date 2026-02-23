#!/usr/bin/env python3
"""Unified AI Training Script for DeepPacketSentinel & Ulti_Argus.

Reads synthetic network flows from `DeepPacketSentinel/data/sample_flows.ndjson`.
Trains the Layer 2 Isolation Forest (Sklearn) for anomaly detection.
Trains the Layer 3 PyTorch CNN (Payload Classifier) for deep payload inspection.
Saves the resulting models to `models/` so Aegis can load them at boot.
"""

import json
import os
import pickle
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import torch
import torch.nn as nn
import torch.optim as optim
from sklearn.ensemble import IsolationForest
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.preprocessing import StandardScaler

# Add the Ulti_argus Python package to path so we can import the CNN architecture
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../Ulti_argus")))
try:
    from src.argus_v.mnemosyne.pytorch_model import PayloadClassifier
except ImportError:
    print("Error: Could not import PayloadClassifier from Ulti_argus.")
    sys.exit(1)

# Paths
ROOT_DIR = Path(__file__).parent.parent
DATA_FILE = ROOT_DIR / "DeepPacketSentinel" / "data" / "sample_flows.ndjson"
MODEL_DIR = ROOT_DIR / "models"
MODEL_DIR.mkdir(exist_ok=True)

# Isolation Forest features exactly as expected by model_manager.py
IF_FEATURES = [
    "bytes_in", "bytes_out", "packets_in", "packets_out", 
    "duration", "src_port", "dst_port", "protocol"
]

def load_data():
    """Load NDJSON data into a list of dicts."""
    print(f"[*] Loading data from {DATA_FILE}...")
    if not DATA_FILE.exists():
        print(f"[!] Error: Training data not found at {DATA_FILE}")
        print("    Run `python3 DeepPacketSentinel/scripts/generate_sample_data.py` first.")
        sys.exit(1)
        
    records = []
    with open(DATA_FILE, "r") as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    print(f"[*] Loaded {len(records)} flow records.")
    return records


def train_isolation_forest(records):
    """Train the Layer 2 Isolation Forest model on numerical traffic features."""
    print("\n" + "="*50)
    print("--- Training Layer 2: Isolation Forest ---")
    
    # 1. Prepare DataFrame
    df = pd.DataFrame(records)
    
    # Map protocols to ints as model_manager does
    protocol_map = {'TCP': 1, 'UDP': 2, 'ICMP': 3, 'OTHER': 0}
    df['protocol'] = df.get('protocol', 'OTHER').map(protocol_map).fillna(0)
    
    # Synthesize packets_in/out if missing (DPS only provides bytes currently)
    if 'packets_in' not in df.columns:
        df['packets_in'] = (df['bytes_in'] / 1500).apply(np.ceil).clip(lower=1)
    if 'packets_out' not in df.columns:
        df['packets_out'] = (df['bytes_out'] / 1500).apply(np.ceil).clip(lower=1)
        
    X = df[IF_FEATURES].fillna(0).values
    
    # 2. Scale
    print("[*] Fitting StandardScaler...")
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    
    # 3. Train
    print("[*] Training IsolationForest (contamination=0.1)...")
    clf = IsolationForest(contamination=0.1, random_state=42, n_jobs=-1)
    clf.fit(X_scaled)
    
    # 4. Evaluate
    print("\n[*] Evaluating Isolation Forest...")
    scores = clf.decision_function(X_scaled)
    predictions = clf.predict(X_scaled)
    n_anomalies = int((predictions == -1).sum())
    n_normal = int((predictions == 1).sum())
    
    print(f"    Anomalies detected : {n_anomalies}/{len(predictions)} "
          f"({n_anomalies / len(predictions) * 100:.1f}%)")
    print(f"    Normal flows       : {n_normal}/{len(predictions)}")
    print(f"    Decision scores    : mean={scores.mean():.4f}, "
          f"std={scores.std():.4f}")
    print(f"    Score percentiles  : P5={np.percentile(scores, 5):.4f}, "
          f"P50={np.percentile(scores, 50):.4f}, "
          f"P95={np.percentile(scores, 95):.4f}")

    # Cross-check: contamination ~0.1 should yield ~10% anomalies
    actual_contam = n_anomalies / len(predictions)
    if abs(actual_contam - 0.1) > 0.05:
        print(f"    [!] Warning: actual contamination {actual_contam:.2%} "
              f"deviates from target 10%")
    else:
        print(f"    [✓] Contamination within expected range")
    
    # 5. Save
    timestamp = "00000000_000000"
    model_path = MODEL_DIR / f"model_{timestamp}.pkl"
    scaler_path = MODEL_DIR / f"scaler_{timestamp}.pkl"
    
    with open(model_path, "wb") as f:
        pickle.dump(clf, f)
    with open(scaler_path, "wb") as f:
        pickle.dump(scaler, f)
        
    print(f"\n[+] Saved Isolation Forest -> {model_path}")
    print(f"[+] Saved IF Scaler        -> {scaler_path}")


def train_pytorch_cnn(records):
    """Train the Layer 3 PyTorch CNN on raw base64 payloads."""
    print("\n" + "="*50)
    print("--- Training Layer 3: PyTorch CNN Payload Classifier ---")
    
    import base64
    
    # 1. Filter records that actually have a payload
    payload_records = [r for r in records if r.get("payload") is not None]
    print(f"[*] Found {len(payload_records)} records with payload bytes.")
    
    if len(payload_records) == 0:
        print("[!] Not enough payload data to train CNN. Skipping.")
        return
        
    # 2. Prepare Tensors
    X_list = []
    y_list = []
    
    for r in payload_records:
        try:
            raw_bytes = base64.b64decode(r["payload"])
        except Exception:
            continue
            
        # Truncate or pad to 1024 bytes (CNN input size)
        data = list(raw_bytes[:1024])
        if len(data) < 1024:
            data += [0] * (1024 - len(data))
            
        # Normal=0, Attack=1
        label = 0 if r.get("label", "benign") == "benign" else 1
        
        X_list.append(data)
        y_list.append(label)
        
    if not X_list:
        return
        
    # Create normalized float tensor: [Batch, Channel=1, Length=1024]
    X_tensor = torch.tensor(X_list, dtype=torch.float32) / 255.0
    X_tensor = X_tensor.unsqueeze(1) 
    y_tensor = torch.tensor(y_list, dtype=torch.long)
    
    print(f"[*] Tensor shape: X={X_tensor.shape}, y={y_tensor.shape}")
    
    # 3. Setup Model & Training Loop
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"[*] Using device: {device}")
    
    model = PayloadClassifier(input_len=1024).to(device)
    criterion = nn.CrossEntropyLoss()
    optimizer = optim.Adam(model.parameters(), lr=0.001)
    
    dataset = torch.utils.data.TensorDataset(X_tensor, y_tensor)
    loader = torch.utils.data.DataLoader(dataset, batch_size=32, shuffle=True)
    
    epochs = 10
    print(f"[*] Starting training for {epochs} epochs...")
    
    model.train()
    for epoch in range(epochs):
        total_loss = 0
        correct = 0
        total = 0
        
        for batch_X, batch_y in loader:
            batch_X, batch_y = batch_X.to(device), batch_y.to(device)
            
            optimizer.zero_grad()
            outputs = model(batch_X)
            loss = criterion(outputs, batch_y)
            loss.backward()
            optimizer.step()
            
            total_loss += loss.item()
            _, predicted = torch.max(outputs.data, 1)
            total += batch_y.size(0)
            correct += (predicted == batch_y).sum().item()
            
        acc = 100 * correct / total
        print(f"    Epoch {epoch+1}/{epochs} | Loss: {total_loss/len(loader):.4f} | Accuracy: {acc:.2f}%")
    
    # 4. Evaluate on full dataset
    print("\n[*] Evaluating CNN on full dataset...")
    model.eval()
    all_preds = []
    all_labels = []
    with torch.no_grad():
        for batch_X, batch_y in loader:
            batch_X = batch_X.to(device)
            outputs = model(batch_X)
            _, predicted = torch.max(outputs.data, 1)
            all_preds.extend(predicted.cpu().numpy())
            all_labels.extend(batch_y.numpy())
    
    target_names = ["Benign", "Malicious"]
    print(classification_report(
        all_labels, all_preds, target_names=target_names, zero_division=0
    ))
    
    cm = confusion_matrix(all_labels, all_preds)
    print("    Confusion Matrix:")
    print(f"    {'':>12} Pred:Benign  Pred:Malicious")
    for i, label in enumerate(target_names):
        row = cm[i] if i < len(cm) else [0, 0]
        vals = "  ".join(f"{v:>12}" for v in row)
        print(f"    {label:>12}  {vals}")
        
    # 5. Save
    save_path = MODEL_DIR / "payload_classifier.pth"
    torch.save(model.state_dict(), save_path)
    print(f"\n[+] Saved PyTorch CNN weights -> {save_path}")


def validate_saved_models():
    """Reload saved models from disk and verify they produce valid output."""
    print("\n" + "=" * 50)
    print("--- Validating Saved Models ---")
    
    ok = True
    
    # 1. Isolation Forest
    model_path = MODEL_DIR / "model_00000000_000000.pkl"
    scaler_path = MODEL_DIR / "scaler_00000000_000000.pkl"
    if model_path.exists() and scaler_path.exists():
        with open(model_path, "rb") as f:
            model = pickle.load(f)
        with open(scaler_path, "rb") as f:
            scaler = pickle.load(f)
        
        dummy = np.random.randn(5, len(IF_FEATURES))
        scaled = scaler.transform(dummy)
        preds = model.predict(scaled)
        scores = model.decision_function(scaled)
        
        if len(preds) == 5 and len(scores) == 5:
            print(f"[✓] Isolation Forest: loaded, predictions OK "
                  f"(shapes: preds={preds.shape}, scores={scores.shape})")
        else:
            print("[✗] Isolation Forest: prediction shape mismatch")
            ok = False
    else:
        print("[✗] Isolation Forest: model files not found")
        ok = False
    
    # 2. CNN
    cnn_path = MODEL_DIR / "payload_classifier.pth"
    if cnn_path.exists():
        try:
            from src.argus_v.mnemosyne.pytorch_model import PayloadClassifier
            cnn = PayloadClassifier(input_len=1024)
            cnn.load_state_dict(torch.load(cnn_path, weights_only=True))
            cnn.eval()
            
            dummy_input = torch.randn(2, 1, 1024)
            with torch.no_grad():
                out = cnn(dummy_input)
            
            if out.shape == (2, 2):
                print(f"[✓] CNN Payload Classifier: loaded, output shape {out.shape} OK")
            else:
                print(f"[✗] CNN: unexpected output shape {out.shape}")
                ok = False
        except Exception as e:
            print(f"[✗] CNN validation failed: {e}")
            ok = False
    else:
        print("[!] CNN: weights file not found (may have been skipped)")
    
    return ok


def main():
    records = load_data()
    train_isolation_forest(records)
    train_pytorch_cnn(records)
    
    valid = validate_saved_models()
    
    if valid:
        print("\n[✓] All models trained and validated. Aegis will load these on boot.")
    else:
        print("\n[!] Training completed with validation warnings — check output above.")
        sys.exit(1)


if __name__ == "__main__":
    main()
