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
    
    # 4. Save
    # We use a fixed timestamp to represent the "Foundation" model,
    # or the installer will just point Aegis at these files.
    timestamp = "00000000_000000"
    model_path = MODEL_DIR / f"model_{timestamp}.pkl"
    scaler_path = MODEL_DIR / f"scaler_{timestamp}.pkl"
    
    with open(model_path, "wb") as f:
        pickle.dump(clf, f)
    with open(scaler_path, "wb") as f:
        pickle.dump(scaler, f)
        
    print(f"[+] Saved Isolation Forest -> {model_path}")
    print(f"[+] Saved IF Scaler      -> {scaler_path}")


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
        
    # 4. Save
    save_path = MODEL_DIR / "payload_classifier.pth"
    torch.save(model.state_dict(), save_path)
    print(f"[+] Saved PyTorch CNN weights -> {save_path}")


def main():
    records = load_data()
    train_isolation_forest(records)
    train_pytorch_cnn(records)
    print("\n[*] All models trained successfully. Aegis will load these on boot.")

if __name__ == "__main__":
    main()
