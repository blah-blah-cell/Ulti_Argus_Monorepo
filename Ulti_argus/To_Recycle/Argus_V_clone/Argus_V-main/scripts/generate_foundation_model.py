#!/usr/bin/env python3
"""
Generate a Synthetic Foundation Model for Argus_V.

This script creates a "Cold Start" model by training an Isolation Forest
on synthetic data that approximates normal IoT network traffic patterns
(DNS, HTTP, NTP, etc.).

This solves the "Security Theater" problem of starting with a random model.
"""

import argparse
import pickle
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

# Define features used by Argus_V
FEATURE_COLUMNS = [
    "bytes_in",
    "bytes_out",
    "packets_in",
    "packets_out",
    "duration",
    "src_port",
    "dst_port",
    "protocol",
]

def generate_synthetic_traffic(n_samples=5000):
    """
    Generate synthetic network traffic data representing "normal" behavior.

    Simulates:
    - DNS (UDP 53): Small packets, short duration.
    - HTTP/HTTPS (TCP 80/443): Larger packets, variable duration.
    - NTP (UDP 123): Very small, periodic.
    - SSH (TCP 22): Interactive, keep-alives.
    """
    data = []

    # Traffic mix ratios
    n_dns = int(n_samples * 0.3)
    n_http = int(n_samples * 0.5)
    n_ntp = int(n_samples * 0.1)
    n_ssh = int(n_samples * 0.1)

    # 1. DNS Traffic (UDP 53)
    # Typically small queries/responses
    for _ in range(n_dns):
        data.append({
            "bytes_in": np.random.normal(80, 20),
            "bytes_out": np.random.normal(120, 30),
            "packets_in": np.random.randint(1, 3),
            "packets_out": np.random.randint(1, 3),
            "duration": np.abs(np.random.exponential(0.05)),
            "src_port": np.random.randint(49152, 65535),
            "dst_port": 53,
            "protocol": 2, # UDP
        })

    # 2. HTTP/HTTPS Traffic (TCP 80/443)
    # Browsing, updates, API calls
    for _ in range(n_http):
        dst_port = np.random.choice([80, 443])
        if dst_port == 443:
            # TLS handshake overhead + data
            b_in = np.random.lognormal(8, 1)  # ~3000 bytes
            b_out = np.random.lognormal(7, 1) # ~1000 bytes
        else:
            b_in = np.random.lognormal(7, 1)
            b_out = np.random.lognormal(6, 1)

        data.append({
            "bytes_in": b_in,
            "bytes_out": b_out,
            "packets_in": np.random.randint(5, 50),
            "packets_out": np.random.randint(4, 40),
            "duration": np.abs(np.random.exponential(1.0)),
            "src_port": np.random.randint(49152, 65535),
            "dst_port": dst_port,
            "protocol": 1, # TCP
        })

    # 3. NTP Traffic (UDP 123)
    for _ in range(n_ntp):
        data.append({
            "bytes_in": 48,
            "bytes_out": 48,
            "packets_in": 1,
            "packets_out": 1,
            "duration": np.abs(np.random.normal(0.01, 0.005)),
            "src_port": 123,
            "dst_port": 123,
            "protocol": 2, # UDP
        })

    # 4. SSH Traffic (TCP 22) - Management
    for _ in range(n_ssh):
        data.append({
            "bytes_in": np.random.lognormal(9, 1),
            "bytes_out": np.random.lognormal(9, 1),
            "packets_in": np.random.randint(20, 100),
            "packets_out": np.random.randint(20, 100),
            "duration": np.abs(np.random.exponential(30.0)), # Longer sessions
            "src_port": np.random.randint(49152, 65535),
            "dst_port": 22,
            "protocol": 1, # TCP
        })

    return pd.DataFrame(data)

def main():
    parser = argparse.ArgumentParser(description="Generate Foundation Model")
    parser.add_argument("--output-dir", type=str, default="src/argus_v/data", help="Output directory")
    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    print("Generating synthetic traffic data...")
    df = generate_synthetic_traffic(10000)

    # Ensure correct column order
    df = df[FEATURE_COLUMNS]

    print("Training Foundation Model (Isolation Forest)...")

    # Initialize Scaler
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(df)

    # Train Model
    # Contamination set low because this is "normal" data, but we allow some noise
    model = IsolationForest(
        n_estimators=100,
        contamination=0.01, # Assume 1% noise in our synthetic data
        random_state=42,
        n_jobs=-1
    )
    model.fit(X_scaled)

    # Save Artifacts
    model_path = output_dir / "foundation_model.pkl"
    scaler_path = output_dir / "foundation_scaler.pkl"

    with open(model_path, 'wb') as f:
        pickle.dump(model, f)

    with open(scaler_path, 'wb') as f:
        pickle.dump(scaler, f)

    print(f"✅ Foundation Model saved to: {model_path}")
    print(f"✅ Foundation Scaler saved to: {scaler_path}")

    # Validation check
    print("\nVerifying model...")
    test_normal = scaler.transform(df.iloc[:5])
    preds = model.predict(test_normal)
    print(f"Predictions on normal data (should be 1): {preds}")

if __name__ == "__main__":
    main()
