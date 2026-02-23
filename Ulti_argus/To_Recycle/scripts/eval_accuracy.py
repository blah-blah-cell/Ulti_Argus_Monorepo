import os
import sys

import torch
from torch.utils.data import DataLoader, TensorDataset

# Ensure src is in path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../")))
from src.mnemosyne.model import PayloadClassifier

MODEL_PATH = "d:/Argus_AI/models/payload_classifier.pth"

# Reuse data generation functions from training script (duplicate for simplicity)
import random


def generate_normal_payload():
    methods = [b"GET", b"POST"]
    paths = [b"/api/login", b"/api/user", b"/api/data", b"/index.html", b"/style.css"]
    users = [b"alice", b"bob", b"admin", b"user123"]
    keys = [b"id", b"token", b"value", b"timestamp"]
    m = random.choice(methods)
    p = random.choice(paths)
    payload = m + b" " + p + b" HTTP/1.1\r\n"
    payload += b"Host: api.internal\r\n"
    payload += b"Content-Type: application/json\r\n"
    if m == b"POST":
        u = random.choice(users)
        k = random.choice(keys)
        v = str(random.randint(1000, 9999)).encode()
        body = b'{"user": "' + u + b'", "' + k + b'": ' + v + b'}'
        payload += b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n"
        payload += body
    else:
        payload += b"\r\n"
    byte_list = list(payload[:1024])
    if len(byte_list) < 1024:
        byte_list += [0] * (1024 - len(byte_list))
    return byte_list

def generate_attack_payload():
    attack_type = random.choice(["sqli", "xss"])
    if attack_type == "sqli":
        payload = b"GET /search?q=' OR '1'='1 HTTP/1.1\r\nHost: vulnerable.site\r\n\r\n"
    else:
        payload = b"GET /page?input=<script>alert('xss')</script> HTTP/1.1\r\nHost: vulnerable.site\r\n\r\n"
    byte_list = list(payload[:1024])
    if len(byte_list) < 1024:
        byte_list += [0] * (1024 - len(byte_list))
    return byte_list

def generate_test_data(num_normal=500, num_attack=500):
    data = []
    labels = []
    for _ in range(num_normal):
        data.append(generate_normal_payload())
        labels.append(0)
    for _ in range(num_attack):
        data.append(generate_attack_payload())
        labels.append(1)
    combined = list(zip(data, labels))
    random.shuffle(combined)
    data[:], labels[:] = zip(*combined)
    data_tensor = torch.tensor(data, dtype=torch.float32) / 255.0
    label_tensor = torch.tensor(labels, dtype=torch.long)
    return data_tensor, label_tensor

def evaluate():
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model = PayloadClassifier().to(device)
    model.load_state_dict(torch.load(MODEL_PATH, map_location=device))
    model.eval()
    data_tensor, label_tensor = generate_test_data()
    dataset = TensorDataset(data_tensor, label_tensor)
    loader = DataLoader(dataset, batch_size=32, shuffle=False)
    correct = 0
    total = 0
    with torch.no_grad():
        for inputs, targets in loader:
            inputs = inputs.to(device).unsqueeze(1)
            targets = targets.to(device)
            logits = model(inputs)
            preds = torch.argmax(logits, dim=1)
            correct += (preds == targets).sum().item()
            total += targets.size(0)
    acc = correct / total * 100
    print(f"Accuracy: {acc:.2f}%")
    # Exit code 0 if >=90, else 1
    sys.exit(0 if acc >= 90 else 1)

if __name__ == "__main__":
    evaluate()
