import requests
import time
import json

API_URL = "http://localhost:8000"

payloads = [
    {"desc": "Normal User Search", "payload": "GET /search?q=cybersecurity HTTP/1.1"},
    {"desc": "Malicious SQLi", "payload": "GET /search?q=' OR 1=1 -- HTTP/1.1"},
    {"desc": "XSS Attempt", "payload": "<script>alert('pwned')</script>"},
    {"desc": "System Discovery", "payload": "cat /etc/passwd"},
    {"desc": "Honey-Mesh Target", "payload": "GET /admin/db_config.php HTTP/1.1"},
    {"desc": "DICOM PHI Leak", "payload": "DICM PatientName: John Doe BirthDate: 19800101"},
]

print(f"[*] Starting Live Integration Test against {API_URL}")

for p in payloads:
    print(f"[>] Sending: {p['desc']}")
    try:
        r = requests.post(f"{API_URL}/analyze", json={"payload": p["payload"]}, timeout=5)
        data = r.json()
        print(f"    [Result] Judgment: {data['judgment']} | Score: {data['score']:.4f}")
    except Exception as e:
        print(f"    [Error] {e}")
    time.sleep(1)

print("\n[*] Fetching live logs from dashboard...")
r = requests.get(f"{API_URL}/logs")
logs = r.json()
for l in logs[:5]:
    print(f"    [{l['time']}] {l['type']} - {l['desc']}")

print("\n[*] Fetching system stats...")
r = requests.get(f"{API_URL}/stats")
stats = r.json()
print(f"    Total Scanned: {stats['packets_scanned']}")
print(f"    Threats Blocked: {stats['threats_blocked']}")
print(f"    System RAM: {stats['memory_info']} ({stats['memory_percent']}%)")
