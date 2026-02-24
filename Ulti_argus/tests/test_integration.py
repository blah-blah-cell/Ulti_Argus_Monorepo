import os
import sys

# Ensure src is in path (Two levels up if in tests/ subdir, but let's be robust)
# d:\Argus_AI\tests\test_integration.py -> dirname = d:\Argus_AI\tests -> .. = d:\Argus_AI
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../")))

from argus_v.mnemosyne.pytorch_inference import analyze_payload


def test_integration():
    print("TEST: Initializing Neural Engine...")
    
    # Create a dummy payload (HTTP GET request simulation)
    normal_payload = b"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
    anomalous_payload = os.urandom(1024) # Random noise
    
    print(f"TEST: Analyzing Normal Payload ({len(normal_payload)} bytes)...")
    score_normal = analyze_payload(normal_payload)
    print(f"RESULT: Score = {score_normal:.6f}")
    
    print(f"TEST: Analyzing Random/Anomalous Payload ({len(anomalous_payload)} bytes)...")
    score_anomaly = analyze_payload(anomalous_payload)
    print(f"RESULT: Score = {score_anomaly:.6f}")
    
    # Since the model is uninitialized, we just check that it runs and produces a float.
    # In a trained model, score_anomaly should typically be higher.
    assert isinstance(score_normal, float)
    assert isinstance(score_anomaly, float)
    print("SUCCESS: Pipeline is functional.")

if __name__ == "__main__":
    test_integration()
