#!/usr/bin/env python3
"""Run the training script and save output to file."""
import subprocess
import sys

result = subprocess.run(
    [sys.executable, "/home/engine/project/scripts/train_nsl_kdd.py"],
    capture_output=True,
    text=True,
    timeout=300
)

print("STDOUT:", result.stdout)
print("STDERR:", result.stderr)
print("Return code:", result.returncode)
