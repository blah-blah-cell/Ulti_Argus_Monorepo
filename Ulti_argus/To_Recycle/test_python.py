#!/usr/bin/env python3
"""Simple test to verify Python execution and imports."""
import sys

print(f"Python version: {sys.version}")

try:
    import sklearn
    print(f"sklearn version: {sklearn.__version__}")
except Exception as e:
    print(f"sklearn import error: {e}")
    
try:
    import pandas
    print(f"pandas version: {pandas.__version__}")
except Exception as e:
    print(f"pandas import error: {e}")

try:
    import numpy
    print(f"numpy version: {numpy.__version__}")
except Exception as e:
    print(f"numpy import error: {e}")

print("Basic imports test complete!")
