import os
import platform
import sys

import torch

# Ensure src path
FEATURE_DIR = "d:/Argus_AI"
sys.path.append(FEATURE_DIR)

def check_step(name, status, details=""):
    symbol = "✅" if status else "❌"
    print(f"{symbol} [{name:<20}]: {details}")

def run_diagnostics():
    print("="*60)
    print(f"ARGUS AI SYSTEM DIAGNOSTIC TOOL - {platform.system()}")
    print("="*60)

    # 1. Environment Check
    print("\n[!] Checking Environment...")
    check_step("Python Version", sys.version_info.major == 3, sys.version.split()[0])
    check_step("OS Compatibility", platform.system() in ["Linux", "Windows"], platform.system())
    
    # 2. Filesystem Check
    print("\n[!] Checking Filesystem...")
    required_paths = [
        "src/aegis/core/filter.c",
        "src/aegis/proxy/interceptor.py",
        "src/mnemosyne/model.py",
        "models/payload_ae.pth",
        "src/argus_plugins/manager.py"
    ]
    for p in required_paths:
        full_p = os.path.join(FEATURE_DIR, p)
        exists = os.path.exists(full_p)
        check_step(os.path.basename(p), exists, full_p if not exists else "Found")
        if not exists:
            pass
        
    # 3. AI Brain Check
    print("\n[!] Checking Mnemosyne (AI Brain)...")
    try:
        model_path = os.path.join(FEATURE_DIR, "models/payload_ae.pth")
        if os.path.exists(model_path):
            torch.load(model_path, map_location='cpu')
            check_step("Model Weights", True, "Loaded successfully")
            
            from src.mnemosyne.inference import analyze_payload
            score = analyze_payload(b"TEST_PAYLOAD")
            check_step("Inference Engine", True, f"Test Inference Score: {score:.6f}")
        else:
            check_step("Model Weights", False, "File missing!")
    except Exception as e:
        check_step("Inference Engine", False, str(e))

    # 4. Plugin System Check
    print("\n[!] Checking Plugin System...")
    try:
        from src.argus_plugins.manager import PluginManager
        pm = PluginManager(plugin_dir=os.path.join(FEATURE_DIR, "src/argus_plugins"))
        pm.discover_and_load()
        count = len(pm.plugins)
        
        check_step("Plugin Loader", True, f"Found {count} plugins")
        
        for p in pm.plugins:
            print(f"    - {p.name()}: {p.description()[:40]}...")
            
    except Exception as e:
        check_step("Plugin Loader", False, str(e))

    # 5. Kernel Check (Simulation on Windows)
    print("\n[!] Checking Kernel Subsystem...")
    if platform.system() == "Linux":
        # Check for BCC
        try:
            from bcc import BPF  # noqa: F401
            check_step("eBPF Support", True, "BCC Library Available")
        except ImportError:
            check_step("eBPF Support", False, "BCC not installed (Required for Aegis Kernel)")
    else:
        check_step("eBPF Support", False, "Simulation Mode (Windows doesn't support XDP)")

    print("\n" + "="*60)
    print("DIAGNOSTIC COMPLETE")
    print("="*60)

if __name__ == "__main__":
    run_diagnostics()
