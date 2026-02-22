import time
import sqlite3
import shutil
import tempfile
import threading
from pathlib import Path
from argus_v.aegis.blacklist_manager import BlacklistManager
from argus_v.oracle_core.anonymize import HashAnonymizer

class MockConfig:
    def __init__(self, temp_dir):
        self.blacklist_db_path = str(temp_dir / "blacklist.db")
        self.blacklist_json_path = str(temp_dir / "blacklist.json")
        self.iptables_chain_name = "TEST"
        self.emergency_stop_file = str(temp_dir / "emergency.stop")

def setup_benchmark():
    temp_dir = Path(tempfile.mkdtemp())
    config = MockConfig(temp_dir)
    anonymizer = HashAnonymizer(salt="benchmark")
    manager = BlacklistManager(config, anonymizer)

    # Populate blacklist
    print("Populating blacklist...")
    with sqlite3.connect(config.blacklist_db_path) as conn:
        cursor = conn.cursor()
        for i in range(1000):
            ip = f"192.168.1.{i % 255}"
            cursor.execute("""
                INSERT OR REPLACE INTO blacklist
                (ip_address, reason, source, risk_level, is_active)
                VALUES (?, ?, ?, ?, ?)
            """, (anonymizer.anonymize_ip(ip), "Benchmark", "prediction", "high", True))
        conn.commit()

    return manager, temp_dir

def run_benchmark(manager, iterations=1000):
    start_time = time.time()
    for i in range(iterations):
        ip = f"192.168.1.{i % 255}"
        manager.is_blacklisted(ip)
    end_time = time.time()
    return end_time - start_time

def main():
    manager, temp_dir = setup_benchmark()
    try:
        iterations = 5000
        print(f"Running benchmark with {iterations} iterations...")

        # Warmup
        run_benchmark(manager, 100)

        # Benchmark
        duration = run_benchmark(manager, iterations)
        ops_per_sec = iterations / duration

        print(f"Time taken: {duration:.4f} seconds")
        print(f"Operations per second: {ops_per_sec:.2f}")

    finally:
        shutil.rmtree(temp_dir)

if __name__ == "__main__":
    main()
