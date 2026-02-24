import os
import random
import time

# ANSI Colors
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
CYAN = "\033[96m"
WHITE = "\033[97m"
RESET = "\033[0m"

LOG_FILE = "/var/log/argus/proxy.log"

def clear_screen():
    print("\033[2J\033[H", end="")

def banner():
    print(f"{CYAN}   _____  __________  ________  __________{RESET}")
    print(f"{CYAN}  /  _  \\ \\______   \\/  _____/ /  ___/    |{RESET}")
    print(f"{CYAN} /  /_\\  \\ |       _/   \\  ___ \\___  \\|    |{RESET}")
    print(f"{CYAN}/    |    \\|    |   \\    \\_\\  \\/    /|    |__ /\\{RESET}")
    print(f"{CYAN}\\____|__  /|____|_  /\\______  /____//_______  /){RESET}")
    print(f"{CYAN}        \\/        \\/        \\/              \\/{RESET}")
    print(f"{WHITE}    :: NEURAL KERNEL INTERFACE v0.3 ::{RESET}")
    print("-" * 50)

def draw_bar(val, max_val=1.0, width=30):
    percent = val / max_val
    filled = int(width * percent)
    
    color = GREEN
    if val > 0.05:
        color = YELLOW
    if val > 0.15:
        color = RED
    
    bar = "=" * filled
    empty = " " * (width - filled)
    return f"[{color}{bar}{empty}{RESET}] {val:.4f}"

def tail_f(file_path):
    if not os.path.exists(file_path):
        return
    with open(file_path, "r") as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.1)
                continue
            yield line

def main():
    # Ensure log dir exists for demo
    if not os.path.exists("/var/log/argus"):
        try:
             os.makedirs("/var/log/argus")
             with open(LOG_FILE, "w") as f:
                 f.write("[*] Log initialized\n")
        except Exception:
             pass 

    print("Initializing ARGUS Neuro-Link...")
    time.sleep(1)
    
    last_score = 0.0
    packets_processed = 0
    threats_blocked = 0
    
    # In a real scenario we read from the log file continuously.
    # For this demo, we can simulate if file doesn't update, 
    # but let's try to read real logs.
    
    log_file_sim = None
    if not os.path.exists(LOG_FILE):
         print(f"{YELLOW}[!] Log file {LOG_FILE} not found. Running Simulation Mode.{RESET}")
         log_file_sim = True
    
    try:
        while True:
            clear_screen()
            banner()
            
            # Simulate or Read data
            if log_file_sim:
                 # Generate fake fluctuation
                 if random.random() < 0.1:
                     last_score = random.uniform(0.0, 0.2) # Spike
                 else:
                     last_score = random.uniform(0.0, 0.01) # Baseline
                 packets_processed += random.randint(1, 10)
                 if last_score > 0.05:
                     threats_blocked += 1
            
            print(f"{WHITE}SYSTEM STATUS    :{RESET} {GREEN}ONLINE{RESET}")
            print(f"{WHITE}KERNEL HOOK      :{RESET} {GREEN}ACTIVE (eBPF XDP){RESET}")
            print(f"{WHITE}NEURAL ENGINE    :{RESET} {GREEN}MNEMOSYNE v1.0{RESET}")
            print("-" * 50)
            print(f"PACKETS PROCESSED: {packets_processed}")
            print(f"THREATS BLOCKED  : {threats_blocked}")
            print("-" * 50)
            
            print("LIVE THREAT SCORES (ANOMALY):")
            print(f"INBOUND LOAD: {draw_bar(last_score)}")
            
            # History Visualization (Fake scrolling graph)
            # In a real app we'd keep a list of history.
            
            if last_score > 0.05:
                print(f"\n{RED}[!] ANOMALY DETECTED - PATTERN REJECTED{RESET}")
            
            time.sleep(0.5)

    except KeyboardInterrupt:
        print("\n[!] Disconnected.")

if __name__ == "__main__":
    main()
