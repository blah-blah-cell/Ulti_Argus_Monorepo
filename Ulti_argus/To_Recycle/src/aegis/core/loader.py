import argparse
import os
import socket
import struct
import sys

from bcc import BPF

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../")))
from src.argus_plugins.manager import plugin_manager

# Define the C struct in Python to decode the perf buffer
# struct flow_feature_t {
#     u32 src_ip;
#     u32 dst_ip;
#     u16 src_port;
#     u16 dst_port;
#     u32 packet_len;
#     u32 timestamp;
# };

def handle_event(cpu, data, size):
    event = b["events"].event(data)
    
    # Construct a flow dict to pass to plugins
    flow_data = {
        "src_ip": inet_ntoa(event.src_ip),
        "dst_ip": inet_ntoa(event.dst_ip),
        "src_port": socket.ntohs(event.src_port),
        "dst_port": socket.ntohs(event.dst_port),
        "num_len": event.packet_len,
        "timestamp": event.timestamp  # eBPF time in nanoseconds
    }
    
    # print(f"[{time.strftime('%H:%M:%S')}] Pkt: {flow_data['src_ip']}:{flow_data['src_port']} "
    #       f"-> {flow_data['dst_ip']}:{flow_data['dst_port']} len={flow_data['len']}")

    # Pass to Plugin Manager
    plugin_manager.run_on_packet(flow_data)

def inet_ntoa(addr):
    # eBPF IPs are in network byte order already
    return socket.inet_ntoa(struct.pack("I", addr))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Argus Aegis Core (eBPF Loader)")
    parser.add_argument("-i", "--interface", help="Network interface to attach to (e.g., eth0)", required=True)
    args = parser.parse_args()

    print(f"[*] Loading eBPF program on {args.interface}...")
    
    # Initialize Plugins
    plugin_manager.discover_and_load()
    
    # Load eBPF program
    b = BPF(src_file="src/aegis/core/filter.c")
    
    # Attach XDP function
    fn = b.load_func("xdp_prog", BPF.XDP)
    b.attach_xdp(args.interface, fn, 0)

    print("[*] Successfully attached XDP hook. Press Ctrl+C to stop.")
    
    try:
        # Open perf buffer
        b["events"].open_perf_buffer(handle_event)
        while True:
            try:
                b.perf_buffer_poll()
            except KeyboardInterrupt:
                break
    finally:
        print("\n[*] Detaching XDP hook...")
        b.remove_xdp(args.interface, 0)
        print("[*] Done.")
