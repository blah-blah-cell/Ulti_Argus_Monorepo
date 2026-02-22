#!/bin/bash
set -e

# Cleanup function
cleanup() {
    echo "Cleaning up..."
    # ip link del veth-server 2>/dev/null || true
    pkill -f userspace || true
}
trap cleanup EXIT

# 1. Setup Veth Pair
echo "Setting up veth pair..."
sudo ip link del veth-server 2>/dev/null || true
sudo ip link add veth-server type veth peer name veth-client
sudo ip link set veth-server up
sudo ip link set veth-client up
sudo ip addr add 192.168.50.1/24 dev veth-server
sudo ip addr add 192.168.50.2/24 dev veth-client

# Disable offloading to be safe with XDP (generic mode handles it, but good practice)
sudo ethtool -K veth-server rx off tx off 2>/dev/null || true
sudo ethtool -K veth-client rx off tx off 2>/dev/null || true

# 2. Run Userspace

echo "Starting DeepPacketSentinel on veth-server..."
# Run in background, redirect output
# We need to run as root for XDP
sudo RUST_LOG=info ./target/debug/userspace --iface veth-server > sentinel.log 2>&1 &
PID=$!

echo "Waiting for startup..."
sleep 5

# 3. Send Traffic
echo "Sending ping from veth-client..."
# We expect some loss if XDP drops or redirects to blackhole (FD=0)
ping -c 4 192.168.50.1 -I veth-client || true

# 4. Check Logs
echo "Checking logs..."
cat sentinel.log

if grep -q "DeepPacketSentinel attached" sentinel.log; then
    echo "SUCCESS: Program attached."
else
    echo "FAILURE: Program did not attach."
    exit 1
fi

if grep -q "Telemetry: Packet" sentinel.log; then
    echo "SUCCESS: Telemetry received."
else
    echo "WARNING: No telemetry received."
fi

if grep -q "Data Plane Worker" sentinel.log; then
     echo "SUCCESS: Worker thread started."
fi
