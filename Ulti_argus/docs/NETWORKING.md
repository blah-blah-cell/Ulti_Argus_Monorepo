# ARGUS Network Configuration Guide

This guide covers network setup for ARGUS Raspberry Pi deployment. It explains different network topologies and provides configuration examples for common equipment.

---

## Network Topology Options

### Option A: Inline Deployment (Pi Between Router and LAN)

In this setup, all network traffic flows through the Raspberry Pi. This gives ARGUS complete visibility but requires the Pi to be always on.

```
                                    Inline Deployment Topology
                                    ==========================

    Internet
        │
        ▼
┌─────────────────┐
│   ISP Router    │
│   (or Modem)    │
└────────┬────────┘
         │  WAN (from ISP)
         │
         ▼
┌─────────────────────────────────────────────────────────────┐
│                    ETHERNET CABLE                           │
│    (Pi monitors all traffic passing through it)             │
└─────────────────────────────────────────────────────────────┘
         │
         ▼
┌─────────────────────┐
│   Raspberry Pi 4    │
│   ┌───────────────┐ │
│   │   ARGUS v0    │ │
│   │  (Monitoring) │ │
│   └───────────────┘ │
└─────────┬───────────┘
          │
          ▼
┌─────────────────────────────────────────────────────────────┐
│                    ETHERNET CABLE                           │
│              (traffic to/from devices)                      │
└─────────────────────────────────────────────────────────────┘
          │
          ▼
┌───────────────────────────┐
│     Network Switch        │
│     (or direct devices)   │
└───────────┬───────────────┘
            │
    ┌───────┴───────┬───────────────┐
    ▼               ▼               ▼
┌───────┐     ┌───────┐       ┌───────┐
│ PC 1  │     │ PC 2  │       │ Other │
│       │     │       │       │Devices│
└───────┘     └───────┘       └───────┘


Advantages:                      Disadvantages:
- Complete traffic visibility    - Pi must always be on
- No switch configuration        - Pi adds slight latency
- Simple setup                   - Network fails if Pi fails
```

**Important Notes for Inline Deployment:**
- The Pi needs two Ethernet ports (or use a USB Ethernet adapter)
- All traffic between router and devices passes through the Pi
- If Pi fails or loses power, network connectivity is interrupted

### Option B: Port Mirroring / SPAN (Recommended)

In this setup, the Pi connects to a switch that copies all traffic to the Pi's port. This is the recommended method.

```
                            Port Mirroring / SPAN Topology
                            ==============================

    Internet
        │
        ▼
┌─────────────────┐
│   ISP Router    │
└────────┬────────┘
         │
         ▼
┌───────────────────────────┐
│   Managed Network Switch  │
│   ┌─────────────────────┐ │
│   │  SPAN/Mirror Port   │◄────┐
│   │  (copies all traffic)    │
│   └─────────────────────┘     │
└───────────┬───────────────────┘
            │
    ┌───────┴───────┬───────────────┐
    ▼               ▼               ▼
┌───────┐     ┌───────┐       ┌───────┐
│ PC 1  │     │ PC 2  │       │ Other │
│       │     │       │       │Devices│
└───────┘     └───────┘       └───────┘
            │
            ▼
┌─────────────────────┐
│   Raspberry Pi 4    │
│   ┌───────────────┐ │
│   │   ARGUS v0    │ │
│   │  (Monitoring) │ │
│   └───────────────┘ │
└─────────────────────┘


Advantages:                      Disadvantages:
- No impact on network speed    - Requires managed switch
- Network works if Pi fails     - Switch configuration needed
- Full traffic visibility       - Some switches lack SPAN feature
- No single point of failure
```

---

## ISP Router Configuration

Most consumer routers don't support port mirroring. If you have a basic ISP router, you have two options:

1. **Put a managed switch after the router** (recommended)
2. **Use inline deployment** with a second network adapter

### Common ISP Router Settings

**Finding Your Router's IP Address:**

```bash
# On the Pi or any computer
ip route | grep default
```

The output shows your router IP:
```
default via 192.168.1.1 dev eth0 proto dhcp metric 100
```

**Accessing Router Admin Panel:**

1. Open a web browser
2. Enter the router IP (e.g., `http://192.168.1.1`)
3. Log in with admin credentials (check router label or documentation)

### Example: TP-Link Router

```
Step 1: Login to router admin panel
        http://192.168.0.1 or http://192.168.1.1

Step 2: Navigate to: Advanced → Network → DHCP Client List
        Note the MAC address of your Pi: AA:BB:CC:DD:EE:FF

Step 3: Reserve a static IP for the Pi:
        Advanced → Network → Address Reservation
        Add: 192.168.1.100 → AA:BB:CC:DD:EE:FF

Step 4: For port mirroring, look for:
        Advanced → NAT Forwarding → Port Mirroring
        Or: Forwarding → Port Triggering
```

### Example: Netgear Router

```
Step 1: Login at http://routerlogin.net or http://192.168.1.1

Step 2: Advanced → Setup → LAN Setup
        Set static IP for Pi (e.g., 192.168.1.100)

Step 3: For port mirroring:
        Advanced → Advanced Setup → Port Mirroring
        Source: All ports
        Destination: Port connected to Pi
```

### Example: ASUS Router

```
Step 1: Login at http://router.asus.com or http://192.168.1.1

Step 2: LAN → DHCP Server
        Set static IP for Pi

Step 3: For monitoring:
        WAN → Port Triggering
        Or: Traffic Manager → Traffic Analyzer
```

**Note:** Many ISP-provided routers have limited features. For advanced port mirroring, consider adding a managed switch.

---

## Managed Switch SPAN Configuration

A managed switch allows you to copy (mirror) all network traffic to a specific port where the Pi is connected.

### Cisco Switch Configuration

```bash
# Connect to switch via console or SSH
# Enter configuration mode

enable
configure terminal

# Create a SPAN session
# Session 1, source = all ports, destination = port Gi1/0/10 (where Pi is connected)

monitor session 1 source interface Gi1/0/1-24 both
monitor session 1 destination interface Gi1/0/10

# Verify configuration
show monitor session 1

# Save configuration
write memory
```

**Explanation:**
- `source interface Gi1/0/1-24 both` = Monitor ports 1-24, both incoming and outgoing traffic
- `destination interface Gi1/0/10` = Send copied traffic to port 10 (where Pi connects)
- `both` = Capture traffic in both directions (Rx and Tx)

**Alternative: VLAN-based SPAN**

```bash
# Monitor entire VLAN
monitor session 1 source vlan 10 both
monitor session 1 destination interface Gi1/0/10
```

### Dell Switch Configuration

```bash
# Connect via serial console or SSH

enable
configure

# Create SPAN session
monitor session 1 source interface Gi1/0/1-24 rx tx
monitor session 1 destination interface Gi1/0/10

# Verify
show monitor session 1

# Save
write memory
```

### Ubiquiti UniFi Switch Configuration

```
Step 1: Access UniFi Network Controller (web UI)

Step 2: Go to: Settings → Profiles → Switch Ports

Step 3: Create a Mirror Profile:
        - Name: Argus-Mirror
        - Mirror Source: All Ports
        - Mirror Destination: Port X (where Pi is connected)

Step 4: Apply to the destination port:
        - Go to Devices → Select Switch
        - Port Configuration
        - Enable: Mirror (Argus-Mirror)
```

### MikroTik Switch Configuration

```bash
# Connect via WinBox or SSH

# Create a mirror interface
/interface bridge port
add bridge=bridge interface=ether1
add bridge=bridge interface=ether2
# ... add all ports you want to monitor

# Create port mirror
/interface ethernet switch
set switch1 mirror-source=ether1-ether24
set switch1 mirror-target=ether10
```

### TP-Link T1600G / T1700G Configuration

```
Step 1: Web interface login

Step 2: Navigate to: Monitoring → Port Mirroring

Step 3: Configure:
        - Mirror Session: 1
        - Destination Port: Select port where Pi is connected
        - Source Port(s): Select all ports or specific ports
        - Direction: Both (Rx + Tx)

Step 4: Click Apply
Step 5: Click Save Config
```

---

## Security Considerations

### The Pi Should NOT Be Exposed to the Internet

```
┌─────────────────────────────────────────────────┐
│                                                 │
│   INTERNET                                      │
│      │                                         │
│      │    NEVER directly exposed!              │
│      ▼                                         │
│   ┌─────────────────────────────────────┐      │
│   │         FIREWALL / ROUTER           │      │
│   │    (blocks inbound connections)     │      │
│   └────────────┬────────────────────────┘      │
│                │                               │
│                ▼                               │
│   Pi only receives, never initiates connections │
│   from outside your network                    │
│                                                 │
└─────────────────────────────────────────────────┘
```

### Why This Matters

| Risk | What Could Happen | Protection |
|------|-------------------|------------|
| Unauthorized access | Someone controls your Pi | Never expose SSH to internet |
| Data breach | Captured traffic exposed | Pi stays inside your network |
| Botnet infection | Pi used for attacks | Internal network only |
| Privacy violation | Your monitoring data stolen | No public access |

### Proper Security Setup

**1. The Pi should only be accessible from inside your network**

```bash
# Check current firewall status
sudo ufw status

# Allow SSH only from local network
sudo ufw allow from 192.168.1.0/24 to any port 22

# Enable firewall
sudo ufw enable
```

**2. Disable password authentication (use keys instead)**

```bash
# Generate SSH key on your computer
ssh-keygen -t ed25519

# Copy to Pi
ssh-copy-id pi@argus-pi.local

# Disable password login
sudo nano /etc/ssh/sshd_config
```

Add or modify:
```
PasswordAuthentication no
PermitRootLogin no
```

**3. Keep the Pi updated**

```bash
# Set up automatic security updates
sudo apt install unattended-upgrades
sudo dpkg-reconfigure -plow unattended-upgrades
```

**4. Physical security**

- Keep the Pi in a locked cabinet
- Disable USB ports if not needed
- Use a case that obscures the SD card

### Network Isolation Best Practices

```
                    Recommended Network Setup
                    ========================

┌─────────────────────────────────────────────────────────────┐
│                        ISP MODEM/ROUTER                      │
│                    (provides NAT firewall)                   │
└─────────────────────────────┬───────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    INTERNAL NETWORK                          │
│              192.168.1.x / 10.0.0.x                         │
│                                                              │
│   ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    │
│   │   Devices   │    │   Pi with   │    │  Switch/    │    │
│   │   (trusted) │    │   ARGUS     │    │  Router     │    │
│   └─────────────┘    └─────────────┘    └─────────────┘    │
│                                                              │
│   ARGUS only monitors traffic, does not route it            │
└─────────────────────────────────────────────────────────────┘
```

---

## Bandwidth and Performance Requirements

### Raspberry Pi 4 Performance Metrics

| Resource | Requirement | Notes |
|----------|-------------|-------|
| **CPU** | < 50% typical load | Spikes during traffic analysis |
| **RAM** | 2-4GB used | 8GB Pi recommended for heavy loads |
| **Storage** | 10-50MB/hour | Depends on network traffic volume |
| **Network** | 100Mbps sufficient | 1Gbps recommended for high traffic |

### Expected Resource Usage

**At Idle (no traffic):**
```
CPU:     2-5%
Memory:  1.5-2.0 GB
Disk:    Minimal writes
Network: < 1 Mbps
```

**With Moderate Traffic (50 devices):**
```
CPU:     15-30%
Memory:  2.5-3.5 GB
Disk:    20-40 MB/hour
Network: 10-50 Mbps
```

**With Heavy Traffic (100+ devices, file sharing):**
```
CPU:     40-60%
Memory:  4-6 GB
Disk:    50-100 MB/hour
Network: 100-500 Mbps
```

### Network Traffic Volume Guidelines

| Network Size | Expected Daily Data | Storage/week |
|--------------|---------------------|--------------|
| Home network (10 devices) | 1-5 GB | 7-35 GB |
| Small office (50 devices) | 10-30 GB | 70-210 GB |
| Medium office (100 devices) | 30-80 GB | 210-560 GB |

### Recommended MicroSD Card Specs

| Usage Level | Minimum Spec | Recommended |
|-------------|--------------|-------------|
| Light (home) | Class 10, 32GB | Samsung EVO+ 64GB |
| Medium (office) | U3, 64GB | SanDisk Max Endurance 128GB |
| Heavy (high traffic) | U3, 128GB + USB SSD | Samsung T5 SSD |

### Monitoring Pi Performance

```bash
# Check CPU and memory
htop

# Check disk usage
df -h

# Check network throughput
nload -u M  # Shows in MB/s

# Monitor I/O waits
iostat -x 1
```

If resource usage is too high:

1. **Reduce capture window** in retina.yaml:
   ```yaml
   aggregation:
     window_seconds: 10  # Increase from 5 to reduce CPU
   ```

2. **Reduce batch size** in aegis.yaml:
   ```yaml
   polling:
     batch_size: 50  # Reduce from 100
   ```

3. **Add cooling** - thermal throttling reduces performance

4. **Use USB SSD** - faster and more reliable than microSD

---

## Firewall Considerations

### Required Outbound Connections

| Destination | Port | Purpose | Required? |
|-------------|------|---------|-----------|
| Firebase Storage | 443 (HTTPS) | Model updates | Optional |
| GitHub API | 443 (HTTPS) | Configuration sync | Optional |
| Package servers | 443 (HTTPS) | Updates | Yes |
| NTP servers | 123 (UDP) | Time sync | Recommended |

### Configure Firewall

```bash
# Install uncomplicated firewall
sudo apt install ufw

# Set default policies
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Allow SSH from local network only
sudo ufw allow from 192.168.1.0/24 to any port 22

# Allow ARGUS health check (if needed)
# sudo ufw allow from 192.168.1.0/24 to any port 8080

# Enable firewall
sudo ufw enable

# Check status
sudo ufw status verbose
```

---

## Troubleshooting Network Issues

### Pi Not Receiving Traffic

**Symptoms:** No data captured, CSV files empty

**Checklist:**

1. **Cable connected to correct port?**
   ```bash
   # Check link status
   ip link show eth0
   ```
   Look for "state UP" and "link/ether"

2. **SPAN configured correctly?**
   - Verify switch configuration
   - Check SPAN session is active
   - Try a different destination port

3. **Interface in promiscuous mode?**
   ```bash
   # Check current mode
   ip link show eth0 | grep promisc
   ```
   If not showing PROMISC, check Retina configuration.

4. **Traffic actually flowing?**
   ```bash
   # Capture 10 packets with tcpdump
   sudo tcpdump -i eth0 -c 10 -v
   ```
   If you see packets, ARGUS should capture them.

### Slow Network Performance

**Symptoms:** Network feels sluggish, high latency

**Checklist:**

1. **Is Pi causing the issue?**
   - Temporarily remove Pi from network
   - Test network speed without Pi

2. **Check Pi CPU temperature**
   ```bash
   vcgencmd measure_temp
   ```
   If above 80°C, add cooling. Thermal throttling causes slowdowns.

3. **Check for packet loss**
   ```bash
   # Ping from Pi to router
   ping -c 100 192.168.1.1
   ```
   Loss should be < 1%.

### Duplicate or Missing Traffic

**Symptoms:** Some traffic not captured, or captured twice

**Checklist:**

1. **Only one SPAN source?**
   Verify you're not mirroring overlapping ports.

2. **Check for full-duplex issues:**
   ```bash
   # Check interface duplex
   ethtool eth0
   ```
   Should show "Speed: 1000Mb/s, Duplex: Full"

3. **SPAN session overloaded?**
   High-traffic networks may exceed SPAN port bandwidth.
   - Reduce monitored ports
   - Use faster SPAN destination port (10Gbps if available)

---

## Quick Reference Card

```
╔══════════════════════════════════════════════════════════════╗
║                    NETWORK SETUP QUICK REFERENCE              ║
╠══════════════════════════════════════════════════════════════╣
║                                                              ║
║  Finding Pi's IP:                                            ║
║    ip route | grep default                                   ║
║                                                              ║
║  Checking network interfaces:                                ║
║    ip link show                                              ║
║    ip addr                                                   ║
║                                                              ║
║  Testing connectivity:                                       ║
║    ping -c 4 8.8.8.8           # Internet test              ║
║    ping -c 4 192.168.1.1       # Router test                ║
║                                                              ║
║  Capturing test packets:                                     ║
║    sudo tcpdump -i eth0 -c 10                                ║
║                                                              ║
║  Checking promiscuous mode:                                  ║
║    ip link show eth0 | grep PROMISC                          ║
║                                                              ║
║  Enable promiscuous mode:                                    ║
║    sudo ip link set eth0 promisc on                          ║
║                                                              ║
║  Viewing network stats:                                      ║
║    nload -u M                                                ║
║    iftop                                                     ║
║                                                              ║
║  Check link speed/duplex:                                    ║
║    sudo ethtool eth0                                         ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
```

For installation instructions, see [DEPLOYMENT.md](DEPLOYMENT.md).

For support information, see [SUPPORT.md](SUPPORT.md).
