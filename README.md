# Network Packet Sniffer

A Python-based network packet sniffer that captures and analyzes network traffic in real-time.

## Features

- **Real-time packet capture** - Captures packets as they traverse the network
- **Protocol parsing** - Parses Ethernet, IPv4, TCP, UDP, and ICMP headers
- **Traffic analysis** - Provides statistics on captured traffic
- **Filtering** - Filter by protocol (TCP/UDP/ICMP) or port number
- **Service identification** - Identifies common services (HTTP, HTTPS, SSH, DNS, etc.)
- **Export functionality** - Save captured packets to JSON format
- **Cross-platform** - Works on Windows and Linux

## Requirements

- Python 3.6+
- Scapy library
- Npcap (Windows) or libpcap (Linux)

## Installation

```bash
# Install Scapy
pip install scapy

# On Windows: Install Npcap from https://npcap.com
# During installation, check "Install Npcap in WinPcap API-compatible Mode"

# On Linux: Install libpcap
sudo apt install libpcap-dev  # Debian/Ubuntu
sudo yum install libpcap-devel  # RHEL/CentOS
```

## Usage

### Basic Usage

```bash
# Capture all traffic (no admin required with Npcap installed)
python sniffer.py

# Note: If Npcap was installed with "Restrict access to Administrators only",
# you may still need to run as admin
```

### Command Line Options

| Option | Description |
|--------|-------------|
| `-i, --interface` | Network interface to capture on (auto-detect if not specified) |
| `-p, --protocol` | Filter by protocol: TCP, UDP, or ICMP |
| `--port` | Filter by port number |
| `-v, --verbose` | Enable verbose output (shows flags, sequence numbers, data preview) |
| `-o, --output` | Save captured packets to JSON file |
| `-n, --count` | Number of packets to capture (unlimited if not specified) |

### Examples

```bash
# Capture only TCP traffic
python sniffer.py -p TCP

# Capture DNS traffic (UDP port 53)
python sniffer.py -p UDP --port 53

# Capture HTTP traffic
python sniffer.py -p TCP --port 80

# Capture HTTPS traffic with verbose output
python sniffer.py -p TCP --port 443 -v

# Capture 100 packets and save to file
python sniffer.py -n 100 -o capture.json

# Verbose capture with all details
python sniffer.py -v -o traffic_capture.json
```

## Output Format

### Console Output

```
[2025-12-02 10:30:45.123] TCP   192.168.1.100:54321 → 93.184.216.34:443 (HTTPS)
[2025-12-02 10:30:45.125] UDP   192.168.1.100:12345 → 8.8.8.8:53 (DNS)
[2025-12-02 10:30:45.130] ICMP  192.168.1.100 → 8.8.8.8
```

### Verbose Output

```
[2025-12-02 10:30:45.123] TCP   192.168.1.100:54321 → 93.184.216.34:443 (HTTPS)
    Flags: SYN, ACK
    TTL: 64
    Seq: 1234567890, Ack: 9876543210
    Data: HTTP/1.1 200 OK...
```

### JSON Output

```json
{
  "summary": {
    "total_packets": 1000,
    "elapsed_time": "60.00s",
    "packets_per_second": "16.67",
    "protocols": {"TCP": 800, "UDP": 150, "ICMP": 50},
    "top_ips": {"192.168.1.100": 500, "8.8.8.8": 200},
    "top_ports": {"443": 400, "80": 200, "53": 150}
  },
  "packets": [...]
}
```

## Captured Information

For each packet, the sniffer captures:

- **Timestamp** - When the packet was captured
- **MAC addresses** - Source and destination
- **IP addresses** - Source and destination
- **Protocol** - TCP, UDP, ICMP, or other
- **Ports** - Source and destination (for TCP/UDP)
- **TCP Flags** - SYN, ACK, PSH, RST, FIN, URG
- **Sequence/Acknowledgment numbers** - For TCP
- **TTL** - Time to live
- **Payload preview** - First 200 bytes of data

## Statistics Provided

At the end of capture, you get:

- Total packets captured
- Capture duration
- Packets per second
- Protocol distribution
- Top 10 IP addresses by packet count
- Top 10 ports by packet count
- Bandwidth by protocol

## Supported Protocols

| Protocol | Description |
|----------|-------------|
| TCP | Transmission Control Protocol |
| UDP | User Datagram Protocol |
| ICMP | Internet Control Message Protocol |
| IGMP | Internet Group Management Protocol |
| GRE | Generic Routing Encapsulation |
| ESP | Encapsulating Security Payload |
| AH | Authentication Header |
| OSPF | Open Shortest Path First |

## Common Services Identified

HTTP (80), HTTPS (443), SSH (22), FTP (21), DNS (53), SMTP (25), 
POP3 (110), IMAP (143), MySQL (3306), PostgreSQL (5432), 
Redis (6379), MongoDB (27017), RDP (3389), and more.

## Troubleshooting

### Scapy Not Installed

```
[!] Error: Scapy library is not installed!
```

**Solution:**
```bash
pip install scapy
```

### Permission Denied / Npcap Error (Windows)

```
[!] Error: Permission denied!
```

**Solution:**
1. Install Npcap from https://npcap.com
2. During installation, check **"Install Npcap in WinPcap API-compatible Mode"**
3. If you checked "Restrict Npcap driver's access to Administrators only", run as admin

### Permission Denied (Linux)

**Solution:**
```bash
# Option 1: Run with sudo
sudo python sniffer.py

# Option 2: Add capability to Python (persistent)
sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)
```

### No Packets Captured

1. Ensure you have network activity
2. Try without filters first
3. Check if firewall is blocking packet capture
4. Verify network interface is up
5. Try specifying interface: `python sniffer.py -i eth0`

## Security Notice

⚠️ **Use responsibly and legally!**

- Only capture traffic on networks you own or have permission to monitor
- Capturing others' traffic without authorization may be illegal
- This tool is intended for educational and legitimate network analysis purposes

## License

MIT License - Feel free to use, modify, and distribute.
