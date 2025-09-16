### Portable Wi-Fi Monitoring, Network Capture & Port Scanning Environment for Raspberry Pi

![Wi-Fi Monitor](https://img.shields.io/badge/status-beta-yellow)

A **portable, rule-based Wi-Fi monitoring, network capture, and port scanning environment** designed to run on **Raspberry Pi** devices with multiple Wi-Fi interfaces. This solution supports real-time monitoring, packet capture, probe/AP tracking, automated WPA handshake processing, and intelligent port scanning of network clients, all in a single Python script.

---

## Features

- **Wi-Fi Monitoring**  
  - Detects probe requests, beacon frames, and stations/APs in real time.  
  - Provides a sticky terminal summary with packet stats, entropy, and device counts.  
  - Alerts on suspicious traffic or abnormal network activity.  

- **Network Capture**  
  - Capture full Wi-Fi traffic to `.pcap` files on a separate interface.  
  - Supports continuous capture in the background with automatic restart if tcpdump fails.  

- **Handshake Capture & Processing**  
  - Continuous capture of WPA/WPA2 handshake packets (`EAPOL`).  
  - Automatic conversion of `.pcap` handshakes to `.hc22000` files for cracking tools.  
  - Output files are named after the corresponding access point and saved in a dedicated folder.  
  - Automatic pruning of handshake files to prevent excessive disk usage.  

- **Intelligent Port Scanning**  
  - Automatic discovery of network clients using ARP table (`arp -a`).  
  - Smart tracking system to avoid scanning previously scanned clients.  
  - Comprehensive nmap scans with service detection, OS fingerprinting, and vulnerability scripts.  
  - Organized report storage with timestamped scan results.  
  - Continuous scanning mode with configurable intervals.  
  - Single-scan mode for one-time assessments.  

- **Multi-interface Support**  
  - Default: `wlan1mon` for Wi-Fi monitoring, `wlan0` for full network capture.  
  - Fully configurable via CLI flags.  

- **Portable RPi Environment**  
  - Lightweight Python-based solution using **Scapy**, **PyShark**, and **tcpdump**.  
  - Single script deployable on a Raspberry Pi with minimal setup.  

- **Silence Mode**  
  - Suppress terminal output for silent monitoring or background operations.  

---

## Requirements

- **Hardware**: Raspberry Pi (3/4 recommended) with at least one Wi-Fi interface capable of monitor mode.  
- **Software**:  
  - Python 3.13+  
  - [Scapy](https://scapy.net/)  
  - [PyShark](https://kiminewt.github.io/pyshark/)  
  - tcpdump  
  - hcxtools (for handshake processing)  
  - nmap (for port scanning)
  - airmon-ng (for easy monitor mode)

---

## Installation

1. **Install Python dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Install system dependencies:**
   ```bash
   # On Debian/Ubuntu/Raspberry Pi OS
   sudo apt update
   sudo apt install aircrack-ng tcpdump nmap hcxtools
   ```

3. **Set up monitor mode interface (if needed):**
   ```bash
   sudo airmon-ng start wlan1
   ```

---

## Usage

### Basic Wi-Fi Monitoring
Start basic Wi-Fi monitoring with default settings:
```bash
sudo python3 main.py
```

### Network Capture
Enable continuous network packet capture:
```bash
sudo python3 main.py --capture-network --network-out /root/network_capture.pcap
```

### Handshake Capture
Enable WPA handshake capture and automatic conversion:
```bash
sudo python3 main.py --capture-handshakes --handshake-out /root/handshakes.pcap --hc22000-dir /root/hc22000s/
```

### Port Scanning

#### Single Port Scan
Perform a one-time port scan of new clients found via ARP:
```bash
sudo python3 main.py --scan-once --scan-reports-dir /root/5t3wportscans/
```

#### Continuous Port Scanning
Enable continuous port scanning with custom interval:
```bash
sudo python3 main.py --port-scan --scan-interval 30 --scan-reports-dir /root/5t3wportscans/
```

#### Combined Monitoring and Scanning
Run full monitoring with handshake capture and port scanning:
```bash
sudo python3 main.py \
  --capture-handshakes \
  --capture-network \
  --port-scan \
  --scan-interval 60 \
  --silence
```

### Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `--monitor-iface` | Interface for Wi-Fi monitoring | `wlan1mon` |
| `--network-iface` | Interface for network capture | `wlan0` |
| `--handshake-out` | Path to save handshake .pcap | `/root/5t3whandshakes.pcap` |
| `--capture-handshakes` | Enable continuous handshake capture | `False` |
| `--network-out` | Path to save network capture .pcap | `/root/5t3wnet.pcap` |
| `--capture-network` | Enable continuous network capture | `False` |
| `--hc22000-dir` | Folder to save hc22000 files | `/root/5t3whc22000s/` |
| `--port-scan` | Enable continuous port scanning | `False` |
| `--scan-once` | Perform single port scan and exit | `False` |
| `--scan-interval` | Interval in minutes for port scanning | `30` |
| `--scan-reports-dir` | Directory to save port scan reports | `/root/5t3wportscans` |
| `--silence` | Suppress terminal output | `False` |

---

## Port Scanning Features

### ARP Discovery
The system uses `arp -a` to discover active devices on the network by parsing the ARP table. This provides a reliable method to identify clients without active scanning.

### Smart Tracking
- Maintains a JSON file (`scanned_ips.json`) to track previously scanned clients
- Avoids duplicate scans to reduce network noise and improve efficiency
- Timestamps scan records for audit trails

### Comprehensive Scanning
Port scans include:
- Service version detection (`-sV`)
- Default script scanning (`-sC`)
- OS fingerprinting (`-O`)
- Vulnerability detection scripts (`--script=vuln`)
- Aggressive timing (`-T4`)

### Report Organization
- Timestamped report files: `scan_[IP]_[YYYYMMDD_HHMMSS].txt`
- Centralized storage in specified directory
- Human-readable nmap output format
- Automatic directory creation

---

## Output Files

### Wi-Fi Monitoring
- Terminal output with real-time statistics
- Alerts for suspicious network activity

### Network Capture
- `.pcap` files with full network traffic
- Compatible with Wireshark and other analysis tools

### Handshake Processing
- Raw handshake `.pcap` files
- Converted `.hc22000` files for hashcat
- Automatic file rotation to prevent disk overflow

### Port Scan Reports
```
/root/5t3wportscans/
├── scanned_ips.json           # Tracking file for scanned clients
├── scan_192.168.1.100_20250916_143022.txt
├── scan_192.168.1.101_20250916_143155.txt
└── scan_192.168.1.102_20250916_143301.txt
```

---

## Security Considerations

- **Root privileges** required for packet capture and monitor mode
- Use responsibly and only on networks you own or have permission to test
- Port scanning may trigger network security alerts
- Consider legal implications before deployment
- Monitor disk usage, especially for continuous capture modes

---
