# Portable Wi-Fi Monitoring, Network Capture, Port Scanning, Vulnerability Assessment & Association Attack Environment for Raspberry Pi

<div align="center">
<img align="center" width="600" height="300" alt="5t3w" src="https://github.com/user-attachments/assets/5e3c6270-09db-4a48-9c16-3106f03c6c36" />
</div>

![Wi-Fi Monitor](https://img.shields.io/badge/status-beta-yellow)
![Platform](https://img.shields.io/badge/platform-Raspberry%20Pi-red)
![Python](https://img.shields.io/badge/python-3.13+-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Security](https://img.shields.io/badge/security-vulnerability%20scanning-orange)
![Network](https://img.shields.io/badge/network-monitoring-purple)
![WiFi](https://img.shields.io/badge/WiFi-packet%20capture-lightblue)
![Nmap](https://img.shields.io/badge/nmap-NSE%20scripts-darkgreen)
![Attacks](https://img.shields.io/badge/WiFi-association%20attacks-red)
![Maintained](https://img.shields.io/badge/maintained-yes-brightgreen)

A **small and portable, rule-based Wi-Fi monitoring, network capture, port scanning, vulnerability assessment, and association attack environment** designed to run on **Raspberry Pi** devices with multiple Wi-Fi interfaces. This lightweight solution supports real-time monitoring, packet capture, probe/AP tracking, automated WPA handshake processing, intelligent port scanning of network clients, comprehensive vulnerability scanning using nmap NSE scripts, and WiFi association attacks for security testing in a compact, portable package.

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

- **Vulnerability Assessment**  
  - Comprehensive vulnerability scanning using nmap NSE scripts.  
  - Automated detection of CVEs, exploits, and security weaknesses.  
  - Intelligent vulnerability categorization (Critical, Medium, Low, Info).  
  - Structured vulnerability reports with severity ratings and remediation guidance.  
  - Master vulnerability database with historical tracking.  
  - Integration with existing port scanning for efficient target discovery.  
  - Support for continuous vulnerability monitoring with configurable intervals.  

- **WiFi Association Attacks**  
  - Deauthentication attacks to disconnect clients from access points.  
  - Disassociation attacks to force client reconnection.  
  - Association flood attacks to overwhelm access point resources.  
  - Automated target discovery from monitored WiFi traffic.  
  - Comprehensive attack logging and audit trails.  
  - Support for continuous attack campaigns with configurable intervals.  
  - Frame crafting using Scapy for precise 802.11 management frame injection.  

- **Multi-interface Support**  
  - Default: `wlan1mon` for Wi-Fi monitoring, `wlan0` for full network capture.  
  - Fully configurable via CLI flags.  

- **Portable RPi Environment**  
  - Lightweight Python-based solution using **Scapy**, **PyShark**, and **tcpdump**.  
  - Small and portable package deployable on a Raspberry Pi with minimal setup.  

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
  - netifaces (for network interface management)

---

## Installation

1. **Use the init script:**
   ```bash
   chmod +x init.sh
   sudo ./init.sh
   ```

2. **Set up monitor mode interface (if needed):**
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

### Vulnerability Scanning

#### Single Vulnerability Scan
Perform a one-time vulnerability scan of new clients:
```bash
sudo python3 main.py --vuln-scan-once --vuln-reports-dir /root/5t3wvulns/
```

#### Continuous Vulnerability Scanning
Enable continuous vulnerability scanning with custom interval:
```bash
sudo python3 main.py --vuln-scan --vuln-scan-interval 60 --vuln-reports-dir /root/5t3wvulns/
```

#### Generate Vulnerability Report
Create a comprehensive vulnerability report from existing scan data:
```bash
sudo python3 main.py --generate-vuln-report --vuln-reports-dir /root/5t3wvulns/
```

#### Combined Monitoring and Scanning
Run full monitoring with handshake capture, port scanning, and vulnerability assessment:
```bash
sudo python3 main.py \
  --capture-handshakes \
  --capture-network \
  --port-scan \
  --vuln-scan \
  --scan-interval 30 \
  --vuln-scan-interval 60 \
  --silence
```

### Association Attacks

#### Single Deauthentication Attack
Perform targeted deauthentication attack:
```bash
sudo python3 main.py --attack-once --association-attack \
  --attack-types deauth --attack-target 00:11:22:33:44:55 \
  --attack-ap 66:77:88:99:aa:bb --attack-count 20
```

#### Association Flood Attack
Perform association flood against an access point:
```bash
sudo python3 main.py --attack-once --association-attack \
  --attack-types assoc_flood --attack-ap 66:77:88:99:aa:bb \
  --attack-ssid "TargetNetwork" --attack-count 50
```

#### Multiple Attack Types
Perform combined deauth and disassociation attacks:
```bash
sudo python3 main.py --attack-once --association-attack \
  --attack-types deauth,disassoc --attack-target 00:11:22:33:44:55 \
  --attack-ap 66:77:88:99:aa:bb --attack-count 15
```

#### Continuous Association Attacks
Enable continuous association attacks with automatic target discovery:
```bash
sudo python3 main.py --association-attack --attack-types deauth \
  --attack-interval 5 --attack-logs-dir /root/5t3wattacks/
```

#### Combined Full Operation
Run complete monitoring with all attack capabilities:
```bash
sudo python3 main.py \
  --capture-handshakes \
  --capture-network \
  --port-scan \
  --vuln-scan \
  --association-attack \
  --attack-types deauth,disassoc \
  --scan-interval 30 \
  --vuln-scan-interval 60 \
  --attack-interval 10 \
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
| `--vuln-scan` | Enable continuous vulnerability scanning | `False` |
| `--vuln-scan-once` | Perform single vulnerability scan and exit | `False` |
| `--vuln-scan-interval` | Interval in minutes for vulnerability scanning | `60` |
| `--vuln-reports-dir` | Directory to save vulnerability reports | `/root/5t3wvulns` |
| `--generate-vuln-report` | Generate vulnerability report and exit | `False` |
| `--association-attack` | Enable WiFi association attacks | `False` |
| `--attack-types` | Types of attacks: deauth,disassoc,assoc_flood | `deauth` |
| `--attack-target` | Target MAC address for attacks | `None` |
| `--attack-ap` | AP MAC address for attacks | `None` |
| `--attack-ssid` | SSID for association flood attacks | `""` |
| `--attack-count` | Number of attack frames to send | `10` |
| `--attack-interval` | Interval in minutes for continuous attacks | `10` |
| `--attack-once` | Perform single attack and exit | `False` |
| `--attack-logs-dir` | Directory to save attack logs | `/root/5t3wattacks` |
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

## Association Attack Features

### Attack Types
The association attack system supports multiple WiFi attack vectors:

#### Deauthentication Attacks
- **Purpose**: Force clients to disconnect from access points
- **Method**: Sends spoofed deauthentication frames from both AP and client perspectives
- **Use Cases**: WiFi security testing, forcing WPA handshake capture, network disruption testing
- **Frame Types**: 802.11 Management frames (subtype 12)

#### Disassociation Attacks  
- **Purpose**: Force clients to disassociate while maintaining authentication
- **Method**: Sends spoofed disassociation frames with configurable reason codes
- **Use Cases**: Testing client reconnection behavior, intermediate disruption
- **Frame Types**: 802.11 Management frames (subtype 10)

#### Association Flood Attacks
- **Purpose**: Overwhelm access point resources with fake association requests
- **Method**: Generates multiple fake client MACs and floods AP with association requests
- **Use Cases**: DoS testing, AP resource exhaustion testing, capacity testing
- **Frame Types**: 802.11 Authentication + Association Request frames

### Target Discovery
- **Automatic Discovery**: Leverages existing WiFi monitoring to identify targets
- **Manual Targeting**: Supports specific MAC address targeting via command line
- **Real-time Updates**: Continuously updates target list from monitored traffic
- **Filter Capabilities**: Distinguishes between access points and client stations

### Attack Execution
- **Frame Crafting**: Uses Scapy for precise 802.11 frame construction
- **Sequence Control**: Implements proper sequence numbering for realistic frames  
- **Timing Control**: Configurable delays between frames and attack rounds
- **Batch Processing**: Supports sending multiple frames per attack session

### Logging and Audit
- **Comprehensive Logging**: Records all attack attempts with timestamps
- **Target Tracking**: Maintains database of attacked targets and success rates
- **Audit Trail**: JSON-formatted logs for compliance and analysis
- **Activity Monitoring**: Real-time status updates and attack progress tracking

### Safety Features
- **Rate Limiting**: Built-in delays to prevent interface overload
- **Target Validation**: MAC address format validation and sanity checks
- **Error Handling**: Graceful failure handling with detailed error reporting
- **Interface Management**: Automatic interface MAC detection and validation

---

## Vulnerability Scanning Features

### Comprehensive NSE Script Coverage
The vulnerability scanner uses an extensive collection of nmap NSE scripts:
- **Vulnerability Detection**: `--script vuln` for known CVE identification
- **Exploit Detection**: `--script exploit` for available exploits
- **Malware Detection**: `--script malware` for backdoor and malware identification
- **Authentication Testing**: `--script auth` for weak authentication mechanisms
- **Intrusive Testing**: `--script intrusive` for comprehensive security assessment

### Intelligent Vulnerability Classification
Vulnerabilities are automatically categorized by severity:
- **Critical**: Remote code execution, privilege escalation, authentication bypass
- **Medium**: Information disclosure, denial of service, moderate impact flaws
- **Low**: Minor information leaks, configuration issues
- **Info**: Informational findings, version disclosures

### Advanced Reporting
- **Raw Scan Results**: Complete nmap output with detailed findings
- **Structured JSON Data**: Machine-readable vulnerability data with metadata
- **XML Output**: Compatible with vulnerability management tools
- **Master Summary Database**: Historical vulnerability tracking across all targets
- **Comprehensive Reports**: Executive-style reports with severity breakdowns

### Smart Target Management
- Leverages existing ARP discovery for efficient target identification
- Maintains separate tracking for vulnerability scans vs. port scans
- Avoids duplicate vulnerability assessments
- Configurable scan intervals for continuous monitoring

### CVE Integration
- Automatic CVE number extraction from scan results
- CVE cross-referencing in vulnerability reports
- Integration with public vulnerability databases
- Timeline tracking for vulnerability disclosure dates

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

### Vulnerability Scan Reports
```
/root/5t3wvulns/
├── vuln_scanned_ips.json      # Tracking file for vulnerability-scanned clients
├── vulnerability_summary.json # Master vulnerability database
├── vuln_scan_192.168.1.100_20250916_143022.txt    # Raw nmap output
├── vuln_scan_192.168.1.100_20250916_143022.xml    # XML format output
├── vuln_data_192.168.1.100_20250916_143022.json   # Structured JSON data
├── vulnerability_report_20250916_150000.txt       # Comprehensive report
└── vulnerability_report_20250916_160000.txt       # Latest report
```

### Association Attack Logs
```
/root/5t3wattacks/
├── attack_targets.json        # Discovered attack targets database
├── attack_logs.json          # Comprehensive attack audit trail
├── deauth_session_20250916_143022.log             # Session-specific logs
├── assoc_flood_session_20250916_143155.log        # Attack type logs
└── attack_summary_20250916.json                   # Daily attack summary
```

---

## Security Considerations

- **Root privileges** required for packet capture and monitor mode
- Use responsibly and only on networks you own or have permission to test
- Port scanning and vulnerability assessment may trigger network security alerts
- Vulnerability scans can be intrusive and may impact target system performance
- **Association attacks are highly disruptive** and may violate computer crime laws
- **WiFi attacks can interfere with legitimate network operations** and cause service outages
- Consider legal implications before deployment, especially for vulnerability scanning and WiFi attacks
- Monitor disk usage, especially for continuous capture and scanning modes
- Vulnerability scan results may contain sensitive security information - secure appropriately
- Some vulnerability tests may cause service disruption on target systems
- **Association attacks should only be used on networks you own or have explicit permission to test**
- **Deauthentication and disassociation attacks may violate FCC regulations** in some jurisdictions
- **Always comply with local laws and regulations regarding WiFi security testing**

---
