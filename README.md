### Portable Wi-Fi Monitoring & Network Capture Environment for Raspberry Pi

![Wi-Fi Monitor](https://img.shields.io/badge/status-beta-yellow)

A **portable, rule-based Wi-Fi monitoring and network capture environment** designed to run on **Raspberry Pi** devices with multiple Wi-Fi interfaces. This solution supports real-time monitoring, packet capture, probe/AP tracking, and automated WPA handshake processing, all in a single Python script.

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
  - hcxpcapngtool (for handshake processing)
