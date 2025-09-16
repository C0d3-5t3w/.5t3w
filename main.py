#!/usr/bin/env python3
import time
import math
import logging
import requests
import smtplib
from email.mime.text import MIMEText
from logging.handlers import SysLogHandler
from collections import Counter
import argparse
import threading
import subprocess
import os
import re
import json
from datetime import datetime
import ipaddress

import pandas as pd
import pyshark
from scapy.all import sniff, Raw

# --- Config ---
WINDOW_SEC = 5
PACKET_THRESHOLD = 500
UNIQUE_MAC_THRESHOLD = 50
MGMT_FRAME_THRESHOLD = 0.5
ENTROPY_THRESHOLD = 7.5

ALERT_EMAIL = None
ALERT_WEBHOOK = None
ALERT_SYSLOG = "/dev/log"

OUI_DB = {}
packets_buffer = []

stations = set()
access_points = set()

# --- Port Scanning Configuration ---
SCAN_REPORTS_DIR = "/root/5t3wportscans"
SCANNED_IPS_FILE = os.path.join(SCAN_REPORTS_DIR, "scanned_ips.json")
NMAP_ARGS = ["-sV", "-sC", "-O", "--script=vuln", "-T4"]  # Comprehensive scan

# --- Vulnerability Scanning Configuration ---
VULN_REPORTS_DIR = "/root/5t3wvulns"
VULN_SCANNED_IPS_FILE = os.path.join(VULN_REPORTS_DIR, "vuln_scanned_ips.json")
VULN_SUMMARY_FILE = os.path.join(VULN_REPORTS_DIR, "vulnerability_summary.json")
NMAP_VULN_ARGS = [
    "--script", "vuln,exploit,malware,intrusive,auth",
    "--script-args", "unsafe=1",
    "-sV", "-sC", "-T4", "--max-retries", "2"
]  # Comprehensive vulnerability scan

# --- ARP Discovery ---
def get_arp_table():
    """Get all IP addresses from ARP table using 'arp -a' command"""
    try:
        result = subprocess.run(['arp', '-a'], capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            logging.error(f"ARP command failed: {result.stderr}")
            return []
        
        ip_addresses = []
        # Parse ARP output format: hostname (ip_address) at mac_address [ether] on interface
        for line in result.stdout.split('\n'):
            if line.strip():
                # Extract IP address using regex
                ip_match = re.search(r'\(([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\)', line)
                if ip_match:
                    ip = ip_match.group(1)
                    # Validate IP address
                    try:
                        ipaddress.ip_address(ip)
                        ip_addresses.append(ip)
                    except ValueError:
                        continue
        
        logging.info(f"Found {len(ip_addresses)} IP addresses in ARP table")
        return list(set(ip_addresses))  # Remove duplicates
    
    except subprocess.TimeoutExpired:
        logging.error("ARP command timed out")
        return []
    except Exception as e:
        logging.error(f"Error getting ARP table: {e}")
        return []

def load_scanned_ips():
    """Load previously scanned IPs from file"""
    try:
        if os.path.exists(SCANNED_IPS_FILE):
            with open(SCANNED_IPS_FILE, 'r') as f:
                data = json.load(f)
                return set(data.get('scanned_ips', []))
        return set()
    except Exception as e:
        logging.error(f"Error loading scanned IPs: {e}")
        return set()

def save_scanned_ips(scanned_ips):
    """Save scanned IPs to file"""
    try:
        os.makedirs(SCAN_REPORTS_DIR, exist_ok=True)
        with open(SCANNED_IPS_FILE, 'w') as f:
            json.dump({
                'scanned_ips': list(scanned_ips),
                'last_updated': datetime.now().isoformat()
            }, f, indent=2)
    except Exception as e:
        logging.error(f"Error saving scanned IPs: {e}")

def get_new_clients():
    """Get list of new IP addresses that haven't been scanned yet"""
    current_ips = set(get_arp_table())
    scanned_ips = load_scanned_ips()
    new_ips = current_ips - scanned_ips
    
    if new_ips:
        logging.info(f"Found {len(new_ips)} new clients: {', '.join(new_ips)}")
    else:
        logging.info("No new clients found")
    
    return list(new_ips)

def run_nmap_scan(target_ip):
    """Run nmap scan on target IP and return results"""
    try:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = os.path.join(SCAN_REPORTS_DIR, f"scan_{target_ip}_{timestamp}.txt")
        
        cmd = ['nmap'] + NMAP_ARGS + ['-oN', output_file, target_ip]
        logging.info(f"Starting nmap scan on {target_ip}")
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)  # 10 min timeout
        
        if result.returncode == 0:
            logging.info(f"Scan completed for {target_ip}, report saved to {output_file}")
            return output_file, result.stdout
        else:
            logging.error(f"Nmap scan failed for {target_ip}: {result.stderr}")
            return None, None
            
    except subprocess.TimeoutExpired:
        logging.error(f"Nmap scan timed out for {target_ip}")
        return None, None
    except Exception as e:
        logging.error(f"Error running nmap scan on {target_ip}: {e}")
        return None, None

def scan_new_clients():
    """Main function to scan new clients found via ARP"""
    logging.info("Starting port scan discovery process...")
    
    # Create output directory
    os.makedirs(SCAN_REPORTS_DIR, exist_ok=True)
    
    # Get new clients
    new_clients = get_new_clients()
    if not new_clients:
        return
    
    # Load existing scanned IPs
    scanned_ips = load_scanned_ips()
    
    # Scan each new client
    for ip in new_clients:
        logging.info(f"Scanning {ip}...")
        output_file, scan_results = run_nmap_scan(ip)
        
        if output_file:
            # Mark as scanned
            scanned_ips.add(ip)
            
            # Save updated scanned IPs list
            save_scanned_ips(scanned_ips)
            
            # Log summary
            if scan_results:
                open_ports = len([line for line in scan_results.split('\n') if '/tcp' in line and 'open' in line])
                logging.info(f"Scan complete for {ip}: {open_ports} open ports found")
    
    logging.info("Port scan discovery process completed")

# --- Vulnerability Scanning Functions ---
def load_vuln_scanned_ips():
    """Load previously vulnerability-scanned IPs from file"""
    try:
        if os.path.exists(VULN_SCANNED_IPS_FILE):
            with open(VULN_SCANNED_IPS_FILE, 'r') as f:
                data = json.load(f)
                return set(data.get('vuln_scanned_ips', []))
        return set()
    except Exception as e:
        logging.error(f"Error loading vulnerability scanned IPs: {e}")
        return set()

def save_vuln_scanned_ips(scanned_ips):
    """Save vulnerability-scanned IPs to file"""
    try:
        os.makedirs(VULN_REPORTS_DIR, exist_ok=True)
        with open(VULN_SCANNED_IPS_FILE, 'w') as f:
            json.dump({
                'vuln_scanned_ips': list(scanned_ips),
                'last_updated': datetime.now().isoformat()
            }, f, indent=2)
    except Exception as e:
        logging.error(f"Error saving vulnerability scanned IPs: {e}")

def run_vulnerability_scan(target_ip):
    """Run comprehensive vulnerability scan on target IP"""
    try:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = os.path.join(VULN_REPORTS_DIR, f"vuln_scan_{target_ip}_{timestamp}.txt")
        xml_output_file = os.path.join(VULN_REPORTS_DIR, f"vuln_scan_{target_ip}_{timestamp}.xml")
        
        cmd = ['nmap'] + NMAP_VULN_ARGS + ['-oN', output_file, '-oX', xml_output_file, target_ip]
        logging.info(f"Starting vulnerability scan on {target_ip}")
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=1200)  # 20 min timeout
        
        if result.returncode == 0:
            logging.info(f"Vulnerability scan completed for {target_ip}")
            
            # Parse and categorize vulnerabilities
            vulnerabilities = parse_vulnerability_results(result.stdout, target_ip)
            
            # Save structured vulnerability data
            vuln_json_file = os.path.join(VULN_REPORTS_DIR, f"vuln_data_{target_ip}_{timestamp}.json")
            with open(vuln_json_file, 'w') as f:
                json.dump({
                    'target': target_ip,
                    'scan_time': datetime.now().isoformat(),
                    'vulnerabilities': vulnerabilities,
                    'scan_command': ' '.join(cmd)
                }, f, indent=2)
            
            return output_file, vulnerabilities
        else:
            logging.error(f"Vulnerability scan failed for {target_ip}: {result.stderr}")
            return None, []
            
    except subprocess.TimeoutExpired:
        logging.error(f"Vulnerability scan timed out for {target_ip}")
        return None, []
    except Exception as e:
        logging.error(f"Error running vulnerability scan on {target_ip}: {e}")
        return None, []

def parse_vulnerability_results(scan_output, target_ip):
    """Parse nmap vulnerability scan output and categorize findings"""
    vulnerabilities = []
    current_vuln = None
    
    lines = scan_output.split('\n')
    for line in lines:
        line = line.strip()
        
        # Look for vulnerability script results
        if '|' in line and any(keyword in line.lower() for keyword in 
                               ['vuln', 'cve', 'exploit', 'vulnerable', 'security']):
            
            # Extract CVE numbers
            cve_matches = re.findall(r'CVE-\d{4}-\d{4,}', line)
            
            # Determine severity based on keywords
            severity = 'info'
            if any(keyword in line.lower() for keyword in ['critical', 'high']):
                severity = 'critical'
            elif any(keyword in line.lower() for keyword in ['medium', 'moderate']):
                severity = 'medium'
            elif any(keyword in line.lower() for keyword in ['low', 'minor']):
                severity = 'low'
            elif any(keyword in line.lower() for keyword in ['exploit', 'remote code', 'rce']):
                severity = 'critical'
            
            vuln_entry = {
                'target': target_ip,
                'description': line,
                'severity': severity,
                'cves': cve_matches,
                'timestamp': datetime.now().isoformat()
            }
            
            vulnerabilities.append(vuln_entry)
    
    return vulnerabilities

def update_vulnerability_summary(new_vulnerabilities):
    """Update the master vulnerability summary file"""
    try:
        # Load existing summary
        summary_data = {'targets': {}, 'last_updated': None, 'total_vulnerabilities': 0}
        if os.path.exists(VULN_SUMMARY_FILE):
            with open(VULN_SUMMARY_FILE, 'r') as f:
                summary_data = json.load(f)
        
        # Update with new vulnerabilities
        for vuln in new_vulnerabilities:
            target = vuln['target']
            if target not in summary_data['targets']:
                summary_data['targets'][target] = {
                    'critical': 0, 'medium': 0, 'low': 0, 'info': 0,
                    'last_scan': None, 'vulnerabilities': []
                }
            
            summary_data['targets'][target]['vulnerabilities'].append(vuln)
            summary_data['targets'][target][vuln['severity']] += 1
            summary_data['targets'][target]['last_scan'] = vuln['timestamp']
        
        # Update totals
        summary_data['total_vulnerabilities'] = sum(
            len(target_data['vulnerabilities']) 
            for target_data in summary_data['targets'].values()
        )
        summary_data['last_updated'] = datetime.now().isoformat()
        
        # Save updated summary
        with open(VULN_SUMMARY_FILE, 'w') as f:
            json.dump(summary_data, f, indent=2)
            
        logging.info(f"Updated vulnerability summary: {summary_data['total_vulnerabilities']} total vulnerabilities across {len(summary_data['targets'])} targets")
        
    except Exception as e:
        logging.error(f"Error updating vulnerability summary: {e}")

def get_new_vuln_targets():
    """Get list of IPs that need vulnerability scanning"""
    current_ips = set(get_arp_table())
    vuln_scanned_ips = load_vuln_scanned_ips()
    new_targets = current_ips - vuln_scanned_ips
    
    if new_targets:
        logging.info(f"Found {len(new_targets)} new targets for vulnerability scanning: {', '.join(new_targets)}")
    else:
        logging.info("No new targets found for vulnerability scanning")
    
    return list(new_targets)

def scan_vulnerabilities():
    """Main function to scan for vulnerabilities on new targets"""
    logging.info("Starting vulnerability scanning process...")
    
    # Create output directory
    os.makedirs(VULN_REPORTS_DIR, exist_ok=True)
    
    # Get new targets
    new_targets = get_new_vuln_targets()
    if not new_targets:
        return
    
    # Load existing scanned IPs
    vuln_scanned_ips = load_vuln_scanned_ips()
    all_vulnerabilities = []
    
    # Scan each new target
    for ip in new_targets:
        logging.info(f"Vulnerability scanning {ip}...")
        output_file, vulnerabilities = run_vulnerability_scan(ip)
        
        if output_file:
            # Mark as scanned
            vuln_scanned_ips.add(ip)
            
            # Collect vulnerabilities
            all_vulnerabilities.extend(vulnerabilities)
            
            # Save updated scanned IPs list
            save_vuln_scanned_ips(vuln_scanned_ips)
            
            # Log summary
            vuln_count = len(vulnerabilities)
            critical_count = len([v for v in vulnerabilities if v['severity'] == 'critical'])
            logging.info(f"Vulnerability scan complete for {ip}: {vuln_count} vulnerabilities found ({critical_count} critical)")
    
    # Update master summary
    if all_vulnerabilities:
        update_vulnerability_summary(all_vulnerabilities)
    
    logging.info("Vulnerability scanning process completed")

def continuous_vulnerability_scanning(interval_minutes=60):
    """Continuously scan for vulnerabilities at specified interval"""
    logging.info(f"Starting continuous vulnerability scanning (interval: {interval_minutes} minutes)")
    
    while True:
        try:
            scan_vulnerabilities()
            time.sleep(interval_minutes * 60)
        except KeyboardInterrupt:
            logging.info("Continuous vulnerability scanning stopped by user")
            break
        except Exception as e:
            logging.error(f"Error in continuous vulnerability scanning: {e}")
            time.sleep(60)  # Wait 1 minute before retrying

def generate_vulnerability_report():
    """Generate a comprehensive vulnerability report"""
    try:
        if not os.path.exists(VULN_SUMMARY_FILE):
            logging.info("No vulnerability data found")
            return
        
        with open(VULN_SUMMARY_FILE, 'r') as f:
            summary_data = json.load(f)
        
        report_file = os.path.join(VULN_REPORTS_DIR, f"vulnerability_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
        
        with open(report_file, 'w') as f:
            f.write("=" * 60 + "\n")
            f.write("5T3W VULNERABILITY SCAN REPORT\n")
            f.write("=" * 60 + "\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Total Targets Scanned: {len(summary_data['targets'])}\n")
            f.write(f"Total Vulnerabilities: {summary_data['total_vulnerabilities']}\n")
            f.write("\n" + "=" * 60 + "\n")
            f.write("VULNERABILITY SUMMARY BY TARGET\n")
            f.write("=" * 60 + "\n")
            
            for target, data in summary_data['targets'].items():
                f.write(f"\nTarget: {target}\n")
                f.write(f"Last Scan: {data['last_scan']}\n")
                f.write(f"Critical: {data['critical']}, Medium: {data['medium']}, Low: {data['low']}, Info: {data['info']}\n")
                f.write("-" * 40 + "\n")
                
                for vuln in data['vulnerabilities']:
                    f.write(f"[{vuln['severity'].upper()}] {vuln['description']}\n")
                    if vuln['cves']:
                        f.write(f"CVEs: {', '.join(vuln['cves'])}\n")
                    f.write(f"Timestamp: {vuln['timestamp']}\n\n")
        
        logging.info(f"Vulnerability report generated: {report_file}")
        return report_file
        
    except Exception as e:
        logging.error(f"Error generating vulnerability report: {e}")
        return None

def continuous_port_scanning(interval_minutes=30):
    """Continuously scan for new clients at specified interval"""
    logging.info(f"Starting continuous port scanning (interval: {interval_minutes} minutes)")
    
    while True:
        try:
            scan_new_clients()
            time.sleep(interval_minutes * 60)
        except KeyboardInterrupt:
            logging.info("Continuous port scanning stopped by user")
            break
        except Exception as e:
            logging.error(f"Error in continuous scanning: {e}")
            time.sleep(60)  # Wait 1 minute before retrying

# --- OUI Vendor Lookup ---
def load_oui_db(path="oui.txt"):
    global OUI_DB
    try:
        with open(path) as f:
            for line in f:
                if "(hex)" in line:
                    prefix, vendor = line.split("(hex)")
                    prefix = prefix.strip().replace("-", ":")
                    OUI_DB[prefix] = vendor.strip()
        logging.info(f"Loaded {len(OUI_DB)} OUI entries")
    except FileNotFoundError:
        logging.warning("OUI DB not found, vendor lookup disabled")

def lookup_vendor(mac):
    if not mac:
        return "Unknown"
    prefix = mac.upper()[0:8]
    return OUI_DB.get(prefix, "Unknown")

# --- Entropy ---
def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counter = Counter(data)
    length = len(data)
    return -sum((count/length) * math.log2(count/length) for count in counter.values())

# --- Alerts ---
def send_alert(msg: str):
    logging.warning(msg)
    if ALERT_EMAIL:
        try:
            email = MIMEText(msg)
            email["Subject"] = "WiFi Monitor Alert"
            email["From"] = ALERT_EMAIL
            email["To"] = ALERT_EMAIL
            with smtplib.SMTP("localhost") as server:
                server.sendmail(ALERT_EMAIL, [ALERT_EMAIL], email.as_string())
        except Exception as e:
            logging.error(f"Email alert failed: {e}")

    if ALERT_WEBHOOK:
        try:
            requests.post(ALERT_WEBHOOK, json={"alert": msg})
        except Exception as e:
            logging.error(f"Webhook alert failed: {e}")

    if ALERT_SYSLOG:
        try:
            syslog = SysLogHandler(address=ALERT_SYSLOG)
            syslog.emit(logging.LogRecord("wifi-monitor", logging.WARNING, "", 0, msg, None, None))
        except Exception as e:
            logging.error(f"Syslog alert failed: {e}")

# --- Verbose / sticky logging ---
def verbose_log(pkt_dict, silent=False):
    if silent:
        return
    src = pkt_dict.get("src", "Unknown")
    dst = pkt_dict.get("dst", "Unknown")
    frame_type = pkt_dict.get("frame_type", "Unknown")
    subtype = pkt_dict.get("subtype", "Unknown")
    ssid = pkt_dict.get("ssid", "")
    log_msg = f"[{frame_type.upper()}:{subtype}] {src} -> {dst}"
    if ssid:
        log_msg += f" SSID:{ssid}"
    logging.info(log_msg)

    # Track stations and APs
    if frame_type == "mgmt":
        if subtype == "probe-req":
            stations.add(src)
        elif subtype == "beacon":
            access_points.add(src)

# --- Capture with Scapy ---
def scapy_handler(pkt, silent=False):
    try:
        ts = time.time()
        src = pkt.addr2 if hasattr(pkt, "addr2") else None
        dst = pkt.addr1 if hasattr(pkt, "addr1") else None
        length = len(pkt)
        payload = bytes(pkt[Raw]) if Raw in pkt else b""

        pkt_dict = {
            "timestamp": ts,
            "src": src,
            "dst": dst,
            "length": length,
            "entropy": shannon_entropy(payload),
            "frame_type": "unknown",
            "subtype": "unknown",
            "ssid": ""
        }

        if pkt.haslayer("Dot11"):
            fc_type = int(pkt.type)
            fc_subtype = int(pkt.subtype)
            if fc_type == 0:
                pkt_dict["frame_type"] = "mgmt"
                if fc_subtype == 4:
                    pkt_dict["subtype"] = "probe-req"
                    pkt_dict["ssid"] = pkt.info.decode(errors="ignore") if hasattr(pkt, "info") else ""
                elif fc_subtype == 8:
                    pkt_dict["subtype"] = "beacon"
                    pkt_dict["ssid"] = pkt.info.decode(errors="ignore") if hasattr(pkt, "info") else ""
                else:
                    pkt_dict["subtype"] = str(fc_subtype)
            elif fc_type == 1:
                pkt_dict["frame_type"] = "ctrl"
                pkt_dict["subtype"] = str(fc_subtype)
            else:
                pkt_dict["frame_type"] = "data"
                pkt_dict["subtype"] = str(fc_subtype)

        packets_buffer.append(pkt_dict)
        verbose_log(pkt_dict, silent=silent)
    except Exception as e:
        logging.debug(f"scapy_handler error: {e}")

# --- Sticky summary ---
def print_summary_sticky(total, unique_macs, avg_entropy, mgmt_ratio, stations, access_points, silent=False):
    if silent:
        return
    summary_lines = [
        f"--- Window Summary ---",
        f"Packets: {total}, Unique MACs: {unique_macs}, Avg Entropy: {avg_entropy:.2f}",
        f"Management Ratio: {mgmt_ratio:.2%}",
        f"Stations observed: {len(stations)}, APs observed: {len(access_points)}",
        f"Stations: {stations}",
        f"Access Points (MACs): {access_points}"
    ]
    print("\033[6A", end="")
    print("\033[J", end="")
    for line in summary_lines:
        print(line)

# --- Window analysis ---
def analyze_window(df: pd.DataFrame, silent=False):
    if df.empty:
        return

    total = len(df)
    unique_macs = df["src"].nunique()
    avg_entropy = df["entropy"].mean()
    mgmt_count = (df.get("frame_type") == "mgmt").sum() if "frame_type" in df else 0
    mgmt_ratio = mgmt_count / total if total > 0 else 0

    if total > PACKET_THRESHOLD:
        send_alert(f"High traffic: {total} packets in {WINDOW_SEC}s")
    if unique_macs > UNIQUE_MAC_THRESHOLD:
        send_alert(f"Too many unique MACs: {unique_macs}")
    if mgmt_ratio > MGMT_FRAME_THRESHOLD:
        send_alert(f"Suspicious management traffic: {mgmt_ratio:.2%}")
    if avg_entropy > ENTROPY_THRESHOLD:
        send_alert(f"High entropy traffic: {avg_entropy:.2f}")

    print_summary_sticky(total, unique_macs, avg_entropy, mgmt_ratio, stations, access_points, silent=silent)

# --- PyShark Enhancer ---
def enrich_with_pyshark(interface, duration=WINDOW_SEC):
    try:
        cap = pyshark.LiveCapture(interface=interface)
        cap.sniff(timeout=duration)
        subtype_map = []
        for pkt in cap:
            try:
                if "WLAN" in pkt:
                    fc_type = int(pkt.wlan.fc_type)
                    subtype = pkt.wlan.fc_type_subtype
                    if fc_type == 0:
                        frame_type = "mgmt"
                    elif fc_type == 1:
                        frame_type = "ctrl"
                    else:
                        frame_type = "data"
                    subtype_map.append((pkt.wlan.sa, frame_type, subtype))
            except Exception:
                continue
        return subtype_map
    except Exception:
        return []

# --- Monitor loop ---
def monitor(interface, silent=False):
    global packets_buffer
    load_oui_db()

    logging.info(f"Starting WiFi monitor on interface {interface}...")
    t = threading.Thread(target=lambda: sniff(iface=interface, prn=lambda pkt: scapy_handler(pkt, silent=silent), store=0), daemon=True)
    t.start()

    while True:
        time.sleep(WINDOW_SEC)
        df = pd.DataFrame(packets_buffer)
        subtype_info = enrich_with_pyshark(interface, duration=1)
        subtype_map = {src: (ftype, stype) for src, ftype, stype in subtype_info}
        if not df.empty:
            df["frame_type"] = df["src"].map(lambda x: subtype_map.get(x, ("unknown", None))[0])
            df["subtype"] = df["src"].map(lambda x: subtype_map.get(x, ("", "unknown"))[1])
        analyze_window(df, silent=silent)
        packets_buffer = []

# --- Handshake conversion ---
def handshake_converter_loop(handshake_pcap, output_dir, silent=False):
    os.makedirs(output_dir, exist_ok=True)
    last_size = 0
    while True:
        try:
            if not os.path.exists(handshake_pcap):
                time.sleep(5)
                continue
            current_size = os.path.getsize(handshake_pcap)
            if current_size > last_size:
                proc = subprocess.Popen([
                    "hcxpcapngtool",
                    "-o", output_dir,
                    handshake_pcap
                ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                stdout, stderr = proc.communicate()
                if proc.returncode == 0 and not silent:
                    logging.info(f"[+] Handshakes converted to {output_dir}")
                elif proc.returncode != 0:
                    logging.error(f"[!] hcxpcapngtool error: {stderr.decode()}")
                last_size = current_size
            time.sleep(5)
        except KeyboardInterrupt:
            logging.info("Handshake converter stopped")
            break
        except Exception as e:
            logging.error(f"Handshake converter error: {e}")
            time.sleep(5)

# --- Main ---
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    parser = argparse.ArgumentParser(description="All-in-one Wi-Fi monitor and network capture")
    parser.add_argument("--monitor-iface", type=str, default="wlan1mon",
                        help="Interface for Wi-Fi monitoring")
    parser.add_argument("--network-iface", type=str, default="wlan0",
                        help="Interface for network capture")
    parser.add_argument("--handshake-out", type=str, default="/root/5t3whandshakes.pcap",
                        help="Path to save handshake .pcap")
    parser.add_argument("--capture-handshakes", action="store_true",
                        help="Enable continuous handshake capture")
    parser.add_argument("--network-out", type=str, default="/root/5t3wnet.pcap",
                        help="Path to save network capture .pcap")
    parser.add_argument("--capture-network", action="store_true",
                        help="Enable continuous network capture")
    parser.add_argument("--silence", action="store_true",
                        help="Suppress terminal output")
    parser.add_argument("--hc22000-dir", type=str, default="/root/5t3whc22000s/",
                        help="Folder to save hc22000 files")
    parser.add_argument("--port-scan", action="store_true",
                        help="Enable port scanning of new ARP clients")
    parser.add_argument("--scan-interval", type=int, default=30,
                        help="Interval in minutes for continuous port scanning (default: 30)")
    parser.add_argument("--scan-once", action="store_true",
                        help="Perform a single port scan and exit")
    parser.add_argument("--scan-reports-dir", type=str, default="/root/5t3wportscans",
                        help="Directory to save port scan reports")
    parser.add_argument("--vuln-scan", action="store_true",
                        help="Enable vulnerability scanning of new ARP clients")
    parser.add_argument("--vuln-scan-interval", type=int, default=60,
                        help="Interval in minutes for continuous vulnerability scanning (default: 60)")
    parser.add_argument("--vuln-scan-once", action="store_true",
                        help="Perform a single vulnerability scan and exit")
    parser.add_argument("--vuln-reports-dir", type=str, default="/root/5t3wvulns",
                        help="Directory to save vulnerability scan reports")
    parser.add_argument("--generate-vuln-report", action="store_true",
                        help="Generate vulnerability report from existing scan data and exit")
    args = parser.parse_args()

    if os.geteuid() != 0:
        logging.warning("[!] Root permissions recommended for packet capture")

    if args.silence:
        logging.getLogger().setLevel(logging.ERROR)

    # Update global scan reports directory
    SCAN_REPORTS_DIR = args.scan_reports_dir
    SCANNED_IPS_FILE = os.path.join(SCAN_REPORTS_DIR, "scanned_ips.json")
    
    # Update global vulnerability reports directory
    VULN_REPORTS_DIR = args.vuln_reports_dir
    VULN_SCANNED_IPS_FILE = os.path.join(VULN_REPORTS_DIR, "vuln_scanned_ips.json")
    VULN_SUMMARY_FILE = os.path.join(VULN_REPORTS_DIR, "vulnerability_summary.json")

    # Handle vulnerability scanning modes
    if args.vuln_scan_once:
        logging.info("Performing single vulnerability scan...")
        scan_vulnerabilities()
        logging.info("Single vulnerability scan completed, exiting.")
        exit()
    
    if args.generate_vuln_report:
        logging.info("Generating vulnerability report...")
        report_file = generate_vulnerability_report()
        if report_file:
            logging.info(f"Vulnerability report saved to: {report_file}")
        logging.info("Report generation completed, exiting.")
        exit()

    # Handle port scanning modes
    if args.scan_once:
        logging.info("Performing single port scan...")
        scan_new_clients()
        logging.info("Single port scan completed, exiting.")
        exit()
    
    if args.vuln_scan:
        logging.info(f"Starting continuous vulnerability scanning with {args.vuln_scan_interval} minute intervals")
        t_vuln_scan = threading.Thread(target=continuous_vulnerability_scanning, 
                                       args=(args.vuln_scan_interval,), daemon=True)
        t_vuln_scan.start()
    
    if args.port_scan:
        logging.info(f"Starting continuous port scanning with {args.scan_interval} minute intervals")
        t_port_scan = threading.Thread(target=continuous_port_scanning, 
                                       args=(args.scan_interval,), daemon=True)
        t_port_scan.start()

    # --- Handshake capture with pruning ---
    HANDSHAKE_MAX_SIZE_MB = 100  # max .pcap size before prune

    if args.capture_handshakes:
        def handshake_capture_prune():
            while True:
                try:
                    # prune if file too large
                    if os.path.exists(args.handshake_out):
                        size_mb = os.path.getsize(args.handshake_out) / (1024 * 1024)
                        if size_mb > HANDSHAKE_MAX_SIZE_MB:
                            backup_file = args.handshake_out + f".old.{int(time.time())}"
                            os.rename(args.handshake_out, backup_file)
                            logging.info(f"[!] Handshake file exceeded {HANDSHAKE_MAX_SIZE_MB}MB, rotated to {backup_file}")

                    proc = subprocess.Popen([
                        "tcpdump",
                        "-i", args.monitor_iface,
                        "-w", args.handshake_out,
                        "ether proto 0x888e"
                    ])
                    proc.wait()
                    logging.warning("tcpdump handshake capture exited, restarting in 5s...")
                    time.sleep(5)
                except KeyboardInterrupt:
                    logging.info("Handshake capture stopped")
                    break
                except Exception as e:
                    logging.error(f"Handshake capture error: {e}")
                    time.sleep(5)

        t_hs = threading.Thread(target=handshake_capture_prune, daemon=True)
        t_hs.start()
        logging.info(f"[*] Continuous handshake capture with pruning started on {args.monitor_iface}")

    # Handshake converter thread stays the same
    t_hc = threading.Thread(target=handshake_converter_loop,
                            args=(args.handshake_out, args.hc22000_dir, args.silence),
                            daemon=True)
    t_hc.start()
    logging.info(f"[*] Handshake converter started, saving hc22000 to {args.hc22000_dir}")

    # Handshake converter thread stays the same
    t_hc = threading.Thread(target=handshake_converter_loop,
                            args=(args.handshake_out, args.hc22000_dir, args.silence),
                            daemon=True)
    t_hc.start()
    logging.info(f"[*] Handshake converter started, saving hc22000 to {args.hc22000_dir}")

    # --- Network capture ---
    if args.capture_network:
        def network_capture():
            try:
                while True:
                    proc = subprocess.Popen([
                        "tcpdump",
                        "-i", args.network_iface,
                        "-w", args.network_out
                    ])
                    proc.wait()
                    logging.warning("tcpdump network capture exited, restarting in 5s...")
                    time.sleep(5)
            except KeyboardInterrupt:
                logging.info("Network capture stopped")
        t_net = threading.Thread(target=network_capture, daemon=True)
        t_net.start()
        logging.info(f"[*] Continuous network capture started on {args.network_iface}, saving to {args.network_out}")

    # --- Start Wi-Fi monitor ---
    monitor(interface=args.monitor_iface, silent=args.silence)
