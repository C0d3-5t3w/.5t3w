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
    args = parser.parse_args()

    if os.geteuid() != 0:
        logging.warning("[!] Root permissions recommended for packet capture")

    if args.silence:
        logging.getLogger().setLevel(logging.ERROR)

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
