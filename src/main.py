import time
import math
import logging
import requests
import smtplib
from email.mime.text import MIMEText
from logging.handlers import SysLogHandler
from collections import Counter

import pandas as pd
import pyshark
from scapy.all import sniff, Raw

# --- Config ---
INTERFACE = "wlan0"
WINDOW_SEC = 5
PACKET_THRESHOLD = 500
UNIQUE_MAC_THRESHOLD = 50
MGMT_FRAME_THRESHOLD = 0.5
ENTROPY_THRESHOLD = 7.5

ALERT_EMAIL = None
ALERT_WEBHOOK = None
ALERT_SYSLOG = "/dev/log"

OUI_DB = {}

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

# --- Capture with Scapy ---
packets_buffer = []

def scapy_handler(pkt):
    try:
        ts = time.time()
        src = pkt.addr2 if hasattr(pkt, "addr2") else None
        dst = pkt.addr1 if hasattr(pkt, "addr1") else None
        length = len(pkt)
        payload = bytes(pkt[Raw]) if Raw in pkt else b""

        packets_buffer.append({
            "timestamp": ts,
            "src": src,
            "dst": dst,
            "length": length,
            "entropy": shannon_entropy(payload)
        })
    except Exception:
        pass

# --- Window Analysis ---
def analyze_window(df: pd.DataFrame):
    if df.empty:
        return

    total = len(df)
    unique_macs = df["src"].nunique()
    avg_entropy = df["entropy"].mean()

    # --- Management subtype ratio (from PyShark) ---
    mgmt_count = (df["frame_type"] == "mgmt").sum()
    mgmt_ratio = mgmt_count / total if total > 0 else 0

    # --- Rules ---
    if total > PACKET_THRESHOLD:
        send_alert(f"High traffic: {total} packets in {WINDOW_SEC}s")

    if unique_macs > UNIQUE_MAC_THRESHOLD:
        send_alert(f"Too many unique MACs: {unique_macs}")

    if mgmt_ratio > MGMT_FRAME_THRESHOLD:
        send_alert(f"Suspicious management traffic: {mgmt_ratio:.2%}")

    if avg_entropy > ENTROPY_THRESHOLD:
        send_alert(f"High entropy traffic: {avg_entropy:.2f}")

# --- PyShark Enhancer ---
def enrich_with_pyshark(interface=INTERFACE, duration=WINDOW_SEC):
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

# --- Monitor Loop ---
def monitor(interface=INTERFACE):
    global packets_buffer
    load_oui_db()

    logging.info("Starting WiFi monitor...")
    sniff_thread = lambda: sniff(iface=interface, prn=scapy_handler, store=0)

    import threading
    t = threading.Thread(target=sniff_thread, daemon=True)
    t.start()

    while True:
        time.sleep(WINDOW_SEC)
        df = pd.DataFrame(packets_buffer)
        subtype_info = enrich_with_pyshark(interface, duration=1)

        # merge subtype info
        subtype_map = {src: (ftype, stype) for src, ftype, stype in subtype_info}
        if not df.empty:
            df["frame_type"] = df["src"].map(lambda x: subtype_map.get(x, ("unknown", None))[0])
            df["subtype"] = df["src"].map(lambda x: subtype_map.get(x, ("", "unknown"))[1])

        analyze_window(df)
        packets_buffer = []

# --- Main ---
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    monitor()
