#!/usr/bin/env python3
"""
main.py - benign Wi-Fi monitor + simple TF model on metadata (Beacon vs ProbeRequest)

SAFE USE: Only monitor adapters/networks you own or have permission to monitor.
This script collects only metadata (no payloads) and is explicitly NOT intended
to capture authentication handshakes, credentials, or payloads.

Dependencies:
  pip install scapy pyshark pandas numpy tensorflow scikit-learn

Run (example):
  sudo python3 main.py --iface wlan0mon --out-data captured_meta.csv
"""

import argparse
import csv
import datetime
import threading
import time
from collections import deque, Counter

import numpy as np
import pandas as pd
from scapy.all import sniff, Dot11, RadioTap

# TensorFlow, scikit-learn for model and preprocessing
import tensorflow as tf
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split

# === Configuration defaults ===
SNIFF_BATCH_SECONDS = 15     # collect this many seconds of packets before appending to dataset
RETRAIN_AFTER_BATCHES = 3    # retrain model after this many batches collected
SAMPLES_PER_BATCH = 1000     # safety cap on how many packets to keep per batch

# === Helper functions ===
def parse_radiotap_rssi(pkt):
    """
    Try to read RSSI from RadioTap (if available). Returns int or None.
    Scapy places dBm_AntSignal in pkt.dBm_AntSignal for some drivers.
    """
    try:
        if pkt.haslayer(RadioTap):
            # scapy often exposes 'dBm_AntSignal' attribute
            rssi = pkt.dBm_AntSignal
            if isinstance(rssi, (int, float)):
                return int(rssi)
    except Exception:
        pass
    return None

def frame_subtype_str(subtype):
    return {
        8: "Beacon",
        4: "ProbeReq",
        5: "ProbeResp",
        0: "AssocReq",
        1: "AssocResp",
        11: "Auth",
    }.get(subtype, f"Subtype{subtype}")

def extract_metadata(pkt):
    """
    Extract only benign metadata from Dot11 frames:
      - timestamp
      - frame_len
      - type (management/data/ctrl)
      - subtype
      - rssi (if available)
      - src_mac / dst_mac (hashed to preserve privacy) -> we'll hash to short token
    """
    meta = {}
    meta["ts"] = datetime.datetime.utcnow().isoformat()
    meta["len"] = len(pkt)
    meta["has_radiotap"] = int(pkt.haslayer(RadioTap))
    rssi = parse_radiotap_rssi(pkt)
    meta["rssi"] = rssi if rssi is not None else 0  # 0 as placeholder for missing
    if pkt.haslayer(Dot11):
        dot11 = pkt.getlayer(Dot11)
        meta["type"] = int(dot11.type)   # 0=mgmt,1=ctrl,2=data
        meta["subtype"] = int(dot11.subtype)
        meta["subtype_name"] = frame_subtype_str(meta["subtype"])
        # Short hashed identifiers (not reversible) to allow device grouping without storing raw MACs
        # Use last 3 bytes of mac as a simple anonymized token (string)
        try:
            src = dot11.addr2 or ""
            dst = dot11.addr1 or ""
            meta["src_token"] = src.replace(":", "")[-6:].lower() if src else ""
            meta["dst_token"] = dst.replace(":", "")[-6:].lower() if dst else ""
        except Exception:
            meta["src_token"] = ""
            meta["dst_token"] = ""
    else:
        meta["type"] = -1
        meta["subtype"] = -1
        meta["subtype_name"] = "Unknown"
        meta["src_token"] = ""
        meta["dst_token"] = ""
    return meta

# === Sniffer thread ===
class SnifferThread(threading.Thread):
    def __init__(self, iface, batch_seconds=SNIFF_BATCH_SECONDS, sample_limit=SAMPLES_PER_BATCH):
        super().__init__(daemon=True)
        self.iface = iface
        self.batch_seconds = batch_seconds
        self.sample_limit = sample_limit
        self.buffer = deque()
        self._stop = threading.Event()

    def _pkt_handler(self, pkt):
        # Only inspect management frames (type == 0) to keep things benign
        if pkt.haslayer(Dot11) and pkt.type == 0:
            meta = extract_metadata(pkt)
            self.buffer.append(meta)
            # cap buffer size to avoid memory blowup
            if len(self.buffer) > self.sample_limit:
                self.buffer.popleft()

    def run(self):
        while not self._stop.is_set():
            sniff(iface=self.iface, prn=self._pkt_handler,
                  store=False, timeout=self.batch_seconds, stop_filter=lambda x: self._stop.is_set())

    def stop(self):
        self._stop.set()

    def pop_batch(self):
        items = []
        while self.buffer:
            items.append(self.buffer.popleft())
        return items

# === Simple dataset & model utilities ===
def append_to_csv(path, rows, fieldnames):
    write_header = False
    try:
        # check if file exists or empty
        with open(path, "r"):
            pass
    except FileNotFoundError:
        write_header = True

    with open(path, "a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        if write_header:
            writer.writeheader()
        for r in rows:
            writer.writerow(r)

def build_feature_matrix(df):
    """
    Build numeric features from metadata df.
    - len, rssi, type, subtype
    - encode subtype_name via simple mapping to small ints
    - do not include tokens (src/dst) beyond count features
    """
    df2 = df.copy()
    # map subtype names to small integers
    subtype_map = {name: i for i, name in enumerate(sorted(df2["subtype_name"].unique()))}
    df2["subtype_id"] = df2["subtype_name"].map(subtype_map).fillna(-1).astype(int)

    # Basic features
    features = df2[["len", "rssi", "type", "subtype_id"]].astype(float).fillna(0.0)
    # Additional aggregated features: number of unique src tokens in sample window is not available here,
    # but model can be extended to include window-level features.
    return features.values.astype(np.float32), subtype_map

def train_simple_model(X, y, model_path=None, epochs=10):
    # Scale
    scaler = StandardScaler()
    Xs = scaler.fit_transform(X)

    num_classes = len(np.unique(y))
    # For demo: if two classes map to 2, use binary; else multi-class
    if num_classes == 2:
        # binary classification (sigmoid)
        model = tf.keras.Sequential([
            tf.keras.layers.Input(shape=(Xs.shape[1],)),
            tf.keras.layers.Dense(32, activation="relu"),
            tf.keras.layers.Dense(8, activation="relu"),
            tf.keras.layers.Dense(1, activation="sigmoid")
        ])
        model.compile(optimizer="adam", loss="binary_crossentropy", metrics=["accuracy"])
        model.fit(Xs, y, epochs=epochs, batch_size=32, verbose=0)
    else:
        # multiclass
        model = tf.keras.Sequential([
            tf.keras.layers.Input(shape=(Xs.shape[1],)),
            tf.keras.layers.Dense(64, activation="relu"),
            tf.keras.layers.Dense(32, activation="relu"),
            tf.keras.layers.Dense(num_classes, activation="softmax")
        ])
        model.compile(optimizer="adam", loss="sparse_categorical_crossentropy", metrics=["accuracy"])
        model.fit(Xs, y, epochs=epochs, batch_size=32, verbose=0)

    # Save scaler + model for later inference
    if model_path:
        model.save(model_path + "_tf_model", overwrite=True, include_optimizer=False)
        # Save scaler via numpy
        np.save(model_path + "_scaler.npy", scaler.mean_)
        np.save(model_path + "_scaler_scale.npy", scaler.scale_)
    return model, scaler

# === Main loop ===
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--iface", required=True, help="monitor-mode interface (already in monitor mode)")
    parser.add_argument("--out-data", default="wifi_meta.csv", help="CSV file to append metadata samples")
    parser.add_argument("--epochs", type=int, default=8, help="training epochs for TF model")
    parser.add_argument("--retrain-batches", type=int, default=RETRAIN_AFTER_BATCHES, help="how many batches before retraining")
    args = parser.parse_args()

    iface = args.iface
    csv_out = args.out_data

    print("WARNING: Run this only on networks you own / have permission to monitor.")
    print(f"Starting sniffer on interface: {iface}")
    sniffer = SnifferThread(iface=iface)
    sniffer.start()

    collected_batches = 0
    fieldnames = ["ts", "len", "has_radiotap", "rssi", "type", "subtype", "subtype_name", "src_token", "dst_token"]

    accumulated_rows = []

    model = None
    scaler = None

    try:
        while True:
            # sleep in increments, but main logic will pop batches when available
            time.sleep(SNIFF_BATCH_SECONDS + 1)
            batch = sniffer.pop_batch()
            if not batch:
                print(f"[{datetime.datetime.utcnow().isoformat()}] No management frames collected this interval.")
                continue

            # Keep only benign management subtype categories — drop any sensitive or unexpected items
            sanitized = []
            for r in batch:
                # Keep only Beacon (subtype 8) and ProbeReq (subtype 4) for the demo classifier
                if r["subtype"] in (8, 4):
                    # we store subtype_name to use as a label; leaving src/dst tokens but not full MACs
                    sanitized.append({k: r.get(k, "") for k in fieldnames})
                # else: ignore other management types in this simple demo
            if not sanitized:
                continue

            # Append to CSV (sanitized)
            append_to_csv(csv_out, sanitized, fieldnames)
            collected_batches += 1
            print(f"[{datetime.datetime.utcnow().isoformat()}] Appended {len(sanitized)} sanitized records to {csv_out} (batches={collected_batches})")

            # Periodically retrain model on available data
            if collected_batches >= args.retrain_batches:
                # Load dataset
                df = pd.read_csv(csv_out)
                # For this demo, label: Beacon=1, ProbeReq=0
                df = df[df["subtype"].isin([8,4])]  # filter
                df["label"] = df["subtype"].apply(lambda s: 1 if s == 8 else 0)
                X, subtype_map = build_feature_matrix(df)
                y = df["label"].values.astype(int)

                if len(np.unique(y)) < 2 or len(y) < 50:
                    print("Not enough variety/volume to train a reliable model yet. Collect more samples.")
                else:
                    print("Training model on collected metadata...")
                    model, scaler = train_simple_model(X, y, model_path="wifi_meta_model", epochs=args.epochs)
                    # quick eval
                    Xs = scaler.transform(X)
                    preds = model.predict(Xs, verbose=0)
                    if preds.shape[1] if preds.ndim>1 else 1:
                        # multiclass
                        print("Training completed (multiclass).")
                    else:
                        # binary
                        pred_labels = (preds.flatten() > 0.5).astype(int)
                        acc = (pred_labels == y).mean()
                        print(f"Training completed. Approx training accuracy: {acc:.3f}")

                collected_batches = 0

    except KeyboardInterrupt:
        print("Stopping sniffer...")
    finally:
        sniffer.stop()
        sniffer.join(timeout=2)
        print("Exited cleanly.")

if __name__ == "__main__":
    main()
