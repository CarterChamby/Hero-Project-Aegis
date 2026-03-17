"""
Aegis Real-Time Network Analyzer v2.0
======================================
Reads enriched CSV from the C sniffer via stdin, classifies each packet
using a pre-trained Random Forest model, and displays a live CLI dashboard
with threat alerts and traffic statistics.

Usage:
    sudo ./sniffer [device] | python3 analyzer.py

Requires:
    - aegis_model.pkl  (trained model)
    - aegis_meta.pkl   (feature names + label map)
    Both produced by train_model.py
"""

import sys
import os
import time
import signal
import numpy as np
import joblib
from collections import defaultdict, deque
from datetime import datetime

# ─── Configuration ───────────────────────────────────────────────
ALERT_THRESHOLD = 5          # consecutive malicious packets before alert
RATE_WINDOW = 10             # seconds for rate calculation
STATS_INTERVAL = 30          # print summary stats every N packets
LOG_FILE = "aegis_alerts.log"
MODEL_DIR = os.path.dirname(os.path.abspath(__file__))

# ─── ANSI Colors ─────────────────────────────────────────────────
class Color:
    RED     = "\033[91m"
    YELLOW  = "\033[93m"
    GREEN   = "\033[92m"
    CYAN    = "\033[96m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RESET   = "\033[0m"


# ─── Threat Tracker ─────────────────────────────────────────────
class ThreatTracker:
    """Tracks per-IP threat scores and fires alerts."""

    def __init__(self, threshold=ALERT_THRESHOLD):
        self.threshold = threshold
        self.ip_scores = defaultdict(int)
        self.ip_history = defaultdict(lambda: deque(maxlen=100))
        self.alerts_fired = set()

    def record(self, src_ip, label, label_name):
        if label > 0:
            self.ip_scores[src_ip] += 1
            self.ip_history[src_ip].append(label_name)
        else:
            # Decay score for benign traffic
            self.ip_scores[src_ip] = max(0, self.ip_scores[src_ip] - 1)

    def check_alert(self, src_ip):
        score = self.ip_scores[src_ip]
        if score >= self.threshold and src_ip not in self.alerts_fired:
            self.alerts_fired.add(src_ip)
            return True
        return False

    def get_top_threats(self, n=5):
        sorted_ips = sorted(self.ip_scores.items(), key=lambda x: -x[1])
        return sorted_ips[:n]


# ─── Statistics ──────────────────────────────────────────────────
class Stats:
    """Aggregates traffic statistics."""

    def __init__(self):
        self.total = 0
        self.by_label = defaultdict(int)
        self.by_protocol = defaultdict(int)
        self.bytes_total = 0
        self.timestamps = deque(maxlen=1000)
        self.start_time = time.time()

    def record(self, label_name, protocol, length, timestamp):
        self.total += 1
        self.by_label[label_name] += 1
        self.by_protocol[protocol] += 1
        self.bytes_total += length
        self.timestamps.append(timestamp)

    def packets_per_second(self):
        if len(self.timestamps) < 2:
            return 0.0
        window = self.timestamps[-1] - self.timestamps[0]
        if window == 0:
            return 0.0
        return len(self.timestamps) / window

    def uptime(self):
        return time.time() - self.start_time


# ─── Feature Extraction ─────────────────────────────────────────
def parse_flags(flags_str):
    """Convert flag string like 'SA' into individual binary features."""
    flags_str = flags_str.upper().strip()
    return {
        "flag_syn":  1 if "S" in flags_str else 0,
        "flag_ack":  1 if "A" in flags_str else 0,
        "flag_fin":  1 if "F" in flags_str else 0,
        "flag_rst":  1 if "R" in flags_str else 0,
        "flag_push": 1 if "P" in flags_str else 0,
    }


def extract_features(parts):
    """
    Parse a CSV line from the sniffer and return a feature vector.
    Expected: timestamp, src_ip, dst_ip, src_port, dst_port, protocol, length, tcp_flags
    """
    timestamp = int(parts[0])
    src_ip    = parts[1]
    dst_ip    = parts[2]
    src_port  = int(parts[3])
    dst_port  = int(parts[4])
    protocol  = parts[5].strip().upper()
    length    = int(parts[6])
    flags_str = parts[7] if len(parts) > 7 else "-"

    flags = parse_flags(flags_str)

    feature_vector = np.array([[
        length,
        src_port,
        dst_port,
        1 if protocol == "TCP"  else 0,
        1 if protocol == "UDP"  else 0,
        1 if protocol == "ICMP" else 0,
        flags["flag_syn"],
        flags["flag_ack"],
        flags["flag_fin"],
        flags["flag_rst"],
        flags["flag_push"],
    ]])

    return feature_vector, timestamp, src_ip, dst_ip, src_port, dst_port, protocol, length


# ─── Display ─────────────────────────────────────────────────────
def print_banner():
    print(f"""
{Color.CYAN}{Color.BOLD}
    ╔══════════════════════════════════════════════════╗
    ║          AEGIS Network Defense System            ║
    ║              Real-Time Analyzer v2.0             ║
    ╚══════════════════════════════════════════════════╝
{Color.RESET}""")


def print_packet(src_ip, dst_ip, src_port, dst_port, protocol, length, label, label_name):
    """Print a single classified packet."""
    if label == 0:
        color = Color.GREEN
        icon = "✓"
    elif label == 1:
        color = Color.RED
        icon = "⚠"
    elif label == 2:
        color = Color.YELLOW
        icon = "🔍"
    else:
        color = Color.RED
        icon = "💀"

    ts = datetime.now().strftime("%H:%M:%S")
    print(
        f"  {Color.DIM}{ts}{Color.RESET} "
        f"{icon} {color}{label_name:15s}{Color.RESET} "
        f"{src_ip}:{src_port} → {dst_ip}:{dst_port} "
        f"{Color.DIM}| {protocol} | {length}B{Color.RESET}"
    )


def print_alert(src_ip, tracker):
    """Print a threat alert for a specific IP."""
    history = list(tracker.ip_history[src_ip])[-5:]
    attacks = ", ".join(history)
    print(f"""
{Color.RED}{Color.BOLD}  ╔══════════════════════════════════════════════════╗
  ║  🚨 THREAT ALERT                                 ║
  ╠══════════════════════════════════════════════════╣
  ║  Source IP: {src_ip:37s} ║
  ║  Score:     {tracker.ip_scores[src_ip]:<37d} ║
  ║  Attacks:   {attacks:37s} ║
  ╚══════════════════════════════════════════════════╝{Color.RESET}
""")


def print_stats(stats, tracker):
    """Print a periodic statistics summary."""
    uptime = stats.uptime()
    mins, secs = divmod(int(uptime), 60)
    hrs, mins = divmod(mins, 60)
    pps = stats.packets_per_second()

    print(f"""
{Color.CYAN}  ┌──────────────── Traffic Summary ────────────────┐
  │  Uptime:    {hrs:02d}:{mins:02d}:{secs:02d}                               │
  │  Packets:   {stats.total:<37d} │
  │  Data:      {stats.bytes_total / 1024:.1f} KB{' ' * (33 - len(f'{stats.bytes_total / 1024:.1f} KB'))}│
  │  Rate:      {pps:.1f} pkt/s{' ' * (33 - len(f'{pps:.1f} pkt/s'))}│
  ├─────────────────────────────────────────────────┤""")

    for label_name, count in sorted(stats.by_label.items()):
        pct = (count / stats.total * 100) if stats.total else 0
        bar = "█" * int(pct / 5)
        print(f"  │  {label_name:15s} {count:6d} ({pct:5.1f}%) {bar:20s} │")

    print(f"  ├─────────────────────────────────────────────────┤")

    top = tracker.get_top_threats(3)
    if top and top[0][1] > 0:
        print(f"  │  Top Threat Sources:                              │")
        for ip, score in top:
            if score > 0:
                print(f"  │    {ip:20s} score: {score:<18d} │")
    else:
        print(f"  │  No active threats detected.                     │")

    print(f"  └─────────────────────────────────────────────────┘{Color.RESET}")


def log_alert(src_ip, label_name, score):
    """Append alert to log file."""
    ts = datetime.now().isoformat()
    with open(LOG_FILE, "a") as f:
        f.write(f"{ts},{src_ip},{label_name},{score}\n")


# ─── Main Loop ───────────────────────────────────────────────────
def main():
    print_banner()

    # Load model
    model_path = os.path.join(MODEL_DIR, "aegis_model.pkl")
    meta_path  = os.path.join(MODEL_DIR, "aegis_meta.pkl")

    if not os.path.exists(model_path):
        print(f"{Color.RED}  [ERROR] Model not found at {model_path}")
        print(f"  Run: python3 Hero-Project-Aegis/train_model.py{Color.RESET}")
        sys.exit(1)

    print(f"  {Color.DIM}Loading model from {model_path}...{Color.RESET}")
    clf = joblib.load(model_path)

    label_names = {0: "Benign", 1: "DDoS/Flood", 2: "Port Scan", 3: "ICMP Flood"}
    if os.path.exists(meta_path):
        meta = joblib.load(meta_path)
        label_names = meta.get("labels", label_names)

    print(f"  {Color.GREEN}Model loaded. Waiting for packet stream...{Color.RESET}\n")
    print(f"  {Color.DIM}{'─' * 70}{Color.RESET}")

    tracker = ThreatTracker()
    stats = Stats()
    header_skipped = False

    try:
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue

            # Skip CSV header from sniffer
            if not header_skipped and line.startswith("timestamp"):
                header_skipped = True
                continue

            parts = line.split(",")
            if len(parts) < 7:
                continue

            try:
                features, timestamp, src_ip, dst_ip, src_port, dst_port, protocol, length = \
                    extract_features(parts)

                prediction = clf.predict(features)[0]
                label = int(prediction)
                label_name = label_names.get(label, f"Unknown({label})")

                # Record stats
                stats.record(label_name, protocol, length, timestamp)
                tracker.record(src_ip, label, label_name)

                # Display packet
                print_packet(src_ip, dst_ip, src_port, dst_port,
                             protocol, length, label, label_name)

                # Check for alerts
                if tracker.check_alert(src_ip):
                    print_alert(src_ip, tracker)
                    log_alert(src_ip, label_name, tracker.ip_scores[src_ip])

                # Periodic summary
                if stats.total % STATS_INTERVAL == 0:
                    print_stats(stats, tracker)

            except (ValueError, IndexError) as e:
                continue

    except KeyboardInterrupt:
        print(f"\n{Color.CYAN}  [Aegis] Shutting down...{Color.RESET}")
        print_stats(stats, tracker)
        print(f"  {Color.DIM}Alerts logged to: {LOG_FILE}{Color.RESET}")
        sys.exit(0)


if __name__ == "__main__":
    main()
