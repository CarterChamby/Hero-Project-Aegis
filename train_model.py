"""
Aegis ML Model Trainer
======================
Generates synthetic network traffic data with multiple features
and trains a Random Forest classifier to distinguish between
benign traffic and several attack types.

Features used:
  0 - packet_length       (bytes)
  1 - src_port            (0-65535)
  2 - dst_port            (0-65535)
  3 - protocol_tcp        (1/0)
  4 - protocol_udp        (1/0)
  5 - protocol_icmp       (1/0)
  6 - flag_syn            (1/0)
  7 - flag_ack            (1/0)
  8 - flag_fin            (1/0)
  9 - flag_rst            (1/0)
 10 - flag_push           (1/0)

Labels:
  0 = Benign
  1 = DDoS / Flood
  2 = Port Scan
  3 = Ping of Death / ICMP Flood
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report
import joblib
import os

FEATURE_NAMES = [
    "packet_length", "src_port", "dst_port",
    "protocol_tcp", "protocol_udp", "protocol_icmp",
    "flag_syn", "flag_ack", "flag_fin", "flag_rst", "flag_push",
]

LABEL_NAMES = {
    0: "Benign",
    1: "DDoS / Flood",
    2: "Port Scan",
    3: "ICMP Flood",
}


def generate_benign(n=3000):
    """Normal web browsing, DNS, streaming — mixed protocols, typical sizes."""
    rng = np.random.default_rng(42)
    rows = []
    for _ in range(n):
        proto = rng.choice(["tcp", "udp"], p=[0.8, 0.2])
        length = int(max(40, min(1500, rng.normal(400, 200))))
        src_port = int(rng.integers(1024, 65535))
        # Common destination ports for normal traffic
        dst_port = int(rng.choice([80, 443, 53, 8080, 3000, 8443]))

        tcp, udp, icmp = (1, 0, 0) if proto == "tcp" else (0, 1, 0)
        # Normal TCP traffic: mostly ACK, some SYN for new connections
        if proto == "tcp":
            syn = int(rng.random() < 0.05)
            ack = 1
            fin = int(rng.random() < 0.03)
            rst = 0
            push = int(rng.random() < 0.3)
        else:
            syn, ack, fin, rst, push = 0, 0, 0, 0, 0

        rows.append([length, src_port, dst_port, tcp, udp, icmp,
                      syn, ack, fin, rst, push])
    return np.array(rows), np.zeros(n, dtype=int)


def generate_ddos(n=1000):
    """DDoS flood: many small packets, SYN flood or UDP flood to same port."""
    rng = np.random.default_rng(43)
    rows = []
    for _ in range(n):
        proto = rng.choice(["tcp", "udp"], p=[0.7, 0.3])
        # Small, rapid packets
        length = int(rng.integers(40, 120))
        src_port = int(rng.integers(1024, 65535))
        dst_port = int(rng.choice([80, 443]))  # Targeting web servers

        tcp, udp, icmp = (1, 0, 0) if proto == "tcp" else (0, 1, 0)
        if proto == "tcp":
            # SYN flood — lots of SYN, no ACK
            syn = 1
            ack = 0
            fin, rst, push = 0, 0, 0
        else:
            syn, ack, fin, rst, push = 0, 0, 0, 0, 0

        rows.append([length, src_port, dst_port, tcp, udp, icmp,
                      syn, ack, fin, rst, push])
    return np.array(rows), np.ones(n, dtype=int)


def generate_port_scan(n=800):
    """Port scanning: sequential destination ports, tiny packets, SYN probes."""
    rng = np.random.default_rng(44)
    rows = []
    for i in range(n):
        length = int(rng.integers(40, 80))
        src_port = int(rng.integers(40000, 65535))
        # Sequential or random high port scanning
        dst_port = int(rng.integers(1, 1024))

        tcp, udp, icmp = 1, 0, 0
        # SYN scan: SYN only, no ACK
        syn, ack = 1, 0
        # Occasional RST from closed ports
        rst = int(rng.random() < 0.4)
        fin, push = 0, 0

        rows.append([length, src_port, dst_port, tcp, udp, icmp,
                      syn, ack, fin, rst, push])
    return np.array(rows), np.full(n, 2, dtype=int)


def generate_icmp_flood(n=600):
    """Ping of Death / ICMP flood: large ICMP packets, no ports."""
    rng = np.random.default_rng(45)
    rows = []
    for _ in range(n):
        # Oversized ICMP packets
        length = int(rng.integers(1000, 65000))
        src_port = 0
        dst_port = 0

        tcp, udp, icmp = 0, 0, 1
        syn, ack, fin, rst, push = 0, 0, 0, 0, 0

        rows.append([length, src_port, dst_port, tcp, udp, icmp,
                      syn, ack, fin, rst, push])
    return np.array(rows), np.full(n, 3, dtype=int)


def main():
    print("=" * 50)
    print("  Aegis ML Model Trainer v2.0")
    print("=" * 50)

    # Generate synthetic data
    print("\n[1/4] Generating synthetic training data...")
    X_benign, y_benign = generate_benign()
    X_ddos, y_ddos = generate_ddos()
    X_scan, y_scan = generate_port_scan()
    X_icmp, y_icmp = generate_icmp_flood()

    X = np.vstack((X_benign, X_ddos, X_scan, X_icmp))
    y = np.concatenate((y_benign, y_ddos, y_scan, y_icmp))

    print(f"       Total samples: {len(y)}")
    for label, name in LABEL_NAMES.items():
        print(f"         {name}: {(y == label).sum()}")

    # Split for evaluation
    print("\n[2/4] Splitting data (80/20 train/test)...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # Train
    print("\n[3/4] Training Random Forest (200 trees)...")
    clf = RandomForestClassifier(
        n_estimators=200,
        max_depth=15,
        min_samples_split=5,
        random_state=42,
        n_jobs=-1,
    )
    clf.fit(X_train, y_train)

    # Evaluate
    y_pred = clf.predict(X_test)
    print("\n[4/4] Evaluation Results:")
    print("-" * 50)
    target_names = [LABEL_NAMES[i] for i in sorted(LABEL_NAMES.keys())]
    print(classification_report(y_test, y_pred, target_names=target_names))

    # Cross-validation
    scores = cross_val_score(clf, X, y, cv=5, scoring="accuracy")
    print(f"5-Fold Cross-Validation Accuracy: {scores.mean():.4f} (+/- {scores.std():.4f})")

    # Feature importance
    print("\nFeature Importances:")
    importances = clf.feature_importances_
    for name, imp in sorted(zip(FEATURE_NAMES, importances), key=lambda x: -x[1]):
        bar = "#" * int(imp * 50)
        print(f"  {name:20s} {imp:.4f} {bar}")

    # Save model
    model_path = os.path.join(os.path.dirname(__file__), "aegis_model.pkl")
    joblib.dump(clf, model_path)
    print(f"\nModel saved to: {model_path}")

    # Also save label map and feature names for the analyzer
    meta_path = os.path.join(os.path.dirname(__file__), "aegis_meta.pkl")
    joblib.dump({"features": FEATURE_NAMES, "labels": LABEL_NAMES}, meta_path)
    print(f"Metadata saved to: {meta_path}")

    print("\nReady for deployment!")


if __name__ == "__main__":
    main()
