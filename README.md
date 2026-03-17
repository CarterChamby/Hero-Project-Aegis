# Project Aegis

A real-time network intrusion detection system that captures live traffic with a C packet sniffer, then classifies each packet using a machine learning model to flag DDoS attacks, port scans, and ICMP floods.

## Architecture

```
┌─────────────┐       CSV pipe        ┌─────────────────┐
│  sniffer.c  │ ───── stdout ──────── │  analyzer.py    │
│  (libpcap)  │                       │  (scikit-learn) │
└─────────────┘                       └─────────────────┘
     │                                        │
     │ Captures raw packets                   │ Loads aegis_model.pkl
     │ Extracts: IP, ports,                   │ Classifies each packet
     │   protocol, TCP flags                  │ Tracks threats per IP
     │ Outputs enriched CSV                   │ Live CLI dashboard
     │                                        │ Logs alerts to file
```

## Components

**sniffer.c** — Packet capture engine built on libpcap. Extracts source/destination IPs, ports, protocol type (TCP/UDP/ICMP), packet length, and TCP flags. Outputs a CSV stream to stdout.

**train_model.py** — Generates synthetic network traffic for four classes (Benign, DDoS, Port Scan, ICMP Flood) and trains a Random Forest classifier on 11 features. Saves the model and metadata to disk.

**analyzer.py** — Reads the sniffer's CSV stream via stdin, extracts features from each packet, runs the ML model, and displays classified traffic in a color-coded CLI dashboard. Fires alerts when a source IP exceeds a threat score threshold.

## Quick Start

### 1. Install dependencies

```bash
# Python
pip install numpy pandas scikit-learn joblib

# C (macOS — libpcap is included)
# Linux:
sudo apt install libpcap-dev
```

### 2. Train the model

```bash
python3 train_model.py
```

This produces `aegis_model.pkl` and `aegis_meta.pkl`.

### 3. Compile the sniffer

```bash
gcc -o sniffer sniffer.c -lpcap
```

### 4. Run the pipeline

```bash
sudo ./sniffer en0 | python3 analyzer.py
```

Replace `en0` with your network interface (use `ifconfig` or `ip link` to find it).

## Features Extracted

| # | Feature | Description |
|---|---------|-------------|
| 0 | packet_length | Total packet size in bytes |
| 1 | src_port | Source port number |
| 2 | dst_port | Destination port number |
| 3 | protocol_tcp | Is TCP (1/0) |
| 4 | protocol_udp | Is UDP (1/0) |
| 5 | protocol_icmp | Is ICMP (1/0) |
| 6 | flag_syn | TCP SYN flag set |
| 7 | flag_ack | TCP ACK flag set |
| 8 | flag_fin | TCP FIN flag set |
| 9 | flag_rst | TCP RST flag set |
| 10 | flag_push | TCP PSH flag set |

## Threat Classes

| Label | Class | Indicators |
|-------|-------|------------|
| 0 | Benign | Normal browsing, DNS, streaming |
| 1 | DDoS / Flood | SYN floods, UDP floods to web ports |
| 2 | Port Scan | Sequential port probes, SYN+RST patterns |
| 3 | ICMP Flood | Oversized ICMP packets (Ping of Death) |

## Output

The analyzer displays each packet with a classification label, color-coded by threat level. Every 30 packets it prints a traffic summary with protocol breakdown, threat percentages, and top threat source IPs. Alerts are logged to `aegis_alerts.log`.
