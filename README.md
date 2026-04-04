# RTT Monitor — CN Mini Project

A passive TCP Round-Trip Time (RTT) monitoring tool using Python and Scapy.
Measures per-flow latency by matching SYN/SYN-ACK pairs — no probe packets, no firewall issues.

---

## Versions

### v1 — Baseline Live Monitor
- First working implementation
- Detects 3 traffic categories: LAN (Wired), Campus WiFi, Remote Internet
- Basic spike detection using 2.5x median threshold
- Result: 2,243 samples | LAN: 1.4ms mean | WiFi: 15ms mean | Remote: 66ms mean

### v2 — Offline pcap Analysis
- Added offline mode to analyse pre-captured .pcap files
- Dual RTT measurement: SYN-ACK handshake + DATA-ACK method for better coverage
- Result: 247 samples | HTTPS P50: 0.2ms | Max: 431ms | Spike rate: 10.4%

### v3 — Configurable Live Monitor (Final Version)
- Fully configurable via --interval and --duration flags
- Live per-window stats table printed every N seconds during capture
- Fixed P95_ms column missing in live aggregation path
- Result: 176 samples | HTTPS P50 < 1ms | P90 < 11ms | 60s session

---

## Usage

Live mode (v3 — recommended):
    cd v3
    sudo python3 projectv3.py --live --interval 5 --duration 60

Offline pcap mode (v2):
    cd v2
    sudo python3 projectv2.py

Live mode (v1):
    cd v1
    sudo python3 projectv1.py --live --interval 5 --duration 60

## Install Dependencies
    pip install -r requirements.txt

Requires sudo for raw socket access on macOS/Linux.

## Repository Structure
    rtt_monitor/
    |-- v1/
    |   |-- projectv1.py       Baseline live monitor
    |   |-- output/            CSV + PNG results
    |-- v2/
    |   |-- projectv2.py       Offline pcap analyser
    |   |-- output/            CSV + PNG results
    |-- v3/
    |   |-- projectv3.py       Final configurable live monitor
    |   |-- output/            CSV + PNG results
    |-- README.md
    |-- requirements.txt
    |-- .gitignore

## CN Mini Project | TY SEM VI | April 2026
