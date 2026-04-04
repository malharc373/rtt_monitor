# RTT Live Monitor

A Python tool to capture and analyse TCP Round-Trip Time (RTT) in real time by sniffing packets on a network interface using Scapy.

## Features
- Live packet sniffing on any interface (e.g. en0)
- Per-category RTT stats: Mean, P50, P90, P95, Max
- Auto-saves output/rtt_live.csv and output/rtt_analysis.png
- Offline mode for analysing a pre-captured .pcap file

## Requirements
- Python 3.10+, macOS/Linux
- Run with sudo (raw socket access required)

Install dependencies:
    pip install -r requirements.txt

## Usage

Live mode (60s capture, 5s intervals):
    sudo python3 projectv3.py --live --interval 5 --duration 60

Offline mode:
    sudo python3 projectv3.py --pcap path/to/file.pcap

## Output
- output/rtt_live.csv      Per-flow RTT samples
- output/rtt_analysis.png  Multi-panel RTT analysis chart

## Project Structure
    rtt_project/
    |-- projectv3.py
    |-- requirements.txt
    |-- output/            (gitignored)
    |-- README.md

## CN Mini Project - TY SEM VI
