# Network Packet Analyzer

> **Month 1 of 12** - Built by [Abishek Devanand](https://github.com/abishek-07d) as part of a 12-month Cybersecurity + AI project challenge.

A real-time network packet capture and analysis tool built entirely in Python with zero heavy dependencies.

---

## Features

| Feature | Description |
|---|---|
| Live Capture | Raw socket capture of TCP, UDP, ICMP packets |
| Web Dashboard | Live browser dashboard - no Flask needed |
| Rich Terminal UI | Color-coded live packet stream in terminal |
| Protocol Parsing | Full IPv4, TCP (with flags), UDP header parsing |
| Smart Filtering | Filter by protocol or IP address |
| Live Stats | PPS, bytes, protocol breakdown, top IPs and ports |
| JSON Export | Save full capture session to JSON |
| Test Suite | 21 unit tests - all passing |
| Simulator Mode | Fake traffic demo - no admin needed |

---

## Project Structure

```
network-packet-analyzer/
├── core/
│   ├── analyzer.py       # Core engine: parsers, PacketAnalyzer class
│   └── simulator.py      # Fake traffic generator for demo/testing
├── dashboard/
│   └── app.py            # Web dashboard (stdlib http.server)
├── tests/
│   └── test_analyzer.py  # 21 unit tests (pytest)
├── data/                 # JSON capture output goes here
├── main.py               # CLI entry point
├── requirements.txt
└── README.md
```
---

## Quick Start

### 1. Clone and Install
```bash
git clone https://github.com/abishek-07d/network-packet-analyzer
cd network-packet-analyzer
pip install -r requirements.txt
```

### 2. Run Web Dashboard (no admin needed)
```bash
python dashboard/app.py
# Open http://127.0.0.1:5000
```

### 3. Run Terminal UI
```bash
python main.py --sim
```

### 4. Live Capture (requires admin on Windows)
```bash
# Run PowerShell as Administrator
python main.py
python main.py --proto TCP
python main.py --ip 192.168.1.1
python main.py --count 100 --save data/capture.json
```

---

## Running Tests

```bash
python -m pytest tests/ -v
# 21 passed in 0.42s
```

---

## What I Learned

- Raw socket programming - How IP/TCP/UDP headers are structured in binary
- struct.unpack - Parsing binary network data byte by byte
- Threading - Running capture in background while UI stays responsive
- Protocol internals - TCP flags, TTL, IHL, port to service mapping
- Stdlib HTTP server - Building a live API without Flask
- Test-driven development - Writing tests for all parsers

---

## Tech Stack

| Tool | Purpose |
|---|---|
| Python 3.14 | Core language |
| socket | Raw packet capture |
| struct | Binary protocol parsing |
| threading | Concurrent capture and display |
| http.server | Web dashboard backend |
| rich | Terminal UI colors |
| pytest | Test suite |

---

## 12-Month Project Roadmap

| Month | Project | Domain |
|---|---|---|
| 1 - Done | Network Packet Analyzer | Cybersecurity |
| 2 | AI-Powered Log Anomaly Detector | AI + Cyber |
| 3 | Satellite Orbit Tracker | Space Tech |
| 4 | Password Strength Analyzer | Cybersecurity |
| 5 | Space Weather Dashboard | Space Tech |
| 6 | Malware Behavior Classifier | AI + Cyber |
| 7 | AI Phishing URL Detector | AI + Cyber |
| 8 | Lunar Seismic Analysis Toolkit | Space Tech |
| 9 | Network Intrusion Detection System | Cybersecurity |
| 10 | Threat Intelligence Aggregator | Cybersecurity |
| 11 | AI Space Debris Predictor | AI + Space |
| 12 | Full Cyber + AI Platform | Combo |

---

## Author

**Abishek D** - Cybersecurity Student | AI | Network Engineer  
Location: Tenkasi, Tamil Nadu  
LinkedIn: https://linkedin.com/in/abishek-d-437638323  
GitHub: https://github.com/abishek-07d

---

*Built as Month 1 of a 12-month project challenge in Cybersecurity, AI, and Space Tech.*
