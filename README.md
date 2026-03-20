# NIDS — Network Intrusion Detection System

A Network Intrusion Detection System built from scratch using Python 
and Scapy. Captures live network traffic and detects real attacks in 
real time with a live web dashboard.

---

## What It Detects

- **Port scans** — detects reconnaissance attempts targeting multiple ports
- **SYN flood attacks** — detects denial of service attempts via TCP SYN flooding
- **ARP sweep attacks** — detects network mapping and host discovery via ARP requests
- **Ping sweeps** — detects ICMP-based host discovery

---

## Project Structure
```
NIDS/
├── config.py       — all settings, thresholds and configuration
├── logger.py       — logging to file, console and email alerts
├── nids.py         — core detection engine
└── dashboard.py    — Flask web dashboard with Chart.js visualisation
```

---

## How It Works

The NIDS puts the network interface into promiscuous mode using Scapy, 
capturing every packet passing through. Each packet is inspected and 
routed to the appropriate detection function:

- **ARP packets** are checked for sweep patterns across multiple IPs
- **TCP packets** are checked for port scan patterns and SYN flood volume
- **ICMP packets** are checked for ping sweep patterns

Detection uses sliding time windows — if a source IP hits thresholds 
within the configured time window, an alert fires, gets logged to file 
and appears on the dashboard.

---

## Requirements

- Python 3.11 or later
- Npcap (Windows) — download from npcap.com
- libpcap (Linux) — usually pre-installed

Install Python dependencies:
```bash
pip install scapy flask
```

---

## Configuration

All settings are in `config.py`:
```python
# Detection thresholds
PORT_SCAN_THRESHOLD = 5     # unique ports within TIME_WINDOW
TIME_WINDOW         = 10    # seconds
SYN_FLOOD_THRESHOLD = 100   # SYN packets per second
PING_SWEEP_THRESHOLD = 3    # unique IPs within TIME_WINDOW

# Email alerts (optional)
EMAIL_ENABLED  = False
EMAIL_SENDER   = "your_email@gmail.com"
EMAIL_PASSWORD = "your_app_password"
EMAIL_RECEIVER = "your_email@gmail.com"

# Interface — set to None for auto-detection
INTERFACE = None
```

To enable email alerts set `EMAIL_ENABLED = True` and add your Gmail 
App Password. To override the auto-detected interface set `INTERFACE` 
to the full device path.

---

## How to Run

Open two terminal windows as Administrator (Windows) or with sudo (Linux).

**Terminal 1 — Start the detection engine:**
```bash
python nids.py
```

**Terminal 2 — Start the dashboard:**
```bash
python dashboard.py
```

**Open the dashboard in your browser:**
```
http://localhost:5000
```

---

## Test Environment

This project was built and tested using:

- Windows host machine running the NIDS
- Kali Linux VM as the attacker machine
- VirtualBox Host-Only network connecting both machines
- Kali Linux VM connected to Windows host via VirtualBox Host-Only network

**Attacks used for testing:**
```bash
# ARP sweep
for i in $(seq 1 20); do ping -c 1 TARGET_IP.$i & done

# Port scan
nmap -sS -T4 --min-rate 1000 TARGET_IP

# SYN flood
sudo hping3 -S --flood TARGET_IP
```

---

## Dashboard

The web dashboard auto-refreshes every 5 seconds and shows:

- Live stat cards — total alerts, port scans, SYN floods, ping sweeps, total events
- Doughnut chart — visual breakdown of attack types
- Events table — timestamped log entries with severity badges and attack type indicators

---

## Detection Results

All three attack types were successfully detected during testing:

- Port scan detected — 5 unique ports hit within the time window
- SYN flood detected — 100 SYN packets received within 1 second
- ARP sweep detected — 3 unique IPs probed within the time window

---

## Known Limitations

- Scapy is not optimised for high traffic volumes — designed for learning not production
- Detection thresholds are fixed — no adaptive baseline learning
- Alert deduplication is basic — multiple alerts can fire for one attack session
- Email requires Gmail App Password setup

---

## Future Improvements

- Dynamic threshold adaptation based on baseline traffic
- UDP flood detection
- ARP spoofing detection
- Alert deduplication with cooldown periods
- Cross-platform interface auto-detection improvements
- More attack signatures

---

## Tools Used

Python, Scapy, Flask, Chart.js, Kali Linux, nmap, hping3, VirtualBox

---

## Author

Built by Thando Chipango as a hands-on cybersecurity learning project.
