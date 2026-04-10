# KronoTrace

**KronoTrace** is a production-grade forensic log analysis platform and threat detection pipeline. Built entirely from the ground up for Phase 3, this platform ingests diverse log sources, normalizes them onto a chronological timeline, and automatically identifies targeted cyber-attacks using a multi-pattern detection engine.

All of this is presented through a dark, premium, cyberpunk-themed interface designed for real-time observability.

## Features

### 📡 The Ingestion Pipeline
KronoTrace natively parses multiple raw file formats without relying on heavy external dependencies like Wireshark or Splunk:
- **Windows Event Logs (`.evtx`)**: Parsed natively via `python-evtx`.
- **Network Captures (`.pcap`, `.pcapng`)**: Deep packet inspection using `scapy`.
- **System Logs (`.log`, `syslog`)**: Intelligent regex-based parsers mapping auth mechanisms and process triggers.
- **CSV Dumps (`.csv`)**: Auto-mapped schema detection.

### 🧠 The Normalizer
All uploaded files are evaluated simultaneously, translating their chaotic properties into a **Unified EventLog Schema**. Timestamps are all forced to precise UTC timing, allowing you to trace an attack that begins as a network port scan (`.pcap`) and ends as a Windows process execution (`.evtx`).

### 🛡️ Core Detection Engine
Built directly into the core, 5 primary threat hunting algorithms trace the timeline to find anomalous patterns:
1. **Brute Force Detection:** Uses a sliding time window (configurable) tracking failed login rates per unique Username/IP matrix.
2. **Privilege Escalation Tracker:** Links a successful authentication immediately following brute force or new IP appearances to administrative rights assignments.
3. **Data Exfiltration:** Identifies abnormal outbound traffic payload thresholds and suspected DNS tunneling.
4. **File Access Anomaly:** Tracks bulk, rapid-fire object permission read/writes—often an immediate precursor to Ransomware encryption or data harvesting.
5. **New IP Anomaly:** Historical behavior tracking to alert on high-impact service access from totally unknown addresses.

### ⚡ The Real-Time Dashboard
- **FastAPI + WebSockets:** Complete asynchronous backend ensuring large forensic dumps (100MB+ logs) do not lock up the processor. WebSockets push progress, data batches, and alerts to the interface in real-time.
- **Vis.js Interactive Timeline:** Seamless dragging and zooming across the entire timeline to pinpoint simultaneous actions.
- **Cyberpunk Dark Theme:** Polished with glassmorphism, responsive gradients, and custom micro-animations (Pure CSS + JS — no heavy frontend frameworks).

## Installation

1. **Clone & Setup:**
   ```bash
   git clone https://github.com/shyamraj7292/KronoTrace.git
   cd KronoTrace
   python -m venv venv
   source venv/bin/activate  # On Windows use: venv\Scripts\activate
   ```

2. **Install Dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Start the Application:**
   ```bash
   python run.py
   ```
   *The server will start on http://localhost:8000*

## Quick Start (Demo Mode)

Want to see the pipeline catch a real attack? 

1. Generate the synthetic attack data:
   ```bash
   python generate_samples.py
   ```
   *(This creates an `auth.log` and `security_events.csv` filled with Brute Force, Privilege Escalation, and File Harvesting anomalies in the `sample_data/` folder).*

2. Open **[http://localhost:8000](http://localhost:8000)**
3. Drag both files into the upload zone and hit **Analyze Files**.
4. Watch the pipeline normalize the data and surface the critical threats directly onto the dashboard!

---
*Developed for DEVTrails 2026.*