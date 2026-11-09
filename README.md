 <p align="center">
  <img src="Image/Spectre.png" alt="SPECTRE Banner" width="800">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Version-2.1.0-blue.svg?style=flat-square" alt="Version">
  <img src="https://img.shields.io/badge/Python-3.9+-blue.svg?style=flat-square" alt="Python">
  <img src="https://img.shields.io/badge/Detection-Hybrid%20AI-red.svg?style=flat-square" alt="Detection">
  <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-lightgrey.svg?style=flat-square" alt="Platform">
  <img src="https://img.shields.io/badge/Network-DNS-black.svg?style=flat-square" alt="Network">
</p>

<h1 align="center">SPECTRE</h1>

<p align="center">
  <b>Stealthy DNS Threat Detection & Intelligence Engine</b>
</p>

<p align="center">
  SPECTRE is an intelligent DNS threat detection engine that identifies covert tunneling, anomalous DNS behavior, suspicious query patterns, and potential data exfiltration through real-time traffic analysis, behavioral correlation, and unsupervised machine learning.
</p>

---

## Overview

SPECTRE addresses the challenge of identifying DNS-based threats hidden within legitimate network traffic. Its hybrid detection architecture combines deterministic analysis, statistical baselining, and machine learning to identify suspicious DNS activity and generate explainable risk assessments.

Unlike conventional threshold-based monitoring, SPECTRE evaluates multiple behavioral indicators and correlates them into a unified risk score, helping security analysts distinguish potentially malicious DNS activity from normal network behavior.

### Key Capabilities

- **Real-Time DNS Monitoring** — Captures and analyzes UDP and TCP DNS traffic using Scapy.
- **DNS Tunneling Detection** — Identifies suspicious query lengths, high-entropy labels, encoded patterns, and abnormal subdomain structures.
- **Behavioral Analysis** — Detects unusual query frequencies, unique-subdomain ratios, TXT record concentration, and NXDOMAIN spikes.
- **Statistical Baselining** — Maintains rolling per-host behavioral baselines to identify deviations from normal DNS activity.
- **Machine Learning Detection** — Uses an unsupervised Isolation Forest model to identify anomalous DNS patterns.
- **Explainable Risk Scoring** — Correlates multiple detection signals into a unified 0–100 risk score with supporting evidence.
- **Dynamic Target Scoping** — Supports IP addresses, CIDR networks, hostnames, domains, and URLs.
- **Live Monitoring Dashboard** — Provides real-time event visibility, severity classification, and dynamic target switching.
- **Persistent Event Logging** — Stores detection events in JSON with a dedicated log monitoring utility.

---

## Detection Architecture

SPECTRE implements a layered hybrid detection pipeline designed to identify DNS threats through multiple independent signals.

| Layer | Module | Responsibility |
|---|---|---|
| 01 | Feature Extraction | Extracts lexical, encoding, and behavioral DNS features. |
| 02 | Rule Engine | Applies weighted deterministic detection rules. |
| 03 | Statistical Analysis | Identifies deviations using rolling per-host baselines. |
| 04 | ML Anomaly Detection | Uses Isolation Forest for unsupervised anomaly scoring. |
| 05 | Correlation Engine | Combines detection signals into an explainable risk verdict. |
| 06 | Event Storage | Persists findings and provides historical event access. |

### Risk Classification

| Score | Severity |
|---|---|
| 85–100 | CRITICAL |
| 70–84 | HIGH |
| 50–69 | SUSPICIOUS |
| 25–49 | LOW |
| 0–24 | BENIGN |

---

## Technical Architecture

| Component | Function |
|---|---|
| `main.py` | CLI orchestration, privilege management, and execution control. |
| `collector/` | Asynchronous DNS packet capture using Scapy. |
| `core/` | Configuration, target parsing, and monitoring scope management. |
| `features/` | Lexical, entropy, encoding, and frequency feature extraction. |
| `detection/` | Rule-based analysis, statistical baselines, ML scoring, and correlation. |
| `dashboard/` | Flask-based live monitoring interface and API endpoints. |
| `storage/` | Thread-safe JSON event persistence and retrieval. |
| `Loggings.py` | Standalone detection log monitoring utility. |
| `tests/` | Automated tests for detection logic, target scoping, and collector behavior. |
| `config.yaml` | Detection thresholds and rule-weight configuration. |

---

## Installation & Deployment

### Requirements

- Python 3.9+
- Scapy 2.5+
- Flask 3.0+
- NumPy
- Scikit-learn
- PyYAML
- Colorama
- libpcap (Linux) or Npcap (Windows)

Linux is recommended for packet capture and deployment.

### 1. Clone Repository

```bash
git clone https://github.com/project-hellhound-org/Spectre.git
cd Spectre
```

### 2. Install System Dependencies

**Debian / Kali Linux:**

```bash
sudo apt update
sudo apt install python3 python3-venv python3-pip libpcap-dev
```

### 3. Configure Environment

```bash
python3 -m venv venv
source venv/bin/activate
```

### 4. Install SPECTRE

```bash
pip install -e .
```

This registers the following commands:

- `dnstune` — Main DNS monitoring engine.
- `dnstune-logs` — Standalone detection log viewer.

---

## Operational Usage

### Basic Execution

Start monitoring a specific IP address, network, or domain:

```bash
dnstune 192.168.1.100
```

```bash
dnstune 192.168.1.0/24
```

```bash
dnstune example.com
```

SPECTRE also accepts full URLs and prompts for a target when launched without one.

### Network Interface Selection

Specify the interface used for packet capture:

```bash
dnstune 192.168.1.0/24 --interface eth0
```

### Dashboard Configuration

Launch SPECTRE using a custom dashboard port:

```bash
dnstune 192.168.1.0/24 --port 8080
```

Disable automatic browser launching:

```bash
dnstune 192.168.1.0/24 --no-browser
```

The dashboard is served locally at:

```text
http://127.0.0.1:5000
```

### Interactive Monitoring

SPECTRE provides an interactive console for managing monitoring sessions.

| Command | Description |
|---|---|
| `status` | Displays the current monitoring scope and event statistics. |
| `swap <target>` | Changes the monitoring target without restarting. |
| `swap all` | Removes target restrictions. |
| `logs` | Opens the integrated detection log viewer. |
| `quit` | Terminates the monitoring session. |

Example:

```text
dnstune> status
dnstune> swap 10.0.0.0/24
dnstune> logs
dnstune> quit
```

### Headless Monitoring

Run SPECTRE without the interactive console:

```bash
dnstune 192.168.1.0/24 --no-repl --no-browser
```

For persistent background operation, use `nohup` or the included systemd service template.

---

## Detection Logs & Configuration

### Log Monitoring

Access historical and live detection events:

```bash
dnstune-logs
```

Display the latest 50 events:

```bash
dnstune-logs --no-follow --limit 50
```

Filter high-severity findings:

```bash
dnstune-logs --severity HIGH
```

### Detection Configuration

Customize detection thresholds and scoring weights through `config.yaml`.

```yaml
detection:
  entropy_threshold: 4.2
  max_fqdn_length: 50
  max_label_count: 5
  window_seconds: 300
  qps_threshold: 5.0
  txt_ratio_threshold: 0.5
  nxdomain_ratio_threshold: 0.3
```

SPECTRE supports configurable detection thresholds and weighted rule scoring, allowing monitoring behavior to be adjusted for different network environments.

---

## Testing & Verification

Run the built-in self-test:

```bash
dnstune --self-test
```

Execute the automated test suite:

```bash
pip install -e ".[dev]"
python3 -m pytest tests/ -v
```

Tests cover detection rules, lexical analysis, target parsing, network capture orchestration, and privilege handling.

---

## Use Cases

- **SOC Operations:** Monitor DNS traffic and identify suspicious communication patterns.
- **Threat Hunting:** Investigate potential DNS tunneling and covert communication channels.
- **Data Exfiltration Detection:** Identify unusual DNS query structures and behavioral indicators associated with potential data leakage.
- **Network Security Monitoring:** Establish behavioral baselines and detect anomalous DNS activity.
- **Security Research:** Analyze DNS-based attack techniques in controlled environments.
- **Incident Investigation:** Review historical DNS events and correlate suspicious activity using detection evidence.

---

## Detection Scope & Limitations

- Monitors conventional DNS traffic over UDP and TCP port 53.
- Requires packet capture privileges and a supported packet capture backend.
- Does not directly inspect encrypted DNS protocols such as DNS-over-HTTPS (DoH) or DNS-over-TLS (DoT).
- Machine learning anomaly scoring requires sufficient historical feature data before meaningful model scoring begins.
- Detection results are risk assessments, not definitive proof of malicious activity.
- Domain grouping currently uses a simplified registered-domain heuristic.

---

## Author & Project

<p align="center">
  <img src="https://img.shields.io/badge/Founder-ALPH4_X3-c0392b?style=for-the-badge" alt="ALPH4_X3">
</p>

<p align="center">
  Developed by <b>Project Hellhound</b>
  <br>
  Part of the <a href="https://github.com/project-hellhound-org">Project Hellhound</a> security research ecosystem.
</p>

<p align="center">
  <b>Think Beyond Visibility. Detect Beyond Signatures.</b>
</p>

---

## Legal Disclaimer

SPECTRE is intended for authorized network monitoring, cybersecurity research, and defensive security assessments. Deploy it only on networks and systems you own or have explicit permission to monitor. The developer assumes no responsibility for unauthorized or unlawful use.</p>


