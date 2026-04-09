# CyberSentinel — Threat Monitoring System

A real-time cybersecurity threat monitoring dashboard with ML-powered anomaly detection.

## Quick Start

```bash
chmod +x start.sh
./start.sh
```

Or manually:

```bash
# Terminal 1 — Backend
pip install flask numpy scikit-learn
python3 backend/threat_monitor.py

# Terminal 2 — Frontend
# Open frontend/index.html in your browser
# (or serve it: python3 -m http.server 8080 -d frontend)
```

---

## Architecture

```
┌─────────────────────────────────────────┐
│           Browser (index.html)           │
│   - Network topology canvas             │
│   - Live log stream table               │
│   - Admin alerts panel                  │
│   - Top threat IPs                      │
│   - Risk sparkline chart                │
└───────────────┬─────────────────────────┘
                │ REST + SSE (localhost:5000)
┌───────────────▼─────────────────────────┐
│        Flask Backend (Python)            │
│                                         │
│  ┌──────────────────────────────────┐   │
│  │         ThreatEngine             │   │
│  │  - Request simulator             │   │
│  │  - IP reputation database        │   │
│  │  - Malware signature matching    │   │
│  │  - Risk score calculator         │   │
│  │  - IsolationForest (sklearn)     │   │
│  │  - Alert queue                   │   │
│  └──────────────────────────────────┘   │
└─────────────────────────────────────────┘
```

---

## Backend API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/stats` | System-wide metrics |
| GET | `/api/requests?limit=N` | Recent request log |
| GET | `/api/alerts` | Admin alerts queue |
| GET | `/api/network` | Network topology + node status |
| GET | `/api/top_ips` | Top 10 threat IPs by risk score |
| GET | `/api/stream` | SSE stream of live events |
| POST | `/api/block_ip` | Block an IP address |
| POST | `/api/acknowledge_alert` | Acknowledge an alert |
| POST | `/api/analyze` | On-demand IP analysis |

---

## ML / Detection Engine

### Anomaly Detection
- **Model**: `IsolationForest` (scikit-learn) with 100 estimators, 10% contamination
- **Features**: requests/min, payload size, latency, protocol index, error rate, malformed ratio
- **Pre-trained** on synthetic normal traffic at startup; scores each request in real-time

### Risk Scoring (0–100)
| Factor | Max Points |
|--------|-----------|
| Known malicious IP range | +40 |
| Sensitive endpoint access | +20 |
| Malware signature match | +20–50 |
| High request rate | +25 |
| ML anomaly contribution | +30 |

**Risk levels**: Low (<25) · Medium (25–49) · High (50–74) · Critical (≥75)

### Malware Signatures
- Mirai Botnet, Log4Shell, SQLi, XSS, Directory Traversal
- Shellshock, WannaCry, Heartbleed, Port Scan, Brute Force

---

## Replacing Simulation with Real Traffic

To plug in real network data, replace `generate_request()` in `ThreatEngine` with a live packet capture using **Scapy** or **pyshark**:

```python
from scapy.all import sniff, IP, TCP

def packet_handler(pkt):
    if IP in pkt:
        req = {
            "ip": pkt[IP].src,
            "protocol": "TCP" if TCP in pkt else "UDP",
            "payload_kb": len(pkt) / 1024,
            # ... extract other fields
        }
        risk, reasons, malware = engine._compute_risk(
            req["ip"], "/", str(pkt), req["protocol"]
        )
        # push to engine.request_log ...

sniff(iface="eth0", prn=packet_handler, store=False)
```

---

## File Structure

```
cybersentinel/
├── start.sh              # One-command launcher
├── README.md
├── backend/
│   └── threat_monitor.py # Flask + ML backend
└── frontend/
    └── index.html        # Full dashboard UI
```
