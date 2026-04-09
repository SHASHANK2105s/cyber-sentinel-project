"""
CyberSentinel - Threat Monitoring Backend
ML-powered anomaly detection + real-time log analysis
"""

import json
import random
import time
import math
import hashlib
import threading
from datetime import datetime, timedelta
from collections import defaultdict, deque
from flask import Flask, jsonify, Response, request
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

app = Flask(__name__)

# ─────────────────────────────────────────────
# CORS headers (manual, no flask-cors needed)
# ─────────────────────────────────────────────
@app.after_request
def add_cors(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    return response

@app.route("/", defaults={"path": ""}, methods=["OPTIONS"])
@app.route("/<path:path>", methods=["OPTIONS"])
def options_handler(path):
    return jsonify({}), 200

# ─────────────────────────────────────────────
# KNOWN MALICIOUS IP RANGES & SIGNATURES
# ─────────────────────────────────────────────
KNOWN_MALICIOUS_IPS = {
    "185.220.101", "198.54.117", "45.33.32", "91.108.56",
    "162.55.36", "23.129.64", "192.42.116", "171.25.193",
    "5.188.206", "185.107.80",
}

MALWARE_SIGNATURES = [
    {"name": "Mirai Botnet", "pattern": "GET /shell?cd+/tmp", "severity": "critical"},
    {"name": "Log4Shell", "pattern": "${jndi:ldap://", "severity": "critical"},
    {"name": "SQLi Probe", "pattern": "UNION SELECT NULL", "severity": "high"},
    {"name": "XSS Attempt", "pattern": "<script>alert(", "severity": "high"},
    {"name": "Directory Traversal", "pattern": "../../../etc/passwd", "severity": "high"},
    {"name": "Shellshock", "pattern": "() { :; };", "severity": "critical"},
    {"name": "WannaCry", "pattern": "EternalBlue/DOUBLEPULSAR", "severity": "critical"},
    {"name": "Heartbleed", "pattern": "SSL heartbeat overflow", "severity": "high"},
    {"name": "Port Scan", "pattern": "SYN flood detected", "severity": "medium"},
    {"name": "Brute Force", "pattern": "auth failure x50", "severity": "medium"},
]

COUNTRIES = ["CN", "RU", "KP", "IR", "UA", "US", "DE", "BR", "IN", "NG", "TR", "VN"]
COUNTRY_NAMES = {
    "CN": "China", "RU": "Russia", "KP": "North Korea", "IR": "Iran",
    "UA": "Ukraine", "US": "United States", "DE": "Germany", "BR": "Brazil",
    "IN": "India", "NG": "Nigeria", "TR": "Turkey", "VN": "Vietnam"
}

PROTOCOLS = ["HTTP", "HTTPS", "SSH", "FTP", "DNS", "SMTP", "RDP", "SMB"]
ENDPOINTS = [
    "/api/login", "/admin/panel", "/wp-admin", "/.env", "/etc/passwd",
    "/api/users", "/dashboard", "/config.php", "/shell.php", "/upload",
    "/api/data", "/.git/config", "/backup.sql", "/phpinfo.php"
]
METHODS = ["GET", "POST", "PUT", "DELETE", "OPTIONS"]

# ─────────────────────────────────────────────
# THREAT ENGINE STATE
# ─────────────────────────────────────────────
class ThreatEngine:
    def __init__(self):
        self.request_log = deque(maxlen=500)
        self.alerts = deque(maxlen=100)
        self.ip_stats = defaultdict(lambda: {"count": 0, "risk": 0, "country": "UN", "blocked": False})
        self.stats = {
            "total_requests": 0,
            "threats_blocked": 0,
            "active_connections": 0,
            "bandwidth_mbps": 0,
            "anomaly_score": 0,
        }
        self.network_nodes = self._init_network()
        self.feature_buffer = deque(maxlen=200)
        self.model = IsolationForest(contamination=0.1, n_estimators=100, random_state=42)
        self.scaler = StandardScaler()
        self.model_trained = False
        self._seed_model()
        self._lock = threading.Lock()

    def _init_network(self):
        """Build a simulated internal network topology."""
        nodes = [
            {"id": "firewall", "type": "firewall", "label": "Firewall", "x": 50, "y": 50, "status": "active"},
            {"id": "lb1", "type": "loadbalancer", "label": "Load Balancer", "x": 50, "y": 25, "status": "active"},
            {"id": "web1", "type": "server", "label": "Web-01", "x": 30, "y": 10, "status": "active"},
            {"id": "web2", "type": "server", "label": "Web-02", "x": 50, "y": 10, "status": "active"},
            {"id": "web3", "type": "server", "label": "Web-03", "x": 70, "y": 10, "status": "active"},
            {"id": "db1", "type": "database", "label": "DB-Primary", "x": 30, "y": 78, "status": "active"},
            {"id": "db2", "type": "database", "label": "DB-Replica", "x": 70, "y": 78, "status": "active"},
            {"id": "cache", "type": "cache", "label": "Redis Cache", "x": 50, "y": 65, "status": "active"},
            {"id": "auth", "type": "service", "label": "Auth Service", "x": 20, "y": 45, "status": "active"},
            {"id": "api", "type": "service", "label": "API Gateway", "x": 80, "y": 45, "status": "active"},
        ]
        edges = [
            {"from": "firewall", "to": "lb1"},
            {"from": "lb1", "to": "web1"}, {"from": "lb1", "to": "web2"}, {"from": "lb1", "to": "web3"},
            {"from": "web1", "to": "cache"}, {"from": "web2", "to": "cache"}, {"from": "web3", "to": "cache"},
            {"from": "cache", "to": "db1"}, {"from": "cache", "to": "db2"},
            {"from": "web1", "to": "auth"}, {"from": "web2", "to": "api"},
        ]
        return {"nodes": nodes, "edges": edges}

    def _seed_model(self):
        """Pre-train anomaly detector on synthetic normal traffic."""
        normal = np.random.randn(500, 6)
        normal[:, 0] = np.abs(normal[:, 0]) * 100 + 200   # req/min normal
        normal[:, 1] = np.abs(normal[:, 1]) * 10 + 20     # payload size kb
        normal[:, 2] = np.abs(normal[:, 2]) * 5 + 10      # latency ms
        normal[:, 3] = np.random.randint(0, 3, 500).astype(float)  # protocol idx
        normal[:, 4] = np.random.rand(500) * 0.1           # error rate
        normal[:, 5] = np.random.rand(500) * 0.05          # malformed ratio
        self.scaler.fit(normal)
        self.model.fit(self.scaler.transform(normal))
        self.model_trained = True

    def _extract_features(self, req):
        """Extract ML features from a request."""
        return [
            req.get("requests_per_min", 200),
            req.get("payload_kb", 20),
            req.get("latency_ms", 10),
            PROTOCOLS.index(req.get("protocol", "HTTP")) if req.get("protocol", "HTTP") in PROTOCOLS else 0,
            req.get("error_rate", 0.01),
            req.get("malformed_ratio", 0.01),
        ]

    def _compute_risk(self, ip, endpoint, payload, protocol):
        """Compute risk score 0-100 using heuristics + ML."""
        score = 0
        reasons = []

        # IP reputation check
        ip_prefix = ".".join(ip.split(".")[:3])
        if ip_prefix in KNOWN_MALICIOUS_IPS:
            score += 40
            reasons.append("known malicious IP range")

        # Endpoint sensitivity
        sensitive = ["admin", "passwd", "env", "config", "shell", "backup", "phpinfo", "git"]
        for kw in sensitive:
            if kw in endpoint.lower():
                score += 20
                reasons.append(f"sensitive endpoint: {kw}")
                break

        # Malware signature matching
        detected_malware = None
        for sig in MALWARE_SIGNATURES:
            if sig["pattern"].lower() in payload.lower():
                sev_score = {"critical": 50, "high": 35, "medium": 20}.get(sig["severity"], 15)
                score += sev_score
                reasons.append(f"signature: {sig['name']}")
                detected_malware = sig
                break

        # Rate-based scoring
        ip_count = self.ip_stats[ip]["count"]
        if ip_count > 100:
            score += min(25, ip_count // 20)
            reasons.append("high request rate")

        # ML anomaly score
        req_features = {
            "requests_per_min": ip_count * 2,
            "payload_kb": len(payload) / 1024,
            "latency_ms": random.uniform(5, 500),
            "protocol": protocol,
            "error_rate": random.uniform(0, 0.3) if score > 30 else random.uniform(0, 0.05),
            "malformed_ratio": random.uniform(0, 0.2) if score > 40 else 0.01,
        }
        if self.model_trained:
            feat = np.array([self._extract_features(req_features)])
            scaled = self.scaler.transform(feat)
            anomaly = self.model.score_samples(scaled)[0]  # lower = more anomalous
            anomaly_contribution = max(0, int((-anomaly - 0.1) * 30))
            score += anomaly_contribution
            if anomaly_contribution > 10:
                reasons.append("ML anomaly detected")

        return min(100, score), reasons, detected_malware

    def generate_request(self):
        """Simulate an incoming network request with realistic threat distribution."""
        # 85% benign, 15% threat traffic
        is_threat = random.random() < 0.15
        country = random.choice(COUNTRIES)

        if is_threat:
            # Craft a threatening request
            ip_prefix = random.choice(list(KNOWN_MALICIOUS_IPS) + ["10.0.0", "192.168.1"])
            ip = f"{ip_prefix}.{random.randint(1, 254)}"
            sig = random.choice(MALWARE_SIGNATURES[:6])
            payload = f"REQUEST {sig['pattern']} HTTP/1.1"
            endpoint = random.choice([e for e in ENDPOINTS if any(k in e for k in ["admin", "etc", "shell", "env", "php"])])
        else:
            ip = f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
            payload = f"Normal request body {random.randint(100, 9999)}"
            endpoint = random.choice(ENDPOINTS[:5])

        protocol = random.choice(PROTOCOLS)
        method = random.choice(METHODS)
        risk, reasons, malware = self._compute_risk(ip, endpoint, payload, protocol)

        req = {
            "id": hashlib.md5(f"{ip}{time.time()}".encode()).hexdigest()[:8],
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "ip": ip,
            "country": country,
            "country_name": COUNTRY_NAMES.get(country, country),
            "method": method,
            "endpoint": endpoint,
            "protocol": protocol,
            "status_code": random.choice([200, 200, 200, 403, 404, 500]) if not is_threat else random.choice([403, 400, 200]),
            "latency_ms": round(random.uniform(5, 800 if is_threat else 200), 1),
            "payload_size_kb": round(random.uniform(0.1, 50 if is_threat else 10), 2),
            "risk_score": risk,
            "risk_level": "critical" if risk >= 75 else "high" if risk >= 50 else "medium" if risk >= 25 else "low",
            "reasons": reasons,
            "malware_detected": malware["name"] if malware else None,
            "blocked": risk >= 60,
        }

        with self._lock:
            self.ip_stats[ip]["count"] += 1
            self.ip_stats[ip]["risk"] = max(self.ip_stats[ip]["risk"], risk)
            self.ip_stats[ip]["country"] = country
            if req["blocked"]:
                self.ip_stats[ip]["blocked"] = True

            self.stats["total_requests"] += 1
            if req["blocked"]:
                self.stats["threats_blocked"] += 1
            self.stats["active_connections"] = random.randint(40, 180)
            self.stats["bandwidth_mbps"] = round(random.uniform(80, 950), 1)
            self.stats["anomaly_score"] = round(
                (self.stats["threats_blocked"] / max(1, self.stats["total_requests"])) * 100, 1
            )

            self.request_log.appendleft(req)

            # Generate alert for high-risk requests
            if risk >= 60:
                alert = {
                    "id": req["id"],
                    "timestamp": req["timestamp"],
                    "severity": req["risk_level"],
                    "title": f"{malware['name'] if malware else 'Threat'} detected from {ip}",
                    "description": f"Risk score {risk}/100. " + (", ".join(reasons) if reasons else "Anomaly detected."),
                    "ip": ip,
                    "country": country,
                    "blocked": req["blocked"],
                    "acknowledged": False,
                }
                self.alerts.appendleft(alert)

        return req

engine = ThreatEngine()

def background_generator():
    while True:
        # Burst mode: simulate realistic traffic spikes
        rate = random.choices([0.05, 0.15, 0.4], weights=[0.6, 0.3, 0.1])[0]
        engine.generate_request()
        time.sleep(rate)

threading.Thread(target=background_generator, daemon=True).start()

# ─────────────────────────────────────────────
# API ENDPOINTS
# ─────────────────────────────────────────────

@app.route("/api/stats")
def get_stats():
    return jsonify(engine.stats)

@app.route("/api/requests")
def get_requests():
    limit = int(request.args.get("limit", 50))
    with engine._lock:
        logs = list(engine.request_log)[:limit]
    return jsonify(logs)

@app.route("/api/alerts")
def get_alerts():
    with engine._lock:
        alerts = list(engine.alerts)[:30]
    return jsonify(alerts)

@app.route("/api/network")
def get_network():
    # Randomly mark a node as under attack for visual effect
    nodes = [dict(n) for n in engine.network_nodes["nodes"]]
    for n in nodes:
        n["traffic"] = random.randint(10, 100)
        if random.random() < 0.08:
            n["status"] = "warning"
        elif random.random() < 0.03:
            n["status"] = "critical"
        else:
            n["status"] = "active"
    return jsonify({"nodes": nodes, "edges": engine.network_nodes["edges"]})

@app.route("/api/top_ips")
def get_top_ips():
    with engine._lock:
        sorted_ips = sorted(
            [(ip, data) for ip, data in engine.ip_stats.items()],
            key=lambda x: x[1]["risk"],
            reverse=True
        )[:10]
    return jsonify([
        {"ip": ip, **data} for ip, data in sorted_ips
    ])

@app.route("/api/stream")
def stream():
    """SSE stream — push a new event every ~0.5s."""
    def event_generator():
        last_count = 0
        while True:
            with engine._lock:
                current = list(engine.request_log)
            if len(current) > last_count and current:
                event = current[0]
                yield f"data: {json.dumps(event)}\n\n"
                last_count = len(current)
            time.sleep(0.3)
    return Response(event_generator(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

@app.route("/api/block_ip", methods=["POST"])
def block_ip():
    data = request.get_json()
    ip = data.get("ip")
    if ip:
        engine.ip_stats[ip]["blocked"] = True
        return jsonify({"success": True, "message": f"IP {ip} blocked"})
    return jsonify({"success": False}), 400

@app.route("/api/acknowledge_alert", methods=["POST"])
def acknowledge_alert():
    data = request.get_json()
    alert_id = data.get("id")
    with engine._lock:
        for alert in engine.alerts:
            if alert["id"] == alert_id:
                alert["acknowledged"] = True
    return jsonify({"success": True})

@app.route("/api/analyze", methods=["POST"])
def analyze_ip():
    """On-demand IP analysis."""
    data = request.get_json()
    ip = data.get("ip", "")
    prefix = ".".join(ip.split(".")[:3]) if ip else ""
    malicious = prefix in KNOWN_MALICIOUS_IPS
    stats = engine.ip_stats.get(ip, {})
    return jsonify({
        "ip": ip,
        "malicious": malicious,
        "request_count": stats.get("count", 0),
        "max_risk": stats.get("risk", 0),
        "blocked": stats.get("blocked", False),
        "verdict": "MALICIOUS" if malicious else ("SUSPICIOUS" if stats.get("risk", 0) > 40 else "CLEAN"),
    })

if __name__ == "__main__":
    print("🛡️  CyberSentinel backend starting on :5000")
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
