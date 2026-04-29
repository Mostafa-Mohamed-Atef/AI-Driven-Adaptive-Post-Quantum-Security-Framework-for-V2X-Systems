from flask import Flask, jsonify, send_from_directory
import threading
import socket
import json
from datetime import datetime, timedelta
import time
import random

app = Flask(__name__)

# Store messages
messages = []
MAX_MESSAGES = 100
START_TIME = datetime.now()

# Activity tracking
misbehavior_reports = []
activity_log = []

# Service URLs (for Docker)
IDS_URL = "http://ids-service:5010"
MA_URL = "http://ma:5004"
RA_URL = "http://ra:5003"
PCA_URL = "http://pca:5005"

# Initialize some mock data
def init_mock_data():
    global misbehavior_reports, activity_log
    
    # Mock Misbehavior Reports
    types = ["Invalid signature detected", "Suspicious message pattern", "Certificate revocation attempt", "Anomaly in location data", "Timestamp mismatch"]
    severities = ["Critical", "Medium", "Critical", "Low", "Medium"]
    for i in range(5):
        misbehavior_reports.append({
            "id": i,
            "title": types[i],
            "vehicle_id": f"Vehicle-{random.randint(1000, 9999)}",
            "severity": severities[i],
            "time": f"{random.randint(5, 60)} min ago"
        })

    # Mock Activity Log
    actions = ["Certificate issued to", "Vehicle connected to network", "PQC certificate generated", "Certificate renewal reminder sent", "Security scan completed", "CRL updated successfully"]
    icons = ["check-circle", "car", "key", "exclamation-circle", "shield-alt", "sync"]
    colors = ["text-green-500", "text-blue-500", "text-purple-500", "text-yellow-500", "text-green-500", "text-blue-500"]
    
    for i in range(6):
        idx = i % len(actions)
        vid = f"Vehicle-{random.randint(1000, 9999)}" if "Vehicle" in actions[idx] or "Certificate" in actions[idx] else ""
        activity_log.append({
            "id": i,
            "text": f"{actions[idx]} {vid}".strip(),
            "time": f"{random.randint(2, 60)} {'seconds' if i < 3 else 'minutes'} ago",
            "icon": icons[idx],
            "color": colors[idx]
        })

init_mock_data()

def udp_listener():
    """Listen for V2X messages on UDP port 5008"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind(('0.0.0.0', 5008))
        print(f"[{datetime.now().strftime('%H:%M:%S')}] ✓ UDP listener started on port 5008")
        
        while True:
            data, addr = sock.recvfrom(1024)
            try:
                msg = json.loads(data.decode())

                # Normalize payloads that wrap the real fields under a `data` key.
                # Vehicles send {'data': {...}, 'signature': ..., 'crypto': ...}
                if isinstance(msg, dict) and 'data' in msg and isinstance(msg['data'], dict):
                    payload = msg['data']
                    # populate flat fields expected by the dashboard/UI
                    msg.setdefault('type', payload.get('message_type') or payload.get('type'))
                    msg.setdefault('vehicle_id', payload.get('vehicle_id') or payload.get('vehicle'))

                msg['received_at'] = datetime.now().strftime('%H:%M:%S')
                msg['source_ip'] = addr[0]

                messages.append(msg)
                if len(messages) > MAX_MESSAGES:
                    messages.pop(0)
                
                print(f"[{msg['received_at']}] Received: {msg.get('type', 'UNKNOWN')} from vehicle {msg.get('vehicle_id', 'unknown')}")
                
            except json.JSONDecodeError:
                print(f"[{datetime.now().strftime('%H:%M:%S')}] ✗ Invalid JSON from {addr[0]}")
            except Exception as e:
                print(f"[{datetime.now().strftime('%H:%M:%S')}] ✗ Error processing: {e}")
                
    except Exception as e:
        print(f"[{datetime.now().strftime('%H:%M:%S')}] ✗ UDP listener failed: {e}")
        import traceback
        traceback.print_exc()

@app.route('/')
def index():
    # Serve the static single-page dashboard
    try:
        return send_from_directory('static', 'index.html')
    except Exception:
        return jsonify({
            "service": "V2X Security Dashboard",
            "status": "running",
            "udp_port": 5008,
            "messages_received": len(messages),
            "endpoints": ["/", "/health", "/messages", "/clear", "/stats"]
        })


@app.route('/status')
def status():
    return jsonify({
        "service": "V2X Security Dashboard",
        "status": "running",
        "udp_port": 5008,
        "messages_received": len(messages),
        "endpoints": ["/status", "/health", "/messages", "/clear", "/stats"]
    })

@app.route('/health')
def health():
    return jsonify({"status": "healthy", "timestamp": datetime.now().isoformat()})

@app.route('/messages')
def get_messages():
    return jsonify({
        "count": len(messages),
        "messages": messages[-20:]  # Last 20 messages
    })

@app.route('/clear')
def clear_messages():
    messages.clear()
    return jsonify({"status": "cleared", "count": 0})

@app.route('/stats')
def stats():
    cam_count = sum(1 for m in messages if m.get('type') == 'CAM')
    denm_count = sum(1 for m in messages if m.get('type') == 'DENM')
    classical_count = sum(1 for m in messages if m.get('crypto') == 'classical')
    pqc_count = sum(1 for m in messages if m.get('crypto') == 'post_quantum')
    
    return jsonify({
        "total_messages": len(messages),
        "cam_messages": cam_count,
        "denm_messages": denm_count,
        "classical_crypto": classical_count,
        "post_quantum_crypto": pqc_count
    })

# --- New API Endpoints for Enhanced Dashboard ---

@app.route('/api/overview')
def api_overview():
    # Calculate uptime
    uptime_seconds = (datetime.now() - START_TIME).total_seconds()
    uptime_str = f"{int(uptime_seconds // 3600)}h {int((uptime_seconds % 3600) // 60)}m"

    # Active vehicles (unique IDs in last 100 messages)
    active_vehicles = len(set(m.get('vehicle_id') for m in messages if m.get('vehicle_id')))
    
    # Try to get real stats from SCMS
    certs_issued = 0
    pending_reports = 0
    try:
        import requests as req
        # Proxying some real counts if services are up
        ma_health = req.get(f"{MA_URL}/health", timeout=1).json()
        certs_issued = ma_health.get("revoked_certificates", 0) + 120 # Mock base + real revoked
        pending_reports = ma_health.get("ids_alerts_received", 0)
    except:
        certs_issued = 45234 + len(messages)
        pending_reports = len(misbehavior_reports)

    return jsonify({
        "active_vehicles": active_vehicles if active_vehicles > 0 else random.randint(5, 12),
        "certificates_issued": certs_issued,
        "pending_reports": pending_reports,
        "system_uptime": "99.9%"
    })

@app.route('/api/components')
def api_components():
    # Return status of components. In a real system, these would check actual services.
    # Here we mock them to match screenshots.
    components = [
        {"name": "CA Server", "status": "Operational", "icon": "server", "color": "green"},
        {"name": "RA Server", "status": "Operational", "icon": "check-circle", "color": "green"},
        {"name": "OCSP Service", "status": "Operational", "icon": "check-circle", "color": "green"},
        {"name": "CRL Service", "status": "High Load", "icon": "exclamation-triangle", "color": "yellow"}, # Example variation
        {"name": "HSM", "status": "Operational", "icon": "lock", "color": "green"},
        {"name": "Database", "status": "Operational", "icon": "database", "color": "green"},
        {"name": "API Gateway", "status": "Operational", "icon": "cloud", "color": "green"},
        {"name": "Load Balancer", "status": "Operational", "icon": "network-wired", "color": "green"},
        {"name": "Message Queue", "status": "Operational", "icon": "layer-group", "color": "green"},
        {"name": "Auth Service", "status": "Operational", "icon": "key", "color": "green"},
        {"name": "Logging Service", "status": "Operational", "icon": "file-alt", "color": "green"},
        {"name": "Monitoring", "status": "Operational", "icon": "chart-line", "color": "green"},
        {"name": "Backup Service", "status": "Operational", "icon": "cloud-upload-alt", "color": "green"},
    ]
    return jsonify(components)

@app.route('/api/charts/distribution')
def api_chart_distribution():
    # Calculate real distribution from messages if available, else mock
    classical_count = sum(1 for m in messages if m.get('crypto') == 'classical')
    pqc_count = sum(1 for m in messages if m.get('crypto') == 'post_quantum')
    total = classical_count + pqc_count
    
    if total == 0:
        # Default mock values from screenshot
        return jsonify([
            {"label": "Classical (ECDSA)", "value": 71.1, "color": "#7c3aed"},
            {"label": "PQC (Dilithium)", "value": 28.9, "color": "#ec4899"}
        ])
    
    return jsonify([
        {"label": "Classical (ECDSA)", "value": round(classical_count/total * 100, 1), "color": "#7c3aed"},
        {"label": "PQC (Dilithium)", "value": round(pqc_count/total * 100, 1), "color": "#ec4899"}
    ])

@app.route('/api/charts/provisioning')
def api_chart_provisioning():
    # Mock data for the line chart
    days = ["Jan 18", "Jan 19", "Jan 20", "Jan 21", "Jan 22", "Jan 23", "Jan 24"]
    ecdsa_data = [1800, 1950, 2100, 2050, 2200, 2350, 2400]
    dilithium_data = [450, 500, 550, 600, 650, 700, 750]
    return jsonify({
        "labels": days,
        "datasets": [
            {"label": "ECDSA", "data": ecdsa_data, "borderColor": "#7c3aed"},
            {"label": "Dilithium", "data": dilithium_data, "borderColor": "#ec4899"}
        ]
    })

@app.route('/api/activity')
def api_activity():
    # Combine real recent messages with mock activity
    # We'll take the global mock activity_log and prepend any new real messages
    
    real_activity = []
    for m in messages[-5:]: # Last 5 real messages
        real_activity.append({
            "text": f"Received {m.get('type')} from {m.get('vehicle_id')}",
            "time": "Just now",
            "icon": "satellite-dish",
            "color": "text-blue-400"
        })
    
    # Return mix
    return jsonify(real_activity + activity_log)

@app.route('/api/misbehavior')
def api_misbehavior():
    return jsonify(misbehavior_reports)

@app.route('/api/fleet')
def api_fleet():
    # Mock fleet status
    fleet = [
        {"id": "VH-2341", "status": "Online", "time": "45 min", "color": "green"},
        {"id": "VH-4829", "status": "Online", "time": "12 min", "color": "green"},
        {"id": "VH-7823", "status": "Offline", "time": "2 hrs", "color": "red"},
        {"id": "VH-9102", "status": "Online", "time": "8 min", "color": "green"},
        {"id": "VH-5634", "status": "Online", "time": "23 min", "color": "green"},
        {"id": "VH-3421", "status": "Warning", "time": "5 min", "color": "yellow"},
        {"id": "VH-1298", "status": "Online", "time": "34 min", "color": "green"},
        {"id": "VH-6745", "status": "Online", "time": "17 min", "color": "green"},
    ]
    return jsonify(fleet)

# --- IDS Integration Endpoints ---

IDS_URL = "http://ids-service:5010"

@app.route('/api/ids/stats')
def ids_stats_proxy():
    """Proxy IDS stats to the dashboard frontend."""
    try:
        import requests as req
        resp = req.get(f"{IDS_URL}/api/ids/stats", timeout=3)
        return jsonify(resp.json()), resp.status_code
    except Exception:
        return jsonify({
            "messages_processed": 0,
            "alerts_generated": 0,
            "attacks_detected": {"sybil": 0, "fdi": 0, "replay": 0, "dos": 0},
            "avg_latency_ms": 0,
            "models_trained": False,
            "status": "ids_unreachable"
        })

@app.route('/api/ids/alerts')
def ids_alerts_proxy():
    """Proxy IDS alerts to the dashboard frontend."""
    try:
        import requests as req
        resp = req.get(f"{IDS_URL}/api/ids/alerts", timeout=3)
        return jsonify(resp.json()), resp.status_code
    except Exception:
        return jsonify({"count": 0, "alerts": []})

@app.route('/api/ids/metrics')
def ids_metrics_proxy():
    """Proxy IDS model metrics to the dashboard frontend."""
    try:
        import requests as req
        resp = req.get(f"{IDS_URL}/api/ids/metrics", timeout=3)
        return jsonify(resp.json()), resp.status_code
    except Exception:
        return jsonify({"evaluator_history": [], "training_results": {}})

@app.route('/api/ids/sybil/summary')
def ids_sybil_proxy():
    """Proxy Sybil detector summary."""
    try:
        import requests as req
        resp = req.get(f"{IDS_URL}/api/ids/sybil/summary", timeout=3)
        return jsonify(resp.json()), resp.status_code
    except Exception:
        return jsonify({"window_size": 0, "flagged_groups": 0, "active_vehicles": 0})

@app.route('/api/ids/train', methods=['POST'])
def ids_train_proxy():
    """Trigger IDS model training."""
    try:
        import requests as req
        resp = req.post(f"{IDS_URL}/api/ids/train", timeout=5)
        return jsonify(resp.json()), resp.status_code
    except Exception:
        return jsonify({"error": "IDS service unreachable"}), 503

if __name__ == '__main__':
    # Start UDP listener in background thread
    udp_thread = threading.Thread(target=udp_listener, daemon=True)
    udp_thread.start()
    print(f"[{datetime.now().strftime('%H:%M:%S')}] UDP listener thread started")
    
    # Give UDP thread a moment to start
    time.sleep(1)
    
    print(f"[{datetime.now().strftime('%H:%M:%S')}] Starting Flask server on port 8000")
    app.run(host='0.0.0.0', port=8000, debug=False, use_reloader=False)
