#!/usr/bin/env python3
"""
Misbehavior Authority (MA) for V2X SCMS
Detects and revokes misbehaving vehicles.
Enhanced with IDS integration for AI-driven alert processing.
"""

import logging
from datetime import datetime
from flask import Flask, request, jsonify

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Simulated Certificate Revocation List (CRL)
crl = []

# IDS alert tracking
ids_alerts = []
ids_stats = {
    "total_ids_alerts": 0,
    "auto_revocations": 0,
    "attack_breakdown": {
        "sybil": 0, "false_data_injection": 0,
        "replay": 0, "dos": 0, "anomaly": 0,
        "revoked_certificate": 0,
    },
}

@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        "service": "Misbehavior Authority",
        "status": "running",
        "revoked_certificates": len(crl),
        "ids_alerts_received": ids_stats["total_ids_alerts"],
    }), 200

@app.route('/report_misbehavior', methods=['POST'])
def report_misbehavior():
    """Report vehicle misbehavior"""
    data = request.get_json()
    certificate_id = data.get('certificate_id')
    vehicle_id = data.get('vehicle_id')
    reason = data.get('reason', 'unspecified')
    
    if not certificate_id:
        return jsonify({"error": "Missing certificate_id"}), 400
    
    # Check if already revoked
    if any(e["certificate_id"] == certificate_id for e in crl):
        return jsonify({
            "status": "already_revoked",
            "certificate_id": certificate_id,
        }), 200

    # Add to CRL
    revocation_entry = {
        "certificate_id": certificate_id,
        "vehicle_id": vehicle_id,
        "reason": reason,
        "timestamp": datetime.now().isoformat(),
        "revoked_by": "MA"
    }
    
    crl.append(revocation_entry)
    
    logger.warning(f"Revoked certificate {certificate_id} for reason: {reason}")
    
    # Notify PCA and RA
    import requests
    try:
        requests.post("http://pca:5005/revoke_certificate", 
                     json={"certificate_id": certificate_id}, timeout=2)
    except:
        pass
    
    return jsonify({
        "status": "revoked",
        "certificate_id": certificate_id,
        "crl_entry": revocation_entry
    }), 200

@app.route('/crl', methods=['GET'])
def get_crl():
    """Get Certificate Revocation List"""
    return jsonify({
        "count": len(crl),
        "crl": crl
    }), 200

@app.route('/ids_alert', methods=['POST'])
def receive_ids_alert():
    """
    Receive an alert from the IDS service.
    Critical/high-severity alerts trigger automatic certificate revocation.
    """
    alert = request.get_json()
    ids_alerts.append(alert)
    ids_stats["total_ids_alerts"] += 1

    attack_type = alert.get("attack_type", "unknown")
    if attack_type in ids_stats["attack_breakdown"]:
        ids_stats["attack_breakdown"][attack_type] += 1

    severity = alert.get("severity", "low")
    vehicle_id = alert.get("vehicle_id", "unknown")

    logger.info(
        "IDS ALERT [%s] %s — vehicle: %s — %s",
        severity.upper(), attack_type, vehicle_id,
        alert.get("description", "")[:80],
    )

    # Auto-revoke on critical severity
    if severity == "critical":
        cert_id = f"cert_{vehicle_id}"
        if not any(e["certificate_id"] == cert_id for e in crl):
            crl.append({
                "certificate_id": cert_id,
                "vehicle_id": vehicle_id,
                "reason": f"IDS auto-revocation: {attack_type}",
                "timestamp": datetime.now().isoformat(),
                "revoked_by": "MA-IDS",
            })
            ids_stats["auto_revocations"] += 1
            logger.warning(
                "AUTO-REVOKED certificate %s due to IDS %s alert",
                cert_id, attack_type,
            )

    return jsonify({"status": "received", "alert_id": ids_stats["total_ids_alerts"]}), 200

@app.route('/ids_stats', methods=['GET'])
def get_ids_stats():
    """Return IDS-related statistics."""
    return jsonify(ids_stats), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5004, debug=True)

