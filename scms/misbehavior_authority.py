#!/usr/bin/env python3
"""
Misbehavior Authority (MA) for V2X SCMS
Detects and revokes misbehaving vehicles
"""

import logging
from flask import Flask, request, jsonify

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Simulated Certificate Revocation List (CRL)
crl = []

@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        "service": "Misbehavior Authority",
        "status": "running",
        "revoked_certificates": len(crl)
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
    
    # Add to CRL
    revocation_entry = {
        "certificate_id": certificate_id,
        "vehicle_id": vehicle_id,
        "reason": reason,
        "timestamp": __import__('datetime').datetime.now().isoformat(),
        "revoked_by": "MA"
    }
    
    crl.append(revocation_entry)
    
    logger.warning(f"Revoked certificate {certificate_id} for reason: {reason}")
    
    # Notify PCA and RA
    import requests
    try:
        requests.post("http://pca:5002/revoke_certificate", 
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

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5004, debug=True)
