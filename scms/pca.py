#!/usr/bin/env python3
"""
Pseudonym Certificate Authority (PCA) for V2X SCMS
Simulates issuing pseudonym certificates to vehicles
"""

import os
import json
import logging
from flask import Flask, request, jsonify
import requests

app = Flask(__name__)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Configuration
ICA_URL = os.getenv('ICA_URL', 'http://intermediate-ca:5002')

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        "service": "PCA",
        "status": "running",
        "ica_url": ICA_URL
    }), 200

@app.route('/issue_pseudonym_cert', methods=['POST'])
def issue_pseudonym_cert():
    """Issue a pseudonym certificate to a vehicle"""
    try:
        data = request.get_json()
        vehicle_id = data.get('vehicle_id')
        public_key = data.get('public_key')
        
        if not vehicle_id or not public_key:
            return jsonify({"error": "Missing vehicle_id or public_key"}), 400
        
        logger.info(f"Issuing pseudonym certificate for vehicle {vehicle_id}")
        
        # In a real SCMS, PCA would:
        # 1. Verify with ICA
        # 2. Generate pseudonym
        # 3. Issue certificate
        
        # Simulate certificate issuance
        cert_data = {
            "certificate_id": f"pseudonym_cert_{vehicle_id}_{os.urandom(4).hex()}",
            "vehicle_id": vehicle_id,
            "issuer": "PCA",
            "validity_period": "7 days",
            "crypto_algorithm": "ECDSA_P256",
            "status": "issued"
        }
        
        return jsonify(cert_data), 201
        
    except Exception as e:
        logger.error(f"Error issuing certificate: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/revoke_certificate', methods=['POST'])
def revoke_certificate():
    """Revoke a pseudonym certificate"""
    data = request.get_json()
    cert_id = data.get('certificate_id')
    
    if not cert_id:
        return jsonify({"error": "Missing certificate_id"}), 400
    
    logger.warning(f"Revoking certificate: {cert_id}")
    
    # Forward to Misbehavior Authority
    try:
        ma_response = requests.post('http://ma:5004/report_misbehavior', json={
            'certificate_id': cert_id,
            'reason': 'revoked_by_pca'
        }, timeout=5)
    except:
        logger.warning("Could not reach Misbehavior Authority")
    
    return jsonify({
        "certificate_id": cert_id,
        "status": "revoked",
        "timestamp": __import__('datetime').datetime.now().isoformat()
    }), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5005, debug=True)

