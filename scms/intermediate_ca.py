#!/usr/bin/env python3
"""
Intermediate Certificate Authority (ICA) for V2X SCMS
Issues certificates to PCAs
"""

import logging
from flask import Flask, request, jsonify
import requests

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

ROOT_CA_URL = "http://root-ca:5001"

@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        "service": "Intermediate CA",
        "status": "running",
        "root_ca": ROOT_CA_URL
    }), 200

@app.route('/issue_certificate', methods=['POST'])
def issue_certificate():
    """Issue certificate to a PCA"""
    try:
        data = request.get_json()
        pca_id = data.get('pca_id')
        
        # Verify with Root CA
        try:
            root_response = requests.get(f"{ROOT_CA_URL}/health", timeout=5)
            if root_response.status_code != 200:
                return jsonify({"error": "Root CA unavailable"}), 503
        except:
            return jsonify({"error": "Cannot connect to Root CA"}), 503
        
        # Issue certificate
        cert = {
            "certificate_id": f"ica_cert_{pca_id}",
            "issuer": "Intermediate CA",
            "subject": f"PCA-{pca_id}",
            "validity": "1 year",
            "status": "issued"
        }
        
        logger.info(f"Issued certificate to PCA-{pca_id}")
        return jsonify(cert), 201
        
    except Exception as e:
        logger.error(f"Error: {e}")
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5002, debug=True)
