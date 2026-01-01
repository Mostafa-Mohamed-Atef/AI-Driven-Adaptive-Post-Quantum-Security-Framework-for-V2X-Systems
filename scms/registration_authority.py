#!/usr/bin/env python3
"""
Registration Authority (RA) for V2X SCMS
Registers vehicles and manages enrollment
"""

import logging
from flask import Flask, request, jsonify
import requests

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Simulated vehicle database
vehicles_db = {}

@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        "service": "Registration Authority",
        "status": "running",
        "registered_vehicles": len(vehicles_db)
    }), 200

@app.route('/register_vehicle', methods=['POST'])
def register_vehicle():
    """Register a new vehicle"""
    data = request.get_json()
    vehicle_id = data.get('vehicle_id')
    public_key = data.get('public_key')
    vehicle_type = data.get('vehicle_type', 'car')
    
    if not vehicle_id or not public_key:
        return jsonify({"error": "Missing vehicle_id or public_key"}), 400
    
    # Check with PCA and Linkage Authorities
    try:
        # Verify with PCA
        pca_response = requests.get("http://pca:5002/health", timeout=3)
        if pca_response.status_code != 200:
            return jsonify({"error": "PCA unavailable"}), 503
        
        # Get linkage seeds
        la1_response = requests.post("http://linkage-auth-1:6001/generate_linkage_seed", 
                                    json={"batch_size": 10}, timeout=3)
        la2_response = requests.post("http://linkage-auth-2:6002/generate_linkage_seed", 
                                    json={"batch_size": 10}, timeout=3)
        
    except requests.RequestException as e:
        logger.warning(f"Could not connect to SCMS components: {e}")
    
    # Register vehicle
    vehicles_db[vehicle_id] = {
        "public_key": public_key,
        "vehicle_type": vehicle_type,
        "status": "registered",
        "registration_date": __import__('datetime').datetime.now().isoformat()
    }
    
    logger.info(f"Registered vehicle {vehicle_id}")
    
    return jsonify({
        "vehicle_id": vehicle_id,
        "status": "registered",
        "message": "Vehicle registered successfully"
    }), 201

@app.route('/vehicles', methods=['GET'])
def list_vehicles():
    """List all registered vehicles"""
    return jsonify({
        "count": len(vehicles_db),
        "vehicles": list(vehicles_db.keys())
    }), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5003, debug=True)
