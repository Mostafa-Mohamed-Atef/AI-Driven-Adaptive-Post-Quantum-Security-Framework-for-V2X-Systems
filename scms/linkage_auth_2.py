#!/usr/bin/env python3
"""
Linkage Authority for V2X SCMS
Prevents tracking of vehicles through encryption
"""

import sys
import logging
from flask import Flask, request, jsonify

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Get LA ID from command line args
la_id = 1
if len(sys.argv) > 2 and sys.argv[1] == '--id':
    la_id = int(sys.argv[2])

PORT = 6001 if la_id == 1 else 6002

@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        "service": f"Linkage Authority {la_id}",
        "status": "running",
        "port": PORT
    }), 200

@app.route('/generate_linkage_seed', methods=['POST'])
def generate_linkage_seed():
    """Generate linkage seed for vehicle batch"""
    data = request.get_json()
    batch_size = data.get('batch_size', 100)
    
    # Simulate linkage seed generation
    import hashlib
    import time
    
    seed = hashlib.sha256(f"la{la_id}_{time.time()}".encode()).hexdigest()[:32]
    
    return jsonify({
        "linkage_authority_id": la_id,
        "linkage_seed": seed,
        "batch_size": batch_size,
        "timestamp": time.time()
    }), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=PORT, debug=True)
