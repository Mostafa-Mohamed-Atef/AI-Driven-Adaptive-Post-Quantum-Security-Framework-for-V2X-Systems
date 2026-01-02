import json
import logging
import time
import hashlib
import argparse
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.x509.oid import NameOID
import datetime
import requests
import socket
import threading
import base64
import os
import sys

# Windows socket compatibility
if sys.platform == "win32":
    import socket
    BROADCAST_ADDR = "255.255.255.255"
else:
    BROADCAST_ADDR = "<broadcast>"

class Vehicle:
    def __init__(self, vehicle_id, ra_url="http://localhost:5003"):
        self.vehicle_id = vehicle_id
        self.ra_url = ra_url
        
        # Classical Crypto for CAM (ECDSA)
        self.cam_private_key = ec.generate_private_key(ec.SECP256R1())
        
        # PQC simulation for DENM
        self.pqc_public_key = b"PQC-SIM-PUBLIC-KEY"
        
        # Windows-specific initialization
        self.setup_windows_sockets()
        
        logging.info(f"Vehicle {vehicle_id} initialized on {sys.platform}")
    
    def setup_windows_sockets(self):
        """Setup sockets for Windows"""
        try:
            self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            
            # Windows-specific socket options
            if sys.platform == "win32":
                self.udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            self.broadcast_port = 5005
            self.listening = False
            
        except Exception as e:
            logging.error(f"Socket setup failed: {e}")
    
    def generate_cam(self):
        """Generate CAM with Classical Crypto"""
        cam_data = {
            'message_type': 'CAM',
            'vehicle_id': self.vehicle_id,
            'timestamp': time.time(),
            'position': [42.3314, -83.0458],
            'speed': 60.5,
            'heading': 90.0,
            'acceleration': 0.0,
            'crypto_type': 'ECDSA-P256-SHA256'
        }
        
        # Simulate ECDSA signature
        signature = hashlib.sha256(json.dumps(cam_data).encode()).hexdigest()
        
        return json.dumps({
            'data': cam_data,
            'signature': signature,
            'crypto': 'classical'
        })
    
    def generate_denm(self, event_type="accident", severity=3):
        """Generate DENM with PQC simulation"""
        denm_data = {
            'message_type': 'DENM',
            'vehicle_id': self.vehicle_id,
            'event_type': event_type,
            'severity': severity,
            'position': [42.3314, -83.0458],
            'timestamp': time.time(),
            'validity': time.time() + 300,
            'crypto_type': 'PQC-SIMULATION'
        }
        
        # Simulate PQC signature
        pqc_signature = hashlib.sha512(json.dumps(denm_data).encode()).hexdigest()
        
        return json.dumps({
            'data': denm_data,
            'signature': pqc_signature,
            'crypto': 'pqc',
            'pqc_algorithm': 'CRYSTALS-DILITHIUM2-SIM'
        })
    
    def broadcast_message(self, message):
        """Broadcast message (Windows compatible) AND send to dashboard"""
        try:
            # Original broadcast
            self.udp_socket.sendto(
                message.encode(),
                (BROADCAST_ADDR, self.broadcast_port)
            )
            
            # NEW: Also send to dashboard
            import socket
            dashboard_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            dashboard_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if sys.platform == 'win32':
                dashboard_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            
            # Use environment-configurable dashboard host/port so Docker service name works
            dashboard_host = os.environ.get('DASHBOARD_HOST', 'dashboard')
            dashboard_port = int(os.environ.get('DASHBOARD_PORT', '5008'))

            dashboard_socket.sendto(
                message.encode(),
                (dashboard_host, dashboard_port)
            )
            dashboard_socket.close()

            logging.info(f"Vehicle {self.vehicle_id} broadcast to dashboard {dashboard_host}:{dashboard_port}: {message[:50]}...")
        except Exception as e:
            logging.error(f"Broadcast error: {e}")
    def start_listening(self):
        """Start listening thread"""
        self.listening = True
        thread = threading.Thread(target=self.listen_thread)
        thread.daemon = True
        thread.start()
    
    def listen_thread(self):
        """Listening thread for Windows"""
        listen_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        listen_socket.bind(('0.0.0.0', self.broadcast_port))
        listen_socket.settimeout(1.0)
        
        while self.listening:
            try:
                data, addr = listen_socket.recvfrom(65535)
                message = data.decode()
                logging.info(f"Vehicle {self.vehicle_id} received from {addr}: {message[:50]}...")
            except socket.timeout:
                continue
            except Exception as e:
                logging.error(f"Listen error: {e}")
        
        listen_socket.close()

def main():
    parser = argparse.ArgumentParser(description='V2X Vehicle Node (Windows)')
    parser.add_argument('--id', type=int, required=True, help='Vehicle ID')
    parser.add_argument('--ra-url', default='http://localhost:5003', help='Registration Authority URL')
    args = parser.parse_args()
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(f'vehicle_{args.id}.log'),
            logging.StreamHandler()
        ]
    )
    
    vehicle = Vehicle(args.id, args.ra_url)
    vehicle.start_listening()
    
    # Simulation loop
    try:
        count = 0
        while True:
            # Send CAM every 2 seconds
            if count % 2 == 0:
                cam = vehicle.generate_cam()
                vehicle.broadcast_message(cam)
            
            # Send DENM every 10 seconds
            if count % 10 == 0:
                denm = vehicle.generate_denm()
                vehicle.broadcast_message(denm)
            
            time.sleep(1)
            count += 1
            
    except KeyboardInterrupt:
        vehicle.listening = False
        logging.info("Vehicle stopped")

if __name__ == '__main__':
    main()
