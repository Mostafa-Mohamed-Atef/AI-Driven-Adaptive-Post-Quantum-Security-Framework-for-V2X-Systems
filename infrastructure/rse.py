#!/usr/bin/env python3
"""
Roadside Equipment (RSE) for V2X
Receives and processes V2X messages
"""

import socket
import json
import time
import logging
from datetime import datetime

logging.basicConfig(level=logging.INFO, format='%(asctime)s - RSE - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class RoadsideEquipment:
    def __init__(self, rse_id=1):
        self.rse_id = rse_id
        self.messages_received = 0
        self.udp_port = 5009
        
    def start(self):
        """Start RSE to listen for V2X messages"""
        logger.info(f"Starting RSE-{self.rse_id} on UDP port {self.udp_port}")
        
        # Create UDP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(('0.0.0.0', self.udp_port))
        
        logger.info(f"RSE-{self.rse_id} listening on port {self.udp_port}")
        
        while True:
            try:
                # Receive message
                data, addr = sock.recvfrom(1024)
                self.messages_received += 1
                
                # Parse message
                message = json.loads(data.decode())
                message_type = message.get('type', 'UNKNOWN')
                vehicle_id = message.get('vehicle_id', 'UNKNOWN')
                
                logger.info(f"Received {message_type} from vehicle {vehicle_id} at {addr[0]}")
                
                # Process message (in real system, this would do more)
                self.process_message(message, addr)
                
                # Send acknowledgment to dashboard
                self.send_to_dashboard(message)

                # Forward to IDS for intrusion detection
                self.send_to_ids(message)
                
            except Exception as e:
                logger.error(f"Error processing message: {e}")
    
    def process_message(self, message, source_addr):
        """Process received V2X message"""
        # In a real RSE, this would:
        # 1. Verify message signature
        # 2. Check certificate validity
        # 3. Process safety information
        # 4. Take appropriate action
        
        message_type = message.get('type', 'UNKNOWN')
        
        if message_type == 'CAM':
            # Cooperative Awareness Message
            logger.debug(f"Processing CAM: vehicle {message.get('vehicle_id')}")
        elif message_type == 'DENM':
            # Decentralized Environmental Notification Message
            logger.warning(f"Processing DENM alert: {message.get('message', 'No details')}")
    
    def send_to_dashboard(self, message):
        """Forward message to dashboard"""
        try:
            # Add RSE metadata
            message['processed_by'] = f'RSE-{self.rse_id}'
            message['processed_at'] = datetime.now().isoformat()
            
            # Send to dashboard
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(json.dumps(message).encode(), ('dashboard', 5008))
            sock.close()
        except Exception as e:
            logger.error(f"Failed to send to dashboard: {e}")

    def send_to_ids(self, message):
        """Forward message to IDS service for intrusion detection"""
        try:
            import os
            ids_host = os.environ.get('IDS_HOST', 'ids-service')
            ids_port = int(os.environ.get('IDS_PORT', '5011'))
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(json.dumps(message).encode(), (ids_host, ids_port))
            sock.close()
        except Exception as e:
            logger.debug(f"Failed to send to IDS (non-critical): {e}")

if __name__ == '__main__':
    import sys
    rse_id = 1
    if len(sys.argv) > 2 and sys.argv[1] == '--id':
        rse_id = int(sys.argv[2])
    
    rse = RoadsideEquipment(rse_id)
    rse.start()
