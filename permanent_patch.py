import sys
import os

# Dashboard IP (from earlier detection)
DASHBOARD_IP = "172.18.0.4"
DASHBOARD_PORT = 5005

print(f"Permanently patching vehicle.py to send to {DASHBOARD_IP}:{DASHBOARD_PORT}")

# Read the vehicle.py file
vehicle_path = "/app/vehicles/vehicle.py"
with open(vehicle_path, 'r') as f:
    content = f.read()

# Find the broadcast_message method
import re

# Look for the broadcast_message method definition
method_pattern = r'def broadcast_message\(self, message\):(.*?)(?=\n    def|\nclass|\Z)'
method_match = re.search(method_pattern, content, re.DOTALL)

if method_match:
    original_method = method_match.group(0)
    method_body = method_match.group(1)
    
    # Create patched method
    patched_method = '''def broadcast_message(self, message):
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
            
            dashboard_socket.sendto(
                message.encode(),
                ('172.18.0.4', 5005)  # Dashboard IP and port
            )
            dashboard_socket.close()
            
            logging.info(f"Vehicle {self.vehicle_id} broadcast: {message[:50]}...")
        except Exception as e:
            logging.error(f"Broadcast error: {e}")'''
    
    # Replace the method
    content = content.replace(original_method, patched_method)
    
    # Write back
    with open(vehicle_path, 'w') as f:
        f.write(content)
    
    print("✓ Successfully patched vehicle.py")
    print("✓ Vehicles will now send to dashboard on every broadcast")
else:
    print("✗ Could not find broadcast_message method")
