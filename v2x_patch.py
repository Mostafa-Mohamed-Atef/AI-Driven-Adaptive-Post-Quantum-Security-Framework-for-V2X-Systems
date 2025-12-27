import socket
import logging
import sys
import os

print("=== Applying V2X Dashboard Communication Patch ===")

# Get the dashboard IP from environment or use detected one
DASHBOARD_IP = os.environ.get('DASHBOARD_IP', '172.18.0.4')
DASHBOARD_PORT = 5005

print(f"Configuring vehicles to send to dashboard at {DASHBOARD_IP}:{DASHBOARD_PORT}")

# Monkey-patch the Vehicle class's broadcast_message method
try:
    # Import the Vehicle class
    import sys
    sys.path.insert(0, '/app')
    from vehicles.vehicle import Vehicle
    
    # Save the original method
    original_broadcast = Vehicle.broadcast_message
    
    # Create patched version
    def patched_broadcast_message(self, message):
        '''Send to broadcast AND to dashboard'''
        try:
            # Call original broadcast (to 255.255.255.255:5005)
            original_broadcast(self, message)
            
            # Additionally send directly to dashboard
            dashboard_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            dashboard_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            # On Windows, we need to enable broadcast
            if sys.platform == 'win32':
                dashboard_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            
            dashboard_socket.sendto(
                message.encode(),
                (DASHBOARD_IP, DASHBOARD_PORT)
            )
            dashboard_socket.close()
            
            logging.info(f"Vehicle {self.vehicle_id} also sent to dashboard at {DASHBOARD_IP}:{DASHBOARD_PORT}")
            
        except Exception as e:
            logging.error(f"Dashboard send failed: {e}")
            # Still allow original broadcast to continue
    
    # Replace the method
    Vehicle.broadcast_message = patched_broadcast_message
    
    print("✓ Vehicle.broadcast_message successfully patched!")
    
except Exception as e:
    print(f"✗ Patch failed: {e}")
    import traceback
    traceback.print_exc()

print("=== Patch Applied Successfully ===")
print("Vehicles will now send messages to both broadcast AND dashboard")
