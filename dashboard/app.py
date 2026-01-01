from flask import Flask, jsonify
import threading
import socket
import json
from datetime import datetime
import time

app = Flask(__name__)

# Store messages
messages = []
MAX_MESSAGES = 100

print("=== V2X Dashboard Starting ===")

def udp_listener():
    """Listen for V2X messages on UDP port 5008"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind(('0.0.0.0', 5008))
        print(f"[{datetime.now().strftime('%H:%M:%S')}] ✓ UDP listener started on port 5008")
        
        while True:
            data, addr = sock.recvfrom(1024)
            try:
                msg = json.loads(data.decode())
                msg['received_at'] = datetime.now().strftime('%H:%M:%S')
                msg['source_ip'] = addr[0]
                
                messages.append(msg)
                if len(messages) > MAX_MESSAGES:
                    messages.pop(0)
                
                print(f"[{msg['received_at']}] Received: {msg.get('type', 'UNKNOWN')} from vehicle {msg.get('vehicle_id', 'unknown')}")
                
            except json.JSONDecodeError:
                print(f"[{datetime.now().strftime('%H:%M:%S')}] ✗ Invalid JSON from {addr[0]}")
            except Exception as e:
                print(f"[{datetime.now().strftime('%H:%M:%S')}] ✗ Error processing: {e}")
                
    except Exception as e:
        print(f"[{datetime.now().strftime('%H:%M:%S')}] ✗ UDP listener failed: {e}")
        import traceback
        traceback.print_exc()

@app.route('/')
def index():
    return jsonify({
        "service": "V2X Security Dashboard",
        "status": "running",
        "udp_port": 5008,
        "messages_received": len(messages),
        "endpoints": ["/", "/health", "/messages", "/clear", "/stats"]
    })

@app.route('/health')
def health():
    return jsonify({"status": "healthy", "timestamp": datetime.now().isoformat()})

@app.route('/messages')
def get_messages():
    return jsonify({
        "count": len(messages),
        "messages": messages[-20:]  # Last 20 messages
    })

@app.route('/clear')
def clear_messages():
    messages.clear()
    return jsonify({"status": "cleared", "count": 0})

@app.route('/stats')
def stats():
    cam_count = sum(1 for m in messages if m.get('type') == 'CAM')
    denm_count = sum(1 for m in messages if m.get('type') == 'DENM')
    classical_count = sum(1 for m in messages if m.get('crypto') == 'classical')
    pqc_count = sum(1 for m in messages if m.get('crypto') == 'post_quantum')
    
    return jsonify({
        "total_messages": len(messages),
        "cam_messages": cam_count,
        "denm_messages": denm_count,
        "classical_crypto": classical_count,
        "post_quantum_crypto": pqc_count
    })

if __name__ == '__main__':
    # Start UDP listener in background thread
    udp_thread = threading.Thread(target=udp_listener, daemon=True)
    udp_thread.start()
    print(f"[{datetime.now().strftime('%H:%M:%S')}] UDP listener thread started")
    
    # Give UDP thread a moment to start
    time.sleep(1)
    
    print(f"[{datetime.now().strftime('%H:%M:%S')}] Starting Flask server on port 8000")
    app.run(host='0.0.0.0', port=8000, debug=False, use_reloader=False)
