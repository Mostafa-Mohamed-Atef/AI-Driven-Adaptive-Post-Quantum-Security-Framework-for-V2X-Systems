from flask import Flask, render_template_string, jsonify
import json
import threading
import socket
import time

app = Flask(__name__)

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>V2X Security Architecture Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .container { display: flex; gap: 20px; }
        .panel { flex: 1; border: 1px solid #ccc; padding: 15px; border-radius: 5px; }
        .crypto { background: #e3f2fd; }
        .messages { background: #f3e5f5; }
        .nodes { background: #e8f5e8; }
        .message { padding: 5px; margin: 5px 0; border-left: 3px solid; }
        .cam { border-color: #2196f3; }
        .denm { border-color: #f44336; }
        h3 { color: #333; border-bottom: 2px solid; padding-bottom: 5px; }
    </style>
</head>
<body>
    <h1>V2X Security Architecture Dashboard</h1>
    <p><strong>Platform:</strong> {{ platform }} | <strong>CAM Crypto:</strong> ECDSA | <strong>DENM Crypto:</strong> PQC Simulation</p>

    <div class="container">
        <div class="panel crypto">
            <h3>Cryptography Status</h3>
            <p><strong>Classical (CAM):</strong> ECDSA P-256 SHA256</p>
            <p><strong>Post-Quantum (DENM):</strong> CRYSTALS-Dilithium2 Simulation</p>
            <p><strong>SCMS Status:</strong> {{ scms_status }}</p>
        </div>

        <div class="panel messages">
            <h3>Recent Messages</h3>
            {% for msg in messages[-10:] %}
            <div class="message {{ msg.type }}">
                [{{ msg.time }}] {{ msg.type }}: {{ msg.content|truncate(50) }}
            </div>
            {% endfor %}
        </div>

        <div class="panel nodes">
            <h3>Active Nodes</h3>
            {% for node in nodes %}
            <p>{{ node.name }}: {{ node.status }}</p>
            {% endfor %}
        </div>
    </div>

    <script>
        setTimeout(() => location.reload(), 3000);
    </script>
</body>
</html>
"""

messages = []
nodes = []

@app.route('/')
def dashboard():
    return render_template_string(HTML_TEMPLATE,
        platform="Windows",
        scms_status="Active",
        messages=messages[-10:],
        nodes=nodes)

@app.route('/api/messages')
def get_messages():
    return jsonify(messages[-20:])

@app.route('/api/nodes')
def get_nodes():
    return jsonify(nodes)

def message_listener():
    """Listen for V2X messages on port 5008"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('0.0.0.0', 5008))  # USING PORT 5008
    sock.settimeout(1.0)

    print(f"Dashboard listening on port 5008...")

    while True:
        try:
            data, addr = sock.recvfrom(65535)
            msg = json.loads(data.decode())

            msg_type = "CAM" if msg.get('crypto') == 'classical' else "DENM"

            messages.append({
                'type': msg_type.lower(),
                'content': str(msg),
                'time': time.strftime("%H:%M:%S"),
                'sender': addr[0]
            })

            # Keep only last 100 messages
            if len(messages) > 100:
                messages.pop(0)

            print(f"Received {msg_type} from {addr[0]}")

        except socket.timeout:
            continue
        except Exception as e:
            print(f"Error: {e}")

if __name__ == '__main__':
    # Start listener thread
    listener_thread = threading.Thread(target=message_listener, daemon=True)
    listener_thread.start()

    # Initialize nodes
    nodes = [
        {'name': 'Root CA', 'status': 'Running'},
        {'name': 'PCA', 'status': 'Running'},
        {'name': 'Vehicle 1', 'status': 'Broadcasting'},
        {'name': 'Vehicle 2', 'status': 'Broadcasting'},
        {'name': 'RSE 1', 'status': 'Active'}
    ]

    app.run(host='0.0.0.0', port=8080, debug=False)  # debug=False to avoid auto-reload issues
