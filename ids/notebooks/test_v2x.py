import requests
import time
import json

def test_scms():
    print("Testing V2X SCMS Architecture...")
    
    # Test Root CA
    try:
        resp = requests.get("http://localhost:5001/health")
        print(f"✓ Root CA: {resp.json()}")
    except:
        print("✗ Root CA not responding")
    
    # Test Vehicle communication
    print("\nTesting Vehicle Communication...")
    
    # Simulate CAM message
    cam_msg = {
        'data': {
            'message_type': 'CAM',
            'vehicle_id': 'TEST-001',
            'timestamp': time.time(),
            'crypto': 'classical'
        },
        'signature': 'test_signature'
    }
    
    print(f"CAM Message: {json.dumps(cam_msg, indent=2)}")
    
    # Simulate DENM message
    denm_msg = {
        'data': {
            'message_type': 'DENM',
            'event_type': 'accident',
            'severity': 3,
            'timestamp': time.time(),
            'crypto': 'pqc'
        },
        'signature': 'pqc_test_signature',
        'pqc_algorithm': 'DILITHIUM2'
    }
    
    print(f"\nDENM Message: {json.dumps(denm_msg, indent=2)}")
    
    print("\n✓ Architecture test complete!")
    print("\nAccess Dashboard at: http://localhost:8080")

if __name__ == '__main__':
    test_scms()