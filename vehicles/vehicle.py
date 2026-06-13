import json
import logging
import time
import hashlib
import argparse
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
import datetime
import requests
import socket
import threading
import base64
import os
import sys
import math

if sys.platform == "win32":
    BROADCAST_ADDR = "255.255.255.255"
else:
    BROADCAST_ADDR = "<broadcast>"

# Each vehicle starts at a distinct position and moves along a highway
# (approximate highway A8, Germany — consistent with VeReMi NextGen scenario)
_VEHICLE_START_POSITIONS = {
    1: (48.3705, 10.8978),   # Augsburg area
    2: (48.3720, 10.9010),   # ~200 m ahead
    3: (48.3690, 10.8950),   # ~200 m behind
}
_DEFAULT_START = (48.3705, 10.8978)

_HIGHWAY_HEADING = math.radians(90.0)  # eastbound
_BROADCAST_PORT  = 5020                # avoids conflict with PCA (5006)


class Vehicle:
    def __init__(self, vehicle_id: int, ra_url: str = "http://localhost:5003"):
        self.vehicle_id  = vehicle_id
        self.ra_url      = ra_url

        # Starting position — unique per vehicle ID
        lat0, lon0 = _VEHICLE_START_POSITIONS.get(vehicle_id, _DEFAULT_START)
        self._lat = lat0
        self._lon = lon0
        self._spd = 25.0 + vehicle_id * 2.0  # m/s  (~90–96 km/h)
        self._hed = _HIGHWAY_HEADING          # radians, eastbound
        self._acl = 0.0                       # m/s²
        self._last_ts = time.time()

        # Classical crypto for CAM (ECDSA P-256)
        self.cam_private_key = ec.generate_private_key(ec.SECP256R1())
        self.cam_public_key  = self.cam_private_key.public_key()

        # PQC simulation for DENM
        self.pqc_public_key = b"PQC-SIM-PUBLIC-KEY"

        self._setup_sockets()
        logging.info("Vehicle %d initialised at (%.4f, %.4f)", vehicle_id, lat0, lon0)

    # ── Socket setup ─────────────────────────────────────────────────────────

    def _setup_sockets(self):
        self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        if sys.platform == "win32":
            self.udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listening = False

    # ── Position simulation ───────────────────────────────────────────────────

    def _advance_position(self):
        """Move vehicle forward along heading by elapsed time."""
        now = time.time()
        dt  = now - self._last_ts
        self._last_ts = now

        # Simple constant-speed kinematic model
        # 1 degree latitude  ≈ 111 320 m
        # 1 degree longitude ≈ 111 320 * cos(lat) m
        cos_lat = math.cos(math.radians(self._lat))
        self._lat += (self._spd * math.sin(self._hed) * dt) / 111_320.0
        self._lon += (self._spd * math.cos(self._hed) * dt) / (111_320.0 * cos_lat)

    # ── Message generation ────────────────────────────────────────────────────

    def generate_cam(self) -> str:
        """Generate CAM with real ECDSA P-256 signature."""
        self._advance_position()

        cam_data = {
            "message_type": "CAM",
            "vehicle_id":   self.vehicle_id,
            "timestamp":    time.time(),
            "position":     [round(self._lat, 6), round(self._lon, 6)],
            "speed":        round(self._spd, 2),      # m/s
            "heading":      round(self._hed, 4),      # radians
            "acceleration": round(self._acl, 3),      # m/s²
            "crypto_type":  "ECDSA-P256-SHA256",
        }

        msg_bytes = json.dumps(cam_data, sort_keys=True).encode()
        sig_bytes = self.cam_private_key.sign(msg_bytes, ec.ECDSA(hashes.SHA256()))
        signature = base64.b64encode(sig_bytes).decode()

        return json.dumps({
            "data":      cam_data,
            "signature": signature,
            "crypto":    "classical",
        })

    def generate_denm(self, event_type: str = "accident", severity: int = 3) -> str:
        """Generate DENM with PQC-simulated signature (CRYSTALS-Dilithium3 sim)."""
        denm_data = {
            "message_type": "DENM",
            "vehicle_id":   self.vehicle_id,
            "event_type":   event_type,
            "severity":     severity,
            "position":     [round(self._lat, 6), round(self._lon, 6)],
            "timestamp":    time.time(),
            "validity":     time.time() + 300,
            "crypto_type":  "PQC-SIMULATION",
        }

        # Simulate Dilithium3: use SHA-512 as stand-in (real impl uses liboqs)
        pqc_signature = hashlib.sha512(json.dumps(denm_data).encode()).hexdigest()

        return json.dumps({
            "data":          denm_data,
            "signature":     pqc_signature,
            "crypto":        "pqc",
            "pqc_algorithm": "CRYSTALS-DILITHIUM3-SIM",
        })

    # ── Broadcast ─────────────────────────────────────────────────────────────

    def broadcast_message(self, message: str):
        try:
            self.udp_socket.sendto(
                message.encode(), (BROADCAST_ADDR, _BROADCAST_PORT)
            )
        except Exception as e:
            logging.debug("Broadcast failed: %s", e)

        # Send to IDS
        try:
            ids_host = os.environ.get("IDS_HOST", "ids-service")
            ids_port = int(os.environ.get("IDS_PORT", "5011"))
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.sendto(message.encode(), (ids_host, ids_port))
            s.close()
        except Exception as e:
            logging.debug("IDS send failed: %s", e)

        # Send to dashboard
        try:
            dash_host = os.environ.get("DASHBOARD_HOST", "dashboard")
            dash_port = int(os.environ.get("DASHBOARD_PORT", "5008"))
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            s.sendto(message.encode(), (dash_host, dash_port))
            s.close()
        except Exception as e:
            logging.debug("Dashboard send failed: %s", e)

        logging.info("Vehicle %d broadcast: %s", self.vehicle_id, message[:60])

    # ── Listen thread ─────────────────────────────────────────────────────────

    def start_listening(self):
        self.listening = True
        t = threading.Thread(target=self._listen_thread, daemon=True)
        t.start()

    def _listen_thread(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("0.0.0.0", _BROADCAST_PORT))
        s.settimeout(1.0)
        while self.listening:
            try:
                data, addr = s.recvfrom(65535)
                msg = data.decode()
                parsed = json.loads(msg)
                sender = parsed.get("data", {}).get("vehicle_id")
                if sender != self.vehicle_id:
                    logging.debug("Vehicle %d received from %s", self.vehicle_id, addr)
            except socket.timeout:
                continue
            except Exception as e:
                logging.debug("Listen error: %s", e)
        s.close()


def main():
    parser = argparse.ArgumentParser(description="V2X Vehicle Node")
    parser.add_argument("--id",     type=int, required=True, help="Vehicle ID")
    parser.add_argument("--ra-url", default="http://localhost:5003")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[
            logging.FileHandler(f"vehicle_{args.id}.log"),
            logging.StreamHandler(),
        ],
    )

    vehicle = Vehicle(args.id, args.ra_url)
    vehicle.start_listening()

    try:
        count = 0
        while True:
            if count % 2 == 0:
                vehicle.broadcast_message(vehicle.generate_cam())

            if count % 10 == 0:
                vehicle.broadcast_message(vehicle.generate_denm())

            time.sleep(1)
            count += 1
    except KeyboardInterrupt:
        vehicle.listening = False
        logging.info("Vehicle %d stopped", args.id)


if __name__ == "__main__":
    main()
