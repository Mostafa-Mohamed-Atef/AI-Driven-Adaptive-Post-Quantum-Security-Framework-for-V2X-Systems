#!/usr/bin/env python3
"""
Hybrid AI-Driven Intrusion Detection System (IDS) Service.

Main entry point that runs the full detection pipeline:
  1. UDP listener ingests BSMs from vehicles / RSE
  2. Preprocessor cleans, normalizes, extracts features
  3. Signature detector checks CRL, replay, DoS
  4. CNN + LSTM anomaly detector scores each message
  5. Sybil detector clusters vehicle behaviour
  6. FDI detector validates trajectories
  7. Alerts are forwarded to the Misbehavior Authority
  8. REST API exposes metrics and alerts to the dashboard

Runs on HTTP port 5010 and UDP port 5011.
"""

import json
import time
import socket
import logging
import threading
from datetime import datetime

from flask import Flask, jsonify, request

from ids.config import (
    IDS_HOST, IDS_HTTP_PORT, IDS_UDP_PORT,
    MA_URL, MAX_ALERTS, LSTM_WINDOW_SIZE,
    ANOMALY_THRESHOLD, TARGET_LATENCY_MS,
    AUTO_REPORT_SEVERITY, ALERT_SEVERITY_LEVELS,
)
from ids.preprocessing.bsm_preprocessor import BSMPreprocessor
from ids.detection.signature_detector import SignatureDetector
from ids.detection.anomaly_detector import AnomalyDetector
from ids.detection.sybil_detector import SybilDetector
from ids.detection.fdi_detector import FDIDetector
from ids.models.trainer import ModelTrainer
from ids.metrics.evaluator import IDSEvaluator

# ── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - IDS - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# ── Flask App ────────────────────────────────────────────────────────────────
app = Flask(__name__)

# ── Global State ─────────────────────────────────────────────────────────────
preprocessor = BSMPreprocessor()
sig_detector = SignatureDetector()
anomaly_detector = AnomalyDetector()
sybil_detector = SybilDetector()
fdi_detector = FDIDetector()
evaluator = IDSEvaluator()

alerts: list[dict] = []
stats = {
    "messages_processed": 0,
    "alerts_generated": 0,
    "attacks_detected": {"sybil": 0, "fdi": 0, "replay": 0, "dos": 0,
                         "revoked_certificate": 0, "anomaly": 0},
    "avg_latency_ms": 0.0,
    "models_trained": False,
    "start_time": datetime.now().isoformat(),
}
latency_samples: list[float] = []


# ── Detection Pipeline ───────────────────────────────────────────────────────

def run_detection_pipeline(raw_msg: dict):
    """Process a single BSM through the full detection pipeline."""
    global alerts
    t0 = time.perf_counter()

    # 1. Preprocess
    processed = preprocessor.preprocess(raw_msg)
    if processed is None:
        return

    stats["messages_processed"] += 1
    new_alerts = []

    # 2. Signature-based detection
    sig_alerts = sig_detector.detect(processed)
    new_alerts.extend(sig_alerts)

    # 3. AI anomaly detection
    sequence = preprocessor.get_vehicle_sequence(
        processed["vehicle_id"], LSTM_WINDOW_SIZE
    )
    ai_alerts = anomaly_detector.detect(processed, sequence)
    new_alerts.extend(ai_alerts)

    # 4. Sybil detection
    sybil_alerts = sybil_detector.detect(processed)
    new_alerts.extend(sybil_alerts)

    # 5. FDI detection
    fdi_alerts = fdi_detector.detect(processed)
    new_alerts.extend(fdi_alerts)

    # Record latency
    latency_ms = (time.perf_counter() - t0) * 1000
    latency_samples.append(latency_ms)
    if len(latency_samples) > 1000:
        latency_samples.pop(0)
    stats["avg_latency_ms"] = round(
        sum(latency_samples) / len(latency_samples), 2
    )

    # Process alerts
    for alert in new_alerts:
        alert["latency_ms"] = round(latency_ms, 2)
        alerts.append(alert)
        stats["alerts_generated"] += 1

        attack_type = alert.get("attack_type", "unknown")
        if attack_type in stats["attacks_detected"]:
            stats["attacks_detected"][attack_type] += 1

        # Auto-report critical/high to MA
        sev = alert.get("severity", "low")
        if ALERT_SEVERITY_LEVELS.get(sev, 0) >= \
           ALERT_SEVERITY_LEVELS.get(AUTO_REPORT_SEVERITY, 3):
            _report_to_ma(alert)

        logger.warning(
            "ALERT [%s] %s — %s (%.1fms)",
            sev.upper(), attack_type,
            alert.get("description", "")[:80], latency_ms,
        )

    # Trim alerts
    if len(alerts) > MAX_ALERTS:
        alerts = alerts[-MAX_ALERTS:]


def _report_to_ma(alert: dict):
    """Forward a critical alert to the Misbehavior Authority."""
    try:
        import requests as req
        req.post(
            f"{MA_URL}/report_misbehavior",
            json={
                "certificate_id": f"cert_{alert.get('vehicle_id', 'unknown')}",
                "vehicle_id": alert.get("vehicle_id", "unknown"),
                "reason": f"IDS: {alert.get('attack_type')} — "
                          f"{alert.get('description', '')[:100]}",
            },
            timeout=2,
        )
    except Exception as exc:
        logger.debug("Failed to report to MA: %s", exc)


# ── UDP Listener ─────────────────────────────────────────────────────────────

def udp_listener():
    """Listen for BSMs on UDP and feed them into the detection pipeline."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", IDS_UDP_PORT))
    logger.info("IDS UDP listener started on port %d", IDS_UDP_PORT)

    while True:
        try:
            data, addr = sock.recvfrom(65535)
            msg = json.loads(data.decode())
            run_detection_pipeline(msg)
        except json.JSONDecodeError:
            logger.debug("Invalid JSON from %s", addr)
        except Exception as exc:
            logger.error("UDP listener error: %s", exc)


# ── REST API ─────────────────────────────────────────────────────────────────

@app.route("/health")
def health():
    return jsonify({
        "service": "IDS — Hybrid AI-Driven Intrusion Detection",
        "status": "running",
        "models_trained": stats["models_trained"],
        "timestamp": datetime.now().isoformat(),
    })


@app.route("/api/ids/stats")
def get_stats():
    return jsonify(stats)


@app.route("/api/ids/alerts")
def get_alerts():
    limit = request.args.get("limit", 50, type=int)
    severity = request.args.get("severity", None)
    result = alerts[-limit:]
    if severity:
        result = [a for a in result if a.get("severity") == severity]
    return jsonify({"count": len(result), "alerts": result})


@app.route("/api/ids/alerts/clear", methods=["POST"])
def clear_alerts():
    alerts.clear()
    return jsonify({"status": "cleared"})


@app.route("/api/ids/metrics")
def get_metrics():
    return jsonify({
        "evaluator_history": evaluator.get_latest_results(),
        "training_results": getattr(trainer, "training_results", {}),
    })


@app.route("/api/ids/sybil/summary")
def sybil_summary():
    return jsonify(sybil_detector.get_cluster_summary())


@app.route("/api/ids/detect", methods=["POST"])
def detect_single():
    """REST endpoint to submit a single BSM for detection."""
    raw_msg = request.get_json()
    run_detection_pipeline(raw_msg)
    return jsonify({"status": "processed", "alerts": alerts[-5:]})


@app.route("/api/ids/train", methods=["POST"])
def trigger_training():
    """Trigger model training (async)."""
    threading.Thread(target=_train_models, daemon=True).start()
    return jsonify({"status": "training_started"})


# ── Model Training ───────────────────────────────────────────────────────────

trainer = ModelTrainer()


def _train_models():
    """Train models and inject them into detectors."""
    global trainer
    logger.info("Starting model training...")
    results = trainer.train_all()
    anomaly_detector.set_models(
        cnn_model=trainer.cnn_model,
        lstm_model=trainer.lstm_model,
    )
    fdi_detector.set_lstm_model(trainer.lstm_model)
    stats["models_trained"] = True
    logger.info("Models trained and injected into detectors")


# ── Main ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    # Start UDP listener
    udp_thread = threading.Thread(target=udp_listener, daemon=True)
    udp_thread.start()

    # Try to load pre-trained models
    if trainer.load_pretrained():
        anomaly_detector.set_models(
            cnn_model=trainer.cnn_model,
            lstm_model=trainer.lstm_model,
        )
        fdi_detector.set_lstm_model(trainer.lstm_model)
        stats["models_trained"] = True
        logger.info("Pre-trained models loaded")
    else:
        # Auto-train on startup
        logger.info("No pre-trained models found — training on synthetic data...")
        threading.Thread(target=_train_models, daemon=True).start()

    logger.info("IDS service starting on %s:%d", IDS_HOST, IDS_HTTP_PORT)
    app.run(host=IDS_HOST, port=IDS_HTTP_PORT, debug=False, use_reloader=False)
