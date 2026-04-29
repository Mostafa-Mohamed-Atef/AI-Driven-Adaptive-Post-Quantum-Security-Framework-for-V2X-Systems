"""
Centralized configuration for the IDS service.
All thresholds, model parameters, and service URLs are defined here.
"""

import os


# ─── Service Configuration ───────────────────────────────────────────────────

IDS_HOST = os.getenv("IDS_HOST", "0.0.0.0")
IDS_HTTP_PORT = int(os.getenv("IDS_HTTP_PORT", "5010"))
IDS_UDP_PORT = int(os.getenv("IDS_UDP_PORT", "5011"))

MA_URL = os.getenv("MA_URL", "http://ma:5004")
DASHBOARD_HOST = os.getenv("DASHBOARD_HOST", "dashboard")
DASHBOARD_PORT = int(os.getenv("DASHBOARD_PORT", "5008"))
REDIS_HOST = os.getenv("REDIS_HOST", "redis")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))


# ─── Detection Thresholds ────────────────────────────────────────────────────

# Anomaly score above this triggers an alert (0.0 – 1.0)
ANOMALY_THRESHOLD = float(os.getenv("ANOMALY_THRESHOLD", "0.65"))

# Sybil detector: minimum cluster size to flag as Sybil
SYBIL_MIN_CLUSTER_SIZE = int(os.getenv("SYBIL_MIN_CLUSTER_SIZE", "3"))
# Maximum allowed spatial deviation within a cluster (meters)
SYBIL_MAX_SPATIAL_DEVIATION = float(os.getenv("SYBIL_MAX_SPATIAL_DEVIATION", "50.0"))
# Coordination score threshold
SYBIL_COORDINATION_THRESHOLD = float(os.getenv("SYBIL_COORDINATION_THRESHOLD", "0.75"))

# FDI: maximum acceptable position error from predicted trajectory (meters)
FDI_POSITION_ERROR_THRESHOLD = float(os.getenv("FDI_POSITION_ERROR_THRESHOLD", "100.0"))
# FDI: maximum acceptable speed discrepancy (km/h)
FDI_SPEED_ERROR_THRESHOLD = float(os.getenv("FDI_SPEED_ERROR_THRESHOLD", "30.0"))

# Replay: max acceptable message age (seconds)
REPLAY_MAX_AGE = float(os.getenv("REPLAY_MAX_AGE", "5.0"))

# DoS: max messages per vehicle per second
DOS_RATE_LIMIT = int(os.getenv("DOS_RATE_LIMIT", "10"))

# Latency target (ms) — edge deployment optimization
TARGET_LATENCY_MS = float(os.getenv("TARGET_LATENCY_MS", "10.0"))


# ─── Model Parameters ────────────────────────────────────────────────────────

# Feature vector size for BSM input
BSM_FEATURE_DIM = 10

# LSTM sequence window (number of consecutive BSMs)
LSTM_WINDOW_SIZE = int(os.getenv("LSTM_WINDOW_SIZE", "20"))

# CNN filter configuration
CNN_FILTERS = [32, 64, 128]
CNN_KERNEL_SIZE = 3

# Training parameters
TRAINING_EPOCHS = int(os.getenv("TRAINING_EPOCHS", "50"))
TRAINING_BATCH_SIZE = int(os.getenv("TRAINING_BATCH_SIZE", "64"))
LEARNING_RATE = float(os.getenv("LEARNING_RATE", "0.001"))

# Model persistence
MODEL_SAVE_DIR = os.getenv("MODEL_SAVE_DIR", "/app/ids/models/saved")

# K-Means parameters for Sybil detection
KMEANS_N_CLUSTERS = int(os.getenv("KMEANS_N_CLUSTERS", "5"))
KMEANS_MAX_ITER = int(os.getenv("KMEANS_MAX_ITER", "300"))


# ─── Data Generation ─────────────────────────────────────────────────────────

# Number of synthetic BSMs to generate for training
SYNTHETIC_NORMAL_SAMPLES = int(os.getenv("SYNTHETIC_NORMAL_SAMPLES", "5000"))
SYNTHETIC_ATTACK_SAMPLES = int(os.getenv("SYNTHETIC_ATTACK_SAMPLES", "1000"))

# Attack distribution in synthetic data
ATTACK_DISTRIBUTION = {
    "sybil": 0.30,
    "fdi": 0.30,
    "replay": 0.20,
    "dos": 0.20,
}


# ─── Alert Configuration ─────────────────────────────────────────────────────

ALERT_SEVERITY_LEVELS = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
}

# Maximum alerts stored in memory
MAX_ALERTS = int(os.getenv("MAX_ALERTS", "500"))

# Auto-report to MA above this severity
AUTO_REPORT_SEVERITY = "high"
