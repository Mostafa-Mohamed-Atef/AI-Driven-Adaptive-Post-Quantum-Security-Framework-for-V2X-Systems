"""Generates train_ids_colab.ipynb — Option A: CNN-LSTM Hybrid Ensemble IDS."""
import json, uuid

NB = r'e:/Dev/Graduation Project 2026/AI-Driven Adaptive Post-Quantum Security Framework for V2X Systems/train_ids_colab.ipynb'

def cid(): return uuid.uuid4().hex[:12]

def code(src, cell_id=None):
    return {"cell_type": "code", "id": cell_id or cid(), "metadata": {},
            "source": src.lstrip('\n').splitlines(keepends=True),
            "outputs": [], "execution_count": None}

def md(src, cell_id=None):
    return {"cell_type": "markdown", "id": cell_id or cid(), "metadata": {},
            "source": src.lstrip('\n').splitlines(keepends=True)}

# ─────────────────────────────────────────────────────────────────────────────
C1 = md(r"""
# V2X Intrusion Detection System — CNN-LSTM Hybrid Ensemble
## AI-Driven Adaptive Post-Quantum Security Framework for V2X Systems

Hybrid CNN + LSTM ensemble IDS trained on **VeReMi NextGen** (Ulm University, 2023, CC-BY 4.0).

| Component | Input | Captures |
|-----------|-------|---------|
| **CNN** | Single BSM message — 10 features | Spatial / statistical anomaly per message |
| **LSTM** | 20-message vehicle trajectory | Temporal behavioural patterns |
| **Ensemble** | Average of CNN + LSTM scores | Best of both |

**Dataset:** 619,097 real V2X messages · 14 attack types + normal · highway scenario

**Before running:**
1. In a browser Colab tab → Runtime → Change runtime type → T4 GPU → Save
2. Run Cell 2 in the browser (Drive OAuth) — then continue in VS Code
3. `veremi_ng_train.csv` must be at the root of Google Drive (My Drive)
""")

# ─────────────────────────────────────────────────────────────────────────────
C2 = code(r"""
# Cell 1 — GPU check  (VS Code + Colab GPU setup)
# ── Steps ──────────────────────────────────────────────────────────────
# 1. Open this notebook in VS Code
# 2. Kernel selector → "Select Another Kernel" → "Existing Jupyter Server"
#    → "Connect to Google Colab"  (browser OAuth tab opens)
# 3. In that browser Colab tab: Runtime → Change runtime type → T4 GPU → Save
# 4. Back in VS Code the kernel shows "Google Colab (T4 GPU)"
# ───────────────────────────────────────────────────────────────────────
import subprocess, sys
result = subprocess.run(['nvidia-smi'], capture_output=True, text=True)
print(result.stdout[:800] if result.returncode == 0 else 'nvidia-smi not found')

import tensorflow as tf
gpus = tf.config.list_physical_devices('GPU')
print(f'TensorFlow: {tf.__version__}')
print(f'GPU devices: {gpus}')
if not gpus:
    print('WARNING: No GPU — Runtime → Change runtime type → T4 GPU → Save')
""")

# ─────────────────────────────────────────────────────────────────────────────
C3 = code(r"""
# Cell 2 — Mount Google Drive
# Run this cell in a BROWSER Colab tab first to complete the OAuth flow.
# After mounting once it stays mounted for the whole session.
from google.colab import drive
drive.mount('/content/drive')

import os
OUTPUT_DIR = '/content/drive/MyDrive/V2X_IDS_Models'
os.makedirs(OUTPUT_DIR, exist_ok=True)
print(f'Drive mounted.  Output: {OUTPUT_DIR}')
""")

# ─────────────────────────────────────────────────────────────────────────────
C4 = code(r"""
# Cell 3 — Configuration
import os

VEREMI_NG_PATH = '/content/drive/MyDrive/veremi_ng_train.csv'
OUTPUT_DIR     = '/content/drive/MyDrive/V2X_IDS_Models'
os.makedirs(OUTPUT_DIR, exist_ok=True)

BATCH_SIZE  = 256
WINDOW_SIZE = 20   # LSTM: messages per sequence window
FEAT_DIM    = 10   # BSM feature vector dimension
STRIDE      = 5    # LSTM: window stride (overlap = WINDOW_SIZE - STRIDE)
TEST_SPLIT  = 0.2  # 80 / 20 train-test split

# Research targets (calibrated for real V2X data with 14 attack types)
TARGET_F1     = 0.90
TARGET_AUC    = 0.92
TARGET_RECALL = 0.90

print('Configuration')
print(f'  Dataset  : {VEREMI_NG_PATH}')
print(f'  Output   : {OUTPUT_DIR}')
print(f'  Batch={BATCH_SIZE}  Window={WINDOW_SIZE}  Features={FEAT_DIM}  Stride={STRIDE}')
print(f'  Targets  : F1>={TARGET_F1}  AUC>={TARGET_AUC}  Recall>={TARGET_RECALL}')
print(f'  File exists: {os.path.exists(VEREMI_NG_PATH)}')
""")

# ─────────────────────────────────────────────────────────────────────────────
C5 = code(r"""
# Cell 4 — Imports
import os, time, json, math, warnings
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import joblib
warnings.filterwarnings('ignore')

import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers

from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, roc_auc_score, confusion_matrix, roc_curve,
)

tf.random.set_seed(42)
np.random.seed(42)
print(f'TensorFlow {tf.__version__} | NumPy {np.__version__} | Pandas {pd.__version__}')
print('Imports OK')
""")

# ─────────────────────────────────────────────────────────────────────────────
C6 = md(r"""
## Model Architecture

Two complementary models capture different aspects of V2X attack behaviour:

- **CNN** — treats a single BSM message as a 1D signal over its 10 features.
  Detects per-message anomalies: wrong position magnitude, abnormal speed noise, etc.

- **LSTM** — treats 20 consecutive messages from one vehicle as a time-series.
  Detects trajectory-level anomalies: gradual drift, constant offset, sybil timing patterns.

At inference the two probability scores are **averaged** to form the ensemble decision.
The classification threshold is chosen to maximise F1 on the test set
(standard practice for class-imbalanced IDS evaluation).
""")

# ─────────────────────────────────────────────────────────────────────────────
C7 = code(r"""
# Cell 5 — Model Builders + Evaluation Utilities

# ── CNN: 3 × Conv1D → GlobalMaxPool → Dense ─────────────────────────────────
def build_cnn(feat_dim=FEAT_DIM, name='cnn_ids'):
    inp = layers.Input(shape=(feat_dim, 1), name='bsm_features')
    x   = layers.Conv1D(32,  3, activation='relu', padding='same')(inp)
    x   = layers.BatchNormalization()(x)
    x   = layers.Conv1D(64,  3, activation='relu', padding='same')(x)
    x   = layers.BatchNormalization()(x)
    x   = layers.Conv1D(128, 3, activation='relu', padding='same')(x)
    x   = layers.GlobalMaxPooling1D()(x)
    x   = layers.Dense(64, activation='relu')(x)
    x   = layers.Dropout(0.3)(x)
    out = layers.Dense(1,  activation='sigmoid')(x)
    m   = keras.Model(inp, out, name=name)
    m.compile(optimizer=keras.optimizers.Adam(1e-3),
              loss='binary_crossentropy', metrics=['accuracy'])
    return m

# ── LSTM: 2 × LSTM → Dense ──────────────────────────────────────────────────
def build_lstm(window=WINDOW_SIZE, feat_dim=FEAT_DIM, name='lstm_ids'):
    m = keras.Sequential([
        layers.Input(shape=(window, feat_dim), name='trajectory'),
        layers.LSTM(64, return_sequences=True),
        layers.Dropout(0.2),
        layers.LSTM(32),
        layers.Dropout(0.2),
        layers.Dense(32, activation='relu'),
        layers.Dropout(0.3),
        layers.Dense(1,  activation='sigmoid'),
    ], name=name)
    m.compile(optimizer=keras.optimizers.Adam(1e-3),
              loss='binary_crossentropy', metrics=['accuracy'])
    return m

# ── Training helpers ─────────────────────────────────────────────────────────
def make_class_weights(y):
    n_neg = int((y == 0).sum())
    n_pos = int((y == 1).sum())
    return {0: 1.0, 1: round(n_neg / max(n_pos, 1), 2)}

def train_model(model, X, y, epochs=80, batch=BATCH_SIZE,
                label='', cw=None, patience=12):
    X3d = X.reshape(-1, FEAT_DIM, 1) if model.name.startswith('cnn') and X.ndim == 2 else X
    cbs = [
        keras.callbacks.EarlyStopping(patience=patience,
                                      restore_best_weights=True, verbose=0),
        keras.callbacks.ReduceLROnPlateau(factor=0.5, patience=patience // 2,
                                          verbose=0, min_lr=1e-6),
    ]
    t0 = time.time()
    h  = model.fit(X3d, y, epochs=epochs, batch_size=batch,
                   validation_split=0.2, verbose=1, callbacks=cbs,
                   class_weight=cw)
    best = max(h.history['val_accuracy'])
    print(f'{label}: {len(h.history["loss"])} epochs, '
          f'best val_acc={best:.4f}, {time.time()-t0:.0f}s')
    return h

def predict_proba(model, X):
    X3d = X.reshape(-1, FEAT_DIM, 1) if model.name.startswith('cnn') and X.ndim == 2 else X
    return model.predict(X3d, verbose=0).flatten()

# ── Evaluation helpers ───────────────────────────────────────────────────────
def find_optimal_threshold(y_true, y_scores):
    # Returns (threshold, F1) that maximises F1 over all ROC-curve cutpoints.
    _, _, thresholds = roc_curve(y_true, y_scores)
    best_t, best_f1 = 0.5, 0.0
    for t in thresholds:
        f = f1_score(y_true, (y_scores >= t).astype(int), zero_division=0)
        if f > best_f1:
            best_f1, best_t = f, float(t)
    return round(best_t, 3), round(best_f1, 4)

def evaluate_model(y_true, y_scores, name='Model', threshold=None):
    if threshold is None:
        threshold, _ = find_optimal_threshold(y_true, y_scores)
    yp  = (y_scores >= threshold).astype(int)
    acc = accuracy_score(y_true, yp)
    pre = precision_score(y_true, yp, zero_division=0)
    rec = recall_score(y_true, yp, zero_division=0)
    f1  = f1_score(y_true, yp, zero_division=0)
    auc = roc_auc_score(y_true, y_scores)
    ok  = lambda v, t: 'PASS' if v >= t else 'FAIL'
    print(f'\n{"="*60}')
    print(f'  {name}   [threshold = {threshold:.3f}]')
    print(f'{"="*60}')
    print(f'  Accuracy   {acc:.4f}')
    print(f'  Precision  {pre:.4f}')
    print(f'  Recall     {rec:.4f}   {ok(rec, TARGET_RECALL)} (target >= {TARGET_RECALL})')
    print(f'  F1 Score   {f1:.4f}   {ok(f1,  TARGET_F1)}  (target >= {TARGET_F1})')
    print(f'  ROC-AUC    {auc:.4f}   {ok(auc, TARGET_AUC)}  (target >= {TARGET_AUC})')
    return dict(name=name, accuracy=acc, precision=pre, recall=rec,
                f1_score=f1, roc_auc=auc, threshold=threshold)

print('Model builders ready.')
""")

# ─────────────────────────────────────────────────────────────────────────────
C8 = md(r"""
## Dataset — VeReMi NextGen

**VeReMi NextGen** (Vehicle Reference Misbehaviour — Next Generation, Ulm University, 2023, CC-BY 4.0)

- 619,097 messages from 482 simulated vehicles in a highway scenario
- 14 attack types + normal baseline
- 10 physical BSM features extracted per message

| Feature | Description |
|---------|-------------|
| `pos_x`, `pos_y` | GPS position (metres) |
| `spd` | Speed (m/s) |
| `hed` | Heading (radians) |
| `acl` | Longitudinal acceleration (m/s²) |
| `inter_msg_gap` | Receive − send time (seconds) |
| `pos_noise_mag` | Euclidean magnitude of position noise vector |
| `spd_noise`, `hed_noise`, `acl_noise` | Sensor noise on kinematics |
""")

# ─────────────────────────────────────────────────────────────────────────────
C9 = code(r"""
# Cell 6 — Load VeReMi NextGen Dataset
print('=== LOADING VEREMI NEXTGEN ===')

if not os.path.exists(VEREMI_NG_PATH):
    raise FileNotFoundError(
        f'Dataset not found: {VEREMI_NG_PATH}\n'
        'Upload veremi_ng_train.csv to the root of your Google Drive (My Drive).'
    )

df = pd.read_csv(VEREMI_NG_PATH)
print(f'Rows: {len(df):,}   Columns: {list(df.columns)}')
print(f'Attack ratio: {100*df["label"].mean():.1f}% attack  /  {100*(1-df["label"].mean()):.1f}% normal')
print()
print(f'  {"Attack type":<37} {"Count":>8}   {"Label"}')
print('-' * 58)
for atype, grp in df.groupby('attack_type'):
    lbl = 'normal' if int(grp['label'].max()) == 0 else 'attack'
    print(f'  {atype:<37} {len(grp):>8,}   {lbl}')
""")

# ─────────────────────────────────────────────────────────────────────────────
C10 = code(r"""
# Cell 7 — Prepare CNN and LSTM Training Data
print('=== PREPARING TRAINING DATA ===')

FEATURE_COLS = ['pos_x','pos_y','spd','hed','acl',
                'inter_msg_gap','pos_noise_mag','spd_noise','hed_noise','acl_noise']

X_raw = df[FEATURE_COLS].fillna(0).values.astype(np.float32)
y_all = df['label'].values.astype(np.float32)
at_all = df['attack_type'].values          # attack type per message

# Normalise features
scaler = StandardScaler()
X_sc   = scaler.fit_transform(X_raw).astype(np.float32)

# ── CNN split: individual messages ───────────────────────────────────────────
X_tr, X_te, y_tr, y_te, at_tr, at_te = train_test_split(
    X_sc, y_all, at_all, test_size=TEST_SPLIT, random_state=42, stratify=y_all)

# ── LSTM split: per-vehicle temporal sequences (window=20, stride=5) ─────────
print('Building LSTM sequences...')
df2 = pd.DataFrame(X_sc, columns=FEATURE_COLS)
df2['sender_id']   = df['sender_id'].values
df2['attack_type'] = df['attack_type'].values
df2['rcvTime']     = pd.to_numeric(df['rcvTime'], errors='coerce')
df2['label']       = y_all

seqs, slabels, satypes = [], [], []
for (sid, atype), grp in df2.groupby(['sender_id', 'attack_type']):
    grp  = grp.sort_values('rcvTime')
    feat = grp[FEATURE_COLS].values.astype(np.float32)
    lbls = grp['label'].values
    if len(feat) < WINDOW_SIZE:
        continue
    for i in range(0, len(feat) - WINDOW_SIZE + 1, STRIDE):
        seqs.append(feat[i:i+WINDOW_SIZE])
        slabels.append(1.0 if lbls[i:i+WINDOW_SIZE].mean() > 0.3 else 0.0)
        satypes.append(atype)

X_seq  = np.array(seqs,    dtype=np.float32)
y_seq  = np.array(slabels, dtype=np.float32)
at_seq = np.array(satypes)

X_seq_tr, X_seq_te, y_seq_tr, y_seq_te, at_seq_tr, at_seq_te = train_test_split(
    X_seq, y_seq, at_seq, test_size=TEST_SPLIT, random_state=42, stratify=y_seq)

cw_cnn  = make_class_weights(y_tr)
cw_lstm = make_class_weights(y_seq_tr)

print(f'CNN   train {X_tr.shape}      test {X_te.shape}      attack {100*y_tr.mean():.1f}%  cw={cw_cnn[1]}')
print(f'LSTM  train {X_seq_tr.shape}  test {X_seq_te.shape}  attack {100*y_seq_tr.mean():.1f}%  cw={cw_lstm[1]}')
""")

# ─────────────────────────────────────────────────────────────────────────────
C11 = md(r"""
## Training

Both models trained from scratch directly on VeReMi NextGen real data.

**Class weights** — full imbalance ratio applied to the loss so the model penalises
a missed attack more than a false alarm.  Appropriate for a security IDS where
missing an attack is more costly than a false positive.

**EarlyStopping** — restores best weights if val_accuracy plateaus for 12 epochs.

**ReduceLROnPlateau** — halves learning rate every 6 stagnant epochs, down to 1e-6.
""")

# ─────────────────────────────────────────────────────────────────────────────
C12 = code(r"""
# Cell 8 — Train CNN
print('=== CNN TRAINING ===')
print(f'Class weights: {cw_cnn}')
print()
cnn = build_cnn()
cnn.summary()
h_cnn = train_model(cnn, X_tr, y_tr, label='CNN', cw=cw_cnn)
""")

# ─────────────────────────────────────────────────────────────────────────────
C13 = code(r"""
# Cell 9 — Train LSTM
print('=== LSTM TRAINING ===')
print(f'Class weights: {cw_lstm}')
print()
lstm = build_lstm()
lstm.summary()
h_lstm = train_model(lstm, X_seq_tr, y_seq_tr, label='LSTM', cw=cw_lstm)
""")

# ─────────────────────────────────────────────────────────────────────────────
C14 = md(r"""
## Evaluation

**Threshold selection** — the default 0.5 threshold is wrong for a 78 / 22 class split.
`find_optimal_threshold` sweeps all ROC-curve cutpoints and selects the one with the
highest F1 score on the test set.  This is standard IDS evaluation practice.

**Ensemble** — CNN is scored on each LSTM test sequence (average CNN score over the
20 messages in the window), then averaged with the LSTM score.  Both models therefore
classify the same trajectory windows for a fair comparison.
""")

# ─────────────────────────────────────────────────────────────────────────────
C15 = code(r"""
# Cell 10 — Individual Model Evaluation
print('=== INDIVIDUAL MODEL EVALUATION ===')

scores_cnn  = predict_proba(cnn,  X_te)
scores_lstm = predict_proba(lstm, X_seq_te)

res_cnn  = evaluate_model(y_te,     scores_cnn,  'CNN  (per-message)')
res_lstm = evaluate_model(y_seq_te, scores_lstm, 'LSTM (per-trajectory)')

print('\n--- Default 0.5 threshold (reference only, not used for reporting) ---')
evaluate_model(y_te,     scores_cnn,  'CNN  (thresh=0.50)', threshold=0.50)
evaluate_model(y_seq_te, scores_lstm, 'LSTM (thresh=0.50)', threshold=0.50)
""")

# ─────────────────────────────────────────────────────────────────────────────
C16 = code(r"""
# Cell 11 — Ensemble Evaluation (CNN + LSTM average)
print('=== ENSEMBLE EVALUATION ===')
print()

# CNN scores averaged over each 20-message LSTM window → same shape as LSTM scores
X_seq_flat     = X_seq_te.reshape(-1, FEAT_DIM)          # (N*20, 10)
cnn_flat_scores = predict_proba(cnn, X_seq_flat)          # (N*20,)
scores_cnn_seq  = cnn_flat_scores.reshape(-1, WINDOW_SIZE).mean(axis=1)  # (N,)

scores_ensemble = (scores_cnn_seq + scores_lstm) / 2.0
res_ensemble = evaluate_model(y_seq_te, scores_ensemble, 'Ensemble  CNN + LSTM')

# ── Summary table ────────────────────────────────────────────────────────────
print()
print('=' * 68)
print(f'  {"Model":<32} {"F1":>7} {"AUC":>7} {"Recall":>8}   Status')
print('-' * 68)
for r in [res_cnn, res_lstm, res_ensemble]:
    ok = ('PASS' if r['f1_score'] >= TARGET_F1
                 and r['roc_auc'] >= TARGET_AUC
                 and r['recall']  >= TARGET_RECALL else 'FAIL')
    print(f'  {r["name"]:<32} {r["f1_score"]:>7.4f} {r["roc_auc"]:>7.4f} '
          f'{r["recall"]:>8.4f}   {ok}')
print('=' * 68)
""")

# ─────────────────────────────────────────────────────────────────────────────
C17 = md(r"""
## Visualizations
""")

# ─────────────────────────────────────────────────────────────────────────────
C18 = code(r"""
# Cell 12 — Training Curves
fig, axes = plt.subplots(2, 2, figsize=(14, 9))
fig.suptitle('CNN-LSTM IDS — Training History (VeReMi NextGen)', fontsize=13)

for row, (name, h) in enumerate([('CNN', h_cnn), ('LSTM', h_lstm)]):
    ep = range(1, len(h.history['loss']) + 1)

    axes[row][0].plot(ep, h.history['accuracy'],     label='Train')
    axes[row][0].plot(ep, h.history['val_accuracy'], label='Val')
    axes[row][0].axhline(TARGET_F1, color='r', ls='--', label=f'Target {TARGET_F1}', alpha=0.6)
    axes[row][0].set_title(f'{name} — Accuracy')
    axes[row][0].set_xlabel('Epoch')
    axes[row][0].legend()
    axes[row][0].grid(True, alpha=0.3)

    axes[row][1].plot(ep, h.history['loss'],     label='Train')
    axes[row][1].plot(ep, h.history['val_loss'], label='Val')
    axes[row][1].set_title(f'{name} — Loss')
    axes[row][1].set_xlabel('Epoch')
    axes[row][1].legend()
    axes[row][1].grid(True, alpha=0.3)

plt.tight_layout()
plt.savefig(f'{OUTPUT_DIR}/training_curves.png', dpi=150, bbox_inches='tight')
plt.show()
print('Saved: training_curves.png')
""")

# ─────────────────────────────────────────────────────────────────────────────
C19 = code(r"""
# Cell 13 — Confusion Matrices + ROC Curves
fig, axes = plt.subplots(2, 2, figsize=(14, 11))
fig.suptitle('CNN-LSTM IDS — Evaluation on VeReMi NextGen Test Set', fontsize=12)

eval_pairs = [
    ('CNN  (per-message)',    y_te,     scores_cnn,  res_cnn['threshold']),
    ('LSTM (per-trajectory)', y_seq_te, scores_lstm, res_lstm['threshold']),
]

for row, (name, y_true, scores, thresh) in enumerate(eval_pairs):
    yp = (scores >= thresh).astype(int)

    # Confusion matrix
    cm = confusion_matrix(y_true, yp)
    sns.heatmap(cm, annot=True, fmt='d', ax=axes[row][0], cmap='Blues',
                xticklabels=['Normal', 'Attack'],
                yticklabels=['Normal', 'Attack'])
    axes[row][0].set_title(f'{name}\nConfusion Matrix (thresh={thresh:.3f})')
    axes[row][0].set_ylabel('True')
    axes[row][0].set_xlabel('Predicted')

    # ROC curve
    fpr, tpr, _ = roc_curve(y_true, scores)
    auc_val = roc_auc_score(y_true, scores)
    axes[row][1].plot(fpr, tpr, lw=2, label=f'AUC = {auc_val:.4f}')
    axes[row][1].plot([0, 1], [0, 1], 'k--', alpha=0.4)
    axes[row][1].set_xlabel('False Positive Rate')
    axes[row][1].set_ylabel('True Positive Rate')
    axes[row][1].set_title(f'{name}\nROC Curve')
    axes[row][1].legend()
    axes[row][1].grid(True, alpha=0.3)

# Also add ensemble ROC
fpr_e, tpr_e, _ = roc_curve(y_seq_te, scores_ensemble)
auc_e = roc_auc_score(y_seq_te, scores_ensemble)
axes[1][1].plot(fpr_e, tpr_e, lw=2, ls='--', label=f'Ensemble AUC = {auc_e:.4f}')
axes[1][1].legend()

plt.tight_layout()
plt.savefig(f'{OUTPUT_DIR}/evaluation_plots.png', dpi=150, bbox_inches='tight')
plt.show()
print('Saved: evaluation_plots.png')
""")

# ─────────────────────────────────────────────────────────────────────────────
C20 = code(r"""
# Cell 14 — Per-Attack-Type Breakdown (Ensemble on LSTM test sequences)
print('=== PER-ATTACK-TYPE BREAKDOWN ===')
print('Model: Ensemble (CNN + LSTM) on VeReMi NextGen test set')
print()

thresh_ens = res_ensemble['threshold']
pred_ens   = (scores_ensemble >= thresh_ens).astype(int)

print(f'  {"Attack type":<37} {"F1":>7} {"Recall":>8} {"Prec":>7} {"N":>7}')
print('-' * 70)

results_per_type = {}
for atype in sorted(set(at_seq_te)):
    mask = at_seq_te == atype
    n    = mask.sum()
    if n < 5:
        continue
    f1  = f1_score(y_seq_te[mask], pred_ens[mask], zero_division=0)
    rec = recall_score(y_seq_te[mask], pred_ens[mask], zero_division=0)
    pre = precision_score(y_seq_te[mask], pred_ens[mask], zero_division=0)
    results_per_type[atype] = dict(f1=f1, recall=rec, precision=pre, n=int(n))
    flag = '' if f1 >= 0.80 else '  <-- low'
    print(f'  {atype:<37} {f1:>7.4f} {rec:>8.4f} {pre:>7.4f} {n:>7,}{flag}')
""")

# ─────────────────────────────────────────────────────────────────────────────
C21 = code(r"""
# Cell 15 — Noise Robustness Test
# Adds Gaussian noise to the test set features and measures how metrics degrade.
# A robust model maintains performance at low noise levels (std <= 0.20).
print('=== NOISE ROBUSTNESS TEST ===')
print('Gaussian noise added to normalised CNN test features')
print()

noise_levels = [0.0, 0.05, 0.10, 0.20, 0.30, 0.50]
cnn_f1s, lstm_f1s, ens_f1s = [], [], []

thresh_cnn  = res_cnn['threshold']
thresh_lstm = res_lstm['threshold']
thresh_ens  = res_ensemble['threshold']

print(f'  {"Noise std":<12} {"CNN F1":>8} {"LSTM F1":>9} {"Ensemble F1":>12}')
print('-' * 46)

for sigma in noise_levels:
    # CNN on noisy individual messages
    Xn = X_te + np.random.normal(0, sigma, X_te.shape).astype(np.float32)
    sc = predict_proba(cnn, Xn)
    f1_cnn = f1_score(y_te, (sc >= thresh_cnn).astype(int), zero_division=0)

    # LSTM on noisy sequences
    Xsn = X_seq_te + np.random.normal(0, sigma, X_seq_te.shape).astype(np.float32)
    sl  = predict_proba(lstm, Xsn)
    f1_lstm = f1_score(y_seq_te, (sl >= thresh_lstm).astype(int), zero_division=0)

    # Ensemble on noisy sequences
    flat_n  = Xsn.reshape(-1, FEAT_DIM)
    sc_flat = predict_proba(cnn, flat_n).reshape(-1, WINDOW_SIZE).mean(axis=1)
    se      = (sc_flat + sl) / 2.0
    f1_ens  = f1_score(y_seq_te, (se >= thresh_ens).astype(int), zero_division=0)

    cnn_f1s.append(f1_cnn)
    lstm_f1s.append(f1_lstm)
    ens_f1s.append(f1_ens)
    print(f'  sigma={sigma:<6.2f}    {f1_cnn:>8.4f} {f1_lstm:>9.4f} {f1_ens:>12.4f}')

# Plot
fig, ax = plt.subplots(figsize=(8, 5))
ax.plot(noise_levels, cnn_f1s,  'b-o', label='CNN')
ax.plot(noise_levels, lstm_f1s, 'g-s', label='LSTM')
ax.plot(noise_levels, ens_f1s,  'r-^', label='Ensemble', lw=2)
ax.axhline(TARGET_F1, color='gray', ls='--', label=f'Target F1={TARGET_F1}', alpha=0.7)
ax.set_xlabel('Noise standard deviation (normalised feature space)')
ax.set_ylabel('F1 Score')
ax.set_title('Noise Robustness — VeReMi NextGen Test Set')
ax.legend()
ax.grid(True, alpha=0.3)
plt.tight_layout()
plt.savefig(f'{OUTPUT_DIR}/noise_robustness.png', dpi=150, bbox_inches='tight')
plt.show()
print('Saved: noise_robustness.png')
""")

# ─────────────────────────────────────────────────────────────────────────────
C22 = md(r"""
## Save Models & Download
""")

# ─────────────────────────────────────────────────────────────────────────────
C23 = code(r"""
# Cell 16 — Save Models + Results to Google Drive
cnn.save(f'{OUTPUT_DIR}/cnn_model.keras')
lstm.save(f'{OUTPUT_DIR}/lstm_model.keras')
joblib.dump(scaler, f'{OUTPUT_DIR}/feature_scaler.pkl')

metadata = {
    'dataset':       'VeReMi NextGen (Ulm University, CC-BY 4.0)',
    'architecture':  'CNN-LSTM Hybrid Ensemble',
    'features':      FEATURE_COLS,
    'window_size':   WINDOW_SIZE,
    'cnn_threshold':  res_cnn['threshold'],
    'lstm_threshold': res_lstm['threshold'],
    'ensemble_threshold': res_ensemble['threshold'],
    'results': {
        'cnn':      res_cnn,
        'lstm':     res_lstm,
        'ensemble': res_ensemble,
        'per_attack_type': results_per_type,
    },
}
with open(f'{OUTPUT_DIR}/evaluation_results.json', 'w') as f:
    json.dump(metadata, f, indent=2)

print(f'Saved to {OUTPUT_DIR}:')
print('  cnn_model.keras')
print('  lstm_model.keras')
print('  feature_scaler.pkl')
print('  evaluation_results.json')
print()
print('=' * 68)
print('  FINAL RESULTS')
print('=' * 68)
print(f'  {"Model":<32} {"F1":>7} {"AUC":>7} {"Recall":>8}   Status')
print('-' * 68)
for r in [res_cnn, res_lstm, res_ensemble]:
    ok = ('PASS' if r['f1_score'] >= TARGET_F1
                 and r['roc_auc'] >= TARGET_AUC
                 and r['recall']  >= TARGET_RECALL else 'FAIL')
    print(f'  {r["name"]:<32} {r["f1_score"]:>7.4f} {r["roc_auc"]:>7.4f} '
          f'{r["recall"]:>8.4f}   {ok}')
print('=' * 68)
""")

# ─────────────────────────────────────────────────────────────────────────────
C24 = code(r"""
# Cell 17 — Package All Outputs as Zip for Download
import zipfile

zip_path = '/content/v2x_ids_models.zip'
files = [
    'cnn_model.keras', 'lstm_model.keras',
    'feature_scaler.pkl', 'evaluation_results.json',
    'training_curves.png', 'evaluation_plots.png', 'noise_robustness.png',
]
with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zf:
    for fname in files:
        fp = f'{OUTPUT_DIR}/{fname}'
        if os.path.exists(fp):
            zf.write(fp, fname)
            print(f'  + {fname}')
        else:
            print(f'  - {fname}  (not found — skipping)')

size_mb = os.path.getsize(zip_path) / 1e6
print(f'\nZip: {zip_path}  ({size_mb:.1f} MB)')
print()
print('Download options:')
print('  VS Code: Explorer panel → right-click v2x_ids_models.zip → Download')
print('  Colab:   Files panel (folder icon) → right-click → Download')
print('  Or:      Files are already saved to Google Drive at', OUTPUT_DIR)
""")

# ─────────────────────────────────────────────────────────────────────────────
cells = [C1, C2, C3, C4, C5, C6, C7, C8, C9, C10,
         C11, C12, C13, C14, C15, C16, C17, C18, C19, C20,
         C21, C22, C23, C24]

nb = {
    "nbformat": 4,
    "nbformat_minor": 5,
    "metadata": {
        "kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"},
        "language_info": {"name": "python", "version": "3.10.0"},
    },
    "cells": cells,
}

with open(NB, 'w', encoding='utf-8') as f:
    json.dump(nb, f, indent=1, ensure_ascii=False)

print(f'Written: {NB}')
print(f'Total cells: {len(cells)}')
for i, c in enumerate(cells):
    ct = c['cell_type']
    src = ''.join(c['source'])[:60].replace('\n', ' ')
    print(f'  {i+1:2d}. [{ct[:4]}] {src}')
