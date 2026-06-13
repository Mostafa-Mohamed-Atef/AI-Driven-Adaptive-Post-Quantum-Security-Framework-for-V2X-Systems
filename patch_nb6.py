import json

NB = r'e:/Dev/Graduation Project 2026/AI-Driven Adaptive Post-Quantum Security Framework for V2X Systems/train_ids_colab.ipynb'
with open(NB, encoding='utf-8') as f:
    nb = json.load(f)

DRIVE_PATH = '/content/drive/MyDrive/veremi_ng_train.csv'

updates = {}

# Cell 2 (a7dc1ca2) — restore Drive mount
updates['a7dc1ca2'] = '''\
# Cell 2 — Mount Google Drive + output directory
from google.colab import drive
drive.mount('/content/drive')

import os
OUTPUT_DIR = '/content/drive/MyDrive/V2X_IDS_Models'
os.makedirs(OUTPUT_DIR, exist_ok=True)
print(f'Output directory: {OUTPUT_DIR}')
'''

# Cell 3 (09398e66) — remove MisbehaviorX, point dataset to Drive
updates['09398e66'] = '''\
# Cell 3 — Configuration
import os

VEREMI_NG_PATH = '/content/drive/MyDrive/veremi_ng_train.csv'

OUTPUT_DIR = '/content/drive/MyDrive/V2X_IDS_Models'
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Phase 1 — Pre-training (general network anomaly)
PRETRAIN_NORMAL  = 350_000
PRETRAIN_ATTACK  = 150_000
PRETRAIN_EPOCHS  = 20

# Phase 2 — Fine-tuning (VeReMi NextGen real data)
FINETUNE_NORMAL  = 200_000
FINETUNE_ATTACK  = 150_000
FINETUNE_EPOCHS  = 15

BATCH_SIZE  = 256
WINDOW_SIZE = 20
FEAT_DIM    = 10

TARGET_F1     = 0.951
TARGET_AUC    = 0.960
TARGET_RECALL = 0.968

print("Configuration:")
print(f"  Dataset:   {VEREMI_NG_PATH}")
print(f"  Output:    {OUTPUT_DIR}")
print(f"  Pre-train: {PRETRAIN_NORMAL+PRETRAIN_ATTACK:,} samples  ({PRETRAIN_EPOCHS} epochs)")
print(f"  Batch: {BATCH_SIZE}  |  Window: {WINDOW_SIZE}  |  Features: {FEAT_DIM}")
print(f"  Dataset exists: {os.path.exists(VEREMI_NG_PATH)}")
'''

# Cell 11 (abfca893) — use Drive path, no fallback auto-detection
updates['abfca893'] = '''\
# Cell 11 — Phase 2 data: VeReMi NextGen from Google Drive
print('=== PHASE 2: FINE-TUNING DATA ===')

FEATURE_COLS = ['pos_x','pos_y','spd','hed','acl',
                'inter_msg_gap','pos_noise_mag','spd_noise','hed_noise','acl_noise']

if not os.path.exists(VEREMI_NG_PATH):
    raise FileNotFoundError(
        f"Dataset not found: {VEREMI_NG_PATH}\\n"
        "Make sure veremi_ng_train.csv is in your Google Drive root (My Drive)."
    )

print(f'Loading: {VEREMI_NG_PATH}')
df = pd.read_csv(VEREMI_NG_PATH)
print(f'  Rows: {len(df):,}  |  attack ratio: {100*df["label"].mean():.1f}%')
print(f'  Attack types ({df["attack_type"].nunique()}): {sorted(df["attack_type"].unique())}')

X_raw = df[FEATURE_COLS].fillna(0).values.astype(np.float32)
y_all = df['label'].values.astype(np.float32)

scaler = StandardScaler()
X_sc   = scaler.fit_transform(X_raw).astype(np.float32)

Xv_tr, Xv_te, yv_tr, yv_te = train_test_split(
    X_sc, y_all, test_size=0.2, random_state=42, stratify=y_all)

# LSTM: per-vehicle temporal sequences (stride=5 for more windows)
print('  Building LSTM sequences (stride=5, per-vehicle trajectories)...')
df2 = pd.DataFrame(X_sc, columns=FEATURE_COLS)
df2['sender_id']   = df['sender_id'].values
df2['attack_type'] = df['attack_type'].values
df2['rcvTime']     = pd.to_numeric(df['rcvTime'], errors='coerce')
df2['label']       = y_all

seqs, seq_labels = [], []
for (sid, atype), grp in df2.groupby(['sender_id', 'attack_type']):
    grp  = grp.sort_values('rcvTime')
    feat = grp[FEATURE_COLS].values.astype(np.float32)
    lbls = grp['label'].values
    if len(feat) < WINDOW_SIZE:
        continue
    for i in range(0, len(feat) - WINDOW_SIZE + 1, 5):
        seqs.append(feat[i:i+WINDOW_SIZE])
        seq_labels.append(1.0 if lbls[i:i+WINDOW_SIZE].mean() > 0.3 else 0.0)

Xv_seq = np.array(seqs,       dtype=np.float32)
yv_seq = np.array(seq_labels, dtype=np.float32)
Xv_seq_tr, Xv_seq_te, yv_seq_tr, yv_seq_te = train_test_split(
    Xv_seq, yv_seq, test_size=0.2, random_state=42, stratify=yv_seq)

print(f'  CNN  train {Xv_tr.shape}  test {Xv_te.shape}  attack {100*yv_tr.mean():.1f}%')
print(f'  LSTM train {Xv_seq_tr.shape}  test {Xv_seq_te.shape}  attack {100*yv_seq_tr.mean():.1f}%')
print('  VeReMi NextGen (Ulm University, CC-BY 4.0)')
'''

# Cell 19 (d461ddce) — remove misbx references from results
updates['d461ddce'] = '''\
# Cell 19 — Save final models
cnn.save(os.path.join(OUTPUT_DIR, 'cnn_model.keras'))
lstm.save(os.path.join(OUTPUT_DIR, 'lstm_model.keras'))
joblib.dump(scaler, os.path.join(OUTPUT_DIR, 'feature_scaler.pkl'))
print(f'Models saved to {OUTPUT_DIR}')

results = {
    'dataset': 'VeReMi NextGen (Ulm University, CC-BY 4.0)',
    'strategy': 'Transfer learning: synthetic pre-train + VeReMi NextGen fine-tune',
    'phase1': {'n_normal': PRETRAIN_NORMAL, 'n_attack': PRETRAIN_ATTACK, 'epochs': PRETRAIN_EPOCHS},
    'phase2': {'source': 'VeReMi NextGen', 'attack_types': list(V2XDatasetGenerator.ATTACK_NAMES.values())},
    'cnn_results':  cnn_res_v2x,
    'lstm_results': lstm_res_v2x,
}
with open(os.path.join(OUTPUT_DIR, 'evaluation_results.json'), 'w') as f:
    json.dump(results, f, indent=2)

print()
print('='*62)
print('  FINAL RESULTS SUMMARY')
print('='*62)
print(f'  {"Model":<30} {"F1":>7} {"AUC":>7} {"Recall":>8}  Status')
print('-'*62)
for name, r in [('CNN  (VeReMi NextGen)', cnn_res_v2x),
                ('LSTM (VeReMi NextGen)', lstm_res_v2x)]:
    if r:
        ok = 'PASS' if r['f1_score']>=TARGET_F1 and r['roc_auc']>=TARGET_AUC and r['recall']>=TARGET_RECALL else 'FAIL'
        print(f'  {name:<30} {r["f1_score"]:>7.4f} {r["roc_auc"]:>7.4f} {r["recall"]:>8.4f}  {ok}')
print('='*62)
'''

# Remove MisbehaviorX cells entirely (delete cell 14 optional benchmark markdown + cell 14 code + cell 16 eval)
REMOVE_IDS = {'8a4088dd', '60a129d7', 'ab31a62c', 'xDlK7IYl'}

before = len(nb['cells'])
nb['cells'] = [c for c in nb['cells'] if c.get('id') not in REMOVE_IDS]
print(f'Removed {before - len(nb["cells"])} MisbehaviorX cells')

# Apply source updates
changed = 0
for cell in nb['cells']:
    cid = cell.get('id', '')
    if cid in updates:
        cell['source'] = updates[cid].splitlines(keepends=True)
        print(f'Updated: {cid}')
        changed += 1

with open(NB, 'w', encoding='utf-8') as f:
    json.dump(nb, f, indent=1, ensure_ascii=False)

print(f'Done. {changed} updated, {before - len(nb["cells"])} removed. Total cells: {len(nb["cells"])}')
