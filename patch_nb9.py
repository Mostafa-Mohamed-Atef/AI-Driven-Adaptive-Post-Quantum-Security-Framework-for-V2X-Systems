"""
patch_nb9.py — Add 5 engineered features to fix zero-detection attack types.

Changes:
  Cell 3  (80c23fde90d3): FEAT_DIM 10 → 15
  Cell 6  (5cd2ca27e65e): add feature-table note in load cell
  NEW Cell 6b            : kinematic + spatial feature engineering
  Cell 7  (f1a620cf5757): expand FEATURE_COLS to 15
  Markdown (94f5925c47cc): update feature table
"""

import json, uuid

NB = r'e:/Dev/Graduation Project 2026/AI-Driven Adaptive Post-Quantum Security Framework for V2X Systems/train_ids_colab.ipynb'

with open(NB, encoding='utf-8') as f:
    nb = json.load(f)

# ── Cell 3: FEAT_DIM = 15 ────────────────────────────────────────────────────
CELL3_NEW = """\
# Cell 3 — Configuration
import os

VEREMI_NG_PATH = '/content/drive/MyDrive/veremi_ng_train.csv'
OUTPUT_DIR     = '/content/drive/MyDrive/V2X_IDS_Models'
os.makedirs(OUTPUT_DIR, exist_ok=True)

BATCH_SIZE  = 256
WINDOW_SIZE = 20    # LSTM: messages per sequence window
FEAT_DIM    = 15    # 10 original BSM + 5 engineered kinematic/spatial features
STRIDE      = 5     # LSTM: window stride
TEST_SPLIT  = 0.2   # 80 / 20 train-test split

TARGET_F1     = 0.90
TARGET_AUC    = 0.92
TARGET_RECALL = 0.90

print('Configuration')
print(f'  Dataset  : {VEREMI_NG_PATH}')
print(f'  Output   : {OUTPUT_DIR}')
print(f'  Batch={BATCH_SIZE}  Window={WINDOW_SIZE}  Features={FEAT_DIM}  Stride={STRIDE}')
print(f'  Targets  : F1>={TARGET_F1}  AUC>={TARGET_AUC}  Recall>={TARGET_RECALL}')
print(f'  File exists: {os.path.exists(VEREMI_NG_PATH)}')
"""

# ── New Cell 6b: feature engineering ─────────────────────────────────────────
CELL6B_CODE = """\
# Cell 6b — Kinematic Consistency + Spatial Density Features
# All derived from existing real data — no synthetic samples added.
#
# Targets the zero-detection attack types:
#   timeDelayAttack       → kinematic_error, speed_consistency spike on replayed position
#   trafficCongestionSybil → spatial_density spikes (many fake vehicles in one cell)
#   positionMirroring     → kinematic_error, heading_consistency catch mirrored trajectory
#   feignedBraking        → accel_consistency catches inconsistent deceleration report
#   suddenConstantSpeed   → accel_consistency catches constant speed with near-zero acl

print('=== FEATURE ENGINEERING (real data only) ===')

df = df.sort_values(['sender_id', 'rcvTime']).reset_index(drop=True)
g  = df.groupby('sender_id', sort=False)

dt       = g['rcvTime'].diff().clip(lower=0.05)   # time step (seconds), min 50 ms
dx       = g['pos_x'].diff()                       # x displacement
dy       = g['pos_y'].diff()                       # y displacement
spd_prev = g['spd'].shift(1)                       # previous reported speed

# 1. kinematic_error
#    Expected displacement from kinematic model (prev_spd × heading × dt)
#    vs actual position change. Replay attack breaks this because the replayed
#    position is inconsistent with the vehicle's current trajectory.
exp_dx = spd_prev * np.cos(df['hed']) * dt
exp_dy = spd_prev * np.sin(df['hed']) * dt
df['kinematic_error'] = np.sqrt((dx - exp_dx)**2 + (dy - exp_dy)**2)

# 2. speed_consistency
#    Speed implied by consecutive position change vs reported speed.
#    Sybil fake positions jump inconsistently; replay positions are stale.
pos_spd = np.sqrt(dx**2 + dy**2) / dt
df['speed_consistency'] = (pos_spd - df['spd']).abs()

# 3. heading_consistency
#    Actual movement direction vs reported heading (angular error in [0, pi]).
#    Mirrored positions produce movement in the wrong direction.
move_hed = np.arctan2(dy, dx)
raw_diff = ((move_hed - df['hed']) % (2 * np.pi))
df['heading_consistency'] = np.minimum(raw_diff, 2 * np.pi - raw_diff)

# 4. accel_consistency
#    Acceleration derived from consecutive speed readings vs reported acl.
#    Feigned braking reports large deceleration that doesn't match speed change.
df['accel_consistency'] = ((df['spd'] - spd_prev) / dt - df['acl']).abs()

# 5. spatial_density
#    Number of distinct sender_ids in the same 100 m × 100 m grid cell per
#    1-second time bin. Sybil attack injects many fake vehicles in one spot.
df['_gx'] = (df['pos_x'] / 100).round().astype(int)
df['_gy'] = (df['pos_y'] / 100).round().astype(int)
df['_tb'] = df['rcvTime'].round().astype(int)
df['spatial_density'] = (
    df.groupby(['_tb', '_gx', '_gy'])['sender_id']
      .transform('nunique')
      .astype(np.float32)
)
df.drop(columns=['_gx', '_gy', '_tb'], inplace=True)

# Fill NaN (first message per vehicle has no previous) and cap extreme outliers
NEW_COLS = ['kinematic_error', 'speed_consistency', 'heading_consistency',
            'accel_consistency', 'spatial_density']
df[NEW_COLS] = df[NEW_COLS].fillna(0).clip(upper=1e4)

print(f'  {"Feature":<25}  {"mean":>9}  {"std":>9}  {"max":>10}')
print('-' * 60)
for col in NEW_COLS:
    print(f'  {col:<25}  {df[col].mean():>9.3f}  {df[col].std():>9.3f}  {df[col].max():>10.1f}')

print()
print('kinematic_error by attack type (attack should be >> normal):')
for atype, val in df.groupby('attack_type')['kinematic_error'].mean() \\
                    .sort_values(ascending=False).items():
    marker = ' <-- target' if atype in ('timeDelayAttack', 'positionMirroring') else ''
    print(f'  {atype:<37}  {val:>8.3f}{marker}')

print()
print('spatial_density by attack type (Sybil should be >> normal):')
for atype, val in df.groupby('attack_type')['spatial_density'].mean() \\
                    .sort_values(ascending=False).items():
    marker = ' <-- target' if atype == 'trafficCongestionSybil' else ''
    print(f'  {atype:<37}  {val:>8.2f}{marker}')
"""

# ── Cell 7: updated FEATURE_COLS (15 features) ───────────────────────────────
CELL7_NEW = """\
# Cell 7 — Prepare CNN and LSTM Training Data
print('=== PREPARING TRAINING DATA ===')

FEATURE_COLS = [
    # Original 10 BSM fields
    'pos_x', 'pos_y', 'spd', 'hed', 'acl',
    'inter_msg_gap', 'pos_noise_mag', 'spd_noise', 'hed_noise', 'acl_noise',
    # 5 engineered kinematic / spatial features (Cell 6b)
    'kinematic_error', 'speed_consistency', 'heading_consistency',
    'accel_consistency', 'spatial_density',
]

X_raw = df[FEATURE_COLS].fillna(0).values.astype(np.float32)
y_all = df['label'].values.astype(np.float32)
at_all = df['attack_type'].values

scaler = StandardScaler()
X_sc   = scaler.fit_transform(X_raw).astype(np.float32)

X_tr, X_te, y_tr, y_te, at_tr, at_te = train_test_split(
    X_sc, y_all, at_all, test_size=TEST_SPLIT, random_state=42, stratify=y_all)

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

print(f'CNN   train {X_tr.shape}  test {X_te.shape}  attack {100*y_tr.mean():.1f}%  cw={cw_cnn[1]}')
print(f'LSTM  train {X_seq_tr.shape}  test {X_seq_te.shape}  attack {100*y_seq_tr.mean():.1f}%  cw={cw_lstm[1]}')
"""

# ── Dataset markdown: updated feature table ───────────────────────────────────
MD_DS_NEW = """\
## Dataset — VeReMi NextGen

**VeReMi NextGen** (Vehicle Reference Misbehaviour — Next Generation, Ulm University, 2023, CC-BY 4.0)

- 619,097 messages from 482 simulated vehicles in a highway scenario
- 14 attack types + normal baseline
- **15 features**: 10 original BSM fields + 5 engineered kinematic/spatial features

| Feature | Description |
|---------|-------------|
| `pos_x`, `pos_y` | GPS position (metres) |
| `spd` | Speed (m/s) |
| `hed` | Heading (radians) |
| `acl` | Longitudinal acceleration (m/s²) |
| `inter_msg_gap` | Time between consecutive messages (seconds) |
| `pos_noise_mag` | Position deviation from ground truth |
| `spd_noise`, `hed_noise`, `acl_noise` | Kinematic noise magnitudes |
| `kinematic_error` | Expected vs actual position displacement (kinematic model) |
| `speed_consistency` | Position-implied speed vs reported speed |
| `heading_consistency` | Movement direction vs reported heading (angular error) |
| `accel_consistency` | Speed-delta acceleration vs reported acceleration |
| `spatial_density` | Distinct vehicles per 100 m grid cell per second |
"""

# ── Apply updates to existing cells ──────────────────────────────────────────
UPDATES = {
    '80c23fde90d3': CELL3_NEW,
    'f1a620cf5757': CELL7_NEW,
    '94f5925c47cc': MD_DS_NEW,
}

changed = 0
cell6_idx = None

for i, cell in enumerate(nb['cells']):
    cid = cell.get('id', '')

    if cid in UPDATES:
        src = UPDATES[cid]
        cell['source'] = src.splitlines(keepends=True)
        if cell['cell_type'] == 'code':
            cell['outputs'] = []
            cell['execution_count'] = None
        changed += 1
        print(f'Updated: {cid}')

    if cid == '5cd2ca27e65e':
        cell6_idx = i

# ── Insert new Cell 6b right after Cell 6 ────────────────────────────────────
if cell6_idx is not None:
    new_cell = {
        'cell_type': 'code',
        'id': uuid.uuid4().hex[:8],
        'metadata': {},
        'source': CELL6B_CODE.splitlines(keepends=True),
        'outputs': [],
        'execution_count': None,
    }
    nb['cells'].insert(cell6_idx + 1, new_cell)
    print(f'Inserted Cell 6b (id={new_cell["id"]}) after Cell 6')
    changed += 1
else:
    print('ERROR: Cell 6 (5cd2ca27e65e) not found — cannot insert Cell 6b')

with open(NB, 'w', encoding='utf-8') as f:
    json.dump(nb, f, indent=1, ensure_ascii=False)

print(f'\nDone. {changed} changes applied.')
print('FEAT_DIM: 10 → 15')
print('New features: kinematic_error, speed_consistency, heading_consistency, accel_consistency, spatial_density')
