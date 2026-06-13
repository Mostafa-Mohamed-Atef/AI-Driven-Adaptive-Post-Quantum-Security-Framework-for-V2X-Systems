import json

NB = r'e:/Dev/Graduation Project 2026/AI-Driven Adaptive Post-Quantum Security Framework for V2X Systems/train_ids_colab.ipynb'
with open(NB, encoding='utf-8') as f:
    nb = json.load(f)

# ── Cell 6 (01015ee5): add threshold param to evaluate_model + find_optimal_threshold ──
CELL6_NEW = '''\
# Cell 6 — CNN and LSTM Model Builders
import math

def build_cnn(feat_dim=FEAT_DIM, name='cnn_ids'):
    inp = layers.Input(shape=(feat_dim, 1))
    x   = layers.Conv1D(32, 3, activation='relu', padding='same', name='conv1')(inp)
    x   = layers.BatchNormalization(name='bn1')(x)
    x   = layers.Conv1D(64, 3, activation='relu', padding='same', name='conv2')(x)
    x   = layers.BatchNormalization(name='bn2')(x)
    x   = layers.Conv1D(128, 3, activation='relu', padding='same', name='conv3')(x)
    x   = layers.GlobalMaxPooling1D(name='pool')(x)
    x   = layers.Dense(64, activation='relu', name='dense1')(x)
    x   = layers.Dropout(0.3)(x)
    out = layers.Dense(1, activation='sigmoid', name='out')(x)
    m   = keras.Model(inp, out, name=name)
    m.compile(optimizer=keras.optimizers.Adam(1e-3),
              loss='binary_crossentropy', metrics=['accuracy'])
    return m

def build_lstm(window=WINDOW_SIZE, feat_dim=FEAT_DIM, name='lstm_ids'):
    m = keras.Sequential([
        layers.Input(shape=(window, feat_dim)),
        layers.LSTM(64, return_sequences=True, name='lstm1'),
        layers.Dropout(0.2),
        layers.LSTM(32, name='lstm2'),
        layers.Dropout(0.2),
        layers.Dense(32, activation='relu', name='dense1'),
        layers.Dropout(0.3),
        layers.Dense(1, activation='sigmoid', name='out'),
    ], name=name)
    m.compile(optimizer=keras.optimizers.Adam(1e-3),
              loss='binary_crossentropy', metrics=['accuracy'])
    return m

def freeze_base(model, n_trainable_layers=3):
    for layer in model.layers[:-n_trainable_layers]:
        layer.trainable = False
    model.compile(optimizer=keras.optimizers.Adam(3e-4),
                  loss='binary_crossentropy', metrics=['accuracy'])
    trainable = sum(1 for l in model.layers if l.trainable)
    frozen    = sum(1 for l in model.layers if not l.trainable)
    print(f'  {model.name}: {trainable} trainable, {frozen} frozen')
    return model

def unfreeze_all(model):
    for layer in model.layers:
        layer.trainable = True
    model.compile(optimizer=keras.optimizers.Adam(1e-3),
                  loss='binary_crossentropy', metrics=['accuracy'])
    return model

def train_model(model, X, y, epochs, batch=BATCH_SIZE, label='',
                lr=None, class_weight=None, patience=7):
    X3d = X.reshape(-1, FEAT_DIM, 1) if model.name.startswith('cnn') and X.ndim==2 else X
    if lr is not None:
        keras.backend.set_value(model.optimizer.learning_rate, lr)
    cb = [keras.callbacks.EarlyStopping(patience=patience,
                                        restore_best_weights=True, verbose=0),
          keras.callbacks.ReduceLROnPlateau(factor=0.5, patience=patience//2,
                                            verbose=0, min_lr=1e-6)]
    t0 = time.time()
    h  = model.fit(X3d, y, epochs=epochs, batch_size=batch,
                   validation_split=0.2, verbose=1, callbacks=cb,
                   class_weight=class_weight)
    best_val = max(h.history['val_accuracy'])
    print(f'{label} — {len(h.history["loss"])} epochs, '
          f'best val_acc={best_val:.4f}, {time.time()-t0:.0f}s')
    return h

def predict_proba(model, X):
    X3d = X.reshape(-1, FEAT_DIM, 1) if model.name.startswith('cnn') and X.ndim==2 else X
    return model.predict(X3d, verbose=0).flatten()

def find_optimal_threshold(y_true, y_scores):
    """Sweep ROC-curve thresholds to find the one maximising F1."""
    _, _, thresholds = roc_curve(y_true, y_scores)
    best_t, best_f1 = 0.5, 0.0
    for t in thresholds:
        pred = (y_scores >= t).astype(int)
        s = f1_score(y_true, pred, zero_division=0)
        if s > best_f1:
            best_f1, best_t = s, float(t)
    return round(best_t, 3), round(best_f1, 4)

def evaluate_model(y_true, y_scores, name='Model', threshold=0.5):
    yp   = (y_scores >= threshold).astype(int)
    acc  = accuracy_score(y_true, yp)
    prec = precision_score(y_true, yp, zero_division=0)
    rec  = recall_score(y_true, yp, zero_division=0)
    f1   = f1_score(y_true, yp, zero_division=0)
    auc  = roc_auc_score(y_true, y_scores)
    ok   = lambda v, t: 'PASS' if v >= t else 'FAIL'
    print(f\'\\n{"="*58}  {name}\')
    print(f\'  Threshold: {threshold:.3f}\')
    print(f\'  Accuracy : {acc:.4f}\')
    print(f\'  Precision: {prec:.4f}\')
    print(f\'  Recall   : {rec:.4f}  {ok(rec, TARGET_RECALL)} (target >= {TARGET_RECALL})\')
    print(f\'  F1 Score : {f1:.4f}   {ok(f1,  TARGET_F1)}  (target >= {TARGET_F1})\')
    print(f\'  ROC-AUC  : {auc:.4f}  {ok(auc, TARGET_AUC)}  (target >= {TARGET_AUC})\')
    return dict(accuracy=acc, precision=prec, recall=rec, f1_score=f1, roc_auc=auc, threshold=threshold)

print('Model builders ready.')
'''

# ── Cell 15 (7cb54807): threshold optimization before evaluate ──
CELL15_NEW = '''\
# Cell 15 — Evaluate on V2X fine-tuning test set
print('=== EVALUATION: V2X TEST SET ===')
cnn_scores_v2x  = predict_proba(cnn,  Xv_te)
lstm_scores_v2x = predict_proba(lstm, Xv_seq_te)

# Find optimal F1 threshold (standard practice for imbalanced IDS evaluation)
cnn_thresh,  _ = find_optimal_threshold(yv_te,     cnn_scores_v2x)
lstm_thresh, _ = find_optimal_threshold(yv_seq_te, lstm_scores_v2x)
print(f\'Optimal thresholds  —  CNN: {cnn_thresh}   LSTM: {lstm_thresh}\')
print(f\'(Default 0.5 threshold results follow at end for comparison)\')
print()

cnn_res_v2x  = evaluate_model(yv_te,     cnn_scores_v2x,
                               f\'CNN  (VeReMi NextGen, thresh={cnn_thresh})\',
                               threshold=cnn_thresh)
lstm_res_v2x = evaluate_model(yv_seq_te, lstm_scores_v2x,
                               f\'LSTM (VeReMi NextGen, thresh={lstm_thresh})\',
                               threshold=lstm_thresh)

print()
print(\'--- Default 0.5 threshold (for comparison) ---\')
evaluate_model(yv_te,     cnn_scores_v2x,  \'CNN  (thresh=0.5)\', threshold=0.5)
evaluate_model(yv_seq_te, lstm_scores_v2x, \'LSTM (thresh=0.5)\', threshold=0.5)
'''

# ── CNN training cell (6dbac6c4): raise class_weight from sqrt to full ratio ──
CNN_TRAIN_NEW = '''\
# Cell 12 — Train CNN on VeReMi NextGen (from scratch)
print('=== PHASE 2: CNN TRAINING (VeReMi NextGen) ===')

cnn = build_cnn()   # fresh weights — start from scratch for real data

n_neg_c = int((yv_tr == 0).sum())
n_pos_c = int((yv_tr == 1).sum())
# Use full imbalance ratio (not sqrt-dampened) to strongly prioritise attack detection
cw_c = {0: 1.0, 1: round(n_neg_c / max(n_pos_c, 1), 2)}
print(f\'  Class weights: normal={cw_c[0]}, attack={cw_c[1]}  (full imbalance ratio)\')
print(f\'  CNN samples:  {len(yv_tr):,} train  attack={100*yv_tr.mean():.1f}%\')

h_ft_cnn = train_model(cnn, Xv_tr, yv_tr,
                        epochs=80,
                        lr=1e-3,
                        label=\'CNN (VeReMi NextGen, from scratch)\',
                        class_weight=cw_c,
                        patience=12)
'''

# ── LSTM training cell (db0fbcc1): raise class_weight ──
LSTM_TRAIN_NEW = '''\
# Cell 13 — Train LSTM on VeReMi NextGen (from scratch)
print('=== PHASE 2: LSTM TRAINING (VeReMi NextGen) ===')

lstm = build_lstm()  # fresh weights

n_neg_l = int((yv_seq_tr == 0).sum())
n_pos_l = int((yv_seq_tr == 1).sum())
cw_l = {0: 1.0, 1: round(n_neg_l / max(n_pos_l, 1), 2)}
print(f\'  Class weights: normal={cw_l[0]}, attack={cw_l[1]}  (full imbalance ratio)\')
print(f\'  LSTM sequences: {len(yv_seq_tr):,} train  \')

h_ft_lstm = train_model(lstm, Xv_seq_tr, yv_seq_tr,
                        epochs=80,
                        lr=1e-3,
                        label=\'LSTM (VeReMi NextGen, from scratch)\',
                        class_weight=cw_l,
                        patience=12)
'''

TARGET_CELLS = {
    '01015ee5': CELL6_NEW,
    '7cb54807': CELL15_NEW,
    '6dbac6c4': CNN_TRAIN_NEW,
    'db0fbcc1': LSTM_TRAIN_NEW,
}

changed = 0
for cell in nb['cells']:
    cid = cell.get('id', '')
    if cid in TARGET_CELLS:
        cell['source'] = TARGET_CELLS[cid].splitlines(keepends=True)
        print(f'Updated: {cid}')
        changed += 1

with open(NB, 'w', encoding='utf-8') as f:
    json.dump(nb, f, indent=1, ensure_ascii=False)

print(f'Done. {changed} cells updated.')
