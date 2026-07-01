# AI-Driven Adaptive Post-Quantum Security Framework for V2X Systems

Graduation Project 2026 — E-JUST / Alexandria University

## Overview

This project implements an **AI-powered Intrusion Detection System (IDS)** for Vehicle-to-Everything (V2X) communication networks. The core model is **ST-GAT** (Spatio-Temporal Graph Attention Transformer), a 4-stream deep learning architecture that detects 14 attack types in vehicular networks with high accuracy.

## Architecture

ST-GAT fuses four complementary views of each 20-BSM sliding window:

| Stream | Component | Output Dim |
|--------|-----------|-----------|
| A | Temporal Transformer (positional encoding + 2-head attention) | 128 |
| B | iTransformer (feature-axis attention) | 64 |
| C | 2-Layer Graph Attention Network (GAT) | 128 |
| D | Window Aggregate MLP | 64 |

The four streams are concatenated (384-d) → FC(192) → sigmoid binary classifier.

**Loss**: Focal Loss (γ=2.0, α=0.75) + per-attack inverse-frequency sample weights.

## Dataset

**VeReMi NextGen** — Vehicular Reference Misbehavior dataset (highway scenario):

- **619,097** Basic Safety Messages (BSMs)
- **14 attack types** + normal (binary label)
- **~422 unique sender IDs**

| Split | Senders | Windows (approx.) |
|-------|---------|-------------------|
| Train | ~303 | ~122,047 (normal upsampled to 25%) |
| Val   | ~34  | ~13,554 |
| Test  | ~85  | ~33,925 |

Split is **vehicle-ID-stratified** so no sender's time series spans multiple splits — eliminates monitoring-signal leakage.

## Key Results

Evaluated on the held-out test set (threshold = 0.687, tuned on val):

| Metric | Value |
|--------|-------|
| F1 Score | **0.9913** |
| ROC-AUC | **0.9923** |
| Recall | **0.9886** |
| Precision | **0.9940** |
| Accuracy | **0.9838** |
| MCC | **0.8699** |
| Normal Specificity | 0.9125 |

### Per-Attack F1 (highlights)

| Attack | F1 | Recall |
|--------|----|--------|
| timeDelayAttack | 0.9348 | 0.8776 |
| trafficCongestionSybil | 0.9995 | 0.9990 |
| All others | ≥ 0.9980 | ≥ 0.9965 |

## Training Pipeline

**Stage 1 — Base Training**: LR=1e-3, batch=256, epochs=100, patience=15. Uses a clean vehicle-stratified validation set (`validation_data=`). Normal windows upsampled to 25% of training set (reducing effective class weight from 14.6× to ~3×).

**Stage 2 — Targeted Fine-Tune**: Boosts `timeDelayAttack` sample weight ×5. LR=1e-4, patience=10. Same focal loss. Saves to `stgat_ft.keras`.

## Repository Structure

```
├── ids/
│   ├── notebooks/
│   │   ├── loss_increased.ipynb      # Main training notebook (Colab / T4 GPU)
│   │   ├── README_AI_IDS.md          # Detailed methodology & results
│   │   ├── paper_stgat_ids.tex       # IEEE conference paper (LaTeX)
│   │   ├── build_pptx.py             # Generates presentation_stgat.pptx
│   │   └── presentation_stgat.pptx   # 15-slide presentation
│   ├── test_ids.py                   # Unit tests for IDS pipeline
│   └── test_v2x.py                   # V2X integration tests
├── dashboard/
│   └── app.py                        # Real-time monitoring dashboard
└── README.md
```

## Running

### Training (Google Colab, T4 GPU recommended)

Open `ids/notebooks/loss_increased.ipynb` in Google Colab and run all cells.

### Dashboard

```bash
python dashboard/app.py
```

### Simulated Vehicle

```bash
$env:DASHBOARD_HOST="127.0.0.1"; python vehicles/vehicle.py --id 101
```

## Requirements

- Python 3.10+
- TensorFlow 2.15+ (GPU recommended)
- pandas, numpy, scikit-learn, matplotlib, spektral
- python-pptx (for `build_pptx.py` only)

## Authors

E-JUST / Alexandria University — Graduation Project 2026
