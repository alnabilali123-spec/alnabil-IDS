---
license: mit
tags:
  - network-intrusion-detection
  - cybersecurity
  - lightgbm
  - scikit-learn
  - tabular-classification
datasets:
  - cicids2017
metrics:
  - f1
---

# CICIDS-2017 SOC Tier-1 Intrusion Detector

Calibrated LightGBM for 5-class network intrusion detection trained on the
[official CICIDS-2017 dataset](https://cicresearch.ca/CICDataset/CIC-IDS-2017/).

## Performance (calibrated, temporal test split)

| Class        | Precision | Recall | F1   |
|---|---|---|---|
| Normal       | 0.98      | 1.00   | 0.99 |
| DoS          | 1.00      | 0.85   | 0.92 |
| PortScan     | 0.95      | 1.00   | 0.97 |
| Brute Force  | 0.99      | 0.99   | 0.99 |
| Web Attack   | 0.86      | 0.91   | 0.88 |
| **Macro F1** |           |        | **0.9518** |

Web Attack precision improved from **0.19 → 0.86** vs the standard baseline.

## Artifacts

| File | Description |
|---|---|
| `tier1_lgbm_calibrated.pkl` | Calibrated LightGBM (isotonic, natural-dist cal set) |
| `scaler.pkl` | StandardScaler fitted on training data only |
| `feature_selector.pkl` | RF-based SelectFromModel (24 of 71 features kept) |
| `selected_features.pkl` | List of 24 selected feature names |
| `feature_cols.pkl` | Full list of 71 input features (pre-selection) |
| `label_encoder.pkl` | LabelEncoder: Brute Force=0, DoS=1, Normal=2, PortScan=3, Web Attack=4 |

## Usage

```python
import joblib, numpy as np

le       = joblib.load('label_encoder.pkl')
scaler   = joblib.load('scaler.pkl')
selector = joblib.load('feature_selector.pkl')
model    = joblib.load('tier1_lgbm_calibrated.pkl')

# flows: DataFrame with columns matching feature_cols (71 CICFlowMeter features)
X = scaler.transform(flows.values.astype('float32'))
X = selector.transform(X)
preds  = le.inverse_transform(model.predict(X))
probas = model.predict_proba(X)   # calibrated — P(Normal)~0.83 for benign traffic
Key design decisions
- **Temporal split**: per-class 80/20 chronological cut per daily file
- **SMOTE**: Web Attack 1.5k→5k, Brute Force 7k→15k before undersampling
- **Early stopping**: balanced resampled eval set (not natural-dist) so all 5 classes
  contribute equally to the stopping signal
- **Calibration**: `FrozenEstimator` + isotonic on natural-distribution val set (83% Normal)
