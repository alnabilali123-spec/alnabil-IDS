---
license: mit
language:
- en
metrics:
- accuracy
- f1
- precision
- recall
- recall
tags:
- >-
  xgboost - onnx - cybersecurity - ddos - intrusion-detection - network-security
  - binary-classification
datasets:
  - CIC-DDoS2019
pipeline_tag: tabular-classification
base_model: "null"
---


# 🛡️ Model Card: DDoS Detection using XGBoost (ONNX)

A high-performance model to detect **DDoS attacks** from network traffic flow data. Trained on [CIC-DDoS2019](https://www.kaggle.com/datasets/dhoogla/cicddos2019), optimized with **Optuna**, and exported to **ONNX** for fast, portable inference.

---

## Model Details

### Model Description

- **Developed by:** Sunny Thakur 
- **Model type:** Gradient Boosted Tree (XGBoost)
- **Language(s):** Not NLP-specific; flow data in numeric format
- **License:** MIT
- **Finetuned from model:** None (Trained from scratch)

### Model Sources

- **Repository:** https://github.com/SunnyThakur25/DDoS-Detection-XGBoost
- **Demo:** Coming soon
- **Paper:** N/A (model based on CIC-DDoS2019 dataset)

---

## Uses

### Direct Use

- Detect DDoS attacks from structured flow data (CSV, Parquet, JSONL after transformation)
- Ideal for cybersecurity monitoring systems, SOC pipelines, or SIEM integrations

### Downstream Use

- Can be integrated in larger threat detection systems
- Extended to multi-class detection or traffic categorization

### Out-of-Scope Use

- Real-time packet-level classification without flow aggregation
- NLP, audio, or image data tasks

---

## Bias, Risks, and Limitations

- Model may overfit synthetic DDoS traffic patterns
- Limited to features available in CIC-DDoS2019
- SMOTE oversampling may create synthetic minority patterns that don't generalize

### Recommendations

- Validate on real-world or updated datasets before deployment
- Periodic retraining recommended as attack patterns evolve

---

## How to Get Started with the Model

### ONNX Inference (Python)

```python
import onnxruntime as ort
import numpy as np

session = ort.InferenceSession("ddos_model.onnx")
input_data = np.array([...], dtype=np.float32).reshape(1, -1)
outputs = session.run(None, {"input": input_data})
```



```python

import joblib
pipeline = joblib.load("ddos_detection_pipeline.pkl")
prediction = pipeline.predict(input_df)
```


Training Details
Training Data

    Dataset: CIC-DDoS2019

    Source: https://www.kaggle.com/datasets/dhoogla/cicddos2019

    Classes: Binary (Benign vs DDoS)

Training Procedure

    Preprocessed: IPs, ports, timestamps dropped

    Feature engineered: requests_per_sec, pkt_len_variation

    Balancing: SMOTE (30% oversample minority)

    Scaler: StandardScaler

    Model: XGBoost

    Optimized using Optuna (F1-score, 30 trials)

Training Hyperparameters

    n_estimators: 100–500 (tuned)

    max_depth: 3–12 (tuned)

    learning_rate: 0.001–0.2

    gamma, colsample_bytree, scale_pos_weight: tuned

    tree_method: hist

    early_stopping_rounds: 20

Evaluation
Testing Data

    20% hold-out split from full data

    Stratified on class label

| Metric    | Value  |
| --------- | ------ |
| Accuracy  | 99.98% |
| F1-Score  | 99.98% |
| AUC-PR    | 1.000  |
| Precision | \~1.00 |
| Recall    | \~1.00 |


Model Examination
Explainability

    Integrated SHAP

    Summary plots identify dominant flow-level features
    
Environmental Impact

    Hardware: Kaggle Tesla T4 or P100

    Training Time: < 1 hour

    Carbon Emitted: Low (can be estimated via ML CO2 Impact)

Technical Specifications

    Architecture: Gradient Boosted Trees (XGBoost)

    Format: ONNX + .pkl pipeline

    Dependencies: XGBoost, ONNX, Scikit-learn, Optuna, SHAP



Citation
```java
@misc{ddos-detection-xgboost-007,
  author = {Sunny Thakur (007)},
  title = {DDoS Detection Model - CICDDoS2019 - XGBoost + ONNX},
  year = {2025},
  url = https://huggingface.co/darkknight25/ddos_xgboost_onnx
}
```
Model Card Authors

    Sunny Thakur 

Contact

    GitHub: SunnyThakur25

    LinkedIn: Sunny thakur