"""Reproducible evaluation script for RansomWatch Isolation Forest model.
Tests model predictions on an independent held-out synthetic test set.
Computes real evaluation metrics: Precision, Recall, F1-Score, False-Positive Rate.

Explicitly documents evaluation methodology and real-world limitations.
"""

import os
import json
import numpy as np
import pandas as pd
from sklearn.metrics import precision_score, recall_score, f1_score, confusion_matrix
import joblib
from ml.train_model import generate_synthetic_data, FEATURE_NAMES

EVAL_SEED = 999  # Distinct seed for independent test set


def evaluate_model():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    model_path = os.path.join(base_dir, "saved_model", "isolation_forest.joblib")
    meta_path = os.path.join(base_dir, "saved_model", "model_metadata.json")

    if not os.path.exists(model_path):
        raise FileNotFoundError(f"Model not found at {model_path}. Run train_model.py first.")

    model = joblib.load(model_path)

    # Generate held-out independent test set
    print(f"[*] Generating independent held-out test data (seed={EVAL_SEED})...")
    df_benign_test, df_ransom_test = generate_synthetic_data(
        num_benign=1000, num_ransomware=250, seed=EVAL_SEED
    )
    df_test = pd.concat([df_benign_test, df_ransom_test], ignore_index=True)

    X_test = df_test[FEATURE_NAMES]
    y_true = df_test["label"].values  # 0 = Benign, 1 = Ransomware

    # Isolation Forest: -1 = Anomaly, 1 = Normal
    raw_preds = model.predict(X_test)
    y_pred = np.where(raw_preds == -1, 1, 0)

    # Compute metrics
    precision = precision_score(y_true, y_pred, zero_division=0)
    recall = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)

    tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    results = {
        "evaluation_timestamp": pd.Timestamp.now().isoformat(),
        "test_dataset_size": len(df_test),
        "benign_test_samples": len(df_benign_test),
        "ransomware_test_samples": len(df_ransom_test),
        "metrics": {
            "precision": round(float(precision), 4),
            "recall": round(float(recall), 4),
            "f1_score": round(float(f1), 4),
            "false_positive_rate": round(float(fpr), 4),
            "true_positives": int(tp),
            "false_positives": int(fp),
            "true_negatives": int(tn),
            "false_negatives": int(fn)
        },
        "evaluation_protocol": (
            "Held-out synthetic test set with separate random seed (999). "
            "Evaluated unsupervised Isolation Forest decision threshold (-1 -> 1, 1 -> 0)."
        ),
        "scientific_limitations": (
            "CRITICAL NOTE: These metrics reflect performance strictly against synthetic behavioral "
            "distributions designed to model ransomware properties. Real-world malware environments "
            "feature diverse legitimate enterprise workloads, evasion techniques (slow encryption, "
            "process injection), and legitimate high-throughput programs that would induce different "
            "false positive and false negative dynamics."
        )
    }

    print("\n" + "=" * 60)
    print(" RansomWatch Model Evaluation Report (Synthetic Benchmark)")
    print("=" * 60)
    print(f" Test Set Size:       {results['test_dataset_size']} samples")
    print(f" Precision:           {results['metrics']['precision']:.4f}")
    print(f" Recall:              {results['metrics']['recall']:.4f}")
    print(f" F1-Score:            {results['metrics']['f1_score']:.4f}")
    print(f" False Positive Rate: {results['metrics']['false_positive_rate']:.4f}")
    print(f" Confusion Matrix:    TP={tp}, FP={fp}, TN={tn}, FN={fn}")
    print("=" * 60)
    print(" Limitations Notice:")
    print(results["scientific_limitations"])
    print("=" * 60 + "\n")

    eval_output_path = os.path.join(base_dir, "saved_model", "evaluation_report.json")
    with open(eval_output_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    return results


if __name__ == "__main__":
    evaluate_model()
