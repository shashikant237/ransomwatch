"""Reproducible training pipeline for RansomWatch Isolation Forest model.
Generates representative synthetic behavioral feature vectors representing
benign endpoint operations and ransomware-like anomalous behaviors.

Persists the trained model artifact and configuration metadata.
"""

import os
import json
from datetime import datetime, timezone
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
import joblib

RANDOM_SEED = 42
MODEL_VERSION = "1.0.0"

FEATURE_NAMES = [
    "file_modification_rate",
    "file_rename_frequency",
    "file_deletion_frequency",
    "unique_directories_accessed",
    "unique_files_affected",
    "suspicious_extension_changes",
    "file_ops_per_process",
    "unique_files_per_process",
    "rapid_sequential_modifications",
    "file_entropy_delta",
    "unusual_write_burst_frequency",
    "ransom_note_indicators",
    "unusual_type_conversions",
    "process_activity_deviation",
    "backup_tamper_attempts",
]


def generate_synthetic_data(num_benign: int = 2000, num_ransomware: int = 400, seed: int = RANDOM_SEED):
    """Generates synthetic behavioral vectors for training and evaluation.
    Synthetic data models statistical properties of both benign endpoint tasks
    (office work, compilation, web browsing, system maintenance) and
    ransomware-like bursts (rapid encryption, mass renaming, ransom note creation).
    """
    rng = np.random.default_rng(seed)

    # 1. Benign Samples (Typical endpoint activity)
    # - Low to moderate modification rate
    # - Zero or near-zero suspicious extensions, ransom notes, backup tampering
    # - Low entropy delta (text/code modifications don't create high-entropy ciphertext)
    benign_data = {
        "file_modification_rate": rng.gamma(shape=1.5, scale=1.0, size=num_benign),  # ~0.5 to 4.0
        "file_rename_frequency": rng.exponential(scale=0.4, size=num_benign),
        "file_deletion_frequency": rng.exponential(scale=0.3, size=num_benign),
        "unique_directories_accessed": rng.integers(1, 4, size=num_benign),
        "unique_files_affected": rng.integers(1, 15, size=num_benign),
        "suspicious_extension_changes": np.zeros(num_benign, dtype=int),
        "file_ops_per_process": rng.integers(5, 45, size=num_benign),
        "unique_files_per_process": rng.integers(1, 12, size=num_benign),
        "rapid_sequential_modifications": rng.poisson(lam=0.4, size=num_benign),
        "file_entropy_delta": rng.normal(loc=0.1, scale=0.2, size=num_benign).clip(0.0, 1.2),
        "unusual_write_burst_frequency": rng.exponential(scale=0.5, size=num_benign),
        "ransom_note_indicators": np.zeros(num_benign, dtype=int),
        "unusual_type_conversions": np.zeros(num_benign, dtype=int),
        "process_activity_deviation": rng.normal(loc=0.5, scale=0.4, size=num_benign).clip(0.0, 2.0),
        "backup_tamper_attempts": np.zeros(num_benign, dtype=int),
    }

    # Add a small subset of benign power-user / compiler tasks (edge benign cases)
    edge_cases = rng.choice(num_benign, size=int(num_benign * 0.1), replace=False)
    benign_data["file_modification_rate"][edge_cases] += rng.uniform(4.0, 9.0, size=len(edge_cases))
    benign_data["file_ops_per_process"][edge_cases] += rng.integers(30, 70, size=len(edge_cases))
    benign_data["unique_directories_accessed"][edge_cases] += rng.integers(2, 5, size=len(edge_cases))

    df_benign = pd.DataFrame(benign_data)
    df_benign["label"] = 0  # 0 = Benign

    # 2. Ransomware-like Samples (High-velocity, high-entropy anomalies)
    ransomware_data = {
        "file_modification_rate": rng.uniform(15.0, 60.0, size=num_ransomware),
        "file_rename_frequency": rng.uniform(12.0, 45.0, size=num_ransomware),
        "file_deletion_frequency": rng.uniform(8.0, 30.0, size=num_ransomware),
        "unique_directories_accessed": rng.integers(5, 20, size=num_ransomware),
        "unique_files_affected": rng.integers(45, 300, size=num_ransomware),
        "suspicious_extension_changes": rng.integers(1, 40, size=num_ransomware),
        "file_ops_per_process": rng.integers(90, 500, size=num_ransomware),
        "unique_files_per_process": rng.integers(35, 200, size=num_ransomware),
        "rapid_sequential_modifications": rng.integers(8, 60, size=num_ransomware),
        "file_entropy_delta": rng.uniform(2.3, 4.2, size=num_ransomware),
        "unusual_write_burst_frequency": rng.uniform(4.0, 15.0, size=num_ransomware),
        "ransom_note_indicators": rng.integers(1, 10, size=num_ransomware),
        "unusual_type_conversions": rng.integers(1, 12, size=num_ransomware),
        "process_activity_deviation": rng.uniform(3.2, 8.0, size=num_ransomware),
        "backup_tamper_attempts": rng.choice([0, 1, 2], p=[0.3, 0.5, 0.2], size=num_ransomware),
    }

    df_ransom = pd.DataFrame(ransomware_data)
    df_ransom["label"] = 1  # 1 = Ransomware-like anomaly

    return df_benign, df_ransom


def train_isolation_forest():
    """Trains the scikit-learn Isolation Forest model and saves artifacts."""
    base_dir = os.path.dirname(os.path.abspath(__file__))
    output_dir = os.path.join(base_dir, "saved_model")
    os.makedirs(output_dir, exist_ok=True)

    print(f"[*] Generating synthetic training data with fixed seed {RANDOM_SEED}...")
    df_benign, df_ransom = generate_synthetic_data(num_benign=2500, num_ransomware=450, seed=RANDOM_SEED)

    # Isolation Forest is unsupervised; we train on baseline dataset with expected contamination
    df_train = pd.concat([df_benign, df_ransom], ignore_index=True)
    X_train = df_train[FEATURE_NAMES]

    contamination_rate = len(df_ransom) / len(df_train)
    print(f"[*] Training IsolationForest (n_estimators=150, contamination={contamination_rate:.3f})...")

    model = IsolationForest(
        n_estimators=150,
        max_samples="auto",
        contamination=contamination_rate,
        random_state=RANDOM_SEED,
        bootstrap=False,
        n_jobs=-1
    )
    model.fit(X_train)

    # Compute baseline reference statistics for calibration
    benign_scores = model.decision_function(df_benign[FEATURE_NAMES])
    min_score = float(np.min(benign_scores))
    max_score = float(np.max(benign_scores))

    model_path = os.path.join(output_dir, "isolation_forest.joblib")
    joblib.dump(model, model_path)
    print(f"[+] Saved model to: {model_path}")

    metadata = {
        "model_name": "IsolationForest-BehavioralDetector",
        "model_version": MODEL_VERSION,
        "algorithm": "IsolationForest",
        "random_seed": RANDOM_SEED,
        "training_timestamp": datetime.now(timezone.utc).isoformat(),
        "total_training_samples": len(df_train),
        "benign_samples": len(df_benign),
        "anomalous_samples": len(df_ransom),
        "contamination": round(contamination_rate, 4),
        "features": FEATURE_NAMES,
        "calibration": {
            "benign_decision_min": min_score,
            "benign_decision_max": max_score,
            "benign_decision_mean": float(np.mean(benign_scores)),
            "benign_decision_std": float(np.std(benign_scores))
        },
        "disclaimer": (
            "Isolation Forest is an unsupervised anomaly detection algorithm. "
            "It flags statistical outliers in feature space based on path length in isolation trees. "
            "Trained on synthetic behavioral vectors for defensive demonstration. "
            "Does not constitute an authenticated real-world malware classifier."
        )
    }

    metadata_path = os.path.join(output_dir, "model_metadata.json")
    with open(metadata_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)
    print(f"[+] Saved model metadata to: {metadata_path}")

    return model_path, metadata_path


if __name__ == "__main__":
    train_isolation_forest()
