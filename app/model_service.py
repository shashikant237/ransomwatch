"""Model loading and inference service for RansomWatch.
Wraps the scikit-learn Isolation Forest model, performs validation,
normalizes decision scores to a calibrated 0-100 anomaly scale,
and provides transparent metadata explaining model assumptions and limits.
"""

import os
import json
from typing import Dict, Any, Tuple
import numpy as np
import pandas as pd
import joblib

from app.schemas import BehavioralFeatures, MLAnomalyResult
from app.feature_extractor import FEATURE_NAMES


class ModelService:
    def __init__(self, model_dir: str = None):
        if model_dir is None:
            # Default relative to this file
            cur_dir = os.path.dirname(os.path.abspath(__file__))
            model_dir = os.path.join(cur_dir, "..", "ml", "saved_model")
        
        self.model_dir = os.path.abspath(model_dir)
        self.model_path = os.path.join(self.model_dir, "isolation_forest.joblib")
        self.meta_path = os.path.join(self.model_dir, "model_metadata.json")
        self.eval_path = os.path.join(self.model_dir, "evaluation_report.json")
        
        self.model = None
        self.metadata: Dict[str, Any] = {}
        self.eval_report: Dict[str, Any] = {}
        self.load_model()

    def load_model(self):
        """Loads trained Isolation Forest and metadata from disk."""
        if os.path.exists(self.model_path):
            self.model = joblib.load(self.model_path)
        else:
            self.model = None

        if os.path.exists(self.meta_path):
            with open(self.meta_path, "r", encoding="utf-8") as f:
                self.metadata = json.load(f)
        else:
            self.metadata = {
                "status": "UNINITIALIZED",
                "message": "Model not yet trained. Run ml/train_model.py."
            }

        if os.path.exists(self.eval_path):
            with open(self.eval_path, "r", encoding="utf-8") as f:
                self.eval_report = json.load(f)

    @property
    def is_loaded(self) -> bool:
        return self.model is not None

    def predict(self, features: BehavioralFeatures) -> MLAnomalyResult:
        """Runs Isolation Forest anomaly detection on behavioral parameters.
        Maps the raw decision function to a calibrated 0 - 100 anomaly score.
        """
        if self.model is None:
            return MLAnomalyResult(
                is_anomaly=False,
                raw_score=0.0,
                calibrated_anomaly_score=0.0,
                model_name="Fallback-Heuristic",
                model_version="None",
                interpretation="ML model artifact not loaded. Relying strictly on rule-based detection engine."
            )

        features_dict = features.model_dump()
        row = [float(features_dict.get(feat, 0.0)) for feat in FEATURE_NAMES]
        df_sample = pd.DataFrame([row], columns=FEATURE_NAMES)

        # Decision function: positive for inliers, negative for outliers
        # Typically between -0.35 (extreme anomaly) and +0.25 (typical normal)
        raw_score = float(self.model.decision_function(df_sample)[0])
        prediction = int(self.model.predict(df_sample)[0])  # 1: normal, -1: anomaly
        is_anomaly = (prediction == -1)

        # Calibration: Transform raw decision score to 0.0 - 100.0 anomaly scale
        # If raw_score >= 0.15 -> perfectly normal (~0-10)
        # If raw_score == 0.00 -> decision threshold (~50)
        # If raw_score <= -0.20 -> extreme anomaly (~90-100)
        calibrated = 50.0 - (raw_score * 200.0)
        calibrated = max(0.0, min(100.0, calibrated))

        if is_anomaly:
            if calibrated >= 80:
                interpretation = (
                    f"Severe statistical outlier (raw score {raw_score:.3f}). "
                    f"Process displays extreme spatial separation from benign operational clusters."
                )
            else:
                interpretation = (
                    f"Moderate statistical anomaly / outlier (raw score {raw_score:.3f}). "
                    f"Process features cross normal baseline boundaries into suspect cluster."
                )
        else:
            interpretation = (
                f"Statistical inlier (raw score {raw_score:.3f}). "
                f"Behavior conforms with baseline distributions observed in normal operations."
            )

        return MLAnomalyResult(
            is_anomaly=is_anomaly,
            raw_score=round(raw_score, 4),
            calibrated_anomaly_score=round(calibrated, 2),
            model_name=self.metadata.get("model_name", "IsolationForest"),
            model_version=self.metadata.get("model_version", "1.0.0"),
            interpretation=interpretation
        )

    def get_info(self) -> Dict[str, Any]:
        """Returns model metadata, feature configuration, and evaluation metrics."""
        return {
            "loaded": self.is_loaded,
            "metadata": self.metadata,
            "evaluation": self.eval_report,
            "feature_names": FEATURE_NAMES,
            "algorithm": "Isolation Forest (Unsupervised Ensembles)",
            "hyperparameters": {
                "n_estimators": 150,
                "contamination": self.metadata.get("contamination", 0.15),
                "random_state": self.metadata.get("random_seed", 42)
            }
        }
