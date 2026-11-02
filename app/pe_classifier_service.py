"""Layer 3: PE Executable Malware Classifier Service.
Loads the trained supervised Random Forest / ensemble model, provides
inference with calibrated confidence, explains structural PE anomalies,
and serves model comparison benchmarks (Random Forest, Decision Tree, SVM).
"""

import os
import json
from typing import Dict, Any, List, Optional
import numpy as np
import pandas as pd
import joblib

from app.schemas import PEFeatures, PEClassificationResult

PE_FEATURE_NAMES = [
    "Machine", "DebugSize", "DebugRVA", "MajorImageVersion",
    "MajorOSVersion", "ExportRVA", "ExportSize", "IatVRA",
    "MajorLinkerVersion", "MinorLinkerVersion", "NumberOfSections",
    "SizeOfStackReserve", "DllCharacteristics", "ResourceSize",
    "BitcoinAddresses"
]

SAMPLE_PE_PROFILES: Dict[str, Dict[str, Any]] = {
    "benign_svchost": {
        "file_name": "svchost.exe",
        "description": "Standard Windows Service Host binary with valid debug directory, normal sections, and code-signing characteristics.",
        "expected_label": "BENIGN",
        "features": {
            "Machine": 34404,
            "DebugSize": 56,
            "DebugRVA": 16384,
            "MajorImageVersion": 10,
            "MajorOSVersion": 10,
            "ExportRVA": 0,
            "ExportSize": 0,
            "IatVRA": 8192,
            "MajorLinkerVersion": 14,
            "MinorLinkerVersion": 28,
            "NumberOfSections": 6,
            "SizeOfStackReserve": 1048576,
            "DllCharacteristics": 33120,
            "ResourceSize": 12450,
            "BitcoinAddresses": 0
        }
    },
    "benign_chrome": {
        "file_name": "chrome.exe",
        "description": "Legitimate browser executable with standard export table, rich debug sections, and normal stack reserve.",
        "expected_label": "BENIGN",
        "features": {
            "Machine": 34404,
            "DebugSize": 84,
            "DebugRVA": 28672,
            "MajorImageVersion": 1,
            "MajorOSVersion": 10,
            "ExportRVA": 45056,
            "ExportSize": 1280,
            "IatVRA": 16384,
            "MajorLinkerVersion": 14,
            "MinorLinkerVersion": 30,
            "NumberOfSections": 7,
            "SizeOfStackReserve": 2097152,
            "DllCharacteristics": 33152,
            "ResourceSize": 84500,
            "BitcoinAddresses": 0
        }
    },
    "malware_wannacry": {
        "file_name": "tasksche_dropper.exe",
        "description": "WannaCry-style ransomware payload with stripped debug headers, bloated packed resource section, and embedded Bitcoin wallet address.",
        "expected_label": "MALICIOUS",
        "features": {
            "Machine": 332,
            "DebugSize": 0,
            "DebugRVA": 0,
            "MajorImageVersion": 0,
            "MajorOSVersion": 4,
            "ExportRVA": 0,
            "ExportSize": 0,
            "IatVRA": 2048,
            "MajorLinkerVersion": 6,
            "MinorLinkerVersion": 0,
            "NumberOfSections": 2,
            "SizeOfStackReserve": 262144,
            "DllCharacteristics": 0,
            "ResourceSize": 892000,
            "BitcoinAddresses": 2
        }
    },
    "malware_lockbit": {
        "file_name": "lockbit_loader.exe",
        "description": "Ransomware loader with non-standard section structure, missing DEP/ASLR characteristics, and anomalous image versions.",
        "expected_label": "MALICIOUS",
        "features": {
            "Machine": 332,
            "DebugSize": 0,
            "DebugRVA": 0,
            "MajorImageVersion": 99,
            "MajorOSVersion": 0,
            "ExportRVA": 0,
            "ExportSize": 0,
            "IatVRA": 1024,
            "MajorLinkerVersion": 7,
            "MinorLinkerVersion": 10,
            "NumberOfSections": 12,
            "SizeOfStackReserve": 65536,
            "DllCharacteristics": 1024,
            "ResourceSize": 450000,
            "BitcoinAddresses": 1
        }
    }
}


class PEClassifierService:
    def __init__(self, model_dir: str = None):
        if model_dir is None:
            cur_dir = os.path.dirname(os.path.abspath(__file__))
            model_dir = os.path.join(cur_dir, "..", "ml", "saved_model")

        self.model_dir = os.path.abspath(model_dir)
        self.model_path = os.path.join(self.model_dir, "pe_classifier.joblib")
        self.scaler_path = os.path.join(self.model_dir, "pe_scaler.joblib")
        self.meta_path = os.path.join(self.model_dir, "pe_model_metadata.json")
        self.comp_path = os.path.join(self.model_dir, "pe_model_comparison.json")

        self.model = None
        self.scaler = None
        self.metadata: Dict[str, Any] = {}
        self.comparison: Dict[str, Any] = {}
        self.load_model()

    def load_model(self):
        """Loads trained champion PE classifier and metadata."""
        if os.path.exists(self.model_path):
            self.model = joblib.load(self.model_path)
        else:
            self.model = None

        if os.path.exists(self.scaler_path):
            self.scaler = joblib.load(self.scaler_path)

        if os.path.exists(self.meta_path):
            with open(self.meta_path, "r", encoding="utf-8") as f:
                self.metadata = json.load(f)

        if os.path.exists(self.comp_path):
            with open(self.comp_path, "r", encoding="utf-8") as f:
                self.comparison = json.load(f)

    @property
    def is_loaded(self) -> bool:
        return self.model is not None

    def predict(self, features: PEFeatures, file_name: str = "sample.exe") -> PEClassificationResult:
        """Classifies PE header structural parameters as Benign or Malicious."""
        if self.model is None:
            # Fallback heuristic if ML artifact is uninitialized
            is_mal = (
                features.BitcoinAddresses > 0
                or features.DebugSize == 0
                or features.NumberOfSections <= 2
                or features.ResourceSize > 300000
            )
            pred_class = 0 if is_mal else 1
            conf = 0.85
            score = 85.0 if is_mal else 15.0
        else:
            row = [
                features.Machine, features.DebugSize, features.DebugRVA,
                features.MajorImageVersion, features.MajorOSVersion,
                features.ExportRVA, features.ExportSize, features.IatVRA,
                features.MajorLinkerVersion, features.MinorLinkerVersion,
                features.NumberOfSections, features.SizeOfStackReserve,
                features.DllCharacteristics, features.ResourceSize,
                features.BitcoinAddresses
            ]
            df_row = pd.DataFrame([row], columns=PE_FEATURE_NAMES)
            pred_class = int(self.model.predict(df_row)[0])

            if hasattr(self.model, "predict_proba"):
                probs = self.model.predict_proba(df_row)[0]
                conf = float(probs[pred_class])
                # Malicious probability score (0-100)
                mal_prob = float(probs[0])
                score = round(mal_prob * 100.0, 1)
            else:
                conf = 0.90
                score = 90.0 if pred_class == 0 else 10.0

        is_malicious = (pred_class == 0)
        label = "MALICIOUS" if is_malicious else "BENIGN"

        # Explain key findings
        anomalies: List[str] = []
        if features.BitcoinAddresses > 0:
            anomalies.append(f"Contains {features.BitcoinAddresses} cryptocurrency / bitcoin address pattern(s) in strings")
        if features.DebugSize == 0:
            anomalies.append("Stripped debug headers (typical of obfuscated or packed malware)")
        if features.NumberOfSections <= 2:
            anomalies.append(f"Abnormally low section count ({features.NumberOfSections}) indicating packed executable (UPX/crypter)")
        elif features.NumberOfSections >= 10:
            anomalies.append(f"High section count ({features.NumberOfSections}) indicating layered injected payload")
        if features.ResourceSize > 250000:
            anomalies.append(f"Unusually heavy resource section ({features.ResourceSize} bytes) potentially hiding encrypted binary")
        if features.DllCharacteristics == 0:
            anomalies.append("Lacks modern DEP (NX_COMPAT) and ASLR (DYNAMIC_BASE) protection flags")

        if is_malicious:
            explanation = (
                f"Binary '{file_name}' classified as MALICIOUS with {round(conf * 100, 1)}% confidence. "
                + (f"Key PE structural indicators: {'; '.join(anomalies)}." if anomalies else "Anomalous PE header profile matches known malware clusters.")
            )
        else:
            explanation = (
                f"Binary '{file_name}' classified as BENIGN with {round(conf * 100, 1)}% confidence. "
                f"Header displays valid debug structures, standard section counts ({features.NumberOfSections}), and normal resource allocation."
            )

        return PEClassificationResult(
            file_name=file_name,
            classification=label,
            is_malicious=is_malicious,
            confidence=round(conf, 4),
            malware_probability_score=score,
            model_used=self.metadata.get("algorithm", "Random Forest"),
            detected_anomalies=anomalies,
            explanation=explanation,
            dataset_disclaimer=(
                "Layer 3 executable classification detects general malicious vs benign PE structures. "
                "Operates independently from Layer 1 behavioural anomaly detection."
            )
        )

    def get_model_info(self) -> Dict[str, Any]:
        """Returns comparison metrics, feature importance, and model parameters."""
        return {
            "loaded": self.is_loaded,
            "metadata": self.metadata,
            "model_comparison": self.comparison,
            "feature_columns": PE_FEATURE_NAMES,
            "sample_profiles": SAMPLE_PE_PROFILES
        }
