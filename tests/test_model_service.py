"""Tests for the Isolation Forest machine learning model service."""

import pytest
from app.schemas import BehavioralFeatures
from app.model_service import ModelService
from app.feature_extractor import PRESET_SCENARIOS


def test_model_loaded_and_metadata():
    service = ModelService()
    assert service.is_loaded is True
    info = service.get_info()
    assert info["loaded"] is True
    assert len(info["feature_names"]) == 15
    assert info["algorithm"] == "Isolation Forest (Unsupervised Ensembles)"


def test_benign_prediction():
    service = ModelService()
    features = BehavioralFeatures(**PRESET_SCENARIOS["normal_office"]["features"])
    result = service.predict(features)

    assert result.is_anomaly is False
    assert result.calibrated_anomaly_score < 50.0
    assert "inlier" in result.interpretation.lower()


def test_ransomware_prediction():
    service = ModelService()
    features = BehavioralFeatures(**PRESET_SCENARIOS["combined_attack"]["features"])
    result = service.predict(features)

    assert result.is_anomaly is True
    assert result.calibrated_anomaly_score > 60.0
    assert "outlier" in result.interpretation.lower()
