"""Tests for explainable threat assessment and dynamic explanation generator."""

import pytest
from app.schemas import BehavioralFeatures
from app.detection_engine import DetectionEngine
from app.model_service import ModelService
from app.risk_scoring import (
    compute_composite_risk,
    generate_dynamic_explanation,
    get_recommended_action
)
from app.feature_extractor import PRESET_SCENARIOS


def test_composite_risk_weighting():
    # 60% rule score (100) + 40% ML score (50) -> 60 + 20 = 80 (HIGH)
    score, level = compute_composite_risk(
        rule_score=100.0,
        ml_result=type("MLObj", (), {"calibrated_anomaly_score": 50.0})(),
        rule_weight_ratio=0.6,
        ml_weight_ratio=0.4
    )
    assert score == 80.0
    assert level == "HIGH"


def test_dynamic_explanation_uniqueness():
    engine = DetectionEngine()
    model = ModelService()

    # Scenario 1: Mass Rename
    feat1 = BehavioralFeatures(**PRESET_SCENARIOS["mass_rename"]["features"])
    _, rules1, _ = engine.evaluate(feat1)
    ml1 = model.predict(feat1)
    exp1 = generate_dynamic_explanation("proc1.exe", 101, "HIGH", rules1, ml1, feat1)

    # Scenario 2: High Entropy
    feat2 = BehavioralFeatures(**PRESET_SCENARIOS["high_entropy"]["features"])
    _, rules2, _ = engine.evaluate(feat2)
    ml2 = model.predict(feat2)
    exp2 = generate_dynamic_explanation("proc2.exe", 202, "CRITICAL", rules2, ml2, feat2)

    # Scenario 3: Normal
    feat3 = BehavioralFeatures(**PRESET_SCENARIOS["normal_office"]["features"])
    _, rules3, _ = engine.evaluate(feat3)
    ml3 = model.predict(feat3)
    exp3 = generate_dynamic_explanation("proc3.exe", 303, "LOW", rules3, ml3, feat3)

    # All three explanations must be distinct and non-hardcoded
    assert exp1 != exp2
    assert exp2 != exp3
    assert exp1 != exp3

    # Check that scenario-specific details are present
    assert "renam" in exp1.lower()
    assert "entropy" in exp2.lower()
    assert "benign" in exp3.lower() or "normal" in exp3.lower()


def test_action_recommendation_tailoring():
    feat_crit = BehavioralFeatures(**PRESET_SCENARIOS["combined_attack"]["features"])
    rec_crit = get_recommended_action("CRITICAL", feat_crit, "malware.exe", "C:\\Data")
    assert "isolate" in rec_crit.lower()
    assert "shadow copies" in rec_crit.lower()

    feat_low = BehavioralFeatures(**PRESET_SCENARIOS["normal_office"]["features"])
    rec_low = get_recommended_action("LOW", feat_low, "word.exe", "C:\\Doc")
    assert "benign" in rec_low.lower()
