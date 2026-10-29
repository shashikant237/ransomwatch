"""Tests for the multi-parameter behavioral detection engine and heuristic rules."""

import pytest
from app.schemas import BehavioralFeatures
from app.detection_engine import DetectionEngine
from app.feature_extractor import PRESET_SCENARIOS


def test_normal_event_evaluation():
    engine = DetectionEngine()
    features = BehavioralFeatures(**PRESET_SCENARIOS["normal_office"]["features"])
    score, rules_triggered, contributors = engine.evaluate(features)

    assert score < 25.0
    triggered = [r for r in rules_triggered if r.triggered]
    assert len(triggered) == 0


def test_high_modification_rate_rule():
    engine = DetectionEngine()
    features_dict = PRESET_SCENARIOS["normal_office"]["features"].copy()
    features_dict["file_modification_rate"] = 35.0  # Well above threshold of 12.0
    features = BehavioralFeatures(**features_dict)

    score, rules_triggered, contributors = engine.evaluate(features)
    triggered_ids = [r.rule_id for r in rules_triggered if r.triggered]

    assert "RULE_01_MOD_RATE" in triggered_ids
    assert score > 0


def test_mass_rename_and_deletion_rules():
    engine = DetectionEngine()
    features_dict = PRESET_SCENARIOS["normal_office"]["features"].copy()
    features_dict["file_rename_frequency"] = 25.0
    features_dict["file_deletion_frequency"] = 18.0
    features = BehavioralFeatures(**features_dict)

    score, rules_triggered, contributors = engine.evaluate(features)
    triggered_ids = [r.rule_id for r in rules_triggered if r.triggered]

    assert "RULE_02_RENAME_SPIKE" in triggered_ids
    assert "RULE_03_MASS_DELETION" in triggered_ids


def test_combined_suspicious_indicators():
    engine = DetectionEngine()
    features = BehavioralFeatures(**PRESET_SCENARIOS["combined_attack"]["features"])
    score, rules_triggered, contributors = engine.evaluate(features)

    assert score >= 75.0
    triggered = [r for r in rules_triggered if r.triggered]
    assert len(triggered) >= 8

    # Ensure critical indicators are flagged in contributors
    contrib_names = [c.feature_name for c in contributors]
    assert "file_entropy_delta" in contrib_names
    assert "backup_tamper_attempts" in contrib_names
    assert "ransom_note_indicators" in contrib_names


def test_configurable_threshold_updates():
    engine = DetectionEngine()
    features = BehavioralFeatures(**PRESET_SCENARIOS["normal_office"]["features"])

    # Normal mod rate is 0.8; default threshold is 12.0
    # Lower threshold to 0.5 and verify rule triggers
    engine.update_rules([
        {"rule_id": "RULE_01_MOD_RATE", "threshold": 0.5, "weight": 20.0, "enabled": True}
    ])

    score, rules_triggered, contributors = engine.evaluate(features)
    rule_01 = next(r for r in rules_triggered if r.rule_id == "RULE_01_MOD_RATE")
    assert rule_01.triggered is True
