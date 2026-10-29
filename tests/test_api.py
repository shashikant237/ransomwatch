"""Tests for FastAPI API handlers, route logic, input validation, and responses."""

import pytest
from pydantic import ValidationError
from fastapi import HTTPException
from app.main import (
    get_health,
    get_dashboard_summary,
    analyze_event,
    run_demo_scenario,
    get_recent_events,
    get_alerts,
    get_alert_by_id,
    get_rules,
    update_rules,
    get_model_info,
    calculate_entropy_demo,
    acknowledge_incident,
    simulate_response_action,
    export_incidents
)
from app.schemas import (
    EventAnalysisRequest,
    BehavioralFeatures,
    RulesUpdateRequest,
    RuleConfig,
    AcknowledgeRequest,
    ResponseSimulationRequest
)
from app.feature_extractor import PRESET_SCENARIOS


def test_health_handler():
    data = get_health()
    assert data["status"] == "HEALTHY"
    assert data["ml_model_loaded"] is True
    assert data["database"] == "CONNECTED"
    assert data["rules_active"] >= 14


def test_dashboard_summary_handler():
    data = get_dashboard_summary()
    assert data.total_events >= 0
    assert data.rules_active_count == 14
    assert "ONLINE" in data.model_status


def test_analyze_event_valid_request():
    req = EventAnalysisRequest(
        process_name="WINWORD.EXE",
        process_id=4120,
        user_account="CORP\\jsmith",
        target_path="C:\\Docs\\Report.docx",
        features=BehavioralFeatures(**PRESET_SCENARIOS["normal_office"]["features"]),
        scenario_name="Test Normal Scenario"
    )
    result = analyze_event(req)
    assert result.risk_level == "LOW"
    assert result.risk_score < 40.0
    assert result.process_name == "WINWORD.EXE"
    assert len(result.dynamic_explanation) > 10


def test_analyze_event_schema_validation_error():
    # Negative modification rate violates ge=0.0 in Pydantic schema
    invalid_features = PRESET_SCENARIOS["normal_office"]["features"].copy()
    invalid_features["file_modification_rate"] = -5.0

    with pytest.raises(ValidationError):
        EventAnalysisRequest(
            process_name="test.exe",
            process_id=100,
            features=BehavioralFeatures(**invalid_features)
        )


def test_demo_run_preset_handler():
    result = run_demo_scenario("combined_attack")
    assert result.risk_level in ["HIGH", "CRITICAL"]
    assert result.risk_score >= 70.0
    assert result.ml_result.is_anomaly is True


def test_demo_run_invalid_scenario_key():
    with pytest.raises(HTTPException) as exc_info:
        run_demo_scenario("non_existent_key_xyz")
    assert exc_info.value.status_code == 400


def test_rules_get_and_update_handler():
    data = get_rules()
    assert "rules" in data
    assert len(data["rules"]) >= 14

    current_rules = data["rules"]
    rule_configs = [
        RuleConfig(
            rule_id=r["rule_id"],
            name=r["name"],
            feature_key=r["feature_key"],
            threshold=18.0 if r["rule_id"] == "RULE_01_MOD_RATE" else r["threshold"],
            weight=r["weight"],
            enabled=r["enabled"],
            description=r["description"]
        )
        for r in current_rules
    ]

    update_payload = RulesUpdateRequest(
        rules=rule_configs,
        rule_weight_ratio=0.65,
        ml_weight_ratio=0.35
    )
    update_res = update_rules(update_payload)
    assert update_res["status"] == "SUCCESS"
    assert update_res["weight_config"]["rule_weight_ratio"] == 0.65


def test_shannon_entropy_test_handler():
    plain_res = calculate_entropy_demo({"content": "AAAAAAAABBBBBBBBCCCCCCCC"})
    assert plain_res["shannon_entropy_bits"] < 3.0

    # High entropy pseudorandom bytes
    random_str = "8F3B9A1C5D7E2F0B4A6C8E1D3F5A7B9C2E4D6F8A0B2C4D6E8F0A2B4C6D8E0F1A"
    cipher_res = calculate_entropy_demo({"content": random_str})
    assert cipher_res["shannon_entropy_bits"] > plain_res["shannon_entropy_bits"]


def test_incident_response_workflow_handlers():
    # 1. Run a demo event to create an incident
    incident = run_demo_scenario("ransom_note")
    inc_id = incident.incident_id

    # 2. Query alerts
    alerts = get_alerts(limit=10)
    assert any(a["incident_id"] == inc_id for a in alerts)

    # 3. Retrieve by ID
    single = get_alert_by_id(inc_id)
    assert single["incident_id"] == inc_id

    # 4. Acknowledge
    ack_res = acknowledge_incident(inc_id, AcknowledgeRequest(notes="Investigating threat"))
    assert ack_res["status"] == "SUCCESS"

    # 5. Simulate containment action
    sim_res = simulate_response_action(
        inc_id,
        ResponseSimulationRequest(
            action_type="SIMULATE_ENDPOINT_ISOLATION",
            analyst_name="SOC Commander",
            notes="Testing defensive playbook"
        )
    )
    assert sim_res["status"] == "SUCCESS"
    assert "SIMULATED — NO REAL ENDPOINT ISOLATED" in sim_res["notice"]


def test_export_handler():
    csv_response = export_incidents("csv")
    assert csv_response.media_type == "text/csv"

    json_response = export_incidents("json")
    assert json_response.media_type == "application/json"
