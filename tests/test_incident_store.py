"""Tests for SQLite persistence, audit logging, and export."""

import os
import tempfile
import pytest
from app.incident_store import IncidentStore
from app.schemas import (
    IncidentReport,
    MLAnomalyResult,
    RuleEvaluationResult,
    ContributorIndicator
)


@pytest.fixture
def temp_store():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    store = IncidentStore(db_path=path)
    yield store
    try:
        if os.path.exists(path):
            os.remove(path)
    except (PermissionError, OSError):
        pass


def test_save_and_retrieve_incident(temp_store):
    sample_incident = IncidentReport(
        incident_id="INC-TEST-001",
        timestamp="2026-10-29T20:00:00Z",
        process_name="test_proc.exe",
        process_id=1234,
        user_account="TEST\\user",
        target_path="C:\\TestPath",
        risk_level="HIGH",
        risk_score=75.5,
        rule_score=80.0,
        ml_score=70.0,
        status="NEW",
        rules_triggered=[],
        ml_result=MLAnomalyResult(
            is_anomaly=True,
            raw_score=-0.15,
            calibrated_anomaly_score=80.0,
            model_name="IsolationForest",
            model_version="1.0.0",
            interpretation="Outlier"
        ),
        top_contributors=[],
        dynamic_explanation="Test high risk explanation",
        recommended_action="Simulate containment",
        simulated_actions_taken=[],
        features_snapshot={"file_modification_rate": 20.0}
    )

    temp_store.save_incident(sample_incident)
    fetched = temp_store.get_incident_by_id("INC-TEST-001")

    assert fetched is not None
    assert fetched["incident_id"] == "INC-TEST-001"
    assert fetched["process_name"] == "test_proc.exe"
    assert fetched["risk_score"] == 75.5


def test_acknowledge_and_simulated_action(temp_store):
    sample_incident = IncidentReport(
        incident_id="INC-TEST-002",
        timestamp="2026-10-29T20:00:00Z",
        process_name="evil.exe",
        process_id=666,
        user_account="CORP\\admin",
        target_path="C:\\Shares",
        risk_level="CRITICAL",
        risk_score=95.0,
        rule_score=90.0,
        ml_score=95.0,
        status="NEW",
        rules_triggered=[],
        ml_result=MLAnomalyResult(
            is_anomaly=True,
            raw_score=-0.25,
            calibrated_anomaly_score=95.0,
            model_name="IsolationForest",
            model_version="1.0.0",
            interpretation="Critical Outlier"
        ),
        top_contributors=[],
        dynamic_explanation="Critical ransomware wave",
        recommended_action="Isolate immediately",
        simulated_actions_taken=[],
        features_snapshot={}
    )
    temp_store.save_incident(sample_incident)

    # 1. Acknowledge
    ack_res = temp_store.acknowledge_incident("INC-TEST-002", "Analyst Bob", "Triaged")
    assert ack_res is True
    inc_acked = temp_store.get_incident_by_id("INC-TEST-002")
    assert inc_acked["status"] == "ACKNOWLEDGED"

    # 2. Simulated Containment
    act = temp_store.record_simulated_action(
        "INC-TEST-002",
        "SIMULATE_ENDPOINT_ISOLATION",
        "Analyst Bob",
        "Safe defensive test"
    )
    assert act is not None
    assert "SIMULATED — NO REAL ENDPOINT ISOLATED" in act["simulation_notice"]

    inc_contained = temp_store.get_incident_by_id("INC-TEST-002")
    assert inc_contained["status"] == "CONTAINED_SIMULATED"
    assert len(inc_contained["simulated_actions_taken"]) == 1


def test_export_formats(temp_store):
    json_out = temp_store.export_incidents("json")
    assert isinstance(json_out, str)
    assert json_out.startswith("[") or json_out.startswith("{")

    csv_out = temp_store.export_incidents("csv")
    assert "Incident ID" in csv_out
    assert "Process Name" in csv_out
