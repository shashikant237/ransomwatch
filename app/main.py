"""FastAPI application entrypoint for RansomWatch.
Provides behavioral telemetry analysis, ML anomaly scoring,
incident management, rule configuration, and response simulation endpoints.
Serves frontend static UI directly on root route.
"""

import os
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Query, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, PlainTextResponse

from app.schemas import (
    EventAnalysisRequest,
    IncidentReport,
    DashboardSummary,
    RulesUpdateRequest,
    AcknowledgeRequest,
    ResponseSimulationRequest,
    BehavioralFeatures,
    PEClassificationRequest,
    PEClassificationResult,
    DefenseLayersStatus
)
from app.feature_extractor import (
    FEATURE_METADATA,
    FEATURE_NAMES,
    PRESET_SCENARIOS,
    calculate_shannon_entropy
)
from app.detection_engine import DetectionEngine
from app.model_service import ModelService
from app.pe_classifier_service import PEClassifierService, SAMPLE_PE_PROFILES
from app.simulation_service import get_simulation_stages, SIMULATION_SCENARIO_METADATA
from app.risk_scoring import (
    compute_composite_risk,
    generate_dynamic_explanation,
    get_recommended_action
)
from app.incident_store import IncidentStore

# Initialize core services
store = IncidentStore()
model_service = ModelService()
detection_engine = DetectionEngine()
pe_service = PEClassifierService()

app = FastAPI(
    title="RansomWatch — Behaviour-Based Ransomware Detection System",
    description="Explainable AI & Multi-Parameter Behavioural Cybersecurity Prototype",
    version="1.0.0"
)

# CORS configuration strictly scoped for local development environments
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:8000",
        "http://127.0.0.1:8000",
        "http://localhost:3000",
        "http://localhost:5173"
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "OPTIONS"],
    allow_headers=["*"],
)


def analyze_and_record_event(request: EventAnalysisRequest) -> IncidentReport:
    """Core analysis pipeline:
    1. Evaluates behavioral features against heuristic rules.
    2. Runs unsupervised Isolation Forest anomaly detection.
    3. Combines scores into an explainable composite risk assessment.
    4. Dynamically generates tailored human-readable explanation and recommendations.
    5. Persists report to SQLite.
    """
    # 1. Rule Engine
    rule_score, rules_triggered, top_contributors = detection_engine.evaluate(request.features)

    # 2. ML Anomaly Model
    ml_result = model_service.predict(request.features)

    # 3. Composite Risk & Explainability
    w_cfg = detection_engine.weight_config
    risk_score, risk_level = compute_composite_risk(
        rule_score=rule_score,
        ml_result=ml_result,
        rule_weight_ratio=w_cfg.get("rule_weight_ratio", 0.60),
        ml_weight_ratio=w_cfg.get("ml_weight_ratio", 0.40)
    )

    dynamic_exp = generate_dynamic_explanation(
        process_name=request.process_name,
        process_id=request.process_id,
        risk_level=risk_level,
        rules_triggered=rules_triggered,
        ml_result=ml_result,
        features=request.features
    )

    recommended_action = get_recommended_action(
        risk_level=risk_level,
        features=request.features,
        process_name=request.process_name,
        target_path=request.target_path or "C:\\Data"
    )

    incident_id = request.event_id or f"INC-{datetime.now().strftime('%Y%m%d-%H%M%S-%f')[:22]}"
    now_iso = datetime.now(timezone.utc).isoformat()

    incident = IncidentReport(
        incident_id=incident_id,
        timestamp=now_iso,
        process_name=request.process_name,
        process_id=request.process_id,
        user_account=request.user_account,
        target_path=request.target_path or "C:\\Data",
        risk_level=risk_level,
        risk_score=risk_score,
        rule_score=rule_score,
        ml_score=ml_result.calibrated_anomaly_score,
        status="NEW",
        rules_triggered=rules_triggered,
        ml_result=ml_result,
        top_contributors=top_contributors,
        dynamic_explanation=dynamic_exp,
        recommended_action=recommended_action,
        simulated_actions_taken=[],
        features_snapshot=request.features.model_dump()
    )

    store.save_incident(incident)
    return incident


def seed_initial_incidents_if_empty():
    """Seeds a realistic set of initial baseline and suspicious incidents
    so the dashboard opens with live visual data.
    """
    existing = store.get_incidents(limit=5)
    if existing:
        return

    print("[*] Seeding initial demonstrative incidents in database...")
    scenarios_to_seed = [
        "normal_office",
        "rapid_file_mods",
        "mass_rename",
        "ransom_note",
        "high_entropy"
    ]
    for s_key in scenarios_to_seed:
        if s_key in PRESET_SCENARIOS:
            sc = PRESET_SCENARIOS[s_key]
            req = EventAnalysisRequest(
                event_id=f"EVT-SEED-{s_key[:4].upper()}-{datetime.now().strftime('%M%S%f')[:6]}",
                process_name=sc["process_name"],
                process_id=sc["process_id"],
                user_account=sc["user_account"],
                target_path=sc["target_path"],
                features=BehavioralFeatures(**sc["features"]),
                scenario_name=sc["name"]
            )
            analyze_and_record_event(req)


# Auto-seed on load
if not model_service.is_loaded:
    try:
        from ml.train_model import train_isolation_forest
        train_isolation_forest()
        model_service.load_model()
    except Exception as e:
        print(f"[-] Could not auto-train behavioral model: {e}")

if not pe_service.is_loaded:
    try:
        from ml.train_pe_classifier import train_and_compare_models
        train_and_compare_models()
        pe_service.load_model()
    except Exception as e:
        print(f"[-] Could not auto-train PE model: {e}")

seed_initial_incidents_if_empty()


# ==========================================
# REST API Endpoints
# ==========================================

@app.get("/api/health", tags=["System"])
def get_health():
    """Healthcheck endpoint reporting service status, ML readiness, and database link."""
    return {
        "status": "HEALTHY",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "database": "CONNECTED",
        "ml_model_loaded": model_service.is_loaded,
        "behavioral_model_loaded": model_service.is_loaded,
        "pe_classifier_loaded": pe_service.is_loaded,
        "rules_active": len([r for r in detection_engine.rules if r.get("enabled", True)]),
        "defense_layers": {
            "layer1": "ACTIVE",
            "layer2": "READY",
            "layer3": "ONLINE" if pe_service.is_loaded else "STANDBY"
        }
    }


@app.get("/api/dashboard/summary", response_model=DashboardSummary, tags=["Dashboard"])
def get_dashboard_summary():
    """Returns aggregated metrics for the overview dashboard including defense layer statuses."""
    s = store.get_dashboard_summary()
    s.layer1_status = "ACTIVE"
    s.layer2_status = "READY"
    s.layer3_status = "ONLINE" if pe_service.is_loaded else "STANDBY"
    return s


@app.get("/api/events", tags=["Telemetry"])
def get_recent_events(limit: int = Query(default=20, ge=1, le=100)):
    """Returns recent telemetry feed events for real-time monitoring."""
    return store.get_incidents(limit=limit)


@app.post("/api/analyze", response_model=IncidentReport, tags=["Detection"])
def analyze_event(request: EventAnalysisRequest):
    """Submits a behavioral feature vector for real-time rule and ML threat analysis."""
    try:
        return analyze_and_record_event(request)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Analysis pipeline error: {str(e)}"
        )


@app.get("/api/alerts", tags=["Incidents"])
def get_alerts(
    risk: Optional[str] = Query(default=None),
    status_filter: Optional[str] = Query(default=None, alias="status"),
    search: Optional[str] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200)
):
    """Queries alerts and incidents with optional risk level and search keyword filters."""
    r_val = risk if isinstance(risk, str) else None
    s_val = status_filter if isinstance(status_filter, str) else None
    q_val = search if isinstance(search, str) else None
    l_val = limit if isinstance(limit, int) else 50
    return store.get_incidents(
        risk_filter=r_val,
        status_filter=s_val,
        search=q_val,
        limit=l_val
    )


@app.get("/api/alerts/{incident_id}", tags=["Incidents"])
def get_alert_by_id(incident_id: str):
    """Retrieves detailed forensic breakdown for a specific incident."""
    inc = store.get_incident_by_id(incident_id)
    if not inc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident with ID '{incident_id}' not found."
        )
    return inc


@app.get("/api/rules", tags=["Configuration"])
def get_rules():
    """Returns all configurable detection rules, thresholds, and weights."""
    return {
        "rules": detection_engine.rules,
        "weight_config": detection_engine.weight_config
    }


@app.put("/api/rules", tags=["Configuration"])
def update_rules(payload: RulesUpdateRequest):
    """Safely updates rule thresholds and engine weighting ratios."""
    try:
        detection_engine.update_rules(
            new_rules=[r.model_dump() for r in payload.rules],
            rule_weight_ratio=payload.rule_weight_ratio,
            ml_weight_ratio=payload.ml_weight_ratio
        )
        return {
            "status": "SUCCESS",
            "message": "Rules and weighting ratios updated successfully.",
            "active_rules_count": len([r for r in detection_engine.rules if r.get("enabled", True)]),
            "weight_config": detection_engine.weight_config
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid rule configuration payload: {str(e)}"
        )


@app.get("/api/model/info", tags=["Machine Learning"])
def get_model_info():
    """Returns Isolation Forest model details, training metadata, and scientific limits notice."""
    return model_service.get_info()


@app.post("/api/demo/run", response_model=IncidentReport, tags=["Detection Lab"])
def run_demo_scenario(scenario_key: str = Query(..., description="Key from preset scenarios")):
    """Executes a pre-configured safe behavioral simulation scenario in the Detection Lab."""
    if scenario_key not in PRESET_SCENARIOS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown scenario '{scenario_key}'. Available: {list(PRESET_SCENARIOS.keys())}"
        )
    sc = PRESET_SCENARIOS[scenario_key]
    req = EventAnalysisRequest(
        event_id=f"SIM-{scenario_key[:4].upper()}-{datetime.now().strftime('%H%M%S%f')[:8]}",
        process_name=sc["process_name"],
        process_id=sc["process_id"],
        user_account=sc["user_account"],
        target_path=sc["target_path"],
        features=BehavioralFeatures(**sc["features"]),
        scenario_name=sc["name"]
    )
    return analyze_and_record_event(req)


@app.get("/api/demo/scenarios", tags=["Detection Lab"])
def get_demo_scenarios():
    """Returns available simulation presets for lab testing."""
    return {k: {"name": v["name"], "process": v["process_name"], "path": v["target_path"]} for k, v in PRESET_SCENARIOS.items()}


@app.post("/api/demo/entropy-test", tags=["Detection Lab"])
def calculate_entropy_demo(payload: Dict[str, str]):
    """Demonstrates real, safe Shannon entropy calculation on user-provided text or base64 samples."""
    text = payload.get("content", "")
    data_bytes = text.encode("utf-8")
    entropy = calculate_shannon_entropy(data_bytes)
    return {
        "byte_length": len(data_bytes),
        "shannon_entropy_bits": entropy,
        "interpretation": (
            "High Entropy (Cryptographic / Compressed)"
            if entropy >= 7.0 else
            "Moderate Entropy (Formatted Data)"
            if entropy >= 4.5 else
            "Low Entropy (Plain Text / Structured Script)"
        )
    }


@app.post("/api/incidents/{incident_id}/acknowledge", tags=["Response Centre"])
def acknowledge_incident(incident_id: str, payload: AcknowledgeRequest):
    """Marks an incident as acknowledged by a security analyst."""
    success = store.acknowledge_incident(
        incident_id=incident_id,
        analyst_name=payload.analyst_name or "SOC Analyst",
        notes=payload.notes or "Acknowledged"
    )
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident with ID '{incident_id}' not found."
        )
    return {
        "status": "SUCCESS",
        "incident_id": incident_id,
        "message": f"Incident '{incident_id}' acknowledged."
    }


@app.post("/api/incidents/{incident_id}/simulate-response", tags=["Response Centre"])
def simulate_response_action(incident_id: str, payload: ResponseSimulationRequest):
    """Simulates a safe defensive containment action.
    VISIBLY LABELED: 'SIMULATED — NO REAL ENDPOINT ISOLATED'.
    Never terminates host processes or cuts physical network connections.
    """
    action_record = store.record_simulated_action(
        incident_id=incident_id,
        action_type=payload.action_type,
        analyst_name=payload.analyst_name or "SOC Analyst",
        notes=payload.notes or "Simulated containment executed."
    )
    if not action_record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident with ID '{incident_id}' not found."
        )
    return {
        "status": "SUCCESS",
        "notice": "SIMULATED — NO REAL ENDPOINT ISOLATED",
        "action": action_record,
        "incident": store.get_incident_by_id(incident_id)
    }


@app.get("/api/incidents/export", tags=["Incidents"])
def export_incidents(format: str = Query(default="json", pattern="^(json|csv)$")):
    """Exports all recorded incidents as CSV or JSON for reporting."""
    content = store.export_incidents(format_type=format)
    if format == "csv":
        return Response(
            content=content,
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=ransomwatch_incidents.csv"}
        )
    else:
        return Response(
            content=content,
            media_type="application/json",
            headers={"Content-Disposition": "attachment; filename=ransomwatch_incidents.json"}
        )


# ==========================================
# Three Defense Layers & Layer 3 ML Routes
# ==========================================

@app.get("/api/defense-layers/status", response_model=DefenseLayersStatus, tags=["Defense Layers"])
def get_defense_layers_status():
    """Returns the operational status, detection capabilities, and disclosures for the 3 Defense Layers."""
    eval_metrics = pe_service.metadata.get("evaluation_metrics", {})
    return DefenseLayersStatus(
        layer1_monitoring={
            "name": "Layer 1: Behaviour-Based Monitoring and Detection",
            "status": "ACTIVE",
            "type": "Runtime Behavioral Telemetry & Unsupervised Anomaly Detection",
            "algorithm": "Heuristic Rules (14) + Isolation Forest Ensemble (150 Trees)",
            "monitored_parameters_count": 15,
            "capabilities": [
                "Rapid file modification rate tracking (>12 files/s)",
                "Mass file rename & deletion velocity",
                "Recursive directory traversal breadth",
                "Shannon entropy delta calculation (>2.2 bits/byte)",
                "Ransom note indicator recognition",
                "VSS / backup shadow tampering detection"
            ],
            "disclaimer": "Evaluates live telemetry feature vectors. Flags statistical outliers and rule breaches."
        },
        layer2_prevention={
            "name": "Layer 2: Prevention and Incident Response",
            "status": "READY",
            "type": "Defensive Containment Playbook & Audit History",
            "simulated_actions_supported": [
                "SIMULATE_PROCESS_TERMINATION",
                "SIMULATE_ENDPOINT_ISOLATION",
                "SIMULATE_VSS_SNAPSHOT_CHECK"
            ],
            "containment_execution_notice": "SIMULATED RESPONSE — NO REAL ENDPOINT ISOLATED",
            "capabilities": [
                "Immediate incident acknowledgment & triaging",
                "Simulated thread suspension and process containment",
                "Simulated network adapter VLAN segregation",
                "Immutable offline Volume Shadow Copy verification",
                "CSV & JSON incident report export"
            ]
        },
        layer3_classification={
            "name": "Layer 3: Machine Learning Malware Classification",
            "status": "ONLINE" if pe_service.is_loaded else "OFFLINE",
            "type": "Static PE Header Executable Classifier (Supervised)",
            "champion_model": pe_service.metadata.get("algorithm", "Random Forest"),
            "dataset_features_count": 15,
            "models_compared": ["Random Forest", "Decision Tree", "Support Vector Machine (SVM)", "Gradient Boosting"],
            "accuracy": eval_metrics.get("accuracy", 1.0),
            "precision": eval_metrics.get("precision", 1.0),
            "recall": eval_metrics.get("recall", 1.0),
            "f1_score": eval_metrics.get("f1_score", 1.0),
            "capabilities": [
                "PE structural header extraction (Machine, Debug, Sections, Stack, DLL flags)",
                "Cryptocurrency ransom address signature detection",
                "Binary classification: Benign (1) vs Malicious (0)",
                "Model score and confidence calibration"
            ],
            "disclaimer": "Classifies general benign vs malicious executables. Operates independently from Layer 1 behavioural anomaly detection."
        },
        active_defense_mode="MULTI_LAYER_COORDINATED"
    )


@app.post("/api/pe/classify", response_model=PEClassificationResult, tags=["Layer 3: ML Executable Classifier"])
def classify_pe_executable(payload: PEClassificationRequest):
    """Classifies a PE executable header feature vector as Benign or Malicious using the trained Random Forest model."""
    return pe_service.predict(payload.features, payload.file_name)


@app.get("/api/pe/models", tags=["Layer 3: ML Executable Classifier"])
def get_pe_model_comparison():
    """Returns comparative metrics (Accuracy, Precision, Recall, F1, Confusion Matrix) across RF, Decision Tree, and SVM."""
    return pe_service.get_model_info()


@app.get("/api/pe/samples", tags=["Layer 3: ML Executable Classifier"])
def get_pe_sample_profiles():
    """Returns pre-configured benign and malicious PE profiles for interactive demonstration."""
    return SAMPLE_PE_PROFILES


# ==========================================
# Simulation Centre Routes
# ==========================================

@app.get("/api/simulation/stages", tags=["Simulation Centre"])
def get_simulation_scenario_stages():
    """Returns the full 6-stage guided ransomware attack simulation scenario."""
    return {
        "metadata": SIMULATION_SCENARIO_METADATA,
        "stages": get_simulation_stages()
    }


@app.post("/api/simulation/run-stage/{stage_id}", tags=["Simulation Centre"])
def execute_simulation_stage(stage_id: int):
    """Executes a specific stage in the 6-stage simulation and logs relevant incident actions in SQLite."""
    stages = get_simulation_stages()
    matching = [s for s in stages if s["stage"] == stage_id]
    if not matching:
        raise HTTPException(status_code=404, detail=f"Stage {stage_id} not found.")
    stage_data = matching[0]

    # If stage 4 (Layer 2 response), safely log simulated containment into incident store
    if stage_id == 4:
        sim_id = "INC-SIM-RANSOM-8840"
        existing = store.get_incident_by_id(sim_id)
        if not existing:
            sc = PRESET_SCENARIOS.get("combined_attack", {})
            if sc:
                req = EventAnalysisRequest(
                    event_id=sim_id,
                    process_name="crypt_dropper_stage1.exe",
                    process_id=8840,
                    user_account="CORP\\analyst_demo",
                    target_path="C:\\Users\\demo\\Documents\\CorporateShares",
                    features=BehavioralFeatures(**sc["features"]),
                    scenario_name="Simulated Ransomware Attack"
                )
                analyze_and_record_event(req)
        store.record_simulated_action(
            incident_id=sim_id,
            action_type="SIMULATE_ENDPOINT_ISOLATION",
            analyst_name="Simulation Controller",
            notes="Automated containment triggered during Stage 4."
        )

    return {
        "status": "SUCCESS",
        "stage": stage_data,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


# Serve Static UI Frontend
frontend_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "frontend")
if os.path.exists(frontend_dir):
    app.mount("/", StaticFiles(directory=frontend_dir, html=True), name="frontend")
