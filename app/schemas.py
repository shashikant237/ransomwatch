"""Pydantic schemas for RansomWatch.
Defines strict validation for behavioral parameters, analysis requests,
threat assessment outputs, PE executable classification, and live attack simulation workflows.
"""

from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class BehavioralFeatures(BaseModel):
    """The 15 core ransomware behavioral parameters."""
    file_modification_rate: float = Field(
        ..., ge=0.0, description="Rate of file modifications per second"
    )
    file_rename_frequency: float = Field(
        ..., ge=0.0, description="File rename operations per minute"
    )
    file_deletion_frequency: float = Field(
        ..., ge=0.0, description="File deletion operations per minute"
    )
    unique_directories_accessed: int = Field(
        ..., ge=0, description="Count of distinct directories traversed"
    )
    unique_files_affected: int = Field(
        ..., ge=0, description="Total count of distinct files modified, renamed, or deleted"
    )
    suspicious_extension_changes: int = Field(
        ..., ge=0, description="Modifications involving suspicious ransom extensions (.locked, .crypto, etc.)"
    )
    file_ops_per_process: int = Field(
        ..., ge=0, description="Total file I/O operations recorded for the process"
    )
    unique_files_per_process: int = Field(
        ..., ge=0, description="Distinct target files opened or manipulated by the process"
    )
    rapid_sequential_modifications: int = Field(
        ..., ge=0, description="Count of burst modifications occurring within <50ms intervals"
    )
    file_entropy_delta: float = Field(
        ..., ge=-8.0, le=8.0, description="Difference in Shannon entropy (bits/byte) before and after modification"
    )
    unusual_write_burst_frequency: float = Field(
        ..., ge=0.0, description="Frequency of anomalous write burst spikes per minute"
    )
    ransom_note_indicators: int = Field(
        ..., ge=0, description="Occurrences of known ransom note patterns (e.g. HOW_TO_RESTORE.txt)"
    )
    unusual_type_conversions: int = Field(
        ..., ge=0, description="Frequency of abnormal file header/extension mismatch conversions"
    )
    process_activity_deviation: float = Field(
        ..., ge=0.0, description="Statistical deviation (sigma / z-score) above benign process baseline"
    )
    backup_tamper_attempts: int = Field(
        ..., ge=0, description="Simulated attempts to alter VSS shadow copies, wbadmin, or recovery catalogs"
    )
    entropy_measurement_source: str = Field(
        default="simulated",
        description="Origin of entropy calculation: 'measured_live' or 'simulated_vector'"
    )


class EventAnalysisRequest(BaseModel):
    """Payload submitted for multi-parameter behavioral analysis."""
    event_id: Optional[str] = None
    process_name: str = Field(default="unknown.exe", min_length=1, max_length=128)
    process_id: int = Field(default=1000, ge=1)
    user_account: str = Field(default="WORKSTATION\\User", max_length=128)
    target_path: Optional[str] = Field(default="C:\\Users\\User\\Documents")
    features: BehavioralFeatures
    scenario_name: Optional[str] = Field(default="Custom Behavioral Event")


class RuleEvaluationResult(BaseModel):
    rule_id: str
    rule_name: str
    triggered: bool
    threshold: float
    actual_value: float
    weight: float
    score_contribution: float
    description: str


class MLAnomalyResult(BaseModel):
    is_anomaly: bool
    raw_score: float
    calibrated_anomaly_score: float
    model_name: str
    model_version: str
    interpretation: str
    synthetic_notice: str = (
        "Isolation Forest anomaly detection trained on synthetic behavioral feature vectors. "
        "Flags statistical deviations from baseline, not specific malware signatures."
    )


class ContributorIndicator(BaseModel):
    feature_name: str
    display_name: str
    value: float
    threshold: float
    contribution: float
    severity: str


class IncidentReport(BaseModel):
    incident_id: str
    timestamp: str
    process_name: str
    process_id: int
    user_account: str
    target_path: str
    risk_level: str
    risk_score: float
    rule_score: float
    ml_score: float
    status: str
    rules_triggered: List[RuleEvaluationResult]
    ml_result: MLAnomalyResult
    top_contributors: List[ContributorIndicator]
    dynamic_explanation: str
    recommended_action: str
    simulated_actions_taken: List[Dict[str, Any]] = []
    features_snapshot: Dict[str, Any]


class RuleConfig(BaseModel):
    rule_id: str
    name: str
    feature_key: str
    threshold: float
    weight: float
    enabled: bool = True
    description: str


class RulesUpdateRequest(BaseModel):
    rules: List[RuleConfig]
    rule_weight_ratio: Optional[float] = Field(default=0.6, ge=0.0, le=1.0)
    ml_weight_ratio: Optional[float] = Field(default=0.4, ge=0.0, le=1.0)


class AcknowledgeRequest(BaseModel):
    analyst_name: Optional[str] = "SOC Analyst"
    notes: Optional[str] = "Incident acknowledged and triaged."


class ResponseSimulationRequest(BaseModel):
    action_type: str = Field(
        ...,
        description="SIMULATE_PROCESS_TERMINATION, SIMULATE_ENDPOINT_ISOLATION, or SIMULATE_RESTORE_CHECK"
    )
    analyst_name: Optional[str] = "SOC Analyst"
    notes: Optional[str] = "Initiating safe simulated containment."


class DashboardSummary(BaseModel):
    total_events: int
    normal_events: int
    suspicious_events: int
    high_risk_incidents: int
    critical_incidents: int
    avg_risk_score: float
    rules_active_count: int
    model_status: str
    last_updated: str
    layer1_status: Optional[str] = "ACTIVE"
    layer2_status: Optional[str] = "READY"
    layer3_status: Optional[str] = "ONLINE"


# =====================================================================
# LAYER 3: PE Executable Malware Classification Schemas
# =====================================================================

class PEFeatures(BaseModel):
    """The 15 executable header structural features for Layer 3 classification."""
    Machine: int = Field(default=34404, description="Target machine architecture (e.g. 332 x86, 34404 x64)")
    DebugSize: int = Field(default=56, ge=0, description="Size of debug directory in bytes")
    DebugRVA: int = Field(default=16384, ge=0, description="RVA of debug directory")
    MajorImageVersion: int = Field(default=1, ge=0, description="Major image version")
    MajorOSVersion: int = Field(default=10, ge=0, description="Minimum OS version required")
    ExportRVA: int = Field(default=0, ge=0, description="RVA of export directory")
    ExportSize: int = Field(default=0, ge=0, description="Size of export directory")
    IatVRA: int = Field(default=8192, ge=0, description="Import Address Table RVA")
    MajorLinkerVersion: int = Field(default=14, ge=0, description="Compiler linker major version")
    MinorLinkerVersion: int = Field(default=0, ge=0, description="Compiler linker minor version")
    NumberOfSections: int = Field(default=6, ge=1, le=100, description="Number of PE sections (.text, .data, etc.)")
    SizeOfStackReserve: int = Field(default=1048576, ge=0, description="Stack reserve size in bytes")
    DllCharacteristics: int = Field(default=33120, ge=0, description="PE security flags (NX_COMPAT, DYNAMIC_BASE)")
    ResourceSize: int = Field(default=12000, ge=0, description="Resource section size in bytes")
    BitcoinAddresses: int = Field(default=0, ge=0, description="Extracted cryptocurrency wallet string matches")


class PEClassificationRequest(BaseModel):
    file_name: str = Field(default="sample.exe", min_length=1, max_length=128)
    md5_hash: Optional[str] = Field(default="d41d8cd98f00b204e9800998ecf8427e")
    features: PEFeatures


class PEClassificationResult(BaseModel):
    file_name: str
    classification: str  # "BENIGN" or "MALICIOUS"
    is_malicious: bool
    confidence: float
    malware_probability_score: float
    model_used: str
    detected_anomalies: List[str]
    explanation: str
    dataset_disclaimer: str


# =====================================================================
# SIMULATION CENTRE & DEFENCE LAYERS SCHEMAS
# =====================================================================

class SimulationStageEvent(BaseModel):
    stage_id: int
    stage_name: str
    timestamp: str
    event_type: str
    description: str
    process_name: str
    pid: int
    risk_score: float
    layer_active: str
    is_simulated: bool = True


class DefenseLayersStatus(BaseModel):
    layer1_monitoring: Dict[str, Any]
    layer2_prevention: Dict[str, Any]
    layer3_classification: Dict[str, Any]
    active_defense_mode: str = "MULTI_LAYER_COORDINATED"
