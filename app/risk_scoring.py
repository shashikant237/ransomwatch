"""Explainable Threat Assessment and Risk Scoring Engine for RansomWatch.
Combines rule-based heuristic evaluations and machine-learning anomaly scores
into a transparent, configurable composite risk score.

Generates contextual, dynamic human-readable explanations tailored to
the specific behavioral indicators triggered during each event.
"""

from typing import List, Dict, Any, Tuple
from app.schemas import (
    BehavioralFeatures,
    RuleEvaluationResult,
    MLAnomalyResult,
    ContributorIndicator,
    IncidentReport
)


def compute_composite_risk(
    rule_score: float,
    ml_result: MLAnomalyResult,
    rule_weight_ratio: float = 0.60,
    ml_weight_ratio: float = 0.40
) -> Tuple[float, str]:
    """Combines rule score (0-100) and ML anomaly score (0-100) into composite threat score."""
    total_ratio = rule_weight_ratio + ml_weight_ratio
    if total_ratio <= 0:
        total_ratio = 1.0
    r_norm = rule_weight_ratio / total_ratio
    m_norm = ml_weight_ratio / total_ratio

    composite = (rule_score * r_norm) + (ml_result.calibrated_anomaly_score * m_norm)
    composite = round(max(0.0, min(100.0, composite)), 2)

    if composite >= 85.0:
        risk_level = "CRITICAL"
    elif composite >= 60.0:
        risk_level = "HIGH"
    elif composite >= 30.0:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return composite, risk_level


def generate_dynamic_explanation(
    process_name: str,
    process_id: int,
    risk_level: str,
    rules_triggered: List[RuleEvaluationResult],
    ml_result: MLAnomalyResult,
    features: BehavioralFeatures
) -> str:
    """Generates a dynamic, non-repetitive, human-readable threat explanation
    derived specifically from the features and rules triggered in this incident.
    """
    triggered_rules = [r for r in rules_triggered if r.triggered]
    feat_dict = features.model_dump()

    if risk_level == "LOW" and not triggered_rules and not ml_result.is_anomaly:
        return (
            f"Normal benign activity observed for process '{process_name}' (PID {process_id}). "
            f"File modification rate ({feat_dict['file_modification_rate']} files/s) and entropy shift "
            f"({feat_dict['file_entropy_delta']} bits/byte) remain well within baseline operational parameters. "
            f"No extortion markers or suspicious extensions were detected."
        )

    # Compile specific behavioral observation clauses
    clauses: List[str] = []

    if feat_dict.get("backup_tamper_attempts", 0) > 0:
        clauses.append(
            f"attempted to tamper with backup/shadow copy services ({int(feat_dict['backup_tamper_attempts'])} event(s))"
        )

    if feat_dict.get("ransom_note_indicators", 0) > 0:
        clauses.append(
            f"created known ransom note instructional files ({int(feat_dict['ransom_note_indicators'])} file(s))"
        )

    if feat_dict.get("suspicious_extension_changes", 0) > 0:
        clauses.append(
            f"appended known ransomware extensions to {int(feat_dict['suspicious_extension_changes'])} file(s)"
        )

    if feat_dict.get("file_entropy_delta", 0.0) >= 2.0:
        clauses.append(
            f"exhibited an abnormal file entropy surge (+{feat_dict['file_entropy_delta']:.2f} bits/byte) "
            f"indicative of cryptographic payload execution"
        )

    if feat_dict.get("file_modification_rate", 0.0) >= 12.0:
        clauses.append(
            f"modified files at an excessive velocity ({feat_dict['file_modification_rate']:.1f} files/s)"
        )

    if feat_dict.get("file_rename_frequency", 0.0) >= 10.0:
        clauses.append(
            f"performed rapid batch file renaming ({feat_dict['file_rename_frequency']:.1f} renames/min)"
        )

    if feat_dict.get("file_deletion_frequency", 0.0) >= 8.0:
        clauses.append(
            f"executed rapid bulk deletions ({feat_dict['file_deletion_frequency']:.1f} deletes/min)"
        )

    if feat_dict.get("rapid_sequential_modifications", 0) >= 5:
        clauses.append(
            f"conducted {int(feat_dict['rapid_sequential_modifications'])} sub-50ms rapid sequential writes"
        )

    if feat_dict.get("unique_directories_accessed", 0) >= 6:
        clauses.append(
            f"traversed {int(feat_dict['unique_directories_accessed'])} distinct directory hierarchies"
        )

    if feat_dict.get("process_activity_deviation", 0.0) >= 3.0:
        clauses.append(
            f"deviated {feat_dict['process_activity_deviation']:.1f} standard deviations above historical process baseline"
        )

    # ML Anomaly contribution clause
    ml_clause = ""
    if ml_result.is_anomaly:
        ml_clause = (
            f" Furthermore, the Isolation Forest detector flagged the process as an unsupervised statistical "
            f"outlier (calibrated anomaly score: {ml_result.calibrated_anomaly_score}/100, raw decision score: {ml_result.raw_score})."
        )
    elif ml_result.calibrated_anomaly_score >= 40.0:
        ml_clause = (
            f" The ML model observed borderline statistical displacement (score: {ml_result.calibrated_anomaly_score}/100)."
        )

    # Construct complete natural sentence
    if clauses:
        joined_clauses = "; ".join(clauses)
        explanation = (
            f"{risk_level}-risk activity detected for process '{process_name}' (PID {process_id}) "
            f"because the process {joined_clauses}.{ml_clause}"
        )
    else:
        explanation = (
            f"{risk_level}-risk activity flagged for process '{process_name}' (PID {process_id}) "
            f"due to cumulative subtle variations across multiple file activity metrics.{ml_clause}"
        )

    return explanation


def get_recommended_action(risk_level: str, features: BehavioralFeatures, process_name: str, target_path: str) -> str:
    """Provides actionable, tailored incident containment guidance based on risk level and active threat vectors."""
    feat_dict = features.model_dump()
    has_backup_tamper = feat_dict.get("backup_tamper_attempts", 0) > 0
    has_ransom_note = feat_dict.get("ransom_note_indicators", 0) > 0

    if risk_level == "CRITICAL":
        action = (
            f"CRITICAL CONTAINMENT: Isolate endpoint network connection immediately. "
            f"Terminate process '{process_name}' and child processes. "
            f"Initiate forensic memory snapshot. "
        )
        if has_backup_tamper:
            action += "Audit Volume Shadow Copies (VSS) and disconnect secondary backup drives immediately. "
        if has_ransom_note:
            action += "Preserve ransom note samples for decryptor intelligence and notify incident response commander."
        return action

    elif risk_level == "HIGH":
        return (
            f"HIGH THREAT ACTION: Restrict file write permissions in target directory '{target_path}'. "
            f"Suspend process '{process_name}' pending analyst verification. "
            f"Inspect recent rename and deletion histories for encrypted artifact staging."
        )

    elif risk_level == "MEDIUM":
        return (
            f"MEDIUM TRIAGE: Notify SOC tier-2 analyst. Verify process lineage for '{process_name}'. "
            f"Cross-reference user identity with authorized file manipulation change requests."
        )

    else:
        return (
            "ROUTINE MONITORING: Event marked as benign. "
            "No active containment or user interruption required. Telemetry retained in baseline store."
        )
