"""Simulation Service for RansomWatch.
Provides deterministic, presentation-ready 6-stage simulated ransomware attack workflows.
Runs entirely in memory with sample telemetry; never modifies real files or processes.
"""

from typing import Dict, Any, List
from datetime import datetime, timezone

SIMULATION_SCENARIO_METADATA = {
    "scenario_name": "Simulated Ransomware Attack",
    "description": "Guided demonstration of multi-layer ransomware detection and simulated defense workflow.",
    "total_stages": 6,
    "target_process": "crypt_dropper_stage1.exe",
    "target_pid": 8840,
    "user_account": "CORP\\analyst_demo",
    "target_directory": "C:\\Users\\demo\\Documents\\CorporateShares"
}

def get_simulation_stages() -> List[Dict[str, Any]]:
    return [
        {
            "stage": 1,
            "title": "Stage 1: Normal System Activity",
            "layer_focus": "Baseline Monitoring",
            "system_status": "NORMAL",
            "risk_score": 12.0,
            "risk_level": "LOW",
            "description": "Standard endpoint operations. Benign applications performing routine file reads and low-frequency writes.",
            "events": [
                {
                    "time_offset_ms": 0,
                    "event_type": "FILE_READ",
                    "process": "explorer.exe",
                    "pid": 2180,
                    "target": "C:\\Users\\demo\\Documents\\QuarterlyReport.docx",
                    "entropy": 3.42,
                    "status": "ALLOWED",
                    "notes": "User browsed documents folder"
                },
                {
                    "time_offset_ms": 600,
                    "event_type": "FILE_WRITE",
                    "process": "WINWORD.EXE",
                    "pid": 4120,
                    "target": "C:\\Users\\demo\\Documents\\QuarterlyReport.docx",
                    "entropy": 3.51,
                    "status": "ALLOWED",
                    "notes": "Normal document save operation (0.8 files/s)"
                },
                {
                    "time_offset_ms": 1200,
                    "event_type": "REGISTRY_QUERY",
                    "process": "taskhostw.exe",
                    "pid": 3210,
                    "target": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion",
                    "entropy": 0.0,
                    "status": "ALLOWED",
                    "notes": "Routine background telemetry check"
                }
            ],
            "telemetry_metrics": {
                "file_modification_rate": 0.8,
                "file_rename_frequency": 0.0,
                "file_deletion_frequency": 0.0,
                "entropy_delta": 0.09,
                "backup_tamper_attempts": 0
            }
        },
        {
            "stage": 2,
            "title": "Stage 2: Suspicious Activity Begins",
            "layer_focus": "Early Warning Telemetry",
            "system_status": "ELEVATED",
            "risk_score": 45.0,
            "risk_level": "MEDIUM",
            "description": "Anomalous process launched from temp directory. High-frequency write bursts and rapid sequential file access observed.",
            "events": [
                {
                    "time_offset_ms": 0,
                    "event_type": "PROCESS_START",
                    "process": "crypt_dropper_stage1.exe",
                    "pid": 8840,
                    "target": "C:\\Users\\demo\\AppData\\Local\\Temp\\crypt_dropper_stage1.exe",
                    "entropy": 6.88,
                    "status": "FLAGGED",
                    "notes": "Unsigned binary executed from AppData directory"
                },
                {
                    "time_offset_ms": 400,
                    "event_type": "RAPID_DIR_TRAVERSAL",
                    "process": "crypt_dropper_stage1.exe",
                    "pid": 8840,
                    "target": "C:\\Users\\demo\\Documents\\*",
                    "entropy": 0.0,
                    "status": "MONITORED",
                    "notes": "Enumerated 8 directory hierarchies in 120ms"
                },
                {
                    "time_offset_ms": 800,
                    "event_type": "BURST_FILE_MODIFICATION",
                    "process": "crypt_dropper_stage1.exe",
                    "pid": 8840,
                    "target": "C:\\Users\\demo\\Documents\\Finance\\Ledger.xlsx",
                    "entropy": 5.92,
                    "status": "SUSPICIOUS",
                    "notes": "Sub-50ms write burst detected (18.5 files/s)"
                },
                {
                    "time_offset_ms": 1200,
                    "event_type": "FILE_RENAME_BURST",
                    "process": "crypt_dropper_stage1.exe",
                    "pid": 8840,
                    "target": "Ledger.xlsx -> Ledger.xlsx.locked",
                    "entropy": 6.10,
                    "status": "SUSPICIOUS",
                    "notes": "Appending suspicious extension .locked"
                }
            ],
            "telemetry_metrics": {
                "file_modification_rate": 18.5,
                "file_rename_frequency": 14.0,
                "file_deletion_frequency": 2.0,
                "entropy_delta": 2.41,
                "backup_tamper_attempts": 0
            }
        },
        {
            "stage": 3,
            "title": "Stage 3: Layer 1 Behaviour-Based Detection",
            "layer_focus": "Layer 1: Behaviour & ML Anomaly Detection",
            "system_status": "THREAT DETECTED",
            "risk_score": 82.0,
            "risk_level": "HIGH",
            "description": "Multi-parameter heuristics triggered. Isolation Forest flags statistical outlier. Massive entropy delta confirmed.",
            "events": [
                {
                    "time_offset_ms": 0,
                    "event_type": "RULE_TRIGGER",
                    "process": "crypt_dropper_stage1.exe",
                    "pid": 8840,
                    "target": "RULE_01_MOD_RATE & RULE_06_SUSPICIOUS_EXT",
                    "entropy": 7.42,
                    "status": "TRIGGERED",
                    "notes": "Modification rate (28.4 files/s) and .locked extensions verified"
                },
                {
                    "time_offset_ms": 300,
                    "event_type": "ENTROPY_SURGE_CONFIRMED",
                    "process": "crypt_dropper_stage1.exe",
                    "pid": 8840,
                    "target": "Sample: Corporate_Strategy.pdf",
                    "entropy": 7.84,
                    "status": "CRITICAL",
                    "notes": "Shannon entropy surged from 3.20 to 7.84 bits/byte (+4.64 delta)"
                },
                {
                    "time_offset_ms": 600,
                    "event_type": "ML_ISOLATION_FOREST_OUTLIER",
                    "process": "crypt_dropper_stage1.exe",
                    "pid": 8840,
                    "target": "15-Parameter Feature Vector",
                    "entropy": 7.84,
                    "status": "ANOMALY",
                    "notes": "Isolation Forest anomaly score: 88.5/100 (Extreme spatial outlier)"
                },
                {
                    "time_offset_ms": 900,
                    "event_type": "RANSOM_NOTE_DETECTED",
                    "process": "crypt_dropper_stage1.exe",
                    "pid": 8840,
                    "target": "HOW_TO_RECOVER_FILES.txt",
                    "entropy": 4.15,
                    "status": "CRITICAL",
                    "notes": "Extortion note generated in 4 target folders"
                }
            ],
            "telemetry_metrics": {
                "file_modification_rate": 28.4,
                "file_rename_frequency": 22.0,
                "file_deletion_frequency": 9.5,
                "entropy_delta": 3.75,
                "backup_tamper_attempts": 1
            }
        },
        {
            "stage": 4,
            "title": "Stage 4: Layer 2 Prevention & Incident Response",
            "layer_focus": "Layer 2: Simulated Containment Playbook",
            "system_status": "CONTAINED (SIMULATED)",
            "risk_score": 94.0,
            "risk_level": "CRITICAL",
            "description": "Simulated security response playbook triggered. Simulated endpoint isolation, process containment, and alert logging.",
            "events": [
                {
                    "time_offset_ms": 0,
                    "event_type": "SECURITY_ALERT_GENERATED",
                    "process": "crypt_dropper_stage1.exe",
                    "pid": 8840,
                    "target": "Incident ID: INC-SIM-RANSOM-8840",
                    "entropy": 0.0,
                    "status": "LOGGED",
                    "notes": "Critical alert dispatched to SIEM / Incident Store"
                },
                {
                    "time_offset_ms": 400,
                    "event_type": "SIMULATED_PROCESS_CONTAINMENT",
                    "process": "crypt_dropper_stage1.exe",
                    "pid": 8840,
                    "target": "Process Thread Tree (PID 8840)",
                    "entropy": 0.0,
                    "status": "SIMULATED RESPONSE",
                    "notes": "[SIMULATED] Process suspended and terminated in simulation sandbox. No real OS process modified."
                },
                {
                    "time_offset_ms": 800,
                    "event_type": "SIMULATED_ENDPOINT_ISOLATION",
                    "process": "Network Adapter Layer",
                    "pid": 0,
                    "target": "192.168.1.105 (VLAN 10)",
                    "entropy": 0.0,
                    "status": "SIMULATED RESPONSE",
                    "notes": "[SIMULATED] Network connection severed to prevent lateral movement. No physical network affected."
                },
                {
                    "time_offset_ms": 1200,
                    "event_type": "VSS_INTEGRITY_AUDIT",
                    "process": "vssadmin_check.exe",
                    "pid": 1050,
                    "target": "ShadowCopyStore: Volume C:",
                    "entropy": 0.0,
                    "status": "VERIFIED",
                    "notes": "[SIMULATED] Immutable backup snapshot verified intact"
                }
            ],
            "telemetry_metrics": {
                "containment_status": "ACTIVE_SIMULATED",
                "simulated_actions": ["PROCESS_SUSPEND", "ENDPOINT_ISOLATE", "VSS_AUDIT"]
            }
        },
        {
            "stage": 5,
            "title": "Stage 5: Layer 3 ML Malware Classification",
            "layer_focus": "Layer 3: Executable Header Classifier",
            "system_status": "THREAT CLASSIFIED",
            "risk_score": 96.0,
            "risk_level": "CRITICAL",
            "description": "Binary payload static PE header analyzed by Random Forest model. Validates malicious characteristics.",
            "events": [
                {
                    "time_offset_ms": 0,
                    "event_type": "PE_FEATURE_EXTRACTION",
                    "process": "crypt_dropper_stage1.exe",
                    "pid": 8840,
                    "target": "Portable Executable (PE) Headers",
                    "entropy": 7.84,
                    "status": "ANALYZING",
                    "notes": "Extracted 15 structural features (DebugSize=0, BitcoinAddresses=2, Sections=2)"
                },
                {
                    "time_offset_ms": 400,
                    "event_type": "RANDOM_FOREST_INFERENCE",
                    "process": "crypt_dropper_stage1.exe",
                    "pid": 8840,
                    "target": "PE Classifier Ensemble (100 Trees)",
                    "entropy": 0.0,
                    "status": "CLASSIFIED",
                    "notes": "Model prediction: MALICIOUS (Confidence: 99.4%, Target=0)"
                },
                {
                    "time_offset_ms": 800,
                    "event_type": "MALWARE_INDICATORS_CORRELATED",
                    "process": "crypt_dropper_stage1.exe",
                    "pid": 8840,
                    "target": "Bitcoin Wallets & Stripped Debug Tables",
                    "entropy": 0.0,
                    "status": "VERIFIED",
                    "notes": "Extortion cryptocurrency wallet signature confirmed in binary strings"
                }
            ],
            "pe_classification_result": {
                "file_name": "crypt_dropper_stage1.exe",
                "classification": "MALICIOUS",
                "is_malicious": True,
                "confidence": 0.994,
                "malware_probability_score": 99.4,
                "model_used": "Random Forest (PE Header Classifier)",
                "detected_anomalies": [
                    "Contains 2 cryptocurrency / bitcoin address pattern(s) in strings",
                    "Stripped debug headers (typical of obfuscated or packed malware)",
                    "Abnormally low section count (2) indicating packed executable (UPX/crypter)",
                    "Unusually heavy resource section (892000 bytes) potentially hiding encrypted binary",
                    "Lacks modern DEP (NX_COMPAT) and ASLR (DYNAMIC_BASE) protection flags"
                ]
            }
        },
        {
            "stage": 6,
            "title": "Stage 6: Final Incident Forensic Report",
            "layer_focus": "Comprehensive Synthesis",
            "system_status": "SIMULATION COMPLETED",
            "risk_score": 96.0,
            "risk_level": "CRITICAL",
            "description": "Simulation completed. Threat categorized, defense layers verified, and response containment logged in audit store.",
            "final_report": {
                "simulation_status": "COMPLETED",
                "incident_id": "INC-SIM-RANSOM-8840",
                "threat_category": "High-Velocity Cryptographic Ransomware Dropper",
                "detection_layers_activated": [
                    "Layer 1: Behaviour-Based Monitoring (15 Features + Isolation Forest)",
                    "Layer 2: Prevention & Simulated Response (Process Terminate + Host Isolate)",
                    "Layer 3: Machine Learning Malware Classification (Random Forest PE Classifier)"
                ],
                "suspicious_events_generated": 14,
                "behavioural_risk_score": "94.0 / 100 (CRITICAL)",
                "ml_classification_result": "MALICIOUS (99.4% Confidence)",
                "simulated_response_actions": [
                    "SIMULATE_PROCESS_TERMINATION [Executed]",
                    "SIMULATE_ENDPOINT_ISOLATION [Executed]",
                    "SIMULATE_VSS_SNAPSHOT_CHECK [Verified]"
                ],
                "recommended_security_actions": [
                    "Maintain network isolation until digital forensics extraction completes.",
                    "Preserve memory dump (.dmp) to attempt private decryption key recovery.",
                    "Revoke AD service accounts associated with execution path.",
                    "Restore affected network shares from immutable offline Volume Shadow Copies."
                ],
                "total_simulation_duration": "4.8 seconds (Interactive Demonstration)",
                "disclaimer": "ALL ACTIONS SIMULATED SAFELY IN-MEMORY. ZERO HOST FILES OR PROCESSES MODIFIED."
            }
        }
    ]
