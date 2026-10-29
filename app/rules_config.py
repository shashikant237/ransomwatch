"""Configurable rules and default thresholds for RansomWatch.
Allows dynamic tuning from the dashboard API.
"""

from typing import Dict, Any, List

DEFAULT_RULES: List[Dict[str, Any]] = [
    {
        "rule_id": "RULE_01_MOD_RATE",
        "name": "Rapid File Modification Rate",
        "feature_key": "file_modification_rate",
        "threshold": 12.0,
        "weight": 14.0,
        "enabled": True,
        "description": "Flags processes modifying files faster than normal user productivity (>12 files/s)."
    },
    {
        "rule_id": "RULE_02_RENAME_SPIKE",
        "name": "Mass File Renaming Frequency",
        "feature_key": "file_rename_frequency",
        "threshold": 10.0,
        "weight": 15.0,
        "enabled": True,
        "description": "Detects high-frequency batch rename operations (>10 renames/min) common in encryptor loops."
    },
    {
        "rule_id": "RULE_03_MASS_DELETION",
        "name": "Mass File Deletion Velocity",
        "feature_key": "file_deletion_frequency",
        "threshold": 8.0,
        "weight": 12.0,
        "enabled": True,
        "description": "Monitors rapid unlinking/deletion of original files after staging encrypted copies."
    },
    {
        "rule_id": "RULE_04_DIR_SPREAD",
        "name": "Broad Directory Traversal",
        "feature_key": "unique_directories_accessed",
        "threshold": 6.0,
        "weight": 10.0,
        "enabled": True,
        "description": "Identifies recursive walking across more than 6 distinct directory trees in a short window."
    },
    {
        "rule_id": "RULE_05_MASS_AFFECTED",
        "name": "High File Volume Impact",
        "feature_key": "unique_files_affected",
        "threshold": 40.0,
        "weight": 12.0,
        "enabled": True,
        "description": "Triggers when a single process impacts over 40 distinct files."
    },
    {
        "rule_id": "RULE_06_SUSPICIOUS_EXT",
        "name": "Known Ransomware Extension Change",
        "feature_key": "suspicious_extension_changes",
        "threshold": 1.0,
        "weight": 24.0,
        "enabled": True,
        "description": "Detects renaming files to known ransomware extensions (.locked, .crypto, .crypted, .wnry)."
    },
    {
        "rule_id": "RULE_07_PROC_OPS_SPIKE",
        "name": "Excessive Process I/O Burst",
        "feature_key": "file_ops_per_process",
        "threshold": 90.0,
        "weight": 10.0,
        "enabled": True,
        "description": "Monitors total file operations per process exceeding expected benign thresholds."
    },
    {
        "rule_id": "RULE_08_RAPID_SEQUENTIAL",
        "name": "Sub-50ms Sequential Writes",
        "feature_key": "rapid_sequential_modifications",
        "threshold": 5.0,
        "weight": 14.0,
        "enabled": True,
        "description": "Detects automated script or compiled loop writing files at sub-50ms intervals."
    },
    {
        "rule_id": "RULE_09_ENTROPY_DELTA",
        "name": "High Entropy Differential (Encryption)",
        "feature_key": "file_entropy_delta",
        "threshold": 2.2,
        "weight": 25.0,
        "enabled": True,
        "description": "Measures Shannon entropy shift (>2.2 bits/byte) indicating plain text to ciphertext conversion."
    },
    {
        "rule_id": "RULE_10_WRITE_BURSTS",
        "name": "Anomalous Write Burst Frequency",
        "feature_key": "unusual_write_burst_frequency",
        "threshold": 4.0,
        "weight": 10.0,
        "enabled": True,
        "description": "Detects repeating episodic write spikes characteristic of multi-threaded encryptors."
    },
    {
        "rule_id": "RULE_11_RANSOM_NOTE",
        "name": "Ransom Note File Pattern Detected",
        "feature_key": "ransom_note_indicators",
        "threshold": 1.0,
        "weight": 28.0,
        "enabled": True,
        "description": "Identifies creation of extortion notes like README_DECRYPT, HOW_TO_RECOVER, or DECRYPT_FILES."
    },
    {
        "rule_id": "RULE_12_TYPE_CONVERSION",
        "name": "Abnormal File Type Conversion",
        "feature_key": "unusual_type_conversions",
        "threshold": 2.0,
        "weight": 12.0,
        "enabled": True,
        "description": "Detects converting document/database extensions to encrypted blob binary structures."
    },
    {
        "rule_id": "RULE_13_ACTIVITY_DEVIATION",
        "name": "Process Baseline Activity Deviation",
        "feature_key": "process_activity_deviation",
        "threshold": 3.0,
        "weight": 12.0,
        "enabled": True,
        "description": "Identifies behavioral deviations exceeding 3 standard deviations from historic application profile."
    },
    {
        "rule_id": "RULE_14_BACKUP_TAMPER",
        "name": "VSS / Backup Tampering Activity",
        "feature_key": "backup_tamper_attempts",
        "threshold": 1.0,
        "weight": 30.0,
        "enabled": True,
        "description": "Flags attempts to interact with shadow copies (vssadmin), recovery boot catalogs, or backups."
    }
]

# Configurable weights for combining Rule Engine and ML Anomaly Detector
DEFAULT_WEIGHT_CONFIG = {
    "rule_weight_ratio": 0.60,
    "ml_weight_ratio": 0.40,
    "max_possible_rule_sum": sum(r["weight"] for r in DEFAULT_RULES)
}
