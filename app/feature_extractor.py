"""Feature extraction, schema definitions, and safe scenario generation for RansomWatch.
Defines the 15 behavioral parameters, safe Shannon entropy calculation,
and realistic behavioral simulation vectors.
"""

import math
from typing import Dict, Any, List

FEATURE_NAMES: List[str] = [
    "file_modification_rate",
    "file_rename_frequency",
    "file_deletion_frequency",
    "unique_directories_accessed",
    "unique_files_affected",
    "suspicious_extension_changes",
    "file_ops_per_process",
    "unique_files_per_process",
    "rapid_sequential_modifications",
    "file_entropy_delta",
    "unusual_write_burst_frequency",
    "ransom_note_indicators",
    "unusual_type_conversions",
    "process_activity_deviation",
    "backup_tamper_attempts",
]

FEATURE_METADATA: Dict[str, Dict[str, Any]] = {
    "file_modification_rate": {
        "display_name": "File Modification Rate",
        "unit": "files/sec",
        "benign_baseline": 1.2,
        "suspicious_range": "> 12.0",
        "description": "Rate at which files are opened for write and modified."
    },
    "file_rename_frequency": {
        "display_name": "File Rename Frequency",
        "unit": "renames/min",
        "benign_baseline": 0.5,
        "suspicious_range": "> 10.0",
        "description": "Pace of file renaming operations (staging encrypted artifacts)."
    },
    "file_deletion_frequency": {
        "display_name": "File Deletion Frequency",
        "unit": "deletions/min",
        "benign_baseline": 0.2,
        "suspicious_range": "> 8.0",
        "description": "Pace of deleting original unencrypted files."
    },
    "unique_directories_accessed": {
        "display_name": "Unique Directories Traversed",
        "unit": "dirs",
        "benign_baseline": 2,
        "suspicious_range": "> 6",
        "description": "Breadth of directory traversal across user profiles and shares."
    },
    "unique_files_affected": {
        "display_name": "Unique Files Affected",
        "unit": "files",
        "benign_baseline": 5,
        "suspicious_range": "> 40",
        "description": "Total count of individual files touched during observation window."
    },
    "suspicious_extension_changes": {
        "display_name": "Suspicious Extension Changes",
        "unit": "events",
        "benign_baseline": 0,
        "suspicious_range": ">= 1",
        "description": "Extensions altered to ransomware markers (.locked, .crypted, etc.)."
    },
    "file_ops_per_process": {
        "display_name": "File Operations Per Process",
        "unit": "ops",
        "benign_baseline": 18,
        "suspicious_range": "> 90",
        "description": "Total combined I/O handles and system calls for this PID."
    },
    "unique_files_per_process": {
        "display_name": "Unique Files Per Process",
        "unit": "files",
        "benign_baseline": 4,
        "suspicious_range": "> 35",
        "description": "Count of distinct files opened exclusively by this process."
    },
    "rapid_sequential_modifications": {
        "display_name": "Rapid Sequential Writes (<50ms)",
        "unit": "bursts",
        "benign_baseline": 0,
        "suspicious_range": "> 5",
        "description": "Microsecond loop operations bypassing normal user interaction delays."
    },
    "file_entropy_delta": {
        "display_name": "File Entropy Shift (Delta)",
        "unit": "bits/byte",
        "benign_baseline": 0.1,
        "suspicious_range": ">= 2.2",
        "description": "Shannon entropy delta between pre and post modification data."
    },
    "unusual_write_burst_frequency": {
        "display_name": "Unusual Write Burst Frequency",
        "unit": "bursts/min",
        "benign_baseline": 0.5,
        "suspicious_range": "> 4.0",
        "description": "Intermittent high-throughput buffer write occurrences."
    },
    "ransom_note_indicators": {
        "display_name": "Ransom Note File Indicators",
        "unit": "files",
        "benign_baseline": 0,
        "suspicious_range": ">= 1",
        "description": "Creation of known extortion instructional files."
    },
    "unusual_type_conversions": {
        "display_name": "Unusual Type Conversions",
        "unit": "conversions",
        "benign_baseline": 0,
        "suspicious_range": ">= 2",
        "description": "MIME type header corruptions or unhandled format shifts."
    },
    "process_activity_deviation": {
        "display_name": "Process Baseline Deviation",
        "unit": "z-score",
        "benign_baseline": 0.3,
        "suspicious_range": "> 3.0",
        "description": "Deviation from historical behavioral profiling for this binary."
    },
    "backup_tamper_attempts": {
        "display_name": "Backup / Shadow Tampering",
        "unit": "attempts",
        "benign_baseline": 0,
        "suspicious_range": ">= 1",
        "description": "Probing or invoking commands against volume shadow copies or backup stores."
    }
}


def calculate_shannon_entropy(data: bytes) -> float:
    """Calculate the Shannon entropy of a byte sequence (0.0 to 8.0 bits/byte).
    High entropy (~7.5 - 8.0) is a standard characteristic of encrypted or compressed streams.
    Safe defensive measurement function.
    """
    if not data:
        return 0.0
    byte_counts = [0] * 256
    for b in data:
        byte_counts[b] += 1
    total = len(data)
    entropy = 0.0
    for count in byte_counts:
        if count > 0:
            p = count / total
            entropy -= p * math.log2(p)
    return round(entropy, 4)


# Pre-configured safe simulated behavioral vectors for the Detection Lab
PRESET_SCENARIOS: Dict[str, Dict[str, Any]] = {
    "normal_office": {
        "name": "Normal Office Document Editing",
        "process_name": "WINWORD.EXE",
        "process_id": 4120,
        "user_account": "CORP\\jsmith",
        "target_path": "C:\\Users\\jsmith\\Documents\\Report.docx",
        "features": {
            "file_modification_rate": 0.8,
            "file_rename_frequency": 0.0,
            "file_deletion_frequency": 0.0,
            "unique_directories_accessed": 1,
            "unique_files_affected": 2,
            "suspicious_extension_changes": 0,
            "file_ops_per_process": 12,
            "unique_files_per_process": 2,
            "rapid_sequential_modifications": 0,
            "file_entropy_delta": 0.15,
            "unusual_write_burst_frequency": 0.2,
            "ransom_note_indicators": 0,
            "unusual_type_conversions": 0,
            "process_activity_deviation": 0.4,
            "backup_tamper_attempts": 0,
            "entropy_measurement_source": "simulated"
        }
    },
    "rapid_file_mods": {
        "name": "Suspicious Rapid File Modifications",
        "process_name": "svchost_updater.exe",
        "process_id": 8940,
        "user_account": "CORP\\jsmith",
        "target_path": "C:\\Users\\jsmith\\Data",
        "features": {
            "file_modification_rate": 28.5,
            "file_rename_frequency": 1.0,
            "file_deletion_frequency": 0.5,
            "unique_directories_accessed": 4,
            "unique_files_affected": 65,
            "suspicious_extension_changes": 0,
            "file_ops_per_process": 140,
            "unique_files_per_process": 58,
            "rapid_sequential_modifications": 18,
            "file_entropy_delta": 0.8,
            "unusual_write_burst_frequency": 6.2,
            "ransom_note_indicators": 0,
            "unusual_type_conversions": 0,
            "process_activity_deviation": 4.1,
            "backup_tamper_attempts": 0,
            "entropy_measurement_source": "simulated"
        }
    },
    "mass_rename": {
        "name": "Mass File Renaming Spike",
        "process_name": "batch_converter.exe",
        "process_id": 6732,
        "user_account": "CORP\\jsmith",
        "target_path": "C:\\SharedStorage\\Finance",
        "features": {
            "file_modification_rate": 14.0,
            "file_rename_frequency": 24.5,
            "file_deletion_frequency": 1.0,
            "unique_directories_accessed": 5,
            "unique_files_affected": 72,
            "suspicious_extension_changes": 8,
            "file_ops_per_process": 110,
            "unique_files_per_process": 60,
            "rapid_sequential_modifications": 12,
            "file_entropy_delta": 1.2,
            "unusual_write_burst_frequency": 4.5,
            "ransom_note_indicators": 0,
            "unusual_type_conversions": 3,
            "process_activity_deviation": 3.8,
            "backup_tamper_attempts": 0,
            "entropy_measurement_source": "simulated"
        }
    },
    "mass_deletion": {
        "name": "Mass File Deletion Velocity",
        "process_name": "disk_cleanup_worker.exe",
        "process_id": 9210,
        "user_account": "CORP\\jsmith",
        "target_path": "C:\\Users\\jsmith\\Desktop",
        "features": {
            "file_modification_rate": 6.0,
            "file_rename_frequency": 2.0,
            "file_deletion_frequency": 22.0,
            "unique_directories_accessed": 5,
            "unique_files_affected": 55,
            "suspicious_extension_changes": 0,
            "file_ops_per_process": 88,
            "unique_files_per_process": 48,
            "rapid_sequential_modifications": 8,
            "file_entropy_delta": 0.2,
            "unusual_write_burst_frequency": 3.5,
            "ransom_note_indicators": 0,
            "unusual_type_conversions": 0,
            "process_activity_deviation": 4.5,
            "backup_tamper_attempts": 0,
            "entropy_measurement_source": "simulated"
        }
    },
    "ransom_note": {
        "name": "Ransom Note Indicator Activity",
        "process_name": "payload_stage2.exe",
        "process_id": 5104,
        "user_account": "CORP\\jsmith",
        "target_path": "C:\\Users\\jsmith\\Documents\\READ_ME_RECOVER.txt",
        "features": {
            "file_modification_rate": 8.0,
            "file_rename_frequency": 4.0,
            "file_deletion_frequency": 1.0,
            "unique_directories_accessed": 7,
            "unique_files_affected": 32,
            "suspicious_extension_changes": 2,
            "file_ops_per_process": 64,
            "unique_files_per_process": 28,
            "rapid_sequential_modifications": 6,
            "file_entropy_delta": 1.8,
            "unusual_write_burst_frequency": 3.0,
            "ransom_note_indicators": 4,
            "unusual_type_conversions": 1,
            "process_activity_deviation": 3.4,
            "backup_tamper_attempts": 0,
            "entropy_measurement_source": "simulated"
        }
    },
    "high_entropy": {
        "name": "High-Entropy Bulk File Write (Encryption Pattern)",
        "process_name": "cipher_engine.exe",
        "process_id": 7820,
        "user_account": "CORP\\jsmith",
        "target_path": "C:\\Users\\jsmith\\Accounting",
        "features": {
            "file_modification_rate": 22.0,
            "file_rename_frequency": 12.0,
            "file_deletion_frequency": 3.0,
            "unique_directories_accessed": 6,
            "unique_files_affected": 80,
            "suspicious_extension_changes": 12,
            "file_ops_per_process": 160,
            "unique_files_per_process": 75,
            "rapid_sequential_modifications": 24,
            "file_entropy_delta": 3.65,
            "unusual_write_burst_frequency": 7.8,
            "ransom_note_indicators": 0,
            "unusual_type_conversions": 5,
            "process_activity_deviation": 4.8,
            "backup_tamper_attempts": 0,
            "entropy_measurement_source": "simulated"
        }
    },
    "combined_attack": {
        "name": "Combined Multi-Indicator Ransomware Wave",
        "process_name": "mal_encryptor.exe",
        "process_id": 6660,
        "user_account": "CORP\\Administrator",
        "target_path": "C:\\NetworkShares\\EnterpriseData",
        "features": {
            "file_modification_rate": 36.0,
            "file_rename_frequency": 28.0,
            "file_deletion_frequency": 15.0,
            "unique_directories_accessed": 12,
            "unique_files_affected": 140,
            "suspicious_extension_changes": 35,
            "file_ops_per_process": 280,
            "unique_files_per_process": 120,
            "rapid_sequential_modifications": 42,
            "file_entropy_delta": 3.85,
            "unusual_write_burst_frequency": 9.5,
            "ransom_note_indicators": 8,
            "unusual_type_conversions": 10,
            "process_activity_deviation": 5.9,
            "backup_tamper_attempts": 2,
            "entropy_measurement_source": "simulated"
        }
    }
}
