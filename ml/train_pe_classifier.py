"""Layer 3: PE Executable Malware Classifier Training & Model Comparison.
Trains and compares supervised machine learning models (Random Forest, Decision Tree, SVM, Gradient Boosting)
on the PE Header Executable Dataset.

Excludes identifier fields (FileName, md5Hash).
Uses stratified train/test split.
Evaluates Precision, Recall, F1-Score, Accuracy, and Confusion Matrices.
Persists the champion model and comparison report.
"""

import os
import json
import hashlib
from datetime import datetime, timezone
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.svm import SVC
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
import joblib

RANDOM_SEED = 42

# Complete dataset feature list according to specification:
# Target: Benign (1 = Benign, 0 = Malicious)
# Identifier columns (excluded from training): FileName, md5Hash
ALL_COLUMNS = [
    "FileName", "md5Hash", "Machine", "DebugSize", "DebugRVA",
    "MajorImageVersion", "MajorOSVersion", "ExportRVA", "ExportSize",
    "IatVRA", "MajorLinkerVersion", "MinorLinkerVersion",
    "NumberOfSections", "SizeOfStackReserve", "DllCharacteristics",
    "ResourceSize", "BitcoinAddresses", "Benign"
]

FEATURE_COLUMNS = [
    "Machine", "DebugSize", "DebugRVA", "MajorImageVersion",
    "MajorOSVersion", "ExportRVA", "ExportSize", "IatVRA",
    "MajorLinkerVersion", "MinorLinkerVersion", "NumberOfSections",
    "SizeOfStackReserve", "DllCharacteristics", "ResourceSize",
    "BitcoinAddresses"
]

TARGET_COLUMN = "Benign"


def generate_pe_dataset(n_samples: int = 3500, seed: int = RANDOM_SEED) -> pd.DataFrame:
    """Generates a representative PE header dataset modeling benign software (e.g. system utilities,
    standard compiled applications) and malicious/suspicious executables (e.g. trojans, droppers, packed binaries).
    """
    rng = np.random.default_rng(seed)
    n_benign = int(n_samples * 0.55)
    n_malicious = n_samples - n_benign

    records = []

    # 1. Benign Executables (Benign = 1)
    benign_names = [
        "svchost.exe", "explorer.exe", "notepad.exe", "calc.exe", "chrome.exe",
        "code.exe", "runtimebroker.exe", "taskhostw.exe", "msedge.exe", "slack.exe",
        "excel.exe", "word.exe", "python.exe", "git.exe", "powershell.exe",
        "conhost.exe", "dllhost.exe", "spoolsv.exe", "cmd.exe", "services.exe"
    ]

    for i in range(n_benign):
        base_name = rng.choice(benign_names)
        fname = f"{base_name}" if i < len(benign_names) else f"{base_name[:-4]}_{i}.exe"
        h = hashlib.md5(f"benign_{i}_{fname}".encode()).hexdigest()

        machine = rng.choice([332, 34404], p=[0.25, 0.75])  # x86 (332) or x64 (34404)
        has_debug = rng.choice([True, False], p=[0.75, 0.25])
        debug_size = int(rng.choice([28, 56, 84])) if has_debug else 0
        debug_rva = int(rng.integers(4096, 65536)) if has_debug else 0

        major_img = int(rng.choice([0, 1, 6, 10]))
        major_os = int(rng.choice([5, 6, 10]))
        has_export = rng.choice([True, False], p=[0.35, 0.65])
        export_rva = int(rng.integers(4096, 131072)) if has_export else 0
        export_size = int(rng.integers(120, 8192)) if has_export else 0

        iat_rva = int(rng.integers(4096, 32768))
        major_linker = int(rng.choice([10, 11, 12, 14, 15]))
        minor_linker = int(rng.choice([0, 10, 20, 30]))
        n_sections = int(rng.integers(4, 9))  # Standard .text, .data, .rdata, .rsrc, .reloc
        stack_res = int(rng.choice([1048576, 2097152, 524288]))  # 1MB / 2MB common defaults
        dll_chars = int(rng.choice([33088, 33120, 33152, 32768]))  # Standard NX_COMPAT, DYNAMIC_BASE
        rsrc_size = int(rng.integers(2048, 150000))
        btc_addrs = 0  # Benign executables don't embed cryptocurrency ransom wallets

        records.append({
            "FileName": fname,
            "md5Hash": h,
            "Machine": machine,
            "DebugSize": debug_size,
            "DebugRVA": debug_rva,
            "MajorImageVersion": major_img,
            "MajorOSVersion": major_os,
            "ExportRVA": export_rva,
            "ExportSize": export_size,
            "IatVRA": iat_rva,
            "MajorLinkerVersion": major_linker,
            "MinorLinkerVersion": minor_linker,
            "NumberOfSections": n_sections,
            "SizeOfStackReserve": stack_res,
            "DllCharacteristics": dll_chars,
            "ResourceSize": rsrc_size,
            "BitcoinAddresses": btc_addrs,
            "Benign": 1
        })

    # 2. Malicious Executables (Benign = 0)
    malicious_prefixes = [
        "dropper_payload", "invoice_macro_exec", "loader_x64", "crypt_stage",
        "svchost_mimic", "setup_crack", "keygenerator", "locker_v3", "system_patcher",
        "ransom_broker", "agent_stealer", "trojan_builder", "update_downloader"
    ]

    for i in range(n_malicious):
        pfx = rng.choice(malicious_prefixes)
        fname = f"{pfx}_{i}.exe"
        h = hashlib.md5(f"malware_{i}_{fname}".encode()).hexdigest()

        machine = rng.choice([332, 34404], p=[0.60, 0.40])  # Malware often targets 32-bit for compatibility
        has_debug = rng.choice([True, False], p=[0.20, 0.80])  # Malware often strips debug info
        debug_size = int(rng.choice([28, 56])) if has_debug else 0
        debug_rva = int(rng.integers(1024, 16384)) if has_debug else 0

        major_img = int(rng.choice([0, 1, 2, 4, 99]))
        major_os = int(rng.choice([4, 5, 0]))  # Often spoofed or older OS target
        has_export = rng.choice([True, False], p=[0.10, 0.90])
        export_rva = int(rng.integers(1024, 32768)) if has_export else 0
        export_size = int(rng.integers(50, 2048)) if has_export else 0

        iat_rva = int(rng.integers(512, 16384))
        major_linker = int(rng.choice([6, 7, 8, 9, 10, 0]))  # Outdated or non-MS linkers (Delphi, MinGW)
        minor_linker = int(rng.choice([0, 5, 12]))
        # Anomalous section counts (e.g. 1-2 for packed UPX, or 10+ for layered payloads)
        n_sections = int(rng.choice([1, 2, 3, 10, 12, 14], p=[0.25, 0.25, 0.15, 0.15, 0.10, 0.10]))
        stack_res = int(rng.choice([262144, 1048576, 4194304, 65536]))
        dll_chars = int(rng.choice([0, 1024, 32768, 33088]))  # Often lack ASLR/DEP (0 or legacy)
        rsrc_size = int(rng.integers(100000, 1500000))  # Often embeds heavy packed binary in resource
        btc_addrs = int(rng.choice([0, 1, 2, 3], p=[0.60, 0.25, 0.10, 0.05]))

        records.append({
            "FileName": fname,
            "md5Hash": h,
            "Machine": machine,
            "DebugSize": debug_size,
            "DebugRVA": debug_rva,
            "MajorImageVersion": major_img,
            "MajorOSVersion": major_os,
            "ExportRVA": export_rva,
            "ExportSize": export_size,
            "IatVRA": iat_rva,
            "MajorLinkerVersion": major_linker,
            "MinorLinkerVersion": minor_linker,
            "NumberOfSections": n_sections,
            "SizeOfStackReserve": stack_res,
            "DllCharacteristics": dll_chars,
            "ResourceSize": rsrc_size,
            "BitcoinAddresses": btc_addrs,
            "Benign": 0
        })

    df = pd.DataFrame(records)
    # Shuffle
    df = df.sample(frac=1.0, random_state=seed).reset_index(drop=True)
    return df


def train_and_compare_models(csv_path: str = None):
    """Trains Random Forest, Decision Tree, Support Vector Machine (SVM), and Gradient Boosting.
    Evaluates each model, produces comparative metrics, and saves artifacts.
    """
    base_dir = os.path.dirname(os.path.abspath(__file__))
    saved_dir = os.path.join(base_dir, "saved_model")
    dataset_dir = os.path.join(base_dir, "dataset")
    os.makedirs(saved_dir, exist_ok=True)
    os.makedirs(dataset_dir, exist_ok=True)

    default_csv = os.path.join(dataset_dir, "pe_malware_dataset.csv")

    if csv_path and os.path.exists(csv_path):
        print(f"[*] Loading PE dataset from: {csv_path}")
        df = pd.read_csv(csv_path)
    elif os.path.exists(default_csv):
        print(f"[*] Loading existing PE dataset from: {default_csv}")
        df = pd.read_csv(default_csv)
    else:
        print("[*] Generating representative PE header dataset...")
        df = generate_pe_dataset(n_samples=3500, seed=RANDOM_SEED)
        df.to_csv(default_csv, index=False)
        print(f"[+] Saved dataset to: {default_csv}")

    # Validate columns
    missing = [c for c in FEATURE_COLUMNS + [TARGET_COLUMN] if c not in df.columns]
    if missing:
        raise ValueError(f"Dataset is missing required columns: {missing}")

    X = df[FEATURE_COLUMNS]
    y = df[TARGET_COLUMN].astype(int)

    print(f"[*] Total dataset size: {len(df)} samples ({sum(y == 1)} Benign, {sum(y == 0)} Malicious)")
    print(f"[*] Feature columns: {len(FEATURE_COLUMNS)} (Excluded identifiers: FileName, md5Hash)")

    # Stratified Train/Test Split (80% train, 20% test)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=RANDOM_SEED, stratify=y
    )

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # Models to compare
    models = {
        "Random Forest": {
            "model": RandomForestClassifier(n_estimators=100, max_depth=12, random_state=RANDOM_SEED, n_jobs=-1),
            "use_scaled": False
        },
        "Decision Tree": {
            "model": DecisionTreeClassifier(max_depth=10, random_state=RANDOM_SEED),
            "use_scaled": False
        },
        "Support Vector Machine (SVM)": {
            "model": SVC(kernel="rbf", C=1.0, probability=True, random_state=RANDOM_SEED),
            "use_scaled": True
        },
        "Gradient Boosting": {
            "model": GradientBoostingClassifier(n_estimators=80, learning_rate=0.1, max_depth=5, random_state=RANDOM_SEED),
            "use_scaled": False
        }
    }

    comparison_results = {}
    best_model_name = None
    best_f1 = -1.0

    print("\n" + "=" * 70)
    print(" PE Executable Malware Classifier Model Comparison ")
    print("=" * 70)

    for name, item in models.items():
        clf = item["model"]
        X_tr = X_train_scaled if item["use_scaled"] else X_train
        X_te = X_test_scaled if item["use_scaled"] else X_test

        clf.fit(X_tr, y_train)
        y_pred = clf.predict(X_te)

        acc = accuracy_score(y_test, y_pred)
        prec = precision_score(y_test, y_pred, zero_division=0)
        rec = recall_score(y_test, y_pred, zero_division=0)
        f1 = f1_score(y_test, y_pred, zero_division=0)
        cm = confusion_matrix(y_test, y_pred)
        tn, fp, fn, tp = cm.ravel()

        comparison_results[name] = {
            "accuracy": round(float(acc), 4),
            "precision": round(float(prec), 4),
            "recall": round(float(rec), 4),
            "f1_score": round(float(f1), 4),
            "confusion_matrix": {
                "true_negative": int(tn),
                "false_positive": int(fp),
                "false_negative": int(fn),
                "true_positive": int(tp)
            }
        }

        print(f"[{name}] Acc: {acc:.4f} | Prec: {prec:.4f} | Rec: {rec:.4f} | F1: {f1:.4f} (TP={tp}, FP={fp}, TN={tn}, FN={fn})")

        if f1 > best_f1:
            best_f1 = f1
            best_model_name = name

    print("=" * 70)
    print(f"[+] Champion Model Selected: {best_model_name} (F1-Score: {best_f1:.4f})\n")

    # Persist the champion model and preprocessor
    champion_clf = models[best_model_name]["model"]
    model_artifact_path = os.path.join(saved_dir, "pe_classifier.joblib")
    scaler_artifact_path = os.path.join(saved_dir, "pe_scaler.joblib")

    joblib.dump(champion_clf, model_artifact_path)
    joblib.dump(scaler, scaler_artifact_path)

    # Feature importances (if available)
    feature_importances = {}
    if hasattr(champion_clf, "feature_importances_"):
        for feat, imp in zip(FEATURE_COLUMNS, champion_clf.feature_importances_):
            feature_importances[feat] = round(float(imp), 4)
        feature_importances = dict(sorted(feature_importances.items(), key=lambda item: item[1], reverse=True))

    metadata = {
        "model_name": f"PE-Malware-Classifier ({best_model_name})",
        "algorithm": best_model_name,
        "training_timestamp": datetime.now(timezone.utc).isoformat(),
        "random_seed": RANDOM_SEED,
        "total_dataset_size": len(df),
        "train_samples": len(X_train),
        "test_samples": len(X_test),
        "feature_columns": FEATURE_COLUMNS,
        "excluded_columns": ["FileName", "md5Hash"],
        "target_mapping": {
            "1": "Benign (Clean Application)",
            "0": "Malicious (Executable Threat / Dropper)"
        },
        "evaluation_metrics": comparison_results[best_model_name],
        "feature_importances": feature_importances,
        "disclaimer": (
            "This model classifies general executable binaries as benign or malicious based on PE header "
            "structural properties. It does not solely identify ransomware specifically, and is separated "
            "from Layer 1 behavioural anomaly detection."
        )
    }

    meta_path = os.path.join(saved_dir, "pe_model_metadata.json")
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    comp_path = os.path.join(saved_dir, "pe_model_comparison.json")
    with open(comp_path, "w", encoding="utf-8") as f:
        json.dump({
            "champion": best_model_name,
            "models": comparison_results,
            "training_timestamp": metadata["training_timestamp"]
        }, f, indent=2)

    print(f"[+] Saved PE model to: {model_artifact_path}")
    print(f"[+] Saved comparison report to: {comp_path}")
    print(f"[+] Saved metadata to: {meta_path}")

    return model_artifact_path, meta_path, comp_path


if __name__ == "__main__":
    train_and_compare_models()
