# RansomWatch — Behaviour-Based Ransomware Detection Using Explainable AI

**Network Security & Cryptography | Manav Rachna University**  
*Defensive Cybersecurity Prototype & Behavioral Telemetry Analyzer*

---

## 1. Executive Summary

Traditional signature-based antivirus solutions struggle against novel, polymorphically packed, or zero-day ransomware strains because cryptographic payloads can execute before signatures are published. **RansomWatch** is a next-generation, defensive cybersecurity prototype designed to demonstrate **behavior-based detection** combined with **unsupervised Machine Learning (Isolation Forest)** and **Explainable AI (XAI)** threat scoring.

Rather than relying on static file hashes or single-threshold indicators, RansomWatch correlates **15 multi-dimensional behavioral parameters**—including file modification rates, rename velocity, directory traversal breadth, Shannon entropy shifts, and simulated shadow copy tampering—to synthesize a calibrated threat score (0–100) and generate human-readable explanations tailored specifically to the forensic indicators observed in each event.

---

## 2. Key Architectural Pillars

```
+---------------------------------------------------------------------------------------------------+
|                                  RansomWatch System Architecture                                  |
+---------------------------------------------------------------------------------------------------+
|                                                                                                   |
|  [ Endpoint Behavioral Telemetry / Simulated Scenarios ]                                         |
|         │                                                                                         |
|         ▼                                                                                         |
|  [ Feature Extractor & Shannon Entropy Calculator ] ── (15 Behavioral Parameters)                |
|         │                                                                                         |
|         ├─────────────────────────────────────────┐                                               |
|         ▼                                         ▼                                               |
|  [ Configurable Rule Engine ]            [ Isolation Forest ML Detector ]                        |
|  - 14 Heuristic Rules                    - scikit-learn Unsupervised Ensemble                     |
|  - Dynamic Threshold Tuning              - Calibrated Anomaly Score (0–100)                       |
|  - Contributor Severity Analysis         - Trained on Synthetic Distributions                     |
|         │                                         │                                               |
|         └────────────────────┬────────────────────┘                                               |
|                              ▼                                                                    |
|              [ Explainable Risk Scoring Engine ]                                                  |
|              - Weighted Composite Score: (Rule × 60%) + (ML × 40%)                                |
|              - Risk Categorization: LOW, MEDIUM, HIGH, CRITICAL                                   |
|              - Dynamic, Non-Hardcoded Narrative Explanation                                       |
|              - Tailored Containment Recommendations                                               |
|                              │                                                                    |
|                              ├──────────────────────────────┐                                     |
|                              ▼                              ▼                                     |
|                 [ SQLite Incident Store ]       [ Modern Cyber UI Dashboard ]                     |
|                 - Incidents & Alerts            - Dark Navy & Neon Cyan Glassmorphism             |
|                 - Telemetry Audit History       - Interactive Detection Lab (7 Scenarios)         |
|                 - Simulated Action Logs         - Chart.js Trend Visualizations                   |
|                 - CSV / JSON Export             - Response Playbook Simulation                    |
+---------------------------------------------------------------------------------------------------+
```

---

## 3. The 15 Multi-Parameter Behavioral Indicators

RansomWatch extracts and evaluates 15 distinct behavioral features representing the lifecycle of an encryptor loop:

| # | Parameter Name | Metric / Unit | Benign Baseline | Suspicious Threshold | Defensive Significance |
|---|----------------|---------------|-----------------|----------------------|------------------------|
| **1** | `file_modification_rate` | files/sec | ~1.2 | > 12.0 | Velocity of writing/overwriting file contents. |
| **2** | `file_rename_frequency` | renames/min | ~0.5 | > 10.0 | High-frequency rename operations typical of extension appending. |
| **3** | `file_deletion_frequency` | deletes/min | ~0.2 | > 8.0 | Velocity of unlinking original files after staging ciphertext. |
| **4** | `unique_directories_accessed`| dirs | 1–3 | > 6 | Breadth of recursive traversal across user libraries and network shares. |
| **5** | `unique_files_affected` | count | < 15 | > 40 | Total individual file descriptors manipulated. |
| **6** | `suspicious_extension_changes`| events | 0 | &ge; 1 | Renaming to known ransomware markers (`.locked`, `.wnry`, `.crypto`). |
| **7** | `file_ops_per_process` | total ops | < 45 | > 90 | Cumulative I/O handle allocations requested by the process PID. |
| **8** | `unique_files_per_process` | count | < 12 | > 35 | Target files opened exclusively by a single binary instance. |
| **9** | `rapid_sequential_modifications`| bursts | 0 | > 5 | Sub-50ms automated write bursts bypassing human keystroke intervals. |
| **10**| `file_entropy_delta` | &Delta; bits/byte | ~0.1 | &ge; 2.2 | Shannon entropy surge from plaintext (~3.5) to ciphertext (~7.9). |
| **11**| `unusual_write_burst_frequency`| bursts/min | < 0.5 | > 4.0 | Episodic buffer write spikes characteristic of multi-threaded encryptors. |
| **12**| `ransom_note_indicators` | count | 0 | &ge; 1 | Creation of instructional notes (`HOW_TO_RESTORE.txt`, `README_DECRYPT.txt`). |
| **13**| `unusual_type_conversions` | conversions | 0 | &ge; 2 | Standard MIME structures replaced by unstructured binary blobs. |
| **14**| `process_activity_deviation` | &sigma; (z-score) | < 1.0 | > 3.0 | Statistical divergence from historical benign baseline profiling. |
| **15**| `backup_tamper_attempts` | attempts | 0 | &ge; 1 | Safe simulation of probing Volume Shadow Copies (`vssadmin delete shadows`). |

---

## 4. Machine Learning & Explainable AI (XAI)

### Unsupervised Isolation Forest Anomaly Detection
- **Algorithm**: `sklearn.ensemble.IsolationForest`
- **Ensemble Depth**: 150 Isolation Trees (`n_estimators=150`)
- **Contamination**: 0.153 (estimated baseline outlier ratio)
- **Reproducibility**: Fixed pseudo-random seed (`RANDOM_SEED = 42`)
- **Calibrated Scoring Formula**: Transforms raw decision function values ($[-0.35, +0.25]$) to an intuitive 0–100 scale:
  $$\text{Calibrated Score} = \max(0, \min(100, 50.0 - (\text{raw\_score} \times 200.0)))$$

### Composite Threat Scoring Formula
The system combines the deterministic rule engine and the ML model with configurable weights (default: 60% Rule, 40% ML):
$$\text{Risk Score} = (\text{Rule Score} \times 0.60) + (\text{ML Anomaly Score} \times 0.40)$$

Categorical Risk Levels:
- **LOW**: $0.0 \le \text{Score} < 30.0$
- **MEDIUM**: $30.0 \le \text{Score} < 60.0$
- **HIGH**: $60.0 \le \text{Score} < 85.0$
- **CRITICAL**: $85.0 \le \text{Score} \le 100.0$

### Dynamic, Non-Hardcoded Narrative Explanations
Rather than outputting static alert templates, RansomWatch constructs tailored narrative sentences parsing the exact active indicators for each incident. For example:
> *"CRITICAL-risk activity detected for process 'mal_encryptor.exe' (PID 6660) because the process attempted to tamper with backup/shadow copy services (2 event(s)); created known ransom note instructional files (8 file(s)); appended known ransomware extensions to 35 file(s); exhibited an abnormal file entropy surge (+3.85 bits/byte) indicative of cryptographic payload execution; modified files at an excessive velocity (36.0 files/s). Furthermore, the Isolation Forest detector flagged the process as an unsupervised statistical outlier (calibrated anomaly score: 98.4/100, raw decision score: -0.242)."*

---

## 5. Directory Structure

```
ransomwatch/
├── app/
│   ├── __init__.py
│   ├── main.py                  # FastAPI application entrypoint, CORS, static routes
│   ├── schemas.py               # Pydantic schemas for behavioral parameters & API validation
│   ├── feature_extractor.py     # 15 behavioral parameters, presets & Shannon entropy calculator
│   ├── detection_engine.py      # Rule engine evaluating configurable thresholds
│   ├── rules_config.py          # Heuristic rules and default threshold definitions
│   ├── model_service.py         # Isolation Forest model loading, prediction & score calibration
│   ├── risk_scoring.py          # Composite threat scoring & dynamic explanation generator
│   └── incident_store.py        # SQLite persistence layer for alerts, events & audit history
├── frontend/
│   ├── index.html               # Modern cybersecurity dashboard
│   ├── styles.css               # Dark navy glassmorphism & responsive CSS3 styling
│   └── app.js                   # Chart.js charts, real-time lab tuner & response simulation
├── ml/
│   ├── __init__.py
│   ├── train_model.py           # Reproducible training pipeline with synthetic dataset
│   ├── evaluate_model.py        # Held-out evaluation script (Precision, Recall, F1, FPR)
│   └── saved_model/
│       ├── isolation_forest.joblib  # Trained scikit-learn model artifact
│       ├── model_metadata.json      # Training metadata & hyperparameter records
│       └── evaluation_report.json   # Held-out benchmark metrics
├── tests/
│   ├── test_detection_engine.py # Tests for rule triggers, threshold updates & contributors
│   ├── test_model_service.py    # Tests for Isolation Forest loading, benign/anomaly inference
│   ├── test_risk_scoring.py     # Tests for dynamic explanation uniqueness & recommendations
│   ├── test_incident_store.py   # Tests for SQLite CRUD, audit logging & CSV/JSON export
│   └── test_api.py              # Tests for FastAPI route handlers & schema validation
├── requirements.txt             # Python project dependencies
└── README.md                    # Project documentation & presentation guide
```

---

## 6. Setup & Execution Instructions (Windows)

### Step 1: Open Terminal in Project Directory
```powershell
cd C:\Users\kantg\.gemini\antigravity\scratch\ransomwatch
```

### Step 2: Install Dependencies
```powershell
python -m pip install -r requirements.txt
```

### Step 3: Train / Retrain the Machine Learning Model
The repository includes a pre-trained model artifact. To retrain the model with the fixed random seed (42):
```powershell
python ml/train_model.py
```

### Step 4: Run Model Evaluation Benchmark
To test the model on an independent held-out synthetic test set:
```powershell
python -m ml.evaluate_model
```

### Step 5: Run Automated Test Suite
To verify that all 24 automated test cases pass:
```powershell
python -m pytest tests -v
```

### Step 6: Launch the RansomWatch Server
Start the FastAPI server via Uvicorn:
```powershell
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

### Step 7: Access the Dashboard
Open your web browser and navigate to:
```
http://localhost:8000
```
Interactive API documentation is also available at:
```
http://localhost:8000/docs
```

---



## 8. Safety & Ethical Disclosure

RansomWatch is strictly an **educational defensive system**:
- It **never** executes ransomware, encrypts user files, or executes destructive payloads.
- It operates on **in-memory behavioral vectors** and synthetic telemetry.
- It requires **no administrator privileges** to demonstrate.
- All simulated containment actions are clearly labeled to prevent confusion with actual host intervention.
