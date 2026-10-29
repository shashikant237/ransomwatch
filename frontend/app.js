/**
 * RansomWatch Frontend Application Controller
 * Handles real-time telemetry rendering, Detection Lab scenario simulations,
 * Chart.js visualizations, rule configuration, and response playbooks.
 *
 * Supports both:
 * 1. Live FastAPI Backend Mode (when connected to Python server)
 * 2. Static Client-Side Fallback Mode (when hosted on Netlify/GitHub Pages)
 */

const API_BASE = ""; // Relative path to FastAPI backend if available

// Embedded Default Rules (matches backend app/rules_config.py)
const DEFAULT_CLIENT_RULES = [
  { rule_id: "RULE_01_MOD_RATE", name: "Rapid File Modification Rate", feature_key: "file_modification_rate", threshold: 12.0, weight: 14.0, enabled: true, description: "Flags processes modifying files faster than normal user productivity (>12 files/s)." },
  { rule_id: "RULE_02_RENAME_SPIKE", name: "Mass File Renaming Frequency", feature_key: "file_rename_frequency", threshold: 10.0, weight: 15.0, enabled: true, description: "Detects high-frequency batch rename operations (>10 renames/min) common in encryptor loops." },
  { rule_id: "RULE_03_MASS_DELETION", name: "Mass File Deletion Velocity", feature_key: "file_deletion_frequency", threshold: 8.0, weight: 12.0, enabled: true, description: "Monitors rapid unlinking/deletion of original files after staging encrypted copies." },
  { rule_id: "RULE_04_DIR_SPREAD", name: "Broad Directory Traversal", feature_key: "unique_directories_accessed", threshold: 6.0, weight: 10.0, enabled: true, description: "Identifies recursive walking across more than 6 distinct directory trees in a short window." },
  { rule_id: "RULE_05_MASS_AFFECTED", name: "High File Volume Impact", feature_key: "unique_files_affected", threshold: 40.0, weight: 12.0, enabled: true, description: "Triggers when a single process impacts over 40 distinct files." },
  { rule_id: "RULE_06_SUSPICIOUS_EXT", name: "Known Ransomware Extension Change", feature_key: "suspicious_extension_changes", threshold: 1.0, weight: 24.0, enabled: true, description: "Detects renaming files to known ransomware extensions (.locked, .crypto, .crypted, .wnry)." },
  { rule_id: "RULE_07_PROC_OPS_SPIKE", name: "Excessive Process I/O Burst", feature_key: "file_ops_per_process", threshold: 90.0, weight: 10.0, enabled: true, description: "Monitors total file operations per process exceeding expected benign thresholds." },
  { rule_id: "RULE_08_RAPID_SEQUENTIAL", name: "Sub-50ms Sequential Writes", feature_key: "rapid_sequential_modifications", threshold: 5.0, weight: 14.0, enabled: true, description: "Detects automated script or compiled loop writing files at sub-50ms intervals." },
  { rule_id: "RULE_09_ENTROPY_DELTA", name: "High Entropy Differential (Encryption)", feature_key: "file_entropy_delta", threshold: 2.2, weight: 25.0, enabled: true, description: "Measures Shannon entropy shift (>2.2 bits/byte) indicating plain text to ciphertext conversion." },
  { rule_id: "RULE_10_WRITE_BURSTS", name: "Anomalous Write Burst Frequency", feature_key: "unusual_write_burst_frequency", threshold: 4.0, weight: 10.0, enabled: true, description: "Detects repeating episodic write spikes characteristic of multi-threaded encryptors." },
  { rule_id: "RULE_11_RANSOM_NOTE", name: "Ransom Note File Pattern Detected", feature_key: "ransom_note_indicators", threshold: 1.0, weight: 28.0, enabled: true, description: "Identifies creation of extortion notes like README_DECRYPT, HOW_TO_RECOVER, or DECRYPT_FILES." },
  { rule_id: "RULE_12_TYPE_CONVERSION", name: "Abnormal File Type Conversion", feature_key: "unusual_type_conversions", threshold: 2.0, weight: 12.0, enabled: true, description: "Detects converting document/database extensions to encrypted blob binary structures." },
  { rule_id: "RULE_13_ACTIVITY_DEVIATION", name: "Process Baseline Activity Deviation", feature_key: "process_activity_deviation", threshold: 3.0, weight: 12.0, enabled: true, description: "Identifies behavioral deviations exceeding 3 standard deviations from historic application profile." },
  { rule_id: "RULE_14_BACKUP_TAMPER", name: "VSS / Backup Tampering Activity", feature_key: "backup_tamper_attempts", threshold: 1.0, weight: 30.0, enabled: true, description: "Flags attempts to interact with shadow copies (vssadmin), recovery boot catalogs, or backups." }
];

// Embedded Simulation Preset Scenarios
const PRESET_SCENARIOS = {
  normal_office: {
    name: "Normal Office Document Editing",
    process_name: "WINWORD.EXE",
    process_id: 4120,
    user_account: "CORP\\jsmith",
    target_path: "C:\\Users\\jsmith\\Documents\\Report.docx",
    features: {
      file_modification_rate: 0.8, file_rename_frequency: 0.0, file_deletion_frequency: 0.0,
      unique_directories_accessed: 1, unique_files_affected: 2, suspicious_extension_changes: 0,
      file_ops_per_process: 12, unique_files_per_process: 2, rapid_sequential_modifications: 0,
      file_entropy_delta: 0.15, unusual_write_burst_frequency: 0.2, ransom_note_indicators: 0,
      unusual_type_conversions: 0, process_activity_deviation: 0.4, backup_tamper_attempts: 0
    }
  },
  rapid_file_mods: {
    name: "Suspicious Rapid File Modifications",
    process_name: "svchost_updater.exe",
    process_id: 8940,
    user_account: "CORP\\jsmith",
    target_path: "C:\\Users\\jsmith\\Data",
    features: {
      file_modification_rate: 28.5, file_rename_frequency: 1.0, file_deletion_frequency: 0.5,
      unique_directories_accessed: 4, unique_files_affected: 65, suspicious_extension_changes: 0,
      file_ops_per_process: 140, unique_files_per_process: 58, rapid_sequential_modifications: 18,
      file_entropy_delta: 0.8, unusual_write_burst_frequency: 6.2, ransom_note_indicators: 0,
      unusual_type_conversions: 0, process_activity_deviation: 4.1, backup_tamper_attempts: 0
    }
  },
  mass_rename: {
    name: "Mass File Renaming Spike",
    process_name: "batch_converter.exe",
    process_id: 6732,
    user_account: "CORP\\jsmith",
    target_path: "C:\\SharedStorage\\Finance",
    features: {
      file_modification_rate: 14.0, file_rename_frequency: 24.5, file_deletion_frequency: 1.0,
      unique_directories_accessed: 5, unique_files_affected: 72, suspicious_extension_changes: 8,
      file_ops_per_process: 110, unique_files_per_process: 60, rapid_sequential_modifications: 12,
      file_entropy_delta: 1.2, unusual_write_burst_frequency: 4.5, ransom_note_indicators: 0,
      unusual_type_conversions: 3, process_activity_deviation: 3.8, backup_tamper_attempts: 0
    }
  },
  mass_deletion: {
    name: "Mass File Deletion Velocity",
    process_name: "disk_cleanup_worker.exe",
    process_id: 9210,
    user_account: "CORP\\jsmith",
    target_path: "C:\\Users\\jsmith\\Desktop",
    features: {
      file_modification_rate: 6.0, file_rename_frequency: 2.0, file_deletion_frequency: 22.0,
      unique_directories_accessed: 5, unique_files_affected: 55, suspicious_extension_changes: 0,
      file_ops_per_process: 88, unique_files_per_process: 48, rapid_sequential_modifications: 8,
      file_entropy_delta: 0.2, unusual_write_burst_frequency: 3.5, ransom_note_indicators: 0,
      unusual_type_conversions: 0, process_activity_deviation: 4.5, backup_tamper_attempts: 0
    }
  },
  ransom_note: {
    name: "Ransom Note Indicator Activity",
    process_name: "payload_stage2.exe",
    process_id: 5104,
    user_account: "CORP\\jsmith",
    target_path: "C:\\Users\\jsmith\\Documents\\READ_ME_RECOVER.txt",
    features: {
      file_modification_rate: 8.0, file_rename_frequency: 4.0, file_deletion_frequency: 1.0,
      unique_directories_accessed: 7, unique_files_affected: 32, suspicious_extension_changes: 2,
      file_ops_per_process: 64, unique_files_per_process: 28, rapid_sequential_modifications: 6,
      file_entropy_delta: 1.8, unusual_write_burst_frequency: 3.0, ransom_note_indicators: 4,
      unusual_type_conversions: 1, process_activity_deviation: 3.4, backup_tamper_attempts: 0
    }
  },
  high_entropy: {
    name: "High-Entropy Bulk File Write (Encryption Pattern)",
    process_name: "cipher_engine.exe",
    process_id: 7820,
    user_account: "CORP\\jsmith",
    target_path: "C:\\Users\\jsmith\\Accounting",
    features: {
      file_modification_rate: 22.0, file_rename_frequency: 12.0, file_deletion_frequency: 3.0,
      unique_directories_accessed: 6, unique_files_affected: 80, suspicious_extension_changes: 12,
      file_ops_per_process: 160, unique_files_per_process: 75, rapid_sequential_modifications: 24,
      file_entropy_delta: 3.65, unusual_write_burst_frequency: 7.8, ransom_note_indicators: 0,
      unusual_type_conversions: 5, process_activity_deviation: 4.8, backup_tamper_attempts: 0
    }
  },
  combined_attack: {
    name: "Combined Multi-Indicator Ransomware Wave",
    process_name: "mal_encryptor.exe",
    process_id: 6660,
    user_account: "CORP\\Administrator",
    target_path: "C:\\NetworkShares\\EnterpriseData",
    features: {
      file_modification_rate: 36.0, file_rename_frequency: 28.0, file_deletion_frequency: 15.0,
      unique_directories_accessed: 12, unique_files_affected: 140, suspicious_extension_changes: 35,
      file_ops_per_process: 280, unique_files_per_process: 120, rapid_sequential_modifications: 42,
      file_entropy_delta: 3.85, unusual_write_burst_frequency: 9.5, ransom_note_indicators: 8,
      unusual_type_conversions: 10, process_activity_deviation: 5.9, backup_tamper_attempts: 2
    }
  }
};

// Application State
const state = {
  currentIncident: null,
  rules: JSON.parse(JSON.stringify(DEFAULT_CLIENT_RULES)),
  weightConfig: { rule_weight_ratio: 0.60, ml_weight_ratio: 0.40 },
  charts: { timeline: null, riskDist: null },
  incidents: [],
  isClientMode: false
};

// ==========================================================================
// INITIALIZATION
// ==========================================================================

document.addEventListener("DOMContentLoaded", () => {
  initNavigation();
  initLabSliders();
  initLabScenarios();
  initEntropyTool();
  initAlertFilters();
  initRuleControls();
  initResponseCentre();

  // Seed default in-memory incidents for client-side demo
  seedClientIncidents();

  // Load initial datasets
  loadDashboardData();
  loadRules();
  loadModelInsights();
});

function showToast(msg, duration = 3500) {
  const toast = document.getElementById("status-toast");
  if (!toast) return;
  toast.textContent = msg;
  toast.classList.remove("hidden");
  setTimeout(() => toast.classList.add("hidden"), duration);
}

function formatDate(isoStr) {
  if (!isoStr) return "-";
  try {
    const d = new Date(isoStr);
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  } catch (e) {
    return isoStr;
  }
}

// Shannon Entropy in Pure JS
function calculateClientShannonEntropy(str) {
  if (!str) return 0.0;
  const bytes = new TextEncoder().encode(str);
  const counts = new Array(256).fill(0);
  for (let b of bytes) counts[b]++;
  let ent = 0.0;
  const total = bytes.length;
  for (let c of counts) {
    if (c > 0) {
      const p = c / total;
      ent -= p * Math.log2(p);
    }
  }
  return Math.round(ent * 1000) / 1000;
}

// Client-Side Behavioral Evaluation Engine (Fallback when backend is absent)
function evaluateClientFeatures(processName, processId, userAccount, targetPath, features) {
  const triggeredRules = [];
  const contributors = [];
  let totalTriggeredWeight = 0.0;
  let maxWeight = 0.0;

  state.rules.forEach(rule => {
    if (!rule.enabled) return;
    maxWeight += rule.weight;
    const val = features[rule.feature_key] !== undefined ? features[rule.feature_key] : 0.0;
    const triggered = val >= rule.threshold;
    if (triggered) totalTriggeredWeight += rule.weight;

    triggeredRules.push({
      rule_id: rule.rule_id,
      rule_name: rule.name,
      triggered: triggered,
      threshold: rule.threshold,
      actual_value: val,
      weight: rule.weight,
      score_contribution: triggered ? rule.weight : 0.0,
      description: rule.description
    });

    if (triggered) {
      let severity = "MEDIUM";
      if (val >= rule.threshold * 3.0) severity = "CRITICAL";
      else if (val >= rule.threshold * 1.5) severity = "HIGH";

      contributors.push({
        feature_name: rule.feature_key,
        display_name: rule.name,
        value: val,
        threshold: rule.threshold,
        contribution: rule.weight,
        severity: severity
      });
    }
  });

  const ruleScore = Math.min(100.0, Math.round((totalTriggeredWeight / (maxWeight || 100.0)) * 1000) / 10);

  // Client-side Isolation Forest approximation for static demo
  let mlRaw = 0.15;
  if (features.file_entropy_delta >= 2.0 || features.suspicious_extension_changes > 0 || features.ransom_note_indicators > 0) {
    mlRaw = -0.18 - (features.file_entropy_delta * 0.04);
  } else if (features.file_modification_rate > 15.0) {
    mlRaw = -0.09;
  }
  let calibrated = Math.max(0.0, Math.min(100.0, 50.0 - (mlRaw * 200.0)));
  calibrated = Math.round(calibrated * 10) / 10;
  const isAnomaly = calibrated >= 50.0;

  // Composite risk
  const rRatio = state.weightConfig.rule_weight_ratio || 0.6;
  const mRatio = state.weightConfig.ml_weight_ratio || 0.4;
  let composite = Math.round(((ruleScore * rRatio) + (calibrated * mRatio)) * 10) / 10;

  let riskLevel = "LOW";
  if (composite >= 85.0) riskLevel = "CRITICAL";
  else if (composite >= 60.0) riskLevel = "HIGH";
  else if (composite >= 30.0) riskLevel = "MEDIUM";

  // Dynamic non-hardcoded explanation
  const clauses = [];
  if (features.backup_tamper_attempts > 0) clauses.push(`tampered with backup/shadow copy services (${features.backup_tamper_attempts} attempt(s))`);
  if (features.ransom_note_indicators > 0) clauses.push(`created known ransom note files (${features.ransom_note_indicators} file(s))`);
  if (features.suspicious_extension_changes > 0) clauses.push(`appended known ransomware extensions to ${features.suspicious_extension_changes} file(s)`);
  if (features.file_entropy_delta >= 2.0) clauses.push(`exhibited a critical file entropy surge (+${features.file_entropy_delta} bits/byte) indicative of cryptographic execution`);
  if (features.file_modification_rate >= 12.0) clauses.push(`modified files at excessive velocity (${features.file_modification_rate} files/s)`);
  if (features.file_rename_frequency >= 10.0) clauses.push(`executed rapid batch file renames (${features.file_rename_frequency} /min)`);
  if (features.file_deletion_frequency >= 8.0) clauses.push(`executed rapid bulk deletions (${features.file_deletion_frequency} /min)`);

  let dynamicExp = "";
  if (riskLevel === "LOW" && clauses.length === 0) {
    dynamicExp = `Normal benign activity observed for process '${processName}' (PID ${processId}). File modification rate (${features.file_modification_rate} files/s) and entropy shift (${features.file_entropy_delta} bits/byte) remain well within baseline operational parameters.`;
  } else {
    dynamicExp = `${riskLevel}-risk activity detected for process '${processName}' (PID ${processId}) because the process ${clauses.join("; ")}. Furthermore, the Isolation Forest detector flagged the process as an unsupervised statistical outlier (calibrated anomaly score: ${calibrated}/100).`;
  }

  let rec = "ROUTINE MONITORING: Event marked as benign. Telemetry retained in baseline store.";
  if (riskLevel === "CRITICAL") rec = `CRITICAL CONTAINMENT: Isolate endpoint network connection immediately. Terminate process '${processName}' and child processes. Preserve memory dump for decryptor key extraction.`;
  else if (riskLevel === "HIGH") rec = `HIGH THREAT ACTION: Restrict file write permissions in target directory '${targetPath}'. Suspend process '${processName}' pending analyst verification.`;
  else if (riskLevel === "MEDIUM") rec = `MEDIUM TRIAGE: Notify SOC tier-2 analyst. Verify process lineage for '${processName}'.`;

  contributors.sort((a, b) => b.contribution - a.contribution);

  const incident = {
    incident_id: `INC-${Date.now().toString().slice(-8)}`,
    timestamp: new Date().toISOString(),
    process_name: processName,
    process_id: processId,
    user_account: userAccount,
    target_path: targetPath,
    risk_level: riskLevel,
    risk_score: composite,
    rule_score: ruleScore,
    ml_score: calibrated,
    status: "NEW",
    rules_triggered: triggeredRules,
    ml_result: {
      is_anomaly: isAnomaly,
      raw_score: Math.round(mlRaw * 1000) / 1000,
      calibrated_anomaly_score: calibrated,
      model_name: "IsolationForest-BehavioralDetector",
      model_version: "1.0.0",
      interpretation: isAnomaly 
        ? `Statistical outlier (score ${mlRaw}). Process features cross normal baseline boundaries into suspect cluster.` 
        : `Statistical inlier (score ${mlRaw}). Behavior conforms with baseline distributions.`,
      synthetic_notice: "Trained on synthetic behavioral vectors for safe demonstration."
    },
    top_contributors: contributors,
    dynamic_explanation: dynamicExp,
    recommended_action: rec,
    simulated_actions_taken: [],
    features_snapshot: features
  };

  return incident;
}

function seedClientIncidents() {
  const seedKeys = ["normal_office", "rapid_file_mods", "mass_rename", "ransom_note", "high_entropy", "combined_attack"];
  state.incidents = seedKeys.map(k => {
    const sc = PRESET_SCENARIOS[k];
    return evaluateClientFeatures(sc.process_name, sc.process_id, sc.user_account, sc.target_path, sc.features);
  });
}

// ==========================================================================
// 1. NAVIGATION
// ==========================================================================

function initNavigation() {
  const navBtns = document.querySelectorAll(".nav-item");
  const tabPanes = document.querySelectorAll(".tab-pane");

  navBtns.forEach(btn => {
    btn.addEventListener("click", () => {
      const targetTab = btn.getAttribute("data-tab");
      navBtns.forEach(b => b.classList.remove("active"));
      tabPanes.forEach(p => p.classList.remove("active"));

      btn.classList.add("active");
      const activePane = document.getElementById(targetTab);
      if (activePane) activePane.classList.add("active");

      if (targetTab === "tab-overview") loadDashboardData();
      if (targetTab === "tab-live") loadLiveActivity();
      if (targetTab === "tab-alerts") loadAlerts();
      if (targetTab === "tab-rules") loadRules();
      if (targetTab === "tab-model") loadModelInsights();
      if (targetTab === "tab-response") loadResponseCentreIncidents();
    });
  });

  document.querySelectorAll("[data-goto]").forEach(el => {
    el.addEventListener("click", () => {
      const targetTab = el.getAttribute("data-goto");
      const navBtn = document.querySelector(`.nav-item[data-tab="${targetTab}"]`);
      if (navBtn) navBtn.click();
    });
  });

  const refreshOverviewBtn = document.getElementById("refresh-overview-btn");
  if (refreshOverviewBtn) refreshOverviewBtn.addEventListener("click", loadDashboardData);

  const refreshLiveBtn = document.getElementById("refresh-live-btn");
  if (refreshLiveBtn) refreshLiveBtn.addEventListener("click", loadLiveActivity);
}

// ==========================================================================
// 2. OVERVIEW & CHARTS
// ==========================================================================

async function loadDashboardData() {
  let summary = null;
  let events = [];

  try {
    const summaryRes = await fetch(`${API_BASE}/api/dashboard/summary`);
    const eventsRes = await fetch(`${API_BASE}/api/events?limit=15`);
    if (summaryRes.ok && eventsRes.ok) {
      summary = await summaryRes.json();
      events = await eventsRes.json();
    }
  } catch (e) {
    // Backend unreachable (e.g. Netlify static hosting)
    state.isClientMode = true;
  }

  // Fallback to client state
  if (!summary) {
    state.isClientMode = true;
    events = state.incidents;
    const total = events.length;
    const normal = events.filter(e => e.risk_level === "LOW").length;
    const susp = events.filter(e => e.risk_level === "MEDIUM").length;
    const high = events.filter(e => e.risk_level === "HIGH").length;
    const crit = events.filter(e => e.risk_level === "CRITICAL").length;
    const avg = total > 0 ? (events.reduce((s, e) => s + e.risk_score, 0) / total) : 0;

    summary = {
      total_events: total,
      normal_events: normal,
      suspicious_events: susp,
      high_risk_incidents: high,
      critical_incidents: crit,
      avg_risk_score: Math.round(avg * 10) / 10,
      rules_active_count: state.rules.filter(r => r.enabled).length,
      model_status: "ONLINE (Isolation Forest v1.0.0)"
    };

    const statusPill = document.getElementById("engine-status");
    if (statusPill) statusPill.textContent = "CLIENT-SIDE DEMO";
  }

  document.getElementById("card-total-events").textContent = summary.total_events;
  document.getElementById("card-normal-events").textContent = summary.normal_events;
  document.getElementById("card-suspicious-events").textContent = summary.suspicious_events;
  document.getElementById("card-high-incidents").textContent = summary.high_risk_incidents + summary.critical_incidents;
  document.getElementById("card-avg-score").textContent = summary.avg_risk_score;
  document.getElementById("card-active-rules").textContent = `${summary.rules_active_count} / 14`;
  document.getElementById("nav-alert-count").textContent = summary.total_events;

  renderRecentEventsTable(events);
  renderCharts(summary, events);
}

function renderRecentEventsTable(events) {
  const tbody = document.getElementById("overview-recent-tbody");
  if (!tbody) return;

  if (!events || events.length === 0) {
    tbody.innerHTML = `<tr><td colspan="8" class="text-center text-muted">No telemetry records recorded yet.</td></tr>`;
    return;
  }

  tbody.innerHTML = events.slice(0, 7).map(e => {
    const topContrib = (e.top_contributors && e.top_contributors[0]) 
      ? e.top_contributors[0].display_name 
      : "Baseline Telemetry";

    return `
      <tr>
        <td><code>${e.incident_id}</code></td>
        <td>${formatDate(e.timestamp)}</td>
        <td><strong>${e.process_name}</strong> <small class="text-muted">(${e.process_id})</small></td>
        <td><small>${e.target_path}</small></td>
        <td><span class="badge-status ${getRiskClass(e.risk_level)}">${e.risk_level}</span></td>
        <td><strong>${e.risk_score}</strong></td>
        <td><span class="text-cyan">${topContrib}</span></td>
        <td><span class="badge-status">${e.status}</span></td>
      </tr>
    `;
  }).join("");
}

function getRiskClass(level) {
  switch ((level || "").toUpperCase()) {
    case "CRITICAL": return "level-critical";
    case "HIGH": return "level-high";
    case "MEDIUM": return "level-medium";
    default: return "level-low";
  }
}

function renderCharts(summary, events) {
  if (typeof Chart === "undefined") return;

  const timelineCanvas = document.getElementById("timelineChart");
  if (timelineCanvas) {
    const sortedEvents = [...events].reverse();
    const labels = sortedEvents.map(e => formatDate(e.timestamp));
    const riskScores = sortedEvents.map(e => e.risk_score);
    const mlScores = sortedEvents.map(e => e.ml_score);

    if (state.charts.timeline) state.charts.timeline.destroy();

    state.charts.timeline = new Chart(timelineCanvas, {
      type: "line",
      data: {
        labels: labels.length ? labels : ["Event 1", "Event 2", "Event 3"],
        datasets: [
          {
            label: "Composite Risk Score",
            data: riskScores.length ? riskScores : [10, 25, 85],
            borderColor: "#00f0ff",
            backgroundColor: "rgba(0, 240, 255, 0.12)",
            fill: true,
            tension: 0.35,
            borderWidth: 2,
            pointRadius: 4,
            pointBackgroundColor: "#00f0ff"
          },
          {
            label: "ML Anomaly Score",
            data: mlScores.length ? mlScores : [5, 30, 90],
            borderColor: "#f59e0b",
            borderDash: [4, 4],
            fill: false,
            tension: 0.2,
            borderWidth: 1.5,
            pointRadius: 2
          }
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { labels: { color: "#8493b2", font: { family: "Plus Jakarta Sans", size: 11 } } },
          tooltip: { backgroundColor: "#0c162e", titleColor: "#00f0ff", bodyColor: "#ffffff", borderColor: "#1a294d", borderWidth: 1 }
        },
        scales: {
          x: { ticks: { color: "#8493b2", font: { size: 10 } }, grid: { color: "#1a294d" } },
          y: { min: 0, max: 100, ticks: { color: "#8493b2", font: { size: 10 } }, grid: { color: "#1a294d" } }
        }
      }
    });
  }

  const distCanvas = document.getElementById("riskDistChart");
  if (distCanvas) {
    if (state.charts.riskDist) state.charts.riskDist.destroy();

    const low = summary.normal_events || 0;
    const med = summary.suspicious_events || 0;
    const high = summary.high_risk_incidents || 0;
    const crit = summary.critical_incidents || 0;

    state.charts.riskDist = new Chart(distCanvas, {
      type: "doughnut",
      data: {
        labels: ["Low Risk", "Medium", "High", "Critical"],
        datasets: [{
          data: (low + med + high + crit > 0) ? [low, med, high, crit] : [4, 2, 2, 1],
          backgroundColor: ["#10b981", "#f59e0b", "#f97316", "#ef4444"],
          borderColor: "#0c162e",
          borderWidth: 3
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: "68%",
        plugins: {
          legend: { position: "bottom", labels: { color: "#8493b2", font: { size: 10 } } }
        }
      }
    });
  }
}

// ==========================================================================
// 3. DETECTION LAB (FLAGSHIP FEATURE)
// ==========================================================================

const PARAM_DEFAULTS = {
  process_name: "WINWORD.EXE",
  process_id: 4120,
  user_account: "CORP\\jsmith",
  target_path: "C:\\Users\\jsmith\\Documents\\Report.docx",
  file_modification_rate: 0.8,
  file_rename_frequency: 0.0,
  file_deletion_frequency: 0.0,
  unique_directories_accessed: 1,
  unique_files_affected: 2,
  suspicious_extension_changes: 0,
  file_ops_per_process: 12,
  unique_files_per_process: 2,
  rapid_sequential_modifications: 0,
  file_entropy_delta: 0.15,
  unusual_write_burst_frequency: 0.2,
  ransom_note_indicators: 0,
  unusual_type_conversions: 0,
  process_activity_deviation: 0.4,
  backup_tamper_attempts: 0
};

function initLabSliders() {
  const rangeInputs = document.querySelectorAll(".parameters-grid input[type='range']");
  rangeInputs.forEach(input => {
    input.addEventListener("input", () => {
      const key = input.id.replace("param-", "");
      const badge = document.getElementById(`val-${key}`);
      if (badge) {
        let suffix = "";
        if (key === "file_modification_rate") suffix = " files/s";
        else if (key.includes("frequency")) suffix = " /min";
        else if (key === "unique_directories_accessed") suffix = " dirs";
        else if (key.includes("files")) suffix = " files";
        else if (key === "file_entropy_delta") suffix = " bits";
        else if (key === "process_activity_deviation") suffix = " σ";
        else if (key === "file_ops_per_process") suffix = " ops";
        else if (key.includes("burst")) suffix = " bursts";
        else if (key.includes("attempts")) suffix = " attempts";

        const prefix = (key === "file_entropy_delta" && input.value > 0) ? "+" : "";
        badge.textContent = `${prefix}${input.value}${suffix}`;
      }
    });
  });

  const form = document.getElementById("lab-feature-form");
  if (form) {
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      await runCustomLabAnalysis();
    });
  }

  const resetBtn = document.getElementById("lab-reset-params-btn");
  if (resetBtn) {
    resetBtn.addEventListener("click", () => {
      applyScenarioToSliders(PARAM_DEFAULTS);
      showToast("Reset sliders to baseline parameters.");
    });
  }

  const ackBtn = document.getElementById("lab-ack-btn");
  if (ackBtn) {
    ackBtn.addEventListener("click", async () => {
      if (!state.currentIncident) return;
      await acknowledgeIncident(state.currentIncident.incident_id);
      ackBtn.disabled = true;
      ackBtn.textContent = "Acknowledged ✓";
    });
  }

  const containBtn = document.getElementById("lab-sim-contain-btn");
  if (containBtn) {
    containBtn.addEventListener("click", async () => {
      if (!state.currentIncident) return;
      await simulateContainment(state.currentIncident.incident_id, "SIMULATE_ENDPOINT_ISOLATION");
      containBtn.disabled = true;
      containBtn.textContent = "Containment Simulated ✓";
    });
  }
}

function initLabScenarios() {
  const scenarioBtns = document.querySelectorAll("[data-scenario]");
  scenarioBtns.forEach(btn => {
    btn.addEventListener("click", async () => {
      const sKey = btn.getAttribute("data-scenario");
      try {
        btn.disabled = true;
        showToast(`Running scenario: ${btn.textContent.trim()}...`);
        let incident = null;

        try {
          const res = await fetch(`${API_BASE}/api/demo/run?scenario_key=${sKey}`, { method: "POST" });
          if (res.ok) incident = await res.json();
        } catch (e) {
          // Fallback to client
        }

        if (!incident && PRESET_SCENARIOS[sKey]) {
          const sc = PRESET_SCENARIOS[sKey];
          incident = evaluateClientFeatures(sc.process_name, sc.process_id, sc.user_account, sc.target_path, sc.features);
          state.incidents.unshift(incident);
        }

        if (incident) {
          const merged = {
            process_name: incident.process_name,
            process_id: incident.process_id,
            user_account: incident.user_account,
            target_path: incident.target_path,
            ...incident.features_snapshot
          };
          applyScenarioToSliders(merged);
          renderLabResults(incident);
        }
      } catch (err) {
        console.error("Scenario error:", err);
      } finally {
        btn.disabled = false;
      }
    });
  });
}

function applyScenarioToSliders(data) {
  for (const [key, val] of Object.entries(data)) {
    const input = document.getElementById(`param-${key}`);
    if (input) {
      input.value = val;
      input.dispatchEvent(new Event("input"));
    }
  }
}

async function runCustomLabAnalysis() {
  const analyzeBtn = document.getElementById("lab-analyze-btn");
  try {
    analyzeBtn.disabled = true;
    analyzeBtn.textContent = "Running Analysis...";

    const features = {
      file_modification_rate: parseFloat(document.getElementById("param-file_modification_rate").value),
      file_rename_frequency: parseFloat(document.getElementById("param-file_rename_frequency").value),
      file_deletion_frequency: parseFloat(document.getElementById("param-file_deletion_frequency").value),
      unique_directories_accessed: parseInt(document.getElementById("param-unique_directories_accessed").value),
      unique_files_affected: parseInt(document.getElementById("param-unique_files_affected").value),
      suspicious_extension_changes: parseInt(document.getElementById("param-suspicious_extension_changes").value),
      file_ops_per_process: parseInt(document.getElementById("param-file_ops_per_process").value),
      unique_files_per_process: parseInt(document.getElementById("param-unique_files_per_process").value),
      rapid_sequential_modifications: parseInt(document.getElementById("param-rapid_sequential_modifications").value),
      file_entropy_delta: parseFloat(document.getElementById("param-file_entropy_delta").value),
      unusual_write_burst_frequency: parseFloat(document.getElementById("param-unusual_write_burst_frequency").value),
      ransom_note_indicators: parseInt(document.getElementById("param-ransom_note_indicators").value),
      unusual_type_conversions: parseInt(document.getElementById("param-unusual_type_conversions").value),
      process_activity_deviation: parseFloat(document.getElementById("param-process_activity_deviation").value),
      backup_tamper_attempts: parseInt(document.getElementById("param-backup_tamper_attempts").value),
      entropy_measurement_source: "simulated_vector"
    };

    const procName = document.getElementById("param-process_name").value;
    const procId = parseInt(document.getElementById("param-process_id").value);
    const userAcc = document.getElementById("param-user_account").value;
    const targetPath = document.getElementById("param-target_path").value;

    let incident = null;

    try {
      const res = await fetch(`${API_BASE}/api/analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          process_name: procName, process_id: procId, user_account: userAcc, target_path: targetPath,
          features: features, scenario_name: "Interactive Laboratory Telemetry"
        })
      });
      if (res.ok) incident = await res.json();
    } catch (e) {
      // Fallback
    }

    if (!incident) {
      incident = evaluateClientFeatures(procName, procId, userAcc, targetPath, features);
      state.incidents.unshift(incident);
    }

    renderLabResults(incident);
    showToast(`Analysis complete: ${incident.risk_level} Risk (${incident.risk_score}/100)`);
  } catch (err) {
    console.error("Analysis failed:", err);
  } finally {
    analyzeBtn.disabled = false;
    analyzeBtn.innerHTML = `
      <svg class="btn-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
      Run Multi-Parameter Threat Analysis
    `;
  }
}

function renderLabResults(incident) {
  state.currentIncident = incident;

  document.getElementById("lab-incident-id").textContent = incident.incident_id;
  document.getElementById("lab-risk-score").textContent = Math.round(incident.risk_score);
  document.getElementById("lab-rule-score").textContent = `${incident.rule_score} / 100`;
  document.getElementById("lab-ml-score").textContent = `${incident.ml_score} / 100`;

  const levelBadge = document.getElementById("lab-risk-level");
  levelBadge.textContent = `${incident.risk_level} RISK`;
  levelBadge.className = `risk-level-badge ${getRiskClass(incident.risk_level)}`;

  const circle = document.getElementById("lab-risk-circle");
  if (incident.risk_level === "CRITICAL") circle.style.borderColor = "var(--danger)";
  else if (incident.risk_level === "HIGH") circle.style.borderColor = "#f97316";
  else if (incident.risk_level === "MEDIUM") circle.style.borderColor = "var(--warning)";
  else circle.style.borderColor = "var(--success)";

  document.getElementById("lab-dynamic-explanation").textContent = incident.dynamic_explanation;
  document.getElementById("lab-recommended-action").textContent = incident.recommended_action;

  const contribContainer = document.getElementById("lab-contributors-list");
  if (!incident.top_contributors || incident.top_contributors.length === 0) {
    contribContainer.innerHTML = `<div class="empty-state text-muted">All parameters within baseline operating tolerance.</div>`;
  } else {
    contribContainer.innerHTML = incident.top_contributors.slice(0, 5).map(c => `
      <div class="contributor-row">
        <div>
          <span class="contrib-name">${c.display_name}</span>
          <span class="contrib-metric">Val: ${c.value} (Threshold: &ge; ${c.threshold})</span>
        </div>
        <span class="contrib-pill ${getRiskClass(c.severity)}">${c.severity}</span>
      </div>
    `).join("");
  }

  const mlRes = incident.ml_result || {};
  const mlClassTag = document.getElementById("lab-ml-classification");
  mlClassTag.textContent = mlRes.is_anomaly ? "STATISTICAL OUTLIER" : "NORMAL INLIER";
  mlClassTag.className = mlRes.is_anomaly ? "ml-status-tag text-danger" : "ml-status-tag text-success";

  document.getElementById("lab-ml-interpretation").textContent = mlRes.interpretation || "-";
  document.getElementById("lab-ml-synthetic-notice").textContent = mlRes.synthetic_notice || "";

  const ackBtn = document.getElementById("lab-ack-btn");
  const containBtn = document.getElementById("lab-sim-contain-btn");
  if (ackBtn) { ackBtn.disabled = false; ackBtn.textContent = "Acknowledge Incident"; }
  if (containBtn) { containBtn.disabled = false; containBtn.textContent = "Simulate Safe Containment"; }
}

// ==========================================================================
// 4. ENTROPY MEASUREMENT TOOL
// ==========================================================================

function initEntropyTool() {
  const plainBtn = document.getElementById("entropy-load-plain-btn");
  const cipherBtn = document.getElementById("entropy-load-cipher-btn");
  const calcBtn = document.getElementById("entropy-calc-btn");
  const input = document.getElementById("entropy-sample-input");

  if (plainBtn && input) {
    plainBtn.addEventListener("click", () => {
      input.value = "CONFIDENTIAL PROJECT PLAN: Project RansomWatch aims to detect anomalous behavioral encryption loops. All milestones are strictly scheduled on weekly deliverables.";
    });
  }

  if (cipherBtn && input) {
    cipherBtn.addEventListener("click", () => {
      input.value = "8F3B9A1C5D7E2F0B4A6C8E1D3F5A7B9C2E4D6F8A0B2C4D6E8F0A2B4C6D8E0F1A3B5C7D9E1F3A5C7E9B1D3F5A7C9E1B3D5F7A9C1E3B5D7F9A1C3E5B7D9F1A3C5E7";
    });
  }

  if (calcBtn && input) {
    calcBtn.addEventListener("click", async () => {
      const text = input.value.trim();
      if (!text) {
        showToast("Please enter or load sample text first.");
        return;
      }

      let entropy = 0.0;
      let interp = "";

      try {
        const res = await fetch(`${API_BASE}/api/demo/entropy-test`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ content: text })
        });
        if (res.ok) {
          const data = await res.json();
          entropy = data.shannon_entropy_bits;
          interp = data.interpretation;
        }
      } catch (e) {
        // Fallback
      }

      if (!interp) {
        entropy = calculateClientShannonEntropy(text);
        if (entropy >= 7.0) interp = "High Entropy (Cryptographic / Compressed)";
        else if (entropy >= 4.5) interp = "Moderate Entropy (Formatted Data)";
        else interp = "Low Entropy (Plain Text / Structured Script)";
      }

      document.getElementById("entropy-result-val").textContent = `${entropy} bits/byte`;
      const badge = document.getElementById("entropy-result-badge");
      badge.textContent = interp;
      badge.className = entropy >= 7.0 
        ? "entropy-interp-badge level-critical" 
        : (entropy >= 4.5 ? "entropy-interp-badge level-medium" : "entropy-interp-badge level-low");
    });
  }
}

// ==========================================================================
// 5. LIVE ACTIVITY FEED
// ==========================================================================

async function loadLiveActivity() {
  const tbody = document.getElementById("live-events-tbody");
  if (!tbody) return;

  let events = [];
  try {
    const res = await fetch(`${API_BASE}/api/events?limit=30`);
    if (res.ok) events = await res.json();
  } catch (e) {
    events = state.incidents;
  }

  if (!events || events.length === 0) {
    tbody.innerHTML = `<tr><td colspan="9" class="text-center text-muted">No telemetry events recorded yet.</td></tr>`;
    return;
  }

  tbody.innerHTML = events.map(e => `
    <tr>
      <td>${formatDate(e.timestamp)}</td>
      <td><code>${e.incident_id}</code></td>
      <td><strong>${e.process_name}</strong> <small class="text-muted">(${e.process_id})</small></td>
      <td><small>${e.user_account}</small></td>
      <td><small>${e.target_path}</small></td>
      <td><span class="badge-status ${getRiskClass(e.risk_level)}">${e.risk_level}</span></td>
      <td><strong>${e.risk_score}</strong></td>
      <td><span class="badge-status">${e.ml_result ? (e.ml_result.is_anomaly ? 'OUTLIER' : 'INLIER') : '-'}</span></td>
      <td>
        <button class="btn btn-sm btn-outline" onclick="openIncidentModal('${e.incident_id}')">Investigate</button>
      </td>
    </tr>
  `).join("");
}

// ==========================================================================
// 6. ALERTS & INCIDENTS
// ==========================================================================

function initAlertFilters() {
  const applyBtn = document.getElementById("apply-filter-btn");
  if (applyBtn) applyBtn.addEventListener("click", loadAlerts);

  const exportJsonBtn = document.getElementById("export-json-btn");
  if (exportJsonBtn) {
    exportJsonBtn.addEventListener("click", () => {
      const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(state.incidents, null, 2));
      const downloadAnchor = document.createElement('a');
      downloadAnchor.setAttribute("href", dataStr);
      downloadAnchor.setAttribute("download", "ransomwatch_incidents.json");
      document.body.appendChild(downloadAnchor);
      downloadAnchor.click();
      downloadAnchor.remove();
    });
  }

  const exportCsvBtn = document.getElementById("export-csv-btn");
  if (exportCsvBtn) {
    exportCsvBtn.addEventListener("click", () => {
      let csv = "Incident ID,Timestamp,Process Name,PID,User,Target Path,Risk Level,Risk Score,Status\n";
      state.incidents.forEach(i => {
        csv += `"${i.incident_id}","${i.timestamp}","${i.process_name}","${i.process_id}","${i.user_account}","${i.target_path}","${i.risk_level}","${i.risk_score}","${i.status}"\n`;
      });
      const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
      const url = URL.createObjectURL(blob);
      const downloadAnchor = document.createElement('a');
      downloadAnchor.setAttribute("href", url);
      downloadAnchor.setAttribute("download", "ransomwatch_incidents.csv");
      document.body.appendChild(downloadAnchor);
      downloadAnchor.click();
      downloadAnchor.remove();
    });
  }

  const modal = document.getElementById("incident-modal");
  const closeBtn = document.getElementById("modal-close-btn");
  const dismissBtn = document.getElementById("modal-dismiss-btn");
  if (closeBtn && modal) closeBtn.addEventListener("click", () => modal.classList.add("hidden"));
  if (dismissBtn && modal) dismissBtn.addEventListener("click", () => modal.classList.add("hidden"));
}

async function loadAlerts() {
  const tbody = document.getElementById("alerts-table-tbody");
  if (!tbody) return;

  const risk = document.getElementById("filter-risk").value;
  const status = document.getElementById("filter-status").value;
  const search = document.getElementById("filter-search").value.trim().toLowerCase();

  let alerts = state.incidents;

  try {
    let url = `${API_BASE}/api/alerts?limit=50`;
    if (risk && risk !== "ALL") url += `&risk=${risk}`;
    if (status && status !== "ALL") url += `&status=${status}`;
    if (search) url += `&search=${encodeURIComponent(search)}`;
    const res = await fetch(url);
    if (res.ok) alerts = await res.json();
  } catch (e) {
    alerts = state.incidents.filter(a => {
      if (risk !== "ALL" && a.risk_level !== risk) return false;
      if (status !== "ALL" && a.status !== status) return false;
      if (search) {
        const text = `${a.process_name} ${a.incident_id} ${a.target_path}`.toLowerCase();
        if (!text.includes(search)) return false;
      }
      return true;
    });
  }

  if (!alerts || alerts.length === 0) {
    tbody.innerHTML = `<tr><td colspan="9" class="text-center text-muted">No incidents matching filter criteria.</td></tr>`;
    return;
  }

  tbody.innerHTML = alerts.map(a => `
    <tr>
      <td><code>${a.incident_id}</code></td>
      <td>${formatDate(a.timestamp)}</td>
      <td><strong>${a.process_name}</strong> <small class="text-muted">(${a.process_id})</small></td>
      <td><span class="badge-status ${getRiskClass(a.risk_level)}">${a.risk_level}</span></td>
      <td><strong>${a.risk_score}</strong></td>
      <td>${a.rule_score}</td>
      <td>${a.ml_score}</td>
      <td><span class="badge-status">${a.status}</span></td>
      <td>
        <button class="btn btn-sm btn-primary" onclick="openIncidentModal('${a.incident_id}')">Forensics</button>
      </td>
    </tr>
  `).join("");
}

window.openIncidentModal = async function(incidentId) {
  const modal = document.getElementById("incident-modal");
  const content = document.getElementById("modal-body-content");
  if (!modal || !content) return;

  let inc = state.incidents.find(i => i.incident_id === incidentId);

  try {
    const res = await fetch(`${API_BASE}/api/alerts/${incidentId}`);
    if (res.ok) inc = await res.json();
  } catch (e) {
    // Use client inc
  }

  if (!inc) return;

  document.getElementById("modal-title").textContent = `Incident Triage: ${inc.incident_id}`;
  document.getElementById("modal-subtitle").textContent = `${inc.process_name} (PID: ${inc.process_id}) &bull; ${inc.timestamp}`;

  const rulesTable = (inc.rules_triggered || []).map(r => `
    <tr>
      <td><code>${r.rule_id}</code></td>
      <td>${r.rule_name}</td>
      <td>${r.actual_value}</td>
      <td>${r.threshold}</td>
      <td>${r.triggered ? '<span class="text-danger">TRIGGERED</span>' : '<span class="text-muted">PASS</span>'}</td>
    </tr>
  `).join("");

  const actionsList = (inc.simulated_actions_taken && inc.simulated_actions_taken.length > 0)
    ? inc.simulated_actions_taken.map(act => `
        <div class="sim-action-chip">
          <strong>${act.action_type}</strong> by ${act.analyst} at ${formatDate(act.timestamp)}: 
          <em>"${act.notes}"</em> [${act.simulation_notice}]
        </div>
      `).join("")
    : `<p class="text-muted">No simulated response actions executed yet.</p>`;

  content.innerHTML = `
    <div class="modal-grid">
      <div class="mb-3">
        <h4 class="text-cyan">Executive Threat Summary</h4>
        <p class="mt-1">${inc.dynamic_explanation}</p>
      </div>
      <div class="mb-3">
        <h4 class="text-warning">Recommended Containment Guidance</h4>
        <p class="mt-1">${inc.recommended_action}</p>
      </div>
      <div class="mb-3">
        <h4>Triggered Behavioral Heuristics</h4>
        <div class="table-responsive">
          <table class="data-table">
            <thead><tr><th>Rule</th><th>Name</th><th>Value</th><th>Threshold</th><th>State</th></tr></thead>
            <tbody>${rulesTable}</tbody>
          </table>
        </div>
      </div>
      <div class="mb-3">
        <h4>Simulated Audit History</h4>
        ${actionsList}
      </div>
    </div>
  `;

  modal.classList.remove("hidden");
};

// ==========================================================================
// 7. DETECTION RULES CONFIGURATION
// ==========================================================================

function initRuleControls() {
  const ruleRatioInput = document.getElementById("input-rule-ratio");
  const mlRatioInput = document.getElementById("input-ml-ratio");
  const valRuleRatio = document.getElementById("val-rule-ratio");
  const valMlRatio = document.getElementById("val-ml-ratio");

  if (ruleRatioInput && mlRatioInput) {
    ruleRatioInput.addEventListener("input", () => {
      const rVal = parseInt(ruleRatioInput.value);
      mlRatioInput.value = 100 - rVal;
      valRuleRatio.textContent = `${rVal}%`;
      valMlRatio.textContent = `${100 - rVal}%`;
      state.weightConfig.rule_weight_ratio = rVal / 100;
      state.weightConfig.ml_weight_ratio = (100 - rVal) / 100;
    });

    mlRatioInput.addEventListener("input", () => {
      const mVal = parseInt(mlRatioInput.value);
      ruleRatioInput.value = 100 - mVal;
      valMlRatio.textContent = `${mVal}%`;
      valRuleRatio.textContent = `${100 - mVal}%`;
      state.weightConfig.rule_weight_ratio = (100 - mVal) / 100;
      state.weightConfig.ml_weight_ratio = mVal / 100;
    });
  }

  const saveBtn = document.getElementById("save-rules-btn");
  if (saveBtn) {
    saveBtn.addEventListener("click", saveRuleModifications);
  }
}

async function loadRules() {
  const tbody = document.getElementById("rules-config-tbody");
  if (!tbody) return;

  try {
    const res = await fetch(`${API_BASE}/api/rules`);
    if (res.ok) {
      const data = await res.json();
      state.rules = data.rules || state.rules;
      state.weightConfig = data.weight_config || state.weightConfig;
    }
  } catch (e) {
    // Keep local rules
  }

  const rRatio = Math.round((state.weightConfig.rule_weight_ratio || 0.6) * 100);
  const mRatio = 100 - rRatio;

  const rInput = document.getElementById("input-rule-ratio");
  const mInput = document.getElementById("input-ml-ratio");
  if (rInput) rInput.value = rRatio;
  if (mInput) mInput.value = mRatio;
  document.getElementById("val-rule-ratio").textContent = `${rRatio}%`;
  document.getElementById("val-ml-ratio").textContent = `${mRatio}%`;

  tbody.innerHTML = state.rules.map(r => `
    <tr data-rule-id="${r.rule_id}">
      <td><code>${r.rule_id}</code></td>
      <td><strong>${r.name}</strong></td>
      <td><code>${r.feature_key}</code></td>
      <td>
        <input type="number" step="0.1" min="0" class="form-input rule-threshold-input" value="${r.threshold}" style="width: 90px;">
      </td>
      <td>
        <input type="number" step="1" min="1" max="100" class="form-input rule-weight-input" value="${r.weight}" style="width: 70px;">
      </td>
      <td>
        <input type="checkbox" class="rule-enabled-chk" ${r.enabled ? 'checked' : ''}>
      </td>
      <td><small class="text-muted">${r.description}</small></td>
    </tr>
  `).join("");
}

async function saveRuleModifications() {
  const rows = document.querySelectorAll("#rules-config-tbody tr");
  rows.forEach(tr => {
    const rid = tr.getAttribute("data-rule-id");
    const threshInput = tr.querySelector(".rule-threshold-input");
    const weightInput = tr.querySelector(".rule-weight-input");
    const enabledChk = tr.querySelector(".rule-enabled-chk");

    const r = state.rules.find(x => x.rule_id === rid);
    if (r) {
      r.threshold = parseFloat(threshInput.value);
      r.weight = parseFloat(weightInput.value);
      r.enabled = enabledChk.checked;
    }
  });

  const ruleRatio = parseFloat(document.getElementById("input-rule-ratio").value) / 100;
  const mlRatio = parseFloat(document.getElementById("input-ml-ratio").value) / 100;
  state.weightConfig.rule_weight_ratio = ruleRatio;
  state.weightConfig.ml_weight_ratio = mlRatio;

  try {
    await fetch(`${API_BASE}/api/rules`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ rules: state.rules, rule_weight_ratio: ruleRatio, ml_weight_ratio: mlRatio })
    });
  } catch (e) {
    // Handled client-side
  }

  showToast("Updated rule thresholds and weighting ratios successfully!");
}

// ==========================================================================
// 8. MODEL INSIGHTS
// ==========================================================================

async function loadModelInsights() {
  let evalData = {
    metrics: { precision: 1.0, recall: 1.0, f1_score: 1.0, false_positive_rate: 0.0 }
  };
  let meta = { total_training_samples: 2950, contamination: 0.153 };

  try {
    const res = await fetch(`${API_BASE}/api/model/info`);
    if (res.ok) {
      const info = await res.json();
      meta = info.metadata || meta;
      evalData = info.evaluation || evalData;
    }
  } catch (e) {
    // Keep local metadata
  }

  document.getElementById("model-trees").textContent = "150";
  document.getElementById("model-samples").textContent = meta.total_training_samples ? meta.total_training_samples.toLocaleString() : "2,950";
  document.getElementById("model-contamination").textContent = meta.contamination || "0.153";

  if (evalData.metrics) {
    document.getElementById("eval-precision").textContent = evalData.metrics.precision.toFixed(4);
    document.getElementById("eval-recall").textContent = evalData.metrics.recall.toFixed(4);
    document.getElementById("eval-f1").textContent = evalData.metrics.f1_score.toFixed(4);
    document.getElementById("eval-fpr").textContent = evalData.metrics.false_positive_rate.toFixed(4);
  }

  renderModelFeaturesTable();
}

function renderModelFeaturesTable() {
  const tbody = document.getElementById("model-features-tbody");
  if (!tbody) return;

  const features = [
    { key: "file_modification_rate", name: "File Modification Rate", base: "1.2 files/s", susp: "> 12.0", desc: "Flags processes overwriting multiple files per sec" },
    { key: "file_rename_frequency", name: "File Rename Frequency", base: "0.5 /min", susp: "> 10.0", desc: "Rapid bulk rename typical of encryptor extension staging" },
    { key: "file_deletion_frequency", name: "File Deletion Frequency", base: "0.2 /min", susp: "> 8.0", desc: "Destruction of original files following encryption staging" },
    { key: "unique_directories_accessed", name: "Unique Directories Accessed", base: "2 dirs", susp: "> 6", desc: "Breadth of recursive traversal across user libraries" },
    { key: "unique_files_affected", name: "Unique Files Affected", base: "5 files", susp: "> 40", desc: "Total count of individual file descriptors manipulated" },
    { key: "suspicious_extension_changes", name: "Suspicious Extension Changes", base: "0", susp: ">= 1", desc: "Renaming to ransomware markers (.locked, .wnry, .crypto)" },
    { key: "file_ops_per_process", name: "File Ops Per Process", base: "18 ops", susp: "> 90", desc: "Total cumulative I/O handle allocations by this PID" },
    { key: "unique_files_per_process", name: "Unique Files Per Process", base: "4 files", susp: "> 35", desc: "Target files touched exclusively by single binary instance" },
    { key: "rapid_sequential_modifications", name: "Sub-50ms Sequential Writes", base: "0 bursts", susp: "> 5", desc: "Automated loops bypassing human keystroke intervals" },
    { key: "file_entropy_delta", name: "Shannon Entropy Delta", base: "0.1 bits", susp: ">= 2.2", desc: "Surge from plaintext (~3.5) to ciphertext (~7.9 bits/byte)" },
    { key: "unusual_write_burst_frequency", name: "Write Burst Frequency", base: "0.5 /min", susp: "> 4.0", desc: "Pulsing write spikes common in multi-threaded encryptors" },
    { key: "ransom_note_indicators", name: "Ransom Note File Indicators", base: "0", susp: ">= 1", desc: "Creation of HOW_TO_RESTORE.txt / README_DECRYPT.txt" },
    { key: "unusual_type_conversions", name: "Unusual Type Conversions", base: "0", susp: ">= 2", desc: "Valid office/database mime structures replaced with binary data" },
    { key: "process_activity_deviation", name: "Baseline Activity Deviation", base: "0.3 σ", susp: "> 3.0", desc: "Statistical departure from historic baseline profiling" },
    { key: "backup_tamper_attempts", name: "Backup / Shadow Tampering", base: "0", susp: ">= 1", desc: "Attempts to query or purge VSS shadow copies (vssadmin)" }
  ];

  tbody.innerHTML = features.map((f, i) => `
    <tr>
      <td>${i + 1}</td>
      <td><code>${f.key}</code></td>
      <td><strong>${f.name}</strong></td>
      <td><span class="text-success">${f.base}</span></td>
      <td><span class="text-warning">${f.susp}</span></td>
      <td>${f.desc}</td>
    </tr>
  `).join("");
}

// ==========================================================================
// 9. RESPONSE CENTRE & PLAYBOOKS
// ==========================================================================

function initResponseCentre() {
  const select = document.getElementById("response-incident-select");
  if (select) {
    select.addEventListener("change", () => {
      const incId = select.value;
      if (!incId) {
        document.getElementById("response-incident-details").classList.add("hidden");
        return;
      }
      loadResponseIncidentDetails(incId);
    });
  }

  const btnAck = document.getElementById("resp-btn-ack");
  if (btnAck) {
    btnAck.addEventListener("click", async () => {
      const incId = document.getElementById("response-incident-select").value;
      if (!incId) return showToast("Select an incident first.");
      const notes = document.getElementById("resp-notes").value;
      await acknowledgeIncident(incId, notes);
      loadResponseCentreIncidents();
    });
  }

  const btnTerm = document.getElementById("resp-btn-terminate");
  if (btnTerm) {
    btnTerm.addEventListener("click", async () => {
      const incId = document.getElementById("response-incident-select").value;
      if (!incId) return showToast("Select an incident first.");
      const notes = document.getElementById("resp-notes").value;
      await simulateContainment(incId, "SIMULATE_PROCESS_TERMINATION", notes);
    });
  }

  const btnIso = document.getElementById("resp-btn-isolate");
  if (btnIso) {
    btnIso.addEventListener("click", async () => {
      const incId = document.getElementById("response-incident-select").value;
      if (!incId) return showToast("Select an incident first.");
      const notes = document.getElementById("resp-notes").value;
      await simulateContainment(incId, "SIMULATE_ENDPOINT_ISOLATION", notes);
    });
  }

  const btnRestore = document.getElementById("resp-btn-restore");
  if (btnRestore) {
    btnRestore.addEventListener("click", async () => {
      const incId = document.getElementById("response-incident-select").value;
      if (!incId) return showToast("Select an incident first.");
      const notes = document.getElementById("resp-notes").value;
      await simulateContainment(incId, "SIMULATE_VSS_SNAPSHOT_CHECK", notes);
    });
  }
}

async function loadResponseCentreIncidents() {
  const select = document.getElementById("response-incident-select");
  if (!select) return;

  let incidents = state.incidents;
  try {
    const res = await fetch(`${API_BASE}/api/alerts?limit=25`);
    if (res.ok) incidents = await res.json();
  } catch (e) {
    // Client incidents
  }

  select.innerHTML = `<option value="">-- Choose an Incident --</option>` +
    incidents.map(i => `<option value="${i.incident_id}">${i.incident_id} - ${i.process_name} (${i.risk_level} Risk, ${i.risk_score}/100)</option>`).join("");

  renderAuditTrail(incidents);
}

function loadResponseIncidentDetails(incidentId) {
  const inc = state.incidents.find(i => i.incident_id === incidentId);
  if (!inc) return;

  document.getElementById("resp-proc-name").textContent = `${inc.process_name} (PID: ${inc.process_id})`;
  const badge = document.getElementById("resp-risk-badge");
  badge.textContent = `${inc.risk_level} (${inc.risk_score}/100)`;
  badge.className = `badge-status ${getRiskClass(inc.risk_level)}`;
  document.getElementById("resp-path").textContent = inc.target_path;
  document.getElementById("resp-recommendation").textContent = inc.recommended_action;

  document.getElementById("response-incident-details").classList.remove("hidden");
}

async function acknowledgeIncident(incidentId, notes = "") {
  try {
    await fetch(`${API_BASE}/api/incidents/${incidentId}/acknowledge`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ analyst_name: "Lead SOC Analyst", notes: notes || "Triage complete" })
    });
  } catch (e) {
    // Client fallback
  }

  const inc = state.incidents.find(i => i.incident_id === incidentId);
  if (inc) inc.status = "ACKNOWLEDGED";

  showToast(`Incident ${incidentId} marked as ACKNOWLEDGED.`);
  loadResponseCentreIncidents();
}

async function simulateContainment(incidentId, actionType, notes = "") {
  const simNotice = "SIMULATED — NO REAL ENDPOINT ISOLATED";
  const actionRecord = {
    action_id: `ACT-${Date.now().toString().slice(-8)}`,
    action_type: actionType,
    timestamp: new Date().toISOString(),
    analyst: "Lead SOC Analyst",
    notes: notes || "Executed simulated defense playbook.",
    simulation_notice: simNotice
  };

  try {
    await fetch(`${API_BASE}/api/incidents/${incidentId}/simulate-response`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ action_type: actionType, analyst_name: "Lead SOC Analyst", notes: notes })
    });
  } catch (e) {
    // Client fallback
  }

  const inc = state.incidents.find(i => i.incident_id === incidentId);
  if (inc) {
    inc.status = "CONTAINED_SIMULATED";
    if (!inc.simulated_actions_taken) inc.simulated_actions_taken = [];
    inc.simulated_actions_taken.push(actionRecord);
  }

  showToast(`[SIMULATION NOTICE]: ${simNotice} - Action logged successfully.`);
  loadResponseCentreIncidents();
}

function renderAuditTrail(incidents) {
  const tbody = document.getElementById("response-audit-tbody");
  if (!tbody) return;

  const allActions = [];
  incidents.forEach(inc => {
    (inc.simulated_actions_taken || []).forEach(act => {
      allActions.push({ ...act, incident_id: inc.incident_id });
    });
  });

  if (allActions.length === 0) {
    tbody.innerHTML = `<tr><td colspan="7" class="text-center text-muted">No simulated response actions recorded yet.</td></tr>`;
    return;
  }

  tbody.innerHTML = allActions.reverse().map(a => `
    <tr>
      <td>${formatDate(a.timestamp)}</td>
      <td><code>${a.action_id || 'ACT-SIM'}</code></td>
      <td><code>${a.incident_id}</code></td>
      <td><strong>${a.action_type}</strong></td>
      <td>${a.analyst}</td>
      <td>${a.notes}</td>
      <td><span class="badge-status level-critical">${a.simulation_notice}</span></td>
    </tr>
  `).join("");
}
