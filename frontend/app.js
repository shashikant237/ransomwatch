/**
 * RansomWatch Frontend Application Controller
 * Handles real-time telemetry rendering, Detection Lab scenario simulations,
 * Chart.js visualizations, rule configuration, and response playbooks.
 */

const API_BASE = ""; // Relative path to FastAPI backend

// Application State
const state = {
  currentIncident: null,
  rules: [],
  weightConfig: { rule_weight_ratio: 0.60, ml_weight_ratio: 0.40 },
  charts: { timeline: null, riskDist: null },
  featureMetadata: {}
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

  // Load initial datasets
  loadDashboardData();
  loadRules();
  loadModelInsights();
});

// Toast notification helper
function showToast(msg, duration = 3500) {
  const toast = document.getElementById("status-toast");
  if (!toast) return;
  toast.textContent = msg;
  toast.classList.remove("hidden");
  setTimeout(() => toast.classList.add("hidden"), duration);
}

// Format ISO date strings
function formatDate(isoStr) {
  if (!isoStr) return "-";
  try {
    const d = new Date(isoStr);
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  } catch (e) {
    return isoStr;
  }
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

      // Contextual refresh
      if (targetTab === "tab-overview") loadDashboardData();
      if (targetTab === "tab-live") loadLiveActivity();
      if (targetTab === "tab-alerts") loadAlerts();
      if (targetTab === "tab-rules") loadRules();
      if (targetTab === "tab-model") loadModelInsights();
      if (targetTab === "tab-response") loadResponseCentreIncidents();
    });
  });

  // Cross-link buttons (e.g. "View All Alerts ->")
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
  try {
    const [summaryRes, eventsRes] = await Promise.all([
      fetch(`${API_BASE}/api/dashboard/summary`),
      fetch(`${API_BASE}/api/events?limit=15`)
    ]);

    if (!summaryRes.ok || !eventsRes.ok) return;

    const summary = await summaryRes.json();
    const events = await eventsRes.json();

    // Update Overview Metric Cards
    document.getElementById("card-total-events").textContent = summary.total_events;
    document.getElementById("card-normal-events").textContent = summary.normal_events;
    document.getElementById("card-suspicious-events").textContent = summary.suspicious_events;
    document.getElementById("card-high-incidents").textContent = summary.high_risk_incidents + summary.critical_incidents;
    document.getElementById("card-avg-score").textContent = summary.avg_risk_score;
    document.getElementById("card-active-rules").textContent = `${summary.rules_active_count} / 14`;
    document.getElementById("nav-alert-count").textContent = summary.total_events;

    renderRecentEventsTable(events);
    renderCharts(summary, events);
  } catch (err) {
    console.error("Failed to load dashboard data:", err);
  }
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

  // 1. Timeline Chart
  const timelineCanvas = document.getElementById("timelineChart");
  if (timelineCanvas) {
    const sortedEvents = [...events].reverse();
    const labels = sortedEvents.map(e => formatDate(e.timestamp));
    const riskScores = sortedEvents.map(e => e.risk_score);
    const ruleScores = sortedEvents.map(e => e.rule_score);
    const mlScores = sortedEvents.map(e => e.ml_score);

    if (state.charts.timeline) {
      state.charts.timeline.destroy();
    }

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
          tooltip: {
            backgroundColor: "#0c162e",
            titleColor: "#00f0ff",
            bodyColor: "#ffffff",
            borderColor: "#1a294d",
            borderWidth: 1
          }
        },
        scales: {
          x: { ticks: { color: "#8493b2", font: { size: 10 } }, grid: { color: "#1a294d" } },
          y: { min: 0, max: 100, ticks: { color: "#8493b2", font: { size: 10 } }, grid: { color: "#1a294d" } }
        }
      }
    });
  }

  // 2. Risk Distribution Doughnut Chart
  const distCanvas = document.getElementById("riskDistChart");
  if (distCanvas) {
    if (state.charts.riskDist) {
      state.charts.riskDist.destroy();
    }

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

  // Quick Action Buttons in Lab
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
        showToast(`Running simulation scenario: ${btn.textContent.trim()}...`);
        const res = await fetch(`${API_BASE}/api/demo/run?scenario_key=${sKey}`, { method: "POST" });
        if (!res.ok) throw new Error("Scenario execution failed");
        const incident = await res.json();
        
        // Populate inputs with scenario values
        const merged = {
          process_name: incident.process_name,
          process_id: incident.process_id,
          user_account: incident.user_account,
          target_path: incident.target_path,
          ...incident.features_snapshot
        };
        applyScenarioToSliders(merged);

        // Display results
        renderLabResults(incident);
      } catch (err) {
        console.error("Scenario error:", err);
        showToast("Error running scenario: " + err.message);
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

    const payload = {
      process_name: document.getElementById("param-process_name").value,
      process_id: parseInt(document.getElementById("param-process_id").value),
      user_account: document.getElementById("param-user_account").value,
      target_path: document.getElementById("param-target_path").value,
      features: features,
      scenario_name: "Interactive Laboratory Telemetry"
    };

    const res = await fetch(`${API_BASE}/api/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });

    if (!res.ok) throw new Error("Backend analysis endpoint returned an error");
    const incident = await res.json();
    renderLabResults(incident);
    showToast(`Analysis complete: ${incident.risk_level} Risk (${incident.risk_score}/100)`);
  } catch (err) {
    console.error("Analysis failed:", err);
    showToast("Analysis error: " + err.message);
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

  // Header and Score Circle
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

  // Dynamic Non-Hardcoded Explanation
  document.getElementById("lab-dynamic-explanation").textContent = incident.dynamic_explanation;

  // Tailored Recommended Action
  document.getElementById("lab-recommended-action").textContent = incident.recommended_action;

  // Top Contributors Breakdown
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

  // ML Interpretation
  const mlRes = incident.ml_result || {};
  const mlClassTag = document.getElementById("lab-ml-classification");
  mlClassTag.textContent = mlRes.is_anomaly ? "STATISTICAL OUTLIER" : "NORMAL INLIER";
  mlClassTag.className = mlRes.is_anomaly ? "ml-status-tag text-danger" : "ml-status-tag text-success";

  document.getElementById("lab-ml-interpretation").textContent = mlRes.interpretation || "-";
  document.getElementById("lab-ml-synthetic-notice").textContent = mlRes.synthetic_notice || "";

  // Enable action buttons
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
      // High-entropy pseudorandom ciphertext simulation string
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
      try {
        const res = await fetch(`${API_BASE}/api/demo/entropy-test`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ content: text })
        });
        if (!res.ok) throw new Error("Calculation failed");
        const data = await res.json();

        document.getElementById("entropy-result-val").textContent = `${data.shannon_entropy_bits} bits/byte`;
        const badge = document.getElementById("entropy-result-badge");
        badge.textContent = data.interpretation;
        badge.className = data.shannon_entropy_bits >= 7.0 
          ? "entropy-interp-badge level-critical" 
          : (data.shannon_entropy_bits >= 4.5 ? "entropy-interp-badge level-medium" : "entropy-interp-badge level-low");
      } catch (err) {
        showToast("Entropy tool error: " + err.message);
      }
    });
  }
}

// ==========================================================================
// 5. LIVE ACTIVITY FEED
// ==========================================================================

async function loadLiveActivity() {
  const tbody = document.getElementById("live-events-tbody");
  if (!tbody) return;
  try {
    const res = await fetch(`${API_BASE}/api/events?limit=30`);
    if (!res.ok) throw new Error("Could not fetch events");
    const events = await res.json();

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
  } catch (err) {
    console.error("Live feed error:", err);
  }
}

// ==========================================================================
// 6. ALERTS & INCIDENTS (SQLITE PERSISTENCE)
// ==========================================================================

function initAlertFilters() {
  const applyBtn = document.getElementById("apply-filter-btn");
  if (applyBtn) applyBtn.addEventListener("click", loadAlerts);

  const exportJsonBtn = document.getElementById("export-json-btn");
  if (exportJsonBtn) {
    exportJsonBtn.addEventListener("click", () => {
      window.open(`${API_BASE}/api/incidents/export?format=json`, "_blank");
    });
  }

  const exportCsvBtn = document.getElementById("export-csv-btn");
  if (exportCsvBtn) {
    exportCsvBtn.addEventListener("click", () => {
      window.open(`${API_BASE}/api/incidents/export?format=csv`, "_blank");
    });
  }

  // Modal Dismiss
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
  const search = document.getElementById("filter-search").value.trim();

  let url = `${API_BASE}/api/alerts?limit=50`;
  if (risk && risk !== "ALL") url += `&risk=${risk}`;
  if (status && status !== "ALL") url += `&status=${status}`;
  if (search) url += `&search=${encodeURIComponent(search)}`;

  try {
    const res = await fetch(url);
    if (!res.ok) throw new Error("Failed to load alerts");
    const alerts = await res.json();

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
  } catch (err) {
    console.error("Alerts error:", err);
  }
}

window.openIncidentModal = async function(incidentId) {
  const modal = document.getElementById("incident-modal");
  const content = document.getElementById("modal-body-content");
  if (!modal || !content) return;

  try {
    const res = await fetch(`${API_BASE}/api/alerts/${incidentId}`);
    if (!res.ok) throw new Error("Incident not found");
    const inc = await res.json();

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
  } catch (err) {
    showToast("Error opening modal: " + err.message);
  }
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
    });

    mlRatioInput.addEventListener("input", () => {
      const mVal = parseInt(mlRatioInput.value);
      ruleRatioInput.value = 100 - mVal;
      valMlRatio.textContent = `${mVal}%`;
      valRuleRatio.textContent = `${100 - mVal}%`;
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
    if (!res.ok) throw new Error("Failed to load rules");
    const data = await res.json();
    state.rules = data.rules || [];
    state.weightConfig = data.weight_config || {};

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
  } catch (err) {
    console.error("Rules error:", err);
  }
}

async function saveRuleModifications() {
  const rows = document.querySelectorAll("#rules-config-tbody tr");
  const updatedRules = [];

  rows.forEach(tr => {
    const rid = tr.getAttribute("data-rule-id");
    const threshInput = tr.querySelector(".rule-threshold-input");
    const weightInput = tr.querySelector(".rule-weight-input");
    const enabledChk = tr.querySelector(".rule-enabled-chk");

    const original = state.rules.find(r => r.rule_id === rid) || {};
    updatedRules.push({
      rule_id: rid,
      name: original.name || rid,
      feature_key: original.feature_key || "",
      threshold: parseFloat(threshInput.value),
      weight: parseFloat(weightInput.value),
      enabled: enabledChk.checked,
      description: original.description || ""
    });
  });

  const ruleRatio = parseFloat(document.getElementById("input-rule-ratio").value) / 100;
  const mlRatio = parseFloat(document.getElementById("input-ml-ratio").value) / 100;

  try {
    const res = await fetch(`${API_BASE}/api/rules`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        rules: updatedRules,
        rule_weight_ratio: ruleRatio,
        ml_weight_ratio: mlRatio
      })
    });
    if (!res.ok) throw new Error("Could not update rules");
    showToast("Updated rule thresholds and weighting ratios successfully!");
    loadRules();
  } catch (err) {
    showToast("Failed to save rules: " + err.message);
  }
}

// ==========================================================================
// 8. MODEL INSIGHTS
// ==========================================================================

async function loadModelInsights() {
  try {
    const res = await fetch(`${API_BASE}/api/model/info`);
    if (!res.ok) return;
    const info = await res.json();

    const meta = info.metadata || {};
    const evalData = info.evaluation || {};

    document.getElementById("model-trees").textContent = info.hyperparameters ? info.hyperparameters.n_estimators : 150;
    document.getElementById("model-samples").textContent = meta.total_training_samples ? meta.total_training_samples.toLocaleString() : "2,950";
    document.getElementById("model-contamination").textContent = meta.contamination || "0.153";

    if (evalData.metrics) {
      document.getElementById("eval-precision").textContent = evalData.metrics.precision.toFixed(4);
      document.getElementById("eval-recall").textContent = evalData.metrics.recall.toFixed(4);
      document.getElementById("eval-f1").textContent = evalData.metrics.f1_score.toFixed(4);
      document.getElementById("eval-fpr").textContent = evalData.metrics.false_positive_rate.toFixed(4);
    }

    renderModelFeaturesTable();
  } catch (err) {
    console.error("Model insights error:", err);
  }
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
// 9. RESPONSE CENTRE & SIMULATED PLAYBOOKS
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

  try {
    const res = await fetch(`${API_BASE}/api/alerts?limit=25`);
    if (!res.ok) return;
    const incidents = await res.json();

    select.innerHTML = `<option value="">-- Choose an Incident --</option>` +
      incidents.map(i => `<option value="${i.incident_id}">${i.incident_id} - ${i.process_name} (${i.risk_level} Risk, ${i.risk_score}/100)</option>`).join("");

    renderAuditTrail(incidents);
  } catch (err) {
    console.error("Response centre load error:", err);
  }
}

async function loadResponseIncidentDetails(incidentId) {
  try {
    const res = await fetch(`${API_BASE}/api/alerts/${incidentId}`);
    if (!res.ok) return;
    const inc = await res.json();

    document.getElementById("resp-proc-name").textContent = `${inc.process_name} (PID: ${inc.process_id})`;
    const badge = document.getElementById("resp-risk-badge");
    badge.textContent = `${inc.risk_level} (${inc.risk_score}/100)`;
    badge.className = `badge-status ${getRiskClass(inc.risk_level)}`;
    document.getElementById("resp-path").textContent = inc.target_path;
    document.getElementById("resp-recommendation").textContent = inc.recommended_action;

    document.getElementById("response-incident-details").classList.remove("hidden");
  } catch (err) {
    console.error(err);
  }
}

async function acknowledgeIncident(incidentId, notes = "") {
  try {
    const res = await fetch(`${API_BASE}/api/incidents/${incidentId}/acknowledge`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ analyst_name: "Lead SOC Analyst", notes: notes || "Triage complete" })
    });
    if (!res.ok) throw new Error("Acknowledge request failed");
    showToast(`Incident ${incidentId} marked as ACKNOWLEDGED.`);
    loadResponseCentreIncidents();
  } catch (err) {
    showToast("Error: " + err.message);
  }
}

async function simulateContainment(incidentId, actionType, notes = "") {
  try {
    const res = await fetch(`${API_BASE}/api/incidents/${incidentId}/simulate-response`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        action_type: actionType,
        analyst_name: "Lead SOC Analyst",
        notes: notes || "Executed simulated defense playbook."
      })
    });
    if (!res.ok) throw new Error("Simulation execution failed");
    const data = await res.json();
    showToast(`[SIMULATION NOTICE]: ${data.notice} - Action logged successfully.`);
    loadResponseCentreIncidents();
  } catch (err) {
    showToast("Error: " + err.message);
  }
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
