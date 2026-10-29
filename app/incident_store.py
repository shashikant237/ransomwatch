"""SQLite incident and telemetry persistence layer for RansomWatch.
Stores analyzed events, alerts, rule updates, and simulated response audit logs.
Provides filtering, summary metrics, and export capabilities.
"""

import os
import json
import sqlite3
import csv
import io
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

from app.schemas import IncidentReport, DashboardSummary


class IncidentStore:
    def __init__(self, db_path: str = None):
        if db_path is None:
            cur_dir = os.path.dirname(os.path.abspath(__file__))
            db_path = os.path.join(cur_dir, "..", "ransomwatch.db")
        self.db_path = os.path.abspath(db_path)
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        """Initializes tables for incidents, telemetry events, and simulated audit logs."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS incidents (
                    incident_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    process_name TEXT NOT NULL,
                    process_id INTEGER NOT NULL,
                    user_account TEXT NOT NULL,
                    target_path TEXT NOT NULL,
                    risk_level TEXT NOT NULL,
                    risk_score REAL NOT NULL,
                    rule_score REAL NOT NULL,
                    ml_score REAL NOT NULL,
                    status TEXT NOT NULL,
                    dynamic_explanation TEXT NOT NULL,
                    recommended_action TEXT NOT NULL,
                    rules_triggered_json TEXT NOT NULL,
                    ml_result_json TEXT NOT NULL,
                    top_contributors_json TEXT NOT NULL,
                    features_snapshot_json TEXT NOT NULL,
                    simulated_actions_json TEXT NOT NULL
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS audit_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    incident_id TEXT NOT NULL,
                    action_type TEXT NOT NULL,
                    analyst_name TEXT NOT NULL,
                    notes TEXT NOT NULL,
                    simulation_notice TEXT NOT NULL,
                    FOREIGN KEY(incident_id) REFERENCES incidents(incident_id)
                )
            """)
            conn.commit()

    def save_incident(self, incident: IncidentReport) -> IncidentReport:
        """Saves or updates an analyzed incident in SQLite."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO incidents (
                    incident_id, timestamp, process_name, process_id, user_account,
                    target_path, risk_level, risk_score, rule_score, ml_score,
                    status, dynamic_explanation, recommended_action,
                    rules_triggered_json, ml_result_json, top_contributors_json,
                    features_snapshot_json, simulated_actions_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                incident.incident_id,
                incident.timestamp,
                incident.process_name,
                incident.process_id,
                incident.user_account,
                incident.target_path,
                incident.risk_level,
                incident.risk_score,
                incident.rule_score,
                incident.ml_score,
                incident.status,
                incident.dynamic_explanation,
                incident.recommended_action,
                json.dumps([r.model_dump() for r in incident.rules_triggered]),
                json.dumps(incident.ml_result.model_dump()),
                json.dumps([c.model_dump() for c in incident.top_contributors]),
                json.dumps(incident.features_snapshot),
                json.dumps(incident.simulated_actions_taken)
            ))
            conn.commit()
        return incident

    def get_incidents(
        self,
        risk_filter: Optional[str] = None,
        status_filter: Optional[str] = None,
        search: Optional[str] = None,
        limit: int = 50
    ) -> List[Dict[str, Any]]:
        """Queries incidents with optional risk level, status, and process search filters."""
        query = "SELECT * FROM incidents WHERE 1=1"
        params: List[Any] = []

        if risk_filter and isinstance(risk_filter, str) and risk_filter.upper() != "ALL":
            query += " AND risk_level = ?"
            params.append(risk_filter.upper())

        if status_filter and isinstance(status_filter, str) and status_filter.upper() != "ALL":
            query += " AND status = ?"
            params.append(status_filter.upper())

        if search and isinstance(search, str):
            query += " AND (process_name LIKE ? OR incident_id LIKE ? OR target_path LIKE ?)"
            term = f"%{search}%"
            params.extend([term, term, term])

        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            rows = cursor.fetchall()

        results = []
        for r in rows:
            results.append({
                "incident_id": r["incident_id"],
                "timestamp": r["timestamp"],
                "process_name": r["process_name"],
                "process_id": r["process_id"],
                "user_account": r["user_account"],
                "target_path": r["target_path"],
                "risk_level": r["risk_level"],
                "risk_score": r["risk_score"],
                "rule_score": r["rule_score"],
                "ml_score": r["ml_score"],
                "status": r["status"],
                "dynamic_explanation": r["dynamic_explanation"],
                "recommended_action": r["recommended_action"],
                "rules_triggered": json.loads(r["rules_triggered_json"]),
                "ml_result": json.loads(r["ml_result_json"]),
                "top_contributors": json.loads(r["top_contributors_json"]),
                "features_snapshot": json.loads(r["features_snapshot_json"]),
                "simulated_actions_taken": json.loads(r["simulated_actions_json"])
            })
        return results

    def get_incident_by_id(self, incident_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves complete details for a single incident."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM incidents WHERE incident_id = ?", (incident_id,))
            r = cursor.fetchone()
            if not r:
                return None
            return {
                "incident_id": r["incident_id"],
                "timestamp": r["timestamp"],
                "process_name": r["process_name"],
                "process_id": r["process_id"],
                "user_account": r["user_account"],
                "target_path": r["target_path"],
                "risk_level": r["risk_level"],
                "risk_score": r["risk_score"],
                "rule_score": r["rule_score"],
                "ml_score": r["ml_score"],
                "status": r["status"],
                "dynamic_explanation": r["dynamic_explanation"],
                "recommended_action": r["recommended_action"],
                "rules_triggered": json.loads(r["rules_triggered_json"]),
                "ml_result": json.loads(r["ml_result_json"]),
                "top_contributors": json.loads(r["top_contributors_json"]),
                "features_snapshot": json.loads(r["features_snapshot_json"]),
                "simulated_actions_taken": json.loads(r["simulated_actions_json"])
            }

    def acknowledge_incident(self, incident_id: str, analyst_name: str = "SOC Analyst", notes: str = "") -> bool:
        """Transitions incident status to ACKNOWLEDGED."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE incidents SET status = 'ACKNOWLEDGED' WHERE incident_id = ?",
                (incident_id,)
            )
            if cursor.rowcount == 0:
                return False

            now = datetime.now(timezone.utc).isoformat()
            cursor.execute("""
                INSERT INTO audit_logs (timestamp, incident_id, action_type, analyst_name, notes, simulation_notice)
                VALUES (?, ?, 'ACKNOWLEDGE', ?, ?, 'INCIDENT_TRIAGED_BY_ANALYST')
            """, (now, incident_id, analyst_name, notes or "Acknowledged"))
            conn.commit()
            return True

    def record_simulated_action(
        self,
        incident_id: str,
        action_type: str,
        analyst_name: str = "SOC Analyst",
        notes: str = ""
    ) -> Optional[Dict[str, Any]]:
        """Applies a safe defensive simulated containment action and logs it clearly."""
        inc = self.get_incident_by_id(incident_id)
        if not inc:
            return None

        sim_notice = "SIMULATED — NO REAL ENDPOINT ISOLATED"
        now = datetime.now(timezone.utc).isoformat()
        action_record = {
            "action_id": f"ACT-{datetime.now().strftime('%H%M%S%f')[:10]}",
            "action_type": action_type,
            "timestamp": now,
            "analyst": analyst_name,
            "notes": notes,
            "simulation_notice": sim_notice,
            "execution_status": "SUCCESS_SIMULATED"
        }

        actions = inc.get("simulated_actions_taken", [])
        actions.append(action_record)

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE incidents
                SET status = 'CONTAINED_SIMULATED', simulated_actions_json = ?
                WHERE incident_id = ?
            """, (json.dumps(actions), incident_id))

            cursor.execute("""
                INSERT INTO audit_logs (timestamp, incident_id, action_type, analyst_name, notes, simulation_notice)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (now, incident_id, action_type, analyst_name, notes, sim_notice))
            conn.commit()

        return action_record

    def get_dashboard_summary(self) -> DashboardSummary:
        """Computes live aggregated metrics from all recorded incidents."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM incidents")
            total = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM incidents WHERE risk_level = 'LOW'")
            normal = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM incidents WHERE risk_level = 'MEDIUM'")
            suspicious = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM incidents WHERE risk_level = 'HIGH'")
            high = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM incidents WHERE risk_level = 'CRITICAL'")
            critical = cursor.fetchone()[0]

            cursor.execute("SELECT AVG(risk_score) FROM incidents")
            avg_score = cursor.fetchone()[0] or 0.0

        return DashboardSummary(
            total_events=total,
            normal_events=normal,
            suspicious_events=suspicious,
            high_risk_incidents=high,
            critical_incidents=critical,
            avg_risk_score=round(avg_score, 1),
            rules_active_count=14,
            model_status="ONLINE (Isolation Forest v1.0.0)",
            last_updated=datetime.now(timezone.utc).isoformat()
        )

    def export_incidents(self, format_type: str = "json") -> str:
        """Exports all recorded incidents as JSON or CSV formatted string."""
        incidents = self.get_incidents(limit=1000)
        if format_type.lower() == "csv":
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow([
                "Incident ID", "Timestamp", "Process Name", "PID", "User",
                "Target Path", "Risk Level", "Risk Score", "Rule Score",
                "ML Score", "Status", "Explanation", "Recommended Action"
            ])
            for i in incidents:
                writer.writerow([
                    i["incident_id"], i["timestamp"], i["process_name"], i["process_id"],
                    i["user_account"], i["target_path"], i["risk_level"], i["risk_score"],
                    i["rule_score"], i["ml_score"], i["status"], i["dynamic_explanation"],
                    i["recommended_action"]
                ])
            return output.getvalue()
        else:
            return json.dumps(incidents, indent=2)
