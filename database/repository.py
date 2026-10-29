"""Repository for data access operations using parameterized queries."""

from typing import List, Optional, Dict, Any
import json
from datetime import datetime

from database.db import Database, db as default_db
from database.models import (
    Device,
    SensorReading,
    NetworkTrafficEvent,
    AttackAlert,
    QuantumSession,
    QberMeasurement,
    ModelEvaluation,
    User,
    EmailNotificationRecord,
)
from config.logging_config import logger


class Repository:
    """Thread-safe data repository for SCADA entities and telemetry."""

    def __init__(self, database: Optional[Database] = None):
        self.db = database or default_db

    # --- DEVICES ---

    def get_all_devices(self) -> List[Device]:
        """Fetch all registered industrial devices."""
        with self.db.get_connection() as conn:
            rows = conn.execute(
                "SELECT id, name, device_type, protocol, ip_address, port, status, last_seen FROM devices"
            ).fetchall()
            return [Device(**dict(r)) for r in rows]

    def update_device_status(self, device_id: str, status: str) -> None:
        """Update device online/offline status and timestamp."""
        with self.db.get_connection() as conn:
            conn.execute(
                "UPDATE devices SET status = ?, last_seen = CURRENT_TIMESTAMP WHERE id = ?",
                (status, device_id),
            )
            conn.commit()

    # --- SENSOR READINGS ---

    def insert_sensor_reading(self, reading: SensorReading) -> int:
        """Insert a sensor reading."""
        with self.db.get_connection() as conn:
            cur = conn.execute(
                """
                INSERT INTO sensor_readings
                (sensor_id, rtu_id, temperature_c, pressure_bar, water_level_mm, flow_rate_lpm,
                 operating_status, is_anomaly, anomaly_score, source)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    reading.sensor_id,
                    reading.rtu_id,
                    reading.temperature_c,
                    reading.pressure_bar,
                    reading.water_level_mm,
                    reading.flow_rate_lpm,
                    reading.operating_status,
                    reading.is_anomaly,
                    reading.anomaly_score,
                    reading.source,
                ),
            )
            conn.commit()
            return cur.lastrowid

    def get_recent_sensor_readings(self, limit: int = 50) -> List[SensorReading]:
        """Get latest sensor readings ordered by timestamp descending."""
        with self.db.get_connection() as conn:
            rows = conn.execute(
                """
                SELECT id, timestamp, sensor_id, rtu_id, temperature_c, pressure_bar,
                       water_level_mm, flow_rate_lpm, operating_status, is_anomaly, anomaly_score, source
                FROM sensor_readings
                ORDER BY id DESC LIMIT ?
                """,
                (limit,),
            ).fetchall()
            return [SensorReading(**dict(r)) for r in rows]

    def get_sensor_time_series(self, limit: int = 30) -> List[Dict[str, Any]]:
        """Get readings ordered chronologically for Chart.js display."""
        with self.db.get_connection() as conn:
            rows = conn.execute(
                """
                SELECT id, timestamp, temperature_c, pressure_bar, water_level_mm, flow_rate_lpm, is_anomaly
                FROM sensor_readings
                ORDER BY id DESC LIMIT ?
                """,
                (limit,),
            ).fetchall()
            # Return reversed so it is in ascending order
            return [dict(r) for r in reversed(rows)]

    # --- NETWORK TRAFFIC EVENTS ---

    def insert_traffic_event(self, event: NetworkTrafficEvent) -> int:
        """Insert a network traffic observation event."""
        with self.db.get_connection() as conn:
            cur = conn.execute(
                """
                INSERT OR REPLACE INTO network_traffic_events
                (event_id, src_device, dst_device, protocol, packet_rate, payload_length,
                 function_code, is_write, register_count, is_duplicate, anomaly_flag,
                 predicted_class, confidence, attack_category, expected_label, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.event_id,
                    event.src_device,
                    event.dst_device,
                    event.protocol,
                    event.packet_rate,
                    event.payload_length,
                    event.function_code,
                    event.is_write,
                    event.register_count,
                    event.is_duplicate,
                    event.anomaly_flag,
                    event.predicted_class,
                    event.confidence,
                    event.attack_category,
                    event.expected_label,
                    event.status,
                ),
            )
            conn.commit()
            return cur.lastrowid

    def get_recent_traffic_events(self, limit: int = 50, protocol: Optional[str] = None) -> List[NetworkTrafficEvent]:
        """Fetch latest network events with optional protocol filter."""
        with self.db.get_connection() as conn:
            if protocol:
                rows = conn.execute(
                    """
                    SELECT id, event_id, timestamp, src_device, dst_device, protocol, packet_rate,
                           payload_length, function_code, is_write, register_count, is_duplicate,
                           anomaly_flag, predicted_class, confidence, attack_category, expected_label, status
                    FROM network_traffic_events
                    WHERE protocol = ?
                    ORDER BY id DESC LIMIT ?
                    """,
                    (protocol, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    """
                    SELECT id, event_id, timestamp, src_device, dst_device, protocol, packet_rate,
                           payload_length, function_code, is_write, register_count, is_duplicate,
                           anomaly_flag, predicted_class, confidence, attack_category, expected_label, status
                    FROM network_traffic_events
                    ORDER BY id DESC LIMIT ?
                    """,
                    (limit,),
                ).fetchall()
            return [NetworkTrafficEvent(**dict(r)) for r in rows]

    def get_traffic_summary(self) -> Dict[str, Any]:
        """Calculate counts of normal vs malicious traffic events."""
        with self.db.get_connection() as conn:
            total = conn.execute("SELECT COUNT(*) FROM network_traffic_events").fetchone()[0]
            normal = conn.execute(
                "SELECT COUNT(*) FROM network_traffic_events WHERE predicted_class = 'normal'"
            ).fetchone()[0]
            attacks = total - normal
            return {
                "total_messages": total,
                "normal_count": normal,
                "attack_count": attacks,
                "attack_rate": round((attacks / total * 100) if total > 0 else 0.0, 1),
            }

    # --- ATTACK ALERTS ---

    def insert_attack_alert(self, alert: AttackAlert) -> int:
        """Insert a security alert."""
        with self.db.get_connection() as conn:
            cur = conn.execute(
                """
                INSERT OR REPLACE INTO attack_alerts
                (alert_id, attack_type, source_device, severity, predicted_label,
                 confidence, details, mitigation_action, acknowledged)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    alert.alert_id,
                    alert.attack_type,
                    alert.source_device,
                    alert.severity,
                    alert.predicted_label,
                    alert.confidence,
                    alert.details,
                    alert.mitigation_action,
                    alert.acknowledged,
                ),
            )
            conn.commit()
            return cur.lastrowid

    def get_recent_alerts(self, limit: int = 50) -> List[AttackAlert]:
        """Fetch latest attack alerts."""
        with self.db.get_connection() as conn:
            rows = conn.execute(
                """
                SELECT id, alert_id, timestamp, attack_type, source_device, severity,
                       predicted_label, confidence, details, mitigation_action, acknowledged
                FROM attack_alerts
                ORDER BY id DESC LIMIT ?
                """,
                (limit,),
            ).fetchall()
            return [AttackAlert(**dict(r)) for r in rows]

    # --- QUANTUM SESSIONS & QBER ---

    def insert_quantum_session(self, session: QuantumSession) -> None:
        """Insert a BB84 QKD simulated session record."""
        with self.db.get_connection() as conn:
            conn.execute(
                """
                INSERT INTO quantum_sessions
                (session_id, alice_id, bob_id, raw_bits_count, sifted_bits_count,
                 disclosed_sample_count, final_key_bits_count, qber, qber_threshold,
                 status, eavesdropper_present, noise_level, rejection_reason)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    session.session_id,
                    session.alice_id,
                    session.bob_id,
                    session.raw_bits_count,
                    session.sifted_bits_count,
                    session.disclosed_sample_count,
                    session.final_key_bits_count,
                    session.qber,
                    session.qber_threshold,
                    session.status,
                    session.eavesdropper_present,
                    session.noise_level,
                    session.rejection_reason,
                ),
            )
            conn.commit()

    def insert_qber_measurement(self, m: QberMeasurement) -> int:
        """Insert a QBER sample measurement record."""
        with self.db.get_connection() as conn:
            cur = conn.execute(
                """
                INSERT INTO qber_measurements
                (session_id, qber, sample_size, errors_detected, noise_level,
                 eavesdropper_present, threshold, passed)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    m.session_id,
                    m.qber,
                    m.sample_size,
                    m.errors_detected,
                    m.noise_level,
                    m.eavesdropper_present,
                    m.threshold,
                    m.passed,
                ),
            )
            conn.commit()
            return cur.lastrowid

    def get_latest_quantum_session(self) -> Optional[QuantumSession]:
        """Fetch the most recent BB84 session."""
        with self.db.get_connection() as conn:
            row = conn.execute(
                """
                SELECT session_id, timestamp, alice_id, bob_id, raw_bits_count, sifted_bits_count,
                       disclosed_sample_count, final_key_bits_count, qber, qber_threshold,
                       status, eavesdropper_present, noise_level, rejection_reason
                FROM quantum_sessions
                ORDER BY timestamp DESC LIMIT 1
                """
            ).fetchone()
            if row:
                return QuantumSession(**dict(row))
            return None

    def get_qber_history(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Fetch QBER measurement history for charts."""
        with self.db.get_connection() as conn:
            rows = conn.execute(
                """
                SELECT id, timestamp, qber, threshold, passed, noise_level, eavesdropper_present
                FROM qber_measurements
                ORDER BY id DESC LIMIT ?
                """,
                (limit,),
            ).fetchall()
            return [dict(r) for r in reversed(rows)]

    # --- MODEL EVALUATIONS ---

    def insert_model_evaluation(self, eval_run: ModelEvaluation) -> int:
        """Record a model training/evaluation benchmark result."""
        with self.db.get_connection() as conn:
            cur = conn.execute(
                """
                INSERT INTO model_evaluations
                (model_name, model_type, dataset_name, train_samples, test_samples,
                 accuracy, precision, recall, f1_score, metrics_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    eval_run.model_name,
                    eval_run.model_type,
                    eval_run.dataset_name,
                    eval_run.train_samples,
                    eval_run.test_samples,
                    eval_run.accuracy,
                    eval_run.precision,
                    eval_run.recall,
                    eval_run.f1_score,
                    eval_run.metrics_json,
                ),
            )
            conn.commit()
            return cur.lastrowid

    def get_latest_model_evaluations(self) -> Dict[str, Any]:
        """Fetch the latest evaluation metrics for each model."""
        with self.db.get_connection() as conn:
            rows = conn.execute(
                """
                SELECT m1.*
                FROM model_evaluations m1
                INNER JOIN (
                    SELECT model_name, MAX(id) as max_id
                    FROM model_evaluations
                    GROUP BY model_name
                ) m2 ON m1.id = m2.max_id
                """
            ).fetchall()
            results = {}
            for r in rows:
                data = dict(r)
                if data.get("metrics_json"):
                    try:
                        data["metrics_detail"] = json.loads(data["metrics_json"])
                    except Exception:
                        data["metrics_detail"] = {}
                results[data["model_name"]] = data
            return results

    # --- USERS / AUTHENTICATION ---

    def create_user(
        self, username: str, email: str, password_hash: str, role: str = "Operator"
    ) -> Optional[int]:
        """Create a new user account. Returns user ID on success, None on conflict."""
        with self.db.get_connection() as conn:
            try:
                cur = conn.execute(
                    """
                    INSERT INTO users (username, email, password_hash, role)
                    VALUES (?, ?, ?, ?)
                    """,
                    (username.strip(), email.strip().lower(), password_hash, role.strip()),
                )
                conn.commit()
                return cur.lastrowid
            except Exception as e:
                logger.warning("Failed to create user %s: %s", email, e)
                return None

    def get_user_by_email(self, email: str) -> Optional[User]:
        """Fetch user by email address (case-insensitive)."""
        with self.db.get_connection() as conn:
            row = conn.execute(
                """
                SELECT id, username, email, password_hash, role, created_at
                FROM users
                WHERE LOWER(email) = LOWER(?)
                """,
                (email.strip(),),
            ).fetchone()
            if row:
                return User(**dict(row))
            return None

    def get_user_by_id(self, user_id: int) -> Optional[User]:
        """Fetch user by primary key ID."""
        with self.db.get_connection() as conn:
            row = conn.execute(
                """
                SELECT id, username, email, password_hash, role, created_at
                FROM users
                WHERE id = ?
                """,
                (user_id,),
            ).fetchone()
            if row:
                return User(**dict(row))
            return None

    # --- EMAIL NOTIFICATIONS ---

    def insert_email_notification(self, rec: EmailNotificationRecord) -> int:
        """Insert or replace an email notification audit record."""
        with self.db.get_connection() as conn:
            cur = conn.execute(
                """
                INSERT OR REPLACE INTO email_notifications
                (incident_id, recipient, subject, status, attempt_count, last_attempt, sent_at, failure_reason)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    rec.incident_id,
                    rec.recipient,
                    rec.subject,
                    rec.status,
                    rec.attempt_count,
                    rec.last_attempt,
                    rec.sent_at,
                    rec.failure_reason,
                ),
            )
            conn.commit()
            return cur.lastrowid

    def update_email_notification_status(
        self,
        incident_id: str,
        status: str,
        sent_at: Optional[str] = None,
        failure_reason: Optional[str] = None,
        increment_attempts: bool = True,
    ) -> None:
        """Update email notification status, attempt count, and timestamps."""
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with self.db.get_connection() as conn:
            if increment_attempts:
                conn.execute(
                    """
                    UPDATE email_notifications
                    SET status = ?,
                        attempt_count = attempt_count + 1,
                        last_attempt = ?,
                        sent_at = COALESCE(?, sent_at),
                        failure_reason = ?
                    WHERE incident_id = ?
                    """,
                    (status, now_str, sent_at, failure_reason, incident_id),
                )
            else:
                conn.execute(
                    """
                    UPDATE email_notifications
                    SET status = ?,
                        sent_at = COALESCE(?, sent_at),
                        failure_reason = ?
                    WHERE incident_id = ?
                    """,
                    (status, sent_at, failure_reason, incident_id),
                )
            conn.commit()

    def get_email_notification(self, incident_id: str) -> Optional[EmailNotificationRecord]:
        """Fetch notification record by incident ID."""
        with self.db.get_connection() as conn:
            row = conn.execute(
                """
                SELECT id, incident_id, recipient, subject, status, attempt_count, created_at,
                       last_attempt, sent_at, failure_reason
                FROM email_notifications
                WHERE incident_id = ?
                """,
                (incident_id,),
            ).fetchone()
            if row:
                return EmailNotificationRecord(**dict(row))
            return None

    def get_recent_email_notifications(self, limit: int = 50) -> List[EmailNotificationRecord]:
        """Fetch latest notification audit records."""
        with self.db.get_connection() as conn:
            rows = conn.execute(
                """
                SELECT id, incident_id, recipient, subject, status, attempt_count, created_at,
                       last_attempt, sent_at, failure_reason
                FROM email_notifications
                ORDER BY id DESC LIMIT ?
                """,
                (limit,),
            ).fetchall()
            return [EmailNotificationRecord(**dict(r)) for r in rows]


repo = Repository()
