"""Centralized automated email security notification service for SCADA alerts.

Sends validated alerts via authenticated SMTP when eligible security incidents
are detected, prevents duplicate transmissions, aggregates high-frequency DoS
events, and logs delivery status to SQLite.
"""

import smtplib
import threading
import time
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from typing import Dict, Any, Optional, Callable

from config.settings import settings
from config.logging_config import logger
from database.models import AttackAlert, EmailNotificationRecord
from database.repository import repo as default_repo, Repository


class EmailNotifier:
    """Manages asynchronous, authenticated SMTP security alert dispatching."""

    def __init__(self, repository: Optional[Repository] = None):
        self.repo = repository or default_repo
        self.lock = threading.Lock()

        # Duplicate suppression and DoS aggregation state
        self._processed_incidents = set()
        self._last_dos_alert_time: float = 0.0
        self._aggregated_dos_count: int = 0
        self._dos_rate_limit_seconds: float = 60.0

        # Optional test mock hook: callable(to_email, subject, body) -> bool
        self._mock_sender: Optional[Callable[[str, str, str], bool]] = None

    def set_mock_sender(self, mock_fn: Optional[Callable[[str, str, str], bool]]) -> None:
        """Inject a mock sender for unit and integration testing without real SMTP."""
        self._mock_sender = mock_fn

    def reset_state(self) -> None:
        """Reset internal rate limiting and processed cache (useful between tests or resets)."""
        with self.lock:
            self._processed_incidents.clear()
            self._last_dos_alert_time = 0.0
            self._aggregated_dos_count = 0


    def format_email_content(self, alert: AttackAlert, metadata: Optional[Dict[str, Any]] = None) -> Dict[str, str]:
        """Generate structured subject and body according to project requirements."""
        meta = metadata or {}
        attack_type_raw = alert.attack_type or "Unknown Attack"

        # Link to Attack Detection page
        public_url = (settings.SCADA_PUBLIC_URL or "http://127.0.0.1:5000").rstrip("/")
        dashboard_link = f"{public_url}/attack-alerts"

        # Dedicated format for Brute-Force Login Attacks (Section 5 requirement)
        if attack_type_raw.lower() in ("password", "brute_force", "bruteforce"):
            subject = "[SCADA SECURITY ALERT] Multiple Failed Login Attempts Detected"
            masked_target = meta.get("masked_account") or meta.get("target_account") or "ad***n@scada.local"
            attempts_count = meta.get("failed_attempts", 5)
            timeframe = meta.get("timeframe", "5 minutes")
            source_ip = meta.get("source_ip", alert.source_device)
            target = meta.get("target_device", "AUTH_SVC (Operator Login)")

            body = f"""SCADA SECURITY ALERT

A security incident has been identified by the SCADA monitoring system.

SCADA System: Industrial SCADA Security & BB84 Quantum Communication Platform
Attack Type: Password Brute-Force Authentication Attack
Target Account: {masked_target}
Number of Failed Attempts: {attempts_count}
Detection Window: {timeframe}
Source Identifier: {source_ip}
Detection Method: Server-Side Authentication Rate Guard & Anomaly Monitor
Severity: {alert.severity}
Detection Result: {alert.predicted_label.upper()} (Confidence: {round(alert.confidence * 100, 1)}%)
Timestamp: {alert.timestamp or datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Incident ID: {alert.alert_id}

Recommended Action:
{alert.mitigation_action or 'Enforce temporary account lockout, review authorization audit logs, and consider IP-based rate limiting.'}

Incident Status: DETECTED & RECORDED (DEFENSIVE LOCKOUT ACTIVATED)
Attack Detection Dashboard: {dashboard_link}

This is an automated notification from the SCADA security monitoring system."""
            return {"subject": subject, "body": body, "target": target}

        attack_title_map = {
            "injection": "False Data Injection",
            "replay": "Replay Attack",
            "mitm": "MITM Simulation",
            "dos": "DoS Flood Simulation",
        }
        attack_type_display = attack_title_map.get(attack_type_raw.lower(), attack_type_raw.upper())

        # Subject: [SCADA SECURITY ALERT] — Attack Type Detected
        subject = f"[SCADA SECURITY ALERT] — {attack_type_display} Detected"

        # Determine target device
        target = meta.get("target_device")
        if not target:
            if "->" in alert.source_device:
                target = alert.source_device.split("->")[-1].strip()
            else:
                target = alert.source_device

        # Determine readings
        orig_reading = meta.get("original_reading", "28.5 °C (Process Baseline)")
        susp_reading = meta.get("suspicious_reading", "N/A (Non-telemetry Event)")
        if alert.attack_type.lower() == "injection":
            if "original_reading" not in meta:
                orig_reading = "35.0 °C (Nominal Operating Baseline)"
            if "suspicious_reading" not in meta:
                susp_reading = "90.0 °C (Injected Value)"

        # Detection method
        detection_method = meta.get("detection_method")
        if not detection_method:
            if "IsolationForest" in alert.details or "RandomForest" in alert.details:
                detection_method = "Machine Learning Intrusion Detection (RandomForest / IsolationForest)"
            elif "Rule" in alert.details or "Guard" in alert.details:
                detection_method = "Protocol Rule-Based Guard (Stateful Freshness & Sequence Verification)"
            else:
                detection_method = "Hybrid SCADA Detection Pipeline"

        # Body formatting exactly matching required specification
        body = f"""SCADA SECURITY ALERT

A security incident has been identified by the SCADA monitoring system.

SCADA System: Industrial SCADA Security & BB84 Quantum Communication Platform
Attack Type: {attack_type_display}
Target Device: {target}
Source Identifier: {alert.source_device}
Original Reading: {orig_reading}
Suspicious Reading: {susp_reading}
Detection Method: {detection_method}
Severity: {alert.severity}
Detection Result: {alert.predicted_label.upper()} (Confidence: {round(alert.confidence * 100, 1)}%)
Timestamp: {alert.timestamp or datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Incident ID: {alert.alert_id}

Recommended Action:
{alert.mitigation_action or 'Investigate the affected device and verify telemetry readings.'}

Incident Status: DETECTED & RECORDED
Attack Detection Dashboard: {dashboard_link}

This is an automated notification from the SCADA security monitoring system."""

        return {"subject": subject, "body": body, "target": target}

    def notify_incident(
        self,
        alert: AttackAlert,
        metadata: Optional[Dict[str, Any]] = None,
        blocking: bool = False,
    ) -> Dict[str, Any]:
        """
        Evaluate eligibility, prevent duplicates, and dispatch notification.
        Returns notification status dict.
        """
        incident_id = alert.alert_id

        with self.lock:
            # 1. Duplicate check
            existing_rec = self.repo.get_email_notification(incident_id)
            if existing_rec and existing_rec.status in ("sent", "pending"):
                logger.info("Email notification for incident %s already handled (%s).", incident_id, existing_rec.status)
                return {"status": "duplicate_suppressed", "incident_id": incident_id}

            if incident_id in self._processed_incidents:
                return {"status": "duplicate_suppressed", "incident_id": incident_id}

            # 2. DoS aggregation and rate-limiting
            now_ts = time.time()
            if alert.attack_type.lower() == "dos":
                time_since_last_dos = now_ts - self._last_dos_alert_time
                if time_since_last_dos < self._dos_rate_limit_seconds:
                    self._aggregated_dos_count += 1
                    logger.info(
                        "DoS alert rate-limited. Suppressed repeated email for %s (aggregated count: %d).",
                        incident_id,
                        self._aggregated_dos_count,
                    )
                    return {
                        "status": "rate_limited",
                        "incident_id": incident_id,
                        "aggregated_count": self._aggregated_dos_count,
                    }
                else:
                    self._last_dos_alert_time = now_ts
                    self._aggregated_dos_count = 1

            self._processed_incidents.add(incident_id)

        # 3. Build message
        email_data = self.format_email_content(alert, metadata)
        recipient = settings.SCADA_ALERT_EMAIL or "operator@scada-defense.local"
        subject = email_data["subject"]
        body = email_data["body"]

        # 4. Check if SMTP is configured
        is_configured = bool(settings.SMTP_HOST and settings.SMTP_HOST.strip())

        # If unconfigured and no mock sender, log gracefully and record 'skipped'
        if not is_configured and self._mock_sender is None:
            logger.info(
                "SMTP not configured (SMTP_HOST empty). Email notification skipped for %s.",
                incident_id,
            )
            audit_record = EmailNotificationRecord(
                incident_id=incident_id,
                recipient=recipient,
                subject=subject,
                status="skipped",
                attempt_count=0,
                last_attempt=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                failure_reason="SMTP not configured (set SMTP_HOST in .env)",
            )
            self.repo.insert_email_notification(audit_record)
            return {
                "status": "skipped",
                "incident_id": incident_id,
                "reason": "SMTP_HOST not configured",
            }

        # 5. Insert initial pending audit record
        audit_record = EmailNotificationRecord(
            incident_id=incident_id,
            recipient=recipient,
            subject=subject,
            status="pending",
            attempt_count=0,
            last_attempt=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        )
        self.repo.insert_email_notification(audit_record)

        # 6. Dispatch (non-blocking thread or synchronous if requested)
        if blocking:
            return self._execute_send(incident_id, recipient, subject, body)

        thread = threading.Thread(
            target=self._execute_send,
            args=(incident_id, recipient, subject, body),
            daemon=True,
            name=f"EmailNotifier-{incident_id}",
        )
        thread.start()
        return {"status": "dispatched", "incident_id": incident_id}

    def _execute_send(self, incident_id: str, recipient: str, subject: str, body: str) -> Dict[str, Any]:
        """Execute SMTP transmission with bounded retries and status logging."""
        max_retries = 2
        last_error = None

        for attempt in range(1, max_retries + 1):
            try:
                # Use test mock sender if injected
                if self._mock_sender is not None:
                    success = self._mock_sender(recipient, subject, body)
                    if success:
                        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        self.repo.update_email_notification_status(
                            incident_id=incident_id,
                            status="sent",
                            sent_at=now_str,
                            increment_attempts=True,
                        )
                        logger.info("Mock security email delivered successfully for %s", incident_id)
                        return {"status": "sent", "incident_id": incident_id, "attempt": attempt}
                    else:
                        raise RuntimeError("Mock sender indicated failure")

                # Real SMTP delivery
                msg = MIMEMultipart()
                msg["From"] = settings.SMTP_FROM_EMAIL
                msg["To"] = recipient
                msg["Subject"] = subject
                msg.attach(MIMEText(body, "plain", "utf-8"))

                host = settings.SMTP_HOST
                port = settings.SMTP_PORT

                server = smtplib.SMTP(host, port, timeout=10.0)
                try:
                    server.ehlo()
                    if port == 587:
                        server.starttls()
                        server.ehlo()

                    if settings.SMTP_USERNAME and settings.SMTP_PASSWORD:
                        server.login(settings.SMTP_USERNAME, settings.SMTP_PASSWORD)

                    server.sendmail(settings.SMTP_FROM_EMAIL, [recipient], msg.as_string())
                finally:
                    server.quit()

                now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                self.repo.update_email_notification_status(
                    incident_id=incident_id,
                    status="sent",
                    sent_at=now_str,
                    increment_attempts=True,
                )
                logger.info("Security email alert transmitted to %s for incident %s", recipient, incident_id)
                return {"status": "sent", "incident_id": incident_id, "attempt": attempt}

            except Exception as e:
                last_error = str(e)
                logger.warning("SMTP send attempt %d failed for %s: %s", attempt, incident_id, e)
                self.repo.update_email_notification_status(
                    incident_id=incident_id,
                    status="pending" if attempt < max_retries else "failed",
                    failure_reason=last_error,
                    increment_attempts=True,
                )
                if attempt < max_retries:
                    time.sleep(1.0)

        logger.error("All email attempts exhausted for incident %s. Final error: %s", incident_id, last_error)
        return {"status": "failed", "incident_id": incident_id, "error": last_error}


# Global singleton instance
email_notifier = EmailNotifier()
