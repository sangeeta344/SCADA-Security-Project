"""Server-side monitoring for repeated failed authentication attempts and account protection.

Tracks failed attempts by target account and source IP within a rolling time window.
Enforces defensive temporary account lockout and triggers automated security alerts
and email notifications upon crossing threshold (e.g., 5 failed attempts in 5 minutes).

Security & Privacy Guarantees:
- NEVER logs, transmits, or persists submitted plaintext passwords or hashes.
- Masks account identifiers in alerts and logs (e.g. ad***n@scada.local).
- Provides generic feedback to clients to prevent account enumeration.
"""

import time
import uuid
import threading
from typing import Dict, List, Tuple, Optional, Any
from datetime import datetime

from config.logging_config import logger
from database.repository import repo as default_repo, Repository
from database.models import AttackAlert, NetworkTrafficEvent


class LoginMonitor:
    """Thread-safe server-side monitor for operator authentication security."""

    def __init__(
        self,
        repository: Optional[Repository] = None,
        max_attempts: int = 5,
        window_seconds: int = 300,       # 5-minute rolling window
        lockout_seconds: int = 300,      # 5-minute temporary defensive lockout
    ):
        self.repo = repository or default_repo
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self.lockout_seconds = lockout_seconds

        # Internal state guarded by lock
        self._lock = threading.Lock()
        # account -> list of failed attempt timestamps
        self._failed_attempts: Dict[str, List[float]] = {}
        # ip -> list of failed attempt timestamps
        self._ip_failed_attempts: Dict[str, List[float]] = {}
        # account -> unlock timestamp
        self._locked_accounts: Dict[str, float] = {}
        # account -> lockout count (for progressive delay)
        self._lockout_count: Dict[str, int] = {}
        # alerts generated to prevent rapid duplicate alert firing in same window
        self._alerted_windows: Dict[str, float] = {}

    @staticmethod
    def mask_identifier(identifier: str) -> str:
        """Mask account username or email for privacy preservation (e.g. ad***n@example.com)."""
        if not identifier:
            return "***"
        ident = identifier.strip().lower()
        if "@" in ident:
            parts = ident.split("@", 1)
            local, domain = parts[0], parts[1]
            if len(local) <= 2:
                masked_local = local[0] + "***" if local else "***"
            else:
                masked_local = f"{local[:2]}***{local[-1]}"
            return f"{masked_local}@{domain}"
        else:
            if len(ident) <= 2:
                return f"{ident[0]}***"
            return f"{ident[:2]}***{ident[-1]}"

    def is_account_locked(self, account: str) -> Tuple[bool, float]:
        """Check if account is temporarily locked. Returns (is_locked, remaining_seconds)."""
        if not account:
            return False, 0.0

        norm_account = account.strip().lower()
        now = time.time()

        with self._lock:
            if norm_account in self._locked_accounts:
                unlock_time = self._locked_accounts[norm_account]
                if now < unlock_time:
                    return True, round(unlock_time - now, 1)
                else:
                    # Lock expired
                    del self._locked_accounts[norm_account]

        return False, 0.0

    def record_failed_login(
        self,
        account: str,
        ip: str = "127.0.0.1",
        source: str = "WEB_LOGIN",
    ) -> Dict[str, Any]:
        """
        Record a failed authentication attempt.
        Never accepts or processes passwords.
        If threshold (5 attempts in 5m) is reached, triggers lockout, DB alert, and email dispatch.
        """
        norm_account = (account or "unknown_account").strip().lower()
        client_ip = (ip or "127.0.0.1").strip()
        now = time.time()
        masked = self.mask_identifier(norm_account)

        with self._lock:
            # 1. Prune timestamps outside rolling window
            cutoff = now - self.window_seconds
            attempts = [t for t in self._failed_attempts.get(norm_account, []) if t > cutoff]
            attempts.append(now)
            self._failed_attempts[norm_account] = attempts

            # IP tracking
            ip_attempts = [t for t in self._ip_failed_attempts.get(client_ip, []) if t > cutoff]
            ip_attempts.append(now)
            self._ip_failed_attempts[client_ip] = ip_attempts

            attempt_count = len(attempts)
            logger.warning(
                "Failed authentication attempt for account '%s' from IP %s (attempt %d/%d in window, source: %s)",
                masked,
                client_ip,
                attempt_count,
                self.max_attempts,
                source,
            )

            # 2. Check if threshold reached
            if attempt_count >= self.max_attempts:
                # Progressive lockout calculation
                current_lockouts = self._lockout_count.get(norm_account, 0)
                lockout_duration = self.lockout_seconds * (1 + current_lockouts)
                self._locked_accounts[norm_account] = now + lockout_duration
                self._lockout_count[norm_account] = current_lockouts + 1

                # Generate AttackAlert if not recently alerted in this window
                last_alert = self._alerted_windows.get(norm_account, 0)
                alert_record = None
                if (now - last_alert) > 60:  # Prevent duplicate alert storm within 60s
                    self._alerted_windows[norm_account] = now
                    alert_id = f"alt_pwd_{uuid.uuid4().hex[:8]}"
                    timestamp_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                    alert_record = AttackAlert(
                        alert_id=alert_id,
                        attack_type="password",
                        source_device=f"IP:{client_ip} -> AUTH_SVC",
                        severity="HIGH",
                        predicted_label="PASSWORD_BRUTE_FORCE",
                        confidence=0.98,
                        details=(
                            f"[Brute-Force Authentication Guard] Multiple failed login attempts detected "
                            f"targeting account '{masked}' ({attempt_count} failed attempts within "
                            f"{self.window_seconds // 60}m timeframe from {client_ip})"
                        ),
                        mitigation_action=(
                            f"Enforce temporary account lockout ({lockout_duration // 60}m) / "
                            f"Progressive delay on authentication requests / Review authentication audit logs"
                        ),
                        acknowledged=0,
                    )

                    try:
                        self.repo.insert_attack_alert(alert_record)
                        logger.info("Security incident persisted for brute-force attack: %s", alert_id)

                        # Insert corresponding NetworkTrafficEvent for telemetry monitoring
                        traffic_event = NetworkTrafficEvent(
                            event_id=f"ev_pwd_{uuid.uuid4().hex[:8]}",
                            src_device=f"IP:{client_ip} -> AUTH_SVC",
                            dst_device="AUTH_SVC",
                            protocol="HTTPS",
                            packet_rate=15.0,
                            payload_length=32,
                            function_code=None,
                            is_write=1,
                            register_count=0,
                            is_duplicate=0,
                            anomaly_flag=1,
                            predicted_class="password",
                            confidence=0.98,
                            attack_category="password",
                            expected_label="password",
                            status="BLOCKED",
                        )
                        self.repo.insert_traffic_event(traffic_event)

                        # Trigger automated email security notification
                        from security.email_notifier import email_notifier
                        email_notifier.notify_incident(
                            alert_record,
                            metadata={
                                "masked_account": masked,
                                "failed_attempts": attempt_count,
                                "timeframe": f"{self.window_seconds // 60} minutes",
                                "source_ip": client_ip,
                                "target_device": "AUTH_SVC (Operator Login)",
                                "detection_method": "Server-Side Authentication Rate Guard & Anomaly Monitor",
                            },
                        )
                    except Exception as err:
                        logger.error("Failed to record brute force alert or email notification: %s", err)

                return {
                    "locked": True,
                    "attempts": attempt_count,
                    "threshold_exceeded": True,
                    "alert_id": alert_record.alert_id if alert_record else None,
                    "masked_account": masked,
                    "remaining_seconds": lockout_duration,
                    "message": "Account protection active due to excessive failed attempts.",
                }

            return {
                "locked": False,
                "attempts": attempt_count,
                "threshold_exceeded": False,
                "alert_id": None,
                "masked_account": masked,
                "remaining_seconds": 0,
                "message": "Authentication failed.",
            }

    def record_successful_login(self, account: str, ip: str = "127.0.0.1") -> None:
        """Reset failed attempt counters upon successful authentication."""
        if not account:
            return
        norm_account = account.strip().lower()
        with self._lock:
            self._failed_attempts.pop(norm_account, None)
            self._locked_accounts.pop(norm_account, None)
            logger.info("Successful login for account '%s' from IP %s. Attempt counter reset.", self.mask_identifier(norm_account), ip)

    def reset_account(self, account: str) -> bool:
        """Administrative unlock/reset for an account."""
        if not account:
            return False
        norm_account = account.strip().lower()
        with self._lock:
            self._failed_attempts.pop(norm_account, None)
            self._locked_accounts.pop(norm_account, None)
            self._lockout_count.pop(norm_account, None)
            self._alerted_windows.pop(norm_account, None)
            logger.info("Account '%s' manually unlocked/reset by administrator.", self.mask_identifier(norm_account))
            return True

    def reset_all(self) -> None:
        """Reset all tracking and locked accounts (useful for test isolation)."""
        with self._lock:
            self._failed_attempts.clear()
            self._ip_failed_attempts.clear()
            self._locked_accounts.clear()
            self._lockout_count.clear()
            self._alerted_windows.clear()

    def get_status(self, account: str) -> Dict[str, Any]:
        """Get monitoring status for a given account."""
        norm_account = (account or "").strip().lower()
        now = time.time()
        with self._lock:
            cutoff = now - self.window_seconds
            attempts = [t for t in self._failed_attempts.get(norm_account, []) if t > cutoff]
            is_locked = False
            remaining = 0.0
            if norm_account in self._locked_accounts:
                unlock_time = self._locked_accounts[norm_account]
                if now < unlock_time:
                    is_locked = True
                    remaining = round(unlock_time - now, 1)

            return {
                "account": self.mask_identifier(norm_account),
                "failed_attempts": len(attempts),
                "threshold": self.max_attempts,
                "is_locked": is_locked,
                "remaining_seconds": remaining,
            }


# Singleton monitor instance
login_monitor = LoginMonitor()
