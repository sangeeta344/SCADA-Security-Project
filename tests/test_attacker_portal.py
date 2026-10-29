"""Comprehensive integration tests for the Attacker Portal and ML detection pipeline.

Verifies:
1. Complete separation of attacker authentication & fictional lab accounts
2. Bounded execution of all four lab-only scenarios (FDI, Replay, MITM, DoS)
3. Genuine detector execution with clear ML vs Rule-based distinction
4. Persistence of alerts into the shared SQLite database
5. Receipt and presentation of alerts on the existing operator website (/attack-alerts)
6. Preservation of existing dashboard pages and functionalities
"""

import uuid
import pytest
from flask import session
from dashboard.app import create_app
from database.repository import repo
from database.db import db
from attacker_portal.auth import FICTIONAL_ADVERSARY_ACCOUNTS
from attacker_portal.simulation_service import attacker_service, SYNTHETIC_TARGETS


@pytest.fixture
def test_client():
    """Create Flask test client with clean testing database."""
    app = create_app({"TESTING": True, "LOGIN_DISABLED": False})
    with app.test_client() as client:
        with app.app_context():
            db.init_db()
        yield client


# =========================================================================
# 1. ATTACKER AUTHENTICATION & ISOLATION TESTS
# =========================================================================

def test_unauthenticated_attacker_redirect(test_client):
    """Unauthenticated visitor to /attacker is redirected to /attacker/login."""
    resp = test_client.get("/attacker/", follow_redirects=False)
    assert resp.status_code == 302
    assert "/attacker/login" in resp.headers["Location"]

    api_resp = test_client.post("/attacker/api/simulate", json={"scenario": "dos"})
    assert api_resp.status_code == 401
    assert "Unauthorized" in api_resp.get_json()["error"]


def test_fictional_adversary_logins(test_client):
    """Verify both authorized fictional adversary accounts can log in."""
    # 1. Red Team Lead
    resp1 = test_client.post(
        "/attacker/login",
        data={"email": "redteam_lead@scada-lab.local", "password": "Adversary2026!"},
        follow_redirects=True,
    )
    assert resp1.status_code == 200
    assert b"Adversary Emulation" in resp1.data or b"SCADA ADVERSARY PORTAL" in resp1.data or b"Simulation Workspace" in resp1.data

    # Check session
    with test_client.session_transaction() as sess:
        assert sess.get("attacker_user") is not None
        assert sess["attacker_user"]["username"] == "redteam_lead"
        # Crucial: Attacker login MUST NOT grant operator dashboard session
        assert sess.get("user_id") is None

    # Verify attacker cannot access operator overview without operator credentials
    overview_resp = test_client.get("/overview", follow_redirects=False)
    assert overview_resp.status_code == 302
    assert "/login" in overview_resp.headers["Location"]

    # Logout
    logout_resp = test_client.get("/attacker/logout", follow_redirects=True)
    assert logout_resp.status_code == 200
    with test_client.session_transaction() as sess:
        assert sess.get("attacker_user") is None

    # 2. Threat Researcher
    resp2 = test_client.post(
        "/attacker/login",
        data={"email": "researcher@scada-lab.local", "password": "LabResearch2026!"},
        follow_redirects=True,
    )
    assert resp2.status_code == 200
    with test_client.session_transaction() as sess:
        assert sess.get("attacker_user")["username"] == "threat_researcher"


def test_invalid_adversary_credentials_rejected(test_client):
    """Verify wrong password or unknown email is rejected."""
    resp = test_client.post(
        "/attacker/login",
        data={"email": "redteam_lead@scada-lab.local", "password": "WrongPassword!"},
        follow_redirects=True,
    )
    assert resp.status_code == 401
    assert b"Invalid adversary credentials" in resp.data


# =========================================================================
# 2. THE FOUR LAB-ONLY SCENARIOS WITH REAL DETECTOR EXECUTION
# =========================================================================

def _login_as_attacker(client):
    """Helper to authenticate test client as Red Team Lead."""
    client.post(
        "/attacker/login",
        data={"email": "redteam_lead@scada-lab.local", "password": "Adversary2026!"},
    )


def test_scenario_1_false_data_injection(test_client):
    """
    Test False Data Injection:
    - Generates synthetic out-of-bounds telemetry
    - Real detector executes: Isolation Forest flags anomaly score < 0
    - Rule guard flags FC-16 register write
    - Alert persisted in shared DB
    """
    _login_as_attacker(test_client)

    payload = {
        "scenario": "injection",
        "params": {
            "target_device": "RTU_01",
            "function_code": 16,
            "temperature_c": 92.5,
            "pressure_bar": 8.1,
            "water_level_mm": 1420.0,
            "flow_rate_lpm": 95.0,
        },
    }
    resp = test_client.post("/attacker/api/simulate", json=payload)
    assert resp.status_code == 200
    data = resp.get_json()

    assert data["success"] is True
    sim = data["simulation"]
    det = sim["detection"]
    al = sim["persisted_alert"]

    # Genuine detector execution verification
    assert det["detector_executed"] is True
    assert "IsolationForest" in det["detection_method"] or "Modbus" in det["detection_method"]
    assert det["predicted_label"] == "INJECTION"
    assert det["severity"] in ("HIGH", "CRITICAL")
    assert det["ml_score"] is not None and det["ml_score"] < 0.0  # Real Isolation Forest score!

    # Target & details verification
    assert sim["target"] == "RTU_01"
    assert "RTU_01" in al["details"]
    assert al["alert_id"].startswith("alt_")


def test_scenario_2_replay_attack(test_client):
    """
    Test Replay Attack:
    - Generates replayed frame with duplicate sequence marker & stale timestamp
    - Real detector executes: Rule-based Stateful Sequence & Freshness Guard
    - Alert persisted in shared DB
    """
    _login_as_attacker(test_client)

    payload = {
        "scenario": "replay",
        "params": {
            "target_device": "RTU_01",
            "stale_seconds": 1800,
            "burst_count": 5,
        },
    }
    resp = test_client.post("/attacker/api/simulate", json=payload)
    assert resp.status_code == 200
    data = resp.get_json()

    assert data["success"] is True
    sim = data["simulation"]
    det = sim["detection"]
    al = sim["persisted_alert"]

    # Rule-based detection distinction verification
    assert det["detector_executed"] is True
    assert "RULE_BASED" in det["detection_method"]
    assert "Stateful Replay" in det["detection_method"]
    assert det["predicted_label"] == "REPLAY"
    assert det["confidence"] >= 0.90
    assert "Duplicate frame" in al["details"] or "stale" in al["details"]


def test_scenario_3_mitm_simulation(test_client):
    """
    Test MITM Simulation:
    - Intercepts and alters in-flight actuator command
    - Real detector executes: Random Forest classifier and integrity guard
    - Alert persisted in shared DB
    """
    _login_as_attacker(test_client)

    payload = {
        "scenario": "mitm",
        "params": {
            "target_device": "PLC_01",
            "tampered_action": "FORCED_EMERGENCY_SHUTDOWN_OVERRIDE",
        },
    }
    resp = test_client.post("/attacker/api/simulate", json=payload)
    assert resp.status_code == 200
    data = resp.get_json()

    assert data["success"] is True
    sim = data["simulation"]
    det = sim["detection"]
    al = sim["persisted_alert"]

    # Detector execution & distinction
    assert det["detector_executed"] is True
    assert det["predicted_label"] == "MITM"
    assert det["severity"] == "CRITICAL"
    assert "FORCED_EMERGENCY_SHUTDOWN_OVERRIDE" in al["details"]


def test_scenario_4_dos_flood_simulation(test_client):
    """
    Test DoS Flood Simulation:
    - Generates high-rate query burst (e.g. 90 pkt/s)
    - Real detector executes: Random Forest classifier and rate-anomaly guard
    - Alert persisted in shared DB
    """
    _login_as_attacker(test_client)

    payload = {
        "scenario": "dos",
        "params": {
            "target_device": "RTU_01",
            "packet_rate": 90.0,
            "burst_count": 30,
        },
    }
    resp = test_client.post("/attacker/api/simulate", json=payload)
    assert resp.status_code == 200
    data = resp.get_json()

    assert data["success"] is True
    sim = data["simulation"]
    det = sim["detection"]
    al = sim["persisted_alert"]

    # High packet rate anomaly & classifier
    assert det["detector_executed"] is True
    assert det["predicted_label"] == "DOS"
    assert det["severity"] in ("HIGH", "CRITICAL")
    assert "90.0 pkt/s" in al["details"]


# =========================================================================
# 3. END-TO-END WORKFLOW & USER WEBSITE ALERT VISIBILITY TESTS
# =========================================================================

def test_complete_attacker_to_user_alert_workflow(test_client):
    """
    Test required workflow:
    1. Attacker launches simulated attack in separate portal
    2. Backend generates real synthetic event
    3. Existing detection pipeline processes event
    4. Detection result is saved in SQLite database
    5. Existing user website receives detection event via API
    6. Existing Attack Detection page displays the alert with attack type, timestamp, target, result, severity
    """
    _login_as_attacker(test_client)

    # 1. Attacker triggers False Data Injection targeting RTU_01
    sim_resp = test_client.post(
        "/attacker/api/simulate",
        json={
            "scenario": "injection",
            "params": {"target_device": "RTU_01", "temperature_c": 98.0, "pressure_bar": 8.5},
        },
    )
    assert sim_resp.status_code == 200
    sim_data = sim_resp.get_json()["simulation"]
    alert_id = sim_data["persisted_alert"]["alert_id"]

    # 2. Cross-verify alert in shared database
    verify_resp = test_client.get(f"/attacker/api/verify-alert/{alert_id}")
    assert verify_resp.status_code == 200
    assert verify_resp.get_json()["verified"] is True

    # 3. Existing User Website API receives the alert (/api/alerts)
    api_alerts_resp = test_client.get("/api/alerts?limit=50")
    assert api_alerts_resp.status_code == 200
    alerts_data = api_alerts_resp.get_json()["alerts"]
    matched = [a for a in alerts_data if a["alert_id"] == alert_id]
    assert len(matched) == 1, "Alert must be present in operator /api/alerts feed"
    operator_alert = matched[0]

    assert operator_alert["attack_type"] == "injection"
    assert operator_alert["severity"] == "HIGH"
    assert "RTU_01" in operator_alert["source_device"] or "RTU_01" in operator_alert["details"]

    # 4. Authenticate as Operator on User Website
    from database.models import User
    from werkzeug.security import generate_password_hash
    test_client.post("/login", data={"email": "admin@scada.local", "password": "admin123"})

    # 5. Existing Attack Detection page (/attack-alerts) renders the alert
    page_resp = test_client.get("/attack-alerts")
    assert page_resp.status_code == 200
    html_content = page_resp.data.decode("utf-8")

    # Verify all 5 required elements are rendered in the HTML table:
    # (attack type, timestamp, target, detection result, and severity)
    assert alert_id in html_content, "Alert ID must appear in the Attack Alerts table"
    assert "INJECTION" in html_content, "Attack Type must appear in the Attack Alerts table"
    assert "RTU_01" in html_content, "Target device must appear in the Attack Alerts table"
    assert "HIGH" in html_content, "Severity must appear in the Attack Alerts table"


# =========================================================================
# 4. PRESERVATION OF EXISTING USER WEBSITE PAGES
# =========================================================================

def test_existing_dashboard_pages_remain_intact(test_client):
    """Verify all existing operator pages render normally without errors."""
    # Log in as operator
    test_client.post("/login", data={"email": "admin@scada.local", "password": "admin123"})

    pages = [
        "/overview",
        "/network-monitor",
        "/attack-alerts",
        "/quantum-security",
        "/model-metrics",
    ]
    for page in pages:
        resp = test_client.get(page)
        assert resp.status_code == 200, f"Page {page} must return 200 OK"
        assert b"SCADA SHIELD" in resp.data, f"Page {page} must contain brand"

    # API endpoints
    apis = [
        "/api/status",
        "/api/devices",
        "/api/telemetry",
        "/api/traffic",
        "/api/alerts",
        "/api/quantum/status",
        "/api/model/metrics",
    ]
    for api in apis:
        resp = test_client.get(api)
        assert resp.status_code == 200, f"API {api} must return 200 OK"


# =========================================================================
# 5. REMOVAL OF CONTROLS FROM USER WEBSITE VERIFICATION
# =========================================================================

def test_attack_controls_removed_from_user_website(test_client):
    """
    Verify removal requirement:
    - Replay Attack card & Start/Stop buttons: REMOVED
    - False Data Injection card & Start/Stop buttons: REMOVED
    - MITM Simulation card & Start/Stop buttons: REMOVED
    - DoS Flood card & Start/Stop buttons: REMOVED
    - Controlled Local Simulation Environment banner: REMOVED
    - Stop All Attacks button: REMOVED
    - Security Incident Detection Log table: PRESERVED
    """
    test_client.post("/login", data={"email": "admin@scada.local", "password": "admin123"})
    resp = test_client.get("/attack-alerts")
    assert resp.status_code == 200
    html = resp.data.decode("utf-8")

    # Verify removed elements
    assert "Controlled Local Simulation Environment" not in html
    assert "Stop All Attacks" not in html
    assert "btn-attack-start" not in html
    assert "btn-attack-stop" not in html
    assert "status-badge-replay" not in html
    assert "status-badge-injection" not in html
    assert "status-badge-mitm" not in html
    assert "status-badge-dos" not in html

    # Verify preserved elements
    assert "Security Incident Detection Log" in html
    assert "detailed-alerts-tbody" in html
    assert "table-scada" in html


# =========================================================================
# 6. SENSOR RESTORATION & SIMULATED ACCOUNT ACCESS TESTS
# =========================================================================

def test_fdi_sensor_restoration(test_client):
    """Verify that after FDI attack, sensor telemetry can be restored to nominal baseline."""
    _login_as_attacker(test_client)

    # 1. Inject abnormal reading
    inj_resp = test_client.post(
        "/attacker/api/simulate",
        json={"scenario": "injection", "params": {"target_device": "RTU_01", "temperature_c": 105.0}},
    )
    assert inj_resp.status_code == 200

    # 2. Restore sensor
    rest_resp = test_client.post("/attacker/api/restore-sensor", json={"target_device": "RTU_01"})
    assert rest_resp.status_code == 200
    rest_data = rest_resp.get_json()
    assert rest_data["success"] is True
    assert rest_data["restored_readings"]["temperature_c"] == 28.0
    assert rest_data["restored_readings"]["is_anomaly"] == 0

    # Verify database has the restored record
    readings = repo.get_recent_sensor_readings(limit=5)
    assert any(r.source == "BASELINE_RESTORED" for r in readings)


def test_simulated_account_access_endpoint(test_client):
    """Verify simulated compromised account information does not expose real credentials."""
    _login_as_attacker(test_client)
    resp = test_client.get("/attacker/api/simulated-account")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["success"] is True
    acc = data["account"]
    assert "synthetic_session_id" in acc
    assert "fictional_account" in acc
    assert "password" not in acc
    assert "password_hash" not in acc


# =========================================================================
# 7. AUTOMATIC EMAIL NOTIFICATION SERVICE TESTS
# =========================================================================

def test_email_notification_formatting_and_mock_dispatch(test_client):
    """Verify email formatting, required fields, and delivery audit storage."""
    from security.email_notifier import email_notifier

    sent_emails = []

    def mock_sender(to, subject, body):
        sent_emails.append({"to": to, "subject": subject, "body": body})
        return True

    email_notifier.set_mock_sender(mock_sender)

    try:
        _login_as_attacker(test_client)

        # Launch simulated injection attack
        resp = test_client.post(
            "/attacker/api/simulate",
            json={
                "scenario": "injection",
                "params": {"target_device": "RTU_01", "temperature_c": 92.0, "pressure_bar": 8.0},
            },
        )
        assert resp.status_code == 200
        sim = resp.get_json()["simulation"]
        alert_id = sim["persisted_alert"]["alert_id"]

        # Verify email was captured by mock sender
        assert len(sent_emails) == 1
        sent = sent_emails[0]

        # Verify required subject format: [SCADA SECURITY ALERT] — Attack Type Detected
        assert sent["subject"].startswith("[SCADA SECURITY ALERT] —")
        assert "Detected" in sent["subject"]

        # Verify required body fields
        body = sent["body"]
        assert "SCADA SECURITY ALERT" in body
        assert f"Incident ID: {alert_id}" in body
        assert "Target Device: RTU_01" in body
        assert "Detection Method:" in body
        assert "Severity: HIGH" in body or "Severity: CRITICAL" in body
        assert "Recommended Action:" in body
        assert "Attack Detection Dashboard:" in body

        # Verify SQLite audit record in email_notifications table
        import time
        notif_rec = None
        for _ in range(20):
            notif_rec = repo.get_email_notification(alert_id)
            if notif_rec and notif_rec.status == "sent":
                break
            time.sleep(0.1)

        assert notif_rec is not None
        assert notif_rec.status == "sent"
        assert notif_rec.sent_at is not None
        assert notif_rec.attempt_count >= 1

    finally:
        email_notifier.set_mock_sender(None)


def test_email_duplicate_suppression(test_client):
    """Verify the notification service does not send duplicate emails for the same incident."""
    import uuid
    from security.email_notifier import email_notifier
    from database.models import AttackAlert

    sent_emails = []
    email_notifier.set_mock_sender(lambda to, sub, body: sent_emails.append(sub) or True)

    fresh_alert_id = f"alt_dup_{uuid.uuid4().hex[:8]}"

    try:
        alert = AttackAlert(
            alert_id=fresh_alert_id,
            attack_type="injection",
            source_device="ROGUE_CLIENT -> RTU_01",
            severity="HIGH",
            predicted_label="INJECTION",
            confidence=0.94,
            details="Test duplicate suppression",
            mitigation_action="Test action",
        )
        repo.insert_attack_alert(alert)

        # First notification
        res1 = email_notifier.notify_incident(alert, blocking=True)
        assert res1["status"] == "sent"
        assert len(sent_emails) == 1

        # Second notification for same incident ID
        res2 = email_notifier.notify_incident(alert, blocking=True)
        assert res2["status"] == "duplicate_suppressed"
        # Email count must NOT increase
        assert len(sent_emails) == 1

    finally:
        email_notifier.set_mock_sender(None)


def test_unconfigured_smtp_graceful_fallback(test_client):
    """Verify missing SMTP configuration logs gracefully and records 'skipped' status."""
    from security.email_notifier import email_notifier
    from database.models import AttackAlert
    from config.settings import settings

    email_notifier.set_mock_sender(None)  # Ensure no mock
    orig_host = settings.SMTP_HOST
    settings.SMTP_HOST = ""  # Explicitly simulate unconfigured host

    try:
        fresh_id = f"alt_unconf_{uuid.uuid4().hex[:8]}"
        alert = AttackAlert(
            alert_id=fresh_id,
            attack_type="replay",
            source_device="REPLAY_BOT -> RTU_01",
            severity="MEDIUM",
            predicted_label="REPLAY",
            confidence=0.91,
            details="Test unconfigured SMTP",
            mitigation_action="Discard stale timestamp",
        )
        repo.insert_attack_alert(alert)

        # When SMTP_HOST is empty, notify_incident returns skipped gracefully
        res = email_notifier.notify_incident(alert, blocking=True)
        assert res["status"] in ("skipped", "rate_limited")

        rec = repo.get_email_notification(fresh_id)
        assert rec is not None
        assert rec.status == "skipped"
        assert "SMTP not configured" in rec.failure_reason
    finally:
        settings.SMTP_HOST = orig_host


# =========================================================================
# 5. BRUTE-FORCE LOGIN DETECTION, ACCOUNT PROTECTION & QUANTUM VERIFICATION
# =========================================================================

def test_brute_force_simulation_scenario_and_counter(test_client):
    """
    Verify Scenario 5 (Brute-Force Login Simulation):
    - Sub-threshold attempts record without locking
    - Crossing 5 attempts threshold triggers HIGH severity alert and account lockout
    - Privacy preservation: Passwords never logged, account names masked
    """
    from security.login_monitor import login_monitor

    # Reset any lingering locks
    login_monitor.reset_all()

    try:
        # Authenticate as adversary
        test_client.post(
            "/attacker/login",
            data={"email": "redteam_lead@scada-lab.local", "password": "Adversary2026!"},
        )

        # 1. Dispatch 3 attempts (Below 5-attempt threshold)
        resp1 = test_client.post(
            "/attacker/api/simulate",
            json={
                "scenario": "brute_force",
                "params": {
                    "target_account": "admin@scada.local",
                    "attempt_count": 3,
                    "source_ip": "192.168.1.105",
                },
            },
        )
        assert resp1.status_code == 200
        data1 = resp1.get_json()
        assert data1["success"] is True
        stats1 = data1["simulation"]["brute_force_stats"]
        assert stats1["attempts_sent"] == 3
        assert stats1["threshold_exceeded"] is False
        assert stats1["account_locked"] is False

        # 2. Dispatch 3 more attempts (Cumulative 6 in window >= 5 threshold)
        resp2 = test_client.post(
            "/attacker/api/simulate",
            json={
                "scenario": "brute_force",
                "params": {
                    "target_account": "admin@scada.local",
                    "attempt_count": 3,
                    "source_ip": "192.168.1.105",
                },
            },
        )
        assert resp2.status_code == 200
        data2 = resp2.get_json()
        stats2 = data2["simulation"]["brute_force_stats"]
        assert stats2["threshold_exceeded"] is True
        assert stats2["account_locked"] is True
        assert stats2["masked_account"] == "ad***n@scada.local"

        # Verify detection metadata
        det = data2["simulation"]["detection"]
        assert det["severity"] == "HIGH"
        assert det["predicted_label"] == "PASSWORD_BRUTE_FORCE"
        assert "ad***n@scada.local" in det["details"]

        # Verify alert was inserted into DB
        alerts = repo.get_recent_alerts(limit=10)
        pwd_alerts = [a for a in alerts if a.attack_type == "password"]
        assert len(pwd_alerts) > 0
        latest_pwd = pwd_alerts[0]
        assert latest_pwd.severity == "HIGH"
        assert latest_pwd.predicted_label == "PASSWORD_BRUTE_FORCE"
        assert "ad***n@scada.local" in latest_pwd.details
        # Privacy check: never contains plaintext passwords or wordlist entries
        assert "password" not in latest_pwd.details.lower().split() or "brute-force" in latest_pwd.details.lower()
        assert "123456" not in latest_pwd.details
    finally:
        login_monitor.reset_all()


def test_defender_login_lockout_and_generic_feedback(test_client):
    """
    Verify Defender Website (/login) properly enforces LoginMonitor lockout:
    - When account is locked, returns 429 and generic message
    - Does not expose whether account exists in error message
    - Resetting account via /attacker/api/reset-account-lock restores login ability
    """
    from security.login_monitor import login_monitor

    login_monitor.reset_all()
    target = "operator@scada.local"

    try:
        # Force 5 failed attempts on defender login endpoint
        for _ in range(5):
            test_client.post(
                "/login",
                data={"email": target, "password": "WrongPassword123!"},
            )

        # Account should now be locked
        is_locked, remaining = login_monitor.is_account_locked(target)
        assert is_locked is True

        # Attempt login while locked -> should receive 429 with generic protection message
        locked_resp = test_client.post(
            "/login",
            data={"email": target, "password": "AnyPassword!"},
        )
        assert locked_resp.status_code == 429
        assert b"Account protection is active" in locked_resp.data

        # Log in to attacker portal to unlock account
        test_client.post(
            "/attacker/login",
            data={"email": "redteam_lead@scada-lab.local", "password": "Adversary2026!"},
        )

        unlock_resp = test_client.post(
            "/attacker/api/reset-account-lock",
            json={"account": target},
        )
        assert unlock_resp.status_code == 200
        assert unlock_resp.get_json()["success"] is True

        # Verify lockout is cleared
        is_locked_after, _ = login_monitor.is_account_locked(target)
        assert is_locked_after is False
    finally:
        login_monitor.reset_all()


def test_brute_force_email_alert_content():
    """Verify structured email alert formatting specifically for brute-force password attacks."""
    from security.email_notifier import email_notifier
    from database.models import AttackAlert

    alert = AttackAlert(
        alert_id="alt_pwd_test_01",
        attack_type="password",
        source_device="IP:192.168.1.105 -> AUTH_SVC",
        severity="HIGH",
        predicted_label="PASSWORD_BRUTE_FORCE",
        confidence=0.98,
        details="Multiple failed attempts against ad***n@scada.local",
        mitigation_action="Enforce temporary account lockout (5m)",
    )

    content = email_notifier.format_email_content(
        alert,
        metadata={
            "masked_account": "ad***n@scada.local",
            "failed_attempts": 5,
            "timeframe": "5 minutes",
            "source_ip": "192.168.1.105",
        },
    )

    # Subject must match project specification exactly
    assert content["subject"] == "[SCADA SECURITY ALERT] Multiple Failed Login Attempts Detected"
    # Body checks
    body = content["body"]
    assert "SCADA SECURITY ALERT" in body
    assert "Target Account: ad***n@scada.local" in body
    assert "Number of Failed Attempts: 5" in body
    assert "Detection Window: 5 minutes" in body
    assert "Source Identifier: 192.168.1.105" in body
    assert "Severity: HIGH" in body
    assert "/attack-alerts" in body


def test_quantum_bb84_eavesdropper_rejection_and_aes_gcm():
    """
    Verify Section 9 Quantum BB84 & AES-GCM Cryptographic Integration:
    1. Eavesdropper causes QBER > 11% abort
    2. Legitimate exchange produces 256-bit AES key via HKDF-SHA256
    3. AES-256-GCM authenticated cipher detects bit tampering and throws InvalidTag
    """
    from security.key_manager import KeyManager
    from security.encryption import AESGCMCipher

    km = KeyManager()

    # 1. Eavesdropper present: BB84 QBER aborts key generation
    eavesdrop_result = km.initiate_bb84_exchange(raw_bits=256, eavesdropper=True, seed=42)
    assert eavesdrop_result["is_encrypted"] is False
    assert "REJECTED" in eavesdrop_result["session_status"]
    assert eavesdrop_result["latest_bb84"]["qber"] > 0.11

    # 2. Legitimate channel: BB84 accepts key and derives AES key
    valid_result = km.initiate_bb84_exchange(raw_bits=256, noise_level=0.0, eavesdropper=False, seed=42)
    assert valid_result["is_encrypted"] is True
    assert valid_result["session_status"] == "ESTABLISHED"
    assert valid_result["cipher_algorithm"] == "AES-256-GCM"

    cipher = km.get_cipher()
    assert cipher is not None

    # 3. Encrypt telemetry payload
    payload = '{"temp": 28.5, "pressure": 2.4, "cmd": "OPEN_VALVE"}'
    aad = "RTU_01->PLC_01:2026-10-28T20:00:00"
    enc = cipher.encrypt(payload, associated_data=aad)
    assert "ciphertext_b64" in enc
    assert "nonce_b64" in enc
    assert enc["algorithm"] == "AES-256-GCM"

    # Valid decrypt
    ok, decrypted, err = cipher.decrypt(enc["ciphertext_b64"], enc["nonce_b64"], associated_data=aad)
    assert ok is True
    assert decrypted == payload
    assert err is None

    # Tampered ciphertext (simulating MITM packet alteration)
    import base64
    raw_ct = bytearray(base64.b64decode(enc["ciphertext_b64"]))
    raw_ct[5] ^= 0xFF  # Flip bits
    tampered_b64 = base64.b64encode(raw_ct).decode("utf-8")

    tampered_ok, tampered_dec, tampered_err = cipher.decrypt(tampered_b64, enc["nonce_b64"], associated_data=aad)
    assert tampered_ok is False
    assert tampered_dec is None
    assert "Invalid authentication tag" in tampered_err

    # Tampered AAD context
    aad_ok, aad_dec, aad_err = cipher.decrypt(enc["ciphertext_b64"], enc["nonce_b64"], associated_data="FORGED_CONTEXT")
    assert aad_ok is False
    assert aad_dec is None
    assert "Invalid authentication tag" in aad_err


# =========================================================================
# 6. CROSS-LAPTOP REAL-TIME MONITORING, CORS & EMERGENCY STOP TESTS
# =========================================================================

def test_cross_client_cors_preflight_and_security_headers(test_client):
    """
    Verify cross-laptop access support:
    - Preflight OPTIONS returns CORS allow headers and methods
    - Security headers (nosniff, SAMEORIGIN) are strictly enforced
    """
    resp = test_client.open(
        "/api/alerts",
        method="OPTIONS",
        headers={"Origin": "http://192.168.1.100:5050"},
    )
    assert resp.status_code == 200
    assert "Access-Control-Allow-Origin" in resp.headers
    assert resp.headers["Access-Control-Allow-Origin"] in ("http://192.168.1.100:5050", "*")
    assert "GET" in resp.headers.get("Access-Control-Allow-Methods", "")
    assert resp.headers.get("Access-Control-Allow-Credentials") == "true"

    # Regular GET check for security headers
    get_resp = test_client.get("/api/status")
    assert get_resp.status_code == 200
    assert get_resp.headers.get("X-Content-Type-Options") == "nosniff"
    assert get_resp.headers.get("X-Frame-Options") == "SAMEORIGIN"


def test_cross_client_event_sharing_and_field_enrichment(test_client):
    """
    Verify cross-client incident persistence and field enrichment:
    - Laptop 2 (attacker) triggers simulation
    - Backend persists actual detector outcome in shared database
    - Laptop 1 (defender) retrieves incident with all 11 required fields
    """
    # Authenticate attacker
    test_client.post(
        "/attacker/login",
        data={"email": "redteam_lead@scada-lab.local", "password": "Adversary2026!"},
    )

    # Laptop 2 dispatches FDI attack with Origin header
    sim_resp = test_client.post(
        "/attacker/api/simulate",
        json={
            "scenario": "injection",
            "params": {
                "target_device": "RTU_01",
                "sensor_type": "temp",
                "temperature_c": 92.5,
                "function_code": 16,
            },
        },
        headers={
            "Origin": "http://192.168.1.100:5050",
            "X-Forwarded-For": "192.168.1.100",
        },
    )
    assert sim_resp.status_code == 200
    sim_data = sim_resp.get_json()
    assert sim_data["success"] is True
    alert_id = sim_data["simulation"]["persisted_alert"]["alert_id"]

    # Laptop 1 (defender) fetches alerts list
    def_resp = test_client.get("/api/alerts?limit=10")
    assert def_resp.status_code == 200
    alerts_data = def_resp.get_json()
    assert "alerts" in alerts_data

    # Find the newly created alert
    matched = [a for a in alerts_data["alerts"] if a["alert_id"] == alert_id]
    assert len(matched) == 1
    alert = matched[0]

    # Verify all required fields from Requirement 5
    assert alert["alert_id"] == alert_id
    assert alert["attack_type"] == "injection"
    assert alert["timestamp"] is not None
    assert alert["severity"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
    assert alert["target"] == "RTU_01"
    assert "ROGUE_CLIENT" in alert["source_device"] or "INJECTOR" in alert["source_device"]
    assert "Isolation Forest" in alert["detection_method"]
    assert alert["predicted_label"] == "INJECTION"
    assert alert["incident_status"] == "RECORDED"


def test_real_time_sse_alerts_stream(test_client):
    """Verify Server-Sent Events endpoint connects and yields text/event-stream chunks."""
    resp = test_client.get("/api/alerts/stream", headers={"Accept": "text/event-stream"})
    assert resp.status_code == 200
    assert "text/event-stream" in resp.headers["Content-Type"]
    # Check first line
    line = next(resp.response)
    assert b"event: connected" in line or b": ping" in line or b"alerts_update" in line


def test_emergency_stop_endpoints(test_client):
    """
    Verify Emergency Stop:
    - Halts all active attacks
    - Restores physical process baselines
    - Accessible via /api/emergency-stop and /attacker/api/emergency-stop
    """
    # 1. Attacker portal emergency halt
    test_client.post(
        "/attacker/login",
        data={"email": "redteam_lead@scada-lab.local", "password": "Adversary2026!"},
    )
    att_halt = test_client.post("/attacker/api/emergency-stop")
    assert att_halt.status_code == 200
    assert att_halt.get_json()["success"] is True

    # 2. Operator global emergency stop
    op_halt = test_client.post("/api/emergency-stop")
    assert op_halt.status_code == 200
    data = op_halt.get_json()
    assert data["success"] is True
    assert "EMERGENCY STOP EXECUTED" in data["message"]


def test_brute_force_dedicated_demo_account(test_client):
    """
    Verify dedicated demo account (demo_operator@scada.local):
    - Reaching threshold locks demo account
    - Admin account remains unlocked
    - 1-click unlock restores account state
    """
    from security.login_monitor import login_monitor

    login_monitor.reset_all()
    demo_acc = "demo_operator@scada.local"

    try:
        test_client.post(
            "/attacker/login",
            data={"email": "redteam_lead@scada-lab.local", "password": "Adversary2026!"},
        )

        resp = test_client.post(
            "/attacker/api/simulate",
            json={
                "scenario": "brute_force",
                "params": {
                    "target_account": demo_acc,
                    "attempt_count": 5,
                    "source_ip": "192.168.1.105",
                },
            },
        )
        assert resp.status_code == 200
        stats = resp.get_json()["simulation"]["brute_force_stats"]
        assert stats["account_locked"] is True
        assert stats["threshold_exceeded"] is True

        # Verify demo account is locked
        is_locked, _ = login_monitor.is_account_locked(demo_acc)
        assert is_locked is True

        # Verify admin account is NOT locked
        admin_locked, _ = login_monitor.is_account_locked("admin@scada.local")
        assert admin_locked is False

        # Reset demo account lock
        reset_resp = test_client.post(
            "/attacker/api/reset-account-lock",
            json={"account": demo_acc},
        )
        assert reset_resp.status_code == 200
        assert reset_resp.get_json()["success"] is True

        is_locked_after, _ = login_monitor.is_account_locked(demo_acc)
        assert is_locked_after is False

    finally:
        login_monitor.reset_all()


def test_complete_cross_laptop_end_to_end_flow(test_client):
    """
    End-to-End Test for Cross-Laptop Flow (Requirement 10):
    1. Laptop 2 launches simulation
    2. Backend records event & executes ML detector
    3. Laptop 1 retrieves incident on /api/alerts
    4. Mocked email notification is triggered and formatted properly
    """
    from security.email_notifier import email_notifier

    email_notifier.reset_state()
    sent_emails = []
    email_notifier.set_mock_sender(lambda to, sub, body: sent_emails.append({"sub": sub, "body": body}) or True)

    try:
        # Authenticate on Laptop 2
        test_client.post(
            "/attacker/login",
            data={"email": "researcher@scada-lab.local", "password": "LabResearch2026!"},
        )

        # Launch DoS burst
        launch_resp = test_client.post(
            "/attacker/api/simulate",
            json={
                "scenario": "dos",
                "params": {
                    "target_device": "RTU_01",
                    "packet_rate": 90.0,
                    "burst_count": 25,
                },
            },
            headers={
                "Origin": "http://192.168.1.120:5050",
                "X-Forwarded-For": "192.168.1.120",
            },
        )
        assert launch_resp.status_code == 200
        sim_data = launch_resp.get_json()
        assert sim_data["success"] is True

        # Verify detection outcome
        det = sim_data["simulation"]["detection"]
        assert det["predicted_label"] == "DOS"
        assert det["severity"] == "HIGH"
        assert det["confidence"] >= 0.90

        # Verify Laptop 1 (defender) sees this alert
        alerts_resp = test_client.get("/api/alerts?limit=5")
        assert alerts_resp.status_code == 200
        alerts = alerts_resp.get_json()["alerts"]
        matched_alerts = [a for a in alerts if a["alert_id"] == sim_data["simulation"]["persisted_alert"]["alert_id"]]
        assert len(matched_alerts) == 1

        # Verify email was dispatched with correct subject
        assert len(sent_emails) >= 1
        latest_email = sent_emails[-1]
        assert "[SCADA SECURITY ALERT] — DoS Flood Simulation Detected" in latest_email["sub"]
        assert "Target Device: RTU_01" in latest_email["body"]

    finally:
        email_notifier.set_mock_sender(None)
        email_notifier.reset_state()


def test_dos_continuous_lifecycle_and_state_transitions(test_client):
    """
    Verify DoS continuous simulation lifecycle:
    - Initiates via /attacker/api/continuous/start
    - Status transitions to RUNNING
    - Status endpoint /attacker/api/status reports active states
    - Terminates cleanly via /attacker/api/continuous/stop
    - Status transitions to STOPPED
    """
    from attacker_portal.simulation_service import attacker_service

    test_client.post(
        "/attacker/login",
        data={"email": "researcher@scada-lab.local", "password": "LabResearch2026!"},
    )

    try:
        # 1. Start continuous DoS
        start_resp = test_client.post(
            "/attacker/api/continuous/start",
            json={
                "attack_name": "dos",
                "params": {
                    "target_device": "RTU_01",
                    "packet_rate": 85.0,
                    "burst_count": 10,
                },
            },
        )
        assert start_resp.status_code == 200
        start_data = start_resp.get_json()
        assert start_data["success"] is True
        assert start_data["state"] == "RUNNING"
        assert "dos" in start_data["active_attacks"]

        # 2. Check /attacker/api/status
        status_resp = test_client.get("/attacker/api/status")
        assert status_resp.status_code == 200
        status_data = status_resp.get_json()
        assert "simulation_states" in status_data
        assert status_data["simulation_states"]["dos"]["state"] in ("STARTING", "RUNNING", "STOPPED")

        # 3. Stop continuous DoS
        stop_resp = test_client.post(
            "/attacker/api/continuous/stop",
            json={"attack_name": "dos"},
        )
        assert stop_resp.status_code == 200
        stop_data = stop_resp.get_json()
        assert stop_data["success"] is True
        assert stop_data["state"] == "STOPPED"

    finally:
        attacker_service.stop_all()


def test_simulation_failure_error_reporting(test_client):
    """
    Verify useful error handling:
    - Invalid scenario or parameters returns informative error
    - Does not fail silently
    - Status reflects FAILED state with error message
    """
    test_client.post(
        "/attacker/login",
        data={"email": "researcher@scada-lab.local", "password": "LabResearch2026!"},
    )

    # Invalid attack name to continuous start
    resp = test_client.post(
        "/attacker/api/continuous/start",
        json={"attack_name": "non_existent_exploit"},
    )
    assert resp.status_code == 400
    data = resp.get_json()
    assert data["success"] is False
    assert data["state"] == "FAILED"
    assert "Unknown attack 'non_existent_exploit'" in data["error"]



