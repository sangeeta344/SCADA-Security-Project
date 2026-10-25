"""Integration tests for Flask dashboard web application, authentication, and REST API endpoints."""

import pytest
from dashboard.app import create_app
from database.repository import repo


@pytest.fixture
def client():
    """Create Flask test client with test configuration."""
    app = create_app({"TESTING": True})
    with app.test_client() as client:
        yield client


def test_unauthenticated_redirects_to_login(client):
    """Verify that unauthenticated access to protected routes redirects to /login."""
    protected_views = [
        "/",
        "/overview",
        "/network-monitor",
        "/attack-alerts",
        "/quantum-security",
        "/model-metrics",
    ]
    for view in protected_views:
        res = client.get(view)
        assert res.status_code == 302, f"View {view} should redirect to /login"
        assert "/login" in res.headers["Location"]


def test_auth_pages_render_ok(client):
    """Verify GET /login and GET /register return HTTP 200 with HTML forms."""
    res_login = client.get("/login")
    assert res_login.status_code == 200
    assert b"SCADA SHIELD" in res_login.data
    assert b"Log In to SCADA System" in res_login.data

    res_register = client.get("/register")
    assert res_register.status_code == 200
    assert b"OPERATOR REGISTRATION" in res_register.data
    assert b"Create Account" in res_register.data


def test_user_registration_and_login_flow(client):
    """Verify end-to-end registration of a new operator and subsequent login."""
    import uuid
    test_email = f"operator_{uuid.uuid4().hex[:8]}@scada.test"
    test_pass = "SecurePass123!"

    # 1. Validation failure: mismatched passwords
    res_mismatch = client.post(
        "/register",
        data={
            "username": "Test Operator",
            "email": test_email,
            "password": test_pass,
            "confirm_password": "WrongPassword",
            "role": "Security Operator",
        },
    )
    assert res_mismatch.status_code == 400
    assert b"Passwords do not match" in res_mismatch.data

    # 2. Successful registration
    res_reg = client.post(
        "/register",
        data={
            "username": "Test Operator",
            "email": test_email,
            "password": test_pass,
            "confirm_password": test_pass,
            "role": "Security Operator",
        },
        follow_redirects=True,
    )
    assert res_reg.status_code == 200
    assert b"Registration successful" in res_reg.data

    # 3. Invalid login rejection
    res_bad_login = client.post(
        "/login",
        data={"email": test_email, "password": "WrongPassword123"},
    )
    assert res_bad_login.status_code == 401
    assert b"Invalid email or password" in res_bad_login.data

    # 4. Valid login
    res_good_login = client.post(
        "/login",
        data={"email": test_email, "password": test_pass},
        follow_redirects=True,
    )
    assert res_good_login.status_code == 200
    assert b"SCADA SHIELD" in res_good_login.data
    assert b"Test Operator" in res_good_login.data

    # 5. Access protected view after login
    res_overview = client.get("/overview")
    assert res_overview.status_code == 200
    assert b"System Overview" in res_overview.data

    # 6. Logout
    res_logout = client.get("/logout", follow_redirects=True)
    assert res_logout.status_code == 200
    assert b"safely logged out" in res_logout.data

    # 7. Access is blocked again after logout
    res_blocked = client.get("/overview")
    assert res_blocked.status_code == 302


def test_default_admin_login(client):
    """Verify default seeded admin credentials (admin@scada.local / admin123)."""
    res = client.post(
        "/login",
        data={"email": "admin@scada.local", "password": "admin123"},
        follow_redirects=True,
    )
    assert res.status_code == 200
    assert b"SCADA Administrator" in res.data or b"System Administrator" in res.data


def test_api_get_endpoints(client):
    """Verify all GET API endpoints return valid JSON structures."""
    endpoints = [
        "/api/status",
        "/api/devices",
        "/api/telemetry",
        "/api/traffic",
        "/api/alerts",
        "/api/quantum/status",
        "/api/model/metrics",
    ]
    for ep in endpoints:
        res = client.get(ep)
        assert res.status_code == 200, f"API endpoint {ep} returned {res.status_code}"
        assert res.is_json, f"Endpoint {ep} did not return JSON"


def test_api_bb84_simulation_endpoint(client):
    """Verify POST /api/quantum/run executes simulated exchange."""
    res = client.post(
        "/api/quantum/run",
        json={"raw_bits": 128, "noise_level": 0.0, "eavesdropper": False, "seed": 42},
    )
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert "result" in data
    assert data["result"]["is_encrypted"] is True


def test_api_attack_simulation_start_stop(client):
    """Verify starting and stopping attack scenarios via API."""
    # Start valid attack
    res_start = client.post("/api/attacks/start", json={"attack_name": "dos"})
    assert res_start.status_code == 200
    data_start = res_start.get_json()
    assert data_start["success"] is True
    assert "dos" in data_start["active_attacks"]

    # Stop valid attack
    res_stop = client.post("/api/attacks/stop", json={"attack_name": "dos"})
    assert res_stop.status_code == 200
    data_stop = res_stop.get_json()
    assert data_stop["success"] is True
    assert "dos" not in data_stop["active_attacks"]

    # Reject invalid attack name
    res_bad = client.post("/api/attacks/start", json={"attack_name": "arbitrary_malware"})
    assert res_bad.status_code == 400
