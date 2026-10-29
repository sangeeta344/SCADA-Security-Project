"""Flask routes and REST API endpoints for SCADA cybersecurity dashboard."""

from functools import wraps
from flask import (
    Blueprint,
    render_template,
    request,
    jsonify,
    redirect,
    url_for,
    session,
    flash,
    current_app,
    Response,
    stream_with_context,
)
from typing import Dict, Any
import json
import time
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

from config.settings import settings
from config.logging_config import logger
from database.repository import repo
from security.key_manager import key_manager
from security.login_monitor import login_monitor
from attack_simulation.attack_controller import attack_controller
from ml_detection.model_loader import model_loader
from ml_detection.evaluate_model import ModelEvaluator

dashboard_bp = Blueprint("dashboard", __name__)


def _is_authorized_client() -> bool:
    """Security check ensuring control endpoints are invoked by authenticated users, localhost, authorized API keys, or authorized CIDRs."""
    if session.get("user_id") or session.get("attacker_user"):
        return True

    api_key = request.headers.get("X-API-Key")
    if api_key and settings.SCADA_API_KEY and api_key == settings.SCADA_API_KEY:
        return True

    remote = request.remote_addr
    if remote in ("127.0.0.1", "::1", "localhost", None):
        return True

    if settings.AUTHORIZED_CIDR:
        try:
            import ipaddress
            client_ip = ipaddress.ip_address(remote)
            network = ipaddress.ip_network(settings.AUTHORIZED_CIDR, strict=False)
            if client_ip in network:
                return True
        except Exception:
            pass

    return False


def _is_localhost() -> bool:
    """Backward compatibility alias for _is_authorized_client."""
    return _is_authorized_client()


def login_required(f):
    """Decorator requiring an authenticated operator session."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_app.config.get("LOGIN_DISABLED"):
            return f(*args, **kwargs)
        if not session.get("user_id"):
            if request.path.startswith("/api/"):
                return jsonify({"error": "Unauthorized", "message": "Authentication required"}), 401
            return redirect(url_for("dashboard.login", next=request.path))
        return f(*args, **kwargs)
    return decorated_function


# =========================================================================
# AUTHENTICATION ROUTES (LOGIN, REGISTER, LOGOUT)
# =========================================================================

@dashboard_bp.route("/login", methods=["GET", "POST"])
def login():
    """User login endpoint using email and password with brute-force rate monitoring."""
    if session.get("user_id"):
        return redirect(url_for("dashboard.overview"))

    if request.method == "POST":
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")

        if not email or not password:
            flash("Please enter both email and password.", "danger")
            return render_template("login.html", email=email), 400

        client_ip = request.remote_addr or "127.0.0.1"

        # Check defensive temporary account lockout
        is_locked, remaining_sec = login_monitor.is_account_locked(email)
        if is_locked:
            flash(
                "Account protection is active due to multiple failed login attempts. Please try again later.",
                "warning",
            )
            return render_template("login.html", email=email), 429

        user = repo.get_user_by_email(email)
        if not user or not check_password_hash(user.password_hash, password):
            # Record failed login attempt without ever logging or exposing passwords
            res = login_monitor.record_failed_login(email, ip=client_ip, source="DEFENDER_LOGIN")
            if res.get("threshold_exceeded"):
                flash(
                    "Account protection is active due to multiple failed login attempts. Please try again later.",
                    "warning",
                )
                return render_template("login.html", email=email), 429

            flash("Invalid email or password. Please try again.", "danger")
            return render_template("login.html", email=email), 401

        # Successful authentication resets failed attempts counter
        login_monitor.record_successful_login(email, ip=client_ip)

        session.clear()
        session["user_id"] = user.id
        session["user_email"] = user.email
        session["username"] = user.username
        session["user_role"] = user.role
        flash(f"Welcome back, {user.username}!", "success")

        next_url = request.args.get("next")
        if next_url and next_url.startswith("/") and not next_url.startswith("/login"):
            return redirect(next_url)
        return redirect(url_for("dashboard.overview"))

    return render_template("login.html", email=request.args.get("email"))


@dashboard_bp.route("/api/admin/unlock-account", methods=["POST"])
@login_required
def admin_unlock_account():
    """Administrative action to reset lockout on an operator account."""
    data = request.get_json(silent=True) or {}
    account = data.get("account", "").strip()
    if not account:
        return jsonify({"error": "Account identifier required"}), 400
    success = login_monitor.reset_account(account)
    return jsonify({
        "success": success,
        "account": account,
        "message": f"Account protection reset for {account}",
    })


@dashboard_bp.route("/register", methods=["GET", "POST"])
def register():
    """User registration endpoint for new SCADA operators."""
    if session.get("user_id"):
        return redirect(url_for("dashboard.overview"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")
        role = request.form.get("role", "Security Operator").strip()

        if not username or len(username) < 2:
            flash("Full name / username must be at least 2 characters.", "danger")
            return render_template("register.html", username=username, email=email, role=role), 400

        if not email or "@" not in email or "." not in email:
            flash("Please enter a valid email address.", "danger")
            return render_template("register.html", username=username, email=email, role=role), 400

        if len(password) < 6:
            flash("Password must be at least 6 characters long.", "danger")
            return render_template("register.html", username=username, email=email, role=role), 400

        if password != confirm_password:
            flash("Passwords do not match.", "danger")
            return render_template("register.html", username=username, email=email, role=role), 400

        existing = repo.get_user_by_email(email)
        if existing:
            flash("An account with this email already exists. Please log in.", "warning")
            return redirect(url_for("dashboard.login", email=email))

        password_hash = generate_password_hash(password)
        user_id = repo.create_user(username, email, password_hash, role)

        if not user_id:
            flash("Failed to register account. Please try again.", "danger")
            return render_template("register.html", username=username, email=email, role=role), 500

        flash("Registration successful! You can now log in with your credentials.", "success")
        return redirect(url_for("dashboard.login", email=email))

    return render_template("register.html")


@dashboard_bp.route("/logout")
def logout():
    """Log out current user and terminate session."""
    session.clear()
    flash("You have been safely logged out.", "info")
    return redirect(url_for("dashboard.login"))


# =========================================================================
# HTML VIEW ROUTES (PROTECTED)
# =========================================================================

@dashboard_bp.route("/")
def index():
    """Initial landing route: redirect unauthenticated users to login, else overview."""
    if not session.get("user_id"):
        return redirect(url_for("dashboard.login"))
    return redirect(url_for("dashboard.overview"))


@dashboard_bp.route("/overview")
@login_required
def overview():
    """Page 1: System Overview and Operations Summary."""
    devices = repo.get_all_devices()
    online_count = sum(1 for d in devices if d.status == "ONLINE")
    traffic_summary = repo.get_traffic_summary()
    q_status = key_manager.get_session_status()
    latest_qber = repo.get_qber_history(limit=1)

    return render_template(
        "index.html",
        active_page="overview",
        total_devices=len(devices),
        online_devices=online_count,
        offline_devices=len(devices) - online_count,
        traffic_summary=traffic_summary,
        quantum_status=q_status,
        latest_qber=latest_qber[0] if latest_qber else None,
        recent_alerts=repo.get_recent_alerts(limit=5),
        recent_readings=repo.get_recent_sensor_readings(limit=5),
    )


@dashboard_bp.route("/network-monitor")
@login_required
def network_monitor():
    """Page 2: Live Network Traffic Monitoring."""
    events = repo.get_recent_traffic_events(limit=50)
    return render_template(
        "network_monitor.html",
        active_page="network_monitor",
        events=events,
    )


@dashboard_bp.route("/attack-alerts")
@login_required
def attack_alerts():
    """Page 3: Attack Detection History & Safe Simulation Controller."""
    alerts = repo.get_recent_alerts(limit=50)
    active_attacks = attack_controller.get_active_attacks()
    return render_template(
        "attack_alerts.html",
        active_page="attack_alerts",
        alerts=alerts,
        active_attacks=active_attacks,
    )


@dashboard_bp.route("/quantum-security")
@login_required
def quantum_security():
    """Page 4: BB84 Quantum Key Distribution and Cryptographic Security."""
    status = key_manager.get_session_status()
    qber_history = repo.get_qber_history(limit=15)
    return render_template(
        "quantum_security.html",
        active_page="quantum_security",
        quantum_status=status,
        qber_history=qber_history,
        qber_threshold=settings.QBER_THRESHOLD,
    )


@dashboard_bp.route("/model-metrics")
@login_required
def model_metrics():
    """Page 5: Machine Learning Evaluation and Dataset Status."""
    eval_report = ModelEvaluator.get_summary_report()
    models_status = model_loader.get_models_status()

    # Load inspection report if present
    inspection_path = settings.BASE_DIR / "data" / "processed" / "dataset_inspection_report.json"
    inspection_data = {}
    if inspection_path.exists():
        try:
            with open(inspection_path, "r", encoding="utf-8") as f:
                inspection_data = json.load(f)
        except Exception:
            pass

    return render_template(
        "model_metrics.html",
        active_page="model_metrics",
        eval_report=eval_report,
        models_status=models_status,
        datasets=inspection_data,
    )



# =========================================================================
# REST API ENDPOINTS
# =========================================================================

@dashboard_bp.route("/api/status", methods=["GET"])
def api_status():
    """System health and subsystem statuses."""
    devices = repo.get_all_devices()
    q_status = key_manager.get_session_status()
    traffic = repo.get_traffic_summary()

    return jsonify({
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "devices": {
            "total": len(devices),
            "online": sum(1 for d in devices if d.status == "ONLINE"),
        },
        "quantum_session": q_status,
        "traffic_summary": traffic,
        "active_attacks": attack_controller.get_active_attacks(),
    })


@dashboard_bp.route("/api/devices", methods=["GET"])
def api_devices():
    """List all registered SCADA devices."""
    devices = repo.get_all_devices()
    return jsonify({"devices": [d.to_dict() for d in devices]})


@dashboard_bp.route("/api/telemetry", methods=["GET"])
def api_telemetry():
    """Recent sensor readings and time-series data."""
    limit = min(100, int(request.args.get("limit", 30)))
    series = repo.get_sensor_time_series(limit=limit)
    latest = repo.get_recent_sensor_readings(limit=1)
    return jsonify({
        "latest": latest[0].to_dict() if latest else None,
        "series": series,
    })


@dashboard_bp.route("/api/traffic", methods=["GET"])
def api_traffic():
    """Recent network traffic observations with filtering."""
    limit = min(200, int(request.args.get("limit", 50)))
    protocol = request.args.get("protocol")
    events = repo.get_recent_traffic_events(limit=limit, protocol=protocol)
    return jsonify({
        "total": len(events),
        "events": [e.to_dict() for e in events],
    })


@dashboard_bp.route("/api/alerts", methods=["GET"])
def api_alerts():
    """Security alerts generated by intrusion detection."""
    limit = min(100, int(request.args.get("limit", 50)))
    alerts = repo.get_recent_alerts(limit=limit)
    return jsonify({
        "total": len(alerts),
        "alerts": [a.to_dict() for a in alerts],
    })


@dashboard_bp.route("/api/quantum/status", methods=["GET"])
def api_quantum_status():
    """Current BB84 quantum session status and QBER measurements."""
    status = key_manager.get_session_status()
    history = repo.get_qber_history(limit=20)
    return jsonify({
        "status": status,
        "qber_history": history,
    })


@dashboard_bp.route("/api/model/metrics", methods=["GET"])
def api_model_metrics():
    """Trained model evaluation metrics and performance reports."""
    summary = ModelEvaluator.get_summary_report()
    status = model_loader.get_models_status()
    return jsonify({
        "models_status": status,
        "metrics": summary,
    })


@dashboard_bp.route("/api/quantum/run", methods=["POST"])
def api_quantum_run():
    """Execute a simulated BB84 key distribution with configurable parameters."""
    if not _is_localhost():
        return jsonify({"error": "Unauthorized: Control requests permitted from localhost only"}), 403

    data = request.get_json(silent=True) or {}
    try:
        raw_bits = int(data.get("raw_bits", settings.BB84_RAW_BITS))
        noise_level = float(data.get("noise_level", 0.0))
        eavesdropper = bool(data.get("eavesdropper", False))
        seed = int(data.get("seed")) if data.get("seed") is not None else None

        # Validate bounds
        raw_bits = max(64, min(1024, raw_bits))
        noise_level = max(0.0, min(1.0, noise_level))

        result = key_manager.initiate_bb84_exchange(
            raw_bits=raw_bits,
            noise_level=noise_level,
            eavesdropper=eavesdropper,
            seed=seed,
        )
        return jsonify({"success": True, "result": result})
    except Exception as e:
        logger.error("Error running BB84 simulation: %s", e)
        return jsonify({"success": False, "error": str(e)}), 400


@dashboard_bp.route("/api/attacks/start", methods=["POST"])
def api_attacks_start():
    """Safely start an authorized local attack simulation."""
    if not _is_localhost():
        return jsonify({"error": "Unauthorized"}), 403

    data = request.get_json(silent=True) or {}
    attack_name = data.get("attack_name", "")
    res = attack_controller.start_attack(attack_name)
    return jsonify(res), (200 if res.get("success") else 400)


@dashboard_bp.route("/api/attacks/stop", methods=["POST"])
def api_attacks_stop():
    """Safely stop an active attack simulation."""
    if not _is_localhost():
        return jsonify({"error": "Unauthorized"}), 403

    data = request.get_json(silent=True) or {}
    attack_name = data.get("attack_name", "")
    if attack_name.lower() == "all":
        attack_controller.stop_all()
        return jsonify({"success": True, "message": "All attacks stopped.", "active_attacks": []})

    res = attack_controller.stop_attack(attack_name)
    return jsonify(res), (200 if res.get("success") else 400)


@dashboard_bp.route("/api/simulation/start", methods=["POST"])
def api_simulation_start():
    """Start synthetic sensor and traffic background generation."""
    if not _is_localhost():
        return jsonify({"error": "Unauthorized"}), 403
    return jsonify({"success": True, "message": "Simulation running."})


@dashboard_bp.route("/api/simulation/stop", methods=["POST"])
def api_simulation_stop():
    """Pause synthetic simulation."""
    if not _is_localhost():
        return jsonify({"error": "Unauthorized"}), 403
    return jsonify({"success": True, "message": "Simulation paused."})


@dashboard_bp.route("/api/alerts/stream")
def api_alerts_stream():
    """Server-Sent Events endpoint pushing real-time attack alerts to connected browsers."""
    def event_generator():
        last_seen_id = None
        # Initial connection event
        yield f"event: connected\ndata: {json.dumps({'status': 'connected', 'timestamp': datetime.now().isoformat()})}\n\n"

        recent = repo.get_recent_alerts(limit=1)
        if recent:
            last_seen_id = recent[0].alert_id

        # Stream loop for push notifications
        for _ in range(60):
            time.sleep(1.0)
            try:
                latest_alerts = repo.get_recent_alerts(limit=50)
                if latest_alerts and (last_seen_id is None or latest_alerts[0].alert_id != last_seen_id):
                    last_seen_id = latest_alerts[0].alert_id
                    payload = json.dumps([a.to_dict() for a in latest_alerts])
                    yield f"event: alerts_update\ndata: {payload}\n\n"
                else:
                    yield ": ping\n\n"
            except Exception as err:
                logger.debug("SSE stream loop terminated: %s", err)
                break

    return Response(
        stream_with_context(event_generator()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
            "Access-Control-Allow-Origin": "*",
        },
    )


@dashboard_bp.route("/api/emergency-stop", methods=["POST"])
def api_emergency_stop():
    """Global emergency stop halting all attack simulations and restoring baselines."""
    if not _is_authorized_client():
        return jsonify({"error": "Unauthorized: Administrative control privileges required"}), 403

    client_ip = request.remote_addr or "127.0.0.1"
    user_info = session.get("username") or (session.get("attacker_user") or {}).get("username") or "OPERATOR"
    logger.warning("GLOBAL EMERGENCY STOP triggered from IP %s by %s", client_ip, user_info)

    # 1. Stop background attack controller
    attack_controller.stop_all()

    # 2. Stop adversary portal continuous loops & restore telemetry
    try:
        from attacker_portal.simulation_service import attacker_service
        attacker_service.stop_all()
        attacker_service.restore_sensor_telemetry("RTU_01")
    except Exception as err:
        logger.warning("Attacker service emergency halt warning: %s", err)

    # 3. Reset account lockouts
    try:
        from security.login_monitor import login_monitor
        login_monitor.reset_all()
    except Exception as err:
        logger.warning("Login monitor emergency reset warning: %s", err)

    return jsonify({
        "success": True,
        "message": "EMERGENCY STOP EXECUTED: All simulations halted and sensor telemetry restored to nominal baseline.",
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "triggered_by": user_info,
        "client_ip": client_ip,
    })
