"""Flask routes and API endpoints for the separate Attacker Portal.

Provides isolated red-team simulation controls, authenticates fictional
adversary credentials, and integrates directly with the ML detection pipeline.
"""

from flask import (
    Blueprint,
    render_template,
    request,
    jsonify,
    redirect,
    url_for,
    session,
    flash,
)
from datetime import datetime

from config.logging_config import logger
from database.repository import repo
from ml_detection.model_loader import model_loader
from attacker_portal.auth import (
    authenticate_adversary,
    get_current_adversary,
    attacker_login_required,
    FICTIONAL_ADVERSARY_ACCOUNTS,
)
from attacker_portal.simulation_service import (
    attacker_service,
    SYNTHETIC_TARGETS,
)

attacker_bp = Blueprint(
    "attacker",
    __name__,
    template_folder="templates",
    static_folder="static",
    static_url_path="/attacker-static",
)


# =========================================================================
# ATTACKER AUTHENTICATION (ISOLATED FICTIONAL ACCOUNTS ONLY)
# =========================================================================

@attacker_bp.route("/login", methods=["GET", "POST"])
def login():
    """Adversary portal login using authorized lab credentials."""
    if session.get("attacker_user"):
        return redirect(url_for("attacker.console"))

    if request.method == "POST":
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")

        user = authenticate_adversary(email, password)
        if not user:
            flash("Invalid adversary credentials. Please use an authorized lab account.", "danger")
            return render_template(
                "attacker_login.html",
                email=email,
                demo_accounts=list(FICTIONAL_ADVERSARY_ACCOUNTS.values()),
            ), 401

        session["attacker_user"] = user
        flash(f"Authenticated as {user['role']} ({user['username']}). Lab emulation mode active.", "success")

        next_url = request.args.get("next")
        if next_url and next_url.startswith("/attacker") and not next_url.startswith("/attacker/login"):
            return redirect(next_url)
        return redirect(url_for("attacker.console"))

    return render_template(
        "attacker_login.html",
        email=request.args.get("email", ""),
        demo_accounts=list(FICTIONAL_ADVERSARY_ACCOUNTS.values()),
    )


@attacker_bp.route("/logout")
def logout():
    """Terminate attacker session without affecting operator session."""
    session.pop("attacker_user", None)
    flash("Attacker session ended safely.", "info")
    return redirect(url_for("attacker.login"))


# =========================================================================
# ATTACKER CONSOLE VIEWS
# =========================================================================

@attacker_bp.route("/")
@attacker_bp.route("/console")
@attacker_login_required
def console():
    """Main Adversary Emulation & Penetration Testing Console."""
    scenarios = attacker_service.get_supported_scenarios()
    active_attacks = attacker_service.get_active_continuous()
    history = attacker_service.get_simulation_history(limit=20)
    current_user = get_current_adversary()
    models_status = model_loader.get_models_status()
    simulated_account = attacker_service.get_simulated_account_access()
    simulated_accounts_status = attacker_service.get_simulated_accounts_status()

    return render_template(
        "attacker_console.html",
        active_page="attacker_console",
        scenarios=scenarios,
        targets=SYNTHETIC_TARGETS,
        active_attacks=active_attacks,
        history=history,
        current_user=current_user,
        models_status=models_status,
        simulated_account=simulated_account,
        simulated_accounts_status=simulated_accounts_status,
        now=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    )


# =========================================================================
# ATTACKER REST APIS
# =========================================================================

@attacker_bp.route("/api/scenarios", methods=["GET"])
@attacker_login_required
def api_scenarios():
    """Retrieve metadata and parameter schemas for the 4 lab scenarios."""
    scenarios = attacker_service.get_supported_scenarios()
    return jsonify({
        "success": True,
        "scenarios": scenarios,
        "targets": SYNTHETIC_TARGETS,
    })


@attacker_bp.route("/api/simulate", methods=["POST"])
@attacker_login_required
def api_simulate():
    """
    Execute a single-shot attack scenario:
    1. Generates real synthetic event
    2. Runs existing detection pipeline (ML & rule models)
    3. Saves result in SQLite
    4. Returns full diagnostics and verification
    """
    data = request.get_json(silent=True) or {}
    scenario_id = data.get("scenario", "")
    params = data.get("params", {})
    current_user = get_current_adversary()
    client_ip = request.remote_addr or "127.0.0.1"

    if not scenario_id:
        return jsonify({"success": False, "error": "Missing 'scenario' parameter"}), 400

    logger.info(
        "AUDIT [ADVERSARY SIMULATION]: Scenario '%s' initiated by %s from IP %s",
        scenario_id,
        current_user.get("username", "anonymous"),
        client_ip,
    )

    # Attach client IP to operator_info for auditing
    op_info = dict(current_user)
    op_info["client_ip"] = client_ip

    result = attacker_service.execute_simulation(
        scenario_id=scenario_id,
        params=params,
        operator_info=op_info,
    )

    status_code = 200 if result.get("success") else 400
    return jsonify(result), status_code


@attacker_bp.route("/api/emergency-stop", methods=["POST"])
@attacker_login_required
def api_emergency_stop():
    """Immediate adversary emergency halt stopping all active simulations and restoring baseline."""
    client_ip = request.remote_addr or "127.0.0.1"
    user = get_current_adversary() or {}
    logger.warning("AUDIT: ADVERSARY EMERGENCY STOP triggered from IP %s by %s", client_ip, user.get("username"))

    attacker_service.stop_all()
    attacker_service.restore_sensor_telemetry("RTU_01")

    try:
        from security.login_monitor import login_monitor
        login_monitor.reset_all()
    except Exception as e:
        logger.warning("Login monitor reset during emergency stop: %s", e)

    return jsonify({
        "success": True,
        "message": "ADVERSARY EMERGENCY STOP EXECUTED: All simulations terminated and sensor telemetry restored to baseline.",
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "triggered_by": user.get("username", "adversary"),
        "client_ip": client_ip,
    })


@attacker_bp.route("/api/restore-sensor", methods=["POST"])
@attacker_login_required
def api_restore_sensor():
    """Restore synthetic sensor values back to nominal baseline after FDI simulation."""
    data = request.get_json(silent=True) or {}
    target_device = data.get("target_device", "RTU_01")
    result = attacker_service.restore_sensor_telemetry(target_device=target_device)
    return jsonify(result), 200


@attacker_bp.route("/api/simulated-account", methods=["GET"])
@attacker_login_required
def api_simulated_account():
    """Retrieve fictional compromised session data for authorized lab demonstration."""
    info = attacker_service.get_simulated_account_access()
    return jsonify({"success": True, "account": info}), 200


@attacker_bp.route("/api/reset-account-lock", methods=["POST"])
@attacker_login_required
def api_reset_account_lock():
    """Reset failed attempt counters and unlock simulated account."""
    data = request.get_json(silent=True) or {}
    account = data.get("account", "admin@scada.local")
    res = attacker_service.reset_account_lock(account)
    return jsonify(res), 200


@attacker_bp.route("/api/accounts-status", methods=["GET"])
@attacker_login_required
def api_accounts_status():
    """Get status of synthetic demo accounts."""
    statuses = attacker_service.get_simulated_accounts_status()
    return jsonify({"success": True, "accounts": statuses}), 200



@attacker_bp.route("/api/continuous/start", methods=["POST"])
@attacker_login_required
def api_continuous_start():
    """Start continuous attack simulation in background worker."""
    data = request.get_json(silent=True) or {}
    attack_name = data.get("attack_name", "")
    params = data.get("params", {})
    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr or "127.0.0.1").split(",")[0].strip()
    user = session.get("attacker_user", {})
    logger.info("AUDIT [ADVERSARY CONTINUOUS START]: Attack '%s' initiated by %s from IP %s", attack_name, user.get("username", "anonymous"), client_ip)
    res = attacker_service.start_continuous(attack_name, params=params)
    return jsonify(res), (200 if res.get("success") else 400)


@attacker_bp.route("/api/continuous/stop", methods=["POST"])
@attacker_login_required
def api_continuous_stop():
    """Stop continuous attack simulation."""
    data = request.get_json(silent=True) or {}
    attack_name = data.get("attack_name", "")
    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr or "127.0.0.1").split(",")[0].strip()
    user = session.get("attacker_user", {})
    logger.info("AUDIT [ADVERSARY CONTINUOUS STOP]: Attack '%s' stopped by %s from IP %s", attack_name, user.get("username", "anonymous"), client_ip)
    res = attacker_service.stop_continuous(attack_name)
    return jsonify(res), (200 if res.get("success") else 400)


@attacker_bp.route("/api/history", methods=["GET"])
@attacker_login_required
def api_history():
    """Retrieve recent simulation execution history."""
    limit = min(100, int(request.args.get("limit", 20)))
    hist = attacker_service.get_simulation_history(limit=limit)
    return jsonify({"success": True, "count": len(hist), "history": hist})


@attacker_bp.route("/api/status", methods=["GET"])
@attacker_login_required
def api_status():
    """Get system readiness, models status, simulation states, and active continuous attacks."""
    models_status = model_loader.get_models_status()
    active_attacks = attacker_service.get_active_continuous()
    simulation_states = attacker_service.get_all_states()
    total_alerts = len(repo.get_recent_alerts(limit=100))

    return jsonify({
        "status": "ready",
        "active_continuous_attacks": active_attacks,
        "simulation_states": simulation_states,
        "models_status": models_status,
        "total_alerts_stored": total_alerts,
        "timestamp": datetime.now().isoformat(),
    })



@attacker_bp.route("/api/verify-alert/<alert_id>", methods=["GET"])
@attacker_login_required
def api_verify_alert(alert_id: str):
    """
    Cross-verification endpoint confirming the alert is stored in the shared
    database and is ready for the existing user website's Attack Detection page.
    """
    alerts = repo.get_recent_alerts(limit=100)
    matched = [a for a in alerts if a.alert_id == alert_id]
    if not matched:
        return jsonify({
            "verified": False,
            "error": f"Alert '{alert_id}' not found in database",
        }), 404

    target_alert = matched[0]
    return jsonify({
        "verified": True,
        "alert": target_alert.to_dict(),
        "propagated_to_user_website": True,
        "user_website_page": "/attack-alerts",
        "user_website_api": f"/api/alerts?limit=50",
    })
