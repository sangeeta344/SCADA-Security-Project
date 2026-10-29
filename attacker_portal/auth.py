"""Authentication and session management for the authorized Attacker Portal.

Uses isolated fictional adversary accounts and never touches, collects,
or exposes real operator credentials, session tokens, or private user data.
"""

from functools import wraps
from typing import Optional, Dict, Any
from datetime import datetime
from flask import session, request, redirect, url_for, jsonify, current_app
from werkzeug.security import generate_password_hash, check_password_hash

# Predefined authorized lab adversary accounts (Fictional lab credentials only)
FICTIONAL_ADVERSARY_ACCOUNTS = {
    "redteam_lead@scada-lab.local": {
        "id": "adv_001",
        "username": "redteam_lead",
        "email": "redteam_lead@scada-lab.local",
        "password_hash": generate_password_hash("Adversary2026!"),
        "role": "Red Team Lead",
        "badge": "Offensive Security Certified Lab Operator",
        "clearance": "Lab Simulation Only",
    },
    "researcher@scada-lab.local": {
        "id": "adv_002",
        "username": "threat_researcher",
        "email": "researcher@scada-lab.local",
        "password_hash": generate_password_hash("LabResearch2026!"),
        "role": "Security Researcher",
        "badge": "Adversary Emulation Specialist",
        "clearance": "Lab Simulation Only",
    },
}


def authenticate_adversary(email: str, password: str) -> Optional[Dict[str, Any]]:
    """Validate fictional attacker credentials."""
    clean_email = (email or "").strip().lower()
    account = FICTIONAL_ADVERSARY_ACCOUNTS.get(clean_email)
    if not account:
        return None

    if check_password_hash(account["password_hash"], password):
        return {
            "id": account["id"],
            "username": account["username"],
            "email": account["email"],
            "role": account["role"],
            "badge": account["badge"],
            "clearance": account["clearance"],
            "login_time": datetime.now().isoformat(),
        }
    return None


def get_current_adversary() -> Optional[Dict[str, Any]]:
    """Retrieve currently authenticated attacker from session."""
    return session.get("attacker_user")


def attacker_login_required(f):
    """Decorator requiring an authenticated attacker session."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_app.config.get("LOGIN_DISABLED"):
            return f(*args, **kwargs)

        if not session.get("attacker_user"):
            if request.path.startswith("/attacker/api/"):
                return jsonify({
                    "error": "Unauthorized",
                    "message": "Attacker portal authentication required. Please log in at /attacker/login.",
                }), 401
            return redirect(url_for("attacker.login", next=request.path))

        return f(*args, **kwargs)
    return decorated_function
