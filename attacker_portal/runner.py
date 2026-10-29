"""Standalone runner for the SCADA Attacker Portal (Optional Separate Port).

Allows launching the Attacker Portal on its own independent port (default 5050)
if separate ports or two different laptops are preferred, while sharing the same
underlying SQLite database and ML pipelines.
"""

import sys
import socket
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from flask import Flask, redirect, url_for, request, Response
from config.settings import settings
from config.logging_config import logger
from database.db import db
from attacker_portal.routes import attacker_bp


def _get_lan_ip() -> str:
    """Detect primary LAN IP address for cross-laptop connectivity."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.2)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def create_attacker_app() -> Flask:
    """Create standalone Flask app for the Attacker Portal with CORS and network config."""
    app = Flask(__name__)
    app.config["SECRET_KEY"] = settings.SECRET_KEY
    app.config["DEBUG"] = settings.FLASK_DEBUG

    # Initialize shared database tables
    try:
        db.init_db()
    except Exception as e:
        logger.warning("Database init: %s", e)

    # CORS Preflight
    @app.before_request
    def handle_cors():
        if request.method == "OPTIONS":
            resp = app.make_default_options_response()
            origin = request.headers.get("Origin") or "*"
            resp.headers["Access-Control-Allow-Origin"] = origin
            resp.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS, HEAD"
            resp.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-Requested-With, X-API-Key"
            resp.headers["Access-Control-Allow-Credentials"] = "true"
            return resp

    # Security & CORS Headers
    @app.after_request
    def apply_cors_headers(response: Response):
        origin = request.headers.get("Origin") or "*"
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS, HEAD"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-Requested-With, X-API-Key"
        response.headers["Access-Control-Allow-Credentials"] = "true"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "SAMEORIGIN"
        return response

    # Global template config
    @app.context_processor
    def inject_network_config():
        backend_api = (settings.BACKEND_API_URL or "").rstrip("/")
        if not backend_api:
            try:
                host_ip = request.host.split(":")[0]
                backend_api = f"{request.scheme}://{host_ip}:5000"
            except Exception:
                backend_api = f"http://{_get_lan_ip()}:5000"
        public_url = (settings.SCADA_PUBLIC_URL or backend_api).rstrip("/")
        return {
            "backend_api_url": backend_api,
            "scada_public_url": public_url,
            "demo_account_email": settings.DEMO_ACCOUNT_EMAIL,
        }

    # Register attacker blueprint at /attacker
    app.register_blueprint(attacker_bp, url_prefix="/attacker")

    @app.route("/")
    def index():
        return redirect(url_for("attacker.console"))

    return app


def main():
    port = 5050
    host = settings.FLASK_HOST or "0.0.0.0"
    lan_ip = _get_lan_ip()

    print("=" * 75)
    print("  SCADA ADVERSARY EMULATION & PENETRATION TESTING PORTAL")
    print("=" * 75)
    print(f"[+] Local URL:               http://127.0.0.1:{port}/")
    print(f"[+] Cross-Laptop Network URL: http://{lan_ip}:{port}/")
    print(f"[+] Shared Database Path:     {settings.DATABASE_PATH}")
    print(f"[+] Bound Interfaces:         {host}:{port}")
    print("=" * 75)

    app = create_attacker_app()
    app.run(host=host, port=port, debug=False)


if __name__ == "__main__":
    main()
