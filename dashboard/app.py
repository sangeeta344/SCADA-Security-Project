"""Flask application factory for SCADA Security Dashboard."""

from flask import Flask, request, Response
from pathlib import Path
from typing import Optional

from config.settings import settings
from config.logging_config import logger
from database.db import db


def _is_origin_allowed(origin: Optional[str]) -> bool:
    """Check if origin matches CORS configuration."""
    if not origin:
        return True
    allowed = (settings.CORS_ALLOWED_ORIGINS or "*").strip()
    if allowed == "*":
        return True
    origins = [o.strip() for o in allowed.split(",") if o.strip()]
    return origin in origins


def _apply_cors_headers(response: Response) -> Response:
    """Apply CORS headers allowing cross-laptop communication."""
    origin = request.headers.get("Origin")
    if _is_origin_allowed(origin):
        response.headers["Access-Control-Allow-Origin"] = origin or "*"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS, HEAD"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-Requested-With, X-API-Key"
        response.headers["Access-Control-Allow-Credentials"] = "true"
        response.headers["Access-Control-Max-Age"] = "86400"
    return response


def create_app(test_config: Optional[dict] = None) -> Flask:
    """Create and configure Flask application."""
    app = Flask(
        __name__,
        template_folder="templates",
        static_folder="static",
    )

    app.config["SECRET_KEY"] = settings.SECRET_KEY
    app.config["DEBUG"] = settings.FLASK_DEBUG

    if test_config:
        app.config.update(test_config)

    # Initialize database tables
    try:
        db.init_db()
    except Exception as e:
        logger.warning("Database init during create_app: %s", e)

    # CORS Preflight Handler
    @app.before_request
    def handle_cors_preflight():
        if request.method == "OPTIONS":
            response = app.make_default_options_response()
            return _apply_cors_headers(response)

    # Security & CORS Headers on all responses
    @app.after_request
    def apply_security_headers(response: Response):
        _apply_cors_headers(response)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "SAMEORIGIN"
        return response

    # Global Template Context Processor (inject API URLs for multi-laptop frontend)
    @app.context_processor
    def inject_network_config():
        backend_api = (settings.BACKEND_API_URL or "").rstrip("/")
        if not backend_api:
            try:
                backend_api = request.host_url.rstrip("/")
            except Exception:
                backend_api = ""
        public_url = (settings.SCADA_PUBLIC_URL or backend_api or "http://127.0.0.1:5000").rstrip("/")
        return {
            "backend_api_url": backend_api,
            "scada_public_url": public_url,
            "demo_account_email": settings.DEMO_ACCOUNT_EMAIL,
        }

    # Register routes
    from dashboard.routes import dashboard_bp
    app.register_blueprint(dashboard_bp)

    # Register Attacker Portal Blueprint
    from attacker_portal.routes import attacker_bp
    app.register_blueprint(attacker_bp, url_prefix="/attacker")

    return app
