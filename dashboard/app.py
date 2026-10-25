"""Flask application factory for SCADA Security Dashboard."""

from flask import Flask
from pathlib import Path
from typing import Optional

from config.settings import settings
from config.logging_config import logger
from database.db import db


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

    # Register routes
    from dashboard.routes import dashboard_bp
    app.register_blueprint(dashboard_bp)

    return app
