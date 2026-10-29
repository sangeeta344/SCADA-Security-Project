"""Database connection and lifecycle management for SQLite."""

import sqlite3
from pathlib import Path
from typing import Optional
from contextlib import contextmanager

from config.settings import settings
from config.logging_config import logger


class Database:
    """SQLite Database manager with thread-safe connections and initialization."""

    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = Path(db_path or settings.DATABASE_PATH)
        self.schema_path = settings.BASE_DIR / "database" / "schema.sql"

    def init_db(self) -> None:
        """Create database tables, indexes, and initial records if not existing."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        if not self.schema_path.exists():
            raise FileNotFoundError(f"Schema file missing at {self.schema_path}")

        with open(self.schema_path, "r", encoding="utf-8") as f:
            schema_sql = f.read()

        with self.get_connection() as conn:
            conn.executescript(schema_sql)
            conn.commit()
            self._seed_default_devices(conn)
            self._seed_default_users(conn)
        logger.info("Database initialized successfully at %s", self.db_path)

    @contextmanager
    def get_connection(self):
        """Context manager providing a SQLite connection with dict-like row factory."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(self.db_path), timeout=15.0)
        conn.row_factory = sqlite3.Row
        # Enable WAL mode for high concurrency
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
        try:
            yield conn
        finally:
            conn.close()

    def _seed_default_devices(self, conn: sqlite3.Connection) -> None:
        """Seed baseline industrial devices if not present."""
        default_devices = [
            ("RTU_01", "Remote Terminal Unit 01", "RTU", "MODBUS_TCP", settings.MODBUS_HOST, settings.MODBUS_PORT, "ONLINE"),
            ("PLC_01", "Programmable Logic Controller 01", "PLC", "INTERNAL", "127.0.0.1", None, "ONLINE"),
            ("MTU_01", "Master Terminal Unit (SCADA Server)", "MTU", "MODBUS_TCP", "127.0.0.1", None, "ONLINE"),
            ("MQTT_BROKER", "Mosquitto Telemetry Broker", "BROKER", "MQTT", settings.MQTT_HOST, settings.MQTT_PORT, "OFFLINE"),
            ("PUMP_01", "Industrial Water Pump 01", "ACTUATOR", "INTERNAL", None, None, "ONLINE"),
            ("VALVE_01", "Safety Release Valve 01", "ACTUATOR", "INTERNAL", None, None, "ONLINE"),
            ("TEMP_SENS", "Core Temperature Sensor", "SENSOR", "MODBUS_TCP", None, None, "ONLINE"),
            ("PRESS_SENS", "Pressure Sensor", "SENSOR", "MODBUS_TCP", None, None, "ONLINE"),
            ("LEVEL_SENS", "Water Level Sensor", "SENSOR", "MODBUS_TCP", None, None, "ONLINE"),
            ("FLOW_SENS", "Flow Rate Sensor", "SENSOR", "MODBUS_TCP", None, None, "ONLINE"),
        ]
        for dev in default_devices:
            conn.execute(
                """
                INSERT OR IGNORE INTO devices (id, name, device_type, protocol, ip_address, port, status)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                dev,
            )
        conn.commit()

    def _seed_default_users(self, conn: sqlite3.Connection) -> None:
        """Seed default administrator and dedicated demo operator accounts if not present."""
        try:
            from werkzeug.security import generate_password_hash
            default_users = [
                ("SCADA Administrator", "admin@scada.local", generate_password_hash("admin123"), "System Administrator"),
                ("Demo SCADA Operator", "demo_operator@scada.local", generate_password_hash("demo123"), "Operator"),
            ]
            for user in default_users:
                conn.execute(
                    """
                    INSERT OR IGNORE INTO users (username, email, password_hash, role)
                    VALUES (?, ?, ?, ?)
                    """,
                    user,
                )
            conn.commit()
            logger.info("Default baseline accounts verified: admin@scada.local, demo_operator@scada.local")
        except Exception as e:
            logger.warning("User seeding error: %s", e)


# Default singleton instance
db = Database()
