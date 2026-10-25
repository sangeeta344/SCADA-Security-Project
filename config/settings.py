"""Configuration management for the SCADA Security & Quantum System."""

import os
from pathlib import Path
from dotenv import load_dotenv

# Base directory of the repository
BASE_DIR = Path(__file__).resolve().parent.parent

# Load .env if present
load_dotenv(BASE_DIR / ".env")


def _find_dataset(filename: str, subdirs: list[str]) -> Path:
    """Find a dataset file by checking multiple potential directories."""
    candidates = [
        BASE_DIR / "dataset" / filename,
        BASE_DIR / "datasets" / filename,
        BASE_DIR / "data" / "samples" / filename,
    ]
    for sub in subdirs:
        candidates.append(BASE_DIR / "dataset" / sub / filename)
        candidates.append(BASE_DIR / "datasets" / sub / filename)

    for p in candidates:
        if p.exists():
            return p
    # Return preferred default path if not found
    return BASE_DIR / "dataset" / filename


class Settings:
    """System-wide configuration settings with environment variable overrides."""

    # Project Root
    BASE_DIR: Path = BASE_DIR

    # Flask Web Dashboard
    FLASK_HOST: str = os.getenv("FLASK_HOST", "127.0.0.1")
    FLASK_PORT: int = int(os.getenv("FLASK_PORT", "5000"))
    FLASK_DEBUG: bool = os.getenv("FLASK_DEBUG", "false").lower() in ("true", "1", "yes")
    SECRET_KEY: str = os.getenv("SECRET_KEY", "scada-quantum-dev-secret-key-change-prod")

    # Database
    DATABASE_PATH: Path = BASE_DIR / os.getenv("DATABASE_PATH", "data/scada_security.db")

    # Modbus TCP Protocol
    MODBUS_HOST: str = os.getenv("MODBUS_HOST", "127.0.0.1")
    MODBUS_PORT: int = int(os.getenv("MODBUS_PORT", "5020"))
    MODBUS_SLAVE_ID: int = int(os.getenv("MODBUS_SLAVE_ID", "1"))

    # MQTT Protocol
    MQTT_HOST: str = os.getenv("MQTT_HOST", "127.0.0.1")
    MQTT_PORT: int = int(os.getenv("MQTT_PORT", "1883"))
    MQTT_KEEPALIVE: int = int(os.getenv("MQTT_KEEPALIVE", "60"))

    # Quantum Key Distribution (BB84)
    QBER_THRESHOLD: float = float(os.getenv("QBER_THRESHOLD", "0.11"))
    BB84_RAW_BITS: int = int(os.getenv("BB84_RAW_BITS", "256"))
    BB84_SAMPLE_RATIO: float = float(os.getenv("BB84_SAMPLE_RATIO", "0.33"))

    # Industrial Simulation
    SIMULATION_INTERVAL: float = float(os.getenv("SIMULATION_INTERVAL", "1.0"))
    RANDOM_SEED: int = int(os.getenv("RANDOM_SEED", "42"))

    # Logging
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")
    LOG_FILE: Path = BASE_DIR / os.getenv("LOG_FILE", "logs/scada_security.log")

    # Datasets
    NETWORK_DATASET_PATH: Path = _find_dataset("train_test_network.csv", ["TON_IoT"])
    SENSOR_DATASET_PATH: Path = _find_dataset("scada_sensor_dataset_200_rows.csv", [])

    # Models Directory
    MODELS_DIR: Path = BASE_DIR / "models"
    NETWORK_MODEL_PATH: Path = MODELS_DIR / "network_intrusion_pipeline.joblib"
    SENSOR_MODEL_PATH: Path = MODELS_DIR / "sensor_anomaly_pipeline.joblib"
    NETWORK_METRICS_PATH: Path = MODELS_DIR / "network_metrics.json"
    SENSOR_METRICS_PATH: Path = MODELS_DIR / "sensor_metrics.json"


settings = Settings()
