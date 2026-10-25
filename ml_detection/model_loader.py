"""Safe model loading, caching, and readiness verification."""

import json
from pathlib import Path
from typing import Optional, Dict, Any
import joblib

from config.settings import settings
from config.logging_config import logger


class ModelLoader:
    """Manages model pipeline caching, schema verification, and readiness status."""

    def __init__(self):
        self._network_pipeline = None
        self._sensor_pipeline = None
        self._network_metrics = None
        self._sensor_metrics = None

    def get_network_pipeline(self):
        """Load and return network intrusion classification pipeline."""
        if self._network_pipeline is None:
            if settings.NETWORK_MODEL_PATH.exists():
                try:
                    self._network_pipeline = joblib.load(settings.NETWORK_MODEL_PATH)
                    logger.info("Loaded network intrusion pipeline from %s", settings.NETWORK_MODEL_PATH)
                except Exception as e:
                    logger.error("Failed to load network model: %s", e)
                    return None
            else:
                logger.warning("Network intrusion model file missing at %s", settings.NETWORK_MODEL_PATH)
        return self._network_pipeline

    def get_sensor_pipeline(self):
        """Load and return sensor anomaly detection pipeline."""
        if self._sensor_pipeline is None:
            if settings.SENSOR_MODEL_PATH.exists():
                try:
                    self._sensor_pipeline = joblib.load(settings.SENSOR_MODEL_PATH)
                    logger.info("Loaded sensor anomaly pipeline from %s", settings.SENSOR_MODEL_PATH)
                except Exception as e:
                    logger.error("Failed to load sensor model: %s", e)
                    return None
            else:
                logger.warning("Sensor anomaly model file missing at %s", settings.SENSOR_MODEL_PATH)
        return self._sensor_pipeline

    def get_network_metrics(self) -> Optional[Dict[str, Any]]:
        """Load evaluation metrics for network model."""
        if self._network_metrics is None and settings.NETWORK_METRICS_PATH.exists():
            try:
                with open(settings.NETWORK_METRICS_PATH, "r", encoding="utf-8") as f:
                    self._network_metrics = json.load(f)
            except Exception:
                pass
        return self._network_metrics

    def get_sensor_metrics(self) -> Optional[Dict[str, Any]]:
        """Load evaluation metrics for sensor model."""
        if self._sensor_metrics is None and settings.SENSOR_METRICS_PATH.exists():
            try:
                with open(settings.SENSOR_METRICS_PATH, "r", encoding="utf-8") as f:
                    self._sensor_metrics = json.load(f)
            except Exception:
                pass
        return self._sensor_metrics

    def get_models_status(self) -> Dict[str, Any]:
        """Check availability and readiness of both models."""
        net_loaded = self.get_network_pipeline() is not None
        sens_loaded = self.get_sensor_pipeline() is not None

        return {
            "network_model": {
                "available": net_loaded,
                "path": str(settings.NETWORK_MODEL_PATH),
                "metrics": self.get_network_metrics(),
            },
            "sensor_model": {
                "available": sens_loaded,
                "path": str(settings.SENSOR_MODEL_PATH),
                "metrics": self.get_sensor_metrics(),
            },
            "all_models_ready": net_loaded and sens_loaded,
        }


model_loader = ModelLoader()
