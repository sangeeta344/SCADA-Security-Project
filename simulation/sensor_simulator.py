"""Sensor simulator for SCADA industrial variables."""

import random
import time
from datetime import datetime
from typing import Dict, Any, Optional
from config.settings import settings


class Sensor:
    """Individual sensor modeling physical boundaries, noise, and units."""

    def __init__(
        self,
        sensor_id: str,
        name: str,
        unit: str,
        min_val: float,
        max_val: float,
        nominal_val: float,
        noise_std: float = 0.2,
        seed: Optional[int] = None,
    ):
        self.sensor_id = sensor_id
        self.name = name
        self.unit = unit
        self.min_val = min_val
        self.max_val = max_val
        self.current_val = nominal_val
        self.noise_std = noise_std
        self.rng = random.Random(seed)
        self.status = "NORMAL"

    def read(self, process_offset: float = 0.0) -> float:
        """Generate a realistic noisy reading bounded by safety limits."""
        noise = self.rng.gauss(0, self.noise_std)
        val = self.current_val + process_offset + noise
        self.current_val = max(self.min_val, min(self.max_val, round(val, 2)))

        # Update status
        if self.current_val >= self.max_val * 0.95 or self.current_val <= self.min_val * 1.05:
            self.status = "WARNING"
        else:
            self.status = "NORMAL"

        return self.current_val


class SensorSimulator:
    """Industrial sensor suite simulator generating 4 core SCADA telemetry measurements."""

    def __init__(self, seed: Optional[int] = None):
        seed_val = seed if seed is not None else settings.RANDOM_SEED
        # Sensor ranges matched to actual scada_sensor_dataset_200_rows.csv statistics:
        # temp: 25.7 - 30.4, press: 2.19 - 2.82, water: 845 - 955, flow: 28.2 - 41.1
        self.temperature = Sensor("TEMP_01", "Core Temperature", "°C", 15.0, 45.0, 28.0, 0.15, seed=seed_val)
        self.pressure = Sensor("PRESS_01", "Line Pressure", "bar", 1.0, 4.0, 2.5, 0.02, seed=seed_val + 1)
        self.water_level = Sensor("LEVEL_01", "Tank Water Level", "mm", 700.0, 1100.0, 910.0, 1.5, seed=seed_val + 2)
        self.flow_rate = Sensor("FLOW_01", "Discharge Flow Rate", "L/min", 20.0, 55.0, 35.0, 0.3, seed=seed_val + 3)

    def sample(self, overrides: Optional[Dict[str, float]] = None) -> Dict[str, Any]:
        """Sample all 4 sensors at the current timestamp, applying any simulation overrides."""
        overrides = overrides or {}
        temp = overrides.get("temperature_c", self.temperature.read())
        press = overrides.get("pressure_bar", self.pressure.read())
        level = overrides.get("water_level_mm", self.water_level.read())
        flow = overrides.get("flow_rate_lpm", self.flow_rate.read())

        status = "NORMAL"
        if any(s.status == "WARNING" for s in [self.temperature, self.pressure, self.water_level, self.flow_rate]):
            status = "WARNING"

        return {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "sensor_id": "SENSOR_01",
            "rtu_id": "RTU_01",
            "temperature_c": float(temp),
            "pressure_bar": float(press),
            "water_level_mm": float(level),
            "flow_rate_lpm": float(flow),
            "operating_status": status,
        }
