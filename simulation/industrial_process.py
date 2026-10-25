"""Coupled physical industrial process simulator."""

from typing import Dict, Any, Optional
from simulation.sensor_simulator import SensorSimulator
from simulation.actuator_simulator import ActuatorSimulator
from config.settings import settings


class IndustrialProcess:
    """Coupled physical process simulating mass and heat balance."""

    def __init__(self, seed: Optional[int] = None):
        self.sensors = SensorSimulator(seed=seed)
        self.actuators = ActuatorSimulator()
        self.step_count = 0

    def step(self, overrides: Optional[Dict[str, float]] = None) -> Dict[str, Any]:
        """Advance physical process by one discrete time step."""
        self.step_count += 1

        # Physical coupling:
        # If pump is ON, water level rises slightly unless valve is OPEN
        level_delta = 0.0
        if self.actuators.pump.is_running:
            level_delta += 1.2
        if self.actuators.valve.is_open:
            level_delta -= 1.8

        # Pressure increases when pump is ON and valve is CLOSED
        press_delta = 0.0
        if self.actuators.pump.is_running and not self.actuators.valve.is_open:
            press_delta += 0.03
        elif not self.actuators.pump.is_running:
            press_delta -= 0.05

        # Update sensor values with process offsets
        self.sensors.water_level.current_val = max(
            750.0, min(1050.0, self.sensors.water_level.current_val + level_delta)
        )
        self.sensors.pressure.current_val = max(
            1.2, min(3.8, self.sensors.pressure.current_val + press_delta)
        )

        sensor_data = self.sensors.sample(overrides=overrides)
        actuator_data = self.actuators.get_state()

        return {
            "step": self.step_count,
            "sensor_readings": sensor_data,
            "actuators": actuator_data,
        }
