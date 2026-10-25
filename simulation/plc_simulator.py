"""Programmable Logic Controller (PLC) simulation with deterministic ladder logic."""

from typing import Dict, Any
from simulation.actuator_simulator import ActuatorSimulator


class PLCSimulator:
    """Industrial PLC executing safety control loops on sensor inputs."""

    def __init__(self, actuator_sim: ActuatorSimulator, plc_id: str = "PLC_01"):
        self.plc_id = plc_id
        self.actuators = actuator_sim
        self.last_rule_fired = "NORMAL_REGULATION"
        self.cycle_count = 0

    def execute_logic(self, sensor_readings: Dict[str, Any]) -> Dict[str, Any]:
        """Execute safety rules based on sensor inputs."""
        self.cycle_count += 1
        level = sensor_readings.get("water_level_mm", 900.0)
        temp = sensor_readings.get("temperature_c", 28.0)
        pressure = sensor_readings.get("pressure_bar", 2.5)

        rule_fired = "NORMAL_REGULATION"

        # High level safety cutoff (prevent tank overflow)
        if level > 980.0:
            self.actuators.pump.set_state(False)
            self.actuators.valve.set_state(True)
            rule_fired = "OVERFLOW_PREVENTION: PUMP_OFF, VALVE_OPEN"

        # Low level safety cutoff (prevent pump cavitation)
        elif level < 820.0:
            self.actuators.pump.set_state(True)
            self.actuators.valve.set_state(False)
            rule_fired = "LOW_LEVEL_PROTECTION: PUMP_ON, VALVE_CLOSE"

        # High pressure safety relief
        elif pressure > 3.4:
            self.actuators.valve.set_state(True)
            rule_fired = "PRESSURE_RELIEF: VALVE_OPEN"

        # High temperature safety interlock
        elif temp > 38.0:
            self.actuators.valve.set_state(True)
            rule_fired = "THERMAL_RELIEF: VALVE_OPEN"

        self.last_rule_fired = rule_fired

        return {
            "plc_id": self.plc_id,
            "cycle": self.cycle_count,
            "rule_fired": rule_fired,
            "actuators": self.actuators.get_state(),
        }
